//! GitHub OAuth flow (CLI-friendly): the worker generates an authorize
//! URL with a CSRF state, the user opens it in a browser, GitHub
//! redirects to `/oauth/github/callback?state=...&code=...`, the
//! callback page surfaces the values, and the user pastes them into
//! `edgereplica oauth complete --state ... --code ...`.
//!
//! Scopes used: `read:user user:email` (we need a verified primary email
//! to look up / create the local user, and nothing else).
//!
//! Wholly env-gated: when `GITHUB_CLIENT_ID` / `GITHUB_CLIENT_SECRET` /
//! `OAUTH_REDIRECT_BASE` are unset the AdminService stubs return
//! `Unimplemented` and never call into here. Google would be a near-copy
//! of this file with provider-specific URLs swapped in.

#![cfg(target_arch = "wasm32")]

use connectrpc::ConnectError;
use edgereplica_shared::IdentityProvider;
use serde::Deserialize;
use worker::send::SendFuture;
use worker::wasm_bindgen::JsValue;
use worker::{Fetch, Headers, Method, Request, RequestInit};

use crate::state::Config;

const GITHUB_AUTHORIZE_URL: &str = "https://github.com/login/oauth/authorize";
const GITHUB_TOKEN_URL: &str = "https://github.com/login/oauth/access_token";
const GITHUB_USER_URL: &str = "https://api.github.com/user";
const GITHUB_EMAILS_URL: &str = "https://api.github.com/user/emails";
const GITHUB_SCOPES: &str = "read:user user:email";

/// Identity returned by the IdP, normalised onto our internal shape.
#[derive(Debug, Clone)]
pub struct OAuthIdentity {
    pub provider: IdentityProvider,
    pub provider_user_id: String,
    pub email: String,
}

/// Build the URL the user should open in their browser. Caller is
/// responsible for `store_oauth_state(state)` before returning the URL
/// — that's an async DB write and we want the OAuth module to stay
/// pure-by-IdP-only.
pub fn github_authorize_url(client_id: &str, redirect_uri: &str, state: &str) -> String {
    format!(
        "{GITHUB_AUTHORIZE_URL}?client_id={}&redirect_uri={}&state={}&scope={}",
        urlencode(client_id),
        urlencode(redirect_uri),
        urlencode(state),
        urlencode(GITHUB_SCOPES),
    )
}

/// Per-provider config knob — returns the configured client id/secret
/// or `None` if the deployment hasn't enabled this provider.
pub fn github_credentials(config: &Config) -> Option<(&str, &str)> {
    let id = config.github_client_id.as_deref()?;
    let secret = config.github_client_secret.as_deref()?;
    Some((id, secret))
}

/// Exchange a callback `code` for the user's GitHub identity. Errors
/// are surfaced as `ConnectError` so they map directly onto the RPC
/// error codes; the message is intentionally brief to avoid leaking
/// IdP error bodies into client-visible text.
pub async fn complete_github(
    config: &Config,
    code: &str,
    redirect_uri: &str,
) -> Result<OAuthIdentity, ConnectError> {
    let (client_id, client_secret) = github_credentials(config)
        .ok_or_else(|| ConnectError::failed_precondition("github oauth not configured"))?;

    let access_token = exchange_code(client_id, client_secret, code, redirect_uri).await?;
    let (provider_user_id, email_from_user) = fetch_github_user(&access_token).await?;
    let email = match email_from_user {
        Some(e) => e,
        None => fetch_github_primary_email(&access_token).await?,
    };
    Ok(OAuthIdentity {
        provider: IdentityProvider::GitHub,
        provider_user_id,
        email,
    })
}

#[derive(Deserialize)]
struct TokenResponse {
    access_token: Option<String>,
    error: Option<String>,
    error_description: Option<String>,
}

async fn exchange_code(
    client_id: &str,
    client_secret: &str,
    code: &str,
    redirect_uri: &str,
) -> Result<String, ConnectError> {
    let body = format!(
        "client_id={}&client_secret={}&code={}&redirect_uri={}",
        urlencode(client_id),
        urlencode(client_secret),
        urlencode(code),
        urlencode(redirect_uri),
    );
    let headers = Headers::new();
    let _ = headers.set("Accept", "application/json");
    let _ = headers.set("Content-Type", "application/x-www-form-urlencoded");
    let init = RequestInit {
        body: Some(JsValue::from_str(&body)),
        headers,
        method: Method::Post,
        ..RequestInit::new()
    };
    let req = Request::new_with_init(GITHUB_TOKEN_URL, &init)
        .map_err(|e| ConnectError::internal(format!("oauth token req: {e}")))?;
    // `Fetch::send` futures are !Send (they capture `JsFuture` whose
    // inner state is `Rc<RefCell<_>>`). The ConnectRPC trait wants
    // `+ Send`. Workers is single-threaded, so wrapping the future
    // with `SendFuture` is safe — same trick `worker::D1Repo` uses.
    let mut resp = SendFuture::new(Fetch::Request(req).send())
        .await
        .map_err(|e| ConnectError::unavailable(format!("github token endpoint: {e}")))?;
    let text = SendFuture::new(resp.text())
        .await
        .map_err(|e| ConnectError::internal(format!("read token resp: {e}")))?;
    let parsed: TokenResponse = serde_json::from_str(&text)
        .map_err(|e| ConnectError::internal(format!("decode token resp: {e}")))?;
    if let Some(err) = parsed.error {
        let detail = parsed.error_description.unwrap_or_default();
        return Err(ConnectError::permission_denied(format!(
            "github oauth: {err} {detail}"
        )));
    }
    parsed
        .access_token
        .ok_or_else(|| ConnectError::internal("github oauth: missing access_token"))
}

#[derive(Deserialize)]
struct UserResponse {
    id: u64,
    email: Option<String>,
}

async fn fetch_github_user(access_token: &str) -> Result<(String, Option<String>), ConnectError> {
    let resp = github_get(access_token, GITHUB_USER_URL).await?;
    let parsed: UserResponse = serde_json::from_str(&resp)
        .map_err(|e| ConnectError::internal(format!("decode /user: {e}")))?;
    Ok((parsed.id.to_string(), parsed.email))
}

#[derive(Deserialize)]
struct EmailEntry {
    email: String,
    primary: bool,
    verified: bool,
}

/// Some users hide their primary email on `/user`; fall through to
/// `/user/emails`. Returns the first verified primary, falling back to
/// any verified address — never an unverified one.
async fn fetch_github_primary_email(access_token: &str) -> Result<String, ConnectError> {
    let resp = github_get(access_token, GITHUB_EMAILS_URL).await?;
    let entries: Vec<EmailEntry> = serde_json::from_str(&resp)
        .map_err(|e| ConnectError::internal(format!("decode /user/emails: {e}")))?;
    if let Some(e) = entries.iter().find(|e| e.primary && e.verified) {
        return Ok(e.email.clone());
    }
    if let Some(e) = entries.iter().find(|e| e.verified) {
        return Ok(e.email.clone());
    }
    Err(ConnectError::failed_precondition(
        "github account has no verified email",
    ))
}

async fn github_get(access_token: &str, url: &str) -> Result<String, ConnectError> {
    let headers = Headers::new();
    let _ = headers.set("Accept", "application/vnd.github+json");
    let _ = headers.set("Authorization", &format!("Bearer {access_token}"));
    // GitHub requires a User-Agent on all API calls.
    let _ = headers.set("User-Agent", "edgereplica-worker");
    let init = RequestInit {
        headers,
        method: Method::Get,
        ..RequestInit::new()
    };
    let req = Request::new_with_init(url, &init)
        .map_err(|e| ConnectError::internal(format!("oauth req {url}: {e}")))?;
    let mut resp = SendFuture::new(Fetch::Request(req).send())
        .await
        .map_err(|e| ConnectError::unavailable(format!("github GET {url}: {e}")))?;
    if resp.status_code() < 200 || resp.status_code() >= 300 {
        return Err(ConnectError::internal(format!(
            "github GET {url}: status {}",
            resp.status_code()
        )));
    }
    SendFuture::new(resp.text())
        .await
        .map_err(|e| ConnectError::internal(format!("read body {url}: {e}")))
}

/// Minimal RFC3986 percent-encoder for application/x-www-form-urlencoded
/// payloads. Avoids pulling in `urlencoding` or `form_urlencoded` for a
/// handful of strings we already trust to be ASCII-ish.
fn urlencode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for byte in s.as_bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(*byte as char);
            }
            b' ' => out.push('+'),
            other => out.push_str(&format!("%{other:02X}")),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::urlencode;

    #[test]
    fn urlencode_handles_reserved_chars() {
        assert_eq!(urlencode("hello world"), "hello+world");
        assert_eq!(urlencode("a/b?c=d&e"), "a%2Fb%3Fc%3Dd%26e");
        assert_eq!(urlencode("plain.text-1_2~3"), "plain.text-1_2~3");
    }
}
