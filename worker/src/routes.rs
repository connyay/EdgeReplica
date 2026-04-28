//! Non-RPC HTTP routes: `/healthz` and the OAuth callback landing page.
//!
//! The callback doesn't *complete* the OAuth flow itself — it just shows
//! the user the `state` and `code` so they can paste them into
//! `edgereplica oauth complete --state ... --code ...`. That command then
//! calls `AdminService.CompleteOAuth`, which does the IdP token exchange.
//! Splitting it this way keeps the worker handler free of tokens that
//! shouldn't end up in browser history.

use bytes::Bytes;
use connectrpc::ConnectRpcBody;
use http::{Method, Response, StatusCode};
use http_body_util::Full;
use worker::HttpRequest;

/// Returns `Some(response)` if `req` matches a non-RPC route, else `None`
/// so the caller can dispatch into the ConnectRPC service.
pub fn try_handle(req: &HttpRequest) -> Option<Response<ConnectRpcBody>> {
    match (req.method(), req.uri().path()) {
        (&Method::GET, "/healthz") => Some(text(StatusCode::OK, "ok")),
        (&Method::GET, p) if p.starts_with("/oauth/") && p.ends_with("/callback") => {
            Some(oauth_callback_page(req))
        }
        // 404 for any other /oauth/ path — clients shouldn't be hitting
        // them directly, the supported flow is via `edgereplica oauth ...`.
        (_, p) if p.starts_with("/oauth/") => Some(text(StatusCode::NOT_FOUND, "not found")),
        _ => None,
    }
}

/// Render the state+code values from the IdP's `?state=...&code=...`
/// redirect as a copy-paste-friendly HTML page. Anything else (no
/// query, missing fields, etc.) falls back to a 400.
fn oauth_callback_page(req: &HttpRequest) -> Response<ConnectRpcBody> {
    let query = req.uri().query().unwrap_or_default();
    let mut state = None;
    let mut code = None;
    let mut error = None;
    for pair in query.split('&').filter(|s| !s.is_empty()) {
        let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
        let v = url_decode(v);
        match k {
            "state" => state = Some(v),
            "code" => code = Some(v),
            "error" | "error_description" => error = Some(v),
            _ => {}
        }
    }
    if let Some(err) = error {
        return html(StatusCode::BAD_REQUEST, &oauth_error_html(&err));
    }
    let (Some(state), Some(code)) = (state, code) else {
        return html(
            StatusCode::BAD_REQUEST,
            "<h1>Missing state or code</h1><p>This URL is reached via an OAuth IdP redirect — open it from <code>edgereplica oauth start github</code>.</p>",
        );
    };
    html(StatusCode::OK, &oauth_success_html(&state, &code))
}

fn oauth_success_html(state: &str, code: &str) -> String {
    let state = html_escape(state);
    let code = html_escape(code);
    format!(
        "<!doctype html><meta charset=utf-8><title>EdgeReplica OAuth</title>\
         <style>body{{font-family:system-ui;max-width:40rem;margin:3rem auto;padding:0 1rem}}\
         pre{{background:#f4f4f4;padding:1rem;border-radius:6px;overflow-x:auto}}</style>\
         <h1>OAuth login: copy this command</h1>\
         <p>Run the following in your terminal to finish signing in:</p>\
         <pre>edgereplica oauth complete --state {state} --code {code}</pre>\
         <p>The values above are single-use and short-lived; you can close this tab.</p>"
    )
}

fn oauth_error_html(err: &str) -> String {
    format!(
        "<!doctype html><meta charset=utf-8><title>EdgeReplica OAuth error</title>\
         <h1>OAuth provider returned an error</h1><pre>{}</pre>",
        html_escape(err)
    )
}

fn html_escape(s: &str) -> String {
    s.chars()
        .map(|c| match c {
            '<' => "&lt;".into(),
            '>' => "&gt;".into(),
            '&' => "&amp;".into(),
            '"' => "&quot;".into(),
            '\'' => "&#39;".into(),
            other => other.to_string(),
        })
        .collect()
}

/// `application/x-www-form-urlencoded` decoder for the limited set of
/// chars an IdP might return — `+` to space, `%xx` to byte. Bad escapes
/// fall through unchanged (the IdP's own validation will reject them).
fn url_decode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'+' => {
                out.push(' ');
                i += 1;
            }
            b'%' if i + 2 < bytes.len() => {
                let hex = std::str::from_utf8(&bytes[i + 1..i + 3]).unwrap_or("");
                if let Ok(byte) = u8::from_str_radix(hex, 16) {
                    out.push(byte as char);
                    i += 3;
                } else {
                    out.push('%');
                    i += 1;
                }
            }
            other => {
                out.push(other as char);
                i += 1;
            }
        }
    }
    out
}

fn html(status: StatusCode, body: &str) -> Response<ConnectRpcBody> {
    let bytes = Bytes::copy_from_slice(body.as_bytes());
    Response::builder()
        .status(status)
        .header(http::header::CONTENT_TYPE, "text/html; charset=utf-8")
        .body(ConnectRpcBody::Full(Full::new(bytes)))
        .expect("static html builder inputs are valid")
}

fn text(status: StatusCode, body: impl Into<Bytes>) -> Response<ConnectRpcBody> {
    Response::builder()
        .status(status)
        .header(http::header::CONTENT_TYPE, "text/plain; charset=utf-8")
        .body(ConnectRpcBody::Full(Full::new(body.into())))
        .expect("static response builder inputs are valid")
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures::executor::block_on;
    use http_body_util::BodyExt;

    fn request(method: Method, uri: &str) -> HttpRequest {
        http::Request::builder()
            .method(method)
            .uri(uri)
            .body(worker::Body::empty())
            .unwrap()
    }

    fn read_body(resp: Response<ConnectRpcBody>) -> (StatusCode, String) {
        let status = resp.status();
        let bytes = block_on(resp.into_body().collect()).unwrap().to_bytes();
        (status, String::from_utf8(bytes.to_vec()).unwrap())
    }

    #[test]
    fn healthz_ok() {
        let resp = try_handle(&request(Method::GET, "/healthz")).unwrap();
        let (status, body) = read_body(resp);
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body, "ok");
    }

    #[test]
    fn rpc_paths_defer() {
        assert!(
            try_handle(&request(
                Method::POST,
                "/edgereplica.admin.v1.AdminService/Login",
            ))
            .is_none()
        );
    }

    #[test]
    fn oauth_callback_renders_copy_command_on_state_and_code() {
        let resp = try_handle(&request(
            Method::GET,
            "/oauth/github/callback?state=abc&code=xyz",
        ))
        .unwrap();
        let (status, body) = read_body(resp);
        assert_eq!(status, StatusCode::OK);
        assert!(body.contains("edgereplica oauth complete"));
        assert!(body.contains("--state abc"));
        assert!(body.contains("--code xyz"));
    }

    #[test]
    fn oauth_callback_400s_without_state_and_code() {
        let resp = try_handle(&request(Method::GET, "/oauth/github/callback")).unwrap();
        let (status, _body) = read_body(resp);
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }

    #[test]
    fn oauth_callback_surfaces_provider_error() {
        let resp = try_handle(&request(
            Method::GET,
            "/oauth/github/callback?error=access_denied",
        ))
        .unwrap();
        let (status, body) = read_body(resp);
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(body.contains("access_denied"));
    }
}
