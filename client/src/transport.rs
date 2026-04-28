//! ConnectRPC client transport setup and authed-client helpers.

use anyhow::{Context, Result, anyhow};
use connectrpc::client::{CallOptions, ClientConfig, HttpClient};
use edgereplica_protocol::admin::v1::AdminServiceClient;
use edgereplica_protocol::sync::v1::SyncServiceClient;
use http::{HeaderValue, Uri};

use crate::config::Config;

pub fn admin_client(server: &str) -> Result<AdminServiceClient<HttpClient>> {
    let (http, config) = build(server)?;
    Ok(AdminServiceClient::new(http, config))
}

pub fn sync_client(server: &str) -> Result<SyncServiceClient<HttpClient>> {
    let (http, config) = build(server)?;
    Ok(SyncServiceClient::new(http, config))
}

/// Build an admin client authed with the session token from `config`.
pub fn authed_admin_client(
    config: &Config,
) -> Result<(AdminServiceClient<HttpClient>, CallOptions)> {
    let token = config.require_session()?;
    Ok((admin_client(&config.server)?, auth_options(token)?))
}

/// Build a sync client authed with an explicit sync token (issued by
/// `db token`), since sync uses the sync token rather than the session.
pub fn authed_sync_client(
    config: &Config,
    token: &str,
) -> Result<(SyncServiceClient<HttpClient>, CallOptions)> {
    Ok((sync_client(&config.server)?, auth_options(token)?))
}

fn auth_options(token: &str) -> Result<CallOptions> {
    CallOptions::default()
        .try_with_header(http::header::AUTHORIZATION, bearer(token)?)
        .context("attach auth header")
}

pub fn bearer(token: &str) -> Result<HeaderValue> {
    HeaderValue::from_str(&format!("Bearer {token}"))
        .context("session token contains invalid header bytes")
}

fn build(server: &str) -> Result<(HttpClient, ClientConfig)> {
    let uri: Uri = server
        .parse()
        .with_context(|| format!("invalid server url: {server}"))?;
    let scheme = uri.scheme_str().unwrap_or("");
    let http = match scheme {
        "http" => HttpClient::plaintext(),
        "https" => HttpClient::with_tls(default_tls_config()?),
        other => {
            return Err(anyhow!(
                "unsupported scheme `{other}` (expected http or https)"
            ));
        }
    };
    Ok((http, ClientConfig::new(uri)))
}

/// rustls config that trusts the system trust roots. Pinning a CA bundle
/// would force CLI users to wrangle PKCS#7, which they didn't sign up for.
fn default_tls_config() -> Result<std::sync::Arc<rustls::ClientConfig>> {
    let roots = load_native_roots()?;
    let cfg = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    Ok(std::sync::Arc::new(cfg))
}

fn load_native_roots() -> Result<rustls::RootCertStore> {
    let mut store = rustls::RootCertStore::empty();
    let result = rustls_native_certs::load_native_certs();
    if !result.errors.is_empty() {
        eprintln!(
            "warning: failed to load some native CA certs: {:?}",
            result.errors
        );
    }
    for cert in result.certs {
        store.add(cert).ok();
    }
    if store.is_empty() {
        return Err(anyhow!("no TLS roots available from the OS trust store"));
    }
    Ok(store)
}
