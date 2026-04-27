//! Shared per-request application state. Each service holds an
//! `Arc<AppState<R>>` and reads through it.

use std::sync::Arc;

use edgereplica_shared::{Keyring, Repo, SharedClock};

/// Tunables sourced from environment vars (or defaults).
#[derive(Clone, Debug)]
pub struct Config {
    pub session_ttl_seconds: i64,
    pub sync_token_ttl_seconds: i64,
    pub max_sync_token_ttl_seconds: i64,
    pub oauth_state_ttl_seconds: i64,
    pub oauth_redirect_base: String,
    pub github_client_id: Option<String>,
    pub github_client_secret: Option<String>,
    pub google_client_id: Option<String>,
    pub google_client_secret: Option<String>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            session_ttl_seconds: 86_400,
            sync_token_ttl_seconds: 3600,
            max_sync_token_ttl_seconds: 24 * 3600,
            oauth_state_ttl_seconds: 10 * 60,
            oauth_redirect_base: String::new(),
            github_client_id: None,
            github_client_secret: None,
            google_client_id: None,
            google_client_secret: None,
        }
    }
}

pub struct AppState<R: Repo> {
    pub repo: R,
    pub keyring: Arc<Keyring>,
    pub clock: SharedClock,
    pub config: Config,
}

pub type SharedState<R> = Arc<AppState<R>>;
