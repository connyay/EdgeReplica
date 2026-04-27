//! EdgeReplica worker entrypoint. AdminService runs in the worker (talks D1).

// `connectrpc::ConnectError` is ~248 bytes, which trips the
// `result_large_err` lint on every handler. Boxing isn't worth it: the
// error path is cold and the type is fixed by the connectrpc trait.
#![allow(clippy::result_large_err)]

use std::sync::Arc;
use std::sync::LazyLock;

use connectrpc::{ConnectRpcBody, ConnectRpcService, Router as RpcRouter};
use edgereplica_protocol::admin::v1::AdminServiceExt;
use edgereplica_shared::{Keyring, SharedClock};
use tower::{Layer, Service};
use worker::{Context, Env, HttpRequest, event};

pub mod clock_worker;
pub mod middleware;
pub mod repo_d1;
pub mod routes;
pub mod services;
pub mod state;

use crate::middleware::{RequestIdLayer, SessionAuthLayer};
use crate::services::AdminServer;
use crate::state::{AppState, Config, SharedState};

#[event(fetch, respond_with_errors)]
async fn fetch(
    req: HttpRequest,
    env: Env,
    _ctx: Context,
) -> worker::Result<http::Response<ConnectRpcBody>> {
    if let Some(resp) = routes::try_handle(&req) {
        return Ok(resp);
    }

    // Hoist the layer out of the per-request path so its monotonic counter
    // persists across requests in the same isolate.
    static REQUEST_ID_LAYER: LazyLock<RequestIdLayer> = LazyLock::new(RequestIdLayer::new);

    let state = build_state(&env).await?;
    let auth_layer = SessionAuthLayer::new(Arc::clone(&state.keyring), Arc::clone(&state.clock));

    let router = RpcRouter::new();
    let router = Arc::new(AdminServer::new(Arc::clone(&state))).register(router);

    let mut svc = REQUEST_ID_LAYER.layer(auth_layer.layer(ConnectRpcService::new(router)));
    let response: http::Response<ConnectRpcBody> = svc
        .call(req)
        .await
        .expect("ConnectRpcService is infallible by design");
    Ok(response)
}

// =================== build_state — wasm path ===================

#[cfg(target_arch = "wasm32")]
async fn build_state(env: &Env) -> worker::Result<SharedState<repo_d1::D1Repo>> {
    use std::sync::atomic::{AtomicBool, Ordering};

    static SCHEMA_READY: AtomicBool = AtomicBool::new(false);

    let db = env.d1("DB")?;
    let repo = repo_d1::D1Repo::new(db);
    if auto_migrate(env) && !SCHEMA_READY.load(Ordering::Relaxed) {
        repo.ensure_schema()
            .await
            .map_err(|e| worker::Error::RustError(format!("schema: {e}")))?;
        SCHEMA_READY.store(true, Ordering::Relaxed);
    }

    let keyring = Arc::new(load_keyring(env));
    let clock: SharedClock = Arc::new(clock_worker::WorkerDateClock::new());
    let config = load_config(env);

    Ok(Arc::new(AppState {
        repo,
        keyring,
        clock,
        config,
    }))
}

// =================== build_state — native (host check + tests) ===================

#[cfg(not(target_arch = "wasm32"))]
async fn build_state(_env: &Env) -> worker::Result<SharedState<edgereplica_shared::InMemoryRepo>> {
    let keyring = Arc::new(Keyring::dev_default());
    let clock: SharedClock = Arc::new(edgereplica_shared::clock::SystemClock::new());
    Ok(Arc::new(AppState {
        repo: edgereplica_shared::InMemoryRepo::new(),
        keyring,
        clock,
        config: Config::default(),
    }))
}

#[cfg(target_arch = "wasm32")]
fn auto_migrate(env: &Env) -> bool {
    env.var("AUTO_MIGRATE")
        .ok()
        .map(|v| matches!(v.to_string().as_str(), "true" | "1" | "yes"))
        .unwrap_or(false)
}

#[cfg(target_arch = "wasm32")]
fn load_keyring(env: &Env) -> Keyring {
    let raw = env
        .var("SESSION_KEY")
        .ok()
        .map(|v| v.to_string())
        .unwrap_or_default();
    if raw.trim().is_empty() {
        // Don't fail the worker boot — wrangler dev should run without any
        // env setup. Production should ALWAYS set SESSION_KEY; the dev key
        // is deterministic and fully recoverable from a leaked binary.
        worker::console_error!("SESSION_KEY unset; using deterministic dev key");
        return Keyring::dev_default();
    }
    match Keyring::from_base64(&raw) {
        Ok(k) => k,
        Err(e) => {
            worker::console_error!("invalid SESSION_KEY ({e}); using dev fallback");
            Keyring::dev_default()
        }
    }
}

#[cfg(target_arch = "wasm32")]
fn load_config(env: &Env) -> Config {
    let read_secs = |k: &str, default: i64| -> i64 {
        env.var(k)
            .ok()
            .and_then(|v| v.to_string().parse::<i64>().ok())
            .unwrap_or(default)
    };
    let read_str = |k: &str| -> Option<String> {
        env.var(k)
            .ok()
            .map(|v| v.to_string())
            .filter(|s| !s.trim().is_empty())
    };

    Config {
        session_ttl_seconds: read_secs("SESSION_TTL_SECONDS", 86_400),
        sync_token_ttl_seconds: read_secs("SYNC_TOKEN_TTL_SECONDS", 3_600),
        max_sync_token_ttl_seconds: read_secs("MAX_SYNC_TOKEN_TTL_SECONDS", 24 * 3_600),
        oauth_state_ttl_seconds: read_secs("OAUTH_STATE_TTL_SECONDS", 10 * 60),
        oauth_redirect_base: read_str("OAUTH_REDIRECT_BASE").unwrap_or_default(),
        github_client_id: read_str("GITHUB_CLIENT_ID"),
        github_client_secret: read_str("GITHUB_CLIENT_SECRET"),
        google_client_id: read_str("GOOGLE_CLIENT_ID"),
        google_client_secret: read_str("GOOGLE_CLIENT_SECRET"),
    }
}
