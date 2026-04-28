//! Worker-side dispatch for `SyncService` calls.
//!
//! The worker is a thin auth/routing edge for sync: it verifies the sync
//! macaroon, derives the DurableObject name from the `database` caveat,
//! and forwards the request through `stub.fetch` so the bidi body streams
//! straight from the client to the DO. The DO re-verifies the same token
//! before dispatching to the ConnectRPC handler — see
//! [`crate::middleware::do_sync_auth`].

use std::sync::Arc;

use edgereplica_shared::{Keyring, SharedClock, SyncContext, verify_sync};
use http::{HeaderValue, Response, StatusCode, header::AUTHORIZATION};
use worker::{Body, Env, HttpRequest, Result, request_to_wasm, response_from_wasm};

use crate::middleware::extract_bearer;

/// Path prefix that identifies a `SyncService` ConnectRPC call. Anything
/// under this prefix is forwarded to the per-database DO.
pub const SYNC_PATH_PREFIX: &str = "/edgereplica.sync.v1.SyncService/";

/// Binding name for the `EdgeReplica` DurableObject namespace (matches
/// `wrangler.toml`).
const DO_BINDING: &str = "EDGE_REPLICA";

/// Forward a `SyncService` request to the appropriate DurableObject.
///
/// Auth: verifies the bearer macaroon and reads the `database` caveat. A
/// missing or invalid token short-circuits with 401 here; the DO will
/// independently re-verify on success. The URL path is *not* checked
/// against the caveat's `database` — the caveat is the source of truth
/// for which DO handles the call.
pub async fn forward(
    req: HttpRequest,
    env: &Env,
    keyring: &Arc<Keyring>,
    clock: &SharedClock,
) -> Result<Response<Body>> {
    let sync_ctx = match verify_request(&req, keyring, clock) {
        Ok(ctx) => ctx,
        Err(resp) => return Ok(resp),
    };

    let namespace = env.durable_object(DO_BINDING)?;
    let stub = namespace.get_by_name(sync_ctx.database.as_str())?;

    let web_req =
        request_to_wasm(req).map_err(|e| worker::Error::RustError(format!("to_wasm req: {e}")))?;
    let worker_req = worker::Request::from(web_req);

    let do_resp = stub.fetch_with_request(worker_req).await?;
    let web_resp: worker::web_sys::Response = do_resp.into();
    response_from_wasm(web_resp)
        .map_err(|e| worker::Error::RustError(format!("from_wasm resp: {e}")))
}

fn verify_request(
    req: &HttpRequest,
    keyring: &Arc<Keyring>,
    clock: &SharedClock,
) -> std::result::Result<SyncContext, Response<Body>> {
    let token = req
        .headers()
        .get(AUTHORIZATION)
        .and_then(|h| h.to_str().ok())
        .and_then(extract_bearer)
        .ok_or_else(|| unauthorized("missing bearer token"))?;

    verify_sync(keyring, clock.now_unix_seconds(), token)
        .map_err(|e| unauthorized(&format!("invalid sync token: {e}")))
}

fn unauthorized(message: &str) -> Response<Body> {
    let bytes: Vec<u8> = message.as_bytes().to_vec();
    let stream = futures::stream::once(async move { Ok::<_, std::io::Error>(bytes) });
    let body = Body::from_stream(stream).expect("static stream is always valid");
    let mut resp = Response::new(body);
    *resp.status_mut() = StatusCode::UNAUTHORIZED;
    resp.headers_mut().insert(
        http::header::CONTENT_TYPE,
        HeaderValue::from_static("text/plain; charset=utf-8"),
    );
    resp
}
