//! Worker-side WebSocket upgrade forwarder for sync.
//!
//! The worker is a thin auth/routing edge for sync: it verifies the
//! sync macaroon, derives the DurableObject name from the signed
//! `database` claim, and forwards the upgrade request through `stub.fetch`. The
//! DO terminates the WebSocket and runs the FSM (see
//! [`crate::do_sync_ws`]). A missing or invalid token short-circuits
//! with 401 here so the upgrade never reaches the DO; the DO
//! independently re-verifies on the inside as defense in depth.

use std::sync::Arc;

use crate::auth::{Keyring, SyncContext, verify_sync};
use crate::clock::SharedClock;
use http::{HeaderValue, Response, StatusCode, header::AUTHORIZATION};
use worker::{Body, Env, HttpRequest, Result, request_to_wasm, response_from_wasm};

use crate::middleware::extract_bearer;

/// Single fixed path the sync WebSocket lives at. The macaroon's signed
/// `database` claim picks the DO; the URL path doesn't carry routing
/// information beyond identifying this as a sync call.
pub const SYNC_PATH: &str = "/sync";

/// Binding name for the `EdgeReplica` DurableObject namespace (matches
/// `wrangler.toml`).
const DO_BINDING: &str = "EDGE_REPLICA";

/// Forward a sync WebSocket upgrade to the appropriate DurableObject.
///
/// `stub.fetch_with_request` propagates the upgrade headers and returns
/// a 101 response with the DO's `WebSocket` extension still attached.
/// `response_from_wasm` preserves that extension on the round-trip back
/// to the client.
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
