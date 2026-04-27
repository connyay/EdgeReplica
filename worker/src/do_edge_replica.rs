//! `EdgeReplica` DurableObject. One instance per (org_id, database_id),
//! addressed by the worker via `EDGE_REPLICA.id_from_name(...)`.
//!
//! The DO **hosts** the ConnectRPC `SyncService` directly — the worker
//! just verifies the macaroon at the edge and forwards via `stub.fetch`.
//! Hosting here keeps the FSM next to the `SqlStorage` it reads/writes
//! and avoids re-encoding envelopes between worker and DO.
//!
//! The DO trait's `fetch` signature is fixed to `worker::Request ->
//! worker::Response`, so we hop into and out of `http::Request<worker::Body>`
//! (via worker's `http` feature) to drive the tower stack.

#![cfg(target_arch = "wasm32")]

use std::sync::Arc;

use connectrpc::{ConnectRpcService, Router as RpcRouter};
use edgereplica_protocol::sync::v1::SyncServiceExt;
use edgereplica_shared::SharedClock;
use tower::{Layer, Service};
// `worker::wasm_bindgen` re-exports the `wasm-bindgen` crate's macro under
// the `wasm_bindgen` name, which the `#[durable_object]` macro expansion
// invokes unqualified. Bringing it into scope makes that resolve.
use worker::wasm_bindgen;
use worker::{
    DurableObject, Env, Request, Response, Result, SqlStorage, State, durable_object,
    request_from_wasm, response_to_wasm, web_sys,
};

use crate::clock_worker::WorkerDateClock;
use crate::do_migrations;
use crate::load_keyring;
use crate::middleware::{DoSyncAuthLayer, RequestIdLayer};
use crate::services::SyncServer;

#[durable_object]
pub struct EdgeReplica {
    sql: SqlStorage,
    clock: SharedClock,
    auth: DoSyncAuthLayer,
    request_id: RequestIdLayer,
    service: ConnectRpcService<RpcRouter>,
}

impl DurableObject for EdgeReplica {
    fn new(state: State, env: Env) -> Self {
        let sql = state.storage().sql();
        let keyring = Arc::new(load_keyring(&env));
        let clock: SharedClock = Arc::new(WorkerDateClock::new());
        let router = Arc::new(SyncServer::new()).register(RpcRouter::new());
        let service = ConnectRpcService::new(router);
        let auth = DoSyncAuthLayer::new(Arc::clone(&keyring), Arc::clone(&clock));
        let request_id = RequestIdLayer::new();
        Self {
            sql,
            clock,
            auth,
            request_id,
            service,
        }
    }

    async fn fetch(&self, req: Request) -> Result<Response> {
        ensure_schema_once(&self.sql, self.clock.now_ms())?;

        let web_req: web_sys::Request = (&req).try_into()?;
        let http_req = request_from_wasm(web_req)
            .map_err(|e| worker::Error::RustError(format!("from_wasm req: {e}")))?;

        let mut svc = self.request_id.layer(self.auth.layer(self.service.clone()));
        let http_resp = svc
            .call(http_req)
            .await
            .expect("ConnectRpcService is infallible by design");

        let web_resp = response_to_wasm(http_resp)
            .map_err(|e| worker::Error::RustError(format!("to_wasm resp: {e}")))?;
        Ok(Response::from(web_resp))
    }
}

fn ensure_schema_once(sql: &SqlStorage, now_ms: i64) -> Result<()> {
    use std::sync::atomic::{AtomicBool, Ordering};
    static READY: AtomicBool = AtomicBool::new(false);
    if READY.load(Ordering::Relaxed) {
        return Ok(());
    }
    do_migrations::ensure_schema(sql, now_ms)
        .map_err(|e| worker::Error::RustError(format!("schema: {e}")))?;
    READY.store(true, Ordering::Relaxed);
    Ok(())
}
