//! `EdgeReplica` DurableObject. One instance per (org_id, database_id),
//! addressed by the worker via `EDGE_REPLICA.id_from_name(...)`.
//!
//! The DO terminates the sync WebSocket directly — the worker verifies
//! the macaroon at the public edge and forwards the upgrade via
//! `stub.fetch`, then this DO re-verifies and runs the FSM in
//! [`crate::do_sync_ws`].
//!
//! AdminService is not hosted here; it lives in the worker (see
//! `crate::services::AdminServer` wired in `lib.rs`). The DO accepts
//! only WebSocket upgrade requests; anything else returns 400.

#![cfg(target_arch = "wasm32")]

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use edgereplica_shared::{Keyring, SharedClock};
// `worker::wasm_bindgen` re-exports the `wasm-bindgen` crate's macro under
// the `wasm_bindgen` name, which the `#[durable_object]` macro expansion
// invokes unqualified. Bringing it into scope makes that resolve.
use worker::wasm_bindgen;
use worker::{DurableObject, Env, Request, Response, Result, SqlStorage, State, durable_object};

use crate::clock_worker::WorkerDateClock;
use crate::do_migrations;
use crate::do_sync_ws;
use crate::load_keyring;

#[durable_object]
pub struct EdgeReplica {
    sql: SqlStorage,
    clock: SharedClock,
    keyring: Arc<Keyring>,
    /// Per-DO migration latch. Must be on the struct (not a `static`)
    /// because a single wasm isolate hosts many DO instances and each
    /// has its own SQLite database. A `static` would let the first DO
    /// to migrate trick every other DO in the isolate into skipping
    /// its own migration, leaving them with no `pages` table.
    schema_ready: AtomicBool,
}

impl DurableObject for EdgeReplica {
    fn new(state: State, env: Env) -> Self {
        let sql = state.storage().sql();
        let keyring = Arc::new(load_keyring(&env));
        let clock: SharedClock = Arc::new(WorkerDateClock::new());
        Self {
            sql,
            clock,
            keyring,
            schema_ready: AtomicBool::new(false),
        }
    }

    async fn fetch(&self, req: Request) -> Result<Response> {
        self.ensure_schema()?;

        if !is_websocket_upgrade(&req) {
            return Response::error(
                "EdgeReplica DO accepts only WebSocket upgrades".to_string(),
                400,
            );
        }

        do_sync_ws::handle_upgrade(
            self.sql.clone(),
            Arc::clone(&self.clock),
            Arc::clone(&self.keyring),
            &req,
        )
    }
}

impl EdgeReplica {
    fn ensure_schema(&self) -> Result<()> {
        if self.schema_ready.load(Ordering::Relaxed) {
            return Ok(());
        }
        do_migrations::ensure_schema(&self.sql, self.clock.now_ms())
            .map_err(|e| worker::Error::RustError(format!("schema: {e}")))?;
        self.schema_ready.store(true, Ordering::Relaxed);
        Ok(())
    }
}

fn is_websocket_upgrade(req: &Request) -> bool {
    req.headers()
        .get("Upgrade")
        .ok()
        .flatten()
        .map(|s| s.eq_ignore_ascii_case("websocket"))
        .unwrap_or(false)
}
