# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Common commands

```bash
# Host build + tests (default target)
cargo check --workspace
cargo test --workspace                            # 45 worker + 10 protocol = 55 tests
cargo test -p edgereplica-worker <test_name>      # single test, e.g. services::sync_fsm::tests::pull_into_empty_client_streams_every_server_page
cargo clippy --workspace --all-targets

# Wasm worker target — must pass before worker-build
cargo check -p edgereplica-worker --target wasm32-unknown-unknown

# Local worker dev loop
cd worker
wrangler d1 migrations apply edgereplica --local      # first time, or after migration changes
wrangler dev

# Integration tests (TypeScript, vitest + miniflare)
pnpm -C integration-tests test                    # rebuilds worker via worker-build, then runs
pnpm -C integration-tests test:no-build           # reuse last build
pnpm -C integration-tests run generate            # regenerate buf-es admin client (after .proto edits)

# Native CLI
cargo build --release -p edgereplica-client
./target/release/edgereplica --server http://localhost:8787 <subcmd>
```

## Architecture

Four-crate Cargo workspace (`Cargo.toml`):

- `protocol/` — every wire format. `protocol::admin` is `connectrpc-build` codegen from `proto/edgereplica/admin/v1/admin.proto`; `protocol::sync` is the hand-written WebSocket+MessagePack frame protocol (see "sync wire format" below). Both server and client decode against the exact same types.
- `worker/` — the server. `crate-type = ["cdylib", "rlib"]`: the cdylib is what `worker-build` packages for `wasm32-unknown-unknown`, the rlib keeps `cargo check --workspace` and host tests honest. Hosts the `AdminService` ConnectRPC handlers, the `EdgeReplica` DurableObject, all middleware, and the per-connection sync FSM. Owns its own `auth/`, `clock`, `domain/`, `error`, `repo`, `repo_mem` modules — these used to live in a `shared/` crate but had only one consumer.
- `client/` — native CLI binary `edgereplica`. Talks to the worker via ConnectRPC for admin and a raw WebSocket for sync.
- `bench/` (+ `bench/wasm-bench`) — page-hash micro-benchmarks comparing SHA-256, BLAKE2, BLAKE3 on host and in wasm. Standalone, no workspace deps.

### Sync routing topology

`/sync` is the only path served outside ConnectRPC. The flow is:

1. Client opens a WebSocket to `https://worker/sync` with `Authorization: Bearer <sync-macaroon>`.
2. Worker (`worker/src/sync_forward.rs`) verifies the macaroon, reads the `database` caveat, and looks up the per-database DurableObject via `EDGE_REPLICA.get_by_name(database_id)`. It then forwards the upgrade with `stub.fetch_with_request(...)`. Workers passes the WebSocket extension through across the round-trip, so no manual relay is needed.
3. The DurableObject (`worker/src/do_edge_replica.rs` → `worker/src/do_sync_ws.rs`) **re-verifies** the macaroon (defense in depth — never implicitly trust the worker), then runs `SyncFsm` over the WebSocket pair.

One DO instance per `(org_id, database_id)`, addressed by name. Each DO owns its own SQLite-backed `SqlStorage` (the `pages` table).

### Sync wire format (`protocol::sync`)

Each WebSocket binary frame = `[u8 protocol_version] ++ msgpack(SyncMessage)`. The version byte lets peers reject incompatible frames before paying decode cost. `SyncMessage` is a `#[serde(tag = "kind", content = "data", rename_all = "snake_case")]` enum so the encoded body is debugger-readable. Page hashes are 32-byte BLAKE3 digests carried as `bytes::Bytes` (msgpack `bin` format).

The FSM (`worker/src/services/sync_fsm.rs`) is target-portable and operates against a `SyncStorage` trait. Two impls: `SqlSyncStorage` (wasm32, real DO) and `InMemorySyncStorage` (host tests). The FSM emits each outbound frame via a callback that ships immediately, so a multi-GB pull never buffers the whole DB in worker RAM.

### Repo trait + dual impl

`worker/src/repo.rs` is the storage trait used by AdminService. Two impls swapped via `cfg(target_arch = "wasm32")`:

- `D1Repo` (`worker/src/repo_d1.rs`, wasm32) — D1-backed, async with workarounds for `worker-rs`'s `!Send` futures (uses `worker::send::IntoSendFuture` to satisfy `+ Send` on the trait's method futures).
- `InMemoryRepo` (`worker/src/repo_mem.rs`, default target) — host-side fake used by handler tests.

Multi-row signup goes through `D1Database::batch` (atomic). The schema lives in `worker/migrations/0001_init.sql`; D1 runs `wrangler d1 migrations apply` in prod, but `AUTO_MIGRATE=true` triggers idempotent CREATE-IF-NOT-EXISTS on first request via `D1Repo::ensure_schema()`.

### Auth model

Macaroons everywhere (`worker/src/auth/`). Two purposes:

- **Session** macaroon: `purpose=session, user, email, org, role, exp`. Issued by `mint_session` after signup/login/OAuth. Verified by the optional `SessionAuthLayer` Tower middleware. It's a decoder, not a gate: on success it inserts a `SessionContext` into request extensions; on failure it silently drops through. Public RPCs (Whoami, Signup, Login, OAuth start/complete) work fine without one; gated handlers call `require_session(&ctx)?` themselves.
- **Sync** macaroon: `purpose=sync, user, org, database, direction=push|pull, exp`. Issued by `AdminService::IssueSyncToken`. Verified at the worker edge AND inside the DO.

Verification is pure (no DB read) — the macaroon's caveats carry everything the handler needs.

### Clock abstraction

`worker/src/clock.rs` defines `Clock` + `SharedClock = Arc<dyn Clock>`. Three impls, cfg-gated:

- `SystemClock` — host only (`std::time::SystemTime` panics on `wasm32-unknown-unknown`).
- `WorkerDateClock` — wasm32 only, backed by `worker::Date::now()`.
- `FixedClock` — always available, for tests.

`worker/src/lib.rs::build_state` selects the right one per target.

## Non-obvious gotchas

- **`SqlStorage` BLOB row decode**: `serde-wasm-bindgen` round-trips a SQLite BLOB through `serialize_bytes`. `Vec<u8>`'s default `Deserialize` only implements `visit_seq` and rejects this with `invalid type: byte array, expected a sequence`. **Always use `bytes::Bytes` (with the `serde` feature) for BLOB fields in `Deserialize` row structs in `worker/src/services/sync_storage.rs::sql_storage` and `worker/src/repo_d1.rs`.** Don't "simplify" them to `Vec<u8>`.
- **WebSocket binary frame quirk**: workerd's WebSocket defaults to `Blob` for binary frames, which makes `worker-rs`'s `MessageEvent::bytes()` silently return an empty `Vec` (`Uint8Array::new(&blob)` produces `[]`). The DO sets `set_binary_type(BinaryType::Arraybuffer)` on the server end of the pair before `accept()` — don't remove that.
- **`Fetch::send` !Send**: outbound `worker::Fetch` futures capture `JsFuture` (`Rc<RefCell<_>>`) and are `!Send`. ConnectRPC's trait wants `+ Send`. Wrap with `worker::send::SendFuture` (Workers is single-threaded, so this is sound — `D1Repo` uses the same trick).
- **D1 timestamps**: `D1Type::Integer` is i32-only. All `i64` ms-since-epoch values go through `D1Type::Real(x as f64)` (JS numbers carry 53 bits of integer precision, lossless for any plausible timestamp). See `ms()` helper in `worker/src/repo_d1.rs`.
- **BLAKE3 not SHA-256**: the wasm worker has no SHA-256 hardware acceleration. `bench/wasm-bench` measured BLAKE3 at ~5x SHA-256 throughput on wasm. Don't switch the page-hash without re-running that bench.
- **`getrandom` `js` feature**: workspace pin is `getrandom = { version = "0.2", features = ["js"] }`. This wires `getrandom` to `crypto.getRandomValues` on wasm32 (used by `uuid::v4` and argon2 password salts). Don't drop the feature.
- **`connectrpc` features**: workspace default has `default-features = false, features = ["gzip"]`. The `zstd` and `streaming` features pull in C bindings that don't build on wasm32. The client crate adds `client` and `client-tls` features; don't propagate those to worker or protocol.
- **`#[allow(warnings, unused, clippy::all)]` scope**: this attribute on `protocol/src/lib.rs` only applies to the inline `mod generated { include!(...) }` block — hand-written `pub mod sync;` gets normal lints, by design.
- **Per-DO migration latch**: `EdgeReplica::schema_ready` is on the struct (not a `static`). One isolate hosts many DO instances each with its own SQLite DB, so a `static` would let the first DO trick every other DO into skipping its own migration. Don't move it back to a static.
- **`SyncComplete` single-emission gate**: the FSM has multiple paths that can satisfy the emit predicate (last `PageData`, `Complete`, peer close). They all route through `maybe_emit_complete`, which short-circuits on `emitted_complete`. Don't bypass it.
