# EdgeReplica

Per-page SQLite sync between a CLI client and a Cloudflare Worker +
DurableObject backend, transported over ConnectRPC bidi-streaming and
authenticated with macaroons.

## Workspace layout

```
proto/      .proto sources (Admin + Sync services)
protocol/   generated Rust types (buffa + connectrpc-build)
shared/     domain types, Repo trait, in-mem repo, macaroon helpers
worker/     Cloudflare Worker (cdylib) — AdminService + EdgeReplica DO
client/     native CLI (`edgereplica`)
```

## Architecture

- **AdminService** runs in the Worker (talks D1): signup, login, OAuth,
  whoami, database CRUD, sync-token issuance.
- **SyncService** runs **inside the EdgeReplica DurableObject** so the
  bidi FSM lives next to the `SqlStorage` it reads/writes. The Worker
  is a thin auth/routing edge: it verifies the sync macaroon, looks up
  the per-`database_id` DO, and forwards the bidi body via `stub.fetch`.
- **Tower middleware** (`RequestIdLayer`, `SessionAuthLayer`,
  `DoSyncAuthLayer`) wraps both stacks. Auth layers are decoders, not
  gates — handlers call `require_session(ctx)?` themselves.
- **Macaroons** carry `purpose`, `user`, `org`, `exp`, plus
  session-specific (`email`, `role`) or sync-specific (`database`,
  `direction`) caveats. Verification is pure (no DB read).
- **Storage** is split: D1 holds users/orgs/databases (worker side),
  `SqlStorage` holds pages (DO side). The FSM uses a `SyncStorage`
  trait so it's host-testable against an in-memory fake.

## Quickstart (local dev)

```bash
# 1. Worker — terminal A
cd worker
wrangler d1 migrations apply edgereplica --local
wrangler dev

# 2. Client — terminal B
cargo build --release -p edgereplica-client
alias edgereplica='./target/release/edgereplica --server http://localhost:8787'

# Signup → session is cached in ~/.config/edgereplica/config.toml
EDGEREPLICA_PASSWORD='hunter2hunter2' \
  edgereplica signup ada@example.com

edgereplica whoami
edgereplica db create main
edgereplica db list
DB_ID=$(edgereplica db list | awk '/main/ {print $1}')

# 3. Sync push
TOKEN=$(edgereplica db token "$DB_ID" --direction push)
edgereplica sync push --db ./local.sqlite --token "$TOKEN"

# 4. Sync pull on a fresh file
TOKEN=$(edgereplica db token "$DB_ID" --direction pull)
edgereplica sync pull --db ./pulled.sqlite --token "$TOKEN"

sqlite3 ./local.sqlite '.tables'
sqlite3 ./pulled.sqlite '.tables'
```

## OAuth (GitHub, optional)

OAuth is fully gated by env presence: omit the secrets and the RPCs return
`Unimplemented`. To enable GitHub login on a deployment:

```toml
# wrangler.toml [vars]
GITHUB_CLIENT_ID = "Iv1...."
GITHUB_CLIENT_SECRET = "....."   # use `wrangler secret put` in prod
OAUTH_REDIRECT_BASE = "https://edgereplica.example.workers.dev"
```

CLI flow:

```bash
edgereplica oauth start github
# → opens an authorize URL. Visit it, click Authorize.
# → GitHub redirects to /oauth/github/callback?state=...&code=...
# → callback page shows: edgereplica oauth complete --state ... --code ...
edgereplica oauth complete --state ... --code ...
```

Google works the same way; add `GOOGLE_CLIENT_ID` / `GOOGLE_CLIENT_SECRET`
and a parallel `services/oauth.rs::complete_google` (the GitHub helper is
the canonical pattern).

## Required env vars (worker)

| var                              | purpose                                                                  |
| -------------------------------- | ------------------------------------------------------------------------ |
| `SESSION_KEY`                    | Macaroon root, base64(32 bytes). Generate with `openssl rand -base64 32`. |
| `SESSION_TTL_SECONDS`            | Default 86400. Session token lifetime.                                   |
| `SYNC_TOKEN_TTL_SECONDS`         | Default 3600. Sync-token lifetime requested by client.                   |
| `MAX_SYNC_TOKEN_TTL_SECONDS`     | Default 86400. Server-side cap on sync-token TTL.                        |
| `OAUTH_STATE_TTL_SECONDS`        | Default 600. CSRF state expiry.                                          |
| `OAUTH_REDIRECT_BASE`            | e.g. `https://your-worker.workers.dev`. Required if any OAuth provider is configured. |
| `GITHUB_CLIENT_ID/SECRET`        | If set, enables `oauth start github`.                                    |
| `GOOGLE_CLIENT_ID/SECRET`        | If set, enables `oauth start google` (handler not yet wired).            |
| `AUTO_MIGRATE`                   | "true" to run D1 migrations on first request. Off in prod.               |

In `wrangler dev`, leave `SESSION_KEY` empty and the worker logs a
warning + uses a deterministic dev key (`Keyring::dev_default`).

## Testing

```bash
cargo test --workspace                              # 21 worker + 20 shared = 41 tests
cargo check -p edgereplica-worker --target wasm32-unknown-unknown
cargo clippy --workspace --all-targets
```

Worker tests run the AdminService and SyncService FSM against an
in-memory `Repo` and `SyncStorage`. The DO bidi handler is the same
code on host and wasm — only the `SyncStorage` impl differs.
