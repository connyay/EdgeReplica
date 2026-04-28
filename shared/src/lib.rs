//! Host-portable core for EdgeReplica.
//!
//! Everything in this crate compiles on both the host (for `cargo test`) and
//! `wasm32-unknown-unknown` (for the worker). It contains:
//!
//! - `domain` — typed ids, entities, role/direction enums.
//! - `auth` — `Keyring`, mint/verify session + sync macaroons (pure, no DB),
//!   argon2 password hashing, the `SessionContext` / `SyncContext` types
//!   placed into request extensions by the worker's auth middleware.
//! - `repo` + `repo_mem` — the storage trait and an in-memory impl used by
//!   handler tests.
//! - `clock` — `Clock` trait + a host `SystemClock`. The worker supplies a
//!   `worker::Date`-backed clock for wasm32; this crate stays free of
//!   wasm-only dependencies.

pub mod auth;
pub mod clock;
pub mod domain;
pub mod error;
pub mod repo;
pub mod repo_mem;
pub mod sync_protocol;

pub use auth::password::AllowAllPolicy;
pub use auth::{
    Keyring, KeyringError, MintSessionInput, MintSyncInput, PasswordError, PasswordPolicy,
    SessionContext, SyncContext, TokenError, hash_new_password, mint_session, mint_sync,
    verify_password, verify_session, verify_sync,
};
pub use clock::{Clock, SharedClock};
pub use domain::{
    Database, DatabaseId, Direction, Identity, IdentityId, IdentityProvider, OAuthState, OrgId,
    OrgMembership, Organization, Role, TokenPurpose, User, UserId,
};
pub use error::{StoreError, StoreResult};
pub use repo::{NewOAuthUser, NewPasswordUser, Repo};
pub use repo_mem::InMemoryRepo;
pub use sync_protocol::{
    FrameError, PROTOCOL_VERSION as SYNC_PROTOCOL_VERSION, PageDataEntry, SyncMessage,
    decode_frame, encode_frame, page_hash,
};
