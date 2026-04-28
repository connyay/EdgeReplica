//! Wire formats for EdgeReplica.
//!
//! - [`admin`] — ConnectRPC service `edgereplica.admin.v1.AdminService`,
//!   generated from `proto/edgereplica/admin/v1/admin.proto` via
//!   `connectrpc-build` in `build.rs`.
//! - [`sync`] — hand-written WebSocket+MessagePack frame protocol used by
//!   the DurableObject's sync handler and the CLI's `push`/`pull` commands.

// `connectrpc-build` emits `super::`-relative paths that resolve against
// this module name. Wrap the include in a private module so the
// generated tree gets the broad allow, then re-export the inner namespace
// at the crate root for ergonomic access:
//
//   edgereplica_protocol::admin::v1::AdminService
#[allow(warnings, unused, clippy::all)]
mod generated {
    include!(concat!(env!("OUT_DIR"), "/_connectrpc.rs"));
}

pub use generated::edgereplica::admin;

pub mod sync;
