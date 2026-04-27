//! Sync macaroon auth middleware that runs **inside the DurableObject**.
//!
//! The worker's `SyncAuthLayer` (phase 6) verifies the same macaroon
//! before forwarding the request to the DO via `stub.fetch`; re-verifying
//! here costs microseconds and gives defense in depth — the DO doesn't
//! implicitly trust the worker's edge.
//!
//! Like [`super::session_auth::SessionAuthLayer`] this is a decoder, not a
//! gate: handlers call `require_sync(ctx)?` to surface
//! `Code::Unauthenticated` themselves.

use std::sync::Arc;
use std::task::{Context, Poll};

use connectrpc::ConnectError;
use edgereplica_shared::{Keyring, SharedClock, SyncContext, verify_sync};
use http::header::AUTHORIZATION;
use tower::{Layer, Service};

use super::extract_bearer;

#[derive(Clone)]
pub struct DoSyncAuthLayer {
    keyring: Arc<Keyring>,
    clock: SharedClock,
}

impl DoSyncAuthLayer {
    pub fn new(keyring: Arc<Keyring>, clock: SharedClock) -> Self {
        Self { keyring, clock }
    }
}

impl<S> Layer<S> for DoSyncAuthLayer {
    type Service = DoSyncAuthService<S>;
    fn layer(&self, inner: S) -> Self::Service {
        DoSyncAuthService {
            inner,
            keyring: Arc::clone(&self.keyring),
            clock: Arc::clone(&self.clock),
        }
    }
}

#[derive(Clone)]
pub struct DoSyncAuthService<S> {
    inner: S,
    keyring: Arc<Keyring>,
    clock: SharedClock,
}

impl<S, B> Service<http::Request<B>> for DoSyncAuthService<S>
where
    S: Service<http::Request<B>>,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future = S::Future;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, mut req: http::Request<B>) -> Self::Future {
        if let Some(token) = req
            .headers()
            .get(AUTHORIZATION)
            .and_then(|h| h.to_str().ok())
            .and_then(extract_bearer)
        {
            let now_unix = self.clock.now_unix_seconds();
            if let Ok(ctx) = verify_sync(&self.keyring, now_unix, token) {
                req.extensions_mut().insert(ctx);
            }
        }
        self.inner.call(req)
    }
}

/// Pluck the verified `SyncContext` from `RpcContext.extensions` or fail
/// with `Code::Unauthenticated`.
pub fn require_sync(ctx: &connectrpc::Context) -> Result<SyncContext, ConnectError> {
    ctx.extensions
        .get::<SyncContext>()
        .cloned()
        .ok_or_else(|| ConnectError::unauthenticated("sync token required"))
}
