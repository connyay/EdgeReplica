//! Backend-agnostic store error. Mapped to `ConnectError` at the
//! service-handler boundary (in the worker crate) so callers see proper
//! gRPC codes (NotFound, AlreadyExists, FailedPrecondition, Internal).

use thiserror::Error;

#[derive(Debug, Error)]
pub enum StoreError {
    #[error("not found: {0}")]
    NotFound(String),
    #[error("already exists: {0}")]
    AlreadyExists(String),
    /// Domain rule violated (e.g. removing the last admin, deleting a
    /// non-empty org).
    #[error("conflict: {0}")]
    Conflict(String),
    /// Underlying storage failure — D1 errored, JSON parse failed, etc.
    #[error("backend: {0}")]
    Backend(String),
}

impl StoreError {
    pub fn not_found(s: impl Into<String>) -> Self {
        StoreError::NotFound(s.into())
    }
    pub fn already_exists(s: impl Into<String>) -> Self {
        StoreError::AlreadyExists(s.into())
    }
    pub fn conflict(s: impl Into<String>) -> Self {
        StoreError::Conflict(s.into())
    }
    pub fn backend(s: impl Into<String>) -> Self {
        StoreError::Backend(s.into())
    }
}

pub type StoreResult<T> = Result<T, StoreError>;
