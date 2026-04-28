//! Helpers shared across handlers: error mapping, simple validation.

use connectrpc::ConnectError;

use crate::auth::{PasswordError, TokenError};
use crate::error::StoreError;

/// Map a `StoreError` onto the right gRPC code. `StoreError` deliberately
/// has no connectrpc dep so the storage layer stays transport-agnostic;
/// translation happens here. Use as `.map_err(map_store_error)?`.
pub fn map_store_error(e: StoreError) -> ConnectError {
    match e {
        StoreError::NotFound(s) => ConnectError::not_found(s),
        StoreError::AlreadyExists(s) => ConnectError::already_exists(s),
        StoreError::Conflict(s) => ConnectError::failed_precondition(s),
        StoreError::Backend(s) => ConnectError::internal(s),
    }
}

pub fn map_token_error(e: TokenError) -> ConnectError {
    match e {
        TokenError::InvalidSignature => ConnectError::unauthenticated("invalid token signature"),
        TokenError::Malformed(s) => ConnectError::unauthenticated(format!("malformed token: {s}")),
        TokenError::Expired => ConnectError::unauthenticated("token expired"),
        TokenError::WrongPurpose { .. } => ConnectError::permission_denied(e.to_string()),
        TokenError::MissingCaveat(_) | TokenError::InvalidCaveat(_) => {
            ConnectError::unauthenticated(e.to_string())
        }
    }
}

pub fn map_password_error(e: PasswordError) -> ConnectError {
    match e {
        PasswordError::TooShort(_) => ConnectError::invalid_argument(e.to_string()),
        PasswordError::Pwned => ConnectError::invalid_argument(
            "password appears in known-breached corpus; pick another",
        ),
        PasswordError::Mismatch => ConnectError::unauthenticated("password mismatch"),
        PasswordError::HashFailed(_) | PasswordError::InvalidHash(_) => {
            ConnectError::internal(e.to_string())
        }
        PasswordError::PolicyError(_) => ConnectError::invalid_argument(e.to_string()),
    }
}

/// Best-effort email shape check: exactly one `@`, non-empty parts. Not a
/// full RFC parse — the IdP / database is the canonical source of truth.
pub fn validate_email(email: &str) -> Result<(), ConnectError> {
    let trimmed = email.trim();
    if trimmed.is_empty() {
        return Err(ConnectError::invalid_argument("email is required"));
    }
    let (local, domain) = trimmed
        .split_once('@')
        .ok_or_else(|| ConnectError::invalid_argument("email must contain '@'"))?;
    if local.is_empty() || domain.is_empty() {
        return Err(ConnectError::invalid_argument("malformed email"));
    }
    if domain.contains('@') {
        return Err(ConnectError::invalid_argument("malformed email"));
    }
    Ok(())
}

pub fn validate_database_name(name: &str) -> Result<(), ConnectError> {
    let trimmed = name.trim();
    if trimmed.is_empty() {
        return Err(ConnectError::invalid_argument("database name is required"));
    }
    if trimmed.len() > 64 {
        return Err(ConnectError::invalid_argument(
            "database name too long (max 64 chars)",
        ));
    }
    if !trimmed
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    {
        return Err(ConnectError::invalid_argument(
            "database name may only contain ASCII alphanumerics, '-', '_'",
        ));
    }
    Ok(())
}
