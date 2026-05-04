//! Argon2id password hashing.
//!
//! Parameters target Workers' CPU budget (m=4MiB, t=2, p=1) — gives ~25-40ms
//! per hash on Workers hardware in our experiments. Tune up `mem_cost` /
//! `time_cost` per actual CPU budget at deploy time.

use argon2::{Algorithm, Argon2, Params, Version};
use password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use rand_core::OsRng;
use thiserror::Error;

const MIN_PASSWORD_LEN: usize = 8;

#[derive(Debug, Error)]
pub enum PasswordError {
    #[error("password too short ({0} chars, need {min})", min = MIN_PASSWORD_LEN)]
    TooShort(usize),
    #[error("password appears in known-breached corpus")]
    Pwned,
    #[error("hash failed: {0}")]
    HashFailed(String),
    #[error("invalid stored hash: {0}")]
    InvalidHash(String),
    #[error("password mismatch")]
    Mismatch,
    #[error("policy: {0}")]
    PolicyError(String),
}

fn hasher() -> Argon2<'static> {
    let params = Params::new(4096, 2, 1, None).expect("valid argon2 params");
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
}

/// Validate and hash a new password. Returns the PHC string suitable for
/// storage in `identities.secret`.
pub async fn hash_new_password(password: &str) -> Result<String, PasswordError> {
    if password.chars().count() < MIN_PASSWORD_LEN {
        return Err(PasswordError::TooShort(password.chars().count()));
    }
    let salt = SaltString::generate(&mut OsRng);
    let hash = hasher()
        .hash_password(password.as_bytes(), &salt)
        .map_err(|e| PasswordError::HashFailed(e.to_string()))?;
    Ok(hash.to_string())
}

pub fn verify_password(stored: &str, password: &str) -> Result<(), PasswordError> {
    let parsed =
        PasswordHash::new(stored).map_err(|e| PasswordError::InvalidHash(e.to_string()))?;
    hasher()
        .verify_password(password.as_bytes(), &parsed)
        .map_err(|_| PasswordError::Mismatch)
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures::executor::block_on;

    #[test]
    fn hash_then_verify_roundtrips() {
        let hash = block_on(hash_new_password("correct horse battery")).unwrap();
        verify_password(&hash, "correct horse battery").unwrap();
        assert!(verify_password(&hash, "wrong-password").is_err());
    }

    #[test]
    fn rejects_short_password() {
        let err = block_on(hash_new_password("short")).unwrap_err();
        assert!(matches!(err, PasswordError::TooShort(5)));
    }
}
