//! Macaroon root-key handling.
//!
//! A single 32-byte root key signs every token. Verification relies on the
//! `purpose=` caveat (and the verifier's exact-match satisfier) to keep
//! token kinds from being interchangeable: a session token can't be used
//! to drive a sync RPC, etc.

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;
use libmacaroon::MacaroonKey;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum KeyringError {
    #[error("invalid key length: {0} (need 32)")]
    InvalidLength(usize),
    #[error("invalid key base64: {0}")]
    InvalidBase64(String),
}

#[derive(Clone)]
pub struct Keyring {
    root: MacaroonKey,
}

impl Keyring {
    pub fn from_key(root: MacaroonKey) -> Self {
        Self { root }
    }

    /// Decode a base64-encoded 32-byte key. Accepts either standard or
    /// URL-safe alphabets, padded or unpadded.
    pub fn from_base64(s: &str) -> Result<Self, KeyringError> {
        let bytes = B64
            .decode(s.trim())
            .map_err(|e| KeyringError::InvalidBase64(e.to_string()))?;
        if bytes.len() != 32 {
            return Err(KeyringError::InvalidLength(bytes.len()));
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        Ok(Self {
            root: MacaroonKey::from(arr),
        })
    }

    /// Deterministic dev fallback used by tests. NOT for production: a
    /// leaked binary trivially recovers the key.
    pub fn dev_default() -> Self {
        Self {
            root: MacaroonKey::generate(b"edgereplica.dev-key.do-not-deploy"),
        }
    }

    pub fn root(&self) -> &MacaroonKey {
        &self.root
    }
}
