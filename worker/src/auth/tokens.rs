//! Mint / verify the two macaroon kinds this workspace issues.
//!
//! All tokens carry:
//!   - `purpose=<session|sync>`
//!   - `exp=<unix_seconds>`
//!
//! Session tokens additionally carry `user`, `email`, `org`, `role`. Sync
//! tokens carry `user`, `org`, `database`, `direction=push|pull`.
//!
//! Verification is pure (no DB reads). Sync tokens are short-lived (default
//! 1h) so we don't need a per-token revocation table; if revocation becomes
//! necessary, add a nonce + `consume_nonce` style table at the sync RPC
//! boundary.

use libmacaroon::{Caveat, Format, Macaroon, MacaroonError, Verifier};
use thiserror::Error;

use crate::domain::{DatabaseId, Direction, OrgId, Role, TokenPurpose, UserId};

use super::keyring::Keyring;
use super::session::{SessionContext, SyncContext};

#[derive(Debug, Error)]
pub enum TokenError {
    #[error("malformed token: {0}")]
    Malformed(String),
    #[error("token expired")]
    Expired,
    #[error("invalid signature")]
    InvalidSignature,
    #[error("wrong token purpose: expected {expected}, got {found}")]
    WrongPurpose {
        expected: TokenPurpose,
        found: String,
    },
    #[error("missing caveat: {0}")]
    MissingCaveat(&'static str),
    #[error("invalid caveat: {0}")]
    InvalidCaveat(String),
}

impl From<MacaroonError> for TokenError {
    fn from(e: MacaroonError) -> Self {
        match e {
            MacaroonError::InvalidSignature => TokenError::InvalidSignature,
            MacaroonError::CaveatNotSatisfied(s) => TokenError::InvalidCaveat(s),
            MacaroonError::DeserializationError(s) => TokenError::Malformed(s),
            other => TokenError::Malformed(other.to_string()),
        }
    }
}

// ===== Caveat helpers =====

const LOCATION: Option<&str> = Some("edgereplica");

fn cv(prefix: &str, value: impl AsRef<str>) -> String {
    format!("{prefix}={}", value.as_ref())
}

fn parse_caveat<'a>(c: &'a Caveat, prefix: &str) -> Option<&'a str> {
    match c {
        Caveat::FirstParty(fp) => std::str::from_utf8(fp.predicate())
            .ok()
            .and_then(|s| s.strip_prefix(prefix)),
        Caveat::ThirdParty(_) => None,
    }
}

fn exp_satisfier(caveat: &[u8], now_unix: i64) -> bool {
    let Some(rest) = caveat.strip_prefix(b"exp=") else {
        return false;
    };
    let Ok(text) = std::str::from_utf8(rest) else {
        return false;
    };
    let Ok(when) = text.parse::<i64>() else {
        return false;
    };
    when > now_unix
}

/// Accept any caveat whose predicate begins with one of `prefixes`. The
/// payload is read off the macaroon afterwards; libmacaroon only needs to
/// know "is this caveat allowed to be here?".
fn add_prefix_satisfiers(verifier: &mut Verifier, prefixes: &[&[u8]]) {
    for prefix in prefixes {
        let p: Vec<u8> = prefix.to_vec();
        verifier.satisfy_general(move |c: &[u8]| c.starts_with(&p));
    }
}

// ===== Session tokens =====

#[derive(Clone, Debug)]
pub struct MintSessionInput<'a> {
    pub user_id: &'a UserId,
    pub email: &'a str,
    pub org: &'a OrgId,
    pub role: Role,
    pub now_unix: i64,
    pub ttl_seconds: i64,
}

pub fn mint_session(keyring: &Keyring, input: MintSessionInput<'_>) -> Result<String, TokenError> {
    let exp = input.now_unix + input.ttl_seconds;
    let mut mac = Macaroon::create(
        LOCATION,
        keyring.root(),
        format!("session:{}", input.user_id),
    )
    .map_err(|e| TokenError::Malformed(e.to_string()))?;
    mac.add_first_party_caveat(cv("purpose", TokenPurpose::Session.as_str()))?
        .add_first_party_caveat(cv("user", input.user_id.as_str()))?
        .add_first_party_caveat(cv("email", input.email))?
        .add_first_party_caveat(cv("org", input.org.as_str()))?
        .add_first_party_caveat(cv("role", input.role.as_str()))?
        .add_first_party_caveat(cv("exp", exp.to_string()))?;
    mac.serialize(Format::V2)
        .map_err(|e| TokenError::Malformed(e.to_string()))
}

pub fn verify_session(
    keyring: &Keyring,
    now_unix: i64,
    token: &str,
) -> Result<SessionContext, TokenError> {
    let macaroon = Macaroon::deserialize(token)?;
    let mut verifier = Verifier::default();
    // `purpose=` is satisfied as a prefix; the explicit value check happens
    // after `verify` succeeds so we can return a typed `WrongPurpose` error
    // instead of a generic caveat-not-satisfied.
    add_prefix_satisfiers(
        &mut verifier,
        &[b"purpose=", b"user=", b"email=", b"org=", b"role="],
    );
    verifier.satisfy_general(move |c: &[u8]| exp_satisfier(c, now_unix));
    verifier.verify(&macaroon, keyring.root(), &[])?;

    let mut user: Option<UserId> = None;
    let mut email: Option<String> = None;
    let mut org: Option<OrgId> = None;
    let mut role: Option<Role> = None;
    let mut exp_unix: Option<i64> = None;
    let mut purpose: Option<String> = None;

    for c in macaroon.caveats() {
        if let Some(v) = parse_caveat(c, "purpose=") {
            purpose = Some(v.into());
        } else if let Some(v) = parse_caveat(c, "user=") {
            user = Some(UserId::from(v));
        } else if let Some(v) = parse_caveat(c, "email=") {
            email = Some(v.into());
        } else if let Some(v) = parse_caveat(c, "org=") {
            org = Some(OrgId::from(v));
        } else if let Some(v) = parse_caveat(c, "role=") {
            role = v.parse().map(Some).map_err(TokenError::InvalidCaveat)?;
        } else if let Some(v) = parse_caveat(c, "exp=") {
            exp_unix = Some(
                v.parse()
                    .map_err(|_| TokenError::InvalidCaveat(format!("exp={v}")))?,
            );
        }
    }

    let purpose = purpose.ok_or(TokenError::MissingCaveat("purpose"))?;
    if purpose != TokenPurpose::Session.as_str() {
        return Err(TokenError::WrongPurpose {
            expected: TokenPurpose::Session,
            found: purpose,
        });
    }

    Ok(SessionContext {
        user: user.ok_or(TokenError::MissingCaveat("user"))?,
        email: email.ok_or(TokenError::MissingCaveat("email"))?,
        org: org.ok_or(TokenError::MissingCaveat("org"))?,
        role: role.ok_or(TokenError::MissingCaveat("role"))?,
        exp_unix: exp_unix.ok_or(TokenError::MissingCaveat("exp"))?,
    })
}

// ===== Sync tokens =====

#[derive(Clone, Debug)]
pub struct MintSyncInput<'a> {
    pub user_id: &'a UserId,
    pub org: &'a OrgId,
    pub database: &'a DatabaseId,
    pub direction: Direction,
    pub now_unix: i64,
    pub ttl_seconds: i64,
}

pub fn mint_sync(keyring: &Keyring, input: MintSyncInput<'_>) -> Result<String, TokenError> {
    let exp = input.now_unix + input.ttl_seconds;
    let mut mac = Macaroon::create(
        LOCATION,
        keyring.root(),
        format!("sync:{}:{}", input.user_id, input.database),
    )
    .map_err(|e| TokenError::Malformed(e.to_string()))?;
    mac.add_first_party_caveat(cv("purpose", TokenPurpose::Sync.as_str()))?
        .add_first_party_caveat(cv("user", input.user_id.as_str()))?
        .add_first_party_caveat(cv("org", input.org.as_str()))?
        .add_first_party_caveat(cv("database", input.database.as_str()))?
        .add_first_party_caveat(cv("direction", input.direction.as_str()))?
        .add_first_party_caveat(cv("exp", exp.to_string()))?;
    mac.serialize(Format::V2)
        .map_err(|e| TokenError::Malformed(e.to_string()))
}

pub fn verify_sync(
    keyring: &Keyring,
    now_unix: i64,
    token: &str,
) -> Result<SyncContext, TokenError> {
    let macaroon = Macaroon::deserialize(token)?;
    let mut verifier = Verifier::default();
    // See `verify_session` for why purpose is a prefix here, not exact.
    add_prefix_satisfiers(
        &mut verifier,
        &[b"purpose=", b"user=", b"org=", b"database=", b"direction="],
    );
    verifier.satisfy_general(move |c: &[u8]| exp_satisfier(c, now_unix));
    verifier.verify(&macaroon, keyring.root(), &[])?;

    let mut user: Option<UserId> = None;
    let mut org: Option<OrgId> = None;
    let mut database: Option<DatabaseId> = None;
    let mut direction: Option<Direction> = None;
    let mut exp_unix: Option<i64> = None;
    let mut purpose: Option<String> = None;

    for c in macaroon.caveats() {
        if let Some(v) = parse_caveat(c, "purpose=") {
            purpose = Some(v.into());
        } else if let Some(v) = parse_caveat(c, "user=") {
            user = Some(UserId::from(v));
        } else if let Some(v) = parse_caveat(c, "org=") {
            org = Some(OrgId::from(v));
        } else if let Some(v) = parse_caveat(c, "database=") {
            database = Some(DatabaseId::from(v));
        } else if let Some(v) = parse_caveat(c, "direction=") {
            direction = v.parse().map(Some).map_err(TokenError::InvalidCaveat)?;
        } else if let Some(v) = parse_caveat(c, "exp=") {
            exp_unix = Some(
                v.parse()
                    .map_err(|_| TokenError::InvalidCaveat(format!("exp={v}")))?,
            );
        }
    }

    let purpose = purpose.ok_or(TokenError::MissingCaveat("purpose"))?;
    if purpose != TokenPurpose::Sync.as_str() {
        return Err(TokenError::WrongPurpose {
            expected: TokenPurpose::Sync,
            found: purpose,
        });
    }

    Ok(SyncContext {
        user: user.ok_or(TokenError::MissingCaveat("user"))?,
        org: org.ok_or(TokenError::MissingCaveat("org"))?,
        database: database.ok_or(TokenError::MissingCaveat("database"))?,
        direction: direction.ok_or(TokenError::MissingCaveat("direction"))?,
        exp_unix: exp_unix.ok_or(TokenError::MissingCaveat("exp"))?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn keyring() -> Keyring {
        Keyring::dev_default()
    }

    #[test]
    fn session_roundtrip() {
        let kr = keyring();
        let user = UserId::from("u_1");
        let org = OrgId::from("o_1");
        let token = mint_session(
            &kr,
            MintSessionInput {
                user_id: &user,
                email: "ada@example.com",
                org: &org,
                role: Role::Admin,
                now_unix: 1_000,
                ttl_seconds: 60,
            },
        )
        .unwrap();
        let session = verify_session(&kr, 1_001, &token).unwrap();
        assert_eq!(session.user, user);
        assert_eq!(session.email, "ada@example.com");
        assert_eq!(session.org, org);
        assert_eq!(session.role, Role::Admin);
    }

    #[test]
    fn session_rejects_after_expiry() {
        let kr = keyring();
        let token = mint_session(
            &kr,
            MintSessionInput {
                user_id: &UserId::from("u_2"),
                email: "x@y",
                org: &OrgId::from("o_2"),
                role: Role::Member,
                now_unix: 0,
                ttl_seconds: 10,
            },
        )
        .unwrap();
        assert!(verify_session(&kr, 100, &token).is_err());
    }

    #[test]
    fn session_rejects_wrong_key() {
        let kr = keyring();
        let other = Keyring::from_key(libmacaroon::MacaroonKey::generate(b"different"));
        let token = mint_session(
            &kr,
            MintSessionInput {
                user_id: &UserId::from("u_3"),
                email: "x@y",
                org: &OrgId::from("o_3"),
                role: Role::Admin,
                now_unix: 0,
                ttl_seconds: 60,
            },
        )
        .unwrap();
        assert!(verify_session(&other, 1, &token).is_err());
    }

    #[test]
    fn session_rejects_tampered_caveat() {
        let kr = keyring();
        let token = mint_session(
            &kr,
            MintSessionInput {
                user_id: &UserId::from("u_4"),
                email: "x@y",
                org: &OrgId::from("o_4"),
                role: Role::Member,
                now_unix: 0,
                ttl_seconds: 60,
            },
        )
        .unwrap();
        // Flip a byte deep in the body — signature check must fail.
        let mut bytes = token.into_bytes();
        let mid = bytes.len() / 2;
        bytes[mid] ^= 0x01;
        let tampered = String::from_utf8_lossy(&bytes).to_string();
        assert!(verify_session(&kr, 1, &tampered).is_err());
    }

    #[test]
    fn sync_roundtrip() {
        let kr = keyring();
        let user = UserId::from("u_5");
        let org = OrgId::from("o_5");
        let db = DatabaseId::from("db_5");
        let token = mint_sync(
            &kr,
            MintSyncInput {
                user_id: &user,
                org: &org,
                database: &db,
                direction: Direction::Push,
                now_unix: 500,
                ttl_seconds: 3600,
            },
        )
        .unwrap();
        let ctx = verify_sync(&kr, 600, &token).unwrap();
        assert_eq!(ctx.user, user);
        assert_eq!(ctx.org, org);
        assert_eq!(ctx.database, db);
        assert_eq!(ctx.direction, Direction::Push);
    }

    #[test]
    fn cross_purpose_rejected() {
        let kr = keyring();
        let session = mint_session(
            &kr,
            MintSessionInput {
                user_id: &UserId::from("u_6"),
                email: "x@y",
                org: &OrgId::from("o_6"),
                role: Role::Member,
                now_unix: 0,
                ttl_seconds: 60,
            },
        )
        .unwrap();
        // Verifying a session token as a sync token must fail. Either via
        // `WrongPurpose` (if the verifier reaches the purpose check) or
        // `InvalidCaveat` (if a session-only caveat the sync verifier
        // doesn't recognize, like `email=`, trips libmacaroon first).
        // Both are correct cross-purpose protection.
        assert!(verify_sync(&kr, 1, &session).is_err());

        let sync = mint_sync(
            &kr,
            MintSyncInput {
                user_id: &UserId::from("u_6"),
                org: &OrgId::from("o_6"),
                database: &DatabaseId::from("db_6"),
                direction: Direction::Pull,
                now_unix: 0,
                ttl_seconds: 60,
            },
        )
        .unwrap();
        assert!(verify_session(&kr, 1, &sync).is_err());
    }

    #[test]
    fn wrong_purpose_specific_error_when_only_purpose_differs() {
        // Mint a session-shaped macaroon manually with `purpose=sync` to
        // exercise the explicit purpose check that runs after the caveat
        // verifier succeeds. This proves the typed `WrongPurpose` error
        // is reachable; the looser `cross_purpose_rejected` test above
        // covers the realistic mint→verify-other-kind path.
        let kr = keyring();
        let mut mac = Macaroon::create(LOCATION, kr.root(), "manual").unwrap();
        mac.add_first_party_caveat(cv("purpose", TokenPurpose::Sync.as_str()))
            .unwrap()
            .add_first_party_caveat(cv("user", "u_7"))
            .unwrap()
            .add_first_party_caveat(cv("email", "x@y"))
            .unwrap()
            .add_first_party_caveat(cv("org", "o_7"))
            .unwrap()
            .add_first_party_caveat(cv("role", "admin"))
            .unwrap()
            .add_first_party_caveat(cv("exp", "9999999999"))
            .unwrap();
        let token = mac.serialize(Format::V2).unwrap();
        let err = verify_session(&kr, 0, &token).unwrap_err();
        assert!(matches!(err, TokenError::WrongPurpose { .. }));
    }
}
