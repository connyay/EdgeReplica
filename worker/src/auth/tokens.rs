//! Mint / verify the two macaroon kinds this workspace issues.
//!
//! # Security model
//!
//! Every authority-bearing claim (user, email, org, role, database,
//! direction, purpose, ...) is packed into a signed [`TokenClaims`] protobuf
//! message that becomes the macaroon **identifier**. The identifier is folded
//! into the root signature (`sig0 = HMAC(root_key, identifier)`), so no holder
//! can alter a claim without the root key.
//!
//! Caveats are deliberately NOT used to carry claims. A first-party caveat can
//! be appended by anyone holding a token — that is the defining macaroon
//! property — so caveats can only ever *attenuate*, never assert authority.
//! The previous design stored identity in caveats and read it back, which let
//! any token holder append `role=admin` / `user=<victim>` / `org=<other>` (or
//! `direction=push` on a pull token) and silently escalate.
//!
//! The single legitimate caveat is `exp=<unix>`: expiry genuinely attenuates,
//! so a holder may append an *earlier* expiry and the effective expiry is the
//! earliest one (it can never be extended — appending a later `exp` is ignored
//! because we take the minimum). The verifier registers exactly one satisfier,
//! for well-formed `exp` caveats, so any *other* caveat (e.g. one an attacker
//! appended) is unsatisfied and verification fails.
//!
//! Verification is pure (no DB reads). Sync tokens are short-lived (default
//! 1h) so we don't need a per-token revocation table; if revocation becomes
//! necessary, add a nonce claim + `consume_nonce` style table at the sync RPC
//! boundary.

use buffa::Message as _;
use edgereplica_protocol::auth::v1::TokenClaims;
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
    #[error("missing claim: {0}")]
    MissingClaim(&'static str),
    #[error("invalid claim: {0}")]
    InvalidClaim(String),
    /// The token carried a caveat other than `exp`. Well-formed tokens have
    /// only `exp`; any other caveat means it was appended after minting
    /// (tampering) and the token is rejected.
    #[error("unexpected caveat on token: {0}")]
    UnexpectedCaveat(String),
}

impl From<MacaroonError> for TokenError {
    fn from(e: MacaroonError) -> Self {
        match e {
            MacaroonError::InvalidSignature => TokenError::InvalidSignature,
            // The verifier only satisfies well-formed `exp` caveats, so any
            // caveat surfacing here was appended post-mint.
            MacaroonError::CaveatNotSatisfied(s) => TokenError::UnexpectedCaveat(s),
            MacaroonError::DeserializationError(s) => TokenError::Malformed(s),
            other => TokenError::Malformed(other.to_string()),
        }
    }
}

// ===== Pack / unpack =====

const LOCATION: Option<&str> = Some("edgereplica");
const EXP_PREFIX: &str = "exp=";

/// Serialize signed claims into the macaroon identifier and add the lone
/// `exp` caveat. The token carries no other caveats.
fn pack(keyring: &Keyring, claims: &TokenClaims, exp_unix: i64) -> Result<String, TokenError> {
    let mut mac = Macaroon::create(LOCATION, keyring.root(), claims.encode_to_vec())?;
    mac.add_first_party_caveat(format!("{EXP_PREFIX}{exp_unix}"))?;
    Ok(mac.serialize(Format::V2)?)
}

/// A caveat is satisfiable iff it is a well-formed `exp=<i64>`. Everything
/// else (including anything an attacker appends) is left unsatisfied, so the
/// verifier rejects the token.
fn parse_exp(caveat: &[u8]) -> Option<i64> {
    let rest = caveat.strip_prefix(EXP_PREFIX.as_bytes())?;
    std::str::from_utf8(rest).ok()?.parse::<i64>().ok()
}

/// Verify the signature, reject any non-`exp` caveat, enforce expiry, and
/// recover the signed claims. Effective expiry is the EARLIEST `exp` caveat,
/// so attenuation can only shorten a token's life, never extend it.
fn unpack(keyring: &Keyring, now_unix: i64, token: &str) -> Result<(TokenClaims, i64), TokenError> {
    let macaroon = Macaroon::deserialize(token)?;
    let mut verifier = Verifier::default();
    verifier.satisfy_general(|c: &[u8]| parse_exp(c).is_some());
    verifier.verify(&macaroon, keyring.root(), &[])?;

    let exp_unix = macaroon
        .caveats()
        .iter()
        .filter_map(|c| match c {
            Caveat::FirstParty(fp) => parse_exp(fp.predicate()),
            Caveat::ThirdParty(_) => None,
        })
        .min()
        .ok_or(TokenError::MissingClaim("exp"))?;
    if exp_unix <= now_unix {
        return Err(TokenError::Expired);
    }

    let claims = TokenClaims::decode_from_slice(macaroon.identifier())
        .map_err(|e| TokenError::Malformed(format!("claims decode: {e}")))?;
    Ok((claims, exp_unix))
}

fn check_purpose(claims: &TokenClaims, expected: TokenPurpose) -> Result<(), TokenError> {
    if claims.purpose != expected.as_str() {
        return Err(TokenError::WrongPurpose {
            expected,
            found: claims.purpose.clone(),
        });
    }
    Ok(())
}

fn require<'a>(value: &'a str, claim: &'static str) -> Result<&'a str, TokenError> {
    if value.is_empty() {
        Err(TokenError::MissingClaim(claim))
    } else {
        Ok(value)
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
    let claims = TokenClaims {
        purpose: TokenPurpose::Session.as_str().to_owned(),
        user_id: input.user_id.as_str().to_owned(),
        org_id: input.org.as_str().to_owned(),
        email: input.email.to_owned(),
        role: input.role.as_str().to_owned(),
        ..Default::default()
    };
    pack(keyring, &claims, input.now_unix + input.ttl_seconds)
}

pub fn verify_session(
    keyring: &Keyring,
    now_unix: i64,
    token: &str,
) -> Result<SessionContext, TokenError> {
    let (claims, exp_unix) = unpack(keyring, now_unix, token)?;
    check_purpose(&claims, TokenPurpose::Session)?;

    let role = claims
        .role
        .parse::<Role>()
        .map_err(TokenError::InvalidClaim)?;

    Ok(SessionContext {
        user: UserId::from(require(&claims.user_id, "user")?),
        email: require(&claims.email, "email")?.to_owned(),
        org: OrgId::from(require(&claims.org_id, "org")?),
        role,
        exp_unix,
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
    let claims = TokenClaims {
        purpose: TokenPurpose::Sync.as_str().to_owned(),
        user_id: input.user_id.as_str().to_owned(),
        org_id: input.org.as_str().to_owned(),
        database_id: input.database.as_str().to_owned(),
        direction: input.direction.as_str().to_owned(),
        ..Default::default()
    };
    pack(keyring, &claims, input.now_unix + input.ttl_seconds)
}

pub fn verify_sync(
    keyring: &Keyring,
    now_unix: i64,
    token: &str,
) -> Result<SyncContext, TokenError> {
    let (claims, exp_unix) = unpack(keyring, now_unix, token)?;
    check_purpose(&claims, TokenPurpose::Sync)?;

    let direction = claims
        .direction
        .parse::<Direction>()
        .map_err(TokenError::InvalidClaim)?;

    Ok(SyncContext {
        user: UserId::from(require(&claims.user_id, "user")?),
        org: OrgId::from(require(&claims.org_id, "org")?),
        database: DatabaseId::from(require(&claims.database_id, "database")?),
        direction,
        exp_unix,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn keyring() -> Keyring {
        Keyring::dev_default()
    }

    fn sample_session(kr: &Keyring, now_unix: i64, ttl_seconds: i64) -> String {
        mint_session(
            kr,
            MintSessionInput {
                user_id: &UserId::from("u_1"),
                email: "ada@example.com",
                org: &OrgId::from("o_1"),
                role: Role::Member,
                now_unix,
                ttl_seconds,
            },
        )
        .unwrap()
    }

    fn sample_sync(kr: &Keyring, direction: Direction, now_unix: i64, ttl_seconds: i64) -> String {
        mint_sync(
            kr,
            MintSyncInput {
                user_id: &UserId::from("u_1"),
                org: &OrgId::from("o_1"),
                database: &DatabaseId::from("db_1"),
                direction,
                now_unix,
                ttl_seconds,
            },
        )
        .unwrap()
    }

    /// Append first-party caveats to a serialized token — the operation any
    /// holder can do without the root key. This is the attacker's tool.
    fn attacker_append(token: &str, extra: &[&str]) -> String {
        let mut mac = Macaroon::deserialize(token).unwrap();
        for c in extra {
            mac.add_first_party_caveat(*c).unwrap();
        }
        mac.serialize(Format::V2).unwrap()
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
        assert_eq!(session.exp_unix, 1_060);
    }

    #[test]
    fn session_rejects_after_expiry() {
        let kr = keyring();
        let token = sample_session(&kr, 0, 10);
        assert!(matches!(
            verify_session(&kr, 100, &token),
            Err(TokenError::Expired)
        ));
    }

    #[test]
    fn session_rejects_wrong_key() {
        let kr = keyring();
        let other = Keyring::from_key(libmacaroon::MacaroonKey::generate(b"different"));
        let token = sample_session(&kr, 0, 60);
        assert!(verify_session(&other, 1, &token).is_err());
    }

    #[test]
    fn session_rejects_tampered_identifier() {
        let kr = keyring();
        let token = sample_session(&kr, 0, 60);
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
        // A session token must not satisfy a sync verify, and vice versa.
        // Both kinds carry only an `exp` caveat now, so verification reaches
        // the purpose check and returns the typed `WrongPurpose`.
        let session = sample_session(&kr, 0, 60);
        assert!(matches!(
            verify_sync(&kr, 1, &session),
            Err(TokenError::WrongPurpose { .. })
        ));

        let sync = sample_sync(&kr, Direction::Pull, 0, 60);
        assert!(matches!(
            verify_session(&kr, 1, &sync),
            Err(TokenError::WrongPurpose { .. })
        ));
    }

    // --- Regression tests for the macaroon-attenuation vulnerability ---
    //
    // These reproduce the original exploit: a token holder appends first-party
    // caveats (no key required) to escalate authority. The fix moves all
    // authority claims into the signed identifier; only an `exp` caveat is
    // satisfiable, so each appended-caveat attack now FAILS.

    #[test]
    fn session_rejects_appended_authority_caveats() {
        let kr = keyring();
        let token = sample_session(&kr, 1_000, 3_600);
        // The exact escalation that used to succeed: become an admin in
        // another org, impersonating a victim.
        let forged = attacker_append(&token, &["role=admin", "user=u_victim", "org=o_victim"]);
        assert!(matches!(
            verify_session(&kr, 1_001, &forged),
            Err(TokenError::UnexpectedCaveat(_))
        ));
    }

    #[test]
    fn session_rejects_any_single_appended_caveat() {
        let kr = keyring();
        let token = sample_session(&kr, 1_000, 3_600);
        let forged = attacker_append(&token, &["role=admin"]);
        assert!(matches!(
            verify_session(&kr, 1_001, &forged),
            Err(TokenError::UnexpectedCaveat(_))
        ));
    }

    #[test]
    fn sync_rejects_appended_direction_override() {
        let kr = keyring();
        // A read-only pull token...
        let token = sample_sync(&kr, Direction::Pull, 1_000, 3_600);
        // ...must not be upgraded to a write (push) by appending a caveat,
        // nor retargeted at another database.
        let forged = attacker_append(&token, &["direction=push", "database=db_victim"]);
        assert!(matches!(
            verify_sync(&kr, 1_001, &forged),
            Err(TokenError::UnexpectedCaveat(_))
        ));
        // Sanity: the untampered token still verifies to a pull on db_1.
        let ok = verify_sync(&kr, 1_001, &token).unwrap();
        assert_eq!(ok.direction, Direction::Pull);
        assert_eq!(ok.database, DatabaseId::from("db_1"));
    }

    // --- `exp` is the one legitimately-attenuating caveat ---

    #[test]
    fn exp_caveat_cannot_be_extended() {
        let kr = keyring();
        // Token already expired (exp = 10).
        let token = sample_session(&kr, 0, 10);
        // Appending a far-future exp must NOT revive it — effective expiry is
        // the earliest exp caveat, so the original exp=10 still governs.
        let forged = attacker_append(&token, &["exp=9999999999"]);
        assert!(matches!(
            verify_session(&kr, 100, &forged),
            Err(TokenError::Expired)
        ));
    }

    #[test]
    fn exp_caveat_can_be_attenuated_shorter() {
        let kr = keyring();
        // Long-lived token (exp = 10_000).
        let token = sample_session(&kr, 0, 10_000);
        // A holder narrows it to expire at 500 — a legitimate attenuation.
        let narrowed = attacker_append(&token, &["exp=500"]);
        // Still valid before the tighter expiry...
        let s = verify_session(&kr, 100, &narrowed).unwrap();
        assert_eq!(s.exp_unix, 500);
        // ...and dead after it, even though the original exp is far away.
        assert!(matches!(
            verify_session(&kr, 600, &narrowed),
            Err(TokenError::Expired)
        ));
    }
}
