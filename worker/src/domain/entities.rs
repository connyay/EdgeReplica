//! Storage-shape entities. Decoupled from generated proto types so the store
//! layer doesn't carry buffa internals (unknown-fields, cached sizes).

use serde::{Deserialize, Serialize};

use super::enums::Role;
use super::ids::{DatabaseId, IdentityId, OrgId, UserId};

/// Personal organization name derived from a user's email. New users are
/// auto-joined to a personal org so they always have somewhere to put a
/// database without an extra setup step.
pub fn personal_org_name(email: &str) -> String {
    format!("{email} (personal)")
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct User {
    pub id: UserId,
    pub email: String,
    pub email_verified: bool,
    pub created_at_ms: i64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Identity {
    pub id: IdentityId,
    pub user_id: UserId,
    /// One of `password`, `github`, `google`.
    pub provider: String,
    /// For `password`, the user id (placeholder); for OAuth, the IdP-issued
    /// user id (`sub`).
    pub provider_user_id: String,
    /// Argon2id PHC string for password identities; `None` for OAuth.
    pub secret: Option<String>,
    pub created_at_ms: i64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Organization {
    pub id: OrgId,
    pub display_name: String,
    /// True for the auto-created personal org. Personal orgs can't be
    /// deleted independently — they're tied to user lifecycle.
    pub personal: bool,
    pub owner_user_id: Option<UserId>,
    pub created_at_ms: i64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OrgMembership {
    pub user_id: UserId,
    pub org_id: OrgId,
    pub role: Role,
    pub created_at_ms: i64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Database {
    pub id: DatabaseId,
    pub org_id: OrgId,
    pub name: String,
    pub created_by: UserId,
    pub created_at_ms: i64,
}

/// CSRF state for an in-flight OAuth round trip. Stored at `StartOAuth` and
/// consumed (single-use) at `CompleteOAuth`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OAuthState {
    pub state: String,
    /// `github` or `google`.
    pub provider: String,
    pub created_at_ms: i64,
    pub expires_at_ms: i64,
}
