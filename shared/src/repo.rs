//! The single `Repo` trait that backs every domain operation.
//!
//! High-level "do everything" methods exist for the multi-row state changes
//! that need to be atomic in production — `create_password_user` bundles
//! user + identity + personal org + admin membership creation, etc. The D1
//! impl (in the worker crate) maps these to `D1Database::batch` (atomic per
//! Cloudflare's docs); the in-memory impl runs them under a single mutex.

use std::future::Future;

use crate::domain::{
    Database, DatabaseId, Identity, IdentityId, OAuthState, OrgId, OrgMembership, Organization,
    Role, User, UserId,
};
use crate::error::StoreResult;

#[derive(Clone, Debug)]
pub struct NewPasswordUser {
    pub email: String,
    pub password_hash: String,
}

#[derive(Clone, Debug)]
pub struct NewOAuthUser {
    pub email: String,
    /// `github` or `google`.
    pub provider: String,
    /// IdP-issued user id (`sub`).
    pub provider_user_id: String,
}

pub type OrgWithRole = (Organization, Role);
pub type OrgMemberRow = (OrgMembership, User);

pub trait Repo: Send + Sync + 'static {
    // ----- Users / identities -----

    fn get_user(&self, id: &UserId) -> impl Future<Output = StoreResult<Option<User>>> + Send;

    fn get_user_by_email(
        &self,
        email: &str,
    ) -> impl Future<Output = StoreResult<Option<User>>> + Send;

    fn list_identities(
        &self,
        user_id: &UserId,
    ) -> impl Future<Output = StoreResult<Vec<Identity>>> + Send;

    fn find_identity(
        &self,
        provider: &str,
        provider_user_id: &str,
    ) -> impl Future<Output = StoreResult<Option<Identity>>> + Send;

    fn link_identity(
        &self,
        user_id: &UserId,
        provider: &str,
        provider_user_id: &str,
        secret: Option<String>,
        now_ms: i64,
    ) -> impl Future<Output = StoreResult<Identity>> + Send;

    fn update_identity_secret(
        &self,
        identity_id: &IdentityId,
        new_secret: String,
    ) -> impl Future<Output = StoreResult<()>> + Send;

    /// Atomic: insert user + password identity + personal org + admin
    /// membership. Returns the created user.
    fn create_password_user(
        &self,
        input: NewPasswordUser,
        now_ms: i64,
    ) -> impl Future<Output = StoreResult<User>> + Send;

    /// Atomic: insert user + OAuth identity + personal org + admin
    /// membership. Used at the OAuth callback when the IdP-issued
    /// (provider, sub) doesn't match an existing identity.
    fn create_oauth_user(
        &self,
        input: NewOAuthUser,
        now_ms: i64,
    ) -> impl Future<Output = StoreResult<User>> + Send;

    // ----- Organizations -----

    fn get_organization(
        &self,
        id: &OrgId,
    ) -> impl Future<Output = StoreResult<Option<Organization>>> + Send;

    fn create_organization(
        &self,
        display_name: String,
        owner_user_id: UserId,
        now_ms: i64,
    ) -> impl Future<Output = StoreResult<Organization>> + Send;

    fn list_organizations_for_user(
        &self,
        user_id: &UserId,
    ) -> impl Future<Output = StoreResult<Vec<OrgWithRole>>> + Send;

    fn delete_organization(&self, id: &OrgId) -> impl Future<Output = StoreResult<()>> + Send;

    // ----- Memberships -----

    fn get_org_membership(
        &self,
        user_id: &UserId,
        org_id: &OrgId,
    ) -> impl Future<Output = StoreResult<Option<OrgMembership>>> + Send;

    fn add_org_membership(
        &self,
        user_id: &UserId,
        org_id: &OrgId,
        role: Role,
        now_ms: i64,
    ) -> impl Future<Output = StoreResult<()>> + Send;

    fn remove_org_membership(
        &self,
        user_id: &UserId,
        org_id: &OrgId,
    ) -> impl Future<Output = StoreResult<()>> + Send;

    fn list_org_memberships(
        &self,
        org_id: &OrgId,
    ) -> impl Future<Output = StoreResult<Vec<OrgMemberRow>>> + Send;

    // ----- Databases -----

    fn create_database(
        &self,
        org_id: OrgId,
        name: String,
        created_by: UserId,
        now_ms: i64,
    ) -> impl Future<Output = StoreResult<Database>> + Send;

    fn get_database(
        &self,
        id: &DatabaseId,
    ) -> impl Future<Output = StoreResult<Option<Database>>> + Send;

    fn list_databases_for_org(
        &self,
        org_id: &OrgId,
    ) -> impl Future<Output = StoreResult<Vec<Database>>> + Send;

    fn delete_database(&self, id: &DatabaseId) -> impl Future<Output = StoreResult<()>> + Send;

    // ----- OAuth state (cross-request CSRF token) -----

    fn store_oauth_state(&self, state: OAuthState) -> impl Future<Output = StoreResult<()>> + Send;

    /// Single-use: returns `Some` only on first matching call within TTL.
    /// Subsequent calls (or expired state) return `None`.
    fn consume_oauth_state(
        &self,
        state: &str,
        now_ms: i64,
    ) -> impl Future<Output = StoreResult<Option<OAuthState>>> + Send;
}
