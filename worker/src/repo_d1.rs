//! D1-backed implementation of [`Repo`].
//!
//! Wasm-only: the JsFuture each D1 call returns is `!Send` outside wasm,
//! so the futures returned here can't satisfy the `+ Send` bound on
//! `Repo`'s method futures. Native unit tests use `InMemoryRepo` from
//! [`crate::repo_mem`].
//!
//! Multi-row state changes (signup) go through `D1Database::batch`, which
//! Cloudflare guarantees as atomic (all-or-nothing). Single-row changes
//! use `prepare().run()`.

#![cfg(target_arch = "wasm32")]

use serde::Deserialize;

use crate::domain::{
    Database, DatabaseId, Identity, IdentityId, IdentityProvider, OAuthState, OrgId, OrgMembership,
    Organization, Role, User, UserId, entities::personal_org_name,
};
use crate::error::{StoreError, StoreResult};
use crate::repo::{NewOAuthUser, NewPasswordUser, OrgMemberRow, OrgWithRole, Repo};
use worker::send::IntoSendFuture;
use worker::{D1Database, D1PreparedStatement, D1Type};

pub const SCHEMA: &str = include_str!("../migrations/0001_init.sql");

pub struct D1Repo {
    db: D1Database,
}

impl D1Repo {
    pub fn new(db: D1Database) -> Self {
        Self { db }
    }

    /// Idempotent CREATE-IF-NOT-EXISTS for every table in the schema. Used
    /// by `wrangler dev` when `AUTO_MIGRATE=true`. D1 in production should
    /// run migrations via `wrangler d1 migrations apply` at deploy time.
    pub async fn ensure_schema(&self) -> StoreResult<()> {
        let stmts: Vec<D1PreparedStatement> = normalized_statements(SCHEMA)
            .iter()
            .map(|s| self.db.prepare(s))
            .collect();
        self.db
            .batch(stmts)
            .into_send()
            .await
            .map_err(|e| StoreError::backend(format!("ensure_schema: {e}")))?;
        Ok(())
    }
}

// =================== signup helper ===================

/// Inputs for the four-statement "create user + identity + personal org +
/// admin membership" batch shared by password and OAuth signup.
struct SignupRecord<'a> {
    email: String,
    email_verified: bool,
    provider: &'a str,
    /// `None` for password (the new user id is used as `provider_user_id`).
    provider_user_id: Option<&'a str>,
    /// Argon2 hash for password identities; `None` for OAuth.
    secret: Option<&'a str>,
    now_ms: i64,
}

impl D1Repo {
    async fn signup_with_personal_org(&self, rec: SignupRecord<'_>) -> StoreResult<User> {
        let user_id = UserId::new();
        let identity_id = IdentityId::new();
        let org_id = OrgId::new();
        let org_name = personal_org_name(&rec.email);
        let user_id_str = user_id.to_string();
        let identity_id_str = identity_id.to_string();
        let org_id_str = org_id.to_string();
        let provider_user_id = rec.provider_user_id.unwrap_or(&user_id_str);
        let secret_param = match rec.secret {
            Some(s) => D1Type::Text(s),
            None => D1Type::Null,
        };
        let email_verified_int = i32::from(rec.email_verified);
        let now_ms = rec.now_ms;
        let stmts = vec![
            self.db
                .prepare(
                    "INSERT INTO users (id, email, email_verified, created_at_ms) \
                     VALUES (?, ?, ?, ?)",
                )
                .bind_refs(&[
                    D1Type::Text(&user_id_str),
                    D1Type::Text(&rec.email),
                    D1Type::Integer(email_verified_int),
                    ms(now_ms),
                ])
                .map_err(d1_err)?,
            self.db
                .prepare(
                    "INSERT INTO identities (id, user_id, provider, provider_user_id, secret, created_at_ms) \
                     VALUES (?, ?, ?, ?, ?, ?)",
                )
                .bind_refs(&[
                    D1Type::Text(&identity_id_str),
                    D1Type::Text(&user_id_str),
                    D1Type::Text(rec.provider),
                    D1Type::Text(provider_user_id),
                    secret_param,
                    ms(now_ms),
                ])
                .map_err(d1_err)?,
            self.db
                .prepare(
                    "INSERT INTO organizations (id, display_name, personal, owner_user_id, created_at_ms) \
                     VALUES (?, ?, 1, ?, ?)",
                )
                .bind_refs(&[
                    D1Type::Text(&org_id_str),
                    D1Type::Text(&org_name),
                    D1Type::Text(&user_id_str),
                    ms(now_ms),
                ])
                .map_err(d1_err)?,
            self.db
                .prepare(
                    "INSERT INTO org_memberships (user_id, org_id, role, created_at_ms) \
                     VALUES (?, ?, ?, ?)",
                )
                .bind_refs(&[
                    D1Type::Text(&user_id_str),
                    D1Type::Text(&org_id_str),
                    D1Type::Text(Role::Admin.as_str()),
                    ms(now_ms),
                ])
                .map_err(d1_err)?,
        ];
        let email = rec.email;
        let email_for_err = email.clone();
        run_batch_mapping_unique(&self.db, stmts, move || {
            StoreError::already_exists(format!("user with email {email_for_err}"))
        })
        .await?;
        Ok(User {
            id: user_id,
            email,
            email_verified: rec.email_verified,
            created_at_ms: now_ms,
        })
    }
}

// =================== row types ===================

#[derive(Deserialize)]
struct UserRow {
    id: String,
    email: String,
    email_verified: i64,
    created_at_ms: i64,
}
impl From<UserRow> for User {
    fn from(r: UserRow) -> Self {
        User {
            id: UserId::from(r.id),
            email: r.email,
            email_verified: r.email_verified != 0,
            created_at_ms: r.created_at_ms,
        }
    }
}

#[derive(Deserialize)]
struct IdentityRow {
    id: String,
    user_id: String,
    provider: String,
    provider_user_id: String,
    secret: Option<String>,
    created_at_ms: i64,
}
impl From<IdentityRow> for Identity {
    fn from(r: IdentityRow) -> Self {
        Identity {
            id: IdentityId::from(r.id),
            user_id: UserId::from(r.user_id),
            provider: r.provider,
            provider_user_id: r.provider_user_id,
            secret: r.secret,
            created_at_ms: r.created_at_ms,
        }
    }
}

#[derive(Deserialize)]
struct OrgRow {
    id: String,
    display_name: String,
    personal: i64,
    owner_user_id: Option<String>,
    created_at_ms: i64,
}
impl From<OrgRow> for Organization {
    fn from(r: OrgRow) -> Self {
        Organization {
            id: OrgId::from(r.id),
            display_name: r.display_name,
            personal: r.personal != 0,
            owner_user_id: r.owner_user_id.map(UserId::from),
            created_at_ms: r.created_at_ms,
        }
    }
}

#[derive(Deserialize)]
struct OrgRowWithRole {
    id: String,
    display_name: String,
    personal: i64,
    owner_user_id: Option<String>,
    created_at_ms: i64,
    role: String,
}

#[derive(Deserialize)]
struct OrgMembershipRow {
    user_id: String,
    org_id: String,
    role: String,
    created_at_ms: i64,
}
impl TryFrom<OrgMembershipRow> for OrgMembership {
    type Error = StoreError;
    fn try_from(r: OrgMembershipRow) -> Result<Self, StoreError> {
        Ok(OrgMembership {
            user_id: UserId::from(r.user_id),
            org_id: OrgId::from(r.org_id),
            role: r
                .role
                .parse()
                .map_err(|e: String| StoreError::backend(format!("role: {e}")))?,
            created_at_ms: r.created_at_ms,
        })
    }
}

#[derive(Deserialize)]
struct DatabaseRow {
    id: String,
    org_id: String,
    name: String,
    created_by: String,
    created_at_ms: i64,
}
impl From<DatabaseRow> for Database {
    fn from(r: DatabaseRow) -> Self {
        Database {
            id: DatabaseId::from(r.id),
            org_id: OrgId::from(r.org_id),
            name: r.name,
            created_by: UserId::from(r.created_by),
            created_at_ms: r.created_at_ms,
        }
    }
}

#[derive(Deserialize)]
struct OAuthStateRow {
    state: String,
    provider: String,
    created_at_ms: i64,
    expires_at_ms: i64,
}
impl From<OAuthStateRow> for OAuthState {
    fn from(r: OAuthStateRow) -> Self {
        OAuthState {
            state: r.state,
            provider: r.provider,
            created_at_ms: r.created_at_ms,
            expires_at_ms: r.expires_at_ms,
        }
    }
}

// =================== Repo impl ===================

impl Repo for D1Repo {
    async fn get_user(&self, id: &UserId) -> StoreResult<Option<User>> {
        let stmt = self
            .db
            .prepare("SELECT id, email, email_verified, created_at_ms FROM users WHERE id = ?")
            .bind_refs(&[D1Type::Text(id.as_str())])
            .map_err(d1_err)?;
        let row: Option<UserRow> = stmt.first(None).into_send().await.map_err(d1_err)?;
        Ok(row.map(Into::into))
    }

    async fn get_user_by_email(&self, email: &str) -> StoreResult<Option<User>> {
        let stmt = self
            .db
            .prepare(
                "SELECT id, email, email_verified, created_at_ms \
                 FROM users WHERE LOWER(email) = LOWER(?)",
            )
            .bind_refs(&[D1Type::Text(email)])
            .map_err(d1_err)?;
        let row: Option<UserRow> = stmt.first(None).into_send().await.map_err(d1_err)?;
        Ok(row.map(Into::into))
    }

    async fn list_identities(&self, user_id: &UserId) -> StoreResult<Vec<Identity>> {
        let stmt = self
            .db
            .prepare(
                "SELECT id, user_id, provider, provider_user_id, secret, created_at_ms \
                 FROM identities WHERE user_id = ?",
            )
            .bind_refs(&[D1Type::Text(user_id.as_str())])
            .map_err(d1_err)?;
        let result = stmt.all().into_send().await.map_err(d1_err)?;
        let rows: Vec<IdentityRow> = result.results().map_err(d1_err)?;
        Ok(rows.into_iter().map(Into::into).collect())
    }

    async fn find_identity(
        &self,
        provider: &str,
        provider_user_id: &str,
    ) -> StoreResult<Option<Identity>> {
        let stmt = self
            .db
            .prepare(
                "SELECT id, user_id, provider, provider_user_id, secret, created_at_ms \
                 FROM identities WHERE provider = ? AND provider_user_id = ?",
            )
            .bind_refs(&[D1Type::Text(provider), D1Type::Text(provider_user_id)])
            .map_err(d1_err)?;
        let row: Option<IdentityRow> = stmt.first(None).into_send().await.map_err(d1_err)?;
        Ok(row.map(Into::into))
    }

    async fn link_identity(
        &self,
        user_id: &UserId,
        provider: &str,
        provider_user_id: &str,
        secret: Option<String>,
        now_ms: i64,
    ) -> StoreResult<Identity> {
        let id = IdentityId::new();
        let secret_str = secret.as_deref().unwrap_or("");
        let secret_param = if secret.is_some() {
            D1Type::Text(secret_str)
        } else {
            D1Type::Null
        };
        self.db
            .prepare(
                "INSERT INTO identities (id, user_id, provider, provider_user_id, secret, created_at_ms) \
                 VALUES (?, ?, ?, ?, ?, ?)",
            )
            .bind_refs(&[
                D1Type::Text(id.as_str()),
                D1Type::Text(user_id.as_str()),
                D1Type::Text(provider),
                D1Type::Text(provider_user_id),
                secret_param,
                ms(now_ms),
            ])
            .map_err(d1_err)?
            .run()
            .into_send()
            .await
            .map_err(d1_err)?;
        Ok(Identity {
            id,
            user_id: user_id.clone(),
            provider: provider.into(),
            provider_user_id: provider_user_id.into(),
            secret,
            created_at_ms: now_ms,
        })
    }

    async fn update_identity_secret(
        &self,
        identity_id: &IdentityId,
        new_secret: String,
    ) -> StoreResult<()> {
        self.db
            .prepare("UPDATE identities SET secret = ? WHERE id = ?")
            .bind_refs(&[
                D1Type::Text(&new_secret),
                D1Type::Text(identity_id.as_str()),
            ])
            .map_err(d1_err)?
            .run()
            .into_send()
            .await
            .map_err(d1_err)?;
        Ok(())
    }

    async fn create_password_user(&self, input: NewPasswordUser, now_ms: i64) -> StoreResult<User> {
        self.signup_with_personal_org(SignupRecord {
            email: input.email,
            email_verified: false,
            provider: IdentityProvider::PASSWORD,
            provider_user_id: None,
            secret: Some(&input.password_hash),
            now_ms,
        })
        .await
    }

    async fn create_oauth_user(&self, input: NewOAuthUser, now_ms: i64) -> StoreResult<User> {
        self.signup_with_personal_org(SignupRecord {
            email: input.email,
            email_verified: true,
            provider: &input.provider,
            provider_user_id: Some(&input.provider_user_id),
            secret: None,
            now_ms,
        })
        .await
    }

    async fn get_organization(&self, id: &OrgId) -> StoreResult<Option<Organization>> {
        let stmt = self
            .db
            .prepare(
                "SELECT id, display_name, personal, owner_user_id, created_at_ms \
                 FROM organizations WHERE id = ?",
            )
            .bind_refs(&[D1Type::Text(id.as_str())])
            .map_err(d1_err)?;
        let row: Option<OrgRow> = stmt.first(None).into_send().await.map_err(d1_err)?;
        Ok(row.map(Into::into))
    }

    async fn create_organization(
        &self,
        display_name: String,
        owner_user_id: UserId,
        now_ms: i64,
    ) -> StoreResult<Organization> {
        let id = OrgId::new();
        let id_str = id.to_string();
        let owner_str = owner_user_id.to_string();
        let stmts = vec![
            self.db
                .prepare(
                    "INSERT INTO organizations (id, display_name, personal, owner_user_id, created_at_ms) \
                     VALUES (?, ?, 0, ?, ?)",
                )
                .bind_refs(&[
                    D1Type::Text(&id_str),
                    D1Type::Text(&display_name),
                    D1Type::Text(&owner_str),
                    ms(now_ms),
                ])
                .map_err(d1_err)?,
            self.db
                .prepare(
                    "INSERT INTO org_memberships (user_id, org_id, role, created_at_ms) \
                     VALUES (?, ?, ?, ?)",
                )
                .bind_refs(&[
                    D1Type::Text(&owner_str),
                    D1Type::Text(&id_str),
                    D1Type::Text(Role::Admin.as_str()),
                    ms(now_ms),
                ])
                .map_err(d1_err)?,
        ];
        run_batch(&self.db, stmts).await?;
        Ok(Organization {
            id,
            display_name,
            personal: false,
            owner_user_id: Some(owner_user_id),
            created_at_ms: now_ms,
        })
    }

    async fn list_organizations_for_user(&self, user_id: &UserId) -> StoreResult<Vec<OrgWithRole>> {
        let stmt = self
            .db
            .prepare(
                "SELECT o.id, o.display_name, o.personal, o.owner_user_id, o.created_at_ms, m.role \
                 FROM organizations o \
                 JOIN org_memberships m ON m.org_id = o.id \
                 WHERE m.user_id = ? \
                 ORDER BY o.id",
            )
            .bind_refs(&[D1Type::Text(user_id.as_str())])
            .map_err(d1_err)?;
        let result = stmt.all().into_send().await.map_err(d1_err)?;
        let rows: Vec<OrgRowWithRole> = result.results().map_err(d1_err)?;
        rows.into_iter()
            .map(|r| {
                let role: Role = r
                    .role
                    .parse()
                    .map_err(|e: String| StoreError::backend(format!("role: {e}")))?;
                Ok((
                    Organization {
                        id: OrgId::from(r.id),
                        display_name: r.display_name,
                        personal: r.personal != 0,
                        owner_user_id: r.owner_user_id.map(UserId::from),
                        created_at_ms: r.created_at_ms,
                    },
                    role,
                ))
            })
            .collect()
    }

    async fn delete_organization(&self, _id: &OrgId) -> StoreResult<()> {
        Err(StoreError::backend(
            "delete_organization not yet implemented for D1",
        ))
    }

    async fn get_org_membership(
        &self,
        user_id: &UserId,
        org_id: &OrgId,
    ) -> StoreResult<Option<OrgMembership>> {
        let stmt = self
            .db
            .prepare(
                "SELECT user_id, org_id, role, created_at_ms FROM org_memberships \
                 WHERE user_id = ? AND org_id = ?",
            )
            .bind_refs(&[
                D1Type::Text(user_id.as_str()),
                D1Type::Text(org_id.as_str()),
            ])
            .map_err(d1_err)?;
        let row: Option<OrgMembershipRow> = stmt.first(None).into_send().await.map_err(d1_err)?;
        row.map(OrgMembership::try_from).transpose()
    }

    async fn add_org_membership(
        &self,
        _user_id: &UserId,
        _org_id: &OrgId,
        _role: Role,
        _now_ms: i64,
    ) -> StoreResult<()> {
        Err(StoreError::backend(
            "add_org_membership not yet implemented for D1",
        ))
    }

    async fn remove_org_membership(&self, _user_id: &UserId, _org_id: &OrgId) -> StoreResult<()> {
        Err(StoreError::backend(
            "remove_org_membership not yet implemented for D1",
        ))
    }

    async fn list_org_memberships(&self, _org_id: &OrgId) -> StoreResult<Vec<OrgMemberRow>> {
        Err(StoreError::backend(
            "list_org_memberships not yet implemented for D1",
        ))
    }

    async fn create_database(
        &self,
        org_id: OrgId,
        name: String,
        created_by: UserId,
        now_ms: i64,
    ) -> StoreResult<Database> {
        let id = DatabaseId::new();
        let id_str = id.to_string();
        let org_str = org_id.to_string();
        let user_str = created_by.to_string();
        self.db
            .prepare(
                "INSERT INTO databases (id, org_id, name, created_by, created_at_ms) \
                 VALUES (?, ?, ?, ?, ?)",
            )
            .bind_refs(&[
                D1Type::Text(&id_str),
                D1Type::Text(&org_str),
                D1Type::Text(&name),
                D1Type::Text(&user_str),
                ms(now_ms),
            ])
            .map_err(d1_err)?
            .run()
            .into_send()
            .await
            .map_err(|e| {
                let s = e.to_string();
                if s.contains("UNIQUE") || s.contains("constraint") {
                    StoreError::already_exists(format!("database '{name}' in {org_id}"))
                } else {
                    StoreError::backend(s)
                }
            })?;
        Ok(Database {
            id,
            org_id,
            name,
            created_by,
            created_at_ms: now_ms,
        })
    }

    async fn get_database(&self, id: &DatabaseId) -> StoreResult<Option<Database>> {
        let stmt = self
            .db
            .prepare(
                "SELECT id, org_id, name, created_by, created_at_ms FROM databases WHERE id = ?",
            )
            .bind_refs(&[D1Type::Text(id.as_str())])
            .map_err(d1_err)?;
        let row: Option<DatabaseRow> = stmt.first(None).into_send().await.map_err(d1_err)?;
        Ok(row.map(Into::into))
    }

    async fn list_databases_for_org(&self, org_id: &OrgId) -> StoreResult<Vec<Database>> {
        let stmt = self
            .db
            .prepare(
                "SELECT id, org_id, name, created_by, created_at_ms FROM databases \
                 WHERE org_id = ? ORDER BY created_at_ms",
            )
            .bind_refs(&[D1Type::Text(org_id.as_str())])
            .map_err(d1_err)?;
        let result = stmt.all().into_send().await.map_err(d1_err)?;
        let rows: Vec<DatabaseRow> = result.results().map_err(d1_err)?;
        Ok(rows.into_iter().map(Into::into).collect())
    }

    async fn delete_database(&self, id: &DatabaseId) -> StoreResult<()> {
        let stmt = self
            .db
            .prepare("DELETE FROM databases WHERE id = ?")
            .bind_refs(&[D1Type::Text(id.as_str())])
            .map_err(d1_err)?;
        let result = stmt.run().into_send().await.map_err(d1_err)?;
        if result
            .meta()
            .map_err(d1_err)?
            .and_then(|m| m.changes)
            .unwrap_or(0)
            == 0
        {
            return Err(StoreError::not_found(format!("database {id}")));
        }
        Ok(())
    }

    async fn store_oauth_state(&self, state: OAuthState) -> StoreResult<()> {
        self.db
            .prepare(
                "INSERT INTO oauth_states (state, provider, created_at_ms, expires_at_ms) \
                 VALUES (?, ?, ?, ?)",
            )
            .bind_refs(&[
                D1Type::Text(&state.state),
                D1Type::Text(&state.provider),
                ms(state.created_at_ms),
                ms(state.expires_at_ms),
            ])
            .map_err(d1_err)?
            .run()
            .into_send()
            .await
            .map_err(d1_err)?;
        Ok(())
    }

    async fn consume_oauth_state(
        &self,
        state: &str,
        now_ms: i64,
    ) -> StoreResult<Option<OAuthState>> {
        // SQLite `DELETE … RETURNING` makes the lookup-and-consume atomic in
        // one round-trip: only one concurrent caller observes the row.
        let stmt = self
            .db
            .prepare(
                "DELETE FROM oauth_states WHERE state = ? \
                 RETURNING state, provider, created_at_ms, expires_at_ms",
            )
            .bind_refs(&[D1Type::Text(state)])
            .map_err(d1_err)?;
        let row: Option<OAuthStateRow> = stmt.first(None).into_send().await.map_err(d1_err)?;
        let Some(row) = row else { return Ok(None) };
        if row.expires_at_ms < now_ms {
            return Ok(None);
        }
        Ok(Some(row.into()))
    }
}

// =================== helpers ===================

fn d1_err(e: impl std::fmt::Display) -> StoreError {
    StoreError::backend(e.to_string())
}

/// `D1Type::Integer` is i32-only, but every timestamp we store is `i64`
/// milliseconds-since-epoch. JS numbers carry 53 bits of integer precision,
/// so `Real(x as f64)` round-trips losslessly for any plausible timestamp.
fn ms(x: i64) -> D1Type<'static> {
    D1Type::Real(x as f64)
}

async fn run_batch(db: &D1Database, stmts: Vec<D1PreparedStatement>) -> StoreResult<()> {
    db.batch(stmts)
        .into_send()
        .await
        .map_err(|e| StoreError::backend(format!("batch: {e}")))?;
    Ok(())
}

/// Run a batch and translate SQLite UNIQUE-constraint failures into a typed
/// `AlreadyExists` (built lazily by `on_unique`). Other errors stay as
/// `Backend`.
async fn run_batch_mapping_unique<F>(
    db: &D1Database,
    stmts: Vec<D1PreparedStatement>,
    on_unique: F,
) -> StoreResult<()>
where
    F: FnOnce() -> StoreError,
{
    db.batch(stmts).into_send().await.map_err(|e| {
        let s = e.to_string();
        if s.contains("UNIQUE") || s.contains("constraint") {
            on_unique()
        } else {
            StoreError::backend(format!("batch: {s}"))
        }
    })?;
    Ok(())
}

/// Strip whole-line comments and split on `;` for D1's `prepare().run()` —
/// our migration file mixes multi-line DDL that D1's `exec()` can't handle.
fn normalized_statements(sql: &str) -> Vec<String> {
    let mut out = Vec::new();
    for stmt in sql.split(';') {
        let cleaned: String = stmt
            .lines()
            .map(|l| l.trim())
            .filter(|l| !l.is_empty() && !l.starts_with("--"))
            .collect::<Vec<_>>()
            .join(" ");
        let cleaned = cleaned.trim().to_string();
        if !cleaned.is_empty() {
            out.push(cleaned);
        }
    }
    out
}
