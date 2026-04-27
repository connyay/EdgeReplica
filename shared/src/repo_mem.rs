//! In-memory implementation of [`Repo`]. Native unit tests run against
//! this; `D1Repo` (in the worker crate) is the wasm32 counterpart.

use std::collections::HashMap;
use std::sync::Mutex;

use crate::domain::{
    Database, DatabaseId, Identity, IdentityId, IdentityProvider, OAuthState, OrgId, OrgMembership,
    Organization, Role, User, UserId, entities::personal_org_name,
};
use crate::error::{StoreError, StoreResult};
use crate::repo::{NewOAuthUser, NewPasswordUser, OrgMemberRow, OrgWithRole, Repo};

#[derive(Default)]
struct State {
    users: HashMap<UserId, User>,
    identities: HashMap<IdentityId, Identity>,
    organizations: HashMap<OrgId, Organization>,
    org_memberships: HashMap<(UserId, OrgId), OrgMembership>,
    databases: HashMap<DatabaseId, Database>,
    oauth_states: HashMap<String, OAuthState>,
}

#[derive(Default)]
pub struct InMemoryRepo {
    inner: Mutex<State>,
}

impl InMemoryRepo {
    pub fn new() -> Self {
        Self::default()
    }
}

impl Repo for InMemoryRepo {
    async fn get_user(&self, id: &UserId) -> StoreResult<Option<User>> {
        let g = self.inner.lock().unwrap();
        Ok(g.users.get(id).cloned())
    }

    async fn get_user_by_email(&self, email: &str) -> StoreResult<Option<User>> {
        let g = self.inner.lock().unwrap();
        Ok(find_user_by_email(&g, email).cloned())
    }

    async fn list_identities(&self, user_id: &UserId) -> StoreResult<Vec<Identity>> {
        let g = self.inner.lock().unwrap();
        Ok(g.identities
            .values()
            .filter(|i| i.user_id == *user_id)
            .cloned()
            .collect())
    }

    async fn find_identity(
        &self,
        provider: &str,
        provider_user_id: &str,
    ) -> StoreResult<Option<Identity>> {
        let g = self.inner.lock().unwrap();
        Ok(g.identities
            .values()
            .find(|i| i.provider == provider && i.provider_user_id == provider_user_id)
            .cloned())
    }

    async fn link_identity(
        &self,
        user_id: &UserId,
        provider: &str,
        provider_user_id: &str,
        secret: Option<String>,
        now_ms: i64,
    ) -> StoreResult<Identity> {
        let mut g = self.inner.lock().unwrap();
        if let Some(existing) = g
            .identities
            .values()
            .find(|i| i.provider == provider && i.provider_user_id == provider_user_id)
            .cloned()
        {
            if existing.user_id != *user_id {
                return Err(StoreError::conflict(format!(
                    "identity {provider}:{provider_user_id} belongs to another user"
                )));
            }
            return Ok(existing);
        }
        let id = IdentityId::new();
        let identity = Identity {
            id: id.clone(),
            user_id: user_id.clone(),
            provider: provider.into(),
            provider_user_id: provider_user_id.into(),
            secret,
            created_at_ms: now_ms,
        };
        g.identities.insert(id, identity.clone());
        Ok(identity)
    }

    async fn update_identity_secret(
        &self,
        identity_id: &IdentityId,
        new_secret: String,
    ) -> StoreResult<()> {
        let mut g = self.inner.lock().unwrap();
        let identity = g
            .identities
            .get_mut(identity_id)
            .ok_or_else(|| StoreError::not_found(format!("identity {identity_id}")))?;
        identity.secret = Some(new_secret);
        Ok(())
    }

    async fn create_password_user(&self, input: NewPasswordUser, now_ms: i64) -> StoreResult<User> {
        let mut g = self.inner.lock().unwrap();
        if find_user_by_email(&g, &input.email).is_some() {
            return Err(StoreError::already_exists(format!(
                "user with email {}",
                input.email
            )));
        }
        let user_id = UserId::new();
        let user = User {
            id: user_id.clone(),
            email: input.email.clone(),
            email_verified: false,
            created_at_ms: now_ms,
        };
        g.users.insert(user_id.clone(), user.clone());

        let identity_id = IdentityId::new();
        g.identities.insert(
            identity_id.clone(),
            Identity {
                id: identity_id,
                user_id: user_id.clone(),
                provider: IdentityProvider::PASSWORD.into(),
                provider_user_id: user_id.to_string(),
                secret: Some(input.password_hash),
                created_at_ms: now_ms,
            },
        );

        insert_personal_org_under_lock(&mut g, &user_id, &input.email, now_ms);
        Ok(user)
    }

    async fn create_oauth_user(&self, input: NewOAuthUser, now_ms: i64) -> StoreResult<User> {
        let mut g = self.inner.lock().unwrap();
        if find_user_by_email(&g, &input.email).is_some() {
            return Err(StoreError::already_exists(format!(
                "user with email {}",
                input.email
            )));
        }
        let user_id = UserId::new();
        let user = User {
            id: user_id.clone(),
            email: input.email.clone(),
            // OAuth IdP already verified the email.
            email_verified: true,
            created_at_ms: now_ms,
        };
        g.users.insert(user_id.clone(), user.clone());

        let identity_id = IdentityId::new();
        g.identities.insert(
            identity_id.clone(),
            Identity {
                id: identity_id,
                user_id: user_id.clone(),
                provider: input.provider,
                provider_user_id: input.provider_user_id,
                secret: None,
                created_at_ms: now_ms,
            },
        );

        insert_personal_org_under_lock(&mut g, &user_id, &input.email, now_ms);
        Ok(user)
    }

    async fn get_organization(&self, id: &OrgId) -> StoreResult<Option<Organization>> {
        let g = self.inner.lock().unwrap();
        Ok(g.organizations.get(id).cloned())
    }

    async fn create_organization(
        &self,
        display_name: String,
        owner_user_id: UserId,
        now_ms: i64,
    ) -> StoreResult<Organization> {
        let mut g = self.inner.lock().unwrap();
        if !g.users.contains_key(&owner_user_id) {
            return Err(StoreError::not_found(format!("user {owner_user_id}")));
        }
        let id = OrgId::new();
        let org = Organization {
            id: id.clone(),
            display_name,
            personal: false,
            owner_user_id: Some(owner_user_id.clone()),
            created_at_ms: now_ms,
        };
        g.organizations.insert(id.clone(), org.clone());
        g.org_memberships.insert(
            (owner_user_id.clone(), id.clone()),
            OrgMembership {
                user_id: owner_user_id,
                org_id: id,
                role: Role::Admin,
                created_at_ms: now_ms,
            },
        );
        Ok(org)
    }

    async fn list_organizations_for_user(&self, user_id: &UserId) -> StoreResult<Vec<OrgWithRole>> {
        let g = self.inner.lock().unwrap();
        let mut out: Vec<OrgWithRole> = g
            .org_memberships
            .iter()
            .filter(|((u, _), _)| u == user_id)
            .filter_map(|((_, oid), m)| g.organizations.get(oid).cloned().map(|o| (o, m.role)))
            .collect();
        out.sort_by(|(a, _), (b, _)| a.id.as_str().cmp(b.id.as_str()));
        Ok(out)
    }

    async fn delete_organization(&self, id: &OrgId) -> StoreResult<()> {
        let mut g = self.inner.lock().unwrap();
        let org = g
            .organizations
            .get(id)
            .cloned()
            .ok_or_else(|| StoreError::not_found(format!("organization {id}")))?;
        if org.personal {
            return Err(StoreError::conflict(
                "personal organizations are deleted with the user",
            ));
        }
        if g.databases.values().any(|d| d.org_id == *id) {
            return Err(StoreError::conflict(
                "cannot delete organization: databases still attached",
            ));
        }
        g.organizations.remove(id);
        g.org_memberships.retain(|(_, oid), _| oid != id);
        Ok(())
    }

    async fn get_org_membership(
        &self,
        user_id: &UserId,
        org_id: &OrgId,
    ) -> StoreResult<Option<OrgMembership>> {
        let g = self.inner.lock().unwrap();
        Ok(g.org_memberships
            .get(&(user_id.clone(), org_id.clone()))
            .cloned())
    }

    async fn add_org_membership(
        &self,
        user_id: &UserId,
        org_id: &OrgId,
        role: Role,
        now_ms: i64,
    ) -> StoreResult<()> {
        let mut g = self.inner.lock().unwrap();
        let key = (user_id.clone(), org_id.clone());
        if g.org_memberships.contains_key(&key) {
            return Err(StoreError::already_exists(format!(
                "org membership {user_id} -> {org_id}"
            )));
        }
        g.org_memberships.insert(
            key,
            OrgMembership {
                user_id: user_id.clone(),
                org_id: org_id.clone(),
                role,
                created_at_ms: now_ms,
            },
        );
        Ok(())
    }

    async fn remove_org_membership(&self, user_id: &UserId, org_id: &OrgId) -> StoreResult<()> {
        let mut g = self.inner.lock().unwrap();
        let key = (user_id.clone(), org_id.clone());
        let existing = g
            .org_memberships
            .get(&key)
            .cloned()
            .ok_or_else(|| StoreError::not_found("org membership"))?;
        if existing.role == Role::Admin {
            let admin_count = g
                .org_memberships
                .values()
                .filter(|x| x.org_id == *org_id && x.role == Role::Admin)
                .count();
            if admin_count <= 1 {
                return Err(StoreError::conflict(
                    "cannot remove the last admin of an organization",
                ));
            }
        }
        g.org_memberships.remove(&key);
        Ok(())
    }

    async fn list_org_memberships(&self, org_id: &OrgId) -> StoreResult<Vec<OrgMemberRow>> {
        let g = self.inner.lock().unwrap();
        let mut out: Vec<OrgMemberRow> = g
            .org_memberships
            .iter()
            .filter(|(_, m)| m.org_id == *org_id)
            .filter_map(|((uid, _), m)| g.users.get(uid).cloned().map(|u| (m.clone(), u)))
            .collect();
        out.sort_by(|(a, _), (b, _)| a.user_id.as_str().cmp(b.user_id.as_str()));
        Ok(out)
    }

    async fn create_database(
        &self,
        org_id: OrgId,
        name: String,
        created_by: UserId,
        now_ms: i64,
    ) -> StoreResult<Database> {
        let mut g = self.inner.lock().unwrap();
        if !g.organizations.contains_key(&org_id) {
            return Err(StoreError::not_found(format!("organization {org_id}")));
        }
        if g.databases
            .values()
            .any(|d| d.org_id == org_id && d.name == name)
        {
            return Err(StoreError::already_exists(format!(
                "database '{name}' in {org_id}"
            )));
        }
        let id = DatabaseId::new();
        let db = Database {
            id: id.clone(),
            org_id,
            name,
            created_by,
            created_at_ms: now_ms,
        };
        g.databases.insert(id, db.clone());
        Ok(db)
    }

    async fn get_database(&self, id: &DatabaseId) -> StoreResult<Option<Database>> {
        let g = self.inner.lock().unwrap();
        Ok(g.databases.get(id).cloned())
    }

    async fn list_databases_for_org(&self, org_id: &OrgId) -> StoreResult<Vec<Database>> {
        let g = self.inner.lock().unwrap();
        let mut out: Vec<Database> = g
            .databases
            .values()
            .filter(|d| d.org_id == *org_id)
            .cloned()
            .collect();
        out.sort_by(|a, b| a.created_at_ms.cmp(&b.created_at_ms));
        Ok(out)
    }

    async fn delete_database(&self, id: &DatabaseId) -> StoreResult<()> {
        let mut g = self.inner.lock().unwrap();
        if g.databases.remove(id).is_none() {
            return Err(StoreError::not_found(format!("database {id}")));
        }
        Ok(())
    }

    async fn store_oauth_state(&self, state: OAuthState) -> StoreResult<()> {
        let mut g = self.inner.lock().unwrap();
        g.oauth_states.insert(state.state.clone(), state);
        Ok(())
    }

    async fn consume_oauth_state(
        &self,
        state: &str,
        now_ms: i64,
    ) -> StoreResult<Option<OAuthState>> {
        let mut g = self.inner.lock().unwrap();
        let Some(s) = g.oauth_states.remove(state) else {
            return Ok(None);
        };
        if s.expires_at_ms < now_ms {
            return Ok(None);
        }
        Ok(Some(s))
    }
}

fn find_user_by_email<'a>(g: &'a State, email: &str) -> Option<&'a User> {
    let needle = email.to_lowercase();
    g.users.values().find(|u| u.email.to_lowercase() == needle)
}

fn insert_personal_org_under_lock(g: &mut State, user_id: &UserId, email: &str, now_ms: i64) {
    let org_id = OrgId::new();
    g.organizations.insert(
        org_id.clone(),
        Organization {
            id: org_id.clone(),
            display_name: personal_org_name(email),
            personal: true,
            owner_user_id: Some(user_id.clone()),
            created_at_ms: now_ms,
        },
    );
    g.org_memberships.insert(
        (user_id.clone(), org_id.clone()),
        OrgMembership {
            user_id: user_id.clone(),
            org_id,
            role: Role::Admin,
            created_at_ms: now_ms,
        },
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures::executor::block_on;

    fn signup(repo: &InMemoryRepo, email: &str, ts: i64) -> User {
        block_on(repo.create_password_user(
            NewPasswordUser {
                email: email.into(),
                password_hash: "h".into(),
            },
            ts,
        ))
        .unwrap()
    }

    #[test]
    fn signup_creates_user_identity_and_personal_org() {
        let repo = InMemoryRepo::new();
        let user = signup(&repo, "ada@example.com", 1_000);
        assert_eq!(user.email, "ada@example.com");

        let identities = block_on(repo.list_identities(&user.id)).unwrap();
        assert_eq!(identities.len(), 1);
        assert_eq!(identities[0].provider, IdentityProvider::PASSWORD);

        let orgs = block_on(repo.list_organizations_for_user(&user.id)).unwrap();
        assert_eq!(orgs.len(), 1);
        assert!(orgs[0].0.personal);
        assert_eq!(orgs[0].1, Role::Admin);
    }

    #[test]
    fn duplicate_email_signup_rejected_case_insensitively() {
        let repo = InMemoryRepo::new();
        signup(&repo, "x@y", 1);
        let err = block_on(repo.create_password_user(
            NewPasswordUser {
                email: "X@Y".into(),
                password_hash: "h".into(),
            },
            1,
        ))
        .unwrap_err();
        assert!(matches!(err, StoreError::AlreadyExists(_)));
    }

    #[test]
    fn create_database_unique_name_per_org() {
        let repo = InMemoryRepo::new();
        let user = signup(&repo, "x@y", 1);
        let org = block_on(repo.create_organization("Acme".into(), user.id.clone(), 2)).unwrap();
        block_on(repo.create_database(org.id.clone(), "main".into(), user.id.clone(), 3)).unwrap();
        let err = block_on(repo.create_database(org.id.clone(), "main".into(), user.id.clone(), 4))
            .unwrap_err();
        assert!(matches!(err, StoreError::AlreadyExists(_)));
    }

    #[test]
    fn delete_org_refuses_personal() {
        let repo = InMemoryRepo::new();
        let user = signup(&repo, "x@y", 1);
        let orgs = block_on(repo.list_organizations_for_user(&user.id)).unwrap();
        let err = block_on(repo.delete_organization(&orgs[0].0.id)).unwrap_err();
        assert!(matches!(err, StoreError::Conflict(_)));
    }

    #[test]
    fn delete_org_refuses_when_databases_attached() {
        let repo = InMemoryRepo::new();
        let user = signup(&repo, "x@y", 1);
        let org = block_on(repo.create_organization("Acme".into(), user.id.clone(), 2)).unwrap();
        block_on(repo.create_database(org.id.clone(), "main".into(), user.id.clone(), 3)).unwrap();
        let err = block_on(repo.delete_organization(&org.id)).unwrap_err();
        assert!(matches!(err, StoreError::Conflict(_)));
    }

    #[test]
    fn cannot_remove_last_admin() {
        let repo = InMemoryRepo::new();
        let user = signup(&repo, "x@y", 1);
        let org = block_on(repo.create_organization("Acme".into(), user.id.clone(), 2)).unwrap();
        let err = block_on(repo.remove_org_membership(&user.id, &org.id)).unwrap_err();
        assert!(matches!(err, StoreError::Conflict(_)));
    }

    #[test]
    fn oauth_state_single_use_and_expiry() {
        let repo = InMemoryRepo::new();
        block_on(repo.store_oauth_state(OAuthState {
            state: "s1".into(),
            provider: "github".into(),
            created_at_ms: 100,
            expires_at_ms: 200,
        }))
        .unwrap();
        // First consume succeeds.
        assert!(
            block_on(repo.consume_oauth_state("s1", 150))
                .unwrap()
                .is_some()
        );
        // Second consume of the same state returns None.
        assert!(
            block_on(repo.consume_oauth_state("s1", 150))
                .unwrap()
                .is_none()
        );
        // Stale state returns None and is cleaned up.
        block_on(repo.store_oauth_state(OAuthState {
            state: "s2".into(),
            provider: "github".into(),
            created_at_ms: 100,
            expires_at_ms: 200,
        }))
        .unwrap();
        assert!(
            block_on(repo.consume_oauth_state("s2", 999))
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn create_oauth_user_links_identity() {
        let repo = InMemoryRepo::new();
        let user = block_on(repo.create_oauth_user(
            NewOAuthUser {
                email: "ada@gh".into(),
                provider: IdentityProvider::GITHUB.into(),
                provider_user_id: "12345".into(),
            },
            1,
        ))
        .unwrap();
        assert!(user.email_verified);
        let found = block_on(repo.find_identity(IdentityProvider::GITHUB, "12345"))
            .unwrap()
            .unwrap();
        assert_eq!(found.user_id, user.id);
    }
}
