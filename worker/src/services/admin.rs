//! `AdminService` implementation: whoami, signup, login, OAuth, database
//! CRUD, sync-token issuance. Lives in the worker (talks D1). Sessions
//! carry caveats `purpose=session`, `user`, `email`, `org`, `role`, `exp`.
//! OAuth start/complete return `Unimplemented` until configured.

use buffa::view::OwnedView;
use connectrpc::{ConnectError, Context as RpcContext};
use edgereplica_protocol::admin::v1 as pb;

use crate::auth::{
    MintSessionInput, MintSyncInput, hash_new_password, mint_session, mint_sync, verify_password,
};
#[cfg(target_arch = "wasm32")]
use crate::domain::OAuthState;
use crate::domain::{Database, DatabaseId, Direction, IdentityProvider, Organization, Role, User};
#[cfg(target_arch = "wasm32")]
use crate::repo::NewOAuthUser;
use crate::repo::{NewPasswordUser, Repo};

use crate::middleware::require_session;
use crate::services::common::{
    map_password_error, map_store_error, map_token_error, validate_database_name, validate_email,
};
use crate::state::SharedState;

pub struct AdminServer<R: Repo> {
    state: SharedState<R>,
}

impl<R: Repo> AdminServer<R> {
    pub fn new(state: SharedState<R>) -> Self {
        Self { state }
    }
}

impl<R: Repo> AdminServer<R> {
    /// Mint a session token rooted on `user`'s first personal org.
    async fn issue_session_for(
        &self,
        user: &User,
    ) -> Result<(String, Organization, Role), ConnectError> {
        let orgs = self
            .state
            .repo
            .list_organizations_for_user(&user.id)
            .await
            .map_err(map_store_error)?;
        let (org, role) = orgs
            .into_iter()
            .find(|(o, _)| o.personal)
            .ok_or_else(|| ConnectError::internal("personal org missing for user"))?;
        let now_unix = self.state.clock.now_unix_seconds();
        let token = mint_session(
            &self.state.keyring,
            MintSessionInput {
                user_id: &user.id,
                email: &user.email,
                org: &org.id,
                role,
                now_unix,
                ttl_seconds: self.state.config.session_ttl_seconds,
            },
        )
        .map_err(map_token_error)?;
        Ok((token, org, role))
    }
}

fn whoami_pb(user: &User, org: &Organization, role: Role) -> pb::WhoamiInfo {
    pb::WhoamiInfo {
        user_id: user.id.to_string(),
        email: user.email.clone(),
        org_id: org.id.to_string(),
        role: role.as_str().to_owned(),
        ..Default::default()
    }
}

fn database_pb(db: &Database) -> pb::Database {
    pb::Database {
        id: db.id.to_string(),
        org_id: db.org_id.to_string(),
        name: db.name.clone(),
        created_at_unix: db.created_at_ms / 1000,
        ..Default::default()
    }
}

impl<R: Repo> pb::AdminService for AdminServer<R> {
    async fn whoami(
        &self,
        ctx: RpcContext,
        _request: OwnedView<pb::WhoamiRequestView<'static>>,
    ) -> Result<(pb::WhoamiResponse, RpcContext), ConnectError> {
        let session = require_session(&ctx)?;
        let (user_res, org_res) = futures::join!(
            self.state.repo.get_user(&session.user),
            self.state.repo.get_organization(&session.org),
        );
        let user = user_res
            .map_err(map_store_error)?
            .ok_or_else(|| ConnectError::unauthenticated("session user no longer exists"))?;
        let org = org_res
            .map_err(map_store_error)?
            .ok_or_else(|| ConnectError::failed_precondition("session org no longer exists"))?;
        Ok((
            pb::WhoamiResponse {
                whoami: buffa::MessageField::some(whoami_pb(&user, &org, session.role)),
                ..Default::default()
            },
            ctx,
        ))
    }

    async fn signup(
        &self,
        ctx: RpcContext,
        request: OwnedView<pb::SignupRequestView<'static>>,
    ) -> Result<(pb::AuthResponse, RpcContext), ConnectError> {
        validate_email(request.email)?;
        let now_ms = self.state.clock.now_ms();

        let password_hash = hash_new_password(request.password)
            .await
            .map_err(map_password_error)?;

        let user = self
            .state
            .repo
            .create_password_user(
                NewPasswordUser {
                    email: request.email.to_owned(),
                    password_hash,
                },
                now_ms,
            )
            .await
            .map_err(map_store_error)?;

        let (token, org, role) = self.issue_session_for(&user).await?;
        Ok((
            pb::AuthResponse {
                session_token: token,
                whoami: buffa::MessageField::some(whoami_pb(&user, &org, role)),
                ..Default::default()
            },
            ctx,
        ))
    }

    async fn login(
        &self,
        ctx: RpcContext,
        request: OwnedView<pb::LoginRequestView<'static>>,
    ) -> Result<(pb::AuthResponse, RpcContext), ConnectError> {
        let user = self
            .state
            .repo
            .get_user_by_email(request.email)
            .await
            .map_err(map_store_error)?
            .ok_or_else(|| ConnectError::unauthenticated("invalid credentials"))?;

        let identities = self
            .state
            .repo
            .list_identities(&user.id)
            .await
            .map_err(map_store_error)?;
        let password_identity = identities
            .into_iter()
            .find(|i| i.provider == IdentityProvider::PASSWORD)
            .ok_or_else(|| ConnectError::unauthenticated("invalid credentials"))?;
        let stored = password_identity
            .secret
            .as_deref()
            .ok_or_else(|| ConnectError::internal("password identity missing secret"))?;
        verify_password(stored, request.password).map_err(map_password_error)?;

        let (token, org, role) = self.issue_session_for(&user).await?;
        Ok((
            pb::AuthResponse {
                session_token: token,
                whoami: buffa::MessageField::some(whoami_pb(&user, &org, role)),
                ..Default::default()
            },
            ctx,
        ))
    }

    async fn start_o_auth(
        &self,
        ctx: RpcContext,
        request: OwnedView<pb::StartOAuthRequestView<'static>>,
    ) -> Result<(pb::StartOAuthResponse, RpcContext), ConnectError> {
        let resp = oauth_start_impl(self, request.provider).await?;
        Ok((resp, ctx))
    }

    async fn complete_o_auth(
        &self,
        ctx: RpcContext,
        request: OwnedView<pb::CompleteOAuthRequestView<'static>>,
    ) -> Result<(pb::AuthResponse, RpcContext), ConnectError> {
        let resp = oauth_complete_impl(self, request.state, request.code).await?;
        Ok((resp, ctx))
    }

    async fn create_database(
        &self,
        ctx: RpcContext,
        request: OwnedView<pb::CreateDatabaseRequestView<'static>>,
    ) -> Result<(pb::Database, RpcContext), ConnectError> {
        let session = require_session(&ctx)?;
        if session.role != Role::Admin {
            return Err(ConnectError::permission_denied(
                "admin role required to create a database",
            ));
        }
        validate_database_name(request.name)?;
        let now_ms = self.state.clock.now_ms();
        let db = self
            .state
            .repo
            .create_database(
                session.org.clone(),
                request.name.trim().to_owned(),
                session.user.clone(),
                now_ms,
            )
            .await
            .map_err(map_store_error)?;
        Ok((database_pb(&db), ctx))
    }

    async fn list_databases(
        &self,
        ctx: RpcContext,
        _request: OwnedView<pb::ListDatabasesRequestView<'static>>,
    ) -> Result<(pb::ListDatabasesResponse, RpcContext), ConnectError> {
        let session = require_session(&ctx)?;
        let dbs = self
            .state
            .repo
            .list_databases_for_org(&session.org)
            .await
            .map_err(map_store_error)?;
        Ok((
            pb::ListDatabasesResponse {
                databases: dbs.iter().map(database_pb).collect(),
                ..Default::default()
            },
            ctx,
        ))
    }

    async fn delete_database(
        &self,
        ctx: RpcContext,
        request: OwnedView<pb::DeleteDatabaseRequestView<'static>>,
    ) -> Result<(pb::DeleteDatabaseResponse, RpcContext), ConnectError> {
        let session = require_session(&ctx)?;
        if session.role != Role::Admin {
            return Err(ConnectError::permission_denied(
                "admin role required to delete a database",
            ));
        }
        let id = DatabaseId::from(request.database_id);
        let db = self
            .state
            .repo
            .get_database(&id)
            .await
            .map_err(map_store_error)?
            .ok_or_else(|| ConnectError::not_found("database not found"))?;
        if db.org_id != session.org {
            return Err(ConnectError::permission_denied(
                "database belongs to another organization",
            ));
        }
        self.state
            .repo
            .delete_database(&id)
            .await
            .map_err(map_store_error)?;
        Ok((pb::DeleteDatabaseResponse::default(), ctx))
    }

    async fn issue_sync_token(
        &self,
        ctx: RpcContext,
        request: OwnedView<pb::IssueSyncTokenRequestView<'static>>,
    ) -> Result<(pb::IssueSyncTokenResponse, RpcContext), ConnectError> {
        let session = require_session(&ctx)?;
        let id = DatabaseId::from(request.database_id);
        let db = self
            .state
            .repo
            .get_database(&id)
            .await
            .map_err(map_store_error)?
            .ok_or_else(|| ConnectError::not_found("database not found"))?;
        if db.org_id != session.org {
            return Err(ConnectError::permission_denied(
                "database belongs to another organization",
            ));
        }

        let direction = match request.direction.as_known() {
            Some(pb::Direction::DIRECTION_PUSH) => Direction::Push,
            Some(pb::Direction::DIRECTION_PULL) => Direction::Pull,
            _ => {
                return Err(ConnectError::invalid_argument(
                    "direction must be DIRECTION_PUSH or DIRECTION_PULL",
                ));
            }
        };

        let cfg = &self.state.config;
        let ttl = if request.ttl_seconds <= 0 {
            cfg.sync_token_ttl_seconds
        } else {
            request.ttl_seconds.min(cfg.max_sync_token_ttl_seconds)
        };
        let now_unix = self.state.clock.now_unix_seconds();

        let token = mint_sync(
            &self.state.keyring,
            MintSyncInput {
                user_id: &session.user,
                org: &session.org,
                database: &db.id,
                direction,
                now_unix,
                ttl_seconds: ttl,
            },
        )
        .map_err(map_token_error)?;

        Ok((
            pb::IssueSyncTokenResponse {
                token,
                exp_unix: now_unix + ttl,
                ..Default::default()
            },
            ctx,
        ))
    }
}

#[cfg(target_arch = "wasm32")]
async fn oauth_start_impl<R: Repo>(
    server: &AdminServer<R>,
    provider: &str,
) -> Result<pb::StartOAuthResponse, ConnectError> {
    use crate::services::oauth;

    let provider: IdentityProvider = provider.parse().map_err(|_| {
        ConnectError::invalid_argument(format!("unknown oauth provider `{provider}`"))
    })?;
    match provider {
        IdentityProvider::GitHub => {}
        IdentityProvider::Google | IdentityProvider::Password => {
            return Err(ConnectError::unimplemented(format!(
                "oauth provider `{provider}` not supported"
            )));
        }
    }
    let (client_id, _) = oauth::github_credentials(&server.state.config).ok_or_else(|| {
        ConnectError::unimplemented("github oauth not configured on this deployment")
    })?;
    let redirect_uri = oauth_redirect_uri(&server.state.config, provider.as_str())?;

    let state = generate_state();
    let now_ms = server.state.clock.now_ms();
    let ttl_ms = server
        .state
        .config
        .oauth_state_ttl_seconds
        .saturating_mul(1_000);
    server
        .state
        .repo
        .store_oauth_state(OAuthState {
            state: state.clone(),
            provider: provider.to_string(),
            created_at_ms: now_ms,
            expires_at_ms: now_ms + ttl_ms,
        })
        .await
        .map_err(map_store_error)?;

    let redirect_url = oauth::github_authorize_url(client_id, &redirect_uri, &state);
    Ok(pb::StartOAuthResponse {
        redirect_url,
        state,
        ..Default::default()
    })
}

#[cfg(not(target_arch = "wasm32"))]
async fn oauth_start_impl<R: Repo>(
    _server: &AdminServer<R>,
    _provider: &str,
) -> Result<pb::StartOAuthResponse, ConnectError> {
    Err(ConnectError::unimplemented(
        "OAuth requires the wasm32 worker runtime",
    ))
}

#[cfg(target_arch = "wasm32")]
async fn oauth_complete_impl<R: Repo>(
    server: &AdminServer<R>,
    state: &str,
    code: &str,
) -> Result<pb::AuthResponse, ConnectError> {
    use crate::services::oauth;

    let now_ms = server.state.clock.now_ms();
    let stored = server
        .state
        .repo
        .consume_oauth_state(state, now_ms)
        .await
        .map_err(map_store_error)?
        .ok_or_else(|| ConnectError::permission_denied("invalid or expired oauth state"))?;

    let provider: IdentityProvider = stored.provider.parse().map_err(|_| {
        ConnectError::internal(format!(
            "stored oauth state has unknown provider `{}`",
            stored.provider
        ))
    })?;
    match provider {
        IdentityProvider::GitHub => {}
        IdentityProvider::Google | IdentityProvider::Password => {
            return Err(ConnectError::unimplemented(format!(
                "oauth provider `{provider}` not supported"
            )));
        }
    }
    let redirect_uri = oauth_redirect_uri(&server.state.config, provider.as_str())?;
    let identity = oauth::complete_github(&server.state.config, code, &redirect_uri).await?;

    let existing = server
        .state
        .repo
        .find_identity(identity.provider.as_str(), &identity.provider_user_id)
        .await
        .map_err(map_store_error)?;

    let user = match existing {
        Some(ident) => server
            .state
            .repo
            .get_user(&ident.user_id)
            .await
            .map_err(map_store_error)?
            .ok_or_else(|| ConnectError::internal("oauth identity points at missing user"))?,
        None => server
            .state
            .repo
            .create_oauth_user(
                NewOAuthUser {
                    email: identity.email,
                    provider: identity.provider.to_string(),
                    provider_user_id: identity.provider_user_id,
                },
                now_ms,
            )
            .await
            .map_err(map_store_error)?,
    };

    let (token, _org, _role) = server.issue_session_for(&user).await?;
    Ok(pb::AuthResponse {
        session_token: token,
        ..Default::default()
    })
}

#[cfg(not(target_arch = "wasm32"))]
async fn oauth_complete_impl<R: Repo>(
    _server: &AdminServer<R>,
    _state: &str,
    _code: &str,
) -> Result<pb::AuthResponse, ConnectError> {
    Err(ConnectError::unimplemented(
        "OAuth requires the wasm32 worker runtime",
    ))
}

#[cfg(target_arch = "wasm32")]
fn oauth_redirect_uri(
    config: &crate::state::Config,
    provider: &str,
) -> Result<String, ConnectError> {
    if config.oauth_redirect_base.trim().is_empty() {
        return Err(ConnectError::unimplemented(
            "OAUTH_REDIRECT_BASE not set on this deployment",
        ));
    }
    let base = config.oauth_redirect_base.trim_end_matches('/');
    Ok(format!("{base}/oauth/{provider}/callback"))
}

#[cfg(target_arch = "wasm32")]
fn generate_state() -> String {
    let mut buf = [0u8; 16];
    getrandom::getrandom(&mut buf).expect("getrandom is wired");
    hex::encode(buf)
}

#[cfg(test)]
mod tests {
    //! High-level handler tests against `InMemoryRepo`, mirroring the
    //! pattern in example-multitenant-worker. These exercise the same
    //! handler code that runs against D1 under wasm.

    use super::*;
    use crate::auth::{Keyring, SessionContext, verify_session, verify_sync};
    use crate::clock::{SharedClock, SystemClock};
    use crate::repo_mem::InMemoryRepo;
    use buffa::MessageView;
    use buffa::view::OwnedView;
    use connectrpc::Context as RpcContext;
    use edgereplica_protocol::admin::v1::AdminService;
    use futures::executor::block_on;
    use std::sync::Arc;

    use crate::state::{AppState, Config};

    fn build_state() -> SharedState<InMemoryRepo> {
        let keyring = Arc::new(Keyring::dev_default());
        let clock: SharedClock = Arc::new(SystemClock::new());
        Arc::new(AppState {
            repo: InMemoryRepo::new(),
            keyring,
            clock,
            config: Config::default(),
        })
    }

    fn view<V>(msg: &V::Owned) -> OwnedView<V>
    where
        V: MessageView<'static>,
        V::Owned: buffa::Message,
    {
        OwnedView::<V>::from_owned(msg).expect("build view")
    }

    fn ctx_with(session: SessionContext) -> RpcContext {
        let mut ctx = RpcContext::default();
        ctx.extensions.insert(session);
        ctx
    }

    fn signup(server: &AdminServer<InMemoryRepo>, email: &str, password: &str) -> String {
        let req = pb::SignupRequest {
            email: email.into(),
            password: password.into(),
            ..Default::default()
        };
        let (resp, _) = block_on(server.signup(RpcContext::default(), view(&req))).unwrap();
        resp.session_token
    }

    fn parse_session(token: &str, kr: &Keyring, clock: &SharedClock) -> SessionContext {
        verify_session(kr, clock.now_unix_seconds(), token).unwrap()
    }

    #[test]
    fn signup_then_login_round_trip() {
        let state = build_state();
        let server = AdminServer::new(Arc::clone(&state));
        let token = signup(&server, "ada@example.com", "correct horse staple");

        let req = pb::LoginRequest {
            email: "ada@example.com".into(),
            password: "correct horse staple".into(),
            ..Default::default()
        };
        let (resp, _) = block_on(server.login(RpcContext::default(), view(&req))).unwrap();
        assert!(!resp.session_token.is_empty());

        let session = parse_session(&token, &state.keyring, &state.clock);
        assert_eq!(session.email, "ada@example.com");
        assert_eq!(session.role, Role::Admin);
    }

    #[test]
    fn login_rejects_wrong_password() {
        let state = build_state();
        let server = AdminServer::new(Arc::clone(&state));
        signup(&server, "x@y", "right-password");
        let req = pb::LoginRequest {
            email: "x@y".into(),
            password: "wrong-password".into(),
            ..Default::default()
        };
        let err = block_on(server.login(RpcContext::default(), view(&req))).unwrap_err();
        assert_eq!(err.code, connectrpc::ErrorCode::Unauthenticated);
    }

    #[test]
    fn whoami_returns_session_org_and_role() {
        let state = build_state();
        let server = AdminServer::new(Arc::clone(&state));
        let token = signup(&server, "ada@example.com", "verylong-password");
        let session = parse_session(&token, &state.keyring, &state.clock);

        let (resp, _) = block_on(server.whoami(
            ctx_with(session.clone()),
            view(&pb::WhoamiRequest::default()),
        ))
        .unwrap();
        let info = resp.whoami.into_option().unwrap();
        assert_eq!(info.email, "ada@example.com");
        assert_eq!(info.org_id, session.org.to_string());
        assert_eq!(info.role, "admin");
    }

    #[test]
    fn whoami_requires_session() {
        let state = build_state();
        let server = AdminServer::new(Arc::clone(&state));
        let err =
            block_on(server.whoami(RpcContext::default(), view(&pb::WhoamiRequest::default())))
                .unwrap_err();
        assert_eq!(err.code, connectrpc::ErrorCode::Unauthenticated);
    }

    #[test]
    fn create_database_and_list_and_delete() {
        let state = build_state();
        let server = AdminServer::new(Arc::clone(&state));
        let token = signup(&server, "x@y", "verylong-password");
        let session = parse_session(&token, &state.keyring, &state.clock);

        let create_req = pb::CreateDatabaseRequest {
            name: "main".into(),
            ..Default::default()
        };
        let (created, _) =
            block_on(server.create_database(ctx_with(session.clone()), view(&create_req))).unwrap();
        assert_eq!(created.name, "main");

        let (list, _) = block_on(server.list_databases(
            ctx_with(session.clone()),
            view(&pb::ListDatabasesRequest::default()),
        ))
        .unwrap();
        assert_eq!(list.databases.len(), 1);
        assert_eq!(list.databases[0].id, created.id);

        let del_req = pb::DeleteDatabaseRequest {
            database_id: created.id.clone(),
            ..Default::default()
        };
        block_on(server.delete_database(ctx_with(session.clone()), view(&del_req))).unwrap();

        let (list_after, _) = block_on(server.list_databases(
            ctx_with(session),
            view(&pb::ListDatabasesRequest::default()),
        ))
        .unwrap();
        assert_eq!(list_after.databases.len(), 0);
    }

    #[test]
    fn create_database_validates_name() {
        let state = build_state();
        let server = AdminServer::new(Arc::clone(&state));
        let token = signup(&server, "x@y", "verylong-password");
        let session = parse_session(&token, &state.keyring, &state.clock);
        let req = pb::CreateDatabaseRequest {
            name: "bad name with spaces".into(),
            ..Default::default()
        };
        let err = block_on(server.create_database(ctx_with(session), view(&req))).unwrap_err();
        assert_eq!(err.code, connectrpc::ErrorCode::InvalidArgument);
    }

    #[test]
    fn issue_sync_token_returns_verifiable_token() {
        let state = build_state();
        let server = AdminServer::new(Arc::clone(&state));
        let token = signup(&server, "x@y", "verylong-password");
        let session = parse_session(&token, &state.keyring, &state.clock);

        let create_req = pb::CreateDatabaseRequest {
            name: "main".into(),
            ..Default::default()
        };
        let (db, _) =
            block_on(server.create_database(ctx_with(session.clone()), view(&create_req))).unwrap();

        let req = pb::IssueSyncTokenRequest {
            database_id: db.id.clone(),
            direction: buffa::EnumValue::Known(pb::Direction::DIRECTION_PUSH),
            ttl_seconds: 60,
            ..Default::default()
        };
        let (resp, _) =
            block_on(server.issue_sync_token(ctx_with(session.clone()), view(&req))).unwrap();
        assert!(!resp.token.is_empty());

        let verified =
            verify_sync(&state.keyring, state.clock.now_unix_seconds(), &resp.token).unwrap();
        assert_eq!(verified.user, session.user);
        assert_eq!(verified.org, session.org);
        assert_eq!(verified.database.to_string(), db.id);
        assert_eq!(verified.direction, Direction::Push);
    }

    #[test]
    fn issue_sync_token_caps_ttl_at_max() {
        let state = build_state();
        let server = AdminServer::new(Arc::clone(&state));
        let token = signup(&server, "x@y", "verylong-password");
        let session = parse_session(&token, &state.keyring, &state.clock);
        let create_req = pb::CreateDatabaseRequest {
            name: "main".into(),
            ..Default::default()
        };
        let (db, _) =
            block_on(server.create_database(ctx_with(session.clone()), view(&create_req))).unwrap();

        // Request a wildly excessive ttl; expect the cap.
        let req = pb::IssueSyncTokenRequest {
            database_id: db.id.clone(),
            direction: buffa::EnumValue::Known(pb::Direction::DIRECTION_PULL),
            ttl_seconds: 365 * 24 * 3600,
            ..Default::default()
        };
        let (resp, _) = block_on(server.issue_sync_token(ctx_with(session), view(&req))).unwrap();
        let now = state.clock.now_unix_seconds();
        assert!(resp.exp_unix - now <= state.config.max_sync_token_ttl_seconds);
    }
}
