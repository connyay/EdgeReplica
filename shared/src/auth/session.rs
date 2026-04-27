//! Verified session/sync contexts inserted into request extensions by the
//! worker's auth middleware. Handlers read them via
//! `ctx.extensions.get::<SessionContext>()` (or `SyncContext`).

use crate::domain::{DatabaseId, Direction, OrgId, Role, UserId};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SessionContext {
    pub user: UserId,
    pub email: String,
    pub org: OrgId,
    pub role: Role,
    pub exp_unix: i64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SyncContext {
    pub user: UserId,
    pub org: OrgId,
    pub database: DatabaseId,
    pub direction: Direction,
    pub exp_unix: i64,
}
