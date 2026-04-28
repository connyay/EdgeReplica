//! `db` subcommands: create, list, delete, issue-token. Require a session.

use anyhow::{Context, Result};
use clap::Args;
use edgereplica_protocol::admin::v1::{
    CreateDatabaseRequest, DeleteDatabaseRequest, Direction as PbDirection, IssueSyncTokenRequest,
    ListDatabasesRequest,
};

use crate::config::Config;
use crate::transport;

#[derive(Args, Debug)]
pub struct CreateArgs {
    pub name: String,
}

#[derive(Args, Debug)]
pub struct DeleteArgs {
    pub database_id: String,
}

#[derive(Args, Debug)]
pub struct TokenArgs {
    pub database_id: String,
    /// Direction the token authorizes: push (client → DO) or pull (DO → client).
    #[arg(long)]
    pub direction: TokenDirection,
    /// Optional override for the issued TTL (capped server-side).
    #[arg(long)]
    pub ttl_seconds: Option<i64>,
}

#[derive(Clone, Copy, Debug, clap::ValueEnum)]
pub enum TokenDirection {
    Push,
    Pull,
}

impl From<TokenDirection> for PbDirection {
    fn from(d: TokenDirection) -> Self {
        match d {
            TokenDirection::Push => PbDirection::DIRECTION_PUSH,
            TokenDirection::Pull => PbDirection::DIRECTION_PULL,
        }
    }
}

pub async fn create(args: CreateArgs, config: Config) -> Result<()> {
    let (client, opts) = transport::authed_admin_client(&config)?;
    let resp = client
        .create_database_with_options(
            CreateDatabaseRequest {
                name: args.name.clone(),
                ..Default::default()
            },
            opts,
        )
        .await
        .context("create_database rpc")?
        .into_owned();
    println!("{}\t{}", resp.id, resp.name);
    Ok(())
}

pub async fn list(config: Config) -> Result<()> {
    let (client, opts) = transport::authed_admin_client(&config)?;
    let resp = client
        .list_databases_with_options(ListDatabasesRequest::default(), opts)
        .await
        .context("list_databases rpc")?
        .into_owned();
    if resp.databases.is_empty() {
        println!("(no databases)");
        return Ok(());
    }
    for db in resp.databases {
        println!("{}\t{}", db.id, db.name);
    }
    Ok(())
}

pub async fn delete(args: DeleteArgs, config: Config) -> Result<()> {
    let (client, opts) = transport::authed_admin_client(&config)?;
    client
        .delete_database_with_options(
            DeleteDatabaseRequest {
                database_id: args.database_id.clone(),
                ..Default::default()
            },
            opts,
        )
        .await
        .context("delete_database rpc")?;
    println!("deleted {}", args.database_id);
    Ok(())
}

pub async fn token(args: TokenArgs, config: Config) -> Result<()> {
    let (client, opts) = transport::authed_admin_client(&config)?;
    let resp = client
        .issue_sync_token_with_options(
            IssueSyncTokenRequest {
                database_id: args.database_id.clone(),
                direction: PbDirection::from(args.direction).into(),
                ttl_seconds: args.ttl_seconds.unwrap_or(0),
                ..Default::default()
            },
            opts,
        )
        .await
        .context("issue_sync_token rpc")?
        .into_owned();
    // Token on stdout, expiry on stderr — lets shell pipelines capture
    // just the token: `T=$(edgereplica db token ...)`.
    eprintln!("# expires at unix {}", resp.exp_unix);
    println!("{}", resp.token);
    Ok(())
}
