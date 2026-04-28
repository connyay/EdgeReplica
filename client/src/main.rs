//! `edgereplica` CLI entrypoint. clap dispatches to the per-feature
//! subcommand modules; every command loads the user's config from
//! `~/.config/edgereplica/config.toml` first.

use anyhow::Result;
use clap::{Parser, Subcommand};

use crate::config::Config;

mod auth_cmd;
mod config;
mod db_cmd;
mod pages;
mod sync_cmd;
mod sync_ws;
mod transport;

#[derive(Parser, Debug)]
#[command(name = "edgereplica", about = "EdgeReplica SQLite page sync client")]
struct Cli {
    /// Override the server URL. Falls back to the config file, then
    /// `http://localhost:8787`.
    #[arg(long, global = true)]
    server: Option<String>,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    Signup(auth_cmd::SignupArgs),
    Login(auth_cmd::LoginArgs),
    Whoami,
    /// Manage databases registered for this account.
    #[command(subcommand)]
    Db(DbCmd),
    /// Run a sync flow.
    #[command(subcommand)]
    Sync(SyncCmd),
    /// OAuth login (currently GitHub).
    #[command(subcommand)]
    Oauth(OAuthCmd),
}

#[derive(Subcommand, Debug)]
enum DbCmd {
    Create(db_cmd::CreateArgs),
    List,
    Delete(db_cmd::DeleteArgs),
    /// Issue a short-lived sync token for a database.
    Token(db_cmd::TokenArgs),
}

#[derive(Subcommand, Debug)]
enum SyncCmd {
    Push(sync_cmd::PushArgs),
    Pull(sync_cmd::PullArgs),
}

#[derive(Subcommand, Debug)]
enum OAuthCmd {
    /// Print the IdP authorize URL to open in a browser.
    Start(auth_cmd::OAuthStartArgs),
    /// Exchange the state+code shown by the callback page for a session.
    Complete(auth_cmd::OAuthCompleteArgs),
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    let mut config = Config::load()?;
    if let Some(server) = cli.server {
        config.server = server;
    }

    match cli.command {
        Command::Signup(args) => auth_cmd::signup(args, config).await,
        Command::Login(args) => auth_cmd::login(args, config).await,
        Command::Whoami => auth_cmd::whoami(config).await,
        Command::Db(DbCmd::Create(args)) => db_cmd::create(args, config).await,
        Command::Db(DbCmd::List) => db_cmd::list(config).await,
        Command::Db(DbCmd::Delete(args)) => db_cmd::delete(args, config).await,
        Command::Db(DbCmd::Token(args)) => db_cmd::token(args, config).await,
        Command::Sync(SyncCmd::Push(args)) => sync_cmd::push(args, config).await,
        Command::Sync(SyncCmd::Pull(args)) => sync_cmd::pull(args, config).await,
        Command::Oauth(OAuthCmd::Start(args)) => auth_cmd::oauth_start(args, config).await,
        Command::Oauth(OAuthCmd::Complete(args)) => auth_cmd::oauth_complete(args, config).await,
    }
}
