//! `signup`, `login`, `whoami` subcommands. Hit AdminService unary RPCs
//! and persist the resulting session token in the local config.

use anyhow::{Context, Result};
use clap::Args;
use edgereplica_protocol::admin::v1::{LoginRequest, SignupRequest, WhoamiRequest};

use crate::config::{Config, resolve_secret};
use crate::transport;

#[derive(Args, Debug)]
pub struct SignupArgs {
    pub email: String,
    /// Reads from `EDGEREPLICA_PASSWORD` if not supplied, keeping the
    /// password out of shell history.
    #[arg(long)]
    pub password: Option<String>,
}

#[derive(Args, Debug)]
pub struct LoginArgs {
    pub email: String,
    #[arg(long)]
    pub password: Option<String>,
}

pub async fn signup(args: SignupArgs, mut config: Config) -> Result<()> {
    let password = resolve_secret(args.password, "EDGEREPLICA_PASSWORD", "password")?;
    let client = transport::admin_client(&config.server)?;
    let resp = client
        .signup(SignupRequest {
            email: args.email.clone(),
            password,
            ..Default::default()
        })
        .await
        .context("signup rpc")?
        .into_owned();
    config.session_token = Some(resp.session_token);
    config.save()?;
    println!("signup ok ({})", args.email);
    Ok(())
}

pub async fn login(args: LoginArgs, mut config: Config) -> Result<()> {
    let password = resolve_secret(args.password, "EDGEREPLICA_PASSWORD", "password")?;
    let client = transport::admin_client(&config.server)?;
    let resp = client
        .login(LoginRequest {
            email: args.email.clone(),
            password,
            ..Default::default()
        })
        .await
        .context("login rpc")?
        .into_owned();
    config.session_token = Some(resp.session_token);
    config.save()?;
    println!("login ok ({})", args.email);
    Ok(())
}

pub async fn whoami(config: Config) -> Result<()> {
    let (client, opts) = transport::authed_admin_client(&config)?;
    let mut resp = client
        .whoami_with_options(WhoamiRequest::default(), opts)
        .await
        .context("whoami rpc")?
        .into_owned();
    let info = resp
        .whoami
        .take()
        .ok_or_else(|| anyhow::anyhow!("server returned empty whoami"))?;
    println!("user_id: {}", info.user_id);
    println!("email:   {}", info.email);
    println!("org_id:  {}", info.org_id);
    println!("role:    {}", info.role);
    Ok(())
}
