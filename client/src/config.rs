//! Persistent CLI config: server URL + cached session token. Lives at
//! `~/.config/edgereplica/config.toml` (XDG-style).

use std::path::PathBuf;

use anyhow::{Context, Result, anyhow};
use serde::{Deserialize, Serialize};

const DEFAULT_SERVER: &str = "http://localhost:8787";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub server: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_token: Option<String>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            server: DEFAULT_SERVER.into(),
            session_token: None,
        }
    }
}

impl Config {
    pub fn load() -> Result<Self> {
        let path = config_path()?;
        if !path.exists() {
            return Ok(Self::default());
        }
        let text =
            std::fs::read_to_string(&path).with_context(|| format!("read {}", path.display()))?;
        toml::from_str(&text).with_context(|| format!("parse {}", path.display()))
    }

    pub fn save(&self) -> Result<()> {
        let path = config_path()?;
        let dir = path
            .parent()
            .ok_or_else(|| anyhow!("config path has no parent"))?;
        std::fs::create_dir_all(dir).with_context(|| format!("mkdir {}", dir.display()))?;
        let text = toml::to_string_pretty(self).context("serialize config")?;
        std::fs::write(&path, text).with_context(|| format!("write {}", path.display()))
    }

    pub fn require_session(&self) -> Result<&str> {
        self.session_token
            .as_deref()
            .ok_or_else(|| anyhow!("no session token; run `edgereplica login` first"))
    }
}

fn config_path() -> Result<PathBuf> {
    let dir = dirs::config_dir().ok_or_else(|| anyhow!("no config dir; set $XDG_CONFIG_HOME"))?;
    Ok(dir.join("edgereplica").join("config.toml"))
}

/// Resolve a CLI secret from `--flag` arg or fall back to an env var.
pub fn resolve_secret(arg: Option<String>, env_var: &str, flag_name: &str) -> Result<String> {
    arg.or_else(|| std::env::var(env_var).ok())
        .ok_or_else(|| anyhow!("{flag_name} not provided (use --{flag_name} or set {env_var})"))
}
