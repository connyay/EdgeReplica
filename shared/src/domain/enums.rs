//! Enumerated domain values. Encoded as string constants on the wire and
//! parsed into typed enums at the service-handler boundary.

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Role {
    Admin,
    Member,
}

impl Role {
    pub fn as_str(&self) -> &'static str {
        match self {
            Role::Admin => "admin",
            Role::Member => "member",
        }
    }
}

impl fmt::Display for Role {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for Role {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "admin" => Ok(Role::Admin),
            "member" => Ok(Role::Member),
            other => Err(format!("unknown role: {other}")),
        }
    }
}

/// Sync direction. Encoded into the sync macaroon as a `direction=` caveat
/// so a push token can't accidentally drive a pull and vice versa.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Direction {
    Push,
    Pull,
}

impl Direction {
    pub fn as_str(&self) -> &'static str {
        match self {
            Direction::Push => "push",
            Direction::Pull => "pull",
        }
    }
}

impl fmt::Display for Direction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for Direction {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "push" => Ok(Direction::Push),
            "pull" => Ok(Direction::Pull),
            other => Err(format!("unknown direction: {other}")),
        }
    }
}

/// Identity provider tag stored on `identities.provider`.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum IdentityProvider {
    Password,
    GitHub,
    Google,
}

impl IdentityProvider {
    pub const PASSWORD: &'static str = "password";
    pub const GITHUB: &'static str = "github";
    pub const GOOGLE: &'static str = "google";

    pub fn as_str(&self) -> &'static str {
        match self {
            IdentityProvider::Password => Self::PASSWORD,
            IdentityProvider::GitHub => Self::GITHUB,
            IdentityProvider::Google => Self::GOOGLE,
        }
    }
}

impl fmt::Display for IdentityProvider {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for IdentityProvider {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            Self::PASSWORD => Ok(IdentityProvider::Password),
            Self::GITHUB => Ok(IdentityProvider::GitHub),
            Self::GOOGLE => Ok(IdentityProvider::Google),
            other => Err(format!("unknown identity provider: {other}")),
        }
    }
}

/// `purpose=` caveat values the workspace mints. Verification rejects a
/// token whose purpose doesn't match the expected one.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum TokenPurpose {
    Session,
    Sync,
}

impl TokenPurpose {
    pub fn as_str(&self) -> &'static str {
        match self {
            TokenPurpose::Session => "session",
            TokenPurpose::Sync => "sync",
        }
    }
}

impl fmt::Display for TokenPurpose {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn role_roundtrips() {
        assert_eq!(Role::Admin.as_str().parse::<Role>().unwrap(), Role::Admin);
        assert_eq!(Role::Member.as_str().parse::<Role>().unwrap(), Role::Member);
        assert!("owner".parse::<Role>().is_err());
    }

    #[test]
    fn direction_roundtrips() {
        assert_eq!("push".parse::<Direction>().unwrap(), Direction::Push);
        assert_eq!("pull".parse::<Direction>().unwrap(), Direction::Pull);
        assert!("sideways".parse::<Direction>().is_err());
    }

    #[test]
    fn identity_provider_roundtrips() {
        assert_eq!(
            "github".parse::<IdentityProvider>().unwrap(),
            IdentityProvider::GitHub
        );
        assert_eq!(
            "google".parse::<IdentityProvider>().unwrap(),
            IdentityProvider::Google
        );
        assert_eq!(
            "password".parse::<IdentityProvider>().unwrap(),
            IdentityProvider::Password
        );
    }
}
