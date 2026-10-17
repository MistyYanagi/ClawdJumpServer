//! Persistent client profile (server URL, pinned server key, identity) and
//! the enrollment flow shared by agents and devices.
use std::path::{Path, PathBuf};
use std::time::Duration;

use cjs_proto::{EnrollToken, ErrorCode, ProtoError, Role};
use serde::{Deserialize, Serialize};

use crate::client::{connect, new_hello, ClientConfig, TransportMode};
use crate::keys::{write_secret_file, StaticKeypair};

pub const PROFILE_FILE: &str = "profile.toml";
pub const KEY_FILE: &str = "identity.key";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Profile {
    /// `https://host[:port]/`
    pub server: String,
    /// Pinned server Noise key (hex).
    pub server_key: String,
    /// `auto`, `ws` or `http`.
    #[serde(default = "auto")]
    pub transport: String,
    /// Extra CA bundle for the outer TLS hop (PEM).
    #[serde(default)]
    pub ca: Option<PathBuf>,
    /// Principal id assigned by the server.
    #[serde(default)]
    pub id: String,
    #[serde(default)]
    pub name: String,
}

fn auto() -> String {
    "auto".into()
}

fn bad(m: impl Into<String>) -> ProtoError {
    ProtoError::new(ErrorCode::BadRequest, m)
}

impl Profile {
    pub fn load(dir: &Path) -> Result<Self, ProtoError> {
        let p = dir.join(PROFILE_FILE);
        let s = std::fs::read_to_string(&p).map_err(|e| {
            ProtoError::new(
                ErrorCode::NotFound,
                format!("{}: {e} (enroll first)", p.display()),
            )
        })?;
        toml::from_str(&s).map_err(|e| bad(format!("{}: {e}", p.display())))
    }

    pub fn save(&self, dir: &Path) -> Result<(), ProtoError> {
        std::fs::create_dir_all(dir).map_err(|e| ProtoError::new(ErrorCode::Io, e.to_string()))?;
        restrict_dir(dir);
        let s = toml::to_string_pretty(self).map_err(|e| bad(e.to_string()))?;
        write_secret_file(&dir.join(PROFILE_FILE), s.as_bytes())
    }

    pub fn key(dir: &Path) -> Result<StaticKeypair, ProtoError> {
        StaticKeypair::load(&dir.join(KEY_FILE))
    }

    pub fn client_config(&self, key: StaticKeypair) -> Result<ClientConfig, ProtoError> {
        let server_key: [u8; 32] = hex::decode(&self.server_key)
            .ok()
            .and_then(|b| b.try_into().ok())
            .ok_or_else(|| bad("bad server_key in profile"))?;
        Ok(ClientConfig {
            server: self
                .server
                .parse()
                .map_err(|e| bad(format!("bad server url: {e}")))?,
            server_key,
            key,
            mode: self.transport.parse().map_err(bad)?,
            extra_ca: self.ca.clone(),
        })
    }
}

/// Best effort: make a config directory private to the current user.
pub fn restrict_dir(dir: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700));
    }
    #[cfg(not(unix))]
    {
        let _ = dir;
    }
}

/// Enroll this machine: create the identity key, redeem the one-time token
/// and store the profile in `dir`.
pub async fn enroll(
    dir: &Path,
    role: Role,
    server: &str,
    token: &str,
    mode: TransportMode,
    ca: Option<PathBuf>,
    version: &str,
) -> Result<Profile, ProtoError> {
    let tok = EnrollToken::parse(token)?;
    // Store an absolute CA path: the daemon may run from another directory.
    let ca = match ca {
        Some(p) => Some(std::fs::canonicalize(&p).map_err(|e| bad(format!("{}: {e}", p.display())))?),
        None => None,
    };
    std::fs::create_dir_all(dir).map_err(|e| ProtoError::new(ErrorCode::Io, e.to_string()))?;
    restrict_dir(dir);
    let key = StaticKeypair::load_or_create(&dir.join(KEY_FILE))?;
    let mut server = server.trim().to_string();
    if !server.ends_with('/') {
        server.push('/');
    }
    let mut profile = Profile {
        server,
        server_key: hex::encode(tok.server_key),
        transport: match mode {
            TransportMode::Auto => "auto",
            TransportMode::Ws => "ws",
            TransportMode::Http => "http",
        }
        .into(),
        ca,
        id: String::new(),
        name: String::new(),
    };
    let cfg = profile.client_config(key)?;
    let conn = tokio::time::timeout(
        Duration::from_secs(60),
        connect(&cfg, new_hello(role, Some(tok.secret), version)),
    )
    .await
    .map_err(|_| ProtoError::new(ErrorCode::Timeout, "enrollment timed out"))??;
    profile.id = conn.welcome.principal_id.clone();
    profile.name = conn.welcome.name.clone();
    conn.handle
        .close(ProtoError::new(ErrorCode::Cancelled, "enrolled"));
    profile.save(dir)?;
    Ok(profile)
}
