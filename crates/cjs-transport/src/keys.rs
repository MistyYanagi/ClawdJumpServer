//! Static X25519 Noise keys. A client's static public key is its identity.
use std::path::Path;

use cjs_proto::{ErrorCode, ProtoError, NOISE_PARAMS};

#[derive(Clone)]
pub struct StaticKeypair {
    pub private: [u8; 32],
    pub public: [u8; 32],
}

impl std::fmt::Debug for StaticKeypair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "StaticKeypair({})", hex::encode(self.public))
    }
}

impl StaticKeypair {
    pub fn generate() -> Self {
        let b = snow::Builder::new(NOISE_PARAMS.parse().expect("valid noise params"));
        let kp = b.generate_keypair().expect("keypair generation");
        let mut private = [0u8; 32];
        let mut public = [0u8; 32];
        private.copy_from_slice(&kp.private);
        public.copy_from_slice(&kp.public);
        Self { private, public }
    }

    /// Rebuild from a private key (derives the public key).
    pub fn from_private(private: [u8; 32]) -> Self {
        let public = x25519_public(&private);
        Self { private, public }
    }

    /// Short fingerprint for display: first 16 hex chars of the public key.
    pub fn fingerprint(&self) -> String {
        fingerprint(&self.public)
    }

    /// Load from a hex file, or create it (mode 0600) when missing.
    pub fn load_or_create(path: &Path) -> Result<Self, ProtoError> {
        if path.exists() {
            return Self::load(path);
        }
        let kp = Self::generate();
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir).map_err(io)?;
        }
        write_secret_file(path, hex::encode(kp.private).as_bytes())?;
        Ok(kp)
    }

    pub fn load(path: &Path) -> Result<Self, ProtoError> {
        let s = std::fs::read_to_string(path).map_err(io)?;
        let b = hex::decode(s.trim()).map_err(|_| ProtoError::new(ErrorCode::BadRequest, "bad key file"))?;
        let private: [u8; 32] = b
            .try_into()
            .map_err(|_| ProtoError::new(ErrorCode::BadRequest, "bad key length"))?;
        Ok(Self::from_private(private))
    }
}

pub fn fingerprint(public: &[u8; 32]) -> String {
    hex::encode(&public[..8])
}

fn io(e: std::io::Error) -> ProtoError {
    ProtoError::new(ErrorCode::Io, e.to_string())
}

/// Write a file readable only by the current user.
pub fn write_secret_file(path: &Path, data: &[u8]) -> Result<(), ProtoError> {
    use std::io::Write;
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut f = opts.open(path).map_err(io)?;
    f.write_all(data).map_err(io)
}

fn x25519_public(private: &[u8; 32]) -> [u8; 32] {
    use snow::params::DHChoice;
    use snow::resolvers::{CryptoResolver, DefaultResolver};
    let mut dh = DefaultResolver
        .resolve_dh(&DHChoice::Curve25519)
        .expect("curve25519 available");
    dh.set(private);
    let mut out = [0u8; 32];
    out.copy_from_slice(dh.pubkey());
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn public_derivation_matches() {
        let kp = StaticKeypair::generate();
        assert_eq!(StaticKeypair::from_private(kp.private).public, kp.public);
    }
}
