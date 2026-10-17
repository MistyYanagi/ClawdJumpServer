//! Server key material: the Noise static key (server identity pinned by
//! clients), the Ed25519 capability-signing key and the Ed25519 audit
//! checkpoint key. Each lives in its own 0600 file under the data dir.
use std::path::Path;

use cjs_transport::keys::write_secret_file;
use cjs_transport::StaticKeypair;
use ed25519_dalek::SigningKey;

use crate::error::ApiError;

pub struct Keys {
    pub noise: StaticKeypair,
    pub cap: SigningKey,
    pub audit: SigningKey,
}

impl std::fmt::Debug for Keys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Keys").field("noise", &self.noise).finish()
    }
}

pub const NOISE_KEY_FILE: &str = "noise.key";
pub const CAP_KEY_FILE: &str = "capability.key";
pub const AUDIT_KEY_FILE: &str = "audit.key";

fn ed_load_or_create(path: &Path) -> Result<SigningKey, ApiError> {
    if path.exists() {
        let s = std::fs::read_to_string(path)
            .map_err(|e| ApiError::internal(format!("{}: {e}", path.display())))?;
        let b =
            hex::decode(s.trim()).map_err(|_| ApiError::internal(format!("{}: bad key", path.display())))?;
        let b: [u8; 32] = b
            .try_into()
            .map_err(|_| ApiError::internal(format!("{}: bad key length", path.display())))?;
        return Ok(SigningKey::from_bytes(&b));
    }
    let k = SigningKey::generate(&mut rand::rngs::OsRng);
    write_secret_file(path, hex::encode(k.to_bytes()).as_bytes())?;
    Ok(k)
}

impl Keys {
    pub fn load_or_create(dir: &Path) -> Result<Self, ApiError> {
        std::fs::create_dir_all(dir).map_err(|e| ApiError::internal(e.to_string()))?;
        Ok(Self {
            noise: StaticKeypair::load_or_create(&dir.join(NOISE_KEY_FILE))?,
            cap: ed_load_or_create(&dir.join(CAP_KEY_FILE))?,
            audit: ed_load_or_create(&dir.join(AUDIT_KEY_FILE))?,
        })
    }

    pub fn generate() -> Self {
        Self {
            noise: StaticKeypair::generate(),
            cap: SigningKey::generate(&mut rand::rngs::OsRng),
            audit: SigningKey::generate(&mut rand::rngs::OsRng),
        }
    }
}
