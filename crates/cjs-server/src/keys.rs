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

/// Make a key file readable only by its owner (also fixes files created
/// with looser permissions or by an older version). Errors propagate.
pub fn restrict_key_file(path: &Path) -> Result<(), ApiError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
            .map_err(|e| ApiError::internal(format!("{}: {e}", path.display())))?;
    }
    #[cfg(not(unix))]
    let _ = path;
    Ok(())
}

fn ed_load(path: &Path) -> Result<SigningKey, ApiError> {
    let s =
        std::fs::read_to_string(path).map_err(|e| ApiError::internal(format!("{}: {e}", path.display())))?;
    let b = hex::decode(s.trim()).map_err(|_| ApiError::internal(format!("{}: bad key", path.display())))?;
    let b: [u8; 32] = b
        .try_into()
        .map_err(|_| ApiError::internal(format!("{}: bad key length", path.display())))?;
    Ok(SigningKey::from_bytes(&b))
}

fn ed_load_or_create(path: &Path) -> Result<SigningKey, ApiError> {
    if path.exists() {
        restrict_key_file(path)?;
        return ed_load(path);
    }
    let k = SigningKey::generate(&mut rand::rngs::OsRng);
    write_secret_file(path, hex::encode(k.to_bytes()).as_bytes())?;
    restrict_key_file(path)?;
    Ok(k)
}

fn must_exist(path: &Path) -> Result<(), ApiError> {
    if path.exists() {
        Ok(())
    } else {
        Err(ApiError::new(
            cjs_proto::ErrorCode::NotFound,
            format!(
                "{} is missing; refusing to create a new key (run `cjs-server init`, or restore the key)",
                path.display()
            ),
        ))
    }
}

/// Load the audit checkpoint key without ever creating one. Verification
/// with a freshly generated key would be meaningless, so a missing key is
/// an error.
pub fn load_audit_key(dir: &Path) -> Result<SigningKey, ApiError> {
    let p = dir.join(AUDIT_KEY_FILE);
    must_exist(&p)?;
    ed_load(&p)
}

impl Keys {
    /// Load all keys; error (instead of creating new ones) when any is
    /// missing. Used by read-only commands (`info`, `audit-verify`).
    pub fn load_existing(dir: &Path) -> Result<Self, ApiError> {
        let noise = dir.join(NOISE_KEY_FILE);
        let cap = dir.join(CAP_KEY_FILE);
        must_exist(&noise)?;
        must_exist(&cap)?;
        Ok(Self {
            noise: StaticKeypair::load(&noise)?,
            cap: ed_load(&cap)?,
            audit: load_audit_key(dir)?,
        })
    }

    pub fn load_or_create(dir: &Path) -> Result<Self, ApiError> {
        std::fs::create_dir_all(dir).map_err(|e| ApiError::internal(e.to_string()))?;
        let noise = StaticKeypair::load_or_create(&dir.join(NOISE_KEY_FILE))?;
        restrict_key_file(&dir.join(NOISE_KEY_FILE))?;
        Ok(Self {
            noise,
            cap: ed_load_or_create(&dir.join(CAP_KEY_FILE))?,
            audit: ed_load_or_create(&dir.join(AUDIT_KEY_FILE))?,
        })
    }

    /// Fingerprint of the audit checkpoint public key, printed at start so
    /// operators can pin it out of band.
    pub fn audit_fingerprint(&self) -> String {
        cjs_audit::key_fingerprint(&self.audit.verifying_key())
    }

    pub fn generate() -> Self {
        Self {
            noise: StaticKeypair::generate(),
            cap: SigningKey::generate(&mut rand::rngs::OsRng),
            audit: SigningKey::generate(&mut rand::rngs::OsRng),
        }
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn key_files_are_0600_even_if_preexisting_loose() {
        let d = tempfile::tempdir().unwrap();
        Keys::load_or_create(d.path()).unwrap();
        for f in [NOISE_KEY_FILE, CAP_KEY_FILE, AUDIT_KEY_FILE] {
            let p = d.path().join(f);
            std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o644)).unwrap();
        }
        Keys::load_or_create(d.path()).unwrap();
        for f in [NOISE_KEY_FILE, CAP_KEY_FILE, AUDIT_KEY_FILE] {
            let m = std::fs::metadata(d.path().join(f)).unwrap().permissions().mode() & 0o777;
            assert_eq!(m, 0o600, "{f}");
        }
    }
}

#[cfg(test)]
mod verify_tests {
    use super::*;

    #[test]
    fn verify_paths_never_create_keys() {
        let d = tempfile::tempdir().unwrap();
        assert!(Keys::load_existing(d.path()).is_err());
        assert!(load_audit_key(d.path()).is_err());
        assert!(!d.path().join(AUDIT_KEY_FILE).exists(), "no key may be created");
        let k = Keys::load_or_create(d.path()).unwrap();
        let e = Keys::load_existing(d.path()).unwrap();
        assert_eq!(k.audit.to_bytes(), e.audit.to_bytes());
        std::fs::remove_file(d.path().join(AUDIT_KEY_FILE)).unwrap();
        assert!(Keys::load_existing(d.path()).is_err());
        assert!(!d.path().join(AUDIT_KEY_FILE).exists());
    }
}
