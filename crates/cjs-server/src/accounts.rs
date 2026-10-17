//! Human authentication: argon2id passwords + mandatory TOTP, lockout.
use argon2::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use argon2::Argon2;
use cjs_audit::{Event, Outcome};
use cjs_authz::Role;
use cjs_proto::ErrorCode;
use totp_rs::{Algorithm, Secret, TOTP};

use cjs_audit::AuditLog;

use crate::db::{new_id, now, Db, User};
use crate::error::ApiError;

pub const MAX_FAILED_LOGINS: i64 = 5;
pub const LOCKOUT_SECS: i64 = 15 * 60;
pub const MIN_PASSWORD_LEN: usize = 12;

pub fn hash_password(pw: &str) -> Result<String, ApiError> {
    let salt = SaltString::generate(&mut rand::rngs::OsRng);
    Argon2::default()
        .hash_password(pw.as_bytes(), &salt)
        .map(|h| h.to_string())
        .map_err(|e| ApiError::internal(e.to_string()))
}

pub fn verify_password(pw: &str, hash: &str) -> bool {
    PasswordHash::new(hash)
        .map(|h| Argon2::default().verify_password(pw.as_bytes(), &h).is_ok())
        .unwrap_or(false)
}

pub fn random_password() -> String {
    use rand::Rng;
    const CHARS: &[u8] = b"ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789";
    let mut r = rand::rngs::OsRng;
    (0..20)
        .map(|_| CHARS[r.gen_range(0..CHARS.len())] as char)
        .collect()
}

pub fn new_totp_secret() -> String {
    Secret::generate_secret().to_encoded().to_string()
}

fn totp(secret_b32: &str, account: &str) -> Result<TOTP, ApiError> {
    let bytes = Secret::Encoded(secret_b32.to_string())
        .to_bytes()
        .map_err(|_| ApiError::internal("bad totp secret"))?;
    TOTP::new(
        Algorithm::SHA1,
        6,
        1,
        30,
        bytes,
        Some("ClawdJumpServer".into()),
        account.to_string(),
    )
    .map_err(|e| ApiError::internal(e.to_string()))
}

pub fn otpauth_url(secret_b32: &str, account: &str) -> String {
    totp(secret_b32, account).map(|t| t.get_url()).unwrap_or_default()
}

/// Current TOTP code (used by tests and the bootstrap helper).
pub fn current_code(secret_b32: &str) -> String {
    totp(secret_b32, "x")
        .map(|t| t.generate(now() as u64))
        .unwrap_or_default()
}

/// Check a TOTP code, allowing one step of clock skew. Returns the matched
/// time step, which must be newer than the last accepted one (no reuse).
pub fn check_totp(secret_b32: &str, code: &str, last_step: i64) -> Option<i64> {
    let t = totp(secret_b32, "x").ok()?;
    let step = now() / 30;
    for s in [step - 1, step, step + 1] {
        if s <= last_step {
            continue;
        }
        let expect = t.generate((s * 30) as u64);
        if subtle::ConstantTimeEq::ct_eq(expect.as_bytes(), code.trim().as_bytes()).into() {
            return Some(s);
        }
    }
    None
}

pub fn check_password_policy(pw: &str) -> Result<(), ApiError> {
    if pw.chars().count() < MIN_PASSWORD_LEN {
        return Err(ApiError::bad(format!(
            "password must be at least {MIN_PASSWORD_LEN} characters"
        )));
    }
    Ok(())
}

pub struct NewUser {
    pub user: User,
    pub password: String,
    pub totp_secret: String,
}

pub fn create_user(name: &str, roles: Vec<Role>, password: Option<String>) -> Result<NewUser, ApiError> {
    cjs_authz::validate_roles(&roles).map_err(ApiError::bad)?;
    if name.is_empty()
        || name.len() > 64
        || !name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "-_.@".contains(c))
    {
        return Err(ApiError::bad("user name must be 1-64 chars of [A-Za-z0-9-_.@]"));
    }
    let password = password.unwrap_or_else(random_password);
    check_password_policy(&password)?;
    let secret = new_totp_secret();
    Ok(NewUser {
        user: User {
            id: new_id("u"),
            name: name.into(),
            display_name: name.into(),
            password_hash: hash_password(&password)?,
            totp_secret: secret.clone(),
            roles,
            status: "active".into(),
            failed_logins: 0,
            locked_until: None,
            expires_at: None,
            last_login: None,
            last_ip: None,
            last_totp_step: 0,
            created_at: now(),
            groups: vec![],
        },
        password,
        totp_secret: secret,
    })
}

/// Full login check. Every outcome is audited; if the audit write fails
/// the login is refused.
pub fn login(
    db: &Db,
    audit: &AuditLog,
    name: &str,
    password: &str,
    code: &str,
    ip: Option<String>,
) -> Result<User, ApiError> {
    let invalid = || ApiError::unauth("invalid credentials");
    let audit_fail = |actor: &str, reason: &str| {
        audit
            .append(
                Event::new("auth.login", actor, "web", Outcome::Denied)
                    .ip(ip.clone())
                    .data(serde_json::json!({"user": name, "reason": reason})),
            )
            .map_err(ApiError::from)
    };
    let Some(mut u) = db.user(name)? else {
        // Equalise timing with a dummy verification.
        static DUMMY: std::sync::OnceLock<String> = std::sync::OnceLock::new();
        let dummy = DUMMY.get_or_init(|| hash_password("dummy-password-for-timing").unwrap_or_default());
        let _ = verify_password(password, dummy);
        audit_fail("anonymous", "unknown user")?;
        return Err(invalid());
    };
    let t = now();
    if let Err(why) = u.usable(t) {
        audit_fail(&u.id, why)?;
        return Err(ApiError::new(
            if why == "account locked" {
                ErrorCode::LimitExceeded
            } else {
                ErrorCode::Disabled
            },
            why,
        ));
    }
    let pw_ok = verify_password(password, &u.password_hash);
    let step = if pw_ok {
        check_totp(&u.totp_secret, code, u.last_totp_step)
    } else {
        None
    };
    match step {
        Some(step) => {
            audit.append(
                Event::new("auth.login", &u.id, "web", Outcome::Success)
                    .ip(ip.clone())
                    .data(serde_json::json!({"user": u.name, "mfa": "totp"})),
            )?;
            u.failed_logins = 0;
            u.locked_until = None;
            u.last_login = Some(t);
            u.last_ip = ip;
            u.last_totp_step = step;
            db.update_user(&u)?;
            Ok(u)
        }
        None => {
            u.failed_logins += 1;
            let reason = if pw_ok {
                "bad or reused totp code"
            } else {
                "bad password"
            };
            if u.failed_logins >= MAX_FAILED_LOGINS {
                u.locked_until = Some(t + LOCKOUT_SECS);
                u.failed_logins = 0;
                audit_fail(&u.id, &format!("{reason}; account locked for {LOCKOUT_SECS}s"))?;
            } else {
                audit_fail(&u.id, reason)?;
            }
            db.update_user(&u)?;
            Err(invalid())
        }
    }
}

pub fn sha256_hex(s: &str) -> String {
    use sha2::{Digest, Sha256};
    hex::encode(Sha256::digest(s.as_bytes()))
}

pub fn random_token(bytes: usize) -> String {
    use rand::RngCore;
    let mut b = vec![0u8; bytes];
    rand::rngs::OsRng.fill_bytes(&mut b);
    base64::Engine::encode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, b)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn password_roundtrip() {
        let h = hash_password("correct horse battery").unwrap();
        assert!(verify_password("correct horse battery", &h));
        assert!(!verify_password("wrong", &h));
    }

    #[test]
    fn totp_no_reuse() {
        let s = new_totp_secret();
        let c = current_code(&s);
        let step = check_totp(&s, &c, 0).unwrap();
        assert!(check_totp(&s, &c, step).is_none(), "code reuse must fail");
        assert!(check_totp(&s, "000000x", 0).is_none());
    }

    #[test]
    fn role_separation_on_create() {
        assert!(create_user("x", vec![Role::Secadmin, Role::Auditor], None).is_err());
        assert!(create_user("bad name", vec![], None).is_err());
        assert!(create_user("ok", vec![Role::Auditor], Some("short".into())).is_err());
    }
}
