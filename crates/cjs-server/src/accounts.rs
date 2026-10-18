//! Human authentication: argon2id passwords + mandatory TOTP, lockout.
use argon2::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use argon2::Argon2;
use cjs_audit::{Event, Outcome};
use cjs_authz::Role;
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

/// TOTP code for a given 30-second time step (tests and tooling).
pub fn code_for_step(secret_b32: &str, step: i64) -> String {
    totp(secret_b32, "x")
        .map(|t| t.generate((step * 30) as u64))
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

fn dummy_hash() -> &'static str {
    static DUMMY: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    DUMMY.get_or_init(|| hash_password("dummy-password-for-timing").unwrap_or_default())
}

/// Do the same argon2 work as a real check, so early refusals (unknown,
/// disabled, expired, locked) take as long as a wrong password.
fn burn(password: &str) {
    let _ = verify_password(password, dummy_hash());
}

/// Check the password and TOTP code of an existing user.
///
/// The attempt is counted toward the lockout *before* anything is verified,
/// so concurrent guesses cannot exceed [`MAX_FAILED_LOGINS`]. On success the
/// TOTP step is claimed atomically (a code works once, even concurrently)
/// and the failure counter is cleared. The inner `Err` is the real reason,
/// meant only for the audit log.
pub fn check_credentials(
    db: &Db,
    u: &User,
    password: &str,
    code: &str,
) -> Result<Result<(), String>, ApiError> {
    let t = now();
    if let Err(why) = u.usable(t) {
        burn(password);
        return Ok(Err(why.into()));
    }
    let Some(locks) = db.reserve_login_attempt(&u.id, t, MAX_FAILED_LOGINS, LOCKOUT_SECS)? else {
        burn(password);
        return Ok(Err("account locked".into()));
    };
    let note = if locks {
        format!("; account locked for {LOCKOUT_SECS}s")
    } else {
        String::new()
    };
    if !verify_password(password, &u.password_hash) {
        return Ok(Err(format!("bad password{note}")));
    }
    let Some(step) = check_totp(&u.totp_secret, code, u.last_totp_step) else {
        return Ok(Err(format!("bad or reused totp code{note}")));
    };
    if !db.claim_login(u, step)? {
        return Ok(Err(format!(
            "totp code already used or account changed concurrently{note}"
        )));
    }
    Ok(Ok(()))
}

/// Full login check. Every outcome is audited; if the audit write fails
/// the login is refused. Unknown, disabled, expired and locked accounts get
/// the same answer as a wrong password; the reason is only audited.
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
    let Some(u) = db.user(name)? else {
        burn(password);
        audit_fail("anonymous", "unknown user")?;
        return Err(invalid());
    };
    if let Err(reason) = check_credentials(db, &u, password, code)? {
        audit_fail(&u.id, &reason)?;
        return Err(invalid());
    }
    audit.append(
        Event::new("auth.login", &u.id, "web", Outcome::Success)
            .ip(ip.clone())
            .data(serde_json::json!({"user": u.name, "mfa": "totp"})),
    )?;
    db.record_login(&u.id, now(), ip.as_deref())?;
    db.user(&u.id)?.ok_or_else(invalid)
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

    const PW: &str = "correct horse battery";

    fn setup() -> (std::sync::Arc<Db>, std::sync::Arc<AuditLog>, String) {
        let db = Db::open_in_memory().unwrap();
        let audit = AuditLog::open_in_memory(ed25519_dalek::SigningKey::from_bytes(&[7u8; 32])).unwrap();
        let nu = create_user("victim", vec![], Some(PW.into())).unwrap();
        db.insert_user(&nu.user).unwrap();
        (
            std::sync::Arc::new(db),
            std::sync::Arc::new(audit),
            nu.totp_secret,
        )
    }

    /// M1: one TOTP code logs in once, even with concurrent requests.
    #[test]
    fn totp_code_accepted_once_under_concurrency() {
        let (db, audit, secret) = setup();
        let code = current_code(&secret);
        let hs: Vec<_> = (0..6)
            .map(|_| {
                let (db, audit, code) = (db.clone(), audit.clone(), code.clone());
                std::thread::spawn(move || login(&db, &audit, "victim", PW, &code, None).is_ok())
            })
            .collect();
        let ok = hs.into_iter().map(|h| h.join().unwrap()).filter(|x| *x).count();
        assert_eq!(ok, 1);
    }

    /// M3: concurrent guessing cannot evaluate more than MAX_FAILED_LOGINS
    /// passwords before the lock.
    #[test]
    fn lockout_bounds_concurrent_guesses() {
        let (db, _audit, _) = setup();
        let evaluated = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let hs: Vec<_> = (0..8)
            .map(|_| {
                let (db, evaluated) = (db.clone(), evaluated.clone());
                std::thread::spawn(move || {
                    for _ in 0..4 {
                        let u = db.user("victim").unwrap().unwrap();
                        if let Err(r) = check_credentials(&db, &u, "wrong-password-xx", "000000").unwrap() {
                            if r.starts_with("bad password") {
                                evaluated.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                            }
                        }
                    }
                })
            })
            .collect();
        for h in hs {
            h.join().unwrap();
        }
        assert_eq!(
            evaluated.load(std::sync::atomic::Ordering::SeqCst),
            MAX_FAILED_LOGINS as usize
        );
        let u = db.user("victim").unwrap().unwrap();
        assert!(u.locked_until.is_some());
    }

    /// M2: a login racing an administrative disable/reset cannot write the
    /// old row back.
    #[test]
    fn login_does_not_revert_concurrent_admin_change() {
        let (db, audit, secret) = setup();
        let u = db.user("victim").unwrap().unwrap();
        // The admin disables and resets while a login holds the old snapshot.
        db.patch_user(
            &u.id,
            &crate::db::UserPatch {
                status: Some("disabled"),
                ..Default::default()
            },
            now(),
        )
        .unwrap();
        db.reset_credentials(&u.id, &hash_password("admin-reset-password-1").unwrap(), &secret)
            .unwrap();
        let code = current_code(&secret);
        assert!(check_credentials(&db, &u, PW, &code).unwrap().is_err());
        let _ = login(&db, &audit, "victim", "wrong-password-xx", "0", None);
        let after = db.user("victim").unwrap().unwrap();
        assert_eq!(after.status, "disabled");
        assert!(!verify_password(PW, &after.password_hash));
    }

    /// M5: unknown, locked and disabled accounts look like a wrong password.
    #[test]
    fn no_user_enumeration() {
        let (db, audit, secret) = setup();
        let unknown = login(&db, &audit, "nobody", "x", "0", None).unwrap_err();
        for _ in 0..MAX_FAILED_LOGINS {
            let _ = login(&db, &audit, "victim", "wrong-password-xx", "000000", None);
        }
        let locked = login(&db, &audit, "victim", PW, &current_code(&secret), None).unwrap_err();
        let id = db.user("victim").unwrap().unwrap().id;
        db.unlock_user(&id).unwrap();
        db.patch_user(
            &id,
            &crate::db::UserPatch {
                status: Some("disabled"),
                ..Default::default()
            },
            now(),
        )
        .unwrap();
        let disabled = login(&db, &audit, "victim", PW, &current_code(&secret), None).unwrap_err();
        for e in [&unknown, &locked, &disabled] {
            assert_eq!(e.code, cjs_proto::ErrorCode::Unauthenticated);
            assert_eq!(e.message, "invalid credentials");
        }
    }
}
