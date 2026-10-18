//! SQLite storage for accounts, assets, grants and approvals.
use std::path::Path;
use std::sync::Mutex;

use cjs_authz::{ApprovalStatus, FullAccess, Grant, Role, RoleChange};
use rusqlite::{params, Connection, OptionalExtension, Row, Transaction, TransactionBehavior};
use serde::{Deserialize, Serialize};

use crate::error::ApiError;

const SCHEMA: &[&str] = &[
    r#"
CREATE TABLE users (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    display_name TEXT NOT NULL DEFAULT '',
    password_hash TEXT NOT NULL,
    totp_secret TEXT NOT NULL,
    roles TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL DEFAULT 'active',
    failed_logins INTEGER NOT NULL DEFAULT 0,
    locked_until INTEGER,
    expires_at INTEGER,
    last_login INTEGER,
    last_ip TEXT,
    last_totp_step INTEGER NOT NULL DEFAULT 0,
    created_at INTEGER NOT NULL
);
CREATE TABLE agents (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    owner_id TEXT NOT NULL REFERENCES users(id),
    pubkey TEXT NOT NULL UNIQUE,
    status TEXT NOT NULL DEFAULT 'active',
    expires_at INTEGER,
    info TEXT NOT NULL DEFAULT '{}',
    last_seen INTEGER,
    created_at INTEGER NOT NULL
);
CREATE TABLE devices (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    pubkey TEXT NOT NULL UNIQUE,
    status TEXT NOT NULL DEFAULT 'active',
    info TEXT NOT NULL DEFAULT '{}',
    last_seen INTEGER,
    created_at INTEGER NOT NULL
);
CREATE TABLE groups (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    kind TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    created_at INTEGER NOT NULL
);
CREATE TABLE group_members (
    group_id TEXT NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
    member_id TEXT NOT NULL,
    PRIMARY KEY (group_id, member_id)
);
CREATE TABLE enroll_tokens (
    id TEXT PRIMARY KEY,
    secret_hash TEXT NOT NULL UNIQUE,
    kind TEXT NOT NULL,
    name TEXT NOT NULL,
    owner_id TEXT,
    created_by TEXT NOT NULL,
    expires_at INTEGER NOT NULL,
    used_at INTEGER,
    used_by TEXT,
    created_at INTEGER NOT NULL
);
CREATE TABLE grants (
    id TEXT PRIMARY KEY,
    body TEXT NOT NULL,
    created_by TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
);
CREATE TABLE full_access (
    id TEXT PRIMARY KEY,
    body TEXT NOT NULL,
    created_at INTEGER NOT NULL
);
CREATE TABLE web_sessions (
    token_hash TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    csrf TEXT NOT NULL,
    ip TEXT,
    created_at INTEGER NOT NULL,
    last_seen INTEGER NOT NULL
);
CREATE TABLE settings (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
"#,
    r#"
CREATE TABLE role_changes (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    status TEXT NOT NULL DEFAULT 'pending',
    body TEXT NOT NULL,
    created_at INTEGER NOT NULL
);
CREATE INDEX role_changes_status ON role_changes(status);
CREATE TABLE revoked_keys (
    pubkey TEXT PRIMARY KEY,
    principal TEXT NOT NULL,
    revoked_at INTEGER NOT NULL
);
"#,
];

pub fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

pub fn new_id(prefix: &str) -> String {
    use rand::RngCore;
    let mut b = [0u8; 8];
    rand::rngs::OsRng.fill_bytes(&mut b);
    format!("{prefix}_{}", hex::encode(b))
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct User {
    pub id: String,
    pub name: String,
    pub display_name: String,
    #[serde(skip)]
    pub password_hash: String,
    #[serde(skip)]
    pub totp_secret: String,
    pub roles: Vec<Role>,
    pub status: String,
    pub failed_logins: i64,
    pub locked_until: Option<i64>,
    pub expires_at: Option<i64>,
    pub last_login: Option<i64>,
    pub last_ip: Option<String>,
    #[serde(skip)]
    pub last_totp_step: i64,
    pub created_at: i64,
    #[serde(default)]
    pub groups: Vec<String>,
}

impl User {
    pub fn has(&self, r: Role) -> bool {
        self.roles.contains(&r)
    }

    /// Usable for a new login = enabled, not expired, not locked.
    pub fn usable(&self, now: i64) -> Result<(), &'static str> {
        self.active(now)?;
        if self.locked_until.map(|l| now < l).unwrap_or(false) {
            return Err("account locked");
        }
        Ok(())
    }

    /// Enabled and not expired. A login lockout only blocks new logins, so
    /// existing sessions only need this.
    pub fn active(&self, now: i64) -> Result<(), &'static str> {
        if self.status != "active" {
            return Err("account disabled");
        }
        if self.expires_at.map(|e| now >= e).unwrap_or(false) {
            return Err("account expired");
        }
        Ok(())
    }

    fn holds(&self, r: Role, now: i64) -> bool {
        self.has(r) && self.active(now).is_ok()
    }

    fn apply(&mut self, p: &UserPatch) {
        if let Some(s) = p.status {
            self.status = s.into();
        }
        if let Some(r) = p.roles {
            self.roles = r.to_vec();
        }
        if let Some(d) = p.display_name {
            self.display_name = d.into();
        }
        if let Some(e) = p.expires_at {
            self.expires_at = e;
        }
    }
}

/// Column changes an administrator can make to a user.
#[derive(Debug, Default, Clone)]
pub struct UserPatch<'a> {
    pub status: Option<&'a str>,
    pub roles: Option<&'a [Role]>,
    pub display_name: Option<&'a str>,
    /// `Some(None)` clears the expiry.
    pub expires_at: Option<Option<i64>>,
}

/// What an enrollment creates.
#[derive(Debug, Clone, Copy)]
pub enum Enrollee<'a> {
    Agent(&'a Agent),
    Device(&'a Device),
}

/// Last-holder protection: `before` -> `after` must not leave a role in
/// [`cjs_authz::LAST_HOLDER_ROLES`] without an active holder.
fn last_holder_guard(c: &Connection, before: &User, after: &User, t: i64) -> R<()> {
    for r in cjs_authz::LAST_HOLDER_ROLES {
        if !before.holds(r, t) {
            continue;
        }
        let keeps = after.has(r)
            && after.status == "active"
            && (after.expires_at.is_none() || after.expires_at == before.expires_at);
        if keeps {
            continue;
        }
        let others = {
            let mut st = c.prepare("SELECT * FROM users WHERE id != ?1")?;
            let rows = st.query_map([&before.id], user_row)?;
            rows.collect::<rusqlite::Result<Vec<User>>>()?
        };
        if !others.iter().any(|u| u.holds(r, t)) {
            return Err(ApiError::new(
                cjs_proto::ErrorCode::Conflict,
                format!(
                    "{} is the last active {}: it cannot be disabled, expired or lose that role",
                    before.name,
                    r.as_str()
                ),
            ));
        }
    }
    Ok(())
}

fn same_roles(a: &[Role], b: &[Role]) -> bool {
    let (mut a, mut b) = (a.to_vec(), b.to_vec());
    a.sort();
    a.dedup();
    b.sort();
    b.dedup();
    a == b
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Agent {
    pub id: String,
    pub name: String,
    pub owner_id: String,
    pub pubkey: String,
    pub status: String,
    pub expires_at: Option<i64>,
    pub info: serde_json::Value,
    pub last_seen: Option<i64>,
    pub created_at: i64,
    #[serde(default)]
    pub groups: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Device {
    pub id: String,
    pub name: String,
    pub pubkey: String,
    pub status: String,
    pub info: serde_json::Value,
    pub last_seen: Option<i64>,
    pub created_at: i64,
    #[serde(default)]
    pub groups: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Group {
    pub id: String,
    pub name: String,
    /// `user`, `agent` (principal groups) or `device`.
    pub kind: String,
    pub description: String,
    pub members: Vec<String>,
    pub created_at: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnrollTokenRow {
    pub id: String,
    pub kind: String,
    pub name: String,
    pub owner_id: Option<String>,
    pub created_by: String,
    pub expires_at: i64,
    pub used_at: Option<i64>,
    pub used_by: Option<String>,
    pub created_at: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredGrant {
    #[serde(flatten)]
    pub grant: Grant,
    pub created_by: String,
    pub created_at: i64,
    pub updated_at: i64,
}

pub struct Db {
    conn: Mutex<Connection>,
}

impl std::fmt::Debug for Db {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Db")
    }
}

fn roles_from(s: &str) -> Vec<Role> {
    s.split(',').filter_map(|r| Role::parse(r.trim())).collect()
}

fn roles_to(r: &[Role]) -> String {
    r.iter().map(|r| r.as_str()).collect::<Vec<_>>().join(",")
}

fn user_row(r: &Row) -> rusqlite::Result<User> {
    Ok(User {
        id: r.get("id")?,
        name: r.get("name")?,
        display_name: r.get("display_name")?,
        password_hash: r.get("password_hash")?,
        totp_secret: r.get("totp_secret")?,
        roles: roles_from(&r.get::<_, String>("roles")?),
        status: r.get("status")?,
        failed_logins: r.get("failed_logins")?,
        locked_until: r.get("locked_until")?,
        expires_at: r.get("expires_at")?,
        last_login: r.get("last_login")?,
        last_ip: r.get("last_ip")?,
        last_totp_step: r.get("last_totp_step")?,
        created_at: r.get("created_at")?,
        groups: vec![],
    })
}

fn json_col(r: &Row, c: &str) -> rusqlite::Result<serde_json::Value> {
    let s: String = r.get(c)?;
    Ok(serde_json::from_str(&s).unwrap_or(serde_json::Value::Null))
}

fn agent_row(r: &Row) -> rusqlite::Result<Agent> {
    Ok(Agent {
        id: r.get("id")?,
        name: r.get("name")?,
        owner_id: r.get("owner_id")?,
        pubkey: r.get("pubkey")?,
        status: r.get("status")?,
        expires_at: r.get("expires_at")?,
        info: json_col(r, "info")?,
        last_seen: r.get("last_seen")?,
        created_at: r.get("created_at")?,
        groups: vec![],
    })
}

fn device_row(r: &Row) -> rusqlite::Result<Device> {
    Ok(Device {
        id: r.get("id")?,
        name: r.get("name")?,
        pubkey: r.get("pubkey")?,
        status: r.get("status")?,
        info: json_col(r, "info")?,
        last_seen: r.get("last_seen")?,
        created_at: r.get("created_at")?,
        groups: vec![],
    })
}

type R<T> = Result<T, ApiError>;

impl Db {
    pub fn open(path: &Path) -> R<Self> {
        let conn = Connection::open(path)?;
        Self::init(conn)
    }

    pub fn open_in_memory() -> R<Self> {
        Self::init(Connection::open_in_memory()?)
    }

    fn init(conn: Connection) -> R<Self> {
        conn.execute_batch("PRAGMA journal_mode=WAL; PRAGMA foreign_keys=ON; PRAGMA synchronous=FULL;")?;
        let v: i64 = conn.query_row("PRAGMA user_version", [], |r| r.get(0))?;
        for (i, m) in SCHEMA.iter().enumerate().skip(v as usize) {
            conn.execute_batch(m)?;
            conn.execute_batch(&format!("PRAGMA user_version = {}", i + 1))?;
        }
        Ok(Self {
            conn: Mutex::new(conn),
        })
    }

    pub fn with<T>(&self, f: impl FnOnce(&Connection) -> rusqlite::Result<T>) -> R<T> {
        let c = self.conn.lock().unwrap_or_else(|p| p.into_inner());
        Ok(f(&c)?)
    }

    // ---- users -----------------------------------------------------------

    pub fn insert_user(&self, u: &User) -> R<()> {
        self.with(|c| {
            c.execute(
                "INSERT INTO users (id, name, display_name, password_hash, totp_secret, roles, status, expires_at, created_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
                params![u.id, u.name, u.display_name, u.password_hash, u.totp_secret, roles_to(&u.roles), u.status, u.expires_at, u.created_at],
            )
            .map(|_| ())
        })
    }

    pub fn user(&self, id_or_name: &str) -> R<Option<User>> {
        let mut u = self.with(|c| {
            c.query_row(
                "SELECT * FROM users WHERE id = ?1 OR name = ?1",
                [id_or_name],
                user_row,
            )
            .optional()
        })?;
        if let Some(u) = &mut u {
            u.groups = self.groups_of(&u.id)?;
        }
        Ok(u)
    }

    pub fn users(&self) -> R<Vec<User>> {
        let mut v: Vec<User> = self.with(|c| {
            let mut st = c.prepare("SELECT * FROM users ORDER BY name")?;
            let rows = st.query_map([], user_row)?;
            rows.collect()
        })?;
        for u in &mut v {
            u.groups = self.groups_of(&u.id)?;
        }
        Ok(v)
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Connection> {
        self.conn.lock().unwrap_or_else(|p| p.into_inner())
    }

    fn user_in(c: &Connection, id: &str) -> R<User> {
        c.query_row("SELECT * FROM users WHERE id = ?1", [id], user_row)
            .optional()?
            .ok_or_else(|| ApiError::not_found("no such user"))
    }

    // Logins and credential changes touch only their own columns with
    // conditional SQL, so a concurrent administrative change (disable,
    // reset) is never overwritten by a stale snapshot.

    /// Reserve one login attempt before the credentials are checked.
    /// Returns `None` if the account is locked, otherwise whether this
    /// attempt used up the last allowed failure and locked the account
    /// (a successful attempt lifts the lock again, see [`Db::claim_login`]).
    pub fn reserve_login_attempt(
        &self,
        id: &str,
        t: i64,
        max_failures: i64,
        lock_secs: i64,
    ) -> R<Option<bool>> {
        let c = self.lock();
        let r: Option<Option<i64>> = c
            .query_row(
                "UPDATE users SET
                    failed_logins = CASE WHEN failed_logins + 1 >= ?3 THEN 0 ELSE failed_logins + 1 END,
                    locked_until = CASE WHEN failed_logins + 1 >= ?3 THEN ?2 + ?4 ELSE NULL END
                 WHERE id = ?1 AND (locked_until IS NULL OR locked_until <= ?2)
                 RETURNING locked_until",
                params![id, t, max_failures, lock_secs],
                |r| r.get(0),
            )
            .optional()?;
        Ok(r.map(|l| l.is_some()))
    }

    /// Accept a verified login: record the TOTP step (only if it is newer
    /// than the last accepted one, so a code is accepted once even under
    /// concurrency) and clear the failure counter. The password hash, TOTP
    /// secret and status must still be the ones that were verified.
    /// Returns false on replay or a concurrent change.
    pub fn claim_login(&self, u: &User, step: i64) -> R<bool> {
        let c = self.lock();
        let n = c.execute(
            "UPDATE users SET last_totp_step = ?2, failed_logins = 0, locked_until = NULL
             WHERE id = ?1 AND last_totp_step < ?2 AND password_hash = ?3 AND totp_secret = ?4 AND status = 'active'",
            params![u.id, step, u.password_hash, u.totp_secret],
        )?;
        Ok(n == 1)
    }

    pub fn record_login(&self, id: &str, t: i64, ip: Option<&str>) -> R<()> {
        let c = self.lock();
        c.execute(
            "UPDATE users SET last_login = ?2, last_ip = ?3 WHERE id = ?1",
            params![id, t, ip],
        )?;
        Ok(())
    }

    /// Replace the password hash, but only if it is still `old_hash`.
    pub fn set_password(&self, id: &str, old_hash: &str, new_hash: &str) -> R<bool> {
        let c = self.lock();
        let n = c.execute(
            "UPDATE users SET password_hash = ?3 WHERE id = ?1 AND password_hash = ?2",
            params![id, old_hash, new_hash],
        )?;
        Ok(n == 1)
    }

    /// New password and TOTP secret (administrative reset).
    pub fn reset_credentials(&self, id: &str, hash: &str, secret: &str) -> R<()> {
        let c = self.lock();
        c.execute(
            "UPDATE users SET password_hash = ?2, totp_secret = ?3, last_totp_step = 0,
             failed_logins = 0, locked_until = NULL WHERE id = ?1",
            params![id, hash, secret],
        )?;
        Ok(())
    }

    pub fn unlock_user(&self, id: &str) -> R<()> {
        let c = self.lock();
        c.execute(
            "UPDATE users SET failed_logins = 0, locked_until = NULL WHERE id = ?1",
            [id],
        )?;
        Ok(())
    }

    /// Apply an administrative change in one transaction, with last-holder
    /// protection. Returns the updated user (without groups).
    pub fn patch_user(&self, id: &str, p: &UserPatch, t: i64) -> R<User> {
        let c = self.lock();
        let tx = Transaction::new_unchecked(&c, TransactionBehavior::Immediate)?;
        let before = Self::user_in(&tx, id)?;
        let mut after = before.clone();
        after.apply(p);
        last_holder_guard(&tx, &before, &after, t)?;
        tx.execute(
            "UPDATE users SET status = ?2, roles = ?3, display_name = ?4, expires_at = ?5 WHERE id = ?1",
            params![
                after.id,
                after.status,
                roles_to(&after.roles),
                after.display_name,
                after.expires_at
            ],
        )?;
        tx.commit()?;
        Ok(after)
    }

    // ---- role changes (two-person rule for privileged roles) ---------------

    pub fn insert_role_change(&self, rc: &RoleChange) -> R<()> {
        let body = serde_json::to_string(rc).map_err(|e| ApiError::internal(e.to_string()))?;
        let c = self.lock();
        c.execute(
            "INSERT INTO role_changes (id, user_id, status, body, created_at) VALUES (?1, ?2, ?3, ?4, ?5)",
            params![rc.id, rc.user_id, rc.status.as_str(), body, rc.created_at],
        )?;
        Ok(())
    }

    pub fn role_changes(&self) -> R<Vec<RoleChange>> {
        self.with(|c| {
            let mut st = c.prepare("SELECT body FROM role_changes ORDER BY created_at DESC LIMIT 500")?;
            let rows = st.query_map([], |r| r.get::<_, String>(0))?;
            let mut out = Vec::new();
            for r in rows {
                if let Ok(rc) = serde_json::from_str(&r?) {
                    out.push(rc);
                }
            }
            Ok(out)
        })
    }

    pub fn role_change(&self, id: &str) -> R<Option<RoleChange>> {
        let body: Option<String> = self.with(|c| {
            c.query_row("SELECT body FROM role_changes WHERE id = ?1", [id], |r| r.get(0))
                .optional()
        })?;
        Ok(body.and_then(|b| serde_json::from_str(&b).ok()))
    }

    fn store_decision(c: &Connection, rc: &RoleChange) -> R<bool> {
        let body = serde_json::to_string(rc).map_err(|e| ApiError::internal(e.to_string()))?;
        let n = c.execute(
            "UPDATE role_changes SET status = ?2, body = ?3 WHERE id = ?1 AND status = 'pending'",
            params![rc.id, rc.status.as_str(), body],
        )?;
        Ok(n == 1)
    }

    /// Record a rejection of a pending change. False if it was no longer
    /// pending.
    pub fn reject_role_change(&self, rc: &RoleChange) -> R<bool> {
        let c = self.lock();
        Self::store_decision(&c, rc)
    }

    /// Apply an approved change (`rc.status` already `Approved`) and mark it
    /// decided, atomically. Refused if the change is no longer pending, the
    /// user's roles changed since the request, or a last holder would lose
    /// its role.
    pub fn apply_role_change(&self, rc: &RoleChange, t: i64) -> R<User> {
        let c = self.lock();
        let tx = Transaction::new_unchecked(&c, TransactionBehavior::Immediate)?;
        let before = Self::user_in(&tx, &rc.user_id)?;
        if !same_roles(&before.roles, &rc.from_roles) {
            return Err(ApiError::new(
                cjs_proto::ErrorCode::Conflict,
                "the user's roles changed since this request; request again",
            ));
        }
        let mut after = before.clone();
        after.roles = rc.roles.clone();
        last_holder_guard(&tx, &before, &after, t)?;
        if !Self::store_decision(&tx, rc)? {
            return Err(ApiError::new(
                cjs_proto::ErrorCode::Conflict,
                "request is no longer pending",
            ));
        }
        tx.execute(
            "UPDATE users SET roles = ?2 WHERE id = ?1",
            params![after.id, roles_to(&after.roles)],
        )?;
        tx.commit()?;
        Ok(after)
    }

    /// Server-local (CLI) role assignment: no approval, no guard.
    pub fn set_roles_local(&self, id: &str, roles: &[Role]) -> R<()> {
        let c = self.lock();
        c.execute(
            "UPDATE users SET roles = ?2 WHERE id = ?1",
            params![id, roles_to(roles)],
        )?;
        Ok(())
    }

    pub fn count_users(&self) -> R<i64> {
        self.with(|c| c.query_row("SELECT COUNT(*) FROM users", [], |r| r.get(0)))
    }

    // ---- agents / devices -------------------------------------------------

    pub fn insert_agent(&self, a: &Agent) -> R<()> {
        self.with(|c| {
            c.execute(
                "INSERT INTO agents (id, name, owner_id, pubkey, status, expires_at, info, created_at) VALUES (?1,?2,?3,?4,?5,?6,?7,?8)",
                params![a.id, a.name, a.owner_id, a.pubkey, a.status, a.expires_at, a.info.to_string(), a.created_at],
            )
            .map(|_| ())
        })
    }

    pub fn agent(&self, id_or_name: &str) -> R<Option<Agent>> {
        let mut a = self.with(|c| {
            c.query_row(
                "SELECT * FROM agents WHERE id = ?1 OR name = ?1",
                [id_or_name],
                agent_row,
            )
            .optional()
        })?;
        if let Some(a) = &mut a {
            a.groups = self.groups_of(&a.id)?;
        }
        Ok(a)
    }

    pub fn agent_by_key(&self, pubkey: &str) -> R<Option<Agent>> {
        let id = self.with(|c| {
            c.query_row("SELECT id FROM agents WHERE pubkey = ?1", [pubkey], |r| {
                r.get::<_, String>(0)
            })
            .optional()
        })?;
        match id {
            Some(id) => self.agent(&id),
            None => Ok(None),
        }
    }

    pub fn agents(&self) -> R<Vec<Agent>> {
        let mut v: Vec<Agent> = self.with(|c| {
            let mut st = c.prepare("SELECT * FROM agents ORDER BY name")?;
            let rows = st.query_map([], agent_row)?;
            rows.collect()
        })?;
        for a in &mut v {
            a.groups = self.groups_of(&a.id)?;
        }
        Ok(v)
    }

    pub fn set_agent_status(&self, id: &str, status: &str) -> R<()> {
        self.with(|c| {
            c.execute("UPDATE agents SET status=?2 WHERE id=?1", params![id, status])
                .map(|_| ())
        })
    }

    /// Delete an agent. If it was disabled its key is revoked, so it
    /// cannot come back through a new enrollment token.
    pub fn delete_agent(&self, id: &str) -> R<()> {
        self.with(|c| {
            c.execute(
                "INSERT OR IGNORE INTO revoked_keys (pubkey, principal, revoked_at)
                 SELECT pubkey, id, ?2 FROM agents WHERE id=?1 AND status != 'active'",
                params![id, now()],
            )?;
            c.execute("DELETE FROM group_members WHERE member_id=?1", [id])?;
            c.execute("DELETE FROM agents WHERE id=?1", [id]).map(|_| ())
        })
    }

    pub fn touch_agent(&self, id: &str, info: &serde_json::Value) -> R<()> {
        self.with(|c| {
            c.execute(
                "UPDATE agents SET last_seen=?2, info=?3 WHERE id=?1",
                params![id, now(), info.to_string()],
            )
            .map(|_| ())
        })
    }

    pub fn insert_device(&self, d: &Device) -> R<()> {
        self.with(|c| {
            c.execute(
                "INSERT INTO devices (id, name, pubkey, status, info, created_at) VALUES (?1,?2,?3,?4,?5,?6)",
                params![d.id, d.name, d.pubkey, d.status, d.info.to_string(), d.created_at],
            )
            .map(|_| ())
        })
    }

    pub fn device(&self, id_or_name: &str) -> R<Option<Device>> {
        let mut d = self.with(|c| {
            c.query_row(
                "SELECT * FROM devices WHERE id = ?1 OR name = ?1",
                [id_or_name],
                device_row,
            )
            .optional()
        })?;
        if let Some(d) = &mut d {
            d.groups = self.groups_of(&d.id)?;
        }
        Ok(d)
    }

    pub fn device_by_key(&self, pubkey: &str) -> R<Option<Device>> {
        let id = self.with(|c| {
            c.query_row("SELECT id FROM devices WHERE pubkey = ?1", [pubkey], |r| {
                r.get::<_, String>(0)
            })
            .optional()
        })?;
        match id {
            Some(id) => self.device(&id),
            None => Ok(None),
        }
    }

    pub fn devices(&self) -> R<Vec<Device>> {
        let mut v: Vec<Device> = self.with(|c| {
            let mut st = c.prepare("SELECT * FROM devices ORDER BY name")?;
            let rows = st.query_map([], device_row)?;
            rows.collect()
        })?;
        for d in &mut v {
            d.groups = self.groups_of(&d.id)?;
        }
        Ok(v)
    }

    pub fn set_device_status(&self, id: &str, status: &str) -> R<()> {
        self.with(|c| {
            c.execute("UPDATE devices SET status=?2 WHERE id=?1", params![id, status])
                .map(|_| ())
        })
    }

    /// Delete a device; a disabled device's key is revoked (see
    /// [`Db::delete_agent`]).
    pub fn delete_device(&self, id: &str) -> R<()> {
        self.with(|c| {
            c.execute(
                "INSERT OR IGNORE INTO revoked_keys (pubkey, principal, revoked_at)
                 SELECT pubkey, id, ?2 FROM devices WHERE id=?1 AND status != 'active'",
                params![id, now()],
            )?;
            c.execute("DELETE FROM group_members WHERE member_id=?1", [id])?;
            c.execute("DELETE FROM devices WHERE id=?1", [id]).map(|_| ())
        })
    }

    pub fn touch_device(&self, id: &str, info: &serde_json::Value) -> R<()> {
        self.with(|c| {
            c.execute(
                "UPDATE devices SET last_seen=?2, info=?3 WHERE id=?1",
                params![id, now(), info.to_string()],
            )
            .map(|_| ())
        })
    }

    // ---- groups -----------------------------------------------------------

    pub fn groups_of(&self, member: &str) -> R<Vec<String>> {
        self.with(|c| {
            let mut st =
                c.prepare("SELECT group_id FROM group_members WHERE member_id = ?1 ORDER BY group_id")?;
            let rows = st.query_map([member], |r| r.get(0))?;
            rows.collect()
        })
    }

    pub fn groups(&self) -> R<Vec<Group>> {
        let mut gs: Vec<Group> = self.with(|c| {
            let mut st = c.prepare("SELECT * FROM groups ORDER BY name")?;
            let rows = st.query_map([], |r| {
                Ok(Group {
                    id: r.get("id")?,
                    name: r.get("name")?,
                    kind: r.get("kind")?,
                    description: r.get("description")?,
                    members: vec![],
                    created_at: r.get("created_at")?,
                })
            })?;
            rows.collect()
        })?;
        for g in &mut gs {
            g.members = self.with(|c| {
                let mut st =
                    c.prepare("SELECT member_id FROM group_members WHERE group_id = ?1 ORDER BY member_id")?;
                let rows = st.query_map([&g.id], |r| r.get(0))?;
                rows.collect()
            })?;
        }
        Ok(gs)
    }

    pub fn group(&self, id_or_name: &str) -> R<Option<Group>> {
        Ok(self
            .groups()?
            .into_iter()
            .find(|g| g.id == id_or_name || g.name == id_or_name))
    }

    pub fn insert_group(&self, g: &Group) -> R<()> {
        self.with(|c| {
            c.execute(
                "INSERT INTO groups (id, name, kind, description, created_at) VALUES (?1,?2,?3,?4,?5)",
                params![g.id, g.name, g.kind, g.description, g.created_at],
            )
            .map(|_| ())
        })
    }

    pub fn delete_group(&self, id: &str) -> R<()> {
        self.with(|c| {
            c.execute("DELETE FROM group_members WHERE group_id=?1", [id])?;
            c.execute("DELETE FROM groups WHERE id=?1", [id]).map(|_| ())
        })
    }

    pub fn set_membership(&self, group: &str, member: &str, present: bool) -> R<()> {
        self.with(|c| {
            if present {
                c.execute(
                    "INSERT OR IGNORE INTO group_members (group_id, member_id) VALUES (?1, ?2)",
                    [group, member],
                )
            } else {
                c.execute(
                    "DELETE FROM group_members WHERE group_id=?1 AND member_id=?2",
                    [group, member],
                )
            }
            .map(|_| ())
        })
    }

    // ---- enrollment tokens -------------------------------------------------

    pub fn insert_enroll_token(&self, t: &EnrollTokenRow, secret_hash: &str) -> R<()> {
        self.with(|c| {
            c.execute(
                "INSERT INTO enroll_tokens (id, secret_hash, kind, name, owner_id, created_by, expires_at, created_at)
                 VALUES (?1,?2,?3,?4,?5,?6,?7,?8)",
                params![t.id, secret_hash, t.kind, t.name, t.owner_id, t.created_by, t.expires_at, t.created_at],
            )
            .map(|_| ())
        })
    }

    fn token_row(r: &Row) -> rusqlite::Result<EnrollTokenRow> {
        Ok(EnrollTokenRow {
            id: r.get("id")?,
            kind: r.get("kind")?,
            name: r.get("name")?,
            owner_id: r.get("owner_id")?,
            created_by: r.get("created_by")?,
            expires_at: r.get("expires_at")?,
            used_at: r.get("used_at")?,
            used_by: r.get("used_by")?,
            created_at: r.get("created_at")?,
        })
    }

    pub fn enroll_token_by_hash(&self, secret_hash: &str) -> R<Option<EnrollTokenRow>> {
        self.with(|c| {
            c.query_row(
                "SELECT * FROM enroll_tokens WHERE secret_hash = ?1",
                [secret_hash],
                Self::token_row,
            )
            .optional()
        })
    }

    pub fn enroll_tokens(&self) -> R<Vec<EnrollTokenRow>> {
        self.with(|c| {
            let mut st = c.prepare("SELECT * FROM enroll_tokens ORDER BY created_at DESC LIMIT 200")?;
            let rows = st.query_map([], Self::token_row)?;
            rows.collect()
        })
    }

    /// Redeem an enrollment token: mark it used and create the agent or
    /// device in one transaction. `before_commit` runs after both writes
    /// succeeded and before the commit (the caller audits there; an error
    /// rolls everything back). Refuses a key that is already enrolled or was
    /// revoked.
    pub fn enroll_principal(
        &self,
        token_id: &str,
        who: Enrollee,
        before_commit: impl FnOnce() -> R<()>,
    ) -> R<()> {
        use cjs_proto::ErrorCode;
        let (id, pubkey) = match who {
            Enrollee::Agent(a) => (&a.id, &a.pubkey),
            Enrollee::Device(d) => (&d.id, &d.pubkey),
        };
        let c = self.lock();
        let tx = Transaction::new_unchecked(&c, TransactionBehavior::Immediate)?;
        let known: i64 = tx.query_row(
            "SELECT (SELECT COUNT(*) FROM revoked_keys WHERE pubkey = ?1)
                  + (SELECT COUNT(*) FROM agents WHERE pubkey = ?1)
                  + (SELECT COUNT(*) FROM devices WHERE pubkey = ?1)",
            [pubkey],
            |r| r.get(0),
        )?;
        if known > 0 {
            return Err(ApiError::new(
                ErrorCode::Forbidden,
                "this key is revoked or already enrolled",
            ));
        }
        let n = tx.execute(
            "UPDATE enroll_tokens SET used_at=?2, used_by=?3 WHERE id=?1 AND used_at IS NULL",
            params![token_id, now(), id],
        )?;
        if n != 1 {
            return Err(ApiError::new(ErrorCode::Replay, "enrollment token already used"));
        }
        let ins = match who {
            Enrollee::Agent(a) => tx.execute(
                "INSERT INTO agents (id, name, owner_id, pubkey, status, expires_at, info, created_at) VALUES (?1,?2,?3,?4,?5,?6,?7,?8)",
                params![a.id, a.name, a.owner_id, a.pubkey, a.status, a.expires_at, a.info.to_string(), a.created_at],
            ),
            Enrollee::Device(d) => tx.execute(
                "INSERT INTO devices (id, name, pubkey, status, info, created_at) VALUES (?1,?2,?3,?4,?5,?6)",
                params![d.id, d.name, d.pubkey, d.status, d.info.to_string(), d.created_at],
            ),
        };
        if let Err(e) = ins {
            let e = ApiError::from(e);
            return Err(if e.code == ErrorCode::Conflict {
                ApiError::new(ErrorCode::Conflict, "name already enrolled")
            } else {
                e
            });
        }
        before_commit()?;
        tx.commit()?;
        Ok(())
    }

    /// Atomically mark a token used. Returns false if it was already used.
    pub fn consume_enroll_token(&self, id: &str, used_by: &str) -> R<bool> {
        self.with(|c| {
            c.execute(
                "UPDATE enroll_tokens SET used_at=?2, used_by=?3 WHERE id=?1 AND used_at IS NULL",
                params![id, now(), used_by],
            )
            .map(|n| n == 1)
        })
    }

    // ---- grants ------------------------------------------------------------

    pub fn grants(&self) -> R<Vec<StoredGrant>> {
        self.with(|c| {
            let mut st =
                c.prepare("SELECT body, created_by, created_at, updated_at FROM grants ORDER BY created_at")?;
            let rows = st.query_map([], |r| {
                let body: String = r.get(0)?;
                Ok((
                    body,
                    r.get::<_, String>(1)?,
                    r.get::<_, i64>(2)?,
                    r.get::<_, i64>(3)?,
                ))
            })?;
            let mut out = Vec::new();
            for row in rows {
                let (body, created_by, created_at, updated_at) = row?;
                if let Ok(grant) = serde_json::from_str::<Grant>(&body) {
                    out.push(StoredGrant {
                        grant,
                        created_by,
                        created_at,
                        updated_at,
                    });
                }
            }
            Ok(out)
        })
    }

    pub fn grant(&self, id: &str) -> R<Option<StoredGrant>> {
        Ok(self.grants()?.into_iter().find(|g| g.grant.id == id))
    }

    pub fn upsert_grant(&self, g: &Grant, by: &str) -> R<()> {
        let body = serde_json::to_string(g).map_err(|e| ApiError::internal(e.to_string()))?;
        let t = now();
        self.with(|c| {
            c.execute(
                "INSERT INTO grants (id, body, created_by, created_at, updated_at) VALUES (?1, ?2, ?3, ?4, ?4)
                 ON CONFLICT(id) DO UPDATE SET body=excluded.body, updated_at=excluded.updated_at",
                params![g.id, body, by, t],
            )
            .map(|_| ())
        })
    }

    pub fn delete_grant(&self, id: &str) -> R<bool> {
        self.with(|c| c.execute("DELETE FROM grants WHERE id=?1", [id]).map(|n| n == 1))
    }

    // ---- full access -------------------------------------------------------

    pub fn full_access_all(&self) -> R<Vec<FullAccess>> {
        self.with(|c| {
            let mut st = c.prepare("SELECT body FROM full_access ORDER BY created_at DESC")?;
            let rows = st.query_map([], |r| r.get::<_, String>(0))?;
            let mut out = Vec::new();
            for r in rows {
                if let Ok(f) = serde_json::from_str(&r?) {
                    out.push(f);
                }
            }
            Ok(out)
        })
    }

    pub fn full_access(&self, id: &str) -> R<Option<FullAccess>> {
        Ok(self.full_access_all()?.into_iter().find(|f| f.id == id))
    }

    /// Store a decision on a request only if it is still in state `from`
    /// (so concurrent approve / reject / revoke cannot overwrite each other).
    pub fn transition_full_access(&self, f: &FullAccess, from: ApprovalStatus) -> R<bool> {
        let body = serde_json::to_string(f).map_err(|e| ApiError::internal(e.to_string()))?;
        self.with(|c| {
            c.execute(
                "UPDATE full_access SET body=?2 WHERE id=?1 AND json_extract(body, '$.status') = ?3",
                params![f.id, body, from.as_str()],
            )
            .map(|n| n == 1)
        })
    }

    pub fn put_full_access(&self, f: &FullAccess) -> R<()> {
        let body = serde_json::to_string(f).map_err(|e| ApiError::internal(e.to_string()))?;
        self.with(|c| {
            c.execute(
                "INSERT INTO full_access (id, body, created_at) VALUES (?1, ?2, ?3)
                 ON CONFLICT(id) DO UPDATE SET body=excluded.body",
                params![f.id, body, f.created_at],
            )
            .map(|_| ())
        })
    }

    // ---- web sessions ------------------------------------------------------

    pub fn insert_web_session(&self, token_hash: &str, user: &str, csrf: &str, ip: Option<&str>) -> R<()> {
        let t = now();
        self.with(|c| {
            c.execute(
                "INSERT INTO web_sessions (token_hash, user_id, csrf, ip, created_at, last_seen) VALUES (?1,?2,?3,?4,?5,?5)",
                params![token_hash, user, csrf, ip, t],
            )
            .map(|_| ())
        })
    }

    /// Returns (user id, csrf, created_at, last_seen).
    pub fn web_session(&self, token_hash: &str) -> R<Option<(String, String, i64, i64)>> {
        self.with(|c| {
            c.query_row(
                "SELECT user_id, csrf, created_at, last_seen FROM web_sessions WHERE token_hash=?1",
                [token_hash],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
            )
            .optional()
        })
    }

    pub fn touch_web_session(&self, token_hash: &str) -> R<()> {
        self.with(|c| {
            c.execute(
                "UPDATE web_sessions SET last_seen=?2 WHERE token_hash=?1",
                params![token_hash, now()],
            )
            .map(|_| ())
        })
    }

    pub fn delete_web_session(&self, token_hash: &str) -> R<()> {
        self.with(|c| {
            c.execute("DELETE FROM web_sessions WHERE token_hash=?1", [token_hash])
                .map(|_| ())
        })
    }

    /// Drop sessions past their idle or absolute timeout.
    pub fn purge_web_sessions(&self, idle_secs: i64, max_secs: i64) -> R<usize> {
        let t = now();
        self.with(|c| {
            c.execute(
                "DELETE FROM web_sessions WHERE last_seen < ?1 OR created_at < ?2",
                params![t - idle_secs, t - max_secs],
            )
        })
    }

    pub fn delete_user_sessions(&self, user: &str) -> R<()> {
        self.with(|c| {
            c.execute("DELETE FROM web_sessions WHERE user_id=?1", [user])
                .map(|_| ())
        })
    }

    // ---- settings ----------------------------------------------------------

    pub fn setting(&self, key: &str) -> R<Option<String>> {
        self.with(|c| {
            c.query_row("SELECT value FROM settings WHERE key=?1", [key], |r| r.get(0))
                .optional()
        })
    }

    pub fn set_setting(&self, key: &str, value: &str) -> R<()> {
        self.with(|c| {
            c.execute(
                "INSERT INTO settings (key, value) VALUES (?1, ?2) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                [key, value],
            )
            .map(|_| ())
        })
    }
}
