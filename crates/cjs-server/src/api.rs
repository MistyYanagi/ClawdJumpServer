//! REST API (`/api/v1`) for people: administrators, security officers and
//! auditors (three-role separation of duties), plus agent owners.
//!
//! * Authentication: password (argon2id) + mandatory TOTP, account lockout
//!   and per-address throttling. Sessions are random cookies (`HttpOnly`,
//!   `SameSite=Strict`, `Secure`), stored hashed, with idle and absolute
//!   timeouts.
//! * Every state-changing request needs the session's CSRF token in
//!   `X-CSRF-Token`, and a cross-site `Origin` is refused.
//! * Every administrative change is audited *before* it is applied; if the
//!   audit write fails the change is refused. Changes that can reduce
//!   access trigger an immediate lease re-check of live sessions.
use std::collections::BTreeSet;

use axum::extract::{FromRequestParts, Path, Query, State};
use axum::http::request::Parts;
use axum::http::{header, HeaderMap, HeaderValue, Method, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, post, put};
use axum::{Json, Router};
use cjs_audit::{Event, Outcome};
use cjs_authz::{ApprovalStatus, FullAccess, Grant, Role, Subject, Target};
use cjs_proto::{ErrorCode, Role as ClientRole};
use serde::Deserialize;
use serde_json::{json, Value};
use subtle::ConstantTimeEq;

use crate::accounts::{self, random_token, sha256_hex};
use crate::db::{new_id, now, Group, User};
use crate::error::ApiError;
use crate::gateway::Server;

pub const COOKIE: &str = "cjs_session";
pub const CSRF_HEADER: &str = "x-csrf-token";
/// Failed logins allowed per client address per window.
const IP_MAX_FAILURES: u32 = 20;
const IP_WINDOW_SECS: i64 = 15 * 60;

type R<T> = Result<T, ApiError>;

/// JSON request body whose rejections are reported as API errors.
pub struct Body<T>(pub T);

impl<S, T> axum::extract::FromRequest<S> for Body<T>
where
    T: serde::de::DeserializeOwned,
    S: Send + Sync,
{
    type Rejection = ApiError;

    async fn from_request(req: axum::extract::Request, state: &S) -> Result<Self, Self::Rejection> {
        match Json::<T>::from_request(req, state).await {
            Ok(Json(v)) => Ok(Body(v)),
            Err(e) => Err(ApiError::bad(e.body_text())),
        }
    }
}

/// An authenticated web session.
#[derive(Debug, Clone)]
pub struct Auth {
    pub user: User,
    pub token_hash: String,
    pub csrf: String,
    pub ip: Option<String>,
}

impl Auth {
    pub fn require(&self, r: Role) -> R<()> {
        if self.user.has(r) {
            Ok(())
        } else {
            Err(ApiError::forbidden(format!("requires the {} role", r.as_str())))
        }
    }

    pub fn require_any(&self, rs: &[Role]) -> R<()> {
        if rs.iter().any(|r| self.user.has(*r)) {
            Ok(())
        } else {
            let names: Vec<_> = rs.iter().map(|r| r.as_str()).collect();
            Err(ApiError::forbidden(format!("requires one of the roles {}", names.join(", "))))
        }
    }

    fn event(&self, kind: &str, target: &str) -> Event {
        Event::new(kind, &self.user.id, target, Outcome::Success).ip(self.ip.clone())
    }
}

fn cookie_value(headers: &HeaderMap, name: &str) -> Option<String> {
    for v in headers.get_all(header::COOKIE) {
        let Ok(s) = v.to_str() else { continue };
        for part in s.split(';') {
            if let Some((k, v)) = part.trim().split_once('=') {
                if k == name {
                    return Some(v.to_string());
                }
            }
        }
    }
    None
}

/// `Origin` (if sent) must be the host the request was addressed to.
fn same_origin(headers: &HeaderMap) -> bool {
    let Some(origin) = headers.get(header::ORIGIN).and_then(|v| v.to_str().ok()) else {
        return true;
    };
    let Some(host) = headers.get(header::HOST).and_then(|v| v.to_str().ok()) else {
        return false;
    };
    match url::Url::parse(origin) {
        Ok(u) => {
            let o = match u.port() {
                Some(p) => format!("{}:{p}", u.host_str().unwrap_or("")),
                None => u.host_str().unwrap_or("").to_string(),
            };
            o.eq_ignore_ascii_case(host)
        }
        Err(_) => false,
    }
}

impl FromRequestParts<Server> for Auth {
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, srv: &Server) -> Result<Self, Self::Rejection> {
        let sh = &srv.shared;
        let ip = cjs_transport::peer_addr(&parts.extensions, &parts.headers, sh.cfg.trust_forwarded_for);
        let token = cookie_value(&parts.headers, COOKIE).ok_or_else(|| ApiError::unauth("not logged in"))?;
        let hash = sha256_hex(&token);
        let (uid, csrf, created, last) = sh
            .db
            .web_session(&hash)?
            .ok_or_else(|| ApiError::unauth("session expired"))?;
        let t = now();
        if t - last > sh.cfg.web_idle_secs || t - created > sh.cfg.web_max_secs {
            sh.db.delete_web_session(&hash)?;
            return Err(ApiError::unauth("session expired"));
        }
        let user = sh.db.user(&uid)?.ok_or_else(|| ApiError::unauth("session expired"))?;
        if let Err(why) = user.usable(t) {
            sh.db.delete_web_session(&hash)?;
            return Err(ApiError::new(ErrorCode::Disabled, why));
        }
        if !matches!(parts.method, Method::GET | Method::HEAD | Method::OPTIONS) {
            let sent = parts
                .headers
                .get(CSRF_HEADER)
                .and_then(|v| v.to_str().ok())
                .unwrap_or("");
            if !bool::from(sent.as_bytes().ct_eq(csrf.as_bytes())) {
                return Err(ApiError::forbidden("missing or invalid CSRF token"));
            }
            if !same_origin(&parts.headers) {
                return Err(ApiError::forbidden("cross-origin request refused"));
            }
        }
        if t - last >= 30 {
            sh.db.touch_web_session(&hash)?;
        }
        Ok(Auth {
            user,
            token_hash: hash,
            csrf,
            ip,
        })
    }
}

fn session_cookie(token: &str, max_age: i64, secure: bool) -> HeaderValue {
    let s = format!(
        "{COOKIE}={token}; Path=/; HttpOnly; SameSite=Strict; Max-Age={max_age}{}",
        if secure { "; Secure" } else { "" }
    );
    HeaderValue::from_str(&s).unwrap_or_else(|_| HeaderValue::from_static(""))
}

// ---------------------------------------------------------------------------
// Router
// ---------------------------------------------------------------------------

/// Documented routes: (method, path, required role, summary). Used to build
/// the OpenAPI document; `tests::openapi_matches_routes` keeps it honest.
pub const ROUTES: &[(&str, &str, &str, &str)] = &[
    ("post", "/api/v1/login", "-", "Log in with name, password and TOTP code"),
    ("post", "/api/v1/logout", "any", "End the current session"),
    ("get", "/api/v1/me", "any", "Current user and CSRF token"),
    ("post", "/api/v1/me/password", "any", "Change own password (needs TOTP)"),
    ("get", "/api/v1/info", "any", "Server version and key fingerprint"),
    ("get", "/api/v1/users", "sysadmin", "List users"),
    ("post", "/api/v1/users", "sysadmin", "Create a user (returns initial password and TOTP secret once)"),
    ("patch", "/api/v1/users/{id}", "sysadmin", "Change status, roles, display name or expiry"),
    ("post", "/api/v1/users/{id}/reset", "sysadmin", "Reset password and TOTP"),
    ("post", "/api/v1/users/{id}/unlock", "sysadmin", "Clear a login lockout"),
    ("get", "/api/v1/agents", "any", "List agents (own agents unless sysadmin)"),
    ("patch", "/api/v1/agents/{id}", "sysadmin|owner", "Enable/disable an agent or set its expiry"),
    ("delete", "/api/v1/agents/{id}", "sysadmin|owner", "Delete an agent"),
    ("get", "/api/v1/devices", "any", "List devices"),
    ("patch", "/api/v1/devices/{id}", "sysadmin", "Enable or disable a device"),
    ("delete", "/api/v1/devices/{id}", "sysadmin", "Delete a device"),
    ("get", "/api/v1/groups", "any", "List groups"),
    ("post", "/api/v1/groups", "sysadmin", "Create a group (kind user, agent or device)"),
    ("delete", "/api/v1/groups/{id}", "sysadmin", "Delete a group"),
    ("put", "/api/v1/groups/{id}/members/{member}", "sysadmin", "Add a member"),
    ("delete", "/api/v1/groups/{id}/members/{member}", "sysadmin", "Remove a member"),
    ("get", "/api/v1/tokens", "any", "List enrollment tokens (own unless sysadmin)"),
    ("post", "/api/v1/tokens", "any", "Create an enrollment token (devices: sysadmin)"),
    ("get", "/api/v1/grants", "secadmin|auditor", "List grants"),
    ("put", "/api/v1/grants/{id}", "secadmin", "Create or replace a grant"),
    ("delete", "/api/v1/grants/{id}", "secadmin", "Delete a grant"),
    ("get", "/api/v1/full-access", "any", "List full-access requests"),
    ("post", "/api/v1/full-access", "any", "Request full access for an agent on a device"),
    ("post", "/api/v1/full-access/{id}/approve", "secadmin", "Approve (two-person rule)"),
    ("post", "/api/v1/full-access/{id}/reject", "secadmin", "Reject a pending request"),
    ("post", "/api/v1/full-access/{id}/revoke", "secadmin", "Revoke an approval"),
    ("get", "/api/v1/live/connections", "secadmin|auditor", "Connected agents and devices"),
    ("get", "/api/v1/live/streams", "secadmin|auditor", "Open sessions"),
    ("post", "/api/v1/live/sessions/{session}/kill", "secadmin", "Terminate a session"),
    ("post", "/api/v1/live/connections/{id}/kick", "secadmin", "Disconnect a client"),
    ("get", "/api/v1/audit", "auditor", "Query the audit log"),
    ("get", "/api/v1/audit/verify", "auditor", "Verify the hash chain and signed checkpoints"),
    ("get", "/api/v1/audit/export", "auditor", "Export events and checkpoints (JSON lines)"),
    ("post", "/api/v1/audit/checkpoint", "auditor", "Sign the current head now"),
    ("get", "/api/v1/recordings/{session}", "auditor", "Download a terminal recording (asciicast v2)"),
    ("get", "/api/v1/openapi.json", "-", "This document"),
];

pub fn router(srv: Server) -> Router {
    Router::new()
        .route("/api/v1/login", post(login))
        .route("/api/v1/logout", post(logout))
        .route("/api/v1/me", get(me))
        .route("/api/v1/me/password", post(change_password))
        .route("/api/v1/info", get(info))
        .route("/api/v1/users", get(list_users).post(create_user))
        .route("/api/v1/users/{id}", axum::routing::patch(patch_user))
        .route("/api/v1/users/{id}/reset", post(reset_user))
        .route("/api/v1/users/{id}/unlock", post(unlock_user))
        .route("/api/v1/agents", get(list_agents))
        .route("/api/v1/agents/{id}", axum::routing::patch(patch_agent).delete(delete_agent))
        .route("/api/v1/devices", get(list_devices))
        .route("/api/v1/devices/{id}", axum::routing::patch(patch_device).delete(delete_device))
        .route("/api/v1/groups", get(list_groups).post(create_group))
        .route("/api/v1/groups/{id}", delete(delete_group))
        .route("/api/v1/groups/{id}/members/{member}", put(add_member).delete(remove_member))
        .route("/api/v1/tokens", get(list_tokens).post(create_token))
        .route("/api/v1/grants", get(list_grants))
        .route("/api/v1/grants/{id}", put(put_grant).delete(delete_grant))
        .route("/api/v1/full-access", get(list_full).post(request_full))
        .route("/api/v1/full-access/{id}/approve", post(approve_full))
        .route("/api/v1/full-access/{id}/reject", post(reject_full))
        .route("/api/v1/full-access/{id}/revoke", post(revoke_full))
        .route("/api/v1/live/connections", get(live_connections))
        .route("/api/v1/live/streams", get(live_streams))
        .route("/api/v1/live/sessions/{session}/kill", post(kill_session))
        .route("/api/v1/live/connections/{id}/kick", post(kick_connection))
        .route("/api/v1/audit", get(audit_query))
        .route("/api/v1/audit/verify", get(audit_verify))
        .route("/api/v1/audit/export", get(audit_export))
        .route("/api/v1/audit/checkpoint", post(audit_checkpoint))
        .route("/api/v1/recordings/{session}", get(recording))
        .route("/api/v1/openapi.json", get(openapi))
        .with_state(srv)
}

// ---------------------------------------------------------------------------
// Authentication
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct LoginReq {
    name: String,
    password: String,
    totp: String,
}

fn user_json(u: &User) -> Value {
    serde_json::to_value(u).unwrap_or_default()
}

async fn login(
    State(srv): State<Server>,
    ext: axum::http::Extensions,
    headers: HeaderMap,
    Body(req): Body<LoginReq>,
) -> R<Response> {
    let sh = &srv.shared;
    let ip = cjs_transport::peer_addr(&ext, &headers, sh.cfg.trust_forwarded_for);
    if !same_origin(&headers) {
        return Err(ApiError::forbidden("cross-origin request refused"));
    }
    let key = ip.clone().unwrap_or_else(|| "unknown".into());
    let t = now();
    {
        let mut f = sh.login_failures.lock().unwrap_or_else(|p| p.into_inner());
        f.retain(|_, (_, start)| t - *start < IP_WINDOW_SECS);
        if f.get(&key).map(|(n, _)| *n >= IP_MAX_FAILURES).unwrap_or(false) {
            drop(f);
            let _ = sh.audit(
                Event::new("auth.login", "anonymous", "web", Outcome::Denied)
                    .ip(ip.clone())
                    .data(json!({"user": req.name, "reason": "too many failures from this address"})),
            );
            return Err(ApiError::new(ErrorCode::LimitExceeded, "too many failed logins; try again later"));
        }
    }
    let user = match accounts::login(&sh.db, &sh.audit, &req.name, &req.password, &req.totp, ip.clone()) {
        Ok(u) => u,
        Err(e) => {
            if e.code != ErrorCode::AuditFailure {
                let mut f = sh.login_failures.lock().unwrap_or_else(|p| p.into_inner());
                let entry = f.entry(key).or_insert((0, t));
                entry.0 += 1;
            }
            return Err(e);
        }
    };
    let token = random_token(32);
    let csrf = random_token(32);
    sh.db
        .insert_web_session(&sha256_hex(&token), &user.id, &csrf, ip.as_deref())?;
    let mut resp = Json(json!({"user": user_json(&user), "csrf": csrf})).into_response();
    resp.headers_mut().insert(
        header::SET_COOKIE,
        session_cookie(&token, sh.cfg.web_max_secs, sh.cfg.secure_cookies),
    );
    Ok(resp)
}

async fn logout(State(srv): State<Server>, auth: Auth) -> R<Response> {
    let sh = &srv.shared;
    sh.audit(auth.event("auth.logout", "web"))?;
    sh.db.delete_web_session(&auth.token_hash)?;
    let mut resp = Json(json!({"ok": true})).into_response();
    resp.headers_mut()
        .insert(header::SET_COOKIE, session_cookie("", 0, sh.cfg.secure_cookies));
    Ok(resp)
}

async fn me(auth: Auth) -> Json<Value> {
    Json(json!({"user": user_json(&auth.user), "csrf": auth.csrf}))
}

#[derive(Deserialize)]
struct PasswordReq {
    old: String,
    new: String,
    totp: String,
}

async fn change_password(State(srv): State<Server>, auth: Auth, Body(req): Body<PasswordReq>) -> R<Json<Value>> {
    let sh = &srv.shared;
    let mut u = auth.user.clone();
    if !accounts::verify_password(&req.old, &u.password_hash) {
        return Err(ApiError::unauth("wrong password"));
    }
    let step = accounts::check_totp(&u.totp_secret, &req.totp, u.last_totp_step)
        .ok_or_else(|| ApiError::unauth("bad or reused TOTP code"))?;
    accounts::check_password_policy(&req.new)?;
    sh.audit(auth.event("auth.password_change", &u.id))?;
    u.password_hash = accounts::hash_password(&req.new)?;
    u.last_totp_step = step;
    sh.db.update_user(&u)?;
    // Other sessions of this user end; this one stays.
    sh.db.delete_user_sessions(&u.id)?;
    sh.db
        .insert_web_session(&auth.token_hash, &u.id, &auth.csrf, auth.ip.as_deref())?;
    Ok(Json(json!({"ok": true})))
}

async fn info(State(srv): State<Server>, _auth: Auth) -> Json<Value> {
    let sh = &srv.shared;
    Json(json!({
        "version": env!("CARGO_PKG_VERSION"),
        "server_key": hex::encode(sh.noise_public),
        "fingerprint": cjs_transport::keys::fingerprint(&sh.noise_public),
        "capability_key": hex::encode(sh.cap_key.verifying_key().as_bytes()),
        "audit_key": hex::encode(sh.audit.verifying_key().as_bytes()),
    }))
}

// ---------------------------------------------------------------------------
// Users
// ---------------------------------------------------------------------------

async fn list_users(State(srv): State<Server>, auth: Auth) -> R<Json<Value>> {
    auth.require(Role::Sysadmin)?;
    Ok(Json(json!(srv.shared.db.users()?)))
}

#[derive(Deserialize)]
struct CreateUser {
    name: String,
    #[serde(default)]
    roles: Vec<Role>,
    #[serde(default)]
    display_name: Option<String>,
    #[serde(default)]
    expires_at: Option<i64>,
}

fn new_credentials(u: &User, password: &str, secret: &str) -> Value {
    json!({
        "user": user_json(u),
        "password": password,
        "totp_secret": secret,
        "otpauth_url": accounts::otpauth_url(secret, &u.name),
    })
}

async fn create_user(State(srv): State<Server>, auth: Auth, Body(req): Body<CreateUser>) -> R<Json<Value>> {
    auth.require(Role::Sysadmin)?;
    let sh = &srv.shared;
    if sh.db.user(&req.name)?.is_some() {
        return Err(ApiError::new(ErrorCode::Conflict, "user exists"));
    }
    let mut nu = accounts::create_user(&req.name, req.roles.clone(), None)?;
    if let Some(d) = req.display_name {
        nu.user.display_name = d;
    }
    nu.user.expires_at = req.expires_at;
    sh.audit(
        auth.event("admin.user.create", &nu.user.id)
            .highlight(!req.roles.is_empty())
            .data(json!({"name": nu.user.name, "roles": req.roles, "expires_at": req.expires_at})),
    )?;
    sh.db.insert_user(&nu.user)?;
    Ok(Json(new_credentials(&nu.user, &nu.password, &nu.totp_secret)))
}

#[derive(Deserialize)]
struct PatchUser {
    status: Option<String>,
    roles: Option<Vec<Role>>,
    display_name: Option<String>,
    /// `0` clears the expiry.
    expires_at: Option<i64>,
}

fn load_user(srv: &Server, id: &str) -> R<User> {
    srv.shared.db.user(id)?.ok_or_else(|| ApiError::not_found("no such user"))
}

async fn patch_user(
    State(srv): State<Server>,
    auth: Auth,
    Path(id): Path<String>,
    Body(req): Body<PatchUser>,
) -> R<Json<Value>> {
    auth.require(Role::Sysadmin)?;
    let sh = &srv.shared;
    let mut u = load_user(&srv, &id)?;
    if u.id == auth.user.id && (req.status.is_some() || req.roles.is_some()) {
        return Err(ApiError::forbidden(
            "you cannot change your own status or roles; ask another administrator",
        ));
    }
    if let Some(s) = &req.status {
        if s != "active" && s != "disabled" {
            return Err(ApiError::bad("status must be active or disabled"));
        }
        u.status = s.clone();
    }
    if let Some(r) = &req.roles {
        cjs_authz::validate_roles(r).map_err(ApiError::bad)?;
        u.roles = r.clone();
    }
    if let Some(d) = &req.display_name {
        u.display_name = d.clone();
    }
    if let Some(e) = req.expires_at {
        u.expires_at = (e != 0).then_some(e);
    }
    sh.audit(
        auth.event("admin.user.update", &u.id)
            .highlight(req.roles.is_some() || req.status.is_some())
            .data(json!({"name": u.name, "status": req.status, "roles": req.roles, "expires_at": req.expires_at})),
    )?;
    sh.db.update_user(&u)?;
    if u.status != "active" {
        sh.db.delete_user_sessions(&u.id)?;
    }
    srv.enforce();
    Ok(Json(user_json(&u)))
}

async fn reset_user(State(srv): State<Server>, auth: Auth, Path(id): Path<String>) -> R<Json<Value>> {
    auth.require(Role::Sysadmin)?;
    let sh = &srv.shared;
    let mut u = load_user(&srv, &id)?;
    if u.id == auth.user.id {
        return Err(ApiError::forbidden("use the password change instead"));
    }
    let password = accounts::random_password();
    let secret = accounts::new_totp_secret();
    sh.audit(auth.event("admin.user.reset", &u.id).highlight(true).data(json!({"name": u.name})))?;
    u.password_hash = accounts::hash_password(&password)?;
    u.totp_secret = secret.clone();
    u.last_totp_step = 0;
    u.failed_logins = 0;
    u.locked_until = None;
    sh.db.update_user(&u)?;
    sh.db.delete_user_sessions(&u.id)?;
    Ok(Json(new_credentials(&u, &password, &secret)))
}

async fn unlock_user(State(srv): State<Server>, auth: Auth, Path(id): Path<String>) -> R<Json<Value>> {
    auth.require(Role::Sysadmin)?;
    let sh = &srv.shared;
    let mut u = load_user(&srv, &id)?;
    sh.audit(auth.event("admin.user.unlock", &u.id))?;
    u.failed_logins = 0;
    u.locked_until = None;
    sh.db.update_user(&u)?;
    Ok(Json(user_json(&u)))
}

// ---------------------------------------------------------------------------
// Agents and devices
// ---------------------------------------------------------------------------

async fn list_agents(State(srv): State<Server>, auth: Auth) -> R<Json<Value>> {
    let sh = &srv.shared;
    let all = auth.user.has(Role::Sysadmin) || auth.user.has(Role::Secadmin) || auth.user.has(Role::Auditor);
    let v: Vec<Value> = sh
        .db
        .agents()?
        .into_iter()
        .filter(|a| all || a.owner_id == auth.user.id)
        .map(|a| {
            let mut v = serde_json::to_value(&a).unwrap_or_default();
            v["online"] = json!(sh.reg.conns().iter().any(|c| c.principal == a.id));
            v
        })
        .collect();
    Ok(Json(json!(v)))
}

#[derive(Deserialize)]
struct PatchStatus {
    status: Option<String>,
    expires_at: Option<i64>,
}

async fn patch_agent(
    State(srv): State<Server>,
    auth: Auth,
    Path(id): Path<String>,
    Body(req): Body<PatchStatus>,
) -> R<Json<Value>> {
    let sh = &srv.shared;
    let a = sh.db.agent(&id)?.ok_or_else(|| ApiError::not_found("no such agent"))?;
    let is_owner = a.owner_id == auth.user.id;
    if !auth.user.has(Role::Sysadmin) {
        // Owners may only switch their own agents off.
        if !is_owner || req.status.as_deref() != Some("disabled") || req.expires_at.is_some() {
            return Err(ApiError::forbidden("owners can only disable their own agents"));
        }
    }
    if let Some(s) = &req.status {
        if s != "active" && s != "disabled" {
            return Err(ApiError::bad("status must be active or disabled"));
        }
    }
    sh.audit(
        auth.event("admin.agent.update", &a.id)
            .highlight(true)
            .data(json!({"name": a.name, "status": req.status, "expires_at": req.expires_at})),
    )?;
    if let Some(s) = &req.status {
        sh.db.set_agent_status(&a.id, s)?;
    }
    if let Some(e) = req.expires_at {
        sh.db.with(|c| {
            c.execute(
                "UPDATE agents SET expires_at=?2 WHERE id=?1",
                rusqlite::params![a.id, (e != 0).then_some(e)],
            )
        })?;
    }
    srv.enforce();
    Ok(Json(json!(sh.db.agent(&a.id)?)))
}

async fn delete_agent(State(srv): State<Server>, auth: Auth, Path(id): Path<String>) -> R<Json<Value>> {
    let sh = &srv.shared;
    let a = sh.db.agent(&id)?.ok_or_else(|| ApiError::not_found("no such agent"))?;
    if !auth.user.has(Role::Sysadmin) && a.owner_id != auth.user.id {
        return Err(ApiError::forbidden("not your agent"));
    }
    sh.audit(auth.event("admin.agent.delete", &a.id).highlight(true).data(json!({"name": a.name})))?;
    sh.db.delete_agent(&a.id)?;
    srv.enforce();
    Ok(Json(json!({"ok": true})))
}

async fn list_devices(State(srv): State<Server>, _auth: Auth) -> R<Json<Value>> {
    let sh = &srv.shared;
    let v: Vec<Value> = sh
        .db
        .devices()?
        .into_iter()
        .map(|d| {
            let mut v = serde_json::to_value(&d).unwrap_or_default();
            v["online"] = json!(sh.reg.is_online(&d.id));
            v
        })
        .collect();
    Ok(Json(json!(v)))
}

async fn patch_device(
    State(srv): State<Server>,
    auth: Auth,
    Path(id): Path<String>,
    Body(req): Body<PatchStatus>,
) -> R<Json<Value>> {
    auth.require(Role::Sysadmin)?;
    let sh = &srv.shared;
    let d = sh.db.device(&id)?.ok_or_else(|| ApiError::not_found("no such device"))?;
    let status = req.status.ok_or_else(|| ApiError::bad("status is required"))?;
    if status != "active" && status != "disabled" {
        return Err(ApiError::bad("status must be active or disabled"));
    }
    sh.audit(
        auth.event("admin.device.update", &d.id)
            .highlight(true)
            .data(json!({"name": d.name, "status": status})),
    )?;
    sh.db.set_device_status(&d.id, &status)?;
    srv.enforce();
    Ok(Json(json!(sh.db.device(&d.id)?)))
}

async fn delete_device(State(srv): State<Server>, auth: Auth, Path(id): Path<String>) -> R<Json<Value>> {
    auth.require(Role::Sysadmin)?;
    let sh = &srv.shared;
    let d = sh.db.device(&id)?.ok_or_else(|| ApiError::not_found("no such device"))?;
    sh.audit(auth.event("admin.device.delete", &d.id).highlight(true).data(json!({"name": d.name})))?;
    sh.db.delete_device(&d.id)?;
    srv.enforce();
    Ok(Json(json!({"ok": true})))
}

// ---------------------------------------------------------------------------
// Groups
// ---------------------------------------------------------------------------

async fn list_groups(State(srv): State<Server>, _auth: Auth) -> R<Json<Value>> {
    Ok(Json(json!(srv.shared.db.groups()?)))
}

#[derive(Deserialize)]
struct CreateGroup {
    name: String,
    kind: String,
    #[serde(default)]
    description: String,
}

fn valid_name(n: &str) -> R<()> {
    if n.is_empty() || n.len() > 64 || !n.chars().all(|c| c.is_ascii_alphanumeric() || "-_.".contains(c)) {
        return Err(ApiError::bad("name must be 1-64 chars of [A-Za-z0-9-_.]"));
    }
    Ok(())
}

async fn create_group(State(srv): State<Server>, auth: Auth, Body(req): Body<CreateGroup>) -> R<Json<Value>> {
    auth.require(Role::Sysadmin)?;
    valid_name(&req.name)?;
    if !["user", "agent", "device"].contains(&req.kind.as_str()) {
        return Err(ApiError::bad("kind must be user, agent or device"));
    }
    let sh = &srv.shared;
    let g = Group {
        id: new_id("g"),
        name: req.name,
        kind: req.kind,
        description: req.description,
        members: vec![],
        created_at: now(),
    };
    sh.audit(auth.event("admin.group.create", &g.id).data(json!({"name": g.name, "kind": g.kind})))?;
    sh.db.insert_group(&g)?;
    Ok(Json(json!(g)))
}

fn load_group(srv: &Server, id: &str) -> R<Group> {
    srv.shared.db.group(id)?.ok_or_else(|| ApiError::not_found("no such group"))
}

async fn delete_group(State(srv): State<Server>, auth: Auth, Path(id): Path<String>) -> R<Json<Value>> {
    auth.require(Role::Sysadmin)?;
    let g = load_group(&srv, &id)?;
    srv.shared
        .audit(auth.event("admin.group.delete", &g.id).highlight(true).data(json!({"name": g.name})))?;
    srv.shared.db.delete_group(&g.id)?;
    srv.enforce();
    Ok(Json(json!({"ok": true})))
}

async fn membership(srv: &Server, auth: &Auth, id: &str, member: &str, present: bool) -> R<Json<Value>> {
    auth.require(Role::Sysadmin)?;
    let sh = &srv.shared;
    let g = load_group(srv, id)?;
    let member_id = match g.kind.as_str() {
        "user" => sh.db.user(member)?.map(|u| u.id),
        "agent" => sh.db.agent(member)?.map(|a| a.id),
        _ => sh.db.device(member)?.map(|d| d.id),
    }
    .ok_or_else(|| ApiError::not_found(format!("no such {}", g.kind)))?;
    sh.audit(
        auth.event(if present { "admin.group.add" } else { "admin.group.remove" }, &g.id)
            .highlight(true)
            .data(json!({"group": g.name, "member": member_id})),
    )?;
    sh.db.set_membership(&g.id, &member_id, present)?;
    srv.enforce();
    Ok(Json(json!(load_group(srv, &g.id)?)))
}

async fn add_member(State(srv): State<Server>, auth: Auth, Path((id, member)): Path<(String, String)>) -> R<Json<Value>> {
    membership(&srv, &auth, &id, &member, true).await
}

async fn remove_member(
    State(srv): State<Server>,
    auth: Auth,
    Path((id, member)): Path<(String, String)>,
) -> R<Json<Value>> {
    membership(&srv, &auth, &id, &member, false).await
}

// ---------------------------------------------------------------------------
// Enrollment tokens
// ---------------------------------------------------------------------------

async fn list_tokens(State(srv): State<Server>, auth: Auth) -> R<Json<Value>> {
    let all = auth.user.has(Role::Sysadmin);
    let v: Vec<_> = srv
        .shared
        .db
        .enroll_tokens()?
        .into_iter()
        .filter(|t| all || t.created_by == auth.user.id)
        .collect();
    Ok(Json(json!(v)))
}

#[derive(Deserialize)]
struct CreateToken {
    kind: String,
    name: String,
    owner: Option<String>,
    #[serde(default = "day")]
    ttl_secs: i64,
}

fn day() -> i64 {
    86400
}

async fn create_token(State(srv): State<Server>, auth: Auth, Body(req): Body<CreateToken>) -> R<Json<Value>> {
    let kind = match req.kind.as_str() {
        "agent" => ClientRole::Agent,
        "device" => ClientRole::Device,
        _ => return Err(ApiError::bad("kind must be agent or device")),
    };
    let owner = match kind {
        ClientRole::Device => {
            auth.require(Role::Sysadmin)?;
            None
        }
        ClientRole::Agent => {
            let o = req.owner.clone().unwrap_or_else(|| auth.user.id.clone());
            let o = srv.shared.db.user(&o)?.ok_or_else(|| ApiError::not_found("no such owner"))?;
            if o.id != auth.user.id {
                auth.require(Role::Sysadmin)?;
            }
            Some(o.id)
        }
    };
    let (row, token) = srv.create_enroll_token(kind, &req.name, owner.as_deref(), &auth.user.id, req.ttl_secs)?;
    Ok(Json(json!({"token": token, "info": row})))
}

// ---------------------------------------------------------------------------
// Grants
// ---------------------------------------------------------------------------

async fn list_grants(State(srv): State<Server>, auth: Auth) -> R<Json<Value>> {
    auth.require_any(&[Role::Secadmin, Role::Auditor])?;
    Ok(Json(json!(srv.shared.db.grants()?)))
}

fn check_refs(srv: &Server, g: &Grant) -> R<()> {
    let db = &srv.shared.db;
    match &g.subject {
        Subject::Principal(p) => {
            if db.agent(p)?.is_none() {
                return Err(ApiError::bad(format!("no agent {p}")));
            }
        }
        Subject::Group(gid) => match db.group(gid)? {
            Some(x) if x.kind == "agent" => {}
            _ => return Err(ApiError::bad(format!("no agent group {gid}"))),
        },
    }
    match &g.target {
        Target::Device(d) => {
            if db.device(d)?.is_none() {
                return Err(ApiError::bad(format!("no device {d}")));
            }
        }
        Target::DeviceGroup(gid) => match db.group(gid)? {
            Some(x) if x.kind == "device" => {}
            _ => return Err(ApiError::bad(format!("no device group {gid}"))),
        },
        Target::Server => {}
    }
    Ok(())
}

/// Store references by id so renames cannot redirect a grant.
fn normalize_refs(srv: &Server, g: &mut Grant) -> R<()> {
    let db = &srv.shared.db;
    match &mut g.subject {
        Subject::Principal(p) => {
            if let Some(a) = db.agent(p)? {
                *p = a.id;
            }
        }
        Subject::Group(x) => {
            if let Some(gr) = db.group(x)? {
                *x = gr.id;
            }
        }
    }
    match &mut g.target {
        Target::Device(d) => {
            if let Some(dev) = db.device(d)? {
                *d = dev.id;
            }
        }
        Target::DeviceGroup(x) => {
            if let Some(gr) = db.group(x)? {
                *x = gr.id;
            }
        }
        Target::Server => {}
    }
    Ok(())
}

async fn put_grant(
    State(srv): State<Server>,
    auth: Auth,
    Path(id): Path<String>,
    Body(mut g): Body<Grant>,
) -> R<Json<Value>> {
    auth.require(Role::Secadmin)?;
    valid_name(&id)?;
    g.id = id;
    if g.name.is_empty() {
        g.name = g.id.clone();
    }
    g.validate().map_err(ApiError::bad)?;
    check_refs(&srv, &g)?;
    normalize_refs(&srv, &mut g)?;
    let sh = &srv.shared;
    let existed = sh.db.grant(&g.id)?.is_some();
    sh.audit(
        auth.event(if existed { "admin.grant.update" } else { "admin.grant.create" }, &g.id)
            .highlight(true)
            .data(serde_json::to_value(&g).unwrap_or_default()),
    )?;
    sh.db.upsert_grant(&g, &auth.user.id)?;
    srv.enforce();
    Ok(Json(json!(g)))
}

async fn delete_grant(State(srv): State<Server>, auth: Auth, Path(id): Path<String>) -> R<Json<Value>> {
    auth.require(Role::Secadmin)?;
    let sh = &srv.shared;
    if sh.db.grant(&id)?.is_none() {
        return Err(ApiError::not_found("no such grant"));
    }
    sh.audit(auth.event("admin.grant.delete", &id).highlight(true))?;
    sh.db.delete_grant(&id)?;
    srv.enforce();
    Ok(Json(json!({"ok": true})))
}

// ---------------------------------------------------------------------------
// Full access (two-person rule)
// ---------------------------------------------------------------------------

async fn list_full(State(srv): State<Server>, auth: Auth) -> R<Json<Value>> {
    let sh = &srv.shared;
    let privileged = auth.user.has(Role::Secadmin) || auth.user.has(Role::Auditor);
    let mine: BTreeSet<String> = sh
        .db
        .agents()?
        .into_iter()
        .filter(|a| a.owner_id == auth.user.id)
        .map(|a| a.id)
        .collect();
    let v: Vec<_> = sh
        .db
        .full_access_all()?
        .into_iter()
        .filter(|f| privileged || f.requested_by == auth.user.id || mine.contains(&f.principal))
        .collect();
    Ok(Json(json!(v)))
}

#[derive(Deserialize)]
struct FullReq {
    agent: String,
    device: String,
    reason: String,
    duration_secs: i64,
}

async fn request_full(State(srv): State<Server>, auth: Auth, Body(req): Body<FullReq>) -> R<Json<Value>> {
    let sh = &srv.shared;
    let a = sh.db.agent(&req.agent)?.ok_or_else(|| ApiError::not_found("no such agent"))?;
    let d = sh.db.device(&req.device)?.ok_or_else(|| ApiError::not_found("no such device"))?;
    if a.owner_id != auth.user.id {
        auth.require(Role::Secadmin)?;
    }
    if req.reason.trim().len() < 5 {
        return Err(ApiError::bad("a reason is required"));
    }
    if req.duration_secs <= 0 || req.duration_secs > cjs_authz::MAX_FULL_ACCESS_SECS {
        return Err(ApiError::bad(format!(
            "duration must be between 1 and {} seconds",
            cjs_authz::MAX_FULL_ACCESS_SECS
        )));
    }
    let f = FullAccess {
        id: new_id("fa"),
        principal: a.id.clone(),
        device: d.id.clone(),
        reason: req.reason.trim().to_string(),
        requested_by: auth.user.id.clone(),
        duration_secs: req.duration_secs,
        status: ApprovalStatus::Pending,
        approved_by: None,
        decided_at: None,
        expires_at: None,
        created_at: now(),
    };
    sh.audit(
        auth.event("admin.full_access.request", &f.id)
            .highlight(true)
            .data(serde_json::to_value(&f).unwrap_or_default()),
    )?;
    sh.db.put_full_access(&f)?;
    Ok(Json(json!(f)))
}

fn load_full(srv: &Server, id: &str) -> R<FullAccess> {
    srv.shared
        .db
        .full_access(id)?
        .ok_or_else(|| ApiError::not_found("no such request"))
}

async fn approve_full(State(srv): State<Server>, auth: Auth, Path(id): Path<String>) -> R<Json<Value>> {
    auth.require(Role::Secadmin)?;
    let sh = &srv.shared;
    let mut f = load_full(&srv, &id)?;
    let owner = sh.db.agent(&f.principal)?.map(|a| a.owner_id);
    f.approve(&auth.user.id, &auth.user.roles, owner.as_deref(), now())
        .map_err(ApiError::forbidden)?;
    sh.audit(
        auth.event("admin.full_access.approve", &f.id)
            .highlight(true)
            .data(serde_json::to_value(&f).unwrap_or_default()),
    )?;
    sh.db.put_full_access(&f)?;
    Ok(Json(json!(f)))
}

async fn decide_full(srv: &Server, auth: &Auth, id: &str, to: ApprovalStatus) -> R<Json<Value>> {
    auth.require(Role::Secadmin)?;
    let sh = &srv.shared;
    let mut f = load_full(srv, id)?;
    let ok = match to {
        ApprovalStatus::Rejected => f.status == ApprovalStatus::Pending,
        ApprovalStatus::Revoked => f.status == ApprovalStatus::Approved,
        _ => false,
    };
    if !ok {
        return Err(ApiError::new(ErrorCode::Conflict, format!("request is {}", f.status.as_str())));
    }
    f.status = to;
    f.decided_at = Some(now());
    if to == ApprovalStatus::Revoked {
        f.expires_at = Some(now());
    }
    sh.audit(
        auth.event(&format!("admin.full_access.{}", to.as_str()), &f.id)
            .highlight(true)
            .data(serde_json::to_value(&f).unwrap_or_default()),
    )?;
    sh.db.put_full_access(&f)?;
    srv.enforce();
    Ok(Json(json!(f)))
}

async fn reject_full(State(srv): State<Server>, auth: Auth, Path(id): Path<String>) -> R<Json<Value>> {
    decide_full(&srv, &auth, &id, ApprovalStatus::Rejected).await
}

async fn revoke_full(State(srv): State<Server>, auth: Auth, Path(id): Path<String>) -> R<Json<Value>> {
    decide_full(&srv, &auth, &id, ApprovalStatus::Revoked).await
}

// ---------------------------------------------------------------------------
// Live sessions
// ---------------------------------------------------------------------------

async fn live_connections(State(srv): State<Server>, auth: Auth) -> R<Json<Value>> {
    auth.require_any(&[Role::Secadmin, Role::Auditor])?;
    Ok(Json(json!(srv.shared.conn_summaries())))
}

async fn live_streams(State(srv): State<Server>, auth: Auth) -> R<Json<Value>> {
    auth.require_any(&[Role::Secadmin, Role::Auditor])?;
    Ok(Json(json!(srv.shared.stream_summaries())))
}

async fn kill_session(State(srv): State<Server>, auth: Auth, Path(session): Path<String>) -> R<Json<Value>> {
    auth.require(Role::Secadmin)?;
    let sh = &srv.shared;
    let streams = sh.reg.stream_by_session(&session);
    if streams.is_empty() {
        return Err(ApiError::not_found("no such live session"));
    }
    sh.audit(auth.event("admin.session.kill", &session).highlight(true).session(session.clone()))?;
    for s in streams {
        s.terminate(cjs_proto::ProtoError::new(ErrorCode::Cancelled, "terminated by a security administrator"));
    }
    Ok(Json(json!({"ok": true})))
}

async fn kick_connection(State(srv): State<Server>, auth: Auth, Path(id): Path<String>) -> R<Json<Value>> {
    auth.require(Role::Secadmin)?;
    let sh = &srv.shared;
    let c = sh.reg.conn(&id).ok_or_else(|| ApiError::not_found("no such connection"))?;
    sh.audit(
        auth.event("admin.connection.kick", &c.principal)
            .highlight(true)
            .data(json!({"connection": c.id})),
    )?;
    c.session
        .close(cjs_proto::ProtoError::new(ErrorCode::Cancelled, "disconnected by a security administrator"));
    Ok(Json(json!({"ok": true})))
}

// ---------------------------------------------------------------------------
// Audit
// ---------------------------------------------------------------------------

async fn audit_query(State(srv): State<Server>, auth: Auth, Query(q): Query<cjs_audit::Query>) -> R<Json<Value>> {
    auth.require(Role::Auditor)?;
    let sh = &srv.shared;
    sh.audit(auth.event("audit.query", "audit").data(json!({
        "kind": q.kind, "actor": q.actor, "session": q.session, "target": q.target, "text": q.text,
    })))?;
    Ok(Json(json!(sh.audit.query(&q)?)))
}

async fn audit_verify(State(srv): State<Server>, auth: Auth) -> R<Json<Value>> {
    auth.require(Role::Auditor)?;
    let sh = &srv.shared;
    let r = sh.audit.verify(None)?;
    sh.audit(auth.event("audit.verify", "audit").data(json!({"ok": r.ok, "events": r.events})))?;
    Ok(Json(json!(r)))
}

async fn audit_export(State(srv): State<Server>, auth: Auth) -> R<Response> {
    auth.require(Role::Auditor)?;
    let sh = &srv.shared;
    sh.audit(auth.event("audit.export", "audit"))?;
    sh.audit.checkpoint()?;
    let mut buf = Vec::new();
    sh.audit.export_jsonl(&mut buf)?;
    Ok((
        StatusCode::OK,
        [
            (header::CONTENT_TYPE, "application/x-ndjson"),
            (header::CONTENT_DISPOSITION, "attachment; filename=\"cjs-audit.jsonl\""),
        ],
        buf,
    )
        .into_response())
}

async fn audit_checkpoint(State(srv): State<Server>, auth: Auth) -> R<Json<Value>> {
    auth.require(Role::Auditor)?;
    let sh = &srv.shared;
    sh.audit(auth.event("audit.checkpoint", "audit"))?;
    Ok(Json(json!({"seq": sh.audit.checkpoint()?})))
}

async fn recording(State(srv): State<Server>, auth: Auth, Path(session): Path<String>) -> R<Response> {
    auth.require(Role::Auditor)?;
    if session.is_empty() || !session.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
        return Err(ApiError::bad("bad session id"));
    }
    let sh = &srv.shared;
    let path = sh.cfg.recordings_dir.join(format!("{session}.cast"));
    let data = std::fs::read(&path).map_err(|_| ApiError::not_found("no recording for this session"))?;
    sh.audit(auth.event("audit.recording.view", &session).session(session.clone()))?;
    Ok((
        StatusCode::OK,
        [(header::CONTENT_TYPE, "application/x-asciicast")],
        data,
    )
        .into_response())
}

// ---------------------------------------------------------------------------
// OpenAPI
// ---------------------------------------------------------------------------

pub fn openapi_doc() -> Value {
    let mut paths = serde_json::Map::new();
    for (method, path, role, summary) in ROUTES {
        let params: Vec<Value> = path
            .split('/')
            .filter_map(|seg| seg.strip_prefix('{').and_then(|s| s.strip_suffix('}')))
            .map(|n| json!({"name": n, "in": "path", "required": true, "schema": {"type": "string"}}))
            .collect();
        let mut op = json!({
            "summary": summary,
            "description": format!("Required role: {role}"),
            "parameters": params,
            "responses": {
                "200": {"description": "OK"},
                "default": {"description": "Error", "content": {"application/json": {"schema": {"$ref": "#/components/schemas/Error"}}}}
            },
        });
        if *role == "-" {
            op["security"] = json!([]);
        }
        if *method != "get" && *role != "-" {
            op["parameters"]
                .as_array_mut()
                .expect("array")
                .push(json!({"name": "X-CSRF-Token", "in": "header", "required": true, "schema": {"type": "string"}}));
        }
        let entry = paths.entry(path.to_string()).or_insert_with(|| json!({}));
        entry[*method] = op;
    }
    json!({
        "openapi": "3.1.0",
        "info": {"title": "ClawdJumpServer API", "version": env!("CARGO_PKG_VERSION")},
        "paths": paths,
        "components": {
            "securitySchemes": {"session": {"type": "apiKey", "in": "cookie", "name": COOKIE}},
            "schemas": {"Error": {"type": "object", "properties": {"error": {"type": "object", "properties": {
                "code": {"type": "string"}, "message": {"type": "string"}}}}}}
        },
        "security": [{"session": []}],
    })
}

async fn openapi() -> Json<Value> {
    Json(openapi_doc())
}
