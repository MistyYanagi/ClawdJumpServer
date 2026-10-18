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
use cjs_authz::{ApprovalStatus, FullAccess, Grant, Role, RoleChange, Subject, Target};
use cjs_proto::{ErrorCode, Role as ClientRole};
use serde::Deserialize;
use serde_json::{json, Value};
use subtle::ConstantTimeEq;

use crate::accounts::{self, random_token, sha256_hex};
use crate::db::{new_id, now, Group, User, UserPatch};
use crate::error::ApiError;
use crate::gateway::Server;

pub const COOKIE: &str = "cjs_session";
/// Cookie name when cookies are `Secure` (TLS): the `__Host-` prefix pins
/// the cookie to this host (no `Domain`, `Path=/`, HTTPS only).
pub const SECURE_COOKIE: &str = "__Host-cjs_session";

pub fn cookie_name(secure: bool) -> &'static str {
    if secure {
        SECURE_COOKIE
    } else {
        COOKIE
    }
}

/// The address a trusted reverse proxy saw: the *rightmost* entry of
/// `X-Forwarded-For` (the one the proxy appended). Entries to its left are
/// supplied by the client and cannot be trusted.
pub fn forwarded_client(xff: &str) -> Option<String> {
    let last = xff.rsplit(',').next()?.trim();
    last.parse::<std::net::IpAddr>().ok().map(|ip| ip.to_string())
}

/// Client address of an API request: the socket peer, or with
/// `trust_forwarded` the proxy-appended `X-Forwarded-For` entry.
pub fn client_ip(ext: &axum::http::Extensions, headers: &HeaderMap, trust_forwarded: bool) -> Option<String> {
    if trust_forwarded {
        let all: Vec<&str> = headers
            .get_all("x-forwarded-for")
            .iter()
            .filter_map(|v| v.to_str().ok())
            .collect();
        if let Some(last) = all.last().and_then(|v| forwarded_client(v)) {
            return Some(last);
        }
    }
    ext.get::<axum::extract::ConnectInfo<std::net::SocketAddr>>()
        .map(|c| c.0.ip().to_string())
}
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
            Err(ApiError::forbidden(format!(
                "requires one of the roles {}",
                names.join(", ")
            )))
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
        let ip = client_ip(&parts.extensions, &parts.headers, sh.cfg.trust_forwarded_for);
        let token = cookie_value(&parts.headers, cookie_name(sh.cfg.secure_cookies))
            .ok_or_else(|| ApiError::unauth("not logged in"))?;
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
        let user = sh
            .db
            .user(&uid)?
            .ok_or_else(|| ApiError::unauth("session expired"))?;
        // A login lockout does not end existing sessions; disable and
        // expiry do.
        if let Err(why) = user.active(t) {
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
        "{}={token}; Path=/; HttpOnly; SameSite=Strict; Max-Age={max_age}{}",
        cookie_name(secure),
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
    (
        "post",
        "/api/v1/login",
        "-",
        "Log in with name, password and TOTP code",
    ),
    ("post", "/api/v1/logout", "any", "End the current session"),
    ("get", "/api/v1/me", "any", "Current user and CSRF token"),
    (
        "post",
        "/api/v1/me/password",
        "any",
        "Change own password (needs TOTP)",
    ),
    ("get", "/api/v1/info", "any", "Server version and key fingerprint"),
    ("get", "/api/v1/users", "sysadmin", "List users"),
    (
        "post",
        "/api/v1/users",
        "sysadmin",
        "Create a user (returns initial password and TOTP secret once)",
    ),
    (
        "patch",
        "/api/v1/users/{id}",
        "sysadmin",
        "Change status, roles, display name or expiry (granting a role needs secadmin approval)",
    ),
    (
        "post",
        "/api/v1/users/{id}/reset",
        "sysadmin",
        "Reset password and TOTP (users without roles; others only on the server host)",
    ),
    (
        "get",
        "/api/v1/role-changes",
        "sysadmin|secadmin|auditor",
        "List requested role changes",
    ),
    (
        "post",
        "/api/v1/role-changes/{id}/approve",
        "secadmin",
        "Approve a role change (not the requester, not the user)",
    ),
    (
        "post",
        "/api/v1/role-changes/{id}/reject",
        "secadmin|requester",
        "Reject or withdraw a pending role change",
    ),
    (
        "post",
        "/api/v1/users/{id}/unlock",
        "sysadmin",
        "Clear a login lockout",
    ),
    (
        "get",
        "/api/v1/agents",
        "any",
        "List agents (own agents unless sysadmin)",
    ),
    (
        "patch",
        "/api/v1/agents/{id}",
        "sysadmin|owner",
        "Enable/disable an agent or set its expiry",
    ),
    (
        "delete",
        "/api/v1/agents/{id}",
        "sysadmin|owner",
        "Delete an agent",
    ),
    (
        "get",
        "/api/v1/devices",
        "any",
        "List devices (others: only devices their agents are granted)",
    ),
    (
        "patch",
        "/api/v1/devices/{id}",
        "sysadmin",
        "Enable or disable a device",
    ),
    ("delete", "/api/v1/devices/{id}", "sysadmin", "Delete a device"),
    (
        "get",
        "/api/v1/groups",
        "any",
        "List groups (others: only groups of themselves and their agents)",
    ),
    (
        "post",
        "/api/v1/groups",
        "sysadmin",
        "Create a group (kind user, agent or device)",
    ),
    ("delete", "/api/v1/groups/{id}", "sysadmin", "Delete a group"),
    (
        "put",
        "/api/v1/groups/{id}/members/{member}",
        "sysadmin",
        "Add a member",
    ),
    (
        "delete",
        "/api/v1/groups/{id}/members/{member}",
        "sysadmin",
        "Remove a member",
    ),
    (
        "get",
        "/api/v1/tokens",
        "any",
        "List enrollment tokens (own unless sysadmin)",
    ),
    (
        "post",
        "/api/v1/tokens",
        "any",
        "Create an enrollment token (devices: sysadmin)",
    ),
    ("get", "/api/v1/grants", "secadmin|auditor", "List grants"),
    (
        "put",
        "/api/v1/grants/{id}",
        "secadmin",
        "Create or replace a grant",
    ),
    ("delete", "/api/v1/grants/{id}", "secadmin", "Delete a grant"),
    ("get", "/api/v1/full-access", "any", "List full-access requests"),
    (
        "post",
        "/api/v1/full-access",
        "any",
        "Request full access for an agent on a device",
    ),
    (
        "post",
        "/api/v1/full-access/{id}/approve",
        "secadmin",
        "Approve (two-person rule)",
    ),
    (
        "post",
        "/api/v1/full-access/{id}/reject",
        "secadmin",
        "Reject a pending request",
    ),
    (
        "post",
        "/api/v1/full-access/{id}/revoke",
        "secadmin",
        "Revoke an approval",
    ),
    (
        "get",
        "/api/v1/live/connections",
        "secadmin|auditor",
        "Connected agents and devices",
    ),
    ("get", "/api/v1/live/streams", "secadmin|auditor", "Open sessions"),
    (
        "post",
        "/api/v1/live/sessions/{session}/kill",
        "secadmin",
        "Terminate a session",
    ),
    (
        "post",
        "/api/v1/live/connections/{id}/kick",
        "secadmin",
        "Disconnect a client",
    ),
    ("get", "/api/v1/audit", "auditor", "Query the audit log"),
    (
        "get",
        "/api/v1/audit/verify",
        "auditor",
        "Verify the hash chain and signed checkpoints",
    ),
    (
        "get",
        "/api/v1/audit/export",
        "auditor",
        "Export events and checkpoints (JSON lines)",
    ),
    (
        "post",
        "/api/v1/audit/checkpoint",
        "auditor",
        "Sign the current head now",
    ),
    (
        "get",
        "/api/v1/recordings/{session}",
        "auditor",
        "Download a terminal recording (asciicast v2)",
    ),
    (
        "get",
        "/api/v1/sessions/{session}/live",
        "secadmin|auditor",
        "Watch a terminal session: long-poll for recording events after a byte offset (read-only)",
    ),
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
        .route("/api/v1/role-changes", get(list_role_changes))
        .route("/api/v1/role-changes/{id}/approve", post(approve_role_change))
        .route("/api/v1/role-changes/{id}/reject", post(reject_role_change))
        .route("/api/v1/agents", get(list_agents))
        .route(
            "/api/v1/agents/{id}",
            axum::routing::patch(patch_agent).delete(delete_agent),
        )
        .route("/api/v1/devices", get(list_devices))
        .route(
            "/api/v1/devices/{id}",
            axum::routing::patch(patch_device).delete(delete_device),
        )
        .route("/api/v1/groups", get(list_groups).post(create_group))
        .route("/api/v1/groups/{id}", delete(delete_group))
        .route(
            "/api/v1/groups/{id}/members/{member}",
            put(add_member).delete(remove_member),
        )
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
        .route("/api/v1/sessions/{session}/live", get(watch_session))
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
    let ip = client_ip(&ext, &headers, sh.cfg.trust_forwarded_for);
    if !same_origin(&headers) {
        return Err(ApiError::forbidden("cross-origin request refused"));
    }
    let key = ip.clone().unwrap_or_else(|| "unknown".into());
    let t = now();
    // Reserve this attempt against the per-address budget *before* the
    // credentials are checked, so concurrent requests cannot all slip in.
    {
        let mut f = sh.login_failures.lock().unwrap_or_else(|p| p.into_inner());
        f.retain(|_, (_, start)| t - *start < IP_WINDOW_SECS);
        let entry = f.entry(key.clone()).or_insert((0, t));
        if entry.0 >= IP_MAX_FAILURES {
            drop(f);
            let _ = sh.audit(
                Event::new("auth.login", "anonymous", "web", Outcome::Denied)
                    .ip(ip.clone())
                    .data(json!({"user": req.name, "reason": "too many failures from this address"})),
            );
            return Err(ApiError::new(
                ErrorCode::LimitExceeded,
                "too many failed logins; try again later",
            ));
        }
        entry.0 += 1;
    }
    let res = accounts::login(&sh.db, &sh.audit, &req.name, &req.password, &req.totp, ip.clone());
    if res
        .as_ref()
        .map(|_| true)
        .unwrap_or_else(|e| e.code == ErrorCode::AuditFailure)
    {
        // Not a failed guess: give the reservation back.
        let mut f = sh.login_failures.lock().unwrap_or_else(|p| p.into_inner());
        if let Some(e) = f.get_mut(&key) {
            e.0 = e.0.saturating_sub(1);
        }
    }
    let user = res?;
    let _ = sh
        .db
        .purge_web_sessions(sh.cfg.web_idle_secs, sh.cfg.web_max_secs);
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

async fn change_password(
    State(srv): State<Server>,
    auth: Auth,
    Body(req): Body<PasswordReq>,
) -> R<Json<Value>> {
    let sh = &srv.shared;
    accounts::check_password_policy(&req.new)?;
    // Same checks, lockout counting and answer as a login.
    let u = sh
        .db
        .user(&auth.user.id)?
        .ok_or_else(|| ApiError::unauth("session expired"))?;
    if let Err(reason) = accounts::check_credentials(&sh.db, &u, &req.old, &req.totp)? {
        sh.audit(
            Event::new("auth.password_change", &u.id, &u.id, Outcome::Denied)
                .ip(auth.ip.clone())
                .data(json!({"reason": reason})),
        )?;
        return Err(ApiError::forbidden("invalid credentials"));
    }
    sh.audit(auth.event("auth.password_change", &u.id))?;
    let new_hash = accounts::hash_password(&req.new)?;
    if !sh.db.set_password(&u.id, &u.password_hash, &new_hash)? {
        return Err(ApiError::new(
            ErrorCode::Conflict,
            "the password was changed concurrently",
        ));
    }
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

/// Request a change of `u`'s roles to `roles`. Changes that only remove
/// roles are returned as `None` (apply directly); changes that grant a
/// privileged role are stored as pending and audited.
fn request_role_change(srv: &Server, auth: &Auth, u: &User, roles: &[Role]) -> R<Option<RoleChange>> {
    cjs_authz::validate_roles(roles).map_err(ApiError::bad)?;
    let added = cjs_authz::added_roles(&u.roles, roles);
    if !added.iter().any(|r| cjs_authz::PRIVILEGED_ROLES.contains(r)) {
        return Ok(None);
    }
    let mut roles = roles.to_vec();
    roles.sort();
    roles.dedup();
    let rc = RoleChange {
        id: new_id("rc"),
        user_id: u.id.clone(),
        user_name: u.name.clone(),
        from_roles: u.roles.clone(),
        roles,
        requested_by: auth.user.id.clone(),
        status: ApprovalStatus::Pending,
        decided_by: None,
        decided_at: None,
        created_at: now(),
    };
    srv.shared.audit(
        auth.event("admin.role_change.request", &u.id)
            .highlight(true)
            .data(serde_json::to_value(&rc).unwrap_or_default()),
    )?;
    srv.shared.db.insert_role_change(&rc)?;
    Ok(Some(rc))
}

async fn create_user(State(srv): State<Server>, auth: Auth, Body(req): Body<CreateUser>) -> R<Json<Value>> {
    auth.require(Role::Sysadmin)?;
    let sh = &srv.shared;
    if sh.db.user(&req.name)?.is_some() {
        return Err(ApiError::new(ErrorCode::Conflict, "user exists"));
    }
    cjs_authz::validate_roles(&req.roles).map_err(ApiError::bad)?;
    // The account starts without roles: every role is privileged and needs
    // a second person (a secadmin) to approve it.
    let mut nu = accounts::create_user(&req.name, vec![], None)?;
    if let Some(d) = req.display_name {
        nu.user.display_name = d;
    }
    nu.user.expires_at = req.expires_at;
    sh.audit(
        auth.event("admin.user.create", &nu.user.id)
            .highlight(!req.roles.is_empty())
            .data(json!({"name": nu.user.name, "requested_roles": req.roles, "expires_at": req.expires_at})),
    )?;
    sh.db.insert_user(&nu.user)?;
    let pending = request_role_change(&srv, &auth, &nu.user, &req.roles)?;
    let mut v = new_credentials(&nu.user, &nu.password, &nu.totp_secret);
    v["pending_role_change"] = json!(pending);
    Ok(Json(v))
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
    srv.shared
        .db
        .user(id)?
        .ok_or_else(|| ApiError::not_found("no such user"))
}

async fn patch_user(
    State(srv): State<Server>,
    auth: Auth,
    Path(id): Path<String>,
    Body(req): Body<PatchUser>,
) -> R<Json<Value>> {
    auth.require(Role::Sysadmin)?;
    let sh = &srv.shared;
    let u = load_user(&srv, &id)?;
    if u.id == auth.user.id && (req.status.is_some() || req.roles.is_some() || req.expires_at.is_some()) {
        return Err(ApiError::forbidden(
            "you cannot change your own status, roles or expiry; ask another administrator",
        ));
    }
    if let Some(s) = &req.status {
        if s != "active" && s != "disabled" {
            return Err(ApiError::bad("status must be active or disabled"));
        }
    }
    // Granting a role only creates a pending request; removing roles
    // applies at once.
    let mut pending = None;
    let mut direct_roles = None;
    if let Some(r) = &req.roles {
        pending = request_role_change(&srv, &auth, &u, r)?;
        if pending.is_none() {
            direct_roles = Some(r.clone());
        }
    }
    let patch = UserPatch {
        status: req.status.as_deref(),
        roles: direct_roles.as_deref(),
        display_name: req.display_name.as_deref(),
        expires_at: req.expires_at.map(|e| (e != 0).then_some(e)),
    };
    let changes = patch.status.is_some()
        || patch.roles.is_some()
        || patch.display_name.is_some()
        || patch.expires_at.is_some();
    let mut out = u.clone();
    if changes {
        sh.audit(
            auth.event("admin.user.update", &u.id)
                .highlight(direct_roles.is_some() || req.status.is_some())
                .data(json!({"name": u.name, "status": req.status, "roles": direct_roles, "expires_at": req.expires_at})),
        )?;
        out = sh.db.patch_user(&u.id, &patch, now())?;
        out.groups = u.groups.clone();
        if out.active(now()).is_err() {
            sh.db.delete_user_sessions(&u.id)?;
        }
        srv.enforce();
    }
    let mut v = user_json(&out);
    v["pending_role_change"] = json!(pending);
    Ok(Json(v))
}

async fn reset_user(State(srv): State<Server>, auth: Auth, Path(id): Path<String>) -> R<Json<Value>> {
    auth.require(Role::Sysadmin)?;
    let sh = &srv.shared;
    let u = load_user(&srv, &id)?;
    if u.id == auth.user.id {
        return Err(ApiError::forbidden("use the password change instead"));
    }
    if !u.roles.is_empty() {
        // The new credentials would be handed to the requester, who could
        // then act as that administrator, secadmin or auditor.
        return Err(ApiError::forbidden(
            "credentials of users with roles can only be reset on the server host (cjs-server reset-user)",
        ));
    }
    let password = accounts::random_password();
    let secret = accounts::new_totp_secret();
    sh.audit(
        auth.event("admin.user.reset", &u.id)
            .highlight(true)
            .data(json!({"name": u.name})),
    )?;
    sh.db
        .reset_credentials(&u.id, &accounts::hash_password(&password)?, &secret)?;
    sh.db.delete_user_sessions(&u.id)?;
    let u = load_user(&srv, &u.id)?;
    Ok(Json(new_credentials(&u, &password, &secret)))
}

async fn unlock_user(State(srv): State<Server>, auth: Auth, Path(id): Path<String>) -> R<Json<Value>> {
    auth.require(Role::Sysadmin)?;
    let sh = &srv.shared;
    let u = load_user(&srv, &id)?;
    sh.audit(auth.event("admin.user.unlock", &u.id))?;
    sh.db.unlock_user(&u.id)?;
    Ok(Json(user_json(&load_user(&srv, &u.id)?)))
}

// ---------------------------------------------------------------------------
// Role changes (two-person rule for privileged roles)
// ---------------------------------------------------------------------------

async fn list_role_changes(State(srv): State<Server>, auth: Auth) -> R<Json<Value>> {
    auth.require_any(&[Role::Sysadmin, Role::Secadmin, Role::Auditor])?;
    Ok(Json(json!(srv.shared.db.role_changes()?)))
}

fn load_role_change(srv: &Server, id: &str) -> R<RoleChange> {
    srv.shared
        .db
        .role_change(id)?
        .ok_or_else(|| ApiError::not_found("no such request"))
}

async fn approve_role_change(
    State(srv): State<Server>,
    auth: Auth,
    Path(id): Path<String>,
) -> R<Json<Value>> {
    auth.require(Role::Secadmin)?;
    let sh = &srv.shared;
    let mut rc = load_role_change(&srv, &id)?;
    let t = now();
    rc.approve(&auth.user.id, &auth.user.roles, t)
        .map_err(ApiError::forbidden)?;
    sh.audit(
        auth.event("admin.role_change.approve", &rc.user_id)
            .highlight(true)
            .data(serde_json::to_value(&rc).unwrap_or_default()),
    )?;
    sh.db.apply_role_change(&rc, t)?;
    srv.enforce();
    Ok(Json(json!(rc)))
}

async fn reject_role_change(State(srv): State<Server>, auth: Auth, Path(id): Path<String>) -> R<Json<Value>> {
    let sh = &srv.shared;
    let mut rc = load_role_change(&srv, &id)?;
    if rc.requested_by != auth.user.id {
        auth.require(Role::Secadmin)?;
    }
    if rc.status != ApprovalStatus::Pending {
        return Err(ApiError::new(
            ErrorCode::Conflict,
            format!("request is {}", rc.status.as_str()),
        ));
    }
    rc.status = ApprovalStatus::Rejected;
    rc.decided_by = Some(auth.user.id.clone());
    rc.decided_at = Some(now());
    sh.audit(
        auth.event("admin.role_change.reject", &rc.user_id)
            .highlight(true)
            .data(serde_json::to_value(&rc).unwrap_or_default()),
    )?;
    if !sh.db.reject_role_change(&rc)? {
        return Err(ApiError::new(ErrorCode::Conflict, "request is no longer pending"));
    }
    Ok(Json(json!(rc)))
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
    let a = sh
        .db
        .agent(&id)?
        .ok_or_else(|| ApiError::not_found("no such agent"))?;
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
    let a = sh
        .db
        .agent(&id)?
        .ok_or_else(|| ApiError::not_found("no such agent"))?;
    if !auth.user.has(Role::Sysadmin) {
        if a.owner_id != auth.user.id {
            return Err(ApiError::forbidden("not your agent"));
        }
        // A disabled agent stays until a sysadmin removes it (and its key
        // is then revoked), so an owner cannot undo a disable by deleting
        // and re-enrolling.
        if a.status != "active" {
            return Err(ApiError::forbidden(
                "a disabled agent can only be deleted by a sysadmin",
            ));
        }
    }
    sh.audit(
        auth.event("admin.agent.delete", &a.id)
            .highlight(true)
            .data(json!({"name": a.name})),
    )?;
    sh.db.delete_agent(&a.id)?;
    srv.enforce();
    Ok(Json(json!({"ok": true})))
}

fn sees_inventory(auth: &Auth) -> bool {
    auth.user.has(Role::Sysadmin) || auth.user.has(Role::Secadmin) || auth.user.has(Role::Auditor)
}

/// Ids of the devices on which one of `owner`'s agents has any grant now.
fn granted_devices(srv: &Server, owner: &str) -> R<BTreeSet<String>> {
    let db = &srv.shared.db;
    let agents: Vec<_> = db.agents()?.into_iter().filter(|a| a.owner_id == owner).collect();
    let mut out = BTreeSet::new();
    if agents.is_empty() {
        return Ok(out);
    }
    let grants: Vec<_> = db.grants()?.into_iter().map(|g| g.grant).collect();
    let full = db.full_access_all()?;
    let t = now();
    let zero = |_: &str| 0u32;
    for d in db.devices()? {
        for a in &agents {
            let ar = cjs_authz::AccessRequest {
                principal: &a.id,
                principal_groups: &a.groups,
                device: Some(&d.id),
                device_groups: &d.groups,
                action: cjs_proto::Action::Shell,
                net: None,
                active: &zero,
                now: t,
            };
            if !cjs_authz::visible(&ar, &grants, &full).actions.is_empty() {
                out.insert(d.id.clone());
                break;
            }
        }
    }
    Ok(out)
}

async fn list_devices(State(srv): State<Server>, auth: Auth) -> R<Json<Value>> {
    let sh = &srv.shared;
    let all = sees_inventory(&auth);
    let mine = if all {
        BTreeSet::new()
    } else {
        granted_devices(&srv, &auth.user.id)?
    };
    let v: Vec<Value> = sh
        .db
        .devices()?
        .into_iter()
        .filter(|d| all || mine.contains(&d.id))
        .map(|d| {
            let mut v = serde_json::to_value(&d).unwrap_or_default();
            v["online"] = json!(sh.reg.is_online(&d.id));
            if !all {
                if let Some(o) = v.as_object_mut() {
                    o.remove("pubkey");
                }
            }
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
    let d = sh
        .db
        .device(&id)?
        .ok_or_else(|| ApiError::not_found("no such device"))?;
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
    let d = sh
        .db
        .device(&id)?
        .ok_or_else(|| ApiError::not_found("no such device"))?;
    sh.audit(
        auth.event("admin.device.delete", &d.id)
            .highlight(true)
            .data(json!({"name": d.name})),
    )?;
    sh.db.delete_device(&d.id)?;
    srv.enforce();
    Ok(Json(json!({"ok": true})))
}

// ---------------------------------------------------------------------------
// Groups
// ---------------------------------------------------------------------------

async fn list_groups(State(srv): State<Server>, auth: Auth) -> R<Json<Value>> {
    let db = &srv.shared.db;
    if sees_inventory(&auth) {
        return Ok(Json(json!(db.groups()?)));
    }
    // Others see only the groups they or their agents belong to, and only
    // themselves / their agents as members.
    let mut own: BTreeSet<String> = db
        .agents()?
        .into_iter()
        .filter(|a| a.owner_id == auth.user.id)
        .map(|a| a.id)
        .collect();
    own.insert(auth.user.id.clone());
    let v: Vec<Group> = db
        .groups()?
        .into_iter()
        .filter(|g| g.members.iter().any(|m| own.contains(m)))
        .map(|mut g| {
            g.members.retain(|m| own.contains(m));
            g
        })
        .collect();
    Ok(Json(json!(v)))
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
    sh.audit(
        auth.event("admin.group.create", &g.id)
            .data(json!({"name": g.name, "kind": g.kind})),
    )?;
    sh.db.insert_group(&g)?;
    Ok(Json(json!(g)))
}

fn load_group(srv: &Server, id: &str) -> R<Group> {
    srv.shared
        .db
        .group(id)?
        .ok_or_else(|| ApiError::not_found("no such group"))
}

async fn delete_group(State(srv): State<Server>, auth: Auth, Path(id): Path<String>) -> R<Json<Value>> {
    auth.require(Role::Sysadmin)?;
    let g = load_group(&srv, &id)?;
    srv.shared.audit(
        auth.event("admin.group.delete", &g.id)
            .highlight(true)
            .data(json!({"name": g.name})),
    )?;
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
        auth.event(
            if present {
                "admin.group.add"
            } else {
                "admin.group.remove"
            },
            &g.id,
        )
        .highlight(true)
        .data(json!({"group": g.name, "member": member_id})),
    )?;
    sh.db.set_membership(&g.id, &member_id, present)?;
    srv.enforce();
    Ok(Json(json!(load_group(srv, &g.id)?)))
}

async fn add_member(
    State(srv): State<Server>,
    auth: Auth,
    Path((id, member)): Path<(String, String)>,
) -> R<Json<Value>> {
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
            let o = srv
                .shared
                .db
                .user(&o)?
                .ok_or_else(|| ApiError::not_found("no such owner"))?;
            if o.id != auth.user.id {
                auth.require(Role::Sysadmin)?;
            }
            Some(o.id)
        }
    };
    let (row, token) =
        srv.create_enroll_token(kind, &req.name, owner.as_deref(), &auth.user.id, req.ttl_secs)?;
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
        auth.event(
            if existed {
                "admin.grant.update"
            } else {
                "admin.grant.create"
            },
            &g.id,
        )
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
    let a = sh
        .db
        .agent(&req.agent)?
        .ok_or_else(|| ApiError::not_found("no such agent"))?;
    let d = sh
        .db
        .device(&req.device)?
        .ok_or_else(|| ApiError::not_found("no such device"))?;
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
    if !sh.db.transition_full_access(&f, ApprovalStatus::Pending)? {
        return Err(ApiError::new(ErrorCode::Conflict, "request is no longer pending"));
    }
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
        return Err(ApiError::new(
            ErrorCode::Conflict,
            format!("request is {}", f.status.as_str()),
        ));
    }
    let from = f.status;
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
    if !sh.db.transition_full_access(&f, from)? {
        return Err(ApiError::new(ErrorCode::Conflict, "request changed concurrently"));
    }
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
    sh.audit(
        auth.event("admin.session.kill", &session)
            .highlight(true)
            .session(session.clone()),
    )?;
    for s in streams {
        s.terminate(cjs_proto::ProtoError::new(
            ErrorCode::Cancelled,
            "terminated by a security administrator",
        ));
    }
    Ok(Json(json!({"ok": true})))
}

async fn kick_connection(State(srv): State<Server>, auth: Auth, Path(id): Path<String>) -> R<Json<Value>> {
    auth.require(Role::Secadmin)?;
    let sh = &srv.shared;
    let c = sh
        .reg
        .conn(&id)
        .ok_or_else(|| ApiError::not_found("no such connection"))?;
    sh.audit(
        auth.event("admin.connection.kick", &c.principal)
            .highlight(true)
            .data(json!({"connection": c.id})),
    )?;
    c.session.close(cjs_proto::ProtoError::new(
        ErrorCode::Cancelled,
        "disconnected by a security administrator",
    ));
    Ok(Json(json!({"ok": true})))
}

// ---------------------------------------------------------------------------
// Audit
// ---------------------------------------------------------------------------

async fn audit_query(
    State(srv): State<Server>,
    auth: Auth,
    Query(q): Query<cjs_audit::Query>,
) -> R<Json<Value>> {
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
    sh.audit(
        auth.event("audit.verify", "audit")
            .data(json!({"ok": r.ok, "events": r.events})),
    )?;
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
            (
                header::CONTENT_DISPOSITION,
                "attachment; filename=\"cjs-audit.jsonl\"",
            ),
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
    sh.audit(
        auth.event("audit.recording.view", &session)
            .session(session.clone()),
    )?;
    Ok((
        StatusCode::OK,
        [(header::CONTENT_TYPE, "application/x-asciicast")],
        data,
    )
        .into_response())
}

#[derive(Deserialize)]
struct WatchQuery {
    /// Byte offset into the recording, as returned by the previous call.
    after: Option<u64>,
    /// Long-poll timeout in seconds (0..=25, default 20).
    wait: Option<u64>,
}

/// Most recording bytes returned by one watch call.
const WATCH_CHUNK: u64 = 256 * 1024;

/// (web session, terminal session) pairs whose watch was audited, so a
/// watcher is audited once rather than on every poll. With `mark`, the
/// pair is recorded; returns whether it was already known.
fn watch_seen(token_hash: &str, session: &str, mark: bool) -> bool {
    use std::collections::HashSet;
    use std::sync::{Mutex, OnceLock};
    static SEEN: OnceLock<Mutex<HashSet<(String, String)>>> = OnceLock::new();
    let mut seen = SEEN
        .get_or_init(Default::default)
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    let key = (token_hash.to_string(), session.to_string());
    if !mark {
        return seen.contains(&key);
    }
    if seen.len() > 10_000 {
        seen.clear();
    }
    !seen.insert(key)
}

/// The complete lines of `path` after byte `after` (at most
/// [`WATCH_CHUNK`] bytes) and the offset just past them.
async fn read_cast_lines(path: &std::path::Path, after: u64) -> R<(Vec<String>, u64)> {
    use tokio::io::{AsyncReadExt, AsyncSeekExt};
    let mut f = tokio::fs::File::open(path)
        .await
        .map_err(|_| ApiError::not_found("no recording for this session"))?;
    let len = f
        .metadata()
        .await
        .map_err(|e| ApiError::internal(e.to_string()))?
        .len();
    if after > len {
        return Err(ApiError::bad("offset beyond the end of the recording"));
    }
    f.seek(std::io::SeekFrom::Start(after))
        .await
        .map_err(|e| ApiError::internal(e.to_string()))?;
    let mut buf = Vec::new();
    f.take(WATCH_CHUNK.min(len - after))
        .read_to_end(&mut buf)
        .await
        .map_err(|e| ApiError::internal(e.to_string()))?;
    // Whole lines only: the recorder may be in the middle of one.
    let end = buf.iter().rposition(|b| *b == b'\n').map_or(0, |i| i + 1);
    let lines = String::from_utf8_lossy(&buf[..end])
        .lines()
        .filter(|l| !l.is_empty())
        .map(str::to_string)
        .collect();
    Ok((lines, after + end as u64))
}

/// Read-only live view of a terminal session. The session's asciicast
/// recording is read from byte `after` on; when nothing new is there and
/// the session is still open, the call waits up to `wait` seconds. Only
/// output and resize events are returned: keystrokes can hold secrets and
/// stay in the (separately audited) recording download. The first watch
/// of a session per web session is audited as `session.watch`.
async fn watch_session(
    State(srv): State<Server>,
    auth: Auth,
    Path(session): Path<String>,
    Query(q): Query<WatchQuery>,
) -> R<Json<Value>> {
    auth.require_any(&[Role::Secadmin, Role::Auditor])?;
    if session.is_empty() || !session.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
        return Err(ApiError::bad("bad session id"));
    }
    let sh = &srv.shared;
    let path = sh.cfg.recordings_dir.join(format!("{session}.cast"));
    if !path.is_file() {
        return Err(ApiError::not_found("no terminal recording for this session"));
    }
    let after = q.after.unwrap_or(0);
    if !watch_seen(&auth.token_hash, &session, false) {
        sh.audit(
            auth.event("session.watch", &session)
                .highlight(true)
                .session(session.clone())
                .data(json!({"live": !sh.reg.stream_by_session(&session).is_empty(), "after": after})),
        )?;
        watch_seen(&auth.token_hash, &session, true);
    }
    let wait = std::time::Duration::from_secs(q.wait.unwrap_or(20).min(25));
    let deadline = tokio::time::Instant::now() + wait;
    loop {
        let live = !sh.reg.stream_by_session(&session).is_empty();
        let (lines, offset) = read_cast_lines(&path, after).await?;
        if !lines.is_empty() || !live || tokio::time::Instant::now() >= deadline {
            let mut header = Value::Null;
            let mut events = Vec::new();
            for (i, l) in lines.iter().enumerate() {
                let Ok(v) = serde_json::from_str::<Value>(l) else {
                    continue;
                };
                if after == 0 && i == 0 && v.is_object() {
                    header = v;
                } else if matches!(v[1].as_str(), Some("o" | "r")) {
                    events.push(v);
                }
            }
            return Ok(Json(json!({
                "session": session,
                "live": live,
                "offset": offset,
                "header": header,
                "events": events,
            })));
        }
        tokio::time::sleep(std::time::Duration::from_millis(250)).await;
    }
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
            "securitySchemes": {"session": {"type": "apiKey", "in": "cookie", "name": COOKIE,
                "description": "Named __Host-cjs_session when the server uses TLS"}},
            "schemas": {"Error": {"type": "object", "properties": {"error": {"type": "object", "properties": {
                "code": {"type": "string"}, "message": {"type": "string"}}}}}}
        },
        "security": [{"session": []}],
    })
}

async fn openapi() -> Json<Value> {
    Json(openapi_doc())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn forwarded_for_uses_proxy_appended_entry() {
        assert_eq!(forwarded_client("6.6.6.6, 10.0.0.7").as_deref(), Some("10.0.0.7"));
        assert_eq!(forwarded_client("10.0.0.7").as_deref(), Some("10.0.0.7"));
        assert_eq!(forwarded_client("1.2.3.4, garbage"), None);
        let mut h = HeaderMap::new();
        h.append("x-forwarded-for", HeaderValue::from_static("6.6.6.6"));
        h.append("x-forwarded-for", HeaderValue::from_static("1.1.1.1, 192.0.2.9"));
        let ext = axum::http::Extensions::new();
        assert_eq!(client_ip(&ext, &h, true).as_deref(), Some("192.0.2.9"));
        assert_eq!(client_ip(&ext, &h, false), None);
    }

    #[test]
    fn secure_cookie_uses_host_prefix() {
        let c = session_cookie("t", 10, true);
        let c = c.to_str().unwrap();
        assert!(c.starts_with("__Host-cjs_session=t;") && c.contains("; Secure") && c.contains("Path=/"));
        assert!(!c.contains("Domain"));
        assert!(session_cookie("t", 10, false)
            .to_str()
            .unwrap()
            .starts_with("cjs_session=t;"));
    }

    #[test]
    fn openapi_lists_every_route() {
        let doc = openapi_doc();
        for (m, p, _, _) in ROUTES {
            assert!(doc["paths"][*p][*m].is_object(), "{m} {p}");
        }
        assert!(doc["paths"]["/api/v1/role-changes/{id}/approve"]["post"].is_object());
    }
}
