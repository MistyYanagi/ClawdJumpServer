//! Gateway: authenticates agents and devices during the Noise handshake,
//! runs one yamux connection per session, and keeps re-checking every
//! lease (account, owner, device, grants, full-access approvals) so that a
//! revocation cuts live connections and streams within one lease interval
//! (immediately when triggered through the API).
use std::sync::Arc;

use cjs_audit::{Event, Outcome};
use cjs_proto::{ErrorCode, Hello, ProtoError, Role, Welcome};
use cjs_transport::{Accepted, Authenticator, TransportServer, TransportServerConfig};
use serde_json::json;

use crate::accounts::sha256_hex;
use crate::db::{new_id, now, Agent, Device};
use crate::keys::Keys;
use crate::state::{ConnInfo, ServerConfig, Shared};
use crate::{db::Db, relay};

struct GatewayAuth(Arc<Shared>);

fn role_str(r: Role) -> &'static str {
    match r {
        Role::Agent => "agent",
        Role::Device => "device",
    }
}

impl GatewayAuth {
    fn check(&self, key: &[u8; 32], hello: &Hello, peer: Option<&str>) -> Result<Welcome, ProtoError> {
        let sh = &self.0;
        let pk = hex::encode(key);
        let (id, name) = match hello.role {
            Role::Agent => {
                let a = match sh.db.agent_by_key(&pk).map_err(|e| e.proto())? {
                    Some(a) => a,
                    None => match &hello.enroll {
                        Some(e) => self.enroll(Role::Agent, &e.secret, &pk, hello, peer)?.0,
                        None => {
                            return Err(ProtoError::new(ErrorCode::Unauthenticated, "unknown client key"))
                        }
                    },
                };
                // Status of the agent and of its responsible user.
                let p = sh.principal(&a.id)?;
                (p.id, p.name)
            }
            Role::Device => {
                let d = match sh.db.device_by_key(&pk).map_err(|e| e.proto())? {
                    Some(d) => d,
                    None => match &hello.enroll {
                        Some(e) => self.enroll(Role::Device, &e.secret, &pk, hello, peer)?.1,
                        None => {
                            return Err(ProtoError::new(ErrorCode::Unauthenticated, "unknown client key"))
                        }
                    },
                };
                let d = sh.device_usable(&d.id)?;
                (d.id, d.name)
            }
        };
        Ok(Welcome {
            principal_id: id,
            name,
            connection_id: new_id("c"),
            signing_key: sh.cap_key.verifying_key().to_bytes(),
            server_time: now(),
        })
    }

    /// Redeem a one-time enrollment token for a new client key.
    fn enroll(
        &self,
        role: Role,
        secret: &str,
        pk: &str,
        hello: &Hello,
        peer: Option<&str>,
    ) -> Result<(Agent, Device), ProtoError> {
        let sh = &self.0;
        let invalid = || ProtoError::new(ErrorCode::Unauthenticated, "invalid enrollment token");
        let t = sh
            .db
            .enroll_token_by_hash(&sha256_hex(secret))
            .map_err(|e| e.proto())?
            .ok_or_else(invalid)?;
        if t.kind != role_str(role) {
            return Err(invalid());
        }
        if t.used_at.is_some() {
            return Err(ProtoError::new(
                ErrorCode::Replay,
                "enrollment token already used",
            ));
        }
        if now() >= t.expires_at {
            return Err(ProtoError::new(ErrorCode::Expired, "enrollment token expired"));
        }
        let id = new_id(if role == Role::Agent { "a" } else { "d" });
        if !sh.db.consume_enroll_token(&t.id, &id).map_err(|e| e.proto())? {
            return Err(ProtoError::new(
                ErrorCode::Replay,
                "enrollment token already used",
            ));
        }
        let info = serde_json::to_value(&hello.info).unwrap_or_default();
        sh.audit(
            Event::new(
                &format!("enroll.{}", role_str(role)),
                &id,
                &t.name,
                Outcome::Success,
            )
            .ip(peer.map(String::from))
            .data(json!({"token": t.id, "name": t.name, "owner": t.owner_id, "pubkey": pk, "info": info})),
        )
        .map_err(|e| e.proto())?;
        let created_at = now();
        let agent = Agent {
            id: id.clone(),
            name: t.name.clone(),
            owner_id: t.owner_id.clone().unwrap_or_default(),
            pubkey: pk.into(),
            status: "active".into(),
            expires_at: None,
            info: info.clone(),
            last_seen: None,
            created_at,
            groups: vec![],
        };
        let device = Device {
            id: id.clone(),
            name: t.name.clone(),
            pubkey: pk.into(),
            status: "active".into(),
            info,
            last_seen: None,
            created_at,
            groups: vec![],
        };
        match role {
            Role::Agent => {
                if agent.owner_id.is_empty() {
                    return Err(ProtoError::new(ErrorCode::BadRequest, "agent token has no owner"));
                }
                sh.db.insert_agent(&agent).map_err(|e| e.proto())?
            }
            Role::Device => sh.db.insert_device(&device).map_err(|e| e.proto())?,
        }
        Ok((agent, device))
    }
}

impl Authenticator for GatewayAuth {
    fn authenticate(&self, key: &[u8; 32], hello: &Hello, peer: Option<&str>) -> Result<Welcome, ProtoError> {
        let r = self.check(key, hello, peer);
        let fp = cjs_transport::keys::fingerprint(key);
        match &r {
            Ok(w) => {
                // Fail closed: no audit record, no connection.
                self.0
                    .audit(
                        Event::new("gateway.connect", &w.principal_id, "gateway", Outcome::Success)
                            .ip(peer.map(String::from))
                            .data(json!({
                                "role": role_str(hello.role),
                                "connection": w.connection_id,
                                "key": fp,
                                "client": hello.info,
                            })),
                    )
                    .map_err(|e| e.proto())?;
            }
            Err(e) => {
                let _ = self.0.audit(
                    Event::new("gateway.reject", "anonymous", "gateway", Outcome::Denied)
                        .ip(peer.map(String::from))
                        .data(json!({"role": role_str(hello.role), "key": fp, "code": e.code.as_str(), "reason": e.message})),
                );
            }
        }
        r
    }

    fn rejected(&self, key: Option<&[u8; 32]>, err: &ProtoError, peer: Option<&str>) {
        let _ = self.0.audit(
            Event::new("gateway.reject", "anonymous", "gateway", Outcome::Denied)
                .ip(peer.map(String::from))
                .data(json!({
                    "key": key.map(cjs_transport::keys::fingerprint),
                    "code": err.code.as_str(),
                    "reason": err.message,
                })),
        );
    }
}

/// The running bastion: gateway, relay and lease enforcement.
#[derive(Clone)]
pub struct Server {
    pub shared: Arc<Shared>,
    pub transport: TransportServer,
}

impl std::fmt::Debug for Server {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Server")
    }
}

impl Server {
    /// Start the gateway. Must be called inside a tokio runtime.
    pub fn start(cfg: ServerConfig, keys: Keys, db: Db, audit: cjs_audit::AuditLog) -> Self {
        let lease = cfg.lease_interval;
        let trust = cfg.trust_forwarded_for;
        let shared = Arc::new(Shared::new(db, audit, keys.cap, keys.noise.public, cfg));
        let (transport, accepted) = TransportServer::new(TransportServerConfig {
            key: keys.noise,
            auth: Arc::new(GatewayAuth(shared.clone())),
            trust_forwarded_for: trust,
        });
        let srv = Self { shared, transport };
        let s2 = srv.clone();
        tokio::spawn(async move { s2.accept_loop(accepted).await });
        let weak = Arc::downgrade(&srv.shared);
        tokio::spawn(async move {
            let mut t = tokio::time::interval(lease);
            t.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            loop {
                t.tick().await;
                let Some(sh) = weak.upgrade() else { return };
                enforce(&sh);
            }
        });
        // Sign the audit head regularly so the unsigned tail stays short.
        let weak = Arc::downgrade(&srv.shared);
        tokio::spawn(async move {
            let mut t = tokio::time::interval(std::time::Duration::from_secs(60));
            loop {
                t.tick().await;
                let Some(sh) = weak.upgrade() else { return };
                let (head, cp) = (sh.audit.head_seq(), sh.audit.last_checkpoint());
                if let (Ok(h), Ok(c)) = (head, cp) {
                    if h > c {
                        if let Err(e) = sh.audit.checkpoint() {
                            tracing::error!(err = %e, "audit checkpoint failed");
                        }
                    }
                }
            }
        });
        srv
    }

    /// Re-check every lease now (called after administrative changes).
    pub fn enforce(&self) {
        enforce(&self.shared)
    }

    async fn accept_loop(&self, mut rx: tokio::sync::mpsc::Receiver<Accepted>) {
        while let Some(a) = rx.recv().await {
            let sh = self.shared.clone();
            tokio::spawn(run_conn(sh, a));
        }
    }
}

async fn run_conn(sh: Arc<Shared>, a: Accepted) {
    let role = a.hello.role;
    let (mux, mut inbound, _task) = cjs_mux::spawn(a.io, cjs_mux::Mode::Server);
    let conn = Arc::new(ConnInfo {
        id: a.welcome.connection_id.clone(),
        role,
        principal: a.welcome.principal_id.clone(),
        name: a.welcome.name.clone(),
        info: a.hello.info.clone(),
        transport: a.transport,
        peer: a.peer.clone(),
        since: now(),
        mux: mux.clone(),
        session: a.handle.clone(),
    });
    let info = serde_json::to_value(&a.hello.info).unwrap_or_default();
    let _ = match role {
        Role::Agent => sh.db.touch_agent(&conn.principal, &info),
        Role::Device => sh.db.touch_device(&conn.principal, &info),
    };
    if let Some(old) = sh.reg.add_conn(conn.clone()) {
        old.session.close(ProtoError::new(
            ErrorCode::Conflict,
            "superseded by a newer connection",
        ));
    }
    tracing::info!(conn = %conn.id, principal = %conn.principal, role = role_str(role), transport = conn.transport, "connected");
    loop {
        tokio::select! {
            s = inbound.recv() => match s {
                Some(s) => {
                    let sh = sh.clone();
                    let c = conn.clone();
                    tokio::spawn(async move {
                        match role {
                            Role::Agent => relay::agent_stream(sh, c, s).await,
                            Role::Device => relay::device_stream(sh, c, s).await,
                        }
                    });
                }
                None => break,
            },
            e = a.handle.closed() => {
                tracing::debug!(err = %e, "session closed");
                break;
            }
        }
    }
    mux.close().await;
    a.handle
        .close(ProtoError::new(ErrorCode::Cancelled, "connection closed"));
    sh.reg.remove_conn(&conn.id);
    let _ = match role {
        Role::Agent => sh.db.touch_agent(&conn.principal, &info),
        Role::Device => sh.db.touch_device(&conn.principal, &info),
    };
    let _ = sh.audit(
        Event::new("gateway.disconnect", &conn.principal, "gateway", Outcome::Info)
            .ip(conn.peer.clone())
            .data(json!({"connection": conn.id, "duration_secs": now() - conn.since})),
    );
    tracing::info!(conn = %conn.id, "disconnected");
}

/// Cut every connection and stream whose lease no longer holds.
pub(crate) fn enforce(sh: &Shared) {
    for c in sh.reg.conns() {
        let check = match c.role {
            Role::Agent => sh.principal(&c.principal).map(|_| ()),
            Role::Device => sh.device_usable(&c.principal).map(|_| ()),
        };
        if let Err(e) = check {
            if c.session.is_closed() {
                continue;
            }
            let _ = sh.audit(
                Event::new("gateway.kick", &c.principal, "gateway", Outcome::Info)
                    .ip(c.peer.clone())
                    .data(json!({"connection": c.id, "code": e.code.as_str(), "reason": e.message})),
            );
            c.session.close(e);
        }
    }
    for s in sh.reg.streams() {
        if s.cancel.is_cancelled() {
            continue;
        }
        let why = match sh.principal(&s.principal) {
            Err(e) => Some(e),
            Ok(p) => match sh.decide(&p, &s.req, Some(s.id)) {
                Err(e) => Some(e.proto()),
                Ok((d, _)) if !d.allow => Some(ProtoError::new(
                    d.code.unwrap_or(ErrorCode::Forbidden),
                    format!("access revoked: {}", d.reason),
                )),
                Ok((d, _)) if s.full_access && d.full_access.is_none() => {
                    Some(ProtoError::new(ErrorCode::Expired, "full access approval ended"))
                }
                Ok(_) => None,
            },
        };
        let why = why.or_else(|| s.device.as_ref().and_then(|d| sh.device_usable(d).err()));
        if let Some(e) = why {
            let _ = sh.audit(
                Event::new("session.revoked", &s.principal, &s.target, Outcome::Info)
                    .session(s.session.clone())
                    .data(json!({"stream": s.id, "kind": s.kind.as_str(), "code": e.code.as_str(), "reason": e.message})),
            );
            s.terminate(e);
        }
    }
}

impl Server {
    /// Issue a one-time enrollment token (`cjs1.<server key>.<secret>`).
    /// Only the secret's SHA-256 is stored. Audited (fail closed).
    pub fn create_enroll_token(
        &self,
        kind: Role,
        name: &str,
        owner: Option<&str>,
        created_by: &str,
        ttl_secs: i64,
    ) -> Result<(crate::db::EnrollTokenRow, String), crate::error::ApiError> {
        use crate::error::ApiError;
        let sh = &self.shared;
        if name.is_empty()
            || name.len() > 64
            || !name
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || "-_.".contains(c))
        {
            return Err(ApiError::bad("name must be 1-64 chars of [A-Za-z0-9-_.]"));
        }
        if !(60..=30 * 86400).contains(&ttl_secs) {
            return Err(ApiError::bad("ttl must be between 60s and 30 days"));
        }
        let taken = match kind {
            Role::Agent => sh.db.agent(name)?.is_some(),
            Role::Device => sh.db.device(name)?.is_some(),
        };
        if taken {
            return Err(ApiError::new(
                ErrorCode::Conflict,
                format!("{} {name} already exists", role_str(kind)),
            ));
        }
        if kind == Role::Agent {
            let o = owner.ok_or_else(|| ApiError::bad("agent tokens need an owner"))?;
            if sh.db.user(o)?.is_none() {
                return Err(ApiError::not_found("owner not found"));
            }
        }
        let owner_id = match owner {
            Some(o) => sh.db.user(o)?.map(|u| u.id),
            None => None,
        };
        let secret = crate::accounts::random_token(32);
        let t = now();
        let row = crate::db::EnrollTokenRow {
            id: new_id("t"),
            kind: role_str(kind).into(),
            name: name.into(),
            owner_id: if kind == Role::Agent { owner_id } else { None },
            created_by: created_by.into(),
            expires_at: t + ttl_secs,
            used_at: None,
            used_by: None,
            created_at: t,
        };
        sh.audit(
            Event::new("admin.token.create", created_by, name, Outcome::Success)
                .data(json!({"token": row.id, "kind": row.kind, "owner": row.owner_id, "expires_at": row.expires_at})),
        )?;
        sh.db.insert_enroll_token(&row, &sha256_hex(&secret))?;
        let token = cjs_proto::EnrollToken {
            server_key: sh.noise_public,
            secret,
        }
        .encode();
        Ok((row, token))
    }
}

impl Server {
    /// All HTTP routes: transport (`/v1/t/*`), REST API (`/api/v1/*`) and
    /// the web UI, with security headers on every response. Serve it with
    /// `into_make_service_with_connect_info::<SocketAddr>()` so client
    /// addresses are audited.
    pub fn router(&self) -> axum::Router {
        self.transport
            .router()
            .merge(crate::api::router(self.clone()))
            .fallback(crate::web::static_file)
            .layer(axum::middleware::from_fn(crate::web::security_headers))
    }
}
