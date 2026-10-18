//! Shared server state: storage, keys, configuration and the registry of
//! live connections, streams and remote-forward listeners.
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use cjs_audit::{AuditLog, Event};
use cjs_authz::{AccessRequest, Decision};
use cjs_mux::MuxHandle;
use cjs_proto::{ClientInfo, ErrorCode, OpenRequest, ProtoError, Role, StreamKind};
use cjs_transport::SessionHandle;
use ed25519_dalek::SigningKey;
use serde::Serialize;
use tokio_util::sync::CancellationToken;

use crate::db::{now, Db, Device};
use crate::error::ApiError;

#[derive(Debug, Clone)]
pub struct ServerConfig {
    /// Directory for asciicast recordings.
    pub recordings_dir: PathBuf,
    /// How often leases (accounts, grants, approvals) are re-checked for
    /// live connections and streams.
    pub lease_interval: Duration,
    /// Trust `X-Forwarded-For` (only behind a trusted reverse proxy).
    pub trust_forwarded_for: bool,
    /// Mark the web session cookie `Secure` (disable only for plain-HTTP
    /// test setups).
    pub secure_cookies: bool,
    /// Web session idle timeout and absolute lifetime (seconds).
    pub web_idle_secs: i64,
    pub web_max_secs: i64,
    /// Size limit of one terminal recording. A session that reaches it is
    /// terminated (recording is mandatory) and the reason is audited.
    pub max_recording_bytes: u64,
}

impl ServerConfig {
    pub fn new(data_dir: &std::path::Path) -> Self {
        Self {
            recordings_dir: data_dir.join("recordings"),
            lease_interval: Duration::from_secs(5),
            trust_forwarded_for: false,
            secure_cookies: true,
            web_idle_secs: 30 * 60,
            web_max_secs: 12 * 3600,
            max_recording_bytes: cjs_audit::recording::DEFAULT_MAX_RECORDING,
        }
    }
}

/// A live client connection (agent or device).
pub struct ConnInfo {
    pub id: String,
    pub role: Role,
    /// Agent id or device id.
    pub principal: String,
    pub name: String,
    pub info: ClientInfo,
    pub transport: &'static str,
    pub peer: Option<String>,
    pub since: i64,
    pub mux: MuxHandle,
    pub session: SessionHandle,
}

impl std::fmt::Debug for ConnInfo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ConnInfo").field("id", &self.id).finish()
    }
}

/// A live relayed stream.
pub struct StreamInfo {
    pub id: u32,
    pub session: String,
    pub kind: StreamKind,
    pub principal: String,
    /// Device id (`None` for server egress).
    pub device: Option<String>,
    /// Agent connection that opened the stream.
    pub conn: String,
    /// Device connection serving the stream.
    pub device_conn: Option<String>,
    pub grant_ids: Vec<String>,
    pub full_access: bool,
    /// Original request (agent form), re-evaluated on every lease check.
    pub req: OpenRequest,
    pub target: String,
    pub started: i64,
    pub peer: Option<String>,
    pub cancel: CancellationToken,
    reason: Mutex<Option<ProtoError>>,
}

impl std::fmt::Debug for StreamInfo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StreamInfo").field("id", &self.id).finish()
    }
}

impl StreamInfo {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        id: u32,
        session: String,
        req: OpenRequest,
        principal: String,
        device: Option<String>,
        conn: String,
        device_conn: Option<String>,
        decision: &Decision,
        target: String,
        peer: Option<String>,
    ) -> Self {
        Self {
            id,
            session,
            kind: req.kind(),
            principal,
            device,
            conn,
            device_conn,
            grant_ids: decision.grant_ids.clone(),
            full_access: decision.full_access.is_some(),
            req,
            target,
            started: now(),
            peer,
            cancel: CancellationToken::new(),
            reason: Mutex::new(None),
        }
    }

    /// Terminate the stream with a reason the relay reports to the agent.
    pub fn terminate(&self, why: ProtoError) {
        let mut r = self.reason.lock().unwrap_or_else(|p| p.into_inner());
        if r.is_none() {
            *r = Some(why);
        }
        drop(r);
        self.cancel.cancel();
    }

    pub fn reason(&self) -> ProtoError {
        self.reason
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .clone()
            .unwrap_or_else(|| ProtoError::new(ErrorCode::Cancelled, "session terminated"))
    }
}

/// A remote-forward listener on a device, opened by an agent.
#[derive(Debug)]
pub struct ListenerReg {
    pub agent_conn: String,
    /// Listener id as known by the agent (its `ForwardR` stream id).
    pub agent_listener: u32,
    pub principal: String,
    pub device: String,
    pub session: String,
    pub cancel: CancellationToken,
}

#[derive(Debug, Clone, Serialize)]
pub struct ConnSummary {
    pub id: String,
    pub role: &'static str,
    pub principal: String,
    pub name: String,
    pub transport: &'static str,
    pub peer: Option<String>,
    pub since: i64,
    pub os: String,
    pub arch: String,
    pub hostname: String,
    pub version: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct StreamSummary {
    pub id: u32,
    pub session: String,
    pub kind: &'static str,
    pub principal: String,
    pub device: Option<String>,
    pub target: String,
    pub started: i64,
    pub full_access: bool,
    pub peer: Option<String>,
}

#[derive(Default)]
struct RegInner {
    conns: HashMap<String, Arc<ConnInfo>>,
    device_conn: HashMap<String, String>,
    streams: HashMap<u32, Arc<StreamInfo>>,
    /// Admitted streams that are not registered yet (device still being
    /// contacted): stream id -> (principal, grant ids). They count against
    /// concurrency limits like live streams.
    reserved: HashMap<u32, (String, Vec<String>)>,
    listeners: HashMap<(String, u32), Arc<ListenerReg>>,
}

#[derive(Default)]
pub struct Registry {
    inner: Mutex<RegInner>,
}

impl std::fmt::Debug for Registry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Registry")
    }
}

/// Removes a stream from the registry when dropped.
pub struct StreamGuard<'a> {
    reg: &'a Registry,
    id: u32,
}

impl Drop for StreamGuard<'_> {
    fn drop(&mut self) {
        self.reg.lock().streams.remove(&self.id);
    }
}

/// A concurrency slot taken at admission; released when dropped (the
/// registered stream, if any, then keeps counting until it ends).
pub struct Reservation<'a> {
    reg: &'a Registry,
    id: u32,
}

impl std::fmt::Debug for Reservation<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Reservation").field("id", &self.id).finish()
    }
}

impl Drop for Reservation<'_> {
    fn drop(&mut self) {
        self.reg.lock().reserved.remove(&self.id);
    }
}

/// Removes a listener from the registry when dropped.
pub struct ListenerGuard<'a> {
    reg: &'a Registry,
    key: (String, u32),
}

impl Drop for ListenerGuard<'_> {
    fn drop(&mut self) {
        self.reg.lock().listeners.remove(&self.key);
    }
}

impl Registry {
    fn lock(&self) -> std::sync::MutexGuard<'_, RegInner> {
        self.inner.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// Register a connection. A device has at most one live connection: a
    /// newer one supersedes (and returns) the older.
    pub fn add_conn(&self, c: Arc<ConnInfo>) -> Option<Arc<ConnInfo>> {
        let mut g = self.lock();
        let mut old = None;
        if c.role == Role::Device {
            if let Some(prev) = g.device_conn.insert(c.principal.clone(), c.id.clone()) {
                old = g.conns.remove(&prev);
            }
        }
        g.conns.insert(c.id.clone(), c);
        old
    }

    pub fn remove_conn(&self, id: &str) {
        let mut g = self.lock();
        if let Some(c) = g.conns.remove(id) {
            if c.role == Role::Device && g.device_conn.get(&c.principal).map(|x| x == id).unwrap_or(false) {
                g.device_conn.remove(&c.principal);
            }
        }
    }

    pub fn conn(&self, id: &str) -> Option<Arc<ConnInfo>> {
        self.lock().conns.get(id).cloned()
    }

    pub fn conns(&self) -> Vec<Arc<ConnInfo>> {
        self.lock().conns.values().cloned().collect()
    }

    pub fn device_conn(&self, device_id: &str) -> Option<Arc<ConnInfo>> {
        let g = self.lock();
        let id = g.device_conn.get(device_id)?;
        g.conns.get(id).cloned()
    }

    pub fn is_online(&self, device_id: &str) -> bool {
        self.lock().device_conn.contains_key(device_id)
    }

    pub fn add_stream(&self, s: Arc<StreamInfo>) -> StreamGuard<'_> {
        let id = s.id;
        self.lock().streams.insert(id, s);
        StreamGuard { reg: self, id }
    }

    pub fn streams(&self) -> Vec<Arc<StreamInfo>> {
        self.lock().streams.values().cloned().collect()
    }

    pub fn stream_by_session(&self, session: &str) -> Vec<Arc<StreamInfo>> {
        self.lock()
            .streams
            .values()
            .filter(|s| s.session == session)
            .cloned()
            .collect()
    }

    /// Open (or admitted but not yet registered) streams of `principal`
    /// covered by `grant`, excluding `exclude`.
    pub fn active(&self, principal: &str, grant: &str, exclude: Option<u32>) -> u32 {
        let g = self.lock();
        let live = g
            .streams
            .values()
            .filter(|s| Some(s.id) != exclude && s.principal == principal)
            .filter(|s| s.kind != StreamKind::Rpc && s.grant_ids.iter().any(|x| x == grant))
            .count();
        let pending = g
            .reserved
            .iter()
            .filter(|(id, _)| Some(**id) != exclude && !g.streams.contains_key(id))
            .filter(|(_, (p, grants))| p == principal && grants.iter().any(|x| x == grant))
            .count();
        (live + pending) as u32
    }

    fn reserve(&self, id: u32, principal: &str, grants: &[String]) -> Reservation<'_> {
        self.lock()
            .reserved
            .insert(id, (principal.to_string(), grants.to_vec()));
        Reservation { reg: self, id }
    }

    pub fn add_listener(&self, device_conn: &str, id: u32, l: Arc<ListenerReg>) -> ListenerGuard<'_> {
        let key = (device_conn.to_string(), id);
        self.lock().listeners.insert(key.clone(), l);
        ListenerGuard { reg: self, key }
    }

    pub fn listener(&self, device_conn: &str, id: u32) -> Option<Arc<ListenerReg>> {
        self.lock().listeners.get(&(device_conn.to_string(), id)).cloned()
    }
}

/// The agent behind a connection, freshly loaded and checked.
#[derive(Debug, Clone)]
pub struct Principal {
    pub id: String,
    pub name: String,
    pub owner_id: String,
    pub owner_name: String,
    pub groups: Vec<String>,
}

pub struct Shared {
    pub db: Db,
    pub audit: AuditLog,
    pub cap_key: SigningKey,
    pub noise_public: [u8; 32],
    pub cfg: ServerConfig,
    pub reg: Registry,
    stream_seq: AtomicU32,
    /// Serializes "decide + reserve a concurrency slot" so concurrent opens
    /// cannot all pass a `max_sessions` check before any is counted.
    admission: Mutex<()>,
    /// Failed web logins per client address: (count, window start).
    pub login_failures: Mutex<HashMap<String, (u32, i64)>>,
}

impl std::fmt::Debug for Shared {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Shared")
    }
}

impl Shared {
    pub fn new(
        db: Db,
        audit: AuditLog,
        cap_key: SigningKey,
        noise_public: [u8; 32],
        cfg: ServerConfig,
    ) -> Self {
        Self {
            db,
            audit,
            cap_key,
            noise_public,
            cfg,
            reg: Registry::default(),
            stream_seq: AtomicU32::new(1),
            admission: Mutex::new(()),
            login_failures: Mutex::new(HashMap::new()),
        }
    }

    pub fn next_stream_id(&self) -> u32 {
        self.stream_seq.fetch_add(1, Ordering::Relaxed)
    }

    /// Append an audit event; an error means the caller must refuse.
    pub fn audit(&self, ev: Event) -> Result<u64, ApiError> {
        Ok(self.audit.append(ev)?)
    }

    /// Load an agent and check that it and its owner may act right now.
    pub fn principal(&self, agent_id: &str) -> Result<Principal, ProtoError> {
        let t = now();
        let a = self
            .db
            .agent(agent_id)
            .map_err(|e| e.proto())?
            .ok_or_else(|| ProtoError::new(ErrorCode::Unauthenticated, "unknown agent"))?;
        if a.status != "active" {
            return Err(ProtoError::new(ErrorCode::Disabled, "agent disabled"));
        }
        if a.expires_at.map(|e| t >= e).unwrap_or(false) {
            return Err(ProtoError::new(ErrorCode::Expired, "agent expired"));
        }
        let owner = self
            .db
            .user(&a.owner_id)
            .map_err(|e| e.proto())?
            .ok_or_else(|| ProtoError::new(ErrorCode::Disabled, "agent owner no longer exists"))?;
        if owner.status != "active" {
            return Err(ProtoError::new(
                ErrorCode::Disabled,
                "agent owner account disabled",
            ));
        }
        if owner.expires_at.map(|e| t >= e).unwrap_or(false) {
            return Err(ProtoError::new(
                ErrorCode::Disabled,
                "agent owner account expired",
            ));
        }
        Ok(Principal {
            id: a.id,
            name: a.name,
            owner_id: owner.id,
            owner_name: owner.name,
            groups: a.groups,
        })
    }

    /// Load a device and check that it is enabled.
    pub fn device_usable(&self, device_id: &str) -> Result<Device, ProtoError> {
        let d = self
            .db
            .device(device_id)
            .map_err(|e| e.proto())?
            .ok_or_else(|| ProtoError::new(ErrorCode::Unauthenticated, "unknown device"))?;
        if d.status != "active" {
            return Err(ProtoError::new(ErrorCode::Disabled, "device disabled"));
        }
        Ok(d)
    }

    /// Policy decision for `req` by `p`. Returns the device the request
    /// targets (if any). Unknown and disabled devices are reported as a
    /// plain denial so the device inventory does not leak.
    pub fn decide(
        &self,
        p: &Principal,
        req: &OpenRequest,
        exclude: Option<u32>,
    ) -> Result<(Decision, Option<Device>), ApiError> {
        let device = match req.device() {
            Some(name) => match self.db.device(name)? {
                Some(d) if d.status == "active" => Some(d),
                _ => {
                    return Ok((
                        deny(ErrorCode::Forbidden, format!("no grant allows this on {name}")),
                        None,
                    ))
                }
            },
            None => None,
        };
        let action = match req.action() {
            Some(a) => a,
            None => return Ok((deny(ErrorCode::BadRequest, "request has no action"), device)),
        };
        let grants: Vec<_> = self.db.grants()?.into_iter().map(|g| g.grant).collect();
        let full = self.db.full_access_all()?;
        let net = match req {
            OpenRequest::ForwardL { host, port, .. } | OpenRequest::Egress { host, port, .. } => {
                Some((host.as_str(), *port))
            }
            OpenRequest::ForwardR {
                bind_host, bind_port, ..
            } => Some((bind_host.as_str(), *bind_port)),
            _ => None,
        };
        let no_groups: Vec<String> = Vec::new();
        let active = |g: &str| self.reg.active(&p.id, g, exclude);
        let ar = AccessRequest {
            principal: &p.id,
            principal_groups: &p.groups,
            device: device.as_ref().map(|d| d.id.as_str()),
            device_groups: device.as_ref().map(|d| &d.groups).unwrap_or(&no_groups),
            action,
            net,
            active: &active,
            now: now(),
        };
        Ok((cjs_authz::decide(&ar, &grants, &full), device))
    }

    /// Decide `req` for a new stream `stream_id` and, when allowed,
    /// atomically reserve its concurrency slot in every grant that allowed
    /// it. Keep the reservation alive until the stream is registered (or
    /// the open failed).
    pub fn decide_and_reserve(
        &self,
        p: &Principal,
        req: &OpenRequest,
        stream_id: u32,
    ) -> Result<(Decision, Option<Device>, Option<Reservation<'_>>), ApiError> {
        let _g = self.admission.lock().unwrap_or_else(|e| e.into_inner());
        let (d, dev) = self.decide(p, req, None)?;
        let res = (d.allow && req.kind() != StreamKind::Rpc)
            .then(|| self.reg.reserve(stream_id, &p.id, &d.grant_ids));
        Ok((d, dev, res))
    }

    pub fn conn_summaries(&self) -> Vec<ConnSummary> {
        let mut v: Vec<_> = self
            .reg
            .conns()
            .into_iter()
            .map(|c| ConnSummary {
                id: c.id.clone(),
                role: match c.role {
                    Role::Agent => "agent",
                    Role::Device => "device",
                },
                principal: c.principal.clone(),
                name: c.name.clone(),
                transport: c.transport,
                peer: c.peer.clone(),
                since: c.since,
                os: c.info.os.clone(),
                arch: c.info.arch.clone(),
                hostname: c.info.hostname.clone(),
                version: c.info.version.clone(),
            })
            .collect();
        v.sort_by_key(|a| a.since);
        v
    }

    pub fn stream_summaries(&self) -> Vec<StreamSummary> {
        let mut v: Vec<_> = self
            .reg
            .streams()
            .into_iter()
            .map(|s| StreamSummary {
                id: s.id,
                session: s.session.clone(),
                kind: s.kind.as_str(),
                principal: s.principal.clone(),
                device: s.device.clone(),
                target: s.target.clone(),
                started: s.started,
                full_access: s.full_access,
                peer: s.peer.clone(),
            })
            .collect();
        v.sort_by_key(|s| s.id);
        v
    }
}

fn deny(code: ErrorCode, reason: impl Into<String>) -> Decision {
    Decision {
        allow: false,
        code: Some(code),
        reason: reason.into(),
        grant_ids: vec![],
        roots: vec![],
        full_access: None,
        egress_rules: vec![],
    }
}
