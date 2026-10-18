//! Server side: axum routes for WebSocket and HTTP long-polling, the session
//! registry, the handshake replay cache and the per-address handshake rate
//! limit.
use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use axum::body::Bytes;
use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::Router;
use cjs_proto::{
    decode, encode, ErrorCode, Hello, HttpBatch, HttpOpenResponse, ProtoError, Welcome, WireMsg,
    HANDSHAKE_MAX_SKEW_SECS, HTTP_AUTH_HEADER, PROTO_VERSION,
};
use futures::{SinkExt, StreamExt};
use tokio::sync::{mpsc, watch};

use crate::core::{Core, SessionHandle};
use crate::handshake;
use crate::io::SessionIo;
use crate::keys::StaticKeypair;
use crate::link::run_link;
use crate::mac::{self, now_unix};
use crate::{LONG_POLL, SESSION_GRACE};

/// Decides whether a client may connect. Called during the handshake with
/// the client's authenticated static key. Transport-level checks (version,
/// clock skew, replay) have already passed. Both methods run on a blocking
/// thread (never on an async worker), so they may do synchronous I/O.
pub trait Authenticator: Send + Sync + 'static {
    /// `peer` is the client's address as seen by the server (or as given by
    /// `X-Forwarded-For` when the server is configured to trust it).
    fn authenticate(
        &self,
        client_key: &[u8; 32],
        hello: &Hello,
        peer: Option<&str>,
    ) -> Result<Welcome, ProtoError>;
    /// Called for transport-level rejections (rate limit, version, skew,
    /// replay, broken handshake) so they can be audited. Implementations
    /// should aggregate: these can be triggered without credentials.
    fn rejected(&self, _client_key: Option<&[u8; 32]>, _err: &ProtoError, _peer: Option<&str>) {}
}

/// Per-source-address token bucket for handshake attempts, checked before
/// any cryptographic work.
#[derive(Debug, Clone, Copy)]
pub struct HandshakeLimit {
    /// Attempts allowed in a burst.
    pub burst: u32,
    /// Sustained attempts per second.
    pub per_sec: u32,
}

impl Default for HandshakeLimit {
    fn default() -> Self {
        Self {
            burst: 30,
            per_sec: 5,
        }
    }
}

pub struct TransportServerConfig {
    pub key: StaticKeypair,
    pub auth: Arc<dyn Authenticator>,
    /// Take the client address from `X-Forwarded-For` (only behind a
    /// trusted reverse proxy).
    pub trust_forwarded_for: bool,
    pub handshake_limit: HandshakeLimit,
}

/// Client address of a request: the socket peer (needs the router to be
/// served with `into_make_service_with_connect_info::<SocketAddr>()`), or,
/// when `trust_forwarded` is set, the *rightmost* `X-Forwarded-For` entry:
/// the one appended by the trusted proxy in front of us. Entries further
/// left were supplied by the client and can be forged.
pub fn peer_addr(ext: &axum::http::Extensions, headers: &HeaderMap, trust_forwarded: bool) -> Option<String> {
    if trust_forwarded {
        // Several header lines are one comma-separated list in order.
        let last = headers
            .get_all("x-forwarded-for")
            .iter()
            .filter_map(|v| v.to_str().ok())
            .flat_map(|v| v.split(','))
            .map(str::trim)
            .rfind(|s| !s.is_empty());
        if let Some(ip) = last.and_then(|s| s.parse::<std::net::IpAddr>().ok()) {
            return Some(ip.to_string());
        }
    }
    ext.get::<axum::extract::ConnectInfo<std::net::SocketAddr>>()
        .map(|c| c.0.ip().to_string())
}

/// A newly established session.
pub struct Accepted {
    pub io: SessionIo,
    pub handle: SessionHandle,
    pub client_key: [u8; 32],
    pub hello: Hello,
    pub welcome: Welcome,
    pub sid: String,
    /// "ws" or "http".
    pub transport: &'static str,
    /// Client address at handshake time.
    pub peer: Option<String>,
}

impl std::fmt::Debug for Accepted {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Accepted").field("sid", &self.sid).finish()
    }
}

/// Request kinds with their own replay counter.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ReqKind {
    Resume = 0,
    Tx = 1,
    Rx = 2,
}

impl ReqKind {
    fn as_str(self) -> &'static str {
        match self {
            ReqKind::Resume => "resume",
            ReqKind::Tx => "tx",
            ReqKind::Rx => "rx",
        }
    }
}

struct ServerSession {
    sid: String,
    core: Arc<Core>,
    link_gen: watch::Sender<u64>,
    last_seen: Mutex<Instant>,
    attached: Mutex<usize>,
    /// Highest accepted request counter per [`ReqKind`].
    ctr: Mutex<[u64; 3]>,
}

impl ServerSession {
    fn touch(&self) {
        *self.last_seen.lock().unwrap() = Instant::now();
    }

    /// MAC of a server response to request `ctr` of `kind`.
    fn resp_mac(&self, kind: ReqKind, ctr: u64, ack: u64, closed: &Option<ProtoError>) -> cjs_proto::Mac {
        mac::tag(
            &self.core.keys.send,
            "http-resp",
            &(kind.as_str(), ctr, ack, closed),
        )
    }
}

/// (client static key, hello nonce).
type ReplayKey = ([u8; 32], [u8; 16]);

/// Bounded replay cache of (client key, hello nonce), evicted in time order.
struct ReplayCache {
    order: VecDeque<(i64, ReplayKey)>,
    set: HashSet<ReplayKey>,
}

/// Most handshake nonces remembered. When full, the oldest entry is evicted
/// even if not expired: a replayed IK message 1 cannot be completed by an
/// attacker anyway (it needs the client's keys); the cache only avoids
/// duplicate sessions and audit noise.
const REPLAY_CAP: usize = 65_536;
/// Most source addresses tracked by the rate limiter; beyond that new
/// addresses share one bucket.
const BUCKETS_CAP: usize = 16_384;

impl ReplayCache {
    fn new() -> Self {
        Self {
            order: VecDeque::new(),
            set: HashSet::new(),
        }
    }

    /// Insert; false when the entry was already present (a replay).
    fn insert(&mut self, k: ReplayKey, now: i64, exp: i64) -> bool {
        while let Some((e, _)) = self.order.front() {
            if *e > now && self.order.len() < REPLAY_CAP {
                break;
            }
            let (_, old) = self.order.pop_front().expect("front exists");
            self.set.remove(&old);
        }
        if !self.set.insert(k) {
            return false;
        }
        self.order.push_back((exp, k));
        true
    }

    fn len(&self) -> usize {
        self.set.len()
    }
}

struct Buckets {
    limit: HandshakeLimit,
    map: HashMap<String, (f64, Instant)>,
}

impl Buckets {
    fn allow(&mut self, peer: Option<&str>) -> bool {
        let now = Instant::now();
        let (burst, rate) = (self.limit.burst as f64, self.limit.per_sec as f64);
        let mut key = peer.unwrap_or("unknown").to_string();
        if !self.map.contains_key(&key) && self.map.len() >= BUCKETS_CAP {
            self.prune(now);
            if self.map.len() >= BUCKETS_CAP {
                key = "*overflow*".into();
            }
        }
        let b = self.map.entry(key).or_insert((burst, now));
        b.0 = (b.0 + now.duration_since(b.1).as_secs_f64() * rate).min(burst);
        b.1 = now;
        if b.0 >= 1.0 {
            b.0 -= 1.0;
            true
        } else {
            false
        }
    }

    /// Forget buckets that have refilled completely.
    fn prune(&mut self, now: Instant) {
        let (burst, rate) = (self.limit.burst as f64, self.limit.per_sec as f64);
        self.map
            .retain(|_, (t, at)| *t + now.duration_since(*at).as_secs_f64() * rate < burst);
    }
}

struct Inner {
    cfg: TransportServerConfig,
    sessions: Mutex<HashMap<String, Arc<ServerSession>>>,
    replay: Mutex<ReplayCache>,
    buckets: Mutex<Buckets>,
    accept_tx: mpsc::Sender<Accepted>,
}

#[derive(Clone)]
pub struct TransportServer {
    inner: Arc<Inner>,
}

impl std::fmt::Debug for TransportServer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("TransportServer")
    }
}

/// Why an authenticated client request was refused.
enum AuthFail {
    /// No such session (unauthenticated answer).
    Unknown,
    /// Bad MAC, stale timestamp or replayed counter.
    Bad,
}

impl TransportServer {
    pub fn new(cfg: TransportServerConfig) -> (Self, mpsc::Receiver<Accepted>) {
        let (accept_tx, accept_rx) = mpsc::channel(64);
        let limit = cfg.handshake_limit;
        let inner = Arc::new(Inner {
            cfg,
            sessions: Mutex::new(HashMap::new()),
            replay: Mutex::new(ReplayCache::new()),
            buckets: Mutex::new(Buckets {
                limit,
                map: HashMap::new(),
            }),
            accept_tx,
        });
        let weak = Arc::downgrade(&inner);
        tokio::spawn(async move {
            let mut t = tokio::time::interval(Duration::from_secs(2));
            loop {
                t.tick().await;
                let Some(inner) = weak.upgrade() else { return };
                reap(&inner);
            }
        });
        (Self { inner }, accept_rx)
    }

    pub fn public_key(&self) -> [u8; 32] {
        self.inner.cfg.key.public
    }

    /// Number of live sessions.
    pub fn session_count(&self) -> usize {
        self.inner.sessions.lock().unwrap().len()
    }

    /// Entries in the handshake replay cache (bounded).
    pub fn replay_cache_len(&self) -> usize {
        self.inner.replay.lock().unwrap().len()
    }

    /// Routes: `GET /v1/t/ws`, `POST /v1/t/open`, `POST /v1/t/{sid}/tx`,
    /// `GET /v1/t/{sid}/rx`.
    pub fn router(&self) -> Router {
        Router::new()
            .route("/v1/t/ws", get(ws_handler))
            .route("/v1/t/open", post(http_open))
            .route("/v1/t/{sid}/tx", post(http_tx))
            .route("/v1/t/{sid}/rx", get(http_rx))
            .with_state(self.clone())
    }

    /// Rate limit, then run the handshake on a blocking thread (Noise DH,
    /// database lookups and durable audit writes must not stall the async
    /// workers).
    async fn handshake_async(
        &self,
        msg1: Vec<u8>,
        transport: &'static str,
        peer: Option<String>,
    ) -> Result<(Vec<u8>, Option<String>), ProtoError> {
        if !self.inner.buckets.lock().unwrap().allow(peer.as_deref()) {
            let e = ProtoError::new(ErrorCode::LimitExceeded, "too many handshakes, slow down");
            let srv = self.clone();
            let (e2, p2) = (e.clone(), peer.clone());
            let _ =
                tokio::task::spawn_blocking(move || srv.inner.cfg.auth.rejected(None, &e2, p2.as_deref()))
                    .await;
            return Err(e);
        }
        let srv = self.clone();
        tokio::task::spawn_blocking(move || srv.handshake(&msg1, transport, peer))
            .await
            .map_err(|e| ProtoError::new(ErrorCode::Internal, format!("handshake task: {e}")))?
    }

    /// Run the handshake. On success the session is registered and handed to
    /// the application.
    fn handshake(
        &self,
        msg1: &[u8],
        transport: &'static str,
        peer: Option<String>,
    ) -> Result<(Vec<u8>, Option<String>), ProtoError> {
        let inner = &self.inner;
        let out = handshake::respond(&inner.cfg.key.private, msg1, |key, hello| {
            if let Err(e) = self.precheck(key, hello) {
                inner.cfg.auth.rejected(Some(key), &e, peer.as_deref());
                return Err(e);
            }
            inner.cfg.auth.authenticate(key, hello, peer.as_deref())
        });
        let out = match out {
            Ok(o) => o,
            Err(e) => {
                inner.cfg.auth.rejected(None, &e, peer.as_deref());
                return Err(e);
            }
        };
        let Some((noise, welcome, hello, client_key, keys)) = out.session else {
            if let Some(e) = &out.rejection {
                tracing::info!(err = %e, "handshake rejected");
            }
            return Ok((out.msg2, None));
        };
        let sid = random_id();
        let (core, in_rx) = Core::new(noise, keys);
        let io = SessionIo::new(core.clone(), in_rx);
        let sess = Arc::new(ServerSession {
            sid: sid.clone(),
            core: core.clone(),
            link_gen: watch::channel(0).0,
            last_seen: Mutex::new(Instant::now()),
            attached: Mutex::new(0),
            ctr: Mutex::new([0; 3]),
        });
        inner.sessions.lock().unwrap().insert(sid.clone(), sess);
        let acc = Accepted {
            io,
            handle: SessionHandle(core.clone()),
            client_key,
            hello,
            welcome,
            sid: sid.clone(),
            transport,
            peer,
        };
        if inner.accept_tx.try_send(acc).is_err() {
            core.close(ProtoError::new(ErrorCode::LimitExceeded, "server busy"));
        }
        Ok((out.msg2, Some(sid)))
    }

    fn precheck(&self, key: &[u8; 32], hello: &Hello) -> Result<(), ProtoError> {
        if hello.version != PROTO_VERSION {
            return Err(ProtoError::new(
                ErrorCode::Unsupported,
                format!("protocol version {} not supported", hello.version),
            ));
        }
        let now = now_unix();
        if (hello.ts - now).abs() > HANDSHAKE_MAX_SKEW_SECS {
            return Err(ProtoError::new(
                ErrorCode::Expired,
                "handshake timestamp outside allowed clock skew",
            ));
        }
        let fresh = self.inner.replay.lock().unwrap().insert(
            (*key, hello.nonce),
            now,
            now + 2 * HANDSHAKE_MAX_SKEW_SECS,
        );
        if !fresh {
            return Err(ProtoError::new(ErrorCode::Replay, "handshake replayed"));
        }
        Ok(())
    }

    /// Check a client request's proof of possession of the session's resume
    /// key: MAC over (sid, kind, ctr, ts, H(data)), timestamp within the
    /// allowed skew, and a counter above every one seen for `kind`.
    fn authorize(
        &self,
        sid: &str,
        kind: ReqKind,
        ctr: u64,
        ts: i64,
        data: &[u8],
        proof: &[u8],
    ) -> Result<Arc<ServerSession>, AuthFail> {
        let s = self
            .inner
            .sessions
            .lock()
            .unwrap()
            .get(sid)
            .cloned()
            .ok_or(AuthFail::Unknown)?;
        let want = mac::request_tag(&s.core.keys.resume, sid, kind.as_str(), ctr, ts, data);
        if !mac::check_raw(&want, proof) {
            return Err(AuthFail::Bad);
        }
        if (ts - now_unix()).abs() > HANDSHAKE_MAX_SKEW_SECS {
            return Err(AuthFail::Bad);
        }
        let mut c = s.ctr.lock().unwrap();
        if ctr <= c[kind as usize] {
            return Err(AuthFail::Bad);
        }
        c[kind as usize] = ctr;
        drop(c);
        Ok(s)
    }
}

fn reap(inner: &Inner) {
    let mut sessions = inner.sessions.lock().unwrap();
    sessions.retain(|_, s| {
        if s.core.closed().is_some() {
            // Keep closed sessions briefly so the peer can learn why.
            return s.last_seen.lock().unwrap().elapsed() < Duration::from_secs(10);
        }
        let idle = *s.attached.lock().unwrap() == 0 && s.last_seen.lock().unwrap().elapsed() > SESSION_GRACE;
        if idle {
            s.core
                .close(ProtoError::new(ErrorCode::Timeout, "session expired"));
        }
        true
    });
    drop(sessions);
    inner.buckets.lock().unwrap().prune(Instant::now());
}

pub(crate) fn random_id() -> String {
    use rand::RngCore;
    let mut b = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut b);
    hex::encode(b)
}

// ---------------------------------------------------------------------------
// WebSocket
// ---------------------------------------------------------------------------

async fn ws_handler(
    State(srv): State<TransportServer>,
    ext: axum::http::Extensions,
    headers: HeaderMap,
    ws: WebSocketUpgrade,
) -> Response {
    let peer = peer_addr(&ext, &headers, srv.inner.cfg.trust_forwarded_for);
    ws.max_message_size(2 * 1024 * 1024)
        .on_upgrade(move |sock| ws_conn(srv, sock, peer))
}

async fn ws_conn(srv: TransportServer, sock: WebSocket, peer: Option<String>) {
    let (mut sink, stream) = sock.split();
    let mut stream = Box::pin(stream.filter_map(|m| async move {
        match m {
            Ok(Message::Binary(b)) => decode::<WireMsg>(&b).ok().map(Some),
            Ok(Message::Close(_)) | Err(_) => Some(None),
            _ => None,
        }
    }));
    let send = |m: WireMsg| Message::Binary(encode(&m).into());
    let first = tokio::time::timeout(Duration::from_secs(15), stream.next()).await;
    let (sess, peer_ack) = match first {
        Ok(Some(Some(WireMsg::Hello { noise }))) => match srv.handshake_async(noise, "ws", peer).await {
            Ok((msg2, Some(sid))) => {
                if sink
                    .send(send(WireMsg::Welcome {
                        sid: sid.clone(),
                        noise: msg2,
                    }))
                    .await
                    .is_err()
                {
                    return;
                }
                let s = srv.inner.sessions.lock().unwrap().get(&sid).cloned();
                match s {
                    Some(s) => (s, 0),
                    None => return,
                }
            }
            Ok((msg2, None)) => {
                let _ = sink
                    .send(send(WireMsg::Welcome {
                        sid: String::new(),
                        noise: msg2,
                    }))
                    .await;
                return;
            }
            Err(e) => {
                let _ = sink.send(send(WireMsg::Reject(e))).await;
                return;
            }
        },
        Ok(Some(Some(WireMsg::Resume {
            sid,
            ctr,
            ts,
            ack,
            proof,
        }))) => match srv.authorize(&sid, ReqKind::Resume, ctr, ts, &ack.to_be_bytes(), &proof) {
            Ok(s) => {
                if let Some(e) = s.core.closed() {
                    // Authenticated: the client learns the real reason.
                    let _ = sink.send(send(s.core.close_msg(e))).await;
                    return;
                }
                let my_ack = s.core.recv_ack();
                let mac = mac::tag(&s.core.keys.send, "resumed", &(ctr, my_ack));
                if sink
                    .send(send(WireMsg::Resumed { ack: my_ack, mac }))
                    .await
                    .is_err()
                {
                    return;
                }
                (s, ack)
            }
            Err(f) => {
                let e = match f {
                    AuthFail::Unknown => ProtoError::new(ErrorCode::NotFound, "no such session"),
                    AuthFail::Bad => ProtoError::new(ErrorCode::Unauthenticated, "resume not authorized"),
                };
                let _ = sink.send(send(WireMsg::Reject(e))).await;
                return;
            }
        },
        _ => return,
    };
    // Take over the session from any previous link.
    sess.link_gen.send_modify(|g| *g += 1);
    let gen_rx = sess.link_gen.subscribe();
    *sess.attached.lock().unwrap() += 1;
    sess.touch();
    let sink = sink.with(|m: WireMsg| async move { Ok::<_, axum::Error>(send(m)) });
    let stream = stream
        .take_while(|m| futures::future::ready(m.is_some()))
        .filter_map(|m| async move { m });
    let end = run_link(
        sess.core.clone(),
        Box::pin(sink),
        Box::pin(stream),
        peer_ack,
        gen_rx,
    )
    .await;
    *sess.attached.lock().unwrap() -= 1;
    sess.touch();
    tracing::debug!(?end, sid = %sess.sid, "ws link ended");
}

// ---------------------------------------------------------------------------
// HTTP long-polling
// ---------------------------------------------------------------------------

const MAX_HTTP_BODY: usize = 4 * 1024 * 1024;

fn bin(status: StatusCode, body: Vec<u8>) -> Response {
    (status, [("content-type", "application/octet-stream")], body).into_response()
}

async fn http_open(
    State(srv): State<TransportServer>,
    ext: axum::http::Extensions,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let peer = peer_addr(&ext, &headers, srv.inner.cfg.trust_forwarded_for);
    match srv.handshake_async(body.to_vec(), "http", peer).await {
        Ok((msg, sid)) => bin(
            StatusCode::OK,
            encode(&HttpOpenResponse {
                sid: sid.unwrap_or_default(),
                msg,
            }),
        ),
        Err(e) if e.code == ErrorCode::LimitExceeded => bin(StatusCode::TOO_MANY_REQUESTS, encode(&e)),
        Err(e) => bin(StatusCode::UNAUTHORIZED, encode(&e)),
    }
}

/// Authenticate an HTTP request; returns the session and request counter.
fn http_session(
    srv: &TransportServer,
    sid: &str,
    kind: ReqKind,
    headers: &HeaderMap,
    data: &[u8],
) -> Result<(Arc<ServerSession>, u64), Response> {
    let parsed = headers
        .get(HTTP_AUTH_HEADER)
        .and_then(|v| v.to_str().ok())
        .and_then(mac::parse_auth_header);
    let Some((ctr, ts, proof)) = parsed else {
        return Err(bin(StatusCode::UNAUTHORIZED, Vec::new()));
    };
    match srv.authorize(sid, kind, ctr, ts, data, &proof) {
        Ok(s) => Ok((s, ctr)),
        Err(AuthFail::Bad) => Err(bin(StatusCode::UNAUTHORIZED, Vec::new())),
        Err(AuthFail::Unknown) => Err(bin(
            StatusCode::GONE,
            encode(&HttpBatch {
                closed: Some(ProtoError::new(ErrorCode::NotFound, "no such session")),
                ..Default::default()
            }),
        )),
    }
}

/// Authenticated "session closed" answer to request `ctr`.
fn closed_batch(sess: &ServerSession, kind: ReqKind, ctr: u64, e: ProtoError) -> Response {
    let ack = sess.core.recv_ack();
    let closed = Some(e);
    let mac = sess.resp_mac(kind, ctr, ack, &closed);
    bin(
        StatusCode::GONE,
        encode(&HttpBatch {
            ack,
            closed,
            mac: Some(mac),
            ..Default::default()
        }),
    )
}

fn ok_batch(sess: &ServerSession, kind: ReqKind, ctr: u64, msgs: Vec<(u64, Vec<u8>)>) -> Response {
    let ack = sess.core.recv_ack();
    let mac = sess.resp_mac(kind, ctr, ack, &None);
    bin(
        StatusCode::OK,
        encode(&HttpBatch {
            ack,
            msgs,
            closed: None,
            mac: Some(mac),
        }),
    )
}

async fn http_tx(
    State(srv): State<TransportServer>,
    Path(sid): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    if body.len() > MAX_HTTP_BODY {
        return bin(StatusCode::PAYLOAD_TOO_LARGE, Vec::new());
    }
    // The request MAC binds the whole body (ack, segments, close).
    let (sess, ctr) = match http_session(&srv, &sid, ReqKind::Tx, &headers, &body) {
        Ok(s) => s,
        Err(r) => return r,
    };
    sess.touch();
    let batch: HttpBatch = match decode(&body) {
        Ok(b) => b,
        Err(e) => return bin(StatusCode::BAD_REQUEST, encode(&e)),
    };
    if let Some(e) = sess.core.closed() {
        return closed_batch(&sess, ReqKind::Tx, ctr, e);
    }
    if let Err(e) = sess.core.ack(batch.ack) {
        sess.core.close(e.clone());
        return closed_batch(&sess, ReqKind::Tx, ctr, e);
    }
    for (seq, data) in &batch.msgs {
        if let Err(e) = sess.core.receive(*seq, data) {
            // Not fatal for the session: the client re-sends from our ack.
            tracing::warn!(err = %e, "rejected segment");
            return bin(StatusCode::BAD_REQUEST, encode(&e));
        }
    }
    if let Some(e) = batch.closed {
        sess.core.close(e);
    }
    ok_batch(&sess, ReqKind::Tx, ctr, Vec::new())
}

#[derive(serde::Deserialize)]
struct RxQuery {
    ack: u64,
}

async fn http_rx(
    State(srv): State<TransportServer>,
    Path(sid): Path<String>,
    Query(q): Query<RxQuery>,
    headers: HeaderMap,
) -> Response {
    let (sess, ctr) = match http_session(&srv, &sid, ReqKind::Rx, &headers, &q.ack.to_be_bytes()) {
        Ok(s) => s,
        Err(r) => return r,
    };
    sess.touch();
    if let Err(e) = sess.core.ack(q.ack) {
        sess.core.close(e.clone());
        return closed_batch(&sess, ReqKind::Rx, ctr, e);
    }
    *sess.attached.lock().unwrap() += 1;
    let mut ver = sess.core.subscribe();
    let deadline = tokio::time::Instant::now() + LONG_POLL;
    let resp = loop {
        if let Some(e) = sess.core.closed() {
            break closed_batch(&sess, ReqKind::Rx, ctr, e);
        }
        let msgs = sess.core.segs_after(q.ack, 1024 * 1024);
        if !msgs.is_empty() {
            break ok_batch(&sess, ReqKind::Rx, ctr, msgs);
        }
        match tokio::time::timeout_at(deadline, ver.changed()).await {
            Ok(Ok(())) => continue,
            _ => break ok_batch(&sess, ReqKind::Rx, ctr, Vec::new()),
        }
    };
    *sess.attached.lock().unwrap() -= 1;
    sess.touch();
    resp
}

#[cfg(test)]
mod tests {
    use super::*;

    fn headers(xff: &[&str]) -> HeaderMap {
        let mut h = HeaderMap::new();
        for v in xff {
            h.append("x-forwarded-for", v.parse().unwrap());
        }
        h
    }

    fn ext() -> axum::http::Extensions {
        let mut e = axum::http::Extensions::new();
        e.insert(axum::extract::ConnectInfo(std::net::SocketAddr::from((
            [10, 0, 0, 1],
            5,
        ))));
        e
    }

    #[test]
    fn forwarded_for_uses_rightmost_entry() {
        // The client forged the first entry; the trusted proxy appended the
        // real address last.
        let h = headers(&["1.2.3.4, 203.0.113.7"]);
        assert_eq!(peer_addr(&ext(), &h, true).as_deref(), Some("203.0.113.7"));
        // Multiple header lines form one list.
        let h = headers(&["1.2.3.4", "198.51.100.2"]);
        assert_eq!(peer_addr(&ext(), &h, true).as_deref(), Some("198.51.100.2"));
        // Not trusted: the socket address.
        assert_eq!(peer_addr(&ext(), &h, false).as_deref(), Some("10.0.0.1"));
        // Garbage in the rightmost slot: fall back to the socket address.
        let h = headers(&["1.2.3.4, not-an-ip"]);
        assert_eq!(peer_addr(&ext(), &h, true).as_deref(), Some("10.0.0.1"));
        assert_eq!(
            peer_addr(&ext(), &headers(&[]), true).as_deref(),
            Some("10.0.0.1")
        );
    }

    #[test]
    fn replay_cache_is_bounded_and_time_ordered() {
        let mut c = ReplayCache::new();
        let k = |i: u32| {
            let mut key = [0u8; 32];
            key[..4].copy_from_slice(&i.to_be_bytes());
            (key, [0u8; 16])
        };
        assert!(c.insert(k(1), 100, 200));
        assert!(!c.insert(k(1), 101, 201), "replay detected");
        // Expired entries are evicted.
        assert!(c.insert(k(2), 300, 400));
        assert_eq!(c.len(), 1);
        assert!(c.insert(k(1), 300, 400), "expired entry forgotten");
        for i in 10..(REPLAY_CAP as u32 + 1000) {
            c.insert(k(i), 300, 400);
        }
        assert!(c.len() <= REPLAY_CAP);
        assert_eq!(c.order.len(), c.set.len());
    }

    #[test]
    fn token_bucket_per_address() {
        let mut b = Buckets {
            limit: HandshakeLimit { burst: 3, per_sec: 1 },
            map: HashMap::new(),
        };
        for _ in 0..3 {
            assert!(b.allow(Some("1.1.1.1")));
        }
        assert!(!b.allow(Some("1.1.1.1")));
        assert!(b.allow(Some("2.2.2.2")), "other addresses unaffected");
        b.map.get_mut("1.1.1.1").unwrap().1 -= Duration::from_secs(2);
        assert!(b.allow(Some("1.1.1.1")), "refills over time");
    }
}
