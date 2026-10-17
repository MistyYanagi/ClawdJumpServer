//! Server side: axum routes for WebSocket and HTTP long-polling, the session
//! registry and the handshake replay cache.
use std::collections::HashMap;
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
    HANDSHAKE_MAX_SKEW_SECS, PROTO_VERSION,
};
use futures::{SinkExt, StreamExt};
use subtle::ConstantTimeEq;
use tokio::sync::{mpsc, watch};

use crate::core::{Core, SessionHandle};
use crate::handshake;
use crate::io::SessionIo;
use crate::keys::StaticKeypair;
use crate::link::{run_link, LinkEnd};
use crate::{LONG_POLL, SESSION_GRACE};

/// Decides whether a client may connect. Called during the handshake with
/// the client's authenticated static key. Transport-level checks (version,
/// clock skew, replay) have already passed.
pub trait Authenticator: Send + Sync + 'static {
    fn authenticate(&self, client_key: &[u8; 32], hello: &Hello) -> Result<Welcome, ProtoError>;
    /// Called for every rejected handshake (for audit).
    fn rejected(&self, _client_key: Option<&[u8; 32]>, _err: &ProtoError) {}
}

pub struct TransportServerConfig {
    pub key: StaticKeypair,
    pub auth: Arc<dyn Authenticator>,
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
}

impl std::fmt::Debug for Accepted {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Accepted").field("sid", &self.sid).finish()
    }
}

struct ServerSession {
    core: Arc<Core>,
    secret: String,
    link_gen: watch::Sender<u64>,
    last_seen: Mutex<Instant>,
    attached: Mutex<usize>,
}

impl ServerSession {
    fn touch(&self) {
        *self.last_seen.lock().unwrap() = Instant::now();
    }
}

/// (client key, hello nonce) -> expiry (unix seconds).
type ReplayCache = HashMap<([u8; 32], [u8; 16]), i64>;

struct Inner {
    cfg: TransportServerConfig,
    sessions: Mutex<HashMap<String, Arc<ServerSession>>>,
    replay: Mutex<ReplayCache>,
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

fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

impl TransportServer {
    pub fn new(cfg: TransportServerConfig) -> (Self, mpsc::Receiver<Accepted>) {
        let (accept_tx, accept_rx) = mpsc::channel(64);
        let inner = Arc::new(Inner {
            cfg,
            sessions: Mutex::new(HashMap::new()),
            replay: Mutex::new(HashMap::new()),
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

    /// Run the handshake. On success the session is registered and handed to
    /// the application.
    fn handshake(
        &self,
        msg1: &[u8],
        transport: &'static str,
    ) -> Result<(Vec<u8>, Option<String>), ProtoError> {
        let inner = &self.inner;
        let out = handshake::respond(&inner.cfg.key.private, msg1, |key, hello| {
            if let Err(e) = self.precheck(key, hello) {
                inner.cfg.auth.rejected(Some(key), &e);
                return Err(e);
            }
            inner.cfg.auth.authenticate(key, hello)
        });
        let out = match out {
            Ok(o) => o,
            Err(e) => {
                inner.cfg.auth.rejected(None, &e);
                return Err(e);
            }
        };
        let Some((noise, welcome, hello, client_key, secret)) = out.session else {
            if let Some(e) = &out.rejection {
                // Key is unknown here unless we re-parse; the authenticator
                // already saw it in `authenticate`.
                tracing::info!(err = %e, "handshake rejected");
            }
            return Ok((out.msg2, None));
        };
        let sid = random_id();
        let (core, in_rx) = Core::new(noise);
        let io = SessionIo::new(core.clone(), in_rx);
        let sess = Arc::new(ServerSession {
            core: core.clone(),
            secret,
            link_gen: watch::channel(0).0,
            last_seen: Mutex::new(Instant::now()),
            attached: Mutex::new(0),
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
        let mut replay = self.inner.replay.lock().unwrap();
        replay.retain(|_, exp| *exp > now);
        if replay
            .insert((*key, hello.nonce), now + 2 * HANDSHAKE_MAX_SKEW_SECS)
            .is_some()
        {
            return Err(ProtoError::new(ErrorCode::Replay, "handshake replayed"));
        }
        Ok(())
    }

    fn lookup(&self, sid: &str, secret: &str) -> Option<Arc<ServerSession>> {
        let s = self.inner.sessions.lock().unwrap().get(sid).cloned()?;
        if bool::from(s.secret.as_bytes().ct_eq(secret.as_bytes())) {
            Some(s)
        } else {
            None
        }
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

async fn ws_handler(State(srv): State<TransportServer>, ws: WebSocketUpgrade) -> Response {
    ws.max_message_size(2 * 1024 * 1024)
        .on_upgrade(move |sock| ws_conn(srv, sock))
}

async fn ws_conn(srv: TransportServer, sock: WebSocket) {
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
        Ok(Some(Some(WireMsg::Hello { noise }))) => match srv.handshake(&noise, "ws") {
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
        Ok(Some(Some(WireMsg::Resume { sid, secret, ack }))) => match srv.lookup(&sid, &secret) {
            Some(s) => {
                if let Some(e) = s.core.closed() {
                    let _ = sink.send(send(WireMsg::Reject(e))).await;
                    return;
                }
                if sink
                    .send(send(WireMsg::Resumed {
                        ack: s.core.recv_ack(),
                    }))
                    .await
                    .is_err()
                {
                    return;
                }
                (s, ack)
            }
            None => {
                let _ = sink
                    .send(send(WireMsg::Reject(ProtoError::new(
                        ErrorCode::NotFound,
                        "no such session",
                    ))))
                    .await;
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
    tracing::debug!(?end, "ws link ended");
    if end == LinkEnd::Closed {
        // Session over; keep it a little so a late resume learns the reason.
    }
}

// ---------------------------------------------------------------------------
// HTTP long-polling
// ---------------------------------------------------------------------------

const SECRET_HEADER: &str = "x-cjs-resume";
const MAX_HTTP_BODY: usize = 4 * 1024 * 1024;

fn bin(status: StatusCode, body: Vec<u8>) -> Response {
    (status, [("content-type", "application/octet-stream")], body).into_response()
}

async fn http_open(State(srv): State<TransportServer>, body: Bytes) -> Response {
    match srv.handshake(&body, "http") {
        Ok((msg, sid)) => bin(
            StatusCode::OK,
            encode(&HttpOpenResponse {
                sid: sid.unwrap_or_default(),
                msg,
            }),
        ),
        Err(e) => bin(StatusCode::UNAUTHORIZED, encode(&e)),
    }
}

fn http_session(
    srv: &TransportServer,
    sid: &str,
    headers: &HeaderMap,
) -> Result<Arc<ServerSession>, Response> {
    let secret = headers
        .get(SECRET_HEADER)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    srv.lookup(sid, secret).ok_or_else(|| {
        bin(
            StatusCode::GONE,
            encode(&HttpBatch {
                closed: Some(ProtoError::new(ErrorCode::NotFound, "no such session")),
                ..Default::default()
            }),
        )
    })
}

fn closed_batch(e: ProtoError) -> Response {
    bin(
        StatusCode::GONE,
        encode(&HttpBatch {
            closed: Some(e),
            ..Default::default()
        }),
    )
}

async fn http_tx(
    State(srv): State<TransportServer>,
    Path(sid): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let sess = match http_session(&srv, &sid, &headers) {
        Ok(s) => s,
        Err(r) => return r,
    };
    sess.touch();
    if body.len() > MAX_HTTP_BODY {
        return bin(StatusCode::PAYLOAD_TOO_LARGE, Vec::new());
    }
    let batch: HttpBatch = match decode(&body) {
        Ok(b) => b,
        Err(e) => return bin(StatusCode::BAD_REQUEST, encode(&e)),
    };
    if let Some(e) = sess.core.closed() {
        return closed_batch(e);
    }
    let mut res = sess.core.ack(batch.ack);
    for (seq, data) in &batch.msgs {
        if res.is_err() {
            break;
        }
        res = sess.core.receive(*seq, data);
    }
    if let Err(e) = res {
        sess.core.close(e.clone());
        return closed_batch(e);
    }
    if let Some(e) = batch.closed {
        sess.core.close(e);
    }
    bin(
        StatusCode::OK,
        encode(&HttpBatch {
            ack: sess.core.recv_ack(),
            ..Default::default()
        }),
    )
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
    let sess = match http_session(&srv, &sid, &headers) {
        Ok(s) => s,
        Err(r) => return r,
    };
    sess.touch();
    if let Err(e) = sess.core.ack(q.ack) {
        sess.core.close(e.clone());
        return closed_batch(e);
    }
    *sess.attached.lock().unwrap() += 1;
    let mut ver = sess.core.subscribe();
    let deadline = tokio::time::Instant::now() + LONG_POLL;
    let resp = loop {
        if let Some(e) = sess.core.closed() {
            break closed_batch(e);
        }
        let msgs = sess.core.segs_after(q.ack, 1024 * 1024);
        if !msgs.is_empty() {
            break bin(
                StatusCode::OK,
                encode(&HttpBatch {
                    ack: sess.core.recv_ack(),
                    msgs,
                    closed: None,
                }),
            );
        }
        match tokio::time::timeout_at(deadline, ver.changed()).await {
            Ok(Ok(())) => continue,
            _ => {
                break bin(
                    StatusCode::OK,
                    encode(&HttpBatch {
                        ack: sess.core.recv_ack(),
                        ..Default::default()
                    }),
                )
            }
        }
    };
    *sess.attached.lock().unwrap() -= 1;
    sess.touch();
    resp
}
