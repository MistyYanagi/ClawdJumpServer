//! Client side: connect over WebSocket or HTTP long-polling, keep the
//! session alive and transparently resume it after network failures.
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use cjs_proto::{
    decode, encode, ErrorCode, Hello, HttpBatch, HttpOpenResponse, ProtoError, Welcome, WireMsg,
    HTTP_AUTH_HEADER,
};
use futures::{SinkExt, StreamExt};
use tokio::sync::watch;
use tokio_tungstenite::tungstenite::Message;

use crate::core::{Core, SessionHandle};
use crate::handshake::ClientHs;
use crate::io::SessionIo;
use crate::keys::StaticKeypair;
use crate::link::{run_link, LinkEnd};
use crate::mac;
use crate::tls;
use crate::SESSION_GRACE;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportMode {
    /// Try WebSocket, fall back to HTTP long-polling.
    Auto,
    Ws,
    Http,
}

impl std::str::FromStr for TransportMode {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, String> {
        match s {
            "auto" => Ok(Self::Auto),
            "ws" => Ok(Self::Ws),
            "http" => Ok(Self::Http),
            _ => Err(format!("unknown transport {s:?} (auto|ws|http)")),
        }
    }
}

#[derive(Clone)]
pub struct ClientConfig {
    /// `https://host[:port]` (or `http://` for local testing).
    pub server: url::Url,
    pub server_key: [u8; 32],
    pub key: StaticKeypair,
    pub mode: TransportMode,
    pub extra_ca: Option<PathBuf>,
}

impl std::fmt::Debug for ClientConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ClientConfig")
            .field("server", &self.server.as_str())
            .field("mode", &self.mode)
            .finish()
    }
}

pub struct ClientConn {
    pub io: SessionIo,
    pub handle: SessionHandle,
    pub welcome: Welcome,
    /// "ws" or "http".
    pub transport: &'static str,
    /// Number of successful re-attachments so far.
    pub resumes: watch::Receiver<u64>,
}

impl std::fmt::Debug for ClientConn {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ClientConn")
            .field("transport", &self.transport)
            .finish()
    }
}

fn ioe(m: impl std::fmt::Display) -> ProtoError {
    ProtoError::new(ErrorCode::Io, m.to_string())
}

/// How long the server must keep saying "no such session" without
/// authentication before the client believes it. One forged answer only
/// costs a retry; a server that really lost the session (restart) is
/// detected after this long and the owner reconnects.
const GONE_GRACE: Duration = Duration::from_secs(10);

/// A refusal that did not come through an authenticated channel (outside
/// Noise, no valid MAC). Anyone on the path could have forged it, so its
/// code is not trusted: it is reported as a transient I/O failure, which
/// makes daemons reconnect instead of giving up.
fn unauthenticated(e: ProtoError) -> ProtoError {
    ProtoError::new(
        ErrorCode::Io,
        format!("server refused (unauthenticated reply): {e}"),
    )
}

fn ws_url(base: &url::Url) -> Result<url::Url, ProtoError> {
    let mut u = base.join("v1/t/ws").map_err(ioe)?;
    let scheme = if base.scheme() == "https" { "wss" } else { "ws" };
    u.set_scheme(scheme).map_err(|_| ioe("bad url"))?;
    Ok(u)
}

/// Connect, authenticate and start the background link task.
pub async fn connect(cfg: &ClientConfig, hello: Hello) -> Result<ClientConn, ProtoError> {
    match cfg.mode {
        TransportMode::Ws => connect_ws(cfg, hello).await,
        TransportMode::Http => connect_http(cfg, hello).await,
        TransportMode::Auto => {
            let mut h2 = hello.clone();
            match tokio::time::timeout(Duration::from_secs(10), connect_ws(cfg, hello)).await {
                Ok(Ok(c)) => Ok(c),
                // Authentication decisions are final; only transport failures fall back.
                Ok(Err(e)) if e.code != ErrorCode::Io && e.code != ErrorCode::Timeout => Err(e),
                r => {
                    tracing::info!(err = ?r.err().map(|_| "timeout").or(None), "websocket unavailable, using HTTP long-polling");
                    // Fresh nonce: the WS attempt may have reached the server.
                    use rand::RngCore;
                    rand::thread_rng().fill_bytes(&mut h2.nonce);
                    connect_http(cfg, h2).await
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// WebSocket
// ---------------------------------------------------------------------------

type WsStream = tokio_tungstenite::WebSocketStream<Box<dyn tls::Io>>;

async fn ws_dial(cfg: &ClientConfig) -> Result<WsStream, ProtoError> {
    let url = ws_url(&cfg.server)?;
    let host = url.host_str().ok_or_else(|| ioe("no host"))?.to_string();
    let port = url.port_or_known_default().unwrap_or(443);
    let tcp = tls::dial(url.scheme(), &host, port).await?;
    let io: Box<dyn tls::Io> = if url.scheme() == "wss" {
        let tcfg = tls::client_config(cfg.extra_ca.as_deref())?;
        let name = rustls::pki_types::ServerName::try_from(host.clone()).map_err(ioe)?;
        Box::new(
            tokio_rustls::TlsConnector::from(tcfg)
                .connect(name, tcp)
                .await
                .map_err(ioe)?,
        )
    } else {
        tcp
    };
    let mut wcfg = tokio_tungstenite::tungstenite::protocol::WebSocketConfig::default();
    wcfg.max_message_size = Some(2 * 1024 * 1024);
    let (ws, _resp) = tokio_tungstenite::client_async_with_config(url.as_str(), io, Some(wcfg))
        .await
        .map_err(ioe)?;
    Ok(ws)
}

async fn ws_send(ws: &mut WsStream, m: &WireMsg) -> Result<(), ProtoError> {
    ws.send(Message::Binary(encode(m).into())).await.map_err(ioe)
}

async fn ws_recv(ws: &mut WsStream) -> Result<WireMsg, ProtoError> {
    loop {
        match tokio::time::timeout(Duration::from_secs(15), ws.next()).await {
            Err(_) => return Err(ProtoError::new(ErrorCode::Timeout, "server did not answer")),
            Ok(None) => return Err(ioe("connection closed")),
            Ok(Some(Err(e))) => return Err(ioe(e)),
            Ok(Some(Ok(Message::Binary(b)))) => return decode(&b),
            Ok(Some(Ok(Message::Close(_)))) => return Err(ioe("connection closed")),
            Ok(Some(Ok(_))) => continue,
        }
    }
}

async fn connect_ws(cfg: &ClientConfig, hello: Hello) -> Result<ClientConn, ProtoError> {
    let mut ws = ws_dial(cfg).await?;
    let (hs, msg1) = ClientHs::start(&cfg.key.private, &cfg.server_key, &hello)?;
    ws_send(&mut ws, &WireMsg::Hello { noise: msg1 }).await?;
    let (sid, msg2) = match ws_recv(&mut ws).await? {
        WireMsg::Welcome { sid, noise } => (sid, noise),
        WireMsg::Reject(e) => return Err(unauthenticated(e)),
        _ => return Err(ioe("unexpected handshake reply")),
    };
    let (noise, welcome, keys) = hs.finish(&msg2)?;
    let (core, in_rx) = Core::new(noise, keys);
    let io = SessionIo::new(core.clone(), in_rx);
    let (resumes_tx, resumes) = watch::channel(0u64);
    let cfg2 = cfg.clone();
    let c2 = core.clone();
    tokio::spawn(async move { ws_keeper(cfg2, c2, sid, ws, resumes_tx).await });
    Ok(ClientConn {
        handle: SessionHandle(core),
        io,
        welcome,
        transport: "ws",
        resumes,
    })
}

async fn ws_keeper(
    cfg: ClientConfig,
    core: Arc<Core>,
    sid: String,
    first: WsStream,
    resumes: watch::Sender<u64>,
) {
    let mut link = Some((first, 0u64));
    // Resume attempts are numbered; the server only accepts increasing
    // counters, so a captured request cannot be replayed.
    let mut ctr = 0u64;
    let mut gone_since: Option<Instant> = None;
    let mut lost_at: Option<Instant> = None;
    let mut backoff = Duration::from_millis(200);
    // Clients are never superseded; keep the sender alive for the loop.
    let (_never_tx, never) = watch::channel(0u64);
    loop {
        if let Some((ws, peer_ack)) = link.take() {
            lost_at = None;
            backoff = Duration::from_millis(200);
            let (sink, stream) = ws.split();
            let sink = sink.with(|m: WireMsg| async move {
                Ok::<_, tokio_tungstenite::tungstenite::Error>(Message::Binary(encode(&m).into()))
            });
            let stream = stream
                .take_while(|m| futures::future::ready(m.is_ok()))
                .filter_map(|m| async move {
                    match m {
                        Ok(Message::Binary(b)) => decode::<WireMsg>(&b).ok(),
                        _ => None,
                    }
                });
            let end = run_link(
                core.clone(),
                Box::pin(sink),
                Box::pin(stream),
                peer_ack,
                never.clone(),
            )
            .await;
            if end == LinkEnd::Closed {
                return;
            }
            tracing::info!("link lost, resuming");
        }
        if core.closed().is_some() {
            return;
        }
        let since = *lost_at.get_or_insert_with(Instant::now);
        if since.elapsed() > SESSION_GRACE {
            core.close(ProtoError::new(ErrorCode::Timeout, "could not resume session"));
            return;
        }
        tokio::time::sleep(backoff).await;
        backoff = (backoff * 2).min(Duration::from_secs(5));
        ctr += 1;
        let attempt = async {
            let mut ws = ws_dial(&cfg).await?;
            let ack = core.recv_ack();
            let ts = mac::now_unix();
            let proof = mac::request_tag(&core.keys.resume, &sid, "resume", ctr, ts, &ack.to_be_bytes());
            ws_send(
                &mut ws,
                &WireMsg::Resume {
                    sid: sid.clone(),
                    ctr,
                    ts,
                    ack,
                    proof,
                },
            )
            .await?;
            match ws_recv(&mut ws).await? {
                WireMsg::Resumed { ack, mac: m }
                    if mac::check(&core.keys.recv, "resumed", &(ctr, ack), &m) =>
                {
                    Ok(Resume::Ok(ws, ack))
                }
                WireMsg::Close { err, mac: m } if core.check_close(&err, &m) => Ok(Resume::Closed(err)),
                // The server does not know the session (e.g. it restarted).
                // Unauthenticated: end the session as lost, never with the
                // claimed code, so the owner reconnects.
                WireMsg::Reject(e) => Ok(Resume::Lost(e)),
                _ => Err(ioe("unauthenticated or unexpected resume reply")),
            }
        };
        match attempt.await {
            Ok(Resume::Ok(ws, ack)) => {
                gone_since = None;
                resumes.send_modify(|n| *n += 1);
                link = Some((ws, ack));
            }
            Ok(Resume::Closed(e)) => {
                core.close(e);
                return;
            }
            Ok(Resume::Lost(e)) => {
                if gone_since.get_or_insert_with(Instant::now).elapsed() >= GONE_GRACE {
                    core.close(unauthenticated(e));
                    return;
                }
                tracing::debug!(err = %e, "unauthenticated resume refusal; retrying");
            }
            Err(e) => {
                tracing::debug!(err = %e, "resume attempt failed");
            }
        }
    }
}

enum Resume {
    Ok(WsStream, u64),
    Closed(ProtoError),
    Lost(ProtoError),
}

// ---------------------------------------------------------------------------
// HTTP long-polling
// ---------------------------------------------------------------------------

fn http_client(cfg: &ClientConfig) -> Result<reqwest::Client, ProtoError> {
    let mut b = reqwest::Client::builder()
        .connect_timeout(Duration::from_secs(10))
        .pool_idle_timeout(Duration::from_secs(50));
    if let Some(p) = &cfg.extra_ca {
        for c in tls::load_pem_certs(p)? {
            b = b.add_root_certificate(reqwest::Certificate::from_der(&c).map_err(ioe)?);
        }
    }
    b.build().map_err(ioe)
}

async fn connect_http(cfg: &ClientConfig, hello: Hello) -> Result<ClientConn, ProtoError> {
    let http = http_client(cfg)?;
    let (hs, msg1) = ClientHs::start(&cfg.key.private, &cfg.server_key, &hello)?;
    let url = cfg.server.join("v1/t/open").map_err(ioe)?;
    let resp = http
        .post(url)
        .header("content-type", "application/octet-stream")
        .body(msg1)
        .timeout(Duration::from_secs(20))
        .send()
        .await
        .map_err(ioe)?;
    let status = resp.status();
    let body = resp.bytes().await.map_err(ioe)?;
    if !status.is_success() {
        return Err(decode::<ProtoError>(&body)
            .map(unauthenticated)
            .unwrap_or_else(|_| ioe(format!("server returned {status}"))));
    }
    let open: HttpOpenResponse = decode(&body)?;
    let (noise, welcome, keys) = hs.finish(&open.msg)?;
    let (core, in_rx) = Core::new(noise, keys);
    let io = SessionIo::new(core.clone(), in_rx);
    let (resumes_tx, resumes) = watch::channel(0u64);
    let base = cfg.server.join(&format!("v1/t/{}/", open.sid)).map_err(ioe)?;
    let st = Arc::new(HttpLink {
        http,
        base,
        sid: open.sid.clone(),
        core: core.clone(),
        resumes: resumes_tx,
        gone_since: std::sync::Mutex::new(None),
    });
    tokio::spawn(st.clone().tx_loop());
    tokio::spawn(st.rx_loop());
    Ok(ClientConn {
        handle: SessionHandle(core),
        io,
        welcome,
        transport: "http",
        resumes,
    })
}

struct HttpLink {
    http: reqwest::Client,
    base: url::Url,
    sid: String,
    core: Arc<Core>,
    resumes: watch::Sender<u64>,
    gone_since: std::sync::Mutex<Option<Instant>>,
}

enum HttpErr {
    /// Unauthenticated "session gone": believed only after [`GONE_GRACE`].
    Gone(ProtoError),
    Transient(ProtoError),
    Fatal(ProtoError),
}

impl HttpLink {
    /// Send one request with a proof of possession of the resume key over
    /// (sid, kind, ctr, ts, H(data)) and check the response MAC.
    async fn call(
        &self,
        kind: &str,
        ctr: u64,
        data: &[u8],
        req: reqwest::RequestBuilder,
    ) -> Result<HttpBatch, HttpErr> {
        let auth = mac::auth_header(&self.core.keys.resume, &self.sid, kind, ctr, data);
        let resp = req
            .header(HTTP_AUTH_HEADER, auth)
            .send()
            .await
            .map_err(|e| HttpErr::Transient(ioe(e)))?;
        let status = resp.status();
        let body = resp.bytes().await.map_err(|e| HttpErr::Transient(ioe(e)))?;
        let authentic = |b: &HttpBatch| {
            b.mac
                .map(|m| {
                    mac::check(
                        &self.core.keys.recv,
                        "http-resp",
                        &(kind, ctr, b.ack, &b.closed),
                        &m,
                    )
                })
                .unwrap_or(false)
        };
        if status == reqwest::StatusCode::GONE {
            let b = decode::<HttpBatch>(&body).ok();
            return Err(HttpErr::Fatal(match b {
                Some(b) if authentic(&b) => b
                    .closed
                    .unwrap_or_else(|| ProtoError::new(ErrorCode::Cancelled, "session closed")),
                // Unknown session (server restarted) or forged: retried for
                // a while, the claimed reason is never trusted.
                b => {
                    return Err(HttpErr::Gone(
                        b.and_then(|b| b.closed)
                            .unwrap_or_else(|| ProtoError::new(ErrorCode::NotFound, "session gone")),
                    ))
                }
            }));
        }
        if !status.is_success() {
            return Err(HttpErr::Transient(ioe(format!("server returned {status}"))));
        }
        let b: HttpBatch = decode(&body).map_err(HttpErr::Transient)?;
        if !authentic(&b) {
            return Err(HttpErr::Transient(ioe("unauthenticated response")));
        }
        *self.gone_since.lock().unwrap() = None;
        Ok(b)
    }

    fn fail(&self, e: HttpErr, lost_at: &mut Option<Instant>) -> bool {
        match e {
            HttpErr::Fatal(e) => {
                self.core.close(e);
                true
            }
            HttpErr::Gone(e) => {
                let mut g = self.gone_since.lock().unwrap();
                if g.get_or_insert_with(Instant::now).elapsed() >= GONE_GRACE {
                    self.core.close(unauthenticated(e));
                    return true;
                }
                tracing::debug!(err = %e, "unauthenticated session-gone answer; retrying");
                false
            }
            HttpErr::Transient(e) => {
                tracing::debug!(err = %e, "http transport error");
                let since = *lost_at.get_or_insert_with(Instant::now);
                if since.elapsed() > SESSION_GRACE {
                    self.core
                        .close(ProtoError::new(ErrorCode::Timeout, "could not reach server"));
                    return true;
                }
                false
            }
        }
    }

    async fn tx_loop(self: Arc<Self>) {
        let url = self.base.join("tx").expect("url");
        let mut posted = 0u64;
        let mut ver = self.core.subscribe();
        let mut lost_at = None;
        let mut backoff = Duration::from_millis(200);
        let mut ctr = 0u64;
        loop {
            let closed = self.core.closed();
            let msgs = self.core.segs_after(posted, 1024 * 1024);
            if msgs.is_empty() && closed.is_none() {
                let _ = tokio::time::timeout(Duration::from_secs(20), ver.changed()).await;
                continue;
            }
            let last = msgs.last().map(|m| m.0).unwrap_or(posted);
            let batch = HttpBatch {
                ack: self.core.recv_ack(),
                msgs,
                closed: closed.clone(),
                mac: None,
            };
            let body = encode(&batch);
            ctr += 1;
            let req = self
                .http
                .post(url.clone())
                .body(body.clone())
                .timeout(Duration::from_secs(30));
            match self.call("tx", ctr, &body, req).await {
                Ok(resp) => {
                    if lost_at.take().is_some() {
                        self.resumes.send_modify(|n| *n += 1);
                    }
                    backoff = Duration::from_millis(200);
                    posted = last;
                    if let Err(e) = self.core.ack(resp.ack) {
                        self.core.close(e);
                    }
                    if closed.is_some() {
                        return;
                    }
                }
                Err(e) => {
                    if closed.is_some() || self.fail(e, &mut lost_at) {
                        return;
                    }
                    posted = self.core.acked();
                    tokio::time::sleep(backoff).await;
                    backoff = (backoff * 2).min(Duration::from_secs(5));
                }
            }
        }
    }

    async fn rx_loop(self: Arc<Self>) {
        let url = self.base.join("rx").expect("url");
        let mut lost_at = None;
        let mut backoff = Duration::from_millis(200);
        let mut ctr = 0u64;
        loop {
            if self.core.closed().is_some() {
                return;
            }
            let ack = self.core.recv_ack();
            ctr += 1;
            let req = self
                .http
                .get(url.clone())
                .query(&[("ack", ack)])
                .timeout(crate::LONG_POLL + Duration::from_secs(15));
            match self.call("rx", ctr, &ack.to_be_bytes(), req).await {
                Ok(batch) => {
                    // A recovered download link counts as a resume too.
                    if lost_at.take().is_some() {
                        self.resumes.send_modify(|n| *n += 1);
                    }
                    backoff = Duration::from_millis(200);
                    // The ack is authenticated by the response MAC.
                    if let Err(e) = self.core.ack(batch.ack) {
                        self.core.close(e);
                        return;
                    }
                    for (seq, data) in &batch.msgs {
                        // A rejected segment only costs a re-poll.
                        if let Err(e) = self.core.receive(*seq, data) {
                            tracing::warn!(err = %e, "rejected segment");
                            break;
                        }
                    }
                    if let Some(e) = batch.closed {
                        self.core.close(e);
                        return;
                    }
                }
                Err(e) => {
                    if self.fail(e, &mut lost_at) {
                        return;
                    }
                    tokio::time::sleep(backoff).await;
                    backoff = (backoff * 2).min(Duration::from_secs(5));
                }
            }
        }
    }
}

/// Build a fresh handshake `Hello` (current time, random nonce).
pub fn new_hello(role: cjs_proto::Role, enroll_secret: Option<String>, version: &str) -> Hello {
    use rand::RngCore;
    let mut nonce = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut nonce);
    Hello {
        version: cjs_proto::PROTO_VERSION,
        role,
        ts: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0),
        nonce,
        enroll: enroll_secret.map(|secret| cjs_proto::Enroll { secret }),
        info: cjs_proto::ClientInfo::current(version),
    }
}
