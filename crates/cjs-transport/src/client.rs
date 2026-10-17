//! Client side: connect over WebSocket or HTTP long-polling, keep the
//! session alive and transparently resume it after network failures.
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use cjs_proto::{
    decode, encode, ErrorCode, Hello, HttpBatch, HttpOpenResponse, ProtoError, Welcome, WireMsg,
};
use futures::{SinkExt, StreamExt};
use tokio::sync::watch;
use tokio_tungstenite::tungstenite::Message;

use crate::core::{Core, SessionHandle};
use crate::handshake::ClientHs;
use crate::io::SessionIo;
use crate::keys::StaticKeypair;
use crate::link::{run_link, LinkEnd};
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
        WireMsg::Reject(e) => return Err(e),
        _ => return Err(ProtoError::new(ErrorCode::Protocol, "unexpected handshake reply")),
    };
    let (noise, welcome, secret) = hs.finish(&msg2)?;
    let (core, in_rx) = Core::new(noise);
    let io = SessionIo::new(core.clone(), in_rx);
    let (resumes_tx, resumes) = watch::channel(0u64);
    let cfg2 = cfg.clone();
    let c2 = core.clone();
    tokio::spawn(async move { ws_keeper(cfg2, c2, sid, secret, ws, resumes_tx).await });
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
    secret: String,
    first: WsStream,
    resumes: watch::Sender<u64>,
) {
    let mut link = Some((first, 0u64));
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
        let attempt = async {
            let mut ws = ws_dial(&cfg).await?;
            ws_send(
                &mut ws,
                &WireMsg::Resume {
                    sid: sid.clone(),
                    secret: secret.clone(),
                    ack: core.recv_ack(),
                },
            )
            .await?;
            match ws_recv(&mut ws).await? {
                WireMsg::Resumed { ack } => Ok((ws, ack)),
                WireMsg::Reject(e) => Err(e),
                _ => Err(ProtoError::new(ErrorCode::Protocol, "unexpected resume reply")),
            }
        };
        match attempt.await {
            Ok(l) => {
                resumes.send_modify(|n| *n += 1);
                link = Some(l);
            }
            Err(e) if e.code == ErrorCode::Io || e.code == ErrorCode::Timeout => {
                tracing::debug!(err = %e, "resume attempt failed");
            }
            Err(e) => {
                core.close(e);
                return;
            }
        }
    }
}

// ---------------------------------------------------------------------------
// HTTP long-polling
// ---------------------------------------------------------------------------

const SECRET_HEADER: &str = "x-cjs-resume";

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
        return Err(decode::<ProtoError>(&body).unwrap_or_else(|_| ioe(format!("server returned {status}"))));
    }
    let open: HttpOpenResponse = decode(&body)?;
    let (noise, welcome, secret) = hs.finish(&open.msg)?;
    let (core, in_rx) = Core::new(noise);
    let io = SessionIo::new(core.clone(), in_rx);
    let (resumes_tx, resumes) = watch::channel(0u64);
    let base = cfg.server.join(&format!("v1/t/{}/", open.sid)).map_err(ioe)?;
    let st = Arc::new(HttpLink {
        http,
        base,
        secret,
        core: core.clone(),
        resumes: resumes_tx,
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
    secret: String,
    core: Arc<Core>,
    resumes: watch::Sender<u64>,
}

enum HttpErr {
    Transient(ProtoError),
    Fatal(ProtoError),
}

impl HttpLink {
    async fn call(&self, req: reqwest::RequestBuilder) -> Result<HttpBatch, HttpErr> {
        let resp = req
            .header(SECRET_HEADER, &self.secret)
            .send()
            .await
            .map_err(|e| HttpErr::Transient(ioe(e)))?;
        let status = resp.status();
        let body = resp.bytes().await.map_err(|e| HttpErr::Transient(ioe(e)))?;
        if status == reqwest::StatusCode::GONE {
            let e = decode::<HttpBatch>(&body)
                .ok()
                .and_then(|b| b.closed)
                .unwrap_or_else(|| ProtoError::new(ErrorCode::NotFound, "session gone"));
            return Err(HttpErr::Fatal(e));
        }
        if !status.is_success() {
            return Err(HttpErr::Transient(ioe(format!("server returned {status}"))));
        }
        decode(&body).map_err(HttpErr::Fatal)
    }

    fn fail(&self, e: HttpErr, lost_at: &mut Option<Instant>) -> bool {
        match e {
            HttpErr::Fatal(e) => {
                self.core.close(e);
                true
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
            };
            let req = self
                .http
                .post(url.clone())
                .body(encode(&batch))
                .timeout(Duration::from_secs(30));
            match self.call(req).await {
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
        loop {
            if self.core.closed().is_some() {
                return;
            }
            let req = self
                .http
                .get(url.clone())
                .query(&[("ack", self.core.recv_ack())])
                .timeout(crate::LONG_POLL + Duration::from_secs(15));
            match self.call(req).await {
                Ok(batch) => {
                    lost_at = None;
                    backoff = Duration::from_millis(200);
                    let mut res = self.core.ack(batch.ack);
                    for (seq, data) in &batch.msgs {
                        if res.is_err() {
                            break;
                        }
                        res = self.core.receive(*seq, data);
                    }
                    if let Err(e) = res {
                        self.core.close(e);
                        return;
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
