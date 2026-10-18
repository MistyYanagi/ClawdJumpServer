use std::sync::{Arc, Mutex};
use std::time::Duration;

use cjs_proto::{ClientInfo, ErrorCode, Hello, ProtoError, Role, Welcome, PROTO_VERSION};
use cjs_transport::{
    connect, Authenticator, ClientConfig, StaticKeypair, TransportMode, TransportServer,
    TransportServerConfig,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

struct AllowKey(Vec<[u8; 32]>);

impl Authenticator for AllowKey {
    fn authenticate(
        &self,
        key: &[u8; 32],
        _hello: &Hello,
        _peer: Option<&str>,
    ) -> Result<Welcome, ProtoError> {
        if self.0.contains(key) {
            Ok(Welcome {
                principal_id: "p1".into(),
                name: "agent".into(),
                connection_id: "c1".into(),
                signing_key: [0; 32],
                server_time: 0,
            })
        } else {
            Err(ProtoError::new(ErrorCode::Unauthenticated, "unknown key"))
        }
    }
}

fn hello() -> Hello {
    use rand::RngCore;
    let mut nonce = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut nonce);
    Hello {
        version: PROTO_VERSION,
        role: Role::Agent,
        ts: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64,
        nonce,
        enroll: None,
        info: ClientInfo::current("test"),
    }
}

/// TCP proxy whose live connections can be cut on demand.
struct Chaos {
    addr: std::net::SocketAddr,
    conns: Arc<Mutex<Vec<tokio::task::AbortHandle>>>,
}

impl Chaos {
    async fn start(target: std::net::SocketAddr) -> Self {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        let conns: Arc<Mutex<Vec<tokio::task::AbortHandle>>> = Default::default();
        let c2 = conns.clone();
        tokio::spawn(async move {
            loop {
                let (mut a, _) = l.accept().await.unwrap();
                let h = tokio::spawn(async move {
                    let mut b = TcpStream::connect(target).await.unwrap();
                    let _ = tokio::io::copy_bidirectional(&mut a, &mut b).await;
                });
                c2.lock().unwrap().push(h.abort_handle());
            }
        });
        Self { addr, conns }
    }

    fn cut(&self) {
        for h in self.conns.lock().unwrap().drain(..) {
            h.abort();
        }
    }
}

async fn server(allowed: Vec<[u8; 32]>) -> (TransportServer, std::net::SocketAddr, StaticKeypair) {
    let key = StaticKeypair::generate();
    let (srv, mut acc) = TransportServer::new(TransportServerConfig {
        key: key.clone(),
        auth: Arc::new(AllowKey(allowed)),
        trust_forwarded_for: false,
        handshake_limit: Default::default(),
    });
    let app = srv.router();
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(
            axum::serve::ListenerExt::tap_io(l, |t| {
                let _ = t.set_nodelay(true);
            }),
            app,
        )
        .await
        .unwrap()
    });
    // Echo application on every accepted session (yamux server side).
    tokio::spawn(async move {
        while let Some(a) = acc.recv().await {
            let (_h, mut inbound, _t) = cjs_mux::spawn(a.io, cjs_mux::Mode::Server);
            tokio::spawn(async move {
                while let Some(mut s) = inbound.recv().await {
                    tokio::spawn(async move {
                        let mut buf = vec![0u8; 16384];
                        loop {
                            let n = s.read(&mut buf).await.unwrap_or(0);
                            if n == 0 {
                                break;
                            }
                            if s.write_all(&buf[..n]).await.is_err() {
                                break;
                            }
                        }
                        let _ = s.shutdown().await;
                    });
                }
            });
        }
    });
    (srv, addr, key)
}

fn cfg(
    addr: std::net::SocketAddr,
    server_key: [u8; 32],
    key: StaticKeypair,
    mode: TransportMode,
) -> ClientConfig {
    ClientConfig {
        server: format!("http://{addr}/").parse().unwrap(),
        server_key,
        key,
        mode,
        extra_ca: None,
    }
}

async fn echo_roundtrip(h: &cjs_mux::MuxHandle, size: usize, seed: u8) {
    let s = h.open().await.unwrap();
    let data: Vec<u8> = (0..size)
        .map(|i| (i as u8).wrapping_mul(31).wrapping_add(seed))
        .collect();
    let d2 = data.clone();
    let (mut r, mut w) = tokio::io::split(s);
    let writer = tokio::spawn(async move {
        for c in d2.chunks(7000) {
            w.write_all(c).await.unwrap();
        }
        w.shutdown().await.unwrap();
    });
    let mut back = Vec::new();
    r.read_to_end(&mut back).await.unwrap();
    writer.await.unwrap();
    assert_eq!(back.len(), data.len());
    assert!(back == data, "payload mismatch");
}

async fn parallel_echo(mode: TransportMode) {
    let ck = StaticKeypair::generate();
    let (_srv, addr, sk) = server(vec![ck.public]).await;
    let conn = connect(&cfg(addr, sk.public, ck, mode), hello()).await.unwrap();
    assert_eq!(conn.welcome.principal_id, "p1");
    let (h, _in, _t) = cjs_mux::spawn(conn.io, cjs_mux::Mode::Client);
    let mut tasks = Vec::new();
    for i in 0..10u8 {
        let h = h.clone();
        tasks.push(tokio::spawn(async move {
            echo_roundtrip(&h, 300_000 + i as usize * 1000, i).await
        }));
    }
    for t in tasks {
        t.await.unwrap();
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn ws_parallel_streams() {
    parallel_echo(TransportMode::Ws).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn http_parallel_streams() {
    parallel_echo(TransportMode::Http).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn auto_picks_ws() {
    let ck = StaticKeypair::generate();
    let (_srv, addr, sk) = server(vec![ck.public]).await;
    let conn = connect(&cfg(addr, sk.public, ck, TransportMode::Auto), hello())
        .await
        .unwrap();
    assert_eq!(conn.transport, "ws");
}

async fn resume_under_chaos(mode: TransportMode) {
    let ck = StaticKeypair::generate();
    let (_srv, addr, sk) = server(vec![ck.public]).await;
    let chaos = Chaos::start(addr).await;
    let conn = connect(&cfg(chaos.addr, sk.public, ck, mode), hello())
        .await
        .unwrap();
    let resumes = conn.resumes.clone();
    let (h, _in, _t) = cjs_mux::spawn(conn.io, cjs_mux::Mode::Client);
    let h2 = h.clone();
    // Keep data flowing until every cut has happened, so the cuts always
    // hit live transfers (fast machines finish a fixed workload early).
    let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let stop2 = stop.clone();
    let work = tokio::spawn(async move {
        let mut i = 0u8;
        while !stop2.load(std::sync::atomic::Ordering::SeqCst) || i < 4 {
            echo_roundtrip(&h2, 2_000_000, i).await;
            i = i.wrapping_add(1);
        }
    });
    for _ in 0..4 {
        tokio::time::sleep(Duration::from_millis(250)).await;
        chaos.cut();
    }
    stop.store(true, std::sync::atomic::Ordering::SeqCst);
    tokio::time::timeout(Duration::from_secs(60), work)
        .await
        .unwrap()
        .unwrap();
    assert!(*resumes.borrow() >= 1, "expected at least one resume");
    // Session is still usable afterwards.
    echo_roundtrip(&h, 1000, 9).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn ws_resumes_after_link_cuts() {
    resume_under_chaos(TransportMode::Ws).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn http_resumes_after_link_cuts() {
    resume_under_chaos(TransportMode::Http).await;
}

#[tokio::test]
async fn unknown_client_is_rejected() {
    let (_srv, addr, sk) = server(vec![]).await;
    for mode in [TransportMode::Ws, TransportMode::Http] {
        let e = connect(&cfg(addr, sk.public, StaticKeypair::generate(), mode), hello())
            .await
            .unwrap_err();
        assert_eq!(e.code, ErrorCode::Unauthenticated, "{mode:?}: {e}");
    }
}

#[tokio::test]
async fn wrong_pinned_server_key_fails() {
    let ck = StaticKeypair::generate();
    let (_srv, addr, _sk) = server(vec![ck.public]).await;
    let bogus = StaticKeypair::generate();
    for mode in [TransportMode::Ws, TransportMode::Http] {
        assert!(connect(&cfg(addr, bogus.public, ck.clone(), mode), hello())
            .await
            .is_err());
    }
}

#[tokio::test]
async fn stale_and_replayed_hello_rejected() {
    let ck = StaticKeypair::generate();
    let (_srv, addr, sk) = server(vec![ck.public]).await;
    let c = cfg(addr, sk.public, ck, TransportMode::Ws);
    let mut old = hello();
    old.ts -= 3600;
    assert_eq!(connect(&c, old).await.unwrap_err().code, ErrorCode::Expired);
    let h = hello();
    connect(&c, h.clone()).await.unwrap();
    assert_eq!(connect(&c, h).await.unwrap_err().code, ErrorCode::Replay);
}

#[tokio::test]
async fn server_can_cut_session() {
    let ck = StaticKeypair::generate();
    let key = StaticKeypair::generate();
    let (srv, mut acc) = TransportServer::new(TransportServerConfig {
        key: key.clone(),
        auth: Arc::new(AllowKey(vec![ck.public])),
        trust_forwarded_for: false,
        handshake_limit: Default::default(),
    });
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    let app = srv.router();
    tokio::spawn(async move {
        axum::serve(
            axum::serve::ListenerExt::tap_io(l, |t| {
                let _ = t.set_nodelay(true);
            }),
            app,
        )
        .await
        .unwrap()
    });
    for mode in [TransportMode::Ws, TransportMode::Http] {
        let conn = connect(&cfg(addr, key.public, ck.clone(), mode), hello())
            .await
            .unwrap();
        let a = acc.recv().await.unwrap();
        a.handle
            .close(ProtoError::new(ErrorCode::Disabled, "account disabled"));
        let e = tokio::time::timeout(Duration::from_secs(10), conn.handle.closed())
            .await
            .unwrap();
        assert_eq!(e.code, ErrorCode::Disabled, "{mode:?}");
    }
}

// ---------------------------------------------------------------------------
// A TLS-intercepting proxy sees and can inject everything outside Noise.
// ---------------------------------------------------------------------------

use cjs_proto::{decode, encode, HttpBatch, WireMsg, HTTP_AUTH_HEADER};
use futures::{SinkExt, StreamExt};
use tokio_tungstenite::tungstenite::Message as TMsg;

/// WebSocket man in the middle: forwards frames, records client frames and
/// injects forged frames towards the client on demand.
struct WsMitm {
    addr: std::net::SocketAddr,
    inject: tokio::sync::mpsc::UnboundedSender<WireMsg>,
    seen_up: Arc<Mutex<Vec<WireMsg>>>,
}

impl WsMitm {
    async fn start(target: std::net::SocketAddr) -> Self {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        let (inject, rx) = tokio::sync::mpsc::unbounded_channel::<WireMsg>();
        let rx = Arc::new(tokio::sync::Mutex::new(rx));
        let seen_up: Arc<Mutex<Vec<WireMsg>>> = Default::default();
        let seen = seen_up.clone();
        tokio::spawn(async move {
            loop {
                let (tcp, _) = l.accept().await.unwrap();
                let rx = rx.clone();
                let seen = seen.clone();
                tokio::spawn(async move {
                    let Ok(client) = tokio_tungstenite::accept_async(tcp).await else {
                        return;
                    };
                    let up_tcp = TcpStream::connect(target).await.unwrap();
                    let Ok((up, _)) =
                        tokio_tungstenite::client_async(format!("ws://{target}/v1/t/ws"), up_tcp).await
                    else {
                        return;
                    };
                    let (mut csink, mut cstream) = client.split();
                    let (mut usink, mut ustream) = up.split();
                    let upward = async {
                        while let Some(Ok(m)) = cstream.next().await {
                            if let TMsg::Binary(b) = &m {
                                if let Ok(w) = decode::<WireMsg>(b) {
                                    seen.lock().unwrap().push(w);
                                }
                            }
                            if usink.send(m).await.is_err() {
                                break;
                            }
                        }
                    };
                    let downward = async {
                        let mut rx = rx.lock().await;
                        loop {
                            tokio::select! {
                                m = ustream.next() => match m {
                                    Some(Ok(m)) => if csink.send(m).await.is_err() { break },
                                    _ => break,
                                },
                                Some(f) = rx.recv() => {
                                    if csink.send(TMsg::Binary(encode(&f).into())).await.is_err() { break }
                                }
                            }
                        }
                    };
                    tokio::select! { _ = upward => {}, _ = downward => {} }
                });
            }
        });
        Self {
            addr,
            inject,
            seen_up,
        }
    }
}

async fn wait_resumes(r: &tokio::sync::watch::Receiver<u64>, n: u64) {
    for _ in 0..200 {
        if *r.borrow() >= n {
            return;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("expected {n} resumes, got {}", *r.borrow());
}

/// T1: forged `Close` and `Ack` frames (no valid MAC) only drop the link;
/// the session resumes, loses no data and is not closed with the forged
/// reason. A captured resume request cannot be replayed.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn ws_forged_control_frames_only_drop_the_link() {
    let ck = StaticKeypair::generate();
    let (_srv, addr, sk) = server(vec![ck.public]).await;
    let mitm = WsMitm::start(addr).await;
    let conn = connect(&cfg(mitm.addr, sk.public, ck, TransportMode::Ws), hello())
        .await
        .unwrap();
    let resumes = conn.resumes.clone();
    let handle = conn.handle.clone();
    let (h, _in, _t) = cjs_mux::spawn(conn.io, cjs_mux::Mode::Client);
    echo_roundtrip(&h, 100_000, 1).await;

    mitm.inject
        .send(WireMsg::Close {
            err: ProtoError::new(ErrorCode::Disabled, "forged"),
            mac: [0; 32],
        })
        .unwrap();
    wait_resumes(&resumes, 1).await;
    assert!(!handle.is_closed(), "forged close must not end the session");
    echo_roundtrip(&h, 100_000, 2).await;

    // A forged ack far beyond the data sent would make the peer drop
    // undelivered segments (or end the session); it only drops the link.
    mitm.inject
        .send(WireMsg::Ack {
            n: 1 << 40,
            mac: [7; 32],
        })
        .unwrap();
    // Keep data in flight while the forged ack arrives.
    let h2 = h.clone();
    let busy = tokio::spawn(async move { echo_roundtrip(&h2, 3_000_000, 3).await });
    wait_resumes(&resumes, 2).await;
    busy.await.unwrap();
    assert!(!handle.is_closed());

    // Replaying a captured resume request is refused, and the session
    // still works afterwards.
    let resume = mitm
        .seen_up
        .lock()
        .unwrap()
        .iter()
        .find(|m| matches!(m, WireMsg::Resume { .. }))
        .cloned()
        .expect("a resume was sent");
    let tcp = TcpStream::connect(addr).await.unwrap();
    let (mut ws, _) = tokio_tungstenite::client_async(format!("ws://{addr}/v1/t/ws"), tcp)
        .await
        .unwrap();
    ws.send(TMsg::Binary(encode(&resume).into())).await.unwrap();
    let reply = loop {
        match ws.next().await.unwrap().unwrap() {
            TMsg::Binary(b) => break decode::<WireMsg>(&b).unwrap(),
            _ => continue,
        }
    };
    assert!(
        matches!(reply, WireMsg::Reject(_)),
        "replayed resume accepted: {reply:?}"
    );
    echo_roundtrip(&h, 10_000, 4).await;
}

/// Recorded requests: (path and query, auth header, body).
type Seen = Arc<Mutex<Vec<(String, String, Vec<u8>)>>>;

/// HTTP man in the middle: records requests and can answer one `rx` poll
/// with a forged "session closed" response.
struct HttpMitm {
    addr: std::net::SocketAddr,
    forge_gone: Arc<std::sync::atomic::AtomicBool>,
    seen: Seen,
}

impl HttpMitm {
    async fn start(target: std::net::SocketAddr) -> Self {
        use axum::extract::Request;
        use axum::response::IntoResponse;
        let forge_gone = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let seen: Seen = Default::default();
        let (fg, sn) = (forge_gone.clone(), seen.clone());
        let http = reqwest::Client::new();
        let app = axum::Router::new().fallback(move |req: Request| {
            let (fg, sn, http) = (fg.clone(), sn.clone(), http.clone());
            async move {
                let (parts, body) = req.into_parts();
                let body = axum::body::to_bytes(body, 8 << 20).await.unwrap().to_vec();
                let pq = parts
                    .uri
                    .path_and_query()
                    .map(|p| p.to_string())
                    .unwrap_or_default();
                let auth = parts
                    .headers
                    .get(HTTP_AUTH_HEADER)
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or("")
                    .to_string();
                sn.lock().unwrap().push((pq.clone(), auth.clone(), body.clone()));
                if parts.uri.path().ends_with("/rx") && fg.swap(false, std::sync::atomic::Ordering::SeqCst) {
                    let forged = HttpBatch {
                        closed: Some(ProtoError::new(ErrorCode::Disabled, "forged")),
                        mac: Some([1; 32]),
                        ..Default::default()
                    };
                    return (axum::http::StatusCode::GONE, encode(&forged)).into_response();
                }
                let mut r = http.request(parts.method.clone(), format!("http://{target}{pq}"));
                if !auth.is_empty() {
                    r = r.header(HTTP_AUTH_HEADER, auth);
                }
                match r.body(body).send().await {
                    Ok(resp) => {
                        let st = resp.status();
                        let b = resp.bytes().await.unwrap_or_default().to_vec();
                        (st, b).into_response()
                    }
                    Err(_) => axum::http::StatusCode::BAD_GATEWAY.into_response(),
                }
            }
        });
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(l, app).await.unwrap() });
        Self {
            addr,
            forge_gone,
            seen,
        }
    }
}

/// T1 (HTTP): the resume key never appears on the wire (requests carry a
/// per-request MAC), captured requests cannot be replayed, and a forged
/// "session closed" answer does not end the session.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn http_forged_close_and_replay_are_ignored() {
    let ck = StaticKeypair::generate();
    let (_srv, addr, sk) = server(vec![ck.public]).await;
    let mitm = HttpMitm::start(addr).await;
    let conn = connect(&cfg(mitm.addr, sk.public, ck, TransportMode::Http), hello())
        .await
        .unwrap();
    let handle = conn.handle.clone();
    let (h, _in, _t) = cjs_mux::spawn(conn.io, cjs_mux::Mode::Client);
    echo_roundtrip(&h, 100_000, 1).await;

    mitm.forge_gone.store(true, std::sync::atomic::Ordering::SeqCst);
    // Traffic completes the parked long poll, so a new one is issued.
    for i in 0..100u8 {
        if !mitm.forge_gone.load(std::sync::atomic::Ordering::SeqCst) {
            break;
        }
        echo_roundtrip(&h, 1000, i).await;
    }
    assert!(
        !mitm.forge_gone.load(std::sync::atomic::Ordering::SeqCst),
        "forgery not delivered"
    );
    echo_roundtrip(&h, 100_000, 2).await;
    assert!(!handle.is_closed(), "forged close must not end the session");

    // Every request carries a fresh proof; none repeats, and none is a
    // bearer secret that stays the same.
    let seen = mitm.seen.lock().unwrap().clone();
    let auths: Vec<&String> = seen.iter().map(|s| &s.1).filter(|a| !a.is_empty()).collect();
    assert!(auths.len() >= 4);
    let uniq: std::collections::HashSet<_> = auths.iter().collect();
    assert_eq!(uniq.len(), auths.len(), "auth header repeated");
    assert!(seen.iter().all(|s| !s.0.contains("x-cjs-resume")));
    // Replaying a captured tx request directly is refused.
    let (pq, auth, body) = seen.iter().rev().find(|s| s.0.ends_with("/tx")).cloned().unwrap();
    let r = reqwest::Client::new()
        .post(format!("http://{addr}{pq}"))
        .header(HTTP_AUTH_HEADER, auth)
        .body(body)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status().as_u16(), 401, "replayed request accepted");
    // A request without proof is refused too.
    let r = reqwest::Client::new()
        .post(format!("http://{addr}{pq}"))
        .body(encode(&HttpBatch::default()))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status().as_u16(), 401);
    echo_roundtrip(&h, 10_000, 3).await;
    assert!(!handle.is_closed());
}

/// T2: handshake attempts are rate limited per source address before any
/// cryptographic work, and the replay cache stays bounded.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn handshake_flood_is_rate_limited() {
    let key = StaticKeypair::generate();
    let rejected = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    struct Count(Arc<std::sync::atomic::AtomicUsize>);
    impl Authenticator for Count {
        fn authenticate(&self, _: &[u8; 32], _: &Hello, _: Option<&str>) -> Result<Welcome, ProtoError> {
            Err(ProtoError::new(ErrorCode::Unauthenticated, "no"))
        }
        fn rejected(&self, _: Option<&[u8; 32]>, e: &ProtoError, _: Option<&str>) {
            if e.code == ErrorCode::LimitExceeded {
                self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            }
        }
    }
    let (srv, _acc) = TransportServer::new(TransportServerConfig {
        key,
        auth: Arc::new(Count(rejected.clone())),
        trust_forwarded_for: false,
        handshake_limit: cjs_transport::HandshakeLimit { burst: 5, per_sec: 1 },
    });
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    let app = srv.router();
    tokio::spawn(async move { axum::serve(l, app).await.unwrap() });
    let http = reqwest::Client::new();
    let mut statuses = Vec::new();
    for _ in 0..20 {
        let r = http
            .post(format!("http://{addr}/v1/t/open"))
            .body(vec![0u8; 10])
            .send()
            .await
            .unwrap();
        statuses.push(r.status().as_u16());
    }
    assert_eq!(statuses.iter().filter(|s| **s == 401).count(), 5, "{statuses:?}");
    assert_eq!(statuses.iter().filter(|s| **s == 429).count(), 15, "{statuses:?}");
    assert_eq!(rejected.load(std::sync::atomic::Ordering::SeqCst), 15);
    assert!(srv.replay_cache_len() <= 5);
}
