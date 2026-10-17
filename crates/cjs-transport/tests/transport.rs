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
