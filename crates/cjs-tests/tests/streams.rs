//! End-to-end tests for exec, files, forwards, egress, RPC and the daemon.
#![cfg(unix)]
use std::time::Duration;

use cjs_agent::{ops, Opener};
use cjs_authz::net::NetRule;
use cjs_proto::{Action, ErrorCode, OpenRequest};
use cjs_tests::*;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

async fn opener(env: &Env) -> Opener {
    Opener::new(&env.agent_dir, true).await.unwrap()
}

async fn echo_server() -> u16 {
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = l.local_addr().unwrap().port();
    tokio::spawn(async move {
        loop {
            let (mut s, _) = l.accept().await.unwrap();
            tokio::spawn(async move {
                let mut buf = [0u8; 4096];
                loop {
                    match s.read(&mut buf).await {
                        Ok(0) | Err(_) => break,
                        Ok(n) => {
                            if s.write_all(&buf[..n]).await.is_err() {
                                break;
                            }
                        }
                    }
                }
            });
        }
    });
    port
}

async fn echo_roundtrip<S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin>(s: &mut S) {
    s.write_all(b"ping-123").await.unwrap();
    let mut b = [0u8; 8];
    tokio::time::timeout(Duration::from_secs(10), s.read_exact(&mut b))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&b, b"ping-123");
}

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn exec_output_exit_env_and_limits() {
    let env = Env::start(mode_from_env()).await;
    env.put_grant(&env.grant("g1", &[Action::Exec]));
    let op = opener(&env).await;
    let req = OpenRequest::Exec {
        device: "dev1".into(),
        argv: vec![
            "/bin/sh".into(),
            "-c".into(),
            "echo out-$FOO; echo err >&2; cat; exit 7".into(),
        ],
        cwd: None,
        env: vec![("FOO".into(), "bar".into())],
        timeout_secs: Some(30),
    };
    let r = ops::exec_collect(&op, &req, Some(b"from-stdin".to_vec()), 1 << 20)
        .await
        .unwrap();
    assert_eq!(r.stdout, "out-bar\nfrom-stdin");
    assert_eq!(r.stderr, "err\n");
    assert_eq!(r.exit_code, Some(7));
    // The device's own environment does not leak into commands.
    std::env::set_var("CJS_TEST_SECRET", "s3cret");
    let r = ops::exec_collect(&op, &exec_req("dev1", "env"), None, 1 << 20)
        .await
        .unwrap();
    assert!(!r.stdout.contains("s3cret"));
    assert!(r.stdout.contains("CJS_SESSION="));
    // Loader variables are refused before anything runs.
    let bad = OpenRequest::Exec {
        device: "dev1".into(),
        argv: vec!["/bin/true".into()],
        cwd: None,
        env: vec![("LD_PRELOAD".into(), "/tmp/x.so".into())],
        timeout_secs: None,
    };
    assert_eq!(
        ops::exec_collect(&op, &bad, None, 10).await.unwrap_err().code,
        ErrorCode::Forbidden
    );
    // Timeouts kill the command.
    let slow = OpenRequest::Exec {
        device: "dev1".into(),
        argv: vec!["/bin/sleep".into(), "30".into()],
        cwd: None,
        env: vec![],
        timeout_secs: Some(1),
    };
    let r = ops::exec_collect(&op, &slow, None, 10).await.unwrap();
    assert!(r.timed_out);
    // cwd outside the project roots is refused.
    let outside = OpenRequest::Exec {
        device: "dev1".into(),
        argv: vec!["/bin/pwd".into()],
        cwd: Some("/etc".into()),
        env: vec![],
        timeout_secs: None,
    };
    assert_eq!(
        ops::exec_collect(&op, &outside, None, 10).await.unwrap_err().code,
        ErrorCode::Forbidden
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn files_roundtrip_resume_and_jail() {
    let env = Env::start(mode_from_env()).await;
    env.put_grant(&env.grant("g1", &[Action::FileRead, Action::FileWrite]));
    let op = opener(&env).await;
    let local = env.tmp().join("big.bin");
    let data: Vec<u8> = (0..300_000u32).map(|i| (i * 7 % 251) as u8).collect();
    std::fs::write(&local, &data).unwrap();
    let up = ops::upload(&op, "dev1", &local, "sub/dir/big.bin", false, true)
        .await
        .unwrap();
    assert_eq!(up.size, data.len() as u64);
    assert_eq!(std::fs::read(env.project.join("sub/dir/big.bin")).unwrap(), data);
    // Resume an upload: remote has a prefix only.
    std::fs::write(env.project.join("part.bin"), &data[..100_000]).unwrap();
    let up = ops::upload(&op, "dev1", &local, "part.bin", true, false)
        .await
        .unwrap();
    assert_eq!(up.resumed_from, 100_000);
    assert_eq!(std::fs::read(env.project.join("part.bin")).unwrap(), data);
    // Download, then resume a partial download.
    let dl = env.tmp().join("dl.bin");
    ops::download(&op, "dev1", "sub/dir/big.bin", &dl, false)
        .await
        .unwrap();
    assert_eq!(std::fs::read(&dl).unwrap(), data);
    std::fs::write(&dl, &data[..12_345]).unwrap();
    let t = ops::download(&op, "dev1", "sub/dir/big.bin", &dl, true)
        .await
        .unwrap();
    assert_eq!(t.resumed_from, 12_345);
    assert_eq!(std::fs::read(&dl).unwrap(), data);
    // Listing.
    let (_, entries) = ops::list(&op, "dev1", ".").await.unwrap();
    let names: Vec<_> = entries.iter().map(|e| e.name.as_str()).collect();
    assert!(names.contains(&"sub") && names.contains(&"part.bin"), "{names:?}");
    // Jail: absolute paths outside, `..`, and symlinks pointing out are refused.
    std::fs::write(env.tmp().join("secret.txt"), "top secret").unwrap();
    std::os::unix::fs::symlink(env.tmp().join("secret.txt"), env.project.join("link")).unwrap();
    for p in ["/etc/passwd", "../secret.txt", "link", "sub/../../secret.txt"] {
        let e = ops::download(&op, "dev1", p, &env.tmp().join("x"), false)
            .await
            .unwrap_err();
        assert_eq!(e.code, ErrorCode::Forbidden, "{p}: {e}");
    }
    let e = ops::upload(&op, "dev1", &local, "../escape.bin", false, false)
        .await
        .unwrap_err();
    assert_eq!(e.code, ErrorCode::Forbidden);
    assert!(!env.tmp().join("escape.bin").exists());
    // Read-only grant: writes are denied by policy.
    env.put_grant(&env.grant("g1", &[Action::FileRead]));
    let e = ops::upload(&op, "dev1", &local, "new.bin", false, false)
        .await
        .unwrap_err();
    assert_eq!(e.code, ErrorCode::Forbidden);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn local_and_remote_forwarding() {
    let env = Env::start(mode_from_env()).await;
    let echo = echo_server().await;
    let rport = free_port();
    let mut g = env.grant("g1", &[Action::ForwardLocal, Action::ForwardRemote]);
    g.forward_targets = vec![NetRule::allow("127.0.0.1", &[&echo.to_string()])];
    g.remote_ports = vec![rport.to_string().parse().unwrap()];
    env.put_grant(&g);
    let op = opener(&env).await;
    // -L: agent -> device -> 127.0.0.1:echo
    let (mut s, _) = op
        .open(&OpenRequest::ForwardL {
            device: "dev1".into(),
            host: "127.0.0.1".into(),
            port: echo,
        })
        .await
        .unwrap();
    echo_roundtrip(&mut s).await;
    // Other ports are denied.
    let e = op
        .open(&OpenRequest::ForwardL {
            device: "dev1".into(),
            host: "127.0.0.1".into(),
            port: 22,
        })
        .await
        .unwrap_err();
    assert_eq!(e.code, ErrorCode::Forbidden);
    // -R: device 127.0.0.1:rport -> agent -> 127.0.0.1:echo
    let (_ctl, _o, _g) = op
        .forward_remote(
            &OpenRequest::ForwardR {
                device: "dev1".into(),
                bind_host: "127.0.0.1".into(),
                bind_port: rport,
            },
            "127.0.0.1",
            echo,
        )
        .await
        .unwrap();
    let mut c = tokio::net::TcpStream::connect(("127.0.0.1", rport))
        .await
        .unwrap();
    echo_roundtrip(&mut c).await;
    // Binding on all interfaces needs full access.
    let e = op
        .forward_remote(
            &OpenRequest::ForwardR {
                device: "dev1".into(),
                bind_host: "0.0.0.0".into(),
                bind_port: rport,
            },
            "127.0.0.1",
            echo,
        )
        .await
        .unwrap_err();
    assert_eq!(e.code, ErrorCode::Forbidden);
    let kinds = env.audit_kinds();
    assert!(kinds.iter().any(|(k, _)| k == "forward.conn"), "{kinds:?}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn egress_with_ssrf_guard() {
    let env = Env::start(mode_from_env()).await;
    let echo = echo_server().await;
    let op = opener(&env).await;
    let egress = |rules: Vec<NetRule>| {
        let mut g = env.grant("eg", &[Action::Egress]);
        g.target = cjs_authz::Target::Server;
        g.project_roots = vec![];
        g.egress = rules;
        g
    };
    // `*` allows names, but loopback/private addresses stay blocked after DNS.
    env.put_grant(&egress(vec![NetRule::allow("*", &[])]));
    let req = OpenRequest::Egress {
        host: "localhost".into(),
        port: echo,
        via: None,
    };
    let e = op.open(&req).await.unwrap_err();
    assert_eq!(e.code, ErrorCode::Forbidden, "{e}");
    assert!(env.audit_kinds().iter().any(|(k, _)| k == "egress.blocked"));
    // An explicit IP rule allows it.
    env.put_grant(&egress(vec![
        NetRule::allow("127.0.0.1/32", &[&echo.to_string()]),
        NetRule::allow("localhost", &[]),
    ]));
    let (mut s, _) = op.open(&req).await.unwrap();
    echo_roundtrip(&mut s).await;
    // Egress through the device as exit node applies the same post-DNS rules.
    let mut g = env.grant("dev-eg", &[Action::Egress]);
    g.egress = vec![NetRule::allow("*", &[])];
    env.put_grant(&g);
    let via = OpenRequest::Egress {
        host: "localhost".into(),
        port: echo,
        via: Some("dev1".into()),
    };
    let e = op.open(&via).await.unwrap_err();
    assert_eq!(e.code, ErrorCode::Forbidden, "{e}");
    g.egress = vec![
        NetRule::allow("localhost", &[]),
        NetRule::allow("::1/128", &[]),
        NetRule::allow("127.0.0.1", &[]),
    ];
    env.put_grant(&g);
    let (mut s, _) = op.open(&via).await.unwrap();
    echo_roundtrip(&mut s).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn rpc_and_daemon() {
    let env = Env::start(mode_from_env()).await;
    let op = opener(&env).await;
    assert!(
        ops::devices(&op).await.unwrap().is_empty(),
        "no grant, no device listed"
    );
    env.put_grant(&env.grant("g1", &[Action::Exec, Action::FileRead]));
    let ds = ops::devices(&op).await.unwrap();
    assert_eq!(ds.len(), 1);
    assert!(ds[0].online);
    assert_eq!(ds[0].actions, vec![Action::Exec, Action::FileRead]);
    // Through the daemon.
    let dir = env.agent_dir.clone();
    let d = tokio::spawn(async move { cjs_agent::local::run_daemon(&dir).await });
    let mut daemon = None;
    for _ in 0..100 {
        if let Ok(o @ Opener::Daemon { .. }) = Opener::new(&env.agent_dir, false).await {
            daemon = Some(o);
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let daemon = daemon.expect("daemon did not come up");
    let r = ops::exec_collect(&daemon, &exec_req("dev1", "echo via-daemon"), None, 1000)
        .await
        .unwrap();
    assert_eq!(r.stdout, "via-daemon\n");
    // Wrong token is refused.
    let bogus = Opener::Daemon {
        dir: env.agent_dir.clone(),
        token: "nope".into(),
    };
    assert!(bogus.open(&exec_req("dev1", "true")).await.is_err());
    d.abort();
}
