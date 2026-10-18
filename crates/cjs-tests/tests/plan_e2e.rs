//! End-to-end checks from the delivery plan: parallel sessions, large
//! transfers, recursive copies, the local proxy with curl, and an audit
//! trail for every stream kind. Runs over WS and HTTP like the other suites.
#![cfg(unix)]
use std::collections::BTreeSet;
use std::time::Duration;

use cjs_agent::{ops, proxy, Opener};
use cjs_authz::net::NetRule;
use cjs_mux::write_msg;
use cjs_proto::{Action, OpenRequest, PtyIn};
use cjs_tests::*;
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

async fn opener(env: &Env) -> Opener {
    Opener::new(&env.agent_dir, true).await.unwrap()
}

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

/// Minimal HTTP/1.1 server answering every request with `body`.
async fn http_server(body: &'static str) -> u16 {
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = l.local_addr().unwrap().port();
    tokio::spawn(async move {
        loop {
            let (mut s, _) = l.accept().await.unwrap();
            tokio::spawn(async move {
                let mut buf = Vec::new();
                let mut b = [0u8; 1024];
                while !buf.windows(4).any(|w| w == b"\r\n\r\n") {
                    match s.read(&mut b).await {
                        Ok(0) | Err(_) => return,
                        Ok(n) => buf.extend_from_slice(&b[..n]),
                    }
                }
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = s.write_all(resp.as_bytes()).await;
            });
        }
    });
    port
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn ten_parallel_shells_and_execs() {
    let env = Env::start(mode_from_env()).await;
    env.put_grant(&env.grant("g1", &[Action::Shell, Action::Exec]));
    let a = std::sync::Arc::new(env.agent().await);
    let mut tasks = Vec::new();
    for i in 0..10u32 {
        let a1 = a.clone();
        tasks.push(tokio::spawn(async move {
            let (mut s, _) = a1.open(pty_req("dev1")).await.unwrap();
            let cmd = format!("echo shell-$(({i}+1000))\nexit\n");
            write_msg(&mut s, &PtyIn::Input(cmd.into_bytes())).await.unwrap();
            pty_expect(&mut s, &format!("shell-{}", i + 1000), 60)
                .await
                .unwrap();
        }));
        let a2 = a.clone();
        tasks.push(tokio::spawn(async move {
            let (out, _, code) = run_exec(&a2, exec_req("dev1", &format!("echo exec-$(({i}+2000))")))
                .await
                .unwrap();
            assert_eq!(code, Some(0));
            assert_eq!(out.trim(), format!("exec-{}", i + 2000));
        }));
    }
    for t in tasks {
        tokio::time::timeout(Duration::from_secs(120), t)
            .await
            .expect("parallel session timed out")
            .unwrap();
    }
}

fn sha_hex(p: &std::path::Path) -> String {
    let mut f = std::fs::File::open(p).unwrap();
    let mut h = Sha256::new();
    std::io::copy(&mut f, &mut h).unwrap();
    hex::encode(h.finalize())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn hundred_megabyte_file_both_ways() {
    let env = Env::start(mode_from_env()).await;
    env.put_grant(&env.grant("g1", &[Action::FileRead, Action::FileWrite]));
    let op = opener(&env).await;
    // Deterministic, incompressible-looking content.
    let src = env.tmp().join("big.bin");
    {
        use std::io::Write;
        let mut f = std::io::BufWriter::new(std::fs::File::create(&src).unwrap());
        let mut x: u64 = 0x9e37_79b9_7f4a_7c15;
        let mut block = vec![0u8; 1 << 20];
        for _ in 0..100 {
            for c in block.chunks_mut(8) {
                x ^= x << 13;
                x ^= x >> 7;
                x ^= x << 17;
                c.copy_from_slice(&x.to_le_bytes());
            }
            f.write_all(&block).unwrap();
        }
    }
    let want = sha_hex(&src);
    let t0 = std::time::Instant::now();
    let up = ops::upload(&op, "dev1", &src, "big.bin", false, false)
        .await
        .unwrap();
    assert_eq!(up.size, 100 << 20);
    assert_eq!(up.sha256, want);
    assert_eq!(sha_hex(&env.project.join("big.bin")), want);
    let back = env.tmp().join("back.bin");
    let down = ops::download(&op, "dev1", "big.bin", &back, false).await.unwrap();
    assert_eq!(down.sha256, want);
    assert_eq!(sha_hex(&back), want);
    eprintln!("100 MiB up+down over {:?} in {:?}", env.mode, t0.elapsed());
    // The audit trail carries size and checksum of both transfers.
    let ends = env
        .server
        .shared
        .audit
        .query(&cjs_audit::Query {
            kind: Some("session.end".into()),
            ..Default::default()
        })
        .unwrap();
    let text = ends
        .iter()
        .map(|r| r.record.event.data.to_string())
        .collect::<String>();
    assert!(text.contains(&want), "sha256 audited: {text}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn recursive_copy_skips_symlinks() {
    let env = Env::start(mode_from_env()).await;
    env.put_grant(&env.grant("g1", &[Action::FileRead, Action::FileWrite]));
    let op = opener(&env).await;
    let tree = env.tmp().join("tree");
    std::fs::create_dir_all(tree.join("a/b")).unwrap();
    std::fs::write(tree.join("top.txt"), "top").unwrap();
    std::fs::write(tree.join("a/mid.txt"), "mid").unwrap();
    std::fs::write(tree.join("a/b/deep.txt"), "deep").unwrap();
    std::os::unix::fs::symlink("/etc/hosts", tree.join("a/link")).unwrap();
    let up = ops::upload_tree(&op, "dev1", &tree, "copy", false).await.unwrap();
    assert_eq!(up.files.len(), 3, "{up:?}");
    assert_eq!(up.skipped, vec!["a/link".to_string()]);
    assert_eq!(
        std::fs::read_to_string(env.project.join("copy/a/b/deep.txt")).unwrap(),
        "deep"
    );
    assert!(std::fs::symlink_metadata(env.project.join("copy/a/link")).is_err());
    // A symlink on the device side is not followed on the way back either.
    std::os::unix::fs::symlink("/etc/hosts", env.project.join("copy/a/devlink")).unwrap();
    let dst = env.tmp().join("back");
    let down = ops::download_tree(&op, "dev1", "copy", &dst, false)
        .await
        .unwrap();
    assert_eq!(down.files.len(), 3, "{down:?}");
    assert_eq!(down.skipped, vec!["a/devlink".to_string()]);
    assert_eq!(std::fs::read_to_string(dst.join("a/mid.txt")).unwrap(), "mid");
    assert!(!dst.join("a/devlink").exists());
}

fn curl(args: &[&str]) -> (i32, String) {
    let o = std::process::Command::new("curl")
        .args(["-sS", "--max-time", "30", "--noproxy", ""])
        .args(args)
        .env_remove("HTTP_PROXY")
        .env_remove("HTTPS_PROXY")
        .env_remove("http_proxy")
        .env_remove("https_proxy")
        .env_remove("ALL_PROXY")
        .env_remove("all_proxy")
        .output()
        .expect("curl is installed");
    (
        o.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&o.stdout).into_owned() + &String::from_utf8_lossy(&o.stderr),
    )
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn curl_through_cjs_proxy() {
    if std::process::Command::new("curl")
        .arg("--version")
        .output()
        .is_err()
    {
        eprintln!("curl not installed; skipping");
        return;
    }
    let env = Env::start(mode_from_env()).await;
    let web = http_server("hello-through-proxy").await;
    let mut g = env.grant("eg", &[Action::Egress]);
    g.project_roots = vec![];
    g.target = cjs_authz::model::Target::Server;
    g.egress = vec![NetRule::allow("127.0.0.1/32", &[&web.to_string()])];
    env.put_grant(&g);
    let op = opener(&env).await;
    let port = free_port();
    let listen = format!("127.0.0.1:{port}");
    let auth = proxy::Auth::generate();
    let pass = auth.pass.clone();
    tokio::spawn({
        let listen = listen.clone();
        async move {
            proxy::run(
                op,
                &listen,
                None,
                Some(auth),
                Some(std::env::temp_dir().join(format!("cjs-proxy-{port}.env"))),
            )
            .await
        }
    });
    for _ in 0..100 {
        if tokio::net::TcpStream::connect(&listen).await.is_ok() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let url = format!("http://127.0.0.1:{web}/x");
    let http = format!("http://cjs:{pass}@{listen}");
    let socks = format!("socks5h://cjs:{pass}@{listen}");
    let out = tokio::task::spawn_blocking({
        let (url, http, socks, listen) = (url.clone(), http.clone(), socks.clone(), listen.clone());
        move || {
            vec![
                // Plain HTTP forward proxying.
                curl(&["-x", &http, &url]),
                // CONNECT tunnel.
                curl(&["-p", "-x", &http, &url]),
                // SOCKS5 with username/password.
                curl(&["-x", &socks, &url]),
                // No credentials: refused.
                curl(&[
                    "-x",
                    &format!("http://{listen}"),
                    "-o",
                    "/dev/null",
                    "-w",
                    "%{http_code}",
                    &url,
                ]),
                curl(&["-x", &format!("socks5h://{listen}"), &url]),
                // A destination outside the egress rules: refused by the server.
                curl(&[
                    "-x",
                    &http,
                    "-o",
                    "/dev/null",
                    "-w",
                    "%{http_code}",
                    "http://127.0.0.1:9/",
                ]),
            ]
        }
    })
    .await
    .unwrap();
    for (i, (code, body)) in out.iter().take(3).enumerate() {
        assert_eq!(*code, 0, "case {i}: {body}");
        assert!(body.contains("hello-through-proxy"), "case {i}: {body}");
    }
    assert!(out[3].1.contains("407"), "no credentials: {:?}", out[3]);
    assert_ne!(out[4].0, 0, "socks without credentials: {:?}", out[4]);
    assert!(out[5].1.contains("403"), "egress rule: {:?}", out[5]);
    let kinds = env.audit_kinds();
    assert!(
        kinds
            .iter()
            .any(|(k, _)| k == "egress.blocked" || k == "authz.decision"),
        "{kinds:?}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn every_stream_kind_is_audited() {
    let env = Env::start(mode_from_env()).await;
    let web = http_server("ok").await;
    let rport = free_port();
    let mut g = env.grant(
        "g1",
        &[
            Action::Shell,
            Action::Exec,
            Action::FileRead,
            Action::FileWrite,
            Action::ForwardLocal,
            Action::ForwardRemote,
        ],
    );
    g.forward_targets = vec![NetRule::allow("127.0.0.1", &[&web.to_string()])];
    g.remote_ports = vec![rport.to_string().parse().unwrap()];
    env.put_grant(&g);
    let mut eg = env.grant("eg", &[Action::Egress]);
    eg.project_roots = vec![];
    eg.target = cjs_authz::model::Target::Server;
    eg.egress = vec![NetRule::allow("127.0.0.1/32", &[&web.to_string()])];
    env.put_grant(&eg);
    let op = opener(&env).await;
    let a = env.agent().await;

    let (mut s, _) = a.open(pty_req("dev1")).await.unwrap();
    write_msg(&mut s, &PtyIn::Input(b"echo p-$((1+1))\nexit\n".to_vec()))
        .await
        .unwrap();
    pty_expect(&mut s, "p-2", 30).await.unwrap();
    run_exec(&a, exec_req("dev1", "true")).await.unwrap();
    let f = env.tmp().join("f.txt");
    std::fs::write(&f, "x").unwrap();
    ops::upload(&op, "dev1", &f, "f.txt", false, false).await.unwrap();
    ops::download(&op, "dev1", "f.txt", &env.tmp().join("g.txt"), false)
        .await
        .unwrap();
    ops::list(&op, "dev1", ".").await.unwrap();
    let (mut l, _) = op
        .open(&OpenRequest::ForwardL {
            device: "dev1".into(),
            host: "127.0.0.1".into(),
            port: web,
        })
        .await
        .unwrap();
    l.write_all(b"GET / HTTP/1.0\r\n\r\n").await.unwrap();
    let mut sink = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(10), l.read_to_end(&mut sink)).await;
    let _ = l.shutdown().await;
    drop(l);
    let (ctl, _o, _g) = op
        .forward_remote(
            &OpenRequest::ForwardR {
                device: "dev1".into(),
                bind_host: "127.0.0.1".into(),
                bind_port: rport,
            },
            "127.0.0.1",
            web,
        )
        .await
        .unwrap();
    let mut c = tokio::net::TcpStream::connect(("127.0.0.1", rport))
        .await
        .unwrap();
    c.write_all(b"GET / HTTP/1.0\r\n\r\n").await.unwrap();
    let _ = tokio::time::timeout(Duration::from_secs(10), c.read_to_end(&mut sink)).await;
    drop(c);
    drop(ctl);
    let (mut e, _) = op
        .open(&OpenRequest::Egress {
            host: "127.0.0.1".into(),
            port: web,
            via: None,
        })
        .await
        .unwrap();
    e.write_all(b"GET / HTTP/1.0\r\n\r\n").await.unwrap();
    let _ = tokio::time::timeout(Duration::from_secs(10), e.read_to_end(&mut sink)).await;
    let _ = e.shutdown().await;
    drop(e);

    let want: BTreeSet<&str> = [
        "pty",
        "exec",
        "file_put",
        "file_get",
        "file_list",
        "forward_local",
        "forward_remote",
        "egress",
    ]
    .into();
    let mut started = BTreeSet::new();
    let mut ended = BTreeSet::new();
    for _ in 0..100 {
        let recs = env
            .server
            .shared
            .audit
            .query(&cjs_audit::Query {
                limit: Some(10_000),
                ..Default::default()
            })
            .unwrap();
        let mut sessions = std::collections::HashMap::new();
        for r in &recs {
            let ev = &r.record.event;
            if ev.kind == "session.start" {
                if let (Some(s), Some(k)) = (ev.session.clone(), ev.data["kind"].as_str()) {
                    sessions.insert(s, k.to_string());
                    started.insert(k.to_string());
                }
            }
        }
        for r in &recs {
            let ev = &r.record.event;
            if ev.kind == "session.end" {
                if let Some(k) = ev.session.as_ref().and_then(|s| sessions.get(s)) {
                    ended.insert(k.clone());
                }
            }
        }
        if want.iter().all(|k| ended.contains(*k)) {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    for k in &want {
        assert!(started.contains(*k), "no session.start for {k}: {started:?}");
        assert!(ended.contains(*k), "no session.end for {k}: {ended:?}");
    }
    assert!(env.audit_kinds().iter().any(|(k, _)| k == "forward.conn"));
    assert!(env.server.shared.audit.verify(None).unwrap().ok);
}
