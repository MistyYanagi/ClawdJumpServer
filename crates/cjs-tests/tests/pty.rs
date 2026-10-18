//! End-to-end tests of the terminal relay.
#![cfg(unix)]
use cjs_mux::write_msg;
use cjs_proto::{Action, ErrorCode, PtyIn};
use cjs_tests::*;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn pty_roundtrip_is_recorded_and_audited() {
    let env = Env::start(mode_from_env()).await;
    env.put_grant(&env.grant("g1", &[Action::Shell]));
    let a = env.agent().await;
    let (mut s, session) = a.open(pty_req("dev1")).await.unwrap();
    write_msg(&mut s, &PtyIn::Input(b"echo hi-$((40+2))\n".to_vec()))
        .await
        .unwrap();
    pty_expect(&mut s, "hi-42", 20).await.unwrap();
    write_msg(&mut s, &PtyIn::Resize { cols: 100, rows: 30 })
        .await
        .unwrap();
    write_msg(&mut s, &PtyIn::Input(b"pwd; exit 3\n".to_vec()))
        .await
        .unwrap();
    let out = pty_expect(&mut s, &env.project.to_string_lossy(), 20)
        .await
        .unwrap();
    assert!(!out.is_empty());
    // Wait for the session to end and the audit trail to be complete.
    let mut ok = false;
    for _ in 0..100 {
        if env.audit_kinds().iter().any(|(k, _)| k == "session.end") {
            ok = true;
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    assert!(ok, "session.end not audited: {:?}", env.audit_kinds());
    let cast = std::fs::read_to_string(
        env.server
            .shared
            .cfg
            .recordings_dir
            .join(format!("{session}.cast")),
    )
    .unwrap();
    assert!(cast.contains("hi-42"), "recording has output");
    assert!(cast.contains("\"i\""), "recording has input");
    assert!(cast.contains("100x30"), "recording has resize");
    let end = env
        .server
        .shared
        .audit
        .query(&cjs_audit::Query {
            kind: Some("session.end".into()),
            ..Default::default()
        })
        .unwrap();
    let data = &end[0].record.event.data;
    assert_eq!(data["exit"], 3, "{data}");
    assert_eq!(data["recording"]["sha256"].as_str().unwrap().len(), 64);
    assert!(env.server.shared.audit.verify(None).unwrap().ok);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn pty_denied_without_grant() {
    let env = Env::start(mode_from_env()).await;
    env.put_grant(&env.grant("g1", &[Action::Exec]));
    let a = env.agent().await;
    let e = a.open(pty_req("dev1")).await.unwrap_err();
    assert_eq!(e.code, ErrorCode::Forbidden);
    assert!(env
        .audit_kinds()
        .contains(&("authz.decision".into(), "denied".into())));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn pty_revoked_mid_session() {
    let env = Env::start(mode_from_env()).await;
    env.put_grant(&env.grant("g1", &[Action::Shell]));
    let a = env.agent().await;
    let (mut s, _) = a.open(pty_req("dev1")).await.unwrap();
    write_msg(&mut s, &PtyIn::Input(b"echo ready\n".to_vec()))
        .await
        .unwrap();
    pty_expect(&mut s, "ready", 20).await.unwrap();
    env.server.shared.db.delete_grant("g1").unwrap();
    env.server.enforce();
    let e = pty_expect(&mut s, "never-printed", 10).await.unwrap_err();
    assert!(e.contains("session terminated"), "{e}");
    assert!(env.audit_kinds().iter().any(|(k, _)| k == "session.revoked"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn pty_shell_is_sandboxed() {
    if cjs_sandbox::probe().is_err() {
        eprintln!("skipping: no sandbox on this kernel");
        return;
    }
    let env = Env::start(mode_from_env()).await;
    env.put_grant(&env.grant("g1", &[Action::Shell]));
    let a = env.agent().await;
    let (mut s, _) = a.open(pty_req("dev1")).await.unwrap();
    let outside = env.tmp().join("outside.txt");
    let cmd = format!(
        "echo x > {o} || echo BLOCKED; echo y > {p}/inside.txt && echo WROTE-$((40+2))\n",
        o = outside.display(),
        p = env.project.display()
    );
    write_msg(&mut s, &PtyIn::Input(cmd.into_bytes())).await.unwrap();
    // The marker is computed by the shell, so the echoed input cannot match.
    pty_expect(&mut s, "WROTE-42", 20).await.unwrap();
    assert!(!outside.exists(), "write outside the project must be blocked");
    assert!(env.project.join("inside.txt").exists());
}

/// `GET /sessions/{id}/live`: secadmin/auditor can watch a live terminal
/// session read-only; other roles cannot; the watch is audited once per
/// watcher.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn live_watch_is_role_checked_and_audited() {
    use cjs_authz::Role;
    let env = Env::start(mode_from_env()).await;
    env.put_grant(&env.grant("g1", &[Action::Shell]));
    env.add_user("sys", vec![Role::Sysadmin]);
    env.add_user("sec", vec![Role::Secadmin]);
    env.add_user("aud", vec![Role::Auditor]);
    env.add_user("plain", vec![]);
    let a = env.agent().await;
    let (mut s, session) = a.open(pty_req("dev1")).await.unwrap();
    write_msg(&mut s, &PtyIn::Input(b"echo watch-$((6*7))\n".to_vec()))
        .await
        .unwrap();
    pty_expect(&mut s, "watch-42", 20).await.unwrap();

    let path = format!("/sessions/{session}/live?wait=0");
    for name in ["sys", "plain"] {
        let (st, _) = env.web(name).await.call("GET", &path, None).await;
        assert_eq!(st, 403, "{name} must not watch");
    }
    let aud = env.web("aud").await;
    let (st, _) = aud.call("GET", "/sessions/bad-id/live", None).await;
    assert_eq!(st, 400);
    let (st, _) = aud.call("GET", "/sessions/nosuchsession/live?wait=0", None).await;
    assert_eq!(st, 404);

    let (st, v) = aud.call("GET", &path, None).await;
    assert_eq!(st, 200, "{v}");
    assert_eq!(v["live"], true);
    assert_eq!(v["header"]["version"], 2, "{v}");
    let events = v["events"].as_array().unwrap();
    let text: String = events
        .iter()
        .filter(|e| e[1] == "o")
        .map(|e| e[2].as_str().unwrap().to_string())
        .collect();
    assert!(text.contains("watch-42"), "{text}");
    assert!(events.iter().all(|e| e[1] != "i"), "keystrokes are not exposed");
    let off = v["offset"].as_u64().unwrap();
    let far = format!("/sessions/{session}/live?after={}", off + 1_000_000);
    let (st, _) = aud.call("GET", &far, None).await;
    assert_eq!(st, 400, "offset past the end");

    // Long-poll: output that arrives while the request waits is returned.
    let wait_path = format!("/sessions/{session}/live?after={off}&wait=10");
    let poll = aud.call("GET", &wait_path, None);
    let send = async {
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
        write_msg(&mut s, &PtyIn::Input(b"echo later-$((50+5))\n".to_vec()))
            .await
            .unwrap();
    };
    let ((st, v), ()) = tokio::join!(poll, send);
    assert_eq!(st, 200);
    assert!(v["header"].is_null());
    let mut off = v["offset"].as_u64().unwrap();
    let mut seen = v.to_string();
    for _ in 0..20 {
        if seen.contains("later-55") {
            break;
        }
        let p = format!("/sessions/{session}/live?after={off}&wait=2");
        let (_, v) = aud.call("GET", &p, None).await;
        off = v["offset"].as_u64().unwrap();
        seen.push_str(&v.to_string());
    }
    assert!(seen.contains("later-55"), "{seen}");

    // A secadmin may watch too; after the session ends the watch says so.
    let sec = env.web("sec").await;
    let (st, _) = sec.call("GET", &path, None).await;
    assert_eq!(st, 200);
    write_msg(&mut s, &PtyIn::Input(b"exit\n".to_vec())).await.unwrap();
    let mut ended = false;
    for _ in 0..100 {
        let p = format!("/sessions/{session}/live?after={off}&wait=1");
        let (_, v) = sec.call("GET", &p, None).await;
        if v["live"] == false {
            ended = true;
            break;
        }
        off = v["offset"].as_u64().unwrap();
    }
    assert!(ended, "the watch reports the end of the session");

    // Audited once per watcher, not once per poll.
    let watches = env
        .server
        .shared
        .audit
        .query(&cjs_audit::Query {
            kind: Some("session.watch".into()),
            ..Default::default()
        })
        .unwrap();
    assert_eq!(watches.len(), 2, "one per watcher");
    assert!(watches
        .iter()
        .all(|w| w.record.event.session.as_deref() == Some(session.as_str())));
    assert!(env.server.shared.audit.verify(None).unwrap().ok);
}
