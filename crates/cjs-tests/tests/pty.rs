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
        "echo x > {o} || echo BLOCKED; echo y > {p}/inside.txt && echo WROTE\n",
        o = outside.display(),
        p = env.project.display()
    );
    write_msg(&mut s, &PtyIn::Input(cmd.into_bytes())).await.unwrap();
    pty_expect(&mut s, "WROTE", 20).await.unwrap();
    assert!(!outside.exists(), "write outside the project must be blocked");
    assert!(env.project.join("inside.txt").exists());
}
