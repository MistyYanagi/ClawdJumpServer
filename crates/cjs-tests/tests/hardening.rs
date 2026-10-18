//! Regression tests for resource limits and admission races found in the
//! internal security review.
#![cfg(unix)]
use std::time::Duration;

use cjs_mux::write_msg;
use cjs_proto::Action;
use cjs_tests::*;

async fn session_end(env: &Env, session: &str) -> cjs_audit::StoredRecord {
    for _ in 0..100 {
        let r = env
            .server
            .shared
            .audit
            .query(&cjs_audit::Query {
                kind: Some("session.end".into()),
                session: Some(session.into()),
                ..Default::default()
            })
            .unwrap();
        if let Some(r) = r.into_iter().next() {
            return r;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("no session.end for {session}");
}

/// T3: concurrent opens cannot race past `max_sessions`: decision and
/// slot reservation are atomic.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn max_sessions_holds_under_concurrent_opens() {
    let env = Env::start(mode_from_env()).await;
    let mut g = env.grant("g1", &[Action::Exec]);
    g.max_sessions = Some(1);
    env.put_grant(&g);
    let a = std::sync::Arc::new(env.agent().await);
    let mut hs = vec![];
    for _ in 0..8 {
        let a = a.clone();
        hs.push(tokio::spawn(async move {
            a.open(exec_req("dev1", "sleep 2")).await.map(|(s, _)| s)
        }));
    }
    let mut ok = vec![];
    for h in hs {
        match h.await.unwrap() {
            Ok(s) => ok.push(s),
            Err(e) => assert_eq!(e.code, cjs_proto::ErrorCode::LimitExceeded, "{e}"),
        }
    }
    assert_eq!(ok.len(), 1, "max_sessions=1 admitted {} sessions", ok.len());
    // The slot is released when the session ends.
    drop(ok);
    let mut admitted = false;
    for _ in 0..100 {
        if run_exec(&a, exec_req("dev1", "echo again")).await.is_ok() {
            admitted = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(admitted, "slot never released");
}

/// T4: a terminal session that exceeds the recording size limit is
/// terminated and the reason is audited; the recording stays bounded and
/// its audited hash matches the file.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn recording_size_limit_terminates_session() {
    let limit = 64 * 1024;
    let env = Env::start_with(mode_from_env(), |c| c.max_recording_bytes = limit).await;
    env.put_grant(&env.grant("g1", &[Action::Shell]));
    let a = env.agent().await;
    let (mut s, session) = a.open(pty_req("dev1")).await.unwrap();
    write_msg(
        &mut s,
        &cjs_proto::PtyIn::Input(b"i=0; while [ $i -lt 20000 ]; do echo 0123456789abcdef0123456789abcdef; i=$((i+1)); done\n".to_vec()),
    )
    .await
    .unwrap();
    let out = pty_expect(&mut s, "never-printed", 30).await.unwrap_err();
    assert!(out.contains("recording size limit"), "{out}");
    let end = session_end(&env, &session).await;
    let d = &end.record.event.data;
    assert_eq!(d["error"]["code"], "limit_exceeded", "{d}");
    let rec = &d["recording"];
    let size = rec["size"].as_u64().unwrap();
    assert!(size <= limit, "{size}");
    let file = env.server.shared.cfg.recordings_dir.join(rec["file"].as_str().unwrap());
    let data = std::fs::read(file).unwrap();
    use sha2::Digest;
    assert_eq!(data.len() as u64, size);
    assert_eq!(hex::encode(sha2::Sha256::digest(&data)), rec["sha256"].as_str().unwrap());
}
