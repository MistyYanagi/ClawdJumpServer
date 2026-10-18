//! Sandbox guarantees seen end to end: the device's own state is not
//! readable from a sandboxed command, and nothing a session starts outlives
//! its revocation.
#![cfg(target_os = "linux")]
use std::time::Duration;

use cjs_mux::write_msg;
use cjs_proto::{Action, ExecIn, ExecOut, OpenRequest, PtyIn};
use cjs_tests::*;

fn sandbox_ok() -> bool {
    match cjs_sandbox::probe() {
        Ok(_) => true,
        Err(e) => {
            eprintln!("skipping: {e}");
            false
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn device_state_is_hidden_from_exec_and_pty() {
    if !sandbox_ok() {
        return;
    }
    let env = Env::start(mode_from_env()).await;
    env.put_grant(&env.grant("g1", &[Action::Exec, Action::Shell]));
    let a = env.agent().await;
    let dir = env.device_dir.display().to_string();
    let (out, _, _) = run_exec(
        &a,
        exec_req(
            &env.device_id,
            &format!("cat {dir}/identity.key >/dev/null 2>&1 && echo KEY_READ; ls {dir} >/dev/null 2>&1 && echo DIR_LISTED; echo $((6*7))"),
        ),
    )
    .await
    .unwrap();
    assert!(out.contains("42"), "{out}");
    assert!(!out.contains("KEY_READ") && !out.contains("DIR_LISTED"), "{out}");
    let (mut s, _) = a.open(pty_req(&env.device_id)).await.unwrap();
    let cmd = format!("cat {dir}/identity.key >/dev/null 2>&1 || echo hidden-$((40+2))\nexit\n");
    write_msg(&mut s, &PtyIn::Input(cmd.into_bytes())).await.unwrap();
    pty_expect(&mut s, "hidden-42", 30).await.unwrap();
}

fn alive(pidfile: &std::path::Path) -> bool {
    let Ok(pid) = std::fs::read_to_string(pidfile) else {
        return false;
    };
    std::fs::read_to_string(format!("/proc/{}/stat", pid.trim()))
        .map(|s| !s.contains(") Z "))
        .unwrap_or(false)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn revoked_exec_leaves_no_background_process() {
    if !sandbox_ok() {
        return;
    }
    let env = Env::start(mode_from_env()).await;
    env.put_grant(&env.grant("g1", &[Action::Exec]));
    let a = env.agent().await;
    let pf = env.project.join("bg.pid");
    let marker = env.project.join("survived");
    let script = format!(
        "(setsid sh -c 'echo $$ > {pf}; sleep 3; echo alive > {m}' </dev/null >/dev/null 2>&1 &); sleep 300",
        pf = pf.display(),
        m = marker.display()
    );
    let (mut s, _) = a
        .open(OpenRequest::Exec {
            device: env.device_id.clone(),
            argv: vec!["/bin/sh".into(), "-c".into(), script],
            cwd: None,
            env: vec![],
            timeout_secs: None,
        })
        .await
        .unwrap();
    write_msg(&mut s, &ExecIn::StdinEof).await.unwrap();
    for _ in 0..100 {
        if alive(&pf) {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(alive(&pf), "background job started");
    env.server.shared.db.delete_grant("g1").unwrap();
    env.server.enforce();
    let mut ended = false;
    while let Ok(Ok(Some(m))) =
        tokio::time::timeout(Duration::from_secs(10), cjs_mux::read_msg::<_, ExecOut>(&mut s)).await
    {
        if matches!(m, ExecOut::Exit { .. }) {
            ended = true;
            break;
        }
    }
    assert!(ended, "agent saw the session end");
    for _ in 0..100 {
        if !alive(&pf) {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(!alive(&pf), "background job survived revocation");
    tokio::time::sleep(Duration::from_secs(4)).await;
    assert!(!marker.exists(), "background job kept running after revocation");
}
