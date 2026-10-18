//! 4A conformance suite (Account, Authentication, Authorization, Audit).
//!
//! Each test is one requirement from docs/4a.md; the case numbers match.
#![cfg(unix)]
use std::time::Duration;

use cjs_authz::capability::{self, CAP_TTL_SECS, CAP_VERSION};
use cjs_authz::Role;
use cjs_mux::{expect_msg, write_msg};
use cjs_proto::{Action, Capability, DeviceOpen, ErrorCode, OpenReply, OpenRequest, Role as ClientRole};
use cjs_tests::*;
use cjs_transport::profile::enroll;
use serde_json::json;

fn mode() -> cjs_transport::TransportMode {
    mode_from_env()
}

/// A1 — Accounts: enrollment tokens are one-time, expire, are bound to a
/// kind, and unknown keys cannot connect.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn c01_enrollment_tokens_are_one_time_and_scoped() {
    let env = Env::start(mode()).await;
    let srv = &env.server;
    let (_, tok) = srv
        .create_enroll_token(ClientRole::Device, "dev2", None, &env.admin, 600)
        .unwrap();
    enroll(
        &env.tmp().join("d2"),
        ClientRole::Device,
        &env.url,
        &tok,
        env.mode,
        None,
        "t",
    )
    .await
    .unwrap();
    // Reuse by another machine fails.
    let e = enroll(
        &env.tmp().join("d3"),
        ClientRole::Device,
        &env.url,
        &tok,
        env.mode,
        None,
        "t",
    )
    .await
    .unwrap_err();
    assert!(
        matches!(e.code, ErrorCode::Replay | ErrorCode::Unauthenticated),
        "{e}"
    );
    // A device token cannot enroll an agent.
    let (_, tok) = srv
        .create_enroll_token(ClientRole::Device, "dev4", None, &env.admin, 600)
        .unwrap();
    let e = enroll(
        &env.tmp().join("a2"),
        ClientRole::Agent,
        &env.url,
        &tok,
        env.mode,
        None,
        "t",
    )
    .await
    .unwrap_err();
    assert_eq!(e.code, ErrorCode::Unauthenticated);
    // Expired tokens fail.
    let (row, tok) = srv
        .create_enroll_token(ClientRole::Device, "dev5", None, &env.admin, 600)
        .unwrap();
    srv.shared
        .db
        .with(|c| c.execute("UPDATE enroll_tokens SET expires_at = 1 WHERE id = ?1", [&row.id]))
        .unwrap();
    let e = enroll(
        &env.tmp().join("d5"),
        ClientRole::Device,
        &env.url,
        &tok,
        env.mode,
        None,
        "t",
    )
    .await
    .unwrap_err();
    assert_eq!(e.code, ErrorCode::Expired);
    // A random key without a token is rejected, and the attempt is audited.
    let dir = env.tmp().join("stranger");
    std::fs::create_dir_all(&dir).unwrap();
    let mut p = cjs_transport::profile::Profile::load(&env.agent_dir).unwrap();
    p.id.clear();
    p.save(&dir).unwrap();
    let key = cjs_transport::StaticKeypair::generate();
    let cfg = p.client_config(key).unwrap();
    let e = cjs_transport::connect(&cfg, cjs_transport::new_hello(ClientRole::Agent, None, "t"))
        .await
        .unwrap_err();
    assert_eq!(e.code, ErrorCode::Unauthenticated);
    assert!(env
        .audit_kinds()
        .contains(&("gateway.reject".into(), "denied".into())));
    // Only the secret's hash is stored.
    let stored: Vec<String> = srv
        .shared
        .db
        .with(|c| {
            let mut st = c.prepare("SELECT secret_hash FROM enroll_tokens")?;
            let rows = st.query_map([], |r| r.get(0))?;
            rows.collect()
        })
        .unwrap();
    let secret = cjs_proto::EnrollToken::parse(&tok).unwrap().secret;
    assert!(stored.iter().all(|h| h.len() == 64 && *h != secret));
}

/// A2 — Accounts: disabling an agent, its responsible user or a device cuts
/// live connections at once and blocks reconnection.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn c02_disable_cuts_live_connections() {
    let env = Env::start(mode()).await;
    let admin = env.web("admin").await;
    // Owner disabled -> agent cut.
    let a = env.agent().await;
    let (st, _) = admin
        .call(
            "PATCH",
            &format!("/users/{}", env.owner),
            Some(json!({"status": "disabled"})),
        )
        .await;
    assert_eq!(st, 200);
    let e = tokio::time::timeout(Duration::from_secs(10), a.handle.closed())
        .await
        .expect("agent connection must be cut");
    assert_eq!(e.code, ErrorCode::Disabled, "{e}");
    let p = cjs_transport::profile::Profile::load(&env.agent_dir).unwrap();
    let cfg = p
        .client_config(cjs_transport::profile::Profile::key(&env.agent_dir).unwrap())
        .unwrap();
    let e = cjs_transport::connect(&cfg, cjs_transport::new_hello(ClientRole::Agent, None, "t"))
        .await
        .unwrap_err();
    assert_eq!(e.code, ErrorCode::Disabled);
    admin
        .call(
            "PATCH",
            &format!("/users/{}", env.owner),
            Some(json!({"status": "active"})),
        )
        .await;
    // Agent disabled by its owner -> cut.
    let a = env.agent().await;
    let alice = env.web("alice").await;
    let (st, _) = alice
        .call(
            "PATCH",
            &format!("/agents/{}", env.agent_id),
            Some(json!({"status": "disabled"})),
        )
        .await;
    assert_eq!(st, 200);
    let e = tokio::time::timeout(Duration::from_secs(10), a.handle.closed())
        .await
        .unwrap();
    assert_eq!(e.code, ErrorCode::Disabled);
    // The owner cannot re-enable it (only a sysadmin can).
    let (st, _) = alice
        .call(
            "PATCH",
            &format!("/agents/{}", env.agent_id),
            Some(json!({"status": "active"})),
        )
        .await;
    assert_eq!(st, 403);
    // Device disabled -> goes offline.
    let (st, _) = admin
        .call(
            "PATCH",
            &format!("/devices/{}", env.device_id),
            Some(json!({"status": "disabled"})),
        )
        .await;
    assert_eq!(st, 200);
    env.wait_device_online(false).await;
    assert!(env.audit_kinds().iter().any(|(k, _)| k == "gateway.kick"));
}

/// A3 — Authentication: password and TOTP are both required, codes cannot
/// be reused, and repeated failures lock the account.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn c03_login_needs_password_and_totp_with_lockout() {
    let env = Env::start(mode()).await;
    env.add_user("bob", vec![]);
    let (_, pw, secret) = env.cred("bob");
    let http = reqwest::Client::new();
    let login = |pw: String, code: String| {
        let http = http.clone();
        let url = format!("{}api/v1/login", env.url);
        async move {
            let r = http
                .post(url)
                .json(&json!({"name": "bob", "password": pw, "totp": code}))
                .send()
                .await
                .unwrap();
            let st = r.status().as_u16();
            (st, r.json::<serde_json::Value>().await.unwrap_or_default())
        }
    };
    let step = cjs_server::db::now() / 30;
    let code = cjs_server::accounts::code_for_step(&secret, step);
    assert_eq!(login(pw.clone(), "000000".into()).await.0, 401, "wrong code");
    assert_eq!(
        login("wrong-password-x".into(), code.clone()).await.0,
        401,
        "wrong password"
    );
    assert_eq!(login(pw.clone(), code.clone()).await.0, 200, "correct");
    assert_eq!(login(pw.clone(), code.clone()).await.0, 401, "code reuse");
    // Lockout after repeated failures, even with correct credentials.
    for _ in 0..5 {
        login("wrong-password-x".into(), "123456".into()).await;
    }
    let next = cjs_server::accounts::code_for_step(&secret, step + 1);
    let (st, v) = login(pw, next).await;
    assert_eq!(st, 429, "{v}");
    assert_eq!(v["error"]["code"], "limit_exceeded");
    // Unknown users get the same answer as wrong passwords.
    let r = http
        .post(format!("{}api/v1/login", env.url))
        .json(&json!({"name": "nobody", "password": "x", "totp": "1"}))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status().as_u16(), 401);
    let denied = env
        .audit_kinds()
        .iter()
        .filter(|(k, o)| k == "auth.login" && o == "denied")
        .count();
    assert!(denied >= 7, "every failure is audited ({denied})");
}

/// A4 — Authentication: web sessions need the CSRF token for changes,
/// refuse cross-origin requests, and end on logout.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn c04_web_session_csrf_origin_logout() {
    let env = Env::start(mode()).await;
    let admin = env.web("admin").await;
    let url = format!("{}api/v1/groups", admin.base);
    let body = json!({"name": "ops", "kind": "agent"});
    let r = admin
        .http
        .post(&url)
        .header("cookie", format!("cjs_session={}", admin.cookie))
        .json(&body)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status().as_u16(), 403, "missing CSRF token");
    let r = admin
        .http
        .post(&url)
        .header("cookie", format!("cjs_session={}", admin.cookie))
        .header("x-csrf-token", &admin.csrf)
        .header("origin", "https://evil.example")
        .json(&body)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status().as_u16(), 403, "cross-origin");
    assert_eq!(admin.call("POST", "/groups", Some(body)).await.0, 200);
    // Headers.
    let r = admin.http.get(admin.base.to_string()).send().await.unwrap();
    let csp = r.headers()["content-security-policy"]
        .to_str()
        .unwrap()
        .to_string();
    assert!(csp.contains("script-src 'self'") && csp.contains("frame-ancestors 'none'"));
    assert_eq!(r.headers()["x-frame-options"], "DENY");
    // Logout invalidates the cookie.
    assert_eq!(admin.call("POST", "/logout", Some(json!({}))).await.0, 200);
    assert_eq!(admin.call("GET", "/me", None).await.0, 401);
    // Idle sessions expire.
    let admin = env.web("admin").await;
    env.server
        .shared
        .db
        .with(|c| c.execute("UPDATE web_sessions SET last_seen = last_seen - 100000", []))
        .unwrap();
    assert_eq!(admin.call("GET", "/me", None).await.0, 401);
}

/// A5 — Authorization: default deny, per-action least privilege, inventory
/// not revealed, time-bounded grants and session limits.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn c05_default_deny_and_least_privilege() {
    let env = Env::start(mode()).await;
    let a = env.agent().await;
    for req in [pty_req("dev1"), exec_req("dev1", "true")] {
        assert_eq!(a.open(req).await.unwrap_err().code, ErrorCode::Forbidden);
    }
    // Unknown devices look exactly like forbidden ones.
    let e = a.open(exec_req("no-such-device", "true")).await.unwrap_err();
    assert_eq!(e.code, ErrorCode::Forbidden);
    env.put_grant(&env.grant("g1", &[Action::Exec]));
    assert_eq!(run_exec(&a, exec_req("dev1", "echo ok")).await.unwrap().0, "ok\n");
    assert_eq!(
        a.open(pty_req("dev1")).await.unwrap_err().code,
        ErrorCode::Forbidden
    );
    // Expired grant.
    let mut g = env.grant("g1", &[Action::Exec]);
    g.expires_at = Some(1);
    env.put_grant(&g);
    assert_eq!(
        a.open(exec_req("dev1", "true")).await.unwrap_err().code,
        ErrorCode::Expired
    );
    // Concurrent session limit.
    let mut g = env.grant("g1", &[Action::Shell]);
    g.max_sessions = Some(1);
    env.put_grant(&g);
    let (_s1, _) = a.open(pty_req("dev1")).await.unwrap();
    assert_eq!(
        a.open(pty_req("dev1")).await.unwrap_err().code,
        ErrorCode::LimitExceeded
    );
}

/// A6 — Authorization: separation of duties between sysadmin, secadmin and
/// auditor; nobody can change their own roles.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn c06_separation_of_duties() {
    let env = Env::start(mode()).await;
    env.add_user("sys", vec![Role::Sysadmin]);
    env.add_user("sec", vec![Role::Secadmin]);
    env.add_user("aud", vec![Role::Auditor]);
    let sys = env.web("sys").await;
    let sec = env.web("sec").await;
    let aud = env.web("aud").await;
    let grant = serde_json::to_value(env.grant("g1", &[Action::Exec])).unwrap();
    // Grants: secadmin only.
    assert_eq!(sys.call("PUT", "/grants/g1", Some(grant.clone())).await.0, 403);
    assert_eq!(aud.call("PUT", "/grants/g1", Some(grant.clone())).await.0, 403);
    assert_eq!(sec.call("PUT", "/grants/g1", Some(grant)).await.0, 200);
    // Accounts: sysadmin only.
    let new = json!({"name": "eve", "roles": []});
    assert_eq!(sec.call("POST", "/users", Some(new.clone())).await.0, 403);
    assert_eq!(aud.call("POST", "/users", Some(new.clone())).await.0, 403);
    assert_eq!(sys.call("POST", "/users", Some(new)).await.0, 200);
    // Audit: auditor only (read-only).
    assert_eq!(sys.call("GET", "/audit", None).await.0, 403);
    assert_eq!(sec.call("GET", "/audit", None).await.0, 403);
    assert_eq!(aud.call("GET", "/audit", None).await.0, 200);
    assert_eq!(aud.call("GET", "/audit/verify", None).await.0, 200);
    // secadmin + auditor on one account is refused.
    let (st, _) = sys
        .call(
            "POST",
            "/users",
            Some(json!({"name": "both", "roles": ["secadmin", "auditor"]})),
        )
        .await;
    assert_eq!(st, 400);
    let (sec_id, _, _) = env.cred("sec");
    let (st, _) = sys
        .call(
            "PATCH",
            &format!("/users/{sec_id}"),
            Some(json!({"roles": ["secadmin", "auditor"]})),
        )
        .await;
    assert_eq!(st, 400);
    // No self-escalation.
    let (sys_id, _, _) = env.cred("sys");
    let (st, _) = sys
        .call(
            "PATCH",
            &format!("/users/{sys_id}"),
            Some(json!({"roles": ["sysadmin", "secadmin"]})),
        )
        .await;
    assert_eq!(st, 403);
    // Kill/kick are secadmin actions.
    assert_eq!(
        sys.call("POST", "/live/sessions/s_x/kill", Some(json!({})))
            .await
            .0,
        403
    );
}

/// A7 — Authorization: full access needs a second secadmin (not the
/// requester, not the beneficiary's owner), is time-bounded, and its
/// revocation cuts live sessions.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn c07_full_access_two_person_rule() {
    let env = Env::start(mode()).await;
    env.add_user("sec2", vec![Role::Secadmin]);
    env.put_grant(&env.grant("g1", &[Action::Exec, Action::FileRead]));
    let alice = env.web("alice").await;
    let admin = env.web("admin").await;
    let sec2 = env.web("sec2").await;
    let (st, fa) = alice
        .call(
            "POST",
            "/full-access",
            Some(json!({"agent": "agent1", "device": "dev1", "reason": "debug kernel module", "duration_secs": 3600})),
        )
        .await;
    assert_eq!(st, 200, "{fa}");
    let id = fa["id"].as_str().unwrap().to_string();
    // The owner (requester) cannot approve, and plain users cannot either.
    assert_eq!(
        alice
            .call("POST", &format!("/full-access/{id}/approve"), Some(json!({})))
            .await
            .0,
        403
    );
    // A request by a secadmin cannot be approved by the same secadmin.
    let (_, fa2) = admin
        .call(
            "POST",
            "/full-access",
            Some(
                json!({"agent": "agent1", "device": "dev1", "reason": "second request", "duration_secs": 60}),
            ),
        )
        .await;
    let id2 = fa2["id"].as_str().unwrap();
    assert_eq!(
        admin
            .call("POST", &format!("/full-access/{id2}/approve"), Some(json!({})))
            .await
            .0,
        403
    );
    // Over-long windows are refused.
    let (st, _) = alice
        .call(
            "POST",
            "/full-access",
            Some(json!({"agent": "agent1", "device": "dev1", "reason": "forever please", "duration_secs": 999999})),
        )
        .await;
    assert_eq!(st, 400);
    // Without approval, paths outside the roots stay jailed.
    let a = env.agent().await;
    let outside = OpenRequest::FileGet {
        device: "dev1".into(),
        path: "/etc/hosts".into(),
        offset: 0,
    };
    assert_eq!(
        a.open(outside.clone()).await.unwrap_err().code,
        ErrorCode::Forbidden
    );
    assert_eq!(
        sec2.call("POST", &format!("/full-access/{id}/approve"), Some(json!({})))
            .await
            .0,
        200
    );
    let (s, _) = a.open(outside).await.unwrap();
    drop(s);
    let highlighted = env
        .server
        .shared
        .audit
        .query(&cjs_audit::Query {
            kind: Some("session.start".into()),
            highlight: Some(true),
            ..Default::default()
        })
        .unwrap();
    assert!(
        !highlighted.is_empty(),
        "full-access use is highlighted in the audit log"
    );
    // Revocation cuts a running session.
    let (mut s, _) = a.open(exec_req("dev1", "sleep 30")).await.unwrap();
    assert_eq!(
        sec2.call("POST", &format!("/full-access/{id}/revoke"), Some(json!({})))
            .await
            .0,
        200
    );
    let mut terminated = false;
    while let Ok(Ok(Some(m))) = tokio::time::timeout(
        Duration::from_secs(10),
        cjs_mux::read_msg::<_, cjs_proto::ExecOut>(&mut s),
    )
    .await
    {
        if let cjs_proto::ExecOut::Exit { signal, .. } = m {
            terminated = signal.as_deref() == Some("terminated");
            break;
        }
    }
    assert!(
        terminated,
        "session started under full access must end when it is revoked"
    );
}

/// A8 — Authorization: the device verifies every capability itself, so a
/// bypassed or compromised relay cannot forge, widen, redirect or replay one.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn c08_device_verifies_capabilities_independently() {
    let env = Env::start(mode()).await;
    let sh = &env.server.shared;
    let dconn = sh.reg.device_conn(&env.device_id).unwrap();
    let req = OpenRequest::Exec {
        device: String::new(),
        argv: vec!["/bin/echo".into(), "pwned".into()],
        cwd: None,
        env: vec![],
        timeout_secs: None,
    };
    let now = cjs_server::db::now();
    let base = |stream: u32| Capability {
        version: CAP_VERSION,
        id: capability::new_id(),
        principal: env.agent_id.clone(),
        device: env.device_id.clone(),
        action: Action::Exec,
        roots: vec![env.project.to_string_lossy().into_owned()],
        full_access: false,
        issued_at: now,
        expires_at: now + CAP_TTL_SECS,
        stream,
        connection: dconn.id.clone(),
        target: None,
        session: "s_test".into(),
        net_rules: None,
    };
    let forged_key = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
    // (description, key, mutate) -> must be refused.
    type Mutate = fn(&mut Capability, u32);
    let cases: Vec<(&str, &ed25519_dalek::SigningKey, Mutate)> = vec![
        ("forged signature", &forged_key, |_, _| {}),
        ("other device", &sh.cap_key, |c, _| c.device = "d_other".into()),
        ("other connection", &sh.cap_key, |c, _| {
            c.connection = "c_other".into()
        }),
        ("other stream", &sh.cap_key, |c, s| c.stream = s + 1000),
        ("other action", &sh.cap_key, |c, _| c.action = Action::Shell),
        ("expired", &sh.cap_key, |c, _| {
            c.issued_at -= 600;
            c.expires_at -= 600
        }),
        ("overlong ttl", &sh.cap_key, |c, _| c.expires_at += 3600),
        ("no roots", &sh.cap_key, |c, _| c.roots.clear()),
    ];
    for (what, key, mutate) in cases {
        let mut s = dconn.mux.open().await.unwrap();
        let id = s.get_ref().id().val();
        let mut cap = base(id);
        mutate(&mut cap, id);
        write_msg(
            &mut s,
            &DeviceOpen {
                cap: capability::sign(key, &cap),
                req: req.clone(),
            },
        )
        .await
        .unwrap();
        match expect_msg::<_, OpenReply>(&mut s).await.unwrap() {
            OpenReply::Err(e) => assert!(
                matches!(e.code, ErrorCode::Forbidden | ErrorCode::Expired),
                "{what}: {e}"
            ),
            OpenReply::Ok { .. } => panic!("{what}: device accepted an invalid capability"),
        }
    }
    // A valid one works once; replaying it on another stream fails.
    let mut s = dconn.mux.open().await.unwrap();
    let id = s.get_ref().id().val();
    let signed = capability::sign(&sh.cap_key, &base(id));
    write_msg(
        &mut s,
        &DeviceOpen {
            cap: signed.clone(),
            req: req.clone(),
        },
    )
    .await
    .unwrap();
    assert!(matches!(
        expect_msg::<_, OpenReply>(&mut s).await.unwrap(),
        OpenReply::Ok { .. }
    ));
    let mut s2 = dconn.mux.open().await.unwrap();
    write_msg(&mut s2, &DeviceOpen { cap: signed, req })
        .await
        .unwrap();
    assert!(matches!(
        expect_msg::<_, OpenReply>(&mut s2).await.unwrap(),
        OpenReply::Err(_)
    ));
    // A capability for one request cannot be used for another (net target).
    let mut s3 = dconn.mux.open().await.unwrap();
    let id = s3.get_ref().id().val();
    let mut cap = base(id);
    cap.action = Action::ForwardLocal;
    cap.target = Some("127.0.0.1:8080".into());
    let fwd = OpenRequest::ForwardL {
        device: String::new(),
        host: "127.0.0.1".into(),
        port: 22,
    };
    write_msg(
        &mut s3,
        &DeviceOpen {
            cap: capability::sign(&sh.cap_key, &cap),
            req: fwd,
        },
    )
    .await
    .unwrap();
    assert!(matches!(
        expect_msg::<_, OpenReply>(&mut s3).await.unwrap(),
        OpenReply::Err(_)
    ));
}

/// A9 — Authorization: file access is confined to the project roots and
/// shells/commands can only write inside them (OS sandbox).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn c09_project_root_jail_and_sandbox() {
    let env = Env::start(mode()).await;
    env.put_grant(&env.grant("g1", &[Action::Exec, Action::FileRead, Action::FileWrite]));
    let a = env.agent().await;
    std::fs::write(env.tmp().join("outside.txt"), "secret").unwrap();
    std::os::unix::fs::symlink(env.tmp(), env.project.join("escape")).unwrap();
    for path in [
        "/etc/passwd",
        "../outside.txt",
        "escape/outside.txt",
        "./../outside.txt",
        "a\\..\\..\\x",
    ] {
        let r = a
            .open(OpenRequest::FileGet {
                device: "dev1".into(),
                path: path.into(),
                offset: 0,
            })
            .await;
        let e = r.err().unwrap_or_else(|| panic!("{path} must be refused"));
        assert_eq!(e.code, ErrorCode::Forbidden, "{path}: {e}");
    }
    if cjs_sandbox::probe().is_ok() {
        let target = env.tmp().join("written-by-agent");
        let script = format!("echo x > {} ; echo done", target.display());
        let (out, _, _) = run_exec(&a, exec_req("dev1", &script)).await.unwrap();
        assert!(out.contains("done"));
        assert!(
            !target.exists(),
            "sandbox must block writes outside the project roots"
        );
        let (_, _, code) = run_exec(&a, exec_req("dev1", "echo y > inside.txt"))
            .await
            .unwrap();
        assert_eq!(code, Some(0));
        assert!(env.project.join("inside.txt").exists());
    } else {
        eprintln!("sandbox not available here: skipping the write-confinement half");
    }
}

/// A10 — Audit: when the audit log cannot be written, everything that
/// needs an audit record is refused (fail closed).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn c10_audit_failure_fails_closed() {
    let env = Env::start(mode()).await;
    env.put_grant(&env.grant("g1", &[Action::Exec]));
    let a = env.agent().await;
    let admin = env.web("admin").await;
    env.server.shared.audit.inject_failure(true);
    assert_eq!(
        a.open(exec_req("dev1", "true")).await.unwrap_err().code,
        ErrorCode::AuditFailure
    );
    let (st, v) = admin
        .call("POST", "/groups", Some(json!({"name": "g", "kind": "agent"})))
        .await;
    assert_eq!(st, 503, "{v}");
    assert_eq!(v["error"]["code"], "audit_failure");
    let (_, pw, secret) = env.cred("alice");
    let code = cjs_server::accounts::code_for_step(&secret, cjs_server::db::now() / 30);
    let r = reqwest::Client::new()
        .post(format!("{}api/v1/login", env.url))
        .json(&json!({"name": "alice", "password": pw, "totp": code}))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status().as_u16(), 503, "login refused without audit");
    let p = cjs_transport::profile::Profile::load(&env.agent_dir).unwrap();
    let cfg = p
        .client_config(cjs_transport::profile::Profile::key(&env.agent_dir).unwrap())
        .unwrap();
    assert!(
        cjs_transport::connect(&cfg, cjs_transport::new_hello(ClientRole::Agent, None, "t"))
            .await
            .is_err(),
        "new connections refused without audit"
    );
    env.server.shared.audit.inject_failure(false);
    assert_eq!(
        run_exec(&a, exec_req("dev1", "echo back")).await.unwrap().0,
        "back\n"
    );
}

/// A11 — Audit: the log is a verifiable hash chain with signed checkpoints;
/// tampering is detected; recordings are bound to the log by hash.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn c11_audit_chain_tamper_evidence_and_recordings() {
    let env = Env::start(mode()).await;
    env.put_grant(&env.grant("g1", &[Action::Shell]));
    let a = env.agent().await;
    let (mut s, session) = a.open(pty_req("dev1")).await.unwrap();
    write_msg(&mut s, &cjs_proto::PtyIn::Input(b"echo audited; exit\n".to_vec()))
        .await
        .unwrap();
    let _ = pty_expect(&mut s, "never", 10).await;
    let log = &env.server.shared.audit;
    let mut end = vec![];
    for _ in 0..100 {
        end = log
            .query(&cjs_audit::Query {
                kind: Some("session.end".into()),
                session: Some(session.clone()),
                ..Default::default()
            })
            .unwrap();
        if !end.is_empty() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let rec = &end[0].record.event.data["recording"];
    let file = env
        .server
        .shared
        .cfg
        .recordings_dir
        .join(rec["file"].as_str().unwrap());
    let data = std::fs::read(&file).unwrap();
    use sha2::Digest;
    assert_eq!(
        hex::encode(sha2::Sha256::digest(&data)),
        rec["sha256"].as_str().unwrap()
    );
    log.checkpoint().unwrap();
    let report = log.verify(None).unwrap();
    assert!(
        report.ok && report.checkpoints >= 1 && report.unsigned_tail == 0,
        "{report:?}"
    );
    // Auditors can export and verify offline with the published key.
    env.add_user("aud", vec![Role::Auditor]);
    let aud = env.web("aud").await;
    let r = aud
        .http
        .get(format!("{}api/v1/audit/export", aud.base))
        .header("cookie", format!("cjs_session={}", aud.cookie))
        .send()
        .await
        .unwrap();
    let text = r.text().await.unwrap();
    assert!(text.lines().any(|l| l.contains("\"type\":\"checkpoint\"")));
    // Offline verification of the exported file against a key pinned out
    // of band (derived here from the key file, not taken from the export
    // or the API), and the API publishes the same key.
    let key_hex = std::fs::read_to_string(env.tmp.path().join("server/audit.key")).unwrap();
    let key_bytes: [u8; 32] = hex::decode(key_hex.trim()).unwrap().try_into().unwrap();
    let pinned = ed25519_dalek::SigningKey::from_bytes(&key_bytes).verifying_key();
    let (st, info) = aud.call("GET", "/info", None).await;
    assert_eq!(st, 200);
    assert_eq!(info["audit_key"], hex::encode(pinned.as_bytes()));
    let offline = cjs_audit::verify_export(&mut text.as_bytes(), &pinned).unwrap();
    assert!(offline.ok && offline.checkpoints >= 1, "{offline:?}");
    assert_eq!(offline.head, log.verify(None).unwrap().head);
    // A forged export (tampered checkpoint signature) fails offline.
    let cp = text
        .lines()
        .find(|l| l.contains("\"type\":\"checkpoint\""))
        .unwrap();
    let sig = serde_json::from_str::<serde_json::Value>(cp).unwrap()["sig"]
        .as_str()
        .unwrap()
        .to_string();
    let mut bad = hex::decode(&sig).unwrap();
    bad[0] ^= 0x80;
    let forged = text.replace(&sig, &hex::encode(bad));
    let r = cjs_audit::verify_export(&mut forged.as_bytes(), &pinned).unwrap();
    assert!(!r.ok, "tampered checkpoint signature must be detected");
    // ... and so does a correct export checked against another key.
    let other = ed25519_dalek::SigningKey::from_bytes(&[9u8; 32]).verifying_key();
    assert!(!cjs_audit::verify_export(&mut text.as_bytes(), &other).unwrap().ok);
    // Rewriting an event breaks the chain.
    log.with_conn(|c| {
        c.execute(
            "UPDATE events SET body = replace(body, 'session.start', 'session.stert') WHERE kind = 'session.start'",
            [],
        )
    })
    .unwrap();
    let report = log.verify(None).unwrap();
    assert!(!report.ok, "tampering must be detected");
}
