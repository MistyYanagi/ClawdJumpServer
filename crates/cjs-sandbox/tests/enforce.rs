#![cfg(target_os = "linux")]
use std::path::Path;
use std::process::Command;

#[test]
fn shell_cannot_write_outside_project() {
    if let Err(e) = cjs_sandbox::probe() {
        eprintln!("skipping: {e}");
        return;
    }
    let t = tempfile::tempdir().unwrap();
    let proj = t.path().join("proj");
    let scratch = t.path().join("scratch");
    std::fs::create_dir_all(&proj).unwrap();
    std::fs::create_dir_all(&scratch).unwrap();
    let outside = t.path().join("outside.txt");
    let policy = cjs_sandbox::Policy {
        write_roots: vec![proj.clone()],
        temp_dir: Some(scratch.clone()),
        ..Default::default()
    };
    let script = format!(
        "echo in > {p}/in.txt; echo tmp > {s}/t.txt; echo out > {o} 2>/dev/null; mkdir {o}.d 2>/dev/null; cat /etc/hostname >/dev/null && echo readok",
        p = proj.display(),
        s = scratch.display(),
        o = outside.display()
    );
    let argv = cjs_sandbox::wrap(
        Path::new(env!("CARGO_BIN_EXE_cjs-sandbox-helper")),
        &policy,
        &["/bin/sh".to_string(), "-c".into(), script],
    )
    .unwrap();
    let out = Command::new(&argv[0]).args(&argv[1..]).output().unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(proj.join("in.txt").exists(), "write inside project must work");
    assert!(scratch.join("t.txt").exists(), "write to scratch must work");
    assert!(!outside.exists(), "write outside project must be blocked");
    assert!(
        !t.path().join("outside.txt.d").exists(),
        "mkdir outside must be blocked"
    );
    assert!(stdout.contains("readok"), "reads stay allowed: {stdout}");
}

fn run_sandboxed(policy: &cjs_sandbox::Policy, script: &str) -> (String, std::process::ExitStatus) {
    let argv = cjs_sandbox::wrap(
        Path::new(env!("CARGO_BIN_EXE_cjs-sandbox-helper")),
        policy,
        &["/bin/sh".to_string(), "-c".into(), script.to_string()],
    )
    .unwrap();
    let out = Command::new(&argv[0]).args(&argv[1..]).output().unwrap();
    (
        String::from_utf8_lossy(&out.stdout).into_owned() + &String::from_utf8_lossy(&out.stderr),
        out.status,
    )
}

#[test]
fn hidden_dir_unreadable_and_no_device_nodes_or_network() {
    if let Err(e) = cjs_sandbox::probe() {
        eprintln!("skipping: {e}");
        return;
    }
    let t = tempfile::tempdir().unwrap();
    let base = std::fs::canonicalize(t.path()).unwrap();
    let proj = base.join("proj");
    let state = base.join("state");
    let scratch = state.join("scratch/s1");
    std::fs::create_dir_all(&proj).unwrap();
    std::fs::create_dir_all(&scratch).unwrap();
    std::fs::write(state.join("identity.key"), "SECRET").unwrap();
    std::fs::create_dir_all(state.join("scratch/s2")).unwrap();
    std::fs::write(state.join("scratch/s2/other"), "OTHER").unwrap();
    std::os::unix::fs::symlink(state.join("identity.key"), proj.join("keylink")).unwrap();
    let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = l.local_addr().unwrap().port();
    let policy = cjs_sandbox::Policy {
        write_roots: vec![proj.clone()],
        temp_dir: Some(scratch.clone()),
        hidden: vec![state.clone()],
        ..Default::default()
    };
    let script = format!(
        "cat {k} 2>/dev/null && echo KEY_READ; \
         cat {p}/keylink 2>/dev/null && echo LINK_READ; \
         cat {o} 2>/dev/null && echo OTHER_READ; \
         ls {st} >/dev/null 2>&1 && echo STATE_LISTED; \
         echo mine > {s}/f && cat {s}/f; \
         mknod {p}/blk b 7 0 2>/dev/null && echo MKNOD_OK; \
         mknod {p}/chr c 1 3 2>/dev/null && echo MKNODC_OK; \
         mkfifo {p}/fifo && echo fifo-ok; \
         (exec 3<>/dev/tcp/127.0.0.1/{port}) 2>/dev/null && echo NET_OK; \
         cat /etc/hosts >/dev/null && echo read-ok",
        k = state.join("identity.key").display(),
        p = proj.display(),
        o = state.join("scratch/s2/other").display(),
        st = state.display(),
        s = scratch.display(),
    );
    // bash for /dev/tcp; fall back to sh (then the network line is a no-op).
    let sh = if Path::new("/bin/bash").exists() {
        "/bin/bash"
    } else {
        "/bin/sh"
    };
    let argv = cjs_sandbox::wrap(
        Path::new(env!("CARGO_BIN_EXE_cjs-sandbox-helper")),
        &policy,
        &[sh.to_string(), "-c".into(), script],
    )
    .unwrap();
    let out = Command::new(&argv[0]).args(&argv[1..]).output().unwrap();
    let text = String::from_utf8_lossy(&out.stdout);
    for bad in [
        "KEY_READ",
        "LINK_READ",
        "OTHER_READ",
        "STATE_LISTED",
        "MKNOD_OK",
        "MKNODC_OK",
        "NET_OK",
    ] {
        assert!(!text.contains(bad), "{bad}: {text}");
    }
    for good in ["mine", "fifo-ok", "read-ok"] {
        assert!(text.contains(good), "{good}: {text}");
    }
    drop(l);
    // A writable directory that contains the hidden one is refused.
    let bad = cjs_sandbox::Policy {
        write_roots: vec![base.clone()],
        hidden: vec![state.clone()],
        ..Default::default()
    };
    assert!(cjs_sandbox::wrap(Path::new("/bin/true"), &bad, &["sh".into()]).is_err());
    // With network allowed the same connect works.
    let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = l.local_addr().unwrap().port();
    let net = cjs_sandbox::Policy {
        net: true,
        ..policy.clone()
    };
    if sh == "/bin/bash" {
        let argv = cjs_sandbox::wrap(
            Path::new(env!("CARGO_BIN_EXE_cjs-sandbox-helper")),
            &net,
            &[
                sh.into(),
                "-c".into(),
                format!("(exec 3<>/dev/tcp/127.0.0.1/{port}) && echo NET_OK"),
            ],
        )
        .unwrap();
        let out = Command::new(&argv[0]).args(&argv[1..]).output().unwrap();
        assert!(String::from_utf8_lossy(&out.stdout).contains("NET_OK"));
    }
}

fn alive(pidfile: &Path) -> bool {
    let Ok(pid) = std::fs::read_to_string(pidfile) else {
        return false;
    };
    let pid = pid.trim();
    std::fs::read_to_string(format!("/proc/{pid}/stat"))
        .map(|s| !s.contains(") Z "))
        .unwrap_or(false)
}

#[test]
fn background_jobs_die_with_the_session() {
    if let Err(e) = cjs_sandbox::probe() {
        eprintln!("skipping: {e}");
        return;
    }
    let t = tempfile::tempdir().unwrap();
    let proj = std::fs::canonicalize(t.path()).unwrap();
    let policy = cjs_sandbox::Policy {
        write_roots: vec![proj.clone()],
        ..Default::default()
    };
    // 1. The command exits normally; its detached child must not survive.
    let pf = proj.join("bg1.pid");
    let (out, st) = run_sandboxed(
        &policy,
        &format!(
            "setsid sh -c 'echo $$ > {}; exec sleep 300' </dev/null >/dev/null 2>&1 & sleep 0.3; exit 7",
            pf.display()
        ),
    );
    assert_eq!(st.code(), Some(7), "{out}");
    std::thread::sleep(std::time::Duration::from_millis(200));
    assert!(pf.exists(), "background job started");
    assert!(!alive(&pf), "background job outlived the command");

    // 2. The session is terminated (SIGTERM to the helper, as the device does).
    let pf = proj.join("bg2.pid");
    let argv = cjs_sandbox::wrap(
        Path::new(env!("CARGO_BIN_EXE_cjs-sandbox-helper")),
        &policy,
        &[
            "/bin/sh".to_string(),
            "-c".into(),
            format!(
                "(setsid sh -c 'echo $$ > {}; exec sleep 300' &) ; sleep 300",
                pf.display()
            ),
        ],
    )
    .unwrap();
    let mut child = Command::new(&argv[0]).args(&argv[1..]).spawn().unwrap();
    for _ in 0..100 {
        if alive(&pf) {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    assert!(alive(&pf), "double-forked job started");
    let _ = Command::new("kill")
        .args(["-TERM", &child.id().to_string()])
        .status();
    let st = child.wait().unwrap();
    assert_eq!(st.code(), Some(128 + 15));
    assert!(!alive(&pf), "double-forked job survived session termination");
}
