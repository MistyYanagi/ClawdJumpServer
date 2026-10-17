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
