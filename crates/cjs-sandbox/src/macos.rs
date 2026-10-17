use std::path::Path;

use crate::{Policy, SandboxError};

pub const SANDBOX_EXEC: &str = "/usr/bin/sandbox-exec";

fn quote(p: &str) -> String {
    let mut s = String::from("\"");
    for c in p.chars() {
        match c {
            '"' => s.push_str("\\\""),
            '\\' => s.push_str("\\\\"),
            _ => s.push(c),
        }
    }
    s.push('"');
    s
}

/// SBPL profile: everything allowed except writes outside the allow list.
pub fn profile(policy: &Policy) -> String {
    let mut p = String::from("(version 1)\n(allow default)\n(deny file-write*)\n(allow file-write*\n");
    for r in policy.writable() {
        // /tmp and /var are symlinks into /private on macOS.
        let canon = std::fs::canonicalize(&r).unwrap_or(r.clone());
        p.push_str(&format!("  (subpath {})\n", quote(&canon.to_string_lossy())));
    }
    p.push_str(
        "  (literal \"/dev/null\") (literal \"/dev/zero\") (literal \"/dev/tty\") (literal \"/dev/dtracehelper\")\n  (regex #\"^/dev/ttys[0-9]+$\") (regex #\"^/dev/fd/\"))\n",
    );
    p
}

pub(crate) fn wrap(policy: &Policy, argv: &[String]) -> Result<Vec<String>, SandboxError> {
    if !Path::new(SANDBOX_EXEC).exists() {
        return Err(SandboxError::Unavailable("sandbox-exec not found".into()));
    }
    let mut v = vec![SANDBOX_EXEC.to_string(), "-p".into(), profile(policy)];
    v.extend(argv.iter().cloned());
    Ok(v)
}

pub(crate) fn probe() -> Result<String, SandboxError> {
    let st = std::process::Command::new(SANDBOX_EXEC)
        .args([
            "-p",
            "(version 1)(allow default)(deny file-write*)",
            "/usr/bin/true",
        ])
        .status()
        .map_err(|e| SandboxError::Unavailable(format!("sandbox-exec: {e}")))?;
    if st.success() {
        Ok("sandbox-exec".into())
    } else {
        Err(SandboxError::Unavailable(
            "sandbox-exec refused a trivial profile".into(),
        ))
    }
}
