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
    // The device's own state is neither readable nor writable; later rules
    // win, so the session's scratch (inside it) is allowed again after.
    for h in &policy.hidden {
        let canon = std::fs::canonicalize(h).unwrap_or(h.clone());
        p.push_str(&format!(
            "(deny file-read* file-write* (subpath {}))\n",
            quote(&canon.to_string_lossy())
        ));
    }
    if !policy.hidden.is_empty() {
        for r in policy.writable() {
            let canon = std::fs::canonicalize(&r).unwrap_or(r.clone());
            p.push_str(&format!(
                "(allow file-read* file-write* (subpath {}))\n",
                quote(&canon.to_string_lossy())
            ));
        }
    }
    if !policy.net {
        // Network through the server's egress policy only; local Unix
        // sockets keep working.
        p.push_str("(deny network*)\n(allow network* (remote unix-socket))\n");
    }
    p
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn profile_hides_state_and_network() {
        let pol = Policy {
            write_roots: vec!["/work/p\"q".into()],
            temp_dir: Some("/state/scratch/s1".into()),
            hidden: vec!["/state".into()],
            ..Default::default()
        };
        let p = profile(&pol);
        assert!(
            p.contains("(deny file-read* file-write* (subpath \"/state\"))"),
            "{p}"
        );
        let deny = p.find("(deny file-read* file-write*").unwrap();
        let allow = p
            .rfind("(allow file-read* file-write* (subpath \"/state/scratch/s1\"))")
            .unwrap();
        assert!(allow > deny, "scratch re-allowed after the deny: {p}");
        assert!(p.contains("\\\""), "quotes are escaped: {p}");
        assert!(p.contains("(deny network*)"));
        let p = profile(&Policy { net: true, ..pol });
        assert!(!p.contains("(deny network*)"));
    }
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
