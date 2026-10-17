//! OS-level sandbox for agent shells and commands.
//!
//! The sandboxed process may read the system but may only *write* inside
//! the project roots and a private scratch directory:
//!
//! * **Linux**: the device re-executes itself as a small helper
//!   (`<device> __cjs_sandbox --write DIR.. -- CMD..`) which applies a
//!   Landlock ruleset restricting all write accesses, sets
//!   `no_new_privs`, disables core dumps and then `exec`s the command.
//!   If the kernel cannot enforce Landlock the helper refuses to run
//!   (fail closed).
//! * **macOS**: the command runs under `sandbox-exec` with a generated SBPL
//!   profile that denies `file-write*` outside the allowed directories.
//! * **Windows**: the helper starts the command inside an AppContainer
//!   (low-privilege token, no network capability) after granting the
//!   container SID access to the project roots, and places it in a Job
//!   Object that kills the tree when the helper exits.
//!
//! This is the only crate in the workspace that may use `unsafe` (Windows
//! FFI only; the Linux and macOS paths are safe Rust).
#![cfg_attr(not(windows), forbid(unsafe_code))]

use std::path::{Path, PathBuf};

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "macos")]
mod macos;
#[cfg(windows)]
mod windows;

/// argv[1] that selects the helper mode in the device binary.
pub const HELPER_ARG: &str = "__cjs_sandbox";

#[derive(Debug, thiserror::Error)]
pub enum SandboxError {
    #[error("sandbox unavailable: {0}")]
    Unavailable(String),
    #[error("sandbox setup failed: {0}")]
    Setup(String),
}

#[derive(Debug, Clone, Default)]
pub struct Policy {
    /// Directories the process may write to (project roots).
    pub write_roots: Vec<PathBuf>,
    /// Private scratch directory (also exported as TMPDIR/TEMP/TMP).
    pub temp_dir: Option<PathBuf>,
}

impl Policy {
    fn writable(&self) -> Vec<PathBuf> {
        let mut v = self.write_roots.clone();
        if let Some(t) = &self.temp_dir {
            v.push(t.clone());
        }
        v
    }
}

/// Build the argv that runs `argv` inside the sandbox. `helper` is the
/// executable that handles [`HELPER_ARG`] (normally the device binary).
pub fn wrap(helper: &Path, policy: &Policy, argv: &[String]) -> Result<Vec<String>, SandboxError> {
    if argv.is_empty() {
        return Err(SandboxError::Setup("empty command".into()));
    }
    for r in policy.writable() {
        if !r.is_absolute() {
            return Err(SandboxError::Setup(format!("not absolute: {}", r.display())));
        }
    }
    #[cfg(target_os = "macos")]
    {
        let _ = helper;
        macos::wrap(policy, argv)
    }
    #[cfg(not(target_os = "macos"))]
    {
        let mut out = vec![helper.to_string_lossy().into_owned(), HELPER_ARG.to_string()];
        for r in policy.writable() {
            out.push("--write".into());
            out.push(r.to_string_lossy().into_owned());
        }
        out.push("--".into());
        out.extend(argv.iter().cloned());
        Ok(out)
    }
}

/// Parsed helper arguments (everything after [`HELPER_ARG`]).
#[derive(Debug, PartialEq, Eq)]
pub struct HelperArgs {
    pub write: Vec<PathBuf>,
    pub argv: Vec<String>,
}

pub fn parse_helper_args(args: &[String]) -> Result<HelperArgs, SandboxError> {
    let mut write = Vec::new();
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--write" => {
                let p = args
                    .get(i + 1)
                    .ok_or_else(|| SandboxError::Setup("--write needs a value".into()))?;
                write.push(PathBuf::from(p));
                i += 2;
            }
            "--" => {
                let argv = args[i + 1..].to_vec();
                if argv.is_empty() {
                    return Err(SandboxError::Setup("missing command".into()));
                }
                return Ok(HelperArgs { write, argv });
            }
            other => return Err(SandboxError::Setup(format!("unexpected argument {other:?}"))),
        }
    }
    Err(SandboxError::Setup("missing --".into()))
}

/// Helper entry point. `args` are the arguments after [`HELPER_ARG`].
/// Never returns: execs the command (Unix) or exits with its status.
pub fn helper_main(args: &[String]) -> ! {
    let parsed = match parse_helper_args(args) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("cjs-sandbox: {e}");
            std::process::exit(126);
        }
    };
    #[cfg(target_os = "linux")]
    {
        linux::enter_and_exec(&parsed)
    }
    #[cfg(windows)]
    {
        windows::run(&parsed)
    }
    #[cfg(not(any(target_os = "linux", windows)))]
    {
        let _ = parsed;
        eprintln!("cjs-sandbox: helper mode is not used on this platform");
        std::process::exit(126);
    }
}

/// Check whether sandboxing can be enforced on this machine.
pub fn probe() -> Result<String, SandboxError> {
    #[cfg(target_os = "linux")]
    {
        linux::probe()
    }
    #[cfg(target_os = "macos")]
    {
        macos::probe()
    }
    #[cfg(windows)]
    {
        Ok("appcontainer".into())
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
    {
        Err(SandboxError::Unavailable("unsupported platform".into()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// An absolute path on the current platform.
    fn abs(p: &str) -> PathBuf {
        if cfg!(windows) {
            PathBuf::from(format!("C:{}", p.replace('/', "\\")))
        } else {
            PathBuf::from(p)
        }
    }

    #[test]
    fn helper_args_roundtrip() {
        let p = Policy {
            write_roots: vec![abs("/work")],
            temp_dir: Some(abs("/tmp/x")),
        };
        let argv = vec!["sh".to_string(), "-c".into(), "echo hi".into()];
        #[cfg(not(target_os = "macos"))]
        {
            let w = wrap(Path::new("/bin/dev"), &p, &argv).unwrap();
            assert_eq!(w[1], HELPER_ARG);
            let parsed = parse_helper_args(&w[2..]).unwrap();
            assert_eq!(parsed.write, vec![abs("/work"), abs("/tmp/x")]);
            assert_eq!(parsed.argv, argv);
        }
        let _ = (p, argv);
        // Relative roots are refused on every platform.
        let rel = Policy {
            write_roots: vec![PathBuf::from("work")],
            temp_dir: None,
        };
        assert!(wrap(Path::new("/bin/dev"), &rel, &["sh".to_string()]).is_err());
        assert!(parse_helper_args(&["--write".into()]).is_err());
        assert!(parse_helper_args(&["--".into()]).is_err());
    }
}
