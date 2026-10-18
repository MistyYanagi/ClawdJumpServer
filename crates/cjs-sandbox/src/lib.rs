//! OS-level sandbox for agent shells and commands.
//!
//! The sandboxed process may read and execute the system, may *write* only
//! inside the project roots and a private scratch directory, may neither
//! read nor write the *hidden* directories (the device's configuration and
//! state: identity key, profile, other sessions' scratch), may not create
//! device nodes, and has no TCP network access unless [`Policy::net`] is set.
//!
//! * **Linux**: the device re-executes itself as a small helper
//!   (`<device> __cjs_sandbox [--write DIR].. [--hide DIR].. [--net]
//!   [--tty PATH] [--nofile N] -- CMD..`). The helper applies a Landlock
//!   ruleset that handles read, write and execute accesses (an allow-list:
//!   everything outside the hidden directories is readable, see
//!   `linux.rs`), TCP bind/connect (ABI 4+) and signal / abstract-socket
//!   scoping (ABI 6+), sets `no_new_privs` and resource limits, becomes a
//!   child subreaper and runs the command as its child. When the command
//!   exits or the helper receives SIGTERM/SIGHUP, every remaining
//!   descendant is killed, so background jobs (`setsid cmd &`, double
//!   forks) cannot outlive the session. If the kernel cannot enforce
//!   Landlock the helper refuses to run (fail closed).
//! * **macOS**: the command runs under `sandbox-exec` with a generated SBPL
//!   profile that denies `file-write*` outside the allowed directories,
//!   denies `file-read*`/`file-write*` of the hidden directories and,
//!   unless `net`, denies network access other than Unix-domain sockets.
//! * **Windows**: the helper starts the command inside an AppContainer
//!   (low-privilege token, no network capability, no access to the user
//!   profile) after granting the container SID access to the writable
//!   directories only, and places it in a Job Object that kills the tree
//!   when the helper exits.
//!
//! On every platform [`wrap`] (and the helper) refuses a policy whose
//! writable directories contain a hidden directory.
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

/// Default cap on open file descriptors (RLIMIT_NOFILE) inside the sandbox.
/// The helper only ever lowers the inherited limit.
pub const DEFAULT_MAX_OPEN_FILES: u64 = 16384;

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
    /// Directories the process may neither read nor write (the device's
    /// configuration and state). No writable directory may contain one.
    pub hidden: Vec<PathBuf>,
    /// Allow TCP bind/connect. When false the Linux and macOS sandboxes
    /// deny network access (Windows AppContainers never get any).
    pub net: bool,
    /// The session's own terminal (PTY slave). When set, it is the only
    /// writable entry under `/dev/pts` (Linux); otherwise all of
    /// `/dev/pts` stays writable.
    pub tty: Option<PathBuf>,
    /// RLIMIT_NOFILE cap (Unix); `None` means [`DEFAULT_MAX_OPEN_FILES`].
    pub max_open_files: Option<u64>,
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

/// Resolve symlinks when the path exists (best effort).
fn canon(p: &Path) -> PathBuf {
    std::fs::canonicalize(p).unwrap_or_else(|_| p.to_path_buf())
}

fn check_dirs(writable: &[PathBuf], hidden: &[PathBuf]) -> Result<(), SandboxError> {
    for r in writable.iter().chain(hidden.iter()) {
        if !r.is_absolute() {
            return Err(SandboxError::Setup(format!("not absolute: {}", r.display())));
        }
    }
    for w in writable {
        let w = canon(w);
        for h in hidden {
            let h = canon(h);
            if h.starts_with(&w) {
                return Err(SandboxError::Setup(format!(
                    "writable directory {} contains the protected directory {}",
                    w.display(),
                    h.display()
                )));
            }
        }
    }
    Ok(())
}

/// Validate a policy: absolute paths, and no writable directory may contain
/// (or be) a hidden directory, since that would expose it.
pub fn check_policy(policy: &Policy) -> Result<(), SandboxError> {
    check_dirs(&policy.writable(), &policy.hidden)
}

/// Build the argv that runs `argv` inside the sandbox. `helper` is the
/// executable that handles [`HELPER_ARG`] (normally the device binary).
pub fn wrap(helper: &Path, policy: &Policy, argv: &[String]) -> Result<Vec<String>, SandboxError> {
    if argv.is_empty() {
        return Err(SandboxError::Setup("empty command".into()));
    }
    check_policy(policy)?;
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
        for h in &policy.hidden {
            out.push("--hide".into());
            out.push(h.to_string_lossy().into_owned());
        }
        if policy.net {
            out.push("--net".into());
        }
        if let Some(t) = &policy.tty {
            out.push("--tty".into());
            out.push(t.to_string_lossy().into_owned());
        }
        out.push("--nofile".into());
        out.push(
            policy
                .max_open_files
                .unwrap_or(DEFAULT_MAX_OPEN_FILES)
                .to_string(),
        );
        out.push("--".into());
        out.extend(argv.iter().cloned());
        Ok(out)
    }
}

/// Parsed helper arguments (everything after [`HELPER_ARG`]).
#[derive(Debug, PartialEq, Eq, Default)]
pub struct HelperArgs {
    pub write: Vec<PathBuf>,
    pub hide: Vec<PathBuf>,
    pub net: bool,
    pub tty: Option<PathBuf>,
    pub nofile: Option<u64>,
    pub argv: Vec<String>,
}

pub fn parse_helper_args(args: &[String]) -> Result<HelperArgs, SandboxError> {
    let mut h = HelperArgs::default();
    let value = |i: usize, name: &str| -> Result<String, SandboxError> {
        args.get(i + 1)
            .cloned()
            .ok_or_else(|| SandboxError::Setup(format!("{name} needs a value")))
    };
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--write" => {
                h.write.push(PathBuf::from(value(i, "--write")?));
                i += 2;
            }
            "--hide" => {
                h.hide.push(PathBuf::from(value(i, "--hide")?));
                i += 2;
            }
            "--tty" => {
                h.tty = Some(PathBuf::from(value(i, "--tty")?));
                i += 2;
            }
            "--nofile" => {
                let v = value(i, "--nofile")?;
                h.nofile = Some(
                    v.parse()
                        .map_err(|_| SandboxError::Setup(format!("bad --nofile {v:?}")))?,
                );
                i += 2;
            }
            "--net" => {
                h.net = true;
                i += 1;
            }
            "--" => {
                h.argv = args[i + 1..].to_vec();
                if h.argv.is_empty() {
                    return Err(SandboxError::Setup("missing command".into()));
                }
                // Re-checked here: the helper does not trust its caller.
                check_dirs(&h.write, &h.hide)?;
                return Ok(h);
            }
            other => return Err(SandboxError::Setup(format!("unexpected argument {other:?}"))),
        }
    }
    Err(SandboxError::Setup("missing --".into()))
}

/// Helper entry point. `args` are the arguments after [`HELPER_ARG`].
/// Never returns: exits with the command's status (a signal `n` is
/// reported as `128 + n`, like a shell).
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
        linux::enter_and_run(&parsed)
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
            hidden: vec![abs("/etc/cjs")],
            ..Default::default()
        };
        let argv = vec!["sh".to_string(), "-c".into(), "echo hi".into()];
        #[cfg(not(target_os = "macos"))]
        {
            let w = wrap(Path::new("/bin/dev"), &p, &argv).unwrap();
            assert_eq!(w[1], HELPER_ARG);
            let parsed = parse_helper_args(&w[2..]).unwrap();
            assert_eq!(parsed.write, vec![abs("/work"), abs("/tmp/x")]);
            assert_eq!(parsed.hide, vec![abs("/etc/cjs")]);
            assert!(!parsed.net);
            assert_eq!(parsed.tty, None);
            assert_eq!(parsed.nofile, Some(DEFAULT_MAX_OPEN_FILES));
            assert_eq!(parsed.argv, argv);
            let p2 = Policy {
                net: true,
                tty: Some(abs("/dev/pts/3")),
                max_open_files: Some(64),
                ..p.clone()
            };
            let parsed = parse_helper_args(&wrap(Path::new("/bin/dev"), &p2, &argv).unwrap()[2..]).unwrap();
            assert!(parsed.net);
            assert_eq!(parsed.tty, Some(abs("/dev/pts/3")));
            assert_eq!(parsed.nofile, Some(64));
        }
        let _ = (p, argv);
        // Relative roots are refused on every platform.
        let rel = Policy {
            write_roots: vec![PathBuf::from("work")],
            ..Default::default()
        };
        assert!(wrap(Path::new("/bin/dev"), &rel, &["sh".to_string()]).is_err());
        assert!(parse_helper_args(&["--write".into()]).is_err());
        assert!(parse_helper_args(&["--".into()]).is_err());
        assert!(parse_helper_args(&["--nofile".into(), "x".into(), "--".into(), "sh".into()]).is_err());
    }

    #[test]
    fn writable_dir_must_not_contain_hidden_dir() {
        let bad = Policy {
            write_roots: vec![abs("/srv")],
            hidden: vec![abs("/srv/cjs-device")],
            ..Default::default()
        };
        assert!(wrap(Path::new("/bin/dev"), &bad, &["sh".to_string()]).is_err());
        let same = Policy {
            write_roots: vec![abs("/srv/cjs-device")],
            hidden: vec![abs("/srv/cjs-device")],
            ..Default::default()
        };
        assert!(check_policy(&same).is_err());
        // A writable directory *inside* a hidden one is fine (own scratch).
        let ok = Policy {
            write_roots: vec![abs("/work")],
            temp_dir: Some(abs("/var/scratch/s1")),
            hidden: vec![abs("/var/scratch")],
            ..Default::default()
        };
        assert!(check_policy(&ok).is_ok());
        let args = vec![
            "--write".to_string(),
            abs("/srv").to_string_lossy().into_owned(),
            "--hide".into(),
            abs("/srv/k").to_string_lossy().into_owned(),
            "--".into(),
            "sh".into(),
        ];
        assert!(parse_helper_args(&args).is_err(), "helper re-checks containment");
    }
}
