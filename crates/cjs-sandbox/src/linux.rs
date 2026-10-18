//! Linux sandbox helper: Landlock + no_new_privs + rlimits, and a small
//! supervisor that keeps every descendant of the command inside the
//! session's lifetime.
//!
//! File system policy (Landlock is an allow-list):
//! * read + execute everywhere, except the hidden directories. Rules are
//!   added for every directory entry along the way down from `/`, skipping
//!   the hidden ones and descending into their ancestors instead of
//!   granting them whole;
//! * read + write in the writable directories (project roots, scratch),
//!   but never creating block or character device nodes;
//! * write on a few harmless device nodes and the session's own terminal;
//! * connecting to pathname Unix sockets only inside writable directories.
//!
//! Network: TCP bind/connect are denied (ABI 4+) unless `--net`.
//! Scoping (ABI 6+): no signals to, and no abstract Unix sockets of,
//! processes outside the sandbox (such as the device daemon).
use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use landlock::{
    path_beneath_rules, Access, AccessFs, AccessNet, BitFlags, Ruleset, RulesetAttr, RulesetCreatedAttr,
    RulesetStatus, Scope, ABI,
};
use nix::sys::signal::{kill, SigSet, Signal};
use nix::sys::signalfd::{SfdFlags, SignalFd};
use nix::sys::wait::{waitpid, WaitPidFlag, WaitStatus};
use nix::unistd::Pid;

use crate::{HelperArgs, SandboxError};

/// Newest ABI we know; older kernels get a best-effort subset.
const ABI_TARGET: ABI = ABI::V9;

/// Device nodes an interactive shell legitimately writes to.
const DEV_WRITABLE: &[&str] = &[
    "/dev/null",
    "/dev/zero",
    "/dev/full",
    "/dev/tty",
    "/dev/ptmx",
    "/dev/random",
    "/dev/urandom",
];

/// Most entries visited while building the read allow-list.
const MAX_WALK: usize = 100_000;

fn handled_fs() -> BitFlags<AccessFs> {
    // Device ioctls stay unrestricted so terminals keep working.
    AccessFs::from_all(ABI_TARGET) & !AccessFs::IoctlDev
}

fn read_access() -> BitFlags<AccessFs> {
    AccessFs::from_read(ABI_TARGET)
}

fn write_access() -> BitFlags<AccessFs> {
    handled_fs() & !(AccessFs::MakeBlock | AccessFs::MakeChar)
}

fn canon(p: &Path) -> PathBuf {
    std::fs::canonicalize(p).unwrap_or_else(|_| p.to_path_buf())
}

/// Paths to grant read access to: everything reachable from `/` except the
/// hidden directories. Symlinks are judged by their target, so a link that
/// points into (or above) a hidden directory is never granted.
fn readable_roots(hidden: &[PathBuf]) -> Result<Vec<PathBuf>, SandboxError> {
    let hidden: Vec<PathBuf> = hidden.iter().map(|h| canon(h)).collect();
    if hidden.is_empty() {
        return Ok(vec![PathBuf::from("/")]);
    }
    if hidden.iter().any(|h| h == Path::new("/")) {
        return Err(SandboxError::Setup("cannot hide /".into()));
    }
    let is_hidden = |p: &Path| hidden.iter().any(|h| p.starts_with(h));
    let is_ancestor = |p: &Path| hidden.iter().any(|h| h.starts_with(p) && h != p);
    let mut out = Vec::new();
    let mut stack = vec![PathBuf::from("/")];
    let mut seen = HashSet::new();
    let mut visited = 0usize;
    while let Some(dir) = stack.pop() {
        if !seen.insert(dir.clone()) {
            continue;
        }
        let rd = match std::fs::read_dir(&dir) {
            Ok(rd) => rd,
            Err(_) => continue,
        };
        for e in rd.flatten() {
            visited += 1;
            if visited > MAX_WALK {
                return Err(SandboxError::Setup(
                    "too many entries above the protected directory".into(),
                ));
            }
            let path = e.path();
            let is_link = e.file_type().map(|t| t.is_symlink()).unwrap_or(false);
            let real = canon(&path);
            if is_hidden(&path) || is_hidden(&real) {
                continue;
            }
            if is_ancestor(&real) || is_ancestor(&path) {
                // Reached again through its real path; a link to it is skipped.
                if !is_link {
                    stack.push(path);
                }
                continue;
            }
            out.push(path);
        }
    }
    Ok(out)
}

fn apply(a: &HelperArgs) -> Result<RulesetStatus, SandboxError> {
    let err = |e: landlock::RulesetError| SandboxError::Setup(e.to_string());
    let mut rs = Ruleset::default().handle_access(handled_fs()).map_err(err)?;
    if !a.net {
        rs = rs.handle_access(AccessNet::from_all(ABI_TARGET)).map_err(err)?;
    }
    let rs = rs.scope(Scope::from_all(ABI_TARGET)).map_err(err)?;
    let readable = readable_roots(&a.hide)?;
    let mut created = rs
        .create()
        .map_err(err)?
        .add_rules(path_beneath_rules(&readable, read_access()))
        .map_err(err)?
        .add_rules(path_beneath_rules(&a.write, write_access()))
        .map_err(err)?
        .add_rules(path_beneath_rules(DEV_WRITABLE, write_access()))
        .map_err(err)?;
    // The session's own terminal only, when known; otherwise all of /dev/pts.
    let pts: Vec<PathBuf> = match &a.tty {
        Some(t) => vec![t.clone()],
        None => vec![PathBuf::from("/dev/pts")],
    };
    created = created
        .add_rules(path_beneath_rules(&pts, write_access()))
        .map_err(err)?;
    let status = created.restrict_self().map_err(err)?;
    if !status.no_new_privs {
        return Err(SandboxError::Unavailable("could not set no_new_privs".into()));
    }
    Ok(status.ruleset)
}

fn set_limits(a: &HelperArgs) {
    let _ = rlimit::setrlimit(rlimit::Resource::CORE, 0, 0);
    if let Some(n) = a.nofile {
        if let Ok((soft, hard)) = rlimit::getrlimit(rlimit::Resource::NOFILE) {
            let hard = hard.min(n);
            let _ = rlimit::setrlimit(rlimit::Resource::NOFILE, soft.min(hard), hard);
        }
    }
}

/// Direct children of `pid` (all threads).
fn children_of(pid: i32) -> Vec<i32> {
    let mut out = Vec::new();
    let Ok(tasks) = std::fs::read_dir(format!("/proc/{pid}/task")) else {
        return out;
    };
    for t in tasks.flatten() {
        if let Ok(s) = std::fs::read_to_string(t.path().join("children")) {
            out.extend(s.split_whitespace().filter_map(|x| x.parse::<i32>().ok()));
        }
    }
    out
}

/// Every live descendant of this process. As a child subreaper we inherit
/// orphans, so nothing started inside the session can leave this tree.
fn descendants() -> Vec<i32> {
    let me = std::process::id() as i32;
    let mut out = Vec::new();
    let mut stack = children_of(me);
    let mut seen = HashSet::new();
    while let Some(p) = stack.pop() {
        if seen.insert(p) {
            out.push(p);
            stack.extend(children_of(p));
        }
    }
    out
}

fn reap_all() -> Vec<(Pid, WaitStatus)> {
    let mut v = Vec::new();
    while let Ok(st) = waitpid(Pid::from_raw(-1), Some(WaitPidFlag::WNOHANG)) {
        match st.pid() {
            Some(p) => v.push((p, st)),
            None => break,
        }
    }
    v
}

/// Kill every descendant and reap them. Repeats until none are left (new
/// forks racing with us are caught on the next round).
fn kill_tree() {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let d = descendants();
        if d.is_empty() || Instant::now() > deadline {
            break;
        }
        // Stop first so nothing forks while we go through the list.
        for p in &d {
            let _ = kill(Pid::from_raw(*p), Signal::SIGSTOP);
        }
        for p in &d {
            let _ = kill(Pid::from_raw(*p), Signal::SIGKILL);
        }
        std::thread::sleep(Duration::from_millis(5));
        reap_all();
    }
    reap_all();
}

fn code_of(st: &WaitStatus) -> i32 {
    match st {
        WaitStatus::Exited(_, c) => *c,
        WaitStatus::Signaled(_, s, _) => 128 + *s as i32,
        _ => 1,
    }
}

pub(crate) fn enter_and_run(a: &HelperArgs) -> ! {
    match apply(a) {
        Ok(RulesetStatus::FullyEnforced) | Ok(RulesetStatus::PartiallyEnforced) => {}
        Ok(RulesetStatus::NotEnforced) => {
            eprintln!("cjs-sandbox: Landlock is not enforced by this kernel; refusing to run unsandboxed");
            std::process::exit(126);
        }
        Err(e) => {
            eprintln!("cjs-sandbox: {e}");
            std::process::exit(126);
        }
    }
    set_limits(a);
    // Orphaned descendants are re-parented to us, not to init; and if the
    // device dies we are told to clean up.
    if let Err(e) = nix::sys::prctl::set_child_subreaper(true) {
        eprintln!("cjs-sandbox: subreaper: {e}");
        std::process::exit(126);
    }
    let _ = nix::sys::prctl::set_pdeathsig(Signal::SIGTERM);
    // Block the signals we handle before starting the child (the standard
    // library resets the child's signal mask). SIGINT/SIGQUIT from the
    // terminal are meant for the command, not for us.
    let mut mask = SigSet::empty();
    for s in [
        Signal::SIGCHLD,
        Signal::SIGTERM,
        Signal::SIGHUP,
        Signal::SIGINT,
        Signal::SIGQUIT,
    ] {
        mask.add(s);
    }
    if let Err(e) = mask.thread_block() {
        eprintln!("cjs-sandbox: sigmask: {e}");
        std::process::exit(126);
    }
    let mut sfd = match SignalFd::with_flags(&mask, SfdFlags::SFD_CLOEXEC) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("cjs-sandbox: signalfd: {e}");
            std::process::exit(126);
        }
    };
    let child = match std::process::Command::new(&a.argv[0]).args(&a.argv[1..]).spawn() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("cjs-sandbox: exec {}: {e}", a.argv[0]);
            std::process::exit(127);
        }
    };
    let main = Pid::from_raw(child.id() as i32);
    // `child` is never waited on through std: we reap with waitpid(-1).
    std::mem::forget(child);
    let mut status: Option<WaitStatus> = None;
    let mut stop_signal: Option<i32> = None;
    // The main child may already be gone.
    for (p, st) in reap_all() {
        if p == main {
            status = Some(st);
        }
    }
    while status.is_none() && stop_signal.is_none() {
        match sfd.read_signal() {
            Ok(Some(info)) => {
                let sig = info.ssi_signo as i32;
                if sig == Signal::SIGTERM as i32 || sig == Signal::SIGHUP as i32 {
                    stop_signal = Some(sig);
                } else if sig == Signal::SIGINT as i32 || sig == Signal::SIGQUIT as i32 {
                    // The command (same terminal) receives these itself.
                }
            }
            Ok(None) => {}
            Err(nix::errno::Errno::EINTR) => {}
            Err(_) => stop_signal = Some(Signal::SIGTERM as i32),
        }
        for (p, st) in reap_all() {
            if p == main {
                status = Some(st);
            }
        }
    }
    // The session is over: nothing the command started may outlive it.
    kill_tree();
    let code = match (status, stop_signal) {
        (Some(st), _) => code_of(&st),
        (None, Some(sig)) => 128 + sig,
        (None, None) => 1,
    };
    std::process::exit(code);
}

pub(crate) fn probe() -> Result<String, SandboxError> {
    // Landlock and no_new_privs apply to the calling thread (and what it
    // spawns afterwards), so enforce a ruleset in a throwaway thread.
    let r = std::thread::spawn(|| {
        let args = HelperArgs {
            argv: vec!["true".into()],
            ..Default::default()
        };
        apply(&args)
    })
    .join();
    match r {
        Ok(Ok(RulesetStatus::FullyEnforced)) => Ok("landlock".into()),
        Ok(Ok(RulesetStatus::PartiallyEnforced)) => Ok("landlock (partial: older kernel ABI)".into()),
        Ok(Ok(RulesetStatus::NotEnforced)) => Err(SandboxError::Unavailable(
            "Landlock is not enforced by this kernel".into(),
        )),
        Ok(Err(e)) => Err(e),
        Err(_) => Err(SandboxError::Setup("probe thread panicked".into())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hidden_dirs_and_links_to_them_are_not_readable() {
        let t = tempfile::tempdir().unwrap();
        let base = canon(t.path());
        let hidden = base.join("state");
        std::fs::create_dir_all(hidden.join("inner")).unwrap();
        std::fs::create_dir_all(base.join("other")).unwrap();
        std::os::unix::fs::symlink(&hidden, base.join("link")).unwrap();
        std::os::unix::fs::symlink(&base, base.join("uplink")).unwrap();
        let r = readable_roots(std::slice::from_ref(&hidden)).unwrap();
        assert!(r.iter().all(|p| !canon(p).starts_with(&hidden)), "{r:?}");
        assert!(r.contains(&base.join("other")));
        assert!(!r.contains(&base.join("link")));
        assert!(!r.contains(&base.join("uplink")));
        assert!(!r.iter().any(|p| p == Path::new("/")));
        assert_eq!(readable_roots(&[]).unwrap(), vec![PathBuf::from("/")]);
    }
}
