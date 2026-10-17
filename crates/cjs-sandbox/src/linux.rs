use std::os::unix::process::CommandExt;

use landlock::{path_beneath_rules, AccessFs, Ruleset, RulesetAttr, RulesetCreatedAttr, RulesetStatus, ABI};

use crate::{HelperArgs, SandboxError};

const ABI_TARGET: ABI = ABI::V5;

/// Device nodes an interactive shell legitimately writes to.
const DEV_WRITABLE: &[&str] = &[
    "/dev/null",
    "/dev/zero",
    "/dev/full",
    "/dev/tty",
    "/dev/pts",
    "/dev/ptmx",
    "/dev/random",
    "/dev/urandom",
];

fn write_access() -> landlock::BitFlags<AccessFs> {
    // Restrict every write-type access. Device ioctls are left alone so
    // terminals keep working (they are not a file-write vector).
    AccessFs::from_write(ABI_TARGET) & !AccessFs::IoctlDev
}

fn apply(write: &[std::path::PathBuf]) -> Result<RulesetStatus, SandboxError> {
    let err = |e: landlock::RulesetError| SandboxError::Setup(e.to_string());
    let status = Ruleset::default()
        .handle_access(write_access())
        .map_err(err)?
        .create()
        .map_err(err)?
        .add_rules(path_beneath_rules(write, write_access()))
        .map_err(err)?
        .add_rules(path_beneath_rules(DEV_WRITABLE, write_access()))
        .map_err(err)?
        .restrict_self()
        .map_err(err)?;
    if !status.no_new_privs {
        return Err(SandboxError::Unavailable("could not set no_new_privs".into()));
    }
    Ok(status.ruleset)
}

pub(crate) fn enter_and_exec(a: &HelperArgs) -> ! {
    match apply(&a.write) {
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
    let _ = rlimit::setrlimit(rlimit::Resource::CORE, 0, 0);
    let err = std::process::Command::new(&a.argv[0]).args(&a.argv[1..]).exec();
    eprintln!("cjs-sandbox: exec {}: {err}", a.argv[0]);
    std::process::exit(127);
}

pub(crate) fn probe() -> Result<String, SandboxError> {
    // Landlock and no_new_privs apply to the calling thread (and what it
    // spawns afterwards), so enforce a ruleset in a throwaway thread.
    let r = std::thread::spawn(|| apply(&[])).join();
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
