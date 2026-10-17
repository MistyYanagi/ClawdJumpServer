//! Per-project defaults from `.cjs.toml`, searched upwards from the current
//! directory but not past the enclosing git repository root (or the user's
//! home directory). Files owned by another user are ignored, so a
//! `.cjs.toml` planted in a shared parent such as `/tmp` cannot pick the
//! device or remote directory.
//!
//! ```toml
//! device = "build-box"       # default device
//! cwd = "/work/my-project"   # default remote working directory
//! ```
use std::path::{Path, PathBuf};

use serde::Deserialize;

pub const FILE: &str = ".cjs.toml";

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Project {
    pub device: Option<String>,
    pub cwd: Option<String>,
    #[serde(skip)]
    pub path: Option<PathBuf>,
}

impl Project {
    pub fn find(start: &Path) -> Result<Self, String> {
        let home = dirs::home_dir();
        let mut dir = Some(start);
        while let Some(d) = dir {
            let p = d.join(FILE);
            if p.is_file() {
                if !owned_by_me(&p) {
                    tracing::warn!(path = %p.display(), "ignoring .cjs.toml owned by another user");
                } else {
                    let s = std::fs::read_to_string(&p).map_err(|e| format!("{}: {e}", p.display()))?;
                    let mut proj: Project =
                        toml::from_str(&s).map_err(|e| format!("{}: {e}", p.display()))?;
                    proj.path = Some(p);
                    return Ok(proj);
                }
            }
            // Stop at the repository root or the home directory.
            if d.join(".git").exists() || home.as_deref() == Some(d) {
                break;
            }
            dir = d.parent();
        }
        Ok(Project::default())
    }
}

#[cfg(unix)]
fn owned_by_me(p: &Path) -> bool {
    use std::os::unix::fs::MetadataExt;
    let Ok(m) = std::fs::metadata(p) else {
        return false;
    };
    // Our uid without libc::geteuid (unsafe code is not allowed here): the
    // owner of /proc/self on Linux, else the owner of our home directory.
    let me = std::fs::metadata("/proc/self").map(|s| s.uid()).ok().or_else(|| {
        dirs::home_dir()
            .and_then(|h| std::fs::metadata(h).ok())
            .map(|h| h.uid())
    });
    match me {
        Some(uid) => m.uid() == uid && m.mode() & 0o022 == 0,
        None => false,
    }
}

#[cfg(not(unix))]
fn owned_by_me(_p: &Path) -> bool {
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_upwards() {
        let t = tempfile::tempdir().unwrap();
        std::fs::write(t.path().join(FILE), "device = \"d1\"\ncwd = \"/w\"\n").unwrap();
        let sub = t.path().join("a/b");
        std::fs::create_dir_all(&sub).unwrap();
        let p = Project::find(&sub).unwrap();
        assert_eq!(p.device.as_deref(), Some("d1"));
        assert_eq!(p.cwd.as_deref(), Some("/w"));
        std::fs::write(t.path().join(FILE), "bogus = 1\n").unwrap();
        assert!(Project::find(&sub).is_err());
    }

    #[test]
    fn stops_at_git_root() {
        let t = tempfile::tempdir().unwrap();
        std::fs::write(t.path().join(FILE), "device = \"outer\"\n").unwrap();
        let repo = t.path().join("repo");
        std::fs::create_dir_all(repo.join(".git")).unwrap();
        let sub = repo.join("src");
        std::fs::create_dir_all(&sub).unwrap();
        assert_eq!(Project::find(&sub).unwrap().device, None);
        std::fs::write(repo.join(FILE), "device = \"inner\"\n").unwrap();
        assert_eq!(Project::find(&sub).unwrap().device.as_deref(), Some("inner"));
    }

    #[cfg(unix)]
    #[test]
    fn ignores_group_writable() {
        use std::os::unix::fs::PermissionsExt;
        let t = tempfile::tempdir().unwrap();
        let f = t.path().join(FILE);
        std::fs::write(&f, "device = \"d\"\n").unwrap();
        std::fs::set_permissions(&f, std::fs::Permissions::from_mode(0o666)).unwrap();
        assert_eq!(Project::find(t.path()).unwrap().device, None);
    }
}
