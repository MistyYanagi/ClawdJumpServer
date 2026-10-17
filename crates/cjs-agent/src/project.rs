//! Per-project defaults from `.cjs.toml` (searched upwards from the
//! current directory).
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
        let mut dir = Some(start);
        while let Some(d) = dir {
            let p = d.join(FILE);
            if p.is_file() {
                let s = std::fs::read_to_string(&p).map_err(|e| format!("{}: {e}", p.display()))?;
                let mut proj: Project = toml::from_str(&s).map_err(|e| format!("{}: {e}", p.display()))?;
                proj.path = Some(p);
                return Ok(proj);
            }
            dir = d.parent();
        }
        Ok(Project::default())
    }
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
}
