//! Project-directory jail.
//!
//! All file access by agents goes through a [`Jail`]. In the default mode
//! every path is resolved *beneath* one of the project roots using cap-std
//! capability handles, so `..`, absolute symlinks, symlink chains, Windows
//! junctions and similar tricks cannot leave the root: resolution happens
//! in the kernel (`openat2(RESOLVE_BENEATH)` on Linux) or with cap-std's
//! manual, symlink-aware walk elsewhere. On top of that we reject paths that
//! are suspicious on any platform before touching the file system: NUL
//! bytes, `..` components, Windows UNC / device paths (`\\?\`, `\\.\`),
//! alternate data streams (`file:stream`) and reserved device names
//! (`CON`, `NUL`, `COM1`, ...).
//!
//! In full-access mode (approved by a second secadmin) paths are used as
//! given.
#![forbid(unsafe_code)]

use std::io;
use std::path::{Component, Path, PathBuf};

use cap_std::ambient_authority;
use cap_std::fs::{Dir, OpenOptions};
use cjs_proto::{DirEntry, EntryKind, ErrorCode, ProtoError};

#[derive(Debug)]
pub struct Root {
    /// Canonical host path of the root.
    path: PathBuf,
    /// The root as configured (may go through symlinks, e.g. `/tmp` on
    /// macOS). Accepted as a prefix too; the remainder is still resolved
    /// beneath `dir`, so it cannot widen access.
    given: PathBuf,
    dir: Dir,
}

#[derive(Debug)]
pub enum Jail {
    Roots(Vec<Root>),
    Full { base: PathBuf },
}

pub fn forbidden(m: impl Into<String>) -> ProtoError {
    ProtoError::new(ErrorCode::Forbidden, m)
}

fn io_err(e: io::Error) -> ProtoError {
    let code = match e.kind() {
        io::ErrorKind::NotFound => ErrorCode::NotFound,
        io::ErrorKind::PermissionDenied => ErrorCode::Forbidden,
        _ => ErrorCode::Io,
    };
    // cap-std reports escape attempts as PermissionDenied / "a path led
    // outside of the filesystem".
    let msg = e.to_string();
    if msg.contains("outside of the filesystem") {
        return forbidden("path escapes the project root");
    }
    ProtoError::new(code, msg)
}

const RESERVED: &[&str] = &[
    "con", "prn", "aux", "nul", "com1", "com2", "com3", "com4", "com5", "com6", "com7", "com8", "com9",
    "lpt1", "lpt2", "lpt3", "lpt4", "lpt5", "lpt6", "lpt7", "lpt8", "lpt9", "conin$", "conout$",
];

/// Platform-independent sanity checks on a user supplied path.
pub fn check_path_syntax(p: &str) -> Result<(), ProtoError> {
    if p.contains('\0') {
        return Err(forbidden("path contains NUL"));
    }
    let norm = p.replace('\\', "/");
    if norm.starts_with("//") {
        return Err(forbidden("UNC and device paths are not allowed"));
    }
    for (i, comp) in norm.split('/').enumerate() {
        if comp == ".." {
            return Err(forbidden("`..` is not allowed"));
        }
        // Drive letter is allowed only as the first component ("C:").
        let is_drive =
            i == 0 && comp.len() == 2 && comp.as_bytes()[0].is_ascii_alphabetic() && comp.ends_with(':');
        if comp.contains(':') && !is_drive {
            return Err(forbidden("alternate data streams are not allowed"));
        }
        let stem = comp
            .split('.')
            .next()
            .unwrap_or("")
            .trim_end_matches([' ', '.'])
            .to_ascii_lowercase();
        if RESERVED.contains(&stem.as_str()) {
            return Err(forbidden("reserved device names are not allowed"));
        }
        if comp.ends_with(' ') || (comp.ends_with('.') && comp != ".") {
            // Windows silently strips these; refuse to avoid aliasing.
            return Err(forbidden("path components may not end in a dot or space"));
        }
    }
    Ok(())
}

fn case_insensitive_fs() -> bool {
    cfg!(any(windows, target_os = "macos"))
}

fn is_abs(p: &str) -> bool {
    let b = p.as_bytes();
    p.starts_with('/') || p.starts_with('\\') || (b.len() >= 2 && b[0].is_ascii_alphabetic() && b[1] == b':')
}

/// Strip `root` from `full` (both already normalised), respecting
/// case-insensitive file systems.
fn strip_root(full: &Path, root: &Path) -> Option<PathBuf> {
    let fc: Vec<_> = full.components().collect();
    let rc: Vec<_> = root.components().collect();
    if fc.len() < rc.len() {
        return None;
    }
    for (a, b) in fc.iter().zip(rc.iter()) {
        let (a, b) = (a.as_os_str().to_string_lossy(), b.as_os_str().to_string_lossy());
        let eq = if case_insensitive_fs() {
            a.eq_ignore_ascii_case(&b)
        } else {
            a == b
        };
        if !eq {
            return None;
        }
    }
    Some(fc[rc.len()..].iter().collect())
}

/// Resolved location inside a jail.
#[derive(Debug)]
pub struct Resolved<'a> {
    dir: Option<&'a Dir>,
    /// Relative path below the root (jail mode) or absolute (full mode).
    rel: PathBuf,
    /// Host path for display / audit.
    pub host_path: PathBuf,
}

impl Jail {
    /// Open the jail. Roots must exist; they are canonicalised.
    pub fn new(roots: &[String], full_access: bool) -> Result<Self, ProtoError> {
        if full_access {
            let base = roots
                .first()
                .map(PathBuf::from)
                .or_else(home_dir)
                .unwrap_or_else(|| PathBuf::from("/"));
            return Ok(Jail::Full { base });
        }
        if roots.is_empty() {
            return Err(forbidden("no project roots"));
        }
        let mut out = Vec::new();
        for r in roots {
            let path = std::fs::canonicalize(r)
                .map_err(|e| ProtoError::new(ErrorCode::NotFound, format!("project root {r}: {e}")))?;
            let dir = Dir::open_ambient_dir(&path, ambient_authority()).map_err(io_err)?;
            out.push(Root {
                path,
                given: PathBuf::from(r),
                dir,
            });
        }
        Ok(Jail::Roots(out))
    }

    pub fn is_full(&self) -> bool {
        matches!(self, Jail::Full { .. })
    }

    /// Canonical root paths (empty in full mode).
    pub fn roots(&self) -> Vec<PathBuf> {
        match self {
            Jail::Roots(r) => r.iter().map(|r| r.path.clone()).collect(),
            Jail::Full { .. } => vec![],
        }
    }

    /// Resolve a user path. Relative paths are relative to the first root.
    pub fn resolve(&self, p: &str) -> Result<Resolved<'_>, ProtoError> {
        match self {
            Jail::Full { base } => {
                if p.contains('\0') {
                    return Err(forbidden("path contains NUL"));
                }
                let path = if is_abs(p) { PathBuf::from(p) } else { base.join(p) };
                Ok(Resolved {
                    dir: None,
                    rel: path.clone(),
                    host_path: path,
                })
            }
            Jail::Roots(roots) => {
                check_path_syntax(p)?;
                let p = if p.is_empty() { "." } else { p };
                if !is_abs(p) {
                    let rel = clean_rel(Path::new(p))?;
                    return Ok(Resolved {
                        dir: Some(&roots[0].dir),
                        host_path: roots[0].path.join(&rel),
                        rel,
                    });
                }
                let abs = PathBuf::from(p);
                for r in roots {
                    if let Some(rest) = strip_root(&abs, &r.path).or_else(|| strip_root(&abs, &r.given)) {
                        let rel = clean_rel(&rest)?;
                        return Ok(Resolved {
                            dir: Some(&r.dir),
                            host_path: r.path.join(&rel),
                            rel,
                        });
                    }
                }
                Err(forbidden(format!("{p} is outside the project roots")))
            }
        }
    }

    /// Open a file for reading.
    pub fn open_read(&self, p: &str) -> Result<std::fs::File, ProtoError> {
        let r = self.resolve(p)?;
        let f = match r.dir {
            Some(d) => d.open(&r.rel).map_err(io_err)?.into_std(),
            None => std::fs::File::open(&r.rel).map_err(io_err)?,
        };
        if f.metadata().map_err(io_err)?.is_dir() {
            return Err(ProtoError::new(ErrorCode::BadRequest, "is a directory"));
        }
        Ok(f)
    }

    /// Open a file for writing. With `truncate` the file is emptied,
    /// otherwise it is opened for appending at `offset` by the caller.
    pub fn open_write(&self, p: &str, truncate: bool, mkdirs: bool) -> Result<std::fs::File, ProtoError> {
        let r = self.resolve(p)?;
        if r.rel.as_os_str().is_empty() || r.rel == Path::new(".") {
            return Err(ProtoError::new(
                ErrorCode::BadRequest,
                "cannot write to a directory",
            ));
        }
        match r.dir {
            Some(d) => {
                if mkdirs {
                    if let Some(parent) = r.rel.parent().filter(|p| !p.as_os_str().is_empty()) {
                        d.create_dir_all(parent).map_err(io_err)?;
                    }
                }
                let mut o = OpenOptions::new();
                o.write(true).create(true).truncate(truncate);
                Ok(d.open_with(&r.rel, &o).map_err(io_err)?.into_std())
            }
            None => {
                if mkdirs {
                    if let Some(parent) = r.rel.parent() {
                        std::fs::create_dir_all(parent).map_err(io_err)?;
                    }
                }
                std::fs::OpenOptions::new()
                    .write(true)
                    .create(true)
                    .truncate(truncate)
                    .open(&r.rel)
                    .map_err(io_err)
            }
        }
    }

    /// List a directory (or stat a single file).
    pub fn list(&self, p: &str) -> Result<(DirEntry, Vec<DirEntry>), ProtoError> {
        let r = self.resolve(p)?;
        let name = r
            .host_path
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_else(|| r.host_path.to_string_lossy().into_owned());
        match r.dir {
            Some(d) => {
                let rel = rel_or_dot(&r.rel);
                let meta = d.symlink_metadata(rel).map_err(io_err)?;
                let me = entry(
                    name,
                    &meta.file_type().into_std_lossy(),
                    meta.len(),
                    mode_of_cap(&meta),
                    mtime_cap(&meta),
                );
                if !meta.is_dir() {
                    return Ok((me, vec![]));
                }
                let sub = d.open_dir(rel).map_err(io_err)?;
                let mut out = Vec::new();
                for e in sub.entries().map_err(io_err)? {
                    let e = e.map_err(io_err)?;
                    let m = match e.metadata() {
                        Ok(m) => m,
                        Err(_) => continue,
                    };
                    let ft = e.file_type().map_err(io_err)?;
                    out.push(entry(
                        e.file_name().to_string_lossy().into_owned(),
                        &ft.into_std_lossy(),
                        m.len(),
                        mode_of_cap(&m),
                        mtime_cap(&m),
                    ));
                }
                out.sort_by(|a, b| a.name.cmp(&b.name));
                Ok((me, out))
            }
            None => {
                let meta = std::fs::symlink_metadata(&r.rel).map_err(io_err)?;
                let me = entry(
                    name,
                    &meta.file_type().into(),
                    meta.len(),
                    mode_of_std(&meta),
                    mtime_std(&meta),
                );
                if !meta.is_dir() {
                    return Ok((me, vec![]));
                }
                let mut out = Vec::new();
                for e in std::fs::read_dir(&r.rel).map_err(io_err)? {
                    let e = e.map_err(io_err)?;
                    let Ok(m) = e.metadata() else { continue };
                    out.push(entry(
                        e.file_name().to_string_lossy().into_owned(),
                        &m.file_type().into(),
                        m.len(),
                        mode_of_std(&m),
                        mtime_std(&m),
                    ));
                }
                out.sort_by(|a, b| a.name.cmp(&b.name));
                Ok((me, out))
            }
        }
    }

    /// Host directory to use as working directory for a process. The
    /// directory is opened through the jail first, then canonicalised and
    /// re-checked so that a symlinked cwd cannot point outside.
    pub fn cwd(&self, p: Option<&str>) -> Result<PathBuf, ProtoError> {
        match self {
            Jail::Full { base } => Ok(p
                .map(|p| self.resolve(p).map(|r| r.host_path))
                .transpose()?
                .unwrap_or_else(|| base.clone())),
            Jail::Roots(roots) => {
                let Some(p) = p else {
                    return Ok(roots[0].path.clone());
                };
                let r = self.resolve(p)?;
                if let Some(d) = r.dir {
                    // Fails if any component escapes via symlink.
                    d.open_dir(rel_or_dot(&r.rel)).map_err(io_err)?;
                }
                let canon = std::fs::canonicalize(&r.host_path).map_err(io_err)?;
                if roots.iter().any(|root| strip_root(&canon, &root.path).is_some()) {
                    Ok(canon)
                } else {
                    Err(forbidden("working directory escapes the project root"))
                }
            }
        }
    }
}

fn rel_or_dot(p: &Path) -> &Path {
    if p.as_os_str().is_empty() {
        Path::new(".")
    } else {
        p
    }
}

fn clean_rel(p: &Path) -> Result<PathBuf, ProtoError> {
    let mut out = PathBuf::new();
    for c in p.components() {
        match c {
            Component::Normal(n) => out.push(n),
            Component::CurDir => {}
            Component::ParentDir => return Err(forbidden("`..` is not allowed")),
            Component::RootDir | Component::Prefix(_) => {
                return Err(forbidden("unexpected absolute component"))
            }
        }
    }
    Ok(out)
}

trait IntoStdLossy {
    fn into_std_lossy(self) -> Kind;
}

struct Kind(EntryKind);

impl IntoStdLossy for cap_std::fs::FileType {
    fn into_std_lossy(self) -> Kind {
        Kind(if self.is_dir() {
            EntryKind::Dir
        } else if self.is_file() {
            EntryKind::File
        } else if self.is_symlink() {
            EntryKind::Symlink
        } else {
            EntryKind::Other
        })
    }
}

impl From<std::fs::FileType> for Kind {
    fn from(t: std::fs::FileType) -> Kind {
        Kind(if t.is_dir() {
            EntryKind::Dir
        } else if t.is_file() {
            EntryKind::File
        } else if t.is_symlink() {
            EntryKind::Symlink
        } else {
            EntryKind::Other
        })
    }
}

fn entry(name: String, k: &Kind, size: u64, mode: u32, mtime: i64) -> DirEntry {
    DirEntry {
        name,
        kind: k.0,
        size,
        mode,
        mtime,
    }
}

#[cfg(unix)]
fn mode_of_cap(m: &cap_std::fs::Metadata) -> u32 {
    use cap_std::fs::PermissionsExt;
    m.permissions().mode()
}
#[cfg(not(unix))]
fn mode_of_cap(m: &cap_std::fs::Metadata) -> u32 {
    if m.permissions().readonly() {
        0o444
    } else {
        0o644
    }
}
#[cfg(unix)]
fn mode_of_std(m: &std::fs::Metadata) -> u32 {
    use std::os::unix::fs::PermissionsExt;
    m.permissions().mode()
}
#[cfg(not(unix))]
fn mode_of_std(m: &std::fs::Metadata) -> u32 {
    if m.permissions().readonly() {
        0o444
    } else {
        0o644
    }
}

fn mtime_cap(m: &cap_std::fs::Metadata) -> i64 {
    m.modified()
        .ok()
        .map(|t| t.into_std())
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

fn mtime_std(m: &std::fs::Metadata) -> i64 {
    m.modified()
        .ok()
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

fn home_dir() -> Option<PathBuf> {
    std::env::var_os("HOME")
        .or_else(|| std::env::var_os("USERPROFILE"))
        .map(PathBuf::from)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};

    fn setup() -> (tempfile::TempDir, PathBuf, Jail) {
        let t = tempfile::tempdir().unwrap();
        let root = t.path().join("proj");
        std::fs::create_dir_all(root.join("sub")).unwrap();
        std::fs::write(root.join("sub/a.txt"), b"hello").unwrap();
        std::fs::write(t.path().join("secret.txt"), b"top secret").unwrap();
        let j = Jail::new(&[root.to_string_lossy().into_owned()], false).unwrap();
        (t, root, j)
    }

    /// A root configured through a symlink (like `/tmp` -> `/private/tmp`
    /// on macOS) accepts absolute paths under either spelling, and still
    /// refuses escapes.
    #[cfg(unix)]
    #[test]
    fn root_given_through_symlink() {
        let t = tempfile::tempdir().unwrap();
        let real = t.path().join("real");
        std::fs::create_dir_all(real.join("sub")).unwrap();
        std::fs::write(real.join("sub/a.txt"), "hi").unwrap();
        std::fs::write(t.path().join("outside.txt"), "no").unwrap();
        let link = t.path().join("link");
        std::os::unix::fs::symlink(&real, &link).unwrap();
        let j = Jail::new(&[link.to_string_lossy().into_owned()], false).unwrap();
        assert!(j.open_read(&link.join("sub/a.txt").to_string_lossy()).is_ok());
        let canon = std::fs::canonicalize(&real).unwrap();
        assert!(j.open_read(&canon.join("sub/a.txt").to_string_lossy()).is_ok());
        assert!(j
            .open_read(&t.path().join("outside.txt").to_string_lossy())
            .is_err());
        assert!(j
            .open_read(&format!("{}/../outside.txt", link.display()))
            .is_err());
    }

    #[test]
    fn reads_inside() {
        let (_t, root, j) = setup();
        let mut s = String::new();
        j.open_read("sub/a.txt").unwrap().read_to_string(&mut s).unwrap();
        assert_eq!(s, "hello");
        let abs = root.join("sub/a.txt").to_string_lossy().into_owned();
        assert!(j.open_read(&abs).is_ok());
        let (me, entries) = j.list("sub").unwrap();
        assert_eq!(me.kind, EntryKind::Dir);
        assert_eq!(entries.len(), 1);
        let mut f = j.open_write("new/dir/b.txt", true, true).unwrap();
        f.write_all(b"x").unwrap();
        assert!(root.join("new/dir/b.txt").exists());
    }

    #[test]
    fn escapes_fail() {
        let (t, root, j) = setup();
        let outside = t.path().join("secret.txt").to_string_lossy().into_owned();
        // Lexical and absolute escapes.
        for p in [
            "../secret.txt",
            "sub/../../secret.txt",
            outside.as_str(),
            "/etc/passwd",
        ] {
            assert!(j.open_read(p).is_err(), "{p} must fail");
        }
        // Windows-specific forms are refused on every platform.
        for p in [
            "\\\\?\\C:\\x",
            "//server/share/x",
            "a.txt:stream",
            "sub/CON",
            "nul.txt",
            "x. ",
            "trailing.",
        ] {
            assert_eq!(j.open_read(p).unwrap_err().code, ErrorCode::Forbidden, "{p}");
        }
        // Symlink escapes (absolute and relative targets).
        #[cfg(unix)]
        {
            std::os::unix::fs::symlink(t.path().join("secret.txt"), root.join("abs_link")).unwrap();
            std::os::unix::fs::symlink("../secret.txt", root.join("rel_link")).unwrap();
            std::os::unix::fs::symlink(t.path(), root.join("dir_link")).unwrap();
            for p in ["abs_link", "rel_link", "dir_link/secret.txt"] {
                assert!(j.open_read(p).is_err(), "{p} must fail");
            }
            assert!(j.open_write("dir_link/evil.txt", true, false).is_err());
            assert!(!t.path().join("evil.txt").exists());
            assert!(j.cwd(Some("dir_link")).is_err());
        }
        // Case games on the absolute prefix do not help on case-sensitive
        // systems and are handled by canonical comparison elsewhere.
        let upper = root.to_string_lossy().to_uppercase() + "/sub/a.txt";
        if !case_insensitive_fs() {
            assert!(j.open_read(&upper).is_err());
        }
    }

    #[test]
    fn full_mode_is_unrestricted() {
        let (t, _root, _) = setup();
        let j = Jail::new(&[], true).unwrap();
        assert!(j.is_full());
        assert!(j
            .open_read(&t.path().join("secret.txt").to_string_lossy())
            .is_ok());
    }

    #[test]
    fn cwd_checks() {
        let (_t, root, j) = setup();
        assert_eq!(j.cwd(None).unwrap(), std::fs::canonicalize(&root).unwrap());
        assert!(j.cwd(Some("sub")).is_ok());
        assert!(j.cwd(Some("/")).is_err());
    }
}
