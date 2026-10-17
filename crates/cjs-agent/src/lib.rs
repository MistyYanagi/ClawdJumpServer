//! ClawdJumpServer agent: the `cjs` CLI, its local daemon and an MCP
//! server, all speaking the multiplexed stream protocol to the bastion.
#![forbid(unsafe_code)]

pub mod conn;
pub mod local;
pub mod mcp;
pub mod ops;
pub mod project;
pub mod proxy;
pub mod term;

pub use conn::AgentConn;
pub use local::Opener;

pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Default configuration directory (`~/.config/cjs` or platform equivalent).
pub fn default_dir() -> std::path::PathBuf {
    dirs::config_dir()
        .unwrap_or_else(|| std::path::PathBuf::from("."))
        .join("cjs")
}

pub(crate) fn random_secret() -> String {
    use rand::RngCore;
    let mut b = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut b);
    hex::encode(b)
}

/// Split `device:path` (a single letter before `:` is a Windows drive,
/// i.e. a local path). `:path` means the default device.
pub fn split_remote(s: &str) -> Option<(Option<&str>, &str)> {
    let (d, p) = s.split_once(':')?;
    if d.len() == 1 && d.chars().all(|c| c.is_ascii_alphabetic()) {
        return None;
    }
    if d.contains('/') || d.contains('\\') {
        return None;
    }
    Some(((!d.is_empty()).then_some(d), p))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn remote_paths() {
        assert_eq!(split_remote("dev1:/a/b"), Some((Some("dev1"), "/a/b")));
        assert_eq!(split_remote(":x"), Some((None, "x")));
        assert_eq!(split_remote("C:\\file"), None);
        assert_eq!(split_remote("./a:b"), None);
        assert_eq!(split_remote("local.txt"), None);
    }
}
