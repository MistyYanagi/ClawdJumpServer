//! Service definitions for running the device daemon at boot.
use std::path::Path;

/// systemd unit. The daemon runs as the given user; the sandbox (Landlock)
/// confines what shells may write, so the unit itself stays permissive
/// about paths but drops every privilege it does not need.
pub fn systemd_unit(exe: &Path, dir: &Path, user: &str) -> String {
    format!(
        "[Unit]
Description=ClawdJumpServer device
After=network-online.target
Wants=network-online.target

[Service]
User={user}
ExecStart={exe} run --config {dir}
Restart=always
RestartSec=5
NoNewPrivileges=yes
PrivateTmp=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
RestrictSUIDSGID=yes
LockPersonality=yes
UMask=0077

[Install]
WantedBy=multi-user.target
",
        exe = exe.display(),
        dir = dir.display()
    )
}

/// launchd property list (per-user agent).
pub fn launchd_plist(exe: &Path, dir: &Path) -> String {
    fn esc(s: &str) -> String {
        s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;")
    }
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>com.clawdjumpserver.device</string>
  <key>ProgramArguments</key>
  <array>
    <string>{exe}</string><string>run</string><string>--config</string><string>{dir}</string>
  </array>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
  <key>StandardErrorPath</key><string>{dir}/device.log</string>
</dict>
</plist>
"#,
        exe = esc(&exe.to_string_lossy()),
        dir = esc(&dir.to_string_lossy())
    )
}

/// Windows: a scheduled task that starts the daemon at logon of the
/// current user (no service control protocol needed).
pub fn windows_schtasks_args(exe: &Path, dir: &Path) -> Vec<String> {
    vec![
        "/Create".into(),
        "/F".into(),
        "/SC".into(),
        "ONLOGON".into(),
        "/RL".into(),
        "LIMITED".into(),
        "/TN".into(),
        "ClawdJumpServer Device".into(),
        "/TR".into(),
        format!("\"{}\" run --config \"{}\"", exe.display(), dir.display()),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn units_render() {
        let u = systemd_unit(
            Path::new("/usr/bin/cjs-device"),
            Path::new("/var/lib/cjs-device"),
            "cjs",
        );
        assert!(u.contains("ExecStart=/usr/bin/cjs-device run --config /var/lib/cjs-device"));
        assert!(u.contains("NoNewPrivileges=yes"));
        let p = launchd_plist(Path::new("/a&b"), Path::new("/d"));
        assert!(p.contains("/a&amp;b"));
        assert_eq!(windows_schtasks_args(Path::new("x"), Path::new("y")).len(), 10);
    }
}
