//! ClawdJumpServer device daemon.
//!
//! The device dials out to the server and serves the streams the server
//! opens. Before doing anything for a stream it verifies the capability
//! token itself (signature, device, connection, stream, action, network
//! target, expiry, replay), so a compromised or bypassed relay cannot widen
//! access. Shells and commands run inside the OS sandbox (writes limited to
//! the project roots and a private scratch directory) with a minimal
//! environment; file access goes through the project-root jail.
#![forbid(unsafe_code)]

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use cjs_authz::capability::CapVerifier;
use cjs_mux::{expect_msg, write_msg, MuxHandle, MuxStream};
use cjs_proto::{
    validate_request, Capability, DeviceOpen, ErrorCode, OpenReply, OpenRequest, ProtoError, Role,
};
use cjs_transport::profile::Profile;
use cjs_transport::{connect, new_hello};
use ed25519_dalek::VerifyingKey;
use tokio::io::AsyncWriteExt;

mod exec;
mod files;
mod net;
mod pty;
pub mod service;

pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Device runtime settings.
#[derive(Debug, Clone)]
pub struct DeviceOptions {
    /// Configuration directory (profile and identity key).
    pub dir: PathBuf,
    /// Executable that implements the sandbox helper (normally the device
    /// binary itself).
    pub helper: PathBuf,
}

pub(crate) fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

pub(crate) fn perr(code: ErrorCode, m: impl Into<String>) -> ProtoError {
    ProtoError::new(code, m)
}

/// Connect and serve until the process is stopped. Reconnects with backoff.
pub async fn run(opts: DeviceOptions) -> Result<(), ProtoError> {
    let profile = Profile::load(&opts.dir)?;
    let key = Profile::key(&opts.dir)?;
    let cfg = profile.client_config(key)?;
    let sandbox = cjs_sandbox::probe().map_err(|e| e.to_string());
    match &sandbox {
        Ok(s) => tracing::info!(sandbox = %s, "sandbox available"),
        Err(e) => {
            tracing::warn!(err = %e, "sandbox unavailable: shells and commands will be refused unless full access is approved")
        }
    }
    let mut verifier: Option<(VerifyingKey, Arc<CapVerifierShared>)> = None;
    let mut backoff = Duration::from_secs(1);
    loop {
        match connect(&cfg, new_hello(Role::Device, None, VERSION)).await {
            Ok(conn) => {
                backoff = Duration::from_secs(1);
                let vk = match VerifyingKey::from_bytes(&conn.welcome.signing_key) {
                    Ok(k) => k,
                    Err(_) => {
                        tracing::error!("server sent an invalid signing key");
                        conn.handle.close(perr(ErrorCode::Protocol, "bad signing key"));
                        tokio::time::sleep(Duration::from_secs(30)).await;
                        continue;
                    }
                };
                // Keep the replay cache across reconnects unless the key changed.
                let shared = match &verifier {
                    Some((k, v)) if *k == vk => v.clone(),
                    _ => {
                        let v = Arc::new(CapVerifierShared(CapVerifier::new(
                            vk,
                            conn.welcome.principal_id.clone(),
                        )));
                        verifier = Some((vk, v.clone()));
                        v
                    }
                };
                tracing::info!(device = %conn.welcome.name, connection = %conn.welcome.connection_id, transport = conn.transport, "connected");
                serve(conn, opts.clone(), shared, sandbox.clone()).await;
                tracing::warn!("disconnected from server");
            }
            Err(e) => {
                let fatal = matches!(
                    e.code,
                    ErrorCode::Unauthenticated | ErrorCode::Disabled | ErrorCode::Forbidden
                );
                tracing::warn!(err = %e, "connect failed");
                if fatal {
                    backoff = Duration::from_secs(60);
                }
            }
        }
        tokio::time::sleep(backoff).await;
        backoff = (backoff * 2).min(Duration::from_secs(60));
    }
}

/// Wrapper so the verifier can be shared across reconnects.
pub(crate) struct CapVerifierShared(CapVerifier);

async fn serve(
    conn: cjs_transport::ClientConn,
    opts: DeviceOptions,
    verifier: Arc<CapVerifierShared>,
    sandbox: Result<String, String>,
) {
    let (mux, mut inbound, _task) = cjs_mux::spawn(conn.io, cjs_mux::Mode::Client);
    let connection = conn.welcome.connection_id.clone();
    let handle = conn.handle.clone();
    loop {
        tokio::select! {
            s = inbound.recv() => match s {
                Some(s) => {
                    let ctx = CtxRef {
                        opts: opts.clone(),
                        verifier: verifier.clone(),
                        connection: connection.clone(),
                        mux: mux.clone(),
                        sandbox: sandbox.clone(),
                    };
                    tokio::spawn(handle_stream(ctx, s));
                }
                None => break,
            },
            e = handle.closed() => {
                tracing::info!(err = %e, "session closed");
                break;
            }
        }
    }
    mux.close().await;
}

/// Per-stream view of the device context.
#[derive(Clone)]
pub(crate) struct CtxRef {
    pub opts: DeviceOptions,
    verifier: Arc<CapVerifierShared>,
    pub connection: String,
    pub mux: MuxHandle,
    pub sandbox: Result<String, String>,
}

pub(crate) async fn reply_ok(s: &mut MuxStream, id: u32, cap: &Capability) -> Result<(), ProtoError> {
    write_msg(
        s,
        &OpenReply::Ok {
            id,
            session: cap.session.clone(),
        },
    )
    .await
}

async fn handle_stream(ctx: CtxRef, mut s: MuxStream) {
    let stream_id = s.get_ref().id().val();
    let open: DeviceOpen = match tokio::time::timeout(Duration::from_secs(30), expect_msg(&mut s)).await {
        Ok(Ok(o)) => o,
        Ok(Err(e)) => return fail(&mut s, e).await,
        Err(_) => return,
    };
    if let Err(e) = validate_request(&open.req) {
        return fail(&mut s, e).await;
    }
    // Independent verification: the device trusts the signature, not the relay.
    let cap = match ctx
        .verifier
        .0
        .verify(&open.cap, &open.req, &ctx.connection, stream_id, now())
    {
        Ok(c) => c,
        Err(e) => {
            tracing::warn!(err = %e, "capability rejected");
            return fail(&mut s, e).await;
        }
    };
    tracing::info!(session = %cap.session, principal = %cap.principal, action = %cap.action, full_access = cap.full_access, "stream authorized");
    let mut replied = false;
    let r = match &open.req {
        OpenRequest::Pty { .. } => pty::run(&ctx, &cap, &open.req, &mut s, &mut replied).await,
        OpenRequest::Exec { .. } => exec::run(&ctx, &cap, &open.req, &mut s, &mut replied).await,
        OpenRequest::FileGet { .. } => files::get(&cap, &open.req, &mut s, &mut replied).await,
        OpenRequest::FilePut { .. } => files::put(&cap, &open.req, &mut s, &mut replied).await,
        OpenRequest::FileList { .. } => files::list(&cap, &open.req, &mut s, &mut replied).await,
        OpenRequest::ForwardL { .. } => net::forward_local(&cap, &open.req, &mut s, &mut replied).await,
        OpenRequest::ForwardR { .. } => {
            net::forward_remote(&ctx, &cap, &open.req, &mut s, &mut replied).await
        }
        OpenRequest::Egress { .. } => net::egress(&cap, &open.req, &mut s, &mut replied).await,
        OpenRequest::ForwardRConn { .. } | OpenRequest::Rpc(_) => {
            Err(perr(ErrorCode::BadRequest, "unsupported stream kind"))
        }
    };
    match r {
        Err(e) if !replied => fail(&mut s, e).await,
        Err(e) => tracing::info!(session = %cap.session, err = %e, "stream ended with error"),
        Ok(()) => tracing::info!(session = %cap.session, "stream finished"),
    }
}

async fn fail(s: &mut MuxStream, e: ProtoError) {
    let _ = write_msg(s, &OpenReply::Err(e)).await;
    let _ = s.shutdown().await;
}

/// Default configuration directory.
pub fn default_dir() -> PathBuf {
    #[cfg(unix)]
    {
        if std::env::var("USER").map(|u| u == "root").unwrap_or(false) {
            return PathBuf::from("/var/lib/cjs-device");
        }
    }
    dirs::config_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join("cjs-device")
}

/// Private per-session scratch directory under the config dir.
pub(crate) fn scratch_dir(base: &Path, session: &str) -> Result<PathBuf, ProtoError> {
    let safe: String = session
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '_')
        .collect();
    let d = base
        .join("scratch")
        .join(if safe.is_empty() { "s".into() } else { safe });
    std::fs::create_dir_all(&d).map_err(|e| perr(ErrorCode::Io, format!("scratch dir: {e}")))?;
    cjs_transport::profile::restrict_dir(&d);
    Ok(d)
}

/// Environment for sandboxed processes: a small allow-list copied from the
/// device's own environment (never secrets such as tokens), plus session
/// variables.
pub(crate) fn base_env(scratch: &Path, term: Option<&str>, cap: &Capability) -> Vec<(String, String)> {
    const KEEP: &[&str] = &[
        "PATH",
        "HOME",
        "USER",
        "LOGNAME",
        "SHELL",
        "LANG",
        "LC_ALL",
        "LC_CTYPE",
        "TZ",
        "SystemRoot",
        "SYSTEMROOT",
        "windir",
        "COMSPEC",
        "PATHEXT",
        "USERPROFILE",
        "USERNAME",
        "HOMEDRIVE",
        "HOMEPATH",
        "APPDATA",
        "LOCALAPPDATA",
        "ProgramData",
        "ProgramFiles",
        "ProgramFiles(x86)",
        "SystemDrive",
        "NUMBER_OF_PROCESSORS",
        "PROCESSOR_ARCHITECTURE",
        "OS",
    ];
    let mut env: Vec<(String, String)> = KEEP
        .iter()
        .filter_map(|k| std::env::var(k).ok().map(|v| (k.to_string(), v)))
        .collect();
    if !env.iter().any(|(k, _)| k == "PATH") {
        env.push(("PATH".into(), "/usr/local/bin:/usr/bin:/bin".into()));
    }
    let tmp = scratch.to_string_lossy().into_owned();
    for k in ["TMPDIR", "TEMP", "TMP"] {
        env.push((k.into(), tmp.clone()));
    }
    env.push((
        "HISTFILE".into(),
        scratch.join(".history").to_string_lossy().into_owned(),
    ));
    if let Some(t) = term {
        env.push(("TERM".into(), t.into()));
    }
    env.push(("CJS_SESSION".into(), cap.session.clone()));
    env.push(("CJS_PRINCIPAL".into(), cap.principal.clone()));
    env
}

/// Final argv for a shell or command: sandboxed unless full access was
/// approved. Fails closed when the sandbox is unavailable.
pub(crate) fn sandboxed_argv(
    ctx: &CtxRef,
    cap: &Capability,
    jail: &cjs_fsjail::Jail,
    scratch: &Path,
    argv: Vec<String>,
) -> Result<Vec<String>, ProtoError> {
    if cap.full_access {
        return Ok(argv);
    }
    if let Err(e) = &ctx.sandbox {
        return Err(perr(ErrorCode::SandboxUnavailable, e.clone()));
    }
    let policy = cjs_sandbox::Policy {
        write_roots: jail.roots(),
        temp_dir: Some(scratch.to_path_buf()),
    };
    cjs_sandbox::wrap(&ctx.opts.helper, &policy, &argv)
        .map_err(|e| perr(ErrorCode::SandboxUnavailable, e.to_string()))
}

pub(crate) fn default_shell() -> Vec<String> {
    #[cfg(windows)]
    {
        vec![std::env::var("COMSPEC").unwrap_or_else(|_| "cmd.exe".into())]
    }
    #[cfg(not(windows))]
    {
        let sh = std::env::var("SHELL")
            .ok()
            .filter(|s| Path::new(s).is_absolute() && Path::new(s).exists())
            .or_else(|| {
                ["/bin/bash", "/bin/zsh", "/bin/sh"]
                    .iter()
                    .find(|p| Path::new(p).exists())
                    .map(|s| s.to_string())
            })
            .unwrap_or_else(|| "/bin/sh".into());
        vec![sh, "-i".into()]
    }
}
