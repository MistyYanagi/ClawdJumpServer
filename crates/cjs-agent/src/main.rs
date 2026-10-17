//! `cjs`: the ClawdJumpServer agent CLI.
use std::path::PathBuf;

use cjs_agent::project::Project;
use cjs_agent::{default_dir, local, mcp, ops, proxy, split_remote, term, Opener, VERSION};
use cjs_proto::{ErrorCode, ExecOut, OpenRequest, ProtoError, Role, RpcRequest, RpcResponse};
use cjs_transport::TransportMode;
use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "cjs", version, about = "ClawdJumpServer agent CLI")]
struct Cli {
    /// Configuration directory (identity key, profile, daemon socket).
    #[arg(long, global = true, env = "CJS_CONFIG_DIR")]
    config: Option<PathBuf>,
    /// Connect directly even if a daemon is running.
    #[arg(long, global = true)]
    direct: bool,
    /// Device to use (default: `device` from .cjs.toml).
    #[arg(short = 'd', long, global = true, env = "CJS_DEVICE")]
    device: Option<String>,
    /// Machine-readable JSON output.
    #[arg(long, global = true)]
    json: bool,
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Register this agent with a one-time enrollment token.
    Enroll {
        #[arg(long)]
        server: String,
        #[arg(long, env = "CJS_ENROLL_TOKEN")]
        token: String,
        #[arg(long, default_value = "auto")]
        transport: TransportMode,
        #[arg(long)]
        ca: Option<PathBuf>,
    },
    /// Keep a connection open and serve other `cjs` invocations.
    Daemon,
    /// Show connection status.
    Status,
    /// Show the identity this agent authenticates as.
    Whoami,
    /// List devices this agent may use.
    Devices,
    /// Interactive shell on a device.
    Shell {
        #[arg(long)]
        cwd: Option<String>,
        /// Command to run instead of the login shell.
        #[arg(last = true)]
        command: Vec<String>,
    },
    /// Run a command on a device.
    Exec {
        #[arg(long)]
        cwd: Option<String>,
        /// Environment variable (repeatable).
        #[arg(long = "env", value_name = "K=V")]
        env: Vec<String>,
        /// Kill the command after this many seconds.
        #[arg(long)]
        timeout: Option<u64>,
        #[arg(required = true, last = true)]
        argv: Vec<String>,
    },
    /// Copy files: `cjs cp local dev:remote` or `cjs cp dev:remote local`.
    Cp {
        /// Continue an interrupted transfer.
        #[arg(long)]
        resume: bool,
        /// Create missing remote directories.
        #[arg(long)]
        mkdirs: bool,
        /// Copy a directory tree (symlinks are skipped, never followed).
        #[arg(short = 'r', long)]
        recursive: bool,
        src: String,
        dst: String,
    },
    /// List a remote directory.
    Ls { path: Option<String> },
    /// Port forwarding.
    Forward {
        /// `[bind:]lport:host:rport` — local port to host:rport seen from the device.
        #[arg(short = 'L', conflicts_with = "remote")]
        local: Option<String>,
        /// `[bind:]rport:lhost:lport` — device port back to lhost:lport here.
        #[arg(short = 'R')]
        remote: Option<String>,
    },
    /// Local SOCKS5 / HTTP proxy whose traffic egresses via the server.
    /// Prints `export` lines (with generated credentials) on stdout, or
    /// writes them to `--env-file` (mode 0600) for `. FILE`.
    Proxy {
        #[arg(long, default_value = "127.0.0.1:1080")]
        listen: String,
        /// Exit through this device instead of the server.
        #[arg(long)]
        via: Option<String>,
        /// Accept clients without credentials (any local process can then
        /// use this agent's identity).
        #[arg(long)]
        no_auth: bool,
        /// Write the export lines to this file (mode 0600) instead of stdout.
        #[arg(long)]
        env_file: Option<PathBuf>,
    },
    /// MCP server on stdio exposing ClawdJumpServer tools.
    Mcp,
}

fn fail(json: bool, e: &ProtoError) -> i32 {
    if json {
        println!(
            "{}",
            serde_json::json!({"error": {"code": e.code.as_str(), "message": e.message}})
        );
    } else {
        eprintln!("error: {}: {}", e.code, e.message);
    }
    e.code.exit_code()
}

fn bad(m: impl Into<String>) -> ProtoError {
    ProtoError::new(ErrorCode::BadRequest, m)
}

fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "warn".into()),
        )
        .with_writer(std::io::stderr)
        .init();
    let cli = Cli::parse();
    let rt = tokio::runtime::Runtime::new().expect("tokio runtime");
    let json = cli.json;
    let code = rt.block_on(async move {
        match run(cli).await {
            Ok(c) => c,
            Err(e) => fail(json, &e),
        }
    });
    std::process::exit(code);
}

async fn run(cli: Cli) -> Result<i32, ProtoError> {
    let dir = cli.config.clone().unwrap_or_else(default_dir);
    let project = Project::find(&std::env::current_dir().unwrap_or_default()).map_err(bad)?;
    let device = || -> Result<String, ProtoError> {
        cli.device
            .clone()
            .or_else(|| project.device.clone())
            .ok_or_else(|| bad("no device: pass -d DEVICE or set `device` in .cjs.toml"))
    };
    let opener = || Opener::new(&dir, cli.direct);
    match &cli.cmd {
        Cmd::Enroll {
            server,
            token,
            transport,
            ca,
        } => {
            let p = cjs_transport::profile::enroll(
                &dir,
                Role::Agent,
                server,
                token,
                *transport,
                ca.clone(),
                VERSION,
            )
            .await?;
            if cli.json {
                println!(
                    "{}",
                    serde_json::json!({"id": p.id, "name": p.name, "config": dir})
                );
            } else {
                println!(
                    "enrolled as agent {} ({}); config in {}",
                    p.name,
                    p.id,
                    dir.display()
                );
            }
            Ok(0)
        }
        Cmd::Daemon => {
            local::run_daemon(&dir).await?;
            Ok(0)
        }
        Cmd::Status => {
            let op = opener().await?;
            let st = op.status().await?;
            let mode = match op {
                Opener::Direct(_) => "direct",
                Opener::Daemon { .. } => "daemon",
            };
            if cli.json {
                println!("{}", serde_json::json!({"mode": mode, "status": st}));
            } else {
                println!(
                    "{} as {} ({}) to {} over {} [{mode}]",
                    if st.connected { "connected" } else { "disconnected" },
                    st.name,
                    st.principal,
                    st.server,
                    st.transport
                );
            }
            Ok(0)
        }
        Cmd::Whoami => {
            let op = opener().await?;
            match ops::rpc(&op, RpcRequest::WhoAmI).await? {
                RpcResponse::WhoAmI {
                    principal_id,
                    name,
                    owner,
                } => {
                    if cli.json {
                        println!(
                            "{}",
                            serde_json::json!({"id": principal_id, "name": name, "owner": owner})
                        );
                    } else {
                        println!("{name} ({principal_id}), owner {}", owner.unwrap_or_default());
                    }
                    Ok(0)
                }
                _ => Err(ProtoError::new(ErrorCode::Protocol, "unexpected reply")),
            }
        }
        Cmd::Devices => {
            let op = opener().await?;
            let ds = ops::devices(&op).await?;
            if cli.json {
                println!("{}", serde_json::to_string_pretty(&ds).unwrap_or_default());
            } else {
                println!(
                    "{:<20} {:<8} {:<10} {:<40} ROOTS",
                    "NAME", "STATE", "OS", "ACTIONS"
                );
                for d in ds {
                    let actions: Vec<_> = d.actions.iter().map(|a| a.as_str()).collect();
                    println!(
                        "{:<20} {:<8} {:<10} {:<40} {}{}",
                        d.name,
                        if d.online { "online" } else { "offline" },
                        d.os,
                        actions.join(","),
                        d.roots.join(","),
                        if d.full_access { " [FULL ACCESS]" } else { "" }
                    );
                }
            }
            Ok(0)
        }
        Cmd::Shell { cwd, command } => {
            let op = opener().await?;
            let cwd = cwd.clone().or_else(|| project.cwd.clone());
            let cmd = (!command.is_empty()).then(|| command.clone());
            let code = term::shell(&op, device()?, cwd, cmd).await?;
            Ok(code.unwrap_or(1))
        }
        Cmd::Exec {
            cwd,
            env,
            timeout,
            argv,
        } => {
            let mut envs = Vec::new();
            for kv in env {
                let (k, v) = kv
                    .split_once('=')
                    .ok_or_else(|| bad(format!("--env {kv}: expected K=V")))?;
                envs.push((k.to_string(), v.to_string()));
            }
            let req = OpenRequest::Exec {
                device: device()?,
                argv: argv.clone(),
                cwd: cwd.clone().or_else(|| project.cwd.clone()),
                env: envs,
                timeout_secs: *timeout,
            };
            let op = opener().await?;
            use std::io::IsTerminal;
            let stdin_data = if std::io::stdin().is_terminal() {
                None
            } else {
                Some(tokio::io::stdin())
            };
            if cli.json {
                let mut data = Vec::new();
                if let Some(mut s) = stdin_data {
                    use tokio::io::AsyncReadExt;
                    s.read_to_end(&mut data)
                        .await
                        .map_err(|e| ProtoError::new(ErrorCode::Io, e.to_string()))?;
                }
                let r = ops::exec_collect(&op, &req, Some(data), 64 * 1024 * 1024).await?;
                println!("{}", serde_json::to_string(&r).unwrap_or_default());
                return Ok(r.exit_code.unwrap_or(1));
            }
            use std::io::Write;
            // Output going to a terminal gets the same clipboard filter as
            // interactive shells; pipes and files receive the exact bytes.
            let mut fo = std::io::stdout().is_terminal().then(term::OutputFilter::default);
            let mut fe = std::io::stderr().is_terminal().then(term::OutputFilter::default);
            fn emit(w: &mut dyn Write, f: &mut Option<term::OutputFilter>, b: &[u8]) {
                match f {
                    Some(f) => {
                        let mut v = Vec::with_capacity(b.len());
                        f.feed(b, &mut v);
                        let _ = w.write_all(&v);
                    }
                    None => {
                        let _ = w.write_all(b);
                    }
                }
                let _ = w.flush();
            }
            let r = ops::exec_stream(&op, &req, stdin_data, |m| match m {
                ExecOut::Stdout(b) => emit(&mut std::io::stdout(), &mut fo, b),
                ExecOut::Stderr(b) => emit(&mut std::io::stderr(), &mut fe, b),
                ExecOut::Exit { .. } => {}
            })
            .await?;
            for (w, f) in [
                (&mut std::io::stdout() as &mut dyn Write, &mut fo),
                (&mut std::io::stderr() as &mut dyn Write, &mut fe),
            ] {
                if let Some(f) = f {
                    let mut v = Vec::new();
                    f.finish(&mut v);
                    let _ = w.write_all(&v);
                    let _ = w.flush();
                }
            }
            if r.timed_out {
                eprintln!("cjs: command timed out");
            }
            Ok(r.exit_code.unwrap_or(1))
        }
        Cmd::Cp {
            resume,
            mkdirs,
            recursive,
            src,
            dst,
        } => {
            let op = opener().await?;
            let dev = |d: Option<&str>| d.map(String::from).map(Ok).unwrap_or_else(device);
            if *recursive {
                let t = match (split_remote(src), split_remote(dst)) {
                    (Some((d, rp)), None) => {
                        ops::download_tree(&op, &dev(d)?, rp, std::path::Path::new(dst), *resume).await?
                    }
                    (None, Some((d, rp))) => {
                        ops::upload_tree(&op, &dev(d)?, std::path::Path::new(src), rp, *resume).await?
                    }
                    _ => return Err(bad("exactly one of SRC and DST must be remote (device:path)")),
                };
                if cli.json {
                    println!("{}", serde_json::to_string(&t).unwrap_or_default());
                } else {
                    eprintln!(
                        "{} files, {} directories, {} bytes{}",
                        t.files.len(),
                        t.dirs,
                        t.bytes,
                        if t.skipped.is_empty() {
                            String::new()
                        } else {
                            format!(
                                "; skipped {} (symlinks/special): {}",
                                t.skipped.len(),
                                t.skipped.join(", ")
                            )
                        }
                    );
                }
                return Ok(0);
            }
            let t = match (split_remote(src), split_remote(dst)) {
                (Some((d, rp)), None) => {
                    ops::download(&op, &dev(d)?, rp, std::path::Path::new(dst), *resume).await?
                }
                (None, Some((d, rp))) => {
                    ops::upload(&op, &dev(d)?, std::path::Path::new(src), rp, *resume, *mkdirs).await?
                }
                _ => return Err(bad("exactly one of SRC and DST must be remote (device:path)")),
            };
            if cli.json {
                println!("{}", serde_json::to_string(&t).unwrap_or_default());
            } else {
                eprintln!(
                    "{} bytes ({} transferred{}), sha256 {}",
                    t.size,
                    t.transferred,
                    if t.resumed_from > 0 {
                        format!(", resumed at {}", t.resumed_from)
                    } else {
                        String::new()
                    },
                    t.sha256
                );
            }
            Ok(0)
        }
        Cmd::Ls { path } => {
            let op = opener().await?;
            let (d, p) = match path.as_deref().and_then(split_remote) {
                Some((d, p)) => (d.map(String::from), p.to_string()),
                None => (
                    None,
                    path.clone()
                        .or_else(|| project.cwd.clone())
                        .unwrap_or_else(|| ".".into()),
                ),
            };
            let d = match d {
                Some(d) => d,
                None => device()?,
            };
            let (me, entries) = ops::list(&op, &d, &p).await?;
            if cli.json {
                println!("{}", serde_json::json!({"path": me, "entries": entries}));
            } else if entries.is_empty() && me.kind != cjs_proto::EntryKind::Dir {
                println!("{:>12} {}", me.size, me.name);
            } else {
                for e in entries {
                    let k = match e.kind {
                        cjs_proto::EntryKind::Dir => 'd',
                        cjs_proto::EntryKind::Symlink => 'l',
                        cjs_proto::EntryKind::File => '-',
                        cjs_proto::EntryKind::Other => '?',
                    };
                    println!("{k}{:04o} {:>12} {}", e.mode & 0o7777, e.size, e.name);
                }
            }
            Ok(0)
        }
        Cmd::Forward { local, remote } => {
            let op = opener().await?;
            let d = device()?;
            if let Some(spec) = local {
                let (bind, lport, host, rport) = parse_forward(spec)?;
                ops::forward_local(op, &format!("{bind}:{lport}"), d, host, rport).await?;
                Ok(0)
            } else if let Some(spec) = remote {
                let (bind, rport, lhost, lport) = parse_forward(spec)?;
                let req = OpenRequest::ForwardR {
                    device: d.clone(),
                    bind_host: bind.clone(),
                    bind_port: rport,
                };
                let (mut ctl, _o, _g) = op.forward_remote(&req, &lhost, lport).await?;
                eprintln!("forwarding {d}:{bind}:{rport} -> {lhost}:{lport} (Ctrl-C to stop)");
                let mut b = [0u8; 16];
                use tokio::io::AsyncReadExt;
                tokio::select! {
                    _ = ctl.read(&mut b) => eprintln!("forward closed by server"),
                    _ = tokio::signal::ctrl_c() => {}
                }
                Ok(0)
            } else {
                Err(bad("give -L or -R"))
            }
        }
        Cmd::Proxy {
            listen,
            via,
            no_auth,
            env_file,
        } => {
            let op = opener().await?;
            let auth = (!*no_auth).then(proxy::Auth::generate);
            proxy::run(op, listen, via.clone(), auth, env_file.clone()).await?;
            Ok(0)
        }
        Cmd::Mcp => {
            let op = opener().await?;
            mcp::serve(op, project.clone()).await?;
            Ok(0)
        }
    }
}

/// `[bind:]port:host:port` -> (bind, port, host, port). IPv6 hosts in [].
fn parse_forward(spec: &str) -> Result<(String, u16, String, u16), ProtoError> {
    let mut parts: Vec<String> = Vec::new();
    let mut cur = String::new();
    let mut depth = 0;
    for c in spec.chars() {
        match c {
            '[' => {
                depth += 1;
                cur.push(c)
            }
            ']' => {
                depth -= 1;
                cur.push(c)
            }
            ':' if depth == 0 => parts.push(std::mem::take(&mut cur)),
            _ => cur.push(c),
        }
    }
    parts.push(cur);
    let port = |s: &str| {
        s.parse::<u16>()
            .map_err(|_| bad(format!("bad port {s:?} in {spec:?}")))
    };
    match parts.as_slice() {
        [p1, h, p2] => Ok(("127.0.0.1".into(), port(p1)?, h.clone(), port(p2)?)),
        [b, p1, h, p2] => Ok((b.clone(), port(p1)?, h.clone(), port(p2)?)),
        _ => Err(bad(format!(
            "bad forward spec {spec:?}: expected [bind:]port:host:port"
        ))),
    }
}
