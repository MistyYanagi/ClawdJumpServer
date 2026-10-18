//! Non-interactive commands with separate stdout/stderr, sandboxed.
use std::process::Stdio;
use std::time::Duration;

use cjs_fsjail::Jail;
use cjs_mux::{read_msg, write_msg, MuxStream};
use cjs_proto::{
    check_env_name, Capability, ErrorCode, ExecIn, ExecOut, OpenRequest, ProtoError, MAX_DATA_CHUNK,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::process::Command;
use tokio::sync::mpsc;

use crate::{base_env, perr, reply_ok, sandboxed_argv, scratch_dir, CtxRef};

enum Out {
    Stdout(Vec<u8>),
    Stderr(Vec<u8>),
}

fn spawn_reader<R: tokio::io::AsyncRead + Unpin + Send + 'static>(
    mut r: R,
    tx: mpsc::Sender<Out>,
    stdout: bool,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut buf = vec![0u8; MAX_DATA_CHUNK];
        loop {
            match r.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    let b = buf[..n].to_vec();
                    let m = if stdout { Out::Stdout(b) } else { Out::Stderr(b) };
                    if tx.send(m).await.is_err() {
                        break;
                    }
                }
            }
        }
    })
}

/// Ask the process to stop. The sandbox helper then kills everything the
/// command started; it gets a grace period before SIGKILL ([`KILL_GRACE`]).
fn terminate(child: &mut tokio::process::Child) {
    #[cfg(unix)]
    {
        if let Some(id) = child.id() {
            use nix::sys::signal::{kill, Signal};
            if kill(nix::unistd::Pid::from_raw(id as i32), Signal::SIGTERM).is_ok() {
                return;
            }
        }
    }
    let _ = child.start_kill();
}

const KILL_GRACE: Duration = Duration::from_secs(3);

#[cfg(unix)]
fn signal_of(st: &std::process::ExitStatus) -> Option<String> {
    use std::os::unix::process::ExitStatusExt;
    st.signal().map(|s| format!("SIG{s}"))
}

#[cfg(not(unix))]
fn signal_of(_: &std::process::ExitStatus) -> Option<String> {
    None
}

pub(crate) async fn run(
    ctx: &CtxRef,
    cap: &Capability,
    req: &OpenRequest,
    s: &mut MuxStream,
    replied: &mut bool,
) -> Result<(), ProtoError> {
    let OpenRequest::Exec {
        argv,
        cwd,
        env,
        timeout_secs,
        ..
    } = req
    else {
        return Err(perr(ErrorCode::BadRequest, "not an exec request"));
    };
    // Re-checked here: the device does not rely on the server's validation.
    for (k, _) in env {
        check_env_name(k)?;
    }
    let jail = Jail::new(&cap.roots, cap.full_access)?;
    let cwd = jail.cwd(cwd.as_deref())?;
    let scratch = scratch_dir(&ctx.opts.dir, &cap.session)?;
    let full = sandboxed_argv(ctx, cap, &jail, &scratch, None, argv.clone())?;
    let mut cmd = Command::new(&full[0]);
    cmd.args(&full[1..])
        .current_dir(&cwd)
        .env_clear()
        .envs(base_env(&scratch, None, cap))
        .envs(env.iter().cloned())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    let mut child = cmd
        .spawn()
        .map_err(|e| perr(ErrorCode::NotFound, format!("cannot start {}: {e}", argv[0])))?;
    let mut stdin = child.stdin.take();
    let (tx, mut rx) = mpsc::channel::<Out>(16);
    let r1 = spawn_reader(child.stdout.take().expect("piped"), tx.clone(), true);
    let r2 = spawn_reader(child.stderr.take().expect("piped"), tx, false);

    reply_ok(s, 0, cap).await?;
    *replied = true;
    let (mut r, mut w) = tokio::io::split(s);
    let deadline = timeout_secs.map(|t| tokio::time::Instant::now() + Duration::from_secs(t));
    let timeout = async {
        match deadline {
            Some(d) => tokio::time::sleep_until(d).await,
            None => std::future::pending().await,
        }
    };
    tokio::pin!(timeout);
    let mut input_open = true;
    let mut timed_out = false;
    let mut status = None;
    let mut outputs_open = true;
    // Set once we asked the process to stop; SIGKILL follows after the grace.
    let mut kill_at: Option<tokio::time::Instant> = None;
    let res: Result<(), ProtoError> = loop {
        if status.is_some() && !outputs_open {
            break Ok(());
        }
        tokio::select! {
            m = read_msg::<_, ExecIn>(&mut r), if input_open => match m {
                Ok(Some(ExecIn::Stdin(b))) => {
                    if let Some(si) = stdin.as_mut() {
                        if si.write_all(&b).await.is_err() {
                            stdin = None;
                        }
                    }
                }
                Ok(Some(ExecIn::StdinEof)) | Ok(None) => {
                    // A clean half-close only ends stdin.
                    stdin = None;
                    if m.as_ref().map(|x| x.is_none()).unwrap_or(false) {
                        input_open = false;
                    }
                }
                Ok(Some(ExecIn::Kill)) => {
                    terminate(&mut child);
                    kill_at.get_or_insert(tokio::time::Instant::now() + KILL_GRACE);
                }
                Err(_) => {
                    // Stream broken: the agent is gone.
                    input_open = false;
                    terminate(&mut child);
                    kill_at.get_or_insert(tokio::time::Instant::now() + KILL_GRACE);
                }
            },
            o = rx.recv(), if outputs_open => match o {
                Some(o) => {
                    let m = match o {
                        Out::Stdout(b) => ExecOut::Stdout(b),
                        Out::Stderr(b) => ExecOut::Stderr(b),
                    };
                    if let Err(e) = write_msg(&mut w, &m).await {
                        break Err(e);
                    }
                }
                None => outputs_open = false,
            },
            st = child.wait(), if status.is_none() => {
                status = Some(st.map_err(|e| perr(ErrorCode::Io, e.to_string()))?);
                // Descendants may keep the pipes open; do not wait forever.
                let grace = tokio::time::sleep(Duration::from_millis(500));
                tokio::pin!(grace);
                while outputs_open {
                    tokio::select! {
                        o = rx.recv() => match o {
                            Some(Out::Stdout(b)) => { let _ = write_msg(&mut w, &ExecOut::Stdout(b)).await; }
                            Some(Out::Stderr(b)) => { let _ = write_msg(&mut w, &ExecOut::Stderr(b)).await; }
                            None => outputs_open = false,
                        },
                        _ = &mut grace => break,
                    }
                }
                break Ok(());
            },
            _ = &mut timeout, if !timed_out => {
                timed_out = true;
                terminate(&mut child);
                kill_at.get_or_insert(tokio::time::Instant::now() + KILL_GRACE);
            }
            _ = async { tokio::time::sleep_until(kill_at.expect("guarded")).await }, if kill_at.is_some() && status.is_none() => {
                let _ = child.start_kill();
                kill_at = None;
            }
        }
    };
    r1.abort();
    r2.abort();
    let status = match status {
        Some(s) => Some(s),
        None => {
            terminate(&mut child);
            match tokio::time::timeout(KILL_GRACE, child.wait()).await {
                Ok(st) => st.ok(),
                Err(_) => {
                    let _ = child.start_kill();
                    child.wait().await.ok()
                }
            }
        }
    };
    let _ = write_msg(
        &mut w,
        &ExecOut::Exit {
            code: status.as_ref().and_then(|s| s.code()),
            signal: status.as_ref().and_then(signal_of),
            timed_out,
        },
    )
    .await;
    let _ = w.shutdown().await;
    let _ = std::fs::remove_dir_all(&scratch);
    res
}
