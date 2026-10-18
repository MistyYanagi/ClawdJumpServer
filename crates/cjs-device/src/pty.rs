//! Interactive terminals (portable-pty), sandboxed.
use std::io::{Read, Write};
use std::time::Duration;

use cjs_fsjail::Jail;
use cjs_mux::{read_msg, write_msg, MuxStream};
use cjs_proto::{
    Capability, ErrorCode, OpenRequest, ProtoError, PtyIn, PtyOut, MAX_DATA_CHUNK, MAX_TERM_DIM,
};
use portable_pty::{native_pty_system, CommandBuilder, PtySize};
use tokio::io::AsyncWriteExt;
use tokio::sync::{mpsc, oneshot};

use crate::{base_env, default_shell, perr, reply_ok, sandboxed_argv, scratch_dir, CtxRef};

fn pe(e: impl std::fmt::Display) -> ProtoError {
    perr(ErrorCode::Io, format!("pty: {e}"))
}

pub(crate) async fn run(
    ctx: &CtxRef,
    cap: &Capability,
    req: &OpenRequest,
    s: &mut MuxStream,
    replied: &mut bool,
) -> Result<(), ProtoError> {
    let OpenRequest::Pty {
        cols,
        rows,
        term,
        command,
        cwd,
        ..
    } = req
    else {
        return Err(perr(ErrorCode::BadRequest, "not a pty request"));
    };
    let jail = Jail::new(&cap.roots, cap.full_access)?;
    let cwd = jail.cwd(cwd.as_deref())?;
    let scratch = scratch_dir(&ctx.opts.dir, &cap.session)?;
    let pair = native_pty_system()
        .openpty(PtySize {
            rows: *rows,
            cols: *cols,
            pixel_width: 0,
            pixel_height: 0,
        })
        .map_err(pe)?;
    // Only this session's terminal is writable inside the sandbox.
    #[cfg(unix)]
    let tty = pair.master.tty_name();
    #[cfg(not(unix))]
    let tty: Option<std::path::PathBuf> = None;
    let argv = command.clone().unwrap_or_else(default_shell);
    let argv = sandboxed_argv(ctx, cap, &jail, &scratch, tty, argv)?;
    let mut cmd = CommandBuilder::new(&argv[0]);
    cmd.args(&argv[1..]);
    cmd.cwd(&cwd);
    cmd.env_clear();
    for (k, v) in base_env(&scratch, Some(term), cap) {
        cmd.env(k, v);
    }
    let mut child = pair.slave.spawn_command(cmd).map_err(pe)?;
    drop(pair.slave);
    let mut killer = child.clone_killer();
    let master = pair.master;
    let mut reader = master.try_clone_reader().map_err(pe)?;
    let mut writer = master.take_writer().map_err(pe)?;

    // Blocking PTY I/O lives on threads; the async side talks to them
    // through channels.
    let (out_tx, mut out_rx) = mpsc::channel::<Vec<u8>>(16);
    std::thread::spawn(move || {
        let mut buf = vec![0u8; MAX_DATA_CHUNK];
        loop {
            match reader.read(&mut buf) {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    if out_tx.blocking_send(buf[..n].to_vec()).is_err() {
                        break;
                    }
                }
            }
        }
    });
    let (in_tx, in_rx) = std::sync::mpsc::channel::<Vec<u8>>();
    std::thread::spawn(move || {
        while let Ok(b) = in_rx.recv() {
            if writer.write_all(&b).and_then(|_| writer.flush()).is_err() {
                break;
            }
        }
    });
    let (exit_tx, mut exit_rx) = oneshot::channel::<Option<i32>>();
    std::thread::spawn(move || {
        let code = child.wait().ok().map(|st| st.exit_code() as i32);
        let _ = exit_tx.send(code);
    });

    reply_ok(s, 0, cap).await?;
    *replied = true;
    let (mut r, mut w) = tokio::io::split(s);
    let mut input_open = true;
    let mut exit: Option<Option<i32>> = None;
    let res: Result<(), ProtoError> = loop {
        tokio::select! {
            m = read_msg::<_, PtyIn>(&mut r), if input_open => match m {
                Ok(Some(PtyIn::Input(b))) => {
                    if in_tx.send(b).is_err() {
                        input_open = false;
                    }
                }
                Ok(Some(PtyIn::Resize { cols, rows })) => {
                    if cols > 0 && rows > 0 && cols <= MAX_TERM_DIM && rows <= MAX_TERM_DIM {
                        let _ = master.resize(PtySize { rows, cols, pixel_width: 0, pixel_height: 0 });
                    }
                }
                // Agent hung up (or the stream broke): hang up the shell.
                Ok(None) | Err(_) => {
                    input_open = false;
                    let _ = killer.kill();
                }
            },
            b = out_rx.recv() => match b {
                Some(b) => {
                    if let Err(e) = write_msg(&mut w, &PtyOut::Output(b)).await {
                        let _ = killer.kill();
                        break Err(e);
                    }
                }
                None => {
                    // Output closed: the session is over once the child exits.
                    let code = tokio::time::timeout(Duration::from_secs(5), &mut exit_rx).await;
                    if code.is_err() {
                        let _ = killer.kill();
                    }
                    exit = Some(code.ok().and_then(|c| c.ok()).flatten());
                    break Ok(());
                }
            },
            c = &mut exit_rx, if exit.is_none() => {
                exit = Some(c.ok().flatten());
                // Drain what is left (background jobs may keep the pty open).
                let deadline = tokio::time::Instant::now() + Duration::from_millis(500);
                while let Ok(Some(b)) = tokio::time::timeout_at(deadline, out_rx.recv()).await {
                    if write_msg(&mut w, &PtyOut::Output(b)).await.is_err() {
                        break;
                    }
                }
                break Ok(());
            }
        }
    };
    drop(in_tx);
    drop(master);
    let _ = write_msg(&mut w, &PtyOut::Exit { code: exit.flatten() }).await;
    let _ = w.shutdown().await;
    let _ = std::fs::remove_dir_all(&scratch);
    res
}
