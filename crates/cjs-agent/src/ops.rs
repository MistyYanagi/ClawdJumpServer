//! Operations shared by the CLI and the MCP server.
use std::path::Path;
use std::time::Duration;

use cjs_mux::{expect_msg, read_msg, write_msg};
use cjs_proto::{
    DeviceSummary, DirEntry, ErrorCode, ExecIn, ExecOut, FileMsg, OpenRequest, ProtoError, RpcRequest,
    RpcResponse, MAX_DATA_CHUNK,
};
use serde::Serialize;
use sha2::{Digest, Sha256};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncSeekExt, AsyncWriteExt};

use crate::local::Opener;

fn ioe(e: std::io::Error) -> ProtoError {
    ProtoError::new(ErrorCode::Io, e.to_string())
}

pub async fn rpc(op: &Opener, req: RpcRequest) -> Result<RpcResponse, ProtoError> {
    let (mut s, _) = op.open(&OpenRequest::Rpc(req)).await?;
    match expect_msg::<_, RpcResponse>(&mut s).await? {
        RpcResponse::Error(e) => Err(e),
        r => Ok(r),
    }
}

pub async fn devices(op: &Opener) -> Result<Vec<DeviceSummary>, ProtoError> {
    match rpc(op, RpcRequest::ListDevices).await? {
        RpcResponse::Devices(d) => Ok(d),
        _ => Err(ProtoError::new(ErrorCode::Protocol, "unexpected reply")),
    }
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct ExecResult {
    pub session: String,
    pub stdout: String,
    pub stderr: String,
    /// True when output beyond the collection limit was dropped.
    pub truncated: bool,
    pub exit_code: Option<i32>,
    pub signal: Option<String>,
    pub timed_out: bool,
}

/// Run a command, streaming its output through `on_out`. `stdin` (if any)
/// is forwarded to the remote process.
pub async fn exec_stream<R, F>(
    op: &Opener,
    req: &OpenRequest,
    stdin: Option<R>,
    mut on_out: F,
) -> Result<ExecResult, ProtoError>
where
    R: AsyncRead + Unpin + Send + 'static,
    F: FnMut(&ExecOut),
{
    let (s, opened) = op.open(req).await?;
    let (mut r, mut w) = tokio::io::split(s);
    let feeder = tokio::spawn(async move {
        if let Some(mut stdin) = stdin {
            let mut buf = vec![0u8; MAX_DATA_CHUNK];
            loop {
                match stdin.read(&mut buf).await {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        if write_msg(&mut w, &ExecIn::Stdin(buf[..n].to_vec()))
                            .await
                            .is_err()
                        {
                            return w;
                        }
                    }
                }
            }
        }
        let _ = write_msg(&mut w, &ExecIn::StdinEof).await;
        w
    });
    let mut res = ExecResult {
        session: opened.session,
        ..Default::default()
    };
    let mut got_exit = false;
    while let Some(m) = read_msg::<_, ExecOut>(&mut r).await? {
        on_out(&m);
        if let ExecOut::Exit {
            code,
            signal,
            timed_out,
        } = m
        {
            res.exit_code = code;
            res.signal = signal;
            res.timed_out = timed_out;
            got_exit = true;
            break;
        }
    }
    feeder.abort();
    if !got_exit {
        return Err(ProtoError::new(
            ErrorCode::Io,
            "connection lost before the command finished",
        ));
    }
    Ok(res)
}

/// Run a command and collect its output (up to `limit` bytes per stream).
pub async fn exec_collect(
    op: &Opener,
    req: &OpenRequest,
    stdin: Option<Vec<u8>>,
    limit: usize,
) -> Result<ExecResult, ProtoError> {
    let mut out = Vec::new();
    let mut err = Vec::new();
    let mut truncated = false;
    let stdin = stdin.map(std::io::Cursor::new);
    let mut res = exec_stream(op, req, stdin, |m| match m {
        ExecOut::Stdout(b) => {
            if out.len() + b.len() > limit {
                truncated = true;
            } else {
                out.extend_from_slice(b);
            }
        }
        ExecOut::Stderr(b) => {
            if err.len() + b.len() > limit {
                truncated = true;
            } else {
                err.extend_from_slice(b);
            }
        }
        ExecOut::Exit { .. } => {}
    })
    .await?;
    res.stdout = String::from_utf8_lossy(&out).into_owned();
    res.stderr = String::from_utf8_lossy(&err).into_owned();
    res.truncated = truncated;
    Ok(res)
}

pub async fn list(op: &Opener, device: &str, path: &str) -> Result<(DirEntry, Vec<DirEntry>), ProtoError> {
    let (mut s, _) = op
        .open(&OpenRequest::FileList {
            device: device.into(),
            path: path.into(),
        })
        .await?;
    let _ = s.shutdown().await;
    let mut me = None;
    let mut entries = Vec::new();
    while let Some(m) = read_msg::<_, FileMsg>(&mut s).await? {
        match m {
            FileMsg::Stat(e) => me = Some(e),
            FileMsg::Entries(e) => entries.extend(e),
            FileMsg::End { .. } => break,
            _ => return Err(ProtoError::new(ErrorCode::Protocol, "unexpected message")),
        }
    }
    let me = me.ok_or_else(|| ProtoError::new(ErrorCode::Protocol, "no stat"))?;
    Ok((me, entries))
}

#[derive(Debug, Clone, Serialize)]
pub struct Transfer {
    pub session: String,
    pub size: u64,
    pub transferred: u64,
    pub sha256: String,
    pub resumed_from: u64,
}

async fn file_sha(path: &Path) -> Result<String, ProtoError> {
    let mut f = tokio::fs::File::open(path).await.map_err(ioe)?;
    let mut h = Sha256::new();
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        let n = f.read(&mut buf).await.map_err(ioe)?;
        if n == 0 {
            break;
        }
        h.update(&buf[..n]);
    }
    Ok(hex::encode(h.finalize()))
}

/// Download `device:remote` to `local`. With `resume`, an existing partial
/// file is continued. The whole-file SHA-256 is verified.
pub async fn download(
    op: &Opener,
    device: &str,
    remote: &str,
    local: &Path,
    resume: bool,
) -> Result<Transfer, ProtoError> {
    let offset = if resume {
        tokio::fs::metadata(local).await.map(|m| m.len()).unwrap_or(0)
    } else {
        0
    };
    let (mut s, opened) = op
        .open(&OpenRequest::FileGet {
            device: device.into(),
            path: remote.into(),
            offset,
        })
        .await?;
    let _ = s.shutdown().await;
    let size = match expect_msg::<_, FileMsg>(&mut s).await? {
        FileMsg::Meta { size, .. } => size,
        _ => return Err(ProtoError::new(ErrorCode::Protocol, "expected file metadata")),
    };
    let part = local.with_extension(match local.extension() {
        Some(e) => format!("{}.cjs-part", e.to_string_lossy()),
        None => "cjs-part".into(),
    });
    // Resume writes in place; fresh downloads go to a temp file first.
    let target = if offset > 0 {
        local.to_path_buf()
    } else {
        part.clone()
    };
    let mut f = tokio::fs::OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(offset == 0)
        .open(&target)
        .await
        .map_err(ioe)?;
    f.seek(std::io::SeekFrom::Start(offset)).await.map_err(ioe)?;
    let mut got = 0u64;
    let remote_sha = loop {
        match read_msg::<_, FileMsg>(&mut s).await? {
            Some(FileMsg::Chunk(b)) => {
                f.write_all(&b).await.map_err(ioe)?;
                got += b.len() as u64;
            }
            Some(FileMsg::End { sha256 }) => break sha256,
            Some(_) => return Err(ProtoError::new(ErrorCode::Protocol, "unexpected message")),
            None => {
                return Err(ProtoError::new(
                    ErrorCode::Io,
                    "transfer interrupted (retry with --resume)",
                ))
            }
        }
    };
    f.flush().await.map_err(ioe)?;
    f.sync_all().await.map_err(ioe)?;
    drop(f);
    let local_sha = file_sha(&target).await?;
    match remote_sha {
        Some(r) if r == local_sha => {}
        Some(_) => {
            return Err(ProtoError::new(
                ErrorCode::Conflict,
                "checksum mismatch (the remote file changed?)",
            ))
        }
        None => {
            return Err(ProtoError::new(
                ErrorCode::Io,
                "remote file shrank during transfer",
            ))
        }
    }
    if target != local {
        tokio::fs::rename(&target, local).await.map_err(ioe)?;
    }
    Ok(Transfer {
        session: opened.session,
        size,
        transferred: got,
        sha256: local_sha,
        resumed_from: offset,
    })
}

/// Upload `local` to `device:remote`. With `resume`, a shorter remote file
/// that matches our prefix is continued.
pub async fn upload(
    op: &Opener,
    device: &str,
    local: &Path,
    remote: &str,
    resume: bool,
    mkdirs: bool,
) -> Result<Transfer, ProtoError> {
    let meta = tokio::fs::metadata(local).await.map_err(ioe)?;
    if !meta.is_file() {
        return Err(ProtoError::new(
            ErrorCode::BadRequest,
            format!("{} is not a file", local.display()),
        ));
    }
    let size = meta.len();
    let mut offset = 0;
    if resume {
        if let Ok((st, _)) = list(op, device, remote).await {
            if st.size <= size {
                offset = st.size;
            }
        }
    }
    #[cfg(unix)]
    let mode = {
        use std::os::unix::fs::PermissionsExt;
        Some(meta.permissions().mode() & 0o777)
    };
    #[cfg(not(unix))]
    let mode = None;
    let (s, opened) = op
        .open(&OpenRequest::FilePut {
            device: device.into(),
            path: remote.into(),
            offset,
            size,
            mode,
            mkdirs,
        })
        .await?;
    let (mut r, mut w) = tokio::io::split(s);
    let mut f = tokio::fs::File::open(local).await.map_err(ioe)?;
    f.seek(std::io::SeekFrom::Start(offset)).await.map_err(ioe)?;
    let mut buf = vec![0u8; MAX_DATA_CHUNK];
    let mut sent = 0u64;
    let total = size - offset;
    while sent < total {
        let want = buf.len().min((total - sent) as usize);
        let n = f.read(&mut buf[..want]).await.map_err(ioe)?;
        if n == 0 {
            return Err(ProtoError::new(
                ErrorCode::Conflict,
                "local file shrank during upload",
            ));
        }
        write_msg(&mut w, &FileMsg::Chunk(buf[..n].to_vec())).await?;
        sent += n as u64;
    }
    write_msg(&mut w, &FileMsg::End { sha256: None }).await?;
    let remote_sha = match tokio::time::timeout(Duration::from_secs(300), expect_msg::<_, FileMsg>(&mut r))
        .await
        .map_err(|_| ProtoError::new(ErrorCode::Timeout, "device did not confirm the upload"))??
    {
        FileMsg::Done { sha256, .. } => sha256,
        _ => return Err(ProtoError::new(ErrorCode::Protocol, "unexpected message")),
    };
    let _ = w.shutdown().await;
    let local_sha = file_sha(local).await?;
    if remote_sha != local_sha {
        return Err(ProtoError::new(
            ErrorCode::Conflict,
            "checksum mismatch after upload (retry without --resume)",
        ));
    }
    Ok(Transfer {
        session: opened.session,
        size,
        transferred: sent,
        sha256: local_sha,
        resumed_from: offset,
    })
}

/// Accept local TCP connections on `bind` and forward each one to
/// `host:port` as seen from `device`.
pub async fn forward_local(
    op: Opener,
    bind: &str,
    device: String,
    host: String,
    port: u16,
) -> Result<(), ProtoError> {
    let l = tokio::net::TcpListener::bind(bind)
        .await
        .map_err(|e| ProtoError::new(ErrorCode::Io, format!("listen {bind}: {e}")))?;
    eprintln!(
        "forwarding {} -> {device}:{host}:{port}",
        l.local_addr().map_err(ioe)?
    );
    serve_forward_local(op, l, device, host, port).await
}

/// Serve local forwarding on an already bound listener.
pub async fn serve_forward_local(
    op: Opener,
    l: tokio::net::TcpListener,
    device: String,
    host: String,
    port: u16,
) -> Result<(), ProtoError> {
    loop {
        let (mut tcp, peer) = l.accept().await.map_err(ioe)?;
        let _ = tcp.set_nodelay(true);
        let op = op.clone();
        let req = OpenRequest::ForwardL {
            device: device.clone(),
            host: host.clone(),
            port,
        };
        tokio::spawn(async move {
            match op.open(&req).await {
                Ok((mut s, _)) => {
                    let _ = tokio::io::copy_bidirectional(&mut tcp, &mut s).await;
                }
                Err(e) => tracing::info!(%peer, err = %e, "forward failed"),
            }
        });
    }
}

/// Result of a recursive copy.
#[derive(Debug, Clone, Default, Serialize)]
pub struct TreeTransfer {
    pub files: Vec<TreeFile>,
    pub dirs: u64,
    pub bytes: u64,
    /// Entries left out: symlinks (never followed) and special files.
    pub skipped: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct TreeFile {
    pub path: String,
    pub size: u64,
    pub sha256: String,
}

/// A name the device returned in a listing. It is used to build local paths,
/// so anything that could step outside the destination is refused.
fn safe_name(n: &str) -> Result<&str, ProtoError> {
    if n.is_empty() || n == "." || n == ".." || n.contains(['/', '\\', '\0']) || n.contains(':') {
        return Err(ProtoError::new(
            ErrorCode::Protocol,
            format!("device returned an unsafe file name {n:?}"),
        ));
    }
    Ok(n)
}

fn join_remote(base: &str, name: &str) -> String {
    if base.ends_with('/') || base.ends_with('\\') {
        format!("{base}{name}")
    } else {
        format!("{base}/{name}")
    }
}

/// Upper bound on entries in one recursive copy, so a hostile or huge tree
/// cannot make the client loop forever.
const MAX_TREE_ENTRIES: usize = 100_000;

/// Download the directory `device:remote` into `local` (created if missing).
/// Symlinks are skipped, never followed.
pub async fn download_tree(
    op: &Opener,
    device: &str,
    remote: &str,
    local: &Path,
    resume: bool,
) -> Result<TreeTransfer, ProtoError> {
    let mut out = TreeTransfer::default();
    let mut stack = vec![(remote.to_string(), local.to_path_buf(), String::new())];
    let mut seen = 0usize;
    while let Some((rdir, ldir, rel)) = stack.pop() {
        let (me, entries) = list(op, device, &rdir).await?;
        if me.kind != cjs_proto::EntryKind::Dir {
            return Err(ProtoError::new(
                ErrorCode::BadRequest,
                format!("{rdir} is not a directory"),
            ));
        }
        tokio::fs::create_dir_all(&ldir).await.map_err(ioe)?;
        out.dirs += 1;
        for e in entries {
            seen += 1;
            if seen > MAX_TREE_ENTRIES {
                return Err(ProtoError::new(ErrorCode::BadRequest, "directory tree too large"));
            }
            let name = safe_name(&e.name)?;
            let r = join_remote(&rdir, name);
            let l = ldir.join(name);
            let relp = if rel.is_empty() {
                name.to_string()
            } else {
                format!("{rel}/{name}")
            };
            match e.kind {
                cjs_proto::EntryKind::Dir => stack.push((r, l, relp)),
                cjs_proto::EntryKind::File => {
                    let t = download(op, device, &r, &l, resume).await?;
                    out.bytes += t.size;
                    out.files.push(TreeFile {
                        path: relp,
                        size: t.size,
                        sha256: t.sha256,
                    });
                }
                _ => out.skipped.push(relp),
            }
        }
    }
    Ok(out)
}

/// Upload the local directory `local` to `device:remote`. Symlinks and
/// special files are skipped, never followed. Remote directories are created
/// as files are written into them, so empty directories are not copied.
pub async fn upload_tree(
    op: &Opener,
    device: &str,
    local: &Path,
    remote: &str,
    resume: bool,
) -> Result<TreeTransfer, ProtoError> {
    let meta = tokio::fs::symlink_metadata(local).await.map_err(ioe)?;
    if !meta.is_dir() {
        return Err(ProtoError::new(
            ErrorCode::BadRequest,
            format!("{} is not a directory", local.display()),
        ));
    }
    let mut out = TreeTransfer::default();
    let mut stack = vec![(local.to_path_buf(), remote.to_string(), String::new())];
    let mut seen = 0usize;
    while let Some((ldir, rdir, rel)) = stack.pop() {
        out.dirs += 1;
        let mut rd = tokio::fs::read_dir(&ldir).await.map_err(ioe)?;
        while let Some(e) = rd.next_entry().await.map_err(ioe)? {
            seen += 1;
            if seen > MAX_TREE_ENTRIES {
                return Err(ProtoError::new(ErrorCode::BadRequest, "directory tree too large"));
            }
            let name = e.file_name().to_string_lossy().into_owned();
            let relp = if rel.is_empty() {
                name.clone()
            } else {
                format!("{rel}/{name}")
            };
            let ft = e.file_type().await.map_err(ioe)?;
            let r = join_remote(&rdir, &name);
            if ft.is_dir() {
                stack.push((e.path(), r, relp));
            } else if ft.is_file() {
                let t = upload(op, device, &e.path(), &r, resume, true).await?;
                out.bytes += t.size;
                out.files.push(TreeFile {
                    path: relp,
                    size: t.size,
                    sha256: t.sha256,
                });
            } else {
                out.skipped.push(relp);
            }
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tree_tests {
    use super::*;

    #[test]
    fn unsafe_names_rejected() {
        for n in ["", ".", "..", "a/b", "a\\b", "C:x", "a\0"] {
            assert!(safe_name(n).is_err(), "{n:?}");
        }
        assert_eq!(safe_name("ok.txt").unwrap(), "ok.txt");
        assert_eq!(join_remote("a", "b"), "a/b");
        assert_eq!(join_remote("a/", "b"), "a/b");
    }
}
