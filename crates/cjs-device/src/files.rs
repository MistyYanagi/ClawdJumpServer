//! File transfer through the project-root jail.
use std::io::SeekFrom;

use cjs_fsjail::Jail;
use cjs_mux::{read_msg, write_msg, MuxStream};
use cjs_proto::{Capability, ErrorCode, FileMsg, OpenRequest, ProtoError, MAX_DATA_CHUNK};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt};

use crate::{perr, reply_ok};

fn ioe(e: std::io::Error) -> ProtoError {
    perr(ErrorCode::Io, e.to_string())
}

/// Feed the first `n` bytes of `f` (from the start) into `h`.
async fn hash_prefix(f: &mut tokio::fs::File, n: u64, h: &mut Sha256) -> Result<(), ProtoError> {
    f.seek(SeekFrom::Start(0)).await.map_err(ioe)?;
    let mut left = n;
    let mut buf = vec![0u8; 64 * 1024];
    while left > 0 {
        let want = buf.len().min(left as usize);
        let k = f.read(&mut buf[..want]).await.map_err(ioe)?;
        if k == 0 {
            return Err(perr(ErrorCode::Conflict, "file changed during transfer"));
        }
        h.update(&buf[..k]);
        left -= k as u64;
    }
    Ok(())
}

fn mtime(m: &std::fs::Metadata) -> i64 {
    m.modified()
        .ok()
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

#[cfg(unix)]
fn mode(m: &std::fs::Metadata) -> u32 {
    use std::os::unix::fs::PermissionsExt;
    m.permissions().mode() & 0o7777
}

#[cfg(not(unix))]
fn mode(m: &std::fs::Metadata) -> u32 {
    if m.permissions().readonly() {
        0o444
    } else {
        0o644
    }
}

pub(crate) async fn get(
    cap: &Capability,
    req: &OpenRequest,
    s: &mut MuxStream,
    replied: &mut bool,
) -> Result<(), ProtoError> {
    let OpenRequest::FileGet { path, offset, .. } = req else {
        return Err(perr(ErrorCode::BadRequest, "not a get request"));
    };
    let jail = Jail::new(&cap.roots, cap.full_access)?;
    let f = jail.open_read(path)?;
    let meta = f.metadata().map_err(ioe)?;
    let size = meta.len();
    if *offset > size {
        return Err(perr(ErrorCode::BadRequest, "offset beyond end of file"));
    }
    let mut f = tokio::fs::File::from_std(f);
    let mut h = Sha256::new();
    hash_prefix(&mut f, *offset, &mut h).await?;
    reply_ok(s, 0, cap).await?;
    *replied = true;
    write_msg(
        s,
        &FileMsg::Meta {
            size,
            mode: mode(&meta),
            mtime: mtime(&meta),
        },
    )
    .await?;
    let mut buf = vec![0u8; MAX_DATA_CHUNK];
    let mut sent = *offset;
    while sent < size {
        let want = buf.len().min((size - sent) as usize);
        let k = f.read(&mut buf[..want]).await.map_err(ioe)?;
        if k == 0 {
            break;
        }
        h.update(&buf[..k]);
        write_msg(s, &FileMsg::Chunk(buf[..k].to_vec())).await?;
        sent += k as u64;
    }
    let sha = (sent == size).then(|| hex::encode(h.finalize()));
    write_msg(s, &FileMsg::End { sha256: sha }).await?;
    let _ = s.shutdown().await;
    Ok(())
}

pub(crate) async fn put(
    cap: &Capability,
    req: &OpenRequest,
    s: &mut MuxStream,
    replied: &mut bool,
) -> Result<(), ProtoError> {
    let OpenRequest::FilePut {
        path,
        offset,
        size,
        mode,
        mkdirs,
        ..
    } = req
    else {
        return Err(perr(ErrorCode::BadRequest, "not a put request"));
    };
    let jail = Jail::new(&cap.roots, cap.full_access)?;
    let f = jail.open_write(path, *offset == 0, *mkdirs)?;
    let cur = f.metadata().map_err(ioe)?.len();
    if *offset > cur {
        return Err(perr(
            ErrorCode::Conflict,
            format!("cannot resume at {offset}: file has {cur} bytes"),
        ));
    }
    f.set_len(*offset).map_err(ioe)?;
    let mut f = tokio::fs::File::from_std(f);
    f.seek(SeekFrom::Start(*offset)).await.map_err(ioe)?;
    reply_ok(s, 0, cap).await?;
    *replied = true;
    let expected = size - offset;
    let mut got = 0u64;
    loop {
        match read_msg::<_, FileMsg>(s).await? {
            Some(FileMsg::Chunk(b)) => {
                got += b.len() as u64;
                if got > expected {
                    return Err(perr(ErrorCode::BadRequest, "more data than announced"));
                }
                f.write_all(&b).await.map_err(ioe)?;
            }
            Some(FileMsg::End { .. }) => break,
            Some(_) => return Err(perr(ErrorCode::Protocol, "unexpected message")),
            None => return Err(perr(ErrorCode::Cancelled, "upload interrupted")),
        }
    }
    if got != expected {
        return Err(perr(
            ErrorCode::BadRequest,
            format!("expected {expected} bytes, got {got}"),
        ));
    }
    f.flush().await.map_err(ioe)?;
    f.sync_all().await.map_err(ioe)?;
    #[cfg(unix)]
    if let Some(m) = mode {
        use std::os::unix::fs::PermissionsExt;
        // Never set setuid/setgid/sticky bits from a remote request.
        f.set_permissions(std::fs::Permissions::from_mode(m & 0o777))
            .await
            .map_err(ioe)?;
    }
    #[cfg(not(unix))]
    let _ = mode;
    let mut h = Sha256::new();
    hash_prefix(&mut f, *size, &mut h).await?;
    write_msg(
        s,
        &FileMsg::Done {
            size: *size,
            sha256: hex::encode(h.finalize()),
        },
    )
    .await?;
    let _ = s.shutdown().await;
    Ok(())
}

pub(crate) async fn list(
    cap: &Capability,
    req: &OpenRequest,
    s: &mut MuxStream,
    replied: &mut bool,
) -> Result<(), ProtoError> {
    let OpenRequest::FileList { path, .. } = req else {
        return Err(perr(ErrorCode::BadRequest, "not a list request"));
    };
    let jail = Jail::new(&cap.roots, cap.full_access)?;
    let (me, entries) = jail.list(path)?;
    reply_ok(s, 0, cap).await?;
    *replied = true;
    write_msg(s, &FileMsg::Stat(me)).await?;
    for chunk in entries.chunks(256) {
        write_msg(s, &FileMsg::Entries(chunk.to_vec())).await?;
    }
    write_msg(s, &FileMsg::End { sha256: None }).await?;
    let _ = s.shutdown().await;
    Ok(())
}
