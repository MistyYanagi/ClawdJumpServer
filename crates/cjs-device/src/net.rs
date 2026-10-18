//! Port forwarding and egress (device as exit node).
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

use cjs_authz::net::{ip_allowed, NetRule};
use cjs_mux::{expect_msg, write_msg, MuxStream};
use cjs_proto::{Capability, ErrorCode, OpenReply, OpenRequest, ProtoError};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use crate::{perr, reply_ok, CtxRef};

const DIAL_TIMEOUT: Duration = Duration::from_secs(10);

static LISTENER_SEQ: AtomicU32 = AtomicU32::new(1);

async fn dial(addrs: &[SocketAddr]) -> Result<TcpStream, ProtoError> {
    let mut last = perr(ErrorCode::Io, "no address");
    for a in addrs {
        match tokio::time::timeout(DIAL_TIMEOUT, TcpStream::connect(a)).await {
            Ok(Ok(s)) => {
                let _ = s.set_nodelay(true);
                return Ok(s);
            }
            Ok(Err(e)) => last = perr(ErrorCode::Io, format!("connect {a}: {e}")),
            Err(_) => last = perr(ErrorCode::Timeout, format!("connect {a}: timed out")),
        }
    }
    Err(last)
}

/// Network rules the server signed into the capability (fail closed).
fn signed_rules(cap: &Capability) -> Result<Vec<NetRule>, ProtoError> {
    cap.net_rules
        .as_deref()
        .map(serde_json::from_str)
        .transpose()
        .map_err(|_| perr(ErrorCode::Forbidden, "capability carries malformed network rules"))?
        .ok_or_else(|| perr(ErrorCode::Forbidden, "capability carries no network rules"))
}

async fn resolve(host: &str, port: u16) -> Result<Vec<SocketAddr>, ProtoError> {
    let host = host.trim_matches(|c| c == '[' || c == ']');
    Ok(
        tokio::time::timeout(DIAL_TIMEOUT, tokio::net::lookup_host((host, port)))
            .await
            .map_err(|_| perr(ErrorCode::Timeout, "DNS lookup timed out"))?
            .map_err(|e| perr(ErrorCode::NotFound, format!("cannot resolve {host}: {e}")))?
            .collect(),
    )
}

async fn splice(s: &mut MuxStream, tcp: &mut TcpStream) {
    let _ = tokio::io::copy_bidirectional(s, tcp).await;
    let _ = s.shutdown().await;
}

pub(crate) async fn forward_local(
    cap: &Capability,
    req: &OpenRequest,
    s: &mut MuxStream,
    replied: &mut bool,
) -> Result<(), ProtoError> {
    let OpenRequest::ForwardL { host, port, .. } = req else {
        return Err(perr(ErrorCode::BadRequest, "not a forward request"));
    };
    // The capability already pins host:port (verified by CapVerifier); the
    // resolved addresses are checked against the signed forward rules so a
    // `*` rule or an alternate spelling cannot reach metadata endpoints or
    // addresses a deny rule names.
    let rules = signed_rules(cap)?;
    let addrs: Vec<SocketAddr> = resolve(host, *port)
        .await?
        .into_iter()
        .filter(|a| cjs_authz::net::forward_ip_allowed(&rules, &a.ip(), *port))
        .collect();
    if addrs.is_empty() {
        return Err(perr(
            ErrorCode::Forbidden,
            format!("{host} resolves only to addresses that are not allowed"),
        ));
    }
    let mut tcp = dial(&addrs).await?;
    reply_ok(s, 0, cap).await?;
    *replied = true;
    splice(s, &mut tcp).await;
    Ok(())
}

pub(crate) async fn egress(
    cap: &Capability,
    req: &OpenRequest,
    s: &mut MuxStream,
    replied: &mut bool,
) -> Result<(), ProtoError> {
    let OpenRequest::Egress { host, port, .. } = req else {
        return Err(perr(ErrorCode::BadRequest, "not an egress request"));
    };
    // Post-DNS SSRF check with the rules the server signed into the token.
    let rules = signed_rules(cap)?;
    let addrs: Vec<SocketAddr> = resolve(host, *port)
        .await?
        .into_iter()
        .filter(|a| ip_allowed(&rules, &a.ip(), *port))
        .collect();
    if addrs.is_empty() {
        return Err(perr(
            ErrorCode::Forbidden,
            format!("{host} resolves only to addresses that are not allowed"),
        ));
    }
    let mut tcp = dial(&addrs).await?;
    reply_ok(s, 0, cap).await?;
    *replied = true;
    splice(s, &mut tcp).await;
    Ok(())
}

pub(crate) async fn forward_remote(
    ctx: &CtxRef,
    cap: &Capability,
    req: &OpenRequest,
    s: &mut MuxStream,
    replied: &mut bool,
) -> Result<(), ProtoError> {
    let OpenRequest::ForwardR {
        bind_host, bind_port, ..
    } = req
    else {
        return Err(perr(ErrorCode::BadRequest, "not a remote forward request"));
    };
    let host = bind_host.trim_matches(|c| c == '[' || c == ']');
    let listener = TcpListener::bind((host, *bind_port))
        .await
        .map_err(|e| perr(ErrorCode::Io, format!("listen {bind_host}:{bind_port}: {e}")))?;
    let id = LISTENER_SEQ.fetch_add(1, Ordering::Relaxed);
    reply_ok(s, id, cap).await?;
    *replied = true;
    let mut probe = [0u8; 16];
    loop {
        tokio::select! {
            a = listener.accept() => {
                let Ok((tcp, peer)) = a else { continue };
                let mux = ctx.mux.clone();
                tokio::spawn(async move {
                    if let Err(e) = remote_conn(mux, id, tcp, peer).await {
                        tracing::info!(err = %e, "remote forward connection failed");
                    }
                });
            }
            // The control stream carries no data; EOF means the forward ended.
            r = s.read(&mut probe) => {
                if !matches!(r, Ok(n) if n > 0) {
                    break;
                }
            }
        }
    }
    let _ = s.shutdown().await;
    Ok(())
}

async fn remote_conn(
    mux: cjs_mux::MuxHandle,
    listener: u32,
    mut tcp: TcpStream,
    peer: SocketAddr,
) -> Result<(), ProtoError> {
    let _ = tcp.set_nodelay(true);
    let mut s = mux.open().await?;
    write_msg(
        &mut s,
        &OpenRequest::ForwardRConn {
            listener,
            peer: peer.to_string(),
        },
    )
    .await?;
    match tokio::time::timeout(Duration::from_secs(30), expect_msg::<_, OpenReply>(&mut s))
        .await
        .map_err(|_| perr(ErrorCode::Timeout, "server did not answer"))??
    {
        OpenReply::Ok { .. } => {}
        OpenReply::Err(e) => return Err(e),
    }
    splice(&mut s, &mut tcp).await;
    Ok(())
}
