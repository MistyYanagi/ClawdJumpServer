//! Egress through the server. The name was already allowed by the policy
//! decision; here the name is resolved once, every address is checked
//! against the matching grants' rules (SSRF guard: private, loopback,
//! link-local and metadata addresses need a rule naming them by IP), and
//! the connection goes to a checked address, so DNS rebinding between the
//! check and the connect is not possible.
use std::net::SocketAddr;
use std::time::{Duration, Instant};

use cjs_audit::{Event, Outcome};
use cjs_authz::{net, Decision};
use cjs_mux::{write_msg, MuxStream};
use cjs_proto::{ErrorCode, OpenReply, OpenRequest, ProtoError};
use serde_json::json;
use tokio::net::TcpStream;

use crate::relay::relay_raw;
use crate::state::{Principal, Shared, StreamInfo};

const DIAL_TIMEOUT: Duration = Duration::from_secs(10);

/// Resolve `host:port` and keep only addresses allowed by `rules`.
pub async fn resolve_allowed(
    rules: &[net::NetRule],
    host: &str,
    port: u16,
) -> Result<(Vec<SocketAddr>, Vec<SocketAddr>), ProtoError> {
    let host = host.trim_matches(|c| c == '[' || c == ']');
    let addrs: Vec<SocketAddr> = tokio::time::timeout(DIAL_TIMEOUT, tokio::net::lookup_host((host, port)))
        .await
        .map_err(|_| ProtoError::new(ErrorCode::Timeout, "DNS lookup timed out"))?
        .map_err(|e| ProtoError::new(ErrorCode::NotFound, format!("cannot resolve {host}: {e}")))?
        .collect();
    let (ok, blocked): (Vec<_>, Vec<_>) = addrs
        .into_iter()
        .partition(|a| net::ip_allowed(rules, &a.ip(), port));
    Ok((ok, blocked))
}

pub async fn dial_first(addrs: &[SocketAddr]) -> Result<TcpStream, ProtoError> {
    let mut last = ProtoError::new(ErrorCode::Io, "no address");
    for a in addrs {
        match tokio::time::timeout(DIAL_TIMEOUT, TcpStream::connect(a)).await {
            Ok(Ok(s)) => {
                let _ = s.set_nodelay(true);
                return Ok(s);
            }
            Ok(Err(e)) => last = ProtoError::new(ErrorCode::Io, format!("connect {a}: {e}")),
            Err(_) => last = ProtoError::new(ErrorCode::Timeout, format!("connect {a}: timed out")),
        }
    }
    Err(last)
}

pub(crate) async fn server_egress(
    sh: &std::sync::Arc<Shared>,
    p: &Principal,
    info: &StreamInfo,
    dec: &Decision,
    s: &mut MuxStream,
    replied: &mut bool,
) -> Result<(), ProtoError> {
    let OpenRequest::Egress { host, port, .. } = &info.req else {
        return Err(ProtoError::new(ErrorCode::BadRequest, "not an egress request"));
    };
    let (ok, blocked) = resolve_allowed(&dec.egress_rules, host, *port).await?;
    if ok.is_empty() {
        let _ = sh.audit_async(
            Event::new("egress.blocked", &p.id, &info.target, Outcome::Denied)
                .session(info.session.clone())
                .ip(info.peer.clone())
                .data(json!({"resolved": blocked.iter().map(|a| a.to_string()).collect::<Vec<_>>(), "reason": "address not allowed (SSRF guard)"})),
        )
        .await;
        return Err(ProtoError::new(
            ErrorCode::Forbidden,
            format!("{host} resolves only to addresses that are not allowed"),
        ));
    }
    let mut tcp = dial_first(&ok).await?;
    let remote = tcp.peer_addr().map(|a| a.to_string()).unwrap_or_default();
    sh.audit_async(
        Event::new("session.start", &p.id, &info.target, Outcome::Success)
            .session(info.session.clone())
            .ip(info.peer.clone())
            .data(json!({"stream": info.id, "kind": "egress", "via": "server", "remote": remote})),
    )
    .await
    .map_err(|e| e.proto())?;
    write_msg(
        s,
        &OpenReply::Ok {
            id: info.id,
            session: info.session.clone(),
        },
    )
    .await?;
    *replied = true;
    let started = Instant::now();
    let (r, up, down) = relay_raw(s, &mut tcp, &info.cancel).await;
    let _ = sh
        .audit_async(
            Event::new(
                "session.end",
                &p.id,
                &info.target,
                if r.is_ok() {
                    Outcome::Success
                } else {
                    Outcome::Failure
                },
            )
            .session(info.session.clone())
            .ip(info.peer.clone())
            .data(json!({
                "bytes_up": up,
                "bytes_down": down,
                "remote": remote,
                "duration_ms": started.elapsed().as_millis() as u64,
            })),
        )
        .await;
    r
}
