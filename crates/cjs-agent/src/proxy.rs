//! Local proxy: SOCKS5 (CONNECT, no auth) and HTTP CONNECT on one port.
//! Every connection becomes an `Egress` stream, decided and audited by the
//! server (optionally exiting through a device).
use std::time::Duration;

use cjs_proto::{ErrorCode, OpenRequest, ProtoError};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};

use crate::local::Opener;

fn ioe(e: std::io::Error) -> ProtoError {
    ProtoError::new(ErrorCode::Io, e.to_string())
}

pub async fn run(op: Opener, bind: &str, via: Option<String>) -> Result<(), ProtoError> {
    let l = TcpListener::bind(bind)
        .await
        .map_err(|e| ProtoError::new(ErrorCode::Io, format!("listen {bind}: {e}")))?;
    eprintln!(
        "proxy listening on {} (SOCKS5 and HTTP CONNECT){}",
        l.local_addr().map_err(ioe)?,
        via.as_ref()
            .map(|v| format!(", exiting via {v}"))
            .unwrap_or_default()
    );
    loop {
        let (tcp, peer) = l.accept().await.map_err(ioe)?;
        let op = op.clone();
        let via = via.clone();
        tokio::spawn(async move {
            if let Err(e) = handle(op, tcp, via).await {
                tracing::info!(%peer, err = %e, "proxy connection failed");
            }
        });
    }
}

async fn handle(op: Opener, tcp: TcpStream, via: Option<String>) -> Result<(), ProtoError> {
    let _ = tcp.set_nodelay(true);
    let mut first = [0u8; 1];
    tokio::time::timeout(Duration::from_secs(30), tcp.peek(&mut first))
        .await
        .map_err(|_| ProtoError::new(ErrorCode::Timeout, "client sent nothing"))?
        .map_err(ioe)?;
    if first[0] == 5 {
        socks5(op, tcp, via).await
    } else {
        http_connect(op, tcp, via).await
    }
}

async fn socks5(op: Opener, mut tcp: TcpStream, via: Option<String>) -> Result<(), ProtoError> {
    let mut h = [0u8; 2];
    tcp.read_exact(&mut h).await.map_err(ioe)?;
    let mut methods = vec![0u8; h[1] as usize];
    tcp.read_exact(&mut methods).await.map_err(ioe)?;
    if !methods.contains(&0) {
        tcp.write_all(&[5, 0xff]).await.map_err(ioe)?;
        return Err(ProtoError::new(
            ErrorCode::Unsupported,
            "client needs SOCKS authentication",
        ));
    }
    tcp.write_all(&[5, 0]).await.map_err(ioe)?;
    let mut req = [0u8; 4];
    tcp.read_exact(&mut req).await.map_err(ioe)?;
    let reply = |code: u8| [5, code, 0, 1, 0, 0, 0, 0, 0, 0];
    if req[1] != 1 {
        tcp.write_all(&reply(7)).await.map_err(ioe)?;
        return Err(ProtoError::new(
            ErrorCode::Unsupported,
            "only CONNECT is supported",
        ));
    }
    let host = match req[3] {
        1 => {
            let mut a = [0u8; 4];
            tcp.read_exact(&mut a).await.map_err(ioe)?;
            std::net::Ipv4Addr::from(a).to_string()
        }
        3 => {
            let mut n = [0u8; 1];
            tcp.read_exact(&mut n).await.map_err(ioe)?;
            let mut name = vec![0u8; n[0] as usize];
            tcp.read_exact(&mut name).await.map_err(ioe)?;
            String::from_utf8(name).map_err(|_| ProtoError::new(ErrorCode::BadRequest, "bad host name"))?
        }
        4 => {
            let mut a = [0u8; 16];
            tcp.read_exact(&mut a).await.map_err(ioe)?;
            format!("[{}]", std::net::Ipv6Addr::from(a))
        }
        _ => {
            tcp.write_all(&reply(8)).await.map_err(ioe)?;
            return Err(ProtoError::new(ErrorCode::BadRequest, "bad address type"));
        }
    };
    let mut p = [0u8; 2];
    tcp.read_exact(&mut p).await.map_err(ioe)?;
    let port = u16::from_be_bytes(p);
    match op.open(&OpenRequest::Egress { host, port, via }).await {
        Ok((mut s, _)) => {
            tcp.write_all(&reply(0)).await.map_err(ioe)?;
            let _ = tokio::io::copy_bidirectional(&mut tcp, &mut s).await;
            Ok(())
        }
        Err(e) => {
            let code = if e.code == ErrorCode::Forbidden { 2 } else { 5 };
            let _ = tcp.write_all(&reply(code)).await;
            Err(e)
        }
    }
}

async fn http_connect(op: Opener, tcp: TcpStream, via: Option<String>) -> Result<(), ProtoError> {
    let mut r = BufReader::new(tcp);
    let mut line = String::new();
    r.read_line(&mut line).await.map_err(ioe)?;
    // Headers (ignored, bounded).
    let mut total = line.len();
    loop {
        let mut h = String::new();
        let n = r.read_line(&mut h).await.map_err(ioe)?;
        total += n;
        if n == 0 || h == "\r\n" || h == "\n" || total > 16 * 1024 {
            break;
        }
    }
    let mut parts = line.split_whitespace();
    let method = parts.next().unwrap_or("");
    let target = parts.next().unwrap_or("");
    // Bytes the client sent early (after the headers) must not be lost.
    let early = r.buffer().to_vec();
    let mut tcp = r.into_inner();
    if !method.eq_ignore_ascii_case("CONNECT") {
        let _ = tcp
            .write_all(b"HTTP/1.1 405 Method Not Allowed\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
            .await;
        return Err(ProtoError::new(
            ErrorCode::Unsupported,
            "only CONNECT is supported",
        ));
    }
    let (host, port) = target
        .rsplit_once(':')
        .and_then(|(h, p)| p.parse::<u16>().ok().map(|p| (h.to_string(), p)))
        .ok_or_else(|| ProtoError::new(ErrorCode::BadRequest, "bad CONNECT target"))?;
    match op.open(&OpenRequest::Egress { host, port, via }).await {
        Ok((mut s, _)) => {
            tcp.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                .await
                .map_err(ioe)?;
            if !early.is_empty() {
                s.write_all(&early).await.map_err(ioe)?;
            }
            let _ = tokio::io::copy_bidirectional(&mut tcp, &mut s).await;
            Ok(())
        }
        Err(e) => {
            let status = if e.code == ErrorCode::Forbidden {
                "403 Forbidden"
            } else {
                "502 Bad Gateway"
            };
            let body = format!("{e}\n");
            let _ = tcp
                .write_all(
                    format!(
                        "HTTP/1.1 {status}\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                        body.len()
                    )
                    .as_bytes(),
                )
                .await;
            Err(e)
        }
    }
}
