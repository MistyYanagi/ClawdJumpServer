//! Local proxy: SOCKS5 (CONNECT, no auth), HTTP CONNECT and plain HTTP
//! forward proxying (`GET http://host/path`) on one port.
//! Every connection becomes an `Egress` stream, decided and audited by the
//! server (optionally exiting through a device).
//!
//! By default the proxy requires credentials (SOCKS5 username/password,
//! HTTP `Proxy-Authorization: Basic`) generated at start-up and printed in
//! the `export` lines, so other local users or processes cannot borrow the
//! agent's identity through it.
use std::time::Duration;

use cjs_proto::{ErrorCode, OpenRequest, ProtoError};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};

use base64::Engine as _;
use subtle::ConstantTimeEq;

use crate::local::Opener;

/// Proxy credentials.
#[derive(Clone)]
pub struct Auth {
    pub user: String,
    pub pass: String,
}

impl Auth {
    /// Fresh random credentials.
    pub fn generate() -> Self {
        use rand::RngCore;
        let mut b = [0u8; 18];
        rand::rngs::OsRng.fill_bytes(&mut b);
        Auth {
            user: "cjs".into(),
            pass: hex::encode(b),
        }
    }

    fn check(&self, user: &[u8], pass: &[u8]) -> bool {
        let u: bool = self.user.as_bytes().ct_eq(user).into();
        let p: bool = self.pass.as_bytes().ct_eq(pass).into();
        u & p
    }

    fn check_header(&self, value: &str) -> bool {
        let Some(b64) = value
            .trim()
            .strip_prefix("Basic ")
            .or_else(|| value.trim().strip_prefix("basic "))
        else {
            return false;
        };
        let Ok(raw) = base64::engine::general_purpose::STANDARD.decode(b64.trim()) else {
            return false;
        };
        match raw.iter().position(|&c| c == b':') {
            Some(i) => self.check(&raw[..i], &raw[i + 1..]),
            None => false,
        }
    }
}

fn ioe(e: std::io::Error) -> ProtoError {
    ProtoError::new(ErrorCode::Io, e.to_string())
}

pub async fn run(
    op: Opener,
    bind: &str,
    via: Option<String>,
    auth: Option<Auth>,
    env_file: Option<std::path::PathBuf>,
) -> Result<(), ProtoError> {
    let l = TcpListener::bind(bind)
        .await
        .map_err(|e| ProtoError::new(ErrorCode::Io, format!("listen {bind}: {e}")))?;
    let addr = l.local_addr().map_err(ioe)?;
    if !addr.ip().is_loopback() {
        eprintln!("warning: the proxy listens on a non-loopback address; other hosts can reach it");
    }
    if auth.is_none() {
        eprintln!(
            "warning: proxy authentication is disabled; any local process can use this agent's identity"
        );
    }
    eprintln!(
        "proxy listening on {addr} (SOCKS5, HTTP CONNECT and HTTP forward){}",
        via.as_ref()
            .map(|v| format!(", exiting via {v}"))
            .unwrap_or_default()
    );
    // Lines for `eval "$(cjs proxy)"`; diagnostics go to stderr.
    let lines = export_lines(&addr.to_string(), auth.as_ref());
    match env_file {
        Some(p) => write_private(&p, &format!("{lines}\n"))
            .map_err(|e| ProtoError::new(ErrorCode::Io, format!("{}: {e}", p.display())))?,
        None => {
            println!("{lines}");
            use std::io::Write as _;
            let _ = std::io::stdout().flush();
        }
    }
    loop {
        let (tcp, peer) = l.accept().await.map_err(ioe)?;
        let op = op.clone();
        let via = via.clone();
        let auth = auth.clone();
        tokio::spawn(async move {
            if let Err(e) = handle(op, tcp, via, auth).await {
                tracing::info!(%peer, err = %e, "proxy connection failed");
            }
        });
    }
}

/// Write `data` to a file only the current user can read.
fn write_private(p: &std::path::Path, data: &str) -> std::io::Result<()> {
    use std::io::Write as _;
    let _ = std::fs::remove_file(p);
    let mut o = std::fs::OpenOptions::new();
    o.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        o.mode(0o600);
    }
    let mut f = o.open(p)?;
    f.write_all(data.as_bytes())
}

/// Shell `export` lines pointing common tools at the proxy.
pub fn export_lines(addr: &str, auth: Option<&Auth>) -> String {
    let cred = auth
        .map(|a| format!("{}:{}@", a.user, a.pass))
        .unwrap_or_default();
    let http = format!("http://{cred}{addr}");
    let mut out = String::new();
    for k in ["HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy"] {
        out.push_str(&format!("export {k}={http}\n"));
    }
    for k in ["ALL_PROXY", "all_proxy"] {
        out.push_str(&format!("export {k}=socks5h://{cred}{addr}\n"));
    }
    out.push_str("export NO_PROXY=localhost,127.0.0.1,::1\n");
    out.push_str("export no_proxy=localhost,127.0.0.1,::1");
    out
}

async fn handle(
    op: Opener,
    tcp: TcpStream,
    via: Option<String>,
    auth: Option<Auth>,
) -> Result<(), ProtoError> {
    let _ = tcp.set_nodelay(true);
    let mut first = [0u8; 1];
    tokio::time::timeout(Duration::from_secs(30), tcp.peek(&mut first))
        .await
        .map_err(|_| ProtoError::new(ErrorCode::Timeout, "client sent nothing"))?
        .map_err(ioe)?;
    if first[0] == 5 {
        socks5(op, tcp, via, auth).await
    } else {
        http_connect(op, tcp, via, auth).await
    }
}

async fn socks5(
    op: Opener,
    mut tcp: TcpStream,
    via: Option<String>,
    auth: Option<Auth>,
) -> Result<(), ProtoError> {
    let mut h = [0u8; 2];
    tcp.read_exact(&mut h).await.map_err(ioe)?;
    let mut methods = vec![0u8; h[1] as usize];
    tcp.read_exact(&mut methods).await.map_err(ioe)?;
    let want = if auth.is_some() { 2 } else { 0 };
    if !methods.contains(&want) {
        tcp.write_all(&[5, 0xff]).await.map_err(ioe)?;
        return Err(ProtoError::new(
            ErrorCode::Unauthenticated,
            if want == 2 {
                "client did not offer SOCKS username/password authentication"
            } else {
                "client needs SOCKS authentication"
            },
        ));
    }
    tcp.write_all(&[5, want]).await.map_err(ioe)?;
    if let Some(a) = &auth {
        // RFC 1929 sub-negotiation.
        let mut v = [0u8; 2];
        tcp.read_exact(&mut v).await.map_err(ioe)?;
        let mut user = vec![0u8; v[1] as usize];
        tcp.read_exact(&mut user).await.map_err(ioe)?;
        let mut pl = [0u8; 1];
        tcp.read_exact(&mut pl).await.map_err(ioe)?;
        let mut pass = vec![0u8; pl[0] as usize];
        tcp.read_exact(&mut pass).await.map_err(ioe)?;
        if v[0] != 1 || !a.check(&user, &pass) {
            let _ = tcp.write_all(&[1, 1]).await;
            return Err(ProtoError::new(
                ErrorCode::Unauthenticated,
                "bad proxy credentials",
            ));
        }
        tcp.write_all(&[1, 0]).await.map_err(ioe)?;
    }
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

const MAX_HEAD: usize = 16 * 1024;

async fn http_connect(
    op: Opener,
    tcp: TcpStream,
    via: Option<String>,
    auth: Option<Auth>,
) -> Result<(), ProtoError> {
    let mut r = BufReader::new(tcp);
    let mut line = String::new();
    r.read_line(&mut line).await.map_err(ioe)?;
    let mut headers = Vec::new();
    let mut total = line.len();
    loop {
        let mut h = String::new();
        let n = r.read_line(&mut h).await.map_err(ioe)?;
        total += n;
        if total > MAX_HEAD {
            let mut tcp = r.into_inner();
            let _ = tcp
                .write_all(&error_response(
                    "431 Request Header Fields Too Large",
                    "headers too large",
                ))
                .await;
            return Err(ProtoError::new(
                ErrorCode::BadRequest,
                "request headers too large",
            ));
        }
        if n == 0 || h == "\r\n" || h == "\n" {
            break;
        }
        headers.push(h);
    }
    let mut parts = line.split_whitespace();
    let method = parts.next().unwrap_or("").to_string();
    let target = parts.next().unwrap_or("").to_string();
    let version = parts.next().unwrap_or("HTTP/1.1").to_string();
    // Bytes the client sent early (after the headers) must not be lost.
    let early = r.buffer().to_vec();
    let mut tcp = r.into_inner();
    if let Some(a) = &auth {
        let ok = headers.iter().any(|h| {
            h.split_once(':').is_some_and(|(n, v)| {
                n.trim().eq_ignore_ascii_case("proxy-authorization") && a.check_header(v)
            })
        });
        if !ok {
            let body = "proxy authentication required (use the credentials printed by `cjs proxy`)\n";
            let _ = tcp
                .write_all(
                    format!(
                        "HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"cjs\"\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                        body.len()
                    )
                    .as_bytes(),
                )
                .await;
            return Err(ProtoError::new(
                ErrorCode::Unauthenticated,
                "missing or bad proxy credentials",
            ));
        }
    }
    let (host, port, head) = if method.eq_ignore_ascii_case("CONNECT") {
        match parse_authority(&target, None) {
            Some((h, p)) => (h, p, None),
            None => {
                let _ = tcp
                    .write_all(&error_response("400 Bad Request", "bad CONNECT target"))
                    .await;
                return Err(ProtoError::new(ErrorCode::BadRequest, "bad CONNECT target"));
            }
        }
    } else {
        match forward_head(&method, &target, &version, &headers) {
            Some(v) => (v.0, v.1, Some(v.2)),
            None => {
                let _ = tcp
                    .write_all(&error_response(
                        "400 Bad Request",
                        "expected CONNECT or an absolute http:// URL (use CONNECT for https)",
                    ))
                    .await;
                return Err(ProtoError::new(ErrorCode::BadRequest, "bad proxy request"));
            }
        }
    };
    match op.open(&OpenRequest::Egress { host, port, via }).await {
        Ok((mut s, _)) => {
            match head {
                None => tcp
                    .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                    .await
                    .map_err(ioe)?,
                Some(h) => s.write_all(h.as_bytes()).await.map_err(ioe)?,
            }
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
            let _ = tcp.write_all(&error_response(status, &e.to_string())).await;
            Err(e)
        }
    }
}

fn error_response(status: &str, msg: &str) -> Vec<u8> {
    let body = format!("{msg}\n");
    format!(
        "HTTP/1.1 {status}\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    )
    .into_bytes()
}

/// `host:port`, `[v6]:port`, or (with a default port) a bare host.
fn parse_authority(a: &str, default_port: Option<u16>) -> Option<(String, u16)> {
    if a.is_empty() || a.contains(['@', '/', ' ']) {
        return None;
    }
    if let Some(rest) = a.strip_prefix('[') {
        let (h, tail) = rest.split_once(']')?;
        let port = match tail.strip_prefix(':') {
            Some(p) => p.parse().ok()?,
            None if tail.is_empty() => default_port?,
            None => return None,
        };
        return Some((format!("[{h}]"), port));
    }
    match a.rsplit_once(':') {
        Some((h, p)) if !h.is_empty() && !h.contains(':') => Some((h.to_string(), p.parse().ok()?)),
        Some(_) => None,
        None => Some((a.to_string(), default_port?)),
    }
}

/// For a forward-proxy request (`GET http://host/path HTTP/1.1`) returns the
/// target and the request head rewritten to origin form. One request per
/// connection: `Connection: close` is forced so a client cannot reuse the
/// tunnel for a different host.
fn forward_head(
    method: &str,
    target: &str,
    version: &str,
    headers: &[String],
) -> Option<(String, u16, String)> {
    if method.is_empty() || !method.bytes().all(|b| b.is_ascii_alphabetic()) {
        return None;
    }
    let lower = target.get(..7)?.to_ascii_lowercase();
    if lower != "http://" {
        return None;
    }
    let rest = &target[7..];
    let (auth, path) = match rest.find(['/', '?']) {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, "/"),
    };
    let path = if path.starts_with('?') {
        format!("/{path}")
    } else {
        path.to_string()
    };
    let (host, port) = parse_authority(auth, Some(80))?;
    if !version.starts_with("HTTP/1.") {
        return None;
    }
    let mut head = format!("{method} {path} {version}\r\n");
    let mut have_host = false;
    for h in headers {
        let name = h.split(':').next().unwrap_or("").trim().to_ascii_lowercase();
        match name.as_str() {
            "proxy-connection" | "proxy-authorization" | "connection" | "keep-alive" => continue,
            "host" => {
                have_host = true;
                head.push_str(&format!("Host: {auth}\r\n"));
            }
            _ => head.push_str(h.trim_end_matches(['\r', '\n'])),
        }
        if name != "host" {
            head.push_str("\r\n");
        }
    }
    if !have_host {
        head.push_str(&format!("Host: {auth}\r\n"));
    }
    head.push_str("Connection: close\r\n\r\n");
    Some((host, port, head))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn authority() {
        assert_eq!(parse_authority("a.b:443", None), Some(("a.b".into(), 443)));
        assert_eq!(parse_authority("[::1]:8080", None), Some(("[::1]".into(), 8080)));
        assert_eq!(parse_authority("a.b", Some(80)), Some(("a.b".into(), 80)));
        assert_eq!(parse_authority("a.b", None), None);
        assert_eq!(parse_authority("u@a.b:1", None), None);
        assert_eq!(parse_authority("::1:80", None), None);
    }

    #[test]
    fn forward_rewrites_to_origin_form() {
        let hs = vec![
            "Host: evil.example\r\n".to_string(),
            "Proxy-Connection: keep-alive\r\n".to_string(),
            "Accept: */*\r\n".to_string(),
        ];
        let (h, p, head) = forward_head("GET", "http://x.test:8080/a?b=1", "HTTP/1.1", &hs).unwrap();
        assert_eq!((h.as_str(), p), ("x.test", 8080));
        assert_eq!(
            head,
            "GET /a?b=1 HTTP/1.1\r\nHost: x.test:8080\r\nAccept: */*\r\nConnection: close\r\n\r\n"
        );
        assert!(forward_head("GET", "https://x/", "HTTP/1.1", &[]).is_none());
        assert!(forward_head("GET", "/relative", "HTTP/1.1", &[]).is_none());
        let (_, p, head) = forward_head("GET", "http://x.test", "HTTP/1.0", &[]).unwrap();
        assert_eq!(p, 80);
        assert!(head.starts_with("GET / HTTP/1.0\r\nHost: x.test\r\n"));
    }

    #[test]
    fn exports() {
        let e = export_lines("127.0.0.1:1080", None);
        assert!(e.contains("export HTTPS_PROXY=http://127.0.0.1:1080"));
        assert!(e.contains("export ALL_PROXY=socks5h://127.0.0.1:1080"));
        let a = Auth {
            user: "cjs".into(),
            pass: "pw".into(),
        };
        let e = export_lines("127.0.0.1:1080", Some(&a));
        assert!(e.contains("export HTTPS_PROXY=http://cjs:pw@127.0.0.1:1080"));
        assert!(e.contains("export ALL_PROXY=socks5h://cjs:pw@127.0.0.1:1080"));
    }

    #[test]
    fn basic_auth() {
        let a = Auth {
            user: "cjs".into(),
            pass: "pw".into(),
        };
        let ok = base64::engine::general_purpose::STANDARD.encode("cjs:pw");
        assert!(a.check_header(&format!(" Basic {ok}\r\n")));
        let bad = base64::engine::general_purpose::STANDARD.encode("cjs:px");
        assert!(!a.check_header(&format!("Basic {bad}")));
        assert!(!a.check_header("Bearer x"));
        assert!(!a.check(b"cjs", b"pw2"));
    }
}
