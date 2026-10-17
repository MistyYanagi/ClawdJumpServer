//! Client TLS and proxy helpers.
//!
//! Cloud agents usually sit behind an HTTPS proxy that re-signs TLS with its
//! own CA. We trust: the platform roots (which honour `SSL_CERT_FILE` /
//! `SSL_CERT_DIR`), the Mozilla roots, and an optional extra CA bundle. The
//! TLS layer only protects the outer hop; session confidentiality comes from
//! Noise with a pinned server key.
use std::path::Path;
use std::sync::Arc;

use cjs_proto::{ErrorCode, ProtoError};
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;

fn err(m: impl std::fmt::Display) -> ProtoError {
    ProtoError::new(ErrorCode::Io, m.to_string())
}

pub fn load_pem_certs(path: &Path) -> Result<Vec<rustls::pki_types::CertificateDer<'static>>, ProtoError> {
    let data = std::fs::read(path).map_err(|e| err(format!("{}: {e}", path.display())))?;
    use rustls::pki_types::pem::PemObject;
    rustls::pki_types::CertificateDer::pem_slice_iter(&data)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| err(format!("{}: {e}", path.display())))
}

pub fn root_store(extra_ca: Option<&Path>) -> Result<rustls::RootCertStore, ProtoError> {
    let mut roots = rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let native = rustls_native_certs::load_native_certs();
    for c in native.certs {
        let _ = roots.add(c);
    }
    if let Some(p) = extra_ca {
        for c in load_pem_certs(p)? {
            roots.add(c).map_err(err)?;
        }
    }
    Ok(roots)
}

pub fn client_config(extra_ca: Option<&Path>) -> Result<Arc<rustls::ClientConfig>, ProtoError> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let cfg = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(err)?
        .with_root_certificates(root_store(extra_ca)?)
        .with_no_client_auth();
    Ok(Arc::new(cfg))
}

/// Proxy URL to use for `target` (scheme "http"/"https"), honouring
/// `HTTPS_PROXY`/`HTTP_PROXY`/`ALL_PROXY` and `NO_PROXY`.
pub fn proxy_for(scheme: &str, host: &str) -> Option<url::Url> {
    let get = |k: &str| {
        std::env::var(k)
            .ok()
            .or_else(|| std::env::var(k.to_lowercase()).ok())
    };
    if let Some(np) = get("NO_PROXY") {
        for pat in np.split(',').map(str::trim).filter(|p| !p.is_empty()) {
            if pat == "*" {
                return None;
            }
            let pat = pat.trim_start_matches('.').trim_start_matches("*.");
            if host == pat || host.ends_with(&format!(".{pat}")) {
                return None;
            }
        }
    }
    if host == "localhost" || host == "127.0.0.1" || host == "::1" || host == "[::1]" {
        return None;
    }
    let v = if scheme == "https" || scheme == "wss" {
        get("HTTPS_PROXY").or_else(|| get("ALL_PROXY"))
    } else {
        get("HTTP_PROXY").or_else(|| get("ALL_PROXY"))
    }?;
    url::Url::parse(&v).ok()
}

/// Open a TCP connection to `host:port`, through an HTTP CONNECT proxy when
/// one applies.
pub async fn dial(scheme: &str, host: &str, port: u16) -> Result<Box<dyn Io>, ProtoError> {
    if let Some(proxy) = proxy_for(scheme, host) {
        let ph = proxy.host_str().ok_or_else(|| err("bad proxy url"))?.to_string();
        let pp = proxy.port_or_known_default().unwrap_or(8080);
        let tcp = TcpStream::connect((ph.as_str(), pp)).await.map_err(err)?;
        tcp.set_nodelay(true).ok();
        let auth = if !proxy.username().is_empty() {
            use base64::Engine;
            let up = format!(
                "{}:{}",
                urlencoding_decode(proxy.username()),
                urlencoding_decode(proxy.password().unwrap_or(""))
            );
            format!(
                "Proxy-Authorization: Basic {}\r\n",
                base64::engine::general_purpose::STANDARD.encode(up)
            )
        } else {
            String::new()
        };
        let io: Box<dyn Io> = if proxy.scheme() == "https" {
            let cfg = client_config(None)?;
            let name = rustls::pki_types::ServerName::try_from(ph.clone()).map_err(err)?;
            Box::new(
                tokio_rustls::TlsConnector::from(cfg)
                    .connect(name, tcp)
                    .await
                    .map_err(err)?,
            )
        } else {
            Box::new(tcp)
        };
        let mut io = BufReader::new(io);
        let req = format!("CONNECT {host}:{port} HTTP/1.1\r\nHost: {host}:{port}\r\n{auth}\r\n");
        io.get_mut().write_all(req.as_bytes()).await.map_err(err)?;
        let mut line = String::new();
        io.read_line(&mut line).await.map_err(err)?;
        let ok = line
            .split_whitespace()
            .nth(1)
            .map(|c| c.starts_with('2'))
            .unwrap_or(false);
        if !ok {
            return Err(ProtoError::new(
                ErrorCode::Io,
                format!("proxy CONNECT failed: {}", line.trim()),
            ));
        }
        loop {
            line.clear();
            io.read_line(&mut line).await.map_err(err)?;
            if line == "\r\n" || line == "\n" || line.is_empty() {
                break;
            }
        }
        if !io.buffer().is_empty() {
            return Err(err("proxy sent data before tunnel was established"));
        }
        Ok(io.into_inner())
    } else {
        let tcp = TcpStream::connect((host, port)).await.map_err(err)?;
        tcp.set_nodelay(true).ok();
        Ok(Box::new(tcp))
    }
}

fn urlencoding_decode(s: &str) -> String {
    url::form_urlencoded::parse(format!("x={s}").as_bytes())
        .next()
        .map(|(_, v)| v.into_owned())
        .unwrap_or_default()
}

pub trait Io: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Io for T {}
