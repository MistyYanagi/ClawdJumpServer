//! Local daemon: keeps one server connection alive and serves CLI
//! invocations over a Unix socket (Windows: named pipe).
//!
//! Local protocol (length-prefixed postcard, see `cjs-mux`):
//! client -> daemon: [`LocalHello`], then one [`LocalRequest`].
//! * `Open(req)`: the daemon opens a server stream, forwards `req`, and
//!   from then on splices bytes, so the client sees exactly the stream
//!   protocol (starting with the server's `OpenReply`).
//! * `ForwardR`: the daemon runs the remote forward itself (it dials the
//!   local target for every incoming connection); the client connection
//!   is the forward's lifetime.
//! * `Status`: one [`LocalStatus`] reply.
//!
//! The socket lives in the per-user config directory (0700). In addition
//! every client must present the random token from `daemon.token` (0600),
//! compared in constant time, so other local users cannot borrow the
//! agent's identity even if the socket or pipe were reachable.
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use cjs_mux::{expect_msg, write_msg, MuxStream};
use cjs_proto::{ErrorCode, OpenReply, OpenRequest, ProtoError};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio::sync::RwLock;

use crate::conn::{AgentConn, Opened};

pub const TOKEN_FILE: &str = "daemon.token";
pub const LOCAL_VERSION: u16 = 1;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LocalHello {
    pub version: u16,
    pub token: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum LocalRequest {
    Open(OpenRequest),
    ForwardR {
        req: OpenRequest,
        local_host: String,
        local_port: u16,
    },
    Status,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LocalStatus {
    pub connected: bool,
    pub principal: String,
    pub name: String,
    pub transport: String,
    pub server: String,
    pub pid: u32,
}

pub trait Duplex: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Duplex for T {}

impl std::fmt::Debug for dyn Duplex {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Stream")
    }
}

pub type BoxStream = Box<dyn Duplex>;

#[cfg(unix)]
pub fn socket_path(dir: &Path) -> PathBuf {
    dir.join("agent.sock")
}

#[cfg(windows)]
pub fn socket_path(dir: &Path) -> PathBuf {
    use sha2::Digest;
    let h = hex::encode(&sha2::Sha256::digest(dir.to_string_lossy().as_bytes())[..8]);
    PathBuf::from(format!(r"\\.\pipe\cjs-agent-{h}"))
}

fn ioe(e: std::io::Error) -> ProtoError {
    ProtoError::new(ErrorCode::Io, e.to_string())
}

async fn dial_local(dir: &Path) -> Result<BoxStream, ProtoError> {
    let path = socket_path(dir);
    #[cfg(unix)]
    {
        Ok(Box::new(
            tokio::net::UnixStream::connect(&path).await.map_err(ioe)?,
        ))
    }
    #[cfg(windows)]
    {
        let c = tokio::net::windows::named_pipe::ClientOptions::new()
            .open(&path)
            .map_err(ioe)?;
        Ok(Box::new(c))
    }
}

fn read_token(dir: &Path) -> Result<String, ProtoError> {
    std::fs::read_to_string(dir.join(TOKEN_FILE))
        .map(|s| s.trim().to_string())
        .map_err(ioe)
}

/// How CLI commands reach the server.
#[derive(Clone)]
pub enum Opener {
    Direct(Arc<AgentConn>),
    Daemon { dir: PathBuf, token: String },
}

impl std::fmt::Debug for Opener {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Opener::Direct(_) => f.write_str("Opener::Direct"),
            Opener::Daemon { .. } => f.write_str("Opener::Daemon"),
        }
    }
}

impl Opener {
    /// Use the daemon if one is running for `dir`, else connect directly.
    pub async fn new(dir: &Path, direct: bool) -> Result<Self, ProtoError> {
        if !direct {
            if let Ok(token) = read_token(dir) {
                let o = Opener::Daemon {
                    dir: dir.to_path_buf(),
                    token,
                };
                if o.status().await.map(|s| s.connected).unwrap_or(false) {
                    return Ok(o);
                }
            }
        }
        Ok(Opener::Direct(AgentConn::connect(dir).await?))
    }

    async fn local(&self, req: &LocalRequest) -> Result<BoxStream, ProtoError> {
        let Opener::Daemon { dir, token } = self else {
            return Err(ProtoError::new(ErrorCode::Internal, "not a daemon opener"));
        };
        let mut s = dial_local(dir).await?;
        write_msg(
            &mut s,
            &LocalHello {
                version: LOCAL_VERSION,
                token: token.clone(),
            },
        )
        .await?;
        write_msg(&mut s, req).await?;
        Ok(s)
    }

    pub async fn status(&self) -> Result<LocalStatus, ProtoError> {
        match self {
            Opener::Direct(c) => Ok(LocalStatus {
                connected: !c.is_closed(),
                principal: c.welcome.principal_id.clone(),
                name: c.welcome.name.clone(),
                transport: c.transport.into(),
                server: c.server.clone(),
                pid: std::process::id(),
            }),
            Opener::Daemon { .. } => {
                let mut s = self.local(&LocalRequest::Status).await?;
                tokio::time::timeout(Duration::from_secs(5), expect_msg(&mut s))
                    .await
                    .map_err(|_| ProtoError::new(ErrorCode::Timeout, "daemon did not answer"))?
            }
        }
    }

    pub async fn open(&self, req: &OpenRequest) -> Result<(BoxStream, Opened), ProtoError> {
        match self {
            Opener::Direct(c) => {
                let (s, o) = c.open(req).await?;
                Ok((Box::new(s), o))
            }
            Opener::Daemon { .. } => {
                let mut s = self.local(&LocalRequest::Open(req.clone())).await?;
                match expect_msg::<_, OpenReply>(&mut s).await? {
                    OpenReply::Ok { id, session } => Ok((s, Opened { id, session })),
                    OpenReply::Err(e) => Err(e),
                }
            }
        }
    }

    /// Run a remote forward until the returned future's stream ends.
    /// Returns the control stream; dropping it ends the forward.
    pub async fn forward_remote(
        &self,
        req: &OpenRequest,
        local_host: &str,
        local_port: u16,
    ) -> Result<(BoxStream, Opened, Option<crate::conn::ForwardGuard>), ProtoError> {
        match self {
            Opener::Direct(c) => {
                let (s, o, g) = c.forward_remote(req, local_host, local_port).await?;
                Ok((Box::new(s), o, Some(g)))
            }
            Opener::Daemon { .. } => {
                let mut s = self
                    .local(&LocalRequest::ForwardR {
                        req: req.clone(),
                        local_host: local_host.into(),
                        local_port,
                    })
                    .await?;
                match expect_msg::<_, OpenReply>(&mut s).await? {
                    OpenReply::Ok { id, session } => Ok((s, Opened { id, session }, None)),
                    OpenReply::Err(e) => Err(e),
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Daemon
// ---------------------------------------------------------------------------

struct Daemon {
    dir: PathBuf,
    token: String,
    conn: RwLock<Option<Arc<AgentConn>>>,
}

impl Daemon {
    async fn current(&self) -> Result<Arc<AgentConn>, ProtoError> {
        for _ in 0..100 {
            if let Some(c) = self.conn.read().await.as_ref() {
                if !c.is_closed() {
                    return Ok(c.clone());
                }
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        Err(ProtoError::new(
            ErrorCode::Io,
            "daemon is not connected to the server",
        ))
    }

    async fn keep_connected(self: Arc<Self>) {
        let mut backoff = Duration::from_secs(1);
        loop {
            match AgentConn::connect(&self.dir).await {
                Ok(c) => {
                    tracing::info!(agent = %c.welcome.name, transport = c.transport, "connected");
                    backoff = Duration::from_secs(1);
                    *self.conn.write().await = Some(c.clone());
                    let e = c.handle.closed().await;
                    tracing::warn!(err = %e, "connection closed");
                    *self.conn.write().await = None;
                }
                Err(e) => {
                    tracing::warn!(err = %e, "connect failed");
                    if matches!(e.code, ErrorCode::Unauthenticated | ErrorCode::Disabled) {
                        backoff = Duration::from_secs(60);
                    }
                }
            }
            tokio::time::sleep(backoff).await;
            backoff = (backoff * 2).min(Duration::from_secs(60));
        }
    }

    async fn serve_client(self: Arc<Self>, mut s: BoxStream) {
        let hello: LocalHello = match tokio::time::timeout(Duration::from_secs(10), expect_msg(&mut s)).await
        {
            Ok(Ok(h)) => h,
            _ => return,
        };
        let ok: bool = subtle::ConstantTimeEq::ct_eq(hello.token.as_bytes(), self.token.as_bytes()).into();
        if !ok || hello.version != LOCAL_VERSION {
            let _ = write_msg(
                &mut s,
                &OpenReply::Err(ProtoError::new(ErrorCode::Unauthenticated, "bad daemon token")),
            )
            .await;
            return;
        }
        let req: LocalRequest = match expect_msg(&mut s).await {
            Ok(r) => r,
            Err(_) => return,
        };
        match req {
            LocalRequest::Status => {
                let st = match self.conn.read().await.as_ref() {
                    Some(c) if !c.is_closed() => LocalStatus {
                        connected: true,
                        principal: c.welcome.principal_id.clone(),
                        name: c.welcome.name.clone(),
                        transport: c.transport.into(),
                        server: c.server.clone(),
                        pid: std::process::id(),
                    },
                    _ => LocalStatus {
                        connected: false,
                        principal: String::new(),
                        name: String::new(),
                        transport: String::new(),
                        server: String::new(),
                        pid: std::process::id(),
                    },
                };
                let _ = write_msg(&mut s, &st).await;
            }
            LocalRequest::Open(req) => {
                let c = match self.current().await {
                    Ok(c) => c,
                    Err(e) => {
                        let _ = write_msg(&mut s, &OpenReply::Err(e)).await;
                        return;
                    }
                };
                let mut up: MuxStream = match c.mux.open().await {
                    Ok(u) => u,
                    Err(e) => {
                        let _ = write_msg(&mut s, &OpenReply::Err(e)).await;
                        return;
                    }
                };
                if let Err(e) = write_msg(&mut up, &req).await {
                    let _ = write_msg(&mut s, &OpenReply::Err(e)).await;
                    return;
                }
                let _ = tokio::io::copy_bidirectional(&mut s, &mut up).await;
                let _ = up.shutdown().await;
            }
            LocalRequest::ForwardR {
                req,
                local_host,
                local_port,
            } => {
                let c = match self.current().await {
                    Ok(c) => c,
                    Err(e) => {
                        let _ = write_msg(&mut s, &OpenReply::Err(e)).await;
                        return;
                    }
                };
                match c.forward_remote(&req, &local_host, local_port).await {
                    Ok((mut ctl, o, _guard)) => {
                        if write_msg(
                            &mut s,
                            &OpenReply::Ok {
                                id: o.id,
                                session: o.session,
                            },
                        )
                        .await
                        .is_err()
                        {
                            return;
                        }
                        // Lives until either the client or the server side ends.
                        let mut a = [0u8; 16];
                        let mut b = [0u8; 16];
                        use tokio::io::AsyncReadExt;
                        tokio::select! {
                            _ = s.read(&mut a) => {}
                            _ = ctl.read(&mut b) => {}
                        }
                        let _ = ctl.shutdown().await;
                    }
                    Err(e) => {
                        let _ = write_msg(&mut s, &OpenReply::Err(e)).await;
                    }
                }
            }
        }
    }
}

/// Run the daemon in the foreground until killed.
pub async fn run_daemon(dir: &Path) -> Result<(), ProtoError> {
    cjs_transport::profile::Profile::load(dir)?;
    cjs_transport::profile::restrict_dir(dir);
    let token = crate::random_secret();
    cjs_transport::keys::write_secret_file(&dir.join(TOKEN_FILE), token.as_bytes())?;
    let d = Arc::new(Daemon {
        dir: dir.to_path_buf(),
        token,
        conn: RwLock::new(None),
    });
    tokio::spawn(d.clone().keep_connected());
    let path = socket_path(dir);
    tracing::info!(socket = %path.display(), "daemon listening");
    #[cfg(unix)]
    {
        let _ = std::fs::remove_file(&path);
        let l = tokio::net::UnixListener::bind(&path).map_err(ioe)?;
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));
        }
        loop {
            let (s, _) = l.accept().await.map_err(ioe)?;
            tokio::spawn(d.clone().serve_client(Box::new(s)));
        }
    }
    #[cfg(windows)]
    {
        use tokio::net::windows::named_pipe::ServerOptions;
        let mut server = ServerOptions::new()
            .first_pipe_instance(true)
            .reject_remote_clients(true)
            .create(&path)
            .map_err(ioe)?;
        loop {
            server.connect().await.map_err(ioe)?;
            let client = server;
            server = ServerOptions::new()
                .reject_remote_clients(true)
                .create(&path)
                .map_err(ioe)?;
            tokio::spawn(d.clone().serve_client(Box::new(client)));
        }
    }
}
