//! A direct, authenticated connection to the server.
use std::collections::HashMap;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use cjs_mux::{expect_msg, write_msg, MuxHandle, MuxStream};
use cjs_proto::{ErrorCode, OpenReply, OpenRequest, ProtoError, Role, Welcome};
use cjs_transport::profile::Profile;
use cjs_transport::{connect, new_hello, SessionHandle};
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;

use crate::VERSION;

/// Result of a successful open.
#[derive(Debug, Clone)]
pub struct Opened {
    pub id: u32,
    pub session: String,
}

type Forwards = Arc<Mutex<HashMap<u32, (String, u16)>>>;

pub struct AgentConn {
    pub mux: MuxHandle,
    pub handle: SessionHandle,
    pub welcome: Welcome,
    pub transport: &'static str,
    pub server: String,
    forwards: Forwards,
}

impl std::fmt::Debug for AgentConn {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AgentConn")
            .field("name", &self.welcome.name)
            .finish()
    }
}

/// Keeps a remote-forward target registered while alive.
#[derive(Debug)]
pub struct ForwardGuard {
    forwards: Forwards,
    id: u32,
}

impl Drop for ForwardGuard {
    fn drop(&mut self) {
        self.forwards
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .remove(&self.id);
    }
}

impl AgentConn {
    pub async fn connect(dir: &Path) -> Result<Arc<Self>, ProtoError> {
        let profile = Profile::load(dir)?;
        let cfg = profile.client_config(Profile::key(dir)?)?;
        let conn = tokio::time::timeout(
            Duration::from_secs(60),
            connect(&cfg, new_hello(Role::Agent, None, VERSION)),
        )
        .await
        .map_err(|_| ProtoError::new(ErrorCode::Timeout, "connecting to the server timed out"))??;
        let (mux, mut inbound, _t) = cjs_mux::spawn(conn.io, cjs_mux::Mode::Client);
        let forwards: Forwards = Default::default();
        let f2 = forwards.clone();
        tokio::spawn(async move {
            while let Some(s) = inbound.recv().await {
                let f = f2.clone();
                tokio::spawn(async move { inbound_stream(f, s).await });
            }
        });
        Ok(Arc::new(Self {
            mux,
            handle: conn.handle,
            welcome: conn.welcome,
            transport: conn.transport,
            server: profile.server,
            forwards,
        }))
    }

    pub fn is_closed(&self) -> bool {
        self.handle.is_closed() || self.mux.is_closed()
    }

    /// Open a stream and wait for the server's answer.
    pub async fn open(&self, req: &OpenRequest) -> Result<(MuxStream, Opened), ProtoError> {
        let mut s = self.mux.open().await?;
        write_msg(&mut s, req).await?;
        match tokio::time::timeout(Duration::from_secs(60), expect_msg::<_, OpenReply>(&mut s))
            .await
            .map_err(|_| ProtoError::new(ErrorCode::Timeout, "server did not answer"))??
        {
            OpenReply::Ok { id, session } => Ok((s, Opened { id, session })),
            OpenReply::Err(e) => Err(e),
        }
    }

    /// Open a remote forward; incoming connections are dialed to
    /// `local_host:local_port` for as long as the returned guard lives.
    pub async fn forward_remote(
        &self,
        req: &OpenRequest,
        local_host: &str,
        local_port: u16,
    ) -> Result<(MuxStream, Opened, ForwardGuard), ProtoError> {
        if !matches!(req, OpenRequest::ForwardR { .. }) {
            return Err(ProtoError::new(ErrorCode::BadRequest, "not a remote forward"));
        }
        let (s, o) = self.open(req).await?;
        self.forwards
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .insert(o.id, (local_host.to_string(), local_port));
        let g = ForwardGuard {
            forwards: self.forwards.clone(),
            id: o.id,
        };
        Ok((s, o, g))
    }
}

async fn inbound_stream(forwards: Forwards, mut s: MuxStream) {
    let req: OpenRequest = match tokio::time::timeout(Duration::from_secs(30), expect_msg(&mut s)).await {
        Ok(Ok(r)) => r,
        _ => return,
    };
    let OpenRequest::ForwardRConn { listener, peer } = req else {
        let _ = write_msg(
            &mut s,
            &OpenReply::Err(ProtoError::new(
                ErrorCode::Forbidden,
                "agents only accept forward connections",
            )),
        )
        .await;
        return;
    };
    let target = forwards
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .get(&listener)
        .cloned();
    let Some((host, port)) = target else {
        let _ = write_msg(
            &mut s,
            &OpenReply::Err(ProtoError::new(ErrorCode::NotFound, "no such forward")),
        )
        .await;
        return;
    };
    let tcp = tokio::time::timeout(Duration::from_secs(10), TcpStream::connect((host.as_str(), port))).await;
    let mut tcp = match tcp {
        Ok(Ok(t)) => t,
        Ok(Err(e)) => {
            let _ = write_msg(
                &mut s,
                &OpenReply::Err(ProtoError::new(
                    ErrorCode::Io,
                    format!("connect {host}:{port}: {e}"),
                )),
            )
            .await;
            return;
        }
        Err(_) => {
            let _ = write_msg(
                &mut s,
                &OpenReply::Err(ProtoError::new(ErrorCode::Timeout, "connect timed out")),
            )
            .await;
            return;
        }
    };
    let _ = tcp.set_nodelay(true);
    tracing::info!(%peer, "remote forward connection");
    if write_msg(
        &mut s,
        &OpenReply::Ok {
            id: listener,
            session: String::new(),
        },
    )
    .await
    .is_err()
    {
        return;
    }
    let _ = tokio::io::copy_bidirectional(&mut s, &mut tcp).await;
    let _ = s.shutdown().await;
}
