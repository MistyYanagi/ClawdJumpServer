//! Test harness: a real server on a local port, a real device daemon and a
//! real agent identity, all enrolled through one-time tokens.
#![forbid(unsafe_code)]

use std::collections::BTreeSet;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::time::Duration;

use cjs_authz::{Grant, Subject, Target};
use cjs_mux::{expect_msg, write_msg, MuxHandle, MuxStream};
use cjs_proto::{Action, ErrorCode, OpenReply, OpenRequest, ProtoError, Role};
use cjs_server::accounts;
use cjs_server::db::Db;
use cjs_server::{Keys, Server, ServerConfig};
use cjs_transport::profile::Profile;
use cjs_transport::{connect, new_hello, TransportMode};

pub use cjs_server;

pub struct Env {
    pub tmp: tempfile::TempDir,
    pub server: Server,
    pub addr: SocketAddr,
    pub url: String,
    pub mode: TransportMode,
    pub owner: String,
    pub admin: String,
    pub project: PathBuf,
    pub device_dir: PathBuf,
    pub agent_dir: PathBuf,
    pub device_id: String,
    pub agent_id: String,
    device_task: Option<tokio::task::JoinHandle<()>>,
}

impl Drop for Env {
    fn drop(&mut self) {
        if let Some(t) = self.device_task.take() {
            t.abort();
        }
    }
}

/// The sandbox helper binary built next to the test executable
/// (`target/<profile>/cjs-test-helper`).
pub fn helper_exe() -> PathBuf {
    let exe = std::env::current_exe().unwrap();
    let dir = exe.parent().unwrap();
    let dir = if dir.ends_with("deps") {
        dir.parent().unwrap()
    } else {
        dir
    };
    dir.join(format!("cjs-test-helper{}", std::env::consts::EXE_SUFFIX))
}

/// Mode from `CJS_TEST_TRANSPORT` (ws|http), default ws.
pub fn mode_from_env() -> TransportMode {
    std::env::var("CJS_TEST_TRANSPORT")
        .ok()
        .and_then(|m| m.parse().ok())
        .unwrap_or(TransportMode::Ws)
}

pub async fn serve(server: &Server) -> SocketAddr {
    let app = server.router();
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(
            axum::serve::ListenerExt::tap_io(l, |t| {
                let _ = t.set_nodelay(true);
            }),
            app.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .await
        .unwrap()
    });
    addr
}

impl Env {
    pub async fn start(mode: TransportMode) -> Env {
        let tmp = tempfile::tempdir().unwrap();
        let data = tmp.path().join("server");
        std::fs::create_dir_all(&data).unwrap();
        let keys = Keys::load_or_create(&data).unwrap();
        let db = Db::open(&data.join("cjs.db")).unwrap();
        let audit = cjs_audit::AuditLog::open(&data.join("audit.db"), keys.audit.clone()).unwrap();
        let mut cfg = ServerConfig::new(&data);
        cfg.lease_interval = Duration::from_millis(300);
        cfg.secure_cookies = false;
        let server = Server::start(cfg, keys, db, audit);
        let addr = serve(&server).await;
        let url = format!("http://{addr}/");
        // Users: an admin (sysadmin+secadmin) and the agent's owner.
        let admin = accounts::create_user(
            "admin",
            vec![cjs_authz::Role::Sysadmin, cjs_authz::Role::Secadmin],
            None,
        )
        .unwrap();
        server.shared.db.insert_user(&admin.user).unwrap();
        let owner = accounts::create_user("alice", vec![], None).unwrap();
        server.shared.db.insert_user(&owner.user).unwrap();
        let project = tmp.path().join("project");
        std::fs::create_dir_all(&project).unwrap();
        let project = std::fs::canonicalize(&project).unwrap();
        let device_dir = tmp.path().join("device");
        let agent_dir = tmp.path().join("agent");
        let (_, dtok) = server
            .create_enroll_token(Role::Device, "dev1", None, &admin.user.id, 600)
            .unwrap();
        let dp = cjs_transport::profile::enroll(&device_dir, Role::Device, &url, &dtok, mode, None, "test")
            .await
            .unwrap();
        let (_, atok) = server
            .create_enroll_token(Role::Agent, "agent1", Some(&owner.user.id), &admin.user.id, 600)
            .unwrap();
        let ap = cjs_transport::profile::enroll(&agent_dir, Role::Agent, &url, &atok, mode, None, "test")
            .await
            .unwrap();
        let mut env = Env {
            tmp,
            server,
            addr,
            url,
            mode,
            owner: owner.user.id,
            admin: admin.user.id,
            project,
            device_dir,
            agent_dir,
            device_id: dp.id,
            agent_id: ap.id,
            device_task: None,
        };
        env.start_device();
        env.wait_device_online(true).await;
        env
    }

    pub fn start_device(&mut self) {
        let opts = cjs_device::DeviceOptions {
            dir: self.device_dir.clone(),
            helper: helper_exe(),
        };
        self.device_task = Some(tokio::spawn(async move {
            let _ = cjs_device::run(opts).await;
        }));
    }

    pub async fn wait_device_online(&self, online: bool) {
        for _ in 0..200 {
            if self.server.shared.reg.is_online(&self.device_id) == online {
                return;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        panic!("device online != {online}");
    }

    pub fn tmp(&self) -> &Path {
        self.tmp.path()
    }

    /// A grant for the test agent on the test device.
    pub fn grant(&self, id: &str, actions: &[Action]) -> Grant {
        Grant {
            id: id.into(),
            name: id.into(),
            subject: Subject::Principal(self.agent_id.clone()),
            target: Target::Device(self.device_id.clone()),
            actions: actions.iter().copied().collect::<BTreeSet<_>>(),
            project_roots: vec![self.project.to_string_lossy().into_owned()],
            schedule: None,
            not_before: None,
            expires_at: None,
            forward_targets: vec![],
            remote_ports: vec![],
            egress: vec![],
            max_sessions: None,
            enabled: true,
        }
    }

    pub fn put_grant(&self, g: &Grant) {
        g.validate().unwrap();
        self.server.shared.db.upsert_grant(g, &self.admin).unwrap();
    }

    /// Connect as the enrolled agent.
    pub async fn agent(&self) -> Agent {
        let p = Profile::load(&self.agent_dir).unwrap();
        let cfg = p.client_config(Profile::key(&self.agent_dir).unwrap()).unwrap();
        let conn = connect(&cfg, new_hello(Role::Agent, None, "test")).await.unwrap();
        let (mux, inbound, _t) = cjs_mux::spawn(conn.io, cjs_mux::Mode::Client);
        Agent {
            mux,
            inbound,
            handle: conn.handle,
        }
    }

    pub fn audit_kinds(&self) -> Vec<(String, String)> {
        self.server
            .shared
            .audit
            .query(&cjs_audit::Query {
                limit: Some(10_000),
                desc: Some(false),
                ..Default::default()
            })
            .unwrap()
            .into_iter()
            .map(|r| (r.record.event.kind, r.record.event.outcome.as_str().to_string()))
            .collect()
    }
}

pub struct Agent {
    pub mux: MuxHandle,
    pub inbound: tokio::sync::mpsc::UnboundedReceiver<MuxStream>,
    pub handle: cjs_transport::SessionHandle,
}

impl Agent {
    /// Open a stream; returns the stream and the session id, or the error.
    pub async fn open(&self, req: OpenRequest) -> Result<(MuxStream, String), ProtoError> {
        let mut s = self.mux.open().await?;
        write_msg(&mut s, &req).await?;
        match tokio::time::timeout(Duration::from_secs(30), expect_msg::<_, OpenReply>(&mut s))
            .await
            .map_err(|_| ProtoError::new(ErrorCode::Timeout, "open timed out"))??
        {
            OpenReply::Ok { session, .. } => Ok((s, session)),
            OpenReply::Err(e) => Err(e),
        }
    }
}

pub fn pty_req(device: &str) -> OpenRequest {
    OpenRequest::Pty {
        device: device.into(),
        cols: 80,
        rows: 24,
        term: "xterm-256color".into(),
        command: Some(vec!["/bin/sh".into()]),
        cwd: None,
    }
}

pub fn exec_req(device: &str, script: &str) -> OpenRequest {
    OpenRequest::Exec {
        device: device.into(),
        argv: vec!["/bin/sh".into(), "-c".into(), script.into()],
        cwd: None,
        env: vec![],
        timeout_secs: Some(60),
    }
}

/// Run a command to completion: (stdout, stderr, exit code).
pub async fn run_exec(a: &Agent, req: OpenRequest) -> Result<(String, String, Option<i32>), ProtoError> {
    use cjs_proto::{ExecIn, ExecOut};
    let (mut s, _) = a.open(req).await?;
    write_msg(&mut s, &ExecIn::StdinEof).await?;
    let (mut out, mut err, mut code) = (Vec::new(), Vec::new(), None);
    while let Some(m) = cjs_mux::read_msg::<_, ExecOut>(&mut s).await? {
        match m {
            ExecOut::Stdout(b) => out.extend(b),
            ExecOut::Stderr(b) => err.extend(b),
            ExecOut::Exit { code: c, .. } => {
                code = c;
                break;
            }
        }
    }
    Ok((
        String::from_utf8_lossy(&out).into_owned(),
        String::from_utf8_lossy(&err).into_owned(),
        code,
    ))
}

/// Read PTY output until `needle` appears (or timeout). Returns all output.
pub async fn pty_expect(s: &mut MuxStream, needle: &str, secs: u64) -> Result<String, String> {
    use cjs_proto::PtyOut;
    let mut acc = String::new();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(secs);
    loop {
        match tokio::time::timeout_at(deadline, cjs_mux::read_msg::<_, PtyOut>(s)).await {
            Err(_) => return Err(format!("timeout waiting for {needle:?}; got {acc:?}")),
            Ok(Ok(Some(PtyOut::Output(b)))) => {
                acc.push_str(&String::from_utf8_lossy(&b));
                if acc.contains(needle) {
                    return Ok(acc);
                }
            }
            Ok(Ok(Some(PtyOut::Exit { code }))) => {
                return Err(format!("exited ({code:?}) before {needle:?}; got {acc:?}"))
            }
            Ok(Ok(None)) => return Err(format!("eof before {needle:?}; got {acc:?}")),
            Ok(Err(e)) => return Err(format!("{e}; got {acc:?}")),
        }
    }
}
