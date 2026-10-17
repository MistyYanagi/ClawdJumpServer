//! ClawdJumpServer wire protocol.
//!
//! Everything that crosses a process boundary is defined here and encoded
//! with `postcard`. The layering is:
//!
//! ```text
//! TLS (WebSocket | HTTP long-poll) -> WireMsg::Seg (seq/ack, resumable)
//!     -> Noise transport message (nonce = seq) -> byte stream -> yamux
//!     -> length-prefixed postcard messages per stream
//! ```
//!
//! Logical streams are multiplexed with yamux (`cjs-mux`). Each stream is
//! opened with an [`OpenRequest`] (agent -> server) or a [`DeviceOpen`]
//! (server -> device, carrying a signed capability). Inside a stream, data
//! frames carry the per-kind messages ([`PtyIn`], [`ExecOut`], [`FileMsg`],
//! ...), one message per data frame, or raw bytes for TCP-like streams
//! (forwarding and egress).
#![forbid(unsafe_code)]

use serde::{de::DeserializeOwned, Deserialize, Serialize};

/// Protocol version carried in [`Hello`]. Bumped on incompatible change.
pub const PROTO_VERSION: u16 = 1;
/// Noise pattern used for every connection. The client pins the server's
/// static key, the server learns and authenticates the client's static key.
pub const NOISE_PARAMS: &str = "Noise_IK_25519_ChaChaPoly_BLAKE2s";
/// Largest Noise message.
pub const NOISE_MAX_MSG: usize = 65535;
/// Largest plaintext that fits in one Noise message.
pub const MAX_FRAME_PLAINTEXT: usize = NOISE_MAX_MSG - 16;
/// Largest payload of a single `Data` frame (leaves headroom for framing).
pub const MAX_DATA_CHUNK: usize = 32 * 1024;
/// Maximum allowed clock skew for handshake timestamps (seconds).
pub const HANDSHAKE_MAX_SKEW_SECS: i64 = 120;

/// Stable error codes. The string form (see [`ErrorCode::as_str`]) is part of
/// the public CLI/JSON contract and must never change for an existing code.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ErrorCode {
    Unauthenticated,
    Forbidden,
    NotFound,
    DeviceOffline,
    BadRequest,
    Internal,
    AuditFailure,
    Expired,
    Replay,
    Conflict,
    Io,
    Timeout,
    Unsupported,
    LimitExceeded,
    Protocol,
    Disabled,
    Cancelled,
    SandboxUnavailable,
}

impl ErrorCode {
    pub fn as_str(self) -> &'static str {
        match self {
            ErrorCode::Unauthenticated => "unauthenticated",
            ErrorCode::Forbidden => "forbidden",
            ErrorCode::NotFound => "not_found",
            ErrorCode::DeviceOffline => "device_offline",
            ErrorCode::BadRequest => "bad_request",
            ErrorCode::Internal => "internal",
            ErrorCode::AuditFailure => "audit_failure",
            ErrorCode::Expired => "expired",
            ErrorCode::Replay => "replay",
            ErrorCode::Conflict => "conflict",
            ErrorCode::Io => "io",
            ErrorCode::Timeout => "timeout",
            ErrorCode::Unsupported => "unsupported",
            ErrorCode::LimitExceeded => "limit_exceeded",
            ErrorCode::Protocol => "protocol",
            ErrorCode::Disabled => "disabled",
            ErrorCode::Cancelled => "cancelled",
            ErrorCode::SandboxUnavailable => "sandbox_unavailable",
        }
    }

    /// Process exit code used by the CLIs for this error (stable).
    pub fn exit_code(self) -> i32 {
        match self {
            ErrorCode::Unauthenticated => 10,
            ErrorCode::Forbidden => 11,
            ErrorCode::NotFound => 12,
            ErrorCode::DeviceOffline => 13,
            ErrorCode::BadRequest => 14,
            ErrorCode::Internal => 15,
            ErrorCode::AuditFailure => 16,
            ErrorCode::Expired => 17,
            ErrorCode::Replay => 18,
            ErrorCode::Conflict => 19,
            ErrorCode::Io => 20,
            ErrorCode::Timeout => 21,
            ErrorCode::Unsupported => 22,
            ErrorCode::LimitExceeded => 23,
            ErrorCode::Protocol => 24,
            ErrorCode::Disabled => 25,
            ErrorCode::Cancelled => 26,
            ErrorCode::SandboxUnavailable => 27,
        }
    }
}

impl std::fmt::Display for ErrorCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A protocol-level error with a stable code and a human message.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, thiserror::Error)]
#[error("{code}: {message}")]
pub struct ProtoError {
    pub code: ErrorCode,
    pub message: String,
}

impl ProtoError {
    pub fn new(code: ErrorCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }
}

// ---------------------------------------------------------------------------
// Handshake
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Role {
    Agent,
    Device,
}

/// Payload of Noise message 1 (client -> server, encrypted to the pinned
/// server key).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Hello {
    pub version: u16,
    pub role: Role,
    /// Client wall clock, unix seconds. Rejected if skew is too large.
    pub ts: i64,
    /// Random nonce; the server rejects a repeated (key, nonce) pair.
    pub nonce: [u8; 16],
    /// Present on first contact only: registers the client's static key.
    pub enroll: Option<Enroll>,
    pub info: ClientInfo,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ClientInfo {
    pub os: String,
    pub arch: String,
    pub hostname: String,
    pub version: String,
}

impl ClientInfo {
    pub fn current(version: &str) -> Self {
        Self {
            os: std::env::consts::OS.to_string(),
            arch: std::env::consts::ARCH.to_string(),
            hostname: std::env::var("HOSTNAME")
                .or_else(|_| std::env::var("COMPUTERNAME"))
                .ok()
                .filter(|h| !h.is_empty())
                .or_else(|| {
                    std::fs::read_to_string("/etc/hostname")
                        .ok()
                        .map(|h| h.trim().to_string())
                })
                .unwrap_or_default(),
            version: version.to_string(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Enroll {
    /// The secret part of the one-time enrollment token.
    pub secret: String,
}

/// Payload of Noise message 2 (server -> client).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum HandshakeReply {
    Welcome(Welcome),
    Rejected(ProtoError),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Welcome {
    pub principal_id: String,
    pub name: String,
    pub connection_id: String,
    /// Ed25519 key the server signs capability tokens with. Authentic because
    /// it arrives inside the Noise session bound to the pinned server key.
    pub signing_key: [u8; 32],
    pub server_time: i64,
}

// ---------------------------------------------------------------------------
// Enrollment token
// ---------------------------------------------------------------------------

/// Enrollment tokens are handed to a human out of band and look like
/// `cjs1.<server-noise-pubkey-hex>.<secret>`. Embedding the server key lets a
/// fresh client pin the server without a separate fingerprint step.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnrollToken {
    pub server_key: [u8; 32],
    pub secret: String,
}

impl EnrollToken {
    pub fn encode(&self) -> String {
        let mut hexkey = String::with_capacity(64);
        for b in self.server_key {
            hexkey.push_str(&format!("{b:02x}"));
        }
        format!("cjs1.{hexkey}.{}", self.secret)
    }

    pub fn parse(s: &str) -> Result<Self, ProtoError> {
        let bad = || ProtoError::new(ErrorCode::BadRequest, "malformed enrollment token");
        let mut parts = s.trim().splitn(3, '.');
        if parts.next() != Some("cjs1") {
            return Err(bad());
        }
        let key = parts.next().ok_or_else(bad)?;
        let secret = parts.next().ok_or_else(bad)?;
        if key.len() != 64 || secret.is_empty() {
            return Err(bad());
        }
        let mut server_key = [0u8; 32];
        for (i, chunk) in key.as_bytes().chunks(2).enumerate() {
            let s = std::str::from_utf8(chunk).map_err(|_| bad())?;
            server_key[i] = u8::from_str_radix(s, 16).map_err(|_| bad())?;
        }
        Ok(Self {
            server_key,
            secret: secret.to_string(),
        })
    }
}

// ---------------------------------------------------------------------------
// Transport and stream framing
// ---------------------------------------------------------------------------

/// Messages of the resumable session layer. Over WebSocket each binary
/// message is one postcard-encoded `WireMsg`. `Seg.data` is a Noise
/// transport message whose nonce is `seq`, so segments are authenticated,
/// replay-proof and can be re-sent verbatim after a reconnect.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum WireMsg {
    /// Client -> server: Noise IK message 1.
    Hello {
        noise: Vec<u8>,
    },
    /// Server -> client: Noise IK message 2 plus the session id. The resume
    /// secret is derived by both sides from the Noise handshake hash and is
    /// never sent in this message.
    Welcome {
        sid: String,
        noise: Vec<u8>,
    },
    /// Client -> server: re-attach to an existing session. `ack` is the
    /// highest segment the client has received.
    Resume {
        sid: String,
        secret: String,
        ack: u64,
    },
    /// Server -> client: resume accepted; `ack` is the highest segment the
    /// server has received.
    Resumed {
        ack: u64,
    },
    Reject(ProtoError),
    Seg {
        seq: u64,
        data: Vec<u8>,
    },
    Ack(u64),
    /// The session is over (not just this link).
    Close(ProtoError),
}

/// First reply on every multiplexed stream, after the opener sent its
/// [`OpenRequest`] / [`DeviceOpen`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum OpenReply {
    /// `id` is the server-assigned stream id (audit reference; for
    /// `ForwardR` it is the listener id later used in `ForwardRConn`).
    Ok {
        id: u32,
        session: String,
    },
    Err(ProtoError),
}

/// Largest single length-prefixed message on a stream.
pub const MAX_STREAM_MSG: usize = 1024 * 1024;

/// Actions a grant can allow. Each stream kind maps to exactly one action.
/// Serialized (JSON) with the same names as [`Action::as_str`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Action {
    Shell,
    Exec,
    FileRead,
    FileWrite,
    ForwardLocal,
    ForwardRemote,
    Egress,
}

impl Action {
    pub const ALL: [Action; 7] = [
        Action::Shell,
        Action::Exec,
        Action::FileRead,
        Action::FileWrite,
        Action::ForwardLocal,
        Action::ForwardRemote,
        Action::Egress,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Action::Shell => "shell",
            Action::Exec => "exec",
            Action::FileRead => "file_read",
            Action::FileWrite => "file_write",
            Action::ForwardLocal => "forward_local",
            Action::ForwardRemote => "forward_remote",
            Action::Egress => "egress",
        }
    }

    pub fn parse(s: &str) -> Option<Action> {
        Action::ALL.into_iter().find(|a| a.as_str() == s)
    }
}

impl std::fmt::Display for Action {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Stream kinds, used for audit and accounting.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum StreamKind {
    Pty,
    Exec,
    FileGet,
    FilePut,
    FileList,
    ForwardL,
    ForwardR,
    ForwardRConn,
    Egress,
    Rpc,
}

impl StreamKind {
    pub fn as_str(self) -> &'static str {
        match self {
            StreamKind::Pty => "pty",
            StreamKind::Exec => "exec",
            StreamKind::FileGet => "file_get",
            StreamKind::FilePut => "file_put",
            StreamKind::FileList => "file_list",
            StreamKind::ForwardL => "forward_local",
            StreamKind::ForwardR => "forward_remote",
            StreamKind::ForwardRConn => "forward_remote_conn",
            StreamKind::Egress => "egress",
            StreamKind::Rpc => "rpc",
        }
    }
}

/// Opening request for a stream. Agents send these to the server (with a
/// `device` set for device-bound kinds); the server forwards the same request
/// to the device inside a [`DeviceOpen`] with `device` cleared.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum OpenRequest {
    Pty {
        device: String,
        cols: u16,
        rows: u16,
        term: String,
        /// Command to run instead of the login shell.
        command: Option<Vec<String>>,
        cwd: Option<String>,
    },
    Exec {
        device: String,
        argv: Vec<String>,
        cwd: Option<String>,
        env: Vec<(String, String)>,
        timeout_secs: Option<u64>,
    },
    FileGet {
        device: String,
        path: String,
        offset: u64,
    },
    FilePut {
        device: String,
        path: String,
        /// Resume offset: the device keeps the first `offset` bytes.
        offset: u64,
        size: u64,
        mode: Option<u32>,
        mkdirs: bool,
    },
    FileList {
        device: String,
        path: String,
    },
    /// One TCP connection from the agent side to `host:port` reachable from
    /// the device.
    ForwardL {
        device: String,
        host: String,
        port: u16,
    },
    /// Control stream: ask the device to listen on `bind_host:bind_port`.
    /// Each accepted connection comes back as a [`OpenRequest::ForwardRConn`].
    ForwardR {
        device: String,
        bind_host: String,
        bind_port: u16,
    },
    /// Accepted connection of a remote forward. Opened device -> server and
    /// server -> agent. `listener` is the id of the `ForwardR` stream as seen
    /// by the receiver of this open.
    ForwardRConn {
        listener: u32,
        peer: String,
    },
    /// Outbound TCP connection. With `via` unset the server dials; with a
    /// device name the device acts as the exit node.
    Egress {
        host: String,
        port: u16,
        via: Option<String>,
    },
    Rpc(RpcRequest),
}

impl OpenRequest {
    pub fn kind(&self) -> StreamKind {
        match self {
            OpenRequest::Pty { .. } => StreamKind::Pty,
            OpenRequest::Exec { .. } => StreamKind::Exec,
            OpenRequest::FileGet { .. } => StreamKind::FileGet,
            OpenRequest::FilePut { .. } => StreamKind::FilePut,
            OpenRequest::FileList { .. } => StreamKind::FileList,
            OpenRequest::ForwardL { .. } => StreamKind::ForwardL,
            OpenRequest::ForwardR { .. } => StreamKind::ForwardR,
            OpenRequest::ForwardRConn { .. } => StreamKind::ForwardRConn,
            OpenRequest::Egress { .. } => StreamKind::Egress,
            OpenRequest::Rpc(_) => StreamKind::Rpc,
        }
    }

    /// The action a grant must allow for this request, if device-bound or
    /// egress.
    pub fn action(&self) -> Option<Action> {
        Some(match self {
            OpenRequest::Pty { .. } => Action::Shell,
            OpenRequest::Exec { .. } => Action::Exec,
            OpenRequest::FileGet { .. } | OpenRequest::FileList { .. } => Action::FileRead,
            OpenRequest::FilePut { .. } => Action::FileWrite,
            OpenRequest::ForwardL { .. } => Action::ForwardLocal,
            OpenRequest::ForwardR { .. } => Action::ForwardRemote,
            OpenRequest::Egress { .. } => Action::Egress,
            OpenRequest::ForwardRConn { .. } | OpenRequest::Rpc(_) => return None,
        })
    }

    /// Device the request targets (agent -> server form).
    pub fn device(&self) -> Option<&str> {
        match self {
            OpenRequest::Pty { device, .. }
            | OpenRequest::Exec { device, .. }
            | OpenRequest::FileGet { device, .. }
            | OpenRequest::FilePut { device, .. }
            | OpenRequest::FileList { device, .. }
            | OpenRequest::ForwardL { device, .. }
            | OpenRequest::ForwardR { device, .. } => Some(device),
            OpenRequest::Egress { via, .. } => via.as_deref(),
            OpenRequest::ForwardRConn { .. } | OpenRequest::Rpc(_) => None,
        }
    }

    /// Copy with the device field cleared (server -> device form).
    pub fn for_device(&self) -> OpenRequest {
        let mut r = self.clone();
        match &mut r {
            OpenRequest::Pty { device, .. }
            | OpenRequest::Exec { device, .. }
            | OpenRequest::FileGet { device, .. }
            | OpenRequest::FilePut { device, .. }
            | OpenRequest::FileList { device, .. }
            | OpenRequest::ForwardL { device, .. }
            | OpenRequest::ForwardR { device, .. } => device.clear(),
            OpenRequest::Egress { via, .. } => *via = None,
            OpenRequest::ForwardRConn { .. } | OpenRequest::Rpc(_) => {}
        }
        r
    }

    /// `host:port` target string bound into capabilities for network kinds.
    pub fn net_target(&self) -> Option<String> {
        match self {
            OpenRequest::ForwardL { host, port, .. } | OpenRequest::Egress { host, port, .. } => {
                Some(format!("{host}:{port}"))
            }
            OpenRequest::ForwardR {
                bind_host, bind_port, ..
            } => Some(format!("{bind_host}:{bind_port}")),
            _ => None,
        }
    }
}

/// Body of a capability token. Signed by the server with Ed25519 (see
/// `cjs-authz::capability`) and verified again by the device before it does
/// anything, so a compromised or bypassed relay cannot widen access.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Capability {
    pub version: u8,
    /// Random token id, used for replay detection on the device.
    pub id: [u8; 16],
    pub principal: String,
    pub device: String,
    pub action: Action,
    /// Project roots (device paths). Ignored when `full_access`.
    pub roots: Vec<String>,
    pub full_access: bool,
    pub issued_at: i64,
    pub expires_at: i64,
    /// Stream id on the server->device connection this token is bound to.
    pub stream: u32,
    /// Server connection id of the device link this token is bound to.
    pub connection: String,
    /// `host:port` for network actions.
    pub target: Option<String>,
    /// Audit session id.
    pub session: String,
    /// JSON list of network rules (`cjs_authz::net::NetRule`) the device
    /// must apply to resolved addresses for egress (post-DNS SSRF check).
    pub net_rules: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedCapability {
    /// postcard-encoded [`Capability`].
    pub body: Vec<u8>,
    /// Ed25519 signature over `b"cjs-cap-v1" || body`.
    pub sig: Vec<u8>,
}

/// Open metadata for server -> device streams.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceOpen {
    pub cap: SignedCapability,
    pub req: OpenRequest,
}

// ---------------------------------------------------------------------------
// Request validation (shared by server and device)
// ---------------------------------------------------------------------------

/// Longest path or argument accepted in a request.
pub const MAX_ARG_LEN: usize = 4096;
/// Most argv entries / environment variables in a request.
pub const MAX_ARGS: usize = 256;
pub const MAX_ENV: usize = 128;
/// Largest terminal accepted.
pub const MAX_TERM_DIM: u16 = 1000;
/// Longest exec timeout (24h).
pub const MAX_EXEC_TIMEOUT_SECS: u64 = 24 * 3600;

fn bad(m: impl Into<String>) -> ProtoError {
    ProtoError::new(ErrorCode::BadRequest, m)
}

fn check_str(what: &str, s: &str) -> Result<(), ProtoError> {
    if s.len() > MAX_ARG_LEN {
        return Err(bad(format!("{what} too long")));
    }
    if s.contains('\0') {
        return Err(bad(format!("{what} contains NUL")));
    }
    Ok(())
}

/// Validate an environment variable name. Loader-controlling variables are
/// refused outright: they could run code in a helper before the sandbox is
/// applied.
pub fn check_env_name(k: &str) -> Result<(), ProtoError> {
    let mut chars = k.chars();
    let ok_first = chars
        .next()
        .map(|c| c.is_ascii_alphabetic() || c == '_')
        .unwrap_or(false);
    if !ok_first || !k.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') || k.len() > 128 {
        return Err(bad(format!("invalid environment variable name {k:?}")));
    }
    let up = k.to_ascii_uppercase();
    if up.starts_with("LD_") || up.starts_with("DYLD_") || up == "GLIBC_TUNABLES" || up.starts_with("MALLOC_")
    {
        return Err(ProtoError::new(
            ErrorCode::Forbidden,
            format!("environment variable {k} is not allowed"),
        ));
    }
    Ok(())
}

/// `TERM` values: short and made of safe characters only.
pub fn check_term(t: &str) -> Result<(), ProtoError> {
    if t.is_empty() || t.len() > 64 || !t.chars().all(|c| c.is_ascii_alphanumeric() || "-_.+".contains(c)) {
        return Err(bad("invalid TERM"));
    }
    Ok(())
}

fn check_host(h: &str) -> Result<(), ProtoError> {
    if h.is_empty() || h.len() > 253 {
        return Err(bad("invalid host"));
    }
    if !h
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || "-._:[]%".contains(c))
    {
        return Err(bad("invalid host"));
    }
    Ok(())
}

/// Structural checks on a request before any policy decision.
pub fn validate_request(r: &OpenRequest) -> Result<(), ProtoError> {
    if let Some(d) = r.device() {
        check_str("device", d)?;
        if d.len() > 128 {
            return Err(bad("device name too long"));
        }
    }
    match r {
        OpenRequest::Pty {
            cols,
            rows,
            term,
            command,
            cwd,
            ..
        } => {
            if *cols == 0 || *rows == 0 || *cols > MAX_TERM_DIM || *rows > MAX_TERM_DIM {
                return Err(bad("invalid terminal size"));
            }
            check_term(term)?;
            if let Some(c) = command {
                if c.is_empty() || c.len() > MAX_ARGS {
                    return Err(bad("invalid command"));
                }
                for a in c {
                    check_str("argument", a)?;
                }
            }
            if let Some(c) = cwd {
                check_str("cwd", c)?;
            }
        }
        OpenRequest::Exec {
            argv,
            cwd,
            env,
            timeout_secs,
            ..
        } => {
            if argv.is_empty() || argv.len() > MAX_ARGS {
                return Err(bad("invalid argv"));
            }
            for a in argv {
                check_str("argument", a)?;
            }
            if let Some(c) = cwd {
                check_str("cwd", c)?;
            }
            if env.len() > MAX_ENV {
                return Err(bad("too many environment variables"));
            }
            for (k, v) in env {
                check_env_name(k)?;
                check_str("environment value", v)?;
            }
            if timeout_secs
                .map(|t| t == 0 || t > MAX_EXEC_TIMEOUT_SECS)
                .unwrap_or(false)
            {
                return Err(bad("invalid timeout"));
            }
        }
        OpenRequest::FileGet { path, .. } | OpenRequest::FileList { path, .. } => check_str("path", path)?,
        OpenRequest::FilePut {
            path, offset, size, ..
        } => {
            check_str("path", path)?;
            if offset > size {
                return Err(bad("offset beyond size"));
            }
        }
        OpenRequest::ForwardL { host, port, .. } | OpenRequest::Egress { host, port, .. } => {
            check_host(host)?;
            if *port == 0 {
                return Err(bad("invalid port"));
            }
        }
        OpenRequest::ForwardR {
            bind_host, bind_port, ..
        } => {
            check_host(bind_host)?;
            if *bind_port == 0 {
                return Err(bad("invalid port"));
            }
        }
        OpenRequest::ForwardRConn { peer, .. } => check_str("peer", peer)?,
        OpenRequest::Rpc(_) => {}
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// In-stream messages
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum PtyIn {
    Input(Vec<u8>),
    Resize { cols: u16, rows: u16 },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum PtyOut {
    Output(Vec<u8>),
    Exit { code: Option<i32> },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ExecIn {
    Stdin(Vec<u8>),
    StdinEof,
    Kill,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ExecOut {
    Stdout(Vec<u8>),
    Stderr(Vec<u8>),
    Exit {
        code: Option<i32>,
        signal: Option<String>,
        timed_out: bool,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum EntryKind {
    File,
    Dir,
    Symlink,
    Other,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DirEntry {
    pub name: String,
    pub kind: EntryKind,
    pub size: u64,
    pub mode: u32,
    pub mtime: i64,
}

/// Messages of file streams.
///
/// * `FileGet`: device sends `Meta`, `Chunk`*, `End`.
/// * `FilePut`: agent sends `Chunk`*, `End`; device answers `Done` (or the
///   stream is reset with an error).
/// * `FileList`: device sends `Stat` and, for directories, `Entries`* then
///   `End`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum FileMsg {
    Meta {
        size: u64,
        mode: u32,
        mtime: i64,
    },
    Chunk(Vec<u8>),
    /// Full-file SHA-256 (hex), computed over the whole file, not only the
    /// transferred range, so resumed transfers can be checked end to end.
    End {
        sha256: Option<String>,
    },
    Done {
        size: u64,
        sha256: String,
    },
    Stat(DirEntry),
    Entries(Vec<DirEntry>),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum RpcRequest {
    WhoAmI,
    ListDevices,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceSummary {
    pub id: String,
    pub name: String,
    pub online: bool,
    pub os: String,
    pub arch: String,
    pub hostname: String,
    pub groups: Vec<String>,
    /// Actions this principal may perform on the device right now.
    pub actions: Vec<Action>,
    pub roots: Vec<String>,
    pub full_access: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum RpcResponse {
    WhoAmI {
        principal_id: String,
        name: String,
        owner: Option<String>,
    },
    Devices(Vec<DeviceSummary>),
    Error(ProtoError),
}

// ---------------------------------------------------------------------------
// HTTP fallback transport bodies
// ---------------------------------------------------------------------------

/// Response to `POST /v1/t/open`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpOpenResponse {
    pub sid: String,
    /// Noise message 2.
    pub msg: Vec<u8>,
}

/// Body of `POST /v1/t/{sid}/tx` and of `GET /v1/t/{sid}/rx` responses:
/// sequence-numbered Noise transport messages (same as `WireMsg::Seg`).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct HttpBatch {
    /// For `tx` requests: highest downlink seq the client has received.
    pub ack: u64,
    pub msgs: Vec<(u64, Vec<u8>)>,
    /// Set by the server when the session is gone.
    pub closed: Option<ProtoError>,
}

// ---------------------------------------------------------------------------
// Encoding helpers
// ---------------------------------------------------------------------------

pub fn encode<T: Serialize>(v: &T) -> Vec<u8> {
    postcard::to_allocvec(v).expect("postcard encoding of in-memory value cannot fail")
}

pub fn decode<T: DeserializeOwned>(b: &[u8]) -> Result<T, ProtoError> {
    postcard::from_bytes(b).map_err(|e| ProtoError::new(ErrorCode::Protocol, format!("decode: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wire_roundtrip() {
        let f = WireMsg::Seg {
            seq: 7,
            data: vec![1, 2, 3],
        };
        let b = encode(&f);
        assert_eq!(decode::<WireMsg>(&b).unwrap(), f);
    }

    #[test]
    fn enroll_token_roundtrip() {
        let t = EnrollToken {
            server_key: [0xab; 32],
            secret: "s3cr3t-xyz".into(),
        };
        let s = t.encode();
        assert!(s.starts_with("cjs1."));
        assert_eq!(EnrollToken::parse(&s).unwrap(), t);
        assert!(EnrollToken::parse("cjs2.aa.bb").is_err());
        assert!(EnrollToken::parse("cjs1.zz.bb").is_err());
    }

    #[test]
    fn request_helpers() {
        let r = OpenRequest::ForwardL {
            device: "d1".into(),
            host: "127.0.0.1".into(),
            port: 22,
        };
        assert_eq!(r.action(), Some(Action::ForwardLocal));
        assert_eq!(r.device(), Some("d1"));
        assert_eq!(r.net_target().as_deref(), Some("127.0.0.1:22"));
        assert_eq!(r.for_device().device(), Some(""));
        for a in Action::ALL {
            assert_eq!(Action::parse(a.as_str()), Some(a));
        }
    }

    #[test]
    fn validation() {
        let exec = |env: Vec<(String, String)>| OpenRequest::Exec {
            device: "d".into(),
            argv: vec!["ls".into()],
            cwd: None,
            env,
            timeout_secs: None,
        };
        assert!(validate_request(&exec(vec![("FOO".into(), "1".into())])).is_ok());
        assert!(validate_request(&exec(vec![("LD_PRELOAD".into(), "/x.so".into())])).is_err());
        assert!(validate_request(&exec(vec![("dyld_insert_libraries".into(), "x".into())])).is_err());
        assert!(validate_request(&exec(vec![("A=B".into(), "x".into())])).is_err());
        let pty = |cols, term: &str| OpenRequest::Pty {
            device: "d".into(),
            cols,
            rows: 24,
            term: term.into(),
            command: None,
            cwd: None,
        };
        assert!(validate_request(&pty(80, "xterm-256color")).is_ok());
        assert!(validate_request(&pty(0, "xterm")).is_err());
        assert!(validate_request(&pty(80, "x\u{1b}]0;")).is_err());
    }

    #[test]
    fn decode_garbage_is_protocol_error() {
        let e = decode::<WireMsg>(&[0xff, 0xff, 0xff]).unwrap_err();
        assert_eq!(e.code, ErrorCode::Protocol);
    }
}
