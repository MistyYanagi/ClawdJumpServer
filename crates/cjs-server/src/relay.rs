//! Stream relay.
//!
//! For every stream an agent opens:
//!
//! 1. read and validate the [`OpenRequest`];
//! 2. policy decision (default deny) and an audit record of it. If the
//!    audit write fails the request is refused (fail closed);
//! 3. sign a capability bound to the device, its connection, the new
//!    stream, the action, the network target and the project roots;
//! 4. open a stream to the device, send [`DeviceOpen`], wait for its reply;
//! 5. audit `session.start` (fail closed), reply to the agent;
//! 6. relay. PTY, exec and file streams are *decoded and re-encoded*
//!    message by message: the server enforces each kind's message grammar
//!    and size limits, records terminals (asciicast; a recording failure
//!    ends the session) and computes transfer digests. TCP-like streams
//!    are copied with byte counters;
//! 7. audit `session.end` with the summary.
//!
//! Every relayed stream is registered so that the lease checker can
//! terminate it when access is revoked.
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use cjs_audit::recording::Recorder;
use cjs_audit::{Event, Outcome};
use cjs_authz::capability;
use cjs_mux::{expect_msg, read_msg, write_msg, MuxStream};
use cjs_proto::{
    validate_request, Capability, DeviceOpen, DeviceSummary, ErrorCode, ExecIn, ExecOut, FileMsg, OpenReply,
    OpenRequest, ProtoError, PtyIn, PtyOut, RpcRequest, RpcResponse, StreamKind, MAX_TERM_DIM,
};
use serde::{de::DeserializeOwned, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_util::sync::CancellationToken;

use crate::db::{new_id, now};
use crate::egress;
use crate::state::{ConnInfo, ListenerReg, Principal, Shared, StreamInfo};

/// Time allowed for the opening message of a stream.
pub const OPEN_TIMEOUT: Duration = Duration::from_secs(30);
/// Time allowed for a device to answer a `DeviceOpen`.
const DEVICE_OPEN_TIMEOUT: Duration = Duration::from_secs(30);
/// After the agent stopped sending, how long to wait for the device to end.
const DRAIN_TIMEOUT: Duration = Duration::from_secs(30);

fn perr(code: ErrorCode, m: impl Into<String>) -> ProtoError {
    ProtoError::new(code, m)
}

async fn reply_err(s: &mut MuxStream, e: ProtoError) {
    let _ = write_msg(s, &OpenReply::Err(e)).await;
    let _ = s.shutdown().await;
}

async fn read_open<T: DeserializeOwned>(s: &mut MuxStream) -> Result<T, ProtoError> {
    match tokio::time::timeout(OPEN_TIMEOUT, expect_msg(s)).await {
        Ok(r) => r,
        Err(_) => Err(perr(ErrorCode::Timeout, "no open request")),
    }
}

/// Short, secret-free description of a request for the audit log.
pub fn summarize(req: &OpenRequest) -> Value {
    match req {
        OpenRequest::Pty {
            cols,
            rows,
            term,
            command,
            cwd,
            ..
        } => json!({"cols": cols, "rows": rows, "term": term, "command": command, "cwd": cwd}),
        OpenRequest::Exec {
            argv,
            cwd,
            env,
            timeout_secs,
            ..
        } => json!({
            "argv": argv,
            "cwd": cwd,
            // Values may be secrets; names are enough to review.
            "env": env.iter().map(|(k, _)| k).collect::<Vec<_>>(),
            "timeout_secs": timeout_secs,
        }),
        OpenRequest::FileGet { path, offset, .. } => json!({"path": path, "offset": offset}),
        OpenRequest::FilePut {
            path,
            offset,
            size,
            mode,
            mkdirs,
            ..
        } => json!({"path": path, "offset": offset, "size": size, "mode": mode, "mkdirs": mkdirs}),
        OpenRequest::FileList { path, .. } => json!({"path": path}),
        OpenRequest::ForwardL { host, port, .. } => json!({"host": host, "port": port}),
        OpenRequest::ForwardR {
            bind_host, bind_port, ..
        } => json!({"bind_host": bind_host, "bind_port": bind_port}),
        OpenRequest::ForwardRConn { listener, peer } => json!({"listener": listener, "peer": peer}),
        OpenRequest::Egress { host, port, via } => json!({"host": host, "port": port, "via": via}),
        OpenRequest::Rpc(r) => json!({"rpc": format!("{r:?}")}),
    }
}

// ---------------------------------------------------------------------------
// Agent-initiated streams
// ---------------------------------------------------------------------------

pub(crate) async fn agent_stream(sh: Arc<Shared>, conn: Arc<ConnInfo>, mut s: MuxStream) {
    let req: OpenRequest = match read_open(&mut s).await {
        Ok(r) => r,
        Err(e) => return reply_err(&mut s, e).await,
    };
    if let Err(e) = validate_request(&req) {
        return reply_err(&mut s, e).await;
    }
    let principal = match sh.principal(&conn.principal) {
        Ok(p) => p,
        Err(e) => return reply_err(&mut s, e).await,
    };
    let mut replied = false;
    let r = match &req {
        OpenRequest::Rpc(r) => rpc(&sh, &principal, r, &mut s, &mut replied).await,
        OpenRequest::ForwardRConn { .. } => {
            Err(perr(ErrorCode::BadRequest, "agents cannot open this stream kind"))
        }
        _ => open_and_relay(&sh, &conn, &principal, req, &mut s, &mut replied).await,
    };
    if let Err(e) = r {
        if !replied {
            reply_err(&mut s, e).await;
        }
    }
}

async fn rpc(
    sh: &Shared,
    p: &Principal,
    req: &RpcRequest,
    s: &mut MuxStream,
    replied: &mut bool,
) -> Result<(), ProtoError> {
    let resp = match req {
        RpcRequest::WhoAmI => RpcResponse::WhoAmI {
            principal_id: p.id.clone(),
            name: p.name.clone(),
            owner: Some(p.owner_name.clone()),
        },
        RpcRequest::ListDevices => RpcResponse::Devices(list_devices(sh, p).map_err(|e| e.proto())?),
    };
    write_msg(
        s,
        &OpenReply::Ok {
            id: 0,
            session: String::new(),
        },
    )
    .await?;
    *replied = true;
    write_msg(s, &resp).await?;
    let _ = s.shutdown().await;
    Ok(())
}

fn list_devices(sh: &Shared, p: &Principal) -> Result<Vec<DeviceSummary>, crate::error::ApiError> {
    let grants: Vec<_> = sh.db.grants()?.into_iter().map(|g| g.grant).collect();
    let full = sh.db.full_access_all()?;
    let t = now();
    let mut out = Vec::new();
    for d in sh.db.devices()? {
        if d.status != "active" {
            continue;
        }
        let zero = |_: &str| 0u32;
        let ar = cjs_authz::AccessRequest {
            principal: &p.id,
            principal_groups: &p.groups,
            device: Some(&d.id),
            device_groups: &d.groups,
            action: cjs_proto::Action::Shell,
            net: None,
            active: &zero,
            now: t,
        };
        let v = cjs_authz::visible(&ar, &grants, &full);
        if v.actions.is_empty() {
            continue; // do not reveal devices the agent cannot use
        }
        let info = |k: &str| d.info.get(k).and_then(|v| v.as_str()).unwrap_or("").to_string();
        out.push(DeviceSummary {
            id: d.id.clone(),
            name: d.name.clone(),
            online: sh.reg.is_online(&d.id),
            os: info("os"),
            arch: info("arch"),
            hostname: info("hostname"),
            groups: d.groups.clone(),
            actions: v.actions,
            roots: v.roots,
            full_access: v.full_access,
        });
    }
    Ok(out)
}

async fn open_and_relay(
    sh: &Arc<Shared>,
    conn: &Arc<ConnInfo>,
    p: &Principal,
    req: OpenRequest,
    s: &mut MuxStream,
    replied: &mut bool,
) -> Result<(), ProtoError> {
    let session = new_id("s");
    let stream_id = sh.next_stream_id();
    let (dec, device) = sh.decide(p, &req, None).map_err(|e| e.proto())?;
    let target = device
        .as_ref()
        .map(|d| d.id.clone())
        .unwrap_or_else(|| req.net_target().unwrap_or_else(|| "server".into()));
    sh.audit(
        Event::new(
            "authz.decision",
            &p.id,
            &target,
            if dec.allow {
                Outcome::Success
            } else {
                Outcome::Denied
            },
        )
        .session(session.clone())
        .ip(conn.peer.clone())
        .highlight(dec.full_access.is_some())
        .data(json!({
            "kind": req.kind().as_str(),
            "action": req.action().map(|a| a.as_str()),
            "request": summarize(&req),
            "allow": dec.allow,
            "code": dec.code.map(|c| c.as_str()),
            "reason": dec.reason,
            "grants": dec.grant_ids,
            "full_access": dec.full_access,
        })),
    )
    .map_err(|e| e.proto())?;
    if !dec.allow {
        return Err(perr(dec.code.unwrap_or(ErrorCode::Forbidden), dec.reason));
    }

    // Egress through the server itself.
    let Some(device) = device else {
        let info = Arc::new(StreamInfo::new(
            stream_id,
            session.clone(),
            req.clone(),
            p.id.clone(),
            None,
            conn.id.clone(),
            None,
            &dec,
            target.clone(),
            conn.peer.clone(),
        ));
        let _g = sh.reg.add_stream(info.clone());
        return egress::server_egress(sh, p, &info, &dec, s, replied).await;
    };

    let dconn = sh.reg.device_conn(&device.id).ok_or_else(|| {
        perr(
            ErrorCode::DeviceOffline,
            format!("device {} is offline", device.name),
        )
    })?;
    let mut ds = tokio::time::timeout(DEVICE_OPEN_TIMEOUT, dconn.mux.open())
        .await
        .map_err(|_| perr(ErrorCode::Timeout, "device did not accept a stream"))??;
    let issued = now();
    let cap = Capability {
        version: capability::CAP_VERSION,
        id: capability::new_id(),
        principal: p.id.clone(),
        device: device.id.clone(),
        action: req
            .action()
            .ok_or_else(|| perr(ErrorCode::BadRequest, "no action"))?,
        roots: dec.roots.clone(),
        full_access: dec.full_access.is_some(),
        issued_at: issued,
        expires_at: issued + capability::CAP_TTL_SECS,
        stream: ds.get_ref().id().val(),
        connection: dconn.id.clone(),
        target: req.net_target(),
        session: session.clone(),
        net_rules: match req {
            OpenRequest::Egress { .. } => Some(
                serde_json::to_string(&dec.egress_rules)
                    .map_err(|e| perr(ErrorCode::Internal, e.to_string()))?,
            ),
            _ => None,
        },
    };
    let signed = capability::sign(&sh.cap_key, &cap);
    write_msg(
        &mut ds,
        &DeviceOpen {
            cap: signed,
            req: req.for_device(),
        },
    )
    .await?;
    let dreply: OpenReply = tokio::time::timeout(DEVICE_OPEN_TIMEOUT, expect_msg(&mut ds))
        .await
        .map_err(|_| perr(ErrorCode::Timeout, "device did not answer"))??;
    let device_ref = match dreply {
        OpenReply::Ok { id, .. } => id,
        OpenReply::Err(e) => {
            let _ = sh.audit(
                Event::new("session.fail", &p.id, &target, Outcome::Failure)
                    .session(session.clone())
                    .ip(conn.peer.clone())
                    .data(json!({"kind": req.kind().as_str(), "code": e.code.as_str(), "reason": e.message})),
            );
            return Err(e);
        }
    };

    // Terminal sessions are recorded; no recording, no session.
    let recorder = match &req {
        OpenRequest::Pty { cols, rows, .. } => {
            let path = sh.cfg.recordings_dir.join(format!("{session}.cast"));
            let title = format!("{} @ {}", p.name, device.name);
            Some(
                Recorder::create(&path, *cols, *rows, &title)
                    .map_err(|e| perr(ErrorCode::AuditFailure, format!("cannot record session: {e}")))?,
            )
        }
        _ => None,
    };

    let info = Arc::new(StreamInfo::new(
        stream_id,
        session.clone(),
        req.clone(),
        p.id.clone(),
        Some(device.id.clone()),
        conn.id.clone(),
        Some(dconn.id.clone()),
        &dec,
        target.clone(),
        conn.peer.clone(),
    ));
    let _g = sh.reg.add_stream(info.clone());
    sh.audit(
        Event::new("session.start", &p.id, &target, Outcome::Success)
            .session(session.clone())
            .ip(conn.peer.clone())
            .highlight(dec.full_access.is_some())
            .data(json!({
                "stream": stream_id,
                "kind": req.kind().as_str(),
                "device": device.name,
                "request": summarize(&req),
                "roots": dec.roots,
                "full_access": dec.full_access,
                "transport": conn.transport,
            })),
    )
    .map_err(|e| e.proto())?;
    write_msg(
        s,
        &OpenReply::Ok {
            id: stream_id,
            session: session.clone(),
        },
    )
    .await?;
    *replied = true;

    let started = Instant::now();
    let (result, mut stats) = match req.kind() {
        StreamKind::Pty => relay_pty(s, &mut ds, recorder, &info).await,
        StreamKind::Exec => relay_exec(s, &mut ds, &info).await,
        StreamKind::FileGet => relay_file_get(s, &mut ds, &info).await,
        StreamKind::FilePut => relay_file_put(s, &mut ds, &info, &req).await,
        StreamKind::FileList => relay_file_list(s, &mut ds, &info).await,
        StreamKind::ForwardL | StreamKind::Egress => {
            let (r, up, down) = relay_raw(s, &mut ds, &info.cancel).await;
            (r, json!({"bytes_up": up, "bytes_down": down}))
        }
        StreamKind::ForwardR => {
            let reg = Arc::new(ListenerReg {
                agent_conn: conn.id.clone(),
                agent_listener: stream_id,
                principal: p.id.clone(),
                device: device.id.clone(),
                session: session.clone(),
                cancel: info.cancel.clone(),
            });
            let _lg = sh.reg.add_listener(&dconn.id, device_ref, reg);
            let r = hold_control(s, &mut ds, &info.cancel).await;
            (r, json!({}))
        }
        StreamKind::ForwardRConn | StreamKind::Rpc => {
            (Err(perr(ErrorCode::BadRequest, "unexpected kind")), json!({}))
        }
    };
    if info.cancel.is_cancelled() {
        stats["terminated"] = json!(info.reason().message);
    }
    stats["duration_ms"] = json!(started.elapsed().as_millis() as u64);
    let (outcome, err) = match &result {
        Ok(()) => (Outcome::Success, Value::Null),
        Err(e) => (
            Outcome::Failure,
            json!({"code": e.code.as_str(), "reason": e.message}),
        ),
    };
    stats["error"] = err;
    if let Err(e) = sh.audit(
        Event::new("session.end", &p.id, &target, outcome)
            .session(session.clone())
            .ip(conn.peer.clone())
            .highlight(dec.full_access.is_some())
            .data(stats),
    ) {
        tracing::error!(%session, err = %e, "could not audit session end");
    }
    result
}

// ---------------------------------------------------------------------------
// Device-initiated streams (remote-forward connections only)
// ---------------------------------------------------------------------------

pub(crate) async fn device_stream(sh: Arc<Shared>, dconn: Arc<ConnInfo>, mut s: MuxStream) {
    let req: OpenRequest = match read_open(&mut s).await {
        Ok(r) => r,
        Err(e) => return reply_err(&mut s, e).await,
    };
    let OpenRequest::ForwardRConn { listener, peer } = req else {
        return reply_err(
            &mut s,
            perr(
                ErrorCode::Forbidden,
                "devices may only open remote-forward connections",
            ),
        )
        .await;
    };
    if let Err(e) = validate_request(&OpenRequest::ForwardRConn {
        listener,
        peer: peer.clone(),
    }) {
        return reply_err(&mut s, e).await;
    }
    // The listener must have been opened on *this* device connection.
    let Some(reg) = sh.reg.listener(&dconn.id, listener) else {
        return reply_err(&mut s, perr(ErrorCode::NotFound, "no such listener")).await;
    };
    if reg.cancel.is_cancelled() {
        return reply_err(&mut s, perr(ErrorCode::Cancelled, "listener closed")).await;
    }
    let Some(aconn) = sh.reg.conn(&reg.agent_conn) else {
        return reply_err(&mut s, perr(ErrorCode::NotFound, "agent gone")).await;
    };
    let id = sh.next_stream_id();
    let r = async {
        let mut a = tokio::time::timeout(DEVICE_OPEN_TIMEOUT, aconn.mux.open())
            .await
            .map_err(|_| perr(ErrorCode::Timeout, "agent did not accept a stream"))??;
        write_msg(
            &mut a,
            &OpenRequest::ForwardRConn {
                listener: reg.agent_listener,
                peer: peer.clone(),
            },
        )
        .await?;
        match tokio::time::timeout(DEVICE_OPEN_TIMEOUT, expect_msg::<_, OpenReply>(&mut a))
            .await
            .map_err(|_| perr(ErrorCode::Timeout, "agent did not answer"))??
        {
            OpenReply::Ok { .. } => Ok(a),
            OpenReply::Err(e) => Err(e),
        }
    }
    .await;
    let mut a = match r {
        Ok(a) => a,
        Err(e) => return reply_err(&mut s, e).await,
    };
    if let Err(e) = sh.audit(
        Event::new("forward.conn", &reg.principal, &reg.device, Outcome::Success)
            .session(reg.session.clone())
            .data(json!({"stream": id, "listener": reg.agent_listener, "peer": peer})),
    ) {
        return reply_err(&mut s, e.proto()).await;
    }
    if write_msg(
        &mut s,
        &OpenReply::Ok {
            id,
            session: reg.session.clone(),
        },
    )
    .await
    .is_err()
    {
        return;
    }
    let started = Instant::now();
    let (r, down, up) = relay_raw(&mut s, &mut a, &reg.cancel).await;
    let _ = sh.audit(
        Event::new(
            "forward.conn_end",
            &reg.principal,
            &reg.device,
            if r.is_ok() {
                Outcome::Success
            } else {
                Outcome::Failure
            },
        )
        .session(reg.session.clone())
        .data(json!({
            "stream": id,
            "bytes_to_agent": down,
            "bytes_to_device": up,
            "duration_ms": started.elapsed().as_millis() as u64,
        })),
    );
}

// ---------------------------------------------------------------------------
// Pumps
// ---------------------------------------------------------------------------

fn cancelled(info: &StreamInfo) -> ProtoError {
    info.reason()
}

/// Relay typed messages. `on_in` inspects agent -> device messages,
/// `on_out` device -> agent messages and returns true for the final one.
/// On error or cancellation `abort` builds the messages sent to the agent
/// before the stream is closed.
async fn relay_typed<I, O, FI, FO, FA>(
    agent: &mut MuxStream,
    dev: &mut MuxStream,
    info: &StreamInfo,
    mut on_in: FI,
    mut on_out: FO,
    abort: FA,
) -> Result<(), ProtoError>
where
    I: Serialize + DeserializeOwned,
    O: Serialize + DeserializeOwned,
    FI: FnMut(&I) -> Result<(), ProtoError>,
    FO: FnMut(&O) -> Result<bool, ProtoError>,
    FA: Fn(&ProtoError) -> Vec<O>,
{
    let (mut ar, mut aw) = tokio::io::split(agent);
    let (mut dr, mut dw) = tokio::io::split(dev);
    let result = {
        let up = async {
            loop {
                match read_msg::<_, I>(&mut ar).await? {
                    None => {
                        let _ = dw.shutdown().await;
                        return Ok::<(), ProtoError>(());
                    }
                    Some(m) => {
                        on_in(&m)?;
                        write_msg(&mut dw, &m).await?;
                    }
                }
            }
        };
        let down = async {
            loop {
                match read_msg::<_, O>(&mut dr).await? {
                    None => return Ok::<(), ProtoError>(()),
                    Some(m) => {
                        let last = on_out(&m)?;
                        write_msg(&mut aw, &m).await?;
                        if last {
                            return Ok(());
                        }
                    }
                }
            }
        };
        tokio::pin!(up);
        tokio::pin!(down);
        let mut up_done = false;
        let drain = tokio::time::sleep(Duration::from_secs(365 * 86400));
        tokio::pin!(drain);
        loop {
            tokio::select! {
                r = &mut up, if !up_done => {
                    up_done = true;
                    if let Err(e) = r {
                        break Err(e);
                    }
                    drain.as_mut().reset(tokio::time::Instant::now() + DRAIN_TIMEOUT);
                }
                r = &mut down => break r,
                _ = &mut drain, if up_done => break Err(perr(ErrorCode::Timeout, "device did not finish")),
                _ = info.cancel.cancelled() => break Err(cancelled(info)),
            }
        }
    };
    if let Err(e) = &result {
        for m in abort(e) {
            if write_msg(&mut aw, &m).await.is_err() {
                break;
            }
        }
    }
    let _ = aw.shutdown().await;
    let _ = dw.shutdown().await;
    result
}

fn rec_err(e: std::io::Error) -> ProtoError {
    perr(ErrorCode::AuditFailure, format!("session recording failed: {e}"))
}

async fn relay_pty(
    agent: &mut MuxStream,
    dev: &mut MuxStream,
    rec: Option<Recorder>,
    info: &StreamInfo,
) -> (Result<(), ProtoError>, Value) {
    let Some(rec) = rec else {
        return (Err(perr(ErrorCode::AuditFailure, "no recorder")), json!({}));
    };
    let rec = Mutex::new(rec);
    let mut bytes_in = 0u64;
    let mut bytes_out = 0u64;
    let mut exit: Option<Option<i32>> = None;
    let r = relay_typed::<PtyIn, PtyOut, _, _, _>(
        agent,
        dev,
        info,
        |m| {
            let mut rec = rec.lock().unwrap_or_else(|p| p.into_inner());
            match m {
                PtyIn::Input(b) => {
                    bytes_in += b.len() as u64;
                    rec.input(b).map_err(rec_err)
                }
                PtyIn::Resize { cols, rows } => {
                    if *cols == 0 || *rows == 0 || *cols > MAX_TERM_DIM || *rows > MAX_TERM_DIM {
                        return Err(perr(ErrorCode::BadRequest, "invalid terminal size"));
                    }
                    rec.resize(*cols, *rows).map_err(rec_err)
                }
            }
        },
        |m| {
            let mut rec = rec.lock().unwrap_or_else(|p| p.into_inner());
            match m {
                PtyOut::Output(b) => {
                    bytes_out += b.len() as u64;
                    rec.output(b).map_err(rec_err)?;
                    Ok(false)
                }
                PtyOut::Exit { code } => {
                    exit = Some(*code);
                    Ok(true)
                }
            }
        },
        |e| {
            vec![
                PtyOut::Output(format!("\r\n[cjs] session terminated: {}\r\n", e.message).into_bytes()),
                PtyOut::Exit { code: None },
            ]
        },
    )
    .await;
    let rec = rec.into_inner().unwrap_or_else(|p| p.into_inner());
    let mut stats = json!({"bytes_in": bytes_in, "bytes_out": bytes_out, "exit": exit.flatten()});
    match rec.finish() {
        Ok((path, size, sha)) => {
            stats["recording"] = json!({
                "file": path.file_name().map(|n| n.to_string_lossy().into_owned()),
                "size": size,
                "sha256": sha,
            });
        }
        Err(e) => {
            stats["recording_error"] = json!(e.to_string());
            if r.is_ok() {
                return (Err(rec_err(e)), stats);
            }
        }
    }
    (r, stats)
}

async fn relay_exec(
    agent: &mut MuxStream,
    dev: &mut MuxStream,
    info: &StreamInfo,
) -> (Result<(), ProtoError>, Value) {
    let mut stdin = 0u64;
    let mut out = Sha256::new();
    let mut err = Sha256::new();
    let (mut n_out, mut n_err) = (0u64, 0u64);
    let mut exit = Value::Null;
    let r = relay_typed::<ExecIn, ExecOut, _, _, _>(
        agent,
        dev,
        info,
        |m| {
            if let ExecIn::Stdin(b) = m {
                stdin += b.len() as u64;
            }
            Ok(())
        },
        |m| match m {
            ExecOut::Stdout(b) => {
                n_out += b.len() as u64;
                out.update(b);
                Ok(false)
            }
            ExecOut::Stderr(b) => {
                n_err += b.len() as u64;
                err.update(b);
                Ok(false)
            }
            ExecOut::Exit {
                code,
                signal,
                timed_out,
            } => {
                exit = json!({"code": code, "signal": signal, "timed_out": timed_out});
                Ok(true)
            }
        },
        |e| {
            vec![
                ExecOut::Stderr(format!("[cjs] session terminated: {}\n", e.message).into_bytes()),
                ExecOut::Exit {
                    code: None,
                    signal: Some("terminated".into()),
                    timed_out: false,
                },
            ]
        },
    )
    .await;
    (
        r,
        json!({
            "stdin_bytes": stdin,
            "stdout_bytes": n_out,
            "stderr_bytes": n_err,
            "stdout_sha256": hex::encode(out.finalize()),
            "stderr_sha256": hex::encode(err.finalize()),
            "exit": exit,
        }),
    )
}

fn no_input<T>(_: &T) -> Result<(), ProtoError> {
    Err(perr(ErrorCode::Protocol, "unexpected message from agent"))
}

async fn relay_file_get(
    agent: &mut MuxStream,
    dev: &mut MuxStream,
    info: &StreamInfo,
) -> (Result<(), ProtoError>, Value) {
    let mut bytes = 0u64;
    let mut h = Sha256::new();
    let mut meta = Value::Null;
    let mut end = Value::Null;
    let r = relay_typed::<FileMsg, FileMsg, _, _, _>(
        agent,
        dev,
        info,
        no_input,
        |m| match m {
            FileMsg::Meta { size, mode, mtime } => {
                meta = json!({"size": size, "mode": mode, "mtime": mtime});
                Ok(false)
            }
            FileMsg::Chunk(b) => {
                bytes += b.len() as u64;
                h.update(b);
                Ok(false)
            }
            FileMsg::End { sha256 } => {
                end = json!(sha256);
                Ok(true)
            }
            _ => Err(perr(ErrorCode::Protocol, "unexpected message from device")),
        },
        |_| vec![],
    )
    .await;
    (
        r,
        json!({"meta": meta, "bytes": bytes, "range_sha256": hex::encode(h.finalize()), "file_sha256": end}),
    )
}

async fn relay_file_put(
    agent: &mut MuxStream,
    dev: &mut MuxStream,
    info: &StreamInfo,
    req: &OpenRequest,
) -> (Result<(), ProtoError>, Value) {
    let (offset, size) = match req {
        OpenRequest::FilePut { offset, size, .. } => (*offset, *size),
        _ => (0, 0),
    };
    let expected = size - offset;
    let mut bytes = 0u64;
    let mut ended = false;
    let mut h = Sha256::new();
    let mut done = Value::Null;
    let r = relay_typed::<FileMsg, FileMsg, _, _, _>(
        agent,
        dev,
        info,
        |m| match m {
            FileMsg::Chunk(b) if !ended => {
                bytes += b.len() as u64;
                if bytes > expected {
                    return Err(perr(ErrorCode::BadRequest, "more data than announced"));
                }
                h.update(b);
                Ok(())
            }
            FileMsg::End { .. } if !ended => {
                ended = true;
                Ok(())
            }
            _ => Err(perr(ErrorCode::Protocol, "unexpected message from agent")),
        },
        |m| match m {
            FileMsg::Done { size, sha256 } => {
                done = json!({"size": size, "sha256": sha256});
                Ok(true)
            }
            _ => Err(perr(ErrorCode::Protocol, "unexpected message from device")),
        },
        |_| vec![],
    )
    .await;
    (
        r,
        json!({"bytes": bytes, "range_sha256": hex::encode(h.finalize()), "result": done}),
    )
}

async fn relay_file_list(
    agent: &mut MuxStream,
    dev: &mut MuxStream,
    info: &StreamInfo,
) -> (Result<(), ProtoError>, Value) {
    let mut entries = 0u64;
    let r = relay_typed::<FileMsg, FileMsg, _, _, _>(
        agent,
        dev,
        info,
        no_input,
        |m| match m {
            FileMsg::Stat(_) => Ok(false),
            FileMsg::Entries(e) => {
                entries += e.len() as u64;
                Ok(false)
            }
            FileMsg::End { .. } => Ok(true),
            _ => Err(perr(ErrorCode::Protocol, "unexpected message from device")),
        },
        |_| vec![],
    )
    .await;
    (r, json!({"entries": entries}))
}

/// Copy bytes both ways (with half-close) until both directions ended, an
/// error occurs or the stream is cancelled. Returns (result, a->b, b->a).
pub(crate) async fn relay_raw<A, B>(
    a: &mut A,
    b: &mut B,
    cancel: &CancellationToken,
) -> (Result<(), ProtoError>, u64, u64)
where
    A: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
    B: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let (mut ar, mut aw) = tokio::io::split(a);
    let (mut br, mut bw) = tokio::io::split(b);
    let mut ab = 0u64;
    let mut ba = 0u64;
    let r = {
        let up = copy_count(&mut ar, &mut bw, &mut ab);
        let down = copy_count(&mut br, &mut aw, &mut ba);
        tokio::pin!(up);
        tokio::pin!(down);
        let (mut u, mut d) = (false, false);
        loop {
            if u && d {
                break Ok(());
            }
            tokio::select! {
                r = &mut up, if !u => { u = true; if let Err(e) = r { break Err(e) } }
                r = &mut down, if !d => { d = true; if let Err(e) = r { break Err(e) } }
                _ = cancel.cancelled() => break Err(perr(ErrorCode::Cancelled, "session terminated")),
            }
        }
    };
    let _ = aw.shutdown().await;
    let _ = bw.shutdown().await;
    (r, ab, ba)
}

async fn copy_count<R, W>(r: &mut R, w: &mut W, n: &mut u64) -> Result<(), ProtoError>
where
    R: tokio::io::AsyncRead + Unpin,
    W: tokio::io::AsyncWrite + Unpin,
{
    let mut buf = vec![0u8; 32 * 1024];
    loop {
        let k = r.read(&mut buf).await.map_err(cjs_mux::io_err)?;
        if k == 0 {
            let _ = w.shutdown().await;
            return Ok(());
        }
        w.write_all(&buf[..k]).await.map_err(cjs_mux::io_err)?;
        *n += k as u64;
    }
}

/// Keep a remote-forward control stream pair open until either side ends.
async fn hold_control(
    agent: &mut MuxStream,
    dev: &mut MuxStream,
    cancel: &CancellationToken,
) -> Result<(), ProtoError> {
    let mut a = [0u8; 64];
    let mut d = [0u8; 64];
    let r = tokio::select! {
        r = agent.read(&mut a) => match r {
            Ok(0) | Err(_) => Ok(()),
            Ok(_) => Err(perr(ErrorCode::Protocol, "unexpected data on control stream")),
        },
        r = dev.read(&mut d) => match r {
            Ok(0) | Err(_) => Ok(()),
            Ok(_) => Err(perr(ErrorCode::Protocol, "unexpected data on control stream")),
        },
        _ = cancel.cancelled() => Err(perr(ErrorCode::Cancelled, "session terminated")),
    };
    let _ = agent.shutdown().await;
    let _ = dev.shutdown().await;
    r
}
