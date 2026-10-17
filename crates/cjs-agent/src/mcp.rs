//! MCP server over stdio (newline-delimited JSON-RPC 2.0), so AI agents
//! can use ClawdJumpServer as a tool provider. Every tool call is an
//! ordinary stream: decided, audited and (for files) jailed by the server
//! and the device.
use cjs_mux::{expect_msg, read_msg, write_msg};
use cjs_proto::{ErrorCode, FileMsg, OpenRequest, ProtoError, MAX_DATA_CHUNK};
use serde_json::{json, Value};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

use crate::local::Opener;
use crate::ops;
use crate::project::Project;

const PROTOCOL_VERSION: &str = "2025-06-18";
/// Largest file the MCP tools read or write in one call.
const MAX_FILE: u64 = 4 * 1024 * 1024;
const MAX_OUTPUT: usize = 1024 * 1024;

fn tools() -> Value {
    let device =
        json!({"type": "string", "description": "Device name (defaults to the project's .cjs.toml device)"});
    json!([
        {
            "name": "cjs_list_devices",
            "description": "List devices this agent may use, with allowed actions and project roots.",
            "inputSchema": {"type": "object", "properties": {}},
        },
        {
            "name": "cjs_exec",
            "description": "Run a command on a device (sandboxed; writes limited to the project roots). Returns stdout, stderr and exit code.",
            "inputSchema": {"type": "object", "properties": {
                "device": device,
                "command": {"type": "string", "description": "Shell command line (run with /bin/sh -c, or cmd /C on Windows devices)"},
                "argv": {"type": "array", "items": {"type": "string"}, "description": "Program and arguments, instead of command"},
                "cwd": {"type": "string"},
                "stdin": {"type": "string"},
                "timeout_secs": {"type": "integer", "minimum": 1}
            }},
        },
        {
            "name": "cjs_read_file",
            "description": "Read a text file inside the project roots of a device.",
            "inputSchema": {"type": "object", "properties": {"device": device, "path": {"type": "string"}}, "required": ["path"]},
        },
        {
            "name": "cjs_write_file",
            "description": "Write (create or replace) a text file inside the project roots of a device.",
            "inputSchema": {"type": "object", "properties": {
                "device": device,
                "path": {"type": "string"},
                "content": {"type": "string"},
                "mkdirs": {"type": "boolean"}
            }, "required": ["path", "content"]},
        },
        {
            "name": "cjs_list_dir",
            "description": "List a directory inside the project roots of a device.",
            "inputSchema": {"type": "object", "properties": {"device": device, "path": {"type": "string"}}},
        }
    ])
}

fn text(s: impl Into<String>, is_error: bool) -> Value {
    json!({"content": [{"type": "text", "text": s.into()}], "isError": is_error})
}

pub async fn read_file(op: &Opener, device: &str, path: &str) -> Result<Vec<u8>, ProtoError> {
    let (mut s, _) = op
        .open(&OpenRequest::FileGet {
            device: device.into(),
            path: path.into(),
            offset: 0,
        })
        .await?;
    let _ = s.shutdown().await;
    match expect_msg::<_, FileMsg>(&mut s).await? {
        FileMsg::Meta { size, .. } if size > MAX_FILE => {
            return Err(ProtoError::new(
                ErrorCode::LimitExceeded,
                format!("file is larger than {MAX_FILE} bytes"),
            ))
        }
        FileMsg::Meta { .. } => {}
        _ => return Err(ProtoError::new(ErrorCode::Protocol, "expected metadata")),
    }
    let mut data = Vec::new();
    while let Some(m) = read_msg::<_, FileMsg>(&mut s).await? {
        match m {
            FileMsg::Chunk(b) => data.extend(b),
            FileMsg::End { .. } => return Ok(data),
            _ => return Err(ProtoError::new(ErrorCode::Protocol, "unexpected message")),
        }
    }
    Err(ProtoError::new(ErrorCode::Io, "transfer interrupted"))
}

pub async fn write_file(
    op: &Opener,
    device: &str,
    path: &str,
    data: &[u8],
    mkdirs: bool,
) -> Result<String, ProtoError> {
    let (s, _) = op
        .open(&OpenRequest::FilePut {
            device: device.into(),
            path: path.into(),
            offset: 0,
            size: data.len() as u64,
            mode: None,
            mkdirs,
        })
        .await?;
    let (mut r, mut w) = tokio::io::split(s);
    for c in data.chunks(MAX_DATA_CHUNK) {
        write_msg(&mut w, &FileMsg::Chunk(c.to_vec())).await?;
    }
    write_msg(&mut w, &FileMsg::End { sha256: None }).await?;
    match expect_msg::<_, FileMsg>(&mut r).await? {
        FileMsg::Done { sha256, .. } => Ok(sha256),
        _ => Err(ProtoError::new(ErrorCode::Protocol, "unexpected message")),
    }
}

async fn call(op: &Opener, project: &Project, name: &str, args: &Value) -> Result<Value, ProtoError> {
    let device = || -> Result<String, ProtoError> {
        args.get("device")
            .and_then(|v| v.as_str())
            .map(String::from)
            .or_else(|| project.device.clone())
            .ok_or_else(|| {
                ProtoError::new(
                    ErrorCode::BadRequest,
                    "no device given and no default in .cjs.toml",
                )
            })
    };
    let s = |k: &str| args.get(k).and_then(|v| v.as_str()).map(String::from);
    match name {
        "cjs_list_devices" => {
            let d = ops::devices(op).await?;
            Ok(text(serde_json::to_string_pretty(&d).unwrap_or_default(), false))
        }
        "cjs_exec" => {
            let device = device()?;
            let argv: Vec<String> = match (args.get("argv").and_then(|v| v.as_array()), s("command")) {
                (Some(a), _) => a.iter().filter_map(|x| x.as_str().map(String::from)).collect(),
                (None, Some(c)) => {
                    let windows = ops::devices(op)
                        .await
                        .ok()
                        .and_then(|ds| ds.into_iter().find(|d| d.name == device || d.id == device))
                        .map(|d| d.os == "windows")
                        .unwrap_or(false);
                    if windows {
                        vec!["cmd.exe".into(), "/C".into(), c]
                    } else {
                        vec!["/bin/sh".into(), "-c".into(), c]
                    }
                }
                (None, None) => {
                    return Err(ProtoError::new(
                        ErrorCode::BadRequest,
                        "command or argv is required",
                    ))
                }
            };
            let req = OpenRequest::Exec {
                device,
                argv,
                cwd: s("cwd").or_else(|| project.cwd.clone()),
                env: vec![],
                timeout_secs: args.get("timeout_secs").and_then(|v| v.as_u64()).or(Some(600)),
            };
            let r = ops::exec_collect(op, &req, s("stdin").map(String::into_bytes), MAX_OUTPUT).await?;
            let failed = r.exit_code != Some(0);
            Ok(text(serde_json::to_string_pretty(&r).unwrap_or_default(), failed))
        }
        "cjs_read_file" => {
            let path = s("path").ok_or_else(|| ProtoError::new(ErrorCode::BadRequest, "path is required"))?;
            let data = read_file(op, &device()?, &path).await?;
            match String::from_utf8(data) {
                Ok(t) => Ok(text(t, false)),
                Err(_) => Ok(text(
                    "file is not valid UTF-8 text; use `cjs cp` for binary files",
                    true,
                )),
            }
        }
        "cjs_write_file" => {
            let path = s("path").ok_or_else(|| ProtoError::new(ErrorCode::BadRequest, "path is required"))?;
            let content =
                s("content").ok_or_else(|| ProtoError::new(ErrorCode::BadRequest, "content is required"))?;
            if content.len() as u64 > MAX_FILE {
                return Err(ProtoError::new(ErrorCode::LimitExceeded, "content too large"));
            }
            let mkdirs = args.get("mkdirs").and_then(|v| v.as_bool()).unwrap_or(false);
            let sha = write_file(op, &device()?, &path, content.as_bytes(), mkdirs).await?;
            Ok(text(
                format!("wrote {} bytes (sha256 {sha})", content.len()),
                false,
            ))
        }
        "cjs_list_dir" => {
            let path = s("path")
                .or_else(|| project.cwd.clone())
                .unwrap_or_else(|| ".".into());
            let (_, entries) = ops::list(op, &device()?, &path).await?;
            let lines: Vec<String> = entries
                .iter()
                .map(|e| {
                    let k = match e.kind {
                        cjs_proto::EntryKind::Dir => "dir ",
                        cjs_proto::EntryKind::File => "file",
                        cjs_proto::EntryKind::Symlink => "link",
                        cjs_proto::EntryKind::Other => "othr",
                    };
                    format!("{k} {:>12} {}", e.size, e.name)
                })
                .collect();
            Ok(text(lines.join("\n"), false))
        }
        _ => Err(ProtoError::new(
            ErrorCode::NotFound,
            format!("unknown tool {name}"),
        )),
    }
}

pub async fn serve(op: Opener, project: Project) -> Result<(), ProtoError> {
    let mut lines = BufReader::new(tokio::io::stdin()).lines();
    let mut out = tokio::io::stdout();
    while let Some(line) = lines
        .next_line()
        .await
        .map_err(|e| ProtoError::new(ErrorCode::Io, e.to_string()))?
    {
        if line.trim().is_empty() {
            continue;
        }
        let msg: Value = match serde_json::from_str(&line) {
            Ok(v) => v,
            Err(e) => {
                let r = json!({"jsonrpc": "2.0", "id": null, "error": {"code": -32700, "message": e.to_string()}});
                out.write_all(format!("{r}\n").as_bytes()).await.ok();
                out.flush().await.ok();
                continue;
            }
        };
        let Some(id) = msg.get("id").cloned() else {
            continue; // notification
        };
        let method = msg.get("method").and_then(|m| m.as_str()).unwrap_or("");
        let params = msg.get("params").cloned().unwrap_or(Value::Null);
        let result: Result<Value, (i64, String)> = match method {
            "initialize" => Ok(json!({
                "protocolVersion": PROTOCOL_VERSION,
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "cjs", "version": crate::VERSION},
            })),
            "ping" => Ok(json!({})),
            "tools/list" => Ok(json!({"tools": tools()})),
            "tools/call" => {
                let name = params.get("name").and_then(|n| n.as_str()).unwrap_or("");
                let args = params.get("arguments").cloned().unwrap_or(json!({}));
                Ok(match call(&op, &project, name, &args).await {
                    Ok(v) => v,
                    Err(e) => text(format!("{}: {}", e.code, e.message), true),
                })
            }
            _ => Err((-32601, format!("method not found: {method}"))),
        };
        let r = match result {
            Ok(v) => json!({"jsonrpc": "2.0", "id": id, "result": v}),
            Err((code, m)) => json!({"jsonrpc": "2.0", "id": id, "error": {"code": code, "message": m}}),
        };
        out.write_all(format!("{r}\n").as_bytes())
            .await
            .map_err(|e| ProtoError::new(ErrorCode::Io, e.to_string()))?;
        out.flush().await.ok();
    }
    Ok(())
}
