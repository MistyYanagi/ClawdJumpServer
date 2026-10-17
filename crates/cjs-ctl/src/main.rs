//! `cjsctl`: administer ClawdJumpServer through its REST API.
//!
//! `cjsctl login` stores the session cookie and CSRF token in
//! `<config>/cjsctl/session.json` (0600). All output is JSON.
use std::path::PathBuf;

use clap::{Parser, Subcommand};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

#[derive(Parser)]
#[command(name = "cjsctl", version, about = "ClawdJumpServer administration CLI")]
struct Cli {
    /// Session file (default: <config dir>/cjsctl/session.json).
    #[arg(long, global = true, env = "CJSCTL_SESSION")]
    session: Option<PathBuf>,
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Log in (password and TOTP are prompted unless given via env).
    Login {
        #[arg(long, env = "CJS_SERVER")]
        server: String,
        #[arg(long, env = "CJS_USER")]
        name: String,
        /// Extra CA certificate (PEM) for the server's TLS certificate.
        #[arg(long)]
        ca: Option<PathBuf>,
    },
    Logout,
    /// Show the current user.
    Me,
    /// Change your password.
    Passwd,
    /// Server keys and version.
    Info,
    #[command(subcommand)]
    Users(UserCmd),
    #[command(subcommand)]
    Agents(AssetCmd),
    #[command(subcommand)]
    Devices(AssetCmd),
    #[command(subcommand)]
    Groups(GroupCmd),
    #[command(subcommand)]
    Token(TokenCmd),
    #[command(subcommand)]
    Grants(GrantCmd),
    #[command(subcommand, name = "full-access")]
    FullAccess(FullCmd),
    #[command(subcommand)]
    Live(LiveCmd),
    #[command(subcommand)]
    Audit(AuditCmd),
    /// Download a terminal recording (asciicast v2).
    Recording {
        session: String,
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
}

#[derive(Subcommand)]
enum UserCmd {
    List,
    Create {
        name: String,
        /// sysadmin, secadmin, auditor (comma separated)
        #[arg(long, value_delimiter = ',')]
        roles: Vec<String>,
        #[arg(long)]
        display_name: Option<String>,
        /// Unix time when the account expires.
        #[arg(long)]
        expires_at: Option<i64>,
    },
    Disable {
        user: String,
    },
    Enable {
        user: String,
    },
    /// Replace a user's roles.
    Roles {
        user: String,
        #[arg(value_delimiter = ',')]
        roles: Vec<String>,
    },
    Reset {
        user: String,
    },
    Unlock {
        user: String,
    },
}

#[derive(Subcommand)]
enum AssetCmd {
    List,
    Disable { id: String },
    Enable { id: String },
    Delete { id: String },
}

#[derive(Subcommand)]
enum GroupCmd {
    List,
    Create {
        name: String,
        /// user, agent or device
        #[arg(long)]
        kind: String,
        #[arg(long, default_value = "")]
        description: String,
    },
    Delete {
        group: String,
    },
    Add {
        group: String,
        member: String,
    },
    Remove {
        group: String,
        member: String,
    },
}

#[derive(Subcommand)]
enum TokenCmd {
    List,
    /// Create a one-time enrollment token.
    Create {
        /// agent or device
        #[arg(long)]
        kind: String,
        #[arg(long)]
        name: String,
        /// Owner of an agent (default: you).
        #[arg(long)]
        owner: Option<String>,
        #[arg(long, default_value_t = 86400)]
        ttl: i64,
    },
}

#[derive(Subcommand)]
enum GrantCmd {
    List,
    /// Create or replace a grant from a JSON file ("-" for stdin).
    Put {
        id: String,
        file: PathBuf,
    },
    Delete {
        id: String,
    },
}

#[derive(Subcommand)]
enum FullCmd {
    List,
    Request {
        #[arg(long)]
        agent: String,
        #[arg(long)]
        device: String,
        #[arg(long)]
        reason: String,
        /// Seconds (at most 8h).
        #[arg(long, default_value_t = 3600)]
        duration: i64,
    },
    Approve {
        id: String,
    },
    Reject {
        id: String,
    },
    Revoke {
        id: String,
    },
}

#[derive(Subcommand)]
enum LiveCmd {
    Connections,
    Streams,
    Kill { session: String },
    Kick { connection: String },
}

#[derive(Subcommand)]
enum AuditCmd {
    Query {
        #[arg(long)]
        kind: Option<String>,
        #[arg(long)]
        actor: Option<String>,
        #[arg(long)]
        session: Option<String>,
        #[arg(long)]
        target: Option<String>,
        #[arg(long)]
        outcome: Option<String>,
        #[arg(long)]
        text: Option<String>,
        #[arg(long)]
        highlight: bool,
        #[arg(long, default_value_t = 100)]
        limit: u32,
    },
    Verify,
    Export {
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
    Checkpoint,
}

#[derive(Serialize, Deserialize)]
struct Session {
    server: String,
    cookie: String,
    csrf: String,
    ca: Option<PathBuf>,
}

fn die(m: impl std::fmt::Display) -> ! {
    eprintln!("error: {m}");
    std::process::exit(1)
}

fn session_path(cli: &Cli) -> PathBuf {
    cli.session.clone().unwrap_or_else(|| {
        dirs::config_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join("cjsctl")
            .join("session.json")
    })
}

fn client(ca: Option<&PathBuf>) -> reqwest::Client {
    let mut b = reqwest::Client::builder().timeout(std::time::Duration::from_secs(60));
    if let Some(p) = ca {
        for c in cjs_transport::tls::load_pem_certs(p).unwrap_or_else(|e| die(e)) {
            b = b.add_root_certificate(reqwest::Certificate::from_der(&c).unwrap_or_else(|e| die(e)));
        }
    }
    b.build().unwrap_or_else(|e| die(e))
}

fn prompt(label: &str, env: &str, secret: bool) -> String {
    if let Ok(v) = std::env::var(env) {
        return v;
    }
    if secret {
        rpassword::prompt_password(label).unwrap_or_else(|e| die(e))
    } else {
        eprint!("{label}");
        let mut s = String::new();
        std::io::stdin().read_line(&mut s).unwrap_or_else(|e| die(e));
        s.trim().to_string()
    }
}

struct Api {
    http: reqwest::Client,
    s: Session,
}

impl Api {
    fn load(path: &PathBuf) -> Self {
        let data = std::fs::read(path).unwrap_or_else(|_| die("not logged in (run `cjsctl login`)"));
        let s: Session = serde_json::from_slice(&data).unwrap_or_else(|e| die(e));
        Self {
            http: client(s.ca.as_ref()),
            s,
        }
    }

    fn url(&self, path: &str) -> String {
        format!("{}/api/v1{path}", self.s.server.trim_end_matches('/'))
    }

    async fn raw(&self, method: reqwest::Method, path: &str, body: Option<Value>) -> reqwest::Response {
        let mut r = self
            .http
            .request(method.clone(), self.url(path))
            .header("cookie", format!("cjs_session={}", self.s.cookie));
        if method != reqwest::Method::GET {
            r = r.header("x-csrf-token", &self.s.csrf);
        }
        if let Some(b) = body {
            r = r.json(&b);
        }
        let resp = r.send().await.unwrap_or_else(|e| die(e));
        if !resp.status().is_success() {
            let status = resp.status();
            let v: Value = resp.json().await.unwrap_or(json!({}));
            let code = v["error"]["code"].as_str().unwrap_or("error").to_string();
            let msg = v["error"]["message"].as_str().unwrap_or("").to_string();
            eprintln!("error: {code}: {msg} (HTTP {status})");
            let exit = cjs_proto_exit(&code);
            std::process::exit(exit);
        }
        resp
    }

    async fn call(&self, method: reqwest::Method, path: &str, body: Option<Value>) -> Value {
        self.raw(method, path, body)
            .await
            .json()
            .await
            .unwrap_or(Value::Null)
    }

    async fn get(&self, path: &str) -> Value {
        self.call(reqwest::Method::GET, path, None).await
    }

    async fn post(&self, path: &str, body: Value) -> Value {
        self.call(reqwest::Method::POST, path, Some(body)).await
    }
}

fn cjs_proto_exit(code: &str) -> i32 {
    use cjs_proto::ErrorCode::*;
    [
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
    ]
    .into_iter()
    .find(|c| c.as_str() == code)
    .map(|c| c.exit_code())
    .unwrap_or(1)
}

fn print(v: &Value) {
    println!("{}", serde_json::to_string_pretty(v).unwrap_or_default());
}

fn enc(s: &str) -> String {
    url::form_urlencoded::byte_serialize(s.as_bytes()).collect()
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();
    let path = session_path(&cli);
    match &cli.cmd {
        Cmd::Login { server, name, ca } => {
            let password = prompt("password: ", "CJS_PASSWORD", true);
            let totp = prompt("TOTP code: ", "CJS_TOTP", false);
            let http = client(ca.as_ref());
            let resp = http
                .post(format!("{}/api/v1/login", server.trim_end_matches('/')))
                .json(&json!({"name": name, "password": password, "totp": totp}))
                .send()
                .await
                .unwrap_or_else(|e| die(e));
            let cookie = resp
                .headers()
                .get_all("set-cookie")
                .iter()
                .filter_map(|v| v.to_str().ok())
                .find_map(|c| {
                    c.strip_prefix("cjs_session=")
                        .map(|r| r.split(';').next().unwrap_or("").to_string())
                });
            let ok = resp.status().is_success();
            let v: Value = resp.json().await.unwrap_or(json!({}));
            if !ok {
                die(format!(
                    "{}: {}",
                    v["error"]["code"].as_str().unwrap_or("error"),
                    v["error"]["message"].as_str().unwrap_or("")
                ));
            }
            let s = Session {
                server: server.clone(),
                cookie: cookie.unwrap_or_else(|| die("server did not set a session cookie")),
                csrf: v["csrf"].as_str().unwrap_or_default().to_string(),
                ca: ca.as_ref().map(|p| {
                    std::fs::canonicalize(p).unwrap_or_else(|e| die(format!("{}: {e}", p.display())))
                }),
            };
            if let Some(d) = path.parent() {
                std::fs::create_dir_all(d).unwrap_or_else(|e| die(e));
            }
            cjs_transport::keys::write_secret_file(&path, &serde_json::to_vec(&s).unwrap_or_default())
                .unwrap_or_else(|e| die(e));
            print(&v["user"]);
        }
        Cmd::Logout => {
            let api = Api::load(&path);
            api.post("/logout", json!({})).await;
            let _ = std::fs::remove_file(&path);
        }
        cmd => {
            let api = Api::load(&path);
            run(&api, cmd).await;
        }
    }
}

async fn run(api: &Api, cmd: &Cmd) {
    use reqwest::Method as M;
    let v = match cmd {
        Cmd::Me => api.get("/me").await["user"].clone(),
        Cmd::Info => api.get("/info").await,
        Cmd::Passwd => {
            let old = prompt("current password: ", "CJS_PASSWORD", true);
            let new = prompt("new password: ", "CJS_NEW_PASSWORD", true);
            let totp = prompt("TOTP code: ", "CJS_TOTP", false);
            api.post("/me/password", json!({"old": old, "new": new, "totp": totp})).await
        }
        Cmd::Users(c) => match c {
            UserCmd::List => api.get("/users").await,
            UserCmd::Create {
                name,
                roles,
                display_name,
                expires_at,
            } => {
                api.post(
                    "/users",
                    json!({"name": name, "roles": roles, "display_name": display_name, "expires_at": expires_at}),
                )
                .await
            }
            UserCmd::Disable { user } => {
                api.call(M::PATCH, &format!("/users/{}", enc(user)), Some(json!({"status": "disabled"})))
                    .await
            }
            UserCmd::Enable { user } => {
                api.call(M::PATCH, &format!("/users/{}", enc(user)), Some(json!({"status": "active"})))
                    .await
            }
            UserCmd::Roles { user, roles } => {
                api.call(M::PATCH, &format!("/users/{}", enc(user)), Some(json!({"roles": roles})))
                    .await
            }
            UserCmd::Reset { user } => api.post(&format!("/users/{}/reset", enc(user)), json!({})).await,
            UserCmd::Unlock { user } => api.post(&format!("/users/{}/unlock", enc(user)), json!({})).await,
        },
        Cmd::Agents(c) | Cmd::Devices(c) => {
            let base = if matches!(cmd, Cmd::Agents(_)) { "/agents" } else { "/devices" };
            match c {
                AssetCmd::List => api.get(base).await,
                AssetCmd::Disable { id } => {
                    api.call(M::PATCH, &format!("{base}/{}", enc(id)), Some(json!({"status": "disabled"})))
                        .await
                }
                AssetCmd::Enable { id } => {
                    api.call(M::PATCH, &format!("{base}/{}", enc(id)), Some(json!({"status": "active"})))
                        .await
                }
                AssetCmd::Delete { id } => api.call(M::DELETE, &format!("{base}/{}", enc(id)), None).await,
            }
        }
        Cmd::Groups(c) => match c {
            GroupCmd::List => api.get("/groups").await,
            GroupCmd::Create {
                name,
                kind,
                description,
            } => {
                api.post("/groups", json!({"name": name, "kind": kind, "description": description}))
                    .await
            }
            GroupCmd::Delete { group } => api.call(M::DELETE, &format!("/groups/{}", enc(group)), None).await,
            GroupCmd::Add { group, member } => {
                api.call(M::PUT, &format!("/groups/{}/members/{}", enc(group), enc(member)), None)
                    .await
            }
            GroupCmd::Remove { group, member } => {
                api.call(M::DELETE, &format!("/groups/{}/members/{}", enc(group), enc(member)), None)
                    .await
            }
        },
        Cmd::Token(c) => match c {
            TokenCmd::List => api.get("/tokens").await,
            TokenCmd::Create {
                kind,
                name,
                owner,
                ttl,
            } => {
                api.post("/tokens", json!({"kind": kind, "name": name, "owner": owner, "ttl_secs": ttl}))
                    .await
            }
        },
        Cmd::Grants(c) => match c {
            GrantCmd::List => api.get("/grants").await,
            GrantCmd::Put { id, file } => {
                let data = if file.as_os_str() == "-" {
                    let mut s = String::new();
                    std::io::Read::read_to_string(&mut std::io::stdin(), &mut s).unwrap_or_else(|e| die(e));
                    s
                } else {
                    std::fs::read_to_string(file).unwrap_or_else(|e| die(format!("{}: {e}", file.display())))
                };
                let body: Value = serde_json::from_str(&data).unwrap_or_else(|e| die(format!("grant JSON: {e}")));
                api.call(M::PUT, &format!("/grants/{}", enc(id)), Some(body)).await
            }
            GrantCmd::Delete { id } => api.call(M::DELETE, &format!("/grants/{}", enc(id)), None).await,
        },
        Cmd::FullAccess(c) => match c {
            FullCmd::List => api.get("/full-access").await,
            FullCmd::Request {
                agent,
                device,
                reason,
                duration,
            } => {
                api.post(
                    "/full-access",
                    json!({"agent": agent, "device": device, "reason": reason, "duration_secs": duration}),
                )
                .await
            }
            FullCmd::Approve { id } => api.post(&format!("/full-access/{}/approve", enc(id)), json!({})).await,
            FullCmd::Reject { id } => api.post(&format!("/full-access/{}/reject", enc(id)), json!({})).await,
            FullCmd::Revoke { id } => api.post(&format!("/full-access/{}/revoke", enc(id)), json!({})).await,
        },
        Cmd::Live(c) => match c {
            LiveCmd::Connections => api.get("/live/connections").await,
            LiveCmd::Streams => api.get("/live/streams").await,
            LiveCmd::Kill { session } => api.post(&format!("/live/sessions/{}/kill", enc(session)), json!({})).await,
            LiveCmd::Kick { connection } => {
                api.post(&format!("/live/connections/{}/kick", enc(connection)), json!({}))
                    .await
            }
        },
        Cmd::Audit(c) => match c {
            AuditCmd::Query {
                kind,
                actor,
                session,
                target,
                outcome,
                text,
                highlight,
                limit,
            } => {
                let mut q = vec![format!("limit={limit}")];
                for (k, v) in [
                    ("kind", kind),
                    ("actor", actor),
                    ("session", session),
                    ("target", target),
                    ("outcome", outcome),
                    ("text", text),
                ] {
                    if let Some(v) = v {
                        q.push(format!("{k}={}", enc(v)));
                    }
                }
                if *highlight {
                    q.push("highlight=true".into());
                }
                api.get(&format!("/audit?{}", q.join("&"))).await
            }
            AuditCmd::Verify => api.get("/audit/verify").await,
            AuditCmd::Export { output } => {
                let bytes = api
                    .raw(M::GET, "/audit/export", None)
                    .await
                    .bytes()
                    .await
                    .unwrap_or_else(|e| die(e));
                write_out(output.as_ref(), &bytes);
                return;
            }
            AuditCmd::Checkpoint => api.post("/audit/checkpoint", json!({})).await,
        },
        Cmd::Recording { session, output } => {
            let bytes = api
                .raw(M::GET, &format!("/recordings/{}", enc(session)), None)
                .await
                .bytes()
                .await
                .unwrap_or_else(|e| die(e));
            write_out(output.as_ref(), &bytes);
            return;
        }
        Cmd::Login { .. } | Cmd::Logout => unreachable!(),
    };
    print(&v);
}

fn write_out(path: Option<&PathBuf>, data: &[u8]) {
    match path {
        Some(p) => std::fs::write(p, data).unwrap_or_else(|e| die(format!("{}: {e}", p.display()))),
        None => {
            use std::io::Write;
            let _ = std::io::stdout().write_all(data);
        }
    }
}
