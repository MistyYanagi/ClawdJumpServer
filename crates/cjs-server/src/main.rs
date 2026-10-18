//! `cjs-server`: the ClawdJumpServer bastion.
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use cjs_proto::Role as ClientRole;
use cjs_server::db::Db;
use cjs_server::{accounts, Keys, Server, ServerConfig};
use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "cjs-server", version, about = "ClawdJumpServer bastion server")]
struct Cli {
    /// Data directory (keys, databases, recordings).
    #[arg(long, global = true, env = "CJS_DATA", default_value = "/var/lib/cjs-server")]
    data: PathBuf,
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Create keys, databases, a TLS certificate and the first administrator.
    Init {
        /// Name of the first administrator (sysadmin + secadmin).
        #[arg(long, default_value = "admin")]
        admin: String,
        /// Host names / IPs for the self-signed TLS certificate.
        #[arg(long = "hostname", default_values_t = vec!["localhost".to_string()])]
        hostnames: Vec<String>,
    },
    /// Serve agents, devices, the API and the web UI on one port.
    Run {
        #[arg(long, env = "CJS_LISTEN", default_value = "0.0.0.0:8443")]
        listen: SocketAddr,
        /// TLS certificate chain (PEM). Default: <data>/tls/cert.pem.
        #[arg(long)]
        tls_cert: Option<PathBuf>,
        /// TLS private key (PEM). Default: <data>/tls/key.pem.
        #[arg(long)]
        tls_key: Option<PathBuf>,
        /// Serve plain HTTP (only behind a TLS-terminating reverse proxy or
        /// for local testing; sessions stay Noise-encrypted end to end).
        #[arg(long)]
        no_tls: bool,
        /// Take client addresses from X-Forwarded-For (trusted proxy only).
        #[arg(long)]
        trust_forwarded_for: bool,
    },
    /// Issue a one-time enrollment token from the command line.
    Token {
        #[arg(long)]
        kind: String,
        #[arg(long)]
        name: String,
        /// Owner (user name or id) for agent tokens.
        #[arg(long)]
        owner: Option<String>,
        #[arg(long, default_value_t = 86400)]
        ttl: i64,
    },
    /// Verify the audit log's hash chain and checkpoint signatures.
    AuditVerify,
    /// Print the server's public keys.
    Info,
}

fn die(m: impl std::fmt::Display) -> ! {
    eprintln!("error: {m}");
    std::process::exit(1)
}

fn open(data: &Path) -> (Keys, Db, cjs_audit::AuditLog) {
    let keys = Keys::load_or_create(data).unwrap_or_else(|e| die(e));
    let db = Db::open(&data.join("cjs.db")).unwrap_or_else(|e| die(e));
    let audit =
        cjs_audit::AuditLog::open(&data.join("audit.db"), keys.audit.clone()).unwrap_or_else(|e| die(e));
    (keys, db, audit)
}

fn restrict(dir: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700));
    }
    #[cfg(not(unix))]
    let _ = dir;
}

fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();
    let _ = rustls::crypto::ring::default_provider().install_default();
    let cli = Cli::parse();
    let rt = tokio::runtime::Runtime::new().expect("tokio runtime");
    rt.block_on(async move {
        std::fs::create_dir_all(&cli.data).unwrap_or_else(|e| die(format!("{}: {e}", cli.data.display())));
        restrict(&cli.data);
        match cli.cmd {
            Cmd::Init { admin, hostnames } => init(&cli.data, &admin, hostnames),
            Cmd::Run {
                listen,
                tls_cert,
                tls_key,
                no_tls,
                trust_forwarded_for,
            } => run(&cli.data, listen, tls_cert, tls_key, no_tls, trust_forwarded_for).await,
            Cmd::Token {
                kind,
                name,
                owner,
                ttl,
            } => {
                let (keys, db, audit) = open(&cli.data);
                let srv = Server::start(ServerConfig::new(&cli.data), keys, db, audit);
                let kind = match kind.as_str() {
                    "agent" => ClientRole::Agent,
                    "device" => ClientRole::Device,
                    _ => die("--kind must be agent or device"),
                };
                let (row, token) = srv
                    .create_enroll_token(kind, &name, owner.as_deref(), "system:cli", ttl)
                    .unwrap_or_else(|e| die(e));
                eprintln!(
                    "token {} for {} {name}, expires at {}",
                    row.id, row.kind, row.expires_at
                );
                println!("{token}");
            }
            Cmd::AuditVerify => {
                let keys = Keys::load_existing(&cli.data).unwrap_or_else(|e| die(e));
                let r = cjs_audit::verify_file(&cli.data.join("audit.db"), &keys.audit.verifying_key())
                    .unwrap_or_else(|e| die(e));
                println!("{}", serde_json::to_string_pretty(&r).unwrap_or_default());
                if !r.ok {
                    std::process::exit(2);
                }
            }
            Cmd::Info => {
                let keys = Keys::load_existing(&cli.data).unwrap_or_else(|e| die(e));
                println!("server key:     {}", hex::encode(keys.noise.public));
                println!("fingerprint:    {}", keys.noise.fingerprint());
                println!(
                    "capability key: {}",
                    hex::encode(keys.cap.verifying_key().as_bytes())
                );
                println!(
                    "audit key:      {}",
                    hex::encode(keys.audit.verifying_key().as_bytes())
                );
            }
        }
    });
}

fn init(data: &Path, admin: &str, hostnames: Vec<String>) {
    let (keys, db, audit) = open(data);
    if db.count_users().unwrap_or_else(|e| die(e)) > 0 {
        die("already initialised (users exist)");
    }
    let tls = data.join("tls");
    std::fs::create_dir_all(&tls).unwrap_or_else(|e| die(e));
    restrict(&tls);
    let cert_path = tls.join("cert.pem");
    if !cert_path.exists() {
        let ck = rcgen::generate_simple_self_signed(hostnames.clone()).unwrap_or_else(|e| die(e));
        std::fs::write(&cert_path, ck.cert.pem()).unwrap_or_else(|e| die(e));
        cjs_transport::keys::write_secret_file(&tls.join("key.pem"), ck.key_pair.serialize_pem().as_bytes())
            .unwrap_or_else(|e| die(e));
    }
    let nu = accounts::create_user(
        admin,
        vec![cjs_authz::Role::Sysadmin, cjs_authz::Role::Secadmin],
        None,
    )
    .unwrap_or_else(|e| die(e));
    audit
        .append(
            cjs_audit::Event::new(
                "admin.init",
                "system:cli",
                &nu.user.id,
                cjs_audit::Outcome::Success,
            )
            .highlight(true)
            .data(serde_json::json!({"admin": admin})),
        )
        .unwrap_or_else(|e| die(e));
    db.insert_user(&nu.user).unwrap_or_else(|e| die(e));
    println!("ClawdJumpServer initialised in {}", data.display());
    println!();
    println!("administrator:  {admin}  (roles: sysadmin, secadmin)");
    println!("password:       {}", nu.password);
    println!("TOTP secret:    {}", nu.totp_secret);
    println!(
        "TOTP URL:       {}",
        accounts::otpauth_url(&nu.totp_secret, admin)
    );
    println!();
    println!("server key:     {}", hex::encode(keys.noise.public));
    println!(
        "TLS cert:       {} (self-signed for {})",
        cert_path.display(),
        hostnames.join(", ")
    );
    println!();
    println!("Next: create an auditor and a second secadmin (two-person rule), e.g. with cjsctl.");
}

fn load_tls(cert: &Path, key: &Path) -> Arc<rustls::ServerConfig> {
    use rustls::pki_types::pem::PemObject;
    let certs = cjs_transport::tls::load_pem_certs(cert).unwrap_or_else(|e| die(e));
    let key = rustls::pki_types::PrivateKeyDer::from_pem_file(key)
        .unwrap_or_else(|e| die(format!("{}: {e}", key.display())));
    let mut cfg =
        rustls::ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_safe_default_protocol_versions()
            .unwrap_or_else(|e| die(e))
            .with_no_client_auth()
            .with_single_cert(certs, key)
            .unwrap_or_else(|e| die(e));
    cfg.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    Arc::new(cfg)
}

async fn run(
    data: &Path,
    listen: SocketAddr,
    tls_cert: Option<PathBuf>,
    tls_key: Option<PathBuf>,
    no_tls: bool,
    trust_forwarded_for: bool,
) {
    let (keys, db, audit) = open(data);
    if db.count_users().unwrap_or(0) == 0 {
        die("not initialised: run `cjs-server init` first");
    }
    let report = audit.verify(None).unwrap_or_else(|e| die(e));
    if !report.ok {
        die(format!(
            "audit log failed verification ({}); refusing to start",
            report.error.unwrap_or_default()
        ));
    }
    let fingerprint = keys.noise.fingerprint();
    let mut cfg = ServerConfig::new(data);
    cfg.trust_forwarded_for = trust_forwarded_for;
    cfg.secure_cookies = !no_tls || trust_forwarded_for;
    let srv = Server::start(cfg, keys, db, audit);
    let app = srv.router().into_make_service_with_connect_info::<SocketAddr>();
    tracing::info!(%listen, %fingerprint, tls = !no_tls, "ClawdJumpServer listening");
    let shared = srv.shared.clone();
    tokio::spawn(async move {
        #[cfg(unix)]
        {
            let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
                .unwrap_or_else(|e| die(e));
            tokio::select! {
                _ = tokio::signal::ctrl_c() => {}
                _ = term.recv() => {}
            }
        }
        #[cfg(not(unix))]
        let _ = tokio::signal::ctrl_c().await;
        let _ = shared.audit.checkpoint();
        tracing::info!("shutting down");
        std::process::exit(0);
    });
    if no_tls {
        let l = tokio::net::TcpListener::bind(listen)
            .await
            .unwrap_or_else(|e| die(e));
        axum::serve(
            axum::serve::ListenerExt::tap_io(l, |t| {
                let _ = t.set_nodelay(true);
            }),
            app,
        )
        .await
        .unwrap_or_else(|e| die(e));
    } else {
        let cert = tls_cert.unwrap_or_else(|| data.join("tls/cert.pem"));
        let key = tls_key.unwrap_or_else(|| data.join("tls/key.pem"));
        let tls = axum_server::tls_rustls::RustlsConfig::from_config(load_tls(&cert, &key));
        let acceptor = axum_server::tls_rustls::RustlsAcceptor::new(tls)
            .acceptor(axum_server::accept::NoDelayAcceptor::new());
        axum_server::bind(listen)
            .acceptor(acceptor)
            .serve(app)
            .await
            .unwrap_or_else(|e| die(e));
    }
}
