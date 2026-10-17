//! `cjs-device`: enroll a machine and serve authorized agents.
use std::path::PathBuf;

use cjs_device::{default_dir, service, DeviceOptions, VERSION};
use cjs_proto::Role;
use cjs_transport::TransportMode;
use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "cjs-device", version, about = "ClawdJumpServer device daemon")]
struct Cli {
    /// Configuration directory (identity key and profile).
    #[arg(long, global = true, env = "CJS_DEVICE_DIR")]
    config: Option<PathBuf>,
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Register this machine with a one-time enrollment token.
    Enroll {
        /// Server URL, e.g. https://jump.example.com:8443
        #[arg(long)]
        server: String,
        /// Token from `cjsctl token create --kind device` (cjs1....).
        #[arg(long, env = "CJS_ENROLL_TOKEN")]
        token: String,
        #[arg(long, default_value = "auto")]
        transport: TransportMode,
        /// Extra CA certificate (PEM) for the server's TLS certificate.
        #[arg(long)]
        ca: Option<PathBuf>,
    },
    /// Connect to the server and serve requests (runs until stopped).
    Run,
    /// Check whether the OS sandbox can be enforced here.
    Probe,
    /// Print (or install) a service definition that starts the daemon at boot.
    InstallService {
        /// Write the definition and enable it instead of printing it.
        #[arg(long)]
        apply: bool,
        /// User the systemd service runs as.
        #[arg(long, default_value = "cjs")]
        user: String,
    },
}

fn main() {
    // Sandbox helper mode must be handled before anything else.
    let args: Vec<String> = std::env::args().collect();
    if args.get(1).map(String::as_str) == Some(cjs_sandbox::HELPER_ARG) {
        cjs_sandbox::helper_main(&args[2..]);
    }
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .with_writer(std::io::stderr)
        .init();
    let cli = Cli::parse();
    let dir = cli.config.unwrap_or_else(default_dir);
    let rt = tokio::runtime::Runtime::new().expect("tokio runtime");
    let code = rt.block_on(async move {
        match cli.cmd {
            Cmd::Enroll {
                server,
                token,
                transport,
                ca,
            } => match cjs_transport::profile::enroll(
                &dir,
                Role::Device,
                &server,
                &token,
                transport,
                ca,
                VERSION,
            )
            .await
            {
                Ok(p) => {
                    println!(
                        "enrolled as device {} ({}); config in {}",
                        p.name,
                        p.id,
                        dir.display()
                    );
                    0
                }
                Err(e) => {
                    eprintln!("error: {e}");
                    e.code.exit_code()
                }
            },
            Cmd::Run => {
                let helper = std::env::current_exe().unwrap_or_else(|_| PathBuf::from("cjs-device"));
                match cjs_device::run(DeviceOptions { dir, helper }).await {
                    Ok(()) => 0,
                    Err(e) => {
                        eprintln!("error: {e}");
                        e.code.exit_code()
                    }
                }
            }
            Cmd::Probe => match cjs_sandbox::probe() {
                Ok(s) => {
                    println!("sandbox: {s}");
                    0
                }
                Err(e) => {
                    println!("sandbox unavailable: {e}");
                    1
                }
            },
            Cmd::InstallService { apply, user } => install_service(&dir, apply, &user),
        }
    });
    std::process::exit(code);
}

fn install_service(dir: &std::path::Path, apply: bool, user: &str) -> i32 {
    let exe = std::env::current_exe().unwrap_or_else(|_| PathBuf::from("cjs-device"));
    let run = |cmd: &str, args: &[String]| -> i32 {
        match std::process::Command::new(cmd).args(args).status() {
            Ok(s) if s.success() => 0,
            Ok(s) => s.code().unwrap_or(1),
            Err(e) => {
                eprintln!("error: {cmd}: {e}");
                1
            }
        }
    };
    if cfg!(target_os = "linux") {
        let unit = service::systemd_unit(&exe, dir, user);
        if !apply {
            print!("{unit}");
            return 0;
        }
        let path = "/etc/systemd/system/cjs-device.service";
        if let Err(e) = std::fs::write(path, unit) {
            eprintln!("error: {path}: {e}");
            return 1;
        }
        let r = run("systemctl", &["daemon-reload".into()]);
        if r != 0 {
            return r;
        }
        run(
            "systemctl",
            &["enable".into(), "--now".into(), "cjs-device.service".into()],
        )
    } else if cfg!(target_os = "macos") {
        let plist = service::launchd_plist(&exe, dir);
        if !apply {
            print!("{plist}");
            return 0;
        }
        let Some(home) = dirs::home_dir() else {
            eprintln!("error: no home directory");
            return 1;
        };
        let path = home.join("Library/LaunchAgents/com.clawdjumpserver.device.plist");
        if let Err(e) = std::fs::write(&path, plist) {
            eprintln!("error: {}: {e}", path.display());
            return 1;
        }
        run(
            "launchctl",
            &["load".into(), "-w".into(), path.to_string_lossy().into_owned()],
        )
    } else {
        let args = service::windows_schtasks_args(&exe, dir);
        if !apply {
            println!("schtasks {}", args.join(" "));
            return 0;
        }
        run("schtasks", &args)
    }
}
