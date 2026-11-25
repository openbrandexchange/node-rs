//! node-rs: the Open Brand Exchange reference node.

mod app;
mod article;
mod catalog;
mod config;
mod db;
mod http;
mod ids;
mod imaging;
mod imports;
mod jobs;
mod migrations;
mod model;
mod problem;
mod schemas;
mod secure;
mod settings;
mod store;
mod uploads;

use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(
    name = "node-rs",
    version,
    about = "Open Brand Exchange reference node"
)]
struct Cli {
    #[command(subcommand)]
    cmd: Option<Cmd>,
}

#[derive(Subcommand)]
enum Cmd {
    /// Start the portal (the default).
    Serve,
    /// Write a consistent snapshot (database, secret key, settings) to DIR.
    Backup {
        #[arg(long)]
        to: PathBuf,
    },
    /// Import the canonical CSV format into this node's database.
    Import {
        #[arg(long)]
        csv: Option<PathBuf>,
        #[arg(long)]
        assets: Option<PathBuf>,
        #[arg(long)]
        images: Option<PathBuf>,
        #[arg(long)]
        package: Option<PathBuf>,
        #[arg(long, value_parser = ["upsert", "mirror"], default_value = "upsert")]
        mode: String,
        #[arg(long)]
        dry_run: bool,
    },
    /// Operator commands on the local database.
    Admin {
        #[command(subcommand)]
        cmd: AdminCmd,
    },
    /// Check the configuration without starting.
    CheckConfig,
    /// Exit 0 when the local node answers /healthz.
    Healthcheck,
    /// Print the version.
    Version,
}

#[derive(Subcommand)]
enum AdminCmd {
    /// Print a new secret for an API key (old access tokens stop working).
    RotateClientSecret {
        #[arg(long)]
        client_id: String,
    },
    /// Make every /changes cursor answer 410, as an incompatible spec
    /// upgrade does (conformance P-FEED-7).
    SimulateSpecUpgrade,
    /// Conformance operator hook (obx-conformance --operator-hook): the
    /// action as argument, its JSON on stdin, a JSON object on stdout.
    OperatorHook { action: String },
    /// Create an automatic upload key with all ingest scopes and print it.
    CreateIngestToken {
        #[arg(long)]
        name: String,
    },
}

async fn admin_cmd(cmd: AdminCmd) -> ExitCode {
    let cfg = match load_config() {
        Ok(c) => c,
        Err(e) => return e,
    };
    let database = match db::Db::open(&cfg.sqlite_path()) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("node-rs: {e}");
            return ExitCode::FAILURE;
        }
    };
    let cmd = match cmd {
        AdminCmd::OperatorHook { action } => {
            let mut input = String::new();
            let _ = std::io::Read::read_to_string(&mut std::io::stdin(), &mut input);
            let v: serde_json::Value = serde_json::from_str(&input).unwrap_or_default();
            match action.as_str() {
                "simulate_spec_upgrade" => AdminCmd::SimulateSpecUpgrade,
                "rotate_client_secret" => AdminCmd::RotateClientSecret {
                    client_id: v["params"]["client_id"].as_str().unwrap_or("").to_string(),
                },
                other => {
                    eprintln!(
                        "node-rs admin operator-hook: {other} is done through the Admin and Ingest APIs"
                    );
                    return ExitCode::FAILURE;
                }
            }
        }
        c => c,
    };
    let out =
        match cmd {
            AdminCmd::OperatorHook { .. } => unreachable!(),
            AdminCmd::SimulateSpecUpgrade => {
                database
                    .write(|tx| {
                        http::feed::simulate_spec_upgrade(tx)?;
                        Ok(serde_json::json!({"simulated": "true"}))
                    })
                    .await
            }
            AdminCmd::RotateClientSecret { client_id } => database
                .write(move |tx| {
                    let c = http::protocol::load_client(tx, "client_id = ?", &client_id)?
                        .filter(|c| c.status == "active")
                        .ok_or_else(|| {
                            problem::Problem::new(
                                "not_found",
                                format!("no active API key with client_id {client_id}"),
                            )
                        })?;
                    Ok(serde_json::json!({"client_secret": http::admin::rotate_secret(tx, &c.id)?}))
                })
                .await,
            AdminCmd::CreateIngestToken { name } => {
                database
                    .write(move |tx| {
                        let scopes = vec![
                            "ingest:read".into(),
                            "ingest:write".into(),
                            "ingest:delete".into(),
                        ];
                        let (_, secret) =
                            http::admin::create_ingest_token(tx, &name, scopes, None, None)?;
                        Ok(serde_json::json!({"secret": secret}))
                    })
                    .await
            }
        };
    match out {
        Ok(v) => {
            println!("{v}");
            ExitCode::SUCCESS
        }
        Err(p) => {
            eprintln!("node-rs admin: {p}");
            ExitCode::FAILURE
        }
    }
}

fn init_logs(cfg: Option<&config::Config>) {
    let level = cfg
        .map(|c| c.log_level.clone())
        .unwrap_or_else(|| "info".into());
    let filter = tracing_subscriber::EnvFilter::new(format!("node_rs={level},warn"));
    let b = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr);
    if cfg.is_some_and(|c| c.log_format == "json") {
        b.json().init();
    } else {
        b.init();
    }
}

fn load_config() -> Result<config::Config, ExitCode> {
    config::Config::load().map_err(|problems| {
        eprintln!("node-rs: the configuration has problems:");
        for p in problems {
            eprintln!("  - {p}");
        }
        ExitCode::from(2)
    })
}

#[tokio::main]
async fn main() -> ExitCode {
    let cli = Cli::parse();
    match cli.cmd.unwrap_or(Cmd::Serve) {
        Cmd::Version => {
            println!("node-rs {} (OBX {})", app::VERSION, app::SPEC_VERSION);
            ExitCode::SUCCESS
        }
        Cmd::Admin { cmd } => admin_cmd(cmd).await,
        Cmd::CheckConfig => match load_config() {
            Ok(c) => {
                println!(
                    "configuration OK: {} (data in {})",
                    c.public_url,
                    c.data_dir.display()
                );
                ExitCode::SUCCESS
            }
            Err(e) => e,
        },
        Cmd::Healthcheck => {
            let port = std::env::var("PORT").unwrap_or_else(|_| "8080".into());
            match tokio::net::TcpStream::connect(format!("127.0.0.1:{port}")).await {
                Ok(_) => ExitCode::SUCCESS,
                Err(_) => ExitCode::FAILURE,
            }
        }
        Cmd::Backup { to } => {
            let cfg = match load_config() {
                Ok(c) => c,
                Err(e) => return e,
            };
            init_logs(Some(&cfg));
            match backup(&cfg, &to) {
                Ok(()) => {
                    println!("backup written to {}", to.display());
                    ExitCode::SUCCESS
                }
                Err(e) => {
                    eprintln!("node-rs backup: {e}");
                    ExitCode::FAILURE
                }
            }
        }
        Cmd::Import {
            csv,
            assets,
            images,
            package,
            mode,
            dry_run,
        } => {
            let cfg = match load_config() {
                Ok(c) => c,
                Err(e) => return e,
            };
            init_logs(Some(&cfg));
            let a = match app::App::new(cfg).await {
                Ok(a) => a,
                Err(e) => {
                    eprintln!("node-rs: {e}");
                    return ExitCode::FAILURE;
                }
            };
            match imports::run_import_cli(
                &a,
                csv,
                assets,
                images,
                package,
                mode == "mirror",
                dry_run,
            )
            .await
            {
                Ok(run) => {
                    println!("{}", serde_json::to_string_pretty(&run).unwrap_or_default());
                    ExitCode::SUCCESS
                }
                Err(p) => {
                    eprintln!("node-rs import: {p}");
                    ExitCode::FAILURE
                }
            }
        }
        Cmd::Serve => {
            let cfg = match load_config() {
                Ok(c) => c,
                Err(e) => return e,
            };
            init_logs(Some(&cfg));
            let (port, bind) = (cfg.port, cfg.bind);
            let a = match app::App::new(cfg).await {
                Ok(a) => a,
                Err(e) => {
                    eprintln!("node-rs: {e}");
                    return ExitCode::FAILURE;
                }
            };
            jobs::start_workers(a.clone());
            let listener = match tokio::net::TcpListener::bind(SocketAddr::new(bind, port)).await {
                Ok(l) => l,
                Err(e) => {
                    eprintln!("node-rs: cannot listen on port {port}: {e}");
                    return ExitCode::FAILURE;
                }
            };
            tracing::info!(port, public_url = %a.cfg.public_url, "node-rs is listening");
            let app = http::router::router(a).into_make_service_with_connect_info::<SocketAddr>();
            let shutdown = async {
                let _ = tokio::signal::ctrl_c().await;
            };
            #[cfg(unix)]
            let shutdown = async {
                let mut term =
                    tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
                        .expect("signal");
                tokio::select! { _ = shutdown => {}, _ = term.recv() => {} }
            };
            if let Err(e) = axum::serve(listener, app)
                .with_graceful_shutdown(shutdown)
                .await
            {
                eprintln!("node-rs: {e}");
                return ExitCode::FAILURE;
            }
            ExitCode::SUCCESS
        }
    }
}

/// A consistent snapshot: the SQLite database through the online backup
/// API, plus the secret key. Blobs are content-addressed and immutable, so
/// copying the blob store (or bucket) after this command is consistent.
fn backup(cfg: &config::Config, to: &std::path::Path) -> Result<(), String> {
    std::fs::create_dir_all(to).map_err(|e| format!("{}: {e}", to.display()))?;
    let dest = to.join("obx.db");
    if dest.exists() {
        return Err(format!(
            "{} exists; back up into an empty directory",
            dest.display()
        ));
    }
    let db = db::Db::open(&cfg.sqlite_path())?;
    db.backup_to(&dest)?;
    let key = cfg.data_dir.join("secret.key");
    if key.exists() {
        std::fs::copy(&key, to.join("secret.key")).map_err(|e| e.to_string())?;
    }
    let manifest = serde_json::json!({
        "software": app::SOFTWARE, "version": app::VERSION, "created_at": db::now_str(),
        "schema_version": migrations::MIGRATIONS.len(), "blob_url": config::redact(&cfg.blob_url),
        "secret_key_from_env": !key.exists(),
    });
    std::fs::write(
        to.join("backup.json"),
        serde_json::to_vec_pretty(&manifest).unwrap(),
    )
    .map_err(|e| e.to_string())?;
    Ok(())
}
