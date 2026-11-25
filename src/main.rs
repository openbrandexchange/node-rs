//! node-rs: the Open Brand Exchange reference node.

#![forbid(unsafe_code)]

mod app;
mod article;
mod audit;
mod backup;
mod catalog;
mod config;
mod db;
mod export_proto;
mod exports;
mod http;
mod ids;
mod imaging;
mod imports;
mod jobs;
mod mail;
mod metrics;
mod migrations;
mod model;
mod ops;
mod pgcopy;
mod problem;
mod safeurl;
mod schemas;
mod secure;
mod settings;
mod sources;
mod stats;
mod store;
#[cfg(test)]
mod tests_exports_webhooks;
mod uploads;
mod usage;
mod usage_proto;
mod webhook_proto;
mod webhooks;

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
    /// Write a consistent snapshot (database, local images, secret key) to a new, empty DIR.
    Backup {
        #[arg(long)]
        to: PathBuf,
    },
    /// Put a backup made with `node-rs backup` or `node-go backup` in place
    /// (stop the node first).
    Restore {
        #[arg(long)]
        from: PathBuf,
        /// Replace an existing database.
        #[arg(long)]
        force: bool,
    },
    /// Copy a node-go PostgreSQL database into a new SQLite database in
    /// OBX_DATA_DIR, once (docs/migrating.md). Stop node-go first.
    ImportPostgres {
        /// postgres://user:password@host/db (default: OBX_DATABASE_URL).
        #[arg(long)]
        from: Option<String>,
        /// The new SQLite database (default: $OBX_DATA_DIR/obx.db).
        #[arg(long)]
        to: Option<PathBuf>,
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
    /// Print a one-time password reset link, or set the password from stdin.
    ResetPassword {
        #[arg(long)]
        email: String,
        /// Read the new password from standard input.
        #[arg(long)]
        password_stdin: bool,
    },
    /// Print the latest audit log entries.
    AuditLog {
        #[arg(long, default_value_t = 50)]
        limit: usize,
    },
    /// Print everything stored about an account (--email) or a retailer
    /// (--retailer) as JSON.
    PersonalData {
        #[arg(long, default_value = "")]
        email: String,
        #[arg(long, default_value = "")]
        retailer: String,
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
    let public_url = cfg.public_url.clone();
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
    let out = match cmd {
        AdminCmd::OperatorHook { .. } => unreachable!(),
        AdminCmd::SimulateSpecUpgrade => {
            database
                .write(|tx| {
                    http::feed::simulate_spec_upgrade(tx)?;
                    Ok(serde_json::json!({"simulated": "true"}))
                })
                .await
        }
        AdminCmd::RotateClientSecret { client_id } => {
            database
                .write(move |tx| {
                    let c = http::protocol::load_client(tx, "client_id = ?", &client_id)?
                        .filter(|c| c.status == "active")
                        .ok_or_else(|| {
                            problem::Problem::new(
                                "not_found",
                                format!("no active API key with client_id {client_id}"),
                            )
                        })?;
                    let secret = http::admin::rotate_secret(tx, &c.id)?;
                    audit::write(
                        tx,
                        &audit::cli_entry("api-clients.rotate", "api-client", &c.id),
                    )?;
                    Ok(serde_json::json!({"client_secret": secret}))
                })
                .await
        }
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
                    audit::write(
                        tx,
                        &audit::cli_entry("ingest-tokens.create", "ingest-token", &name),
                    )?;
                    Ok(serde_json::json!({"secret": secret}))
                })
                .await
        }
        AdminCmd::ResetPassword {
            email,
            password_stdin,
        } => {
            if password_stdin {
                let mut pw = String::new();
                let _ = std::io::Read::read_to_string(
                    &mut std::io::Read::take(std::io::stdin(), 1024),
                    &mut pw,
                );
                let pw = pw.trim_end_matches(['\r', '\n']).to_string();
                if let Some(reason) = secure::password_problem(&pw) {
                    eprintln!("node-rs admin: {reason}");
                    return ExitCode::FAILURE;
                }
                let hash = secure::hash_password(&pw);
                database
                        .write(move |tx| {
                            http::people::set_password(tx, &email, &hash)?;
                            audit::write(tx, &audit::cli_entry("password.set", "user", &email))?;
                            Ok(serde_json::json!({"message": "Password changed; all sessions of this account were ended."}))
                        })
                        .await
            } else {
                database
                        .write(move |tx| {
                            let u = http::admin::load_user(tx, "email = ?", &http::admin::norm_email(&email))?
                                .ok_or_else(|| problem::Problem::new("not_found", format!("No account with e-mail {email}.")))?;
                            let token = secure::random_string(32);
                            let exp = db::fmt_time(chrono::Utc::now() + chrono::Duration::hours(1));
                            tx.execute(
                                "UPDATE users SET reset_hash = ?, reset_expires_at = ? WHERE id = ?",
                                rusqlite::params![secure::hash_token(&token), exp, u.id],
                            )?;
                            audit::write(tx, &audit::cli_entry("password.reset-link", "user", &email))?;
                            Ok(serde_json::json!({"message": "Open this link within one hour to choose a new password (works once).",
                                "url": format!("{public_url}/reset-password/{token}")}))
                        })
                        .await
            }
        }
        AdminCmd::AuditLog { limit } => {
            let out = database.read_sync(|c| {
                Ok(audit::rows(
                    c,
                    &format!("ORDER BY at DESC, id DESC LIMIT {}", limit.min(10000)),
                    &[],
                )?)
            });
            match out {
                Ok(items) => {
                    for it in items {
                        let who = it["actor"]["email"]
                            .as_str()
                            .map(String::from)
                            .unwrap_or_else(|| {
                                it["actor"]["type"].as_str().unwrap_or("").to_string()
                            });
                        let tgt = it["target_id"]
                            .as_str()
                            .map(|t| format!(" {t}"))
                            .unwrap_or_default();
                        println!(
                            "{}  {:<28} {who}{tgt} ({})",
                            it["at"].as_str().unwrap_or(""),
                            it["action"].as_str().unwrap_or(""),
                            it["status"]
                        );
                    }
                    return ExitCode::SUCCESS;
                }
                Err(e) => Err(e),
            }
        }
        AdminCmd::PersonalData { email, retailer } => {
            if email.is_empty() == retailer.is_empty() {
                eprintln!("node-rs admin personal-data: pass either --email or --retailer");
                return ExitCode::from(2);
            }
            let out = database
                .write(move |tx| {
                    let v = http::people::personal_data_cli(tx, &email, &retailer)?;
                    let (tt, id) = if retailer.is_empty() {
                        ("user", email)
                    } else {
                        ("retailer", retailer)
                    };
                    audit::write(tx, &audit::cli_entry("personal-data.export", tt, &id))?;
                    Ok(v)
                })
                .await;
            match out {
                Ok(v) => {
                    println!("{}", serde_json::to_string_pretty(&v).unwrap_or_default());
                    return ExitCode::SUCCESS;
                }
                Err(e) => Err(e),
            }
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
        Cmd::ImportPostgres { from, to } => {
            init_logs(None);
            let env = |k: &str| std::env::var(k).ok().filter(|v| !v.trim().is_empty());
            let Some(from) = from.or_else(|| {
                env("OBX_DATABASE_URL")
                    .or_else(|| env("DATABASE_URL"))
                    .filter(|u| u.starts_with("postgres://") || u.starts_with("postgresql://"))
            }) else {
                eprintln!(
                    "node-rs import-postgres: give --from postgres://... (or OBX_DATABASE_URL)"
                );
                return ExitCode::FAILURE;
            };
            let to = to.unwrap_or_else(|| {
                PathBuf::from(env("OBX_DATA_DIR").unwrap_or_else(|| "./data".into())).join("obx.db")
            });
            match pgcopy::import_postgres(&from, &to).await {
                Ok(r) => {
                    let rows: u64 = r.tables.values().sum();
                    println!(
                        "Copied {rows} rows in {} tables (node-go schema version {}) to {}.",
                        r.tables.len(),
                        r.version,
                        to.display()
                    );
                    for (t, n) in &r.tables {
                        println!("  {t}: {n}");
                    }
                    println!(
                        "Next: unset OBX_DATABASE_URL, keep OBX_DATA_DIR, OBX_BLOB_URL and the secret key, then run: node-rs serve"
                    );
                    ExitCode::SUCCESS
                }
                Err(e) => {
                    eprintln!("node-rs import-postgres: {e}");
                    ExitCode::FAILURE
                }
            }
        }
        Cmd::Backup { to } => {
            let cfg = match load_config() {
                Ok(c) => c,
                Err(e) => return e,
            };
            init_logs(Some(&cfg));
            match backup::backup(&cfg, &to) {
                Ok(m) => {
                    println!(
                        "backup written to {} (database, {}, secret key: {})",
                        to.display(),
                        m.files,
                        m.secret_key
                    );
                    ExitCode::SUCCESS
                }
                Err(e) => {
                    eprintln!("node-rs backup: {e}");
                    ExitCode::FAILURE
                }
            }
        }
        Cmd::Restore { from, force } => {
            let cfg = match load_config() {
                Ok(c) => c,
                Err(e) => return e,
            };
            match backup::restore(&cfg, &from, force) {
                Ok(m) => {
                    println!(
                        "Restored the backup of {} (node {}). Start the node with: node-rs serve",
                        m.created_at, m.node_id
                    );
                    ExitCode::SUCCESS
                }
                Err(e) => {
                    eprintln!("node-rs restore: {e}");
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
            sources::start_scheduler(a.clone());
            ops::start(a.clone());
            webhooks::start(a.clone());
            let listener = match tokio::net::TcpListener::bind(SocketAddr::new(bind, port)).await {
                Ok(l) => l,
                Err(e) => {
                    eprintln!("node-rs: cannot listen on port {port}: {e}");
                    return ExitCode::FAILURE;
                }
            };
            tracing::info!(port, public_url = %a.cfg.public_url, "node-rs is listening");
            let drain = a.clone();
            let app = http::router::router(a).into_make_service_with_connect_info::<SocketAddr>();
            let signal = async {
                let _ = tokio::signal::ctrl_c().await;
            };
            #[cfg(unix)]
            let signal = async {
                let mut term =
                    tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
                        .expect("signal");
                tokio::select! { _ = signal => {}, _ = term.recv() => {} }
            };
            // On a signal /readyz answers 503 at once; the server keeps
            // serving OBX_SHUTDOWN_DELAY seconds so load balancers move away,
            // then stops accepting and lets running requests finish.
            let shutdown = async move {
                signal.await;
                drain
                    .draining
                    .store(true, std::sync::atomic::Ordering::SeqCst);
                let d = drain.cfg.shutdown_delay_secs;
                tracing::info!(delay_secs = d, "shutting down");
                tokio::time::sleep(std::time::Duration::from_secs(d)).await;
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
