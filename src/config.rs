//! Configuration from `OBX_*` environment variables. The names and defaults
//! are the ones node-go used, so an existing installation keeps its settings.

use std::path::PathBuf;

use base64::Engine;

#[derive(Clone, Debug)]
#[allow(dead_code)] // mail and job retention settings are read by roadmap features
pub struct Config {
    pub public_url: String,
    pub port: u16,
    /// Address to listen on (`OBX_BIND`, default all interfaces).
    pub bind: std::net::IpAddr,
    pub data_dir: PathBuf,
    pub database_url: String,
    pub blob_url: String,
    pub s3_access_key_id: Option<String>,
    pub s3_secret_access_key: Option<String>,
    pub secret_key: Vec<u8>,
    pub setup_code: Option<String>,
    pub allow_private_urls: bool,
    pub trust_proxy: bool,
    pub workers: usize,
    pub change_retention_days: i64,
    pub job_retention_days: i64,
    pub webhook_log_retention_days: i64,
    pub mail_from: String,
    pub mail_log_bodies: bool,
    pub log_format: String,
    pub log_level: String,
    /// Conformance testing only: lower the per-minute API limit.
    pub test_rate_limit: Option<u32>,
}

/// Every variable node-rs reads; others with the `OBX_` prefix are reported
/// as a probable typo.
const KNOWN: &[&str] = &[
    "OBX_PUBLIC_URL",
    "OBX_DOMAIN",
    "OBX_BIND",
    "OBX_DATA_DIR",
    "OBX_DATABASE_URL",
    "OBX_BLOB_URL",
    "OBX_S3_ACCESS_KEY_ID",
    "OBX_S3_SECRET_ACCESS_KEY",
    "OBX_SECRET_KEY",
    "OBX_SETUP_CODE",
    "OBX_ALLOW_PRIVATE_URLS",
    "OBX_WEBHOOK_LOG_RETENTION_DAYS",
    "OBX_TRUST_PROXY",
    "OBX_WORKERS",
    "OBX_CHANGE_RETENTION_DAYS",
    "OBX_JOB_RETENTION_DAYS",
    "OBX_WEBHOOK_LOG_RETENTION_DAYS",
    "OBX_MAIL_FROM",
    "OBX_SMTP_URL",
    "OBX_MAIL_LOG_BODIES",
    "OBX_LOG_FORMAT",
    "OBX_LOG_LEVEL",
    "OBX_ACCESS_LOG",
    "OBX_METRICS",
    "OBX_METRICS_TOKEN",
    "OBX_SHUTDOWN_DELAY",
    "OBX_TEST_RATE_LIMIT",
    "OBX_CUSTOM_DOMAIN_HELP",
    "OBX_TLS",
    "OBX_ACME_EMAIL",
    "OBX_HTTP_PORT",
    "OBX_HTTPS_PORT",
    "OBX_ACME_DIRECTORY",
    "OBX_VERSION",
];

fn env(k: &str) -> Option<String> {
    std::env::var(k)
        .ok()
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
}

fn env_bool(problems: &mut Vec<String>, k: &str, def: bool) -> bool {
    match env(k).as_deref() {
        None => def,
        Some("1" | "true" | "TRUE" | "True" | "yes") => true,
        Some("0" | "false" | "FALSE" | "False" | "no") => false,
        Some(v) => {
            problems.push(format!("{k} must be true or false, got {v:?}"));
            def
        }
    }
}

fn env_int(problems: &mut Vec<String>, k: &str, def: i64, min: i64, max: i64) -> i64 {
    match env(k) {
        None => def,
        Some(v) => match v.parse::<i64>() {
            Ok(n) if (min..=max).contains(&n) => n,
            _ => {
                problems.push(format!(
                    "{k} must be a whole number from {min} to {max}, got {v:?}"
                ));
                def
            }
        },
    }
}

impl Config {
    /// Loads and checks every variable; all problems are reported at once.
    pub fn load() -> Result<Config, Vec<String>> {
        let mut p = Vec::new();
        let port = env_int(&mut p, "PORT", 8080, 1, 65535) as u16;
        let bind = match env("OBX_BIND") {
            None => std::net::IpAddr::from([0, 0, 0, 0]),
            Some(b) => b.parse().unwrap_or_else(|_| {
                p.push(format!(
                    "OBX_BIND must be an IP address such as 127.0.0.1, got {b:?}"
                ));
                std::net::IpAddr::from([0, 0, 0, 0])
            }),
        };
        let def_url = match env("OBX_DOMAIN") {
            Some(d) => format!("https://{d}"),
            None => format!("http://localhost:{port}"),
        };
        let public_url = env("OBX_PUBLIC_URL")
            .unwrap_or(def_url)
            .trim_end_matches('/')
            .to_string();
        match url::Url::parse(&public_url) {
            Ok(u) if u.scheme() == "http" || u.scheme() == "https" => {
                if u.path() != "/" && !u.path().is_empty() {
                    p.push(format!("OBX_PUBLIC_URL must be the bare address without a path, got {public_url:?}"));
                }
            }
            _ => p.push(format!(
                "OBX_PUBLIC_URL must be an absolute http(s) address such as https://portal.yourbrand.com, got {public_url:?}"
            )),
        }
        let data_dir = PathBuf::from(env("OBX_DATA_DIR").unwrap_or_else(|| "./data".into()));
        let database_url = env("OBX_DATABASE_URL")
            .or_else(|| env("DATABASE_URL"))
            .unwrap_or_else(|| format!("sqlite:{}", data_dir.join("obx.db").display()));
        if !database_url.starts_with("sqlite:") {
            p.push(format!(
                "OBX_DATABASE_URL: only sqlite:/path/obx.db is supported by this release (PostgreSQL is on the roadmap), got {}",
                redact(&database_url)
            ));
        }
        let blob_url = env("OBX_BLOB_URL")
            .unwrap_or_else(|| format!("file://{}", data_dir.join("blobs").display()));
        if !(blob_url.starts_with("file://")
            || blob_url.starts_with("s3://")
            || blob_url.starts_with("r2://"))
        {
            p.push(format!(
                "OBX_BLOB_URL must start with file://, s3:// or r2://, got {}",
                redact(&blob_url)
            ));
        }
        let workers = env_int(&mut p, "OBX_WORKERS", 2, 1, 64) as usize;
        let change_retention_days = env_int(&mut p, "OBX_CHANGE_RETENTION_DAYS", 400, 90, 36500);
        let job_retention_days = env_int(&mut p, "OBX_JOB_RETENTION_DAYS", 30, 8, 36500);
        let webhook_log_retention_days =
            env_int(&mut p, "OBX_WEBHOOK_LOG_RETENTION_DAYS", 8, 1, 365);
        let allow_private_urls = env_bool(&mut p, "OBX_ALLOW_PRIVATE_URLS", false);
        let trust_proxy = env_bool(&mut p, "OBX_TRUST_PROXY", false);
        let mail_log_bodies = env_bool(&mut p, "OBX_MAIL_LOG_BODIES", false);
        let host = url::Url::parse(&public_url)
            .ok()
            .and_then(|u| u.host_str().map(String::from))
            .unwrap_or_default();
        let mail_from = env("OBX_MAIL_FROM").unwrap_or_else(|| format!("no-reply@{host}"));
        let test_rate_limit = env("OBX_TEST_RATE_LIMIT").and_then(|v| v.parse().ok());
        for (k, _) in std::env::vars() {
            if k.starts_with("OBX_") && !KNOWN.contains(&k.as_str()) {
                p.push(format!("{k} is not a node-rs setting (a typo?)"));
            }
        }
        let secret_key = match load_secret(&data_dir) {
            Ok(k) => k,
            Err(e) => {
                p.push(e);
                Vec::new()
            }
        };
        if !p.is_empty() {
            return Err(p);
        }
        Ok(Config {
            public_url,
            port,
            bind,
            data_dir,
            database_url,
            blob_url,
            s3_access_key_id: env("OBX_S3_ACCESS_KEY_ID").or_else(|| env("AWS_ACCESS_KEY_ID")),
            s3_secret_access_key: env("OBX_S3_SECRET_ACCESS_KEY")
                .or_else(|| env("AWS_SECRET_ACCESS_KEY")),
            secret_key,
            setup_code: env("OBX_SETUP_CODE"),
            allow_private_urls,
            trust_proxy,
            workers,
            change_retention_days,
            job_retention_days,
            webhook_log_retention_days,
            mail_from,
            mail_log_bodies,
            log_format: env("OBX_LOG_FORMAT").unwrap_or_else(|| "text".into()),
            log_level: env("OBX_LOG_LEVEL").unwrap_or_else(|| "info".into()),
            test_rate_limit,
        })
    }

    pub fn secure(&self) -> bool {
        self.public_url.starts_with("https://")
    }

    pub fn sqlite_path(&self) -> PathBuf {
        PathBuf::from(
            self.database_url
                .trim_start_matches("sqlite:")
                .trim_start_matches("//"),
        )
    }
}

/// `OBX_SECRET_KEY`, else `$OBX_DATA_DIR/secret.key` (generated once, the
/// same file node-go wrote).
fn load_secret(data_dir: &std::path::Path) -> Result<Vec<u8>, String> {
    if let Some(s) = env("OBX_SECRET_KEY") {
        if s.len() < 32 {
            return Err(
                "OBX_SECRET_KEY must be at least 32 characters (openssl rand -base64 48)".into(),
            );
        }
        return Ok(s.into_bytes());
    }
    let path = data_dir.join("secret.key");
    if let Ok(b) = std::fs::read_to_string(&path) {
        let s = b.trim().to_string();
        if s.len() >= 32 {
            return Ok(s.into_bytes());
        }
        return Err(format!(
            "{} holds a key shorter than 32 characters; restore it from your backup or set OBX_SECRET_KEY",
            path.display()
        ));
    }
    std::fs::create_dir_all(data_dir)
        .map_err(|e| format!("OBX_DATA_DIR {} cannot be created: {e}", data_dir.display()))?;
    let raw: [u8; 48] = rand::random();
    let s = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(raw);
    write_private(&path, format!("{s}\n").as_bytes()).map_err(|e| {
        format!(
            "OBX_SECRET_KEY is not set and {} cannot be written: {e}",
            path.display()
        )
    })?;
    tracing::warn!(path = %path.display(), "OBX_SECRET_KEY is not set; generated one in the data directory. Back it up.");
    Ok(s.into_bytes())
}

fn write_private(path: &std::path::Path, data: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    let mut o = std::fs::OpenOptions::new();
    o.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        o.mode(0o600);
    }
    o.open(path)?.write_all(data)
}

/// Hides credentials in a URL for messages.
pub fn redact(raw: &str) -> String {
    match url::Url::parse(raw) {
        Ok(mut u) if u.password().is_some() => {
            let _ = u.set_password(Some("xxx"));
            u.to_string()
        }
        _ => raw.to_string(),
    }
}
