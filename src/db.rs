//! SQLite storage. One serialised writer connection (every catalog write is
//! one immediate transaction, like node-go) and a small pool of readers in
//! WAL mode. Database work runs on the blocking thread pool.

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use rusqlite::{Connection, OpenFlags, OptionalExtension, Transaction, params};

use crate::migrations::MIGRATIONS;
use crate::problem::{Problem, Result};

/// The timestamp format of every stored time (UTC, microseconds).
pub const TIME_FORMAT: &str = "%Y-%m-%dT%H:%M:%S%.6fZ";

pub fn fmt_time(t: chrono::DateTime<chrono::Utc>) -> String {
    t.format(TIME_FORMAT).to_string()
}

pub fn now_str() -> String {
    fmt_time(chrono::Utc::now())
}

pub fn parse_time(s: &str) -> Option<chrono::DateTime<chrono::Utc>> {
    chrono::DateTime::parse_from_rfc3339(s)
        .ok()
        .map(|t| t.with_timezone(&chrono::Utc))
}

/// `(?,?,?)` with n placeholders.
pub fn in_list(n: usize) -> String {
    if n == 0 {
        return "(NULL)".into();
    }
    format!("({})", vec!["?"; n].join(","))
}

#[derive(Clone)]
pub struct Db {
    inner: Arc<Inner>,
}

struct Inner {
    path: PathBuf,
    writer: Mutex<Connection>,
    readers: Mutex<Vec<Connection>>,
}

fn open_conn(path: &Path) -> rusqlite::Result<Connection> {
    let c = Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_WRITE
            | OpenFlags::SQLITE_OPEN_CREATE
            | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )?;
    c.busy_timeout(std::time::Duration::from_secs(15))?;
    c.pragma_update(None, "journal_mode", "WAL")?;
    c.pragma_update(None, "synchronous", "NORMAL")?;
    c.pragma_update(None, "foreign_keys", "ON")?;
    Ok(c)
}

#[derive(Debug)]
pub struct SchemaTooNew {
    pub database: usize,
    pub binary: usize,
}

impl std::fmt::Display for SchemaTooNew {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "the database has schema version {} but this node-rs knows only up to {}: it was upgraded by a newer release. \
             Run that release (or newer) again; to go back, restore the backup made before the upgrade (docs/backup.md)",
            self.database, self.binary
        )
    }
}

impl Db {
    pub fn open(path: &Path) -> std::result::Result<Db, String> {
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir).map_err(|e| format!("create {}: {e}", dir.display()))?;
        }
        let mut w = open_conn(path).map_err(|e| format!("open {}: {e}", path.display()))?;
        migrate(&mut w).map_err(|e| e.to_string())?;
        Ok(Db {
            inner: Arc::new(Inner {
                path: path.into(),
                writer: Mutex::new(w),
                readers: Mutex::new(Vec::new()),
            }),
        })
    }

    pub fn path(&self) -> &Path {
        &self.inner.path
    }

    /// Runs f with a read connection on the blocking pool.
    pub async fn read<T, F>(&self, f: F) -> Result<T>
    where
        T: Send + 'static,
        F: FnOnce(&Connection) -> Result<T> + Send + 'static,
    {
        let db = self.clone();
        tokio::task::spawn_blocking(move || db.read_sync(f))
            .await
            .map_err(Problem::internal)?
    }

    pub fn read_sync<T>(&self, f: impl FnOnce(&Connection) -> Result<T>) -> Result<T> {
        let conn = self.inner.readers.lock().unwrap().pop();
        let conn = match conn {
            Some(c) => c,
            None => open_conn(&self.inner.path)?,
        };
        let out = f(&conn);
        let mut pool = self.inner.readers.lock().unwrap();
        if pool.len() < 8 {
            pool.push(conn);
        }
        out
    }

    /// Runs f in one immediate write transaction (serialised); commits when f
    /// returns Ok.
    pub async fn write<T, F>(&self, f: F) -> Result<T>
    where
        T: Send + 'static,
        F: FnOnce(&Transaction) -> Result<T> + Send + 'static,
    {
        let db = self.clone();
        tokio::task::spawn_blocking(move || db.write_sync(f))
            .await
            .map_err(Problem::internal)?
    }

    pub fn write_sync<T>(&self, f: impl FnOnce(&Transaction) -> Result<T>) -> Result<T> {
        let mut c = self.inner.writer.lock().unwrap_or_else(|p| p.into_inner());
        let tx = c.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        let out = f(&tx)?;
        tx.commit()?;
        Ok(out)
    }

    /// A consistent online copy of the database (SQLite backup API).
    pub fn backup_to(&self, dest: &Path) -> std::result::Result<(), String> {
        let c = open_conn(&self.inner.path).map_err(|e| e.to_string())?;
        let mut d = Connection::open(dest).map_err(|e| e.to_string())?;
        let b = rusqlite::backup::Backup::new(&c, &mut d).map_err(|e| e.to_string())?;
        b.run_to_completion(256, std::time::Duration::from_millis(5), None)
            .map_err(|e| e.to_string())
    }
}

fn migrate(c: &mut Connection) -> std::result::Result<(), Box<dyn std::error::Error>> {
    c.execute_batch("CREATE TABLE IF NOT EXISTS schema_migrations (version INTEGER PRIMARY KEY, applied_at TEXT NOT NULL)")?;
    let current: usize = c.query_row(
        "SELECT COALESCE(MAX(version),0) FROM schema_migrations",
        [],
        |r| r.get::<_, i64>(0),
    )? as usize;
    if current > MIGRATIONS.len() {
        return Err(Box::new(std::io::Error::other(
            SchemaTooNew {
                database: current,
                binary: MIGRATIONS.len(),
            }
            .to_string(),
        )));
    }
    for (i, ddl) in MIGRATIONS.iter().enumerate().skip(current) {
        let ddl = ddl.replace("{{SERIAL}}", "INTEGER PRIMARY KEY AUTOINCREMENT");
        let tx = c.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        tx.execute_batch(&ddl)
            .map_err(|e| format!("migration {}: {e}", i + 1))?;
        tx.execute(
            "INSERT INTO schema_migrations (version, applied_at) VALUES (?, ?)",
            params![(i + 1) as i64, now_str()],
        )?;
        tx.commit()?;
    }
    Ok(())
}

pub fn get_meta(c: &Connection, key: &str) -> Result<Option<String>> {
    Ok(
        c.query_row("SELECT value FROM meta WHERE key = ?", [key], |r| r.get(0))
            .optional()?,
    )
}

pub fn set_meta(c: &Connection, key: &str, value: &str) -> Result<()> {
    c.execute(
        "INSERT INTO meta (key, value) VALUES (?, ?) ON CONFLICT (key) DO UPDATE SET value = excluded.value",
        [key, value],
    )?;
    Ok(())
}

pub fn is_unique_violation(e: &rusqlite::Error) -> bool {
    e.to_string().contains("UNIQUE constraint failed")
}
