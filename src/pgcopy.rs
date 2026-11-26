//! `node-rs import-postgres`: a one-time copy of a node-go PostgreSQL
//! database into a new node-rs SQLite database (docs/migrating.md).
//!
//! node-go used the same schema on both databases (TEXT, INTEGER and
//! BIGINT columns; `{{SERIAL}}` is BIGSERIAL there and AUTOINCREMENT here),
//! so the copy is table by table, column by column:
//!
//! 1. the SQLite schema is built at the source's migration version;
//! 2. every table is replaced by the source's rows in one transaction
//!    (foreign keys checked at the end), sequences included, so
//!    change-feed cursors continue;
//! 3. the remaining migrations run, as a node-go upgrade would have;
//! 4. row counts are compared and a foreign-key check runs.
//!
//! The target must not exist; nothing is written to PostgreSQL. Blobs stay
//! where they are (the same OBX_BLOB_URL or data folder) and the secret key
//! is the node-go one (secret.key in the data folder or OBX_SECRET_KEY), so
//! tokens, cursors and signed URLs keep working.

use std::collections::BTreeMap;
use std::path::Path;

use futures::{StreamExt, pin_mut};
use rusqlite::types::Value as SqlValue;
use tokio_postgres::types::Type;

use crate::migrations::MIGRATIONS;

/// What was copied: rows per table.
#[derive(Debug, Default)]
pub struct Report {
    pub version: usize,
    pub tables: BTreeMap<String, u64>,
}

fn quote_ident(s: &str) -> String {
    format!("\"{}\"", s.replace('"', "\"\""))
}

async fn connect(url: &str) -> Result<tokio_postgres::Client, String> {
    let mut roots = rustls::RootCertStore::empty();
    let certs = rustls_native_certs::load_native_certs();
    for c in certs.certs {
        let _ = roots.add(c);
    }
    let provider = std::sync::Arc::new(rustls::crypto::ring::default_provider());
    let tls = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|e| e.to_string())?
        .with_root_certificates(roots)
        .with_no_client_auth();
    let connector = tokio_postgres_rustls::MakeRustlsConnect::new(tls);
    let (client, conn) = tokio_postgres::connect(url, connector)
        .await
        .map_err(|e| format!("cannot connect to PostgreSQL: {e}"))?;
    tokio::spawn(async move {
        if let Err(e) = conn.await {
            tracing::warn!(error = %e, "PostgreSQL connection closed");
        }
    });
    Ok(client)
}

/// A PostgreSQL value as SQLite stores it.
fn cell(row: &tokio_postgres::Row, i: usize) -> Result<SqlValue, String> {
    let t = row.columns()[i].type_().clone();
    let err = |e: tokio_postgres::Error| format!("column {}: {e}", row.columns()[i].name());
    Ok(match t {
        Type::INT2 => row
            .try_get::<_, Option<i16>>(i)
            .map_err(err)?
            .map_or(SqlValue::Null, |v| SqlValue::Integer(v.into())),
        Type::INT4 => row
            .try_get::<_, Option<i32>>(i)
            .map_err(err)?
            .map_or(SqlValue::Null, |v| SqlValue::Integer(v.into())),
        Type::INT8 => row
            .try_get::<_, Option<i64>>(i)
            .map_err(err)?
            .map_or(SqlValue::Null, SqlValue::Integer),
        Type::BOOL => row
            .try_get::<_, Option<bool>>(i)
            .map_err(err)?
            .map_or(SqlValue::Null, |v| SqlValue::Integer(v as i64)),
        Type::FLOAT4 => row
            .try_get::<_, Option<f32>>(i)
            .map_err(err)?
            .map_or(SqlValue::Null, |v| SqlValue::Real(v.into())),
        Type::FLOAT8 => row
            .try_get::<_, Option<f64>>(i)
            .map_err(err)?
            .map_or(SqlValue::Null, SqlValue::Real),
        Type::BYTEA => row
            .try_get::<_, Option<Vec<u8>>>(i)
            .map_err(err)?
            .map_or(SqlValue::Null, SqlValue::Blob),
        Type::TEXT | Type::VARCHAR | Type::BPCHAR | Type::NAME => row
            .try_get::<_, Option<String>>(i)
            .map_err(err)?
            .map_or(SqlValue::Null, SqlValue::Text),
        other => {
            return Err(format!(
                "column {} has type {other}, which node-go never used",
                row.columns()[i].name()
            ));
        }
    })
}

/// Copies the node-go database at `from` into a new SQLite database `to`.
pub async fn import_postgres(from: &str, to: &Path) -> Result<Report, String> {
    if to.exists() {
        return Err(format!(
            "{} exists; import-postgres writes a new database only (move it away or choose another OBX_DATA_DIR)",
            to.display()
        ));
    }
    let pg = connect(from).await?;
    let version: i64 = pg
        .query_one(
            "SELECT COALESCE(MAX(version), 0)::BIGINT FROM schema_migrations",
            &[],
        )
        .await
        .map_err(|e| format!("this is not a node-go database (schema_migrations: {e})"))?
        .get(0);
    let version = version as usize;
    if version == 0 {
        return Err("the PostgreSQL database has no node-go schema".into());
    }
    if version > MIGRATIONS.len() {
        return Err(format!(
            "the PostgreSQL database has schema version {version}, this node-rs knows up to {}: use a newer node-rs",
            MIGRATIONS.len()
        ));
    }
    if let Some(dir) = to.parent() {
        std::fs::create_dir_all(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    }
    let tmp = to.with_extension("db.import-postgres");
    let _ = std::fs::remove_file(&tmp);
    let out = copy_into(&pg, &tmp, version).await;
    if let Err(e) = out {
        let _ = std::fs::remove_file(&tmp);
        return Err(e);
    }
    let mut report = out?;
    std::fs::rename(&tmp, to).map_err(|e| format!("{}: {e}", to.display()))?;
    // The remaining migrations, as node-go would have run them.
    crate::db::Db::open(to).map_err(|e| format!("migrating the copy: {e}"))?;
    report.version = version;
    Ok(report)
}

async fn copy_into(
    pg: &tokio_postgres::Client,
    path: &Path,
    version: usize,
) -> Result<Report, String> {
    let mut c = crate::db::open_conn(path).map_err(|e| e.to_string())?;
    crate::db::migrate_to(&mut c, version).map_err(|e| e.to_string())?;
    c.pragma_update(None, "foreign_keys", "OFF")
        .map_err(|e| e.to_string())?;
    let tables: Vec<String> = {
        let mut st = c
            .prepare("SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%' ORDER BY name")
            .map_err(|e| e.to_string())?;
        st.query_map([], |r| r.get(0))
            .map_err(|e| e.to_string())?
            .collect::<rusqlite::Result<Vec<String>>>()
            .map_err(|e| e.to_string())?
    };
    let mut report = Report::default();
    let tx = c.transaction().map_err(|e| e.to_string())?;
    tx.execute("DELETE FROM schema_migrations", [])
        .map_err(|e| e.to_string())?;
    for t in &tables {
        let cols: Vec<String> = {
            let mut st = tx
                .prepare(&format!("PRAGMA table_info({})", quote_ident(t)))
                .map_err(|e| e.to_string())?;
            st.query_map([], |r| r.get::<_, String>(1))
                .map_err(|e| e.to_string())?
                .collect::<rusqlite::Result<Vec<_>>>()
                .map_err(|e| e.to_string())?
        };
        let pg_cols: Vec<(String, Option<String>)> = pg
            .query(
                "SELECT column_name::TEXT, column_default::TEXT FROM information_schema.columns WHERE table_schema = current_schema() AND table_name = $1 ORDER BY ordinal_position",
                &[t],
            )
            .await
            .map_err(|e| format!("{t}: {e}"))?
            .iter()
            .map(|r| (r.get(0), r.get(1)))
            .collect();
        if pg_cols.is_empty() {
            return Err(format!(
                "table {t} is missing in PostgreSQL although schema version {version} has it"
            ));
        }
        if let Some((extra, _)) = pg_cols.iter().find(|(n, _)| !cols.contains(n)) {
            return Err(format!(
                "column {t}.{extra} exists in PostgreSQL but not in node-rs schema version {version}; nothing was copied"
            ));
        }
        let shared: Vec<&String> = cols
            .iter()
            .filter(|c| pg_cols.iter().any(|(n, _)| n == *c))
            .collect();
        let list = shared
            .iter()
            .map(|c| quote_ident(c))
            .collect::<Vec<_>>()
            .join(", ");
        let insert = format!(
            "INSERT INTO {} ({list}) VALUES ({})",
            quote_ident(t),
            vec!["?"; shared.len()].join(", ")
        );
        // Rows the migrations seeded (meta, settings) come from the source.
        tx.execute(&format!("DELETE FROM {}", quote_ident(t)), [])
            .map_err(|e| format!("{t}: {e}"))?;
        let mut ins = tx.prepare(&insert).map_err(|e| e.to_string())?;
        let rows = pg
            .query_raw(
                &format!("SELECT {list} FROM {}", quote_ident(t)),
                std::iter::empty::<&(dyn tokio_postgres::types::ToSql + Sync)>(),
            )
            .await
            .map_err(|e| format!("{t}: {e}"))?;
        pin_mut!(rows);
        let mut n = 0u64;
        while let Some(row) = rows.next().await {
            let row = row.map_err(|e| format!("{t}: {e}"))?;
            let vals = (0..shared.len())
                .map(|i| cell(&row, i))
                .collect::<Result<Vec<_>, _>>()
                .map_err(|e| format!("{t}: {e}"))?;
            ins.execute(rusqlite::params_from_iter(vals))
                .map_err(|e| format!("{t}: {e}"))?;
            n += 1;
        }
        drop(ins);
        let pg_count: i64 = pg
            .query_one(&format!("SELECT COUNT(*) FROM {}", quote_ident(t)), &[])
            .await
            .map_err(|e| format!("{t}: {e}"))?
            .get(0);
        if pg_count as u64 != n {
            return Err(format!(
                "{t}: copied {n} rows but PostgreSQL has {pg_count} (was node-go still running? stop it first)"
            ));
        }
        // Sequences (BIGSERIAL): continue after the source's last value, so
        // a change-feed cursor never sees a number twice.
        for (col, default) in &pg_cols {
            if default
                .as_deref()
                .is_some_and(|d| d.starts_with("nextval("))
            {
                let row = pg
                    .query_one(
                        "SELECT pg_get_serial_sequence($1, $2)",
                        &[&quote_ident(t), col],
                    )
                    .await
                    .map_err(|e| format!("{t}.{col}: {e}"))?;
                let Some(seq): Option<String> = row.get(0) else {
                    continue;
                };
                let r = pg
                    .query_one(&format!("SELECT last_value, is_called FROM {seq}"), &[])
                    .await
                    .map_err(|e| format!("{seq}: {e}"))?;
                let (last, called): (i64, bool) = (r.get(0), r.get(1));
                let last = if called { last } else { last - 1 };
                tx.execute(
                    "UPDATE sqlite_sequence SET seq = MAX(seq, ?1) WHERE name = ?2",
                    rusqlite::params![last, t],
                )
                .map_err(|e| e.to_string())?;
                tx.execute(
                    "INSERT INTO sqlite_sequence (name, seq) SELECT ?2, ?1 WHERE NOT EXISTS (SELECT 1 FROM sqlite_sequence WHERE name = ?2)",
                    rusqlite::params![last, t],
                )
                .map_err(|e| e.to_string())?;
            }
        }
        report.tables.insert(t.clone(), n);
    }
    let bad: i64 = tx
        .query_row("SELECT COUNT(*) FROM pragma_foreign_key_check", [], |r| {
            r.get(0)
        })
        .map_err(|e| e.to_string())?;
    if bad > 0 {
        return Err(format!(
            "{bad} rows refer to rows that do not exist (foreign keys); nothing was copied"
        ));
    }
    tx.commit().map_err(|e| e.to_string())?;
    c.pragma_update(None, "foreign_keys", "ON")
        .map_err(|e| e.to_string())?;
    Ok(report)
}

#[cfg(test)]
mod tests {
    #[test]
    fn identifiers_are_quoted() {
        assert_eq!(super::quote_ident("jobs"), "\"jobs\"");
        assert_eq!(super::quote_ident("a\"b"), "\"a\"\"b\"");
    }

    #[tokio::test]
    async fn refuses_an_existing_target() {
        let d = std::env::temp_dir().join(format!("obx-pgcopy-{}", crate::ids::new("t")));
        std::fs::create_dir_all(&d).unwrap();
        let db = d.join("obx.db");
        std::fs::write(&db, b"x").unwrap();
        let e = super::import_postgres("postgres://127.0.0.1:1/x", &db)
            .await
            .unwrap_err();
        assert!(e.contains("exists"), "{e}");
        let _ = std::fs::remove_dir_all(&d);
    }
}
