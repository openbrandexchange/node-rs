//! Housekeeping (node-go's loop, every 30 seconds): e-mail retries, expired
//! image rights, cleanup of sessions, uploads, prepared files, finished jobs
//! and old statistics, and pruning of the change history.

use rusqlite::params;

use crate::app::App;
use crate::db;

fn days_ago(n: i64) -> String {
    db::fmt_time(chrono::Utc::now() - chrono::Duration::days(n))
}

/// Starts the housekeeping loop.
pub fn start(app: App) {
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(std::time::Duration::from_secs(30));
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        let mut n: u64 = 0;
        loop {
            tick.tick().await;
            n += 1;
            expire_assets(&app).await;
            crate::mail::retry_due(&app).await;
            if n % 10 == 1 {
                if let Err(e) = cleanup(&app).await {
                    tracing::warn!(error = %e, "cleanup failed");
                }
            }
            if n % 120 == 1 {
                if let Err(e) = prune_changes(&app).await {
                    tracing::warn!(error = %e, "change history pruning failed");
                }
                let _ = app
                    .db
                    .write(|tx| {
                        tx.execute_batch("PRAGMA optimize")?;
                        Ok(())
                    })
                    .await;
            }
        }
    });
}

/// Writes tombstones for assets whose rights expired.
pub async fn expire_assets(app: &App) {
    let now = chrono::Utc::now();
    let due = app
        .db
        .read(move |c| {
            let mut st = c.prepare(
                "SELECT external_id FROM assets WHERE visible = 1 AND expires_at IS NOT NULL AND expires_at <= ?",
            )?;
            let ids = st
                .query_map([db::fmt_time(now)], |r| r.get::<_, String>(0))?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            Ok(ids)
        })
        .await
        .unwrap_or_default();
    if due.is_empty() {
        return;
    }
    let r = app
        .catalog_write(None, move |w| {
            for ext in due {
                if let Some(mut row) =
                    crate::catalog::load_row(w.tx, crate::model::KIND_ASSET, &ext)?
                {
                    w.recompute(&mut row)?;
                }
            }
            Ok(())
        })
        .await;
    if let Err(e) = r {
        tracing::warn!(error = %e, "expiring image rights failed");
    }
}

/// Removes the change history older than OBX_CHANGE_RETENTION_DAYS; a
/// cursor from before answers 410 cursor_expired.
pub async fn prune_changes(app: &App) -> crate::problem::Result<i64> {
    let cutoff = days_ago(app.cfg.change_retention_days);
    app.db
        .write(move |tx| {
            let s: Option<i64> = tx.query_row(
                "SELECT MAX(seq) FROM changes WHERE at < ?",
                [&cutoff],
                |r| r.get(0),
            )?;
            let Some(s) = s else { return Ok(0) };
            let n = tx.execute("DELETE FROM changes WHERE seq <= ?", [s])?;
            db::set_meta(tx, "changes_pruned_below", &s.to_string())?;
            Ok(n as i64)
        })
        .await
}

/// Removes expired sessions, uploads, exports, downloads, idempotency
/// records, and data past its retention.
pub async fn cleanup(app: &App) -> crate::problem::Result<()> {
    let st = app.settings().await?;
    let ret = st.retention.clone();
    let (webhook_days, job_days) = (
        app.cfg.webhook_log_retention_days,
        app.cfg.job_retention_days,
    );
    let (uploads, files) = app
        .db
        .write(move |tx| {
            let now = db::now_str();
            tx.execute("DELETE FROM sessions WHERE expires_at < ?", [&now])?;
            tx.execute(
                "DELETE FROM idempotency WHERE created_at < ?",
                [db::fmt_time(chrono::Utc::now() - chrono::Duration::hours(25))],
            )?;
            tx.execute(
                "DELETE FROM webhook_deliveries WHERE created_at < ? AND status <> 'pending'",
                [days_ago(webhook_days)],
            )?;
            tx.execute("DELETE FROM audit_log WHERE at < ?", [days_ago(ret.audit_log_days)])?;
            tx.execute(
                "DELETE FROM mail_outbox WHERE status <> 'pending' AND created_at < ?",
                [days_ago(7)],
            )?;
            // Decided access requests hold contact details.
            tx.execute(
                "DELETE FROM access_requests WHERE status <> 'pending' AND COALESCE(decided_at, created_at) < ?",
                [days_ago(ret.access_requests_days)],
            )?;
            let mut q = tx.prepare("SELECT id FROM uploads WHERE status = 'open' AND expires_at < ?")?;
            let uploads = q
                .query_map([&now], |r| r.get::<_, String>(0))?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            drop(q);
            for id in &uploads {
                tx.execute("UPDATE uploads SET status = 'expired' WHERE id = ?", [id])?;
            }
            let mut q = tx.prepare("SELECT id, kind FROM jobs WHERE kind IN ('export', 'download') AND expires_at IS NOT NULL AND expires_at < ? AND status = 'succeeded'")?;
            let files = q
                .query_map([&now], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            drop(q);
            for (id, _) in &files {
                tx.execute("UPDATE jobs SET status = 'expired' WHERE id = ?", [id])?;
            }
            // Finished jobs and their items are kept OBX_JOB_RETENTION_DAYS.
            let old = days_ago(job_days);
            tx.execute("DELETE FROM job_items WHERE job_id IN (SELECT id FROM jobs WHERE created_at < ? AND kind IN ('batch', 'export', 'download'))", [&old])?;
            tx.execute("DELETE FROM jobs WHERE created_at < ? AND kind IN ('batch', 'export', 'download')", [&old])?;
            // Download statistics: as long as the retention setting, the
            // person's name at most 400 days.
            tx.execute("DELETE FROM download_events WHERE at < ?", [days_ago(ret.download_events_days)])?;
            tx.execute(
                "UPDATE download_events SET actor_id = NULL, actor_name = NULL WHERE at < ? AND actor_name IS NOT NULL AND actor_type = 'user'",
                params![days_ago(ret.download_events_days.min(400))],
            )?;
            Ok((uploads, files))
        })
        .await?;
    for id in uploads {
        delete_prefix(app, &format!("uploads/{id}/")).await;
    }
    for (id, kind) in files {
        if kind == "export" {
            delete_prefix(app, &format!("exports/{id}/")).await;
        } else {
            let _ = app.store.delete(&format!("downloads/{id}.zip")).await;
        }
    }
    Ok(())
}

async fn delete_prefix(app: &App, prefix: &str) {
    if let Err(e) = app.store.delete_prefix(prefix).await {
        tracing::warn!(prefix, error = %e, "removing stored files failed");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn prunes_old_changes_and_expired_rows() {
        let dir = std::env::temp_dir().join(format!("obx-ops-test-{}", crate::ids::new("t")));
        std::fs::create_dir_all(&dir).unwrap();
        let app = App::new(crate::config::Config::for_test(&dir))
            .await
            .unwrap();
        let old = days_ago(500);
        let o2 = old.clone();
        app.db
            .write(move |tx| {
                tx.execute("INSERT INTO changes (type, op, object_id, at) VALUES ('product', 'upsert', 'prd_1', ?)", [&o2])?;
                tx.execute("INSERT INTO changes (type, op, object_id, at) VALUES ('product', 'upsert', 'prd_2', ?)", [db::now_str()])?;
                tx.execute("INSERT INTO sessions (id_hash, user_id, csrf, created_at, expires_at, last_seen_at) VALUES ('h', 'u', 'c', ?, ?, ?)", [&o2, &o2, &o2])?;
                tx.execute("INSERT INTO audit_log (id, at, actor_type, action, method, route, status) VALUES ('aud_1', ?, 'cli', 'x', 'CLI', 'x', 200)", [&o2])?;
                Ok(())
            })
            .await
            .unwrap();
        assert_eq!(prune_changes(&app).await.unwrap(), 1);
        cleanup(&app).await.unwrap();
        let (n, pruned, sessions, audit) = app
            .db
            .read(|c| {
                let n: i64 = c.query_row("SELECT COUNT(*) FROM changes", [], |r| r.get(0))?;
                let s: i64 = c.query_row("SELECT COUNT(*) FROM sessions", [], |r| r.get(0))?;
                let a: i64 = c.query_row("SELECT COUNT(*) FROM audit_log", [], |r| r.get(0))?;
                Ok((n, db::get_meta(c, "changes_pruned_below")?, s, a))
            })
            .await
            .unwrap();
        assert_eq!((n, sessions, audit), (1, 0, 0));
        assert!(pruned.is_some());
        let _ = std::fs::remove_dir_all(dir);
    }
}
