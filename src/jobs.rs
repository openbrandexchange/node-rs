//! Background jobs (ingest.md §7): batch and import jobs in the `jobs`
//! table, claimed by workers with a lease so a job interrupted by a restart
//! is picked up again. Results (IngestResult per batch operation,
//! ImportRowError per import problem) are stored in `job_items`.

#![allow(clippy::result_large_err)]

use std::collections::HashMap;

use axum::extract::{Path, Query, State};
use axum::http::HeaderMap;
use rusqlite::{Connection, OptionalExtension, Row as SqlRow, params};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::app::App;
use crate::db;
use crate::http::{Res, limit_param, ok};
use crate::problem::{Problem, Result};

/// The lease a worker holds on a running job; renewed with every progress
/// update, so a job whose worker died is claimed again afterwards.
const LEASE_MINUTES: i64 = 10;

#[derive(Debug, Clone, Default)]
#[allow(dead_code)]
pub struct Job {
    pub id: String,
    pub kind: String,
    pub status: String,
    pub owner_type: String,
    pub created_at: String,
    pub owner_id: Option<String>,
    pub trigger: Option<String>,
    pub source_id: Option<String>,
    pub result: Option<String>,
    pub payload: String,
    pub done: i64,
    pub total: Option<i64>,
    pub started_at: Option<String>,
    pub finished_at: Option<String>,
    pub expires_at: Option<String>,
    pub error: Option<String>,
    pub attempts: i64,
}

const JOB_COLS: &str = "id, kind, status, owner_type, created_at, owner_id, trigger_kind, source_id, result, payload, progress_done, progress_total, started_at, finished_at, expires_at, error, attempts";

fn scan_job(r: &SqlRow) -> rusqlite::Result<Job> {
    Ok(Job {
        id: r.get(0)?,
        kind: r.get(1)?,
        status: r.get(2)?,
        owner_type: r.get(3)?,
        created_at: r.get(4)?,
        owner_id: r.get(5)?,
        trigger: r.get(6)?,
        source_id: r.get(7)?,
        result: r.get(8)?,
        payload: r.get(9)?,
        done: r.get(10)?,
        total: r.get(11)?,
        started_at: r.get(12)?,
        finished_at: r.get(13)?,
        expires_at: r.get(14)?,
        error: r.get(15)?,
        attempts: r.get(16)?,
    })
}

pub fn load_job_sync(c: &Connection, id: &str) -> Result<Option<Job>> {
    Ok(c.query_row(
        &format!("SELECT {JOB_COLS} FROM jobs WHERE id = ?"),
        [id],
        scan_job,
    )
    .optional()?)
}

pub async fn load_job(app: &App, id: &str) -> Result<Option<Job>> {
    let id = id.to_string();
    app.db.read(move |c| load_job_sync(c, &id)).await
}

/// What to store for a new job.
#[derive(Debug, Clone, Default)]
pub struct JobSpec {
    pub id: Option<String>,
    pub kind: String,
    pub owner_type: String,
    pub owner_id: String,
    pub source_id: String,
    pub trigger: String,
    pub payload: Value,
    pub total: Option<i64>,
}

fn null_if_empty(s: &str) -> Option<String> {
    (!s.is_empty()).then(|| s.to_string())
}

pub async fn create(app: &App, s: JobSpec) -> Result<Job> {
    let id = s.id.clone().unwrap_or_else(|| crate::ids::new("job"));
    let i = id.clone();
    let payload = s.payload.to_string();
    let total = s.total.filter(|t| *t > 0);
    let job = app
        .db
        .write(move |tx| {
            tx.execute(
                "INSERT INTO jobs (id, kind, status, owner_type, owner_id, trigger_kind, source_id, dedupe_key, payload, progress_total, created_at) VALUES (?, ?, 'queued', ?, ?, ?, ?, NULL, ?, ?, ?)",
                params![
                    i,
                    s.kind,
                    s.owner_type,
                    null_if_empty(&s.owner_id),
                    null_if_empty(&s.trigger),
                    null_if_empty(&s.source_id),
                    payload,
                    total,
                    db::now_str()
                ],
            )?;
            load_job_sync(tx, &i)?.ok_or_else(|| Problem::internal("job vanished"))
        })
        .await?;
    app.jobs.notify_one();
    Ok(job)
}

pub async fn create_job(
    app: &App,
    kind: &str,
    owner_type: &str,
    owner_id: &str,
    payload: Value,
    total: Option<i64>,
) -> Result<Job> {
    create(
        app,
        JobSpec {
            kind: kind.into(),
            owner_type: owner_type.into(),
            owner_id: owner_id.into(),
            payload,
            total,
            ..Default::default()
        },
    )
    .await
}

fn lease_until() -> String {
    db::fmt_time(chrono::Utc::now() + chrono::Duration::minutes(LEASE_MINUTES))
}

/// Records progress and renews the lease.
pub async fn progress(app: &App, job_id: &str, done: i64, total: Option<i64>) {
    let id = job_id.to_string();
    let _ = app
        .db
        .write(move |tx| {
            tx.execute(
                "UPDATE jobs SET progress_done = ?, progress_total = COALESCE(?, progress_total), lease_until = ? WHERE id = ?",
                params![done, total, lease_until(), id],
            )?;
            Ok(())
        })
        .await;
}

/// Stores result items (overwriting the same index on a re-run).
pub async fn add_items(
    app: &App,
    job_id: &str,
    start: usize,
    items: Vec<(Value, bool)>,
) -> Result<()> {
    let id = job_id.to_string();
    app.db
        .write(move |tx| {
            let mut st = tx.prepare(
                "INSERT INTO job_items (job_id, idx, item, is_error) VALUES (?, ?, ?, ?) ON CONFLICT (job_id, idx) DO UPDATE SET item = excluded.item, is_error = excluded.is_error",
            )?;
            for (i, (item, is_error)) in items.into_iter().enumerate() {
                st.execute(params![id, (start + i) as i64, item.to_string(), is_error as i64])?;
            }
            Ok(())
        })
        .await
}

async fn claim(app: &App) -> Option<Job> {
    app.db
        .write(|tx| {
            let now = db::now_str();
            let id: Option<String> = tx
                .query_row(
                    "SELECT id FROM jobs WHERE status = 'queued' OR (status = 'running' AND lease_until < ?) ORDER BY created_at LIMIT 1",
                    [&now],
                    |r| r.get(0),
                )
                .optional()?;
            let Some(id) = id else { return Ok(None) };
            tx.execute(
                "UPDATE jobs SET status = 'running', lease_until = ?, attempts = attempts + 1, started_at = COALESCE(started_at, ?) WHERE id = ?",
                params![lease_until(), now, id],
            )?;
            load_job_sync(tx, &id)
        })
        .await
        .ok()
        .flatten()
}

/// Starts `OBX_WORKERS` workers.
pub fn start_workers(app: App) {
    for _ in 0..app.cfg.workers.max(1) {
        let a = app.clone();
        tokio::spawn(async move {
            loop {
                while let Some(j) = claim(&a).await {
                    run_job(&a, j).await;
                }
                tokio::select! {
                    _ = a.jobs.notified() => {}
                    _ = tokio::time::sleep(std::time::Duration::from_secs(2)) => {}
                }
            }
        });
    }
}

/// Runs every queued job now (the `import` command, tests).
#[allow(dead_code)]
pub async fn run_jobs_now(app: &App) {
    while let Some(j) = claim(app).await {
        run_job(app, j).await;
    }
}

async fn run_job(app: &App, j: Job) {
    let outcome: std::result::Result<Option<Value>, (Option<Value>, String)> = if j.attempts > 3 {
        Err((
            None,
            format!(
                "job failed repeatedly (interrupted {} times)",
                j.attempts - 1
            ),
        ))
    } else {
        match j.kind.as_str() {
            "batch" => run_batch_job(app, &j).await,
            "import" => crate::imports::run_import_job(app, &j).await,
            k => Err((None, format!("unknown job kind {k}"))),
        }
    };
    let (status, result, error) = match outcome {
        Ok(r) => ("succeeded", r, None),
        Err((r, e)) => {
            tracing::warn!(job = %j.id, kind = %j.kind, error = %e, "job failed");
            ("failed", r, Some(e))
        }
    };
    let id = j.id.clone();
    let res = result.map(|v| v.to_string());
    let _ = app
        .db
        .write(move |tx| {
            tx.execute(
                "UPDATE jobs SET status = ?, result = COALESCE(?, result), error = ?, finished_at = ?, lease_until = NULL WHERE id = ?",
                params![status, res, error, db::now_str(), id],
            )?;
            Ok(())
        })
        .await;
}

#[derive(Deserialize)]
struct BatchPayload {
    #[serde(default)]
    ops: Vec<Value>,
    #[serde(default)]
    allowed: Option<Vec<String>>,
    #[serde(default)]
    can_delete: bool,
}

async fn run_batch_job(
    app: &App,
    j: &Job,
) -> std::result::Result<Option<Value>, (Option<Value>, String)> {
    let p: BatchPayload = serde_json::from_str(&j.payload).map_err(|e| (None, e.to_string()))?;
    let total = p.ops.len() as i64;
    let (a, id) = (app.clone(), j.id.clone());
    let (results, sum) =
        crate::http::ingest::run_batch(app, p.ops, p.allowed, p.can_delete, move |done| {
            let (a, id) = (a.clone(), id.clone());
            tokio::spawn(async move { progress(&a, &id, done as i64, Some(total)).await });
        })
        .await;
    let items = results
        .iter()
        .map(|r| {
            (
                serde_json::to_value(r).unwrap_or(Value::Null),
                r.result == "error",
            )
        })
        .collect();
    add_items(app, &j.id, 0, items)
        .await
        .map_err(|e| (None, e.to_string()))?;
    progress(app, &j.id, total, Some(total)).await;
    Ok(Some(json!({"summary": sum})))
}

/// The IngestJob of a job (ingest.md §7).
pub async fn ingest_job_json(app: &App, j: &Job) -> Result<Value> {
    let kind = if j.kind == "batch" { "batch" } else { "import" };
    let mut out = json!({
        "id": j.id, "kind": kind, "status": j.status, "created_at": j.created_at, "finished_at": j.finished_at,
        "progress": {"done": j.done, "total": j.total},
        "summary": null, "import_run": null,
        "results_url": format!("{}/obx/v1/ingest/jobs/{}/results", app.cfg.public_url, j.id),
    });
    if let Some(s) = j
        .result
        .as_deref()
        .and_then(|r| serde_json::from_str::<Value>(r).ok())
        .and_then(|r| r.get("summary").filter(|s| !s.is_null()).cloned())
    {
        out["summary"] = s;
    }
    if j.kind == "import" {
        let run = crate::imports::import_run_json(app, j).await?;
        if j.status == "succeeded" {
            let c = &run["counts"];
            out["summary"] = json!({"created": c["created"], "updated": c["updated"], "unchanged": c["unchanged"],
                "deleted": 0, "errors": c["errors"]});
        }
        out["import_run"] = run;
    }
    Ok(out)
}

#[derive(Serialize, Deserialize)]
struct ListCursor {
    c: String,
    i: String,
}

#[derive(Serialize, Deserialize)]
struct ItemCursor {
    i: i64,
}

pub async fn h_jobs(
    State(app): State<App>,
    Query(q): Query<HashMap<String, String>>,
    headers: HeaderMap,
) -> Res {
    crate::http::ingest::ingest_auth(&app, &headers, "ingest:read").await?;
    let limit = limit_param(&q, 25, 100)?;
    let mut where_ =
        String::from("WHERE kind IN ('batch', 'import') AND owner_type = 'ingest_token'");
    let mut args: Vec<String> = Vec::new();
    if let Some(s) = q.get("status").filter(|s| !s.is_empty()) {
        where_.push_str(" AND status = ?");
        args.push(s.clone());
    }
    if let Some(c) = q.get("cursor").filter(|s| !s.is_empty()) {
        let cur: ListCursor = app
            .decode_cursor("jobs", c)
            .ok_or_else(|| Problem::new("cursor_invalid", "The cursor is not valid."))?;
        where_.push_str(" AND (created_at < ? OR (created_at = ? AND id < ?))");
        args.extend([cur.c.clone(), cur.c, cur.i]);
    }
    let mut jobs = app
        .db
        .read(move |c| {
            let mut st = c.prepare(&format!(
                "SELECT {JOB_COLS} FROM jobs {where_} ORDER BY created_at DESC, id DESC LIMIT {}",
                limit + 1
            ))?;
            let r = st
                .query_map(rusqlite::params_from_iter(args.iter()), scan_job)?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            Ok(r)
        })
        .await?;
    let mut next = None;
    if jobs.len() > limit {
        jobs.truncate(limit);
        let l = &jobs[limit - 1];
        next = Some(app.encode_cursor(
            "jobs",
            &ListCursor {
                c: l.created_at.clone(),
                i: l.id.clone(),
            },
        ));
    }
    let mut items = Vec::new();
    for j in &jobs {
        items.push(ingest_job_json(&app, j).await?);
    }
    Ok(ok(&json!({"items": items, "next_cursor": next})))
}

async fn ingest_visible_job(app: &App, id: &str) -> Result<Job> {
    load_job(app, id)
        .await?
        .filter(|j| {
            (j.kind == "batch" || j.kind == "import")
                && j.owner_type != "retailer"
                && j.owner_type != "client"
        })
        .ok_or_else(|| Problem::new("not_found", "Job not found."))
}

pub async fn h_job(State(app): State<App>, Path(id): Path<String>, headers: HeaderMap) -> Res {
    crate::http::ingest::ingest_auth(&app, &headers, "ingest:read").await?;
    let j = ingest_visible_job(&app, &id).await?;
    Ok(ok(&ingest_job_json(&app, &j).await?))
}

pub async fn h_job_results(
    State(app): State<App>,
    Path(id): Path<String>,
    Query(q): Query<HashMap<String, String>>,
    headers: HeaderMap,
) -> Res {
    crate::http::ingest::ingest_auth(&app, &headers, "ingest:read").await?;
    let j = ingest_visible_job(&app, &id).await?;
    job_items(&app, &j.id, &q, 100, 1000).await
}

/// One page of a job's result items.
pub async fn job_items(
    app: &App,
    job_id: &str,
    q: &HashMap<String, String>,
    def: usize,
    max: usize,
) -> Res {
    let limit = limit_param(q, def, max)?;
    let mut after = -1i64;
    if let Some(c) = q.get("cursor").filter(|s| !s.is_empty()) {
        let cur: ItemCursor = app
            .decode_cursor(&format!("items/{job_id}"), c)
            .ok_or_else(|| Problem::new("cursor_invalid", "The cursor is not valid."))?;
        after = cur.i;
    }
    let errors_only = q
        .get("errors_only")
        .map(|v| v.to_lowercase())
        .is_some_and(|v| v == "true" || v == "1");
    let id = job_id.to_string();
    let rows = app
        .db
        .read(move |c| {
            let mut st = c.prepare(&format!(
                "SELECT idx, item FROM job_items WHERE job_id = ? AND idx > ?{} ORDER BY idx LIMIT {}",
                if errors_only { " AND is_error = 1" } else { "" },
                limit + 1
            ))?;
            let r = st
                .query_map(params![id, after], |r| Ok((r.get::<_, i64>(0)?, r.get::<_, String>(1)?)))?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            Ok(r)
        })
        .await?;
    let mut items: Vec<Value> = Vec::new();
    let mut next = None;
    for (n, (idx, item)) in rows.iter().enumerate() {
        if n == limit {
            next = Some(app.encode_cursor(
                &format!("items/{job_id}"),
                &ItemCursor {
                    i: rows[limit - 1].0,
                },
            ));
            break;
        }
        let _ = idx;
        items.push(serde_json::from_str(item).unwrap_or(Value::Null));
    }
    Ok(ok(&json!({"items": items, "next_cursor": next})))
}
