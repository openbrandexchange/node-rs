//! Scheduled imports (node-admin.yaml `ImportSource`): a brand pulls its
//! catalog from an HTTPS URL, an SFTP folder or an S3 bucket on a schedule.
//! A port of node-go `sources.go` and `sources_fetch.go`.
//!
//! * Credentials are write-only: stored encrypted (`Keys::encrypt`) and
//!   never returned; `credentials_set` says which ones are stored.
//! * Every outbound connection is under the URL policy of `safeurl`
//!   (checked when the source is saved, and again at every connection).
//! * A run lists the remote files first; when their fingerprint (names,
//!   sizes, times, ETags or sha256) equals the last successful run, the run
//!   is skipped (`x-node-rs-unchanged`), unless it is forced.
//! * SFTP host keys are pinned on first use (`host_key_fingerprint`).

use std::collections::{BTreeMap, HashMap};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, Method, StatusCode};
use axum::response::IntoResponse;
use rusqlite::{Connection, OptionalExtension, params};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};

use crate::app::{App, MAX_IMPORT_BYTES};
use crate::db;
use crate::http::admin::admin_guard;
use crate::http::{Res, json as json_response, ok, read_json_object};
use crate::imports::{ImportFile, ImportOptions, ImportPayload};
use crate::jobs::{self, Job, JobSpec};
use crate::problem::{Problem, Result};

/// At most this many remote files are listed (node-go maxZipEntries).
const MAX_FILES: usize = 100_000;

#[derive(Debug, Clone)]
pub struct SourceRow {
    pub id: String,
    pub name: String,
    pub kind: String,
    pub mode: String,
    pub created_at: String,
    pub updated_at: String,
    pub enabled: bool,
    pub allow_mass: bool,
    pub schedule: Map<String, Value>,
    pub config: Map<String, Value>,
    pub creds_enc: Option<String>,
    pub next_run: Option<String>,
    pub fingerprint: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct Creds {
    #[serde(skip_serializing_if = "Option::is_none")]
    password: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    private_key: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    access_key_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    secret_access_key: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    headers: Option<BTreeMap<String, String>>,
}

fn obj(s: &str) -> Map<String, Value> {
    match serde_json::from_str::<Value>(s) {
        Ok(Value::Object(m)) => m,
        _ => Map::new(),
    }
}

pub fn load_source(c: &Connection, id: &str) -> Result<Option<SourceRow>> {
    Ok(c.query_row(
        "SELECT id, name, kind, mode, created_at, updated_at, enabled, allow_mass_unpublish, schedule, config, credentials_enc, next_run_at, last_fingerprint FROM import_sources WHERE id = ? AND deleted = 0",
        [id],
        |r| {
            Ok(SourceRow {
                id: r.get(0)?,
                name: r.get(1)?,
                kind: r.get(2)?,
                mode: r.get(3)?,
                created_at: r.get(4)?,
                updated_at: r.get(5)?,
                enabled: r.get::<_, i64>(6)? == 1,
                allow_mass: r.get::<_, i64>(7)? == 1,
                schedule: obj(&r.get::<_, String>(8)?),
                config: obj(&r.get::<_, String>(9)?),
                creds_enc: r.get(10)?,
                next_run: r.get(11)?,
                fingerprint: r.get(12)?,
            })
        },
    )
    .optional()?)
}

fn creds_of(app: &App, s: &SourceRow) -> Creds {
    s.creds_enc
        .as_deref()
        .and_then(|e| app.keys.decrypt(e))
        .and_then(|b| serde_json::from_slice(&b).ok())
        .unwrap_or_default()
}

fn latest_run(c: &Connection, source_id: &str) -> Result<Option<Job>> {
    let id: Option<String> = c
        .query_row(
            "SELECT id FROM jobs WHERE kind = 'import' AND source_id = ? ORDER BY created_at DESC, id DESC LIMIT 1",
            [source_id],
            |r| r.get(0),
        )
        .optional()?;
    match id {
        Some(id) => jobs::load_job_sync(c, &id),
        None => Ok(None),
    }
}

async fn source_json(app: &App, s: &SourceRow) -> Result<Value> {
    let c = creds_of(app, s);
    let headers: Vec<String> = c
        .headers
        .as_ref()
        .map(|h| h.keys().cloned().collect())
        .unwrap_or_default();
    let id = s.id.clone();
    let last = match app.db.read(move |c| latest_run(c, &id)).await? {
        Some(j) => crate::imports::import_run_json(app, &j).await?,
        None => Value::Null,
    };
    let mut cfg = s.config.clone();
    cfg.insert("kind".into(), Value::String(s.kind.clone()));
    Ok(json!({
        "id": s.id, "name": s.name, "kind": s.kind, "enabled": s.enabled, "schedule": s.schedule,
        "mode": s.mode, "allow_mass_unpublish": s.allow_mass, "config": cfg,
        "credentials_set": {"password": c.password.is_some(), "private_key": c.private_key.is_some(),
            "access_key_id": c.access_key_id.is_some(), "secret_access_key": c.secret_access_key.is_some(),
            "headers": headers},
        "last_run": last, "next_run_at": s.next_run, "created_at": s.created_at, "updated_at": s.updated_at,
    }))
}

fn unsafe_field(p: Problem, pointer: &str) -> Problem {
    let d = p.detail_str().to_string();
    Problem::new("unsafe_url", d.clone()).field(pointer, "unsafe_url", d)
}

/// Checks a full source document (after merge); fills schedule defaults.
async fn validate_source(app: &App, doc: &mut Map<String, Value>) -> Result<()> {
    let mut check = doc.clone();
    check.remove("credentials");
    check.insert("id".into(), json!("src_x"));
    check.insert("created_at".into(), json!("2026-01-01T00:00:00Z"));
    check.insert("updated_at".into(), json!("2026-01-01T00:00:00Z"));
    if let Some(Value::Object(cfg)) = check.get("config").cloned() {
        let mut cfg = cfg;
        cfg.insert(
            "kind".into(),
            doc.get("kind").cloned().unwrap_or(Value::Null),
        );
        check.insert("config".into(), Value::Object(cfg));
    }
    let errs = crate::schemas::validate("ImportSource", &Value::Object(check));
    if !errs.is_empty() {
        let mut p = Problem::new("validation_failed", "The request body is not valid.");
        for e in errs {
            p = p.field(&e.pointer, "validation_failed", e.message);
        }
        return Err(p);
    }
    let allow = app.cfg.allow_private_urls;
    let cfg = doc
        .get("config")
        .and_then(|v| v.as_object())
        .cloned()
        .unwrap_or_default();
    let s = |k: &str| {
        cfg.get(k)
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string()
    };
    match doc.get("kind").and_then(|v| v.as_str()).unwrap_or("") {
        "https_url" => {
            for k in ["url", "images_url"] {
                let u = s(k);
                if !u.is_empty() {
                    crate::safeurl::check(&u, allow)
                        .await
                        .map_err(|p| unsafe_field(p, &format!("/config/{k}")))?;
                }
            }
        }
        "sftp" => {
            let port = cfg.get("port").and_then(|v| v.as_u64()).unwrap_or(22) as u16;
            crate::safeurl::check_host(&s("host"), port, allow)
                .await
                .map_err(|p| unsafe_field(p, "/config/host"))?;
        }
        "s3" => {
            let ep = s("endpoint");
            if !ep.is_empty() {
                crate::safeurl::check(&ep, allow)
                    .await
                    .map_err(|p| unsafe_field(p, "/config/endpoint"))?;
            }
        }
        _ => {}
    }
    if let Some(Value::Object(sched)) = doc.get_mut("schedule") {
        if let Some(tz) = sched.get("timezone").and_then(|v| v.as_str()) {
            if !tz.is_empty() && jiff::tz::TimeZone::get(tz).is_err() {
                return Err(
                    Problem::new("validation_failed", format!("Unknown timezone {tz:?}.")).field(
                        "/schedule/timezone",
                        "validation_failed",
                        "unknown timezone",
                    ),
                );
            }
        }
        let f = sched
            .get("frequency")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        if (f == "daily" || f == "weekly") && sched.get("time").is_none_or(|v| v.is_null()) {
            sched.insert("time".into(), json!("03:00"));
        }
        if f == "weekly" && sched.get("weekday").is_none_or(|v| v.is_null()) {
            sched.insert("weekday".into(), json!(1));
        }
    }
    Ok(())
}

/// Applies write-only credential changes (omit = keep, null or "" = clear).
fn merge_creds(mut cur: Creds, patch: &Map<String, Value>) -> Creds {
    let set = |k: &str, dst: &mut Option<String>| {
        if let Some(v) = patch.get(k) {
            *dst = v.as_str().filter(|s| !s.is_empty()).map(String::from);
        }
    };
    set("password", &mut cur.password);
    set("private_key", &mut cur.private_key);
    set("access_key_id", &mut cur.access_key_id);
    set("secret_access_key", &mut cur.secret_access_key);
    if let Some(v) = patch.get("headers") {
        cur.headers = v.as_object().map(|m| {
            m.iter()
                .filter_map(|(k, x)| x.as_str().map(|s| (k.clone(), s.to_string())))
                .collect()
        });
    }
    cur
}

fn not_found() -> Problem {
    Problem::new("not_found", "Import source not found.")
}

async fn load(app: &App, id: &str) -> Result<SourceRow> {
    let id = id.to_string();
    app.db
        .read(move |c| load_source(c, &id))
        .await?
        .ok_or_else(not_found)
}

pub async fn h_list(State(app): State<App>, method: Method, headers: HeaderMap) -> Res {
    admin_guard(&app, &headers, &method, "admin").await?;
    let ids: Vec<String> = app
        .db
        .read(|c| {
            let mut st =
                c.prepare("SELECT id FROM import_sources WHERE deleted = 0 ORDER BY created_at")?;
            let r = st
                .query_map([], |r| r.get::<_, String>(0))?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            Ok(r)
        })
        .await?;
    let mut items = Vec::new();
    for id in ids {
        if let Ok(s) = load(&app, &id).await {
            items.push(source_json(&app, &s).await?);
        }
    }
    Ok(ok(&json!({"items": items})))
}

fn str_field(m: &Map<String, Value>, k: &str) -> String {
    m.get(k).and_then(|v| v.as_str()).unwrap_or("").to_string()
}

fn bool_field(m: &Map<String, Value>, k: &str) -> bool {
    m.get(k).and_then(|v| v.as_bool()).unwrap_or(false)
}

fn encrypt_creds(app: &App, c: &Creds) -> String {
    app.keys.encrypt(&serde_json::to_vec(c).unwrap_or_default())
}

pub async fn h_create(
    State(app): State<App>,
    method: Method,
    headers: HeaderMap,
    body: Bytes,
) -> Res {
    admin_guard(&app, &headers, &method, "admin").await?;
    let mut v = Value::Object(read_json_object(&headers, &body)?);
    crate::model::norm_numbers(&mut v);
    let Value::Object(mut doc) = v else {
        unreachable!()
    };
    doc.entry("enabled").or_insert(json!(true));
    doc.entry("mode").or_insert(json!("upsert"));
    doc.entry("schedule")
        .or_insert(json!({"frequency": "daily", "time": "03:00", "timezone": "UTC"}));
    validate_source(&app, &mut doc).await?;
    let mut creds = Creds::default();
    if let Some(Value::Object(c)) = doc.get("credentials") {
        creds = merge_creds(creds, c);
    }
    let enc = encrypt_creds(&app, &creds);
    let mut cfg = doc
        .get("config")
        .and_then(|v| v.as_object())
        .cloned()
        .unwrap_or_default();
    cfg.remove("kind");
    let sched = doc
        .get("schedule")
        .and_then(|v| v.as_object())
        .cloned()
        .unwrap_or_default();
    let id = crate::ids::new("src");
    let now = db::now_str();
    let enabled = bool_field(&doc, "enabled");
    let next = next_run(&sched, chrono::Utc::now(), enabled);
    let (i, name, kind, mode, mass) = (
        id.clone(),
        str_field(&doc, "name").trim().to_string(),
        str_field(&doc, "kind"),
        str_field(&doc, "mode"),
        bool_field(&doc, "allow_mass_unpublish"),
    );
    app.db
        .write(move |tx| {
            tx.execute(
                "INSERT INTO import_sources (id, name, kind, enabled, schedule, mode, allow_mass_unpublish, config, credentials_enc, created_at, updated_at, next_run_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                params![i, name, kind, enabled as i64, Value::Object(sched).to_string(), mode, mass as i64,
                    Value::Object(cfg).to_string(), enc, now, now, next],
            )?;
            Ok(())
        })
        .await?;
    let s = load(&app, &id).await?;
    Ok(json_response(201, &source_json(&app, &s).await?))
}

pub async fn h_get(
    State(app): State<App>,
    Path(id): Path<String>,
    method: Method,
    headers: HeaderMap,
) -> Res {
    admin_guard(&app, &headers, &method, "admin").await?;
    let s = load(&app, &id).await?;
    Ok(ok(&source_json(&app, &s).await?))
}

pub async fn h_patch(
    State(app): State<App>,
    Path(id): Path<String>,
    method: Method,
    headers: HeaderMap,
    body: Bytes,
) -> Res {
    admin_guard(&app, &headers, &method, "admin").await?;
    let s = load(&app, &id).await?;
    let mut v = Value::Object(read_json_object(&headers, &body)?);
    crate::model::norm_numbers(&mut v);
    let Value::Object(mut patch) = v else {
        unreachable!()
    };
    if let Some(k) = patch.get("kind") {
        if k.as_str() != Some(s.kind.as_str()) {
            return Err(Problem::new(
                "validation_failed",
                "The kind of a source cannot change; create a new source.",
            ));
        }
    }
    let cred_patch = patch.remove("credentials");
    let mut merged = json!({"name": s.name, "kind": s.kind, "enabled": s.enabled, "schedule": s.schedule,
        "mode": s.mode, "allow_mass_unpublish": s.allow_mass, "config": s.config});
    crate::catalog::merge_patch(&mut merged, &Value::Object(patch));
    let Value::Object(mut merged) = merged else {
        unreachable!()
    };
    validate_source(&app, &mut merged).await?;
    let mut creds = creds_of(&app, &s);
    match cred_patch {
        None => {}
        Some(Value::Object(m)) => creds = merge_creds(creds, &m),
        Some(_) => creds = Creds::default(),
    }
    let enc = encrypt_creds(&app, &creds);
    let mut cfg = merged
        .get("config")
        .and_then(|v| v.as_object())
        .cloned()
        .unwrap_or_default();
    cfg.remove("kind");
    let sched = merged
        .get("schedule")
        .and_then(|v| v.as_object())
        .cloned()
        .unwrap_or_default();
    let enabled = bool_field(&merged, "enabled");
    let next = next_run(&sched, chrono::Utc::now(), enabled);
    let fingerprint = if Value::Object(cfg.clone()) != Value::Object(s.config.clone()) {
        None
    } else {
        s.fingerprint.clone()
    };
    let (sid, name, mode, mass) = (
        s.id.clone(),
        str_field(&merged, "name").trim().to_string(),
        str_field(&merged, "mode"),
        bool_field(&merged, "allow_mass_unpublish"),
    );
    app.db
        .write(move |tx| {
            tx.execute(
                "UPDATE import_sources SET name = ?, enabled = ?, schedule = ?, mode = ?, allow_mass_unpublish = ?, config = ?, credentials_enc = ?, updated_at = ?, next_run_at = ?, last_fingerprint = ? WHERE id = ?",
                params![name, enabled as i64, Value::Object(sched).to_string(), mode, mass as i64,
                    Value::Object(cfg).to_string(), enc, db::now_str(), next, fingerprint, sid],
            )?;
            Ok(())
        })
        .await?;
    let s = load(&app, &s.id).await?;
    Ok(ok(&source_json(&app, &s).await?))
}

pub async fn h_delete(
    State(app): State<App>,
    Path(id): Path<String>,
    method: Method,
    headers: HeaderMap,
) -> Res {
    admin_guard(&app, &headers, &method, "admin").await?;
    let n = app
        .db
        .write(move |tx| {
            Ok(tx.execute(
                "UPDATE import_sources SET deleted = 1, enabled = 0, credentials_enc = NULL, next_run_at = NULL WHERE id = ? AND deleted = 0",
                [&id],
            )?)
        })
        .await?;
    if n == 0 {
        return Err(not_found());
    }
    Ok(StatusCode::NO_CONTENT.into_response())
}

/// Queues an import run for a source.
async fn start_run(
    app: &App,
    s: &SourceRow,
    trigger: &str,
    force: bool,
    dry_run: bool,
) -> Result<Job> {
    let sid = s.id.clone();
    let running: Option<String> = app
        .db
        .read(move |c| {
            Ok(c.query_row(
                "SELECT id FROM jobs WHERE kind = 'import' AND source_id = ? AND status IN ('queued', 'running')",
                [&sid],
                |r| r.get(0),
            )
            .optional()?)
        })
        .await?;
    if let Some(r) = running {
        return Err(Problem::new(
            "conflict",
            format!("This source is already importing (run {r})."),
        ));
    }
    let payload = ImportPayload {
        source_id: s.id.clone(),
        force,
        options: ImportOptions {
            mode: s.mode.clone(),
            allow_mass_unpublish: s.allow_mass,
            dry_run,
            ..Default::default()
        },
        can_delete: true,
        ..Default::default()
    };
    jobs::create(
        app,
        JobSpec {
            kind: "import".into(),
            owner_type: "source".into(),
            owner_id: s.id.clone(),
            source_id: s.id.clone(),
            trigger: trigger.into(),
            payload: serde_json::to_value(&payload).unwrap_or(Value::Null),
            ..Default::default()
        },
    )
    .await
}

pub async fn h_run(
    State(app): State<App>,
    Path(id): Path<String>,
    method: Method,
    headers: HeaderMap,
    body: Bytes,
) -> Res {
    admin_guard(&app, &headers, &method, "admin").await?;
    if app.cfg.demo {
        return Err(Problem::new(
            "forbidden",
            "Scheduled imports from other servers are switched off. This is not possible in the demo.",
        )
        .extension("x-obx-demo", serde_json::Value::Bool(true)));
    }
    let s = load(&app, &id).await?;
    let b = if body.iter().all(|c| c.is_ascii_whitespace()) {
        Map::new()
    } else {
        read_json_object(&headers, &body)?
    };
    let job = start_run(
        &app,
        &s,
        "manual_run",
        bool_field(&b, "force"),
        bool_field(&b, "dry_run"),
    )
    .await?;
    Ok(json_response(
        202,
        &crate::imports::import_run_json(&app, &job).await?,
    ))
}

pub async fn h_test(
    State(app): State<App>,
    Path(id): Path<String>,
    method: Method,
    headers: HeaderMap,
) -> Res {
    admin_guard(&app, &headers, &method, "admin").await?;
    let s = load(&app, &id).await?;
    let mut f = Fetcher::new(&app, &s)?;
    let listed = tokio::time::timeout(Duration::from_secs(60), f.list(&app))
        .await
        .unwrap_or_else(|_| {
            Err(FetchError::new(
                "the source did not answer within 60 seconds",
            ))
        });
    let mut out =
        json!({"ok": listed.is_ok(), "message": null, "host_key_fingerprint": null, "files": []});
    if let Some(hk) = f.host_key() {
        out["host_key_fingerprint"] = json!(hk);
    }
    match listed {
        Err(e) => out["message"] = json!(e.msg),
        Ok((files, _)) => {
            // No message on success: the UI says "Connected, N files found".
            out["files"] = files
                .iter()
                .take(100)
                .map(|f| json!({"name": f.name, "bytes": f.size, "modified_at": f.modified}))
                .collect();
        }
    }
    f.close().await;
    Ok(ok(&out))
}

// ---- schedule -------------------------------------------------------------------------

/// A wall-clock time in a zone; a time in a DST gap moves forward, an
/// ambiguous one takes the earlier instant (jiff's "compatible" rule).
fn local_at(
    tz: &jiff::tz::TimeZone,
    d: jiff::civil::Date,
    hh: i8,
    mm: i8,
) -> Option<jiff::ZonedDateTime> {
    d.at(hh.clamp(0, 23), mm.clamp(0, 59), 0, 0)
        .to_zoned_datetime(tz.clone())
        .ok()
}

fn to_chrono(z: &jiff::ZonedDateTime) -> Option<chrono::DateTime<chrono::Utc>> {
    let t = z.timestamp();
    chrono::DateTime::from_timestamp(t.as_second(), t.subsec_nanosecond().max(0) as u32)
}

/// The next scheduled time (None for manual or disabled).
pub fn next_run(
    sched: &Map<String, Value>,
    now: chrono::DateTime<chrono::Utc>,
    enabled: bool,
) -> Option<String> {
    use chrono::Timelike;
    if !enabled {
        return None;
    }
    let freq = sched
        .get("frequency")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let tz = sched
        .get("timezone")
        .and_then(|v| v.as_str())
        .filter(|t| !t.is_empty())
        .and_then(|t| jiff::tz::TimeZone::get(t).ok())
        .unwrap_or(jiff::tz::TimeZone::UTC);
    let (mut hh, mut mm) = (3i8, 0i8);
    if let Some(t) = sched.get("time").and_then(|v| v.as_str()) {
        if t.len() == 5 {
            hh = t[..2].parse().unwrap_or(3);
            mm = t[3..].parse().unwrap_or(0);
        }
    }
    if freq == "hourly" {
        let t =
            now.with_minute(0)?.with_second(0)?.with_nanosecond(0)? + chrono::Duration::hours(1);
        return Some(db::fmt_time(t));
    }
    let ts = jiff::Timestamp::new(now.timestamp(), now.timestamp_subsec_nanos() as i32).ok()?;
    let local = ts.to_zoned_datetime(tz.clone());
    let today = local.date();
    let next = match freq {
        "daily" => {
            let n = local_at(&tz, today, hh, mm)?;
            if n > local {
                n
            } else {
                local_at(&tz, today.tomorrow().ok()?, hh, mm)?
            }
        }
        "weekly" => {
            let wd = sched.get("weekday").and_then(|v| v.as_i64()).unwrap_or(1);
            let want = wd.rem_euclid(7) as i8; // 7 = Sunday = 0
            let mut d = today;
            let mut found = None;
            for _ in 0..15 {
                let n = local_at(&tz, d, hh, mm)?;
                if d.weekday().to_sunday_zero_offset() == want && n > local {
                    found = Some(n);
                    break;
                }
                d = d.tomorrow().ok()?;
            }
            found?
        }
        _ => return None,
    };
    to_chrono(&next).map(db::fmt_time)
}

/// Starts runs of sources whose next_run_at passed.
pub async fn schedule_due(app: &App) {
    let now = db::now_str();
    let due: Vec<(String, String)> = app
        .db
        .read(move |c| {
            let mut st = c.prepare("SELECT id, next_run_at FROM import_sources WHERE deleted = 0 AND enabled = 1 AND next_run_at IS NOT NULL AND next_run_at <= ?")?;
            let r = st
                .query_map([&now], |r| Ok((r.get(0)?, r.get(1)?)))?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            Ok(r)
        })
        .await
        .unwrap_or_default();
    for (id, prev) in due {
        let Ok(s) = load(app, &id).await else {
            continue;
        };
        let next = next_run(&s.schedule, chrono::Utc::now(), s.enabled);
        let sid = s.id.clone();
        let claimed = app
            .db
            .write(move |tx| {
                Ok(tx.execute(
                    "UPDATE import_sources SET next_run_at = ? WHERE id = ? AND next_run_at = ?",
                    params![next, sid, prev],
                )?)
            })
            .await
            .unwrap_or(0);
        if claimed != 1 {
            continue;
        }
        if let Err(p) = start_run(app, &s, "schedule", false, false).await {
            if p.obx_error != "conflict" {
                tracing::warn!(source = %s.id, error = %p.detail_str(), "scheduled import could not start");
            }
        }
    }
}

/// Runs `schedule_due` every 30 seconds.
pub fn start_scheduler(app: App) {
    // The demo never pulls from other servers (docs/demo.md).
    if app.cfg.demo {
        return;
    }
    tokio::spawn(async move {
        loop {
            schedule_due(&app).await;
            tokio::time::sleep(Duration::from_secs(30)).await;
        }
    });
}

// ---- fetching -----------------------------------------------------------------------------

#[derive(Debug, Clone)]
struct RemoteFile {
    name: String,
    size: i64,
    modified: Option<String>,
    tag: String,
}

#[derive(Debug)]
struct FetchError {
    unsafe_url: bool,
    msg: String,
}

impl FetchError {
    fn new(m: impl Into<String>) -> FetchError {
        FetchError {
            unsafe_url: false,
            msg: m.into(),
        }
    }
    fn from_problem(p: Problem) -> FetchError {
        FetchError {
            unsafe_url: p.obx_error == "unsafe_url",
            msg: p.detail_str().to_string(),
        }
    }
}

type FResult<T> = std::result::Result<T, FetchError>;

fn fingerprint_of(files: &[RemoteFile]) -> String {
    let mut fs: Vec<&RemoteFile> = files.iter().collect();
    fs.sort_by(|a, b| a.name.cmp(&b.name));
    let mut h = Sha256::new();
    for f in fs {
        h.update(format!(
            "{}\0{}\0{}\0{}\n",
            f.name,
            f.size,
            f.modified.as_deref().unwrap_or(""),
            f.tag
        ));
    }
    hex::encode(h.finalize())
}

fn base_name(p: &str) -> &str {
    p.trim_end_matches('/').rsplit('/').next().unwrap_or(p)
}

fn rfc3339_secs(t: chrono::DateTime<chrono::Utc>) -> String {
    t.to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
}

/// Strips user info and query strings from an error text.
fn scrub(e: impl std::fmt::Display) -> String {
    let s = e.to_string();
    static URL_RE: std::sync::LazyLock<regex::Regex> =
        std::sync::LazyLock::new(|| regex::Regex::new(r"https?://[^\s)]+").unwrap());
    URL_RE
        .replace_all(&s, |c: &regex::Captures| match url::Url::parse(&c[0]) {
            Ok(mut u) => {
                let _ = u.set_username("");
                let _ = u.set_password(None);
                u.set_query(None);
                u.to_string()
            }
            Err(_) => "(url)".into(),
        })
        .into_owned()
}

enum Fetcher {
    Https(Https),
    Sftp(Box<Sftp>),
    S3(S3),
}

impl Fetcher {
    fn new(app: &App, s: &SourceRow) -> Result<Fetcher> {
        let creds = creds_of(app, s);
        Ok(match s.kind.as_str() {
            "https_url" => Fetcher::Https(Https {
                cfg: s.config.clone(),
                creds,
                files: HashMap::new(),
            }),
            "sftp" => Fetcher::Sftp(Box::new(Sftp {
                source_id: s.id.clone(),
                cfg: s.config.clone(),
                creds,
                conn: None,
                seen: Arc::new(Mutex::new(String::new())),
            })),
            "s3" => Fetcher::S3(S3 {
                cfg: s.config.clone(),
                creds,
                store: None,
            }),
            k => {
                return Err(Problem::new(
                    "validation_failed",
                    format!("Unknown source kind {k}."),
                ));
            }
        })
    }

    async fn list(&mut self, app: &App) -> FResult<(Vec<RemoteFile>, String)> {
        let files = match self {
            Fetcher::Https(f) => f.list(app).await?,
            Fetcher::Sftp(f) => f.list(app).await?,
            Fetcher::S3(f) => f.list(app).await?,
        };
        let fp = fingerprint_of(&files);
        Ok((files, fp))
    }

    async fn open(&mut self, app: &App, f: &RemoteFile) -> FResult<Bytes> {
        match self {
            Fetcher::Https(h) => h
                .files
                .get(&f.name)
                .cloned()
                .ok_or_else(|| FetchError::new("not downloaded")),
            Fetcher::Sftp(s) => s.open(app, f).await,
            Fetcher::S3(s) => s.open(app, f).await,
        }
    }

    fn host_key(&self) -> Option<String> {
        match self {
            Fetcher::Sftp(s) => {
                let k = s.seen.lock().unwrap().clone();
                (!k.is_empty()).then_some(k)
            }
            _ => None,
        }
    }

    async fn close(&mut self) {
        if let Fetcher::Sftp(s) = self {
            if let Some((h, sftp)) = s.conn.take() {
                let _ = sftp.close().await;
                let _ = h
                    .disconnect(russh::Disconnect::ByApplication, "", "en")
                    .await;
            }
        }
    }
}

fn cfg_str(cfg: &Map<String, Value>, k: &str) -> String {
    cfg.get(k)
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string()
}

// ---- https --------------------------------------------------------------------------------

struct Https {
    cfg: Map<String, Value>,
    creds: Creds,
    files: HashMap<String, Bytes>,
}

impl Https {
    async fn get(&self, app: &App, raw: &str) -> FResult<Bytes> {
        let allow = app.cfg.allow_private_urls;
        let u = crate::safeurl::check(raw, allow)
            .await
            .map_err(FetchError::from_problem)?;
        let client = crate::safeurl::client_with_redirects(allow, Duration::from_secs(600), 5);
        let mut req = client.get(u);
        if let Some(h) = &self.creds.headers {
            for (k, v) in h {
                req = req.header(k.as_str(), v.as_str());
            }
        }
        let mut resp = req.send().await.map_err(|e| FetchError {
            unsafe_url: crate::safeurl::is_refused(&e),
            msg: format!("download failed: {}", scrub(&e)),
        })?;
        if resp.status() != reqwest::StatusCode::OK {
            return Err(FetchError::new(format!(
                "the server answered HTTP {}",
                resp.status().as_u16()
            )));
        }
        let mut buf = Vec::new();
        while let Some(chunk) = resp
            .chunk()
            .await
            .map_err(|e| FetchError::new(format!("download failed: {}", scrub(&e))))?
        {
            if (buf.len() + chunk.len()) as u64 > MAX_IMPORT_BYTES {
                return Err(FetchError::new(format!(
                    "the file is larger than {MAX_IMPORT_BYTES} bytes"
                )));
            }
            buf.extend_from_slice(&chunk);
        }
        Ok(Bytes::from(buf))
    }

    async fn list(&mut self, app: &App) -> FResult<Vec<RemoteFile>> {
        self.files.clear();
        let mut out = Vec::new();
        for k in ["url", "images_url"] {
            let raw = cfg_str(&self.cfg, k);
            if raw.is_empty() {
                continue;
            }
            let data = self.get(app, &raw).await?;
            let is_zip = data.starts_with(b"PK\x03\x04");
            let path = raw.split(['?', '#']).next().unwrap_or("");
            let mut name = base_name(path).to_string();
            let lower = name.to_lowercase();
            if k == "images_url" {
                name = "images.zip".into();
            } else if obx_format::importfmt::is_workbook_name(&name) {
                // The name decides (import-format.md §5.1).
                name = "products.xlsx".into();
            } else if is_zip && !lower.ends_with(".zip") {
                name = "package.zip".into();
            } else if !is_zip && !lower.ends_with(".csv") {
                name = "products.csv".into();
            }
            out.push(RemoteFile {
                name: name.clone(),
                size: data.len() as i64,
                modified: None,
                tag: crate::secure::sha256_hex(&data),
            });
            self.files.insert(name, data);
        }
        Ok(out)
    }
}

// ---- sftp ---------------------------------------------------------------------------------

struct SshHandler {
    pinned: String,
    seen: Arc<Mutex<String>>,
}

impl russh::client::Handler for SshHandler {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        key: &russh::keys::PublicKeyOrCertificate,
    ) -> std::result::Result<bool, Self::Error> {
        let fp = match key {
            russh::keys::PublicKeyOrCertificate::PublicKey { key, .. } => {
                key.fingerprint(russh::keys::HashAlg::Sha256).to_string()
            }
            russh::keys::PublicKeyOrCertificate::Certificate(c) => c
                .public_key()
                .fingerprint(russh::keys::HashAlg::Sha256)
                .to_string(),
        };
        *self.seen.lock().unwrap() = fp.clone();
        Ok(self.pinned.is_empty() || crate::secure::eq(&self.pinned, &fp))
    }
}

struct Sftp {
    source_id: String,
    cfg: Map<String, Value>,
    creds: Creds,
    conn: Option<(
        russh::client::Handle<SshHandler>,
        russh_sftp::client::SftpSession,
    )>,
    seen: Arc<Mutex<String>>,
}

impl Sftp {
    async fn connect(&mut self, app: &App) -> FResult<()> {
        if self.conn.is_some() {
            return Ok(());
        }
        let host = cfg_str(&self.cfg, "host");
        let user = cfg_str(&self.cfg, "username");
        let port = self.cfg.get("port").and_then(|v| v.as_u64()).unwrap_or(22) as u16;
        let addrs = crate::safeurl::check_host(&host, port, app.cfg.allow_private_urls)
            .await
            .map_err(FetchError::from_problem)?;
        let pinned = cfg_str(&self.cfg, "host_key_fingerprint");
        let key = match &self.creds.private_key {
            Some(pem) => Some(
                russh::keys::decode_secret_key(pem, self.creds.password.as_deref())
                    .map_err(|_| FetchError::new("the private key cannot be read"))?,
            ),
            None => None,
        };
        let mut stream = None;
        let mut last_err = String::new();
        for a in &addrs {
            match tokio::time::timeout(Duration::from_secs(15), tokio::net::TcpStream::connect(a))
                .await
            {
                Ok(Ok(s)) => {
                    stream = Some(s);
                    break;
                }
                Ok(Err(e)) => last_err = e.to_string(),
                Err(_) => last_err = "timed out".into(),
            }
        }
        let Some(stream) = stream else {
            return Err(FetchError::new(format!("cannot connect: {last_err}")));
        };
        let config = Arc::new(russh::client::Config {
            inactivity_timeout: Some(Duration::from_secs(120)),
            ..Default::default()
        });
        let handler = SshHandler {
            pinned: pinned.clone(),
            seen: self.seen.clone(),
        };
        let connected = tokio::time::timeout(
            Duration::from_secs(15),
            russh::client::connect_stream(config, stream, handler),
        )
        .await
        .map_err(|_| FetchError::new("ssh login failed: timed out"))?;
        let mut h = match connected {
            Ok(h) => h,
            Err(e) => {
                let seen = self.seen.lock().unwrap().clone();
                if !pinned.is_empty() && !seen.is_empty() && seen != pinned {
                    return Err(FetchError::new(format!(
                        "ssh login failed: host key {seen} does not match the pinned {pinned}"
                    )));
                }
                return Err(FetchError::new(format!("ssh login failed: {e}")));
            }
        };
        let authed = match key {
            Some(k) => {
                let hash = h.best_supported_rsa_hash().await.ok().flatten().flatten();
                h.authenticate_publickey(
                    user.clone(),
                    russh::keys::PrivateKeyWithHashAlg::new(Arc::new(k), hash),
                )
                .await
            }
            None => {
                h.authenticate_password(
                    user.clone(),
                    self.creds.password.clone().unwrap_or_default(),
                )
                .await
            }
        }
        .map_err(|e| FetchError::new(format!("ssh login failed: {e}")))?;
        if !authed.success() {
            return Err(FetchError::new(
                "ssh login failed: the server refused the credentials",
            ));
        }
        let ch = h
            .channel_open_session()
            .await
            .map_err(|e| FetchError::new(format!("sftp failed: {e}")))?;
        ch.request_subsystem(true, "sftp")
            .await
            .map_err(|e| FetchError::new(format!("sftp failed: {e}")))?;
        let sftp = russh_sftp::client::SftpSession::new(ch.into_stream())
            .await
            .map_err(|e| FetchError::new(format!("sftp failed: {e}")))?;
        self.conn = Some((h, sftp));
        let seen = self.seen.lock().unwrap().clone();
        if pinned.is_empty() && !self.source_id.is_empty() && !seen.is_empty() {
            // Trust on first use: pin the key we saw.
            self.cfg
                .insert("host_key_fingerprint".into(), Value::String(seen));
            let mut cfg = self.cfg.clone();
            cfg.remove("kind");
            let (cfg, id) = (Value::Object(cfg).to_string(), self.source_id.clone());
            let _ = app
                .db
                .write(move |tx| {
                    tx.execute(
                        "UPDATE import_sources SET config = ? WHERE id = ?",
                        params![cfg, id],
                    )?;
                    Ok(())
                })
                .await;
        }
        Ok(())
    }

    async fn list(&mut self, app: &App) -> FResult<Vec<RemoteFile>> {
        self.connect(app).await?;
        let (_, sftp) = self.conn.as_ref().unwrap();
        let root = cfg_str(&self.cfg, "path");
        let st = sftp
            .metadata(root.clone())
            .await
            .map_err(|_| FetchError::new(format!("path {root} not found")))?;
        let entry = |p: String, m: &russh_sftp::client::fs::Metadata| RemoteFile {
            name: p,
            size: m.len() as i64,
            modified: m
                .mtime
                .and_then(|t| chrono::DateTime::from_timestamp(t as i64, 0))
                .map(rfc3339_secs),
            tag: String::new(),
        };
        let mut out = Vec::new();
        if !st.is_dir() {
            out.push(entry(root, &st));
            return Ok(out);
        }
        let mut stack = vec![root];
        let mut n = 0usize;
        'walk: while let Some(dir) = stack.pop() {
            let Ok(rd) = sftp.read_dir(dir.clone()).await else {
                continue;
            };
            let mut entries: Vec<_> = rd.collect();
            entries.sort_by_key(|e| e.file_name().to_string());
            for e in entries {
                let p = e.path().to_string();
                let m = e.metadata();
                if m.is_dir() {
                    stack.push(p);
                    continue;
                }
                n += 1;
                if n > MAX_FILES {
                    break 'walk;
                }
                if !obx_format::importfmt::ignored(&p) {
                    out.push(entry(p, &m));
                }
            }
        }
        Ok(out)
    }

    async fn open(&mut self, app: &App, f: &RemoteFile) -> FResult<Bytes> {
        self.connect(app).await?;
        if f.size as u64 > MAX_IMPORT_BYTES {
            return Err(FetchError::new(format!(
                "{} is larger than {MAX_IMPORT_BYTES} bytes",
                f.name
            )));
        }
        let (_, sftp) = self.conn.as_ref().unwrap();
        sftp.read(f.name.clone())
            .await
            .map(Bytes::from)
            .map_err(|e| FetchError::new(e.to_string()))
    }
}

// ---- s3 -----------------------------------------------------------------------------------

/// object_store's HTTP client under the URL policy.
#[derive(Debug, Clone, Copy)]
struct SafeConnector {
    allow_private: bool,
}

impl object_store::client::HttpConnector for SafeConnector {
    fn connect(
        &self,
        _: &object_store::ClientOptions,
    ) -> object_store::Result<object_store::client::HttpClient> {
        Ok(object_store::client::HttpClient::new(
            crate::safeurl::client(self.allow_private, Duration::from_secs(600)),
        ))
    }
}

struct S3 {
    cfg: Map<String, Value>,
    creds: Creds,
    store: Option<Arc<dyn object_store::ObjectStore>>,
}

impl S3 {
    async fn connect(&mut self, app: &App) -> FResult<Arc<dyn object_store::ObjectStore>> {
        if let Some(s) = &self.store {
            return Ok(s.clone());
        }
        let allow = app.cfg.allow_private_urls;
        let mut region = cfg_str(&self.cfg, "region");
        let mut endpoint = cfg_str(&self.cfg, "endpoint");
        if endpoint.is_empty() {
            if region.is_empty() {
                region = "us-east-1".into();
            }
            endpoint = format!("https://s3.{region}.amazonaws.com");
        }
        if region.is_empty() {
            region = "us-east-1".into();
        }
        crate::safeurl::check(&endpoint, allow)
            .await
            .map_err(FetchError::from_problem)?;
        let path_style = self
            .cfg
            .get("path_style")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        let aws = endpoint.contains(".amazonaws.com");
        let mut b = object_store::aws::AmazonS3Builder::new()
            .with_bucket_name(cfg_str(&self.cfg, "bucket"))
            .with_region(region)
            .with_allow_http(allow)
            .with_http_connector(SafeConnector {
                allow_private: allow,
            });
        // AWS: virtual-hosted unless path style is asked for; any other
        // endpoint: path style (as minio's automatic lookup does).
        if !aws || path_style {
            b = b
                .with_endpoint(endpoint)
                .with_virtual_hosted_style_request(false);
        }
        match &self.creds.access_key_id {
            Some(k) => {
                b = b.with_access_key_id(k).with_secret_access_key(
                    self.creds.secret_access_key.clone().unwrap_or_default(),
                )
            }
            None => b = b.with_skip_signature(true),
        }
        let s: Arc<dyn object_store::ObjectStore> =
            Arc::new(b.build().map_err(|e| {
                FetchError::new(format!("the bucket cannot be used: {}", scrub(e)))
            })?);
        self.store = Some(s.clone());
        Ok(s)
    }

    async fn list(&mut self, app: &App) -> FResult<Vec<RemoteFile>> {
        use futures::StreamExt;
        let store = self.connect(app).await?;
        let prefix = cfg_str(&self.cfg, "prefix");
        let p = prefix.trim_matches('/');
        let path = (!p.is_empty()).then(|| object_store::path::Path::from(p));
        let mut stream = store.list(path.as_ref());
        let mut out = Vec::new();
        while let Some(m) = stream.next().await {
            let m = m.map_err(|e| FetchError::new(format!("listing failed: {}", scrub(e))))?;
            let key = m.location.to_string();
            if key.ends_with('/') || obx_format::importfmt::ignored(&key) {
                continue;
            }
            out.push(RemoteFile {
                name: key,
                size: m.size as i64,
                modified: Some(rfc3339_secs(m.last_modified)),
                tag: m.e_tag.unwrap_or_default().trim_matches('"').to_string(),
            });
            if out.len() > MAX_FILES {
                break;
            }
        }
        Ok(out)
    }

    async fn open(&mut self, app: &App, f: &RemoteFile) -> FResult<Bytes> {
        let store = self.connect(app).await?;
        if f.size as u64 > MAX_IMPORT_BYTES {
            return Err(FetchError::new(format!(
                "{} is larger than {MAX_IMPORT_BYTES} bytes",
                f.name
            )));
        }
        let r = store
            .get(&object_store::path::Path::from(f.name.as_str()))
            .await
            .map_err(|e| FetchError::new(scrub(e)))?;
        r.bytes().await.map_err(|e| FetchError::new(scrub(e)))
    }
}

// ---- turning a remote folder into import files ----------------------------------------------

/// Downloads a source into staged import files. Ok(true) when the remote
/// files match the last successful run (nothing to do).
pub async fn fetch_source(app: &App, job_id: &str, p: &mut ImportPayload) -> Result<bool> {
    let sid = p.source_id.clone();
    let s = app
        .db
        .read(move |c| load_source(c, &sid))
        .await?
        .ok_or_else(|| Problem::new("not_found", "The import source was deleted."))?;
    let mut f = Fetcher::new(app, &s)?;
    let out = tokio::time::timeout(
        Duration::from_secs(30 * 60),
        fetch_files(app, job_id, p, &s, &mut f),
    )
    .await
    .unwrap_or_else(|_| {
        Err(Problem::new(
            "service_unavailable",
            "Could not read the source: it took longer than 30 minutes.",
        ))
    });
    f.close().await;
    out
}

async fn fetch_files(
    app: &App,
    job_id: &str,
    p: &mut ImportPayload,
    s: &SourceRow,
    f: &mut Fetcher,
) -> Result<bool> {
    let (files, fp) = f.list(app).await.map_err(|e| {
        Problem::new(
            if e.unsafe_url {
                "unsafe_url"
            } else {
                "service_unavailable"
            },
            format!("Could not read the source: {}", e.msg),
        )
    })?;
    if !p.force && s.fingerprint.as_deref() == Some(fp.as_str()) {
        return Ok(true);
    }
    p.fingerprint = fp;
    let mut csvs = Vec::new();
    let mut zips = Vec::new();
    let (mut products_xlsx, mut assets_xlsx): (Option<RemoteFile>, Option<RemoteFile>) =
        (None, None);
    let mut images = Vec::new();
    for rf in files {
        let base = base_name(&rf.name).to_string();
        let lower = base.to_lowercase();
        if lower.ends_with(".csv") {
            csvs.push(rf);
        } else if lower.ends_with(".zip") {
            zips.push(rf);
        } else if lower == "products.xlsx" || lower == "assets.xlsx" {
            let dst = if lower == "assets.xlsx" {
                &mut assets_xlsx
            } else {
                &mut products_xlsx
            };
            if dst.is_some() {
                return Err(Problem::new(
                    "import_invalid",
                    format!("The source has more than one {lower}."),
                ));
            }
            *dst = Some(rf);
        } else if obx_format::importfmt::is_image(&base) {
            images.push((rf, base));
        }
    }
    for (rf, base) in images {
        stage(app, job_id, p, f, &rf, "images", &base).await?;
    }
    let (mut products_csv, mut assets_csv) = (None, None);
    let mut others = Vec::new();
    for c in csvs {
        match base_name(&c.name).to_lowercase().as_str() {
            "products.csv" => products_csv = Some(c),
            "assets.csv" => assets_csv = Some(c),
            _ => others.push(c),
        }
    }
    if products_csv.is_some() && products_xlsx.is_some() {
        return Err(Problem::new(
            "import_invalid",
            "The source has both products.csv and products.xlsx; keep one of them.",
        ));
    }
    if assets_csv.is_some() && assets_xlsx.is_some() {
        return Err(Problem::new(
            "import_invalid",
            "The source has both assets.csv and assets.xlsx; keep one of them.",
        ));
    }
    // The "only *.csv" fallback does not extend to workbooks (§5.1).
    if products_csv.is_none() && products_xlsx.is_none() && others.len() == 1 {
        products_csv = others.pop();
    }
    let has_products = products_csv.is_some() || products_xlsx.is_some();
    if let Some(rf) = &products_csv {
        stage(app, job_id, p, f, rf, "csv", "products.csv").await?;
    }
    if let Some(rf) = &products_xlsx {
        stage(app, job_id, p, f, rf, "csv", "products.xlsx").await?;
    }
    if let Some(rf) = &assets_csv {
        stage(app, job_id, p, f, rf, "assets_csv", "assets.csv").await?;
    }
    if let Some(rf) = &assets_xlsx {
        stage(app, job_id, p, f, rf, "assets_csv", "assets.xlsx").await?;
    }
    let n_zips = zips.len();
    for z in &zips {
        let base = base_name(&z.name).to_string();
        let field = if base.to_lowercase().contains("package") || (!has_products && n_zips == 1) {
            "package"
        } else {
            "images"
        };
        stage(app, job_id, p, f, z, field, &base).await?;
    }
    if p.files.is_empty() {
        return Err(Problem::new(
            "import_invalid",
            "The source contains no products.csv, products.xlsx, zip or images.",
        ));
    }
    Ok(false)
}

async fn stage(
    app: &App,
    job_id: &str,
    p: &mut ImportPayload,
    f: &mut Fetcher,
    rf: &RemoteFile,
    field: &str,
    name: &str,
) -> Result<()> {
    let data = f.open(app, rf).await.map_err(|e| {
        Problem::new(
            "service_unavailable",
            format!("Could not download {}: {}", rf.name, e.msg),
        )
    })?;
    if data.len() as u64 > MAX_IMPORT_BYTES {
        return Err(Problem::new(
            "payload_too_large",
            format!("{} is larger than {MAX_IMPORT_BYTES} bytes.", rf.name),
        ));
    }
    let name = crate::imports::sanitize_filename(name);
    let key = format!(
        "imports/{job_id}/{field}/{}-{name}",
        chrono::Utc::now().timestamp_subsec_nanos()
    );
    let sha = crate::secure::sha256_hex(&data);
    let n = data.len() as i64;
    app.store.put(&key, data).await.map_err(Problem::internal)?;
    p.files.push(ImportFile {
        field: field.into(),
        name,
        key,
        bytes: n,
        sha256: sha,
    });
    Ok(())
}

/// Records the fingerprint of a successful run.
pub async fn record_fingerprint(app: &App, source_id: &str, fp: &str) {
    if fp.is_empty() {
        return;
    }
    let (s, f) = (source_id.to_string(), fp.to_string());
    let _ = app
        .db
        .write(move |tx| {
            tx.execute(
                "UPDATE import_sources SET last_fingerprint = ? WHERE id = ?",
                params![f, s],
            )?;
            Ok(())
        })
        .await;
}

/// After an import job of a source: remember it as the last run.
pub async fn after_run(app: &App, job: &Job) {
    let Some(sid) = job.source_id.clone() else {
        return;
    };
    let id = job.id.clone();
    let _ = app
        .db
        .write(move |tx| {
            tx.execute(
                "UPDATE import_sources SET last_run_id = ? WHERE id = ?",
                params![id, sid],
            )?;
            Ok(())
        })
        .await;
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sched(v: Value) -> Map<String, Value> {
        v.as_object().unwrap().clone()
    }

    fn at(s: &str) -> chrono::DateTime<chrono::Utc> {
        db::parse_time(s).unwrap()
    }

    #[test]
    fn next_run_times() {
        let now = at("2026-11-25T10:20:00Z"); // a Wednesday
        assert_eq!(
            next_run(&sched(json!({"frequency": "manual"})), now, true),
            None
        );
        assert_eq!(
            next_run(&sched(json!({"frequency": "daily"})), now, false),
            None
        );
        assert_eq!(
            next_run(&sched(json!({"frequency": "hourly"})), now, true).as_deref(),
            Some("2026-11-25T11:00:00.000000Z")
        );
        assert_eq!(
            next_run(
                &sched(json!({"frequency": "daily", "time": "03:00"})),
                now,
                true
            )
            .as_deref(),
            Some("2026-11-26T03:00:00.000000Z")
        );
        assert_eq!(
            next_run(
                &sched(
                    json!({"frequency": "daily", "time": "12:00", "timezone": "Europe/Amsterdam"})
                ),
                now,
                true
            )
            .as_deref(),
            Some("2026-11-25T11:00:00.000000Z")
        );
        // Weekly on Monday (1) and on Sunday (7).
        assert_eq!(
            next_run(
                &sched(json!({"frequency": "weekly", "time": "03:00", "weekday": 1})),
                now,
                true
            )
            .as_deref(),
            Some("2026-11-30T03:00:00.000000Z")
        );
        assert_eq!(
            next_run(
                &sched(json!({"frequency": "weekly", "time": "03:00", "weekday": 7})),
                now,
                true
            )
            .as_deref(),
            Some("2026-11-29T03:00:00.000000Z")
        );
        // Wednesday later today.
        assert_eq!(
            next_run(
                &sched(json!({"frequency": "weekly", "time": "23:00", "weekday": 3})),
                now,
                true
            )
            .as_deref(),
            Some("2026-11-25T23:00:00.000000Z")
        );
        // Summer time in Amsterdam.
        assert_eq!(
            next_run(
                &sched(
                    json!({"frequency": "daily", "time": "02:30", "timezone": "Europe/Amsterdam"})
                ),
                at("2026-07-01T12:00:00Z"),
                true
            )
            .as_deref(),
            Some("2026-07-02T00:30:00.000000Z")
        );
    }

    #[test]
    fn credentials_merge() {
        let c = merge_creds(
            Creds::default(),
            json!({"password": "p", "headers": {"Authorization": "Bearer x"}})
                .as_object()
                .unwrap(),
        );
        assert_eq!(c.password.as_deref(), Some("p"));
        let c = merge_creds(c, json!({"access_key_id": "k"}).as_object().unwrap());
        assert_eq!(c.password.as_deref(), Some("p"));
        assert_eq!(c.access_key_id.as_deref(), Some("k"));
        let c = merge_creds(
            c,
            json!({"password": null, "headers": null})
                .as_object()
                .unwrap(),
        );
        assert!(c.password.is_none() && c.headers.is_none());
    }

    #[test]
    fn fingerprints_ignore_order() {
        let f = |n: &str, s: i64| RemoteFile {
            name: n.into(),
            size: s,
            modified: Some("2026-01-01T00:00:00Z".into()),
            tag: String::new(),
        };
        let a = fingerprint_of(&[f("b.csv", 2), f("a.png", 1)]);
        assert_eq!(a, fingerprint_of(&[f("a.png", 1), f("b.csv", 2)]));
        assert_ne!(a, fingerprint_of(&[f("a.png", 1), f("b.csv", 3)]));
    }

    #[test]
    fn errors_are_scrubbed() {
        let s =
            scrub("error sending request for url (https://user:pw@example.com/x.csv?token=abc)");
        assert!(!s.contains("pw") && !s.contains("abc"), "{s}");
    }
}
