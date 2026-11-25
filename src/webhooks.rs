//! Webhooks (protocol.md §10): API clients subscribe to catalog and grant
//! events, the brand to its own events (admin API). Deliveries are queued
//! in `webhook_deliveries`, signed, sent without redirects under the URL
//! policy, retried with backoff for 24 hours; a subscription failing for 72
//! hours is disabled.

use std::collections::HashMap;

use axum::body::Bytes;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, Method, StatusCode};
use axum::response::IntoResponse;
use rusqlite::{Connection, OptionalExtension, Row as SqlRow, params};
use serde_json::{Map, Value, json};

use crate::app::App;
use crate::db;
use crate::http::admin::admin_guard;
use crate::http::protocol::{protocol_auth, viewer_from_tag};
use crate::http::{Res, json as json_resp, limit_param, ok, read_json_object, with_headers};
use crate::problem::{Problem, Result};
use crate::webhook_proto::{self as proto, BRAND_EVENTS, CLIENT_EVENTS};

#[derive(Debug, Clone)]
pub struct Webhook {
    pub id: String,
    pub owner_type: String,
    pub owner_id: Option<String>,
    pub url: String,
    pub events: Vec<String>,
    pub secret_enc: String,
    pub status: String,
    pub created_at: String,
    pub last_delivery_at: Option<String>,
    pub last_status: Option<i64>,
    #[allow(dead_code)]
    pub failing_since: Option<String>,
    pub last_notified_seq: i64,
}

const COLS: &str = "id, owner_type, owner_id, url, events, secret_enc, status, created_at, last_delivery_at, last_status, failing_since, last_notified_seq";

fn scan(r: &SqlRow) -> rusqlite::Result<Webhook> {
    let events: String = r.get(4)?;
    Ok(Webhook {
        id: r.get(0)?,
        owner_type: r.get(1)?,
        owner_id: r.get(2)?,
        url: r.get(3)?,
        events: events.split_whitespace().map(String::from).collect(),
        secret_enc: r.get(5)?,
        status: r.get(6)?,
        created_at: r.get(7)?,
        last_delivery_at: r.get(8)?,
        last_status: r.get(9)?,
        failing_since: r.get(10)?,
        last_notified_seq: r.get(11)?,
    })
}

impl Webhook {
    /// The WebhookSubscription document; the secret only when just created.
    pub fn json(&self, secret: Option<&str>) -> Value {
        json!({"id": self.id, "url": self.url, "events": self.events, "secret": secret, "status": self.status,
            "created_at": self.created_at, "last_delivery_at": self.last_delivery_at, "last_status": self.last_status})
    }
}

pub fn list(c: &Connection, owner_type: &str, owner_id: Option<&str>) -> Result<Vec<Webhook>> {
    let mut q = format!("SELECT {COLS} FROM webhooks WHERE owner_type = ?");
    let mut args = vec![owner_type.to_string()];
    if let Some(o) = owner_id {
        q.push_str(" AND owner_id = ?");
        args.push(o.to_string());
    }
    q.push_str(" ORDER BY created_at");
    let mut st = c.prepare(&q)?;
    let r = st
        .query_map(rusqlite::params_from_iter(args.iter()), scan)?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(r)
}

fn load_any(c: &Connection, id: &str) -> Result<Option<Webhook>> {
    Ok(c.query_row(
        &format!("SELECT {COLS} FROM webhooks WHERE id = ?"),
        [id],
        scan,
    )
    .optional()?)
}

/// The subscription id of owner, or not_found (another owner's id is not
/// found either: S-ISO-1).
pub fn load(c: &Connection, id: &str, owner_type: &str, owner_id: Option<&str>) -> Result<Webhook> {
    match load_any(c, id)? {
        Some(h)
            if h.owner_type == owner_type
                && owner_id.is_none_or(|o| h.owner_id.as_deref() == Some(o)) =>
        {
            Ok(h)
        }
        _ => Err(Problem::new("not_found", "Webhook not found.")),
    }
}

async fn check_url(app: &App, u: &str) -> Result<()> {
    if u.len() > 2048 {
        return Err(
            Problem::new("validation_failed", "The URL is too long.").field(
                "/url",
                "validation_failed",
                "too long",
            ),
        );
    }
    crate::safeurl::check(u, app.cfg.allow_private_urls).await?;
    Ok(())
}

/// Validates and stores a subscription; the secret is returned once.
async fn create(
    app: &App,
    owner_type: &'static str,
    owner_id: Option<String>,
    doc: Map<String, Value>,
    allowed: &[&str],
    max: usize,
) -> Result<Value> {
    let url = doc
        .get("url")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let events: Option<Vec<String>> = doc.get("events").and_then(|v| v.as_array()).map(|a| {
        a.iter()
            .map(|x| x.as_str().unwrap_or("").to_string())
            .collect()
    });
    let events = match events {
        Some(e) if !url.is_empty() && !e.is_empty() => e,
        _ => {
            return Err(
                Problem::new("validation_failed", "url and events are required.").field(
                    "/url",
                    "validation_failed",
                    "required",
                ),
            );
        }
    };
    let mut seen: Vec<&str> = vec![];
    for e in &events {
        if !allowed.contains(&e.as_str()) || seen.contains(&e.as_str()) {
            return Err(Problem::new(
                "validation_failed",
                format!("Unknown or repeated event {e:?}."),
            )
            .field("/events", "validation_failed", "unknown event"));
        }
        seen.push(e);
    }
    check_url(app, &url).await?;
    let secret = crate::secure::token(proto::SECRET_PREFIX);
    let enc = app.keys.encrypt(secret.as_bytes());
    let h = app
        .db
        .write(move |tx| {
            let n = list(tx, owner_type, owner_id.as_deref())?.len();
            if max > 0 && n >= max {
                return Err(Problem::new(
                    "conflict",
                    format!("At most {max} webhook subscriptions."),
                ));
            }
            let seq: i64 = tx.query_row("SELECT COALESCE(MAX(seq), 0) FROM changes", [], |r| r.get(0))?;
            let id = crate::ids::new("whk");
            tx.execute(
                "INSERT INTO webhooks (id, owner_type, owner_id, url, events, secret_enc, status, created_at, last_notified_seq) VALUES (?, ?, ?, ?, ?, ?, 'active', ?, ?)",
                params![id, owner_type, owner_id, url, events.join(" "), enc, db::now_str(), seq],
            )?;
            load_any(tx, &id)?.ok_or_else(|| Problem::internal("webhook vanished"))
        })
        .await?;
    Ok(h.json(Some(&secret)))
}

fn delete_sync(c: &Connection, id: &str) -> Result<()> {
    c.execute("DELETE FROM webhooks WHERE id = ?", [id])?;
    c.execute("DELETE FROM webhook_deliveries WHERE webhook_id = ?", [id])?;
    Ok(())
}

// ---- protocol endpoints ----------------------------------------------------------------

pub async fn h_list(State(app): State<App>, headers: HeaderMap) -> Res {
    let (v, hs) = protocol_auth(&app, &headers, "catalog:read", false).await?;
    let items = app
        .db
        .read(move |c| {
            Ok(list(c, "client", Some(&v.client_row_id))?
                .iter()
                .map(|h| h.json(None))
                .collect::<Vec<_>>())
        })
        .await?;
    Ok(with_headers(ok(&json!({"items": items})), &hs))
}

pub async fn h_create(State(app): State<App>, headers: HeaderMap, body: Bytes) -> Res {
    let (v, hs) = protocol_auth(&app, &headers, "catalog:read", false).await?;
    let doc = read_json_object(&headers, &body)?;
    let out = create(
        &app,
        "client",
        Some(v.client_row_id),
        doc,
        &CLIENT_EVENTS,
        5,
    )
    .await?;
    Ok(with_headers(json_resp(201, &out), &hs))
}

pub async fn h_delete(State(app): State<App>, Path(id): Path<String>, headers: HeaderMap) -> Res {
    let (v, hs) = protocol_auth(&app, &headers, "catalog:read", false).await?;
    app.db
        .write(move |tx| {
            let h = load(tx, &id, "client", Some(&v.client_row_id))?;
            delete_sync(tx, &h.id)
        })
        .await?;
    Ok(with_headers(StatusCode::NO_CONTENT.into_response(), &hs))
}

pub async fn h_test(State(app): State<App>, Path(id): Path<String>, headers: HeaderMap) -> Res {
    let (v, hs) = protocol_auth(&app, &headers, "catalog:read", false).await?;
    let h = app
        .db
        .read(move |c| load(c, &id, "client", Some(&v.client_row_id)))
        .await?;
    let d = deliver_now(&app, &h, proto::TEST_EVENT, json!({})).await;
    Ok(with_headers(
        ok(&json!({"delivered": d["success"], "status": d["status_code"]})),
        &hs,
    ))
}

// ---- admin (brand) endpoints -----------------------------------------------------------

pub async fn admin_list(State(app): State<App>, method: Method, headers: HeaderMap) -> Res {
    admin_guard(&app, &headers, &method, "admin").await?;
    let items = app
        .db
        .read(|c| {
            Ok(list(c, "brand", None)?
                .iter()
                .map(|h| h.json(None))
                .collect::<Vec<_>>())
        })
        .await?;
    Ok(ok(&json!({"items": items})))
}

pub async fn admin_create(
    State(app): State<App>,
    method: Method,
    headers: HeaderMap,
    body: Bytes,
) -> Res {
    admin_guard(&app, &headers, &method, "admin").await?;
    let doc = read_json_object(&headers, &body)?;
    let out = create(&app, "brand", None, doc, &BRAND_EVENTS, 20).await?;
    Ok(json_resp(201, &out))
}

pub async fn admin_patch(
    State(app): State<App>,
    Path(id): Path<String>,
    method: Method,
    headers: HeaderMap,
    body: Bytes,
) -> Res {
    admin_guard(&app, &headers, &method, "admin").await?;
    let doc = read_json_object(&headers, &body)?;
    let out = app
        .db
        .write(move |tx| {
            let mut h = load(tx, &id, "brand", None)?;
            if let Some(ev) = doc.get("events").filter(|v| !v.is_null()) {
                let list: Vec<String> = ev
                    .as_array()
                    .ok_or_else(|| Problem::new("validation_failed", "events must be a list."))?
                    .iter()
                    .map(|x| x.as_str().unwrap_or("").to_string())
                    .collect();
                if let Some(bad) = list.iter().find(|e| !BRAND_EVENTS.contains(&e.as_str())) {
                    return Err(Problem::new(
                        "validation_failed",
                        format!("Unknown event {bad:?}."),
                    ));
                }
                if list.is_empty() {
                    return Err(Problem::new("validation_failed", "Choose at least one event."));
                }
                h.events = list;
            }
            match doc.get("status").and_then(|v| v.as_str()).unwrap_or("") {
                "" => {}
                s @ ("active" | "disabled") => h.status = s.to_string(),
                _ => {
                    return Err(Problem::new(
                        "validation_failed",
                        "status must be active or disabled.",
                    ));
                }
            }
            tx.execute(
                "UPDATE webhooks SET events = ?, status = ?, failing_since = CASE WHEN ? = 'active' THEN NULL ELSE failing_since END WHERE id = ?",
                params![h.events.join(" "), h.status, h.status, h.id],
            )?;
            Ok(h.json(None))
        })
        .await?;
    Ok(ok(&out))
}

pub async fn admin_delete(
    State(app): State<App>,
    Path(id): Path<String>,
    method: Method,
    headers: HeaderMap,
) -> Res {
    admin_guard(&app, &headers, &method, "admin").await?;
    app.db
        .write(move |tx| {
            let h = load(tx, &id, "brand", None)?;
            delete_sync(tx, &h.id)
        })
        .await?;
    Ok(StatusCode::NO_CONTENT.into_response())
}

pub async fn admin_test(
    State(app): State<App>,
    Path(id): Path<String>,
    method: Method,
    headers: HeaderMap,
) -> Res {
    admin_guard(&app, &headers, &method, "admin").await?;
    let h = app.db.read(move |c| load(c, &id, "brand", None)).await?;
    Ok(ok(
        &deliver_now(&app, &h, proto::TEST_EVENT, json!({})).await
    ))
}

#[derive(serde::Serialize, serde::Deserialize)]
struct DeliveryCursor {
    c: String,
    i: String,
}

pub async fn admin_deliveries(
    State(app): State<App>,
    Path(id): Path<String>,
    Query(q): Query<HashMap<String, String>>,
    method: Method,
    headers: HeaderMap,
) -> Res {
    admin_guard(&app, &headers, &method, "admin").await?;
    let limit = limit_param(&q, 50, 200)?;
    let cur = match q.get("cursor").filter(|c| !c.is_empty()) {
        None => None,
        Some(c) => Some(
            app.decode_cursor::<DeliveryCursor>("deliveries", c)
                .ok_or_else(|| Problem::new("cursor_invalid", "The cursor is not valid."))?,
        ),
    };
    let (items, next) = app
        .db
        .read(move |c| {
            let h = load(c, &id, "brand", None)?;
            let mut sql = "SELECT id, event_id, event_type, created_at, at, status_code, duration_ms, attempt, status, error FROM webhook_deliveries WHERE webhook_id = ? AND created_at > ?".to_string();
            let mut args: Vec<String> = vec![
                h.id,
                db::fmt_time(chrono::Utc::now() - chrono::Duration::days(7)),
            ];
            if let Some(k) = cur {
                sql.push_str(" AND (created_at < ? OR (created_at = ? AND id < ?))");
                args.extend([k.c.clone(), k.c, k.i]);
            }
            sql.push_str(&format!(" ORDER BY created_at DESC, id DESC LIMIT {}", limit + 1));
            let mut st = c.prepare(&sql)?;
            let rows = st
                .query_map(rusqlite::params_from_iter(args.iter()), |r| {
                    let created: String = r.get(3)?;
                    let at: Option<String> = r.get(4)?;
                    let status: String = r.get(8)?;
                    Ok((
                        created.clone(),
                        r.get::<_, String>(0)?,
                        delivery_json(
                            &r.get::<_, String>(0)?,
                            &r.get::<_, String>(1)?,
                            &r.get::<_, String>(2)?,
                            at.as_deref().unwrap_or(&created),
                            r.get::<_, Option<i64>>(5)?,
                            r.get::<_, Option<i64>>(6)?.unwrap_or(0),
                            r.get(7)?,
                            status == "delivered",
                            r.get::<_, Option<String>>(9)?,
                        ),
                    ))
                })?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            Ok(rows)
        })
        .await
        .map(|mut rows| {
            let next = (rows.len() > limit).then(|| {
                rows.truncate(limit);
                let (c, i, _) = rows.last().unwrap();
                app.encode_cursor("deliveries", &DeliveryCursor { c: c.clone(), i: i.clone() })
            });
            (rows.into_iter().map(|(_, _, v)| v).collect::<Vec<_>>(), next)
        })?;
    Ok(ok(&json!({"items": items, "next_cursor": next})))
}

// ---- events -----------------------------------------------------------------------------

fn delivery_json(
    id: &str,
    event_id: &str,
    typ: &str,
    at: &str,
    code: Option<i64>,
    dur: i64,
    attempt: i64,
    success: bool,
    error: Option<String>,
) -> Value {
    json!({"id": id, "event_id": event_id, "event_type": typ, "at": at, "status_code": code, "duration_ms": dur,
        "attempt": attempt, "success": success, "error": error})
}

fn enqueue(c: &Connection, h: &Webhook, typ: &str, data: &Value) -> Result<()> {
    let now = db::now_str();
    let eid = crate::ids::new("evt");
    let evt = proto::event(&eid, typ, &now, data.clone());
    c.execute(
        "INSERT INTO webhook_deliveries (id, webhook_id, event_id, event_type, payload, status, next_attempt_at, created_at) VALUES (?, ?, ?, ?, ?, 'pending', ?, ?)",
        params![crate::ids::new("dlv"), h.id, eid, typ, evt.to_string(), now, now],
    )?;
    Ok(())
}

/// Queues an event for every active subscription of owner that wants it.
pub fn event_to(
    c: &Connection,
    owner_type: &str,
    owner_id: Option<&str>,
    typ: &str,
    data: &Value,
) -> Result<usize> {
    let mut n = 0;
    for h in list(c, owner_type, owner_id)? {
        if h.status == "active" && h.events.iter().any(|e| e == typ) {
            enqueue(c, &h, typ, data)?;
            n += 1;
        }
    }
    Ok(n)
}

/// Sends an event to the brand's own webhooks (in the background).
pub fn brand_event(app: &App, typ: &'static str, data: Value) {
    let a = app.clone();
    tokio::spawn(async move {
        let queued =
            a.db.write(move |tx| event_to(tx, "brand", None, typ, &data))
                .await
                .unwrap_or(0);
        if queued > 0 {
            a.webhooks_due.notify_one();
        }
    });
}

/// Sends an event to one API client's webhooks (in the background).
pub fn client_event(app: &App, client_row_id: &str, typ: &'static str, data: Value) {
    let (a, cid) = (app.clone(), client_row_id.to_string());
    tokio::spawn(async move {
        let queued =
            a.db.write(move |tx| event_to(tx, "client", Some(&cid), typ, &data))
                .await
                .unwrap_or(0);
        if queued > 0 {
            a.webhooks_due.notify_one();
        }
    });
}

/// Tells every active client of a retailer that its grant changed.
pub fn retailer_grant_event(app: &App, retailer_id: &str) {
    let (a, rid) = (app.clone(), retailer_id.to_string());
    tokio::spawn(async move {
        let queued =
            a.db.write(move |tx| {
                let Some(r) = crate::http::load_retailer(tx, &rid)? else {
                    return Ok(0);
                };
                let s = crate::settings::Settings::load(tx)?;
                let g = crate::http::grant_of(&s, &r);
                let ids: Vec<String> = {
                    let mut st = tx.prepare(
                        "SELECT id FROM api_clients WHERE retailer_id = ? AND status = 'active'",
                    )?;
                    st.query_map([&rid], |r| r.get(0))?
                        .collect::<rusqlite::Result<_>>()?
                };
                let mut n = 0;
                for id in ids {
                    n += event_to(
                        tx,
                        "client",
                        Some(&id),
                        "grant.updated",
                        &json!({"grant": g}),
                    )?;
                }
                Ok(n)
            })
            .await
            .unwrap_or(0);
        if queued > 0 {
            a.webhooks_due.notify_one();
        }
    });
}

/// The event that follows a finished job (node-go afterJob).
pub fn after_job(app: &App, job_id: &str) {
    let (a, id) = (app.clone(), job_id.to_string());
    tokio::spawn(async move {
        let Ok(Some(j)) = crate::jobs::load_job(&a, &id).await else {
            return;
        };
        match j.kind.as_str() {
            "import" => {
                let counts = crate::imports::import_run_json(&a, &j)
                    .await
                    .ok()
                    .and_then(|r| r.get("counts").cloned())
                    .unwrap_or(Value::Null);
                brand_event(
                    &a,
                    "import_run.completed",
                    json!({"import_run_id": j.id, "status": j.status, "counts": counts}),
                );
            }
            "batch" => brand_event(
                &a,
                "ingest_job.completed",
                json!({"job_id": j.id, "status": j.status}),
            ),
            "export" => {
                if let Some(o) = &j.owner_id {
                    client_event(
                        &a,
                        o,
                        "export.completed",
                        json!({"export_id": j.id, "status": j.status}),
                    );
                }
            }
            _ => {}
        }
    });
}

/// Queues changes.available for client subscriptions that have relevant
/// new change entries (one pending first attempt at a time).
fn notify_changes(c: &Connection) -> Result<usize> {
    let hooks: Vec<Webhook> = {
        let mut st = c.prepare(&format!(
            "SELECT {COLS} FROM webhooks WHERE owner_type = 'client' AND status = 'active'"
        ))?;
        st.query_map([], scan)?.collect::<rusqlite::Result<_>>()?
    };
    let mut queued = 0;
    for h in hooks {
        let Some(owner) = h.owner_id.as_deref() else {
            continue;
        };
        if !h.events.iter().any(|e| e == "changes.available") {
            continue;
        }
        let Ok(v) = viewer_from_tag(c, &format!("c.{owner}")) else {
            continue;
        };
        let (bf, bargs) = v.brand_filter("brand_id");
        let mut args: Vec<rusqlite::types::Value> =
            vec![h.last_notified_seq.into(), v.retailer_id.clone().into()];
        args.extend(bargs.into_iter().map(Into::into));
        let latest: Option<i64> = c.query_row(
            &format!("SELECT MAX(seq) FROM changes WHERE seq > ? AND (retailer_id = ? OR (brand_id IS NOT NULL{bf}))"),
            rusqlite::params_from_iter(args.iter()),
            |r| r.get(0),
        )?;
        let Some(latest) = latest else { continue };
        let pending: i64 = c.query_row(
            "SELECT COUNT(*) FROM webhook_deliveries WHERE webhook_id = ? AND event_type = 'changes.available' AND status = 'pending' AND attempt = 0",
            [&h.id],
            |r| r.get(0),
        )?;
        if pending == 0 {
            enqueue(c, &h, "changes.available", &json!({"latest_seq": latest}))?;
            queued += 1;
        }
        c.execute(
            "UPDATE webhooks SET last_notified_seq = ? WHERE id = ?",
            params![latest, h.id],
        )?;
    }
    Ok(queued)
}

/// Removes URLs (they may carry tokens) from error text.
fn scrub(s: &str) -> String {
    let mut out = String::new();
    for w in s.split(' ') {
        if !out.is_empty() {
            out.push(' ');
        }
        let t = w.trim_matches(|c| c == '(' || c == ')' || c == '"');
        if t.starts_with("http://") || t.starts_with("https://") {
            out.push_str("<url>");
        } else {
            out.push_str(w);
        }
    }
    out
}

/// Posts a signed payload; (status code, duration ms, error).
async fn post(
    app: &App,
    h: &Webhook,
    event_id: &str,
    payload: &str,
) -> (Option<i64>, i64, Option<String>) {
    let Some(secret) = app
        .keys
        .decrypt(&h.secret_enc)
        .and_then(|b| String::from_utf8(b).ok())
    else {
        return (
            None,
            0,
            Some("webhook secret unreadable (was OBX_SECRET_KEY changed?)".into()),
        );
    };
    let start = std::time::Instant::now();
    if let Err(p) = crate::safeurl::check(&h.url, app.cfg.allow_private_urls).await {
        return (None, 0, Some(format!("refused: {}", p.detail_str())));
    }
    let ts = chrono::Utc::now().timestamp().to_string();
    let sig = proto::signature(&secret, &ts, payload.as_bytes());
    let client = crate::safeurl::client(
        app.cfg.allow_private_urls,
        std::time::Duration::from_secs(10),
    );
    let res = client
        .post(&h.url)
        .header("content-type", "application/json")
        .header(proto::HEADER_ID, event_id)
        .header(proto::HEADER_TIMESTAMP, &ts)
        .header(proto::HEADER_SIGNATURE, sig)
        .body(payload.to_string())
        .send()
        .await;
    let dur = start.elapsed().as_millis() as i64;
    match res {
        Err(e) => {
            if crate::safeurl::is_refused(&e) {
                return (None, dur, Some(crate::safeurl::Refused.to_string()));
            }
            let mut chain = String::new();
            let mut src = std::error::Error::source(&e);
            while let Some(s) = src {
                chain.push_str(": ");
                chain.push_str(&s.to_string());
                src = s.source();
            }
            let msg = format!("{}{chain}", e.without_url());
            (None, dur, Some(format!("request failed: {}", scrub(&msg))))
        }
        Ok(r) => {
            let code = r.status().as_u16() as i64;
            // Read (and drop) at most 64 KiB of the answer.
            let mut r = r;
            let mut n = 0usize;
            while let Ok(Some(chunk)) = r.chunk().await {
                n += chunk.len();
                if n > 64 << 10 {
                    break;
                }
            }
            if (200..300).contains(&code) {
                (Some(code), dur, None)
            } else {
                (
                    Some(code),
                    dur,
                    Some(format!("receiver answered HTTP {code}")),
                )
            }
        }
    }
}

fn record_status(c: &Connection, id: &str, code: Option<i64>, success: bool) -> Result<()> {
    let now = db::now_str();
    if success {
        c.execute(
            "UPDATE webhooks SET last_delivery_at = ?, last_status = ?, failing_since = NULL WHERE id = ?",
            params![now, code, id],
        )?;
        return Ok(());
    }
    c.execute(
        "UPDATE webhooks SET last_delivery_at = ?, last_status = ?, failing_since = COALESCE(failing_since, ?) WHERE id = ?",
        params![now, code, now, id],
    )?;
    c.execute(
        "UPDATE webhooks SET status = 'disabled' WHERE id = ? AND failing_since IS NOT NULL AND failing_since < ?",
        params![id, db::fmt_time(chrono::Utc::now() - chrono::Duration::hours(72))],
    )?;
    Ok(())
}

/// Sends one event now and records the delivery (webhook.test).
pub async fn deliver_now(app: &App, h: &Webhook, typ: &str, data: Value) -> Value {
    let now = db::now_str();
    let eid = crate::ids::new("evt");
    let payload = proto::event(&eid, typ, &now, data).to_string();
    let id = crate::ids::new("dlv");
    let (code, dur, err) = post(app, h, &eid, &payload).await;
    let ok = err.is_none();
    let at = db::now_str();
    let (i, hid, e, t, p, er, a2) = (
        id.clone(),
        h.id.clone(),
        eid.clone(),
        typ.to_string(),
        payload,
        err.clone(),
        at.clone(),
    );
    let _ = app
        .db
        .write(move |tx| {
            tx.execute(
                "INSERT INTO webhook_deliveries (id, webhook_id, event_id, event_type, payload, attempt, status, next_attempt_at, status_code, duration_ms, error, created_at, at) VALUES (?, ?, ?, ?, ?, 1, ?, ?, ?, ?, ?, ?, ?)",
                params![i, hid, e, t, p, if ok { "delivered" } else { "failed" }, a2, code, dur, er, a2, a2],
            )?;
            record_status(tx, &hid, code, ok)
        })
        .await;
    delivery_json(&id, &eid, typ, &at, code, dur, 1, ok, err)
}

/// The wait before attempt n+1 after n failed attempts: 30 s doubling, at
/// most 6 hours.
pub fn backoff(attempt: i64) -> chrono::Duration {
    let secs = (1i64 << attempt.clamp(0, 12)) * 15;
    chrono::Duration::seconds(secs.min(6 * 3600))
}

/// Sends pending deliveries whose time has come; returns how many.
pub async fn deliver_due(app: &App) -> usize {
    let now = db::now_str();
    let due: Vec<(String, String, String, String, i64, String)> = app
        .db
        .read(move |c| {
            let mut st = c.prepare("SELECT id, webhook_id, event_id, payload, attempt, created_at FROM webhook_deliveries WHERE status = 'pending' AND next_attempt_at <= ? ORDER BY next_attempt_at LIMIT 50")?;
            let r = st
                .query_map([&now], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?, r.get(5)?)))?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            Ok(r)
        })
        .await
        .unwrap_or_default();
    let n = due.len();
    for (id, hook, eid, payload, attempt, created) in due {
        let hk = hook.clone();
        let h = app.db.read(move |c| load_any(c, &hk)).await.ok().flatten();
        let Some(h) = h.filter(|h| h.status == "active") else {
            let i = id.clone();
            let _ = app
                .db
                .write(move |tx| {
                    tx.execute("UPDATE webhook_deliveries SET status = 'failed', error = 'subscription disabled or deleted' WHERE id = ?", [&i])?;
                    Ok(())
                })
                .await;
            continue;
        };
        let (code, dur, err) = post(app, &h, &eid, &payload).await;
        let attempt = attempt + 1;
        let _ = app
            .db
            .write(move |tx| {
                let now = db::now_str();
                match &err {
                    None => {
                        tx.execute(
                            "UPDATE webhook_deliveries SET status = 'delivered', attempt = ?, status_code = ?, duration_ms = ?, error = NULL, at = ? WHERE id = ?",
                            params![attempt, code, dur, now, id],
                        )?;
                    }
                    Some(e) => {
                        let next = chrono::Utc::now() + backoff(attempt);
                        let give_up = db::parse_time(&created)
                            .is_none_or(|c| next > c + chrono::Duration::hours(24));
                        tx.execute(
                            "UPDATE webhook_deliveries SET status = ?, attempt = ?, status_code = ?, duration_ms = ?, error = ?, at = ?, next_attempt_at = ? WHERE id = ?",
                            params![if give_up { "failed" } else { "pending" }, attempt, code, dur, e, now, db::fmt_time(next), id],
                        )?;
                    }
                }
                record_status(tx, &h.id, code, err.is_none())
            })
            .await;
    }
    n
}

/// Removes delivery logs older than OBX_WEBHOOK_LOG_RETENTION_DAYS.
pub async fn cleanup(app: &App) {
    let cutoff = db::fmt_time(
        chrono::Utc::now() - chrono::Duration::days(app.cfg.webhook_log_retention_days),
    );
    let _ = app
        .db
        .write(move |tx| {
            tx.execute(
                "DELETE FROM webhook_deliveries WHERE created_at < ? AND status <> 'pending'",
                [&cutoff],
            )?;
            Ok(())
        })
        .await;
}

/// The notifier and delivery loop, plus the hourly cleanup of delivery
/// logs and expired exports.
pub fn start(app: App) {
    let a = app.clone();
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(std::time::Duration::from_secs(3));
        let mut ticks = 0u32;
        loop {
            // Changes are checked when a write announces them, and once a
            // minute in case an announcement came while this loop was busy.
            let check_changes = tokio::select! {
                _ = a.changed.notified() => {
                    // Let a burst of writes settle into one notification.
                    tokio::time::sleep(std::time::Duration::from_millis(500)).await;
                    true
                }
                _ = a.webhooks_due.notified() => false,
                _ = tick.tick() => {
                    ticks = ticks.wrapping_add(1);
                    ticks.is_multiple_of(20)
                }
            };
            if check_changes {
                let _ = a.db.write(|tx| notify_changes(tx)).await;
            }
            while deliver_due(&a).await == 50 {}
        }
    });
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(std::time::Duration::from_secs(3600));
        loop {
            tick.tick().await;
            cleanup(&app).await;
            crate::exports::cleanup(&app).await;
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backoff_grows_and_caps() {
        assert_eq!(backoff(1).num_seconds(), 30);
        assert_eq!(backoff(2).num_seconds(), 60);
        assert_eq!(backoff(12).num_seconds(), 6 * 3600);
        assert_eq!(backoff(40).num_seconds(), 6 * 3600);
    }

    #[test]
    fn scrub_removes_urls() {
        assert_eq!(
            scrub("error sending request for url (https://x.example/hook?t=secret)"),
            "error sending request for url <url>"
        );
    }
}
