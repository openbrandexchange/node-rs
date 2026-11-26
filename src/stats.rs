//! Download statistics: every file a retailer receives (portal downloads,
//! zips, CSV, API renditions and exports, usage events) is one row in
//! `download_events`; `GET /admin/api/stats` aggregates them. Admin previews
//! are never recorded.

use std::collections::HashMap;

use axum::extract::{Query, State};
use axum::http::{HeaderMap, Method};
use rusqlite::{Connection, OptionalExtension, params};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::app::App;
use crate::db;
use crate::http::admin::admin_guard;
use crate::http::{Res, Viewer, limit_param, ok};
use crate::problem::{Problem, Result};

/// One delivery. `kind`: image, product_zip, selection_zip, bulk_zip, csv,
/// api_rendition, api_export or usage.
#[derive(Debug, Clone, Default)]
pub struct DownloadEvent {
    pub kind: &'static str,
    pub variant: String,
    pub product_id: String,
    pub asset_id: String,
    pub usage_event: String,
    pub files: i64,
    pub bytes: i64,
    /// RFC 3339 time of the event; empty = now.
    pub at: String,
}

fn none_if_empty(s: &str) -> Option<&str> {
    (!s.is_empty()).then_some(s)
}

/// Stores a statistics event and the retailer's last activity. Admin
/// previews and viewers without a retailer are not recorded.
pub fn log_download(c: &Connection, v: &Viewer, e: &DownloadEvent) -> Result<()> {
    if v.preview() || v.retailer_id.is_empty() {
        return Ok(());
    }
    let (actor_type, actor_id, actor_name) = if v.kind == "client" {
        ("api_client", &v.client_row_id, &v.client_name)
    } else {
        ("user", &v.user_id, &v.user_name)
    };
    let style: Option<String> = match none_if_empty(&e.product_id) {
        Some(pid) => c
            .query_row(
                "SELECT style_number FROM products WHERE id = ?",
                [pid],
                |r| r.get(0),
            )
            .optional()?,
        None => None,
    };
    let now = db::now_str();
    let at = if e.at.is_empty() {
        now.clone()
    } else {
        e.at.clone()
    };
    c.execute(
        "INSERT INTO download_events (id, at, kind, retailer_id, retailer_name, actor_type, actor_id, actor_name, variant, product_id, style_number, asset_id, usage_event, files, bytes) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        params![
            crate::ids::new("dle"),
            at,
            e.kind,
            v.retailer_id,
            v.retailer_name,
            actor_type,
            actor_id,
            actor_name,
            none_if_empty(&e.variant),
            none_if_empty(&e.product_id),
            style,
            none_if_empty(&e.asset_id),
            none_if_empty(&e.usage_event),
            e.files,
            (e.bytes > 0).then_some(e.bytes),
        ],
    )?;
    c.execute(
        "UPDATE retailers SET last_activity_at = ? WHERE id = ?",
        params![now, v.retailer_id],
    )?;
    Ok(())
}

/// Records an event in its own write; a failure is logged, never shown to
/// the person downloading.
pub async fn record(app: &App, v: &Viewer, e: DownloadEvent) {
    if v.preview() || v.retailer_id.is_empty() {
        return;
    }
    let v = v.clone();
    if let Err(err) = app.db.write(move |tx| log_download(tx, &v, &e)).await {
        tracing::warn!(error = %err, "download event not stored");
    }
}

/// A Range request that continues an earlier download is not a new one.
pub fn is_continuation_range(h: &HeaderMap) -> bool {
    h.get(axum::http::header::RANGE)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|r| !r.is_empty() && !r.starts_with("bytes=0-"))
}

fn is_image_kind(k: &str) -> bool {
    matches!(
        k,
        "image" | "product_zip" | "selection_zip" | "bulk_zip" | "api_rendition" | "api_export"
    )
}

#[derive(Default)]
struct Agg {
    downloads: i64,
    images: i64,
    last: String,
    name: String,
    style: String,
}

fn top(m: &HashMap<String, Agg>) -> Vec<(&String, &Agg)> {
    let mut v: Vec<_> = m.iter().collect();
    v.sort_by(|a, b| b.1.downloads.cmp(&a.1.downloads).then(a.0.cmp(b.0)));
    v.truncate(20);
    v
}

pub fn stats_json(c: &Connection, days: i64, today: chrono::NaiveDate) -> Result<Value> {
    let start = today - chrono::Duration::days(days - 1);
    let start_s = format!("{}T00:00:00.000000Z", start.format("%Y-%m-%d"));
    let mut st = c.prepare("SELECT at, kind, retailer_id, retailer_name, product_id, style_number, files FROM download_events WHERE at >= ?")?;
    let mut rows = st.query([&start_s])?;
    let mut totals: Vec<(&str, i64)> = vec![
        ("downloads", 0),
        ("images", 0),
        ("zips", 0),
        ("csv_exports", 0),
        ("api_downloads", 0),
        ("usage_events", 0),
        ("active_retailers", 0),
    ];
    let mut add = |k: &str, n: i64| {
        if let Some(t) = totals.iter_mut().find(|t| t.0 == k) {
            t.1 += n;
        }
    };
    let mut by_day: HashMap<String, Agg> = HashMap::new();
    let mut by_ret: HashMap<String, Agg> = HashMap::new();
    let mut by_prod: HashMap<String, Agg> = HashMap::new();
    while let Some(r) = rows.next()? {
        let at: String = r.get(0)?;
        let kind: String = r.get(1)?;
        let ret: Option<String> = r.get(2)?;
        let ret_name: Option<String> = r.get(3)?;
        let prod: Option<String> = r.get(4)?;
        let style: Option<String> = r.get(5)?;
        let files: i64 = r.get(6)?;
        if kind == "usage" {
            add("usage_events", files);
            continue;
        }
        let imgs = if is_image_kind(&kind) { files } else { 0 };
        add("downloads", 1);
        add("images", imgs);
        match kind.as_str() {
            "product_zip" | "selection_zip" | "bulk_zip" => add("zips", 1),
            "csv" => add("csv_exports", 1),
            "api_rendition" | "api_export" => add("api_downloads", 1),
            _ => {}
        }
        let d = by_day
            .entry(at.get(..10).unwrap_or("").to_string())
            .or_default();
        d.downloads += 1;
        d.images += imgs;
        if let Some(rid) = ret {
            let x = by_ret.entry(rid).or_insert_with(|| Agg {
                name: ret_name.unwrap_or_default(),
                ..Default::default()
            });
            x.downloads += 1;
            x.images += imgs;
            if at > x.last {
                x.last = at.clone();
            }
        }
        if let Some(pid) = prod {
            let x = by_prod.entry(pid).or_insert_with(|| Agg {
                style: style.unwrap_or_default(),
                ..Default::default()
            });
            x.downloads += 1;
        }
    }
    add("active_retailers", by_ret.len() as i64);
    let by_day_out: Vec<Value> = (0..days)
        .map(|i| {
            let d = (start + chrono::Duration::days(i))
                .format("%Y-%m-%d")
                .to_string();
            let x = by_day.get(&d);
            json!({"date": d, "downloads": x.map_or(0, |x| x.downloads), "images": x.map_or(0, |x| x.images)})
        })
        .collect();
    let top_r: Vec<Value> = top(&by_ret)
        .into_iter()
        .map(|(id, x)| {
            json!({"retailer_id": id, "name": x.name, "downloads": x.downloads, "images": x.images,
                "last_activity_at": (!x.last.is_empty()).then(|| x.last.clone())})
        })
        .collect();
    let mut top_p: Vec<Value> = Vec::new();
    for (id, x) in top(&by_prod) {
        let mut item = json!({"product_id": id, "style_number": x.style, "downloads": x.downloads});
        let data: Option<String> = c
            .query_row("SELECT data FROM products WHERE id = ?", [id], |r| r.get(0))
            .optional()?;
        if let Some(d) = data {
            let d: Value = serde_json::from_str(&d).unwrap_or(Value::Null);
            item["name"] = d.get("name").cloned().unwrap_or(Value::Null);
        }
        top_p.push(item);
    }
    let totals: serde_json::Map<String, Value> = totals
        .into_iter()
        .map(|(k, v)| (k.into(), json!(v)))
        .collect();
    Ok(
        json!({"days": days, "totals": totals, "by_day": by_day_out, "top_retailers": top_r, "top_products": top_p}),
    )
}

/// GET /admin/api/stats?days=7|30|90|365
pub async fn h_stats(
    State(app): State<App>,
    Query(q): Query<HashMap<String, String>>,
    method: Method,
    headers: HeaderMap,
) -> Res {
    admin_guard(&app, &headers, &method, "admin").await?;
    let days: i64 = q.get("days").and_then(|d| d.parse().ok()).unwrap_or(30);
    if ![7, 30, 90, 365].contains(&days) {
        return Err(Problem::new(
            "invalid_request",
            "days must be 7, 30, 90 or 365.",
        ));
    }
    let today = chrono::Utc::now().date_naive();
    let out = app.db.read(move |c| stats_json(c, days, today)).await?;
    Ok(ok(&out))
}

#[derive(Serialize, Deserialize)]
struct EventCursor {
    a: String,
    i: String,
}

/// GET /admin/api/stats/events: the newest events first.
pub async fn h_stats_events(
    State(app): State<App>,
    Query(q): Query<HashMap<String, String>>,
    method: Method,
    headers: HeaderMap,
) -> Res {
    admin_guard(&app, &headers, &method, "admin").await?;
    let limit = limit_param(&q, 50, 200)?;
    let mut w = String::from("WHERE 1 = 1");
    let mut args: Vec<String> = Vec::new();
    if let Some(v) = q.get("retailer_id").filter(|v| !v.is_empty()) {
        w.push_str(" AND retailer_id = ?");
        args.push(v.clone());
    }
    if let Some(v) = q.get("kind").filter(|v| !v.is_empty()) {
        w.push_str(" AND kind = ?");
        args.push(v.clone());
    }
    if let Some(c) = q.get("cursor").filter(|v| !v.is_empty()) {
        let cur: EventCursor = app
            .decode_cursor("events", c)
            .ok_or_else(|| Problem::new("cursor_invalid", "The cursor is not valid."))?;
        w.push_str(" AND (at < ? OR (at = ? AND id < ?))");
        args.extend([cur.a.clone(), cur.a, cur.i]);
    }
    let mut items = app
        .db
        .read(move |c| {
            let mut st = c.prepare(&format!("SELECT id, at, kind, retailer_id, retailer_name, actor_type, actor_name, variant, product_id, asset_id, usage_event, files, bytes FROM download_events {w} ORDER BY at DESC, id DESC LIMIT {}", limit + 1))?;
            let rows = st
                .query_map(rusqlite::params_from_iter(args.iter()), |r| {
                    Ok(json!({"id": r.get::<_, String>(0)?, "at": r.get::<_, String>(1)?, "kind": r.get::<_, String>(2)?,
                        "retailer_id": r.get::<_, Option<String>>(3)?, "retailer_name": r.get::<_, Option<String>>(4)?,
                        "actor_type": r.get::<_, String>(5)?, "actor_name": r.get::<_, Option<String>>(6)?,
                        "variant": r.get::<_, Option<String>>(7)?, "product_id": r.get::<_, Option<String>>(8)?,
                        "asset_id": r.get::<_, Option<String>>(9)?, "usage_event": r.get::<_, Option<String>>(10)?,
                        "files": r.get::<_, i64>(11)?, "bytes": r.get::<_, Option<i64>>(12)?}))
                })?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            Ok(rows)
        })
        .await?;
    let mut next = None;
    if items.len() > limit {
        items.truncate(limit);
        let last = &items[limit - 1];
        next = Some(app.encode_cursor(
            "events",
            &EventCursor {
                a: last["at"].as_str().unwrap_or("").into(),
                i: last["id"].as_str().unwrap_or("").into(),
            },
        ));
    }
    Ok(ok(&json!({"items": items, "next_cursor": next})))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn conn() -> Connection {
        let c = Connection::open_in_memory().unwrap();
        c.execute_batch(
            "CREATE TABLE download_events (id TEXT PRIMARY KEY, at TEXT NOT NULL, kind TEXT NOT NULL, retailer_id TEXT, retailer_name TEXT, actor_type TEXT NOT NULL,
              actor_id TEXT, actor_name TEXT, variant TEXT, product_id TEXT, style_number TEXT, asset_id TEXT, usage_event TEXT,
              files INTEGER NOT NULL DEFAULT 0, bytes BIGINT);
             CREATE TABLE products (id TEXT PRIMARY KEY, style_number TEXT, data TEXT);
             CREATE TABLE retailers (id TEXT PRIMARY KEY, last_activity_at TEXT);
             INSERT INTO products VALUES ('prd_1', 'MN-1', '{\"name\":{\"en\":\"Coat\"}}');
             INSERT INTO retailers VALUES ('ret_1', NULL);",
        )
        .unwrap();
        c
    }

    fn retailer() -> Viewer {
        Viewer {
            kind: "user".into(),
            retailer_id: "ret_1".into(),
            retailer_name: "Shop".into(),
            user_id: "usr_1".into(),
            user_name: "Ann".into(),
            ..Default::default()
        }
    }

    #[test]
    fn previews_are_not_counted_and_totals_add_up() {
        let c = conn();
        let ev = |kind, files| DownloadEvent {
            kind,
            product_id: "prd_1".into(),
            files,
            ..Default::default()
        };
        log_download(&c, &Viewer::admin(), &ev("image", 1)).unwrap();
        log_download(&c, &retailer(), &ev("image", 1)).unwrap();
        log_download(&c, &retailer(), &ev("product_zip", 4)).unwrap();
        log_download(&c, &retailer(), &ev("csv", 0)).unwrap();
        log_download(&c, &retailer(), &ev("usage", 3)).unwrap();
        let s = stats_json(&c, 7, chrono::Utc::now().date_naive()).unwrap();
        let t = &s["totals"];
        assert_eq!(t["downloads"], 3);
        assert_eq!(t["images"], 5);
        assert_eq!(t["zips"], 1);
        assert_eq!(t["csv_exports"], 1);
        assert_eq!(t["usage_events"], 3);
        assert_eq!(t["active_retailers"], 1);
        assert_eq!(s["by_day"].as_array().unwrap().len(), 7);
        assert_eq!(s["top_retailers"][0]["retailer_id"], "ret_1");
        assert_eq!(s["top_products"][0]["name"]["en"], "Coat");
        assert_eq!(s["top_products"][0]["style_number"], "MN-1");
        let last: Option<String> = c
            .query_row("SELECT last_activity_at FROM retailers", [], |r| r.get(0))
            .unwrap();
        assert!(last.is_some());
    }

    #[test]
    fn continuation_ranges() {
        let mut h = HeaderMap::new();
        assert!(!is_continuation_range(&h));
        h.insert("range", "bytes=0-99".parse().unwrap());
        assert!(!is_continuation_range(&h));
        h.insert("range", "bytes=100-".parse().unwrap());
        assert!(is_continuation_range(&h));
    }
}
