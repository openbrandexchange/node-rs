//! Usage events (protocol.md §11): a retailer reports what it did with
//! assets; accepted events land in `download_events` (kind `usage`) and
//! count in the brand's statistics.

use axum::body::Bytes;
use axum::extract::State;
use axum::http::HeaderMap;
use rusqlite::{OptionalExtension, params};
use serde::Deserialize;
use serde_json::{Value, json};

use crate::app::App;
use crate::db;
use crate::http::protocol::{protocol_auth, visible_asset};
use crate::http::{Res, Viewer, json as json_resp, read_json_object, with_headers};
use crate::problem::Problem;

/// One reported event (UsageEvent; channel is accepted and not stored,
/// like node-go).
#[derive(Debug, Clone, Deserialize)]
pub struct UsageEvent {
    pub asset_id: String,
    #[serde(default)]
    pub rendition: Option<String>,
    pub event: String,
    #[serde(default)]
    pub at: String,
    #[serde(default)]
    pub count: Option<i64>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Usage {
    #[serde(default)]
    pub events: Vec<UsageEvent>,
}

/// The stored time of a reported event: its own time unless unparsable or
/// more than an hour in the future.
pub fn event_time(at: &str, now: chrono::DateTime<chrono::Utc>) -> String {
    match db::parse_time(at) {
        Some(t) if t < now + chrono::Duration::hours(1) => db::fmt_time(t),
        _ => db::fmt_time(now),
    }
}

/// POST /obx/v1/usage
pub async fn h_usage(State(app): State<App>, headers: HeaderMap, body: Bytes) -> Res {
    let (v, hs) = protocol_auth(&app, &headers, "usage:write", false).await?;
    let doc = Value::Object(read_json_object(&headers, &body)?);
    let errs = crate::schemas::validate("Usage", &doc);
    if !errs.is_empty() {
        let mut p = Problem::new("validation_failed", "The request body is not valid.");
        for e in errs {
            p = p.field(&e.pointer, "validation_failed", e.message);
        }
        return Err(p);
    }
    let u: Usage = serde_json::from_value(doc).map_err(|e| {
        Problem::new(
            "validation_failed",
            format!("The request body is not valid: {e}"),
        )
    })?;
    let accepted = app
        .db
        .write(move |tx| {
            let now = chrono::Utc::now();
            let mut n = 0;
            for e in &u.events {
                let Some(row) = visible_asset(tx, &v, &e.asset_id)? else {
                    continue;
                };
                log_download_tmp(
                    tx,
                    &v,
                    e.rendition.as_deref(),
                    &row.product_id,
                    &row.id,
                    &e.event,
                    e.count.filter(|c| *c > 0).unwrap_or(1),
                    &event_time(&e.at, now),
                )?;
                n += 1;
            }
            Ok(n)
        })
        .await?;
    Ok(with_headers(
        json_resp(202, &json!({"accepted": accepted})),
        &hs,
    ))
}

// TODO(merge): replace with crate::stats::log_download (main lane).
fn log_download_tmp(
    c: &rusqlite::Connection,
    v: &Viewer,
    variant: Option<&str>,
    product_id: &str,
    asset_id: &str,
    usage_event: &str,
    files: i64,
    at: &str,
) -> crate::problem::Result<()> {
    if v.kind != "client" || v.retailer_id.is_empty() {
        return Ok(());
    }
    let style: Option<String> = c
        .query_row(
            "SELECT style_number FROM products WHERE id = ?",
            [product_id],
            |r| r.get(0),
        )
        .optional()?;
    let cname: Option<String> = c
        .query_row(
            "SELECT name FROM api_clients WHERE id = ?",
            [&v.client_row_id],
            |r| r.get(0),
        )
        .optional()?;
    c.execute(
        "INSERT INTO download_events (id, at, kind, retailer_id, retailer_name, actor_type, actor_id, actor_name, variant, product_id, style_number, asset_id, usage_event, files, bytes) VALUES (?, ?, 'usage', ?, ?, 'api_client', ?, ?, ?, ?, ?, ?, ?, ?, NULL)",
        params![crate::ids::new("dle"), at, v.retailer_id, v.retailer_name, v.client_row_id, cname, variant, product_id, style, asset_id, usage_event, files],
    )?;
    c.execute(
        "UPDATE retailers SET last_activity_at = ? WHERE id = ?",
        params![db::now_str(), v.retailer_id],
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    #[test]
    fn event_times() {
        let now = chrono::Utc::now();
        assert_eq!(
            super::event_time("2026-01-02T03:04:05Z", now),
            "2026-01-02T03:04:05.000000Z"
        );
        assert_eq!(super::event_time("nonsense", now), crate::db::fmt_time(now));
        let future = crate::db::fmt_time(now + chrono::Duration::hours(3));
        assert_eq!(super::event_time(&future, now), crate::db::fmt_time(now));
    }
}
