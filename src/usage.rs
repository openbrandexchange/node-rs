//! Usage events (protocol.md §11): a retailer reports what it did with
//! assets; accepted events land in `download_events` (kind `usage`) and
//! count in the brand's statistics.

use axum::body::Bytes;
use axum::extract::State;
use axum::http::HeaderMap;

use serde_json::{Value, json};

use crate::app::App;

use crate::http::protocol::{protocol_auth, visible_asset};
use crate::http::{Res, json as json_resp, read_json_object, with_headers};
use crate::problem::Problem;
use crate::usage_proto::{Usage, event_time};

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
                crate::stats::log_download(
                    tx,
                    &v,
                    &crate::stats::DownloadEvent {
                        kind: "usage",
                        variant: e.rendition.clone().unwrap_or_default(),
                        product_id: row.product_id.clone(),
                        asset_id: row.id.clone(),
                        usage_event: e.event.clone(),
                        files: e.count.filter(|c| *c > 0).unwrap_or(1),
                        at: event_time(&e.at, now),
                        ..Default::default()
                    },
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
