//! The change feed (protocol.md §6): a snapshot of every visible object,
//! then live entries from the high-water mark.

use std::collections::HashMap;

use axum::extract::{Query, State};
use axum::http::HeaderMap;
use rusqlite::{Connection, OptionalExtension};
use serde_json::{Value, json};

use super::protocol::{asset_visible_now, protocol_auth, render_asset, render_plain};
use super::*;
use crate::catalog::load_row_by_id;
use crate::model::*;

fn cursor_epoch(c: &Connection) -> Result<i64> {
    Ok(crate::db::get_meta(c, "cursor_epoch")?
        .and_then(|v| v.parse().ok())
        .unwrap_or(0))
}

pub fn render_data(app: &App, kind: &str, rep: &str, up: &str, v: &Viewer) -> Value {
    if kind == KIND_ASSET {
        render_asset(app, rep, up, v)
    } else {
        render_plain(rep, up)
    }
}

pub async fn changes(
    State(app): State<App>,
    Query(q): Query<HashMap<String, String>>,
    headers: HeaderMap,
) -> Res {
    let (v, hs) = protocol_auth(&app, &headers, "catalog:read", false).await?;
    let limit = limit_param(&q, 100, 500)?;
    let cursor = q.get("cursor").cloned().unwrap_or_default();
    let a = app.clone();
    let page = app
        .db
        .read(move |c| changes_page(&a, c, &v, &cursor, limit))
        .await?;
    Ok(with_headers(ok(&page), &hs))
}

pub fn changes_page(
    app: &App,
    c: &Connection,
    v: &Viewer,
    cursor: &str,
    limit: usize,
) -> Result<Value> {
    let epoch = cursor_epoch(c)?;
    let pruned: i64 = crate::db::get_meta(c, "changes_pruned_below")?
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    let feed = obx_feed::Feed::new(&app.cursors, epoch, pruned);
    let settings = crate::settings::Settings::load(c)?;
    let mut src = Source {
        app,
        c,
        v,
        settings,
    };
    match feed.page(&mut src, cursor, limit) {
        Ok(p) => Ok(serde_json::to_value(p).map_err(Problem::internal)?),
        Err(obx_feed::FeedError::Cursor(e)) => {
            Err(Problem::new(e.code(), e.detail(crate::app::SPEC_VERSION)))
        }
        Err(obx_feed::FeedError::Source(p)) => Err(p),
    }
}

/// The feed of one viewer, read from SQLite.
struct Source<'a> {
    app: &'a App,
    c: &'a Connection,
    v: &'a Viewer,
    settings: crate::settings::Settings,
}

type Entry = (
    i64,
    String,
    String,
    String,
    Option<String>,
    Option<String>,
    Option<String>,
    Option<String>,
    i64,
    String,
);

impl obx_feed::FeedSource for Source<'_> {
    type Error = Problem;

    fn high_water(&mut self) -> Result<i64> {
        Ok(self
            .c
            .query_row("SELECT COALESCE(MAX(seq), 0) FROM changes", [], |r| {
                r.get(0)
            })?)
    }

    fn snapshot(
        &mut self,
        kind: &str,
        after: &str,
        limit: usize,
    ) -> Result<obx_feed::SnapshotBatch> {
        let (app, c, v) = (self.app, self.c, self.v);
        let col = if kind == KIND_BRAND { "id" } else { "brand_id" };
        let (bf, bargs) = v.brand_filter(col);
        let prod = if kind == KIND_VARIANT || kind == KIND_ASSET {
            "product_id"
        } else {
            "''"
        };
        let exp = if kind == KIND_ASSET {
            "expires_at"
        } else {
            "NULL"
        };
        let q = format!(
            "SELECT id, external_id, {col}, rep, updated_at, last_seq, {prod}, {exp} FROM {} WHERE visible = 1 AND id > ?{bf} ORDER BY id LIMIT {}",
            table_of(kind),
            limit + 1
        );
        let mut args = vec![after.to_string()];
        args.extend(bargs);
        let mut st = c.prepare(&q)?;
        let items = st
            .query_map(rusqlite::params_from_iter(args.iter()), |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, String>(2)?,
                    r.get::<_, String>(3)?,
                    r.get::<_, String>(4)?,
                    r.get::<_, i64>(5)?,
                    r.get::<_, String>(6)?,
                    r.get::<_, Option<String>>(7)?,
                ))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        let more = items.len() > limit;
        let mut entries = Vec::new();
        for (id, ext, brand, rep, up, seq, prod, exp) in items.into_iter().take(limit) {
            if kind == KIND_ASSET && !asset_visible_now(exp.as_deref()) {
                entries.push((id, None));
                continue;
            }
            let mut ch = json!({"seq": seq.max(1), "type": kind, "op": "upsert", "id": id, "external_id": ext,
                "brand_id": brand, "product_id": null, "updated_at": up});
            if !prod.is_empty() {
                ch["product_id"] = json!(prod);
            }
            ch["data"] = render_data(app, kind, &rep, &up, v);
            entries.push((id, Some(ch)));
        }
        Ok(obx_feed::SnapshotBatch { entries, more })
    }

    fn live(&mut self, after: i64, limit: usize) -> Result<obx_feed::LiveBatch> {
        let (app, c, v) = (self.app, self.c, self.v);
        let mut changes: Vec<Value> = Vec::new();
        let mut last = after;
        let mut scanned = 0;
        'outer: while changes.len() < limit && scanned < 5000 {
            let mut st = c.prepare(
                "SELECT seq, type, op, object_id, external_id, brand_id, product_id, retailer_id, resync, at FROM changes WHERE seq > ? ORDER BY seq LIMIT 500",
            )?;
            let batch: Vec<Entry> = st
                .query_map([last], |r| {
                    Ok((
                        r.get(0)?,
                        r.get(1)?,
                        r.get(2)?,
                        r.get(3)?,
                        r.get(4)?,
                        r.get(5)?,
                        r.get(6)?,
                        r.get(7)?,
                        r.get(8)?,
                        r.get(9)?,
                    ))
                })?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            if batch.is_empty() {
                break;
            }
            let n = batch.len();
            for (seq, typ, op, id, ext, brand, prod, retailer, resync, at) in batch {
                if changes.len() >= limit {
                    break 'outer;
                }
                last = seq;
                scanned += 1;
                if typ == "grant" {
                    if retailer.as_deref() != Some(v.retailer_id.as_str()) {
                        continue;
                    }
                    let Some(ret) = load_retailer(c, &v.retailer_id)? else {
                        continue;
                    };
                    let g = grant_of(&self.settings, &ret);
                    changes.push(json!({"seq": seq, "type": "grant", "op": "upsert", "id": id, "external_id": null,
                        "brand_id": null, "product_id": null, "updated_at": g["updated_at"], "data": g, "resync": resync == 1}));
                    continue;
                }
                let Some(b) = brand.as_deref().filter(|b| v.sees_brand(b)) else {
                    continue;
                };
                let mut ch = json!({"seq": seq, "type": typ, "op": op, "id": id, "external_id": ext, "brand_id": b,
                    "product_id": prod, "updated_at": at});
                if op == "upsert" {
                    let Some(row) = load_row_by_id(c, &typ, &id)?.filter(|r| r.visible) else {
                        continue;
                    };
                    if typ == KIND_ASSET {
                        let exp: Option<String> = c
                            .query_row("SELECT expires_at FROM assets WHERE id = ?", [&id], |r| {
                                r.get(0)
                            })
                            .optional()?
                            .flatten();
                        if !asset_visible_now(exp.as_deref()) {
                            continue;
                        }
                    }
                    ch["updated_at"] = json!(row.updated_at);
                    ch["data"] = render_data(app, &typ, &row.rep, &row.updated_at, v);
                }
                changes.push(ch);
            }
            if n < 500 {
                break;
            }
        }
        let more: Option<i64> = c
            .query_row(
                "SELECT seq FROM changes WHERE seq > ? LIMIT 1",
                [last],
                |r| r.get(0),
            )
            .optional()?;
        Ok(obx_feed::LiveBatch {
            changes,
            last_seq: last,
            more: more.is_some(),
        })
    }
}

/// Moves the cursor epoch, as an incompatible spec upgrade does (P-FEED-7).
pub fn simulate_spec_upgrade(c: &Connection) -> Result<()> {
    let e = cursor_epoch(c)?;
    crate::db::set_meta(c, "cursor_epoch", &(e + 1).to_string())
}
