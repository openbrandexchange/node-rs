//! The retailer portal API (`/admin/api/portal/*`, node-admin.yaml): what a
//! signed-in retailer (or a brand admin previewing) sees, the product list
//! with facets, product detail, EAN paste, the selection and self-service
//! API keys. Downloads are in `portal_downloads`.

use std::collections::HashMap;

use axum::body::Bytes;
use axum::extract::{Path, RawQuery, State};
use axum::http::{HeaderMap, Method, StatusCode};
use axum::response::IntoResponse;
use rusqlite::{Connection, OptionalExtension, params};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use super::admin::{Session, admin_guard, viewer_for_user};
use super::protocol::{asset_visible_now, product_details, render_plain};
use super::*;
use crate::db::in_list;

pub const SELECTION_MAX: usize = 1000;
pub const SYNC_ZIP_MAX_FILES: usize = 400;
pub const GTIN_LOOKUP_MAX: usize = 2000;

/// The query string as (key, value) pairs, repeated keys kept.
pub fn query_pairs(raw: &Option<String>) -> Vec<(String, String)> {
    raw.as_deref()
        .map(|q| {
            url::form_urlencoded::parse(q.as_bytes())
                .into_owned()
                .collect()
        })
        .unwrap_or_default()
}

pub fn query_get<'a>(q: &'a [(String, String)], k: &str) -> Option<&'a str> {
    q.iter().find(|(a, _)| a == k).map(|(_, v)| v.as_str())
}

pub fn query_map(q: &[(String, String)]) -> HashMap<String, String> {
    let mut m = HashMap::new();
    for (k, v) in q {
        m.entry(k.clone()).or_insert_with(|| v.clone());
    }
    m
}

/// The signed-in user's session and portal viewer, rate limited per user.
pub async fn portal_viewer(
    app: &App,
    headers: &HeaderMap,
    method: &Method,
) -> Result<(Viewer, Session)> {
    let s = admin_guard(app, headers, method, "any")
        .await?
        .ok_or_else(|| Problem::new("unauthorized", "Please log in."))?;
    let u = s.user.clone();
    let v = app.db.read(move |c| viewer_for_user(c, &u)).await?;
    rate_limit(app, &format!("portal:{}", s.user.id), 1200)?;
    Ok((v, s))
}

fn selection_ids(c: &Connection, user_id: &str) -> Result<Vec<String>> {
    let sel: Option<String> = c
        .query_row("SELECT selection FROM users WHERE id = ?", [user_id], |r| {
            r.get(0)
        })
        .optional()?
        .flatten();
    Ok(sel
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default())
}

/// GET /admin/api/portal/viewer
pub async fn viewer(State(app): State<App>, method: Method, headers: HeaderMap) -> Res {
    let (v, s) = portal_viewer(&app, &headers, &method).await?;
    let base = app.cfg.public_url.clone();
    let done = app.setup_done().await;
    let out = app
        .db
        .read(move |c| {
            let st = Settings::load(c)?;
            let (bf, args) = v.brand_filter("id");
            let mut q = c.prepare(&format!(
                "SELECT rep, updated_at FROM brands WHERE visible = 1{bf} ORDER BY name"
            ))?;
            let brands = q
                .query_map(rusqlite::params_from_iter(args.iter()), |r| {
                    Ok(render_plain(&r.get::<_, String>(0)?, &r.get::<_, String>(1)?))
                })?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            let retailer = (!v.retailer_id.is_empty())
                .then(|| json!({"id": v.retailer_id, "name": v.retailer_name}));
            let sel = selection_ids(c, &s.user.id)?;
            let mut branding = super::admin::public_branding_value(c, &base, done)?;
            branding["home"] = crate::branding::resolved_home(c, &st)?;
            Ok(json!({
                "preview": v.preview(),
                "retailer": retailer,
                "brands": brands,
                "permissions": {
                    "original_download": v.original_allowed && (v.preview() || st.portal.allow_original_download),
                    "article_data_export": st.portal.allow_article_data_export,
                    "api_self_service": st.portal.retailer_api_self_service && !v.preview(),
                },
                "branding": branding,
                "languages": st.content_languages(),
                "selection_count": sel.len(),
                "limits": {"selection_max_products": SELECTION_MAX, "sync_zip_max_images": SYNC_ZIP_MAX_FILES, "gtin_lookup_max": GTIN_LOOKUP_MAX},
            }))
        })
        .await?;
    Ok(ok(&out))
}

/// The portal's product filter.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Filter {
    #[serde(default)]
    pub q: String,
    #[serde(default)]
    pub brand_id: Vec<String>,
    #[serde(default)]
    pub item_type: Vec<String>,
    #[serde(default)]
    pub color: Vec<String>,
    #[serde(default)]
    pub season: Vec<String>,
    #[serde(default)]
    pub collection: Vec<String>,
    #[serde(default)]
    pub target_group: Vec<String>,
    #[serde(default)]
    pub qualifier: Vec<String>,
    #[serde(default)]
    pub updated_since: String,
}

impl Filter {
    /// From the query: `k=a,b`, repeated `k=…` and `k[]=…` all add values.
    pub fn from_query(q: &[(String, String)]) -> Filter {
        let multi = |k: &str| -> Vec<String> {
            let mut out = Vec::new();
            for (key, v) in q {
                if key == k {
                    out.extend(
                        v.split(',')
                            .map(|p| p.trim())
                            .filter(|p| !p.is_empty())
                            .map(String::from),
                    );
                } else if key.strip_suffix("[]") == Some(k) && !v.trim().is_empty() {
                    out.push(v.trim().to_string());
                }
            }
            out
        };
        Filter {
            q: query_get(q, "q").unwrap_or("").trim().to_string(),
            brand_id: multi("brand_id"),
            item_type: multi("item_type"),
            color: multi("color"),
            season: multi("season"),
            collection: multi("collection"),
            target_group: multi("target_group"),
            qualifier: multi("qualifier"),
            updated_since: query_get(q, "updated_since").unwrap_or("").to_string(),
        }
    }

    /// The WHERE clause; `skip` leaves one dimension out (for its facet).
    pub fn sql(&self, v: &Viewer, skip: &str) -> (String, Vec<String>) {
        let mut w = String::from(" WHERE p.visible = 1");
        let (bf, bargs) = v.brand_filter("p.brand_id");
        w.push_str(&bf);
        let mut args = bargs;
        if !self.q.is_empty() {
            w.push_str(" AND (p.search_text LIKE ?)");
            args.push(format!("%{}%", self.q.to_lowercase()));
        }
        let mut inl = |col: &str, vals: &[String], dim: &str, w: &mut String| {
            if vals.is_empty() || dim == skip {
                return;
            }
            w.push_str(&format!(" AND {col} IN {}", in_list(vals.len())));
            args.extend(vals.iter().cloned());
        };
        inl("p.brand_id", &self.brand_id, "brand", &mut w);
        inl("p.item_type", &self.item_type, "item_type", &mut w);
        inl("p.season", &self.season, "season", &mut w);
        inl("p.collection", &self.collection, "collection", &mut w);
        inl("p.target_group", &self.target_group, "target_group", &mut w);
        if !self.color.is_empty() && skip != "color" {
            w.push_str(&format!(" AND EXISTS (SELECT 1 FROM variants v WHERE v.product_id = p.id AND v.visible = 1 AND v.color_code IN {})", in_list(self.color.len())));
            args.extend(self.color.iter().cloned());
        }
        if !self.qualifier.is_empty() && skip != "qualifier" {
            w.push_str(&format!(" AND EXISTS (SELECT 1 FROM product_qualifiers pq WHERE pq.product_id = p.id AND pq.code IN {})", in_list(self.qualifier.len())));
            args.extend(self.qualifier.iter().cloned());
        }
        if !self.updated_since.is_empty() {
            if let Some(t) = crate::db::parse_time(&self.updated_since) {
                w.push_str(" AND p.touched_at >= ?");
                args.push(crate::db::fmt_time(t));
            }
        }
        (w, args)
    }
}

pub fn brand_names(c: &Connection) -> Result<HashMap<String, String>> {
    let mut st = c.prepare("SELECT id, name FROM brands")?;
    let m = st
        .query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))?
        .collect::<rusqlite::Result<HashMap<_, _>>>()?;
    Ok(m)
}

/// PortalProductSummary.
fn product_summary(
    app: &App,
    c: &Connection,
    v: &Viewer,
    p: &Value,
    brand_name: &str,
    touched: &str,
) -> Result<Value> {
    let pid = p["id"].as_str().unwrap_or("");
    let mut colors: Vec<Value> = Vec::new();
    let mut idx: HashMap<String, usize> = HashMap::new();
    let mut variant_count = 0;
    let mut st = c.prepare(
        "SELECT rep FROM variants WHERE product_id = ? AND visible = 1 ORDER BY external_id",
    )?;
    for rep in st.query_map([pid], |r| r.get::<_, String>(0))? {
        let vv: Value = serde_json::from_str(&rep?).unwrap_or(Value::Null);
        variant_count += 1;
        let code = vv["color"]["code"].as_str().unwrap_or("").to_string();
        if !idx.contains_key(&code) {
            idx.insert(code.clone(), colors.len());
            colors.push(json!({"code": code, "name": vv["color"]["name"], "thumb_url": null}));
        }
    }
    let mut st = c.prepare(&format!(
        "SELECT id, color_code, expires_at FROM assets WHERE product_id = ? AND visible = 1{}",
        crate::catalog::ASSET_ORDER
    ))?;
    let assets = st
        .query_map([pid], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, Option<String>>(1)?,
                r.get::<_, Option<String>>(2)?,
            ))
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    let mut thumb: Option<String> = None;
    let mut images = 0;
    for (id, color, exp) in assets {
        if !asset_visible_now(exp.as_deref()) {
            continue;
        }
        images += 1;
        let (u, _) = app.signed_url(&format!("/obx/v1/assets/{id}/renditions/thumb"), &v.tag());
        if thumb.is_none() {
            thumb = Some(u.clone());
        }
        if let Some(i) = color.and_then(|c| idx.get(&c).copied()) {
            if colors[i]["thumb_url"].is_null() {
                colors[i]["thumb_url"] = json!(u);
            }
        }
    }
    let up = p["updated_at"].as_str().unwrap_or("");
    let updated = if touched > up { touched } else { up };
    Ok(
        json!({"id": p["id"], "style_number": p["style_number"], "name": p["name"],
        "brand": {"id": p["brand_id"], "name": brand_name},
        "item_type": p["item_type"], "target_group": p["target_group"], "season": p["season"], "collection": p["collection"],
        "thumb_url": thumb, "colors": colors, "image_count": images, "variant_count": variant_count, "updated_at": updated}),
    )
}

#[derive(Serialize, Deserialize)]
struct OffsetCursor {
    o: usize,
}

/// GET /admin/api/portal/products
pub async fn products(
    State(app): State<App>,
    RawQuery(raw): RawQuery,
    method: Method,
    headers: HeaderMap,
) -> Res {
    let (v, _) = portal_viewer(&app, &headers, &method).await?;
    let q = query_pairs(&raw);
    let limit = limit_param(&query_map(&q), 50, 200)?;
    let f = Filter::from_query(&q);
    let offset = match query_get(&q, "cursor").filter(|c| !c.is_empty()) {
        Some(c) => {
            app.decode_cursor::<OffsetCursor>("portal-products", c)
                .ok_or_else(|| Problem::new("cursor_invalid", "The cursor is not valid."))?
                .o
        }
        None => 0,
    };
    let a = app.clone();
    let out = app
        .db
        .read(move |c| {
            let (w, args) = f.sql(&v, "");
            let total: i64 = c.query_row(
                &format!("SELECT COUNT(*) FROM products p{w}"),
                rusqlite::params_from_iter(args.iter()),
                |r| r.get(0),
            )?;
            let mut st = c.prepare(&format!(
                "SELECT p.rep, p.updated_at, p.touched_at, p.brand_id FROM products p{w} ORDER BY p.style_number, p.id LIMIT {} OFFSET {offset}",
                limit + 1
            ))?;
            let mut list = st
                .query_map(rusqlite::params_from_iter(args.iter()), |r| {
                    Ok((
                        r.get::<_, String>(0)?,
                        r.get::<_, String>(1)?,
                        r.get::<_, String>(2)?,
                        r.get::<_, String>(3)?,
                    ))
                })?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            let next = (list.len() > limit).then(|| {
                list.truncate(limit);
                a.encode_cursor("portal-products", &OffsetCursor { o: offset + limit })
            });
            let names = brand_names(c)?;
            let mut items = Vec::new();
            for (rep, up, touched, brand) in list {
                let p = render_plain(&rep, &up);
                items.push(product_summary(
                    &a,
                    c,
                    &v,
                    &p,
                    names.get(&brand).map(String::as_str).unwrap_or(""),
                    &touched,
                )?);
            }
            Ok(json!({"items": items, "next_cursor": next, "total": total}))
        })
        .await?;
    Ok(ok(&out))
}

fn facet(c: &Connection, f: &Filter, v: &Viewer, col: &str, dim: &str) -> Result<Vec<Value>> {
    let (w, args) = f.sql(v, dim);
    let mut st = c.prepare(&format!(
        "SELECT {col}, COUNT(*) FROM products p{w} AND {col} IS NOT NULL GROUP BY {col} ORDER BY {col}"
    ))?;
    let r = st
        .query_map(rusqlite::params_from_iter(args.iter()), |r| {
            Ok(json!({"value": r.get::<_, String>(0)?, "count": r.get::<_, i64>(1)?}))
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(r)
}

/// GET /admin/api/portal/facets
pub async fn facets(
    State(app): State<App>,
    RawQuery(raw): RawQuery,
    method: Method,
    headers: HeaderMap,
) -> Res {
    let (v, _) = portal_viewer(&app, &headers, &method).await?;
    let f = Filter::from_query(&query_pairs(&raw));
    let out = app
        .db
        .read(move |c| {
            let names = brand_names(c)?;
            let mut brands = facet(c, &f, &v, "p.brand_id", "brand")?;
            for b in brands.iter_mut() {
                let n = names
                    .get(b["value"].as_str().unwrap_or(""))
                    .cloned()
                    .unwrap_or_default();
                b["label"] = json!(n);
            }
            brands.sort_by(|a, b| a["label"].as_str().cmp(&b["label"].as_str()));
            let (w, args) = f.sql(&v, "color");
            let mut st = c.prepare(&format!(
                "SELECT v.color_code, COUNT(DISTINCT p.id), MIN(v.id) FROM products p JOIN variants v ON v.product_id = p.id AND v.visible = 1{w} GROUP BY v.color_code ORDER BY v.color_code"
            ))?;
            let rows = st
                .query_map(rusqlite::params_from_iter(args.iter()), |r| {
                    Ok((
                        r.get::<_, String>(0)?,
                        r.get::<_, i64>(1)?,
                        r.get::<_, String>(2)?,
                    ))
                })?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            let mut labels: HashMap<String, Value> = HashMap::new();
            let samples: Vec<String> = rows.iter().map(|r| r.2.clone()).collect();
            for chunk in samples.chunks(500) {
                let mut st = c.prepare(&format!(
                    "SELECT color_code, rep FROM variants WHERE id IN {}",
                    in_list(chunk.len())
                ))?;
                for r in st.query_map(rusqlite::params_from_iter(chunk.iter()), |r| {
                    Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?))
                })? {
                    let (code, rep) = r?;
                    let vv: Value = serde_json::from_str(&rep).unwrap_or(Value::Null);
                    let n = &vv["color"]["name"];
                    if n.as_object().is_some_and(|m| !m.is_empty()) {
                        labels.insert(code, n.clone());
                    }
                }
            }
            let colors: Vec<Value> = rows
                .into_iter()
                .map(|(code, n, _)| {
                    let mut x = json!({"value": code, "count": n});
                    if let Some(l) = labels.get(&code) {
                        x["label"] = l.clone();
                    }
                    x
                })
                .collect();
            let (w, args) = f.sql(&v, "qualifier");
            let mut st = c.prepare(&format!(
                "SELECT pq.code, COUNT(*) FROM products p JOIN product_qualifiers pq ON pq.product_id = p.id{w} GROUP BY pq.code ORDER BY pq.code"
            ))?;
            let qualifiers = st
                .query_map(rusqlite::params_from_iter(args.iter()), |r| {
                    Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?))
                })?
                .collect::<rusqlite::Result<Vec<_>>>()?
                .into_iter()
                .map(|(code, n)| {
                    let mut x = json!({"value": code, "count": n});
                    if let Some(e) = obx_format::vocab::qualifiers().lookup(&code) {
                        if !e.name.is_empty() {
                            x["label"] = json!(e.name);
                        }
                    }
                    x
                })
                .collect::<Vec<_>>();
            Ok(json!({"brands": brands, "item_types": facet(c, &f, &v, "p.item_type", "item_type")?,
                "colors": colors, "seasons": facet(c, &f, &v, "p.season", "season")?,
                "collections": facet(c, &f, &v, "p.collection", "collection")?,
                "target_groups": facet(c, &f, &v, "p.target_group", "target_group")?,
                "qualifiers": qualifiers}))
        })
        .await?;
    Ok(ok(&out))
}

/// GET /admin/api/portal/products/{id}
pub async fn product(
    State(app): State<App>,
    Path(id): Path<String>,
    method: Method,
    headers: HeaderMap,
) -> Res {
    let (v, _) = portal_viewer(&app, &headers, &method).await?;
    let a = app.clone();
    let mut items = app
        .db
        .read(move |c| product_details(&a, c, &v, &[id]))
        .await?;
    match items.pop() {
        Some(p) => Ok(ok(&p)),
        None => Err(Problem::new("not_found", "Product not found.")),
    }
}

/// POST /admin/api/portal/gtin-lookup: `text` (anything pasted: every run
/// of digits is a candidate) and/or `gtins`.
pub async fn gtin_lookup(
    State(app): State<App>,
    method: Method,
    headers: HeaderMap,
    body: Bytes,
) -> Res {
    let (v, _) = portal_viewer(&app, &headers, &method).await?;
    let b = read_json(&headers, &body, 1 << 20)?;
    let mut inputs: Vec<String> = Vec::new();
    if let Some(t) = b.get("text").and_then(|t| t.as_str()) {
        if t.len() > 100_000 {
            return Err(Problem::new(
                "limit_exceeded",
                "Paste at most 100,000 characters.",
            ));
        }
        inputs.extend(
            t.split(|c: char| !c.is_ascii_digit())
                .filter(|s| !s.is_empty())
                .map(String::from),
        );
    }
    if let Some(list) = b.get("gtins").and_then(|g| g.as_array()) {
        for g in list {
            match g {
                Value::String(s) => inputs.push(s.clone()),
                Value::Number(n) => inputs.push(n.to_string()),
                _ => return Err(Problem::new("invalid_request", "gtins must be strings.")),
            }
        }
    }
    if inputs.len() > GTIN_LOOKUP_MAX {
        return Err(Problem::new(
            "limit_exceeded",
            "Paste at most 2000 EANs at once.",
        ));
    }
    let a = app.clone();
    let out = app
        .db
        .read(move |c| super::protocol::lookup_gtins(&a, c, &v, &inputs))
        .await?;
    Ok(ok(&out))
}

// ---- selection ---------------------------------------------------------------------------

/// The ids visible to v, in the order given, without duplicates.
pub fn visible_product_ids(c: &Connection, v: &Viewer, ids: &[String]) -> Result<Vec<String>> {
    let mut okset = std::collections::HashSet::new();
    for chunk in ids.chunks(500) {
        let (bf, bargs) = v.brand_filter("brand_id");
        let mut args: Vec<String> = chunk.to_vec();
        args.extend(bargs);
        let mut st = c.prepare(&format!(
            "SELECT id FROM products WHERE visible = 1 AND id IN {}{bf}",
            in_list(chunk.len())
        ))?;
        for r in st.query_map(rusqlite::params_from_iter(args.iter()), |r| {
            r.get::<_, String>(0)
        })? {
            okset.insert(r?);
        }
    }
    let mut seen = std::collections::HashSet::new();
    Ok(ids
        .iter()
        .filter(|id| okset.contains(*id) && seen.insert((*id).clone()))
        .cloned()
        .collect())
}

pub fn count_images(c: &Connection, ids: &[String]) -> Result<i64> {
    let mut n = 0;
    for chunk in ids.chunks(500) {
        let mut st = c.prepare(&format!(
            "SELECT expires_at FROM assets WHERE visible = 1 AND product_id IN {}",
            in_list(chunk.len())
        ))?;
        for e in st.query_map(rusqlite::params_from_iter(chunk.iter()), |r| {
            r.get::<_, Option<String>>(0)
        })? {
            if asset_visible_now(e?.as_deref()) {
                n += 1;
            }
        }
    }
    Ok(n)
}

pub fn selected_ids(c: &Connection, v: &Viewer, user_id: &str) -> Result<Vec<String>> {
    visible_product_ids(c, v, &selection_ids(c, user_id)?)
}

fn selection_json(c: &Connection, v: &Viewer, user_id: &str) -> Result<Value> {
    let ids = selected_ids(c, v, user_id)?;
    let up: Option<String> = c
        .query_row(
            "SELECT selection_updated_at FROM users WHERE id = ?",
            [user_id],
            |r| r.get(0),
        )
        .optional()?
        .flatten();
    Ok(json!({"product_ids": ids, "image_count": count_images(c, &ids)?, "updated_at": up}))
}

pub async fn selection_get(State(app): State<App>, method: Method, headers: HeaderMap) -> Res {
    let (v, s) = portal_viewer(&app, &headers, &method).await?;
    let out = app
        .db
        .read(move |c| selection_json(c, &v, &s.user.id))
        .await?;
    Ok(ok(&out))
}

pub async fn selection_put(
    State(app): State<App>,
    method: Method,
    headers: HeaderMap,
    body: Bytes,
) -> Res {
    let (v, s) = portal_viewer(&app, &headers, &method).await?;
    let b = read_json(&headers, &body, 1 << 20)?;
    let Some(list) = b.get("product_ids").and_then(|p| p.as_array()) else {
        return Err(Problem::new(
            "invalid_request",
            "Send {\"product_ids\": [...]}.",
        ));
    };
    if list.len() > SELECTION_MAX {
        return Err(Problem::new(
            "limit_exceeded",
            format!("A selection can hold at most {SELECTION_MAX} products."),
        ));
    }
    let ids: Vec<String> = list
        .iter()
        .filter_map(|x| x.as_str().map(String::from))
        .collect();
    let uid = s.user.id.clone();
    let out = app
        .db
        .write(move |tx| {
            let ids = visible_product_ids(tx, &v, &ids)?;
            tx.execute(
                "UPDATE users SET selection = ?, selection_updated_at = ? WHERE id = ?",
                params![
                    serde_json::to_string(&ids).unwrap_or_default(),
                    crate::db::now_str(),
                    uid
                ],
            )?;
            selection_json(tx, &v, &uid)
        })
        .await?;
    Ok(ok(&out))
}

pub async fn selection_delete(State(app): State<App>, method: Method, headers: HeaderMap) -> Res {
    let (_, s) = portal_viewer(&app, &headers, &method).await?;
    let uid = s.user.id.clone();
    app.db
        .write(move |tx| {
            tx.execute(
                "UPDATE users SET selection = NULL, selection_updated_at = ? WHERE id = ?",
                params![crate::db::now_str(), uid],
            )?;
            Ok(())
        })
        .await?;
    Ok(StatusCode::NO_CONTENT.into_response())
}

// ---- self-service API keys ------------------------------------------------------------------

async fn portal_retailer(app: &App, headers: &HeaderMap, method: &Method) -> Result<Viewer> {
    let (v, _) = portal_viewer(app, headers, method).await?;
    if v.retailer_id.is_empty() {
        return Err(Problem::new(
            "forbidden",
            "Only retailer accounts have their own API keys.",
        ));
    }
    Ok(v)
}

pub async fn clients(State(app): State<App>, method: Method, headers: HeaderMap) -> Res {
    let v = portal_retailer(&app, &headers, &method).await?;
    let items = app
        .db
        .read(move |c| {
            let mut st =
                c.prepare("SELECT id FROM api_clients WHERE retailer_id = ? ORDER BY created_at")?;
            let ids = st
                .query_map([&v.retailer_id], |r| r.get::<_, String>(0))?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            let mut out = vec![];
            for id in ids {
                if let Some(cl) = super::protocol::load_client(c, "id = ?", &id)? {
                    out.push(super::admin::api_client_json(&cl));
                }
            }
            Ok(out)
        })
        .await?;
    Ok(ok(&json!({"items": items})))
}

pub async fn client_create(
    State(app): State<App>,
    method: Method,
    headers: HeaderMap,
    body: Bytes,
) -> Res {
    let v = portal_retailer(&app, &headers, &method).await?;
    let b = read_json_object(&headers, &body)?;
    let name = b
        .get("name")
        .and_then(|n| n.as_str())
        .unwrap_or("")
        .to_string();
    let scopes: Option<Vec<String>> = b.get("scopes").and_then(|v| v.as_array()).map(|a| {
        a.iter()
            .filter_map(|x| x.as_str().map(String::from))
            .collect()
    });
    let (cl, secret) = app
        .db
        .write(move |tx| {
            let s = Settings::load(tx)?;
            if !s.portal.retailer_api_self_service {
                return Err(Problem::new(
                    "forbidden",
                    "Ask the brand to create an API key for you.",
                ));
            }
            let n: i64 = tx.query_row(
                "SELECT COUNT(*) FROM api_clients WHERE retailer_id = ? AND status = 'active'",
                [&v.retailer_id],
                |r| r.get(0),
            )?;
            if n >= 5 {
                return Err(Problem::new(
                    "conflict",
                    "You can have at most 5 active API keys; revoke one first.",
                ));
            }
            let ret = load_retailer(tx, &v.retailer_id)?
                .ok_or_else(|| Problem::new("not_found", "Retailer not found."))?;
            let allowed = grant_scopes(&s, &ret);
            let scopes = scopes.unwrap_or_else(|| allowed.clone());
            if let Some(x) = scopes.iter().find(|x| !allowed.contains(x)) {
                return Err(Problem::new(
                    "validation_failed",
                    format!("Scope {x} is not available to you."),
                ));
            }
            super::admin::create_api_client(tx, &v.retailer_id, &name, Some(scopes), "retailer")
        })
        .await?;
    Ok(json(
        201,
        &super::admin::client_with_secret(&app, &cl, &secret),
    ))
}

pub async fn client_rotate(
    State(app): State<App>,
    Path(id): Path<String>,
    method: Method,
    headers: HeaderMap,
) -> Res {
    let v = portal_retailer(&app, &headers, &method).await?;
    let (cl, secret) = app
        .db
        .write(move |tx| {
            let Some(mut cl) = super::protocol::load_client(tx, "id = ?", &id)?
                .filter(|c| c.status == "active" && c.retailer_id == v.retailer_id)
            else {
                return Err(Problem::new("not_found", "API key not found."));
            };
            let s = super::admin::rotate_secret(tx, &cl.id)?;
            cl.version += 1;
            Ok((cl, s))
        })
        .await?;
    Ok(ok(&super::admin::client_with_secret(&app, &cl, &secret)))
}

pub async fn client_revoke(
    State(app): State<App>,
    Path(id): Path<String>,
    method: Method,
    headers: HeaderMap,
) -> Res {
    let v = portal_retailer(&app, &headers, &method).await?;
    app.db
        .write(move |tx| {
            if super::protocol::load_client(tx, "id = ?", &id)?
                .filter(|c| c.retailer_id == v.retailer_id)
                .is_none()
            {
                return Err(Problem::new("not_found", "API key not found."));
            }
            tx.execute("UPDATE api_clients SET status = 'revoked' WHERE id = ?", [&id])?;
            tx.execute(
                "UPDATE webhooks SET status = 'disabled' WHERE owner_type = 'client' AND owner_id = ?",
                [&id],
            )?;
            Ok(())
        })
        .await?;
    Ok(StatusCode::NO_CONTENT.into_response())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn filter_from_query() {
        let q = vec![
            ("qualifier".to_string(), "a".to_string()),
            ("qualifier".to_string(), "b, c".to_string()),
            ("color[]".to_string(), "NVY".to_string()),
            ("q".to_string(), " Coat ".to_string()),
        ];
        let f = Filter::from_query(&q);
        assert_eq!(f.qualifier, vec!["a", "b", "c"]);
        assert_eq!(f.color, vec!["NVY"]);
        assert_eq!(f.q, "Coat");
        let (w, args) = f.sql(&Viewer::admin(), "qualifier");
        assert!(w.contains("search_text LIKE ?") && !w.contains("product_qualifiers"));
        assert_eq!(args, vec!["%coat%", "NVY"]);
    }
}
