//! The OBX Ingest API (ingest.md): records by external id, files and blobs,
//! batch. Imports, jobs and resumable uploads live in crate::jobs,
//! crate::imports and crate::uploads.

use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, HeaderValue, header};
use axum::response::{IntoResponse, Response};
use rusqlite::{Connection, OptionalExtension, params};
use serde::Serialize;
use serde_json::{Map, Value, json};

use super::*;
use crate::catalog::{Writer, load_row, valid_external_id};
use crate::model::*;

#[derive(Debug, Clone, Serialize)]
pub struct IngestToken {
    pub id: String,
    pub name: String,
    pub prefix: String,
    pub status: String,
    pub created_at: String,
    pub scopes: Vec<String>,
    pub brand_external_ids: Option<Vec<String>>,
    pub expires_at: Option<String>,
    pub last_used_at: Option<String>,
}

impl IngestToken {
    pub fn has(&self, s: &str) -> bool {
        self.scopes.iter().any(|x| x == s)
    }

    pub fn effective_status(&self) -> String {
        if self.status != "active" {
            return self.status.clone();
        }
        if self
            .expires_at
            .as_deref()
            .and_then(crate::db::parse_time)
            .is_some_and(|t| t < chrono::Utc::now())
        {
            return "expired".into();
        }
        "active".into()
    }

    pub fn json(&self) -> Value {
        json!({"id": self.id, "name": self.name, "prefix": self.prefix, "scopes": self.scopes,
            "brand_external_ids": self.brand_external_ids, "status": self.effective_status(),
            "expires_at": self.expires_at, "created_at": self.created_at, "last_used_at": self.last_used_at})
    }
}

pub fn load_token(c: &Connection, where_: &str, arg: &str) -> Result<Option<IngestToken>> {
    Ok(c.query_row(
        &format!("SELECT id, name, prefix, status, created_at, scopes, brand_external_ids, expires_at, last_used_at FROM ingest_tokens WHERE {where_}"),
        [arg],
        |r| {
            Ok(IngestToken {
                id: r.get(0)?,
                name: r.get(1)?,
                prefix: r.get(2)?,
                status: r.get(3)?,
                created_at: r.get(4)?,
                scopes: r.get::<_, String>(5)?.split_whitespace().map(String::from).collect(),
                brand_external_ids: r.get::<_, Option<String>>(6)?.map(|s| serde_json::from_str(&s).unwrap_or_default()),
                expires_at: r.get(7)?,
                last_used_at: r.get(8)?,
            })
        },
    )
    .optional()?)
}

/// Authenticates an ingest call (Bearer obxi_…) and checks the scope.
pub async fn ingest_auth(app: &App, headers: &HeaderMap, scope: &str) -> Result<IngestToken> {
    if !app.setup_done().await {
        return Err(
            Problem::new("setup_required", "This node has not been set up yet.").with_status(503),
        );
    }
    let Some(tok) = bearer(headers) else {
        return Err(Problem::new(
            "unauthorized",
            "Send an ingest token: Authorization: Bearer obxi_...",
        ));
    };
    let h = crate::secure::hash_token(&tok);
    let t = app
        .db
        .read(move |c| load_token(c, "token_hash = ?", &h))
        .await?;
    let Some(t) = t else {
        return Err(Problem::new("invalid_token", "Unknown ingest token."));
    };
    if t.effective_status() != "active" {
        return Err(Problem::new(
            "access_revoked",
            "This ingest token was revoked or has expired.",
        ));
    }
    rate_limit(app, &format!("ingest:{}", t.id), 6000)?;
    if !scope.is_empty() && !t.has(scope) {
        return Err(Problem::new(
            "insufficient_scope",
            format!("This token lacks the {scope} scope."),
        ));
    }
    let stale = t
        .last_used_at
        .as_deref()
        .and_then(crate::db::parse_time)
        .is_none_or(|l| chrono::Utc::now() - l > chrono::Duration::minutes(1));
    if stale {
        let id = t.id.clone();
        let _ = app
            .db
            .write(move |tx| {
                tx.execute(
                    "UPDATE ingest_tokens SET last_used_at = ? WHERE id = ?",
                    params![crate::db::now_str(), id],
                )?;
                Ok(())
            })
            .await;
    }
    Ok(t)
}

pub async fn info(State(app): State<App>, headers: HeaderMap) -> Res {
    let t = ingest_auth(&app, &headers, "").await?;
    let (s, brands) = app
        .db
        .read(|c| {
            let s = Settings::load(c)?;
            let mut st = c.prepare("SELECT external_id, name FROM brands ORDER BY external_id")?;
            let b = st
                .query_map([], |r| Ok(json!({"external_id": r.get::<_, String>(0)?, "name": r.get::<_, String>(1)?})))?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            Ok((s, b))
        })
        .await?;
    Ok(ok(&json!({
        "token": {"id": t.id, "name": t.name, "scopes": t.scopes, "brand_external_ids": t.brand_external_ids, "expires_at": t.expires_at},
        "limits": {"max_upload_bytes": crate::app::MAX_UPLOAD_BYTES, "max_object_bytes": crate::app::MAX_OBJECT_BYTES,
                   "part_bytes": crate::app::PART_BYTES, "max_batch_operations": crate::app::MAX_BATCH_OPERATIONS,
                   "max_import_bytes": crate::app::MAX_IMPORT_BYTES},
        "renditions": {"server_generated": true, "required": ["original"]},
        "accepted_content_types": ["image/jpeg", "image/png", "image/webp", "image/tiff"],
        "default_status": s.defaults.ingest_status,
        "brands": brands,
        "languages": s.content_languages(),
    })))
}

/// Runs one write in its own transaction; a failed write is rolled back.
pub async fn write_op<F>(
    app: &App,
    allowed: Option<Vec<String>>,
    f: F,
) -> (IngestResult, Option<Problem>)
where
    F: FnOnce(&mut Writer) -> (IngestResult, Option<Problem>) + Send + 'static,
{
    let slot = std::sync::Arc::new(std::sync::Mutex::new(None::<IngestResult>));
    let s2 = slot.clone();
    let out = app
        .catalog_write(allowed, move |w| {
            let (res, prob) = f(w);
            match prob {
                Some(p) => {
                    *s2.lock().unwrap() = Some(res);
                    Err(p)
                }
                None => Ok(res),
            }
        })
        .await;
    match out {
        Ok(res) => (res, None),
        Err(p) => {
            let mut res = slot.lock().unwrap().take().unwrap_or_default();
            res.result = "error".into();
            res.error = Some(p.clone());
            (res, Some(p))
        }
    }
}

pub fn write_result(res: IngestResult, prob: Option<Problem>, location_base: &str) -> Res {
    if let Some(p) = prob {
        return Err(p);
    }
    let created = res.result == "created";
    let mut r = json(if created { 201 } else { 200 }, &res);
    if let Some(e) = res
        .etag
        .as_deref()
        .and_then(|e| HeaderValue::from_str(e).ok())
    {
        r.headers_mut().insert(header::ETAG, e);
    }
    if created && !location_base.is_empty() {
        let loc = format!(
            "{location_base}/{}",
            url::form_urlencoded::byte_serialize(res.external_id.as_bytes()).collect::<String>()
        );
        if let Ok(v) = HeaderValue::from_str(&loc) {
            r.headers_mut().insert(header::LOCATION, v);
        }
    }
    Ok(r)
}

fn kind_of(seg: &str) -> Result<&'static str> {
    kind_from_segment(seg).ok_or_else(|| Problem::new("not_found", "Not found."))
}

fn token_sees(c: &Connection, allowed: &Option<Vec<String>>, r: &crate::catalog::Row) -> bool {
    let Some(list) = allowed else { return true };
    let bid = if r.kind == KIND_BRAND {
        &r.id
    } else {
        &r.brand_id
    };
    let ext: String = c
        .query_row("SELECT external_id FROM brands WHERE id = ?", [bid], |x| {
            x.get(0)
        })
        .unwrap_or_default();
    list.contains(&ext)
}

pub async fn get_record(
    app: &App,
    kind: &'static str,
    ext: String,
    allowed: Option<Vec<String>>,
) -> Res {
    let (ext, _) = valid_external_id(&ext);
    let e2 = ext.clone();
    let rec = app
        .db
        .read(move |c| {
            let Some(row) = load_row(c, kind, &e2)?.filter(|r| token_sees(c, &allowed, r)) else {
                return Ok(None);
            };
            let s = Settings::load(c)?;
            Ok(Some((
                row.etag.clone(),
                crate::catalog::record(c, &row, &s),
            )))
        })
        .await?;
    let Some((etag, rec)) = rec else {
        return Err(Problem::new(
            "not_found",
            format!("{kind} {ext:?} does not exist."),
        ));
    };
    let mut r = ok(&rec);
    if let Ok(v) = HeaderValue::from_str(&etag) {
        r.headers_mut().insert(header::ETAG, v);
    }
    Ok(r)
}

fn if_match(h: &HeaderMap) -> String {
    h.get(header::IF_MATCH)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string()
}

/// Renders an asset's original before the write, so it is visible at once.
pub async fn prerender_doc(app: &App, doc: &Map<String, Value>) {
    if let Some(sha) = doc
        .get("files")
        .and_then(|f| f.get("original"))
        .and_then(|o| o.get("sha256"))
        .and_then(|s| s.as_str())
    {
        app.prerender(sha).await;
    }
}

pub async fn put_record(
    app: &App,
    kind: &'static str,
    ext: String,
    headers: &HeaderMap,
    body: &[u8],
    allowed: Option<Vec<String>>,
    location: String,
) -> Res {
    let doc = read_json_object(headers, body)?;
    if kind == KIND_ASSET {
        prerender_doc(app, &doc).await;
    }
    let im = if_match(headers);
    let (res, p) = write_op(app, allowed, move |w| w.upsert(kind, &ext, doc, &im)).await;
    write_result(res, p, &location)
}

pub async fn patch_record(
    app: &App,
    kind: &'static str,
    ext: String,
    headers: &HeaderMap,
    body: &[u8],
    allowed: Option<Vec<String>>,
) -> Res {
    let doc = read_json_object(headers, body)?;
    if kind == KIND_ASSET {
        prerender_doc(app, &doc).await;
    }
    let im = if_match(headers);
    let (res, p) = write_op(app, allowed, move |w| {
        w.patch("patch", kind, &ext, Value::Object(doc), &im)
    })
    .await;
    write_result(res, p, "")
}

pub async fn delete_record(
    app: &App,
    kind: &'static str,
    ext: String,
    allowed: Option<Vec<String>>,
) -> Res {
    let (res, p) = write_op(app, allowed, move |w| w.delete(kind, &ext)).await;
    write_result(res, p, "")
}

pub async fn h_get(
    State(app): State<App>,
    Path((seg, ext)): Path<(String, String)>,
    headers: HeaderMap,
) -> Res {
    let kind = kind_of(&seg)?;
    let t = ingest_auth(&app, &headers, "ingest:read").await?;
    get_record(&app, kind, ext, t.brand_external_ids).await
}

pub async fn h_put(
    State(app): State<App>,
    Path((seg, ext)): Path<(String, String)>,
    headers: HeaderMap,
    body: Bytes,
) -> Res {
    let kind = kind_of(&seg)?;
    let t = ingest_auth(&app, &headers, "ingest:write").await?;
    let loc = format!("{}/obx/v1/ingest/{seg}", app.cfg.public_url);
    put_record(&app, kind, ext, &headers, &body, t.brand_external_ids, loc).await
}

pub async fn h_patch(
    State(app): State<App>,
    Path((seg, ext)): Path<(String, String)>,
    headers: HeaderMap,
    body: Bytes,
) -> Res {
    let kind = kind_of(&seg)?;
    let t = ingest_auth(&app, &headers, "ingest:write").await?;
    patch_record(&app, kind, ext, &headers, &body, t.brand_external_ids).await
}

pub async fn h_delete(
    State(app): State<App>,
    Path((seg, ext)): Path<(String, String)>,
    headers: HeaderMap,
) -> Res {
    let kind = kind_of(&seg)?;
    let t = ingest_auth(&app, &headers, "ingest:delete").await?;
    delete_record(&app, kind, ext, t.brand_external_ids).await
}

pub async fn asset_order(
    app: &App,
    product_ext: String,
    headers: &HeaderMap,
    body: &[u8],
    allowed: Option<Vec<String>>,
) -> Res {
    let raw = read_json_object(headers, body)?;
    if !raw.contains_key("color_code") {
        return Err(Problem::new(
            "validation_failed",
            "color_code is required (null for product-wide images).",
        ));
    }
    let color = raw
        .get("color_code")
        .and_then(|v| v.as_str())
        .map(String::from);
    let list: Vec<String> = raw
        .get("asset_external_ids")
        .and_then(|v| v.as_array())
        .map(|a| {
            a.iter()
                .filter_map(|x| x.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default();
    if list.is_empty() {
        return Err(Problem::new(
            "validation_failed",
            "asset_external_ids must list the assets in order.",
        ));
    }
    let out = app
        .catalog_write(allowed, move |w| {
            w.asset_order(&product_ext, color.as_deref(), &list)
        })
        .await?;
    Ok(ok(&out))
}

pub async fn h_asset_order(
    State(app): State<App>,
    Path(ext): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Res {
    let t = ingest_auth(&app, &headers, "ingest:write").await?;
    asset_order(&app, ext, &headers, &body, t.brand_external_ids).await
}

fn check_rendition(b: &crate::app::Blob, name: &str) -> Result<()> {
    if name == "original" {
        return Ok(());
    }
    if b.content_type != "image/jpeg" {
        return Err(Problem::new(
            "validation_failed",
            format!("Rendition {name} must be a JPEG."),
        ));
    }
    let (Some(w), Some(h)) = (b.width, b.height) else {
        return Ok(());
    };
    match name {
        "web" if w.max(h) > crate::imaging::WEB_MAX as i64 => Err(Problem::new(
            "validation_failed",
            "The web rendition may be at most 2000 px on its longest side.",
        )),
        "thumb" if w.max(h) > crate::imaging::THUMB_MAX as i64 => Err(Problem::new(
            "validation_failed",
            "The thumb rendition may be at most 600 px on its longest side.",
        )),
        "square" if w != h => Err(Problem::new(
            "validation_failed",
            "The square rendition must be square.",
        )),
        _ => Ok(()),
    }
}

pub async fn put_file(
    app: &App,
    ext: String,
    name: String,
    headers: &HeaderMap,
    body: Bytes,
    allowed: Option<Vec<String>>,
) -> Res {
    if !RENDITION_NAMES.contains(&name.as_str()) {
        return Err(Problem::new(
            "not_found",
            format!("Unknown rendition {name:?}."),
        ));
    }
    let e2 = ext.clone();
    if app
        .db
        .read(move |c| load_row(c, KIND_ASSET, &e2))
        .await?
        .is_none()
    {
        return Err(Problem::new(
            "not_found",
            format!("Asset {ext:?} does not exist; create its metadata first."),
        ));
    }
    if body.len() as u64 > crate::app::MAX_UPLOAD_BYTES {
        return Err(Problem::new(
            "payload_too_large",
            "Files above 100 MiB use /uploads.",
        ));
    }
    let declared = headers
        .get("obx-content-sha256")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.trim().to_lowercase());
    let b = app.put_blob(body, declared.as_deref()).await?;
    check_rendition(&b, &name)?;
    if name == "original" {
        app.prerender(&b.sha256).await;
    }
    let sha = b.sha256.clone();
    let (res, p) = write_op(app, allowed, move |w| w.put_file(&ext, &name, &sha)).await;
    write_result(res, p, "")
}

pub async fn h_put_file(
    State(app): State<App>,
    Path((ext, name)): Path<(String, String)>,
    headers: HeaderMap,
    body: Bytes,
) -> Res {
    let t = ingest_auth(&app, &headers, "ingest:write").await?;
    put_file(&app, ext, name, &headers, body, t.brand_external_ids).await
}

pub fn is_sha256(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
}

pub async fn head_blob(app: &App, sha: &str) -> Response {
    match app.get_blob(sha).await {
        Ok(Some(_)) => axum::http::StatusCode::OK.into_response(),
        _ => axum::http::StatusCode::NOT_FOUND.into_response(),
    }
}

pub async fn put_blob(app: &App, sha: &str, body: Bytes) -> Res {
    let sha = sha.to_lowercase();
    if !is_sha256(&sha) {
        return Err(Problem::new(
            "validation_failed",
            "The path must be a lowercase hex sha256.",
        ));
    }
    if body.len() as u64 > crate::app::MAX_UPLOAD_BYTES {
        return Err(Problem::new(
            "payload_too_large",
            "Files above 100 MiB use /uploads.",
        ));
    }
    let b = app.put_blob(body, Some(&sha)).await?;
    Ok(json(if b.created { 201 } else { 200 }, &b))
}

pub async fn h_head_blob(
    State(app): State<App>,
    Path(sha): Path<String>,
    headers: HeaderMap,
) -> Res {
    ingest_auth(&app, &headers, "ingest:read").await?;
    Ok(head_blob(&app, &sha).await)
}

pub async fn h_put_blob(
    State(app): State<App>,
    Path(sha): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Res {
    ingest_auth(&app, &headers, "ingest:write").await?;
    put_blob(&app, &sha, body).await
}

// ---- batch ---------------------------------------------------------------------

#[derive(Debug, Clone, Default, Serialize, serde::Deserialize)]
pub struct Summary {
    pub created: usize,
    pub updated: usize,
    pub unchanged: usize,
    pub deleted: usize,
    pub errors: usize,
}

impl Summary {
    pub fn add(&mut self, r: &str) {
        match r {
            "created" => self.created += 1,
            "updated" => self.updated += 1,
            "unchanged" => self.unchanged += 1,
            "deleted" => self.deleted += 1,
            _ => self.errors += 1,
        }
    }
}

pub fn parse_batch(body: &[u8]) -> Result<Vec<Value>> {
    if body.len() > 64 << 20 {
        return Err(Problem::new(
            "payload_too_large",
            "Batch bodies are limited to 64 MiB; upload files as blobs first.",
        ));
    }
    let s = std::str::from_utf8(body)
        .map_err(|_| Problem::new("invalid_request", "The body is not UTF-8."))?
        .trim();
    let ops: Vec<Value> = if s.starts_with('[') {
        serde_json::from_str(s)
            .map_err(|_| Problem::new("invalid_request", "The body is not a valid JSON array."))?
    } else {
        let mut v = Vec::new();
        for (i, line) in s.lines().enumerate() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            v.push(serde_json::from_str(line).map_err(|_| {
                Problem::new(
                    "invalid_request",
                    format!("Operation {i} is not valid JSON."),
                )
            })?);
        }
        v
    };
    if ops.len() > crate::app::MAX_BATCH_OPERATIONS {
        return Err(Problem::new(
            "limit_exceeded",
            "At most 1000 operations per batch.",
        ));
    }
    Ok(ops)
}

fn run_operation(
    w: &mut Writer,
    op: &str,
    kind: &str,
    ext: &str,
    data: Option<Value>,
    if_match: &str,
) -> (IngestResult, Option<Problem>) {
    let base = || IngestResult {
        op: op.into(),
        kind: kind.into(),
        external_id: ext.into(),
        ..Default::default()
    };
    if ![KIND_BRAND, KIND_PRODUCT, KIND_VARIANT, KIND_ASSET].contains(&kind) {
        return (
            base(),
            Some(Problem::new(
                "validation_failed",
                format!("Unknown kind {kind:?}."),
            )),
        );
    }
    match op {
        "upsert" => match data {
            Some(Value::Object(m)) => w.upsert(kind, ext, m, if_match),
            _ => (
                base(),
                Some(Problem::new(
                    "invalid_request",
                    "A JSON object is required.",
                )),
            ),
        },
        "patch" => w.patch("patch", kind, ext, data.unwrap_or(Value::Null), if_match),
        "delete" => w.delete(kind, ext),
        "publish" | "unpublish" => w.set_status(op, kind, ext),
        _ => (
            base(),
            Some(Problem::new(
                "validation_failed",
                format!("Unknown op {op:?}."),
            )),
        ),
    }
}

/// Runs operations in order, each in its own transaction.
pub async fn run_batch(
    app: &App,
    ops: Vec<Value>,
    allowed: Option<Vec<String>>,
    can_delete: bool,
    mut progress: impl FnMut(usize),
) -> (Vec<IngestResult>, Summary) {
    let mut sum = Summary::default();
    let mut results = Vec::with_capacity(ops.len());
    let total = ops.len();
    for (i, op) in ops.into_iter().enumerate() {
        let o = op
            .get("op")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let k = op
            .get("kind")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let e = op
            .get("external_id")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let im = op
            .get("if_match")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let data = op.get("data").cloned().filter(|d| !d.is_null());
        let (mut res, prob) = if o == "delete" && !can_delete {
            let r = IngestResult {
                op: o.clone(),
                kind: k.clone(),
                external_id: e.clone(),
                ..Default::default()
            };
            (
                r,
                Some(Problem::new(
                    "insufficient_scope",
                    "Deleting needs the ingest:delete scope.",
                )),
            )
        } else if o.is_empty() || k.is_empty() || e.is_empty() {
            let r = IngestResult {
                op: o.clone(),
                kind: k.clone(),
                external_id: e.clone(),
                ..Default::default()
            };
            (
                r,
                Some(Problem::new(
                    "validation_failed",
                    "Each operation needs op, kind and external_id.",
                )),
            )
        } else {
            if k == KIND_ASSET {
                if let Some(Value::Object(m)) = &data {
                    prerender_doc(app, m).await;
                }
            }
            let (o2, k2, e2) = (o.clone(), k.clone(), e.clone());
            write_op(app, allowed.clone(), move |w| {
                run_operation(w, &o2, &k2, &e2, data, &im)
            })
            .await
        };
        if let Some(p) = prob {
            res.result = "error".into();
            res.error = Some(p);
        }
        if res.op.is_empty() {
            res.op = o;
        }
        if res.external_id.is_empty() {
            res.external_id = e;
        }
        res.index = Some(i);
        sum.add(&res.result);
        results.push(res);
        if i % 25 == 0 || i + 1 == total {
            progress(i + 1);
        }
    }
    (results, sum)
}

/// Replays a stored answer for an Idempotency-Key (Err: reused with another body).
pub fn replay(
    c: &Connection,
    scope: &str,
    key: &str,
    req_hash: &str,
) -> Result<Option<(u16, String)>> {
    let cutoff = crate::db::fmt_time(chrono::Utc::now() - chrono::Duration::hours(24));
    let row: Option<(String, i64, String)> = c
        .query_row(
            "SELECT request_hash, status, body FROM idempotency WHERE scope = ? AND key = ? AND created_at > ?",
            params![scope, key, cutoff],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .optional()?;
    match row {
        None => Ok(None),
        Some((h, _, _)) if h != req_hash => Err(Problem::new(
            "idempotency_key_reused",
            "This Idempotency-Key was used in the last 24 hours with a different request body; use a new key for a new request.",
        )),
        Some((_, st, body)) => Ok(Some((st as u16, body))),
    }
}

pub fn replayed(status: u16, body: String) -> Response {
    let mut r = (
        axum::http::StatusCode::from_u16(status).unwrap_or(axum::http::StatusCode::OK),
        body,
    )
        .into_response();
    r.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    r.headers_mut()
        .insert("idempotent-replayed", HeaderValue::from_static("true"));
    r
}

pub async fn remember(
    app: &App,
    scope: &str,
    key: &str,
    req_hash: &str,
    status: u16,
    body: &Value,
) {
    if key.is_empty() {
        return;
    }
    let (s, k, h, b) = (
        scope.to_string(),
        key.to_string(),
        req_hash.to_string(),
        body.to_string(),
    );
    let _ = app
        .db
        .write(move |tx| {
            tx.execute(
                "INSERT INTO idempotency (scope, key, request_hash, status, body, created_at) VALUES (?, ?, ?, ?, ?, ?) ON CONFLICT (scope, key) DO UPDATE SET request_hash = excluded.request_hash, status = excluded.status, body = excluded.body, created_at = excluded.created_at",
                params![s, k, h, status as i64, b, crate::db::now_str()],
            )?;
            Ok(())
        })
        .await;
}

pub async fn batch(
    app: &App,
    headers: &HeaderMap,
    body: Bytes,
    allowed: Option<Vec<String>>,
    can_delete: bool,
    scope: String,
    owner_type: &str,
    owner_id: &str,
) -> Res {
    let key = headers
        .get("idempotency-key")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    let req_hash = crate::catalog::hash_hex(&body);
    let scope = format!("{scope}:batch");
    if !key.is_empty() {
        let (s, k, h) = (scope.clone(), key.clone(), req_hash.clone());
        if let Some((st, b)) = app.db.read(move |c| replay(c, &s, &k, &h)).await? {
            return Ok(replayed(st, b));
        }
    }
    let ops = parse_batch(&body)?;
    let prefer_async = headers
        .get("prefer")
        .and_then(|v| v.to_str().ok())
        .is_some_and(|p| p.contains("respond-async"));
    if prefer_async || ops.len() > 200 {
        let total = ops.len();
        let payload = json!({"ops": ops, "allowed": allowed, "can_delete": can_delete});
        let job = crate::jobs::create_job(
            app,
            "batch",
            owner_type,
            owner_id,
            payload,
            Some(total as i64),
        )
        .await?;
        let out = crate::jobs::ingest_job_json(app, &job).await?;
        remember(app, &scope, &key, &req_hash, 202, &out).await;
        let mut r = json(202, &out);
        if let Some(v) = out["results_url"]
            .as_str()
            .and_then(|s| HeaderValue::from_str(s).ok())
        {
            r.headers_mut().insert(header::LOCATION, v);
        }
        return Ok(r);
    }
    let (results, sum) = run_batch(app, ops, allowed, can_delete, |_| {}).await;
    let out = json!({"results": results, "summary": sum});
    remember(app, &scope, &key, &req_hash, 200, &out).await;
    Ok(ok(&out))
}

pub async fn h_batch(State(app): State<App>, headers: HeaderMap, body: Bytes) -> Res {
    let t = ingest_auth(&app, &headers, "ingest:write").await?;
    let scope = format!("ingest:{}", t.id);
    batch(
        &app,
        &headers,
        body,
        t.brand_external_ids.clone(),
        t.has("ingest:delete"),
        scope,
        "ingest_token",
        &t.id,
    )
    .await
}
