//! Bulk exports (protocol.md §9): a background job writes a manifest
//! (NDJSON) and zip parts of at most 2 GiB to the blob store; the client
//! reads them by token or by signed URL for 48 hours.

use std::collections::{BTreeSet, HashMap, HashSet};
use std::io::Write;
use std::path::PathBuf;

use axum::body::{Body, Bytes};
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, HeaderValue, Method, header};
use axum::response::Response;
use rusqlite::{Connection, OptionalExtension, params};
use serde_json::{Map, Value, json};
use sha2::Digest;

use crate::app::App;
use crate::db;
use crate::export_proto::*;
use crate::http::protocol::{product_details, protocol_auth, rendition_filename, viewer_from_tag};
use crate::http::{
    MAX_JSON_BODY, Res, Viewer, content_disposition, json as json_resp, ok, with_headers,
};
use crate::jobs::Job;
use crate::problem::{Problem, Result};
use crate::store::blob_key;

fn expired(j: &Job) -> bool {
    j.expires_at
        .as_deref()
        .and_then(db::parse_time)
        .is_some_and(|t| t < chrono::Utc::now())
}

/// The Export document of a job for viewer v (fresh signed URLs).
pub fn export_json(app: &App, j: &Job, v: &Viewer) -> Value {
    let status = if expired(j) {
        "expired"
    } else {
        j.status.as_str()
    };
    let mut out = json!({"id": j.id, "status": status, "created_at": j.created_at, "finished_at": j.finished_at,
        "expires_at": j.expires_at, "progress": {"done": j.done, "total": j.total}, "manifest_url": null,
        "parts": [], "error": null});
    if status == "failed" {
        if let Some(e) = &j.error {
            out["error"] = serde_json::to_value(Problem::new("internal_error", e.clone()))
                .unwrap_or(Value::Null);
        }
    }
    if status == "succeeded" {
        let res: ExportResult = j
            .result
            .as_deref()
            .and_then(|r| serde_json::from_str(r).ok())
            .unwrap_or_default();
        let (mu, _) = app.signed_url(&format!("/obx/v1/exports/{}/manifest", j.id), &v.tag());
        out["manifest_url"] = Value::String(mu);
        out["parts"] = res
            .parts
            .iter()
            .map(|p| {
                let (u, _) = app.signed_url(&format!("/obx/v1/exports/{}/parts/{}", j.id, p.number), &v.tag());
                json!({"number": p.number, "url": u, "bytes": p.bytes, "sha256": p.sha256, "files": p.files})
            })
            .collect();
    }
    out
}

fn validation(errs: Vec<crate::schemas::FieldError>) -> Problem {
    let mut p = Problem::new("validation_failed", "The request body is not valid.");
    for e in errs {
        p = p.field(&e.pointer, "validation_failed", e.message);
    }
    p
}

/// POST /obx/v1/exports
pub async fn h_create(State(app): State<App>, headers: HeaderMap, body: Bytes) -> Res {
    let (v, hs) = protocol_auth(&app, &headers, "catalog:read", false).await?;
    if body.len() > MAX_JSON_BODY {
        return Err(Problem::new(
            "payload_too_large",
            "The request body is too large.",
        ));
    }
    let key = headers
        .get("idempotency-key")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    let scope = format!("export:{}", v.client_row_id);
    let req_hash = crate::catalog::hash_hex(&body);
    if !key.is_empty() {
        let (s, k, h) = (scope.clone(), key.clone(), req_hash.clone());
        if let Some((st, b)) = app
            .db
            .read(move |c| crate::http::ingest::replay(c, &s, &k, &h))
            .await?
        {
            return Ok(crate::http::ingest::replayed(st, b));
        }
    }
    let raw: Map<String, Value> = match serde_json::from_slice(&body) {
        Ok(Value::Object(m)) => m,
        _ => {
            return Err(Problem::new(
                "invalid_request",
                "The body must be an ExportRequest JSON object.",
            ));
        }
    };
    let raw = Value::Object(raw);
    let errs = crate::schemas::validate("ExportRequest", &raw);
    if !errs.is_empty() {
        return Err(validation(errs));
    }
    let req: ExportRequest = serde_json::from_value(raw).map_err(|e| {
        Problem::new(
            "validation_failed",
            format!("The request body is not valid: {e}"),
        )
    })?;
    for rn in &req.renditions {
        if rn == "original" && !v.original_allowed {
            return Err(Problem::new(
                "original_not_allowed",
                "Original files are not available to you.",
            ));
        }
        if rn != "original" && !v.has_scope("media:read") {
            return Err(Problem::new(
                "insufficient_scope",
                "Exporting files needs the media:read scope.",
            ));
        }
    }
    let owner = v.client_row_id.clone();
    let running: Option<String> = app
        .db
        .read(move |c| {
            Ok(c.query_row(
                "SELECT id FROM jobs WHERE kind = 'export' AND owner_id = ? AND status IN ('queued', 'running')",
                [&owner],
                |r| r.get(0),
            )
            .optional()?)
        })
        .await?;
    if let Some(id) = running {
        return Err(Problem::new(
            "conflict",
            format!("Export {id} is still running; wait for it to finish."),
        ));
    }
    let job = crate::jobs::create_job(
        &app,
        "export",
        "client",
        &v.client_row_id,
        serde_json::to_value(&req).unwrap_or_default(),
        None,
    )
    .await?;
    let out = export_json(&app, &job, &v);
    crate::http::ingest::remember(&app, &scope, &key, &req_hash, 202, &out).await;
    let mut r = json_resp(202, &out);
    if let Ok(l) =
        HeaderValue::from_str(&format!("{}/obx/v1/exports/{}", app.cfg.public_url, job.id))
    {
        r.headers_mut().insert(header::LOCATION, l);
    }
    Ok(with_headers(r, &hs))
}

/// Authenticates an export read by bearer token or signed URL and loads
/// the job; another client's export is not found (S-ISO-1).
async fn export_viewer(
    app: &App,
    headers: &HeaderMap,
    path: &str,
    q: &HashMap<String, String>,
    id: &str,
    scope: &str,
) -> Result<(Viewer, Job, Vec<(String, String)>)> {
    let (v, hs) = if crate::http::bearer(headers).is_none()
        && q.get("sig").is_some_and(|s| !s.is_empty())
    {
        let tag = app.verify_signed(path, q).ok_or_else(|| {
            Problem::new(
                "forbidden",
                "This link has expired or does not match its signature; read the export again for a fresh link.",
            )
        })?;
        let v = app.db.read(move |c| viewer_from_tag(c, &tag)).await?;
        (v, vec![])
    } else {
        let (v, hs) = protocol_auth(app, headers, scope, false).await?;
        (v, hs.to_vec())
    };
    let j = crate::jobs::load_job(app, id).await?;
    match j {
        Some(j)
            if j.kind == "export"
                && !v.client_row_id.is_empty()
                && j.owner_id.as_deref() == Some(v.client_row_id.as_str()) =>
        {
            Ok((v, j, hs))
        }
        _ => Err(Problem::new("not_found", "Export not found.")),
    }
}

/// GET /obx/v1/exports/{id}
pub async fn h_get(
    State(app): State<App>,
    Path(id): Path<String>,
    Query(q): Query<HashMap<String, String>>,
    headers: HeaderMap,
) -> Res {
    let path = format!("/obx/v1/exports/{id}");
    let (v, j, hs) = export_viewer(&app, &headers, &path, &q, &id, "catalog:read").await?;
    Ok(with_headers(ok(&export_json(&app, &j, &v)), &hs))
}

fn ready(j: &Job) -> Result<()> {
    if expired(j) || j.status == "expired" {
        return Err(Problem::new(
            "export_expired",
            "This export expired; start a new one.",
        ));
    }
    if j.status != "succeeded" {
        return Err(Problem::new("not_found", "The export is not finished yet."));
    }
    Ok(())
}

/// GET /obx/v1/exports/{id}/manifest
pub async fn h_manifest(
    State(app): State<App>,
    Path(id): Path<String>,
    Query(q): Query<HashMap<String, String>>,
    headers: HeaderMap,
    method: Method,
) -> Res {
    let path = format!("/obx/v1/exports/{id}/manifest");
    let (_, j, hs) = export_viewer(&app, &headers, &path, &q, &id, "catalog:read").await?;
    ready(&j)?;
    let key = manifest_key(&j.id);
    let r = serve_object(
        &app,
        &headers,
        &method,
        &key,
        "application/x-ndjson",
        "",
        None,
    )
    .await?;
    Ok(with_headers(r, &hs))
}

/// GET /obx/v1/exports/{id}/parts/{n}
pub async fn h_part(
    State(app): State<App>,
    Path((id, n)): Path<(String, String)>,
    Query(q): Query<HashMap<String, String>>,
    headers: HeaderMap,
    method: Method,
) -> Res {
    let path = format!("/obx/v1/exports/{id}/parts/{n}");
    let (v, j, hs) = export_viewer(&app, &headers, &path, &q, &id, "media:read").await?;
    ready(&j)?;
    let res: ExportResult = j
        .result
        .as_deref()
        .and_then(|r| serde_json::from_str(r).ok())
        .unwrap_or_default();
    let num: usize = n.parse().unwrap_or(0);
    if num < 1 || num > res.parts.len() {
        return Err(Problem::new("not_found", "Part not found."));
    }
    let part = res.parts[num - 1].clone();
    let key = part_key(&j.id, num);
    let disp = content_disposition("attachment", &part_filename(&j.id, num));
    let r = serve_object(
        &app,
        &headers,
        &method,
        &key,
        "application/zip",
        &disp,
        Some(&part.sha256),
    )
    .await?;
    if method == Method::GET && !continuation_range(&headers) && r.status().is_success() {
        log_download_tmp(&app, &v, "api_export", part.files as i64, part.bytes as i64).await;
    }
    Ok(with_headers(r, &hs))
}

/// A Range that does not start at byte 0 continues a download already
/// counted (node-go isContinuationRange).
pub fn continuation_range(h: &HeaderMap) -> bool {
    h.get(header::RANGE)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|r| !r.is_empty() && !r.starts_with("bytes=0-"))
}

// TODO(merge): replace with crate::stats::log_download (main lane).
async fn log_download_tmp(app: &App, v: &Viewer, kind: &str, files: i64, bytes: i64) {
    if v.kind != "client" || v.retailer_id.is_empty() {
        return;
    }
    let (rid, rname, cid, kind) = (
        v.retailer_id.clone(),
        v.retailer_name.clone(),
        v.client_row_id.clone(),
        kind.to_string(),
    );
    let _ = app
        .db
        .write(move |tx| {
            let now = db::now_str();
            let cname: Option<String> = tx
                .query_row("SELECT name FROM api_clients WHERE id = ?", [&cid], |r| r.get(0))
                .optional()?;
            tx.execute(
                "INSERT INTO download_events (id, at, kind, retailer_id, retailer_name, actor_type, actor_id, actor_name, files, bytes) VALUES (?, ?, ?, ?, ?, 'api_client', ?, ?, ?, ?)",
                params![crate::ids::new("dle"), now, kind, rid, rname, cid, cname, files, (bytes > 0).then_some(bytes)],
            )?;
            tx.execute("UPDATE retailers SET last_activity_at = ? WHERE id = ?", params![now, rid])?;
            Ok(())
        })
        .await;
}

fn parse_range(h: &str, size: u64) -> Option<std::ops::Range<u64>> {
    let spec = h.strip_prefix("bytes=")?;
    if spec.contains(',') {
        return None;
    }
    let (a, b) = spec.split_once('-')?;
    let (start, end) = if a.is_empty() {
        let n: u64 = b.parse().ok()?;
        if n == 0 {
            return None;
        }
        (size.saturating_sub(n), size)
    } else {
        let s: u64 = a.parse().ok()?;
        let e: u64 = if b.is_empty() {
            size
        } else {
            (b.parse::<u64>().ok()?.saturating_add(1)).min(size)
        };
        (s, e)
    };
    (start < end && start < size).then_some(start..end)
}

/// Streams a stored object (not a content-addressed blob) with Range
/// support; sha, when known, becomes the ETag and OBX-Content-SHA256.
pub async fn serve_object(
    app: &App,
    headers: &HeaderMap,
    method: &Method,
    key: &str,
    ct: &str,
    disposition: &str,
    sha: Option<&str>,
) -> Res {
    let Some(size) = app.store.size(key).await.map_err(Problem::internal)? else {
        return Err(Problem::new(
            "export_expired",
            "The export files were deleted.",
        ));
    };
    let mut b = axum::http::Response::builder()
        .header(header::CONTENT_TYPE, ct)
        .header(header::ACCEPT_RANGES, "bytes")
        .header(header::CACHE_CONTROL, "private")
        .header("X-Content-Type-Options", "nosniff");
    let etag = sha.map(|s| format!("\"{s}\""));
    if let (Some(s), Some(e)) = (sha, &etag) {
        b = b.header("OBX-Content-SHA256", s).header(header::ETAG, e);
        if headers
            .get(header::IF_NONE_MATCH)
            .and_then(|v| v.to_str().ok())
            .is_some_and(|m| m.split(',').any(|x| x.trim() == e || x.trim() == "*"))
        {
            return Ok(b.status(304).body(Body::empty()).unwrap());
        }
    }
    if !disposition.is_empty() {
        b = b.header(header::CONTENT_DISPOSITION, disposition);
    }
    if let Some(rh) = headers.get(header::RANGE).and_then(|v| v.to_str().ok()) {
        let if_range_ok = headers
            .get(header::IF_RANGE)
            .and_then(|v| v.to_str().ok())
            .is_none_or(|v| etag.as_deref() == Some(v));
        if if_range_ok {
            return match parse_range(rh, size) {
                Some(r) => {
                    let b = b
                        .status(206)
                        .header(
                            header::CONTENT_RANGE,
                            format!("bytes {}-{}/{size}", r.start, r.end - 1),
                        )
                        .header(header::CONTENT_LENGTH, r.end - r.start);
                    if *method == Method::HEAD {
                        return Ok(b.body(Body::empty()).unwrap());
                    }
                    let data = app
                        .store
                        .get_range(key, r)
                        .await
                        .map_err(Problem::internal)?;
                    Ok(b.body(Body::from(data)).unwrap())
                }
                None => Ok(b
                    .status(416)
                    .header(header::CONTENT_RANGE, format!("bytes */{size}"))
                    .body(Body::empty())
                    .unwrap()),
            };
        }
    }
    let b = b.status(200).header(header::CONTENT_LENGTH, size);
    if *method == Method::HEAD {
        return Ok(b.body(Body::empty()).unwrap());
    }
    let Some(stream) = app.store.get_stream(key).await.map_err(Problem::internal)? else {
        return Err(Problem::new(
            "export_expired",
            "The export files were deleted.",
        ));
    };
    Ok(b.body(Body::from_stream(stream)).unwrap())
}

// ---- the job ---------------------------------------------------------------------------

/// One file written to a zip part.
#[derive(Debug, Clone)]
pub struct Entry {
    pub part: usize,
    pub path: String,
    pub bytes: u64,
    pub sha256: String,
}

/// Writes zip parts of at most `max` bytes to temporary files; parts are
/// stored uncompressed (images do not compress).
pub struct ZipParts {
    dir: PathBuf,
    max: u64,
    cur: Option<zip::ZipWriter<std::fs::File>>,
    size: u64,
    files: usize,
    paths: HashSet<String>,
    /// (path of the finished part file, files in it)
    pub parts: Vec<(PathBuf, usize)>,
}

impl ZipParts {
    pub fn new(max: u64) -> std::io::Result<ZipParts> {
        let dir = std::env::temp_dir().join(format!("obx-zip-{}", crate::ids::new("tmp")));
        std::fs::create_dir_all(&dir)?;
        Ok(ZipParts {
            dir,
            max,
            cur: None,
            size: 0,
            files: 0,
            paths: HashSet::new(),
            parts: vec![],
        })
    }

    fn open(&mut self) -> std::io::Result<()> {
        let p = self.dir.join(format!("part-{}.zip", self.parts.len() + 1));
        let f = std::fs::File::create(&p)?;
        self.cur = Some(zip::ZipWriter::new(f));
        self.size = 0;
        self.files = 0;
        self.paths.clear();
        Ok(())
    }

    fn close_part(&mut self) -> std::io::Result<()> {
        if let Some(w) = self.cur.take() {
            w.finish().map_err(std::io::Error::other)?;
            let p = self.dir.join(format!("part-{}.zip", self.parts.len() + 1));
            self.parts.push((p, self.files));
        }
        Ok(())
    }

    fn unique(&mut self, p: &str) -> String {
        if self.paths.insert(p.to_string()) {
            return p.to_string();
        }
        let (base, ext) = match (p.rfind('.'), p.rfind('/')) {
            (Some(i), Some(j)) if i > j => (&p[..i], &p[i..]),
            (Some(i), None) => (&p[..i], &p[i..]),
            _ => (p, ""),
        };
        let mut i = 2;
        loop {
            let c = format!("{base}-{i}{ext}");
            if self.paths.insert(c.clone()) {
                return c;
            }
            i += 1;
        }
    }

    fn opts(method: zip::CompressionMethod) -> zip::write::SimpleFileOptions {
        use chrono::{Datelike, Timelike};
        let n = chrono::Utc::now();
        let mut o = zip::write::SimpleFileOptions::default()
            .compression_method(method)
            .large_file(false);
        if let Ok(t) = zip::DateTime::from_date_and_time(
            n.year() as u16,
            n.month() as u8,
            n.day() as u8,
            n.hour() as u8,
            n.minute() as u8,
            n.second() as u8,
        ) {
            o = o.last_modified_time(t);
        }
        o
    }

    /// Adds a stored file; starts a new part when this one would grow past
    /// the limit (a part holds at least one file).
    pub fn add(&mut self, path: &str, data: &[u8]) -> std::io::Result<Entry> {
        let n = data.len() as u64;
        if self.cur.is_none() || (self.files > 0 && self.size + n > self.max) {
            self.close_part()?;
            self.open()?;
        }
        let path = self.unique(path);
        let w = self.cur.as_mut().unwrap();
        w.start_file(path.as_str(), Self::opts(zip::CompressionMethod::Stored))
            .map_err(std::io::Error::other)?;
        w.write_all(data)?;
        self.size += n + path.len() as u64 + 100;
        self.files += 1;
        Ok(Entry {
            part: self.parts.len() + 1,
            path,
            bytes: n,
            sha256: hex::encode(sha2::Sha256::digest(data)),
        })
    }

    /// Adds a small generated file (compressed) to the current part.
    #[allow(dead_code)]
    pub fn add_bytes(&mut self, name: &str, data: &[u8]) -> std::io::Result<()> {
        if self.cur.is_none() {
            self.open()?;
        }
        let name = self.unique(name);
        let w = self.cur.as_mut().unwrap();
        w.start_file(name.as_str(), Self::opts(zip::CompressionMethod::Deflated))
            .map_err(std::io::Error::other)?;
        w.write_all(data)?;
        self.size += data.len() as u64;
        Ok(())
    }

    /// Closes the last part; an export without files still has one (empty) part.
    pub fn finish(&mut self) -> std::io::Result<()> {
        if self.cur.is_none() && self.parts.is_empty() {
            self.open()?;
        }
        self.close_part()
    }
}

impl Drop for ZipParts {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

/// The visible product ids an export covers, in id order.
fn export_product_ids(c: &Connection, v: &Viewer, req: &ExportRequest) -> Result<Vec<String>> {
    let mut q = "SELECT id FROM products WHERE visible = 1".to_string();
    let (bf, mut args) = v.brand_filter("brand_id");
    q.push_str(&bf);
    if let Some(b) = &req.filter.brand_ids {
        if b.is_empty() {
            return Ok(vec![]);
        }
        q.push_str(&format!(" AND brand_id IN {}", db::in_list(b.len())));
        args.extend(b.iter().cloned());
    }
    if let Some(t) = req.filter.updated_since.as_deref().and_then(db::parse_time) {
        q.push_str(" AND touched_at >= ?");
        args.push(db::fmt_time(t));
    }
    q.push_str(" ORDER BY id");
    let mut st = c.prepare(&q)?;
    let mut ids: Vec<String> = st
        .query_map(rusqlite::params_from_iter(args.iter()), |r| r.get(0))?
        .collect::<rusqlite::Result<_>>()?;
    if let Some(p) = &req.filter.product_ids {
        let set: HashSet<&String> = p.iter().collect();
        ids.retain(|i| set.contains(i));
    }
    if let Some(g) = &req.filter.gtins {
        let mut set = HashSet::new();
        for x in g {
            if let Some(n) = crate::catalog::normalize_gtin(x) {
                if let Some(pid) = c
                    .query_row(
                        "SELECT product_id FROM variants WHERE gtin = ? AND visible = 1",
                        [&n],
                        |r| r.get::<_, String>(0),
                    )
                    .optional()?
                {
                    set.insert(pid);
                }
            }
        }
        ids.retain(|i| set.contains(i));
    }
    Ok(ids)
}

type JobOutcome = std::result::Result<Option<Value>, (Option<Value>, String)>;

/// Runs an export job (jobs.rs dispatches kind "export" here).
pub async fn run_export_job(app: &App, j: &Job) -> JobOutcome {
    run(app, j).await.map(Some).map_err(|e| (None, e))
}

async fn run(app: &App, j: &Job) -> std::result::Result<Value, String> {
    let req: ExportRequest = serde_json::from_str(&j.payload).map_err(|e| e.to_string())?;
    let owner = j.owner_id.clone().unwrap_or_default();
    let r2 = req.clone();
    let a = app.clone();
    let (v, ids, cursor) = app
        .db
        .read(move |c| {
            let v = viewer_from_tag(c, &format!("c.{owner}"))?;
            let cursor = crate::http::feed::live_cursor(&a, c)?;
            let ids = export_product_ids(c, &v, &r2)?;
            Ok((v, ids, cursor))
        })
        .await
        .map_err(|p| p.detail_str().to_string())?;
    let include_data = req.include_data.unwrap_or(true);
    let total = ids.len() as i64;
    crate::jobs::progress(app, &j.id, 0, Some(total)).await;
    let mut lines: Vec<Value> = vec![];
    let mut file_lines: Vec<Value> = vec![];
    let mut counts = json!({"products": 0, "variants": 0, "assets": 0, "files": 0});
    let mut zp = ZipParts::new(PART_MAX).map_err(|e| e.to_string())?;
    let mut brands: BTreeSet<String> = BTreeSet::new();
    for (ci, chunk) in ids.chunks(50).enumerate() {
        let (a, v2, ch) = (app.clone(), v.clone(), chunk.to_vec());
        let (products, brand_reps) = app
            .db
            .read(move |c| {
                let ps = product_details(&a, c, &v2, &ch)?;
                let mut reps = HashMap::new();
                for p in &ps {
                    let b = p["brand_id"].as_str().unwrap_or("").to_string();
                    if let Some(row) =
                        crate::catalog::load_row_by_id(c, crate::model::KIND_BRAND, &b)?
                    {
                        reps.insert(
                            b,
                            crate::http::protocol::render_plain(&row.rep, &row.updated_at),
                        );
                    }
                }
                Ok((ps, reps))
            })
            .await
            .map_err(|p| p.detail_str().to_string())?;
        for mut p in products {
            let bid = p["brand_id"].as_str().unwrap_or("").to_string();
            if brands.insert(bid.clone()) && include_data {
                if let Some(b) = brand_reps.get(&bid) {
                    lines.push(json!({"type": "brand", "data": b}));
                }
            }
            let obj = p.as_object_mut().unwrap();
            let vs = obj
                .remove("variants")
                .and_then(|x| x.as_array().cloned())
                .unwrap_or_default();
            let asts = obj
                .remove("assets")
                .and_then(|x| x.as_array().cloned())
                .unwrap_or_default();
            let style = p["style_number"].as_str().unwrap_or("").to_string();
            counts["products"] = json!(counts["products"].as_i64().unwrap_or(0) + 1);
            counts["variants"] = json!(counts["variants"].as_i64().unwrap_or(0) + vs.len() as i64);
            counts["assets"] = json!(counts["assets"].as_i64().unwrap_or(0) + asts.len() as i64);
            if include_data {
                lines.push(json!({"type": "product", "data": p}));
                for x in &vs {
                    lines.push(json!({"type": "variant", "data": x}));
                }
                for x in &asts {
                    lines.push(json!({"type": "asset", "data": x}));
                }
            }
            for x in &asts {
                for rn in &req.renditions {
                    let Some(rend) = x["renditions"].get(rn) else {
                        continue;
                    };
                    let sha = rend["sha256"].as_str().unwrap_or("").to_string();
                    let filename = x["filename"].as_str().unwrap_or("");
                    let name = if rn == "original" {
                        filename.to_string()
                    } else {
                        rendition_filename(filename, rn)
                    };
                    let path = entry_path(&style, rn, &name);
                    let data = app
                        .store
                        .get(&blob_key(&sha))
                        .await?
                        .ok_or_else(|| format!("file {sha} missing"))?;
                    let e = zp.add(&path, &data).map_err(|e| e.to_string())?;
                    file_lines.push(
                        json!({"type": "file", "asset_id": x["id"], "rendition": rn, "part": e.part,
                        "path": e.path, "bytes": e.bytes, "sha256": e.sha256}),
                    );
                    counts["files"] = json!(counts["files"].as_i64().unwrap_or(0) + 1);
                }
            }
        }
        let done = ((ci + 1) * 50).min(ids.len()) as i64;
        crate::jobs::progress(app, &j.id, done, Some(total)).await;
    }
    zp.finish().map_err(|e| e.to_string())?;
    let mut manifest = Vec::new();
    let header = json!({"type": "header", "export_id": j.id, "created_at": j.created_at, "obx_version": crate::app::OBX_VERSION,
        "changes_cursor": cursor, "counts": counts});
    for l in std::iter::once(&header)
        .chain(lines.iter())
        .chain(file_lines.iter())
    {
        serde_json::to_writer(&mut manifest, l).map_err(|e| e.to_string())?;
        manifest.push(b'\n');
    }
    app.store
        .put(&manifest_key(&j.id), Bytes::from(manifest))
        .await?;
    let mut res = ExportResult {
        cursor,
        parts: vec![],
    };
    for (i, (path, files)) in zp.parts.iter().enumerate() {
        let sha = file_sha256(path).await.map_err(|e| e.to_string())?;
        let n = app.store.put_file(&part_key(&j.id, i + 1), path).await?;
        res.parts.push(ExportPart {
            number: i + 1,
            bytes: n,
            sha256: sha,
            files: *files,
        });
    }
    let id = j.id.clone();
    let exp = db::fmt_time(chrono::Utc::now() + chrono::Duration::hours(EXPORT_TTL_HOURS));
    app.db
        .write(move |tx| {
            tx.execute(
                "UPDATE jobs SET expires_at = ? WHERE id = ?",
                params![exp, id],
            )?;
            Ok(())
        })
        .await
        .map_err(|p| p.detail_str().to_string())?;
    serde_json::to_value(&res).map_err(|e| e.to_string())
}

async fn file_sha256(path: &std::path::Path) -> std::io::Result<String> {
    let p = path.to_path_buf();
    tokio::task::spawn_blocking(move || {
        let mut f = std::fs::File::open(p)?;
        let mut h = sha2::Sha256::new();
        std::io::copy(&mut f, &mut h)?;
        Ok(hex::encode(h.finalize()))
    })
    .await
    .map_err(std::io::Error::other)?
}

/// Deletes the files of expired exports and marks them expired.
pub async fn cleanup(app: &App) {
    let now = db::now_str();
    let ids: Vec<String> = app
        .db
        .read(move |c| {
            let mut st = c.prepare("SELECT id FROM jobs WHERE kind = 'export' AND expires_at IS NOT NULL AND expires_at < ? AND status = 'succeeded'")?;
            let r = st.query_map([&now], |r| r.get(0))?.collect::<rusqlite::Result<Vec<String>>>()?;
            Ok(r)
        })
        .await
        .unwrap_or_default();
    for id in ids {
        if app
            .store
            .delete_prefix(&format!("exports/{id}/"))
            .await
            .is_err()
        {
            continue;
        }
        let i = id.clone();
        let _ = app
            .db
            .write(move |tx| {
                tx.execute("UPDATE jobs SET status = 'expired' WHERE id = ?", [&i])?;
                Ok(())
            })
            .await;
    }
}

/// The response type for handlers that only return a Response.
#[allow(dead_code)]
pub type Resp = Response;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zip_parts_split_and_unique_names() {
        let mut z = ZipParts::new(450).unwrap();
        let a = z.add("S1/web/a.jpg", &[1u8; 100]).unwrap();
        let b = z.add("S1/web/a.jpg", &[2u8; 100]).unwrap();
        let c = z.add("S1/web/b.jpg", &[3u8; 100]).unwrap();
        z.finish().unwrap();
        assert_eq!((a.part, a.path.as_str()), (1, "S1/web/a.jpg"));
        assert_eq!(b.path, "S1/web/a-2.jpg");
        assert_eq!(c.part, 2);
        assert_eq!(z.parts.len(), 2);
        let f = std::fs::File::open(&z.parts[0].0).unwrap();
        let mut zr = zip::ZipArchive::new(f).unwrap();
        assert_eq!(zr.len(), 2);
        let mut buf = vec![];
        std::io::Read::read_to_end(&mut zr.by_name("S1/web/a-2.jpg").unwrap(), &mut buf).unwrap();
        assert_eq!(buf, vec![2u8; 100]);
        assert_eq!(b.sha256, hex::encode(sha2::Sha256::digest([2u8; 100])));
    }

    #[test]
    fn empty_export_has_one_part() {
        let mut z = ZipParts::new(PART_MAX).unwrap();
        z.finish().unwrap();
        assert_eq!(z.parts.len(), 1);
        let dir = z.dir.clone();
        drop(z);
        assert!(!dir.exists());
    }

    #[test]
    fn ranges() {
        assert_eq!(parse_range("bytes=0-9", 100), Some(0..10));
        assert_eq!(parse_range("bytes=-10", 100), Some(90..100));
        assert_eq!(parse_range("bytes=95-", 100), Some(95..100));
        assert_eq!(parse_range("bytes=100-", 100), None);
        assert_eq!(
            parse_range("bytes=0-18446744073709551615", 100),
            Some(0..100)
        );
    }
}
