//! Portal downloads: single images, product and selection zips (streamed),
//! `data.csv` in the canonical import format, and background download jobs
//! for large selections. Every zip carries an `assets.csv` with the rights,
//! embargo and AI provenance of its images (import-format.md §2.3).

use std::collections::{BTreeSet, HashMap, HashSet};

use axum::body::{Body, Bytes};
use axum::extract::{Path, RawQuery, State};
use axum::http::{HeaderMap, HeaderValue, Method, header};
use axum::response::Response;
use rusqlite::{Connection, params};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use super::portal::{
    Filter, SYNC_ZIP_MAX_FILES, brand_names, portal_viewer, query_get, query_pairs, selected_ids,
    visible_product_ids,
};
use super::protocol::{product_details, rendition_filename, serve_blob};
use super::*;
use crate::store::blob_key;
use crate::zipout::{ZipOut, safe_segment, unique_name};

/// Download jobs are kept for a week.
const DOWNLOAD_TTL_DAYS: i64 = 7;

/// `?variant=`: original (when allowed), web or square; the default is the
/// original for whoever may have it, else web.
pub fn choose_variant(v: &Viewer, param: &str) -> Result<&'static str> {
    match param {
        "" => Ok(if v.original_allowed {
            "original"
        } else {
            "web"
        }),
        "original" if v.original_allowed => Ok("original"),
        "original" => Err(Problem::new(
            "original_not_allowed",
            "Original files are not available to you.",
        )),
        "web" => Ok("web"),
        "square" => Ok("square"),
        _ => Err(Problem::new(
            "invalid_request",
            "variant must be original, web or square.",
        )),
    }
}

/// One file of a zip.
#[derive(Debug, Clone)]
pub struct ZipFile {
    pub path: String,
    pub sha256: String,
    pub asset: Value,
    pub style: String,
}

/// The stored file and download name of an asset in a variant.
fn asset_file(asset: &Value, variant: &str) -> Option<(String, i64, String, String)> {
    let r = asset["renditions"].get(variant)?;
    let filename = asset["filename"].as_str().unwrap_or("file");
    let name = if variant == "original" {
        filename.to_string()
    } else {
        rendition_filename(filename, variant)
    };
    Some((
        r["sha256"].as_str()?.to_string(),
        r["bytes"].as_i64().unwrap_or(0),
        r["content_type"].as_str().unwrap_or("").to_string(),
        obx_axum::sanitize_filename(&name),
    ))
}

/// A viewer that sees every rendition of what v sees (originals are chosen
/// by the variant, which was checked already).
fn full(v: &Viewer) -> Viewer {
    Viewer {
        original_allowed: true,
        ..v.clone()
    }
}

/// The files of products in a variant; `folders` puts each product in a
/// folder named after its style number. Paths are unique.
pub fn zip_files_for(
    app: &App,
    c: &Connection,
    v: &Viewer,
    ids: &[String],
    variant: &str,
    folders: bool,
) -> Result<Vec<ZipFile>> {
    let fv = full(v);
    let mut out = Vec::new();
    let mut seen = HashSet::new();
    for chunk in ids.chunks(100) {
        for p in product_details(app, c, &fv, chunk)? {
            let style = p["style_number"].as_str().unwrap_or("").to_string();
            for a in p["assets"].as_array().into_iter().flatten() {
                let Some((sha, _, _, name)) = asset_file(a, variant) else {
                    continue;
                };
                let path = if folders {
                    format!("{}/{name}", safe_segment(&style))
                } else {
                    name
                };
                out.push(ZipFile {
                    path: unique_name(&mut seen, &path),
                    sha256: sha,
                    asset: a.clone(),
                    style: style.clone(),
                });
            }
        }
    }
    Ok(out)
}

// ---- CSV ---------------------------------------------------------------------------------

/// Neutralises spreadsheet formulas: a cell starting with = + - @ or a tab
/// or carriage return gets a leading apostrophe, unless it is a number.
pub fn csv_safe(s: &str) -> String {
    static NUM: std::sync::LazyLock<regex::Regex> =
        std::sync::LazyLock::new(|| regex::Regex::new(r"^[+-]?[0-9]+([.,][0-9]+)?$").unwrap());
    if s.is_empty() || NUM.is_match(s) {
        return s.to_string();
    }
    match s.as_bytes()[0] {
        b'=' | b'+' | b'-' | b'@' | b'\t' | b'\r' => format!("'{s}"),
        _ => s.to_string(),
    }
}

/// One CSV record as Go's encoding/csv writes it.
pub fn csv_record(out: &mut Vec<u8>, cells: &[String], delim: u8, crlf: bool) {
    for (i, f) in cells.iter().enumerate() {
        if i > 0 {
            out.push(delim);
        }
        let quote = !f.is_empty()
            && (f == "\\."
                || f.bytes()
                    .any(|b| b == b'\n' || b == b'\r' || b == b'"' || b == delim)
                || f.chars().next().is_some_and(char::is_whitespace));
        if !quote {
            out.extend_from_slice(f.as_bytes());
            continue;
        }
        out.push(b'"');
        for ch in f.chars() {
            match ch {
                '"' => out.extend_from_slice(b"\"\""),
                '\r' if crlf => {}
                '\n' if crlf => out.extend_from_slice(b"\r\n"),
                c => {
                    let mut b = [0u8; 4];
                    out.extend_from_slice(c.encode_utf8(&mut b).as_bytes());
                }
            }
        }
        out.push(b'"');
    }
    out.extend_from_slice(if crlf { b"\r\n" } else { b"\n" });
}

fn s(v: &Value) -> String {
    match v {
        Value::Null => String::new(),
        Value::String(x) => x.clone(),
        Value::Bool(b) => b.to_string(),
        Value::Number(n) => n
            .as_f64()
            .map(obx_format::importfmt::format_number)
            .unwrap_or_else(|| n.to_string()),
        other => other.to_string(),
    }
}

/// `assets.csv` of a download: one row per image with its rights and
/// provenance in the import format's columns; None without images.
pub fn assets_csv(files: &[ZipFile]) -> Option<Vec<u8>> {
    if files.is_empty() {
        return None;
    }
    let mut langs = BTreeSet::new();
    for f in files {
        if let Some(m) = f.asset["alt_text"].as_object() {
            langs.extend(m.keys().cloned());
        }
    }
    let mut header: Vec<String> = [
        "file",
        "style_number",
        "color_code",
        "position",
        "role",
        "view",
    ]
    .iter()
    .map(|x| x.to_string())
    .collect();
    header.extend(langs.iter().map(|l| format!("alt_text:{l}")));
    header.extend(
        [
            "license",
            "license_text",
            "channels",
            "territories",
            "embargo_until",
            "expires_at",
            "credit",
            "model_release",
            "ai_generated",
            "ai_edited",
            "source",
            "c2pa",
            "generator",
        ]
        .iter()
        .map(|x| x.to_string()),
    );
    let mut out = Vec::new();
    csv_record(&mut out, &header, b',', false);
    let join = |v: &Value| -> String {
        v.as_array()
            .map(|a| a.iter().map(s).collect::<Vec<_>>().join("|"))
            .unwrap_or_default()
    };
    for f in files {
        let a = &f.asset;
        let (rt, pv) = (&a["rights"], &a["provenance"]);
        let base = f.path.rsplit('/').next().unwrap_or(&f.path).to_string();
        let mut row = vec![
            base,
            f.style.clone(),
            s(&a["color_code"]),
            s(&a["position"]),
            s(&a["role"]),
            s(&a["view"]),
        ];
        row.extend(langs.iter().map(|l| s(&a["alt_text"][l])));
        row.extend([
            s(&rt["license"]),
            s(&rt["license_text"]),
            join(&rt["channels"]),
            join(&rt["territories"]),
            s(&rt["embargo_until"]),
            s(&rt["expires_at"]),
            s(&rt["credit"]),
            s(&rt["model_release"]),
            pv["ai_generated"].as_bool().unwrap_or(false).to_string(),
            pv["ai_edited"].as_bool().unwrap_or(false).to_string(),
            s(&pv["source"]),
            s(&pv["c2pa"]),
            s(&pv["generator"]),
        ]);
        let row: Vec<String> = row.iter().map(|c| csv_safe(c)).collect();
        csv_record(&mut out, &row, b',', false);
    }
    Some(out)
}

fn format_materials(ms: &Value) -> String {
    let mut parts = Vec::new();
    for m in ms.as_array().into_iter().flatten() {
        let mut fs = Vec::new();
        for f in m["fibers"].as_array().into_iter().flatten() {
            let mut c = s(&f["material"]["code"]);
            if let Some(p) = f["percentage"].as_f64() {
                c = format!("{}% {c}", obx_format::importfmt::format_number(p));
            }
            for q in f["qualifiers"].as_array().into_iter().flatten() {
                c.push_str(&format!(" ({})", s(&q["code"])));
            }
            fs.push(c);
        }
        parts.push(format!("{}: {}", s(&m["part"]["code"]), fs.join(", ")));
    }
    parts.join("; ")
}

fn format_footwear(f: &Value) -> String {
    ["upper", "lining_and_sock", "outer_sole"]
        .iter()
        .filter(|k| f[**k].is_string())
        .map(|k| format!("{k}: {}", s(&f[*k])))
        .collect::<Vec<_>>()
        .join("; ")
}

fn format_certifications(cs: &Value) -> String {
    cs.as_array()
        .into_iter()
        .flatten()
        .map(|c| {
            let mut x = s(&c["scheme"]);
            if c["licence_number"].is_string() {
                x.push(':');
                x.push_str(&s(&c["licence_number"]));
            }
            if c["scope"] == "material" {
                x.push_str(" (material)");
            }
            x
        })
        .collect::<Vec<_>>()
        .join("; ")
}

fn yes_no(v: &Value) -> String {
    match v.as_bool() {
        Some(true) => "yes".into(),
        Some(false) => "no".into(),
        None => String::new(),
    }
}

fn measurement_cell(m: &Value, key: &str) -> String {
    let v = &m[key];
    if key == "strap_length_cm" {
        let (Some(a), Some(b)) = (v["min"].as_f64(), v["max"].as_f64()) else {
            return String::new();
        };
        let f = obx_format::importfmt::format_number;
        return if a == b {
            f(a)
        } else {
            format!("{}-{}", f(a), f(b))
        };
    }
    v.as_f64()
        .map(obx_format::importfmt::format_number)
        .unwrap_or_default()
}

/// The canonical CSV of products (one row per visible variant), with a BOM
/// and CRLF line ends, every cell formula-safe.
pub fn build_csv(
    app: &App,
    c: &Connection,
    v: &Viewer,
    ids: &[String],
    delim: u8,
) -> Result<Vec<u8>> {
    use obx_format::importfmt::{MEASUREMENT_COLUMNS, feature_columns, format_feature};
    let langs = Settings::load(c)?.content_languages();
    let names = brand_names(c)?;
    let fv = full(v);
    let mut products = Vec::new();
    for chunk in ids.chunks(100) {
        products.extend(product_details(app, c, &fv, chunk)?);
    }
    let mut attr_keys = BTreeSet::new();
    let mut feature_keys = BTreeSet::new();
    for p in &products {
        if let Some(m) = p["attributes"].as_object() {
            attr_keys.extend(m.keys().cloned());
        }
        if let Some(m) = p["features"].as_object() {
            feature_keys.extend(m.keys().cloned());
        }
    }
    let features = feature_columns(feature_keys.iter().map(String::as_str));
    let mut header: Vec<String> = vec!["brand".into(), "product_id".into(), "style_number".into()];
    header.extend(langs.iter().map(|l| format!("name:{l}")));
    header.extend(langs.iter().map(|l| format!("description:{l}")));
    for k in [
        "item_type",
        "item_subtype",
        "target_group",
        "season",
        "collection",
        "gpc_brick",
        "materials",
        "contains_animal_origin",
        "footwear_materials",
        "care",
        "country_of_origin",
        "certifications",
        "dpp_url",
        "status",
    ] {
        header.push(k.into());
    }
    header.extend(features.iter().map(|k| format!("feature:{k}")));
    header.extend(attr_keys.iter().map(|k| format!("attr:{k}")));
    for k in ["variant_id", "gtin", "sku", "color_code"] {
        header.push(k.into());
    }
    header.extend(langs.iter().map(|l| format!("color_name:{l}")));
    for k in [
        "color_family",
        "supplier_color",
        "size",
        "size_length",
        "size_system",
    ] {
        header.push(k.into());
    }
    header.extend(MEASUREMENT_COLUMNS.iter().map(|k| k.to_string()));
    header.push("variant_status".into());
    header.push("image_files".into());
    let mut out = "\u{feff}".as_bytes().to_vec();
    csv_record(&mut out, &header, delim, true);
    for p in &products {
        let mut base = vec![
            names
                .get(p["brand_id"].as_str().unwrap_or(""))
                .cloned()
                .unwrap_or_default(),
            s(&p["external_id"]),
            s(&p["style_number"]),
        ];
        base.extend(langs.iter().map(|l| s(&p["name"][l])));
        base.extend(langs.iter().map(|l| s(&p["description"][l])));
        let care: Vec<String> = p["care"]
            .as_array()
            .into_iter()
            .flatten()
            .map(|c| s(&c["code"]))
            .collect();
        base.extend([
            s(&p["item_type"]),
            s(&p["item_subtype"]),
            s(&p["target_group"]),
            s(&p["season"]),
            s(&p["collection"]),
            s(&p["gpc_brick"]),
            format_materials(&p["materials"]),
            yes_no(&p["contains_animal_origin"]),
            format_footwear(&p["footwear_materials"]),
            care.join("|"),
            s(&p["country_of_origin"]),
            format_certifications(&p["certifications"]),
            s(&p["dpp_url"]),
            "published".into(),
        ]);
        base.extend(features.iter().map(|k| match p["features"].get(k) {
            Some(v) => format_feature(v),
            None => String::new(),
        }));
        base.extend(attr_keys.iter().map(|k| match &p["attributes"][k] {
            Value::Object(_) | Value::Array(_) => p["attributes"][k].to_string(),
            v => s(v),
        }));
        let mut by_color: HashMap<String, Vec<String>> = HashMap::new();
        for a in p["assets"].as_array().into_iter().flatten() {
            by_color
                .entry(s(&a["color_code"]))
                .or_default()
                .push(s(&a["filename"]));
        }
        let mut write = |cells: Vec<String>| {
            let cells: Vec<String> = cells.iter().map(|c| csv_safe(c)).collect();
            csv_record(&mut out, &cells, delim, true);
        };
        let variants = p["variants"].as_array().cloned().unwrap_or_default();
        if variants.is_empty() {
            let mut row = base.clone();
            row.extend(std::iter::repeat_n(
                String::new(),
                4 + langs.len() + 5 + MEASUREMENT_COLUMNS.len() + 1,
            ));
            row.push(by_color.get("").cloned().unwrap_or_default().join("|"));
            write(row);
            continue;
        }
        for vv in &variants {
            let code = s(&vv["color"]["code"]);
            let mut row = base.clone();
            row.extend([
                s(&vv["external_id"]),
                s(&vv["gtin_original"]),
                s(&vv["sku"]),
                code.clone(),
            ]);
            row.extend(langs.iter().map(|l| s(&vv["color"]["name"][l])));
            let mut files = by_color.get(&code).cloned().unwrap_or_default();
            if !code.is_empty() {
                files.extend(by_color.get("").cloned().unwrap_or_default());
            }
            row.extend([
                s(&vv["color"]["family"]),
                s(&vv["color"]["supplier_color"]),
                s(&vv["size"]),
                s(&vv["size_length"]),
                s(&vv["size_system"]),
            ]);
            row.extend(
                MEASUREMENT_COLUMNS
                    .iter()
                    .map(|k| measurement_cell(&vv["measurements"], k)),
            );
            row.push("published".into());
            row.push(files.join("|"));
            write(row);
        }
    }
    Ok(out)
}

fn today() -> String {
    chrono::Utc::now().format("%Y-%m-%d").to_string()
}

fn attachment(r: &mut Response, ct: &'static str, name: &str) {
    let h = r.headers_mut();
    h.insert(header::CONTENT_TYPE, HeaderValue::from_static(ct));
    h.insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("private, no-store"),
    );
    h.insert(
        "x-content-type-options",
        HeaderValue::from_static("nosniff"),
    );
    if let Ok(v) = HeaderValue::from_str(&content_disposition("attachment", name)) {
        h.insert(header::CONTENT_DISPOSITION, v);
    }
}

async fn send_csv(app: &App, v: Viewer, ids: Vec<String>, delim: u8, name: String) -> Res {
    let st = app.settings().await?;
    if !st.portal.allow_article_data_export && !v.preview() {
        return Err(Problem::new(
            "forbidden",
            "The brand has switched off article data downloads.",
        ));
    }
    let a = app.clone();
    let v2 = v.clone();
    let data = app
        .db
        .read(move |c| build_csv(&a, c, &v2, &ids, delim))
        .await?;
    let n = data.len() as i64;
    let mut r = Response::new(Body::from(data));
    attachment(&mut r, "text/csv; charset=utf-8", &name);
    crate::stats::record(
        app,
        &v,
        crate::stats::DownloadEvent {
            kind: "csv",
            bytes: n,
            ..Default::default()
        },
    )
    .await;
    Ok(r)
}

fn delimiter(q: &[(String, String)]) -> u8 {
    if query_get(q, "delimiter") == Some("semicolon") {
        b';'
    } else {
        b','
    }
}

/// GET /admin/api/portal/selection/data.csv
pub async fn selection_csv(
    State(app): State<App>,
    RawQuery(raw): RawQuery,
    method: Method,
    headers: HeaderMap,
) -> Res {
    let (v, s) = portal_viewer(&app, &headers, &method).await?;
    let v2 = v.clone();
    let ids = app
        .db
        .read(move |c| selected_ids(c, &v2, &s.user.id))
        .await?;
    let d = delimiter(&query_pairs(&raw));
    send_csv(&app, v, ids, d, format!("selection-{}.csv", today())).await
}

pub fn filtered_ids(c: &Connection, v: &Viewer, f: &Filter, max: usize) -> Result<Vec<String>> {
    let (w, args) = f.sql(v, "");
    let mut st = c.prepare(&format!(
        "SELECT p.id FROM products p{w} ORDER BY p.style_number, p.id LIMIT {max}"
    ))?;
    let ids = st
        .query_map(rusqlite::params_from_iter(args.iter()), |r| {
            r.get::<_, String>(0)
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(ids)
}

/// GET /admin/api/portal/products/data.csv (the list's filter)
pub async fn products_csv(
    State(app): State<App>,
    RawQuery(raw): RawQuery,
    method: Method,
    headers: HeaderMap,
) -> Res {
    let (v, _) = portal_viewer(&app, &headers, &method).await?;
    let q = query_pairs(&raw);
    let f = Filter::from_query(&q);
    let v2 = v.clone();
    let ids = app
        .db
        .read(move |c| filtered_ids(c, &v2, &f, 50_000))
        .await?;
    send_csv(
        &app,
        v,
        ids,
        delimiter(&q),
        format!("products-{}.csv", today()),
    )
    .await
}

// ---- images and zips ---------------------------------------------------------------------

/// GET /admin/api/portal/assets/{id}/download?variant=
pub async fn asset_download(
    State(app): State<App>,
    Path(id): Path<String>,
    RawQuery(raw): RawQuery,
    method: Method,
    headers: HeaderMap,
) -> Res {
    let (v, _) = portal_viewer(&app, &headers, &method).await?;
    let q = query_pairs(&raw);
    let variant = choose_variant(&v, query_get(&q, "variant").unwrap_or(""))?;
    let v2 = v.clone();
    let a = app.clone();
    let asset = app
        .db
        .read(move |c| {
            let Some(r) = super::protocol::visible_asset(c, &v2, &id)? else {
                return Ok(None);
            };
            Ok(Some(super::protocol::render_asset(
                &a,
                &r.rep,
                &r.updated_at,
                &Viewer::admin(),
            )))
        })
        .await?
        .ok_or_else(|| Problem::new("not_found", "Image not found."))?;
    let (sha, bytes, ct, name) =
        asset_file(&asset, variant).ok_or_else(|| Problem::new("not_found", "Image not found."))?;
    let mut r = serve_blob(
        &app,
        &headers,
        &method,
        &sha,
        &ct,
        &content_disposition("attachment", &name),
    )
    .await?;
    r.headers_mut().insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("private, no-store"),
    );
    if method == Method::GET
        && r.status().is_success()
        && !crate::stats::is_continuation_range(&headers)
    {
        crate::stats::record(
            &app,
            &v,
            crate::stats::DownloadEvent {
                kind: "image",
                variant: variant.into(),
                product_id: asset["product_id"].as_str().unwrap_or("").into(),
                asset_id: asset["id"].as_str().unwrap_or("").into(),
                files: 1,
                bytes,
                ..Default::default()
            },
        )
        .await;
    }
    Ok(r)
}

/// A `Write` that hands chunks to an HTTP body.
struct ChannelWriter {
    tx: tokio::sync::mpsc::Sender<std::io::Result<Bytes>>,
    buf: Vec<u8>,
}

impl std::io::Write for ChannelWriter {
    fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
        self.buf.extend_from_slice(b);
        if self.buf.len() >= 256 << 10 {
            self.flush()?;
        }
        Ok(b.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        if self.buf.is_empty() {
            return Ok(());
        }
        let chunk = Bytes::from(std::mem::take(&mut self.buf));
        self.tx
            .blocking_send(Ok(chunk))
            .map_err(|_| std::io::Error::other("client went away"))
    }
}

/// Writes the files (read from the store one by one) and the extra entries
/// into w; returns the number of files and their bytes.
fn write_zip<W: std::io::Write>(
    app: &App,
    w: W,
    files: &[ZipFile],
    extra: &[(String, Vec<u8>)],
) -> std::io::Result<(W, usize, i64)> {
    let rt = tokio::runtime::Handle::current();
    let mut z = ZipOut::new(w);
    let mut total = 0i64;
    for f in files {
        let data = rt
            .block_on(app.store.get(&blob_key(&f.sha256)))
            .map_err(std::io::Error::other)?
            .ok_or_else(|| std::io::Error::other(format!("blob {} is missing", f.sha256)))?;
        total += data.len() as i64;
        z.add(&f.path, &data)?;
    }
    let mut extra: Vec<&(String, Vec<u8>)> = extra.iter().collect();
    extra.sort_by(|a, b| a.0.cmp(&b.0));
    for (name, data) in extra {
        z.add(name, data)?;
    }
    let (w, _) = z.finish()?;
    Ok((w, files.len(), total))
}

/// Streams a zip as the response; the download is recorded when it was
/// written completely.
fn stream_zip(
    app: &App,
    v: Viewer,
    files: Vec<ZipFile>,
    name: String,
    event: crate::stats::DownloadEvent,
) -> Response {
    let (tx, rx) = tokio::sync::mpsc::channel::<std::io::Result<Bytes>>(4);
    let a = app.clone();
    tokio::task::spawn_blocking(move || {
        let extra: Vec<(String, Vec<u8>)> = assets_csv(&files)
            .map(|c| vec![("assets.csv".to_string(), c)])
            .unwrap_or_default();
        let w = ChannelWriter {
            tx: tx.clone(),
            buf: Vec::new(),
        };
        match write_zip(&a, w, &files, &extra) {
            Ok((_, n, total)) => {
                let rt = tokio::runtime::Handle::current();
                rt.block_on(crate::stats::record(
                    &a,
                    &v,
                    crate::stats::DownloadEvent {
                        files: n as i64,
                        bytes: total,
                        ..event
                    },
                ));
            }
            Err(e) => {
                tracing::warn!(error = %e, "zip stream failed");
                let _ = tx.blocking_send(Err(e));
            }
        }
    });
    let body = Body::from_stream(futures::stream::unfold(rx, |mut rx| async move {
        rx.recv().await.map(|x| (x, rx))
    }));
    let mut r = Response::new(body);
    attachment(&mut r, "application/zip", &name);
    r
}

/// GET /admin/api/portal/products/{id}/download.zip?variant=
pub async fn product_zip(
    State(app): State<App>,
    Path(id): Path<String>,
    RawQuery(raw): RawQuery,
    method: Method,
    headers: HeaderMap,
) -> Res {
    let (v, _) = portal_viewer(&app, &headers, &method).await?;
    let q = query_pairs(&raw);
    let variant = choose_variant(&v, query_get(&q, "variant").unwrap_or(""))?;
    let (a, v2) = (app.clone(), v.clone());
    let (pid, style, files) = app
        .db
        .read(move |c| {
            let Some(p) = product_details(&a, c, &v2, &[id])?.pop() else {
                return Err(Problem::new("not_found", "Product not found."));
            };
            let pid = p["id"].as_str().unwrap_or("").to_string();
            let files = zip_files_for(&a, c, &v2, std::slice::from_ref(&pid), variant, false)?;
            Ok((pid, s(&p["style_number"]), files))
        })
        .await?;
    Ok(stream_zip(
        &app,
        v,
        files,
        format!("{style}.zip"),
        crate::stats::DownloadEvent {
            kind: "product_zip",
            variant: variant.into(),
            product_id: pid,
            ..Default::default()
        },
    ))
}

/// GET /admin/api/portal/selection/download.zip?variant=
pub async fn selection_zip(
    State(app): State<App>,
    RawQuery(raw): RawQuery,
    method: Method,
    headers: HeaderMap,
) -> Res {
    let (v, sess) = portal_viewer(&app, &headers, &method).await?;
    let q = query_pairs(&raw);
    let variant = choose_variant(&v, query_get(&q, "variant").unwrap_or(""))?;
    let (a, v2) = (app.clone(), v.clone());
    let files = app
        .db
        .read(move |c| {
            let ids = selected_ids(c, &v2, &sess.user.id)?;
            if ids.is_empty() {
                return Err(Problem::new("invalid_request", "Your selection is empty."));
            }
            zip_files_for(&a, c, &v2, &ids, variant, true)
        })
        .await?;
    if files.len() > SYNC_ZIP_MAX_FILES {
        return Err(Problem::new(
            "limit_exceeded",
            format!(
                "The selection has {} images; downloads of more than {SYNC_ZIP_MAX_FILES} images are prepared in the background.",
                files.len()
            ),
        ));
    }
    Ok(stream_zip(
        &app,
        v,
        files,
        format!("selection-{}.zip", today()),
        crate::stats::DownloadEvent {
            kind: "selection_zip",
            variant: variant.into(),
            ..Default::default()
        },
    ))
}

// ---- background download jobs ----------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct DownloadPayload {
    user_id: String,
    source: String,
    product_ids: Vec<String>,
    variant: String,
    include_data_csv: bool,
    delimiter: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct DownloadResult {
    bytes: i64,
    files: i64,
}

fn expired(j: &crate::jobs::Job) -> bool {
    j.expires_at
        .as_deref()
        .and_then(crate::db::parse_time)
        .is_some_and(|t| t < chrono::Utc::now())
}

fn job_json(j: &crate::jobs::Job) -> Value {
    let p: DownloadPayload = serde_json::from_str(&j.payload).unwrap_or_default();
    let status = if expired(j) {
        "expired"
    } else {
        j.status.as_str()
    };
    let mut out = json!({"id": j.id, "status": status, "source": p.source, "variant": p.variant,
        "include_data_csv": p.include_data_csv, "created_at": j.created_at, "finished_at": j.finished_at,
        "expires_at": j.expires_at, "progress": {"done": j.done, "total": j.total},
        "file_url": null, "bytes": null, "files": null, "error": j.error});
    if status == "succeeded" {
        if let Some(r) = j
            .result
            .as_deref()
            .and_then(|r| serde_json::from_str::<DownloadResult>(r).ok())
        {
            out["file_url"] = json!(format!("/admin/api/portal/download-jobs/{}/file", j.id));
            out["bytes"] = json!(r.bytes);
            out["files"] = json!(r.files);
        }
    }
    out
}

/// GET /admin/api/portal/download-jobs: the user's downloads of the last week.
pub async fn jobs(State(app): State<App>, method: Method, headers: HeaderMap) -> Res {
    let (_, s) = portal_viewer(&app, &headers, &method).await?;
    let since = crate::db::fmt_time(chrono::Utc::now() - chrono::Duration::days(DOWNLOAD_TTL_DAYS));
    let items = app
        .db
        .read(move |c| {
            let mut st = c.prepare("SELECT id FROM jobs WHERE kind = 'download' AND owner_type = 'user' AND owner_id = ? AND created_at > ? ORDER BY created_at DESC")?;
            let ids = st
                .query_map(params![s.user.id, since], |r| r.get::<_, String>(0))?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            let mut out = Vec::new();
            for id in ids {
                if let Some(j) = crate::jobs::load_job_sync(c, &id)? {
                    out.push(job_json(&j));
                }
            }
            Ok(out)
        })
        .await?;
    Ok(ok(&json!({"items": items})))
}

/// POST /admin/api/portal/download-jobs
pub async fn job_create(
    State(app): State<App>,
    method: Method,
    headers: HeaderMap,
    body: Bytes,
) -> Res {
    let (v, s) = portal_viewer(&app, &headers, &method).await?;
    let b = read_json(&headers, &body, 4 << 20)?;
    let vparam = b["variant"].as_str().unwrap_or("");
    if vparam.is_empty() {
        return Err(
            Problem::new("validation_failed", "Choose original, web or square.").field(
                "/variant",
                "validation_failed",
                "required",
            ),
        );
    }
    let variant = choose_variant(&v, vparam)?;
    let source = b["source"].as_str().unwrap_or("").to_string();
    let uid = s.user.id.clone();
    let v2 = v.clone();
    let b2 = b.clone();
    let src = source.clone();
    let ids = app
        .db
        .read(move |c| match src.as_str() {
            "selection" => selected_ids(c, &v2, &uid),
            "products" => {
                let list: Vec<String> = b2["product_ids"]
                    .as_array()
                    .into_iter()
                    .flatten()
                    .filter_map(|x| x.as_str().map(String::from))
                    .collect();
                if list.len() > 10_000 {
                    return Err(Problem::new("limit_exceeded", "At most 10,000 products."));
                }
                visible_product_ids(c, &v2, &list)
            }
            "filter" => {
                let f: Filter = serde_json::from_value(b2["filter"].clone()).unwrap_or_default();
                filtered_ids(c, &v2, &f, 100_000)
            }
            _ => Err(Problem::new(
                "validation_failed",
                "source must be selection, products or filter.",
            )),
        })
        .await?;
    if ids.is_empty() {
        return Err(Problem::new(
            "validation_failed",
            "There are no products to download.",
        ));
    }
    let uid = s.user.id.clone();
    let running: i64 = app
        .db
        .read(move |c| {
            Ok(c.query_row(
                "SELECT COUNT(*) FROM jobs WHERE kind = 'download' AND owner_id = ? AND status IN ('queued', 'running')",
                [&uid],
                |r| r.get(0),
            )?)
        })
        .await?;
    if running >= 2 {
        return Err(Problem::new(
            "conflict",
            "Two downloads are already being prepared; wait until one is ready.",
        ));
    }
    let include = b["include_data_csv"].as_bool().unwrap_or(true);
    let delim = if v.language.starts_with("nl") {
        "semicolon"
    } else {
        "comma"
    };
    let total = ids.len() as i64;
    let p = DownloadPayload {
        user_id: s.user.id.clone(),
        source,
        product_ids: ids,
        variant: variant.into(),
        include_data_csv: include,
        delimiter: delim.into(),
    };
    let j = crate::jobs::create_job(
        &app,
        "download",
        "user",
        &s.user.id,
        serde_json::to_value(&p).map_err(Problem::internal)?,
        Some(total),
    )
    .await?;
    Ok(json(202, &job_json(&j)))
}

async fn own_job(
    app: &App,
    headers: &HeaderMap,
    method: &Method,
    id: String,
) -> Result<(Viewer, crate::jobs::Job)> {
    let (v, s) = portal_viewer(app, headers, method).await?;
    let j = crate::jobs::load_job(app, &id).await?;
    match j {
        Some(j) if j.kind == "download" && j.owner_id.as_deref() == Some(s.user.id.as_str()) => {
            Ok((v, j))
        }
        _ => Err(Problem::new("not_found", "Download not found.")),
    }
}

/// GET /admin/api/portal/download-jobs/{id}
pub async fn job_get(
    State(app): State<App>,
    Path(id): Path<String>,
    method: Method,
    headers: HeaderMap,
) -> Res {
    let (_, j) = own_job(&app, &headers, &method, id).await?;
    Ok(ok(&job_json(&j)))
}

fn download_key(id: &str) -> String {
    format!("downloads/{id}.zip")
}

/// GET /admin/api/portal/download-jobs/{id}/file (Range supported)
pub async fn job_file(
    State(app): State<App>,
    Path(id): Path<String>,
    method: Method,
    headers: HeaderMap,
) -> Res {
    let (v, j) = own_job(&app, &headers, &method, id).await?;
    if expired(&j) {
        return Err(Problem::new(
            "export_expired",
            "This download expired; start a new one.",
        ));
    }
    if j.status != "succeeded" {
        return Err(Problem::new("not_found", "The download is not ready yet."));
    }
    let key = download_key(&j.id);
    let Some(size) = app.store.size(&key).await.map_err(Problem::internal)? else {
        return Err(Problem::new("export_expired", "The file was deleted."));
    };
    let range = headers
        .get(header::RANGE)
        .and_then(|h| h.to_str().ok())
        .map(|h| obx_axum::parse_range(h, size));
    let (status, rng) = match range {
        Some(Some(r)) => (206, Some(r)),
        Some(None) => {
            let mut r = Response::new(Body::empty());
            *r.status_mut() = axum::http::StatusCode::RANGE_NOT_SATISFIABLE;
            if let Ok(v) = HeaderValue::from_str(&format!("bytes */{size}")) {
                r.headers_mut().insert(header::CONTENT_RANGE, v);
            }
            return Ok(r);
        }
        None => (200, None),
    };
    let len = rng.as_ref().map_or(size, |r| r.end - r.start);
    let body = if method == Method::HEAD {
        Body::empty()
    } else {
        let st = app
            .store
            .stream(&key, rng.clone())
            .await
            .map_err(Problem::internal)?
            .ok_or_else(|| Problem::new("export_expired", "The file was deleted."))?;
        Body::from_stream(st)
    };
    let mut r = Response::new(body);
    *r.status_mut() = axum::http::StatusCode::from_u16(status).unwrap_or_default();
    attachment(
        &mut r,
        "application/zip",
        &format!("download-{}.zip", j.created_at.get(..10).unwrap_or("")),
    );
    let h = r.headers_mut();
    h.insert(header::ACCEPT_RANGES, HeaderValue::from_static("bytes"));
    h.insert(header::CONTENT_LENGTH, HeaderValue::from(len));
    if let Some(rg) = &rng {
        if let Ok(v) = HeaderValue::from_str(&format!("bytes {}-{}/{size}", rg.start, rg.end - 1)) {
            h.insert(header::CONTENT_RANGE, v);
        }
    }
    if method == Method::GET && !crate::stats::is_continuation_range(&headers) {
        let res: DownloadResult = j
            .result
            .as_deref()
            .and_then(|r| serde_json::from_str(r).ok())
            .unwrap_or_default();
        crate::stats::record(
            &app,
            &v,
            crate::stats::DownloadEvent {
                kind: "bulk_zip",
                files: res.files,
                bytes: res.bytes,
                ..Default::default()
            },
        )
        .await;
    }
    Ok(r)
}

/// Runs a download job: the zip is written to a temporary file, then stored.
pub async fn run_download_job(
    app: &App,
    j: &crate::jobs::Job,
) -> std::result::Result<Option<Value>, (Option<Value>, String)> {
    let fail = |e: String| (None, e);
    let p: DownloadPayload = serde_json::from_str(&j.payload).map_err(|e| fail(e.to_string()))?;
    let uid = p.user_id.clone();
    let a = app.clone();
    let pl = p.clone();
    let (v, ids, files, csv, user) = app
        .db
        .read(move |c| {
            let u = super::admin::load_user(c, "id = ?", &uid)?
                .filter(|u| u.status == "active")
                .ok_or_else(|| Problem::new("forbidden", "the account is no longer active"))?;
            let v = super::admin::viewer_for_user(c, &u)?;
            let ids = visible_product_ids(c, &v, &pl.product_ids)?;
            let files = zip_files_for(&a, c, &v, &ids, &pl.variant, true)?;
            let csv = if pl.include_data_csv && Settings::load(c)?.portal.allow_article_data_export
            {
                let d = if pl.delimiter == "semicolon" {
                    b';'
                } else {
                    b','
                };
                Some(build_csv(&a, c, &v, &ids, d)?)
            } else {
                None
            };
            Ok((v, ids, files, csv, u))
        })
        .await
        .map_err(|e| fail(e.detail_str().to_string()))?;
    let _ = (v, ids);
    let total = files.len() as i64;
    let mut extra: Vec<(String, Vec<u8>)> = Vec::new();
    if let Some(c) = assets_csv(&files) {
        extra.push(("assets.csv".into(), c));
    }
    if let Some(c) = csv {
        extra.push(("data.csv".into(), c));
    }
    let dir = app.cfg.data_dir.join("tmp");
    std::fs::create_dir_all(&dir).map_err(|e| fail(e.to_string()))?;
    let path = dir.join(format!("{}.zip", j.id));
    let a = app.clone();
    let p2 = path.clone();
    let id = j.id.clone();
    let written = tokio::task::spawn_blocking(move || -> std::io::Result<i64> {
        let f = std::io::BufWriter::new(std::fs::File::create(&p2)?);
        let rt = tokio::runtime::Handle::current();
        let mut z = ZipOut::new(f);
        for (i, f) in files.iter().enumerate() {
            let data = rt
                .block_on(a.store.get(&blob_key(&f.sha256)))
                .map_err(std::io::Error::other)?
                .ok_or_else(|| std::io::Error::other(format!("blob {} is missing", f.sha256)))?;
            z.add(&f.path, &data)?;
            if i % 20 == 0 {
                rt.block_on(crate::jobs::progress(&a, &id, i as i64, Some(total)));
            }
        }
        extra.sort_by(|x, y| x.0.cmp(&y.0));
        for (name, data) in &extra {
            z.add(name, data)?;
        }
        let (mut f, n) = z.finish()?;
        std::io::Write::flush(&mut f)?;
        Ok(n as i64)
    })
    .await
    .map_err(|e| fail(e.to_string()))?;
    let size = match written {
        Ok(n) => n,
        Err(e) => {
            let _ = std::fs::remove_file(&path);
            return Err(fail(e.to_string()));
        }
    };
    let put = app.store.put_file(&download_key(&j.id), &path).await;
    let _ = std::fs::remove_file(&path);
    put.map_err(fail)?;
    crate::jobs::progress(app, &j.id, total, Some(total)).await;
    let exp = chrono::Utc::now() + chrono::Duration::days(DOWNLOAD_TTL_DAYS);
    let (id, es) = (j.id.clone(), crate::db::fmt_time(exp));
    let _ = app
        .db
        .write(move |tx| {
            tx.execute(
                "UPDATE jobs SET expires_at = ? WHERE id = ?",
                params![es, id],
            )?;
            Ok(())
        })
        .await;
    crate::mail::send_mail_later(
        app,
        user.email.clone(),
        user.language.clone(),
        crate::mail::MAIL_ZIP_READY,
        vec![
            ("name", user.name.clone()),
            ("files", total.to_string()),
            ("expires", crate::mail::mail_date(exp)),
            ("url", format!("{}/downloads", app.cfg.public_url)),
        ],
    );
    Ok(Some(json!(DownloadResult {
        bytes: size,
        files: total
    })))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formulas_are_neutralised() {
        assert_eq!(csv_safe("=HYPERLINK(1)"), "'=HYPERLINK(1)");
        assert_eq!(csv_safe("+SUM(1,1)"), "'+SUM(1,1)");
        assert_eq!(csv_safe("-12,5"), "-12,5");
        assert_eq!(csv_safe("@x"), "'@x");
        assert_eq!(csv_safe("plain"), "plain");
    }

    #[test]
    fn records_like_go() {
        let mut o = Vec::new();
        csv_record(
            &mut o,
            &[
                "a".into(),
                "b;c".into(),
                " x".into(),
                "q\"q".into(),
                "l1\nl2".into(),
                "".into(),
            ],
            b';',
            true,
        );
        assert_eq!(
            String::from_utf8(o).unwrap(),
            "a;\"b;c\";\" x\";\"q\"\"q\";\"l1\r\nl2\";\r\n"
        );
    }

    #[test]
    fn variants() {
        let mut v = Viewer::admin();
        assert_eq!(choose_variant(&v, "").unwrap(), "original");
        v.original_allowed = false;
        assert_eq!(choose_variant(&v, "").unwrap(), "web");
        assert_eq!(
            choose_variant(&v, "original").unwrap_err().obx_error,
            "original_not_allowed"
        );
        assert_eq!(
            choose_variant(&v, "thumb").unwrap_err().obx_error,
            "invalid_request"
        );
    }
}
