//! Catalog writes: one serialised transaction per write, which derives the
//! visibility and protocol representation of every touched object and
//! writes the change-feed entries for visible effects (ingest.md §8).

use std::collections::{BTreeMap, BTreeSet, HashSet};

use rusqlite::{Connection, OptionalExtension, Row as SqlRow, params};
use serde_json::{Map, Value, json};

use crate::article;
use crate::model::*;
use crate::problem::{Problem, Result};
use crate::schemas;
use crate::secure::sha256_hex;
use crate::settings::Settings;

/// A stored catalog object.
#[derive(Debug, Clone, Default)]
pub struct Row {
    pub kind: &'static str,
    pub id: String,
    pub external_id: String,
    pub status: String,
    pub data: String,
    pub etag: String,
    pub visible: bool,
    pub rep: String,
    pub rep_hash: String,
    pub last_seq: i64,
    pub created_at: String,
    pub updated_at: String,
    pub record_updated_at: String,
    pub brand_id: String,
    pub product_id: String,
    pub color_code: Option<String>,
    pub position: i64,
    pub original_sha: Option<String>,
    pub live_files: Option<String>,
    pub pending: bool,
}

fn row_columns(kind: &str) -> &'static str {
    match kind {
        KIND_PRODUCT => {
            "id, external_id, status, data, etag, visible, rep, rep_hash, last_seq, created_at, updated_at, record_updated_at, brand_id, ''"
        }
        KIND_VARIANT => {
            "id, external_id, status, data, etag, visible, rep, rep_hash, last_seq, created_at, updated_at, record_updated_at, brand_id, product_id"
        }
        KIND_ASSET => {
            "id, external_id, status, data, etag, visible, rep, rep_hash, last_seq, created_at, updated_at, record_updated_at, brand_id, product_id, color_code, position, original_sha, live_files, pending"
        }
        _ => {
            "id, external_id, status, data, etag, visible, rep, rep_hash, last_seq, created_at, updated_at, record_updated_at, '', ''"
        }
    }
}

fn scan_row(kind: &'static str, r: &SqlRow) -> rusqlite::Result<Row> {
    let mut row = Row {
        kind,
        id: r.get(0)?,
        external_id: r.get(1)?,
        status: r.get(2)?,
        data: r.get(3)?,
        etag: r.get(4)?,
        visible: r.get::<_, i64>(5)? == 1,
        rep: r.get(6)?,
        rep_hash: r.get(7)?,
        last_seq: r.get(8)?,
        created_at: r.get(9)?,
        updated_at: r.get(10)?,
        record_updated_at: r.get(11)?,
        brand_id: r.get(12)?,
        product_id: r.get(13)?,
        ..Default::default()
    };
    if kind == KIND_ASSET {
        row.color_code = r.get(14)?;
        row.position = r.get::<_, Option<i64>>(15)?.unwrap_or(0);
        row.original_sha = r.get(16)?;
        row.live_files = r.get(17)?;
        row.pending = r.get::<_, i64>(18)? == 1;
    }
    Ok(row)
}

pub fn kind_static(kind: &str) -> &'static str {
    match kind {
        KIND_BRAND => KIND_BRAND,
        KIND_PRODUCT => KIND_PRODUCT,
        KIND_VARIANT => KIND_VARIANT,
        _ => KIND_ASSET,
    }
}

pub fn load_row(c: &Connection, kind: &str, external_id: &str) -> Result<Option<Row>> {
    let k = kind_static(kind);
    let q = format!(
        "SELECT {} FROM {} WHERE external_id = ?",
        row_columns(k),
        table_of(k)
    );
    Ok(c.query_row(&q, [external_id], |r| scan_row(k, r))
        .optional()?)
}

pub fn load_row_by_id(c: &Connection, kind: &str, id: &str) -> Result<Option<Row>> {
    let k = kind_static(kind);
    let q = format!(
        "SELECT {} FROM {} WHERE id = ?",
        row_columns(k),
        table_of(k)
    );
    Ok(c.query_row(&q, [id], |r| scan_row(k, r)).optional()?)
}

pub fn load_rows(
    c: &Connection,
    kind: &str,
    where_: &str,
    args: &[&dyn rusqlite::ToSql],
) -> Result<Vec<Row>> {
    let k = kind_static(kind);
    let q = format!("SELECT {} FROM {} {}", row_columns(k), table_of(k), where_);
    let mut st = c.prepare(&q)?;
    let rows = st.query_map(args, |r| scan_row(k, r))?;
    Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
}

/// The canonical asset order: colour (null first), position.
pub const ASSET_ORDER: &str =
    " ORDER BY CASE WHEN color_code IS NULL THEN 0 ELSE 1 END, color_code, position, external_id";

pub fn hash_hex(b: &[u8]) -> String {
    sha256_hex(b)
}

pub fn etag_for(status: &str, data: &str) -> String {
    format!(
        "\"{}\"",
        &hash_hex(format!("{status}\n{data}").as_bytes())[..32]
    )
}

pub fn grant_id_for(retailer_id: &str) -> String {
    format!(
        "grt_{}",
        retailer_id.strip_prefix("rtl_").unwrap_or(retailer_id)
    )
}

fn id_prefix(kind: &str) -> &'static str {
    match kind {
        KIND_BRAND => "brd",
        KIND_PRODUCT => "prd",
        KIND_VARIANT => "var",
        _ => "ast",
    }
}

fn input_schema(kind: &str) -> &'static str {
    match kind {
        KIND_BRAND => "BrandInput",
        KIND_PRODUCT => "ProductInput",
        KIND_VARIANT => "VariantInput",
        _ => "AssetInput",
    }
}

fn known_fields(kind: &str) -> &'static [&'static str] {
    match kind {
        KIND_BRAND => &["name", "logo_url", "website", "description", "status"],
        KIND_PRODUCT => &[
            "brand_external_id",
            "style_number",
            "name",
            "description",
            "item_type",
            "item_subtype",
            "gpc_brick",
            "target_group",
            "season",
            "collection",
            "materials",
            "contains_animal_origin",
            "footwear_materials",
            "care",
            "country_of_origin",
            "certifications",
            "dpp_url",
            "features",
            "attributes",
            "status",
        ],
        KIND_VARIANT => &[
            "product_external_id",
            "gtin",
            "sku",
            "color",
            "size",
            "size_length",
            "size_system",
            "measurements",
            "status",
        ],
        _ => &[
            "product_external_id",
            "color_code",
            "variant_external_ids",
            "media_type",
            "role",
            "view",
            "position",
            "filename",
            "alt_text",
            "rights",
            "provenance",
            "files",
            "status",
        ],
    }
}

/// Checks the ExternalId rules (1-200 characters, no control characters, no
/// '/'); the value is trimmed first.
pub fn valid_external_id(s: &str) -> (String, bool) {
    let s = s.trim().to_string();
    let ok = !s.is_empty()
        && s.chars().count() <= 200
        && !s
            .chars()
            .any(|c| (c as u32) < 0x20 || c == '\x7f' || c == '/');
    (s, ok)
}

pub fn normalize_gtin(s: &str) -> Option<String> {
    obx_format::gtin::normalize(s)
}

fn validation_problem(errs: &[schemas::FieldError]) -> Problem {
    let mut p = Problem::new("validation_failed", "The request body is not valid.");
    for e in errs {
        p = p.field(&e.pointer, "validation_failed", e.message.clone());
    }
    p
}

fn forbidden_brand() -> Problem {
    Problem::new("forbidden", "This token may not write to this brand.")
}

/// RFC 3339 in UTC with the shortest fraction.
pub fn normalize_time(s: &str) -> Option<String> {
    let t = chrono::DateTime::parse_from_rfc3339(s)
        .ok()?
        .with_timezone(&chrono::Utc);
    Some(t.to_rfc3339_opts(chrono::SecondsFormat::AutoSi, true))
}

pub fn expired(expires_at: Option<&str>, now: chrono::DateTime<chrono::Utc>) -> bool {
    match expires_at
        .filter(|s| !s.is_empty())
        .and_then(crate::db::parse_time)
    {
        Some(t) => t <= now,
        None => false,
    }
}

pub fn image_ext(ct: &str) -> &'static str {
    match ct {
        "image/jpeg" => "jpg",
        "image/png" => "png",
        "image/webp" => "webp",
        "image/tiff" => "tif",
        _ => "bin",
    }
}

/// Effective rights: the node default with the asset's own fields.
pub fn merge_rights(def: &Rights, own: Option<&BTreeMap<String, Value>>) -> Rights {
    let mut m = match to_value(def) {
        Value::Object(m) => m,
        _ => Map::new(),
    };
    let mut ext = Ext::new();
    if let Some(own) = own {
        for (k, v) in own {
            if k.starts_with("x-") {
                ext.insert(k.clone(), v.clone());
            } else {
                m.insert(k.clone(), v.clone());
            }
        }
    }
    let mut r: Rights = serde_json::from_value(Value::Object(m)).unwrap_or_default();
    if r.license.is_empty() {
        r.license = "retailer-use".into();
    }
    r.ext = ext;
    r
}

pub fn effective_provenance(own: Option<&BTreeMap<String, Value>>) -> Provenance {
    let mut m = Map::new();
    let mut ext = Ext::new();
    if let Some(own) = own {
        for (k, v) in own {
            if k.starts_with("x-") {
                ext.insert(k.clone(), v.clone());
            } else {
                m.insert(k.clone(), v.clone());
            }
        }
    }
    let mut p: Provenance = serde_json::from_value(Value::Object(m)).unwrap_or(Provenance {
        ai_generated: false,
        ai_edited: false,
        source: String::new(),
        c2pa: String::new(),
        c2pa_manifest_url: None,
        generator: None,
        ext: Ext::new(),
    });
    if p.source.is_empty() {
        p.source = if p.ai_generated { "generated" } else { "photo" }.into();
    }
    if p.c2pa.is_empty() {
        p.c2pa = "none".into();
    }
    p.ext = ext;
    p
}

/// A validated write: the canonical stored data, status and derived columns.
struct Prepared {
    data: String,
    status: Option<String>,
    brand_id: String,
    product_id: String,
    name: String,
    style_number: String,
    gtin: Option<String>,
    color_code: Option<String>,
    sku: Option<String>,
    position: i64,
    original_sha: Option<String>,
    warnings: Vec<String>,
    details: Vec<WarningDetail>,
}

pub struct Writer<'a> {
    pub tx: &'a Connection,
    pub now: String,
    pub now_time: chrono::DateTime<chrono::Utc>,
    pub settings: Settings,
    /// Originals that need renditions (rendered after commit).
    pub renders: BTreeSet<String>,
    /// Change entries written.
    pub entries: usize,
    /// Restricts writes to these brand external ids (None = all).
    pub allowed_brands: Option<Vec<String>>,
    /// Assets whose positions do not count for conflicts (an import applying
    /// a product colour's positions atomically).
    pub position_exclude: HashSet<String>,
    /// Retailers whose grant changed (webhooks grant.updated after commit).
    pub grants: Vec<String>,
}

impl<'a> Writer<'a> {
    pub fn new(tx: &'a Connection) -> Result<Writer<'a>> {
        let now_time = chrono::Utc::now();
        Ok(Writer {
            tx,
            now: crate::db::fmt_time(now_time),
            now_time,
            settings: Settings::load(tx)?,
            renders: BTreeSet::new(),
            entries: 0,
            allowed_brands: None,
            position_exclude: HashSet::new(),
            grants: Vec::new(),
        })
    }

    fn emit(&mut self, typ: &str, op: &str, r: &Row) -> Result<i64> {
        let brand_id: Option<&str> = Some(if r.kind == KIND_BRAND {
            &r.id
        } else {
            &r.brand_id
        });
        let product_id: Option<&str> = if r.kind == KIND_VARIANT || r.kind == KIND_ASSET {
            Some(&r.product_id)
        } else {
            None
        };
        let seq: i64 = self.tx.query_row(
            "INSERT INTO changes (type, op, object_id, external_id, brand_id, product_id, at) VALUES (?, ?, ?, ?, ?, ?, ?) RETURNING seq",
            params![typ, op, r.id, r.external_id, brand_id, product_id, self.now],
            |x| x.get(0),
        )?;
        self.entries += 1;
        let pid = if r.kind == KIND_PRODUCT {
            r.id.as_str()
        } else {
            r.product_id.as_str()
        };
        if !pid.is_empty() {
            self.tx.execute(
                "UPDATE products SET touched_at = ? WHERE id = ?",
                params![self.now, pid],
            )?;
        }
        Ok(seq)
    }

    /// A grant entry for one retailer.
    pub fn emit_grant(&mut self, retailer_id: &str, resync: bool) -> Result<()> {
        self.tx.execute(
            "INSERT INTO changes (type, op, object_id, external_id, retailer_id, resync, at) VALUES ('grant', 'upsert', ?, NULL, ?, ?, ?)",
            params![grant_id_for(retailer_id), retailer_id, resync as i64, self.now],
        )?;
        self.entries += 1;
        self.grants.push(retailer_id.to_string());
        Ok(())
    }

    fn parent_visible(&self, kind: &str, id: &str) -> bool {
        self.tx
            .query_row(
                &format!("SELECT visible FROM {} WHERE id = ?", table_of(kind)),
                [id],
                |r| r.get::<_, i64>(0),
            )
            .map(|v| v == 1)
            .unwrap_or(false)
    }

    /// Derives visibility and representation of r, writes change entries for
    /// visible effects and stores the result.
    pub fn recompute(&mut self, r: &mut Row) -> Result<()> {
        let mut visible = r.status == "published";
        let mut live_files: Option<String> = None;
        let mut pending = false;
        let mut expires_at: Option<String> = None;
        let rep_json = match r.kind {
            KIND_BRAND => {
                let d: BrandData = serde_json::from_str(&r.data).unwrap_or_default();
                to_json(&BrandRep {
                    id: r.id.clone(),
                    external_id: r.external_id.clone(),
                    name: d.name,
                    logo_url: d.logo_url,
                    website: d.website,
                    description: d.description,
                    ext: d.ext,
                })
            }
            KIND_PRODUCT => {
                let d: ProductData = serde_json::from_str(&r.data).unwrap_or_default();
                visible = visible && self.parent_visible(KIND_BRAND, &r.brand_id);
                to_json(&product_rep(r, d))
            }
            KIND_VARIANT => {
                let d: VariantData = serde_json::from_str(&r.data).unwrap_or_default();
                visible = visible && self.parent_visible(KIND_PRODUCT, &r.product_id);
                to_json(&variant_rep(r, d))
            }
            _ => {
                let d: AssetData = serde_json::from_str(&r.data).unwrap_or_default();
                let (live, complete) = self.resolve_files(&d)?;
                if complete {
                    live_files = Some(to_json(&live));
                } else {
                    live_files = r.live_files.clone();
                    pending = true;
                    if let Some(o) = d.files.as_ref().and_then(|f| f.get("original")) {
                        self.renders.insert(o.sha256.clone());
                    }
                }
                let files: Option<BTreeMap<String, LiveFile>> = live_files
                    .as_deref()
                    .and_then(|s| serde_json::from_str(s).ok());
                let rights = merge_rights(&self.settings.defaults.rights, d.rights.as_ref());
                expires_at = rights.expires_at.clone();
                visible = visible
                    && self.parent_visible(KIND_PRODUCT, &r.product_id)
                    && files.is_some()
                    && !expired(rights.expires_at.as_deref(), self.now_time);
                let mut variant_ids = None;
                if let Some(ves) = d.variant_external_ids.as_ref().filter(|v| !v.is_empty()) {
                    let mut ids = Vec::new();
                    for ve in ves {
                        if let Some(id) = self
                            .tx
                            .query_row(
                                "SELECT id FROM variants WHERE external_id = ? AND product_id = ?",
                                params![ve, r.product_id],
                                |x| x.get::<_, String>(0),
                            )
                            .optional()?
                        {
                            ids.push(id);
                        }
                    }
                    ids.sort();
                    variant_ids = Some(ids);
                }
                let mut asset = AssetRep {
                    id: r.id.clone(),
                    external_id: r.external_id.clone(),
                    product_id: r.product_id.clone(),
                    brand_id: r.brand_id.clone(),
                    media_type: "image".into(),
                    color_code: d.color_code.clone(),
                    variant_ids,
                    role: d.role.clone(),
                    view: d.view.clone(),
                    position: d.position,
                    filename: String::new(),
                    alt_text: d.alt_text.clone(),
                    content_type: String::new(),
                    width: 0,
                    height: 0,
                    bytes: 0,
                    sha256: String::new(),
                    rights,
                    provenance: effective_provenance(d.provenance.as_ref()),
                    renditions: None,
                    ext: d.ext.clone(),
                };
                if let Some(files) = files.as_ref() {
                    if let Some(o) = files.get("original") {
                        asset.content_type = o.content_type.clone();
                        asset.width = o.width;
                        asset.height = o.height;
                        asset.bytes = o.bytes;
                        asset.sha256 = o.sha256.clone();
                        asset.filename = d
                            .filename
                            .clone()
                            .filter(|f| !f.is_empty())
                            .unwrap_or_else(|| {
                                format!("{}.{}", r.external_id, image_ext(&o.content_type))
                            });
                        let mut rs = BTreeMap::new();
                        for n in RENDITION_NAMES {
                            if let Some(f) = files.get(n) {
                                rs.insert(
                                    n.to_string(),
                                    RenditionRep {
                                        name: n.into(),
                                        url: String::new(),
                                        url_expires_at: None,
                                        content_type: f.content_type.clone(),
                                        width: f.width,
                                        height: f.height,
                                        bytes: f.bytes,
                                        sha256: f.sha256.clone(),
                                    },
                                );
                            }
                        }
                        asset.renditions = Some(rs);
                    }
                }
                to_json(&asset)
            }
        };
        let rep_hash = hash_hex(rep_json.as_bytes());
        let (mut updated_at, mut last_seq) = (r.updated_at.clone(), r.last_seq);
        if visible && (!r.visible || rep_hash != r.rep_hash) {
            last_seq = self.emit(r.kind, "upsert", r)?;
            updated_at = self.now.clone();
        } else if !visible && r.visible {
            last_seq = self.emit(r.kind, "delete", r)?;
        } else if rep_hash != r.rep_hash {
            updated_at = self.now.clone();
        }
        if r.kind == KIND_ASSET {
            self.tx.execute(
                "UPDATE assets SET visible = ?, rep = ?, rep_hash = ?, updated_at = ?, last_seq = ?, live_files = ?, pending = ?, expires_at = ? WHERE id = ?",
                params![visible as i64, rep_json, rep_hash, updated_at, last_seq, live_files, pending as i64, expires_at, r.id],
            )?;
            r.live_files = live_files;
            r.pending = pending;
        } else {
            self.tx.execute(
                &format!(
                    "UPDATE {} SET visible = ?, rep = ?, rep_hash = ?, updated_at = ?, last_seq = ? WHERE id = ?",
                    table_of(r.kind)
                ),
                params![visible as i64, rep_json, rep_hash, updated_at, last_seq, r.id],
            )?;
        }
        r.visible = visible;
        r.rep = rep_json;
        r.rep_hash = rep_hash;
        r.updated_at = updated_at;
        r.last_seq = last_seq;
        Ok(())
    }

    /// Resolves the asset's files to blobs; complete when the original and
    /// all renditions exist.
    fn resolve_files(&self, d: &AssetData) -> Result<(BTreeMap<String, LiveFile>, bool)> {
        let mut out = BTreeMap::new();
        let Some(files) = d.files.as_ref() else {
            return Ok((out, false));
        };
        let Some(orig) = files.get("original") else {
            return Ok((out, false));
        };
        let Some(of) = self.blob_file(orig)? else {
            return Ok((out, false));
        };
        out.insert("original".to_string(), of);
        for n in DERIVED_RENDITIONS {
            if let Some(rf) = files.get(n) {
                match self.blob_file(rf)? {
                    Some(f) => {
                        out.insert(n.to_string(), f);
                    }
                    None => return Ok((out, false)),
                }
                continue;
            }
            let f = self
                .tx
                .query_row(
                    "SELECT sha256, width, height, bytes FROM renditions WHERE original_sha = ? AND name = ?",
                    params![orig.sha256, n],
                    |x| {
                        Ok(LiveFile {
                            sha256: x.get(0)?,
                            content_type: "image/jpeg".into(),
                            width: x.get(1)?,
                            height: x.get(2)?,
                            bytes: x.get(3)?,
                        })
                    },
                )
                .optional()?;
            match f {
                Some(f) => {
                    out.insert(n.to_string(), f);
                }
                None => return Ok((out, false)),
            }
        }
        Ok((out, true))
    }

    fn blob_file(&self, f: &FileRef) -> Result<Option<LiveFile>> {
        let b = self
            .tx
            .query_row(
                "SELECT sha256, content_type, bytes, width, height FROM blobs WHERE sha256 = ?",
                [&f.sha256],
                |x| {
                    Ok((
                        x.get::<_, String>(0)?,
                        x.get::<_, String>(1)?,
                        x.get::<_, i64>(2)?,
                        x.get::<_, Option<i64>>(3)?,
                        x.get::<_, Option<i64>>(4)?,
                    ))
                },
            )
            .optional()?;
        let Some((sha, ct, bytes, w, h)) = b else {
            return Ok(None);
        };
        let mut width = w.unwrap_or(0);
        let mut height = h.unwrap_or(0);
        if width == 0 {
            width = f.width.unwrap_or(0);
        }
        if height == 0 {
            height = f.height.unwrap_or(0);
        }
        Ok(Some(LiveFile {
            sha256: sha,
            content_type: ct,
            width: width.max(1),
            height: height.max(1),
            bytes,
        }))
    }

    /// Recomputes a product's variants and assets in feed order.
    pub fn cascade_product(&mut self, product_id: &str) -> Result<()> {
        for mut v in load_rows(
            self.tx,
            KIND_VARIANT,
            "WHERE product_id = ? ORDER BY external_id",
            &[&product_id],
        )? {
            self.recompute(&mut v)?;
        }
        let w = format!("WHERE product_id = ?{ASSET_ORDER}");
        for mut a in load_rows(self.tx, KIND_ASSET, &w, &[&product_id])? {
            self.recompute(&mut a)?;
        }
        Ok(())
    }

    /// Recomputes a brand's products, then variants, then assets.
    pub fn cascade_brand(&mut self, brand_id: &str) -> Result<()> {
        for mut p in load_rows(
            self.tx,
            KIND_PRODUCT,
            "WHERE brand_id = ? ORDER BY external_id",
            &[&brand_id],
        )? {
            self.recompute(&mut p)?;
        }
        for mut v in load_rows(
            self.tx,
            KIND_VARIANT,
            "WHERE brand_id = ? ORDER BY product_id, external_id",
            &[&brand_id],
        )? {
            self.recompute(&mut v)?;
        }
        for mut a in load_rows(
            self.tx,
            KIND_ASSET,
            "WHERE brand_id = ? ORDER BY product_id, CASE WHEN color_code IS NULL THEN 0 ELSE 1 END, color_code, position, external_id",
            &[&brand_id],
        )? {
            self.recompute(&mut a)?;
        }
        Ok(())
    }

    /// Recomputes every visible asset (default rights changed).
    pub fn recompute_all_assets(&mut self) -> Result<()> {
        for mut a in load_rows(
            self.tx,
            KIND_ASSET,
            "ORDER BY product_id, CASE WHEN color_code IS NULL THEN 0 ELSE 1 END, color_code, position, external_id",
            &[],
        )? {
            self.recompute(&mut a)?;
        }
        Ok(())
    }

    /// Rebuilds the search columns of a product.
    pub fn refresh_product_index(&mut self, product_id: &str) -> Result<()> {
        let data: Option<String> = self
            .tx
            .query_row(
                "SELECT data FROM products WHERE id = ?",
                [product_id],
                |r| r.get(0),
            )
            .optional()?;
        let Some(data) = data else { return Ok(()) };
        let d: ProductData = serde_json::from_str(&data).unwrap_or_default();
        let mut parts = vec![d.style_number.clone()];
        if let Some(n) = &d.name {
            parts.extend(n.values().cloned());
        }
        let mut st = self
            .tx
            .prepare("SELECT data, gtin FROM variants WHERE product_id = ?")?;
        let rows = st.query_map([product_id], |r| {
            Ok((r.get::<_, String>(0)?, r.get::<_, Option<String>>(1)?))
        })?;
        for row in rows {
            let (vd, g) = row?;
            let v: VariantData = serde_json::from_str(&vd).unwrap_or_default();
            parts.push(v.color.code.clone());
            parts.push(v.sku.clone().unwrap_or_default());
            parts.push(v.gtin.clone().unwrap_or_default());
            parts.push(g.unwrap_or_default());
            parts.push(v.color.supplier_color.clone().unwrap_or_default());
            if let Some(n) = &v.color.name {
                parts.extend(n.values().cloned());
            }
        }
        drop(st);
        let text = parts.join(" ").to_lowercase();
        let name_sort =
            pick(d.name.as_ref(), &self.settings.portal.default_language, &[]).to_lowercase();
        self.tx.execute(
            "UPDATE products SET search_text = ?, name_sort = ?, style_number = ?, item_type = ?, target_group = ?, season = ?, collection = ? WHERE id = ?",
            params![text, name_sort, d.style_number, d.item_type, d.target_group, d.season, d.collection, product_id],
        )?;
        let mut want = BTreeSet::new();
        for m in d.materials.iter().flatten() {
            for f in &m.fibers {
                for q in &f.qualifiers {
                    want.insert(q.code.clone());
                }
            }
        }
        let have: BTreeSet<String> = {
            let mut st = self
                .tx
                .prepare("SELECT code FROM product_qualifiers WHERE product_id = ?")?;
            let r = st
                .query_map([product_id], |r| r.get(0))?
                .collect::<rusqlite::Result<_>>()?;
            r
        };
        for c in have.difference(&want) {
            self.tx.execute(
                "DELETE FROM product_qualifiers WHERE product_id = ? AND code = ?",
                params![product_id, c],
            )?;
        }
        for c in want.difference(&have) {
            self.tx.execute(
                "INSERT INTO product_qualifiers (product_id, code) VALUES (?, ?)",
                params![product_id, c],
            )?;
        }
        Ok(())
    }

    fn brand_allowed(&self, ext: &str) -> bool {
        match &self.allowed_brands {
            None => true,
            Some(l) => l.iter().any(|b| b == ext),
        }
    }

    fn brand_external_id_of(&self, brand_id: &str) -> String {
        self.tx
            .query_row(
                "SELECT external_id FROM brands WHERE id = ?",
                [brand_id],
                |r| r.get(0),
            )
            .unwrap_or_default()
    }

    /// Validates doc for kind and builds the stored write model.
    fn prepare(
        &mut self,
        kind: &str,
        ext: &str,
        doc: &mut Map<String, Value>,
        existing: Option<&Row>,
    ) -> Result<Prepared> {
        let deprecated = article::prepare_article_input(kind, doc);
        let doc_v = Value::Object(doc.clone());
        let errs = schemas::validate(input_schema(kind), &doc_v);
        if !errs.is_empty() {
            if kind == KIND_VARIANT {
                if let Some(e) = errs.iter().find(|e| e.pointer == "/gtin") {
                    return Err(Problem::new(
                        "invalid_gtin",
                        "The GTIN must have 8, 12, 13 or 14 digits and a valid check digit.",
                    )
                    .field("/gtin", "invalid_gtin", e.message.clone()));
                }
            }
            return Err(validation_problem(&errs));
        }
        let mut warnings = Vec::new();
        let mut details = Vec::new();
        let known = known_fields(kind);
        for ptr in schemas::unknown_members(input_schema(kind), &doc_v) {
            let top = ptr.trim_start_matches('/');
            if !top.contains('/') && known.contains(&top) {
                continue;
            }
            warnings.push(format!("unknown member {ptr} ignored"));
        }
        if let Some(ptr) = deprecated {
            details.push(WarningDetail {
                code: article::WARN_QUALIFIER_DEPRECATED.into(),
                pointer: Some(ptr),
                detail: "the single \"qualifier\" of drafts of 0.3 was read as \"qualifiers\"; send \"qualifiers\" (a list) instead".into(),
                ..Default::default()
            });
        }
        let status = doc.get("status").and_then(|v| v.as_str()).map(String::from);
        let decode_err = |e: serde_json::Error| Problem::new("validation_failed", e.to_string());
        let mut p = Prepared {
            data: String::new(),
            status,
            brand_id: String::new(),
            product_id: String::new(),
            name: String::new(),
            style_number: String::new(),
            gtin: None,
            color_code: None,
            sku: None,
            position: 0,
            original_sha: None,
            warnings,
            details,
        };
        match kind {
            KIND_BRAND => {
                if !self.brand_allowed(ext) {
                    return Err(forbidden_brand());
                }
                let mut d: BrandData = serde_json::from_value(doc_v).map_err(decode_err)?;
                d.name = d.name.trim().to_string();
                p.name = d.name.clone();
                p.data = to_json(&d);
            }
            KIND_PRODUCT => {
                let mut d: ProductData = serde_json::from_value(doc_v).map_err(decode_err)?;
                let mut bext = d.brand_external_id.trim().to_string();
                if bext.is_empty() {
                    let n: i64 = self
                        .tx
                        .query_row("SELECT COUNT(*) FROM brands", [], |r| r.get(0))?;
                    if n == 1 {
                        bext = self
                            .tx
                            .query_row("SELECT external_id FROM brands", [], |r| r.get(0))?;
                    } else {
                        return Err(Problem::new(
                            "validation_failed",
                            "brand_external_id is required because this node has more than one brand.",
                        )
                        .field("/brand_external_id", "validation_failed", "required"));
                    }
                }
                let brand_id: Option<String> = self
                    .tx
                    .query_row(
                        "SELECT id FROM brands WHERE external_id = ?",
                        [&bext],
                        |r| r.get(0),
                    )
                    .optional()?;
                let Some(brand_id) = brand_id else {
                    return Err(Problem::new(
                        "unknown_parent",
                        format!("Brand {bext:?} does not exist."),
                    )
                    .field(
                        "/brand_external_id",
                        "unknown_parent",
                        "unknown brand",
                    ));
                };
                if !self.brand_allowed(&bext)
                    || existing.is_some_and(|e| {
                        !self.brand_allowed(&self.brand_external_id_of(&e.brand_id))
                    })
                {
                    return Err(forbidden_brand());
                }
                d.brand_external_id = bext;
                d.style_number = d.style_number.trim().to_string();
                if let Some(a) = d.attributes.as_mut() {
                    a.values_mut().for_each(norm_numbers);
                }
                let mut ms = d.materials.take().unwrap_or_default();
                let mut care = d.care.take().unwrap_or_default();
                article::normalize_terms(&mut ms, &mut care);
                d.materials = if ms.is_empty() && doc.get("materials").is_none_or(|v| v.is_null()) {
                    None
                } else {
                    Some(ms)
                };
                d.care = if care.is_empty() && doc.get("care").is_none_or(|v| v.is_null()) {
                    None
                } else {
                    Some(care)
                };
                if let Some(f) = d.features.as_mut() {
                    f.values_mut().for_each(norm_numbers);
                }
                if d.features.as_ref().is_some_and(|f| f.is_empty()) {
                    d.features = None;
                }
                if d.certifications.as_ref().is_some_and(|c| c.is_empty()) {
                    d.certifications = None;
                }
                if d.footwear_materials.as_ref().is_some_and(|f| {
                    f.upper.is_none()
                        && f.lining_and_sock.is_none()
                        && f.outer_sole.is_none()
                        && f.ext.is_empty()
                }) {
                    d.footwear_materials = None;
                }
                let lw = article::label_warnings(&d);
                p.details.extend(lw);
                for wd in &p.details {
                    p.warnings.push(format!("{}: {}", wd.code, wd.detail));
                }
                p.style_number = d.style_number.clone();
                p.data = to_json(&d);
                p.brand_id = brand_id;
            }
            KIND_VARIANT => {
                let mut d: VariantData = serde_json::from_value(doc_v).map_err(decode_err)?;
                let (product_id, brand_id) = self.product_of(&d.product_external_id)?;
                if !self.brand_allowed(&self.brand_external_id_of(&brand_id))
                    || existing.is_some_and(|e| {
                        !self.brand_allowed(&self.brand_external_id_of(&e.brand_id))
                    })
                {
                    return Err(forbidden_brand());
                }
                if let Some(g) = d.gtin.as_mut() {
                    *g = g.trim().to_string();
                    if !obx_format::gtin::valid_check_digit(g) {
                        return Err(Problem::new(
                            "invalid_gtin",
                            format!("GTIN {g} has a wrong check digit."),
                        )
                        .field(
                            "/gtin",
                            "invalid_gtin",
                            "wrong check digit",
                        ));
                    }
                    let n = normalize_gtin(g).unwrap_or_else(|| g.clone());
                    let other: Option<(String, String)> = self
                        .tx
                        .query_row(
                            "SELECT v.external_id, p.external_id FROM variants v JOIN products p ON p.id = v.product_id WHERE v.gtin = ? AND v.id <> ?",
                            params![n, existing.map(|e| e.id.as_str()).unwrap_or("")],
                            |r| Ok((r.get(0)?, r.get(1)?)),
                        )
                        .optional()?;
                    if let Some((ov, op)) = other {
                        let msg =
                            format!("GTIN {g} already belongs to variant {ov:?} of product {op:?}");
                        return Err(Problem::new("gtin_conflict", format!("{msg}.")).field(
                            "/gtin",
                            "gtin_conflict",
                            msg,
                        ));
                    }
                    p.gtin = Some(n);
                }
                d.color.code = d.color.code.trim().to_string();
                if d.measurements.as_ref().is_some_and(|m| m.empty()) {
                    d.measurements = None;
                }
                if let Some(r) = d
                    .measurements
                    .as_ref()
                    .and_then(|m| m.strap_length_cm.as_ref())
                {
                    if r.min > r.max {
                        return Err(Problem::new(
                            "validation_failed",
                            "strap_length_cm: min is larger than max.",
                        )
                        .field(
                            "/measurements/strap_length_cm",
                            "validation_failed",
                            "min must not be larger than max",
                        ));
                    }
                }
                p.color_code = Some(d.color.code.clone());
                p.sku = d.sku.clone();
                p.data = to_json(&d);
                p.product_id = product_id;
                p.brand_id = brand_id;
            }
            _ => {
                let mut d: AssetData = serde_json::from_value(doc_v).map_err(decode_err)?;
                let (product_id, brand_id) = self.product_of(&d.product_external_id)?;
                if !self.brand_allowed(&self.brand_external_id_of(&brand_id))
                    || existing.is_some_and(|e| {
                        !self.brand_allowed(&self.brand_external_id_of(&e.brand_id))
                    })
                {
                    return Err(forbidden_brand());
                }
                if d.media_type.is_empty() {
                    d.media_type = "image".into();
                }
                d.color_code = d
                    .color_code
                    .map(|c| c.trim().to_string())
                    .filter(|c| !c.is_empty());
                // rights/provenance: keep only what differs from the defaults
                // (a record read with defaults applied and written back is
                // unchanged); extension members are kept.
                d.rights = match doc.get("rights") {
                    Some(Value::Object(raw)) => {
                        let defaults = match to_value(&self.settings.defaults.rights) {
                            Value::Object(m) => m,
                            _ => Map::new(),
                        };
                        let mut out = BTreeMap::new();
                        for (k, v) in raw {
                            let mut v = v.clone();
                            if crate::model::is_ext_name(k) {
                                out.insert(k.clone(), v);
                                continue;
                            }
                            if !matches!(
                                k.as_str(),
                                "license"
                                    | "license_text"
                                    | "channels"
                                    | "territories"
                                    | "embargo_until"
                                    | "expires_at"
                                    | "credit"
                                    | "model_release"
                            ) {
                                continue;
                            }
                            if (k == "embargo_until" || k == "expires_at") && !v.is_null() {
                                match v.as_str().and_then(normalize_time) {
                                    Some(s) => v = Value::String(s),
                                    None => {
                                        return Err(Problem::new(
                                            "validation_failed",
                                            format!("Invalid {k}."),
                                        )
                                        .field(
                                            &format!("/rights/{k}"),
                                            "validation_failed",
                                            "not an RFC 3339 timestamp",
                                        ));
                                    }
                                }
                            }
                            norm_numbers(&mut v);
                            if defaults.get(k) == Some(&v) {
                                continue;
                            }
                            out.insert(k.clone(), v);
                        }
                        if raw.get("license").and_then(|v| v.as_str()) == Some("custom")
                            && raw
                                .get("license_text")
                                .and_then(|v| v.as_str())
                                .is_none_or(|s| s.trim().is_empty())
                        {
                            return Err(Problem::new(
                                "validation_failed",
                                "license_text is required for a custom licence.",
                            )
                            .field(
                                "/rights/license_text",
                                "validation_failed",
                                "required when license is custom",
                            ));
                        }
                        if out.is_empty() { None } else { Some(out) }
                    }
                    _ => None,
                };
                d.provenance = match doc.get("provenance") {
                    Some(Value::Object(raw)) => {
                        let ai = raw
                            .get("ai_generated")
                            .and_then(|v| v.as_bool())
                            .unwrap_or(false);
                        let defaults = json!({"ai_generated": false, "ai_edited": false, "c2pa": "none",
                            "c2pa_manifest_url": null, "generator": null, "source": if ai { "generated" } else { "photo" }});
                        let mut out = BTreeMap::new();
                        for (k, v) in raw {
                            if crate::model::is_ext_name(k) {
                                out.insert(k.clone(), v.clone());
                                continue;
                            }
                            if !matches!(
                                k.as_str(),
                                "ai_generated"
                                    | "ai_edited"
                                    | "source"
                                    | "c2pa"
                                    | "c2pa_manifest_url"
                                    | "generator"
                            ) {
                                continue;
                            }
                            if defaults.get(k) == Some(v) {
                                continue;
                            }
                            out.insert(k.clone(), v.clone());
                        }
                        if out.is_empty() { None } else { Some(out) }
                    }
                    _ => None,
                };
                if !doc.contains_key("files") {
                    if let Some(e) = existing {
                        let cur: AssetData = serde_json::from_str(&e.data).unwrap_or_default();
                        d.files = cur.files;
                    }
                } else if let Some(files) = d.files.as_mut() {
                    for (name, f) in files.iter_mut() {
                        let dims: Option<(Option<i64>, Option<i64>)> = self
                            .tx
                            .query_row(
                                "SELECT width, height FROM blobs WHERE sha256 = ?",
                                [&f.sha256],
                                |r| Ok((r.get(0)?, r.get(1)?)),
                            )
                            .optional()?;
                        let Some((bw, bh)) = dims else {
                            return Err(Problem::new(
                                "blob_missing",
                                format!("File {name} ({}) has not been uploaded.", f.sha256),
                            )
                            .field(
                                &format!("/files/{name}/sha256"),
                                "blob_missing",
                                "unknown sha256",
                            ));
                        };
                        if bw.is_some() && bh.is_some() {
                            f.width = None;
                            f.height = None;
                        }
                    }
                    if let Some(orig) = files.get("original").map(|o| o.sha256.clone()) {
                        for n in DERIVED_RENDITIONS {
                            let Some(rf) = files.get(n) else { continue };
                            let own: Option<String> = self
                                .tx
                                .query_row(
                                    "SELECT sha256 FROM renditions WHERE original_sha = ? AND name = ?",
                                    params![orig, n],
                                    |r| r.get(0),
                                )
                                .optional()?;
                            if own.as_deref() == Some(rf.sha256.as_str()) {
                                files.remove(n);
                            }
                        }
                    }
                    if files.is_empty() {
                        d.files = None;
                    }
                }
                if let Some(files) = d.files.as_ref() {
                    if !files.contains_key("original") {
                        return Err(
                            Problem::new("validation_failed", "files needs an original.").field(
                                "/files/original",
                                "validation_failed",
                                "required",
                            ),
                        );
                    }
                }
                let mut q = String::from(
                    "SELECT id, external_id FROM assets WHERE product_id = ? AND position = ?",
                );
                let mut args: Vec<Box<dyn rusqlite::ToSql>> =
                    vec![Box::new(product_id.clone()), Box::new(d.position)];
                match &d.color_code {
                    None => q.push_str(" AND color_code IS NULL"),
                    Some(c) => {
                        q.push_str(" AND color_code = ?");
                        args.push(Box::new(c.clone()));
                    }
                }
                if let Some(e) = existing {
                    q.push_str(" AND id <> ?");
                    args.push(Box::new(e.id.clone()));
                }
                let mut st = self.tx.prepare(&q)?;
                let refs: Vec<&dyn rusqlite::ToSql> = args.iter().map(|b| b.as_ref()).collect();
                let rows = st.query_map(refs.as_slice(), |r| {
                    Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?))
                })?;
                let mut conflict = None;
                for row in rows {
                    let (id, e) = row?;
                    if !self.position_exclude.contains(&id) {
                        conflict = Some(e);
                    }
                }
                drop(st);
                if let Some(c) = conflict {
                    return Err(Problem::new(
                        "position_conflict",
                        format!(
                            "Asset {c:?} already has position {} for this product and colour.",
                            d.position
                        ),
                    )
                    .field("/position", "position_conflict", "position in use"));
                }
                p.color_code = d.color_code.clone();
                p.position = d.position;
                p.original_sha = d
                    .files
                    .as_ref()
                    .and_then(|f| f.get("original"))
                    .map(|o| o.sha256.clone());
                p.data = to_json(&d);
                p.product_id = product_id;
                p.brand_id = brand_id;
            }
        }
        Ok(p)
    }

    fn product_of(&self, product_ext: &str) -> Result<(String, String)> {
        self.tx
            .query_row(
                "SELECT id, brand_id FROM products WHERE external_id = ?",
                [product_ext],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?
            .ok_or_else(|| {
                Problem::new(
                    "unknown_parent",
                    format!("Product {product_ext:?} does not exist."),
                )
                .field("/product_external_id", "unknown_parent", "unknown product")
            })
    }

    /// Creates or replaces an object (PUT).
    pub fn upsert(
        &mut self,
        kind: &str,
        ext: &str,
        doc: Map<String, Value>,
        if_match: &str,
    ) -> (IngestResult, Option<Problem>) {
        self.write("upsert", kind, ext, doc, if_match)
    }

    pub fn write(
        &mut self,
        op: &str,
        kind: &str,
        ext: &str,
        mut doc: Map<String, Value>,
        if_match: &str,
    ) -> (IngestResult, Option<Problem>) {
        let (ext, ok) = valid_external_id(ext);
        let mut res = IngestResult {
            op: op.into(),
            kind: kind.into(),
            external_id: ext.clone(),
            ..Default::default()
        };
        if !ok {
            return (
                res,
                Some(
                    Problem::new("validation_failed", "Invalid external id.").field(
                        "",
                        "validation_failed",
                        "external id must be 1-200 characters without control characters or '/'",
                    ),
                ),
            );
        }
        match self.write_inner(kind, &ext, &mut doc, if_match, &mut res) {
            Ok(()) => (res, None),
            Err(p) => (res, Some(p)),
        }
    }

    fn write_inner(
        &mut self,
        kind: &str,
        ext: &str,
        doc: &mut Map<String, Value>,
        if_match: &str,
        res: &mut IngestResult,
    ) -> Result<()> {
        let existing = load_row(self.tx, kind, ext)?;
        if !if_match.is_empty()
            && existing
                .as_ref()
                .is_none_or(|e| if_match != "*" && if_match != e.etag)
        {
            return Err(Problem::new(
                "precondition_failed",
                "If-Match does not match the current version.",
            ));
        }
        let p = match self.prepare(kind, ext, doc, existing.as_ref()) {
            Ok(p) => p,
            Err(e) => {
                if let Some(x) = &existing {
                    res.id = Some(x.id.clone());
                }
                return Err(e);
            }
        };
        let mut status = existing
            .as_ref()
            .map(|e| e.status.clone())
            .unwrap_or_else(|| self.settings.defaults.ingest_status.clone());
        if let Some(s) = &p.status {
            status = s.clone();
        }
        res.warnings = p.warnings.clone();
        res.warning_details = p.details.clone();
        if let Some(e) = &existing {
            let same_parent = kind == KIND_BRAND
                || (kind == KIND_PRODUCT && e.brand_id == p.brand_id)
                || (kind != KIND_PRODUCT && e.product_id == p.product_id);
            if e.data == p.data && e.status == status && same_parent {
                res.result = "unchanged".into();
                res.id = Some(e.id.clone());
                res.visibility = Some(visibility_of(self.tx, e));
                res.etag = Some(e.etag.clone());
                return Ok(());
            }
        }
        let etag = etag_for(&status, &p.data);
        let cascade;
        let mut r;
        match existing.clone() {
            None => {
                r = Row {
                    kind: kind_static(kind),
                    id: crate::ids::new(id_prefix(kind)),
                    external_id: ext.into(),
                    status: status.clone(),
                    data: p.data.clone(),
                    etag: etag.clone(),
                    created_at: self.now.clone(),
                    updated_at: self.now.clone(),
                    record_updated_at: self.now.clone(),
                    brand_id: p.brand_id.clone(),
                    product_id: p.product_id.clone(),
                    ..Default::default()
                };
                self.insert_row(&r, &p).map_err(gtin_unique)?;
                res.result = "created".into();
                cascade = true;
            }
            Some(e) => {
                r = e.clone();
                let status_changed = e.status != status;
                let parent_changed = (kind == KIND_PRODUCT && e.brand_id != p.brand_id)
                    || ((kind == KIND_VARIANT || kind == KIND_ASSET)
                        && e.product_id != p.product_id);
                r.status = status.clone();
                r.data = p.data.clone();
                r.etag = etag.clone();
                r.record_updated_at = self.now.clone();
                if !p.brand_id.is_empty() {
                    r.brand_id = p.brand_id.clone();
                }
                if !p.product_id.is_empty() {
                    r.product_id = p.product_id.clone();
                }
                self.update_row(&r, &p).map_err(gtin_unique)?;
                res.result = "updated".into();
                cascade = status_changed || parent_changed;
            }
        }
        self.after_write(&mut r, cascade, existing.as_ref())?;
        res.id = Some(r.id.clone());
        res.visibility = Some(visibility_of(self.tx, &r));
        res.etag = Some(r.etag.clone());
        Ok(())
    }

    fn insert_row(&self, r: &Row, p: &Prepared) -> rusqlite::Result<usize> {
        let n = &self.now;
        match r.kind {
            KIND_BRAND => self.tx.execute(
                "INSERT INTO brands (id, external_id, status, name, data, etag, created_at, updated_at, record_updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                params![r.id, r.external_id, r.status, p.name, r.data, r.etag, n, n, n],
            ),
            KIND_PRODUCT => self.tx.execute(
                "INSERT INTO products (id, external_id, brand_id, status, data, etag, created_at, updated_at, record_updated_at, touched_at, style_number) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                params![r.id, r.external_id, r.brand_id, r.status, r.data, r.etag, n, n, n, n, p.style_number],
            ),
            KIND_VARIANT => self.tx.execute(
                "INSERT INTO variants (id, external_id, product_id, brand_id, status, data, etag, created_at, updated_at, record_updated_at, gtin, color_code, sku) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                params![r.id, r.external_id, r.product_id, r.brand_id, r.status, r.data, r.etag, n, n, n, p.gtin, p.color_code.clone().unwrap_or_default(), p.sku],
            ),
            _ => self.tx.execute(
                "INSERT INTO assets (id, external_id, product_id, brand_id, status, data, etag, created_at, updated_at, record_updated_at, color_code, position, original_sha) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                params![r.id, r.external_id, r.product_id, r.brand_id, r.status, r.data, r.etag, n, n, n, p.color_code, p.position, p.original_sha],
            ),
        }
    }

    fn update_row(&self, r: &Row, p: &Prepared) -> rusqlite::Result<usize> {
        let n = &self.now;
        match r.kind {
            KIND_BRAND => self.tx.execute(
                "UPDATE brands SET status = ?, name = ?, data = ?, etag = ?, record_updated_at = ? WHERE id = ?",
                params![r.status, p.name, r.data, r.etag, n, r.id],
            ),
            KIND_PRODUCT => {
                self.tx.execute(
                    "UPDATE products SET status = ?, brand_id = ?, data = ?, etag = ?, record_updated_at = ? WHERE id = ?",
                    params![r.status, r.brand_id, r.data, r.etag, n, r.id],
                )?;
                self.tx.execute("UPDATE variants SET brand_id = ? WHERE product_id = ?", params![r.brand_id, r.id])?;
                self.tx.execute("UPDATE assets SET brand_id = ? WHERE product_id = ?", params![r.brand_id, r.id])
            }
            KIND_VARIANT => self.tx.execute(
                "UPDATE variants SET status = ?, product_id = ?, brand_id = ?, data = ?, etag = ?, record_updated_at = ?, gtin = ?, color_code = ?, sku = ? WHERE id = ?",
                params![r.status, r.product_id, r.brand_id, r.data, r.etag, n, p.gtin, p.color_code.clone().unwrap_or_default(), p.sku, r.id],
            ),
            _ => self.tx.execute(
                "UPDATE assets SET status = ?, product_id = ?, brand_id = ?, data = ?, etag = ?, record_updated_at = ?, color_code = ?, position = ?, original_sha = ? WHERE id = ?",
                params![r.status, r.product_id, r.brand_id, r.data, r.etag, n, p.color_code, p.position, p.original_sha, r.id],
            ),
        }
    }

    fn after_write(&mut self, r: &mut Row, cascade: bool, existing: Option<&Row>) -> Result<()> {
        let old_product = existing
            .filter(|e| e.kind != KIND_BRAND)
            .map(|e| e.product_id.clone())
            .unwrap_or_default();
        match r.kind {
            KIND_BRAND => {
                self.recompute(r)?;
                if cascade {
                    let id = r.id.clone();
                    self.cascade_brand(&id)?;
                }
            }
            KIND_PRODUCT => {
                self.recompute(r)?;
                let id = r.id.clone();
                self.refresh_product_index(&id)?;
                if cascade {
                    self.cascade_product(&id)?;
                }
            }
            KIND_VARIANT => {
                self.recompute(r)?;
                let pid = r.product_id.clone();
                self.refresh_product_index(&pid)?;
                if !old_product.is_empty() && old_product != pid {
                    self.refresh_product_index(&old_product)?;
                }
            }
            _ => self.recompute(r)?,
        }
        Ok(())
    }

    /// Applies a JSON merge patch (RFC 7396) to the stored write model.
    pub fn patch(
        &mut self,
        op: &str,
        kind: &str,
        ext: &str,
        patch: Value,
        if_match: &str,
    ) -> (IngestResult, Option<Problem>) {
        let (ext, ok) = valid_external_id(ext);
        let res = IngestResult {
            op: op.into(),
            kind: kind.into(),
            external_id: ext.clone(),
            ..Default::default()
        };
        if !ok {
            return (
                res,
                Some(Problem::new("validation_failed", "Invalid external id.")),
            );
        }
        let existing = match load_row(self.tx, kind, &ext) {
            Ok(e) => e,
            Err(p) => return (res, Some(p)),
        };
        let Some(existing) = existing else {
            return (
                res,
                Some(Problem::new(
                    "not_found",
                    format!("{kind} {ext:?} does not exist."),
                )),
            );
        };
        if !patch.is_object() {
            return (
                res,
                Some(Problem::new(
                    "invalid_request",
                    "A JSON object is required.",
                )),
            );
        }
        let mut doc: Value = serde_json::from_str(&existing.data).unwrap_or(json!({}));
        doc["status"] = Value::String(existing.status.clone());
        merge_patch(&mut doc, &patch);
        let mut m = match doc {
            Value::Object(m) => m,
            _ => Map::new(),
        };
        m.retain(|_, v| !v.is_null());
        self.write(op, kind, &ext, m, if_match)
    }

    /// Publishes or unpublishes (a patch of status).
    pub fn set_status(
        &mut self,
        op: &str,
        kind: &str,
        ext: &str,
    ) -> (IngestResult, Option<Problem>) {
        let status = if op == "unpublish" {
            "unpublished"
        } else {
            "published"
        };
        self.patch(op, kind, ext, json!({"status": status}), "")
    }

    /// Removes an object (and a product's variants and assets).
    pub fn delete(&mut self, kind: &str, ext: &str) -> (IngestResult, Option<Problem>) {
        let (ext, _) = valid_external_id(ext);
        let mut res = IngestResult {
            op: "delete".into(),
            kind: kind.into(),
            external_id: ext.clone(),
            ..Default::default()
        };
        match self.delete_inner(kind, &ext, &mut res) {
            Ok(()) => (res, None),
            Err(p) => (res, Some(p)),
        }
    }

    fn delete_inner(&mut self, kind: &str, ext: &str, res: &mut IngestResult) -> Result<()> {
        let Some(existing) = load_row(self.tx, kind, ext)? else {
            res.result = "unchanged".into();
            return Ok(());
        };
        let brand_ext = if kind == KIND_BRAND {
            existing.external_id.clone()
        } else {
            self.brand_external_id_of(&existing.brand_id)
        };
        if !self.brand_allowed(&brand_ext) {
            return Err(forbidden_brand());
        }
        res.id = Some(existing.id.clone());
        match kind {
            KIND_BRAND => {
                let n: i64 = self.tx.query_row(
                    "SELECT COUNT(*) FROM products WHERE brand_id = ?",
                    [&existing.id],
                    |r| r.get(0),
                )?;
                if n > 0 {
                    return Err(Problem::new(
                        "conflict",
                        format!("Brand {ext:?} still has {n} products; delete or move them first."),
                    ));
                }
                self.delete_row(&existing)?;
            }
            KIND_PRODUCT => {
                self.delete_row(&existing)?;
                for v in load_rows(
                    self.tx,
                    KIND_VARIANT,
                    "WHERE product_id = ? ORDER BY external_id",
                    &[&existing.id],
                )? {
                    self.delete_row(&v)?;
                }
                let w = format!("WHERE product_id = ?{ASSET_ORDER}");
                for a in load_rows(self.tx, KIND_ASSET, &w, &[&existing.id])? {
                    self.delete_row(&a)?;
                }
                self.tx.execute(
                    "DELETE FROM product_qualifiers WHERE product_id = ?",
                    [&existing.id],
                )?;
                self.tx
                    .execute("DELETE FROM products WHERE id = ?", [&existing.id])?;
            }
            KIND_VARIANT => {
                self.delete_row(&existing)?;
                self.refresh_product_index(&existing.product_id)?;
            }
            _ => self.delete_row(&existing)?,
        }
        res.result = "deleted".into();
        Ok(())
    }

    fn delete_row(&mut self, r: &Row) -> Result<()> {
        if r.visible {
            self.emit(r.kind, "delete", r)?;
        }
        if r.kind == KIND_PRODUCT {
            return Ok(());
        }
        self.tx.execute(
            &format!("DELETE FROM {} WHERE id = ?", table_of(r.kind)),
            [&r.id],
        )?;
        Ok(())
    }

    /// Assigns positions 1..n to all assets of a product colour.
    pub fn asset_order(
        &mut self,
        product_ext: &str,
        color_code: Option<&str>,
        list: &[String],
    ) -> Result<Vec<IngestResult>> {
        let Some(prod) = load_row(self.tx, KIND_PRODUCT, product_ext)? else {
            return Err(Problem::new(
                "not_found",
                format!("Product {product_ext:?} does not exist."),
            ));
        };
        if !self.brand_allowed(&self.brand_external_id_of(&prod.brand_id)) {
            return Err(forbidden_brand());
        }
        let cur = match color_code {
            None => load_rows(
                self.tx,
                KIND_ASSET,
                &format!("WHERE product_id = ? AND color_code IS NULL{ASSET_ORDER}"),
                &[&prod.id],
            )?,
            Some(c) => load_rows(
                self.tx,
                KIND_ASSET,
                &format!("WHERE product_id = ? AND color_code = ?{ASSET_ORDER}"),
                &[&prod.id, &c],
            )?,
        };
        let mut by_ext: BTreeMap<String, Row> = cur
            .iter()
            .map(|r| (r.external_id.clone(), r.clone()))
            .collect();
        let mut seen = HashSet::new();
        for e in list {
            if !by_ext.contains_key(e) || !seen.insert(e.clone()) {
                return Err(Problem::new(
                    "validation_failed",
                    format!(
                        "Asset {e:?} is not an asset of this product and colour (or listed twice)."
                    ),
                )
                .field(
                    "/asset_external_ids",
                    "validation_failed",
                    "unknown or duplicate asset",
                ));
            }
        }
        if list.len() != cur.len() {
            return Err(Problem::new(
                "validation_failed",
                format!("List all {} assets of this product and colour.", cur.len()),
            )
            .field(
                "/asset_external_ids",
                "validation_failed",
                "all assets must be listed",
            ));
        }
        for (i, e) in list.iter().enumerate() {
            self.tx.execute(
                "UPDATE assets SET position = ? WHERE id = ?",
                params![-(i as i64 + 1), by_ext[e].id],
            )?;
        }
        let mut out = Vec::new();
        for (i, e) in list.iter().enumerate() {
            let r = by_ext.get_mut(e).unwrap();
            let mut d: AssetData = serde_json::from_str(&r.data).unwrap_or_default();
            let pos = i as i64 + 1;
            let mut res = IngestResult {
                op: "patch".into(),
                kind: KIND_ASSET.into(),
                external_id: e.clone(),
                id: Some(r.id.clone()),
                ..Default::default()
            };
            if d.position == pos {
                self.tx.execute(
                    "UPDATE assets SET position = ? WHERE id = ?",
                    params![pos, r.id],
                )?;
                res.result = "unchanged".into();
            } else {
                d.position = pos;
                r.data = to_json(&d);
                r.etag = etag_for(&r.status, &r.data);
                r.position = pos;
                self.tx.execute(
                    "UPDATE assets SET position = ?, data = ?, etag = ?, record_updated_at = ? WHERE id = ?",
                    params![pos, r.data, r.etag, self.now, r.id],
                )?;
                res.result = "updated".into();
            }
            out.push(res);
        }
        for (i, e) in list.iter().enumerate() {
            let mut r = by_ext.remove(e).unwrap();
            self.recompute(&mut r)?;
            out[i].visibility = Some(visibility_of(self.tx, &r));
            out[i].etag = Some(r.etag.clone());
        }
        Ok(out)
    }

    /// Attaches an uploaded blob as one file of an asset.
    pub fn put_file(
        &mut self,
        ext: &str,
        rendition: &str,
        sha: &str,
    ) -> (IngestResult, Option<Problem>) {
        let (ext, _) = valid_external_id(ext);
        let mut res = IngestResult {
            op: "upsert".into(),
            kind: KIND_ASSET.into(),
            external_id: ext.clone(),
            ..Default::default()
        };
        let existing = match load_row(self.tx, KIND_ASSET, &ext) {
            Ok(e) => e,
            Err(p) => return (res, Some(p)),
        };
        let Some(existing) = existing else {
            return (
                res,
                Some(Problem::new(
                    "not_found",
                    format!("Asset {ext:?} does not exist; create its metadata first."),
                )),
            );
        };
        let d: AssetData = serde_json::from_str(&existing.data).unwrap_or_default();
        let cur = d.files.clone().unwrap_or_default();
        if cur.get(rendition).is_some_and(|f| f.sha256 == sha) {
            res.result = "unchanged".into();
            res.id = Some(existing.id.clone());
            res.visibility = Some(visibility_of(self.tx, &existing));
            res.etag = Some(existing.etag.clone());
            return (res, None);
        }
        let mut files = Map::new();
        if rendition == "original" {
            files.insert("original".into(), json!({"sha256": sha}));
        } else {
            if !cur.contains_key("original") {
                return (
                    res,
                    Some(Problem::new(
                        "validation_failed",
                        "Upload the original first.",
                    )),
                );
            }
            for (n, f) in &cur {
                let mut m = Map::new();
                m.insert("sha256".into(), Value::String(f.sha256.clone()));
                if let Some(w) = f.width {
                    m.insert("width".into(), w.into());
                }
                if let Some(h) = f.height {
                    m.insert("height".into(), h.into());
                }
                files.insert(n.clone(), Value::Object(m));
            }
            files.insert(rendition.into(), json!({"sha256": sha}));
        }
        let mut doc = match serde_json::from_str::<Value>(&existing.data) {
            Ok(Value::Object(m)) => m,
            _ => Map::new(),
        };
        doc.insert("status".into(), Value::String(existing.status.clone()));
        doc.insert("files".into(), Value::Object(files));
        doc.retain(|_, v| !v.is_null());
        let (mut r, p) = self.write("upsert", KIND_ASSET, &ext, doc, "");
        r.op = "upsert".into();
        (r, p)
    }
}

fn gtin_unique(e: rusqlite::Error) -> Problem {
    if crate::db::is_unique_violation(&e) {
        Problem::new(
            "gtin_conflict",
            "The GTIN already belongs to another variant.",
        )
    } else {
        Problem::internal(e)
    }
}

pub fn merge_patch(target: &mut Value, patch: &Value) {
    let Value::Object(pm) = patch else {
        *target = patch.clone();
        return;
    };
    if !target.is_object() {
        *target = Value::Object(Map::new());
    }
    let tm = target.as_object_mut().unwrap();
    for (k, v) in pm {
        if v.is_null() {
            tm.remove(k);
        } else {
            merge_patch(tm.entry(k.clone()).or_insert(Value::Null), v);
        }
    }
}

/// The text for lang: the language, its base language, English, then the
/// first in `order`, then alphabetical.
pub fn pick(t: Option<&LocalizedText>, lang: &str, order: &[String]) -> String {
    let Some(t) = t.filter(|t| !t.is_empty()) else {
        return String::new();
    };
    let get = |k: &str| t.get(k).filter(|v| !v.is_empty()).cloned();
    if !lang.is_empty() {
        if let Some(v) = get(lang) {
            return v;
        }
        if let Some((base, _)) = lang.split_once('-') {
            if let Some(v) = get(base) {
                return v;
            }
        }
    }
    if let Some(v) = get("en") {
        return v;
    }
    for o in order {
        if let Some(v) = get(o) {
            return v;
        }
    }
    t.values()
        .find(|v| !v.is_empty())
        .cloned()
        .unwrap_or_default()
}

pub fn product_rep(r: &Row, d: ProductData) -> ProductRep {
    ProductRep {
        id: r.id.clone(),
        external_id: r.external_id.clone(),
        brand_id: r.brand_id.clone(),
        style_number: d.style_number,
        name: d.name,
        description: d.description,
        item_type: d.item_type,
        item_subtype: d.item_subtype,
        gpc_brick: d.gpc_brick,
        target_group: d.target_group,
        season: d.season,
        collection: d.collection,
        materials: d.materials,
        contains_animal_origin: d.contains_animal_origin,
        footwear_materials: d.footwear_materials,
        care: d.care,
        country_of_origin: d.country_of_origin,
        certifications: d.certifications,
        dpp_url: d.dpp_url,
        features: d.features,
        attributes: d.attributes,
        created_at: r.created_at.clone(),
        ext: d.ext,
    }
}

pub fn variant_rep(r: &Row, d: VariantData) -> VariantRep {
    VariantRep {
        id: r.id.clone(),
        external_id: r.external_id.clone(),
        product_id: r.product_id.clone(),
        brand_id: r.brand_id.clone(),
        gtin: d.gtin.as_deref().and_then(normalize_gtin),
        gtin_original: d.gtin,
        sku: d.sku,
        color: d.color,
        size: d.size,
        size_length: d.size_length,
        size_system: d.size_system,
        measurements: d.measurements,
        ext: d.ext,
    }
}

/// The IngestRecord visibility of a row.
pub fn visibility_of(c: &Connection, r: &Row) -> String {
    if r.visible && !(r.kind == KIND_ASSET && r.pending) {
        return "visible".into();
    }
    if r.kind == KIND_ASSET && r.status == "published" {
        let pv: i64 = c
            .query_row(
                "SELECT visible FROM products WHERE id = ?",
                [&r.product_id],
                |x| x.get(0),
            )
            .unwrap_or(0);
        if pv == 1 && (r.pending || r.live_files.is_none()) {
            return "pending_files".into();
        }
    }
    "hidden".into()
}

/// The files an asset still needs.
pub fn missing_files(c: &Connection, r: &Row) -> Vec<String> {
    let d: AssetData = serde_json::from_str(&r.data).unwrap_or_default();
    let files = d.files.unwrap_or_default();
    let Some(orig) = files.get("original") else {
        return RENDITION_NAMES.iter().map(|s| s.to_string()).collect();
    };
    let mut missing = Vec::new();
    for n in DERIVED_RENDITIONS {
        if let Some(rf) = files.get(n) {
            if !blob_exists(c, &rf.sha256) {
                missing.push(n.to_string());
            }
            continue;
        }
        let has: Option<String> = c
            .query_row(
                "SELECT sha256 FROM renditions WHERE original_sha = ? AND name = ?",
                params![orig.sha256, n],
                |x| x.get(0),
            )
            .optional()
            .unwrap_or(None);
        if has.is_none() {
            missing.push(n.to_string());
        }
    }
    missing
}

pub fn blob_exists(c: &Connection, sha: &str) -> bool {
    c.query_row("SELECT 1 FROM blobs WHERE sha256 = ?", [sha], |_| Ok(()))
        .optional()
        .ok()
        .flatten()
        .is_some()
}

/// Every current blob of an asset: the referenced files with their
/// dimensions, plus the renditions the node made itself.
pub fn current_files(c: &Connection, own: &BTreeMap<String, FileRef>) -> BTreeMap<String, FileRef> {
    let mut files = BTreeMap::new();
    for (n, f) in own {
        let mut f = f.clone();
        if f.width.is_none() || f.height.is_none() {
            if let Ok(Some((Some(w), Some(h)))) = c
                .query_row(
                    "SELECT width, height FROM blobs WHERE sha256 = ?",
                    [&f.sha256],
                    |x| Ok((x.get::<_, Option<i64>>(0)?, x.get::<_, Option<i64>>(1)?)),
                )
                .optional()
            {
                f.width = Some(w);
                f.height = Some(h);
            }
        }
        files.insert(n.clone(), f);
    }
    let Some(orig) = files.get("original").map(|o| o.sha256.clone()) else {
        return files;
    };
    for n in DERIVED_RENDITIONS {
        if files.contains_key(n) {
            continue;
        }
        if let Ok(Some((sha, w, h))) = c
            .query_row(
                "SELECT sha256, width, height FROM renditions WHERE original_sha = ? AND name = ?",
                params![orig, n],
                |x| {
                    Ok((
                        x.get::<_, String>(0)?,
                        x.get::<_, i64>(1)?,
                        x.get::<_, i64>(2)?,
                    ))
                },
            )
            .optional()
        {
            files.insert(
                n.to_string(),
                FileRef {
                    sha256: sha,
                    width: Some(w),
                    height: Some(h),
                },
            );
        }
    }
    files
}

/// The IngestRecord of a row (the write model with defaults applied).
pub fn record(c: &Connection, r: &Row, settings: &Settings) -> Value {
    let mut data = match serde_json::from_str::<Value>(&r.data) {
        Ok(Value::Object(m)) => m,
        _ => Map::new(),
    };
    data.insert("status".into(), Value::String(r.status.clone()));
    if r.kind == KIND_ASSET {
        let d: AssetData = serde_json::from_str(&r.data).unwrap_or_default();
        data.insert(
            "rights".into(),
            to_value(&merge_rights(&settings.defaults.rights, d.rights.as_ref())),
        );
        data.insert(
            "provenance".into(),
            to_value(&effective_provenance(d.provenance.as_ref())),
        );
        data.insert(
            "files".into(),
            to_value(&current_files(c, &d.files.unwrap_or_default())),
        );
    }
    let mut rec = json!({
        "kind": r.kind, "id": r.id, "external_id": r.external_id, "status": r.status,
        "visibility": visibility_of(c, r), "etag": r.etag, "created_at": r.created_at,
        "updated_at": r.record_updated_at, "data": Value::Object(data),
    });
    if r.kind == KIND_ASSET {
        rec["missing_files"] = to_value(&missing_files(c, r));
    }
    rec
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn merge_patch_rfc7396() {
        let mut t = json!({"a": "b", "c": {"d": "e", "f": "g"}});
        merge_patch(&mut t, &json!({"a": "z", "c": {"f": null}}));
        assert_eq!(t, json!({"a": "z", "c": {"d": "e"}}));
    }

    #[test]
    fn external_ids() {
        assert!(valid_external_id(" MN-1001 ").1);
        assert!(!valid_external_id("a/b").1);
        assert!(!valid_external_id("").1);
    }
}
