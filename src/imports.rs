//! The canonical import (import-format.md, ingest.md §6): products.csv,
//! assets.csv and images, as a zip package or as separate parts, run as a
//! job. Row and file problems are ImportRowError items of the job; they
//! never fail the request. A port of node-go's imports.go and
//! import_http.go. Excel workbooks (import-format.md §5) are converted to
//! the same rows by `obx_format::importfmt::convert_workbook`.

#![allow(
    clippy::result_large_err,
    clippy::too_many_arguments,
    clippy::type_complexity,
    clippy::collapsible_if
)]

use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use axum::body::Bytes;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, HeaderValue, Method, header};
use rusqlite::{Connection, OptionalExtension};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};

use crate::app::{App, MAX_IMPORT_BYTES, MAX_UPLOAD_BYTES};
use crate::catalog::{Writer, load_row, normalize_gtin, valid_external_id};
use crate::http::{Res, json as json_resp, limit_param, ok};
use crate::jobs::{self, Job, JobSpec};
use crate::model::*;
use crate::problem::{Problem, Result};
use obx_format::importfmt as fmt;

// ---- payload ---------------------------------------------------------------------

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct ImportRowError {
    pub file: String,
    pub row: Option<usize>,
    pub column: Option<String>,
    pub severity: String,
    pub obx_error: String,
    pub detail: String,
    pub value: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ImportFile {
    pub field: String,
    pub name: String,
    pub key: String,
    pub bytes: i64,
    pub sha256: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ManifestRendition {
    pub sha256: String,
    #[serde(default)]
    pub width: i64,
    #[serde(default)]
    pub height: i64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ManifestEntry {
    pub file: String,
    pub sha256: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub width: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub height: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub renditions: Option<BTreeMap<String, ManifestRendition>>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ImportOptions {
    #[serde(default)]
    pub mode: String,
    #[serde(default)]
    pub allow_mass_unpublish: bool,
    #[serde(default)]
    pub dry_run: bool,
    #[serde(default)]
    pub default_language: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ImportPayload {
    #[serde(default)]
    pub files: Vec<ImportFile>,
    #[serde(default)]
    pub manifest: Vec<ManifestEntry>,
    #[serde(default)]
    pub options: ImportOptions,
    #[serde(default)]
    pub allowed: Option<Vec<String>>,
    #[serde(default)]
    pub can_delete: bool,
    /// The ImportSource of a scheduled or pull run (its files are fetched
    /// when the job starts).
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub source_id: String,
    /// Run even when the remote files did not change.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub force: bool,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub fingerprint: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Counts {
    pub rows: usize,
    pub files: usize,
    pub created: usize,
    pub updated: usize,
    pub unchanged: usize,
    pub unpublished: usize,
    pub errors: usize,
    pub warnings: usize,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct ImportResult {
    /// A source run skipped because its files did not change (node-go
    /// wrote x-node-go-unchanged).
    #[serde(
        default,
        rename = "x-node-rs-unchanged",
        alias = "x-node-go-unchanged",
        skip_serializing_if = "std::ops::Not::not"
    )]
    unchanged: bool,
    #[serde(default)]
    mode: String,
    #[serde(default)]
    dry_run: bool,
    #[serde(default)]
    files: Vec<Value>,
    #[serde(default)]
    counts: Counts,
    #[serde(default)]
    error: Option<Value>,
}

// ---- the importer ------------------------------------------------------------------

#[derive(Debug, Clone)]
enum Source {
    Zip { path: PathBuf, index: usize },
    Blob { key: String },
    Manifest(ManifestEntry),
}

#[derive(Debug, Clone)]
struct ImageSource {
    name: String,
    src: Source,
}

#[derive(Debug, Clone)]
struct VariantPlan {
    ext: String,
    def: String,
    gtin14: String,
    gtin_raw: String,
    doc: Map<String, Value>,
    row: usize,
}

#[derive(Debug, Clone)]
struct ImagePlan {
    src: ImageSource,
    ext: String,
    doc: Map<String, Value>,
    sha: String,
}

#[derive(Debug, Clone, Default)]
struct ProductPlan {
    ext: String,
    style: String,
    brand_ref: String,
    /// None for an image-only product that is already in the catalog.
    doc: Option<Map<String, Value>>,
    first: HashMap<String, String>,
    rows: Vec<usize>,
    variants: Vec<VariantPlan>,
    /// lowercase colour code → spelling
    colors: HashMap<String, String>,
    families: HashMap<String, String>,
    images: Vec<ImagePlan>,
}

#[derive(Debug, Clone, Default)]
struct Present {
    plain: HashSet<String>,
    langs: HashMap<String, HashSet<String>>,
    attrs: HashSet<String>,
    features: HashSet<String>,
}

fn columns_of(header: &[String], default_lang: &str) -> Present {
    let mut p = Present::default();
    for base in ["name", "description", "color_name"] {
        p.langs.insert(base.into(), HashSet::new());
    }
    for h in header {
        match h.split_once(':') {
            Some(("attr", k)) => {
                p.attrs.insert(k.into());
            }
            Some(("feature", k)) => {
                p.features.insert(k.into());
            }
            Some((base, lang)) => {
                if let Some(l) = p.langs.get_mut(base) {
                    l.insert(lang.into());
                }
            }
            None => {
                p.plain.insert(h.clone());
                if let Some(l) = p.langs.get_mut(h.as_str()) {
                    l.insert(default_lang.into());
                }
            }
        }
    }
    p
}

#[derive(Clone, Copy)]
enum Keyed {
    No,
    Attr,
    Feature,
    Measurement,
}

struct ColumnField {
    path: &'static str,
    column: &'static str,
    text: bool,
    keyed: Keyed,
}

const fn cf(path: &'static str, column: &'static str) -> ColumnField {
    ColumnField {
        path,
        column,
        text: false,
        keyed: Keyed::No,
    }
}
const fn cft(path: &'static str, column: &'static str) -> ColumnField {
    ColumnField {
        path,
        column,
        text: true,
        keyed: Keyed::No,
    }
}
const fn cfk(path: &'static str, keyed: Keyed) -> ColumnField {
    ColumnField {
        path,
        column: "",
        text: false,
        keyed,
    }
}

const PRODUCT_FIELDS: &[ColumnField] = &[
    cft("name", "name"),
    cft("description", "description"),
    cf("item_type", "item_type"),
    cf("item_subtype", "item_subtype"),
    cf("target_group", "target_group"),
    cf("season", "season"),
    cf("collection", "collection"),
    cf("gpc_brick", "gpc_brick"),
    cf("materials", "materials"),
    cf("contains_animal_origin", "contains_animal_origin"),
    cf("footwear_materials", "footwear_materials"),
    cf("care", "care"),
    cf("country_of_origin", "country_of_origin"),
    cf("certifications", "certifications"),
    cf("dpp_url", "dpp_url"),
    cfk("features", Keyed::Feature),
    cfk("attributes", Keyed::Attr),
];

const VARIANT_FIELDS: &[ColumnField] = &[
    cf("gtin", "gtin"),
    cf("sku", "sku"),
    cf("size", "size"),
    cf("size_length", "size_length"),
    cf("size_system", "size_system"),
    cft("color.name", "color_name"),
    cf("color.family", "color_family"),
    cf("color.supplier_color", "supplier_color"),
    cfk("measurements", Keyed::Measurement),
];

fn keyed_present(k: Keyed, p: &Present, key: &str) -> bool {
    match k {
        Keyed::Attr => p.attrs.contains(key),
        Keyed::Feature => p.features.contains(key),
        Keyed::Measurement => p.plain.contains(key),
        Keyed::No => false,
    }
}

/// A column the file does not have keeps the stored field; an empty cell of
/// a column it has removes it (import-format.md, I-IMP-6).
fn keep_absent_columns(
    doc: &Map<String, Value>,
    stored: &str,
    fields: &[ColumnField],
    present: &Present,
) -> Map<String, Value> {
    let Ok(Value::Object(old)) = serde_json::from_str::<Value>(stored) else {
        return doc.clone();
    };
    let mut out = doc.clone();
    for f in fields {
        let (head, key) = match f.path.split_once('.') {
            Some((h, k)) => (Some(h), k),
            None => (None, f.path),
        };
        let (parent, old_parent): (&mut Map<String, Value>, &Map<String, Value>) = match head {
            None => (&mut out, &old),
            Some(h) => {
                let Some(Value::Object(op)) = old.get(h) else {
                    continue;
                };
                let Some(Value::Object(p)) = out.get_mut(h) else {
                    continue;
                };
                (p, op)
            }
        };
        let Some(was) = old_parent.get(key).filter(|v| !v.is_null()) else {
            continue;
        };
        if !matches!(f.keyed, Keyed::No) || f.text {
            let Some(old_map) = was.as_object() else {
                continue;
            };
            let mut now = parent
                .get(key)
                .and_then(|v| v.as_object())
                .cloned()
                .unwrap_or_default();
            for (k, v) in old_map {
                let stated = now.contains_key(k);
                let absent = (!matches!(f.keyed, Keyed::No) && !keyed_present(f.keyed, present, k))
                    || (f.text && !present.langs.get(f.column).is_some_and(|l| l.contains(k)));
                if !stated && absent {
                    now.insert(k.clone(), v.clone());
                }
            }
            if !now.is_empty() {
                parent.insert(key.into(), Value::Object(now));
            }
        } else if !parent.contains_key(key) && !present.plain.contains(f.column) {
            parent.insert(key.into(), was.clone());
        }
    }
    out
}

/// A new import keeps the stored embargo, credit, alt text and AI label of
/// an image unless assets.csv states them (I-IMP-5).
fn keep_image_facts(doc: &Map<String, Value>, stored: &str) -> Map<String, Value> {
    let Ok(Value::Object(prev)) = serde_json::from_str::<Value>(stored) else {
        return doc.clone();
    };
    let mut out = doc.clone();
    for k in ["alt_text", "rights", "provenance"] {
        let Some(old) = prev
            .get(k)
            .and_then(|v| v.as_object())
            .filter(|o| !o.is_empty())
        else {
            continue;
        };
        let mut merged = old.clone();
        if let Some(stated) = out.get(k).and_then(|v| v.as_object()) {
            for (f, v) in stated {
                merged.insert(f.clone(), v.clone());
            }
        }
        out.insert(k.into(), Value::Object(merged));
    }
    out
}

const PRODUCT_EXT_PATHS: &[&str] = &[
    "",
    "/materials/*",
    "/materials/*/part",
    "/materials/*/fibers/*",
    "/materials/*/fibers/*/material",
    "/materials/*/fibers/*/qualifiers/*",
    "/care/*",
    "/certifications/*",
    "/footwear_materials",
];
const VARIANT_EXT_PATHS: &[&str] = &["", "/color", "/measurements"];
const ASSET_EXT_PATHS: &[&str] = &["", "/rights", "/provenance"];

fn split_path(p: &str) -> Vec<&str> {
    if p.is_empty() {
        vec![]
    } else {
        p.trim_start_matches('/').split('/').collect()
    }
}

fn for_each_at<'a>(
    v: &'a Value,
    segs: &[&str],
    ptr: String,
    f: &mut dyn FnMut(String, &'a Map<String, Value>),
) {
    if segs.is_empty() {
        if let Value::Object(m) = v {
            f(ptr, m);
        }
        return;
    }
    match v {
        Value::Object(m) if segs[0] != "*" => {
            if let Some(c) = m.get(segs[0]) {
                for_each_at(c, &segs[1..], format!("{ptr}/{}", segs[0]), f);
            }
        }
        Value::Array(a) if segs[0] == "*" => {
            for (i, c) in a.iter().enumerate() {
                for_each_at(c, &segs[1..], format!("{ptr}/{i}"), f);
            }
        }
        _ => {}
    }
}

/// The extension members of a stored object, by JSON Pointer.
fn collect_extensions(stored: &str, paths: &[&str]) -> Vec<(String, Map<String, Value>)> {
    if !stored.contains("\"x-") {
        return vec![];
    }
    let Ok(doc) = serde_json::from_str::<Value>(stored) else {
        return vec![];
    };
    let mut out = Vec::new();
    for p in paths {
        for_each_at(&doc, &split_path(p), String::new(), &mut |ptr, obj| {
            let m: Map<String, Value> = obj
                .iter()
                .filter(|(k, _)| is_ext_name(k))
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect();
            if !m.is_empty() {
                out.push((ptr, m));
            }
        });
    }
    out
}

fn object_at<'a>(v: &'a mut Value, segs: &[&str]) -> Option<&'a mut Map<String, Value>> {
    if segs.is_empty() {
        return v.as_object_mut();
    }
    match v {
        Value::Object(m) => object_at(m.get_mut(segs[0])?, &segs[1..]),
        Value::Array(a) => {
            let i: usize = segs[0].parse().ok()?;
            object_at(a.get_mut(i)?, &segs[1..])
        }
        _ => None,
    }
}

/// Copies stored extension members into doc where doc does not set them:
/// an import never removes a brand's extensions.
fn carry_extensions(doc: &mut Map<String, Value>, stored: Vec<(String, Map<String, Value>)>) {
    let mut root = Value::Object(std::mem::take(doc));
    for (ptr, members) in stored {
        let seg = ptr.trim_start_matches('/');
        if matches!(seg, "rights" | "provenance" | "measurements")
            && root.get(seg).is_none_or(|v| v.is_null())
        {
            root[seg] = Value::Object(Map::new());
        }
        let segs = split_path(&ptr);
        if let Some(target) = object_at(&mut root, &segs) {
            for (k, v) in members {
                target.entry(k).or_insert(v);
            }
        }
    }
    if let Value::Object(m) = root {
        *doc = m;
    }
}

fn truncate(s: &str, n: usize) -> String {
    if s.len() <= n {
        return s.to_string();
    }
    let mut i = n;
    while !s.is_char_boundary(i) {
        i -= 1;
    }
    s[..i].to_string()
}

fn problem_column(p: &Problem) -> String {
    for e in &p.errors {
        if let Some(ptr) = e.pointer.as_deref().filter(|p| !p.is_empty()) {
            let c = ptr.trim_start_matches('/').split('/').next().unwrap_or("");
            return match c {
                "product_external_id" => "style_number".into(),
                "color" => "color_code".into(),
                c => c.into(),
            };
        }
    }
    String::new()
}

fn problem_detail(p: &Problem) -> String {
    let mut d = p.detail.clone().unwrap_or_else(|| p.title.clone());
    for e in &p.errors {
        if let Some(ptr) = e.pointer.as_deref().filter(|p| !p.is_empty()) {
            if !e.detail.is_empty() {
                d += &format!(" ({}: {})", ptr.trim_start_matches('/'), e.detail);
                break;
            }
        }
    }
    d
}

/// The default variant external id `<style>-<color>-<size>[-<size_length>]`
/// (import-format.md §1.2.1).
pub fn default_variant_id(style: &str, color: &str, size: &str, size_length: &str) -> String {
    let mut parts = vec![style.trim(), color.trim()];
    for p in [size, size_length] {
        let p = p.trim();
        if !p.is_empty() {
            parts.push(p);
        }
    }
    parts
        .join("-")
        .chars()
        .map(|c| {
            if (c as u32) < 0x20 || c == '\x7f' || c == '/' {
                '_'
            } else {
                c
            }
        })
        .collect()
}

struct CellErr {
    col: String,
    code: String,
    detail: String,
    value: String,
}

fn cell_err(col: &str, code: &str, detail: impl Into<String>, value: &str) -> CellErr {
    CellErr {
        col: col.into(),
        code: code.into(),
        detail: detail.into(),
        value: value.into(),
    }
}

fn is_product_column(h: &str) -> bool {
    let base = h.split(':').next().unwrap_or("");
    matches!(
        base,
        "brand"
            | "item_type"
            | "item_subtype"
            | "target_group"
            | "season"
            | "collection"
            | "gpc_brick"
            | "materials"
            | "contains_animal_origin"
            | "footwear_materials"
            | "care"
            | "country_of_origin"
            | "certifications"
            | "dpp_url"
            | "status"
            | "name"
            | "description"
            | "attr"
            | "feature"
    )
}

fn base_name(s: &str) -> String {
    let n = s.replace('\\', "/");
    n.rsplit('/').next().unwrap_or("").to_string()
}

fn obj(m: std::collections::BTreeMap<String, String>) -> Value {
    Value::Object(m.into_iter().map(|(k, v)| (k, Value::String(v))).collect())
}

const COLOURLESS: &str = "ALL";

/// The import state that is carried through every phase.
#[derive(Debug, Clone, Default)]
struct State_ {
    opts: ImportOptions,
    allowed: Option<Vec<String>>,
    lang: String,
    errors: Vec<ImportRowError>,
    counts: Counts,
    seen_variant: HashMap<String, usize>,
    gtin_ext: HashMap<String, String>,
    gtin_row: HashMap<String, usize>,
    present: Present,
    /// Row 1 of products.xlsx / assets.xlsx, keyed by the CSV file they
    /// stand for (import-format.md §5.5).
    workbooks: HashMap<String, Vec<String>>,
}

#[derive(Debug, Clone, Default)]
struct Importer {
    st: State_,
    plans: Vec<ProductPlan>,
    by_ext: HashMap<String, usize>,
    /// image-only products that are already in the catalog (lowercase style)
    extra: HashMap<String, ProductPlan>,
    extra_ord: Vec<String>,
}

impl State_ {
    fn add(
        &mut self,
        file: &str,
        row: usize,
        col: &str,
        code: &str,
        detail: &str,
        value: &str,
        warning: bool,
    ) {
        let (mut file, mut row, mut detail) = (file.to_string(), row, detail.to_string());
        if let Some(header) = self.workbooks.get(&file) {
            // The rows of a workbook: Excel's row numbers and a locator (§5.5).
            file = file.trim_end_matches(".csv").to_string() + ".xlsx";
            if row > 0 {
                row += 1;
            }
            detail = fmt::workbook_locator(header, row, col) + &detail;
        }
        let detail = detail.as_str();
        let mut e = ImportRowError {
            file,
            severity: if warning { "warning" } else { "error" }.into(),
            obx_error: code.into(),
            detail: truncate(detail, 2000),
            ..Default::default()
        };
        if warning {
            self.counts.warnings += 1;
        } else {
            self.counts.errors += 1;
        }
        if row > 0 {
            e.row = Some(row);
        }
        if !col.is_empty() {
            e.column = Some(col.into());
        }
        if !value.is_empty() {
            e.value = Some(truncate(value, 500));
        }
        self.errors.push(e);
    }

    /// Records a conversion error or warning of a workbook as it is.
    fn add_issue(&mut self, c: &fmt::CellIssue) {
        if c.severity == "warning" {
            self.counts.warnings += 1;
        } else {
            self.counts.errors += 1;
        }
        self.errors.push(ImportRowError {
            file: c.file.clone(),
            severity: c.severity.clone(),
            obx_error: c.obx_error.clone(),
            detail: truncate(&c.detail, 2000),
            row: (c.row > 0).then_some(c.row),
            column: (!c.column.is_empty()).then(|| c.column.clone()),
            value: c.value.as_deref().map(|v| truncate(v, 500)),
        });
    }

    /// The name an import's products / assets file has in messages.
    fn file_name(&self, csv_name: &str) -> String {
        if self.workbooks.contains_key(csv_name) {
            csv_name.trim_end_matches(".csv").to_string() + ".xlsx"
        } else {
            csv_name.to_string()
        }
    }

    /// Parses products.csv or assets.csv (role products / assets), or
    /// converts the workbook that stands for it (import-format.md §5). A
    /// workbook that cannot be imported gives one ImportRowError with row
    /// null and fails the import with that code.
    fn load_table(&mut self, role: &str, input: &TableIn) -> Result<fmt::Table> {
        let csv_name = format!("{role}.csv");
        let data = match input {
            TableIn::Csv(b) => {
                return fmt::parse_csv(b)
                    .map_err(|e| Problem::new("import_invalid", format!("{csv_name}: {e}")));
            }
            TableIn::Workbook(b) => b,
        };
        let file = fmt::workbook_file(role);
        let mut refuse = |code: &str, detail: String| {
            self.add_issue(&fmt::CellIssue {
                file: file.clone(),
                severity: "error".into(),
                obx_error: code.into(),
                detail: detail.clone(),
                ..Default::default()
            });
            Problem::new(code, format!("{file}: {detail}"))
        };
        if data.len() as u64 > crate::app::MAX_IMPORT_BYTES {
            return Err(refuse(
                "payload_too_large",
                format!(
                    "the file is larger than {} bytes",
                    crate::app::MAX_IMPORT_BYTES
                ),
            ));
        }
        let wb = match fmt::convert_workbook(data, role) {
            Ok(wb) => wb,
            Err(e) => return Err(refuse(e.code, e.detail)),
        };
        for c in wb.errors.iter().chain(&wb.warnings) {
            self.add_issue(c);
        }
        self.workbooks.insert(csv_name, wb.rows[0].clone());
        fmt::table_from_records(wb.rows)
            .map_err(|e| Problem::new("import_invalid", format!("{file}: {e}")))
    }

    fn count(&mut self, result: &str) {
        match result {
            "created" => self.counts.created += 1,
            "updated" => self.counts.updated += 1,
            "unchanged" => self.counts.unchanged += 1,
            _ => {}
        }
    }
}

impl Importer {
    fn parse_products(&mut self, t: &mut fmt::Table) -> Result<()> {
        if !t.has("style_number") {
            return Err(Problem::new(
                "import_invalid",
                format!(
                    "{} needs a style_number column.",
                    self.st.file_name("products.csv")
                ),
            ));
        }
        for c in fmt::unknown_columns(&t.header, fmt::KNOWN_COLUMNS) {
            self.st.add(
                "products.csv",
                0,
                &c,
                "validation_failed",
                &format!("unknown column {c:?} ignored"),
                "",
                true,
            );
        }
        let mut seen_feature = HashSet::new();
        for i in 0..t.header.len() {
            let h = t.header[i].clone();
            let Some(key) = h.strip_prefix("feature:") else {
                continue;
            };
            if !seen_feature.insert(h.clone()) {
                continue;
            }
            if !fmt::valid_key(key) {
                self.st.add(
                    "products.csv",
                    0,
                    &t.raw.get(i).cloned().unwrap_or_default(),
                    "validation_failed",
                    &format!("feature key {key:?} must be lowercase letters, digits and _; column ignored"),
                    "",
                    true,
                );
                t.header[i] = String::new();
            } else if fmt::feature_spec(key).is_none() {
                self.st.add(
                    "products.csv",
                    0,
                    &h,
                    "validation_failed",
                    &format!("feature {key:?} is not in the feature registry; its cells are stored as text"),
                    "",
                    true,
                );
            }
        }
        self.st.counts.rows = t.rows.len();
        self.st.present = columns_of(&t.header, &self.st.lang);
        let header = t.header.clone();
        for row in &t.rows {
            let style = row.get("style_number").to_string();
            if style.is_empty() {
                self.st.add(
                    "products.csv",
                    row.num,
                    "style_number",
                    "validation_failed",
                    "style_number is required",
                    "",
                    false,
                );
                continue;
            }
            let mut ext = row.get("product_id").to_string();
            if ext.is_empty() {
                ext = style.clone();
            }
            if !valid_external_id(&ext).1 {
                self.st.add(
                    "products.csv",
                    row.num,
                    "product_id",
                    "validation_failed",
                    "invalid product id",
                    &ext,
                    false,
                );
                continue;
            }
            let existing = self.by_ext.get(&ext).copied();
            let mut new_plan = None;
            match existing {
                None => match self.product_doc(row, &header, &style) {
                    Err(e) => {
                        self.st.add(
                            "products.csv",
                            row.num,
                            &e.col,
                            &e.code,
                            &e.detail,
                            &e.value,
                            false,
                        );
                        continue;
                    }
                    Ok(doc) => {
                        let mut p = ProductPlan {
                            ext: ext.clone(),
                            style: style.clone(),
                            brand_ref: row.get("brand").into(),
                            doc: Some(doc),
                            ..Default::default()
                        };
                        for h in &header {
                            if is_product_column(h) {
                                p.first.insert(h.clone(), row.get(h).into());
                            }
                        }
                        new_plan = Some(p);
                    }
                },
                Some(i) => {
                    let mut warns = Vec::new();
                    let plan = &mut self.plans[i];
                    for h in &header {
                        if !is_product_column(h) {
                            continue;
                        }
                        let v = row.get(h);
                        let first = plan.first.get(h).cloned().unwrap_or_default();
                        if !v.is_empty() && !first.is_empty() && first != v {
                            warns.push((h.clone(), v.to_string()));
                        } else if !v.is_empty() && first.is_empty() {
                            plan.first.insert(h.clone(), v.into());
                        }
                    }
                    for (h, v) in warns {
                        self.st.add(
                            "products.csv",
                            row.num,
                            &h,
                            "validation_failed",
                            &format!("different {h} than on the product's first row; the first value is used"),
                            &v,
                            true,
                        );
                    }
                }
            }
            let has_variant = ["gtin", "variant_id", "sku", "color_code", "size"]
                .iter()
                .any(|c| !row.get(c).is_empty());
            let mut vplan = None;
            if has_variant {
                let mut plan = match existing {
                    Some(i) => std::mem::take(&mut self.plans[i]),
                    None => new_plan.take().unwrap(),
                };
                let r = self.variant_doc(row, &header, &mut plan);
                match existing {
                    Some(i) => self.plans[i] = plan,
                    None => new_plan = Some(plan),
                }
                match r {
                    Err(e) => {
                        self.st.add(
                            "products.csv",
                            row.num,
                            &e.col,
                            &e.code,
                            &e.detail,
                            &e.value,
                            false,
                        );
                        continue;
                    }
                    Ok(v) => vplan = Some(v),
                }
            } else {
                for c in ["color_family", "size_length"]
                    .iter()
                    .chain(fmt::MEASUREMENT_COLUMNS.iter())
                {
                    let v = row.get(c);
                    if !v.is_empty() {
                        self.st.add(
                            "products.csv",
                            row.num,
                            c,
                            "validation_failed",
                            &format!("{c} is ignored on a row without variant columns (gtin, variant_id, sku, color_code or size)"),
                            v,
                            true,
                        );
                    }
                }
            }
            let idx = match existing {
                Some(i) => i,
                None => {
                    self.plans.push(new_plan.take().unwrap());
                    self.by_ext.insert(ext.clone(), self.plans.len() - 1);
                    self.plans.len() - 1
                }
            };
            let plan = &mut self.plans[idx];
            plan.rows.push(row.num);
            if let Some(v) = vplan {
                plan.variants.push(v);
            }
        }
        Ok(())
    }

    fn product_doc(
        &mut self,
        row: &fmt::Row,
        header: &[String],
        style: &str,
    ) -> std::result::Result<Map<String, Value>, CellErr> {
        let lang = self.st.lang.clone();
        let mut doc = Map::new();
        doc.insert("style_number".into(), json!(style));
        let Some(name) = fmt::localized(row, header, "name", &lang) else {
            return Err(cell_err(
                "name",
                "validation_failed",
                "a name is required (name or name:<language>)",
                "",
            ));
        };
        doc.insert("name".into(), obj(name));
        if let Some(d) = fmt::localized(row, header, "description", &lang) {
            doc.insert("description".into(), obj(d));
        }
        for c in ["item_type", "item_subtype", "target_group"] {
            let v = row.get(c);
            if !v.is_empty() {
                let k = fmt::key(v);
                if !fmt::valid_key(&k) {
                    return Err(cell_err(
                        c,
                        "validation_failed",
                        format!("{c} must be a lowercase key like t_shirt"),
                        v,
                    ));
                }
                doc.insert(c.into(), json!(k));
            }
        }
        for c in ["season", "collection", "dpp_url", "gpc_brick"] {
            let v = row.get(c);
            if !v.is_empty() {
                doc.insert(c.into(), json!(v));
            }
        }
        let v = row.get("country_of_origin");
        if !v.is_empty() {
            doc.insert("country_of_origin".into(), json!(v.to_uppercase()));
        }
        let v = row.get("materials");
        if !v.is_empty() {
            let (parts, warns) = fmt::parse_materials(v).map_err(|e| {
                cell_err(
                    "materials",
                    "validation_failed",
                    format!("materials: {e}"),
                    v,
                )
            })?;
            for w in warns {
                self.st.add(
                    "products.csv",
                    row.num,
                    "materials",
                    "validation_failed",
                    &w,
                    v,
                    true,
                );
            }
            doc.insert("materials".into(), fmt::materials_json(&parts));
        }
        let v = row.get("contains_animal_origin");
        if !v.is_empty() {
            let b = fmt::parse_bool(v).ok_or_else(|| {
                cell_err(
                    "contains_animal_origin",
                    "validation_failed",
                    "contains_animal_origin must be yes or no",
                    v,
                )
            })?;
            doc.insert("contains_animal_origin".into(), json!(b));
        }
        let v = row.get("footwear_materials");
        if !v.is_empty() {
            let f = fmt::parse_footwear_materials(v).map_err(|e| {
                cell_err(
                    "footwear_materials",
                    "validation_failed",
                    format!("footwear_materials: {e}"),
                    v,
                )
            })?;
            doc.insert("footwear_materials".into(), f.to_json());
        }
        let v = row.get("certifications");
        if !v.is_empty() {
            let cs = fmt::parse_certifications(v).map_err(|e| {
                cell_err(
                    "certifications",
                    "validation_failed",
                    format!("certifications: {e}"),
                    v,
                )
            })?;
            doc.insert(
                "certifications".into(),
                Value::Array(cs.iter().map(|c| c.to_json()).collect()),
            );
        }
        let mut features = Map::new();
        for h in header {
            let Some(key) = h.strip_prefix("feature:") else {
                continue;
            };
            let v = row.get(h);
            if v.is_empty() {
                continue;
            }
            let val = fmt::parse_feature(key, v)
                .map_err(|e| cell_err(h, "validation_failed", format!("feature {key}: {e}"), v))?;
            features.insert(key.into(), val);
        }
        if !features.is_empty() {
            doc.insert("features".into(), Value::Object(features));
        }
        let v = row.get("care");
        if !v.is_empty() {
            let (codes, warns) = fmt::parse_care(v)
                .map_err(|e| cell_err("care", "validation_failed", e.to_string(), v))?;
            for w in warns {
                self.st.add(
                    "products.csv",
                    row.num,
                    "care",
                    "validation_failed",
                    &w,
                    v,
                    true,
                );
            }
            doc.insert("care".into(), fmt::care_json(&codes));
        }
        let v = row.get("status");
        if !v.is_empty() {
            let s = v.to_lowercase();
            if s != "published" && s != "unpublished" {
                return Err(cell_err(
                    "status",
                    "validation_failed",
                    "status must be published or unpublished",
                    v,
                ));
            }
            doc.insert("status".into(), json!(s));
        }
        let mut attrs = Map::new();
        for h in header {
            let Some(k) = h.strip_prefix("attr:") else {
                continue;
            };
            let v = row.get(h);
            if v.is_empty() {
                continue;
            }
            if !fmt::valid_key(k) {
                return Err(cell_err(
                    h,
                    "validation_failed",
                    "attribute keys are lowercase like fit_type",
                    v,
                ));
            }
            attrs.insert(k.into(), json!(v));
        }
        if !attrs.is_empty() {
            doc.insert("attributes".into(), Value::Object(attrs));
        }
        Ok(doc)
    }

    fn variant_doc(
        &mut self,
        row: &fmt::Row,
        header: &[String],
        plan: &mut ProductPlan,
    ) -> std::result::Result<VariantPlan, CellErr> {
        let color = row.get("color_code").to_string();
        if color.is_empty() {
            return Err(cell_err(
                "color_code",
                "validation_failed",
                "color_code is required for a variant row",
                "",
            ));
        }
        let mut doc = Map::new();
        doc.insert("product_external_id".into(), json!(plan.ext));
        let gtin_raw = row.get("gtin").to_string();
        let mut gtin14 = String::new();
        if !gtin_raw.is_empty() {
            let g = fmt::gtin_cell(&gtin_raw)
                .map_err(|e| cell_err("gtin", "invalid_gtin", e.to_string(), &gtin_raw))?;
            gtin14 = normalize_gtin(&g).unwrap_or_default();
            doc.insert("gtin".into(), json!(g));
        }
        let mut c = Map::new();
        c.insert("code".into(), json!(color));
        if let Some(n) = fmt::localized(row, header, "color_name", &self.st.lang) {
            c.insert("name".into(), obj(n));
        }
        let v = row.get("supplier_color");
        if !v.is_empty() {
            c.insert("supplier_color".into(), json!(v));
        }
        let mut family = None;
        let v = row.get("color_family");
        if !v.is_empty() {
            let fam = fmt::parse_color_family(v)
                .map_err(|e| cell_err("color_family", "validation_failed", e.to_string(), v))?;
            c.insert("family".into(), json!(fam));
            family = Some(fam);
        }
        doc.insert("color".into(), Value::Object(c));
        for k in ["sku", "size", "size_length", "size_system"] {
            let v = row.get(k);
            if !v.is_empty() {
                doc.insert(k.into(), json!(v));
            }
        }
        let mut ms = Map::new();
        for k in fmt::MEASUREMENT_COLUMNS {
            let v = row.get(k);
            if v.is_empty() {
                continue;
            }
            if *k == "strap_length_cm" {
                let (lo, hi) = fmt::parse_strap_length(v)
                    .map_err(|e| cell_err(k, "validation_failed", format!("{k}: {e}"), v))?;
                ms.insert(
                    (*k).into(),
                    json!({"min": fmt::json_number(lo), "max": fmt::json_number(hi)}),
                );
                continue;
            }
            let n = fmt::parse_measurement(v)
                .map_err(|e| cell_err(k, "validation_failed", format!("{k}: {e}"), v))?;
            ms.insert((*k).into(), fmt::json_number(n));
        }
        if !ms.is_empty() {
            doc.insert("measurements".into(), Value::Object(ms));
        }
        let v = row.get("variant_status");
        if !v.is_empty() {
            let s = v.to_lowercase();
            if s != "published" && s != "unpublished" {
                return Err(cell_err(
                    "variant_status",
                    "validation_failed",
                    "variant_status must be published or unpublished",
                    v,
                ));
            }
            doc.insert("status".into(), json!(s));
        }
        let ext = row.get("variant_id").to_string();
        if !ext.is_empty() && !valid_external_id(&ext).1 {
            return Err(cell_err(
                "variant_id",
                "validation_failed",
                "invalid variant id",
                &ext,
            ));
        }
        plan.colors.insert(color.to_lowercase(), color.clone());
        if let Some(fam) = family {
            match plan.families.get(&color) {
                Some(prev) if *prev != fam => {
                    let msg = format!(
                        "differs from an earlier row of colour {color} ({prev}); every variant of one colour should have the same family"
                    );
                    self.st.add(
                        "products.csv",
                        row.num,
                        "color_family",
                        "validation_failed",
                        &msg,
                        &fam,
                        true,
                    );
                }
                Some(_) => {}
                None => {
                    plan.families.insert(color.clone(), fam);
                }
            }
        }
        Ok(VariantPlan {
            ext,
            def: default_variant_id(&plan.style, &color, row.get("size"), row.get("size_length")),
            gtin14,
            gtin_raw,
            doc,
            row: row.num,
        })
    }

    fn parse_assets(&mut self, t: &fmt::Table) -> Result<HashMap<String, (fmt::Row, bool)>> {
        if !t.has("file") {
            return Err(Problem::new(
                "import_invalid",
                format!("{} needs a file column.", self.st.file_name("assets.csv")),
            ));
        }
        for c in fmt::unknown_columns(&t.header, fmt::KNOWN_ASSET_COLUMNS) {
            self.st.add(
                "assets.csv",
                0,
                &c,
                "validation_failed",
                &format!("unknown column {c:?} ignored"),
                "",
                true,
            );
        }
        let mut out = HashMap::new();
        for r in &t.rows {
            if r.get("file").is_empty() {
                self.st.add(
                    "assets.csv",
                    r.num,
                    "file",
                    "validation_failed",
                    "file is required",
                    "",
                    false,
                );
                continue;
            }
            out.insert(base_name(r.get("file")).to_lowercase(), (r.clone(), false));
        }
        Ok(out)
    }

    /// Finds the product of an image: in this file, else in the catalog.
    fn catalog_product(&mut self, c: &Connection, style: &str) -> Option<(bool, usize, String)> {
        let ls = style.to_lowercase();
        for (i, p) in self.plans.iter().enumerate() {
            if p.style.to_lowercase() == ls || p.ext.to_lowercase() == ls {
                return Some((false, i, String::new()));
            }
        }
        if self.extra.contains_key(&ls) {
            return Some((true, 0, ls));
        }
        let found: Option<(String, String)> = c
            .query_row(
                "SELECT external_id, style_number FROM products WHERE LOWER(style_number) = ? OR LOWER(external_id) = ? ORDER BY CASE WHEN external_id = style_number THEN 0 ELSE 1 END LIMIT 1",
                [&ls, &ls],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()
            .ok()
            .flatten();
        let (ext, sn) = found?;
        let mut p = ProductPlan {
            ext: ext.clone(),
            style: sn,
            ..Default::default()
        };
        if let Ok(mut st) = c.prepare("SELECT DISTINCT v.color_code FROM variants v JOIN products p ON p.id = v.product_id WHERE p.external_id = ?") {
            if let Ok(rows) = st.query_map([&ext], |r| r.get::<_, String>(0)) {
                for cc in rows.flatten() {
                    p.colors.insert(cc.to_lowercase(), cc);
                }
            }
        }
        self.extra.insert(ls.clone(), p);
        self.extra_ord.push(ls.clone());
        Some((true, 0, ls))
    }

    fn plan_mut(&mut self, r: &(bool, usize, String)) -> &mut ProductPlan {
        if r.0 {
            self.extra.get_mut(&r.2).unwrap()
        } else {
            &mut self.plans[r.1]
        }
    }

    fn plan_images(
        &mut self,
        c: &Connection,
        mut images: Vec<ImageSource>,
        mut asset_rows: HashMap<String, (fmt::Row, bool)>,
        asset_header: &[String],
    ) {
        images.sort_by(|a, b| a.name.cmp(&b.name));
        let mut by_ext: HashMap<String, Vec<(ImagePlan, (bool, usize, String))>> = HashMap::new();
        let mut order = Vec::new();
        for src in images {
            let base = base_name(&src.name);
            let ar = asset_rows.get_mut(&base.to_lowercase()).map(|(r, used)| {
                *used = true;
                r.clone()
            });
            match self.image_doc(c, &base, ar.as_ref(), asset_header) {
                Err(e) => self
                    .st
                    .add(&base, 0, &e.col, &e.code, &e.detail, &e.value, false),
                Ok((plan, ext, doc)) => {
                    if !by_ext.contains_key(&ext) {
                        order.push(ext.clone());
                    }
                    by_ext.entry(ext.clone()).or_default().push((
                        ImagePlan {
                            src,
                            ext,
                            doc,
                            sha: String::new(),
                        },
                        plan,
                    ));
                }
            }
        }
        for ext in order {
            let list = by_ext.remove(&ext).unwrap();
            if list.len() > 1 {
                for (ip, _) in &list {
                    self.st.add(
                        &base_name(&ip.src.name),
                        0,
                        "",
                        "validation_failed",
                        &format!("more than one file resolves to image {ext}"),
                        "",
                        false,
                    );
                }
                continue;
            }
            let (ip, plan) = list.into_iter().next().unwrap();
            self.plan_mut(&plan).images.push(ip);
        }
        let mut unused: Vec<(String, fmt::Row)> = asset_rows
            .into_iter()
            .filter(|(_, (_, used))| !used)
            .map(|(f, (r, _))| (f, r))
            .collect();
        unused.sort_by_key(|(_, r)| r.num);
        for (f, r) in unused {
            self.st.add(
                "assets.csv",
                r.num,
                "file",
                "files_missing",
                &format!("image {} is not part of this import", r.get("file")),
                &f,
                false,
            );
        }
    }

    fn image_doc(
        &mut self,
        c: &Connection,
        base: &str,
        ar: Option<&fmt::Row>,
        header: &[String],
    ) -> std::result::Result<((bool, usize, String), String, Map<String, Value>), CellErr> {
        let parsed = fmt::parse_image_name(base);
        let (mut style, mut color, mut pos, mut role, mut view) = (
            String::new(),
            String::new(),
            0u32,
            String::new(),
            String::new(),
        );
        if let Ok(n) = &parsed {
            style = n.style.clone();
            color = n.color.clone();
            pos = n.position;
            role = n.role.clone().unwrap_or_default();
            view = n.view.clone().unwrap_or_default();
        }
        if let Some(r) = ar {
            if !r.get("product_id").is_empty() {
                style = r.get("product_id").into();
            } else if !r.get("style_number").is_empty() {
                style = r.get("style_number").into();
            }
            if r.values.contains_key("color_code")
                && (!r.get("color_code").is_empty() || parsed.is_err())
            {
                color = r.get("color_code").into();
            }
            let v = r.get("position");
            if !v.is_empty() {
                match v.parse::<u32>() {
                    Ok(p) if (1..=999).contains(&p) => pos = p,
                    _ => {
                        return Err(cell_err(
                            "position",
                            "validation_failed",
                            "position must be 1-999",
                            v,
                        ));
                    }
                }
            }
            let v = fmt::key(r.get("role"));
            if !v.is_empty() {
                if !fmt::is_role(&v) {
                    return Err(cell_err("role", "validation_failed", "unknown role", &v));
                }
                role = v;
            }
            let v = fmt::key(r.get("view"));
            if !v.is_empty() {
                if !fmt::is_view(&v) {
                    return Err(cell_err("view", "validation_failed", "unknown view", &v));
                }
                view = v;
            }
        }
        if style.is_empty() || pos == 0 {
            return Err(match &parsed {
                Err(e) => cell_err("", "validation_failed", e.to_string(), ""),
                Ok(_) => cell_err(
                    "",
                    "validation_failed",
                    "cannot tell which product this image belongs to",
                    "",
                ),
            });
        }
        let Some(pr) = self.catalog_product(c, &style) else {
            return Err(cell_err(
                "",
                "unknown_parent",
                format!("style {style} is not in the catalog"),
                &style,
            ));
        };
        let (pext, pstyle, spelled) = {
            let p = self.plan_mut(&pr);
            (
                p.ext.clone(),
                p.style.clone(),
                p.colors.get(&color.to_lowercase()).cloned(),
            )
        };
        let mut doc = Map::new();
        doc.insert("product_external_id".into(), json!(pext));
        doc.insert("position".into(), json!(pos));
        doc.insert("filename".into(), json!(base));
        let mut color_out = Value::Null;
        if !color.is_empty() {
            let name_color = parsed.as_ref().map(|n| n.color.clone()).unwrap_or_default();
            if color.eq_ignore_ascii_case(COLOURLESS) && name_color.eq_ignore_ascii_case(&color) {
                color.clear();
            } else if let Some(s) = spelled {
                color_out = json!(s);
                color = s;
            } else {
                return Err(cell_err(
                    "",
                    "unknown_parent",
                    format!("colour {color} of style {pstyle} is not in the catalog"),
                    &color,
                ));
            }
        }
        doc.insert("color_code".into(), color_out);
        if role.is_empty() {
            role = "packshot".into();
        }
        doc.insert("role".into(), json!(role));
        if !view.is_empty() {
            doc.insert("view".into(), json!(view));
        }
        if color.is_empty() {
            color = COLOURLESS.into();
        }
        let mut ext = format!("{pstyle}_{color}_{pos}");
        if let Some(r) = ar {
            if !r.get("asset_id").is_empty() {
                ext = r.get("asset_id").into();
            }
            self.asset_row_fields(r, header, &mut doc)?;
        }
        if !valid_external_id(&ext).1 {
            return Err(cell_err(
                "asset_id",
                "validation_failed",
                "invalid asset id",
                &ext,
            ));
        }
        Ok((pr, ext, doc))
    }

    fn asset_row_fields(
        &mut self,
        r: &fmt::Row,
        header: &[String],
        doc: &mut Map<String, Value>,
    ) -> std::result::Result<(), CellErr> {
        if let Some(alt) = fmt::localized(r, header, "alt_text", &self.st.lang) {
            doc.insert("alt_text".into(), obj(alt));
        }
        let mut rights = Map::new();
        let v = r.get("license");
        if !v.is_empty() {
            rights.insert("license".into(), json!(v.to_lowercase()));
        }
        let v = r.get("license_text");
        if !v.is_empty() {
            rights.insert("license_text".into(), json!(v));
        }
        let v = r.get("channels");
        if !v.is_empty() {
            let ch: Vec<Value> = v
                .split('|')
                .map(fmt::key)
                .filter(|c| !c.is_empty())
                .map(Value::String)
                .collect();
            rights.insert("channels".into(), Value::Array(ch));
        }
        let v = r.get("territories");
        if !v.is_empty() {
            let ts: Vec<Value> = v
                .split('|')
                .map(|c| c.trim().to_uppercase())
                .filter(|c| !c.is_empty())
                .map(Value::String)
                .collect();
            rights.insert("territories".into(), Value::Array(ts));
        }
        for k in ["embargo_until", "expires_at"] {
            let v = r.get(k);
            if !v.is_empty() {
                let d = fmt::parse_date(v).ok_or_else(|| {
                    cell_err(
                        k,
                        "validation_failed",
                        format!("{k} must be a date (YYYY-MM-DD) or RFC 3339 timestamp"),
                        v,
                    )
                })?;
                rights.insert(k.into(), json!(d));
            }
        }
        let v = r.get("credit");
        if !v.is_empty() {
            rights.insert("credit".into(), json!(v));
        }
        let v = r.get("model_release");
        if !v.is_empty() {
            let b = fmt::parse_bool(v).ok_or_else(|| {
                cell_err("model_release", "validation_failed", "use yes or no", v)
            })?;
            rights.insert("model_release".into(), json!(b));
        }
        if !rights.is_empty() {
            doc.insert("rights".into(), Value::Object(rights));
        }
        let mut prov = Map::new();
        for k in ["ai_generated", "ai_edited"] {
            let v = r.get(k);
            if !v.is_empty() {
                let b = fmt::parse_bool(v)
                    .ok_or_else(|| cell_err(k, "validation_failed", "use yes or no", v))?;
                prov.insert(k.into(), json!(b));
            }
        }
        for k in ["source", "c2pa"] {
            let v = r.get(k);
            if !v.is_empty() {
                prov.insert(k.into(), json!(v.to_lowercase()));
            }
        }
        for k in ["c2pa_manifest_url", "generator"] {
            let v = r.get(k);
            if !v.is_empty() {
                prov.insert(k.into(), json!(v));
            }
        }
        if !prov.is_empty() {
            doc.insert("provenance".into(), Value::Object(prov));
        }
        let v = r.get("status");
        if !v.is_empty() {
            let s = v.to_lowercase();
            if s != "published" && s != "unpublished" {
                return Err(cell_err(
                    "status",
                    "validation_failed",
                    "status must be published or unpublished",
                    v,
                ));
            }
            doc.insert("status".into(), json!(s));
        }
        Ok(())
    }

    /// The products a mirror import unpublishes.
    fn mirror_plan(&self, c: &Connection) -> Result<Vec<String>> {
        let mut brands = HashSet::new();
        for p in &self.plans {
            let r = p.brand_ref.trim().to_lowercase();
            let id: Option<String> = if r.is_empty() {
                c.query_row(
                    "SELECT id FROM brands ORDER BY created_at LIMIT 1",
                    [],
                    |x| x.get(0),
                )
                .optional()?
            } else {
                c.query_row(
                    "SELECT id FROM brands WHERE LOWER(name) = ? OR LOWER(external_id) = ? OR external_id = ?",
                    [&r, &r, &fmt::slug(&p.brand_ref)],
                    |x| x.get(0),
                )
                .optional()?
            };
            if let Some(id) = id {
                brands.insert(id);
            }
        }
        let in_file: HashSet<&str> = self.plans.iter().map(|p| p.ext.as_str()).collect();
        let mut to_unpublish = Vec::new();
        let mut total = 0;
        for b in brands {
            let mut st =
                c.prepare("SELECT external_id FROM products WHERE brand_id = ? AND status = 'published' ORDER BY external_id")?;
            for e in st.query_map([&b], |r| r.get::<_, String>(0))? {
                let e = e?;
                total += 1;
                if !in_file.contains(e.as_str()) {
                    to_unpublish.push(e);
                }
            }
        }
        to_unpublish.sort();
        if to_unpublish.len() * 2 > total && !self.st.opts.allow_mass_unpublish {
            return Err(Problem::new(
                "mass_unpublish_refused",
                format!(
                    "This mirror import would unpublish {} of {total} products. Check the file, or allow mass unpublishing explicitly.",
                    to_unpublish.len()
                ),
            ));
        }
        Ok(to_unpublish)
    }
}

// ---- applying a plan (inside a write transaction) -------------------------------------

fn resolve_variants(st: &mut State_, w: &Writer, plan: &mut ProductPlan) -> Result<HashSet<usize>> {
    let mut failed = HashSet::new();
    let mut keep = Vec::new();
    for mut v in std::mem::take(&mut plan.variants) {
        let mut ext = v.ext.clone();
        if !v.gtin14.is_empty() {
            if let Some(first) = st.gtin_row.get(&v.gtin14) {
                let msg = format!(
                    "GTIN {} is also used on row {first} of this file",
                    v.gtin_raw
                );
                st.add(
                    "products.csv",
                    v.row,
                    "gtin",
                    "gtin_conflict",
                    &msg,
                    &v.gtin_raw,
                    false,
                );
                failed.insert(v.row);
                continue;
            }
        }
        if ext.is_empty() && !v.gtin14.is_empty() {
            if let Some(e) = st.gtin_ext.get(&v.gtin14) {
                ext = e.clone();
            } else {
                let found: Option<(String, String, String)> = w
                    .tx
                    .query_row(
                        "SELECT v.external_id, p.external_id, p.style_number FROM variants v JOIN products p ON p.id = v.product_id WHERE v.gtin = ?",
                        [&v.gtin14],
                        |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
                    )
                    .optional()?;
                match found {
                    Some((vext, pext, _)) if pext == plan.ext => ext = vext,
                    Some((vext, pext, style)) => {
                        let msg = format!(
                            "GTIN {} belongs to variant {vext:?} of product {pext} (style {style}); remove it there first",
                            v.gtin_raw
                        );
                        st.add(
                            "products.csv",
                            v.row,
                            "gtin",
                            "gtin_conflict",
                            &msg,
                            &v.gtin_raw,
                            false,
                        );
                        failed.insert(v.row);
                        continue;
                    }
                    None => {}
                }
            }
        }
        if ext.is_empty() {
            ext = v.def.clone();
            if !valid_external_id(&ext).1 {
                st.add(
                    "products.csv",
                    v.row,
                    "variant_id",
                    "validation_failed",
                    "the default variant id (style-colour-size-size_length) is not a valid external id (at most 200 characters); give a variant_id",
                    &ext,
                    false,
                );
                failed.insert(v.row);
                continue;
            }
        }
        if let Some(first) = st.seen_variant.get(&ext) {
            let msg = format!(
                "this row is the same variant as row {first} ({ext}); the first row is used"
            );
            st.add(
                "products.csv",
                v.row,
                "variant_id",
                "validation_failed",
                &msg,
                &ext,
                false,
            );
            failed.insert(v.row);
            continue;
        }
        st.seen_variant.insert(ext.clone(), v.row);
        if !v.gtin14.is_empty() {
            st.gtin_ext.insert(v.gtin14.clone(), ext.clone());
            st.gtin_row.insert(v.gtin14.clone(), v.row);
        }
        v.ext = ext;
        keep.push(v);
    }
    plan.variants = keep;
    Ok(failed)
}

fn resolve_brand(
    st: &mut State_,
    w: &mut Writer,
    plan: &ProductPlan,
) -> std::result::Result<String, Problem> {
    let r = plan.brand_ref.trim();
    if r.is_empty() {
        let n: i64 =
            w.tx.query_row("SELECT COUNT(*) FROM brands", [], |x| x.get(0))?;
        if n == 1 {
            return Ok(w
                .tx
                .query_row("SELECT external_id FROM brands", [], |x| x.get(0))?);
        }
        return Err(Problem::new(
            "validation_failed",
            "brand is required because this node has more than one brand.",
        )
        .field("/brand", "validation_failed", "required"));
    }
    let lr = r.to_lowercase();
    let slug = fmt::slug(r);
    let found: Option<String> = w
        .tx
        .query_row(
            "SELECT external_id FROM brands WHERE LOWER(name) = ? OR LOWER(external_id) = ? OR external_id = ? ORDER BY external_id LIMIT 1",
            [&lr, &lr, &slug],
            |x| x.get(0),
        )
        .optional()?;
    if let Some(e) = found {
        return Ok(e);
    }
    if slug.is_empty() {
        return Err(Problem::new(
            "validation_failed",
            format!("Brand name {r:?} cannot be turned into an id."),
        )
        .field("/brand", "validation_failed", "invalid brand"));
    }
    let mut doc = Map::new();
    doc.insert("name".into(), json!(r));
    let (res, prob) = w.upsert(KIND_BRAND, &slug, doc, "");
    if let Some(p) = prob {
        return Err(p);
    }
    st.count(&res.result);
    Ok(slug)
}

/// Writes one product with its variants and images. Err only for internal
/// errors (the transaction is then rolled back and the import fails).
fn apply_plan(st: &mut State_, w: &mut Writer, plan: &mut ProductPlan) -> Result<()> {
    if let Some(pdoc) = plan.doc.clone() {
        let failed = resolve_variants(st, w, plan)?;
        let Some(first_row) = plan.rows.iter().copied().find(|r| !failed.contains(r)) else {
            return Ok(());
        };
        let bext = match resolve_brand(st, w, plan) {
            Ok(b) => b,
            Err(p) if p.obx_error == "internal_error" => return Err(p),
            Err(p) => {
                st.add(
                    "products.csv",
                    first_row,
                    "brand",
                    &p.obx_error,
                    &problem_detail(&p),
                    &plan.brand_ref,
                    false,
                );
                return Ok(());
            }
        };
        let mut doc = pdoc;
        doc.insert("brand_external_id".into(), json!(bext));
        if let Some(existing) = load_row(w.tx, KIND_PRODUCT, &plan.ext)? {
            doc = keep_absent_columns(&doc, &existing.data, PRODUCT_FIELDS, &st.present);
            carry_extensions(
                &mut doc,
                collect_extensions(&existing.data, PRODUCT_EXT_PATHS),
            );
        }
        let (res, prob) = w.upsert(KIND_PRODUCT, &plan.ext, doc, "");
        if let Some(p) = prob {
            if p.obx_error == "internal_error" {
                return Err(p);
            }
            st.add(
                "products.csv",
                first_row,
                &problem_column(&p),
                &p.obx_error,
                &problem_detail(&p),
                "",
                false,
            );
            return Ok(());
        }
        st.count(&res.result);
        for wd in &res.warning_details {
            st.add(
                "products.csv",
                first_row,
                &wd.column,
                &wd.code,
                &wd.detail,
                &wd.value,
                true,
            );
        }
        for v in &plan.variants {
            let mut vdoc = v.doc.clone();
            if let Some(existing) = load_row(w.tx, KIND_VARIANT, &v.ext)? {
                vdoc = keep_absent_columns(&vdoc, &existing.data, VARIANT_FIELDS, &st.present);
                carry_extensions(
                    &mut vdoc,
                    collect_extensions(&existing.data, VARIANT_EXT_PATHS),
                );
            }
            let gtin = vdoc
                .get("gtin")
                .and_then(|g| g.as_str())
                .unwrap_or("")
                .to_string();
            let (res, prob) = w.upsert(KIND_VARIANT, &v.ext, vdoc, "");
            if let Some(p) = prob {
                if p.obx_error == "internal_error" {
                    return Err(p);
                }
                let val = if p.obx_error == "invalid_gtin" || p.obx_error == "gtin_conflict" {
                    gtin
                } else {
                    String::new()
                };
                st.add(
                    "products.csv",
                    v.row,
                    &problem_column(&p),
                    &p.obx_error,
                    &problem_detail(&p),
                    &val,
                    false,
                );
                continue;
            }
            st.count(&res.result);
        }
    }
    if plan.images.is_empty() {
        return Ok(());
    }
    w.position_exclude.clear();
    for ip in &plan.images {
        if let Some(id) =
            w.tx.query_row(
                "SELECT id FROM assets WHERE external_id = ?",
                [&ip.ext],
                |r| r.get::<_, String>(0),
            )
            .optional()?
        {
            w.position_exclude.insert(id);
        }
    }
    for ip in &plan.images {
        let mut doc = ip.doc.clone();
        if let Some(existing) = load_row(w.tx, KIND_ASSET, &ip.ext)? {
            doc = keep_image_facts(&doc, &existing.data);
            carry_extensions(
                &mut doc,
                collect_extensions(&existing.data, ASSET_EXT_PATHS),
            );
        }
        let (res, prob) = w.upsert(KIND_ASSET, &ip.ext, doc, "");
        if let Some(p) = prob {
            if p.obx_error == "internal_error" {
                w.position_exclude.clear();
                return Err(p);
            }
            st.add(
                &base_name(&ip.src.name),
                0,
                &problem_column(&p),
                &p.obx_error,
                &problem_detail(&p),
                "",
                false,
            );
            continue;
        }
        st.count(&res.result);
    }
    w.position_exclude.clear();
    Ok(())
}

// ---- inputs ----------------------------------------------------------------------------

const MAX_ZIP_ENTRIES: usize = 100_000;
const MAX_ZIP_UNCOMPRESSED: u64 = 10 * MAX_UPLOAD_BYTES * 3;

use fmt::{is_other_spreadsheet_name as is_other_spreadsheet, is_workbook_name};

/// products.csv or assets.csv of an import: CSV bytes, or an Excel workbook
/// (import-format.md §5).
#[derive(Debug, Clone)]
enum TableIn {
    Csv(Vec<u8>),
    Workbook(Vec<u8>),
}

struct Inputs {
    products: Option<TableIn>,
    assets: Option<TableIn>,
    images: Vec<ImageSource>,
    temp: Vec<PathBuf>,
}

fn temp_path(tag: &str) -> PathBuf {
    std::env::temp_dir().join(format!("obx-{tag}-{}", crate::ids::new("tmp")))
}

/// Reads a zip file on disk: products.csv/assets.csv (packages only) and
/// images.
fn read_package(
    path: &PathBuf,
    is_package: bool,
) -> Result<(Option<TableIn>, Option<TableIn>, Vec<ImageSource>)> {
    use std::io::Read;
    let f = std::fs::File::open(path).map_err(Problem::internal)?;
    let mut z = zip::ZipArchive::new(f)
        .map_err(|_| Problem::new("import_invalid", "The file is not a readable zip file."))?;
    if z.len() > MAX_ZIP_ENTRIES {
        return Err(Problem::new(
            "import_invalid",
            format!("The zip has more than {MAX_ZIP_ENTRIES} entries."),
        ));
    }
    let mut total = 0u64;
    let mut entries = Vec::new();
    for i in 0..z.len() {
        let e = z
            .by_index_raw(i)
            .map_err(|_| Problem::new("import_invalid", "The zip cannot be read."))?;
        let name = e.name().to_string();
        let symlink = e.is_symlink();
        fmt::safe_entry(&name, symlink)
            .map_err(|err| Problem::new("import_invalid", format!("Unsafe zip entry: {err}")))?;
        total += e.size();
        if total > MAX_ZIP_UNCOMPRESSED {
            return Err(Problem::new(
                "import_invalid",
                format!("The zip unpacks to more than {MAX_ZIP_UNCOMPRESSED} bytes."),
            ));
        }
        entries.push((i, name, e.is_dir()));
    }
    let mut csvs: Vec<(usize, String)> = Vec::new();
    let mut workbooks: Vec<(usize, String)> = Vec::new();
    let mut images = Vec::new();
    for (i, name, dir) in entries {
        if dir || fmt::ignored(&name) {
            continue;
        }
        let base = base_name(&name);
        let lower = base.to_lowercase();
        if lower.ends_with(".csv") && is_package {
            csvs.push((i, base));
        } else if (lower == "products.xlsx" || lower == "assets.xlsx") && is_package {
            workbooks.push((i, base));
        } else if fmt::is_image(&base) {
            images.push(ImageSource {
                name: base,
                src: Source::Zip {
                    path: path.clone(),
                    index: i,
                },
            });
        }
    }
    let mut read = |i: usize, name: &str, limit: u64| -> Result<Vec<u8>> {
        let mut e = z
            .by_index(i)
            .map_err(|_| Problem::new("import_invalid", format!("{name} cannot be read.")))?;
        let mut b = Vec::new();
        e.by_ref()
            .take(limit)
            .read_to_end(&mut b)
            .map_err(|_| Problem::new("import_invalid", format!("{name} cannot be read.")))?;
        Ok(b)
    };
    let (mut products, mut assets) = (None, None);
    let mut other = Vec::new();
    for (i, base) in &csvs {
        match base.to_lowercase().as_str() {
            "products.csv" => products = Some(TableIn::Csv(read(*i, base, 256 << 20)?)),
            "assets.csv" => assets = Some(TableIn::Csv(read(*i, base, 256 << 20)?)),
            _ => other.push((*i, base.clone())),
        }
    }
    for (i, base) in &workbooks {
        let name = base.to_lowercase();
        let dst = if name == "products.xlsx" {
            &mut products
        } else {
            &mut assets
        };
        match dst {
            Some(TableIn::Workbook(_)) => {
                return Err(Problem::new(
                    "import_invalid",
                    format!("The package has more than one {name}."),
                ));
            }
            Some(TableIn::Csv(_)) => {
                return Err(Problem::new(
                    "import_invalid",
                    format!(
                        "The package has both {} and {name}; send one of them.",
                        name.trim_end_matches(".xlsx").to_string() + ".csv"
                    ),
                ));
            }
            None => {}
        }
        // One byte over the limit, so the import reports payload_too_large.
        *dst = Some(TableIn::Workbook(read(
            *i,
            base,
            crate::app::MAX_IMPORT_BYTES + 1,
        )?));
    }
    // The "only *.csv" fallback does not extend to workbooks (§5.1).
    if products.is_none() && other.len() == 1 {
        products = Some(TableIn::Csv(read(other[0].0, &other[0].1, 256 << 20)?));
    }
    Ok((products, assets, images))
}

async fn load_inputs(app: &App, p: &ImportPayload) -> Result<Inputs> {
    let mut inp = Inputs {
        products: None,
        assets: None,
        images: Vec::new(),
        temp: Vec::new(),
    };
    for f in &p.files {
        let get = || async {
            app.store
                .get(&f.key)
                .await
                .map_err(Problem::internal)?
                .ok_or_else(|| {
                    Problem::new("import_invalid", format!("{} cannot be read.", f.name))
                })
        };
        match f.field.as_str() {
            "csv" | "assets_csv" => {
                let b = get().await?.to_vec();
                let b = if is_workbook_name(&f.name) {
                    TableIn::Workbook(b)
                } else {
                    TableIn::Csv(b)
                };
                if f.field == "csv" {
                    inp.products = Some(b);
                } else {
                    inp.assets = Some(b);
                }
            }
            "package" | "images" => {
                if f.field == "images" && !f.name.to_lowercase().ends_with(".zip") {
                    inp.images.push(ImageSource {
                        name: f.name.clone(),
                        src: Source::Blob { key: f.key.clone() },
                    });
                    continue;
                }
                let data = get().await?;
                let path = temp_path("import.zip");
                tokio::fs::write(&path, &data)
                    .await
                    .map_err(Problem::internal)?;
                inp.temp.push(path.clone());
                let is_pkg = f.field == "package";
                let name = f.name.clone();
                let (pc, ac, imgs) =
                    tokio::task::spawn_blocking(move || read_package(&path, is_pkg))
                        .await
                        .map_err(Problem::internal)?
                        .map_err(|e| {
                            if e.detail_str() == "The file is not a readable zip file." {
                                Problem::new(
                                    "import_invalid",
                                    format!("{name} is not a readable zip file."),
                                )
                            } else {
                                e
                            }
                        })?;
                if pc.is_some() {
                    inp.products = pc;
                }
                if ac.is_some() {
                    inp.assets = ac;
                }
                inp.images.extend(imgs);
            }
            _ => {}
        }
    }
    for m in &p.manifest {
        inp.images.push(ImageSource {
            name: m.file.clone(),
            src: Source::Manifest(m.clone()),
        });
    }
    Ok(inp)
}

async fn open_image(app: &App, src: &Source) -> std::result::Result<Bytes, String> {
    match src {
        Source::Blob { key } => app
            .store
            .get(key)
            .await?
            .ok_or_else(|| "missing".to_string()),
        Source::Manifest(_) => Err("manifest".into()),
        Source::Zip { path, index } => {
            let (path, index) = (path.clone(), *index);
            tokio::task::spawn_blocking(move || {
                use std::io::Read;
                let f = std::fs::File::open(&path).map_err(|e| e.to_string())?;
                let mut z = zip::ZipArchive::new(f).map_err(|e| e.to_string())?;
                let mut e = z.by_index(index).map_err(|e| e.to_string())?;
                let mut b = Vec::new();
                e.by_ref()
                    .take(MAX_UPLOAD_BYTES + 1)
                    .read_to_end(&mut b)
                    .map_err(|e| e.to_string())?;
                Ok(Bytes::from(b))
            })
            .await
            .map_err(|e| e.to_string())?
        }
    }
}

/// Stores the images of a plan (or hashes them in a dry run) and renders
/// them, before the asset writes.
async fn prepare_images(app: &App, st: &mut State_, plan: &mut ProductPlan) {
    let mut kept = Vec::new();
    for mut ip in std::mem::take(&mut plan.images) {
        let base = base_name(&ip.src.name);
        let mut files = Map::new();
        if let Source::Manifest(m) = &ip.src.src {
            if app.get_blob(&m.sha256).await.ok().flatten().is_none() {
                st.add(
                    &base,
                    0,
                    "",
                    "blob_missing",
                    &format!(
                        "the image in images_manifest has not been uploaded ({})",
                        m.sha256
                    ),
                    "",
                    false,
                );
                continue;
            }
            ip.sha = m.sha256.clone();
            let mut orig = Map::new();
            orig.insert("sha256".into(), json!(m.sha256));
            if let Some(w) = m.width {
                orig.insert("width".into(), json!(w));
            }
            if let Some(h) = m.height {
                orig.insert("height".into(), json!(h));
            }
            files.insert("original".into(), Value::Object(orig));
            for (n, rr) in m.renditions.iter().flatten() {
                if !DERIVED_RENDITIONS.contains(&n.as_str()) {
                    continue;
                }
                if app.get_blob(&rr.sha256).await.ok().flatten().is_none() {
                    st.add(
                        &base,
                        0,
                        "",
                        "blob_missing",
                        &format!("rendition {n} in images_manifest has not been uploaded"),
                        "",
                        false,
                    );
                    continue;
                }
                files.insert(
                    n.clone(),
                    json!({"sha256": rr.sha256, "width": rr.width, "height": rr.height}),
                );
            }
        } else {
            let data = match open_image(app, &ip.src.src).await {
                Ok(d) => d,
                Err(e) => {
                    st.add(
                        &base,
                        0,
                        "",
                        "import_invalid",
                        &format!("cannot read the image: {e}"),
                        "",
                        false,
                    );
                    continue;
                }
            };
            if data.len() as u64 > MAX_UPLOAD_BYTES {
                st.add(
                    &base,
                    0,
                    "",
                    "payload_too_large",
                    "The file is larger than 104857600 bytes.",
                    "",
                    false,
                );
                continue;
            }
            if st.opts.dry_run {
                ip.sha = crate::secure::sha256_hex(&data);
                if app.get_blob(&ip.sha).await.ok().flatten().is_some() {
                    files.insert("original".into(), json!({"sha256": ip.sha}));
                }
            } else {
                match app.put_blob(data, None).await {
                    Ok(b) => {
                        ip.sha = b.sha256.clone();
                        files.insert("original".into(), json!({"sha256": b.sha256}));
                    }
                    Err(p) => {
                        st.add(&base, 0, "", &p.obx_error, &problem_detail(&p), "", false);
                        continue;
                    }
                }
            }
        }
        if !st.opts.dry_run && !ip.sha.is_empty() {
            app.prerender(&ip.sha).await;
        }
        if !files.is_empty() {
            ip.doc.insert("files".into(), Value::Object(files));
        }
        kept.push(ip);
    }
    plan.images = kept;
}

/// Runs an import: parse, plan, write product by product (or everything in
/// one rolled-back transaction for a dry run), then unpublish for a mirror.
async fn run(
    app: &App,
    mut im: Importer,
    inp: Inputs,
    progress: &(dyn Fn(i64, i64) + Send + Sync),
) -> (State_, Option<Problem>) {
    let mut products_table = None;
    if let Some(b) = &inp.products {
        match im.st.load_table("products", b) {
            Ok(t) => products_table = Some(t),
            Err(p) => return (im.st, Some(p)),
        }
    }
    let mut assets_table = None;
    if let Some(b) = &inp.assets {
        match im.st.load_table("assets", b) {
            Ok(t) => assets_table = Some(t),
            Err(p) => return (im.st, Some(p)),
        }
    }
    let images = inp.images;
    // Planning reads the catalog (images of products already there).
    let planned = app
        .db
        .read(move |c| {
            if let Some(mut t) = products_table {
                if let Err(p) = im.parse_products(&mut t) {
                    return Ok((im, Err(p)));
                }
            }
            let mut rows = HashMap::new();
            let mut header = Vec::new();
            if let Some(t) = &assets_table {
                match im.parse_assets(t) {
                    Ok(r) => rows = r,
                    Err(p) => return Ok((im, Err(p))),
                }
                header = t.header.clone();
            }
            im.st.counts.files = images.len();
            im.plan_images(c, images, rows, &header);
            let unpub = if im.st.opts.mode == "mirror" {
                im.mirror_plan(c)
            } else {
                Ok(vec![])
            };
            Ok((im, unpub))
        })
        .await;
    let (im, to_unpublish) = match planned {
        Ok((im, Ok(u))) => (im, u),
        Ok((im, Err(p))) => return (im.st, Some(p)),
        Err(p) => return (State_::default(), Some(p)),
    };
    let Importer {
        mut st,
        plans,
        mut extra,
        extra_ord,
        ..
    } = im;
    let mut all: Vec<ProductPlan> = plans;
    for k in &extra_ord {
        if let Some(p) = extra.remove(k).filter(|p| !p.images.is_empty()) {
            all.push(p);
        }
    }
    let allowed = st.allowed.clone();
    if st.opts.dry_run {
        for plan in all.iter_mut() {
            prepare_images(app, &mut st, plan).await;
        }
        let n_unpub = to_unpublish.len();
        let slot = Arc::new(Mutex::new(None));
        let s2 = slot.clone();
        let out: Result<()> = app
            .catalog_write(allowed, move |w| {
                let mut st = st;
                for plan in all.iter_mut() {
                    if let Err(p) = apply_plan(&mut st, w, plan) {
                        *s2.lock().unwrap() = Some((st, Some(p)));
                        return Err(Problem::new("conflict", "dry run"));
                    }
                }
                st.counts.unpublished = n_unpub;
                *s2.lock().unwrap() = Some((st, None));
                Err(Problem::new("conflict", "dry run"))
            })
            .await;
        let _ = out;
        let got = slot.lock().unwrap().take();
        return got
            .unwrap_or_else(|| (State_::default(), Some(Problem::internal("dry run failed"))));
    }
    let total = all.len() as i64;
    for (i, mut plan) in all.into_iter().enumerate() {
        prepare_images(app, &mut st, &mut plan).await;
        let slot = Arc::new(Mutex::new(None));
        let s2 = slot.clone();
        let mut st_in = st;
        let out = app
            .catalog_write(allowed.clone(), move |w| {
                let r = apply_plan(&mut st_in, w, &mut plan);
                let failed = r.is_err();
                *s2.lock().unwrap() = Some(st_in);
                if failed { r } else { Ok(()) }
            })
            .await;
        st = slot.lock().unwrap().take().unwrap_or_default();
        if let Err(p) = out {
            return (st, Some(p));
        }
        progress(i as i64 + 1, total);
    }
    for ext in to_unpublish {
        let e2 = ext.clone();
        let (res, prob) = crate::http::ingest::write_op(app, allowed.clone(), move |w| {
            w.set_status("unpublish", KIND_PRODUCT, &e2)
        })
        .await;
        if let Some(p) = prob {
            st.add(
                "products.csv",
                0,
                "",
                &p.obx_error,
                &format!("could not unpublish {ext}: {}", problem_detail(&p)),
                &ext,
                false,
            );
            continue;
        }
        if res.result == "updated" {
            st.counts.unpublished += 1;
        }
    }
    (st, None)
}

fn new_importer(p: &ImportPayload, default_lang: String) -> Importer {
    let mut opts = p.options.clone();
    if opts.mode.is_empty() {
        opts.mode = "upsert".into();
    }
    let lang = if opts.default_language.is_empty() {
        default_lang
    } else {
        fmt::normalize_lang(&opts.default_language)
    };
    Importer {
        st: State_ {
            opts,
            allowed: p.allowed.clone(),
            lang,
            ..Default::default()
        },
        ..Default::default()
    }
}

fn files_json(p: &ImportPayload) -> Vec<Value> {
    let mut out: Vec<Value> = p
        .files
        .iter()
        .map(|f| json!({"name": f.name, "bytes": f.bytes, "sha256": if f.sha256.is_empty() { Value::Null } else { json!(f.sha256) }}))
        .collect();
    for m in &p.manifest {
        out.push(json!({"name": m.file, "bytes": 0, "sha256": m.sha256}));
    }
    out
}

/// The job handler of `import` jobs.
pub async fn run_import_job(
    app: &App,
    j: &Job,
) -> std::result::Result<Option<Value>, (Option<Value>, String)> {
    let mut p: ImportPayload =
        serde_json::from_str(&j.payload).map_err(|e| (None, e.to_string()))?;
    if !p.source_id.is_empty() && p.files.is_empty() {
        let fetched = crate::sources::fetch_source(app, &j.id, &mut p).await;
        let (id, payload) = (j.id.clone(), serde_json::to_string(&p).unwrap_or_default());
        let _ = app
            .db
            .write(move |tx| {
                tx.execute(
                    "UPDATE jobs SET payload = ? WHERE id = ?",
                    rusqlite::params![payload, id],
                )?;
                Ok(())
            })
            .await;
        let base = ImportResult {
            mode: if p.options.mode.is_empty() {
                "upsert".into()
            } else {
                p.options.mode.clone()
            },
            dry_run: p.options.dry_run,
            ..Default::default()
        };
        match fetched {
            Err(prob) => {
                let detail = problem_detail(&prob);
                let res = ImportResult {
                    error: Some(serde_json::to_value(&prob).unwrap_or(Value::Null)),
                    ..base
                };
                return Err((
                    Some(serde_json::to_value(&res).unwrap_or(Value::Null)),
                    detail,
                ));
            }
            Ok(true) => {
                let res = ImportResult {
                    unchanged: true,
                    ..base
                };
                return Ok(Some(serde_json::to_value(&res).unwrap_or(Value::Null)));
            }
            Ok(false) => {}
        }
    }
    let lang = app
        .settings()
        .await
        .map(|s| s.content_languages()[0].clone())
        .unwrap_or_else(|_| "en".into());
    let im = new_importer(&p, lang);
    let mut res = ImportResult {
        mode: im.st.opts.mode.clone(),
        dry_run: im.st.opts.dry_run,
        files: files_json(&p),
        ..Default::default()
    };
    let (st, prob) = match load_inputs(app, &p).await {
        Err(e) => (im.st.clone(), Some(e)),
        Ok(inp) => {
            let temp = inp.temp.clone();
            let (a, id) = (app.clone(), j.id.clone());
            let progress = move |done: i64, total: i64| {
                let (a, id) = (a.clone(), id.clone());
                tokio::spawn(async move { jobs::progress(&a, &id, done, Some(total)).await });
            };
            let out = run(app, im, inp, &progress).await;
            for t in temp {
                let _ = tokio::fs::remove_file(t).await;
            }
            out
        }
    };
    for f in &p.files {
        let _ = app.store.delete(&f.key).await;
    }
    res.counts = st.counts.clone();
    let items = st
        .errors
        .iter()
        .map(|e| {
            (
                serde_json::to_value(e).unwrap_or(Value::Null),
                e.severity == "error",
            )
        })
        .collect();
    if let Err(e) = jobs::add_items(app, &j.id, 0, items).await {
        return Err((None, e.to_string()));
    }
    match prob {
        Some(p) => {
            let detail = problem_detail(&p);
            res.error = Some(serde_json::to_value(&p).unwrap_or(Value::Null));
            Err((
                Some(serde_json::to_value(&res).unwrap_or(Value::Null)),
                detail,
            ))
        }
        None => {
            if !p.source_id.is_empty() && !p.options.dry_run {
                crate::sources::record_fingerprint(app, &p.source_id, &p.fingerprint).await;
            }
            Ok(Some(serde_json::to_value(&res).unwrap_or(Value::Null)))
        }
    }
}

/// The ImportRun of an import job.
pub async fn import_run_json(app: &App, j: &Job) -> Result<Value> {
    let payload: ImportPayload = serde_json::from_str(&j.payload).unwrap_or_default();
    let mut res = ImportResult {
        mode: if payload.options.mode.is_empty() {
            "upsert".into()
        } else {
            payload.options.mode.clone()
        },
        dry_run: payload.options.dry_run,
        files: files_json(&payload),
        ..Default::default()
    };
    if let Some(r) = j
        .result
        .as_deref()
        .and_then(|r| serde_json::from_str::<ImportResult>(r).ok())
    {
        res = ImportResult {
            files: if r.files.is_empty() {
                res.files
            } else {
                r.files
            },
            ..r
        };
    }
    let mut out = json!({
        "id": j.id, "source_id": j.source_id, "trigger": j.trigger.clone().unwrap_or_else(|| "api".into()),
        "status": j.status, "mode": res.mode, "dry_run": res.dry_run, "created_at": j.created_at,
        "started_at": j.started_at, "finished_at": j.finished_at, "files": res.files,
        "counts": res.counts, "error": null, "errors_preview": [],
    });
    if res.unchanged {
        out["x-node-rs-unchanged"] = json!(true);
    }
    if let Some(e) = res.error {
        out["error"] = e;
    } else if j.status == "failed" {
        if let Some(e) = &j.error {
            out["error"] = serde_json::to_value(Problem::new("internal_error", e.clone()))
                .unwrap_or(Value::Null);
        }
    }
    let id = j.id.clone();
    let prev = app
        .db
        .read(move |c| {
            let mut st = c.prepare("SELECT item FROM job_items WHERE job_id = ? AND is_error = 1 ORDER BY idx LIMIT 50")?;
            let r = st
                .query_map([&id], |r| r.get::<_, String>(0))?
                .filter_map(|s| s.ok())
                .filter_map(|s| serde_json::from_str::<Value>(&s).ok())
                .collect::<Vec<_>>();
            Ok(r)
        })
        .await?;
    out["errors_preview"] = Value::Array(prev);
    Ok(out)
}

// ---- HTTP -------------------------------------------------------------------------------

pub fn sanitize_filename(s: &str) -> String {
    let base = base_name(s);
    let out: String = base
        .chars()
        .map(|c| {
            if (c as u32) < 0x20 || c == '\x7f' || "\":*?<>|".contains(c) {
                '_'
            } else {
                c
            }
        })
        .collect();
    let out = out.trim().trim_start_matches('.').to_string();
    if out.is_empty() { "file".into() } else { out }
}

struct ImportRequest {
    job_id: String,
    files: Vec<ImportFile>,
    manifest: Vec<ManifestEntry>,
    options: ImportOptions,
}

async fn cleanup(app: &App, req: &ImportRequest) {
    for f in &req.files {
        let _ = app.store.delete(&f.key).await;
    }
}

/// Parses the multipart body and stages every file in the blob store.
async fn parse_upload(app: &App, headers: &HeaderMap, body: Bytes) -> Result<ImportRequest> {
    let ct = headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let mt = ct
        .split(';')
        .next()
        .unwrap_or("")
        .trim()
        .to_ascii_lowercase();
    if mt != "multipart/form-data" {
        return Err(Problem::new(
            "unsupported_media_type",
            "Send multipart/form-data with package, csv, assets_csv, images, images_manifest or options.",
        ));
    }
    if body.len() as u64 > MAX_IMPORT_BYTES {
        return Err(Problem::new(
            "payload_too_large",
            format!("Imports are limited to {MAX_IMPORT_BYTES} bytes."),
        ));
    }
    let boundary = multer::parse_boundary(ct)
        .map_err(|_| Problem::new("invalid_request", "The multipart body cannot be read."))?;
    let stream = futures::stream::once(async move { Ok::<Bytes, std::io::Error>(body) });
    let mut mp = multer::Multipart::new(stream, boundary);
    let mut req = ImportRequest {
        job_id: crate::ids::new("job"),
        files: vec![],
        manifest: vec![],
        options: ImportOptions::default(),
    };
    let bad = |m: &str| Problem::new("invalid_request", m.to_string());
    loop {
        let field = match mp.next_field().await {
            Ok(Some(f)) => f,
            Ok(None) => break,
            Err(_) => {
                cleanup(app, &req).await;
                return Err(bad("The multipart body cannot be read."));
            }
        };
        let mut name = field.name().unwrap_or("").to_string();
        let file_name = field.file_name().map(String::from);
        let part_ct = field
            .content_type()
            .map(|m| m.essence_str().to_string())
            .unwrap_or_default();
        let data = match field.bytes().await {
            Ok(d) => d,
            Err(_) => {
                cleanup(app, &req).await;
                return Err(bad("The multipart body cannot be read."));
            }
        };
        match name.as_str() {
            "options" | "images_manifest" => {
                let ok = if name == "options" {
                    serde_json::from_slice::<ImportOptions>(&data)
                        .map(|o| req.options = o)
                        .is_ok()
                } else {
                    serde_json::from_slice::<Vec<ManifestEntry>>(&data)
                        .map(|m| req.manifest = m)
                        .is_ok()
                };
                if !ok {
                    cleanup(app, &req).await;
                    return Err(bad(&format!("{name} must be JSON.")));
                }
            }
            "package" | "csv" | "assets_csv" | "images" | "images[]" => {
                if name == "images[]" {
                    name = "images".into();
                }
                let is_table = name == "csv" || name == "assets_csv";
                let mut fname = file_name.unwrap_or_default();
                if is_table && is_other_spreadsheet(&fname) {
                    cleanup(app, &req).await;
                    return Err(Problem::new(
                        "unsupported_media_type",
                        format!(
                            "{} is not a CSV file or an Excel workbook (.xlsx). Save it as CSV or as \"Excel Workbook (.xlsx)\".",
                            sanitize_filename(&fname)
                        ),
                    ));
                }
                if fname.is_empty() {
                    fname = match name.as_str() {
                        "package" => "package.zip",
                        "csv" => "products.csv",
                        "assets_csv" => "assets.csv",
                        _ => "images.zip",
                    }
                    .into();
                    if is_table
                        && part_ct
                            == "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
                    {
                        fname = fname.trim_end_matches(".csv").to_string() + ".xlsx";
                    }
                }
                let fname = sanitize_filename(&fname);
                let sha = crate::secure::sha256_hex(&data);
                let key = format!(
                    "imports/{}/{name}/{}-{fname}",
                    req.job_id,
                    chrono::Utc::now().timestamp_subsec_nanos()
                );
                let n = data.len() as i64;
                if let Err(e) = app.store.put(&key, data).await {
                    cleanup(app, &req).await;
                    return Err(Problem::internal(e));
                }
                req.files.push(ImportFile {
                    field: name,
                    name: fname,
                    key,
                    bytes: n,
                    sha256: sha,
                });
            }
            _ => {}
        }
    }
    if req.files.is_empty() && req.manifest.is_empty() {
        return Err(bad(
            "Nothing to import: send package, csv, images or images_manifest.",
        ));
    }
    if !matches!(req.options.mode.as_str(), "" | "upsert" | "mirror") {
        cleanup(app, &req).await;
        return Err(Problem::new(
            "validation_failed",
            "options.mode must be upsert or mirror.",
        ));
    }
    Ok(req)
}

fn request_hash(req: &ImportRequest) -> String {
    let mut s = String::new();
    for f in &req.files {
        s.push_str(&format!("{}\0{}\0{}\n", f.field, f.name, f.sha256));
    }
    s.push_str(&serde_json::to_string(&req.manifest).unwrap_or_default());
    s.push_str(&serde_json::to_string(&req.options).unwrap_or_default());
    crate::secure::sha256_hex(s.as_bytes())
}

async fn enqueue(
    app: &App,
    req: ImportRequest,
    trigger: &str,
    owner_type: &str,
    owner_id: &str,
    allowed: Option<Vec<String>>,
    can_delete: bool,
) -> Result<Job> {
    let payload = ImportPayload {
        files: req.files,
        manifest: req.manifest,
        options: req.options,
        allowed,
        can_delete,
        ..Default::default()
    };
    jobs::create(
        app,
        JobSpec {
            id: Some(req.job_id),
            kind: "import".into(),
            owner_type: owner_type.into(),
            owner_id: owner_id.into(),
            trigger: trigger.into(),
            payload: serde_json::to_value(&payload).unwrap_or(Value::Null),
            ..Default::default()
        },
    )
    .await
}

/// POST /obx/v1/ingest/imports
pub async fn h_ingest_import(State(app): State<App>, headers: HeaderMap, body: Bytes) -> Res {
    let t = crate::http::ingest::ingest_auth(&app, &headers, "ingest:write").await?;
    let key = headers
        .get("idempotency-key")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    let req = parse_upload(&app, &headers, body).await?;
    let req_hash = request_hash(&req);
    let scope = format!("ingest:{}:import", t.id);
    if !key.is_empty() {
        let (s, k, h) = (scope.clone(), key.clone(), req_hash.clone());
        match app
            .db
            .read(move |c| crate::http::ingest::replay(c, &s, &k, &h))
            .await
        {
            Ok(Some((st, b))) => {
                cleanup(&app, &req).await;
                return Ok(crate::http::ingest::replayed(st, b));
            }
            Ok(None) => {}
            Err(p) => {
                cleanup(&app, &req).await;
                return Err(p);
            }
        }
    }
    if req.options.mode == "mirror" && !t.has("ingest:delete") {
        cleanup(&app, &req).await;
        return Err(Problem::new(
            "insufficient_scope",
            "A mirror import unpublishes products and needs the ingest:delete scope.",
        ));
    }
    let job = enqueue(
        &app,
        req,
        "api",
        "ingest_token",
        &t.id,
        t.brand_external_ids.clone(),
        t.has("ingest:delete"),
    )
    .await?;
    let out = jobs::ingest_job_json(&app, &job).await?;
    crate::http::ingest::remember(&app, &scope, &key, &req_hash, 202, &out).await;
    let mut r = json_resp(202, &out);
    if let Ok(v) = HeaderValue::from_str(&format!(
        "{}/obx/v1/ingest/jobs/{}",
        app.cfg.public_url, job.id
    )) {
        r.headers_mut().insert(header::LOCATION, v);
    }
    Ok(r)
}

/// POST /admin/api/imports (an upload in the admin)
pub async fn h_admin_import_create(
    State(app): State<App>,
    method: Method,
    headers: HeaderMap,
    body: Bytes,
) -> Res {
    crate::http::admin::admin_guard(&app, &headers, &method, "admin").await?;
    let req = parse_upload(&app, &headers, body).await?;
    let job = enqueue(&app, req, "upload", "user", "", None, true).await?;
    Ok(json_resp(202, &import_run_json(&app, &job).await?))
}

#[derive(Serialize, Deserialize)]
struct ListCursor {
    c: String,
    i: String,
}

/// GET /admin/api/imports
pub async fn h_admin_imports(
    State(app): State<App>,
    method: Method,
    Query(q): Query<HashMap<String, String>>,
    headers: HeaderMap,
) -> Res {
    crate::http::admin::admin_guard(&app, &headers, &method, "admin").await?;
    let limit = limit_param(&q, 50, 200)?;
    let mut where_ = String::from("WHERE kind = 'import'");
    let mut args: Vec<String> = Vec::new();
    if let Some(s) = q.get("source_id").filter(|s| !s.is_empty()) {
        where_.push_str(" AND source_id = ?");
        args.push(s.clone());
    }
    if let Some(c) = q.get("cursor").filter(|s| !s.is_empty()) {
        let cur: ListCursor = app
            .decode_cursor("imports", c)
            .ok_or_else(|| Problem::new("cursor_invalid", "The cursor is not valid."))?;
        where_.push_str(" AND (created_at < ? OR (created_at = ? AND id < ?))");
        args.extend([cur.c.clone(), cur.c, cur.i]);
    }
    let mut ids: Vec<(String, String)> = app
        .db
        .read(move |c| {
            let mut st = c.prepare(&format!("SELECT id, created_at FROM jobs {where_} ORDER BY created_at DESC, id DESC LIMIT {}", limit + 1))?;
            let r = st
                .query_map(rusqlite::params_from_iter(args.iter()), |r| Ok((r.get(0)?, r.get(1)?)))?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            Ok(r)
        })
        .await?;
    let mut next = None;
    if ids.len() > limit {
        ids.truncate(limit);
        let (i, c) = ids[limit - 1].clone();
        next = Some(app.encode_cursor("imports", &ListCursor { c, i }));
    }
    let mut items = Vec::new();
    for (id, _) in ids {
        if let Some(j) = jobs::load_job(&app, &id).await? {
            items.push(import_run_json(&app, &j).await?);
        }
    }
    Ok(ok(&json!({"items": items, "next_cursor": next})))
}

async fn admin_job(app: &App, id: &str) -> Result<Job> {
    jobs::load_job(app, id)
        .await?
        .filter(|j| j.kind == "import")
        .ok_or_else(|| Problem::new("not_found", "Import not found."))
}

/// GET /admin/api/imports/{id}
pub async fn h_admin_import(
    State(app): State<App>,
    method: Method,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> Res {
    crate::http::admin::admin_guard(&app, &headers, &method, "admin").await?;
    let j = admin_job(&app, &id).await?;
    Ok(ok(&import_run_json(&app, &j).await?))
}

/// GET /admin/api/imports/{id}/errors
pub async fn h_admin_import_errors(
    State(app): State<App>,
    method: Method,
    Path(id): Path<String>,
    Query(q): Query<HashMap<String, String>>,
    headers: HeaderMap,
) -> Res {
    crate::http::admin::admin_guard(&app, &headers, &method, "admin").await?;
    let j = admin_job(&app, &id).await?;
    jobs::job_items(&app, &j.id, &q, 50, 200).await
}

/// `node-rs import`: runs an import of local files synchronously and returns
/// the ImportRun.
pub async fn run_import_cli(
    app: &App,
    csv: Option<PathBuf>,
    assets: Option<PathBuf>,
    images: Option<PathBuf>,
    package: Option<PathBuf>,
    mirror: bool,
    dry_run: bool,
) -> Result<Value> {
    let job_id = crate::ids::new("job");
    let mut files = Vec::new();
    let stage = |field: &str, path: PathBuf| (field.to_string(), path);
    let mut todo = Vec::new();
    if let Some(p) = package {
        todo.push(stage("package", p));
    }
    if let Some(p) = csv {
        todo.push(stage("csv", p));
    }
    if let Some(p) = assets {
        todo.push(stage("assets_csv", p));
    }
    let mut image_paths = Vec::new();
    if let Some(p) = images {
        if p.is_dir() {
            let mut rd: Vec<_> = std::fs::read_dir(&p)
                .map_err(Problem::internal)?
                .filter_map(|e| e.ok())
                .map(|e| e.path())
                .collect();
            rd.sort();
            image_paths.extend(rd.into_iter().filter(|x| x.is_file()));
        } else {
            image_paths.push(p);
        }
    }
    for p in image_paths {
        todo.push(stage("images", p));
    }
    for (field, path) in todo {
        let data = tokio::fs::read(&path)
            .await
            .map_err(|e| Problem::new("invalid_request", format!("{}: {e}", path.display())))?;
        let name = sanitize_filename(
            &path
                .file_name()
                .map(|s| s.to_string_lossy().to_string())
                .unwrap_or_default(),
        );
        let key = format!("imports/{job_id}/{field}/{}-{name}", files.len());
        let sha = crate::secure::sha256_hex(&data);
        let n = data.len() as i64;
        app.store
            .put(&key, Bytes::from(data))
            .await
            .map_err(Problem::internal)?;
        files.push(ImportFile {
            field,
            name,
            key,
            bytes: n,
            sha256: sha,
        });
    }
    let req = ImportRequest {
        job_id,
        files,
        manifest: vec![],
        options: ImportOptions {
            mode: if mirror {
                "mirror".into()
            } else {
                "upsert".into()
            },
            dry_run,
            ..Default::default()
        },
    };
    let job = enqueue(app, req, "cli", "cli", "", None, true).await?;
    // Run it here instead of in a worker.
    let id = job.id.clone();
    app.db
        .write(move |tx| {
            tx.execute(
                "UPDATE jobs SET status = 'running', lease_until = ?, attempts = attempts + 1, started_at = ? WHERE id = ?",
                rusqlite::params![crate::db::fmt_time(chrono::Utc::now() + chrono::Duration::minutes(10)), crate::db::now_str(), id],
            )?;
            Ok(())
        })
        .await?;
    let job = jobs::load_job(app, &job.id)
        .await?
        .ok_or_else(|| Problem::internal("job vanished"))?;
    let outcome = run_import_job(app, &job).await;
    let (status, result, error) = match outcome {
        Ok(r) => ("succeeded", r, None),
        Err((r, e)) => ("failed", r, Some(e)),
    };
    let id = job.id.clone();
    let res = result.map(|v| v.to_string());
    app.db
        .write(move |tx| {
            tx.execute(
                "UPDATE jobs SET status = ?, result = COALESCE(?, result), error = ?, finished_at = ?, lease_until = NULL WHERE id = ?",
                rusqlite::params![status, res, error, crate::db::now_str(), id],
            )?;
            Ok(())
        })
        .await?;
    let job = jobs::load_job(app, &job.id)
        .await?
        .ok_or_else(|| Problem::internal("job vanished"))?;
    import_run_json(app, &job).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_ids() {
        assert_eq!(default_variant_id(" MN-1 ", "NVY", "M", ""), "MN-1-NVY-M");
        assert_eq!(default_variant_id("A", "B", "32/34", "L"), "A-B-32_34-L");
    }

    #[test]
    fn absent_columns_keep_stored_fields() {
        let present = columns_of(&["style_number".into(), "name:en".into()], "en");
        let doc: Map<String, Value> =
            serde_json::from_value(json!({"style_number": "A", "name": {"en": "A"}})).unwrap();
        let stored = r#"{"style_number":"A","name":{"en":"Old","nl":"Oud"},"season":"AW26","features":{"fit":"slim"}}"#;
        let out = keep_absent_columns(&doc, stored, PRODUCT_FIELDS, &present);
        assert_eq!(out["name"], json!({"en": "A", "nl": "Oud"}));
        assert_eq!(out["season"], json!("AW26"));
        assert_eq!(out["features"], json!({"fit": "slim"}));
    }

    #[test]
    fn extensions_are_carried() {
        let stored = r#"{"x-acme-a":1,"color":{"code":"X","x-acme-b":2}}"#;
        let mut doc: Map<String, Value> =
            serde_json::from_value(json!({"color": {"code": "X"}})).unwrap();
        carry_extensions(&mut doc, collect_extensions(stored, VARIANT_EXT_PATHS));
        assert_eq!(
            Value::Object(doc),
            json!({"x-acme-a": 1, "color": {"code": "X", "x-acme-b": 2}})
        );
    }

    async fn test_app() -> (App, PathBuf) {
        let dir = std::env::temp_dir().join(format!("obx-import-test-{}", crate::ids::new("t")));
        std::fs::create_dir_all(&dir).unwrap();
        let cfg = crate::config::Config {
            public_url: "http://localhost:8080".into(),
            port: 8080,
            bind: std::net::IpAddr::from([127, 0, 0, 1]),
            data_dir: dir.clone(),
            database_url: format!("sqlite:{}", dir.join("obx.db").display()),
            blob_url: format!("file://{}", dir.join("blobs").display()),
            s3_access_key_id: None,
            s3_secret_access_key: None,
            secret_key: b"test-secret-key-0123456789abcdef0123".to_vec(),
            setup_code: Some("TEST-CODE".into()),
            allow_private_urls: true,
            trust_proxy: false,
            workers: 1,
            change_retention_days: 400,
            job_retention_days: 30,
            mail_from: "no-reply@example.test".into(),
            mail_log_bodies: false,
            log_format: "text".into(),
            log_level: "info".into(),
            test_rate_limit: None,
        };
        (App::new(cfg).await.unwrap(), dir)
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn imports_the_maison_noor_fixtures() {
        let (app, dir) = test_app().await;
        app.catalog_write(None, |w| {
            let mut doc = Map::new();
            doc.insert("name".into(), json!("MAISON NOOR"));
            doc.insert("status".into(), json!("published"));
            let (_, p) = w.upsert(KIND_BRAND, "maison-noor", doc, "");
            p.map_or(Ok(()), Err)
        })
        .await
        .unwrap();
        let fx = PathBuf::from(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/crates/obx-conformance/fixtures/maison-noor"
        ));
        let run = run_import_cli(
            &app,
            Some(fx.join("products.csv")),
            Some(fx.join("assets.csv")),
            Some(fx.join("images")),
            None,
            false,
            false,
        )
        .await
        .unwrap();
        assert_eq!(run["status"], "succeeded", "{run}");
        assert_eq!(run["counts"]["errors"], 0, "{run}");
        let counts = app
            .db
            .read(|c| {
                let n = |t: &str| -> rusqlite::Result<i64> {
                    c.query_row(
                        &format!("SELECT COUNT(*) FROM {t} WHERE visible = 1"),
                        [],
                        |r| r.get(0),
                    )
                };
                Ok((n("brands")?, n("products")?, n("variants")?, n("assets")?))
            })
            .await
            .unwrap();
        let want: Value = serde_json::from_str(include_str!(
            "../crates/obx-conformance/fixtures/expected/counts.json"
        ))
        .unwrap();
        assert_eq!(
            counts,
            (
                want["brands"].as_i64().unwrap(),
                want["products"].as_i64().unwrap(),
                want["variants"].as_i64().unwrap(),
                want["assets"].as_i64().unwrap()
            )
        );
        // Re-importing the same files changes nothing.
        let again = run_import_cli(
            &app,
            Some(fx.join("products.csv")),
            Some(fx.join("assets.csv")),
            Some(fx.join("images")),
            None,
            false,
            false,
        )
        .await
        .unwrap();
        assert_eq!(again["counts"]["created"], 0, "{again}");
        assert_eq!(again["counts"]["updated"], 0, "{again}");
        let _ = std::fs::remove_dir_all(dir);
    }
}
