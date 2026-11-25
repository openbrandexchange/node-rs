//! The OBX objects: the stored write models (what a brand wrote, the
//! IngestRecord `data`) and the protocol representations. Field names and
//! shapes follow the spec's JSON Schemas; node-go stored the same JSON.
//!
//! Extensions (`x-<vendor>-<name>` members, protocol.md §2) are kept in an
//! `ext` map on every object whose schema allows them; any other unknown
//! member is dropped on read (the ingest path reports it as a warning).

use std::collections::BTreeMap;

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json::Value;

pub type Ext = BTreeMap<String, Value>;
pub type LocalizedText = BTreeMap<String, String>;

pub fn is_ext_name(k: &str) -> bool {
    static RE: std::sync::LazyLock<regex::Regex> =
        std::sync::LazyLock::new(|| regex::Regex::new(r"^x-[a-z0-9]+-[a-z0-9_-]+$").unwrap());
    RE.is_match(k)
}

fn ext_only<'de, D: Deserializer<'de>>(d: D) -> Result<Ext, D::Error> {
    let m = BTreeMap::<String, Value>::deserialize(d)?;
    Ok(m.into_iter().filter(|(k, _)| is_ext_name(k)).collect())
}

/// Whole numbers are written without a fraction (`100`, not `100.0`), like
/// every other node.
pub fn ser_num<S: Serializer>(v: &f64, s: S) -> Result<S::Ok, S::Error> {
    if v.fract() == 0.0 && v.abs() < 9.0e15 {
        s.serialize_i64(*v as i64)
    } else {
        s.serialize_f64(*v)
    }
}

pub fn ser_opt_num<S: Serializer>(v: &Option<f64>, s: S) -> Result<S::Ok, S::Error> {
    match v {
        Some(v) => ser_num(v, s),
        None => s.serialize_none(),
    }
}

/// Normalises numbers in free JSON (features, attributes, extensions):
/// whole floats become integers.
pub fn norm_numbers(v: &mut Value) {
    match v {
        Value::Number(n) => {
            if let Some(f) = n.as_f64() {
                if !n.is_i64() && !n.is_u64() && f.fract() == 0.0 && f.abs() < 9.0e15 {
                    *v = Value::from(f as i64);
                }
            }
        }
        Value::Array(a) => a.iter_mut().for_each(norm_numbers),
        Value::Object(o) => o.values_mut().for_each(norm_numbers),
        _ => {}
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct Term {
    pub code: String,
    #[serde(default)]
    pub name: Option<LocalizedText>,
    #[serde(flatten, deserialize_with = "ext_only", default)]
    pub ext: Ext,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct Fiber {
    pub material: Term,
    #[serde(default, serialize_with = "ser_opt_num")]
    pub percentage: Option<f64>,
    #[serde(default, deserialize_with = "null_as_empty")]
    pub qualifiers: Vec<Term>,
    #[serde(flatten, deserialize_with = "ext_only", default)]
    pub ext: Ext,
}

fn null_as_empty<'de, D: Deserializer<'de>, T: Deserialize<'de>>(d: D) -> Result<Vec<T>, D::Error> {
    Ok(Option::<Vec<T>>::deserialize(d)?.unwrap_or_default())
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct MaterialPart {
    pub part: Term,
    #[serde(default, deserialize_with = "null_as_empty")]
    pub fibers: Vec<Fiber>,
    #[serde(flatten, deserialize_with = "ext_only", default)]
    pub ext: Ext,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct CareItem {
    pub code: String,
    #[serde(default)]
    pub category: Option<String>,
    #[serde(default)]
    pub symbol: Option<String>,
    #[serde(default)]
    pub name: Option<LocalizedText>,
    #[serde(default)]
    pub text: Option<LocalizedText>,
    #[serde(flatten, deserialize_with = "ext_only", default)]
    pub ext: Ext,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct Color {
    #[serde(default)]
    pub code: String,
    #[serde(default)]
    pub name: Option<LocalizedText>,
    #[serde(default)]
    pub supplier_color: Option<String>,
    #[serde(default)]
    pub family: Option<String>,
    #[serde(flatten, deserialize_with = "ext_only", default)]
    pub ext: Ext,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct FootwearMaterials {
    #[serde(default)]
    pub upper: Option<String>,
    #[serde(default)]
    pub lining_and_sock: Option<String>,
    #[serde(default)]
    pub outer_sole: Option<String>,
    #[serde(flatten, deserialize_with = "ext_only", default)]
    pub ext: Ext,
}

impl FootwearMaterials {
    pub fn complete(&self) -> bool {
        self.upper.is_some() && self.lining_and_sock.is_some() && self.outer_sole.is_some()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct Certification {
    pub scheme: String,
    #[serde(default)]
    pub licence_number: Option<String>,
    pub scope: String,
    #[serde(flatten, deserialize_with = "ext_only", default)]
    pub ext: Ext,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct Range {
    #[serde(serialize_with = "ser_num")]
    pub min: f64,
    #[serde(serialize_with = "ser_num")]
    pub max: f64,
}

macro_rules! measurements {
    ($($f:ident),*) => {
        #[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
        pub struct Measurements {
            $(
                #[serde(default, skip_serializing_if = "Option::is_none", serialize_with = "ser_opt_num")]
                pub $f: Option<f64>,
            )*
            #[serde(default, skip_serializing_if = "Option::is_none")]
            pub strap_length_cm: Option<Range>,
            #[serde(flatten, deserialize_with = "ext_only", default)]
            pub ext: Ext,
        }
        impl Measurements {
            pub fn empty(&self) -> bool {
                $(self.$f.is_none() &&)* self.strap_length_cm.is_none() && self.ext.is_empty()
            }
            pub fn numbers(&self) -> Vec<(&'static str, Option<f64>)> {
                vec![$((stringify!($f), self.$f)),*]
            }
        }
    };
}
measurements!(
    height_cm,
    width_cm,
    depth_cm,
    weight_kg,
    volume_l,
    volume_expanded_l,
    handle_drop_cm,
    laptop_max_inch,
    heel_height_cm,
    shaft_height_cm,
    inseam_cm
);

pub type Features = BTreeMap<String, Value>;

// ---- stored write models ----------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct BrandData {
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub logo_url: Option<String>,
    #[serde(default)]
    pub website: Option<String>,
    #[serde(default)]
    pub description: Option<LocalizedText>,
    #[serde(flatten, deserialize_with = "ext_only", default)]
    pub ext: Ext,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct ProductData {
    #[serde(default)]
    pub brand_external_id: String,
    #[serde(default)]
    pub style_number: String,
    #[serde(default)]
    pub name: Option<LocalizedText>,
    #[serde(default)]
    pub description: Option<LocalizedText>,
    #[serde(default)]
    pub item_type: Option<String>,
    #[serde(default)]
    pub item_subtype: Option<String>,
    #[serde(default)]
    pub gpc_brick: Option<String>,
    #[serde(default)]
    pub target_group: Option<String>,
    #[serde(default)]
    pub season: Option<String>,
    #[serde(default)]
    pub collection: Option<String>,
    #[serde(default)]
    pub materials: Option<Vec<MaterialPart>>,
    #[serde(default)]
    pub contains_animal_origin: Option<bool>,
    #[serde(default)]
    pub footwear_materials: Option<FootwearMaterials>,
    #[serde(default)]
    pub care: Option<Vec<CareItem>>,
    #[serde(default)]
    pub country_of_origin: Option<String>,
    #[serde(default)]
    pub certifications: Option<Vec<Certification>>,
    #[serde(default)]
    pub dpp_url: Option<String>,
    #[serde(default)]
    pub features: Option<Features>,
    #[serde(default)]
    pub attributes: Option<serde_json::Map<String, Value>>,
    #[serde(flatten, deserialize_with = "ext_only", default)]
    pub ext: Ext,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct VariantData {
    #[serde(default)]
    pub product_external_id: String,
    #[serde(default)]
    pub gtin: Option<String>,
    #[serde(default)]
    pub sku: Option<String>,
    #[serde(default)]
    pub color: Color,
    #[serde(default)]
    pub size: Option<String>,
    #[serde(default)]
    pub size_length: Option<String>,
    #[serde(default)]
    pub size_system: Option<String>,
    #[serde(default)]
    pub measurements: Option<Measurements>,
    #[serde(flatten, deserialize_with = "ext_only", default)]
    pub ext: Ext,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct FileRef {
    pub sha256: String,
    #[serde(default)]
    pub width: Option<i64>,
    #[serde(default)]
    pub height: Option<i64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct AssetData {
    #[serde(default)]
    pub product_external_id: String,
    #[serde(default)]
    pub color_code: Option<String>,
    #[serde(default)]
    pub variant_external_ids: Option<Vec<String>>,
    #[serde(default)]
    pub media_type: String,
    #[serde(default)]
    pub role: String,
    #[serde(default)]
    pub view: Option<String>,
    #[serde(default)]
    pub position: i64,
    #[serde(default)]
    pub filename: Option<String>,
    #[serde(default)]
    pub alt_text: Option<LocalizedText>,
    /// Only the fields the brand set that differ from the node default, plus
    /// extension members.
    #[serde(default)]
    pub rights: Option<BTreeMap<String, Value>>,
    #[serde(default)]
    pub provenance: Option<BTreeMap<String, Value>>,
    #[serde(default)]
    pub files: Option<BTreeMap<String, FileRef>>,
    #[serde(flatten, deserialize_with = "ext_only", default)]
    pub ext: Ext,
}

// ---- protocol representations -------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct BrandRep {
    pub id: String,
    pub external_id: String,
    pub name: String,
    pub logo_url: Option<String>,
    pub website: Option<String>,
    pub description: Option<LocalizedText>,
    #[serde(flatten, deserialize_with = "ext_only", default)]
    pub ext: Ext,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ProductRep {
    pub id: String,
    pub external_id: String,
    pub brand_id: String,
    pub style_number: String,
    pub name: Option<LocalizedText>,
    pub description: Option<LocalizedText>,
    pub item_type: Option<String>,
    pub item_subtype: Option<String>,
    pub gpc_brick: Option<String>,
    pub target_group: Option<String>,
    pub season: Option<String>,
    pub collection: Option<String>,
    pub materials: Option<Vec<MaterialPart>>,
    pub contains_animal_origin: Option<bool>,
    pub footwear_materials: Option<FootwearMaterials>,
    pub care: Option<Vec<CareItem>>,
    pub country_of_origin: Option<String>,
    pub certifications: Option<Vec<Certification>>,
    pub dpp_url: Option<String>,
    pub features: Option<Features>,
    pub attributes: Option<serde_json::Map<String, Value>>,
    pub created_at: String,
    #[serde(flatten, deserialize_with = "ext_only", default)]
    pub ext: Ext,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct VariantRep {
    pub id: String,
    pub external_id: String,
    pub product_id: String,
    pub brand_id: String,
    pub gtin: Option<String>,
    pub gtin_original: Option<String>,
    pub sku: Option<String>,
    pub color: Color,
    pub size: Option<String>,
    pub size_length: Option<String>,
    pub size_system: Option<String>,
    pub measurements: Option<Measurements>,
    #[serde(flatten, deserialize_with = "ext_only", default)]
    pub ext: Ext,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Rights {
    pub license: String,
    #[serde(default)]
    pub license_text: Option<String>,
    #[serde(default)]
    pub channels: Vec<String>,
    #[serde(default)]
    pub territories: Option<Vec<String>>,
    #[serde(default)]
    pub embargo_until: Option<String>,
    #[serde(default)]
    pub expires_at: Option<String>,
    #[serde(default)]
    pub credit: Option<String>,
    #[serde(default)]
    pub model_release: Option<bool>,
    #[serde(flatten, deserialize_with = "ext_only", default)]
    pub ext: Ext,
}

impl Default for Rights {
    /// The default rights of a node that has not configured any (protocol.md §5.6).
    fn default() -> Rights {
        Rights {
            license: "retailer-use".into(),
            license_text: None,
            channels: vec!["webshop".into(), "marketplace".into(), "social".into()],
            territories: None,
            embargo_until: None,
            expires_at: None,
            credit: None,
            model_release: None,
            ext: Ext::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Provenance {
    #[serde(default)]
    pub ai_generated: bool,
    #[serde(default)]
    pub ai_edited: bool,
    #[serde(default)]
    pub source: String,
    #[serde(default)]
    pub c2pa: String,
    #[serde(default)]
    pub c2pa_manifest_url: Option<String>,
    #[serde(default)]
    pub generator: Option<String>,
    #[serde(flatten, deserialize_with = "ext_only", default)]
    pub ext: Ext,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RenditionRep {
    pub name: String,
    #[serde(default)]
    pub url: String,
    #[serde(default)]
    pub url_expires_at: Option<String>,
    pub content_type: String,
    pub width: i64,
    pub height: i64,
    pub bytes: i64,
    pub sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AssetRep {
    pub id: String,
    pub external_id: String,
    pub product_id: String,
    pub brand_id: String,
    pub media_type: String,
    pub color_code: Option<String>,
    pub variant_ids: Option<Vec<String>>,
    pub role: String,
    pub view: Option<String>,
    pub position: i64,
    pub filename: String,
    pub alt_text: Option<LocalizedText>,
    pub content_type: String,
    pub width: i64,
    pub height: i64,
    pub bytes: i64,
    pub sha256: String,
    pub rights: Rights,
    pub provenance: Provenance,
    pub renditions: Option<BTreeMap<String, RenditionRep>>,
    #[serde(flatten, deserialize_with = "ext_only", default)]
    pub ext: Ext,
}

/// One resolved file of an asset (`assets.live_files`).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct LiveFile {
    pub sha256: String,
    pub content_type: String,
    pub width: i64,
    pub height: i64,
    pub bytes: i64,
}

pub const RENDITION_NAMES: [&str; 4] = ["original", "web", "square", "thumb"];
pub const DERIVED_RENDITIONS: [&str; 3] = ["web", "square", "thumb"];

pub const KIND_BRAND: &str = "brand";
pub const KIND_PRODUCT: &str = "product";
pub const KIND_VARIANT: &str = "variant";
pub const KIND_ASSET: &str = "asset";

pub fn table_of(kind: &str) -> &'static str {
    match kind {
        KIND_BRAND => "brands",
        KIND_PRODUCT => "products",
        KIND_VARIANT => "variants",
        _ => "assets",
    }
}

pub fn kind_from_segment(seg: &str) -> Option<&'static str> {
    match seg {
        "brands" => Some(KIND_BRAND),
        "products" => Some(KIND_PRODUCT),
        "variants" => Some(KIND_VARIANT),
        "assets" => Some(KIND_ASSET),
        _ => None,
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct WarningDetail {
    pub code: String,
    pub pointer: Option<String>,
    pub detail: String,
    #[serde(skip)]
    pub column: String,
    #[serde(skip)]
    pub value: String,
}

#[derive(Debug, Clone, Serialize, Default)]
pub struct IngestResult {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub index: Option<usize>,
    pub op: String,
    pub kind: String,
    pub external_id: String,
    pub result: String,
    pub id: Option<String>,
    pub visibility: Option<String>,
    pub etag: Option<String>,
    pub error: Option<crate::problem::Problem>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub warnings: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub warning_details: Vec<WarningDetail>,
}

pub fn to_value<T: Serialize>(v: &T) -> Value {
    serde_json::to_value(v).expect("serialise")
}

pub fn to_json<T: Serialize>(v: &T) -> String {
    serde_json::to_string(v).expect("serialise")
}
