//! Article data (protocol.md §5.9): terms with names from the vocabularies,
//! the 0.1 fibre keys, the draft single qualifier and the label
//! completeness warnings (import-format.md rule 10).

use serde_json::Value;

use crate::model::{CareItem, Ext, LocalizedText, MaterialPart, ProductData, Term, WarningDetail};

pub use obx_format::vocab;

fn names(m: &std::collections::BTreeMap<String, String>) -> Option<LocalizedText> {
    let out: LocalizedText = m
        .iter()
        .filter(|(_, v)| !v.is_empty())
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect();
    if out.is_empty() { None } else { Some(out) }
}

fn clean_text(t: Option<LocalizedText>) -> Option<LocalizedText> {
    let t: LocalizedText = t?
        .into_iter()
        .filter(|(_, v)| !v.trim().is_empty())
        .collect();
    if t.is_empty() { None } else { Some(t) }
}

fn fill_term(t: &mut Term, v: &vocab::Vocabulary) {
    match v.lookup(&t.code) {
        Some(e) => t.name = names(&e.name),
        None => t.name = clean_text(t.name.take()),
    }
}

/// `recycled_polyester` → (`polyester`, [`recycled`]); other codes unchanged.
pub fn normalize_material(key: &str) -> (String, Vec<String>) {
    let mut key = key.to_string();
    let mut qs: Vec<String> = Vec::new();
    loop {
        let q = if key.len() > "recycled_".len() && key.starts_with("recycled_") {
            "recycled"
        } else if key.len() > "organic_".len() && key.starts_with("organic_") {
            "organic"
        } else {
            return (key, qs);
        };
        key = key[q.len() + 1..].to_string();
        if !qs.iter().any(|x| x == q) {
            qs.push(q.to_string());
        }
    }
}

/// Canonical 0.3 materials and care: names from the vocabularies, 0.1 fibre
/// keys become the material with its qualifier (first), repeated qualifiers
/// are dropped (keeping the first).
pub fn normalize_terms(ms: &mut [MaterialPart], care: &mut [CareItem]) {
    for p in ms.iter_mut() {
        fill_term(&mut p.part, vocab::parts());
        for f in p.fibers.iter_mut() {
            let (code, qs) = normalize_material(&f.material.code);
            if code != f.material.code {
                f.material = Term {
                    code,
                    name: None,
                    ext: std::mem::take(&mut f.material.ext),
                };
            }
            fill_term(&mut f.material, vocab::materials());
            let mut list: Vec<Term> = qs
                .into_iter()
                .map(|c| Term {
                    code: c,
                    name: None,
                    ext: Ext::new(),
                })
                .collect();
            for q in std::mem::take(&mut f.qualifiers) {
                if let Some(existing) = list.iter_mut().find(|t| t.code == q.code) {
                    if existing.ext.is_empty() {
                        existing.ext = q.ext;
                    }
                    continue;
                }
                list.push(q);
            }
            for q in list.iter_mut() {
                fill_term(q, vocab::qualifiers());
            }
            f.qualifiers = list;
        }
    }
    for c in care.iter_mut() {
        match vocab::care().lookup(&c.code) {
            Some(e) => {
                c.category = e.category.clone();
                c.symbol = e.symbol.clone();
                c.name = names(&e.name);
            }
            None => c.name = clean_text(c.name.take()),
        }
        c.text = clean_text(c.text.take());
    }
}

/// Prepares a product or variant input before validation: empty
/// `features`/`measurements` (or only nulls) become null, `certifications: []`
/// null, and the draft single `qualifier` of a fibre becomes `qualifiers`.
/// Returns the pointer of the first fibre that used `qualifier`.
pub fn prepare_article_input(
    kind: &str,
    doc: &mut serde_json::Map<String, Value>,
) -> Option<String> {
    let empty_to_null = |doc: &mut serde_json::Map<String, Value>, key: &str| {
        if let Some(Value::Object(m)) = doc.get_mut(key) {
            m.retain(|_, v| !v.is_null());
            if m.is_empty() {
                doc.insert(key.into(), Value::Null);
            }
        }
    };
    let mut first = None;
    match kind {
        crate::model::KIND_PRODUCT => {
            if let Some(Value::Array(parts)) = doc.get_mut("materials") {
                for (i, p) in parts.iter_mut().enumerate() {
                    let Some(Value::Array(fibers)) = p.get_mut("fibers") else {
                        continue;
                    };
                    for (j, f) in fibers.iter_mut().enumerate() {
                        let Some(fm) = f.as_object_mut() else {
                            continue;
                        };
                        let Some(q) = fm.remove("qualifier") else {
                            continue;
                        };
                        if first.is_none() {
                            first = Some(format!("/materials/{i}/fibers/{j}/qualifier"));
                        }
                        if fm.contains_key("qualifiers") {
                            continue;
                        }
                        fm.insert(
                            "qualifiers".into(),
                            if q.is_null() {
                                Value::Array(vec![])
                            } else {
                                Value::Array(vec![q])
                            },
                        );
                    }
                }
            }
            empty_to_null(doc, "features");
            if matches!(doc.get("certifications"), Some(Value::Array(a)) if a.is_empty()) {
                doc.insert("certifications".into(), Value::Null);
            }
        }
        crate::model::KIND_VARIANT => empty_to_null(doc, "measurements"),
        _ => {}
    }
    first
}

pub const WARN_QUALIFIER_DEPRECATED: &str = "qualifier_deprecated";

const TEXTILE: &[&str] = &[
    "t_shirt",
    "top",
    "shirt",
    "blouse",
    "polo",
    "sweater",
    "cardigan",
    "hoodie",
    "sweatshirt",
    "vest",
    "jacket",
    "coat",
    "blazer",
    "suit",
    "dress",
    "skirt",
    "trousers",
    "jeans",
    "shorts",
    "jumpsuit",
    "leggings",
    "underwear",
    "lingerie",
    "nightwear",
    "swimwear",
    "socks",
    "hat",
    "cap",
    "scarf",
    "gloves",
    "tie",
    "bag",
    "backpack",
    "luggage",
];
const FOOTWEAR: &[&str] = &["shoes", "sneakers", "boots", "sandals"];
const ANIMAL: &[&str] = &[
    "leather",
    "suede",
    "fur",
    "down",
    "feather",
    "wool",
    "merino_wool",
    "lambswool",
    "cashmere",
    "alpaca",
    "mohair",
    "silk",
];

fn fmt_g(v: f64) -> String {
    if v.fract() == 0.0 {
        format!("{}", v as i64)
    } else {
        format!("{v}")
    }
}

/// The label completeness warnings and material_unknown of a product.
pub fn label_warnings(d: &ProductData) -> Vec<WarningDetail> {
    let it = d.item_type.as_deref().unwrap_or("");
    let ms: &[MaterialPart] = d.materials.as_deref().unwrap_or(&[]);
    let mut out = Vec::new();
    let mut add = |code: &str, pointer: String, column: &str, detail: String| {
        out.push(WarningDetail {
            code: code.into(),
            pointer: Some(pointer),
            detail,
            column: column.into(),
            value: String::new(),
        });
    };
    if TEXTILE.contains(&it) {
        if ms.is_empty() {
            add(
                "fibre_composition_missing",
                "/materials".into(),
                "materials",
                "the fibre composition is missing; it must be on the label of a textile product and shown before purchase (Regulation (EU) No 1007/2011)".into(),
            );
        }
        if d.contains_animal_origin.is_none() {
            'animal: for p in ms {
                for f in &p.fibers {
                    if ANIMAL.contains(&f.material.code.as_str())
                        || f.material.code.ends_with("_wool")
                    {
                        add(
                            "animal_origin_unknown",
                            "/contains_animal_origin".into(),
                            "contains_animal_origin",
                            format!(
                                "the materials contain {}; state whether the product contains non-textile parts of animal origin (Regulation (EU) No 1007/2011 Art. 12)",
                                f.material.code
                            ),
                        );
                        break 'animal;
                    }
                }
            }
        }
        for (i, p) in ms.iter().enumerate() {
            let mut sum = 0.0;
            let mut all = true;
            for f in &p.fibers {
                match f.percentage {
                    Some(v) => sum += v,
                    None => all = false,
                }
            }
            if (all && (sum - 100.0).abs() > 0.01) || sum > 100.01 {
                add(
                    "fibre_percentages_not_100",
                    format!("/materials/{i}"),
                    "materials",
                    format!(
                        "the percentages of {} add up to {}, not 100 (Regulation (EU) No 1007/2011 Art. 9)",
                        p.part.code,
                        fmt_g(sum)
                    ),
                );
            }
        }
    } else if FOOTWEAR.contains(&it) {
        let f = d.footwear_materials.clone().unwrap_or_default();
        if !f.complete() {
            let mut missing = Vec::new();
            if f.upper.is_none() {
                missing.push("upper");
            }
            if f.lining_and_sock.is_none() {
                missing.push("lining_and_sock");
            }
            if f.outer_sole.is_none() {
                missing.push("outer_sole");
            }
            add(
                "footwear_materials_missing",
                "/footwear_materials".into(),
                "footwear_materials",
                format!(
                    "the footwear materials of {} are missing; they must be on the label of footwear (Directive 94/11/EC)",
                    missing.join(", ")
                ),
            );
        }
    }
    let mut seen: Vec<&str> = Vec::new();
    for (i, p) in ms.iter().enumerate() {
        for (j, f) in p.fibers.iter().enumerate() {
            let c = f.material.code.as_str();
            if vocab::materials().has(c) || seen.contains(&c) {
                continue;
            }
            seen.push(c);
            out.push(WarningDetail {
                code: "material_unknown".into(),
                pointer: Some(format!("/materials/{i}/fibers/{j}/material/code")),
                detail: format!(
                    "material \"{c}\" is not in the vocabulary (vocabularies/materials.json); it is kept as written, without a name"
                ),
                column: "materials".into(),
                value: c.into(),
            });
        }
    }
    out
}
