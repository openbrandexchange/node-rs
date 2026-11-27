//! Language selection (protocol.md §2.3, spec proposal 0010): which language
//! a request asks for (`?lang=` or `Accept-Language`), and the response
//! narrowed to it. Every LocalizedText keeps one member, the selected
//! language where the field has it and otherwise a fallback that is listed in
//! the object's `language_fallbacks`; `universal` sets term names to `null`.
//! Pure functions over `serde_json::Value`, independent of storage.
//!
//! ```
//! use obx_types::lang::{narrow, select, Kind};
//! use serde_json::json;
//!
//! let langs = ["nl".to_string(), "en".to_string()];
//! let selectable = ["nl".to_string(), "en".to_string(), "de".to_string()];
//! let sel = select(Some("de-CH"), None, &selectable, &langs).unwrap().unwrap();
//! assert_eq!(sel.tag, "de");
//! let mut p = json!({"name": {"en": "Sweater", "nl": "Trui"},
//!     "materials": [{"part": {"code": "main", "name": null}, "fibers": [{"material":
//!         {"code": "wool", "name": {"de": "Wolle", "en": "Wool", "nl": "Wol"}}, "percentage": 100, "qualifiers": []}]}]});
//! narrow(Kind::Product, &mut p, &sel, &langs);
//! assert_eq!(p["name"], json!({"nl": "Trui"}));
//! assert_eq!(p["materials"][0]["fibers"][0]["material"]["name"], json!({"de": "Wolle"}));
//! assert_eq!(p["language_fallbacks"], json!({"/name": "nl"}));
//! ```

use std::sync::LazyLock;

use regex::Regex;
use serde_json::{Map, Value};

use crate::Problem;

/// The reserved value of `lang` that asks for codes only.
pub const UNIVERSAL: &str = "universal";
/// The capability string in discovery.
pub const CAPABILITY: &str = "language_selection";

static TAG: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[a-z]{2,3}(-[A-Z][a-z]{3})?(-([A-Z]{2}|[0-9]{3}))?$").unwrap());

/// A language selection: the selected tag (for `universal` the default
/// language, which the free texts are served in) and whether term names are
/// left out.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Selection {
    pub tag: String,
    pub universal: bool,
}

impl Selection {
    /// The `Content-Language` header value.
    pub fn content_language(&self) -> &str {
        &self.tag
    }
}

/// The canonical form of a tag (`de_ch` → `de-CH`, `ZH-hant` → `zh-Hant`),
/// or `None` when it is not of the LocalizedText form.
pub fn canonical_tag(raw: &str) -> Option<String> {
    let t = raw
        .trim()
        .replace('_', "-")
        .split('-')
        .enumerate()
        .map(|(i, s)| match (i, s.len()) {
            (0, _) => s.to_ascii_lowercase(),
            (_, 4) => {
                let mut c = s.chars();
                c.next()
                    .map(|f| f.to_ascii_uppercase().to_string() + &c.as_str().to_ascii_lowercase())
                    .unwrap_or_default()
            }
            _ => s.to_ascii_uppercase(),
        })
        .collect::<Vec<_>>()
        .join("-");
    TAG.is_match(&t).then_some(t)
}

/// RFC 4647 lookup of `tag` in `available` (case-insensitive, truncating
/// from the end: `de-CH` → `de`).
pub fn lookup<'a>(tag: &str, available: &'a [String]) -> Option<&'a String> {
    let parts: Vec<&str> = tag.split('-').collect();
    (1..=parts.len()).rev().find_map(|n| {
        let t = parts[..n].join("-");
        available.iter().find(|a| a.eq_ignore_ascii_case(&t))
    })
}

/// The ranges of an `Accept-Language` header in the order to try: by `q`
/// (equal `q`: as written), without `*` and `q=0`.
pub fn accept_language_ranges(header: &str) -> Vec<String> {
    let mut ranges: Vec<(f32, usize, String)> = header
        .split(',')
        .enumerate()
        .filter_map(|(i, r)| {
            let mut it = r.split(';');
            let tag = it.next()?.trim().to_string();
            let q = it
                .map(str::trim)
                .find_map(|p| p.strip_prefix("q="))
                .map(|q| q.trim().parse::<f32>().unwrap_or(0.0))
                .unwrap_or(1.0);
            (q > 0.0 && !tag.is_empty() && tag != "*").then_some((q, i, tag))
        })
        .collect();
    ranges.sort_by(|a, b| b.0.total_cmp(&a.0).then(a.1.cmp(&b.1)));
    ranges.into_iter().map(|r| r.2).collect()
}

/// The selection of a request. `lang` wins; without it the first
/// `Accept-Language` range that matches `selectable` selects, and no match is
/// no selection (`Ok(None)`, the 0.3 response). `lang` that matches nothing
/// selects the default language (the first of `languages`). A malformed
/// `lang` is `400 invalid_request`.
pub fn select(
    lang: Option<&str>,
    accept_language: Option<&str>,
    selectable: &[String],
    languages: &[String],
) -> Result<Option<Selection>, Problem> {
    let default = languages.first().cloned().unwrap_or_else(|| "en".into());
    if let Some(raw) = lang.map(str::trim).filter(|l| !l.is_empty()) {
        if raw.eq_ignore_ascii_case(UNIVERSAL) {
            return Ok(Some(Selection {
                tag: default,
                universal: true,
            }));
        }
        let Some(tag) = canonical_tag(raw) else {
            return Err(Problem::new(
                "invalid_request",
                "lang must be a BCP 47 language tag (language, optional script and region) or `universal`.",
            ));
        };
        let tag = lookup(&tag, selectable).cloned().unwrap_or(default);
        return Ok(Some(Selection {
            tag,
            universal: false,
        }));
    }
    let Some(h) = accept_language else {
        return Ok(None);
    };
    Ok(accept_language_ranges(h)
        .iter()
        .filter_map(|r| canonical_tag(r))
        .find_map(|t| lookup(&t, selectable).cloned())
        .map(|tag| Selection {
            tag,
            universal: false,
        }))
}

/// Discovery `selectable_languages`: the content languages in their order,
/// then the other languages of `term_languages` (sorted, deduplicated).
pub fn selectable_languages(
    languages: &[String],
    term_languages: impl IntoIterator<Item = String>,
) -> Vec<String> {
    let mut out: Vec<String> = languages.to_vec();
    let mut rest: Vec<String> = term_languages
        .into_iter()
        .filter(|l| !out.contains(l))
        .collect();
    rest.sort();
    rest.dedup();
    out.extend(rest);
    out
}

/// What kind of object [`narrow`] is given.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Brand,
    /// A product without `variants`/`assets` (a change entry's `data`).
    Product,
    /// A ProductDetail: the product and each embedded variant and asset get
    /// their own `language_fallbacks`.
    ProductDetail,
    Variant,
    Asset,
}

impl Kind {
    /// The kind of a change entry `type`, `None` for types without localised
    /// objects (`grant`, `collection`).
    pub fn of_change_type(t: &str) -> Option<Kind> {
        match t {
            "brand" => Some(Kind::Brand),
            "product" => Some(Kind::Product),
            "variant" => Some(Kind::Variant),
            "asset" => Some(Kind::Asset),
            _ => None,
        }
    }
}

fn is_text(v: &Value) -> bool {
    v.as_object()
        .is_some_and(|m| !m.is_empty() && m.iter().all(|(k, v)| v.is_string() && TAG.is_match(k)))
}

/// The tag a LocalizedText is served in: the selected one, the content
/// languages in order, then its other tags in byte order.
fn pick(text: &Map<String, Value>, sel: &str, languages: &[String]) -> Option<String> {
    if text.contains_key(sel) {
        return Some(sel.to_owned());
    }
    languages
        .iter()
        .find(|l| text.contains_key(l.as_str()))
        .cloned()
        .or_else(|| text.keys().min().cloned())
}

fn escape(k: &str) -> String {
    k.replace('~', "~0").replace('/', "~1")
}

fn walk(
    v: &mut Value,
    ptr: &str,
    term: bool,
    sel: &Selection,
    languages: &[String],
    fallbacks: &mut Map<String, Value>,
) {
    if is_text(v) {
        if term && sel.universal {
            *v = Value::Null;
            return;
        }
        let m = v.as_object_mut().expect("text is an object");
        if let Some(tag) = pick(m, &sel.tag, languages) {
            let text = m.remove(&tag).unwrap_or(Value::Null);
            m.clear();
            m.insert(tag.clone(), text);
            if tag != sel.tag {
                fallbacks.insert(ptr.to_owned(), Value::String(tag));
            }
        }
        return;
    }
    match v {
        Value::Array(a) => {
            for (i, x) in a.iter_mut().enumerate() {
                walk(x, &format!("{ptr}/{i}"), false, sel, languages, fallbacks);
            }
        }
        Value::Object(m) => {
            for (k, x) in m.iter_mut() {
                // Extension members are returned unchanged (protocol.md §2).
                if k.starts_with("x-") {
                    continue;
                }
                let in_term =
                    k == "name" && (ptr.starts_with("/materials/") || ptr.starts_with("/care/"));
                walk(
                    x,
                    &format!("{ptr}/{}", escape(k)),
                    in_term,
                    sel,
                    languages,
                    fallbacks,
                );
            }
        }
        _ => {}
    }
}

/// Narrows one object to the selection and sets its `language_fallbacks`.
/// `languages` are the node's content languages, first = default.
pub fn narrow(kind: Kind, obj: &mut Value, sel: &Selection, languages: &[String]) {
    let Some(m) = obj.as_object_mut() else { return };
    m.remove("language_fallbacks");
    let mut nested = Vec::new();
    if kind == Kind::ProductDetail {
        for (k, k2) in [("variants", Kind::Variant), ("assets", Kind::Asset)] {
            if let Some(list) = m.remove(k) {
                nested.push((k, k2, list));
            }
        }
    }
    let mut fallbacks = Map::new();
    walk(obj, "", false, sel, languages, &mut fallbacks);
    let m = obj.as_object_mut().expect("object");
    for (k, k2, mut list) in nested {
        for x in list.as_array_mut().into_iter().flatten() {
            narrow(k2, x, sel, languages);
        }
        m.insert(k.to_owned(), list);
    }
    m.insert("language_fallbacks".into(), Value::Object(fallbacks));
}

/// Narrows the `data` of a change entry (`{type, op, data, ...}`).
pub fn narrow_change(entry: &mut Value, sel: &Selection, languages: &[String]) {
    let Some(kind) = entry["type"].as_str().and_then(Kind::of_change_type) else {
        return;
    };
    if let Some(d) = entry.get_mut("data").filter(|d| d.is_object()) {
        narrow(kind, d, sel, languages);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn s(v: &[&str]) -> Vec<String> {
        v.iter().map(|x| x.to_string()).collect()
    }

    #[test]
    fn selection() {
        let (sel, langs) = (s(&["nl", "en", "de", "fr"]), s(&["nl", "en"]));
        let pick = |l: Option<&str>, a: Option<&str>| {
            select(l, a, &sel, &langs)
                .unwrap()
                .map(|x| (x.tag, x.universal))
        };
        assert_eq!(pick(Some("en-GB"), None), Some(("en".into(), false)));
        assert_eq!(pick(Some("DE_ch"), None), Some(("de".into(), false)));
        assert_eq!(pick(Some("ja"), None), Some(("nl".into(), false)));
        assert_eq!(pick(Some("Universal"), None), Some(("nl".into(), true)));
        assert_eq!(pick(Some("fr"), Some("en")), Some(("fr".into(), false)));
        assert_eq!(
            pick(None, Some("ja, de-CH;q=0.9, en;q=0.8")),
            Some(("de".into(), false))
        );
        assert_eq!(
            pick(None, Some("*, nl;q=0.4, en;q=0.6")),
            Some(("en".into(), false))
        );
        assert_eq!(pick(None, Some("ja, en;q=0")), None);
        assert_eq!(pick(None, None), None);
        assert!(select(Some("en--GB"), None, &sel, &langs).is_err());
        assert_eq!(canonical_tag("zh_hant"), Some("zh-Hant".into()));
        assert_eq!(canonical_tag("es-419"), Some("es-419".into()));
    }

    #[test]
    fn universal_nulls_terms_only() {
        let langs = s(&["nl", "en"]);
        let sel = Selection {
            tag: "nl".into(),
            universal: true,
        };
        let mut p = json!({"name": {"en": "Sweater"}, "care": [{"code": "wash_30", "name": {"en": "Wash at 30 °C"}, "text": {"en": "Inside out"}}],
                           "x-acme-label": {"en": "kept"}});
        narrow(Kind::Product, &mut p, &sel, &langs);
        assert_eq!(p["care"][0]["name"], Value::Null);
        assert_eq!(p["name"], json!({"en": "Sweater"}));
        assert_eq!(p["x-acme-label"], json!({"en": "kept"}));
        assert_eq!(
            p["care"][0]["text"],
            json!({"en": "Inside out"}),
            "the brand's own care text is free text"
        );
        assert_eq!(
            p["language_fallbacks"],
            json!({"/name": "en", "/care/0/text": "en"})
        );
    }

    #[test]
    fn detail_and_changes() {
        let langs = s(&["nl", "en"]);
        let sel = Selection {
            tag: "en".into(),
            universal: false,
        };
        let mut p = json!({"name": {"nl": "Trui"}, "variants": [{"color": {"code": "NVY", "name": {"nl": "Marine", "en": "Navy"}}}],
                           "assets": [{"alt_text": {"nl": "Voorkant"}}]});
        narrow(Kind::ProductDetail, &mut p, &sel, &langs);
        assert_eq!(p["language_fallbacks"], json!({"/name": "nl"}));
        assert_eq!(p["variants"][0]["language_fallbacks"], json!({}));
        assert_eq!(p["variants"][0]["color"]["name"], json!({"en": "Navy"}));
        assert_eq!(
            p["assets"][0]["language_fallbacks"],
            json!({"/alt_text": "nl"})
        );
        let mut e = json!({"type": "variant", "op": "upsert", "data": {"color": {"name": {"nl": "Marine"}}}});
        narrow_change(&mut e, &sel, &langs);
        assert_eq!(
            e["data"]["language_fallbacks"],
            json!({"/color/name": "nl"})
        );
        let mut g = json!({"type": "grant", "op": "upsert", "data": {"resync": true}});
        narrow_change(&mut g, &sel, &langs);
        assert!(g["data"].get("language_fallbacks").is_none());
    }

    #[test]
    fn selectable() {
        assert_eq!(
            selectable_languages(&s(&["nl", "en"]), s(&["fr", "en", "de", "nl"])),
            s(&["nl", "en", "de", "fr"])
        );
    }
}
