//! The article data of spec 0.2 and 0.3 (protocol.md §5.9,
//! import-format.md §1.6): footwear materials, certifications,
//! measurements, colour families and features.

use std::collections::BTreeSet;
use std::sync::LazyLock;

use regex::Regex;
use serde::Serialize;
use serde_json::{Value, json};

use super::values::{append_qualifier, key, parse_bool, valid_key};
use crate::error::{Error, Result, quote};

/// The three parts of a shoe (Directive 94/11/EC), in label order.
pub const FOOTWEAR_PARTS: &[&str] = &["upper", "lining_and_sock", "outer_sole"];

/// The directive's four material categories.
pub const FOOTWEAR_VALUES: &[&str] = &["leather", "coated_leather", "textile", "other"];

/// The colour families of protocol.md §5.9.5.
pub const COLOR_FAMILIES: &[&str] = &[
    "black",
    "white",
    "grey",
    "beige",
    "brown",
    "red",
    "pink",
    "orange",
    "yellow",
    "green",
    "blue",
    "purple",
    "gold",
    "silver",
    "multicolour",
    "transparent",
];

/// The measurement keys, in the order of the schema and of the
/// products.csv columns.
pub const MEASUREMENT_COLUMNS: &[&str] = &[
    "height_cm",
    "width_cm",
    "depth_cm",
    "weight_kg",
    "volume_l",
    "volume_expanded_l",
    "handle_drop_cm",
    "strap_length_cm",
    "laptop_max_inch",
    "heel_height_cm",
    "shaft_height_cm",
    "inseam_cm",
];

/// The type of a registry feature.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum FeatureType {
    Enum,
    Integer,
    Boolean,
    List,
}

/// One registry key: its type and allowed values (integers as text).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FeatureSpec {
    pub kind: FeatureType,
    pub values: &'static [&'static str],
}

const fn spec(kind: FeatureType, values: &'static [&'static str]) -> FeatureSpec {
    FeatureSpec { kind, values }
}

/// The typed feature registry, in registry order (protocol.md §5.9.4).
pub const FEATURE_REGISTRY: &[(&str, FeatureSpec)] = {
    use FeatureType::*;
    &[
        ("shell", spec(Enum, &["hard", "soft", "hybrid"])),
        ("wheels", spec(Integer, &["0", "2", "4", "8"])),
        (
            "lock",
            spec(
                Enum,
                &["none", "combination", "tsa_combination", "tsa_key", "key"],
            ),
        ),
        ("expandable", spec(Boolean, &[])),
        (
            "closure",
            spec(
                Enum,
                &[
                    "zip",
                    "magnet",
                    "flap",
                    "buckle",
                    "drawstring",
                    "button",
                    "hook_and_loop",
                    "laces",
                    "slip_on",
                    "open",
                ],
            ),
        ),
        ("laptop_compartment", spec(Boolean, &[])),
        (
            "water_resistance",
            spec(Enum, &["none", "water_repellent", "waterproof"]),
        ),
        (
            "detachable_parts",
            spec(
                List,
                &[
                    "shoulder_strap",
                    "handle",
                    "lining",
                    "insole",
                    "hood",
                    "belt",
                    "pouch",
                    "wheels",
                ],
            ),
        ),
        (
            "adjustable_parts",
            spec(List, &["shoulder_strap", "waist", "hem", "cuff"]),
        ),
        (
            "fit",
            spec(Enum, &["slim", "regular", "relaxed", "oversized"]),
        ),
        (
            "sleeve_length",
            spec(Enum, &["sleeveless", "short", "three_quarter", "long"]),
        ),
        (
            "neckline",
            spec(
                Enum,
                &[
                    "crew",
                    "v_neck",
                    "collar",
                    "hood",
                    "turtleneck",
                    "boat",
                    "scoop",
                ],
            ),
        ),
    ]
};

/// The registry keys in registry order.
pub const FEATURE_KEYS: &[&str] = &[
    "shell",
    "wheels",
    "lock",
    "expandable",
    "closure",
    "laptop_compartment",
    "water_resistance",
    "detachable_parts",
    "adjustable_parts",
    "fit",
    "sleeve_length",
    "neckline",
];

/// The registry entry of a feature key.
pub fn feature_spec(key: &str) -> Option<&'static FeatureSpec> {
    FEATURE_REGISTRY
        .iter()
        .find(|(k, _)| *k == key)
        .map(|(_, s)| s)
}

/// Turns a 0.1 fibre key `recycled_<fibre>` or `organic_<fibre>` into the
/// material and its qualifiers (protocol.md §5.9.1): `recycled_polyester` →
/// (`polyester`, `[recycled]`); combined prefixes in the order written
/// (`recycled_organic_cotton` → (`cotton`, `[recycled, organic]`)).
pub fn normalize_material(key: &str) -> (String, Vec<String>) {
    let mut key = key;
    let mut qualifiers = Vec::new();
    loop {
        let q = if key.len() > "recycled_".len() && key.starts_with("recycled_") {
            "recycled"
        } else if key.len() > "organic_".len() && key.starts_with("organic_") {
            "organic"
        } else {
            return (key.to_string(), qualifiers);
        };
        key = &key[q.len() + 1..];
        append_qualifier(&mut qualifiers, q);
    }
}

/// A parsed `footwear_materials` cell; a part that is not stated is `None`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct Footwear {
    pub upper: Option<String>,
    pub lining_and_sock: Option<String>,
    pub outer_sole: Option<String>,
}

impl Footwear {
    /// The document value: `{"upper":…,"lining_and_sock":…,"outer_sole":…}`
    /// with `null` for a part that is not stated.
    pub fn to_json(&self) -> Value {
        json!({ "upper": self.upper, "lining_and_sock": self.lining_and_sock, "outer_sole": self.outer_sole })
    }
}

/// Parses `"upper: leather; lining_and_sock: textile; outer_sole: other"`
/// (parts and values lowercased, spaces → `_`).
pub fn parse_footwear_materials(s: &str) -> Result<Footwear> {
    let mut out = Footwear::default();
    let mut any = false;
    for raw in s.split(';') {
        let raw = raw.trim();
        if raw.is_empty() {
            continue;
        }
        let Some((name, value)) = raw.split_once(':') else {
            return Err(Error::new(format!(
                "{}: expected \"<part>: <material>\" with part upper, lining_and_sock or outer_sole",
                quote(raw)
            )));
        };
        let (part, v) = (key(name), key(value));
        if !FOOTWEAR_PARTS.contains(&part.as_str()) {
            return Err(Error::new(format!(
                "{} is not a footwear part (upper, lining_and_sock, outer_sole)",
                quote(name.trim())
            )));
        }
        if !FOOTWEAR_VALUES.contains(&v.as_str()) {
            return Err(Error::new(format!(
                "{} is not a footwear material (leather, coated_leather, textile, other)",
                quote(value.trim())
            )));
        }
        let slot = match part.as_str() {
            "upper" => &mut out.upper,
            "lining_and_sock" => &mut out.lining_and_sock,
            _ => &mut out.outer_sole,
        };
        if slot.is_some() {
            return Err(Error::new(format!("part {part} appears twice")));
        }
        *slot = Some(v);
        any = true;
    }
    if !any {
        return Err(Error::new("no footwear materials found"));
    }
    Ok(out)
}

/// One parsed certification; `licence` is `None` without a licence number.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Certification {
    pub scheme: String,
    #[serde(rename = "licence_number")]
    pub licence: Option<String>,
    pub scope: String,
}

impl Certification {
    /// The document value: `{"scheme":…,"licence_number":…|null,"scope":…}`.
    pub fn to_json(&self) -> Value {
        json!({ "scheme": self.scheme, "licence_number": self.licence, "scope": self.scope })
    }
}

static SCOPE_SUFFIX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)[\t\n\x0C\r ]*\((material|product)\)[\t\n\x0C\r ]*$").unwrap()
});

/// Parses `"gots:CU 123456; rws:CU 200101 (material)"`. The scheme is a key;
/// the licence number is everything after the first `:` (none without `:`
/// or when empty); the scope is product unless `(material)` is given.
pub fn parse_certifications(s: &str) -> Result<Vec<Certification>> {
    let mut out = Vec::new();
    for raw in s.split(';') {
        let mut raw = raw.trim();
        if raw.is_empty() {
            continue;
        }
        let mut scope = "product".to_string();
        if let Some(m) = SCOPE_SUFFIX.captures(raw) {
            scope = m[1].to_lowercase();
            raw = raw[..raw.len() - m[0].len()].trim();
        }
        let (scheme, licence) = raw.split_once(':').unwrap_or((raw, ""));
        let scheme_key = key(scheme);
        if !valid_key(&scheme_key) {
            return Err(Error::new(format!(
                "certification scheme {} is not a key such as gots or oeko_tex_standard_100",
                quote(scheme.trim())
            )));
        }
        let licence = licence.trim();
        if licence.chars().count() > 200 {
            return Err(Error::new(format!(
                "the licence number of {scheme_key} is longer than 200 characters"
            )));
        }
        out.push(Certification {
            scheme: scheme_key,
            licence: (!licence.is_empty()).then(|| licence.to_string()),
            scope,
        });
    }
    if out.is_empty() {
        return Err(Error::new("no certifications found"));
    }
    Ok(out)
}

static MEASUREMENT_NUMBER: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^([0-9]+([.,][0-9]+)?|[.,][0-9]+)$").unwrap());

/// Parses a positive number with `.` or `,` as decimal separator, without
/// thousands separator or unit (`"2.6"`, `"2,6"`).
pub fn parse_measurement(s: &str) -> Result<f64> {
    let s = s.trim();
    if !MEASUREMENT_NUMBER.is_match(s) {
        return Err(Error::new(format!(
            "{} is not a number (for example 2.6 or 2,6, without unit)",
            quote(s)
        )));
    }
    let mut t = s.replacen(',', ".", 1);
    if t.starts_with('.') {
        t.insert(0, '0');
    }
    match t.parse::<f64>() {
        Ok(v) if v > 0.0 && v.is_finite() => Ok(v),
        _ => Err(Error::new(format!("{} is not a positive number", quote(s)))),
    }
}

/// Parses `"min-max"` (`80-130`) or one number for a strap that cannot be
/// adjusted (`120` = `120-120`).
pub fn parse_strap_length(s: &str) -> Result<(f64, f64)> {
    let s = s.trim();
    let Some((lo, hi)) = s.split_once('-') else {
        let v = parse_measurement(s)?;
        return Ok((v, v));
    };
    let wrap = |e: Error| {
        Error::new(format!(
            "{}: {e} (use min-max, for example 80-130)",
            quote(s)
        ))
    };
    let min = parse_measurement(lo).map_err(wrap)?;
    let max = parse_measurement(hi).map_err(wrap)?;
    if min > max {
        return Err(Error::new(format!(
            "{}: the shortest setting comes first (min-max, for example 80-130)",
            quote(s)
        )));
    }
    Ok((min, max))
}

/// Lowercases a colour family; `gray` and `multicolor` are accepted for
/// `grey` and `multicolour`.
pub fn parse_color_family(s: &str) -> Result<String> {
    let v = s.trim().to_lowercase();
    let v = match v.as_str() {
        "gray" => "grey".to_string(),
        "multicolor" => "multicolour".to_string(),
        _ => v,
    };
    if !COLOR_FAMILIES.contains(&v.as_str()) {
        return Err(Error::new(format!(
            "{} is not a colour family ({})",
            quote(s.trim()),
            COLOR_FAMILIES.join(", ")
        )));
    }
    Ok(v)
}

/// Parses the cell of a `feature:<key>` column into its JSON value: for a
/// registry key a value of its type (enum → string key, integer → number,
/// boolean → bool, list → array of string keys without duplicates),
/// anything else is an error; a key outside the registry keeps the cell as
/// a string.
pub fn parse_feature(key_name: &str, s: &str) -> Result<Value> {
    let s = s.trim();
    let Some(spec) = feature_spec(key_name) else {
        return Ok(Value::String(s.to_string()));
    };
    let not_one_of = |v: &str| {
        Error::new(format!(
            "{} is not one of {}",
            quote(v),
            spec.values.join(", ")
        ))
    };
    match spec.kind {
        FeatureType::Enum => {
            let v = key(s);
            if !spec.values.contains(&v.as_str()) {
                return Err(not_one_of(s));
            }
            Ok(Value::String(v))
        }
        FeatureType::Integer => {
            // Go strconv.Atoi without a sign: digits only.
            let n = s
                .parse::<i64>()
                .ok()
                .filter(|_| !s.contains(['+', '-']))
                .filter(|n| spec.values.contains(&n.to_string().as_str()))
                .ok_or_else(|| not_one_of(s))?;
            Ok(Value::from(n))
        }
        FeatureType::Boolean => parse_bool(s)
            .map(Value::Bool)
            .ok_or_else(|| Error::new(format!("{} is not yes or no", quote(s)))),
        FeatureType::List => {
            let mut list = Vec::new();
            for raw in s.split('|') {
                let v = key(raw);
                if v.is_empty() {
                    continue;
                }
                if !spec.values.contains(&v.as_str()) {
                    return Err(not_one_of(raw.trim()));
                }
                if !list.contains(&v) {
                    list.push(v);
                }
            }
            if list.is_empty() {
                return Err(Error::new(format!(
                    "{} is not a list of {}",
                    quote(s),
                    spec.values.join(", ")
                )));
            }
            Ok(Value::Array(list.into_iter().map(Value::String).collect()))
        }
    }
}

/// Writes a number with `.` and without trailing zeros (Go
/// `strconv.FormatFloat(v, 'f', -1, 64)`).
pub fn format_number(v: f64) -> String {
    if v.is_infinite() {
        return if v > 0.0 {
            "+Inf".into()
        } else {
            "-Inf".into()
        };
    }
    format!("{v}")
}

/// Writes a feature value as [`parse_feature`] reads it.
pub fn format_feature(v: &Value) -> String {
    match v {
        Value::Null => String::new(),
        Value::Bool(true) => "yes".into(),
        Value::Bool(false) => "no".into(),
        Value::Array(xs) => xs.iter().map(format_feature).collect::<Vec<_>>().join("|"),
        Value::Number(n) => match (n.as_i64(), n.as_u64(), n.as_f64()) {
            (Some(i), _, _) => i.to_string(),
            (_, Some(u), _) => u.to_string(),
            (_, _, Some(f)) => format_number(f),
            _ => n.to_string(),
        },
        Value::String(s) => s.clone(),
        Value::Object(_) => v.to_string(),
    }
}

/// The feature keys of an export: every registry key, then the other keys
/// of the exported products, sorted.
pub fn feature_columns<'a>(other: impl IntoIterator<Item = &'a str>) -> Vec<String> {
    let extra: BTreeSet<&str> = other
        .into_iter()
        .filter(|k| feature_spec(k).is_none())
        .collect();
    FEATURE_KEYS
        .iter()
        .copied()
        .chain(extra)
        .map(String::from)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::importfmt::normalize_header;

    #[test]
    fn article_data_cells() {
        assert_eq!(
            normalize_header("Feature:Detachable Parts"),
            "feature:detachable_parts"
        );
        assert_eq!(normalize_header("Colour Family"), "color_family");
        let f =
            parse_footwear_materials("upper: Leather; lining_and_sock: coated leather").unwrap();
        assert_eq!(
            f,
            Footwear {
                upper: Some("leather".into()),
                lining_and_sock: Some("coated_leather".into()),
                outer_sole: None
            }
        );
        assert_eq!(
            f.to_json(),
            json!({ "upper": "leather", "lining_and_sock": "coated_leather", "outer_sole": null })
        );
        for bad in [
            "upper: plastic",
            "heel: leather",
            "upper leather",
            "upper: leather; upper: other",
            " ; ",
        ] {
            assert!(parse_footwear_materials(bad).is_err(), "{bad:?} accepted");
        }
        let cs = parse_certifications("GOTS:CU 123456; rws:CU 200101 (material); fsc").unwrap();
        let c = |s: &str, l: Option<&str>, sc: &str| Certification {
            scheme: s.into(),
            licence: l.map(String::from),
            scope: sc.into(),
        };
        assert_eq!(
            cs,
            [
                c("gots", Some("CU 123456"), "product"),
                c("rws", Some("CU 200101"), "material"),
                c("fsc", None, "product")
            ]
        );
        assert_eq!(
            cs[2].to_json(),
            json!({ "scheme": "fsc", "licence_number": null, "scope": "product" })
        );
        assert!(parse_certifications(";").is_err());
        assert!(parse_certifications("9x:1").is_err());
        for (input, want) in [("2.6", 2.6), ("2,7", 2.7), ("55", 55.0), (".5", 0.5)] {
            assert_eq!(parse_measurement(input), Ok(want), "{input}");
        }
        for bad in ["30 cm", "0", "-2", "1.000,5", "2.6kg", ""] {
            assert!(parse_measurement(bad).is_err(), "{bad:?} accepted");
        }
        assert_eq!(parse_strap_length("80-130"), Ok((80.0, 130.0)));
        assert_eq!(parse_strap_length("120"), Ok((120.0, 120.0)));
        assert!(parse_strap_length("130-80").is_err());
        assert_eq!(parse_color_family("Gray").as_deref(), Ok("grey"));
        assert!(parse_color_family("navy").is_err());
        let cases = [
            ("wheels", "4", "4"),
            ("wheels", "3", ""),
            ("shell", "Hard", "hard"),
            ("lock", "TSA combination", "tsa_combination"),
            ("expandable", "yes", "yes"),
            ("expandable", "maybe", ""),
            (
                "detachable_parts",
                "shoulder_strap|Lining|lining",
                "shoulder_strap|lining",
            ),
            ("detachable_parts", "strap", ""),
            ("handle_type", "Padded", "Padded"),
            ("wheels", "+4", ""),
        ];
        for (k, cell, want) in cases {
            let v = parse_feature(k, cell);
            if want.is_empty() {
                assert!(v.is_err(), "{k}={cell:?} accepted");
                continue;
            }
            assert_eq!(format_feature(&v.unwrap()), want, "{k}={cell:?}");
        }
        assert_eq!(parse_feature("wheels", "4").unwrap(), json!(4));
        assert_eq!(parse_feature("expandable", "no").unwrap(), json!(false));
    }

    #[test]
    fn normalize_materials_and_columns() {
        assert_eq!(
            normalize_material("recycled_organic_cotton"),
            ("cotton".into(), vec!["recycled".into(), "organic".into()])
        );
        assert_eq!(
            normalize_material("recycled_"),
            ("recycled_".into(), vec![])
        );
        assert_eq!(
            normalize_material("recycled_recycled_x"),
            ("x".into(), vec!["recycled".into()])
        );
        let cols = feature_columns(["zeta", "alpha", "wheels", "alpha"]);
        assert_eq!(cols.len(), FEATURE_KEYS.len() + 2);
        assert_eq!(&cols[FEATURE_KEYS.len()..], ["alpha", "zeta"]);
        assert_eq!(
            FEATURE_KEYS,
            FEATURE_REGISTRY.iter().map(|(k, _)| *k).collect::<Vec<_>>()
        );
        assert_eq!(format_number(2.6), "2.6");
        assert_eq!(format_number(120.0), "120");
        assert_eq!(format_number(1e21), "1000000000000000000000");
        assert_eq!(format_feature(&json!(2.5)), "2.5");
    }
}
