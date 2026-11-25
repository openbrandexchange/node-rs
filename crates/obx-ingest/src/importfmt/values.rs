//! Cell values: booleans, dates, keys, slugs, materials (§1.4), care codes
//! (§1.5) and GTIN cells.

use std::sync::LazyLock;

use chrono::{FixedOffset, NaiveDate, NaiveDateTime, NaiveTime, TimeZone, Utc};
use regex::Regex;
use serde::Serialize;
use serde_json::{Map, Value, json};
use unicode_normalization::UnicodeNormalization;
use unicode_normalization::char::is_combining_mark;

use super::article::normalize_material;
use crate::error::{Error, Result, quote};
use crate::vocab;

/// Accepts true/false, yes/no, ja/nee, 1/0, y/n, j (case-insensitive).
pub fn parse_bool(s: &str) -> Option<bool> {
    match s.trim().to_lowercase().as_str() {
        "true" | "yes" | "ja" | "1" | "y" | "j" => Some(true),
        "false" | "no" | "nee" | "0" | "n" => Some(false),
        _ => None,
    }
}

static RFC3339_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^([0-9]{4})-([0-9]{2})-([0-9]{2})T([0-9]{2}):([0-9]{2}):([0-9]{2})(?:[.,]([0-9]+))?(?:(Z)|([+-])([0-9]{2}):([0-9]{2}))$").unwrap()
});
static DATE_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^([0-9]{4})-([0-9]{2})-([0-9]{2})$").unwrap());

/// Accepts RFC 3339 or `YYYY-MM-DD` (midnight UTC) and returns the instant
/// in UTC as Go's RFC3339Nano writes it (`2030-01-01T00:00:00Z`, fraction
/// without trailing zeros).
pub fn parse_date(s: &str) -> Option<String> {
    let s = s.trim();
    let num = |m: Option<regex::Match>| m.map_or(0, |m| m.as_str().parse::<u32>().unwrap_or(0));
    if let Some(c) = RFC3339_RE.captures(s) {
        let date = NaiveDate::from_ymd_opt(num(c.get(1)) as i32, num(c.get(2)), num(c.get(3)))?;
        let (h, mi, se) = (num(c.get(4)), num(c.get(5)), num(c.get(6)));
        if h > 23 || mi > 59 || se > 59 {
            return None;
        }
        let nanos = c.get(7).map_or(0, |f| {
            let mut d: String = f.as_str().chars().take(9).collect();
            while d.len() < 9 {
                d.push('0');
            }
            d.parse::<u32>().unwrap_or(0)
        });
        let naive = NaiveDateTime::new(date, NaiveTime::from_hms_nano_opt(h, mi, se, nanos)?);
        let offset = if c.get(8).is_some() {
            0
        } else {
            let (oh, om) = (num(c.get(10)), num(c.get(11)));
            if oh > 23 || om > 59 {
                return None;
            }
            let secs = (oh * 3600 + om * 60) as i32;
            if &c[9] == "-" { -secs } else { secs }
        };
        let t = FixedOffset::east_opt(offset)?
            .from_local_datetime(&naive)
            .single()?;
        return Some(format_rfc3339_nano(t.with_timezone(&Utc).naive_utc()));
    }
    let c = DATE_RE.captures(s)?;
    let date = NaiveDate::from_ymd_opt(num(c.get(1)) as i32, num(c.get(2)), num(c.get(3)))?;
    Some(format_rfc3339_nano(date.and_time(NaiveTime::MIN)))
}

fn format_rfc3339_nano(t: NaiveDateTime) -> String {
    use chrono::Timelike;
    let mut out = t.format("%Y-%m-%dT%H:%M:%S").to_string();
    let n = t.nanosecond();
    if n > 0 {
        let f = format!("{n:09}");
        out.push('.');
        out.push_str(f.trim_end_matches('0'));
    }
    out.push('Z');
    out
}

static KEY_RE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^[a-z][a-z0-9_]{0,63}$").unwrap());

/// Normalises an enum-like key (`"Organic Cotton"` → `"organic_cotton"`):
/// lowercase, runs of white space one `_`, `-` → `_`.
pub fn key(s: &str) -> String {
    s.trim()
        .to_lowercase()
        .split_whitespace()
        .collect::<Vec<_>>()
        .join("_")
        .replace('-', "_")
}

/// Reports whether `s` matches `^[a-z][a-z0-9_]{0,63}$`.
pub fn valid_key(s: &str) -> bool {
    KEY_RE.is_match(s)
}

/// The OBX slug rule: lowercase, diacritics removed, every run outside
/// a-z0-9 becomes `-`, trimmed.
pub fn slug(s: &str) -> String {
    let stripped: String = s.nfd().filter(|&c| !is_combining_mark(c)).nfc().collect();
    let mut b = String::new();
    let mut dash = false;
    for r in stripped.to_lowercase().chars() {
        if r.is_ascii_lowercase() || r.is_ascii_digit() {
            b.push(r);
            dash = false;
        } else if !dash {
            b.push('-');
            dash = true;
        }
    }
    b.trim_matches('-').to_string()
}

/// One fibre of a part, normalised (0.1 keys `recycled_<fibre>` and
/// `organic_<fibre>` become the material with that qualifier). `qualifiers`
/// are the fibre's qualifier codes in order, without repeats.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Fiber {
    pub material: String,
    /// `None`: not stated (`"outer: leather"`).
    pub percentage: Option<f64>,
    pub qualifiers: Vec<String>,
}

/// One material part.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Part {
    pub name: String,
    pub fibers: Vec<Fiber>,
}

static FIBER_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^([0-9]+(?:\.[0-9]+)?)[\t\n\x0C\r ]*%[\t\n\x0C\r ]*(.+)$").unwrap()
});
static DIGITS_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[0-9]+(?:\.[0-9]+)?[\t\n\x0C\r ]*%?$").unwrap());
static QUALIFIER_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"[\t\n\x0C\r ]*\(([^()]*)\)[\t\n\x0C\r ]*$").unwrap());

/// Splits a part on the commas outside brackets, so that
/// `"(organic, recycled)"` stays one fibre and can be refused as such.
fn split_fibers(s: &str) -> Vec<&str> {
    let mut out = Vec::new();
    let (mut depth, mut start) = (0usize, 0usize);
    for (i, r) in s.char_indices() {
        match r {
            '(' => depth += 1,
            ')' => depth = depth.saturating_sub(1),
            ',' if depth == 0 => {
                out.push(&s[start..i]);
                start = i + 1;
            }
            _ => {}
        }
    }
    out.push(&s[start..]);
    out
}

/// Adds `code` to `list` unless it is there already (a fibre names each
/// qualifier once; the first occurrence keeps its place).
pub fn append_qualifier(list: &mut Vec<String>, code: &str) {
    if !list.iter().any(|x| x == code) {
        list.push(code.to_string());
    }
}

/// Parses `"outer: 65% cotton, 35% polyamide; lining: 100% polyester
/// (recycled) (post_consumer)"` (import-format.md §1.4). Returns the parts
/// and warnings (none today: unknown codes and sums are checked by the
/// importer, rule 10).
pub fn parse_materials(s: &str) -> Result<(Vec<Part>, Vec<String>)> {
    let mut parts = Vec::new();
    for p in s.split(';') {
        let p = p.trim();
        if p.is_empty() {
            continue;
        }
        let (name, body) = match p.find(':') {
            Some(i) => (key(&p[..i]), &p[i + 1..]),
            None => ("main".to_string(), p),
        };
        if !valid_key(&name) {
            return Err(Error::new(format!("invalid part name {}", quote(&name))));
        }
        let mut part = Part {
            name,
            fibers: Vec::new(),
        };
        for f in split_fibers(body) {
            let f = f.trim();
            if f.is_empty() {
                continue;
            }
            // A fibre of digits only comes from a decimal comma
            // ("95,5% cotton" splits into "95" and "5% cotton").
            if DIGITS_RE.is_match(f) {
                return Err(Error::new(format!(
                    "decimal comma: {} is a number without a material; write percentages with a decimal point (95.5% cotton), the comma separates fibres",
                    quote(f)
                )));
            }
            let mut percentage = None;
            let mut rest = f;
            if let Some(m) = FIBER_RE.captures(f) {
                let pct: f64 = m[1].parse().unwrap_or(f64::NAN);
                if !(pct > 0.0 && pct <= 100.0) {
                    return Err(Error::new(format!("invalid percentage in {}", quote(f))));
                }
                percentage = Some(pct);
                rest = m.get(2).map_or("", |g| g.as_str());
            } else if f.contains('%') {
                return Err(Error::new(format!(
                    "{} is not like \"95% cotton\" or \"leather\"",
                    quote(f)
                )));
            }
            let mut brackets = Vec::new(); // right to left
            while let Some(qm) = QUALIFIER_RE.captures(rest) {
                if qm[1].contains(',') {
                    return Err(Error::new(format!(
                        "{}: one qualifier per bracket, e.g. \"(recycled) (post_consumer)\"",
                        quote(f)
                    )));
                }
                let q = key(&qm[1]);
                if !valid_key(&q) {
                    return Err(Error::new(format!(
                        "invalid qualifier {} in {}",
                        quote(&qm[1]),
                        quote(f)
                    )));
                }
                brackets.push(q);
                rest = &rest[..rest.len() - qm[0].len()];
            }
            let k = key(rest);
            if !valid_key(&k) {
                return Err(Error::new(format!("invalid material {}", quote(rest))));
            }
            let (material, mut qualifiers) = normalize_material(&k);
            for q in brackets.iter().rev() {
                append_qualifier(&mut qualifiers, q);
            }
            part.fibers.push(Fiber {
                material,
                percentage,
                qualifiers,
            });
        }
        if part.fibers.is_empty() {
            return Err(Error::new(format!(
                "part {} has no fibres",
                quote(&part.name)
            )));
        }
        parts.push(part);
    }
    Ok((parts, Vec::new()))
}

/// A JSON number as Go's encoding/json writes an `f64`: integral values
/// without a fraction (`65`, not `65.0`).
pub fn json_number(v: f64) -> Value {
    if v.fract() == 0.0 && v.abs() < 9.007_199_254_740_992e15 {
        Value::from(v as i64)
    } else {
        serde_json::Number::from_f64(v).map_or(Value::Null, Value::Number)
    }
}

/// The `materials` value node-go writes into a product document for parsed
/// parts: `[{"part":{"code":…},"fibers":[{"material":{"code":…},
/// "percentage":…,"qualifiers":[{"code":…}]}]}]` (`percentage` and
/// `qualifiers` left out when not stated; names are added by the write path).
pub fn materials_json(parts: &[Part]) -> Value {
    Value::Array(
        parts
            .iter()
            .map(|p| {
                let fibers: Vec<Value> = p
                    .fibers
                    .iter()
                    .map(|f| {
                        let mut fib = Map::new();
                        fib.insert("material".into(), json!({ "code": f.material }));
                        if let Some(pct) = f.percentage {
                            fib.insert("percentage".into(), json_number(pct));
                        }
                        if !f.qualifiers.is_empty() {
                            let qs = f.qualifiers.iter().map(|q| json!({ "code": q })).collect();
                            fib.insert("qualifiers".into(), Value::Array(qs));
                        }
                        Value::Object(fib)
                    })
                    .collect();
                json!({ "part": { "code": p.name }, "fibers": fibers })
            })
            .collect(),
    )
}

/// Reports whether `code` is a care code of the vocabulary (care.json).
pub fn is_care_code(code: &str) -> bool {
    vocab::care().has(code)
}

/// Parses `"wash_30|do_not_bleach"` into codes and warnings. Unknown codes
/// with a valid key are kept with a warning; others are errors.
pub fn parse_care(s: &str) -> Result<(Vec<String>, Vec<String>)> {
    let (mut codes, mut warnings) = (Vec::new(), Vec::new());
    for c in s.split('|') {
        let c = c.trim();
        if c.is_empty() {
            continue;
        }
        let k = key(c);
        if !valid_key(&k) {
            return Err(Error::new(format!("invalid care code {}", quote(c))));
        }
        if !is_care_code(&k) {
            warnings.push(format!("unknown care code {} kept", quote(&k)));
        }
        codes.push(k);
    }
    Ok((codes, warnings))
}

/// The `care` value node-go writes into a product document: `[{"code":…}]`.
pub fn care_json(codes: &[String]) -> Value {
    Value::Array(codes.iter().map(|c| json!({ "code": c })).collect())
}

/// Validates a GTIN cell: digits after removing white space; Excel
/// scientific notation is refused. Check digit and length are not checked.
pub fn gtin_cell(s: &str) -> Result<String> {
    let s: String = s.split_whitespace().collect();
    if s.contains(['e', 'E', '+', '.', ',']) {
        return Err(Error::new(format!(
            "{} looks like a number mangled by a spreadsheet; format the column as text",
            quote(&s)
        )));
    }
    if !s.bytes().all(|b| b.is_ascii_digit()) {
        return Err(Error::new(format!(
            "{} is not a GTIN (digits only)",
            quote(&s)
        )));
    }
    Ok(s)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fib(m: &str, pct: f64, qs: &[&str]) -> Fiber {
        Fiber {
            material: m.into(),
            percentage: (pct > 0.0).then_some(pct),
            qualifiers: qs.iter().map(|q| q.to_string()).collect(),
        }
    }

    fn first(s: &str) -> Fiber {
        parse_materials(s).unwrap().0[0].fibers[0].clone()
    }

    #[test]
    fn materials_and_care() {
        let (parts, warns) =
            parse_materials("outer: 65% Cotton, 35% polyamide; lining: 100% polyester").unwrap();
        assert!(
            parts.len() == 2 && parts[0].name == "outer" && parts[0].fibers[0].material == "cotton"
        );
        assert!(warns.is_empty());
        // 0.1 keys and qualifiers give the same normalised fibre.
        for input in [
            "90% organic cotton",
            "90% cotton (organic)",
            "90% Cotton (Organic)",
            "90% organic_cotton (organic)",
        ] {
            let (p, w) = parse_materials(input).unwrap();
            assert!(w.is_empty());
            assert_eq!(p[0].fibers[0], fib("cotton", 90.0, &["organic"]), "{input}");
        }
        let (p, _) = parse_materials("outer: 100% polyester (recycled) (Post-Consumer), 0.5% cotton (organic)(regenerative) (organic); lining: 100% recycled_polyamide (pre_consumer); trim: 100% Merino Wool (Regenerative)").unwrap();
        assert_eq!(
            p[0].fibers[0],
            fib("polyester", 100.0, &["recycled", "post_consumer"])
        );
        assert_eq!(
            p[0].fibers[1],
            fib("cotton", 0.5, &["organic", "regenerative"])
        );
        assert_eq!(
            p[1].fibers[0],
            fib("polyamide", 100.0, &["recycled", "pre_consumer"])
        );
        assert_eq!(p[2].fibers[0], fib("merino_wool", 100.0, &["regenerative"]));
        // The 0.1 key's qualifier comes first; combined prefixes in the order written.
        assert_eq!(
            first("100% recycled_polyester (post_consumer)"),
            fib("polyester", 100.0, &["recycled", "post_consumer"])
        );
        assert_eq!(
            first("100% organic_cotton (recycled)"),
            fib("cotton", 100.0, &["organic", "recycled"])
        );
        assert_eq!(
            first("100% recycled_organic_cotton"),
            fib("cotton", 100.0, &["recycled", "organic"])
        );
        assert!(first("100% cotton").qualifiers.is_empty());
        // One code per bracket: the comma separates fibres.
        for input in [
            "100% cotton (organic, recycled)",
            "50% cotton (organic,recycled), 50% wool",
            "100% cotton ()",
            "100% cotton (?!)",
            "100% cotton (organic",
        ] {
            assert!(parse_materials(input).is_err(), "{input}");
        }
        // A fibre without a percentage is null; decimal commas are refused.
        let (p, _) =
            parse_materials("outer: leather; lining: 60% cotton, polyester (recycled)").unwrap();
        assert_eq!(p[0].fibers[0], fib("leather", 0.0, &[]));
        assert_eq!(p[1].fibers[0], fib("cotton", 60.0, &[]));
        assert_eq!(p[1].fibers[1], fib("polyester", 0.0, &["recycled"]));
        assert_eq!(
            first("95.5% cotton, 4.5% elastane"),
            fib("cotton", 95.5, &[])
        );
        for input in [
            "95,5% cotton, 4,5% elastane",
            "main: 100",
            "lots % cotton",
            "0% cotton",
            "101% cotton",
        ] {
            let err = parse_materials(input).unwrap_err();
            if input.contains(",5") {
                assert!(err.message().starts_with("decimal comma"), "{input}: {err}");
            }
        }
        let (codes, warns) = parse_care("wash_30|Do Not Bleach|special_treatment").unwrap();
        assert_eq!(codes, ["wash_30", "do_not_bleach", "special_treatment"]);
        assert_eq!(warns, ["unknown care code \"special_treatment\" kept"]);
        assert!(parse_care("wash 30!").is_err());
        assert_eq!(care_json(&codes[..1]), json!([{ "code": "wash_30" }]));
    }

    #[test]
    fn materials_to_json() {
        let (p, _) = parse_materials("outer: 65% cotton (organic), leather").unwrap();
        assert_eq!(
            materials_json(&p),
            json!([{ "part": { "code": "outer" }, "fibers": [
                { "material": { "code": "cotton" }, "percentage": 65, "qualifiers": [{ "code": "organic" }] },
                { "material": { "code": "leather" } }
            ]}])
        );
        assert_eq!(serde_json::to_string(&json_number(95.5)).unwrap(), "95.5");
        assert_eq!(serde_json::to_string(&json_number(100.0)).unwrap(), "100");
    }

    #[test]
    fn gtin_cell_and_slug() {
        assert!(gtin_cell("2.00010010102E+12").is_err());
        assert_eq!(gtin_cell("2000 1001 01025").unwrap(), "2000100101025");
        assert!(gtin_cell("12a").is_err());
        assert_eq!(slug("NOOR ATELIER"), "noor-atelier");
        assert_eq!(slug("  Éclair & Co. "), "eclair-co");
    }

    #[test]
    fn bools_dates_keys() {
        assert_eq!(parse_bool(" Ja "), Some(true));
        assert_eq!(parse_bool("NEE"), Some(false));
        assert_eq!(parse_bool("maybe"), None);
        assert_eq!(
            parse_date("2030-01-01").as_deref(),
            Some("2030-01-01T00:00:00Z")
        );
        assert_eq!(
            parse_date("2030-01-01T00:00:00Z").as_deref(),
            Some("2030-01-01T00:00:00Z")
        );
        assert_eq!(
            parse_date("2030-01-01T01:30:00.500+02:00").as_deref(),
            Some("2029-12-31T23:30:00.5Z")
        );
        assert_eq!(
            parse_date("2030-01-01T00:00:00,25Z").as_deref(),
            Some("2030-01-01T00:00:00.25Z")
        );
        for bad in [
            "2030-02-30",
            "2030-1-01",
            "2030-01-01 00:00:00Z",
            "2030-01-01T00:00:60Z",
            "2030-01-01T24:00:00Z",
            "01-01-2030",
            "2030-01-01T00:00:00z",
            "2030-01-01T00:00:00",
        ] {
            assert_eq!(parse_date(bad), None, "{bad}");
        }
        assert_eq!(key(" Organic  Cotton-Blend "), "organic_cotton_blend");
        assert!(valid_key("a_1") && !valid_key("1a") && !valid_key(""));
    }
}
