//! CSV files and header names (import-format.md §1.1, §1.3).

use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::LazyLock;

use regex::Regex;

use crate::error::{Error, Result};

/// A parsed CSV file.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Table {
    /// Normalised column names.
    pub header: Vec<String>,
    /// The header as written.
    pub raw: Vec<String>,
    pub rows: Vec<Row>,
}

/// One data row; `num` is 1-based (header = row 0).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Row {
    pub num: usize,
    pub values: HashMap<String, String>,
}

impl Row {
    /// The trimmed cell of a column (`""` when absent).
    pub fn get(&self, col: &str) -> &str {
        self.values.get(col).map(String::as_str).unwrap_or("")
    }
}

impl Table {
    /// Reports whether the table has a column.
    pub fn has(&self, col: &str) -> bool {
        self.header.iter().any(|h| h == col)
    }
}

fn alias(base: &str) -> Option<&'static str> {
    Some(match base {
        "style" => "style_number",
        "ean" | "barcode" => "gtin",
        "colour_code" | "colour" => "color_code",
        "colour_name" => "color_name",
        "colour_family" => "color_family",
        _ => return None,
    })
}

/// The white space of header names (§1.1): space, tab, CR, LF.
const HEADER_SPACE: &[char] = &[' ', '\t', '\r', '\n'];

/// Trims the white space of §1.1 (space, tab, CR, LF) from a header name.
pub fn trim_header(h: &str) -> &str {
    h.trim_matches(HEADER_SPACE)
}

static HEADER_RUN_RE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"[ \t\r\n-]+").unwrap());

/// The §1.1 normalisation of a name: trimmed, lowercase, each run of white
/// space and '-' one '_'.
pub(crate) fn header_name(h: &str) -> String {
    HEADER_RUN_RE
        .replace_all(&trim_header(h).to_lowercase(), "_")
        .into_owned()
}

/// Normalises a column name (§1.1): trimmed, case-insensitive, each run of
/// white space and '-' becomes one '_', aliases resolved, language suffixes
/// (`name:de-CH`) keep their tag form.
pub fn normalize_header(h: &str) -> String {
    let h = trim_header(h.strip_prefix('\u{feff}').unwrap_or(h));
    let (base, lang) = match h.split_once(':') {
        Some((b, l)) => (b, Some(l)),
        None => (h, None),
    };
    let mut base = header_name(base);
    if let Some(a) = alias(&base) {
        base = a.to_string();
    }
    let Some(lang) = lang else { return base };
    let lang = lang.trim();
    if base == "attr" || base == "feature" {
        return format!("{base}:{}", header_name(lang));
    }
    format!("{base}:{}", normalize_lang(lang))
}

/// Gives a language tag its canonical case (LocalizedText): language
/// lowercase, a four-letter script title case (Hant), a region uppercase
/// (CH) or digits (419); `_` is read as `-`.
pub fn normalize_lang(l: &str) -> String {
    let l = l.trim().replace('_', "-");
    l.split('-')
        .enumerate()
        .map(|(i, p)| {
            if i == 0 {
                p.to_lowercase()
            } else if p.len() == 4 && p.bytes().all(|b| b.is_ascii_alphabetic()) {
                format!("{}{}", p[..1].to_uppercase(), p[1..].to_lowercase())
            } else {
                p.to_uppercase()
            }
        })
        .collect::<Vec<_>>()
        .join("-")
}

static LANG_TAG_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[a-z]{2,3}(-[A-Z][a-z]{3})?(-([A-Z]{2}|[0-9]{3}))?$").unwrap());

/// Reports whether `l` is a language tag in canonical form: language,
/// optional script, optional region (Common.json LanguageTag).
pub fn valid_lang(l: &str) -> bool {
    LANG_TAG_RE.is_match(l)
}

/// Picks `,` or `;` (or tab) from the header line: whichever occurs more
/// often outside quotes; ties give `,`.
pub fn detect_delimiter(header_line: &str) -> u8 {
    let (mut comma, mut semi, mut tab) = (0usize, 0usize, 0usize);
    let mut in_q = false;
    for b in header_line.bytes() {
        match b {
            b'"' => in_q = !in_q,
            b',' if !in_q => comma += 1,
            b';' if !in_q => semi += 1,
            b'\t' if !in_q => tab += 1,
            _ => {}
        }
    }
    let (mut best, mut n) = (b',', comma);
    if semi > n {
        (best, n) = (b';', semi);
    }
    if tab > n {
        best = b'\t';
    }
    best
}

/// Reads a canonical CSV (UTF-8 with or without BOM, RFC 4180, `,`, `;` or
/// tab delimited) the way Go's `encoding/csv` does with `LazyQuotes` and a
/// variable number of fields: empty lines are skipped, CR before LF is
/// dropped (also inside quoted fields), a lone CR is data.
pub fn parse_csv(data: &[u8]) -> Result<Table> {
    let data = data.strip_prefix(b"\xef\xbb\xbf").unwrap_or(data);
    let text = std::str::from_utf8(data).map_err(|_| Error::new("the file is not UTF-8 text"))?;
    let first = match text.find(['\r', '\n']) {
        Some(i) => &text[..i],
        None => text,
    };
    if first.trim().is_empty() {
        return Err(Error::new("the file has no header row"));
    }
    let mut rdr = csv::ReaderBuilder::new()
        .has_headers(false)
        .flexible(true)
        .delimiter(detect_delimiter(first))
        .terminator(csv::Terminator::Any(b'\n'))
        .from_reader(data);
    let mut records: Vec<Vec<String>> = Vec::new();
    for rec in rdr.records() {
        let rec = rec.map_err(|e| {
            if records.is_empty() {
                Error::new(format!("the header row cannot be read: {e}"))
            } else {
                Error::new(format!("row {} cannot be read: {e}", records.len()))
            }
        })?;
        // A line that is only "\r" is the empty line of a CRLF file.
        if rec.len() == 1 && &rec[0] == "\r" {
            let start = rec.position().map(|p| p.byte() as usize).unwrap_or(0);
            if data.get(start) == Some(&b'\r') {
                continue;
            }
        }
        let n = rec.len();
        let fields = rec
            .iter()
            .enumerate()
            .map(|(i, f)| {
                let mut f = f.replace("\r\n", "\n");
                if i + 1 == n && f.ends_with('\r') {
                    f.pop();
                }
                f
            })
            .collect();
        records.push(fields);
    }
    if records.is_empty() {
        return Err(Error::new("the file has no header row"));
    }
    Ok(new_table(records))
}

/// Builds a table from rows that are already split into fields, header
/// first (an Excel workbook, import-format.md §5.3). The rows are treated
/// exactly as the same rows in a CSV file.
pub fn table_from_records(records: Vec<Vec<String>>) -> Result<Table> {
    let Some(header) = records.first() else {
        return Err(Error::new("the file has no header row"));
    };
    let first = String::from_utf8(canonical_csv(std::slice::from_ref(header))).unwrap_or_default();
    let first = match first.find(['\r', '\n']) {
        Some(i) => &first[..i],
        None => &first[..],
    };
    if first.trim().is_empty() {
        return Err(Error::new("the file has no header row"));
    }
    Ok(new_table(records))
}

/// Writes rows as canonical CSV (§5.3): `,`, CRLF after every row, a field
/// quoted only when it contains `,`, `"`, CR or LF.
pub fn canonical_csv(rows: &[Vec<String>]) -> Vec<u8> {
    let mut b = String::new();
    for r in rows {
        for (i, f) in r.iter().enumerate() {
            if i > 0 {
                b.push(',');
            }
            if f.contains([',', '"', '\r', '\n']) {
                b.push('"');
                b.push_str(&f.replace('"', "\"\""));
                b.push('"');
            } else {
                b.push_str(f);
            }
        }
        b.push_str("\r\n");
    }
    b.into_bytes()
}

fn new_table(mut records: Vec<Vec<String>>) -> Table {
    let raw = records.remove(0);
    let header: Vec<String> = raw.iter().map(|h| normalize_header(h)).collect();
    let mut rows = Vec::new();
    for (num, rec) in records.into_iter().enumerate() {
        let mut empty = true;
        let mut vals: HashMap<String, String> = HashMap::new();
        for (i, v) in rec.iter().enumerate() {
            let v = v.trim();
            if !v.is_empty() {
                empty = false;
            }
            if let Some(h) = header.get(i).filter(|h| !h.is_empty())
                && (!vals.contains_key(h) || !v.is_empty())
            {
                vals.insert(h.clone(), v.to_string());
            }
        }
        if empty {
            continue;
        }
        rows.push(Row {
            num: num + 1,
            values: vals,
        });
    }
    Table { header, raw, rows }
}

/// Collects `<base>` and `<base>:<lang>` columns of a row into a map; the
/// plain column is `default_lang` (a tagged column wins). `None` when empty.
pub fn localized(
    r: &Row,
    header: &[String],
    base: &str,
    default_lang: &str,
) -> Option<BTreeMap<String, String>> {
    let mut out = BTreeMap::new();
    let v = r.get(base);
    if !v.is_empty() {
        out.insert(default_lang.to_string(), v.to_string());
    }
    let prefix = format!("{base}:");
    for h in header {
        if let Some(lang) = h.strip_prefix(&prefix).filter(|l| valid_lang(l)) {
            let v = r.get(h);
            if !v.is_empty() {
                out.insert(lang.to_string(), v.to_string());
            }
        }
    }
    (!out.is_empty()).then_some(out)
}

/// The products.csv columns (without language suffixes).
pub const KNOWN_COLUMNS: &[&str] = &[
    "brand",
    "product_id",
    "style_number",
    "name",
    "description",
    "item_type",
    "target_group",
    "season",
    "collection",
    "gpc_brick",
    "materials",
    "care",
    "country_of_origin",
    "dpp_url",
    "status",
    "variant_id",
    "gtin",
    "sku",
    "color_code",
    "color_name",
    "supplier_color",
    "size",
    "size_system",
    "variant_status",
    "image_files",
    // 0.2 article data (import-format.md §1.6)
    "item_subtype",
    "contains_animal_origin",
    "footwear_materials",
    "certifications",
    "color_family",
    "size_length",
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

/// The assets.csv columns.
pub const KNOWN_ASSET_COLUMNS: &[&str] = &[
    "file",
    "asset_id",
    "product_id",
    "style_number",
    "color_code",
    "position",
    "role",
    "view",
    "alt_text",
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
    "c2pa_manifest_url",
    "generator",
    "status",
];

/// Lists header columns that are not part of the format (`known` is
/// [`KNOWN_COLUMNS`] or [`KNOWN_ASSET_COLUMNS`]), each once, in header order.
pub fn unknown_columns(header: &[String], known: &[&str]) -> Vec<String> {
    let mut out = Vec::new();
    let mut seen = HashSet::new();
    for h in header {
        let mut base = h.as_str();
        if let Some((b, lang)) = h.split_once(':') {
            base = b;
            if b != "attr" && b != "feature" && !valid_lang(lang) {
                base = h; // a language tag of another form is an unknown column
            }
        }
        if h.is_empty()
            || known.contains(&base)
            || h.starts_with("attr:")
            || h.starts_with("feature:")
            || seen.contains(h.as_str())
        {
            continue;
        }
        seen.insert(h.as_str());
        out.push(h.clone());
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_csv_go_case() {
        let data = b"\xef\xbb\xbfStyle Number;Name:EN;Colour-Code;attr:Fit Type\r\n\"MN-1\";\"Sweater; \"\"soft\"\"\";NVY;slim\r\n;;;\r\n";
        let tb = parse_csv(data).unwrap();
        assert_eq!(
            tb.header,
            ["style_number", "name:en", "color_code", "attr:fit_type"]
        );
        assert_eq!(tb.raw[0], "Style Number");
        assert_eq!(tb.rows.len(), 1);
        assert_eq!(tb.rows[0].get("name:en"), r#"Sweater; "soft""#);
        assert_eq!(tb.rows[0].num, 1);
    }

    #[test]
    fn parse_csv_line_endings_and_numbers() {
        // Empty lines (LF and CRLF) are not records; a quoted CRLF is LF.
        let tb = parse_csv(b"a,b\r\n\r\n\n1,\"x\r\ny\"\r\n\"\",\r\n3,z\n").unwrap();
        assert_eq!(tb.raw, ["a", "b"]);
        assert_eq!(tb.rows.len(), 2);
        assert_eq!(tb.rows[0].num, 1);
        assert_eq!(tb.rows[0].get("b"), "x\ny");
        assert_eq!(tb.rows[1].num, 3);
        assert_eq!(tb.rows[1].get("b"), "z");
        // Duplicate columns: a later non-empty cell wins, an empty one does not.
        let tb = parse_csv(b"a,a,a\n1,2,\n").unwrap();
        assert_eq!(tb.rows[0].get("a"), "2");
        // Tabs and ties.
        assert_eq!(detect_delimiter("a\tb\tc,d"), b'\t');
        assert_eq!(detect_delimiter("a;b,c"), b',');
        assert_eq!(detect_delimiter("\"a;b\",c"), b',');
        assert!(parse_csv(b"\n\na,b").is_err());
        assert!(parse_csv(b"").is_err());
        assert!(parse_csv(b"a,\xff").is_err());
        assert!(parse_csv(b"\xef\xbb\xbf   \r\nx").is_err());
    }

    #[test]
    fn records_and_canonical_csv() {
        let rows = vec![
            vec!["Style".to_string(), "Name".to_string(), String::new()],
            vec!["MN-1".to_string(), "a, \"b\"".to_string(), "x".to_string()],
        ];
        assert_eq!(
            canonical_csv(&rows),
            b"Style,Name,\r\nMN-1,\"a, \"\"b\"\"\",x\r\n"
        );
        let t = table_from_records(rows).unwrap();
        assert_eq!(t.header, ["style_number", "name", ""]);
        assert_eq!(t.rows[0].get("name"), "a, \"b\"");
        assert!(!t.rows[0].values.contains_key(""));
        assert!(table_from_records(vec![]).is_err());
        assert!(table_from_records(vec![vec![" ".into()]]).is_err());
        // " ," is a header line with two (empty) names, as in Go.
        assert!(table_from_records(vec![vec![" ".into(), "".into()]]).is_ok());
    }

    #[test]
    fn localized_columns() {
        let t = parse_csv(b"name,name:nl,name:english\nA,B,C\nD,,\n").unwrap();
        let m = localized(&t.rows[0], &t.header, "name", "en").unwrap();
        assert_eq!(m.len(), 2);
        assert_eq!(m["en"], "A");
        assert_eq!(m["nl"], "B");
        let t2 = parse_csv(b"name,name:en\nA,B\n").unwrap();
        assert_eq!(
            localized(&t2.rows[0], &t2.header, "name", "en").unwrap()["en"],
            "B"
        );
        assert_eq!(localized(&t.rows[1], &t.header, "description", "en"), None);
    }

    #[test]
    fn language_tags() {
        for (input, want) in [
            ("NL", "nl"),
            ("de_ch", "de-CH"),
            ("ZH_hant", "zh-Hant"),
            ("sr-latn-rs", "sr-Latn-RS"),
            ("es-419", "es-419"),
        ] {
            let got = normalize_lang(input);
            assert_eq!(got, want, "{input}");
            assert!(valid_lang(&got), "{input}");
        }
        assert_eq!(normalize_header("Name:ZH_hant"), "name:zh-Hant");
        for bad in ["nl-x-private", "english", "de-CH-1996"] {
            assert!(!valid_lang(&normalize_lang(bad)), "{bad}");
        }
        let header = vec!["name:zh-Hant".to_string(), "name:english".to_string()];
        assert_eq!(unknown_columns(&header, KNOWN_COLUMNS), ["name:english"]);
        let header: Vec<String> = ["foo", "", "attr:x", "feature:y", "foo", "file"]
            .map(String::from)
            .into();
        assert_eq!(unknown_columns(&header, KNOWN_COLUMNS), ["foo", "file"]);
        assert_eq!(unknown_columns(&header, KNOWN_ASSET_COLUMNS), ["foo"]);
    }

    #[test]
    fn headers() {
        assert_eq!(
            normalize_header("\u{feff} Style  -  Number\t"),
            "style_number"
        );
        assert_eq!(normalize_header("EAN"), "gtin");
        assert_eq!(normalize_header("Colour Name: NL"), "color_name:nl");
        assert_eq!(
            normalize_header("Feature:Detachable Parts"),
            "feature:detachable_parts"
        );
        assert_eq!(normalize_header("Colour Family"), "color_family");
        assert_eq!(normalize_header("  "), "");
    }
}
