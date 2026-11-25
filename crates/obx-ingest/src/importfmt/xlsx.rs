//! Excel workbooks (import-format.md §5, a node feature): an .xlsx file is
//! turned into the rows of products.csv or assets.csv, exactly as the spec
//! says, so every node gives the same rows, errors and row numbers. Port of
//! node-go `internal/importfmt/xlsx.go`.
//!
//! The package is read with the §5.6 limits checked from the central
//! directory before anything is inflated, and the inflated bytes counted.
//! The XML parts are read with a streaming parser: DOCTYPEs are refused and
//! only the five predefined entities exist. Nothing is calculated, run or
//! fetched, and no part is written to disk.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::io::{Cursor, Read};
use std::sync::LazyLock;

use quick_xml::events::Event;
use quick_xml::name::ResolveResult;
use regex::Regex;

use super::csv::{header_name, normalize_header, trim_header};

/// Workbook limits (§5.6). They are fixed so every node gives the same answer.
pub const WORKBOOK_MAX_ENTRIES: usize = 1000;
pub const WORKBOOK_MAX_TOTAL_BYTES: u64 = 256 << 20;
pub const WORKBOOK_RATIO: u64 = 100;
pub const WORKBOOK_RATIO_FLOOR: u64 = 10 << 20;
pub const WORKBOOK_MAX_ROW: i64 = 100_001;
pub const WORKBOOK_MAX_COL: i64 = 1000;

/// The media type of an .xlsx file (§5.1).
pub const WORKBOOK_CONTENT_TYPE: &str =
    "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet";

pub const ERR_WORKBOOK_INVALID: &str = "workbook_invalid";
pub const ERR_WORKBOOK_UNSAFE: &str = "workbook_unsafe";
pub const ERR_WORKBOOK_SHEET_MISSING: &str = "workbook_sheet_missing";
pub const ERR_WORKBOOK_TOO_LARGE: &str = "workbook_too_large";

/// A workbook that cannot be imported: one of the §5.5 codes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkbookError {
    pub code: &'static str,
    pub detail: String,
}

impl std::fmt::Display for WorkbookError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.code, self.detail)
    }
}

impl std::error::Error for WorkbookError {}

fn wb_err(code: &'static str, detail: impl Into<String>) -> WorkbookError {
    WorkbookError {
        code,
        detail: detail.into(),
    }
}

type WbResult<T> = std::result::Result<T, WorkbookError>;

/// Whether a file name makes a file a workbook (§5.1): it ends in .xlsx, in
/// any case.
pub fn is_workbook_name(name: &str) -> bool {
    name.trim().to_lowercase().ends_with(".xlsx")
}

/// Spreadsheet files that are not workbooks in the sense of §5.1.
pub fn is_other_spreadsheet_name(name: &str) -> bool {
    let n = name.trim().to_lowercase();
    let base = n.rsplit('/').next().unwrap_or("");
    let Some(i) = base.rfind('.') else {
        return false;
    };
    matches!(
        &base[i..],
        ".xlsm" | ".xls" | ".xlsb" | ".ods" | ".numbers" | ".xltm" | ".xltx" | ".xlam"
    )
}

/// The ImportRowError file name of a role: products.xlsx or assets.xlsx.
pub fn workbook_file(role: &str) -> String {
    format!("{role}.xlsx")
}

/// A conversion error or warning, in ImportRowError form.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct CellIssue {
    pub file: String,
    /// 0 = null
    pub row: usize,
    pub column: String,
    pub severity: String,
    pub obx_error: String,
    pub detail: String,
    pub value: Option<String>,
}

/// The result of a conversion.
#[derive(Debug, Clone, Default)]
pub struct Workbook {
    pub sheet: String,
    /// Header first; `rows[i]` is Excel row i+1.
    pub rows: Vec<Vec<String>>,
    pub errors: Vec<CellIssue>,
    pub warnings: Vec<CellIssue>,
}

const NS_MAIN: &str = "http://schemas.openxmlformats.org/spreadsheetml/2006/main";
const NS_STRICT: &str = "http://purl.oclc.org/ooxml/spreadsheetml/main";
const NS_REL: &str = "http://schemas.openxmlformats.org/officeDocument/2006/relationships";
const REL_OFFICE_DOC: &str =
    "http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument";
const REL_WORKSHEET: &str =
    "http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet";
const REL_STYLES: &str =
    "http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles";
const REL_SHARED_STRS: &str =
    "http://schemas.openxmlformats.org/officeDocument/2006/relationships/sharedStrings";

const MAIN_TYPES: [&str; 2] = [
    "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml",
    "application/vnd.openxmlformats-officedocument.spreadsheetml.template.main+xml",
];

struct Role {
    sheet: &'static str,
    keys: &'static [&'static str],
    label: &'static str,
}

fn role_of(role: &str) -> Option<Role> {
    match role {
        "products" => Some(Role {
            sheet: "products",
            keys: &["style_number", "style"],
            label: "Products",
        }),
        "assets" => Some(Role {
            sheet: "assets",
            keys: &["file"],
            label: "Assets",
        }),
        _ => None,
    }
}

// ---------------------------------------------------------------- helpers

/// The Excel column letter of a 1-based column number.
pub fn column_letter(mut n: i64) -> String {
    let mut s = Vec::new();
    while n > 0 {
        s.push(b'A' + ((n - 1) % 26) as u8);
        n = (n - 1) / 26;
    }
    s.reverse();
    String::from_utf8(s).unwrap_or_default()
}

fn col_number(letters: &str) -> i64 {
    let mut n: i64 = 0;
    for c in letters.bytes() {
        n = n * 26 + (c - b'A') as i64 + 1;
        if n > 1 << 40 {
            return 1 << 40;
        }
    }
    n
}

static XSTRING_RE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"_x([0-9A-Fa-f]{4})_").unwrap());

/// Replaces the escapes `_xHHHH_` by the UTF-16 code unit U+HHHH, in one
/// pass from left to right (§5.4). Unpaired surrogates become U+FFFD.
pub fn unescape_xstring(s: &str) -> String {
    if !s.contains("_x") {
        return s.to_string();
    }
    let mut units: Vec<u16> = Vec::new();
    let mut last = 0;
    for c in XSTRING_RE.captures_iter(s) {
        let m = c.get(0).unwrap();
        units.extend(s[last..m.start()].encode_utf16());
        units.push(u16::from_str_radix(&c[1], 16).unwrap_or(0xfffd));
        last = m.end();
    }
    units.extend(s[last..].encode_utf16());
    String::from_utf16_lossy(&units)
}

fn go_trim(s: &str) -> &str {
    s.trim()
}

/// Go's strconv.Atoi on a trimmed string, with a default.
fn atoi_or(s: &str, def: i64) -> i64 {
    go_trim(s).parse::<i64>().unwrap_or(def)
}

// ---------------------------------------------------------------- numbers (§5.4)

static NUMBER_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^([+-]?)([0-9]*)(?:\.([0-9]*))?(?:[eE]([+-]?[0-9]+))?$").unwrap()
});

/// The text of a number cell's `<v>`: the exact decimal value, rounded to 15
/// significant digits (halves away from zero), without exponent, trailing
/// zeros or a trailing point. None when `<v>` is not a number or, other than
/// 0, outside Excel's range 1E-308 <= |x| < 1E+308 after the rounding.
pub fn number_text(lex: &str) -> Option<String> {
    let m = NUMBER_RE.captures(go_trim(lex))?;
    let (sign, ip, fp, ex) = (
        m.get(1).map_or("", |x| x.as_str()),
        m.get(2).map_or("", |x| x.as_str()),
        m.get(3).map_or("", |x| x.as_str()),
        m.get(4).map_or("", |x| x.as_str()),
    );
    if ip.is_empty() && fp.is_empty() {
        return None;
    }
    let neg = sign == "-";
    let all = format!("{ip}{fp}");
    let mut digits = all.trim_start_matches('0').to_string();
    let z = all.len() - digits.len();
    if digits.trim_end_matches('0').is_empty() {
        return Some("0".into());
    }
    let mut exp: i64 = 0;
    if !ex.is_empty() {
        if ex
            .trim_start_matches(['+', '-'])
            .trim_start_matches('0')
            .len()
            > 9
        {
            return None;
        }
        exp = ex.parse().ok()?;
    }
    let mut point = ip.len() as i64 + exp - z as i64;
    if digits.len() > 15 {
        let mut kept: Vec<u8> = digits.as_bytes()[..15].to_vec();
        if digits.as_bytes()[15] >= b'5' {
            let mut i: isize = 14;
            while i >= 0 {
                let k = &mut kept[i as usize];
                if *k == b'9' {
                    *k = b'0';
                } else {
                    *k += 1;
                    break;
                }
                i -= 1;
            }
            if i < 0 {
                kept.insert(0, b'1');
                kept.truncate(15);
                point += 1;
            }
        }
        digits = String::from_utf8(kept).unwrap_or_default();
    }
    let digits = digits.trim_end_matches('0');
    if !(-307..=308).contains(&point) {
        return None;
    }
    let n = digits.len() as i64;
    let (int_part, frac) = if point <= 0 {
        (
            "0".to_string(),
            format!("{}{digits}", "0".repeat((-point) as usize)),
        )
    } else if point >= n {
        (
            format!("{digits}{}", "0".repeat((point - n) as usize)),
            String::new(),
        )
    } else {
        (
            digits[..point as usize].to_string(),
            digits[point as usize..].to_string(),
        )
    };
    let mut out = int_part;
    if !frac.is_empty() {
        out.push('.');
        out.push_str(&frac);
    }
    if neg {
        out.insert(0, '-');
    }
    Some(out)
}

const BUILTIN_DATE: [i64; 19] = [
    14, 15, 16, 17, 27, 28, 29, 30, 31, 34, 35, 36, 50, 51, 52, 53, 54, 57, 58,
];
const BUILTIN_DATETIME: [i64; 12] = [18, 19, 20, 21, 22, 32, 33, 45, 46, 47, 55, 56];

static ELAPSED_RE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?i)^(h+|m+|s+)$").unwrap());

/// The first section of a number format code without its literals: quoted
/// text, the character after `\` `_` or `*`, and `[...]` except elapsed time
/// (`[h]`, `[mm]`, `[ss]`).
pub fn format_skeleton(code: &str) -> String {
    let rs: Vec<char> = code.chars().collect();
    let mut out = String::new();
    let mut i = 0;
    let find = |c: char, from: usize| rs.iter().skip(from).position(|&x| x == c).map(|p| p + from);
    while i < rs.len() {
        let c = rs[i];
        match c {
            '"' => {
                i = match find('"', i + 1) {
                    Some(j) => j,
                    None => rs.len(),
                };
            }
            '\\' | '_' | '*' => i += 1,
            '[' => match find(']', i + 1) {
                None => i = rs.len(),
                Some(j) => {
                    let inner: String = rs[i + 1..j].iter().collect();
                    if ELAPSED_RE.is_match(&inner) {
                        out.push_str(&inner);
                    }
                    i = j;
                }
            },
            ';' => return out,
            _ => out.push(c),
        }
        i += 1;
    }
    out
}

pub const KIND_DATE: &str = "date";
pub const KIND_DATETIME: &str = "datetime";

/// Whether a number format (its id and, for a custom format, its code;
/// `has_code` false for a built-in id without one) is a date, a date and
/// time or neither ("").
pub fn date_kind(id: i64, code: &str, has_code: bool) -> &'static str {
    if BUILTIN_DATE.contains(&id) {
        return KIND_DATE;
    }
    if BUILTIN_DATETIME.contains(&id) {
        return KIND_DATETIME;
    }
    if !has_code {
        return "";
    }
    let sk = format_skeleton(code).to_lowercase();
    if !sk.contains(['d', 'm', 'y', 'h', 's']) {
        return "";
    }
    if sk.contains(['h', 's']) {
        return KIND_DATETIME;
    }
    KIND_DATE
}

/// The width a format code made only of zeros (two or more) pads
/// non-negative integers to; 0 for every other code.
pub fn zero_pad(code: &str) -> usize {
    if code.len() >= 2 && code.bytes().all(|b| b == b'0') {
        code.len()
    } else {
        0
    }
}

const MAX_SERIAL_DAYS: f64 = 2_958_466.0;

/// Turns a date serial number into YYYY-MM-DD (kind date) or
/// YYYY-MM-DDTHH:MM:SSZ (kind datetime). None for serials the rule does not
/// accept (before 1900-03-01, below 0 in the 1904 system, or after
/// 9999-12-31, also when the seconds carry over into 10000-01-01).
pub fn serial_text(lex: &str, kind: &str, date1904: bool) -> Option<String> {
    let v: f64 = go_trim(lex).parse().ok()?;
    if v.is_infinite() || v.is_nan() {
        return None;
    }
    if (date1904 && v < 0.0) || (!date1904 && v < 61.0) {
        return None;
    }
    let day = v.floor();
    let mut secs = ((v - day) * 86400.0).round() as i64;
    if day > MAX_SERIAL_DAYS {
        return None;
    }
    let mut days = day as i64;
    if secs >= 86400 {
        days += 1;
        secs -= 86400;
    }
    let epoch = if date1904 {
        chrono::NaiveDate::from_ymd_opt(1904, 1, 1)?
    } else {
        chrono::NaiveDate::from_ymd_opt(1899, 12, 30)?
    };
    let d = epoch.checked_add_days(chrono::Days::new(days as u64))?;
    use chrono::Datelike;
    if d.year() > 9999 {
        return None;
    }
    let ymd = format!("{:04}-{:02}-{:02}", d.year(), d.month(), d.day());
    if kind == KIND_DATE {
        return Some(ymd);
    }
    Some(format!(
        "{ymd}T{:02}:{:02}:{:02}Z",
        secs / 3600,
        secs / 60 % 60,
        secs % 60
    ))
}

static ISO_CELL_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^([0-9]{4}-[0-9]{2}-[0-9]{2})(?:T([0-9]{2}):([0-9]{2})(?::([0-9]{2}))?(?:\.[0-9]+)?(?:Z|[+-]00:00)?)?$").unwrap()
});

/// Converts a `t="d"` cell (ISO 8601).
pub fn iso_cell_text(lex: &str) -> Option<String> {
    let m = ISO_CELL_RE.captures(go_trim(lex))?;
    let date = &m[1];
    let Some(h) = m.get(2).map(|x| x.as_str()) else {
        return Some(date.into());
    };
    let mi = &m[3];
    let sec = m.get(4).map_or("00", |x| x.as_str());
    if h == "00" && mi == "00" && sec == "00" {
        return Some(date.into());
    }
    Some(format!("{date}T{h}:{mi}:{sec}Z"))
}

// ---------------------------------------------------------------- XML

/// One token of a part, in the shape of Go's encoding/xml tokens.
enum Tok {
    Start {
        space: String,
        local: String,
        /// (namespace, local name, value)
        attrs: Vec<(String, String, String)>,
    },
    End {
        local: String,
    },
    Text(String),
}

impl Tok {
    fn attr(attrs: &[(String, String, String)], local: &str) -> Option<String> {
        attrs
            .iter()
            .find(|(s, l, _)| s.is_empty() && l == local)
            .map(|(_, _, v)| v.clone())
    }

    fn attr_ns(attrs: &[(String, String, String)], ns: &str, local: &str) -> Option<String> {
        attrs
            .iter()
            .find(|(s, l, _)| s == ns && l == local)
            .map(|(_, _, v)| v.clone())
    }
}

/// Go's XML decoder turns CR LF and a lone CR into LF in text and attribute
/// values (character references excepted).
fn norm_newlines(s: &str) -> String {
    if !s.contains('\r') {
        return s.to_string();
    }
    s.replace("\r\n", "\n").replace('\r', "\n")
}

enum Flow {
    Go,
    Stop,
}

/// Streams one part. DOCTYPEs are refused, only the five predefined entities
/// exist, and anything not well-formed is workbook_invalid.
fn walk_xml(data: &[u8], part: &str, mut f: impl FnMut(Tok) -> WbResult<Flow>) -> WbResult<()> {
    let bad = |why: String| {
        wb_err(
            ERR_WORKBOOK_INVALID,
            format!("{part} is not well-formed XML ({why})"),
        )
    };
    let text = std::str::from_utf8(data).map_err(|_| bad("invalid UTF-8".into()))?;
    let mut r = quick_xml::reader::NsReader::from_str(text);
    {
        let c = r.config_mut();
        c.check_end_names = true;
        c.trim_text(false);
        c.expand_empty_elements = true;
    }
    let mut depth: usize = 0;
    let local_str = |b: &[u8]| String::from_utf8_lossy(b).into_owned();
    loop {
        let ev = r.read_event().map_err(|e| bad(e.to_string()))?;
        let tok = match ev {
            Event::Eof => {
                if depth > 0 {
                    return Err(bad("unexpected EOF".into()));
                }
                return Ok(());
            }
            Event::DocType(_) => {
                return Err(wb_err(
                    ERR_WORKBOOK_INVALID,
                    format!("{part} has a DOCTYPE"),
                ));
            }
            Event::Decl(d) => {
                if let Some(Ok(enc)) = d.encoding() {
                    let enc = String::from_utf8_lossy(&enc).to_string();
                    if !enc.eq_ignore_ascii_case("utf-8") {
                        return Err(bad(format!("encoding {enc:?} declared")));
                    }
                }
                continue;
            }
            Event::PI(_) | Event::Comment(_) => continue,
            Event::Start(e) => {
                depth += 1;
                let (ns, local) = r.resolve_element(e.name());
                let space = match ns {
                    ResolveResult::Bound(n) => local_str(n.as_ref()),
                    ResolveResult::Unknown(p) => local_str(&p),
                    ResolveResult::Unbound => String::new(),
                };
                let local = local_str(local.as_ref());
                let mut attrs = Vec::new();
                for a in e.attributes().with_checks(true) {
                    let a = a.map_err(|e| bad(e.to_string()))?;
                    let (ans, al) = r.resolve_attribute(a.key);
                    let aspace = match ans {
                        ResolveResult::Bound(n) => local_str(n.as_ref()),
                        ResolveResult::Unknown(p) => local_str(&p),
                        ResolveResult::Unbound => String::new(),
                    };
                    let raw =
                        std::str::from_utf8(&a.value).map_err(|_| bad("invalid UTF-8".into()))?;
                    let v = quick_xml::escape::unescape(&norm_newlines(raw))
                        .map_err(|e| bad(e.to_string()))?
                        .into_owned();
                    attrs.push((aspace, local_str(al.as_ref()), v));
                }
                Tok::Start {
                    space,
                    local,
                    attrs,
                }
            }
            Event::End(e) => {
                depth = depth.saturating_sub(1);
                let (_, local) = r.resolve_element(e.name());
                Tok::End {
                    local: local_str(local.as_ref()),
                }
            }
            Event::Empty(_) => unreachable!("expand_empty_elements"),
            Event::Text(t) => {
                let raw = std::str::from_utf8(&t).map_err(|_| bad("invalid UTF-8".into()))?;
                Tok::Text(norm_newlines(raw))
            }
            Event::CData(t) => {
                let raw = std::str::from_utf8(&t).map_err(|_| bad("invalid UTF-8".into()))?;
                Tok::Text(norm_newlines(raw))
            }
            Event::GeneralRef(g) => {
                if let Some(c) = g.resolve_char_ref().map_err(|e| bad(e.to_string()))? {
                    Tok::Text(c.to_string())
                } else {
                    let name = String::from_utf8_lossy(&g).to_string();
                    let s = match name.as_str() {
                        "amp" => "&",
                        "lt" => "<",
                        "gt" => ">",
                        "apos" => "'",
                        "quot" => "\"",
                        _ => return Err(bad(format!("invalid character entity &{name};"))),
                    };
                    Tok::Text(s.into())
                }
            }
        };
        if let Flow::Stop = f(tok)? {
            return Ok(());
        }
    }
}

// ---------------------------------------------------------------- the package

struct Package {
    archive: zip::ZipArchive<Cursor<Vec<u8>>>,
    /// lower-case name -> (index, declared uncompressed size)
    by_name: HashMap<String, (usize, u64)>,
    names: Vec<String>,
    inflated: u64,
    /// A part read twice counts once (§5.6 step 4).
    done: HashMap<usize, Vec<u8>>,
}

impl Package {
    fn open(data: &[u8]) -> WbResult<Package> {
        let head = &data[..data.len().min(8)];
        if head == [0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1] {
            return Err(wb_err(
                ERR_WORKBOOK_INVALID,
                "the file is an encrypted workbook or a legacy .xls file (OLE compound file)",
            ));
        }
        if !head.starts_with(b"PK\x03\x04") {
            return Err(wb_err(
                ERR_WORKBOOK_INVALID,
                "the file is not an .xlsx workbook (not a zip file)",
            ));
        }
        let mut archive = zip::ZipArchive::new(Cursor::new(data.to_vec())).map_err(|e| {
            wb_err(
                ERR_WORKBOOK_INVALID,
                format!("the zip cannot be read ({e})"),
            )
        })?;
        let mut entries = Vec::new();
        for i in 0..archive.len() {
            let f = archive.by_index_raw(i).map_err(|e| {
                wb_err(
                    ERR_WORKBOOK_INVALID,
                    format!("the zip cannot be read ({e})"),
                )
            })?;
            let name = f.name().to_string();
            if name.ends_with('/') {
                continue;
            }
            if f.encrypted() {
                return Err(wb_err(
                    ERR_WORKBOOK_INVALID,
                    format!("the zip entry {name} is encrypted"),
                ));
            }
            entries.push((i, name, f.size(), f.compressed_size()));
        }
        if entries.len() > WORKBOOK_MAX_ENTRIES {
            return Err(wb_err(
                ERR_WORKBOOK_TOO_LARGE,
                format!(
                    "{} zip entries (limit {WORKBOOK_MAX_ENTRIES})",
                    entries.len()
                ),
            ));
        }
        let mut total: u64 = 0;
        for (_, name, u, c) in &entries {
            total = total.saturating_add(*u);
            if *u > WORKBOOK_RATIO_FLOOR && *u > WORKBOOK_RATIO.saturating_mul((*c).max(1)) {
                return Err(wb_err(
                    ERR_WORKBOOK_TOO_LARGE,
                    format!(
                        "{name} expands from {c} to {u} bytes (more than {WORKBOOK_RATIO} times)"
                    ),
                ));
            }
        }
        if total > WORKBOOK_MAX_TOTAL_BYTES {
            return Err(wb_err(
                ERR_WORKBOOK_TOO_LARGE,
                format!("the parts expand to {total} bytes (limit {WORKBOOK_MAX_TOTAL_BYTES})"),
            ));
        }
        let mut by_name = HashMap::new();
        let mut names = Vec::new();
        for (i, name, u, _) in entries {
            by_name.insert(name.to_lowercase(), (i, u));
            names.push(name);
        }
        Ok(Package {
            archive,
            by_name,
            names,
            inflated: 0,
            done: HashMap::new(),
        })
    }

    /// Inflates one part, counting the bytes; None when it does not exist.
    fn read(&mut self, name: &str) -> WbResult<Option<Vec<u8>>> {
        let key = name.strip_prefix('/').unwrap_or(name).to_lowercase();
        let Some(&(idx, declared)) = self.by_name.get(&key) else {
            return Ok(None);
        };
        if let Some(d) = self.done.get(&idx) {
            return Ok(Some(d.clone()));
        }
        let mut f = self
            .archive
            .by_index(idx)
            .map_err(|e| wb_err(ERR_WORKBOOK_INVALID, format!("{name} cannot be read ({e})")))?;
        let room = WORKBOOK_MAX_TOTAL_BYTES.saturating_sub(self.inflated);
        let limit = declared.min(room) + 1;
        let mut data = Vec::new();
        let res = (&mut f).take(limit).read_to_end(&mut data);
        let real_name = f.name().to_string();
        drop(f);
        let n = data.len() as u64;
        self.inflated += n;
        // A reader that stops at the declared size reports a bad checksum
        // for an entry that inflates beyond it.
        if n > declared
            || self.inflated > WORKBOOK_MAX_TOTAL_BYTES
            || (res.is_err() && n >= declared && declared > 0)
        {
            return Err(wb_err(
                ERR_WORKBOOK_TOO_LARGE,
                format!("{real_name} expands beyond its declared size"),
            ));
        }
        if let Err(e) = res {
            return Err(wb_err(
                ERR_WORKBOOK_INVALID,
                format!("{real_name} cannot be read ({e})"),
            ));
        }
        self.done.insert(idx, data.clone());
        Ok(Some(data))
    }

    fn check_unsafe_names(&self) -> WbResult<()> {
        for name in &self.names {
            let n = name.to_lowercase();
            if n.rsplit('/').next() == Some("vbaproject.bin") {
                return Err(wb_err(
                    ERR_WORKBOOK_UNSAFE,
                    format!("the workbook contains macros ({name})"),
                ));
            }
            for pre in ["xl/macrosheets/", "xl/activex/", "xl/externallinks/"] {
                if n.starts_with(pre) {
                    return Err(wb_err(
                        ERR_WORKBOOK_UNSAFE,
                        format!("the workbook contains {} ({name})", &pre[3..pre.len() - 1]),
                    ));
                }
            }
            if n == "xl/connections.xml" {
                return Err(wb_err(
                    ERR_WORKBOOK_UNSAFE,
                    "the workbook contains data connections (xl/connections.xml)",
                ));
            }
        }
        Ok(())
    }
}

#[derive(Default)]
struct ContentTypes {
    defaults: HashMap<String, String>,
    overrides: HashMap<String, String>,
    all: Vec<String>,
}

impl ContentTypes {
    fn type_of(&self, part: &str) -> String {
        if let Some(t) = self.overrides.get(&part.to_lowercase()) {
            return t.clone();
        }
        let ext = match part.rfind('.') {
            Some(i) => &part[i + 1..],
            None => part,
        };
        self.defaults
            .get(&ext.to_lowercase())
            .cloned()
            .unwrap_or_default()
    }
}

fn parse_content_types(data: &[u8]) -> WbResult<ContentTypes> {
    let mut ct = ContentTypes::default();
    walk_xml(data, "[Content_Types].xml", |t| {
        if let Tok::Start { local, attrs, .. } = t {
            let a = |k: &str| Tok::attr(&attrs, k).unwrap_or_default();
            match local.as_str() {
                "Default" => {
                    let t = a("ContentType");
                    ct.defaults.insert(a("Extension").to_lowercase(), t.clone());
                    ct.all.push(t);
                }
                "Override" => {
                    let t = a("ContentType");
                    ct.overrides.insert(a("PartName").to_lowercase(), t.clone());
                    ct.all.push(t);
                }
                _ => {}
            }
        }
        Ok(Flow::Go)
    })?;
    Ok(ct)
}

#[derive(Clone)]
struct Relationship {
    id: String,
    typ: String,
    target: String,
    external: bool,
}

fn parse_rels(data: &[u8], part: &str) -> WbResult<Vec<Relationship>> {
    let mut rels = Vec::new();
    walk_xml(data, part, |t| {
        if let Tok::Start { local, attrs, .. } = t {
            if local == "Relationship" {
                let a = |k: &str| Tok::attr(&attrs, k).unwrap_or_default();
                rels.push(Relationship {
                    id: a("Id"),
                    typ: a("Type"),
                    target: a("Target"),
                    external: a("TargetMode") == "External",
                });
            }
        }
        Ok(Flow::Go)
    })?;
    Ok(rels)
}

/// Resolves a relationship target against its source part.
fn resolve_part(source: &str, target: &str) -> String {
    let mut base: Vec<&str> = Vec::new();
    if !target.starts_with('/') {
        let segs: Vec<&str> = source.split('/').collect();
        for s in &segs[..segs.len() - 1] {
            if !s.is_empty() {
                base.push(s);
            }
        }
    }
    for seg in target.strip_prefix('/').unwrap_or(target).split('/') {
        match seg {
            ".." => {
                base.pop();
            }
            "." | "" => {}
            s => base.push(s),
        }
    }
    format!("/{}", base.join("/"))
}

fn rels_of(part: &str) -> String {
    let (dir, file) = match part.rfind('/') {
        Some(i) => (&part[..=i], &part[i + 1..]),
        None => ("", part),
    };
    format!("{dir}_rels/{file}.rels")
}

#[derive(Clone)]
struct Sheet {
    name: String,
    state: String,
    rid: String,
    part: String,
}

fn parse_workbook_part(data: &[u8], part: &str) -> WbResult<(Vec<Sheet>, bool)> {
    let mut sheets = Vec::new();
    let (mut date1904, mut root) = (false, false);
    walk_xml(data, part, |t| {
        let Tok::Start {
            space,
            local,
            attrs,
        } = t
        else {
            return Ok(Flow::Go);
        };
        if !root {
            root = true;
            if local != "workbook" || space != NS_MAIN {
                if space == NS_STRICT {
                    return Err(wb_err(
                        ERR_WORKBOOK_INVALID,
                        "the workbook is saved as Strict Open XML; save it as an Excel Workbook (.xlsx)",
                    ));
                }
                return Err(wb_err(
                    ERR_WORKBOOK_INVALID,
                    format!("{part} is not a SpreadsheetML workbook"),
                ));
            }
        }
        match local.as_str() {
            "workbookPr" => {
                let v = Tok::attr(&attrs, "date1904").unwrap_or_default();
                date1904 = v == "1" || v == "true";
            }
            "sheet" => sheets.push(Sheet {
                name: Tok::attr(&attrs, "name").unwrap_or_default(),
                state: Tok::attr(&attrs, "state").unwrap_or_else(|| "visible".into()),
                rid: Tok::attr_ns(&attrs, NS_REL, "id").unwrap_or_default(),
                part: String::new(),
            }),
            _ => {}
        }
        Ok(Flow::Go)
    })?;
    Ok((sheets, date1904))
}

#[derive(Default)]
struct Styles {
    codes: HashMap<i64, String>,
    xfs: Vec<i64>,
}

struct NumFmt {
    id: i64,
    code: String,
    has_code: bool,
}

impl Styles {
    fn format(&self, idx: i64) -> NumFmt {
        let id = if idx >= 0 && (idx as usize) < self.xfs.len() {
            self.xfs[idx as usize]
        } else {
            0
        };
        let code = self.codes.get(&id);
        NumFmt {
            id,
            code: code.cloned().unwrap_or_default(),
            has_code: code.is_some(),
        }
    }
}

fn parse_styles(data: Option<&[u8]>) -> WbResult<Styles> {
    let mut st = Styles::default();
    let Some(data) = data else { return Ok(st) };
    let mut in_xfs = false;
    walk_xml(data, "styles", |t| {
        match t {
            Tok::Start { local, attrs, .. } => match local.as_str() {
                "numFmt" => {
                    let id = Tok::attr(&attrs, "numFmtId").unwrap_or_default();
                    let code = Tok::attr(&attrs, "formatCode").unwrap_or_default();
                    st.codes.insert(atoi_or(&id, -1), code);
                }
                "cellXfs" => in_xfs = true,
                "xf" if in_xfs => {
                    let id = Tok::attr(&attrs, "numFmtId").unwrap_or_else(|| "0".into());
                    st.xfs.push(atoi_or(&id, -1));
                }
                _ => {}
            },
            Tok::End { local } if local == "cellXfs" => in_xfs = false,
            _ => {}
        }
        Ok(Flow::Go)
    })?;
    Ok(st)
}

/// Collects the text of `<si>` / `<is>`: every `<t>` outside phonetic runs
/// `<rPh>`.
#[derive(Default)]
struct RichText {
    in_ph: i64,
    in_t: bool,
    buf: String,
}

impl RichText {
    fn open(&mut self, local: &str) {
        if local == "rPh" {
            self.in_ph += 1;
        }
        if local == "t" && self.in_ph == 0 {
            self.in_t = true;
        }
    }
    fn close(&mut self, local: &str) {
        if local == "rPh" {
            self.in_ph -= 1;
        }
        if local == "t" {
            self.in_t = false;
        }
    }
    fn text(&mut self, s: &str) {
        if self.in_t {
            self.buf.push_str(s);
        }
    }
    fn take(&mut self) -> String {
        unescape_xstring(&std::mem::take(&mut self.buf))
    }
}

fn parse_shared_strings(data: Option<&[u8]>) -> WbResult<Vec<String>> {
    let mut out = Vec::new();
    let Some(data) = data else { return Ok(out) };
    let mut rt = RichText::default();
    let mut in_si = false;
    walk_xml(data, "sharedStrings", |t| {
        match t {
            Tok::Start { local, .. } => {
                if local == "si" {
                    in_si = true;
                } else if in_si {
                    rt.open(&local);
                }
            }
            Tok::End { local } => {
                if local == "si" {
                    in_si = false;
                    out.push(rt.take());
                } else if in_si {
                    rt.close(&local);
                }
            }
            Tok::Text(s) => {
                if in_si {
                    rt.text(&s);
                }
            }
        }
        Ok(Flow::Go)
    })?;
    Ok(out)
}

#[derive(Default, Clone)]
struct RawCell {
    t: String,
    s: i64,
    v: Option<String>,
    f: Option<String>,
    is: Option<String>,
}

#[derive(Default)]
struct SheetCells {
    rows: BTreeMap<i64, BTreeMap<i64, RawCell>>,
    merges: Vec<String>,
}

static CELL_REF_RE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^([A-Z]+)([0-9]+)$").unwrap());

fn parse_sheet(data: &[u8], part: &str, only_row1: bool) -> WbResult<SheetCells> {
    let mut sc = SheetCells::default();
    let (mut row, mut col): (i64, i64) = (0, 0);
    let mut cell: Option<RawCell> = None;
    let mut field: Option<(String, bool)> = None; // (text, is_v)
    let mut rt: Option<RichText> = None;
    walk_xml(data, part, |t| {
        match t {
            Tok::Start { local, attrs, .. } => {
                if local == "row" {
                    row = match Tok::attr(&attrs, "r") {
                        Some(r) => atoi_or(&r, row + 1),
                        None => row + 1,
                    };
                    col = 0;
                    if only_row1 && row > 1 {
                        return Ok(Flow::Stop);
                    }
                } else if local == "c" {
                    let rf = Tok::attr(&attrs, "r").unwrap_or_default();
                    if let Some(m) = CELL_REF_RE.captures(&rf) {
                        col = col_number(&m[1]);
                        row = atoi_or(&m[2], 1 << 40);
                    } else {
                        col += 1;
                    }
                    let mut c = RawCell {
                        t: Tok::attr(&attrs, "t").unwrap_or_else(|| "n".into()),
                        ..Default::default()
                    };
                    let s = Tok::attr(&attrs, "s").unwrap_or_default();
                    if !s.is_empty() {
                        c.s = atoi_or(&s, -1);
                    }
                    cell = Some(c);
                } else if cell.is_some() && local == "v" {
                    field = Some((String::new(), true));
                } else if cell.is_some() && local == "f" {
                    field = Some((String::new(), false));
                } else if cell.is_some() && local == "is" {
                    rt = Some(RichText::default());
                } else if let Some(r) = rt.as_mut() {
                    r.open(&local);
                } else if local == "mergeCell" {
                    sc.merges.push(Tok::attr(&attrs, "ref").unwrap_or_default());
                }
            }
            Tok::End { local } => {
                if local == "c" && cell.is_some() {
                    sc.rows
                        .entry(row)
                        .or_default()
                        .insert(col, cell.take().unwrap());
                } else if local == "is" && rt.is_some() {
                    let s = rt.take().unwrap().take();
                    if let Some(c) = cell.as_mut() {
                        c.is = Some(s);
                    }
                } else if let Some(r) = rt.as_mut() {
                    r.close(&local);
                } else if (local == "v" || local == "f") && field.is_some() {
                    let (s, is_v) = field.take().unwrap();
                    if let Some(c) = cell.as_mut() {
                        if is_v {
                            c.v = Some(s);
                        } else {
                            c.f = Some(s);
                        }
                    }
                }
            }
            Tok::Text(s) => {
                if let Some(r) = rt.as_mut() {
                    r.text(&s);
                } else if cell.is_some() {
                    if let Some((b, _)) = field.as_mut() {
                        b.push_str(&s);
                    }
                }
            }
        }
        Ok(Flow::Go)
    })?;
    Ok(sc)
}

/// A converted cell: text, or a conversion error with its value.
#[derive(Default, Clone)]
struct CellResult {
    text: String,
    is_error: bool,
    value: String,
    reason: String,
}

struct Converter {
    styles: Styles,
    date1904: bool,
    shared: Vec<String>,
}

fn cell_error(value: impl Into<String>, reason: impl Into<String>) -> CellResult {
    CellResult {
        is_error: true,
        value: value.into(),
        reason: reason.into(),
        ..Default::default()
    }
}

fn text(s: impl Into<String>) -> CellResult {
    CellResult {
        text: s.into(),
        ..Default::default()
    }
}

impl Converter {
    fn value(&self, c: &RawCell) -> WbResult<CellResult> {
        if let (Some(f), None) = (&c.f, &c.v) {
            if c.t != "inlineStr" {
                return Ok(cell_error(
                    format!("={f}"),
                    "a formula without a saved result",
                ));
            }
        }
        let blank = c.v.as_deref().is_none_or(|v| go_trim(v).is_empty());
        match c.t.as_str() {
            "s" => {
                if blank {
                    return Ok(CellResult::default());
                }
                let v = c.v.as_deref().unwrap_or("");
                let f: Option<f64> = go_trim(v).parse().ok();
                match f {
                    Some(f) if f == f.trunc() && f >= 0.0 && f < self.shared.len() as f64 => {
                        Ok(text(self.shared[f as usize].clone()))
                    }
                    _ => Err(wb_err(
                        ERR_WORKBOOK_INVALID,
                        format!("shared string {v} does not exist"),
                    )),
                }
            }
            "inlineStr" => Ok(text(c.is.clone().unwrap_or_default())),
            "str" => Ok(text(
                c.v.as_deref().map(unescape_xstring).unwrap_or_default(),
            )),
            "b" => Ok(match c.v.as_deref() {
                Some("1") => text("true"),
                Some("0") => text("false"),
                _ => CellResult::default(),
            }),
            "e" => Ok(cell_error(
                c.v.clone().unwrap_or_default(),
                "an error value",
            )),
            "d" => {
                let v = c.v.as_deref().unwrap_or("");
                if v.is_empty() {
                    return Ok(CellResult::default());
                }
                Ok(match iso_cell_text(v) {
                    Some(t) => text(t),
                    None => cell_error(v, "a date that cannot be read"),
                })
            }
            _ => {
                if blank {
                    return Ok(CellResult::default());
                }
                let v = c.v.as_deref().unwrap_or("");
                let Some(mut t) = number_text(v) else {
                    let shown = if v.len() > 40 {
                        let mut end = 40;
                        while !v.is_char_boundary(end) {
                            end -= 1;
                        }
                        format!("{}…", &v[..end])
                    } else {
                        v.to_string()
                    };
                    return Err(wb_err(
                        ERR_WORKBOOK_INVALID,
                        format!(
                            "a number cell holds {}, which is not a number Excel can store",
                            crate::error::quote(&shown)
                        ),
                    ));
                };
                let f = self.styles.format(c.s);
                let kind = date_kind(f.id, &f.code, f.has_code);
                if !kind.is_empty() {
                    if let Some(d) = serial_text(v, kind, self.date1904) {
                        return Ok(text(d));
                    }
                    let first = if self.date1904 {
                        "1904-01-01"
                    } else {
                        "1900-03-01"
                    };
                    return Ok(cell_error(
                        v,
                        format!("a date outside {first} to 9999-12-31"),
                    ));
                }
                let w = zero_pad(&f.code);
                if w > 0 && f.has_code && is_digits(&t) && t.len() < w {
                    t = format!("{}{t}", "0".repeat(w - t.len()));
                }
                Ok(text(t))
            }
        }
    }
}

fn is_digits(s: &str) -> bool {
    !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit())
}

// ---------------------------------------------------------------- the conversion

/// Turns a workbook into the rows of products.csv (role "products") or
/// assets.csv ("assets"), as §5 says. The caller checks the upload limit
/// (§5.6 step 1) before.
pub fn convert_workbook(data: &[u8], role: &str) -> WbResult<Workbook> {
    let Some(ro) = role_of(role) else {
        return Err(wb_err(
            ERR_WORKBOOK_INVALID,
            format!("unknown workbook role {role:?}"),
        ));
    };
    let file = workbook_file(role);
    let mut pkg = Package::open(data)?;
    // Step 5: unsafe parts, by entry names and content types, before they are read.
    pkg.check_unsafe_names()?;
    let Some(ct_data) = pkg.read("[Content_Types].xml")? else {
        return Err(wb_err(
            ERR_WORKBOOK_INVALID,
            "[Content_Types].xml is missing",
        ));
    };
    let ct = parse_content_types(&ct_data)?;
    for t in &ct.all {
        let lt = t.to_lowercase();
        if lt.contains("macroenabled") || lt.contains("vbaproject") {
            return Err(wb_err(
                ERR_WORKBOOK_UNSAFE,
                format!("the workbook is macro-enabled ({t})"),
            ));
        }
    }
    // Step 6: structure.
    let Some(root_rels) = pkg.read("_rels/.rels")? else {
        return Err(wb_err(ERR_WORKBOOK_INVALID, "_rels/.rels is missing"));
    };
    let rels = parse_rels(&root_rels, "_rels/.rels")?;
    let Some(main) = rels.iter().find(|r| r.typ == REL_OFFICE_DOC && !r.external) else {
        return Err(wb_err(
            ERR_WORKBOOK_INVALID,
            "the package has no main document",
        ));
    };
    let wb_part = resolve_part("/", &main.target);
    let t = ct.type_of(&wb_part);
    if !MAIN_TYPES.contains(&t.as_str()) {
        let t = if t.is_empty() { "missing".into() } else { t };
        return Err(wb_err(
            ERR_WORKBOOK_INVALID,
            format!("the main document is {t}, not an Excel workbook"),
        ));
    }
    let Some(wb_data) = pkg.read(&wb_part)? else {
        return Err(wb_err(
            ERR_WORKBOOK_INVALID,
            format!("{wb_part} is missing"),
        ));
    };
    let (sheets, date1904) = parse_workbook_part(&wb_data, &wb_part)?;
    let wb_rels = match pkg.read(&rels_of(&wb_part))? {
        Some(d) => parse_rels(&d, &rels_of(&wb_part))?,
        None => Vec::new(),
    };
    // Step 7: external relationships of the workbook part.
    if let Some(rel) = wb_rels.iter().find(|r| r.external) {
        let base = rel.typ.rsplit('/').next().unwrap_or("");
        return Err(wb_err(
            ERR_WORKBOOK_UNSAFE,
            format!("the workbook refers to an external resource ({base})"),
        ));
    }
    let mut rel_by_id: HashMap<String, Relationship> = HashMap::new();
    for rel in &wb_rels {
        rel_by_id
            .entry(rel.id.clone())
            .or_insert_with(|| rel.clone());
    }
    let read_rel = |pkg: &mut Package, typ: &str| -> WbResult<Option<Vec<u8>>> {
        match wb_rels.iter().find(|r| r.typ == typ) {
            Some(rel) => pkg.read(&resolve_part(&wb_part, &rel.target)),
            None => Ok(None),
        }
    };
    let styles_data = read_rel(&mut pkg, REL_STYLES)?;
    let styles = parse_styles(styles_data.as_deref())?;
    let ss_data = read_rel(&mut pkg, REL_SHARED_STRS)?;
    let shared = parse_shared_strings(ss_data.as_deref())?;
    let cv = Converter {
        styles,
        date1904,
        shared,
    };

    // Step 8: the sheet (§5.2): visible worksheets only.
    let mut visible = Vec::new();
    for s in sheets {
        let Some(rel) = rel_by_id.get(&s.rid) else {
            continue;
        };
        if s.state != "visible" || rel.typ != REL_WORKSHEET {
            continue;
        }
        let mut s = s;
        s.part = resolve_part(&wb_part, &rel.target);
        visible.push(s);
    }
    let read_sheet = |pkg: &mut Package, s: &Sheet, only_row1: bool| -> WbResult<SheetCells> {
        let Some(data) = pkg.read(&s.part)? else {
            return Err(wb_err(
                ERR_WORKBOOK_INVALID,
                format!("{} is missing", s.part),
            ));
        };
        parse_sheet(&data, &s.part, only_row1)
    };
    let ascii_lower = |s: &str| s.to_ascii_lowercase();
    let mut chosen = visible
        .iter()
        .find(|s| ascii_lower(go_trim(&s.name)) == ro.sheet)
        .cloned();
    if chosen.is_none() {
        'search: for s in &visible {
            let sc = read_sheet(&mut pkg, s, true)?;
            if let Some(cells) = sc.rows.get(&1) {
                for c in cells.values() {
                    let v = cv.value(c)?;
                    let name = header_name(&v.text);
                    if ro.keys.contains(&name.as_str()) {
                        chosen = Some(s.clone());
                        break 'search;
                    }
                }
            }
        }
    }
    let Some(chosen) = chosen else {
        return Err(wb_err(
            ERR_WORKBOOK_SHEET_MISSING,
            format!(
                "no visible sheet is named {} or has a {} column in row 1",
                ro.label, ro.keys[0]
            ),
        ));
    };

    // Steps 9 and 10: the cells.
    let mut sc = read_sheet(&mut pkg, &chosen, false)?;
    for rf in &sc.merges {
        let Some((r1, c1, r2, c2)) = parse_range(rf) else {
            continue;
        };
        for (rn, cells) in sc.rows.iter_mut() {
            if *rn < r1 || *rn > r2 {
                continue;
            }
            cells.retain(|cn, _| !(*cn >= c1 && *cn <= c2 && (*rn != r1 || *cn != c1)));
        }
    }
    let mut values: BTreeMap<i64, BTreeMap<i64, CellResult>> = BTreeMap::new();
    for (rn, cells) in &sc.rows {
        for (cn, c) in cells {
            let v = cv.value(c)?;
            if !v.is_error && v.text.is_empty() {
                continue;
            }
            if *rn > WORKBOOK_MAX_ROW {
                return Err(wb_err(
                    ERR_WORKBOOK_TOO_LARGE,
                    format!(
                        "the sheet has values below row {WORKBOOK_MAX_ROW} (cell {}{rn})",
                        column_letter(*cn)
                    ),
                ));
            }
            if *cn > WORKBOOK_MAX_COL {
                return Err(wb_err(
                    ERR_WORKBOOK_TOO_LARGE,
                    format!(
                        "the sheet has values right of column {} (cell {}{rn})",
                        column_letter(WORKBOOK_MAX_COL),
                        column_letter(*cn)
                    ),
                ));
            }
            values.entry(*rn).or_default().insert(*cn, v);
        }
    }
    let mut out = Workbook {
        sheet: chosen.name.clone(),
        ..Default::default()
    };
    let empty = BTreeMap::new();
    let row1 = values.get(&1).unwrap_or(&empty);
    let width = row1
        .iter()
        .filter(|(_, v)| !v.is_error && !v.text.is_empty())
        .map(|(cn, _)| *cn)
        .max()
        .unwrap_or(0);
    let header: Vec<String> = (1..=width)
        .map(|cn| match row1.get(&cn) {
            Some(v) if !v.is_error => v.text.clone(),
            _ => String::new(),
        })
        .collect();
    let issue = |rn: i64, cn: i64, v: &CellResult| -> CellIssue {
        let column = if rn > 1 {
            trim_header(&header[(cn - 1) as usize]).to_string()
        } else {
            String::new()
        };
        CellIssue {
            file: file.clone(),
            row: rn as usize,
            column: column.clone(),
            severity: "error".into(),
            obx_error: "validation_failed".into(),
            detail: format!(
                "{}the cell holds {}",
                cell_locator(rn as usize, &column, cn),
                v.reason
            ),
            value: (!v.value.is_empty()).then(|| v.value.clone()),
        }
    };
    for (cn, v) in row1 {
        if v.is_error && *cn <= width {
            out.errors.push(issue(1, *cn, v));
        }
    }
    let last = values
        .iter()
        .filter(|(rn, cells)| **rn > 1 && cells.keys().any(|cn| *cn <= width))
        .map(|(rn, _)| *rn)
        .max()
        .unwrap_or(1);
    out.rows.push(header.clone());
    for rn in 2..=last {
        let cells = values.get(&rn).unwrap_or(&empty);
        let mut bad = false;
        for (cn, v) in cells {
            if *cn <= width && v.is_error {
                out.errors.push(issue(rn, *cn, v));
                bad = true;
            }
        }
        let rec: Vec<String> = if bad {
            vec![String::new(); width as usize]
        } else {
            (1..=width)
                .map(|cn| cells.get(&cn).map(|v| v.text.clone()).unwrap_or_default())
                .collect()
        };
        out.rows.push(rec);
    }
    // §5.3: values without a header: right of W, or (rows 2 to R) under an
    // empty header name.
    let mut stray = BTreeSet::new();
    for (rn, cells) in &values {
        for cn in cells.keys() {
            if *cn > width || (*rn > 1 && trim_header(&header[(*cn - 1) as usize]).is_empty()) {
                stray.insert(*cn);
            }
        }
    }
    for cn in stray {
        out.warnings.push(CellIssue {
            file: file.clone(),
            severity: "warning".into(),
            obx_error: "validation_failed".into(),
            detail: format!(
                "column {}: has values but no header in row 1; ignored",
                column_letter(cn)
            ),
            ..Default::default()
        });
    }
    Ok(out)
}

static RANGE_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^([A-Z]+)([0-9]+)(?::([A-Z]+)([0-9]+))?$").unwrap());

fn parse_range(rf: &str) -> Option<(i64, i64, i64, i64)> {
    let m = RANGE_RE.captures(rf)?;
    let (c2, r2) = (m.get(3)?, m.get(4)?);
    Some((
        atoi_or(&m[2], 0),
        col_number(&m[1]),
        atoi_or(r2.as_str(), 0),
        col_number(c2.as_str()),
    ))
}

/// The §5.5 locator at the start of a detail about a cell:
/// "row 12, column ean (C): " (column is the header text, trimmed), or
/// "row 12, column C: " when the column has no header.
pub fn cell_locator(row: usize, column: &str, col: i64) -> String {
    if column.is_empty() {
        format!("row {row}, column {}: ", column_letter(col))
    } else {
        format!("row {row}, column {column} ({}): ", column_letter(col))
    }
}

/// The §5.5 locator for a problem the CSV import of a workbook's rows
/// reports: row is the Excel row (0 = none), column the column as the CSV
/// import names it ("" = none), header the workbook's row 1.
pub fn workbook_locator(header: &[String], row: usize, column: &str) -> String {
    let mut idx = None;
    if !column.is_empty() {
        let norm = normalize_header(column);
        idx = header
            .iter()
            .position(|h| trim_header(h) == column || normalize_header(h) == norm);
    }
    match idx {
        Some(i) if row > 0 => cell_locator(row, trim_header(&header[i]), i as i64 + 1),
        Some(i) => {
            let h = trim_header(&header[i]);
            if h.is_empty() {
                format!("column {}: ", column_letter(i as i64 + 1))
            } else {
                format!("column {h} ({}): ", column_letter(i as i64 + 1))
            }
        }
        None if row > 0 => format!("row {row}: "),
        None => String::new(),
    }
}
