//! Property tests of the parsers: arbitrary input never panics, and what
//! the node writes reads back as written.

use std::io::{Cursor, Write};

use obx_ingest::importfmt::*;
use proptest::prelude::*;

fn config() -> ProptestConfig {
    ProptestConfig {
        cases: 256,
        failure_persistence: None,
        ..ProptestConfig::default()
    }
}

/// A small valid workbook with one inline-string sheet.
fn workbook(cells: &[Vec<String>]) -> Vec<u8> {
    let esc = |s: &str| {
        s.replace('&', "&amp;")
            .replace('<', "&lt;")
            .replace('>', "&gt;")
    };
    let mut rows = String::new();
    for (r, row) in cells.iter().enumerate() {
        rows.push_str(&format!("<row r=\"{}\">", r + 1));
        for (c, v) in row.iter().enumerate() {
            rows.push_str(&format!(
                "<c r=\"{}{}\" t=\"inlineStr\"><is><t xml:space=\"preserve\">{}</t></is></c>",
                column_letter(c as i64 + 1),
                r + 1,
                esc(v)
            ));
        }
        rows.push_str("</row>");
    }
    let parts = [
        ("[Content_Types].xml", r#"<?xml version="1.0" encoding="UTF-8"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/><Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/></Types>"#.to_string()),
        ("_rels/.rels", r#"<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/></Relationships>"#.to_string()),
        ("xl/workbook.xml", r#"<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"><sheets><sheet name="Products" sheetId="1" r:id="rId1"/></sheets></workbook>"#.to_string()),
        ("xl/_rels/workbook.xml.rels", r#"<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet1.xml"/></Relationships>"#.to_string()),
        ("xl/worksheets/sheet1.xml", format!(r#"<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"><sheetData>{rows}</sheetData></worksheet>"#)),
    ];
    let mut buf = Cursor::new(Vec::new());
    let mut z = zip::ZipWriter::new(&mut buf);
    for (n, d) in parts {
        z.start_file(n, zip::write::SimpleFileOptions::default())
            .unwrap();
        z.write_all(d.as_bytes()).unwrap();
    }
    z.finish().unwrap();
    buf.into_inner()
}

fn header_strategy() -> impl Strategy<Value = Vec<String>> {
    prop::collection::btree_set("[a-z]{1,6}", 1..6).prop_map(|s| {
        let mut v: Vec<String> = s.into_iter().collect();
        v.insert(0, "style_number".into());
        v.dedup();
        v
    })
}

fn table_strategy() -> impl Strategy<Value = Vec<Vec<String>>> {
    header_strategy().prop_flat_map(|h| {
        let w = h.len();
        prop::collection::vec(
            ("[A-Z0-9]{1,6}", prop::collection::vec("[a-zA-Z0-9 ,;\"\\n:é€-]{0,10}", w - 1)),
            1..8,
        )
        .prop_map(move |rows| {
            let mut out = vec![h.clone()];
            for (first, rest) in rows {
                let mut r = vec![first];
                r.extend(rest);
                out.push(r);
            }
            out
        })
    })
}

proptest! {
    #![proptest_config(config())]

    #[test]
    fn csv_never_panics(data in prop::collection::vec(any::<u8>(), 0..512)) {
        let _ = parse_csv(&data);
    }

    #[test]
    fn csv_text_never_panics(s in "[a-z,;\t\"\r\n ]{0,200}") {
        let _ = parse_csv(s.as_bytes());
    }

    /// canonical_csv (what the node writes, §5.3) reads back cell for cell.
    #[test]
    fn csv_round_trip(rows in table_strategy()) {
        let t = parse_csv(&canonical_csv(&rows)).expect("parse");
        let header: Vec<String> = rows[0].iter().map(|h| normalize_header(h)).collect();
        prop_assert_eq!(&t.header, &header);
        prop_assert_eq!(t.rows.len(), rows.len() - 1);
        for (r, want) in t.rows.iter().zip(&rows[1..]) {
            for (h, v) in header.iter().zip(want) {
                prop_assert_eq!(r.get(h), v.trim());
            }
        }
    }

    #[test]
    fn workbook_never_panics(data in prop::collection::vec(any::<u8>(), 0..1024)) {
        let _ = convert_workbook(&data, "products");
    }

    /// Damaged workbooks are refused with a §5.5 code, never a panic.
    #[test]
    fn damaged_workbook_never_panics(flips in prop::collection::vec((any::<prop::sample::Index>(), any::<u8>()), 1..8)) {
        let mut data = workbook(&[vec!["style_number".into(), "name:en".into()], vec!["A-1".into(), "Coat".into()]]);
        for (i, b) in flips {
            let n = i.index(data.len());
            data[n] = b;
        }
        if let Err(e) = convert_workbook(&data, "products") {
            prop_assert!(e.code.starts_with("workbook_"), "{}", e.code);
        }
    }

    /// A workbook gives the same rows as the CSV with the same cells.
    #[test]
    fn workbook_matches_csv(rows in table_strategy()) {
        let wb = convert_workbook(&workbook(&rows), "products").expect("convert");
        prop_assert!(wb.errors.is_empty());
        let csv = parse_csv(&canonical_csv(&rows)).unwrap();
        let xl = table_from_records(wb.rows).unwrap();
        prop_assert_eq!(csv.header, xl.header);
        prop_assert_eq!(csv.rows.len(), xl.rows.len());
        for (a, b) in csv.rows.iter().zip(&xl.rows) {
            prop_assert_eq!(&a.values, &b.values);
        }
    }

    /// Number cells: the text is the value to 15 significant digits.
    #[test]
    fn numbers_keep_their_value(x in -1e300f64..1e300f64) {
        let t = number_text(&format!("{x:e}")).expect("a number");
        let back: f64 = t.parse().unwrap();
        let tol = x.abs() * 1e-14;
        prop_assert!((back - x).abs() <= tol, "{} -> {} ({})", x, t, back);
        prop_assert!(!t.contains('e') && !t.ends_with('.'));
    }

    #[test]
    fn number_text_never_panics(s in "[0-9eE+.-]{0,30}") {
        let _ = number_text(&s);
    }

    #[test]
    fn serial_text_never_panics(s in "[0-9.e+-]{0,20}", d1904 in any::<bool>()) {
        let _ = serial_text(&s, KIND_DATETIME, d1904);
    }

    #[test]
    fn xstring_never_panics(s in "(_x[0-9A-Fa-f]{0,5}_?|[a-z_])*") {
        let _ = unescape_xstring(&s);
    }

    #[test]
    fn zip_never_panics(data in prop::collection::vec(any::<u8>(), 0..1024)) {
        if let Ok(mut p) = ZipPackage::open(Cursor::new(data), PACKAGE_LIMITS) {
            let idx: Vec<usize> = p.entries().iter().map(|e| e.index).collect();
            for i in idx {
                let _ = p.read(i, 1 << 20);
            }
        }
    }

    /// No entry name with a `..` segment, an absolute path or a drive
    /// letter is accepted.
    #[test]
    fn zip_slip_is_refused(segs in prop::collection::vec("[a-z]{1,4}", 0..3), pos in 0usize..3, kind in 0u8..3) {
        let mut parts = segs.clone();
        let bad = match kind { 0 => "..".to_string(), 1 => String::new(), _ => "C:".to_string() };
        let at = if kind == 0 { pos.min(parts.len()) } else { 0 };
        parts.insert(at, bad);
        parts.push("x.csv".into());
        let name = parts.join("/");
        prop_assert!(safe_entry(&name, false).is_err(), "{}", name);
        prop_assert!(safe_entry(&name.replace('/', "\\"), false).is_err(), "{}", name);
    }
}
