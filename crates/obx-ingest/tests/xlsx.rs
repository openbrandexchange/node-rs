//! Excel workbooks (import-format.md §5): the spec's
//! fixtures/imports/xlsx/expected.json and node-go's xlsx_test.go cases.

use std::io::Write;

use obx_ingest::importfmt::*;
use serde_json::Value;

const SPEC: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../obx-conformance/fixtures");

fn read(path: &str) -> Vec<u8> {
    std::fs::read(format!("{SPEC}/{path}")).unwrap_or_else(|e| panic!("{path}: {e}"))
}

fn expected() -> Value {
    serde_json::from_slice(&read("imports/xlsx/expected.json")).unwrap()
}

fn opt_str(v: &Value) -> Option<String> {
    v.as_str().map(String::from)
}

fn check_issues(case: &str, what: &str, got: &[CellIssue], want: &Value) {
    let want = want.as_array().cloned().unwrap_or_default();
    assert_eq!(got.len(), want.len(), "{case} {what}: {got:?}");
    for (g, w) in got.iter().zip(&want) {
        assert_eq!(g.file, w["file"].as_str().unwrap(), "{case} {what}");
        assert_eq!(g.severity, w["severity"].as_str().unwrap(), "{case} {what}");
        assert_eq!(
            g.obx_error,
            w["obx_error"].as_str().unwrap(),
            "{case} {what}"
        );
        let prefix = w["detail_prefix"].as_str().unwrap_or("");
        assert!(
            g.detail.starts_with(prefix),
            "{case} {what}: {:?} does not start with {prefix:?}",
            g.detail
        );
        let row = w["row"].as_u64().map(|r| r as usize).unwrap_or(0);
        assert_eq!(g.row, row, "{case} {what} row");
        assert_eq!(
            g.column,
            opt_str(&w["column"]).unwrap_or_default(),
            "{case} {what} column"
        );
        assert_eq!(g.value, opt_str(&w["value"]), "{case} {what} value");
    }
}

#[test]
fn workbook_fixtures() {
    let e = expected();
    let l = &e["limits"];
    assert_eq!(l["entries"], WORKBOOK_MAX_ENTRIES as u64);
    assert_eq!(l["totalBytes"], WORKBOOK_MAX_TOTAL_BYTES);
    assert_eq!(l["ratio"], WORKBOOK_RATIO);
    assert_eq!(l["ratioFloor"], WORKBOOK_RATIO_FLOOR);
    assert_eq!(l["maxRow"], WORKBOOK_MAX_ROW);
    assert_eq!(l["maxCol"], WORKBOOK_MAX_COL);
    let cases = e["cases"].as_array().unwrap();
    assert!(cases.len() >= 15, "only {} cases", cases.len());
    for c in cases {
        let file = c["file"].as_str().unwrap();
        let role = c["role"].as_str().unwrap();
        let got = convert_workbook(&read(&format!("imports/xlsx/{file}")), role);
        if c["error"].is_object() {
            let want = &c["error"];
            let err = got.err().unwrap_or_else(|| panic!("{file}: want an error"));
            assert_eq!(
                err.code,
                want["obx_error"].as_str().unwrap(),
                "{file}: {}",
                err.detail
            );
            assert_eq!(want["file"].as_str().unwrap(), workbook_file(role));
            let needle = want["detail_contains"].as_str().unwrap().to_lowercase();
            assert!(
                err.detail.to_lowercase().contains(&needle),
                "{file}: {:?} does not mention {needle:?}",
                err.detail
            );
            continue;
        }
        let wb = got.unwrap_or_else(|e| panic!("{file}: {e}"));
        assert_eq!(wb.sheet, c["sheet"].as_str().unwrap(), "{file}");
        let csv = canonical_csv(&wb.rows);
        if let Some(cf) = c["csv_file"].as_str() {
            let want = read(cf.trim_start_matches("fixtures/"));
            assert!(
                csv == want,
                "{file}: csv differs from {cf}:\n{}\nwant\n{}",
                String::from_utf8_lossy(&csv),
                String::from_utf8_lossy(&want)
            );
        } else {
            let rows: Vec<Vec<String>> = serde_json::from_value(c["rows"].clone()).unwrap();
            assert_eq!(wb.rows, rows, "{file}");
            assert_eq!(
                String::from_utf8(csv).unwrap(),
                c["csv"].as_str().unwrap(),
                "{file}"
            );
        }
        check_issues(file, "errors", &wb.errors, &c["errors"]);
        check_issues(file, "warnings", &wb.warnings, &c["warnings"]);
    }
}

#[test]
fn workbook_vectors() {
    let e = expected();
    for v in e["number_vectors"].as_array().unwrap() {
        let lex = v["v"].as_str().unwrap();
        let got = number_text(lex);
        let Some(want) = v["text"].as_str() else {
            assert!(
                got.is_none(),
                "number {lex}: {got:?}, want workbook_invalid"
            );
            continue;
        };
        let mut got = got.unwrap_or_else(|| panic!("number {lex}: not a number"));
        let code = v["format"].as_str().unwrap_or("General");
        if code != "General" {
            let w = zero_pad(code);
            if w > 0 && got.bytes().all(|b| b.is_ascii_digit()) && got.len() < w {
                got = format!("{}{got}", "0".repeat(w - got.len()));
            }
        }
        assert_eq!(got, want, "number {lex} ({code})");
    }
    for v in e["date_vectors"].as_array().unwrap() {
        let lex = v["v"].as_str().unwrap();
        let kind = v["kind"].as_str().unwrap();
        let d1904 = v["date1904"].as_bool().unwrap_or(false);
        let got = serial_text(lex, kind, d1904);
        assert_eq!(
            got.as_deref(),
            v["text"].as_str(),
            "date {lex} {kind} 1904={d1904}"
        );
    }
    for v in e["format_vectors"].as_array().unwrap() {
        let id = v["id"].as_i64().unwrap();
        let code = v["code"].as_str().unwrap();
        assert_eq!(
            date_kind(id, code, true),
            v["kind"].as_str().unwrap_or(""),
            "format {id} {code:?}"
        );
    }
    for s in ["abc", "", "1.2.3", "1e", "--1", "1e999"] {
        assert!(number_text(s).is_none(), "{s:?}");
    }
    for (i, w) in [
        ("_x000D_", "\r"),
        ("_x005F_x0031_", "_x0031_"),
        ("a_x0041_b", "aAb"),
        ("_xD83D__xDE00_", "\u{1F600}"),
        ("_x00_", "_x00_"),
    ] {
        assert_eq!(unescape_xstring(i), w, "{i}");
    }
    for (i, w) in [
        ("2026-03-01", "2026-03-01"),
        ("2026-03-01T00:00:00Z", "2026-03-01"),
        ("2026-03-01T12:30:15.5Z", "2026-03-01T12:30:15Z"),
        ("2026-03-01T12:30", "2026-03-01T12:30:00Z"),
    ] {
        assert_eq!(iso_cell_text(i).as_deref(), Some(w), "{i}");
    }
    assert!(iso_cell_text("1 March 2026").is_none());
}

const CT: &str = r#"<?xml version="1.0" encoding="UTF-8"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/><Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/><Override PartName="/xl/worksheets/sheet1.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/></Types>"#;
const RELS: &str = r#"<?xml version="1.0" encoding="UTF-8"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/></Relationships>"#;
const WB: &str = r#"<?xml version="1.0" encoding="UTF-8"?><workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"><sheets><sheet name="Products" sheetId="1" r:id="rId1"/></sheets></workbook>"#;
const WB_RELS: &str = r#"<?xml version="1.0" encoding="UTF-8"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet1.xml"/></Relationships>"#;

fn sheet_xml(sheet: &str) -> String {
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?><worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"><sheetData>{sheet}</sheetData></worksheet>"#
    )
}

/// A minimal workbook with the given parts overriding the defaults (None
/// removes a part).
fn build(sheet: &str, over: &[(&str, Option<&str>)]) -> Vec<u8> {
    let sx = sheet_xml(sheet);
    let mut parts: Vec<(String, String)> = vec![
        ("[Content_Types].xml".into(), CT.into()),
        ("_rels/.rels".into(), RELS.into()),
        ("xl/workbook.xml".into(), WB.into()),
        ("xl/_rels/workbook.xml.rels".into(), WB_RELS.into()),
        ("xl/worksheets/sheet1.xml".into(), sx),
    ];
    for (k, v) in over {
        match parts.iter().position(|(n, _)| n == k) {
            Some(i) => match v {
                Some(v) => parts[i].1 = v.to_string(),
                None => {
                    parts.remove(i);
                }
            },
            None => {
                if let Some(v) = v {
                    parts.push((k.to_string(), v.to_string()));
                }
            }
        }
    }
    let mut buf = std::io::Cursor::new(Vec::new());
    let mut z = zip::ZipWriter::new(&mut buf);
    for (n, v) in parts {
        z.start_file(n, zip::write::SimpleFileOptions::default())
            .unwrap();
        z.write_all(v.as_bytes()).unwrap();
    }
    z.finish().unwrap();
    buf.into_inner()
}

fn inl(r: &str, s: &str) -> String {
    format!(r#"<c r="{r}" t="inlineStr"><is><t>{s}</t></is></c>"#)
}

#[test]
fn workbook_refusals() {
    let ok = format!(
        r#"<row r="1">{}</row><row r="2">{}</row>"#,
        inl("A1", "style_number"),
        inl("A2", "X-1")
    );
    let plus = |s: &str| format!("{ok}{s}");
    let cases: Vec<(&str, Vec<u8>, &str)> = vec![
        ("plain", build(&ok, &[]), ""),
        (
            "no content types",
            build(&ok, &[("[Content_Types].xml", None)]),
            ERR_WORKBOOK_INVALID,
        ),
        (
            "no main document",
            build(
                &ok,
                &[(
                    "_rels/.rels",
                    Some(
                        r#"<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"/>"#,
                    ),
                )],
            ),
            ERR_WORKBOOK_INVALID,
        ),
        (
            "strict",
            build(
                &ok,
                &[(
                    "xl/workbook.xml",
                    Some(r#"<workbook xmlns="http://purl.oclc.org/ooxml/spreadsheetml/main"/>"#),
                )],
            ),
            ERR_WORKBOOK_INVALID,
        ),
        (
            "not well-formed",
            build(r#"<row r="1"><c r="A1"><v>1</v></row>"#, &[]),
            ERR_WORKBOOK_INVALID,
        ),
        (
            "doctype in sheet",
            build(
                &ok,
                &[(
                    "xl/worksheets/sheet1.xml",
                    Some(
                        r#"<?xml version="1.0"?><!DOCTYPE x [<!ENTITY a "aaaa">]><worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"><sheetData><row r="1"><c r="A1" t="inlineStr"><is><t>&a;</t></is></c></row></sheetData></worksheet>"#,
                    ),
                )],
            ),
            ERR_WORKBOOK_INVALID,
        ),
        (
            "unknown entity",
            build(
                r#"<row r="1"><c r="A1" t="inlineStr"><is><t>&nbsp;style_number</t></is></c></row>"#,
                &[],
            ),
            ERR_WORKBOOK_INVALID,
        ),
        (
            "unclosed",
            build(r#"<row r="1">"#, &[]),
            ERR_WORKBOOK_INVALID,
        ),
        (
            "number not a number",
            build(&plus(r#"<row r="3"><c r="A3"><v>12abc</v></c></row>"#), &[]),
            ERR_WORKBOOK_INVALID,
        ),
        (
            "missing shared string",
            build(
                &plus(r#"<row r="3"><c r="A3" t="s"><v>7</v></c></row>"#),
                &[],
            ),
            ERR_WORKBOOK_INVALID,
        ),
        (
            "activeX",
            build(&ok, &[("xl/activeX/activeX1.xml", Some("<x/>"))]),
            ERR_WORKBOOK_UNSAFE,
        ),
        (
            "connections",
            build(&ok, &[("xl/connections.xml", Some("<x/>"))]),
            ERR_WORKBOOK_UNSAFE,
        ),
        (
            "macrosheet",
            build(&ok, &[("xl/macrosheets/sheet1.xml", Some("<x/>"))]),
            ERR_WORKBOOK_UNSAFE,
        ),
        (
            "vba",
            build(&ok, &[("xl/vbaProject.bin", Some("x"))]),
            ERR_WORKBOOK_UNSAFE,
        ),
        (
            "external relationship",
            build(
                &ok,
                &[(
                    "xl/_rels/workbook.xml.rels",
                    Some(
                        r#"<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet1.xml"/><Relationship Id="rId9" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/hyperlink" Target="https://example.com/" TargetMode="External"/></Relationships>"#,
                    ),
                )],
            ),
            ERR_WORKBOOK_UNSAFE,
        ),
        (
            "column 1001",
            build(
                &plus(&format!(r#"<row r="3">{}</row>"#, inl("ALM3", "x"))),
                &[],
            ),
            ERR_WORKBOOK_TOO_LARGE,
        ),
        (
            "column 1000 is fine",
            build(
                &plus(&format!(r#"<row r="3">{}</row>"#, inl("ALL3", "x"))),
                &[],
            ),
            "",
        ),
        (
            "row 100002",
            build(
                &plus(&format!(r#"<row r="100002">{}</row>"#, inl("A100002", "x"))),
                &[],
            ),
            ERR_WORKBOOK_TOO_LARGE,
        ),
        (
            "empty cells far away are fine",
            build(
                &plus(r#"<row r="200000"><c r="A200000" s="0"/></row>"#),
                &[],
            ),
            "",
        ),
        (
            "no visible sheet",
            build(
                &ok,
                &[(
                    "xl/workbook.xml",
                    Some(
                        r#"<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"><sheets><sheet name="Products" sheetId="1" state="veryHidden" r:id="rId1"/></sheets></workbook>"#,
                    ),
                )],
            ),
            ERR_WORKBOOK_SHEET_MISSING,
        ),
        (
            "not a zip",
            b"style_number\r\nX-1\r\n".to_vec(),
            ERR_WORKBOOK_INVALID,
        ),
        (
            "ole",
            vec![0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1, 0, 0],
            ERR_WORKBOOK_INVALID,
        ),
    ];
    let mut many = std::io::Cursor::new(Vec::new());
    {
        let mut z = zip::ZipWriter::new(&mut many);
        for i in 0..1001 {
            z.start_file(
                format!("x/{i}.txt"),
                zip::write::SimpleFileOptions::default(),
            )
            .unwrap();
            z.write_all(b"x").unwrap();
        }
        z.finish().unwrap();
    }
    let mut cases = cases;
    cases.push(("1001 entries", many.into_inner(), ERR_WORKBOOK_TOO_LARGE));
    for (name, data, code) in cases {
        let got = convert_workbook(&data, "products");
        match (code, got) {
            ("", Err(e)) => panic!("{name}: {e}"),
            ("", Ok(_)) => {}
            (c, Ok(_)) => panic!("{name}: want {c}"),
            (c, Err(e)) => assert_eq!(e.code, c, "{name}: {}", e.detail),
        }
    }
}

/// Rewrites one entry's declared uncompressed size in both the local header
/// and the central directory.
fn lie_about_size(data: &mut [u8], name: &str, size: u32) {
    let n = name.as_bytes();
    let mut i = 0;
    while i + 4 <= data.len() {
        let sig = &data[i..i + 4];
        if sig == b"PK\x03\x04" {
            let nl = u16::from_le_bytes([data[i + 26], data[i + 27]]) as usize;
            if data.get(i + 30..i + 30 + nl) == Some(n) {
                data[i + 22..i + 26].copy_from_slice(&size.to_le_bytes());
            }
        } else if sig == b"PK\x01\x02" {
            let nl = u16::from_le_bytes([data[i + 28], data[i + 29]]) as usize;
            if data.get(i + 46..i + 46 + nl) == Some(n) {
                data[i + 24..i + 28].copy_from_slice(&size.to_le_bytes());
            }
        }
        i += 1;
    }
}

#[test]
fn workbook_lying_size() {
    let big = format!(
        r#"<row r="1">{}</row>{}"#,
        inl("A1", "style_number"),
        r#"<row><c t="inlineStr"><is><t>x</t></is></c></row>"#.repeat(2000)
    );
    let mut data = build(&big, &[]);
    lie_about_size(&mut data, "xl/worksheets/sheet1.xml", 1000);
    let err = convert_workbook(&data, "products").expect_err("an error");
    assert_eq!(err.code, ERR_WORKBOOK_TOO_LARGE, "{}", err.detail);
}

#[test]
fn workbook_locator_cases() {
    let header: Vec<String> = ["Style Number", "name:en", " ean ", "", "weight_kg"]
        .iter()
        .map(|s| s.to_string())
        .collect();
    for (row, col, want) in [
        (12, "gtin", "row 12, column ean (C): "),
        (12, "style_number", "row 12, column Style Number (A): "),
        (0, "weight_kg", "column weight_kg (E): "),
        (4, "brand", "row 4: "),
        (0, "brand", ""),
        (4, "", "row 4: "),
    ] {
        assert_eq!(
            workbook_locator(&header, row, col),
            want,
            "({row}, {col:?})"
        );
    }
    assert_eq!(column_letter(1000), "ALL");
    assert_eq!(column_letter(26), "Z");
    assert_eq!(column_letter(27), "AA");
    assert_eq!(cell_locator(1, "", 5), "row 1, column E: ");
    assert_eq!(cell_locator(3, "ean", 3), "row 3, column ean (C): ");
}

#[test]
fn workbook_cdata() {
    let sheet = r#"<row r="1"><c r="A1" t="inlineStr"><is><t><![CDATA[style_number]]></t></is></c><c r="B1" t="inlineStr"><is><t>weight_kg</t></is></c><c r="C1" t="inlineStr"><is><t>name:en</t></is></c></row><row r="2"><c r="A2" t="inlineStr"><is><t>X-<![CDATA[1 & <2>]]></t></is></c><c r="B2"><v><![CDATA[1.50]]></v></c><c r="C2"><f><![CDATA[A1&"x"]]></f></c></row>"#;
    let wb = convert_workbook(&build(sheet, &[]), "products").unwrap();
    assert_eq!(
        wb.rows,
        vec![
            vec!["style_number", "weight_kg", "name:en"],
            vec!["", "", ""]
        ]
    );
    assert_eq!(wb.errors.len(), 1);
    assert_eq!(wb.errors[0].value.as_deref(), Some(r#"=A1&"x""#));
    let sheet = sheet.replace(r#"<c r="C2"><f><![CDATA[A1&"x"]]></f></c>"#, "");
    let wb = convert_workbook(&build(&sheet, &[]), "products").unwrap();
    assert_eq!(wb.rows[1], vec!["X-1 & <2>", "1.5", ""]);
}

#[test]
fn workbook_names() {
    assert!(is_workbook_name(" Products.XLSX "));
    assert!(!is_workbook_name("products.csv"));
    for n in ["a.xlsm", "a.xls", "a.ods", "a.numbers", "a.xltx"] {
        assert!(is_other_spreadsheet_name(n), "{n}");
    }
    assert!(!is_other_spreadsheet_name("a.xlsx"));
}
