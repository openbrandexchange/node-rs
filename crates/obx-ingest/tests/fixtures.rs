//! The canonical fixtures of the specification parse as expected.

use obx_ingest::importfmt::{
    KNOWN_ASSET_COLUMNS, KNOWN_COLUMNS, parse_care, parse_certifications, parse_csv, parse_feature,
    parse_footwear_materials, parse_image_name, parse_materials, unknown_columns,
};
use serde_json::Value;

const SPEC: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../obx-conformance/fixtures");

fn read(path: &str) -> Vec<u8> {
    std::fs::read(format!("{SPEC}/{path}")).unwrap_or_else(|e| panic!("{path}: {e}"))
}

#[test]
fn maison_noor_tables() {
    let products = parse_csv(&read("maison-noor/products.csv")).expect("products.csv");
    assert!(products.has("style_number") && products.has("name:en") && products.has("gtin"));
    assert!(!products.rows.is_empty());
    assert!(
        unknown_columns(&products.header, KNOWN_COLUMNS).is_empty(),
        "{:?}",
        unknown_columns(&products.header, KNOWN_COLUMNS)
    );
    for row in &products.rows {
        assert!(!row.get("style_number").is_empty(), "row {}", row.num);
        // The fixture gives no errors and no care warnings.
        if !row.get("materials").is_empty() {
            parse_materials(row.get("materials"))
                .unwrap_or_else(|e| panic!("row {}: {e}", row.num));
        }
        if !row.get("care").is_empty() {
            let (_, warns) = parse_care(row.get("care")).unwrap();
            assert!(warns.is_empty(), "row {}: {warns:?}", row.num);
        }
        if !row.get("footwear_materials").is_empty() {
            parse_footwear_materials(row.get("footwear_materials")).unwrap();
        }
        if !row.get("certifications").is_empty() {
            parse_certifications(row.get("certifications")).unwrap();
        }
        for h in &products.header {
            if let Some(k) = h.strip_prefix("feature:")
                && !row.get(h).is_empty()
            {
                parse_feature(k, row.get(h)).unwrap_or_else(|e| panic!("row {} {h}: {e}", row.num));
            }
        }
    }
    let assets = parse_csv(&read("maison-noor/assets.csv")).expect("assets.csv");
    assert!(assets.has("file"));
    assert!(!assets.rows.is_empty());
    assert!(unknown_columns(&assets.header, KNOWN_ASSET_COLUMNS).is_empty());
    for row in &assets.rows {
        parse_image_name(row.get("file")).unwrap_or_else(|e| panic!("{e}"));
    }
}

#[test]
fn image_filename_vectors() {
    let doc: Value = serde_json::from_slice(&read("expected/image-filenames.json")).unwrap();
    let cases = doc["cases"].as_array().unwrap();
    assert!(cases.len() >= 20, "only {} vectors", cases.len());
    for c in cases {
        let name = c["name"].as_str().unwrap();
        let parsed = parse_image_name(name);
        if c.get("error").is_some() {
            assert!(parsed.is_err(), "{name}: want an error, got {parsed:?}");
            continue;
        }
        let n = parsed.unwrap_or_else(|e| panic!("{name}: {e}"));
        // What the importer makes of it: ALL means every colour, no role means packshot.
        let color = (!n.color.eq_ignore_ascii_case("ALL")).then(|| n.color.clone());
        let role = n.role.clone().unwrap_or_else(|| "packshot".into());
        let external_id = format!(
            "{}_{}_{}",
            n.style,
            color.as_deref().unwrap_or("ALL"),
            n.position
        );
        assert_eq!(n.style, c["style"].as_str().unwrap(), "{name}: style");
        assert_eq!(color.as_deref(), c["color"].as_str(), "{name}: color");
        assert_eq!(
            u64::from(n.position),
            c["position"].as_u64().unwrap(),
            "{name}: position"
        );
        assert_eq!(role, c["role"].as_str().unwrap(), "{name}: role");
        assert_eq!(n.view.as_deref(), c["view"].as_str(), "{name}: view");
        assert_eq!(
            external_id,
            c["external_id"].as_str().unwrap(),
            "{name}: external_id"
        );
    }
}
