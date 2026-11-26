//! The fixtures of the Open Brand Exchange specification, embedded, with
//! helpers to run them from Rust tests of any OBX implementation:
//!
//! * [`file()`] / [`files()`]: every fixture file (the MAISON NOOR catalog as
//!   canonical CSV with its images, the Excel workbooks, the expected
//!   objects);
//! * [`examples`] and [`validate_examples`]: the example document of every
//!   schema, checked against the schemas of `obx-types`;
//! * [`IngestScript`] and [`replay`]: the 18-operation ingest script with
//!   the expected result of each operation and the live change entries it
//!   must produce, replayed against your implementation through the
//!   [`IngestTarget`] trait.
//!
//! The HTTP-level suite (every profile, every check) is `obx-conformance`
//! from obx-go; this crate is for in-process tests.
//!
//! ```
//! let counts = obx_conformance::expected_counts();
//! assert_eq!(counts["products"], 11);
//! assert!(obx_conformance::file("maison-noor/products.csv").is_some());
//! assert!(obx_conformance::validate_examples().is_empty());
//! ```
#![forbid(unsafe_code)]

use std::borrow::Cow;

use rust_embed::Embed;
use serde::Deserialize;
use serde_json::Value;
use sha2::{Digest, Sha256};

#[derive(Embed)]
#[folder = "fixtures/"]
struct Files;

/// A fixture file by its path under `fixtures/` (for example
/// `maison-noor/products.csv`).
pub fn file(path: &str) -> Option<Cow<'static, [u8]>> {
    Files::get(path).map(|f| f.data)
}

/// The paths of every fixture file under a prefix ("" = all), sorted.
pub fn files(prefix: &str) -> Vec<String> {
    let mut v: Vec<String> = Files::iter()
        .filter(|p| p.starts_with(prefix))
        .map(|p| p.into_owned())
        .collect();
    v.sort();
    v
}

fn json_file(path: &str) -> Value {
    serde_json::from_slice(&file(path).unwrap_or_else(|| panic!("fixture {path}")))
        .unwrap_or_else(|e| panic!("fixture {path}: {e}"))
}

/// `expected/counts.json`: the visible objects after importing
/// `maison-noor/` into a fresh node.
pub fn expected_counts() -> Value {
    json_file("expected/counts.json")
}

/// Every example document: (file name, schema name, document). An
/// `.ndjson` example yields one document per line.
pub fn examples() -> Vec<(String, String, Value)> {
    let mut out = Vec::new();
    for p in files("examples/") {
        let name = p.trim_start_matches("examples/").to_string();
        let schema = name.split('.').next().unwrap_or("").to_string();
        let data = file(&p).unwrap_or_default();
        if name.ends_with(".ndjson") {
            for line in String::from_utf8_lossy(&data)
                .lines()
                .filter(|l| !l.trim().is_empty())
            {
                if let Ok(v) = serde_json::from_str(line) {
                    out.push((name.clone(), schema.clone(), v));
                }
            }
        } else if name.ends_with(".json") {
            if let Ok(v) = serde_json::from_slice(&data) {
                out.push((name, schema, v));
            }
        }
    }
    out
}

/// Validates (strictly) every example whose prefix names a spec schema; the failures
/// as `file: pointer: message` (empty = all valid).
pub fn validate_examples() -> Vec<String> {
    let mut bad = Vec::new();
    let names = obx_types::schemas::schema_names();
    for (name, schema, doc) in examples() {
        if !name.starts_with("webhook-") && names.contains(&schema) {
            for e in obx_types::schemas::validate_strict(&schema, &doc) {
                bad.push(format!("{name}: {}: {}", e.pointer, e.message));
            }
        }
    }
    bad
}

/// One operation of `ingest/script.ndjson`.
#[derive(Debug, Clone, Deserialize)]
pub struct Operation {
    /// `upsert`, `patch`, `publish`, `unpublish` or `delete`.
    pub op: String,
    /// `brand`, `product`, `variant` or `asset`.
    pub kind: String,
    pub external_id: String,
    #[serde(default)]
    pub data: Option<Value>,
}

/// The expected outcome of one operation.
#[derive(Debug, Clone, Deserialize)]
pub struct Expected {
    pub index: usize,
    pub result: String,
    #[serde(default)]
    pub obx_error: Option<String>,
}

/// An expected live change entry.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct ExpectedChange {
    pub after_op: usize,
    #[serde(rename = "type")]
    pub kind: String,
    pub op: String,
    pub external_id: String,
}

/// The ingest replay script (fixtures/README.md, "Replaying the ingest
/// script").
#[derive(Debug, Clone)]
pub struct IngestScript {
    pub operations: Vec<Operation>,
    pub expected: Vec<Expected>,
    pub changes: Vec<ExpectedChange>,
    /// (sha256, bytes) of every image the script references (the images of
    /// `ingest/files/`, not its `files.json` index).
    pub blobs: Vec<(String, Vec<u8>)>,
}

impl IngestScript {
    pub fn load() -> IngestScript {
        let ops =
            String::from_utf8_lossy(&file("ingest/script.ndjson").expect("script")).into_owned();
        let operations = ops
            .lines()
            .filter(|l| !l.trim().is_empty())
            .map(|l| serde_json::from_str(l).expect("script line"))
            .collect();
        let expected = serde_json::from_value(json_file("ingest/expected-results.json"))
            .expect("expected results");
        let changes =
            serde_json::from_value(json_file("ingest/expected-changes.json")["changes"].clone())
                .expect("expected changes");
        let blobs = files("ingest/files/")
            .into_iter()
            .filter(|p| !p.ends_with(".json"))
            .map(|p| {
                let b = file(&p).unwrap_or_default().into_owned();
                (hex::encode(Sha256::digest(&b)), b)
            })
            .collect();
        IngestScript {
            operations,
            expected,
            changes,
            blobs,
        }
    }
}

/// What [`replay`] needs from an implementation.
pub trait IngestTarget {
    /// Stores a blob (`PUT /obx/v1/ingest/blobs/{sha256}`).
    fn put_blob(&mut self, sha256: &str, bytes: &[u8]) -> Result<(), String>;
    /// Applies one operation; the IngestResult `result` (`created`,
    /// `updated`, `unchanged`, `deleted`, or `error` for a refused
    /// operation) and the `obx_error` of a refusal. Waiting for server renditions is the target's business.
    fn apply(&mut self, op: &Operation) -> Result<(String, Option<String>), String>;
    /// The live change entries (type, op, external_id) since the previous
    /// call (the first call drains the snapshot and returns nothing).
    fn new_changes(&mut self) -> Result<Vec<(String, String, String)>, String>;
}

/// Replays the ingest script; the differences from the expected results and
/// change entries (empty = conformant).
pub fn replay<T: IngestTarget>(t: &mut T) -> Vec<String> {
    let s = IngestScript::load();
    let mut diffs = Vec::new();
    if let Err(e) = t.new_changes() {
        return vec![format!("initial snapshot: {e}")];
    }
    for (sha, b) in &s.blobs {
        if let Err(e) = t.put_blob(sha, b) {
            diffs.push(format!("blob {sha}: {e}"));
        }
    }
    for (i, op) in s.operations.iter().enumerate() {
        let want = s.expected.iter().find(|e| e.index == i);
        match t.apply(op) {
            Err(e) => diffs.push(format!(
                "op {i} ({} {} {}): {e}",
                op.op, op.kind, op.external_id
            )),
            Ok((result, code)) => {
                if let Some(w) = want {
                    if w.result != result || (w.obx_error.is_some() && w.obx_error != code) {
                        diffs.push(format!(
                            "op {i} ({} {} {}): got {result} {code:?}, want {} {:?}",
                            op.op, op.kind, op.external_id, w.result, w.obx_error
                        ));
                    }
                }
            }
        }
        let got = match t.new_changes() {
            Ok(g) => g,
            Err(e) => {
                diffs.push(format!("changes after op {i}: {e}"));
                continue;
            }
        };
        let want: Vec<(String, String, String)> = s
            .changes
            .iter()
            .filter(|c| c.after_op == i)
            .map(|c| (c.kind.clone(), c.op.clone(), c.external_id.clone()))
            .collect();
        if got != want {
            diffs.push(format!("changes after op {i}: got {got:?}, want {want:?}"));
        }
    }
    diffs
}

#[cfg(test)]
mod tests {
    #[test]
    fn script_loads() {
        let s = super::IngestScript::load();
        assert_eq!(s.operations.len(), 18);
        assert_eq!(s.expected.len(), 18);
        assert!(!s.changes.is_empty() && !s.blobs.is_empty());
    }
}
