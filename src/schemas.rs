//! Validation against the spec's JSON Schemas (spec/schemas, embedded).
//! Writes are checked leniently (unknown members allowed, as ingest.md §3.1
//! requires) and, separately, strictly to name the unknown members that are
//! ignored.

use std::collections::HashMap;
use std::sync::{LazyLock, Mutex};

use jsonschema::{Resource, ValidationError, Validator, error::ValidationErrorKind};
use rust_embed::Embed;
use serde_json::Value;

#[derive(Embed)]
#[folder = "spec/schemas/"]
struct Files;

pub const BASE: &str = "https://openbrandexchange.com/schemas/v0.3/";

#[derive(Debug, Clone)]
pub struct FieldError {
    pub pointer: String,
    pub message: String,
}

fn open_closed(v: &mut Value) {
    match v {
        Value::Object(m) => {
            if m.get("additionalProperties") == Some(&Value::Bool(false)) {
                m.remove("additionalProperties");
            }
            m.values_mut().for_each(open_closed);
        }
        Value::Array(a) => a.iter_mut().for_each(open_closed),
        _ => {}
    }
}

struct Set {
    lenient: bool,
    docs: HashMap<String, Value>,
    cache: Mutex<HashMap<String, &'static Validator>>,
}

impl Set {
    fn new(lenient: bool) -> Set {
        let mut docs = HashMap::new();
        for name in Files::iter() {
            let f = Files::get(&name).expect("embedded schema");
            let mut v: Value = serde_json::from_slice(&f.data).expect("schema json");
            if lenient {
                open_closed(&mut v);
            }
            docs.insert(name.trim_end_matches(".json").to_string(), v);
        }
        Set {
            lenient,
            docs,
            cache: Mutex::new(HashMap::new()),
        }
    }

    fn validator(&self, name: &str) -> &'static Validator {
        let mut c = self.cache.lock().unwrap();
        if let Some(v) = c.get(name) {
            return v;
        }
        let mut opts = jsonschema::options().should_validate_formats(true);
        for (n, d) in &self.docs {
            opts = opts.with_resource(
                format!("{BASE}{n}.json"),
                Resource::from_contents(d.clone()).expect("schema resource"),
            );
        }
        let schema = match name.split_once('#') {
            Some((file, frag)) => serde_json::json!({"$ref": format!("{BASE}{file}.json#{frag}")}),
            None => self
                .docs
                .get(name)
                .cloned()
                .unwrap_or_else(|| panic!("unknown schema {name}")),
        };
        let v: &'static Validator =
            Box::leak(Box::new(opts.build(&schema).unwrap_or_else(|e| {
                panic!("schema {name} (lenient {}): {e}", self.lenient)
            })));
        c.insert(name.to_string(), v);
        v
    }
}

static LENIENT: LazyLock<Set> = LazyLock::new(|| Set::new(true));
static STRICT: LazyLock<Set> = LazyLock::new(|| Set::new(false));

fn leaf_errors(e: &ValidationError<'_>, out: &mut Vec<FieldError>) {
    out.push(FieldError {
        pointer: e.instance_path.to_string(),
        message: e.to_string(),
    });
}

/// Errors of doc against schema `name` (unknown members allowed).
pub fn validate(name: &str, doc: &Value) -> Vec<FieldError> {
    let v = LENIENT.validator(name);
    let mut out = Vec::new();
    for e in v.iter_errors(doc) {
        leaf_errors(&e, &mut out);
    }
    out.sort_by(|a, b| a.pointer.cmp(&b.pointer));
    out.dedup_by(|a, b| a.pointer == b.pointer && a.message == b.message);
    out
}

/// Errors of doc against the closed schema (producers check their output).
pub fn validate_strict(name: &str, doc: &Value) -> Vec<FieldError> {
    let v = STRICT.validator(name);
    let mut out = Vec::new();
    for e in v.iter_errors(doc) {
        leaf_errors(&e, &mut out);
    }
    out
}

fn collect_unknown(e: &ValidationError<'_>, seen: &mut Vec<String>) {
    match &e.kind {
        ValidationErrorKind::AdditionalProperties { unexpected } => {
            let base = e.instance_path.to_string();
            for p in unexpected {
                let ptr = format!("{base}/{}", p.replace('~', "~0").replace('/', "~1"));
                if !seen.contains(&ptr) {
                    seen.push(ptr);
                }
            }
        }
        ValidationErrorKind::AnyOf { context } | ValidationErrorKind::OneOfNotValid { context } => {
            for branch in context {
                for c in branch {
                    collect_unknown(c, seen);
                }
            }
        }
        _ => {}
    }
}

/// JSON Pointers of the members the closed schema does not know (extensions
/// `x-…` where the schema allows them are not unknown).
pub fn unknown_members(name: &str, doc: &Value) -> Vec<String> {
    let v = STRICT.validator(name);
    let mut out = Vec::new();
    for e in v.iter_errors(doc) {
        collect_unknown(&e, &mut out);
    }
    out.sort();
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn examples_validate() {
        let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/spec/fixtures/examples");
        for e in std::fs::read_dir(dir).unwrap() {
            let p = e.unwrap().path();
            let name = p.file_name().unwrap().to_string_lossy().to_string();
            if !name.ends_with(".json") || name.starts_with("webhook-") {
                continue;
            }
            let schema = name.split('.').next().unwrap();
            if !Files::iter().any(|f| f == format!("{schema}.json")) {
                continue;
            }
            let doc: Value = serde_json::from_slice(&std::fs::read(&p).unwrap()).unwrap();
            let errs = validate_strict(schema, &doc);
            assert!(errs.is_empty(), "{name}: {errs:?}");
        }
    }

    #[test]
    fn unknown_member_is_reported() {
        let doc = serde_json::json!({"style_number": "A", "name": {"en": "A"}, "colour": "x", "x-acme-crop": 1});
        assert_eq!(
            unknown_members("ProductInput", &doc),
            vec!["/colour".to_string()]
        );
        assert!(validate("ProductInput", &doc).is_empty());
    }
}
