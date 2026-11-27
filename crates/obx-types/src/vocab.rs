//! The vocabularies of the OBX specification (`spec/vocabularies/*.json`,
//! CC-BY-4.0): part, material, qualifier and care codes with their names per
//! language and, for care, the ISO 3758 category and the GINETEX symbol code
//! (protocol.md §5.9.1). Port of node-go `internal/vocab`.

use std::collections::{BTreeMap, HashMap};
use std::sync::LazyLock;

use serde::Deserialize;

/// One vocabulary entry. `name` is empty when the code has no name (the
/// part `main`); empty strings in the file are dropped. `category` and
/// `symbol` are only used by care.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct Entry {
    pub code: String,
    #[serde(default, deserialize_with = "null_map")]
    pub name: BTreeMap<String, String>,
    #[serde(default)]
    pub category: Option<String>,
    #[serde(default)]
    pub symbol: Option<String>,
}

fn null_map<'de, D: serde::Deserializer<'de>>(d: D) -> Result<BTreeMap<String, String>, D::Error> {
    let m: Option<BTreeMap<String, String>> = Option::deserialize(d)?;
    let mut m = m.unwrap_or_default();
    m.retain(|_, v| !v.is_empty());
    Ok(m)
}

/// One vocabulary file, entries in file order.
#[derive(Debug)]
pub struct Vocabulary {
    entries: Vec<Entry>,
    by_code: HashMap<String, usize>,
}

impl Vocabulary {
    /// The entries in file order.
    pub fn entries(&self) -> &[Entry] {
        &self.entries
    }

    /// The entry of `code`.
    pub fn lookup(&self, code: &str) -> Option<&Entry> {
        self.by_code.get(code).map(|&i| &self.entries[i])
    }

    /// Reports whether `code` is in the vocabulary.
    pub fn has(&self, code: &str) -> bool {
        self.by_code.contains_key(code)
    }

    fn load(name: &str, json: &str) -> Vocabulary {
        #[derive(Deserialize)]
        struct Doc {
            entries: Vec<Entry>,
        }
        let doc: Doc = serde_json::from_str(json).unwrap_or_else(|e| panic!("vocab: {name}: {e}"));
        let by_code = doc
            .entries
            .iter()
            .enumerate()
            .map(|(i, e)| (e.code.clone(), i))
            .collect();
        Vocabulary {
            entries: doc.entries,
            by_code,
        }
    }
}

static PARTS: LazyLock<Vocabulary> =
    LazyLock::new(|| Vocabulary::load("parts", include_str!("../spec/vocabularies/parts.json")));
static MATERIALS: LazyLock<Vocabulary> = LazyLock::new(|| {
    Vocabulary::load(
        "materials",
        include_str!("../spec/vocabularies/materials.json"),
    )
});
static QUALIFIERS: LazyLock<Vocabulary> = LazyLock::new(|| {
    Vocabulary::load(
        "qualifiers",
        include_str!("../spec/vocabularies/qualifiers.json"),
    )
});
static CARE: LazyLock<Vocabulary> =
    LazyLock::new(|| Vocabulary::load("care", include_str!("../spec/vocabularies/care.json")));

/// The part codes.
pub fn parts() -> &'static Vocabulary {
    &PARTS
}

/// The material codes.
pub fn materials() -> &'static Vocabulary {
    &MATERIALS
}

/// The qualifier codes.
pub fn qualifiers() -> &'static Vocabulary {
    &QUALIFIERS
}

/// The care codes.
pub fn care() -> &'static Vocabulary {
    &CARE
}

/// Every language any vocabulary has a name in, sorted (`de`, `en`, `fr`,
/// `nl`): the term-only languages of discovery `selectable_languages`.
pub fn languages() -> Vec<String> {
    let mut out: Vec<String> = [parts(), materials(), qualifiers(), care()]
        .iter()
        .flat_map(|v| v.entries().iter().flat_map(|e| e.name.keys().cloned()))
        .collect();
    out.sort();
    out.dedup();
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vocabularies_load() {
        let main = parts().lookup("main").expect("main");
        assert!(main.name.is_empty());
        assert_eq!(parts().lookup("outer").unwrap().name["en"], "Outer fabric");
        assert!(materials().has("cotton") && materials().has("merino_wool"));
        assert_eq!(languages(), ["de", "en", "fr", "nl"]);
        assert!(qualifiers().has("recycled") && qualifiers().has("organic"));
        let w = care().lookup("wash_95").unwrap();
        assert_eq!(w.category.as_deref(), Some("washing"));
        assert_eq!(w.symbol.as_deref(), Some("1_A_95"));
        assert_eq!(care().lookup("wash_70").unwrap().symbol, None);
        assert!(!care().has("nope"));
        assert_eq!(care().entries()[0].code, "wash_95");
    }
}
