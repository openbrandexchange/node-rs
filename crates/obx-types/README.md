# obx-types

Types of the Open Brand Exchange (OBX) protocol 0.3: the objects a node publishes and accepts (brands, products, variants, assets, rights, provenance, materials, care, measurements, features), RFC 9457 problem documents with the OBX error codes, object ids, GTINs, the spec's vocabularies and validation against the spec's JSON Schemas.

Features: `validate` (default) embeds the JSON Schemas and validates documents; `axum` makes `Problem` an axum response.

```rust,ignore
let p = obx_types::Problem::new("not_found", "Product not found.");
assert_eq!(p.status, 404);
```

Part of [node-rs](https://github.com/openbrandexchange/node-rs), the Open Brand Exchange reference node. The library crates are storage- and framework-agnostic (traits instead of a database), have no `unsafe` code, and need Rust 1.88 or newer.

Licence: Apache-2.0 for the code; the embedded specification files (schemas, vocabularies, fixtures) are from [openbrandexchange/spec](https://github.com/openbrandexchange/spec) under CC-BY-4.0.
