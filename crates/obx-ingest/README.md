# obx-ingest

Getting catalog data into an OBX node: the canonical import format (CSV tables and headers, materials, care codes, article data, image file names, zip entry checks) and the part plan of resumable multipart uploads, as pure functions.

```rust,ignore
let p = obx_ingest::upload::PartPlan::new(20, 8);
assert_eq!(p.parts_total(), 3);
```

Part of [node-rs](https://github.com/openbrandexchange/node-rs), the Open Brand Exchange reference node. The library crates are storage- and framework-agnostic (traits instead of a database), have no `unsafe` code, and need Rust 1.88 or newer.

Licence: Apache-2.0.
