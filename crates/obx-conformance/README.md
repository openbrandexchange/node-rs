# obx-conformance

The fixtures of the OBX specification, embedded, for in-process Rust tests of any implementation: the MAISON NOOR catalog with images, the Excel workbooks, the example document of every schema (validated against obx-types), and the ingest replay script with its expected results and change entries, replayed through an `IngestTarget` trait. The HTTP-level suite is `obx-conformance` from obx-go.

```rust,ignore
assert!(obx_conformance::validate_examples().is_empty());
```

Part of [node-rs](https://github.com/openbrandexchange/node-rs), the Open Brand Exchange reference node. The library crates are storage- and framework-agnostic (traits instead of a database), have no `unsafe` code, and need Rust 1.88 or newer.

Licence: Apache-2.0 for the code; the embedded specification files (schemas, vocabularies, fixtures) are from [openbrandexchange/spec](https://github.com/openbrandexchange/spec) under CC-BY-4.0.
