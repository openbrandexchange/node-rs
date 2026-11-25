# obx-feed

The OBX change feed without storage: the cursor format and the snapshot-then-live paging rules (high-water mark, epochs, 24-hour snapshots, retention), over a `FeedSource` trait that your storage implements.

```rust,ignore
// see the crate documentation for a complete in-memory FeedSource
```

Part of [node-rs](https://github.com/openbrandexchange/node-rs), the Open Brand Exchange reference node. The library crates are storage- and framework-agnostic (traits instead of a database), have no `unsafe` code, and need Rust 1.88 or newer.

Licence: Apache-2.0.
