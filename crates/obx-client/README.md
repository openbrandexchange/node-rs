# obx-client

A typed async client for retailer software: discovery, OAuth2 client credentials with token renewal, brands, products, GTIN lookup, the change feed, assets and rendition bytes, and access requests. Retries once after `invalid_token` and waits out short `Retry-After`s.

```rust,ignore
let c = obx_client::Client::new("https://brand.example", "obxc_…", "obxs_…")?;
let page = c.changes(None, 500).await?;
```

Part of [node-rs](https://github.com/openbrandexchange/node-rs), the Open Brand Exchange reference node. The library crates are storage- and framework-agnostic (traits instead of a database), have no `unsafe` code, and need Rust 1.88 or newer.

Licence: Apache-2.0.
