# obx-axum

HTTP helpers for serving OBX with axum: problem+json answers, JSON bodies and responses, the `limit` parameter, Bearer tokens, `Range`, `Content-Disposition`, an in-memory rate limiter with `RateLimit-*` headers, and the security and `OBX-Version` headers of security.md §4.

```rust,ignore
let mut h = axum::http::HeaderMap::new();
obx_axum::security_headers(&mut h, obx_axum::Surface::Protocol, true);
```

Part of [node-rs](https://github.com/openbrandexchange/node-rs), the Open Brand Exchange reference node. The library crates are storage- and framework-agnostic (traits instead of a database), have no `unsafe` code, and need Rust 1.88 or newer.

Licence: Apache-2.0.
