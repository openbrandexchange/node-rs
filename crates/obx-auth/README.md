# obx-auth

Secrets of an OBX node: random tokens and their hashes, constant-time comparison, argon2id passwords, keys derived from one master secret (HMAC signatures, AES-256-GCM at rest), the `obxa_` access-token format, OAuth2 client-credentials parsing (Basic and form) and signed opaque cursors. The formats are those of the Go reference node, so data written by either verifies on the other.

```rust,ignore
let keys = obx_auth::Keys::new(b"a master secret of at least 32 bytes!!");
let c = obx_auth::CursorCodec::new(keys, "nod_1");
let s = c.encode("products", &42);
assert_eq!(c.decode::<i32>("products", &s), Some(42));
```

Part of [node-rs](https://github.com/openbrandexchange/node-rs), the Open Brand Exchange reference node. The library crates are storage- and framework-agnostic (traits instead of a database), have no `unsafe` code, and need Rust 1.88 or newer.

Licence: Apache-2.0.
