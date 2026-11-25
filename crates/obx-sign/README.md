# obx-sign

Signatures of the OBX protocol: windowed signed asset URLs (the same URL for a whole window, so HTTP caches hit; the bytes' cache key is their `sha256`; an expired but intact signature is told apart from a forged one), following spec proposal 0007, and the `v1=` webhook signature.

```rust,ignore
let s = obx_sign::UrlSigner::new(obx_auth::Keys::new(b"a master secret of at least 32 bytes!!"), "https://node.example");
let u = s.sign("/obx/v1/assets/ast_1/renditions/web", "c.cli_1");
assert!(u.url.contains("sig="));
```

Part of [node-rs](https://github.com/openbrandexchange/node-rs), the Open Brand Exchange reference node. The library crates are storage- and framework-agnostic (traits instead of a database), have no `unsafe` code, and need Rust 1.88 or newer.

Licence: Apache-2.0.
