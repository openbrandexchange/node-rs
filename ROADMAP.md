# Roadmap

node-rs replaces node-go, node-php and node-ts as the single reference node of Open Brand Exchange. The target was parity with node-go; this file says exactly what is done and what is left, and is updated with every change.

## Status (November 2026)

**Conformance:** `scripts/conformance.sh all` (obx-conformance from obx-go `main`, spec 0.3.1): **CONFORMANT** for protocol, ingest, portal and security, with **every check passing**: 71 passed, 0 failed, 0 not applicable (protocol, ingest, portal and security, required and optional). `CONFORMANCE_ARGS=--rate-limit-test scripts/conformance.sh security` also passes S-RATE-2. CI runs both on every change.

**node-go data folder:** node-rs runs on a node-go SQLite data folder as it is: same schema and migrations, blob layout, secret-key derivation, token, cursor and signed-URL formats, argon2id passwords, backups. `scripts/test-node-go-data.py` (CI job `node-go-data`) sets up node-go, imports the fixtures, then checks that node-rs accepts node-go's access token, client secret, `/changes` cursor and admin password and serves identical products. node-go on PostgreSQL moves with `node-rs import-postgres` ([docs/migrating.md](docs/migrating.md)).

**Library crates:** the protocol logic is in storage- and framework-agnostic crates under `crates/` (Apache-2.0, `#![forbid(unsafe_code)]`, MSRV 1.88 (the node itself needs 1.89), docs and examples, `cargo publish --dry-run` in CI): `obx-types`, `obx-auth`, `obx-sign`, `obx-feed`, `obx-ingest`, `obx-axum`, `obx-client`, `obx-conformance`. They are published on crates.io from each version tag (`.github/workflows/publish-crates.yml`, in dependency order, obx-types first).

## Parity with node-go

| Area | node-go | node-rs |
|---|---|---|
| Discovery, OAuth2 client credentials (basic + post), grant | ✓ | ✓ |
| Brands, products (keyset pages, ids, brand, updated_since), product ETag | ✓ | ✓ |
| GTIN lookup (GET and POST) | ✓ | ✓ |
| Assets, renditions (Range, If-None-Match, ETag, signed URLs, original only with media:original) | ✓ | ✓ (windowed signed URLs: one URL per hour window, `max-age` never past the expiry, spec proposal 0007) |
| Change feed (snapshot, live, grant entries with resync, cursor epochs, 410/400, retention pruning) | ✓ | ✓ |
| Language selection (`lang`, `Accept-Language`, `Content-Language`, `language_fallbacks`, `universal`; read endpoints, `/changes`, exports) | – | ✓ (spec proposal 0010, in `obx_types::lang` and `obx_feed::Page::narrow`; the cases of `expected/language-selection.json` in `obx-conformance`) |
| Access requests (create, poll, credentials once, e-mails) | ✓ | ✓ |
| Rate limits with RateLimit headers | ✓ | ✓ (per process, fixed window) |
| Exports (`exports`) | ✓ | ✓ |
| Webhooks (`webhooks`), brand webhooks | ✓ | ✓ (URL re-checked at delivery and at connect time) |
| Usage events (`usage`) | ✓ | ✓ |
| Ingest: records PUT/PATCH/DELETE, If-Match, extensions, article data, label warnings | ✓ | ✓ |
| Ingest: files, blobs, resumable uploads, asset order | ✓ | ✓ |
| Ingest: batch (JSON, NDJSON, async jobs), Idempotency-Key | ✓ | ✓ |
| Imports: canonical CSV, package zip, images manifest, mirror, dry run | ✓ | ✓ (zip-slip and decompression-bomb limits in `obx-ingest`) |
| Imports: Excel (.xlsx) | ✓ | ✓ (in `obx-ingest`, with property tests) |
| Scheduled imports (https, SFTP, S3 sources) | ✓ | ✓ (host keys pinned on first use; unchanged runs skipped; off in demo mode) |
| Server renditions (web, square, thumb; EXIF orientation; flatten on white) | ✓ | ✓ |
| Admin: setup, sessions, CSRF, login, logout, invitations, `/me`, password reset by e-mail | ✓ | ✓ |
| Admin: settings (merge patch, effects on rights and grants), logo, favicon, appearance images | ✓ | ✓ |
| Admin: catalog list, product, writes, files | ✓ | ✓ |
| Admin: retailers, API keys, upload keys, access requests, users (edit, delete, resend invite), retailer delete | ✓ | ✓ |
| Admin: imports list, detail, errors, template CSV | ✓ | ✓ |
| Portal appearance (theme, login, home blocks, public images, favicon) | ✓ | ✓ (validation and the neutral default per member, spec PR #17, in `obx_types::appearance`) |
| Retailer portal: products, facets, detail, EAN paste, selection, zips, data.csv, download jobs, self-service API keys | ✓ | ✓ |
| Statistics and download events | ✓ | ✓ |
| Audit log, personal-data export and erasure, retention | ✓ | ✓ |
| E-mail (SMTP outbox with retries, 25 languages) | ✓ | ✓ |
| Demo mode (`x-obx-demo`, `/admin/api/demo/login`) | node-ts | ✓ (seeded from the embedded fixtures, no seed archive; [docs/demo.md](docs/demo.md)) |
| Metrics (`/metrics`), `/readyz` drain | ✓ | ✓ |
| Storage: SQLite | ✓ | ✓ |
| Storage: PostgreSQL | ✓ | not planned: SQLite only, plus offsite backups; `node-rs import-postgres` copies a node-go PostgreSQL database once (CI job `node-go-postgres`) |
| Blobs: local disk, S3-compatible (incl. R2) | ✓ | ✓ (GCS with HMAC: via S3 endpoint, untested) |
| HTTPS built in (ACME) | ✓ | not planned: Caddy in front ([docs/hosting.md](docs/hosting.md)) |
| `backup --to` / `restore --from` | ✓ | ✓ (node-go's backup format, both ways) |
| CLI: import, admin create-ingest-token, rotate-client-secret, reset-password, audit-log, personal-data | ✓ | ✓ |
| Docker image, Linux binaries | ✓ | ✓ (release workflow on tags; not released yet) |
| HTTP integration tests, browser walk-through with axe, load test (10 000 products) | ✓ | ✓ (`src/tests_*.rs`, `e2e/`, [docs/performance.md](docs/performance.md)) |

## Quality

- `cargo clippy --workspace --all-targets -D warnings`, `cargo fmt`, no `unsafe` (forbidden workspace-wide), `cargo deny check` (licences, advisories, bans, sources) in CI.
- Property tests for the CSV, Excel and zip readers; zip-slip refusal and decompression-bomb limits (entries, total size, ratio).
- Constant-time comparison of every secret (`obx_auth::eq`, `subtle`).
- Security headers on every response (`obx_axum::security_headers`): CSP, `X-Content-Type-Options`, `Referrer-Policy`, `X-Frame-Options`, `Permissions-Policy`, HSTS behind HTTPS; CORS only on discovery.

## Left

Nothing of node-go's feature set is left. What remains is small, or a step for the maintainer:

1. **Dependencies:** `object_store` 0.12 still pulls in an old `quick-xml` with an advisory (ignored with its reason in `deny.toml`); moving to `object_store` 0.14 needs `reqwest` 0.13 across the node.
2. **Rate limits** are per process (in memory); enough for one instance, which is the supported setup.
3. **Untested combinations:** Google Cloud Storage through its S3 endpoint; `import-postgres` runs in CI only, not against a production-sized database.
4. **Maintainer steps:** `v0.1.0` is tagged (the release workflow builds the binaries and the image) and node-go, node-php and node-ts are deprecated. Still to do: the crates.io token (`CARGO_REGISTRY_TOKEN`, then the publish workflow runs), the demo host and DNS for demo.openbrandexchange.com ([docs/demo.md](docs/demo.md)), and archiving the old nodes after one release has run in production.

## Decisions taken (Richard, November 2026)

- SQLite only, plus offsite backups; a one-time `node-rs import-postgres` for node-go users on PostgreSQL.
- HTTPS through Caddy in front; no built-in TLS.
- node-go, node-php and node-ts are deprecated once the portal, e-mail and exports are in (they are), and archived after one node-rs release has run in production. They are deprecated (26-11); archiving waits for that production release.
- The first release is `v0.1.0` (26-11). Licences decided: the library crates Apache-2.0, the node AGPL-3.0-only.

## Decisions for the maintainer

- **A data import for node-php and node-ts** (retailers, users, API keys) or only the catalog re-import described in docs/migrating.md.
