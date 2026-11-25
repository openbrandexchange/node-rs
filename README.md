# node-rs

**The Open Brand Exchange reference node, in Rust.** One program for a brand's own portal: retailers log in, find products and download images and article data; their shop software reads the same content through the standard [OBX Protocol](https://github.com/openbrandexchange/spec/blob/main/docs/protocol.md). You publish with a spreadsheet and photos, or let your own systems do it through the Ingest API.

- One binary, or one Docker image. Linux first.
- SQLite by default (no database server to run); images on local disk or any S3-compatible bucket.
- Serves the bundled [admin-ui](https://github.com/openbrandexchange/admin-ui) for the brand and its retailers.
- Short-lived signed download links; originals byte-for-byte; web, square and thumb renditions made on the server.
- Checked against the [conformance suite](https://github.com/openbrandexchange/obx-go/tree/main/conformance) on every change.
- Runs on a node-go data folder as it is ([docs/migrating.md](docs/migrating.md)).

Status: under construction; what works and what is left is in [ROADMAP.md](ROADMAP.md).

## Run it locally

```sh
cargo run --release -- serve
```

Open <http://localhost:8080> and enter the setup code from the output. To load the example catalog of the fictional brand MAISON NOOR: in the admin, **Imports**, or

```sh
cargo run --release -- import --csv crates/obx-conformance/fixtures/maison-noor/products.csv \
  --assets crates/obx-conformance/fixtures/maison-noor/assets.csv --images crates/obx-conformance/fixtures/maison-noor/images
```

## Put it online

Linux or Docker, with Caddy for HTTPS: [docs/hosting.md](docs/hosting.md). Back up offsite: [docs/backup.md](docs/backup.md). Settings: [docs/configuration.md](docs/configuration.md). Coming from node-go, node-php or node-ts: [docs/migrating.md](docs/migrating.md).

## Command line

```
node-rs serve                                   start the portal (default)
node-rs import --csv FILE [--assets FILE] [--images DIR|ZIP] [--package ZIP] [--mode mirror] [--dry-run]
node-rs backup --to DIR                         consistent snapshot of database and secret key
node-rs admin create-ingest-token --name NAME   prints an automatic upload key
node-rs admin rotate-client-secret --client-id ID
node-rs admin simulate-spec-upgrade             expire every /changes cursor (410)
node-rs check-config | healthcheck | version
```

## For developers

```sh
cargo fmt --check && cargo clippy --all-targets -- -D warnings
cargo test
scripts/conformance.sh          # obx-conformance against a fresh node (needs obx-conformance on PATH)
scripts/update-ui.sh ../admin-ui
```

- `src/catalog.rs`: every catalog write, visibility and the change-feed entries (ingest.md §8).
- `src/http/`: protocol, change feed, Ingest API, admin API, the UI.
- `src/imports.rs`, `src/jobs.rs`, `src/uploads.rs`: the canonical import, background jobs, resumable uploads.
- `crates/`: the reusable library crates, Apache-2.0, storage- and framework-agnostic, ready for crates.io (not published yet):
  - `obx-types`: objects, problem documents, ids, GTINs, vocabularies, JSON Schema validation;
  - `obx-auth`: tokens, constant-time comparison, passwords, derived keys, access tokens, client credentials, signed cursors;
  - `obx-sign`: windowed signed asset URLs and webhook signatures;
  - `obx-feed`: the change-feed cursor and paging rules over a `FeedSource` trait;
  - `obx-ingest`: the canonical import format and resumable-upload part plans;
  - `obx-axum`: problem responses, security and `OBX-Version` headers, JSON, ranges, rate limits for axum;
  - `obx-client`: a typed client for retailer software;
  - `obx-conformance`: the spec's fixtures and the ingest replay for Rust tests.
  The node itself (this package: SQLite, HTTP server, admin-ui) is AGPL-3.0-only.
- `crates/obx-types/spec/` (schemas, vocabularies) and `crates/obx-conformance/fixtures/` are vendored from [openbrandexchange/spec](https://github.com/openbrandexchange/spec) (CC-BY-4.0).

Security problems: **security@openbrandexchange.com** ([SECURITY.md](SECURITY.md)).

## Licence

[GNU Affero General Public License v3.0](LICENSE) (AGPL-3.0-only). The embedded admin-ui is Apache-2.0; the spec files are CC-BY-4.0. See [NOTICE](NOTICE).
