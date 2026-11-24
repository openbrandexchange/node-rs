# node-rs

**The Open Brand Exchange reference node, in Rust.** One program for a brand's own portal: retailers log in, find products and download images and article data; their shop software reads the same content through the standard [OBX Protocol](https://github.com/openbrandexchange/spec/blob/main/docs/protocol.md). You publish with a spreadsheet and photos, or let your own systems do it through the Ingest API.

- One binary, or one Docker image. Linux first.
- SQLite by default (no database server to run); images on local disk or any S3-compatible store.
- Serves the [admin-ui](https://github.com/openbrandexchange/admin-ui) for the brand and its retailers.
- Short-lived signed download links; originals byte-for-byte.
- Checked against the [conformance suite](https://github.com/openbrandexchange/obx-go/tree/main/conformance) on every change.

Status: under construction. What works and what is left is in [ROADMAP.md](ROADMAP.md).

## Licence

[GNU Affero General Public License v3.0](LICENSE) (AGPL-3.0-only). See [NOTICE](NOTICE).
