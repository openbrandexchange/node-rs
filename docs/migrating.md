# Moving to node-rs

node-rs is the one reference node of Open Brand Exchange; node-go, node-php and node-ts are being retired. The protocol, the Ingest API, the import format and the admin screens stay the same, so retailers' software and your own automation keep working once they point at the new node.

Always make a backup of the old node first.

## From node-go

node-rs uses node-go's database schema, data folder and `OBX_*` settings, so it runs **on the same data folder**:

1. Back up: `node-go backup --to /backup/before-node-rs`.
2. Stop node-go, start node-rs with the same environment (`OBX_DATA_DIR`, `OBX_PUBLIC_URL`, `OBX_SECRET_KEY` or the `secret.key` in the data folder, `OBX_BLOB_URL`). With Docker, swap the image in your compose file for `ghcr.io/openbrandexchange/node-rs` and keep the volume; on Linux, replace the binary and the unit with [`deploy/node-rs.service`](../deploy/node-rs.service) and put Caddy in front ([hosting.md](hosting.md)): node-rs does not obtain certificates itself.
3. Check the admin and **View as retailer**.

What carries over: catalog, images, retailers, users and passwords, sessions, API keys and upload keys (secrets stay valid), access requests and the change history (retailers' `/changes` cursors keep working). The first write to each object after the move stores it in node-rs's own JSON layout; that write produces one ordinary upsert in the change feed even when the content did not change.

Not yet carried over: node-go on **PostgreSQL** (node-rs is SQLite-only for now; stay on node-go until PostgreSQL lands, see [ROADMAP.md](../ROADMAP.md)), Litestream replication (use [backup.md](backup.md) instead), and node-go's built-in HTTPS (`OBX_TLS=auto`; use Caddy). Features still on the roadmap (exports, webhooks, scheduled imports, statistics) keep their stored data and work again when they land.

## From node-php or node-ts

These nodes have their own databases (SQLite/MySQL, Cloudflare D1/R2), so the catalog moves through the import format and retailers get new keys:

1. Set up node-rs ([hosting.md](hosting.md)) on a new address or a temporary one.
2. Move the catalog: import the same `products.csv`, `assets.csv` and images you imported before (admin **Imports**, or `node-rs import --csv … --assets … --images …`). Your automation (`obx push`, PIM connectors, scheduled exports) only needs the new URL and a new upload key.
3. Recreate retailers and their access in the admin, and send retailers' software its new API key (client id and secret). Their software restarts `/changes` without a cursor and gets a full snapshot.
4. Move the domain: point the DNS record at the new server and set `OBX_PUBLIC_URL`.

A direct import of node-php and node-ts data (retailers, users, keys) is on the [roadmap](../ROADMAP.md).
