# Roadmap

node-rs replaces node-go, node-php and node-ts as the single reference node of Open Brand Exchange. The target is parity with node-go. This file says exactly what is done and what is left; it is updated with every change.

## Status (first milestone, November 2026)

**Conformance:** `scripts/conformance.sh all` (obx-conformance from obx-go `main`, spec 0.3.1): **CONFORMANT** for protocol, ingest, portal and security. 60 required checks pass (protocol 24, ingest 20, portal 8, security 8), none fail or are skipped. Not applicable: P-EXP-1, P-HOOK-1, P-USE-1 (capabilities not offered yet). Optional checks not met yet: I-IMP-9, I-IMP-10 (Excel), A-SRC-1 (scheduled imports), A-PORT-1, A-PORT-2, A-STAT-1, S-HDR-1, S-CSV-1 (retailer portal and statistics). S-RATE-2 runs only with `--rate-limit-test`.

**node-go data folder:** node-rs runs on a node-go SQLite data folder as it is: same schema and migrations, blob layout, secret-key derivation, token, cursor and signed-URL formats, argon2id passwords. `scripts/test-node-go-data.py` (CI job `node-go-data`) sets up node-go, imports the fixtures, then checks that node-rs accepts node-go's access token, client secret, `/changes` cursor and admin password and serves identical products.

## Parity with node-go

| Area | node-go | node-rs |
|---|---|---|
| Discovery, OAuth2 client credentials (basic + post), grant | ✓ | ✓ |
| Brands, products (keyset pages, ids, brand, updated_since), product ETag | ✓ | ✓ |
| GTIN lookup (GET and POST) | ✓ | ✓ |
| Assets, renditions (Range, If-None-Match, ETag, signed 1-hour URLs, original only with media:original) | ✓ | ✓ |
| Change feed (snapshot, live, grant entries with resync, cursor epochs, 410/400) | ✓ | ✓ (retention pruning job: left) |
| Access requests (create, poll, credentials once) | ✓ | ✓ (e-mails: left) |
| Rate limits with RateLimit headers | ✓ | ✓ (per process, fixed window) |
| Exports (`exports`) | ✓ | **left** (501) |
| Webhooks (`webhooks`), brand webhooks | ✓ | **left** (501; URL policy checked) |
| Usage events (`usage`) | ✓ | **left** (501) |
| Ingest: records PUT/PATCH/DELETE, If-Match, extensions, article data, label warnings | ✓ | ✓ |
| Ingest: files, blobs, resumable uploads, asset order | ✓ | ✓ |
| Ingest: batch (JSON, NDJSON, async jobs), Idempotency-Key | ✓ | ✓ |
| Imports: canonical CSV, package zip, images manifest, mirror, dry run | ✓ | ✓ |
| Imports: Excel (.xlsx) | ✓ | **left** (refused with `workbook_invalid`) |
| Scheduled imports (https, SFTP, S3 sources) | ✓ | **left** (URL policy only; create answers 501) |
| Server renditions (web, square, thumb; EXIF orientation; flatten on white) | ✓ | ✓ |
| Admin: setup, sessions, CSRF, login, logout, invitations, `/me` | ✓ | ✓ (password reset by e-mail: left) |
| Admin: settings (merge patch, effects on rights and grants), logo | ✓ | ✓ (favicon, appearance images `settings/images`: left) |
| Admin: catalog list, product, writes, files | ✓ | ✓ |
| Admin: retailers, API keys, upload keys, access requests | ✓ | ✓ (retailer delete, user edit/delete, resend invite: left) |
| Admin: imports list, detail, errors, template CSV | ✓ | ✓ (template CSV: left) |
| Portal appearance (theme, login, home blocks, public images) | ✓ | partial: stored and returned by settings; `public/images`, `favicon` and `home` resolution left |
| Retailer portal: products, facets, detail, EAN paste, selection, zips, data.csv, download jobs, self-service API keys | ✓ | **left** (`portal/viewer` only) |
| Statistics and download events | ✓ | **left** (`stats` returns zeros) |
| Audit log, personal-data export and erasure, retention | ✓ | **left** |
| E-mail (SMTP outbox with retries, 25 languages) | ✓ | **left** (links are shown in the admin and logged) |
| Demo mode (`x-obx-demo`, `/admin/api/demo/login`) | node-ts | **left** |
| Metrics (`/metrics`), `/readyz` drain | ✓ | **left** (`/healthz`, `/readyz` answer) |
| Storage: SQLite | ✓ | ✓ |
| Storage: PostgreSQL | ✓ | **left** (decision needed, see below) |
| Blobs: local disk, S3-compatible (incl. R2) | ✓ | ✓ (GCS with HMAC: via S3 endpoint, untested) |
| HTTPS built in (ACME) | ✓ | not planned: Caddy in front (docs/hosting.md) |
| `backup --to` / `restore --from` | ✓ | `backup` ✓, `restore`: left (manual steps in docs/backup.md) |
| CLI: import, admin create-ingest-token, rotate-client-secret | ✓ | ✓ (`reset-password`, `audit-log`, `personal-data`: left) |
| Docker image, Linux binaries | ✓ | ✓ (release workflow on tags; not released yet) |
| Browser tests with axe (e2e), load test (10 000 products) | ✓ | **left** |

## Next milestones, in order

1. **Retailer portal API** (`/admin/api/portal/*`): list with facets, detail, EAN paste, selection, single-image and zip downloads, `data.csv`, background download jobs, self-service API keys; download events and statistics. Closes A-PORT-1, A-PORT-2, A-STAT-1, S-HDR-1, S-CSV-1 and makes the retailer side of admin-ui usable.
2. **E-mail**: SMTP outbox with retries, the `email.*` texts from `ui/dist/locales`; password reset.
3. **Exports, webhooks, usage** (P-EXP-1, P-HOOK-1, P-USE-1), with the SSRF-safe HTTP client of `src/safeurl.rs`.
4. **Excel import** (I-IMP-9, I-IMP-10): port node-go `internal/importfmt/xlsx.go` into `crates/obx-format`.
5. **Scheduled imports** (A-SRC-1): https, SFTP and S3 sources with fingerprints.
6. **Operations**: change-history pruning job, job retention, audit log, personal data, `/metrics`, `restore --from`, the remaining admin endpoints (users, favicon, appearance images, import template), demo mode for demo.openbrandexchange.com.
7. **Tests**: port node-go's HTTP integration tests and the e2e browser walk with axe; the 10 000-product load test.
8. **PostgreSQL**, if decided.

## Decisions for the maintainer

- **PostgreSQL or SQLite only.** node-rs is SQLite-only today. node-go users on PostgreSQL cannot move until it exists. Option: support PostgreSQL behind the same queries (the schema is node-go's and already has a PostgreSQL form), or declare SQLite (plus offsite backups) the one opinionated choice and offer a one-time PostgreSQL → SQLite copy tool.
- **Built-in HTTPS.** node-go obtained certificates itself; node-rs relies on Caddy in front. Keep it that way (less code, one proven ACME client) or add ACME later.
- **Archiving node-go, node-php, node-ts.** Suggested: once milestones 1 to 3 are done (retailer portal, e-mail, exports/webhooks), mark the three repositories deprecated with a pointer to docs/migrating.md, and archive them after one release of node-rs has been in production use.
- **A data import for node-php and node-ts** (retailers, users, API keys) or only the catalog re-import described in docs/migrating.md.
- **First release** (tag `v0.1.0`) and publishing `ghcr.io/openbrandexchange/node-rs`: the docs and the website describe both; nothing is published until a tag is pushed.
