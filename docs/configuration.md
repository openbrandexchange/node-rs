# Configuration

Environment variables, checked at start (`node-rs check-config` checks without starting; an unknown `OBX_…` variable is reported as a probable typo). Names and defaults are node-go's.

| Variable | Default | Meaning |
|---|---|---|
| `OBX_PUBLIC_URL` | `https://$OBX_DOMAIN`, else `http://localhost:$PORT` | The address people and software use, without a path. |
| `PORT` | `8080` | Port to listen on. |
| `OBX_BIND` | `0.0.0.0` | Address to listen on; the systemd unit uses `127.0.0.1` behind Caddy. |
| `OBX_DATA_DIR` | `./data` | Database, secret key and (by default) images. |
| `OBX_DATABASE_URL` | `sqlite:$OBX_DATA_DIR/obx.db` | SQLite only. A node-go PostgreSQL database is copied once with `node-rs import-postgres` ([migrating.md](migrating.md)). |
| `OBX_BLOB_URL` | `file://$OBX_DATA_DIR/blobs` | `file:///path`, `s3://bucket/prefix?region=…&endpoint=…&path_style=true`, `r2://bucket/prefix?endpoint=…`. |
| `OBX_S3_ACCESS_KEY_ID`, `OBX_S3_SECRET_ACCESS_KEY` | the `AWS_*` variables | Keys for an S3-compatible store. |
| `OBX_SECRET_KEY` | generated once into `$OBX_DATA_DIR/secret.key` | At least 32 characters. Signs links, encrypts stored secrets. Never change it after data exists. |
| `OBX_SETUP_CODE` | generated and printed in the log | One-time code for the first-run setup. |
| `OBX_TRUST_PROXY` | `false` | Take the client address from `X-Forwarded-For` (behind Caddy or a load balancer). |
| `OBX_WORKERS` | `2` | Background workers for imports and batches. |
| `OBX_CHANGE_RETENTION_DAYS` | `400` (90–36500) | How long the change history is kept; a `/changes` cursor from before answers `410 cursor_expired`. |
| `OBX_JOB_RETENTION_DAYS` | `30` (8–36500) | How long finished batch, export and download jobs and their results are kept. |
| `OBX_WEBHOOK_LOG_RETENTION_DAYS` | `8` (1–365) | How long the webhook delivery log is kept. |
| `OBX_SMTP_URL` | not set | `smtp://user:password@host:587` (STARTTLS) or `smtps://user:password@host:465`. Encode special characters in the password (`@` → `%40`). Without STARTTLS the node refuses to send credentials, except to `localhost`; `?insecure=true` allows a plain local relay. Not set: e-mails are written to the log (subject and recipient only) and invitation links are shown in the admin. Failed e-mails are retried for about a day (1, 5, 15 minutes, 1, 3, 6, 12 hours). |
| `OBX_MAIL_FROM` | `no-reply@` + the host of `OBX_PUBLIC_URL` | Sender address: a plain address such as `portal@yourbrand.com`. |
| `OBX_MAIL_LOG_BODIES` | `false` | Development only: log whole e-mails, one-time links included. |
| `OBX_ACCESS_LOG` | `true` | One info line per request (method, route, path without query, status, duration, request id). Client addresses are never logged. |
| `OBX_METRICS` | `false` (`true` when a token is set) | Prometheus metrics at `/metrics`: requests and latency per route, jobs, mail outbox, webhook queue, change feed, catalog counts. |
| `OBX_METRICS_TOKEN` | not set | At least 16 characters; scrapers send `Authorization: Bearer <token>`. Without it `/metrics` is readable by anyone who can reach the node. |
| `OBX_SHUTDOWN_DELAY` | `0` (0–60) | Seconds `/readyz` answers 503 after SIGTERM before the server stops accepting requests (for load balancers). Running requests always finish. |
| `OBX_LOG_FORMAT`, `OBX_LOG_LEVEL` | `text` (`json` in Docker), `info` | Logs go to standard error. |
| `OBX_ALLOW_PRIVATE_URLS` | `false` | Development only: allows http:// and private addresses for webhook and import URLs (link-local stays blocked). |
| `OBX_DEMO` | `false` | Public demo mode ([demo.md](demo.md)). **Every reset deletes all data**: never on a real portal. |
| `OBX_DEMO_RESET_MINUTES` | `60` (5–10080) | Demo mode: how often the demo is put back to the fixtures (only when a visitor changed something, else once a day). |
| `OBX_DEMO_MAX_UPLOAD_BYTES` | `2097152` (65536–33554432) | Demo mode: the largest request body. |
| `OBX_DEMO_TURNSTILE_SITE_KEY` | not set | Demo mode: Cloudflare Turnstile site key (public) for the sign-in buttons. |
| `OBX_DEMO_TURNSTILE_SECRET` | not set | Demo mode: its secret key; without it there is no Turnstile check. Needs the site key. |
| `OBX_TEST_RATE_LIMIT` | not set | Conformance testing only: a lower per-minute API limit. |

`/healthz` answers `ok` while the process and database work; `/readyz` answers JSON (`status`, `version`, `schema_version`, `checks`) and 503 while shutting down or when the database or file store does not answer. Every response carries an `X-Request-Id` (a sane incoming one is kept); the audit log records it.

Retention of personal data is set by the brand under Settings (`retention`: download statistics 730 days, audit log 365 days, decided access requests 365 days). Names leave the download statistics after at most 400 days. Housekeeping runs every 30 seconds: e-mail retries, expired image rights, and every five minutes expired sessions, uploads, prepared downloads and exports, old jobs and the retention limits above; the change history is pruned hourly.
