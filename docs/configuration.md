# Configuration

Environment variables, checked at start (`node-rs check-config` checks without starting; an unknown `OBX_…` variable is reported as a probable typo). Names and defaults are node-go's.

| Variable | Default | Meaning |
|---|---|---|
| `OBX_PUBLIC_URL` | `https://$OBX_DOMAIN`, else `http://localhost:$PORT` | The address people and software use, without a path. |
| `PORT` | `8080` | Port to listen on. |
| `OBX_BIND` | `0.0.0.0` | Address to listen on; the systemd unit uses `127.0.0.1` behind Caddy. |
| `OBX_DATA_DIR` | `./data` | Database, secret key and (by default) images. |
| `OBX_DATABASE_URL` | `sqlite:$OBX_DATA_DIR/obx.db` | SQLite only in this release. |
| `OBX_BLOB_URL` | `file://$OBX_DATA_DIR/blobs` | `file:///path`, `s3://bucket/prefix?region=…&endpoint=…&path_style=true`, `r2://bucket/prefix?endpoint=…`. |
| `OBX_S3_ACCESS_KEY_ID`, `OBX_S3_SECRET_ACCESS_KEY` | the `AWS_*` variables | Keys for an S3-compatible store. |
| `OBX_SECRET_KEY` | generated once into `$OBX_DATA_DIR/secret.key` | At least 32 characters. Signs links, encrypts stored secrets. Never change it after data exists. |
| `OBX_SETUP_CODE` | generated and printed in the log | One-time code for the first-run setup. |
| `OBX_TRUST_PROXY` | `false` | Take the client address from `X-Forwarded-For` (behind Caddy or a load balancer). |
| `OBX_WORKERS` | `2` | Background workers for imports and batches. |
| `OBX_CHANGE_RETENTION_DAYS` | `400` (90–36500) | How long the change history is kept. |
| `OBX_WEBHOOK_LOG_RETENTION_DAYS` | `8` (1–365) | How long webhook delivery logs are kept. |
| `OBX_LOG_FORMAT`, `OBX_LOG_LEVEL` | `text` (`json` in Docker), `info` | Logs go to standard error. |
| `OBX_ALLOW_PRIVATE_URLS` | `false` | Development only: allows http:// and private addresses for webhook and import URLs (link-local stays blocked). |
| `OBX_TEST_RATE_LIMIT` | not set | Conformance testing only: a lower per-minute API limit. |
