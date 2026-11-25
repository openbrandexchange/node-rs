# Hosting node-rs

One program, one data folder. Pick **Linux** or **Docker**; both put [Caddy](https://caddyserver.com) in front for HTTPS with free, automatically renewed certificates. node-rs itself speaks plain HTTP on port 8080.

Before you start: a server (any VPS with 1 GB of memory is enough for a start) and an A record for your portal's address, for example `portal.yourbrand.com`, pointing at its IP address.

## Linux (x86_64 or arm64)

```sh
# 1. The binary (from the latest release)
curl -fsSLO https://github.com/openbrandexchange/node-rs/releases/latest/download/node-rs-$(uname -m)-linux.tar.gz
tar xzf node-rs-$(uname -m)-linux.tar.gz && sudo install node-rs /usr/local/bin/

# 2. A system user and the service
sudo useradd --system --home /var/lib/node-rs --create-home --shell /usr/sbin/nologin node-rs
sudo curl -fsSL -o /etc/systemd/system/node-rs.service \
  https://raw.githubusercontent.com/openbrandexchange/node-rs/main/deploy/node-rs.service
sudo systemctl edit node-rs   # add:  [Service]  Environment=OBX_PUBLIC_URL=https://portal.yourbrand.com
sudo systemctl enable --now node-rs

# 3. HTTPS: install Caddy (https://caddyserver.com/docs/install), then
echo 'portal.yourbrand.com {
	reverse_proxy 127.0.0.1:8080
}' | sudo tee /etc/caddy/Caddyfile && sudo systemctl reload caddy

# 4. The one-time setup code
journalctl -u node-rs | grep 'setup code'
```

Open `https://portal.yourbrand.com`, enter the setup code, your company name and your own password. Data lives in `/var/lib/node-rs`. Update: install the new binary and `sudo systemctl restart node-rs` (migrations run on start and only move forward; take a backup first).

## Docker

```sh
curl -fsSLO https://raw.githubusercontent.com/openbrandexchange/node-rs/main/deploy/compose.yaml
DOMAIN=portal.yourbrand.com docker compose up -d
docker compose logs node-rs | grep 'setup code'
```

The image is `ghcr.io/openbrandexchange/node-rs`; data lives in the `node-rs-data` volume. Update: `docker compose pull && DOMAIN=portal.yourbrand.com docker compose up -d`.

## Settings

Everything a brand configures (company, logo, colours, languages, default image rights) is done in the admin. The server settings are `OBX_*` environment variables, with the same names node-go used; none is required beyond `OBX_PUBLIC_URL`. See [configuration.md](configuration.md).

- **Storage:** SQLite in the data folder (no database server). Images on local disk, or in any S3-compatible bucket with `OBX_BLOB_URL=s3://bucket/prefix?endpoint=https://…&region=…` and `OBX_S3_ACCESS_KEY_ID` / `OBX_S3_SECRET_ACCESS_KEY`.
- **The secret key** (`$OBX_DATA_DIR/secret.key`, or `OBX_SECRET_KEY`) signs download links and encrypts stored secrets. Back it up with the data.

## Backups

Back up offsite every night and test a restore every quarter: [backup.md](backup.md).

## A provider instead

If you would rather not run a server, a provider from the list at [openbrandexchange.com/hosting](https://openbrandexchange.com/hosting) can host node-rs for you. It is the same program; you can move between self-hosting and a provider with a backup.
