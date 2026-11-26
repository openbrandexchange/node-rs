# Backups: offsite, encrypted, tested

A portal you host yourself is only as safe as your last restore. Do all four:

1. a consistent snapshot every night,
2. copied encrypted to **another provider or region**,
3. with retention: 7 daily, 4 weekly, 12 monthly,
4. and a restore drill at least every quarter.

## What to back up

| What | Where | How |
|---|---|---|
| The database | `$OBX_DATA_DIR/obx.db` (SQLite, WAL mode) | **`node-rs backup --to DIR`** (recommended): a consistent online copy through SQLite's backup API, safe while the node runs. Never copy `obx.db` with `cp` while it runs. Equivalent: `sqlite3 obx.db ".backup DIR/obx.db"`. |
| The secret key | `$OBX_DATA_DIR/secret.key`, or `OBX_SECRET_KEY` | `node-rs backup` copies the file. If you set `OBX_SECRET_KEY`, keep it in your password manager: without it the restored node cannot decrypt stored credentials and every download link and access token changes. The manifest holds a fingerprint of the key (never the key), so `restore` notices a different `OBX_SECRET_KEY`. |
| Images | `$OBX_DATA_DIR/blobs`, or your S3-compatible bucket | On local disk `node-rs backup` puts them in `DIR/blobs` as hard links (no extra space on the same disk; a copy otherwise). Content-addressed and never rewritten, so this is consistent with the database snapshot. In a bucket: see below. |
| Configuration | the systemd override (`systemctl cat node-rs`), `/etc/node-rs/env`, or `compose.yaml` + `node-rs.env` | Small; keep a copy with the backup (encrypted: it can hold S3 keys). |

`node-rs backup --to DIR` writes `obx.db`, `blobs/` (local images), `secret.key` and `manifest.json` (version, schema version, node id, where the images are, key fingerprint) into a new, empty `DIR`. The format is node-go's: a node-go backup restores into node-rs and the other way round.

## Nightly offsite copy (restic)

[restic](https://restic.net) encrypts on your server before anything leaves it and works with any S3-compatible target. Use a bucket at a **different provider or region** than your server and your image bucket.

```sh
# once
export RESTIC_REPOSITORY=s3:https://s3.other-provider.example/portal-backups
export RESTIC_PASSWORD_FILE=/etc/node-rs/restic-password   # keep a copy outside this server
export AWS_ACCESS_KEY_ID=… AWS_SECRET_ACCESS_KEY=…
restic init
```

`/etc/cron.daily/node-rs-backup` (Linux; for Docker run the same with `docker compose exec node-rs node-rs backup --to /data/backup-tonight` and back up the volume path):

```sh
#!/bin/sh
set -eu
. /etc/node-rs/restic.env                  # the RESTIC_* and AWS_* variables above
SNAP=/var/lib/node-rs/backup-tonight
rm -rf "$SNAP"
sudo -u node-rs env OBX_DATA_DIR=/var/lib/node-rs node-rs backup --to "$SNAP"
restic backup --tag node-rs "$SNAP" /etc/systemd/system/node-rs.service.d /etc/node-rs
restic forget --tag node-rs --keep-daily 7 --keep-weekly 4 --keep-monthly 12 --prune
rm -rf "$SNAP"
```

rclone (`rclone sync` to a `crypt` remote, with `--backup-dir` per day) works too; restic's retention and encryption are simpler to get right.

## Images in an S3-compatible bucket

The bucket holds every image. Turn on **versioning** (or object lock) so a deleted or overwritten object can be recovered, and **replication** to a bucket in another region or at another provider. Without replication, add the bucket to the nightly copy (`rclone sync` from the image bucket to the backup provider). node-rs never deletes or rewrites an image key in place, so versioning costs little.

## Restore (and the quarterly drill)

Drill on a spare server or a local machine, never over the live portal:

```sh
restic restore latest --tag node-rs --target /tmp/restore
sudo systemctl stop node-rs                                   # on the real server only
sudo -u node-rs env OBX_DATA_DIR=/var/lib/node-rs node-rs restore --from /tmp/restore/var/lib/node-rs/backup-tonight --force
sudo systemctl start node-rs
```

`node-rs restore --from DIR` reads `manifest.json` (or the `backup.json` of the first node-rs builds), refuses a backup from a newer schema, refuses without `--force` to replace an existing database or to restore with a different `OBX_SECRET_KEY`, removes stale `-wal`/`-shm` files, then puts the database, the local images and `secret.key` in place. It does not start the node. With images in a bucket, nothing is copied for them: restore the bucket from its versions or replica. By hand, the same is: copy `obx.db` and `secret.key` into the data folder (mode 0600, owner node-rs), delete `obx.db-wal` and `obx.db-shm`, and `rsync -a DIR/blobs/` into `$OBX_DATA_DIR/blobs/`.

Then check: log in to the admin, open a product with images in **View as retailer**, download an image, and fetch `/.well-known/obx`. Write down the date and how long it took. A drill that was not done is a backup you do not have.

A database restored onto a newer node-rs is upgraded on start; a database from a newer release than the binary is refused (run that release or newer).

## After a restore: links, tokens and keys

- **Signed download links** keep working until they expire (one hour) when the secret key is the same. With another secret key every link is invalid: clients read the asset again and get a fresh one.
- **Access tokens** of retailers' software (one hour) behave the same way; clients request a new token with their client credentials and go on.
- **API keys, upload keys, passwords and invitations** are in the database: those created after the backup are gone and must be created again; ones revoked after the backup are active again, so **revoke them again** right after the restore.
- **Change-feed cursors** of retailers that synced after the backup point beyond the restored history; such a cursor finds nothing new until the node passes that position, and changes made after the backup are lost. After a restore, tell retailers' integrations to restart `/changes` without a cursor (a full snapshot), or set a new cursor epoch with `node-rs admin simulate-spec-upgrade`, which makes every old cursor answer `410 cursor_expired` so clients resynchronise by themselves.
