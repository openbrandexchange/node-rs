//! `node-rs backup --to DIR` and `node-rs restore --from DIR`. The backup
//! directory is node-go's format (manifest.json, obx.db, blobs/, secret.key),
//! so a node-go backup restores into node-rs and the other way round.

use std::path::Path;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::config::Config;

#[derive(Debug, Serialize, Deserialize, Default)]
pub struct Manifest {
    pub format: i64,
    pub created_at: String,
    /// The node-go field name; holds the node-rs version in a node-rs backup.
    #[serde(default)]
    pub node_go_version: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub software: String,
    pub schema_version: usize,
    #[serde(default)]
    pub node_id: String,
    pub database: String,
    pub files: String,
    #[serde(default)]
    pub file_count: usize,
    pub secret_key: String,
    #[serde(default)]
    pub secret_fingerprint: String,
}

pub fn secret_fingerprint(key: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(b"obx-backup-fingerprint/");
    h.update(key);
    hex::encode(&h.finalize()[..8])
}

fn local_root(blob_url: &str) -> Option<&Path> {
    blob_url.strip_prefix("file://").map(Path::new)
}

/// Copies the regular files below src into dst (same names replaced; the
/// files are content-addressed, so this is safe). Hard links when possible.
fn copy_tree(src: &Path, dst: &Path, link: bool) -> std::io::Result<usize> {
    let mut n = 0;
    if !src.exists() {
        return Ok(0);
    }
    std::fs::create_dir_all(dst)?;
    for e in std::fs::read_dir(src)? {
        let e = e?;
        let t = e.file_type()?;
        let name = e.file_name();
        let (from, to) = (e.path(), dst.join(&name));
        if t.is_dir() {
            n += copy_tree(&from, &to, link)?;
        } else if t.is_file() && !name.to_string_lossy().starts_with(".tmp-") {
            n += 1;
            if link && !to.exists() && std::fs::hard_link(&from, &to).is_ok() {
                continue;
            }
            copy_file(&from, &to)?;
        }
    }
    Ok(n)
}

fn copy_file(src: &Path, dst: &Path) -> std::io::Result<()> {
    if let Some(d) = dst.parent() {
        std::fs::create_dir_all(d)?;
    }
    let tmp = dst.with_extension("restore-tmp");
    std::fs::copy(src, &tmp)?;
    std::fs::File::open(&tmp)?.sync_all()?;
    std::fs::rename(&tmp, dst)
}

fn write_private(path: &Path, data: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    let mut o = std::fs::OpenOptions::new();
    o.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        o.mode(0o600);
    }
    o.open(path)?.write_all(data)
}

/// A consistent snapshot into an empty or missing directory: the database
/// through SQLite's online backup API (safe while the node runs), the local
/// image files (hard links when on the same disk) and the secret key.
/// Images in a bucket are not copied; the manifest says so.
pub fn backup(cfg: &Config, to: &Path) -> Result<Manifest, String> {
    if std::fs::read_dir(to).is_ok_and(|mut d| d.next().is_some()) {
        return Err(format!(
            "{} is not empty; choose a new directory for each backup",
            to.display()
        ));
    }
    std::fs::create_dir_all(to).map_err(|e| format!("{}: {e}", to.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(to, std::fs::Permissions::from_mode(0o700));
    }
    let db = crate::db::Db::open(&cfg.sqlite_path())?;
    db.backup_to(&to.join("obx.db"))?;
    let node_id = db
        .read_sync(|c| crate::db::get_meta(c, "node_id"))
        .ok()
        .flatten()
        .unwrap_or_default();
    let mut m = Manifest {
        format: 1,
        created_at: chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
        node_go_version: crate::app::VERSION.into(),
        software: crate::app::SOFTWARE.into(),
        schema_version: crate::migrations::MIGRATIONS.len(),
        node_id,
        database: "obx.db".into(),
        secret_fingerprint: secret_fingerprint(&cfg.secret_key),
        ..Default::default()
    };
    match local_root(&cfg.blob_url) {
        Some(root) => {
            m.file_count =
                copy_tree(root, &to.join("blobs"), true).map_err(|e| format!("files: {e}"))?;
            m.files = "blobs".into();
        }
        None => {
            m.files = format!(
                "not included: the files are in {} (use bucket versioning or replication)",
                crate::config::redact(&cfg.blob_url)
            );
        }
    }
    if cfg.secret_from_env {
        m.secret_key =
            "not included: OBX_SECRET_KEY is set in the environment; keep it with this backup"
                .into();
    } else {
        let mut k = cfg.secret_key.clone();
        k.push(b'\n');
        write_private(&to.join("secret.key"), &k).map_err(|e| format!("secret key: {e}"))?;
        m.secret_key = "secret.key".into();
    }
    let mut j = serde_json::to_vec_pretty(&m).unwrap();
    j.push(b'\n');
    write_private(&to.join("manifest.json"), &j).map_err(|e| e.to_string())?;
    Ok(m)
}

/// Reads the manifest; a backup of the first node-rs release (backup.json)
/// is understood too.
fn read_manifest(dir: &Path) -> Result<Manifest, String> {
    if let Ok(raw) = std::fs::read(dir.join("manifest.json")) {
        let m: Manifest = serde_json::from_slice(&raw).map_err(|_| {
            format!(
                "{}/manifest.json is not a backup manifest this version understands",
                dir.display()
            )
        })?;
        if m.format != 1 {
            return Err(format!(
                "{}/manifest.json has format {}; this version understands format 1",
                dir.display(),
                m.format
            ));
        }
        return Ok(m);
    }
    if let Ok(raw) = std::fs::read(dir.join("backup.json")) {
        let v: serde_json::Value = serde_json::from_slice(&raw).map_err(|e| e.to_string())?;
        return Ok(Manifest {
            format: 1,
            created_at: v["created_at"].as_str().unwrap_or("").into(),
            node_go_version: v["version"].as_str().unwrap_or("").into(),
            schema_version: v["schema_version"].as_u64().unwrap_or(0) as usize,
            database: "obx.db".into(),
            files: "not included".into(),
            secret_key: if dir.join("secret.key").exists() {
                "secret.key".into()
            } else {
                String::new()
            },
            ..Default::default()
        });
    }
    Err(format!(
        "{} has no manifest.json; is it a backup made with node-rs backup or node-go backup?",
        dir.display()
    ))
}

/// Puts a backup in place for cfg. The node must not be running. Without
/// force it refuses to replace an existing database.
pub fn restore(cfg: &Config, dir: &Path, force: bool) -> Result<Manifest, String> {
    let m = read_manifest(dir)?;
    let known = crate::migrations::MIGRATIONS.len();
    if m.schema_version > known {
        return Err(format!(
            "the backup has schema version {}; this node-rs knows only up to {known}. Restore it with a newer release",
            m.schema_version
        ));
    }
    if cfg.secret_from_env
        && !m.secret_fingerprint.is_empty()
        && !crate::secure::eq(&secret_fingerprint(&cfg.secret_key), &m.secret_fingerprint)
        && !force
    {
        return Err("OBX_SECRET_KEY differs from the key the backup was made with: stored import credentials and webhook secrets would be unreadable. Set the original key, or pass --force".into());
    }
    if m.database == "obx.db" {
        let target = cfg.sqlite_path();
        if target.exists() && !force {
            return Err(format!(
                "{} already exists; stop the node and pass --force to replace it",
                target.display()
            ));
        }
        for suffix in ["-wal", "-shm"] {
            let _ = std::fs::remove_file(format!("{}{suffix}", target.display()));
        }
        copy_file(&dir.join("obx.db"), &target).map_err(|e| format!("database: {e}"))?;
    } else {
        return Err(format!(
            "the backup holds no SQLite database ({}); node-rs stores its data in SQLite only. Copy a PostgreSQL node with node-rs import-postgres",
            m.database
        ));
    }
    if m.files == "blobs" {
        let Some(root) = local_root(&cfg.blob_url) else {
            return Err(format!(
                "the backup holds local files but OBX_BLOB_URL is {}; restore with the default file store, or copy {}/blobs to the bucket yourself",
                crate::config::redact(&cfg.blob_url),
                dir.display()
            ));
        };
        copy_tree(&dir.join("blobs"), root, false).map_err(|e| format!("files: {e}"))?;
    }
    if m.secret_key == "secret.key" && !cfg.secret_from_env {
        copy_file(&dir.join("secret.key"), &cfg.data_dir.join("secret.key"))
            .map_err(|e| format!("secret key: {e}"))?;
    }
    Ok(m)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backup_and_restore_round_trip() {
        let base = std::env::temp_dir().join(format!("obx-backup-test-{}", crate::ids::new("t")));
        let src = base.join("src");
        std::fs::create_dir_all(src.join("blobs/ab")).unwrap();
        std::fs::write(src.join("blobs/ab/abcd"), b"image").unwrap();
        let mut cfg = Config::for_test(&src);
        cfg.secret_from_env = false;
        crate::db::Db::open(&cfg.sqlite_path()).unwrap();
        let m = backup(&cfg, &base.join("bk")).unwrap();
        assert_eq!(
            (m.file_count, m.files.as_str(), m.secret_key.as_str()),
            (1, "blobs", "secret.key")
        );
        assert!(backup(&cfg, &base.join("bk")).is_err(), "not empty");
        let dst = base.join("dst");
        let mut cfg2 = Config::for_test(&dst);
        cfg2.secret_from_env = false;
        restore(&cfg2, &base.join("bk"), false).unwrap();
        assert_eq!(std::fs::read(dst.join("blobs/ab/abcd")).unwrap(), b"image");
        assert!(dst.join("obx.db").exists());
        assert_eq!(
            std::fs::read_to_string(dst.join("secret.key"))
                .unwrap()
                .trim()
                .as_bytes(),
            cfg.secret_key.as_slice()
        );
        assert!(
            restore(&cfg2, &base.join("bk"), false)
                .unwrap_err()
                .contains("--force")
        );
        restore(&cfg2, &base.join("bk"), true).unwrap();
        // Another key from the environment is refused without --force.
        let mut cfg3 = Config::for_test(&base.join("dst3"));
        cfg3.secret_key = b"another-secret-key-0123456789abcdef".to_vec();
        assert!(
            restore(&cfg3, &base.join("bk"), false)
                .unwrap_err()
                .contains("OBX_SECRET_KEY")
        );
        let _ = std::fs::remove_dir_all(base);
    }
}
