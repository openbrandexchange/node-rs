//! The node: configuration, database, blob store, keys and the background
//! work (renditions) shared by every handler.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use bytes::Bytes;
use rusqlite::{OptionalExtension, params};
use serde::{Serialize, de::DeserializeOwned};
use tokio::sync::{Notify, mpsc};

use crate::catalog::Writer;
use crate::config::Config;
use crate::db::{self, Db};
use crate::imaging;
use crate::problem::{Problem, Result};
use crate::secure::{self, Keys};
use crate::settings::Settings;
use crate::store::{Store, blob_key};

pub const SOFTWARE: &str = "obx-node-rs";
pub const SPEC_VERSION: &str = "0.3.1";
pub const OBX_VERSION: &str = "0.3";
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

pub const MAX_UPLOAD_BYTES: u64 = 100 << 20;
pub const MAX_OBJECT_BYTES: u64 = 2 << 30;
pub const PART_BYTES: u64 = 8 << 20;
pub const MAX_BATCH_OPERATIONS: usize = 1000;
pub const MAX_IMPORT_BYTES: u64 = 2 << 30;

#[derive(Clone)]
pub struct App(pub Arc<Inner>);

pub struct Inner {
    pub cfg: Config,
    pub db: Db,
    pub store: Store,
    pub keys: Keys,
    pub node_id: String,
    render_tx: mpsc::UnboundedSender<String>,
    /// Woken after every write with change entries (webhooks, long polls).
    pub changed: Notify,
    /// Woken when a job is queued.
    pub jobs: Notify,
    /// Woken when webhook deliveries are queued.
    pub webhooks_due: Notify,
    limiter: Mutex<HashMap<String, (i64, u32)>>,
    rendering: Mutex<std::collections::HashSet<String>>,
}

impl std::ops::Deref for App {
    type Target = Inner;
    fn deref(&self) -> &Inner {
        &self.0
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct Blob {
    pub sha256: String,
    pub bytes: i64,
    pub content_type: String,
    pub width: Option<i64>,
    pub height: Option<i64>,
    pub created: bool,
}

fn new_setup_code() -> String {
    const A: &[u8] = b"ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
    let mut s = String::new();
    for i in 0..12 {
        if i > 0 && i % 4 == 0 {
            s.push('-');
        }
        s.push(A[rand::random_range(0..A.len())] as char);
    }
    s
}

impl App {
    pub async fn new(cfg: Config) -> std::result::Result<App, String> {
        let db = Db::open(&cfg.sqlite_path())?;
        let store = Store::open(
            &cfg.blob_url,
            cfg.s3_access_key_id.as_deref(),
            cfg.s3_secret_access_key.as_deref(),
        )?;
        let keys = Keys::new(&cfg.secret_key);
        let (render_tx, mut render_rx) = mpsc::unbounded_channel::<String>();
        let k = keys.clone();
        let setup_code = cfg.setup_code.clone();
        let (node_id, print_code) = db
            .write(move |tx| {
                let id = match db::get_meta(tx, "node_id")? {
                    Some(id) => id,
                    None => {
                        let id = crate::ids::new("nod");
                        db::set_meta(tx, "node_id", &id)?;
                        id
                    }
                };
                // Markers of node-go's one-time rewrites; a fresh node has nothing to rewrite.
                tx.execute(
                    "DELETE FROM meta WHERE key IN ('upgrade_article_data', 'upgrade_terms')",
                    [],
                )?;
                if db::get_meta(tx, "setup_done")?.as_deref() == Some("1") {
                    return Ok((id, None));
                }
                if let Some(code) = setup_code {
                    db::set_meta(tx, "setup_code_hash", &secure::hash_token(&code))?;
                    return Ok((id, None));
                }
                let mut code = None;
                if db::get_meta(tx, "setup_code_hash")?.is_none() {
                    let c = new_setup_code();
                    db::set_meta(tx, "setup_code_hash", &secure::hash_token(&c))?;
                    db::set_meta(tx, "setup_code_plain_once", &k.encrypt(c.as_bytes()))?;
                    code = Some(c);
                } else if let Some(enc) = db::get_meta(tx, "setup_code_plain_once")? {
                    code = k.decrypt(&enc).and_then(|b| String::from_utf8(b).ok());
                }
                Ok((id, code))
            })
            .await
            .map_err(|e| e.to_string())?;
        let app = App(Arc::new(Inner {
            cfg,
            db,
            store,
            keys,
            node_id,
            render_tx,
            changed: Notify::new(),
            jobs: Notify::new(),
            webhooks_due: Notify::new(),
            limiter: Mutex::new(HashMap::new()),
            rendering: Mutex::new(Default::default()),
        }));
        if let Some(code) = print_code {
            tracing::warn!(setup_url = %app.cfg.public_url, setup_code = %code, "node is not set up yet; enter the setup code once in the setup wizard");
            eprintln!(
                "\n  First-run setup: open {} and enter this setup code: {code}\n  (set OBX_SETUP_CODE to choose it yourself)\n",
                app.cfg.public_url
            );
        }
        let a = app.clone();
        tokio::spawn(async move {
            while let Some(sha) = render_rx.recv().await {
                if let Err(e) = a.render_original(&sha).await {
                    tracing::warn!(sha256 = %sha, error = %e, "rendering failed");
                }
            }
        });
        let a = app.clone();
        tokio::spawn(async move { a.render_sweep().await });
        Ok(app)
    }

    pub async fn settings(&self) -> Result<Settings> {
        self.db.read(Settings::load).await
    }

    pub async fn setup_done(&self) -> bool {
        self.db
            .read(|c| Ok(db::get_meta(c, "setup_done")?.as_deref() == Some("1")))
            .await
            .unwrap_or(false)
    }

    /// Runs a catalog write in one transaction; afterwards queues renditions
    /// and wakes the change listeners.
    pub async fn catalog_write<T, F>(&self, allowed_brands: Option<Vec<String>>, f: F) -> Result<T>
    where
        T: Send + 'static,
        F: FnOnce(&mut Writer) -> Result<T> + Send + 'static,
    {
        let (out, renders, entries) = self
            .db
            .write(move |tx| {
                let mut w = Writer::new(tx)?;
                w.allowed_brands = allowed_brands;
                let out = f(&mut w)?;
                Ok((out, std::mem::take(&mut w.renders), w.entries))
            })
            .await?;
        for sha in renders {
            let _ = self.render_tx.send(sha);
        }
        if entries > 0 {
            self.changed.notify_waiters();
        }
        Ok(out)
    }

    pub fn queue_render(&self, sha: &str) {
        let _ = self.render_tx.send(sha.to_string());
    }

    // ---- blobs ---------------------------------------------------------------

    pub async fn get_blob(&self, sha: &str) -> Result<Option<Blob>> {
        let sha = sha.to_string();
        self.db
            .read(move |c| {
                Ok(c.query_row(
                    "SELECT sha256, bytes, content_type, width, height FROM blobs WHERE sha256 = ?",
                    [&sha],
                    |r| {
                        Ok(Blob {
                            sha256: r.get(0)?,
                            bytes: r.get(1)?,
                            content_type: r.get(2)?,
                            width: r.get(3)?,
                            height: r.get(4)?,
                            created: false,
                        })
                    },
                )
                .optional()?)
            })
            .await
    }

    /// Stores bytes as a blob (deduplicated by sha256); only images.
    pub async fn put_blob(&self, data: Bytes, declared_sha: Option<&str>) -> Result<Blob> {
        let sha = secure::sha256_hex(&data);
        if let Some(d) = declared_sha.filter(|d| !d.is_empty()) {
            if !d.eq_ignore_ascii_case(&sha) {
                return Err(Problem::new(
                    "checksum_mismatch",
                    format!("The uploaded bytes have sha256 {sha}, not {d}."),
                ));
            }
        }
        if data.is_empty() {
            return Err(Problem::new("validation_failed", "The file is empty."));
        }
        if let Some(b) = self.get_blob(&sha).await? {
            if self.store.exists(&blob_key(&sha)).await {
                return Ok(b);
            }
        }
        let ct = imaging::sniff(&data).ok_or_else(|| {
            Problem::new(
                "unsupported_media_type",
                "Only JPEG, PNG, WebP and TIFF images are accepted.",
            )
        })?;
        let (width, height) = match imaging::dimensions(&data) {
            Some((w, h)) => (Some(w as i64), Some(h as i64)),
            None if ct == "image/tiff" => (None, None),
            None => {
                return Err(Problem::new(
                    "validation_failed",
                    "The image cannot be read.",
                ));
            }
        };
        let n = data.len() as i64;
        self.store
            .put(&blob_key(&sha), data)
            .await
            .map_err(Problem::internal)?;
        let b = Blob {
            sha256: sha.clone(),
            bytes: n,
            content_type: ct.into(),
            width,
            height,
            created: true,
        };
        let (s, c, w, h) = (sha, ct.to_string(), width, height);
        self.db
            .write(move |tx| {
                tx.execute(
                    "INSERT INTO blobs (sha256, bytes, content_type, width, height, created_at) VALUES (?, ?, ?, ?, ?, ?) ON CONFLICT (sha256) DO NOTHING",
                    params![s, n, c, w, h, db::now_str()],
                )?;
                Ok(())
            })
            .await?;
        Ok(b)
    }

    async fn ensure_renditions(&self, sha: &str) -> Result<()> {
        let s = sha.to_string();
        let (have_blob, n, failed) = self
            .db
            .read(move |c| {
                let have: bool = crate::catalog::blob_exists(c, &s);
                let n: i64 = c.query_row(
                    "SELECT COUNT(*) FROM renditions WHERE original_sha = ?",
                    [&s],
                    |r| r.get(0),
                )?;
                let failed: Option<String> = c
                    .query_row(
                        "SELECT error FROM render_errors WHERE original_sha = ?",
                        [&s],
                        |r| r.get(0),
                    )
                    .optional()?;
                Ok((have, n, failed.is_some()))
            })
            .await?;
        if !have_blob || n >= 3 || failed {
            return Ok(());
        }
        let data = self
            .store
            .get(&blob_key(sha))
            .await
            .map_err(Problem::internal)?;
        let rendered = match data {
            None => Err(format!("original {sha} is missing from storage")),
            Some(d) => tokio::task::spawn_blocking(move || imaging::render(&d))
                .await
                .map_err(Problem::internal)?,
        };
        let outs = match rendered {
            Ok(o) => o,
            Err(e) => {
                let s = sha.to_string();
                self.db
                    .write(move |tx| {
                        tx.execute(
                            "INSERT INTO render_errors (original_sha, error, at) VALUES (?, ?, ?) ON CONFLICT (original_sha) DO UPDATE SET error = excluded.error, at = excluded.at",
                            params![s, e, db::now_str()],
                        )?;
                        Ok(())
                    })
                    .await?;
                return Ok(());
            }
        };
        for r in outs {
            let b = self.put_blob(Bytes::from(r.data), None).await?;
            let (s, name, w, h) = (sha.to_string(), r.name, r.width, r.height);
            self.db
                .write(move |tx| {
                    tx.execute(
                        "INSERT INTO renditions (original_sha, name, sha256, width, height, bytes) VALUES (?, ?, ?, ?, ?, ?) ON CONFLICT (original_sha, name) DO NOTHING",
                        params![s, name, b.sha256, w, h, b.bytes],
                    )?;
                    Ok(())
                })
                .await?;
        }
        Ok(())
    }

    /// Renders an original and makes the assets waiting for it visible.
    pub async fn render_original(&self, sha: &str) -> Result<()> {
        {
            let mut r = self.rendering.lock().unwrap();
            if !r.insert(sha.to_string()) {
                return Ok(());
            }
        }
        let out = self.render_original_inner(sha).await;
        self.rendering.lock().unwrap().remove(sha);
        out
    }

    async fn render_original_inner(&self, sha: &str) -> Result<()> {
        self.ensure_renditions(sha).await?;
        let s = sha.to_string();
        self.catalog_write(None, move |w| {
            let rows = crate::catalog::load_rows(
                w.tx,
                crate::model::KIND_ASSET,
                "WHERE original_sha = ? AND (pending = 1 OR live_files IS NULL) ORDER BY product_id, CASE WHEN color_code IS NULL THEN 0 ELSE 1 END, color_code, position, external_id",
                &[&s],
            )?;
            for mut r in rows {
                w.recompute(&mut r)?;
            }
            Ok(())
        })
        .await
    }

    /// Renders an original before a write that references it, so the write
    /// makes the asset visible at once (ingest.md §4.1: read-your-writes).
    pub async fn prerender(&self, sha: &str) {
        if let Err(e) = self.ensure_renditions(sha).await {
            tracing::warn!(sha256 = %sha, error = %e, "rendering failed");
        }
    }

    async fn render_sweep(&self) {
        loop {
            let shas = self
                .db
                .read(|c| {
                    let mut st =
                        c.prepare("SELECT DISTINCT original_sha FROM assets WHERE pending = 1 AND original_sha IS NOT NULL")?;
                    let r = st.query_map([], |r| r.get::<_, String>(0))?.collect::<rusqlite::Result<Vec<_>>>()?;
                    Ok(r)
                })
                .await
                .unwrap_or_default();
            for s in shas {
                self.queue_render(&s);
            }
            tokio::time::sleep(std::time::Duration::from_secs(60)).await;
        }
    }

    // ---- cursors and signed URLs ----------------------------------------------

    pub fn encode_cursor<T: Serialize>(&self, kind: &str, v: &T) -> String {
        let payload = URL_SAFE_NO_PAD.encode(serde_json::to_vec(v).expect("cursor"));
        let sig = &self
            .keys
            .sign(&format!("cursor/{kind}/{}", self.node_id), &payload)[..32];
        format!("{payload}.{sig}")
    }

    pub fn decode_cursor<T: DeserializeOwned>(&self, kind: &str, c: &str) -> Option<T> {
        if c.len() > 4096 {
            return None;
        }
        let (payload, sig) = c.rsplit_once('.')?;
        if payload.is_empty() {
            return None;
        }
        let want = &self
            .keys
            .sign(&format!("cursor/{kind}/{}", self.node_id), payload)[..32];
        if !secure::eq(sig, want) {
            return None;
        }
        serde_json::from_slice(&URL_SAFE_NO_PAD.decode(payload).ok()?).ok()
    }

    fn sign_path(&self, path: &str, tag: &str, exp: i64) -> String {
        self.keys.sign("url", &format!("GET\n{path}\n{exp}\n{tag}"))
    }

    /// A signed URL valid for one hour and its expiry (RFC 3339).
    pub fn signed_url(&self, path: &str, tag: &str) -> (String, String) {
        let exp = chrono::Utc::now().timestamp() + 3600;
        let sig = self.sign_path(path, tag, exp);
        let mut q = url::form_urlencoded::Serializer::new(String::new());
        q.append_pair("exp", &exp.to_string());
        if !tag.is_empty() {
            q.append_pair("v", tag);
        }
        q.append_pair("sig", &sig);
        let t = chrono::DateTime::from_timestamp(exp, 0).unwrap();
        (
            format!("{}{path}?{}", self.cfg.public_url, q.finish()),
            t.to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
        )
    }

    /// The viewer tag of a valid signature on path.
    pub fn verify_signed(&self, path: &str, q: &HashMap<String, String>) -> Option<String> {
        let sig = q.get("sig").filter(|s| !s.is_empty())?;
        let exp: i64 = q.get("exp")?.parse().ok()?;
        let now = chrono::Utc::now().timestamp();
        if exp < now || exp > now + 25 * 3600 {
            return None;
        }
        let tag = q.get("v").cloned().unwrap_or_default();
        secure::eq(&sig.to_lowercase(), &self.sign_path(path, &tag, exp)).then_some(tag)
    }

    // ---- rate limits -----------------------------------------------------------

    /// A fixed one-minute window per key; Err(retry_after) when exceeded.
    pub fn limit(
        &self,
        key: &str,
        per_window: u32,
        window_secs: i64,
    ) -> std::result::Result<(u32, u32, i64), i64> {
        let per_window = self
            .cfg
            .test_rate_limit
            .unwrap_or(per_window)
            .min(per_window.max(1));
        let now = chrono::Utc::now().timestamp();
        let mut m = self.limiter.lock().unwrap();
        if m.len() > 100_000 {
            m.retain(|_, (start, _)| now - *start < window_secs);
        }
        let e = m.entry(key.to_string()).or_insert((now, 0));
        if now - e.0 >= window_secs {
            *e = (now, 0);
        }
        let reset = window_secs - (now - e.0);
        if e.1 >= per_window {
            return Err(reset.max(1));
        }
        e.1 += 1;
        Ok((per_window, per_window - e.1, reset))
    }
}
