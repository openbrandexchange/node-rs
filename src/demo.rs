//! Demo mode (`OBX_DEMO=true`, off by default; docs/demo.md): a public
//! portal people can look around in without an account. One-click sign-in
//! as a fixed demo retailer or the demo brand admin, a public read-only API
//! key, refusals for everything that could leave the demo or lock others out,
//! no e-mail, and a scheduled reset to the MAISON NOOR fixtures (embedded in
//! the binary through obx-conformance, with a showroom look).
//!
//! Behaviour and refusal rules are node-ts's (src/core/demo.ts).

use std::net::SocketAddr;

use axum::body::{Body, Bytes};
use axum::extract::{ConnectInfo, Request, State};
use axum::http::{HeaderMap, HeaderValue, Method, header};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use rusqlite::{Connection, params};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};

use crate::app::App;
use crate::db;
use crate::http::{Res, client_ip, json as json_resp, ok};
use crate::problem::{Problem, Result};

/// Fixed ids, so sessions survive a reset and the public API key never changes.
pub const BRAND_USER: &str = "usr_demo_brand";
pub const RETAILER_USER: &str = "usr_demo_retailer";
pub const RETAILER: &str = "rtl_demo_northwind";
pub const HARBOUR: &str = "rtl_demo_harbour";
pub const CLIENT: &str = "cli_demo_public";
/// Published on purpose: it can only read the fictional catalog.
pub const CLIENT_ID: &str = "obxc_demo-portal-read-only";
pub const CLIENT_SECRET: &str = "obxs_demo-portal-read-only-public";
pub const SCOPES: [&str; 3] = ["catalog:read", "media:read", "media:original"];
const DEMO_USERS: [&str; 2] = [BRAND_USER, RETAILER_USER];
/// Images a visitor may upload for the portal's look.
pub const MAX_IMAGES: usize = 20;
/// A clean demo is still reset this often (the example statistics stay recent).
const CLEAN_RESET_SECS: i64 = 24 * 3600;
/// A reset still marked running after this long is taken to have died.
const RESET_STALE_SECS: i64 = 600;

/// Tables a reset empties (sessions and blobs are handled separately).
const WIPE: [&str; 23] = [
    "brands",
    "products",
    "variants",
    "assets",
    "product_qualifiers",
    "changes",
    "retailers",
    "users",
    "api_clients",
    "ingest_tokens",
    "access_requests",
    "webhooks",
    "webhook_deliveries",
    "jobs",
    "job_items",
    "import_sources",
    "uploads",
    "download_events",
    "idempotency",
    "audit_log",
    "mail_outbox",
    "branding_images",
    "render_errors",
];

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DemoState {
    /// resetting, ready or failed
    pub phase: String,
    pub reset_at: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

pub fn state(c: &Connection) -> Result<Option<DemoState>> {
    Ok(db::get_meta(c, "demo_state")?.and_then(|s| serde_json::from_str(&s).ok()))
}

fn set_state(c: &Connection, s: &DemoState) -> Result<()> {
    db::set_meta(
        c,
        "demo_state",
        &serde_json::to_string(s).unwrap_or_default(),
    )
}

fn secs_since(t: &str, now: chrono::DateTime<chrono::Utc>) -> i64 {
    db::parse_time(t).map_or(i64::MAX, |t| (now - t).num_seconds())
}

/// The next whole interval after the last reset (when a reset can happen).
pub fn next_reset_at(
    every_minutes: i64,
    s: Option<&DemoState>,
    now: chrono::DateTime<chrono::Utc>,
) -> Option<String> {
    let last = db::parse_time(&s?.reset_at)?;
    let every = every_minutes.max(1) * 60;
    let k = ((now - last).num_seconds() / every + 1).max(1);
    let t = last + chrono::Duration::seconds(k * every);
    Some(t.to_rfc3339_opts(chrono::SecondsFormat::Secs, true))
}

/// What the UI shows about the demo (`x-obx-demo` in the public branding).
pub fn info(app: &App, c: &Connection) -> Result<Value> {
    let s = state(c)?;
    let base = &app.cfg.public_url;
    Ok(json!({
        "reset_every_minutes": app.cfg.demo_reset_minutes,
        "last_reset_at": s.as_ref().map(|s| s.reset_at.clone()),
        "next_reset_at": next_reset_at(app.cfg.demo_reset_minutes, s.as_ref(), chrono::Utc::now()),
        "ready": s.as_ref().is_some_and(|s| s.phase == "ready"),
        "turnstile_site_key": app.cfg.demo_turnstile_site_key,
        "accounts": ["retailer", "brand"],
        "api": {
            "client_id": CLIENT_ID,
            "client_secret": CLIENT_SECRET,
            "scopes": SCOPES,
            "token_endpoint": format!("{base}/obx/v1/oauth/token"),
            "discovery_url": format!("{base}/.well-known/obx"),
        },
    }))
}

// ---- reset ---------------------------------------------------------------------------------

static RESET_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// The showroom look: the spec's full BrandingSettings example.
fn showroom() -> Value {
    obx_conformance::file("examples/BrandingSettings.full.json")
        .and_then(|b| serde_json::from_slice(&b).ok())
        .unwrap_or(Value::Null)
}

/// Writes the embedded fixtures to a folder for the import.
fn write_seed(dir: &std::path::Path) -> std::io::Result<()> {
    let _ = std::fs::remove_dir_all(dir);
    for p in obx_conformance::files("maison-noor/") {
        let rel = p.trim_start_matches("maison-noor/");
        let dest = dir.join(rel);
        if let Some(parent) = dest.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(&dest, obx_conformance::file(&p).unwrap_or_default())?;
    }
    Ok(())
}

/// The sha256 of every fixture image and of its renditions (kept between
/// resets, so a reset does not render them again).
fn keep_shas(c: &Connection) -> Result<std::collections::HashSet<String>> {
    let mut keep = std::collections::HashSet::new();
    for p in obx_conformance::files("maison-noor/images/") {
        keep.insert(crate::secure::sha256_hex(
            &obx_conformance::file(&p).unwrap_or_default(),
        ));
    }
    let mut st = c.prepare("SELECT original_sha, sha256 FROM renditions")?;
    let rows = st
        .query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    for (o, s) in rows {
        if keep.contains(&o) {
            keep.insert(s);
        }
    }
    Ok(keep)
}

/// Puts the demo back to the fixtures: empties every table (keeping the
/// sessions of the two demo accounts and the fixture images), recreates
/// settings, accounts, retailers, the public key and an access request,
/// imports the catalog and adds example statistics.
pub async fn reset(app: &App) -> Result<DemoState> {
    let _guard = RESET_LOCK.lock().await;
    let now = db::now_str();
    let n2 = now.clone();
    let drop = app
        .db
        .write(move |tx| {
            set_state(
                tx,
                &DemoState {
                    phase: "resetting".into(),
                    reset_at: n2.clone(),
                    error: None,
                },
            )?;
            let keep = keep_shas(tx)?;
            // Old /changes cursors must not continue into the new catalog.
            let floor: i64 = tx.query_row("SELECT COALESCE(MAX(seq), 0) + 1 FROM changes", [], |r| r.get(0))?;
            for t in WIPE {
                tx.execute(&format!("DELETE FROM {t}"), [])?;
            }
            tx.execute(
                &format!(
                    "DELETE FROM sessions WHERE user_id NOT IN {}",
                    db::in_list(DEMO_USERS.len())
                ),
                rusqlite::params_from_iter(DEMO_USERS.iter()),
            )?;
            tx.execute(
                "DELETE FROM meta WHERE key IN ('settings', 'setup_done', 'setup_code_hash', 'setup_code_plain_once', 'demo_dirty')",
                [],
            )?;
            db::set_meta(tx, "changes_pruned_below", &floor.to_string())?;
            let mut st = tx.prepare("SELECT sha256 FROM blobs")?;
            let all = st
                .query_map([], |r| r.get::<_, String>(0))?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            let drop: Vec<String> = all.into_iter().filter(|s| !keep.contains(s)).collect();
            for s in &drop {
                tx.execute("DELETE FROM blobs WHERE sha256 = ?", [s])?;
                tx.execute("DELETE FROM renditions WHERE original_sha = ? OR sha256 = ?", [s, s])?;
            }
            Ok(drop)
        })
        .await?;
    for s in drop {
        let _ = app.store.delete(&crate::store::blob_key(&s)).await;
    }
    for prefix in ["uploads/", "downloads/", "exports/", "imports/"] {
        let _ = app.store.delete_prefix(prefix).await;
    }
    let out = seed(app, &now).await;
    let st = match out {
        Ok(()) => DemoState {
            phase: "ready".into(),
            reset_at: now,
            error: None,
        },
        Err(e) => {
            tracing::warn!(error = %e, "demo reset failed");
            DemoState {
                phase: "failed".into(),
                reset_at: now,
                error: Some(e.detail_str().to_string()),
            }
        }
    };
    let s2 = st.clone();
    app.db.write(move |tx| set_state(tx, &s2)).await?;
    app.changed.notify_waiters();
    tracing::info!(phase = %st.phase, "demo reset");
    Ok(st)
}

async fn seed(app: &App, now: &str) -> Result<()> {
    let look = showroom();
    let now2 = now.to_string();
    let lk = look.clone();
    let harbour_brand = app
        .catalog_write(None, move |w| {
            let mut s = crate::settings::Settings::default();
            s.company.name = "MAISON NOOR Group".into();
            s.company.website = Some("https://maison-noor.example".into());
            s.company.contact_email = Some("trade@maison-noor.example".into());
            s.company.country = Some("NL".into());
            s.branding.display_name = "MAISON NOOR".into();
            s.branding.accent_color = lk["accent_color"].as_str().map(String::from).or(Some("#1B1A19".into()));
            s.branding.welcome_text = Some(
                [
                    ("en".to_string(), "MAISON NOOR is a fictional fashion house. Everything in this demo is test data and is put back regularly.".to_string()),
                    ("nl".to_string(), "MAISON NOOR is een fictief modehuis. Alles in deze demo is testdata en wordt regelmatig teruggezet.".to_string()),
                ]
                .into_iter()
                .collect(),
            );
            if let Some(pn) = lk["portal_name"].as_object() {
                s.branding.portal_name = Some(
                    pn.iter()
                        .filter_map(|(k, v)| v.as_str().map(|v| (k.clone(), v.to_string())))
                        .collect(),
                );
            }
            s.branding.theme = lk["theme"].as_object().cloned();
            s.branding.login = lk["login"].as_object().cloned();
            s.branding.home = lk["home"].as_object().cloned();
            s.portal.languages = vec!["en".into(), "nl".into()];
            s.portal.default_language = "en".into();
            s.portal.retailer_api_self_service = false;
            s.save(w.tx)?;
            w.settings = s;
            db::set_meta(w.tx, "setup_done", "1")?;
            let mut doc = Map::new();
            doc.insert("name".into(), json!("MAISON NOOR"));
            doc.insert("website".into(), json!("https://maison-noor.example"));
            doc.insert("status".into(), json!("published"));
            let (_, p) = w.upsert(crate::model::KIND_BRAND, "maison-noor", doc, "");
            if let Some(p) = p {
                return Err(p);
            }
            let brand_id: String = w.tx.query_row(
                "SELECT id FROM brands WHERE external_id = 'maison-noor'",
                [],
                |r| r.get(0),
            )?;
            seed_people(w.tx, &now2, &brand_id)?;
            Ok(brand_id)
        })
        .await?;
    let _ = harbour_brand;
    let dir = app.cfg.data_dir.join("tmp").join("demo-seed");
    write_seed(&dir).map_err(Problem::internal)?;
    let run = crate::imports::run_import_cli(
        app,
        Some(dir.join("products.csv")),
        Some(dir.join("assets.csv")),
        Some(dir.join("images")),
        None,
        false,
        false,
    )
    .await;
    let _ = std::fs::remove_dir_all(&dir);
    let run = run?;
    if run["status"] != "succeeded" {
        return Err(Problem::new(
            "internal_error",
            format!("the fixture import did not succeed: {}", run["status"]),
        ));
    }
    // The showroom's image ids get fixture photographs, so its login page
    // and start page show real pictures.
    let n3 = now.to_string();
    app.db
        .write(move |tx| {
            seed_showroom_images(tx, &look, &n3)?;
            seed_stats(tx)
        })
        .await
}

fn seed_people(tx: &Connection, now: &str, brand_id: &str) -> Result<()> {
    let harbour_brands = serde_json::to_string(&[brand_id]).unwrap_or_default();
    for (id, name, reference, brands, orig, status) in [
        (
            RETAILER,
            "Northwind Stores",
            "NWS-001",
            None,
            None,
            "active",
        ),
        (
            HARBOUR,
            "Harbour & Co",
            "HBR-014",
            Some(harbour_brands.as_str()),
            Some(0),
            "active",
        ),
        (
            "rtl_demo_lumen",
            "Lumen Concept Store",
            "LMN-207",
            None,
            None,
            "blocked",
        ),
    ] {
        tx.execute(
            "INSERT INTO retailers (id, name, reference, country, notes, status, brand_ids, allow_original, created_at, updated_at, grant_updated_at) VALUES (?, ?, ?, 'NL', 'Fictional retailer (demo).', ?, ?, ?, ?, ?, ?)",
            params![id, name, reference, status, brands, orig, now, now, now],
        )?;
    }
    for (id, email, name, role, retailer) in [
        (
            BRAND_USER,
            "brand@maison-noor.example",
            "Demo brand admin",
            "admin",
            None,
        ),
        (
            RETAILER_USER,
            "buyer@northwind.example",
            "Demo retailer",
            "retailer",
            Some(RETAILER),
        ),
        (
            "usr_demo_harbour",
            "orders@harbour.example",
            "Harbour buyer",
            "retailer",
            Some(HARBOUR),
        ),
    ] {
        // No password: these accounts are only reachable through the demo sign-in.
        tx.execute(
            "INSERT INTO users (id, email, name, role, retailer_id, status, language, password_hash, created_at) VALUES (?, ?, ?, ?, ?, 'active', 'en', NULL, ?)",
            params![id, email, name, role, retailer, now],
        )?;
    }
    tx.execute(
        "INSERT INTO api_clients (id, client_id, secret_hash, secret_version, retailer_id, name, scopes, status, created_by, created_at) VALUES (?, ?, ?, 1, ?, 'Public demo key (read-only)', ?, 'active', 'demo', ?)",
        params![CLIENT, CLIENT_ID, crate::secure::hash_token(CLIENT_SECRET), RETAILER, SCOPES.join(" "), now],
    )?;
    let two_hours_ago = db::fmt_time(chrono::Utc::now() - chrono::Duration::hours(2));
    tx.execute(
        "INSERT INTO access_requests (id, status, token_hash, retailer, contact, access, requested_brand_ids, message, created_at) VALUES ('acr_demo_fjord', 'pending', ?, ?, ?, '[\"portal\",\"api\"]', NULL, ?, ?)",
        params![
            crate::secure::hash_token(&format!("demo-{now}")),
            json!({"name": "Fjord Outdoor", "reference": null, "website": "https://fjord.example", "vat_number": null, "country": "NO"}).to_string(),
            json!({"name": "Ingrid Berg", "email": "ingrid@fjord.example", "phone": null, "language": "en"}).to_string(),
            "We would like to sell the MAISON NOOR collection in our three stores.",
            two_hours_ago
        ],
    )?;
    Ok(())
}

/// Stores a branding image row for every image id the showroom references,
/// using the fixture originals in turn (largest first).
fn seed_showroom_images(tx: &Connection, look: &Value, now: &str) -> Result<()> {
    let refs = obx_types::appearance::image_refs(look);
    if refs.is_empty() {
        return Ok(());
    }
    let mut st = tx.prepare(
        "SELECT b.sha256, b.content_type, b.width, b.height, b.bytes FROM blobs b WHERE b.sha256 IN (SELECT original_sha FROM assets WHERE original_sha IS NOT NULL) AND b.width IS NOT NULL ORDER BY b.width * b.height DESC, b.sha256",
    )?;
    let imgs = st
        .query_map([], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, i64>(2)?,
                r.get::<_, i64>(3)?,
                r.get::<_, i64>(4)?,
            ))
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    if imgs.is_empty() {
        return Ok(());
    }
    let mut seen = std::collections::HashSet::new();
    let mut i = 0;
    for (_, id) in refs {
        if !seen.insert(id.clone()) {
            continue;
        }
        let (sha, ct, w, h, b) = &imgs[i % imgs.len()];
        i += 1;
        tx.execute(
            "INSERT INTO branding_images (id, sha256, content_type, width, height, bytes, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
            params![id, sha, ct, w, h, b, now],
        )?;
    }
    Ok(())
}

/// Example download statistics over the last 30 days (deterministic, so
/// every reset looks the same).
fn seed_stats(tx: &Connection) -> Result<()> {
    let ids = |q: &str| -> Result<Vec<(String, String)>> {
        let mut st = tx.prepare(q)?;
        let r = st
            .query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(r)
    };
    let products = ids("SELECT id, style_number FROM products ORDER BY external_id")?;
    let assets = ids("SELECT id, product_id FROM assets ORDER BY external_id")?;
    if products.is_empty() {
        return Ok(());
    }
    let style_of = |pid: &str| {
        products
            .iter()
            .find(|(p, _)| p == pid)
            .map(|(_, s)| s.clone())
    };
    let mut x: i64 = 20261112;
    let mut rnd = move || {
        x = (x.wrapping_mul(1103515245).wrapping_add(12345)) & 0x7fff_ffff;
        x as f64 / 0x7fff_ffff as f64
    };
    let who = [
        (
            RETAILER,
            "Northwind Stores",
            "user",
            RETAILER_USER,
            "Demo retailer",
            0.6,
        ),
        (
            RETAILER,
            "Northwind Stores",
            "api_client",
            CLIENT,
            "Public demo key (read-only)",
            0.85,
        ),
        (
            HARBOUR,
            "Harbour & Co",
            "user",
            "usr_demo_harbour",
            "Harbour buyer",
            1.0,
        ),
    ];
    let kinds = [
        "image",
        "image",
        "image",
        "product_zip",
        "selection_zip",
        "csv",
    ];
    let now = chrono::Utc::now();
    for _ in 0..140 {
        let r = rnd();
        let w = who.iter().find(|w| r <= w.5).unwrap_or(&who[2]);
        let kind = if w.2 == "api_client" {
            if rnd() < 0.8 {
                "api_rendition"
            } else {
                "usage"
            }
        } else {
            kinds[(rnd() * 6.0) as usize % 6]
        };
        let a = (!assets.is_empty())
            .then(|| &assets[(rnd() * assets.len() as f64) as usize % assets.len()]);
        let pid = match a {
            Some((_, p)) => p.clone(),
            None => products[(rnd() * products.len() as f64) as usize % products.len()]
                .0
                .clone(),
        };
        let files: i64 = match kind {
            "product_zip" => 4 + (rnd() * 4.0) as i64,
            "selection_zip" => 8 + (rnd() * 12.0) as i64,
            "csv" => 0,
            _ => 1,
        };
        let variant = match kind {
            "image" | "api_rendition" => {
                Some(["web", "square", "thumb", "original"][(rnd() * 4.0) as usize % 4])
            }
            "usage" => Some("web"),
            _ => None,
        };
        let at = db::fmt_time(
            now - chrono::Duration::milliseconds((rnd() * 30.0 * 86_400_000.0) as i64),
        );
        let product = (kind != "csv" && kind != "selection_zip").then(|| pid.clone());
        let asset = matches!(kind, "image" | "api_rendition" | "usage")
            .then(|| a.map(|a| a.0.clone()))
            .flatten();
        let usage = (kind == "usage").then(|| if rnd() < 0.5 { "published" } else { "synced" });
        let bytes = if files > 0 {
            files * (60_000 + (rnd() * 400_000.0) as i64)
        } else {
            4_000 + (rnd() * 20_000.0) as i64
        };
        tx.execute(
            "INSERT INTO download_events (id, at, kind, retailer_id, retailer_name, actor_type, actor_id, actor_name, variant, product_id, style_number, asset_id, usage_event, files, bytes) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            params![
                crate::ids::new("dle"),
                at,
                kind,
                w.0,
                w.1,
                w.2,
                w.3,
                w.4,
                variant,
                product,
                product.as_deref().and_then(style_of),
                asset,
                usage,
                files,
                bytes
            ],
        )?;
    }
    let hour_ago = db::fmt_time(now - chrono::Duration::hours(1));
    tx.execute(
        "UPDATE retailers SET last_activity_at = ? WHERE id IN (?, ?)",
        params![hour_ago, RETAILER, HARBOUR],
    )?;
    Ok(())
}

/// The demo tick (every minute): reset when never set up, or when the
/// interval passed and a visitor changed something, the last reset failed
/// or a day went by. A demo nobody touched is left alone.
pub async fn tick(app: &App) {
    let every = app.cfg.demo_reset_minutes * 60;
    let due = app
        .db
        .read(move |c| {
            let now = chrono::Utc::now();
            let s = state(c)?;
            let set_up = db::get_meta(c, "setup_done")?.as_deref() == Some("1");
            let Some(s) = s else { return Ok(true) };
            let since = secs_since(&s.reset_at, now);
            if s.phase == "resetting" && since < RESET_STALE_SECS {
                return Ok(false);
            }
            if !set_up {
                return Ok(true);
            }
            if since < every {
                return Ok(false);
            }
            Ok(s.phase != "ready"
                || since >= CLEAN_RESET_SECS
                || db::get_meta(c, "demo_dirty")?.is_some())
        })
        .await
        .unwrap_or(false);
    if due {
        if let Err(e) = reset(app).await {
            tracing::warn!(error = %e, "demo reset failed");
        }
    }
}

/// Makes sure a demo exists before someone signs in.
pub async fn ensure(app: &App) -> Result<()> {
    let need = app
        .db
        .read(|c| {
            let s = state(c)?;
            let set_up = db::get_meta(c, "setup_done")?.as_deref() == Some("1");
            Ok(match s {
                None => true,
                Some(s) => {
                    !set_up
                        && !(s.phase == "resetting"
                            && secs_since(&s.reset_at, chrono::Utc::now()) < RESET_STALE_SECS)
                }
            })
        })
        .await?;
    if need {
        reset(app).await?;
    }
    Ok(())
}

/// Starts the minute tick (demo mode only).
pub fn start(app: App) {
    if !app.cfg.demo {
        return;
    }
    tokio::spawn(async move {
        let mut t = tokio::time::interval(std::time::Duration::from_secs(60));
        t.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            t.tick().await;
            tick(&app).await;
        }
    });
}

// ---- what the demo refuses --------------------------------------------------------------

/// A refusal: (OBX error code, detail).
pub type Refusal = (&'static str, String);

fn refuse(why: &str) -> Option<Refusal> {
    Some((
        "forbidden",
        format!("{why} This is not possible in the demo."),
    ))
}

fn segs(p: &str) -> Vec<&str> {
    p.trim_start_matches('/').split('/').collect()
}

/// The demo's rules for one request (None: allowed). `body` is the parsed
/// JSON body for the few routes whose answer depends on it.
pub fn refusal(method: &Method, path: &str, body: Option<&Map<String, Value>>) -> Option<Refusal> {
    let write = !matches!(*method, Method::GET | Method::HEAD | Method::OPTIONS);
    let p = path.trim_end_matches('/');
    if p.starts_with("/obx/v1/webhooks") {
        return Some((
            "not_implemented",
            "The demo portal does not send webhooks.".into(),
        ));
    }
    if p == "/obx/v1/usage" {
        return Some((
            "not_implemented",
            "The demo portal's key can only read, so it does not take usage events.".into(),
        ));
    }
    if p == "/obx/v1/ingest" || p.starts_with("/obx/v1/ingest/") {
        return Some((
            "not_implemented",
            "The demo portal has no Ingest API; try the Excel import as the demo brand.".into(),
        ));
    }
    if !write {
        if p.starts_with("/admin/api/invites/") {
            return refuse("Invitations are switched off.");
        }
        return None;
    }
    let s = segs(p);
    let is =
        |pat: &[&str]| s.len() == pat.len() && s.iter().zip(pat).all(|(a, b)| *b == "*" || a == b);
    let starts = |pre: &str| p == pre || p.starts_with(&format!("{pre}/"));
    let rules: Vec<(bool, &str)> = vec![
        (p == "/admin/api/setup", "The demo is already set up."),
        (
            p.starts_with("/admin/api/password/"),
            "Passwords cannot be reset.",
        ),
        (
            p.starts_with("/admin/api/invites/"),
            "Invitations are switched off.",
        ),
        (p == "/admin/api/me", "The demo accounts cannot be removed."),
        (
            is(&["admin", "api", "import-sources"])
                || is(&["admin", "api", "import-sources", "*"])
                || is(&["admin", "api", "import-sources", "*", "run"])
                || is(&["admin", "api", "import-sources", "*", "test"]),
            "Scheduled imports from other servers are switched off.",
        ),
        (
            p == "/admin/api/users/invites",
            "No e-mail is sent, so nobody can be invited.",
        ),
        (
            is(&["admin", "api", "users", "*", "resend-invite"]),
            "No e-mail is sent, so nobody can be invited.",
        ),
        (
            is(&["admin", "api", "users", "*"]) && DEMO_USERS.contains(&s[3]),
            "The demo accounts cannot be changed.",
        ),
        (
            p == format!("/admin/api/retailers/{RETAILER}"),
            "Northwind Stores is the shared demo retailer and cannot be changed; try Harbour & Co.",
        ),
        (
            starts("/admin/api/api-clients") || starts("/admin/api/portal/api-clients"),
            "No API keys can be created or changed; use the public read-only demo key.",
        ),
        (
            starts("/admin/api/ingest-tokens"),
            "No upload keys can be created or changed.",
        ),
        (
            is(&["admin", "api", "webhooks"])
                || is(&["admin", "api", "webhooks", "*"])
                || is(&["admin", "api", "webhooks", "*", "test"]),
            "Webhooks are switched off.",
        ),
        (
            is(&["admin", "api", "catalog", "*", "*"])
                && ["brands", "products", "variants", "assets"].contains(&s[3]),
            "Catalog records cannot be deleted (unpublish them instead).",
        ),
    ];
    for (hit, why) in rules {
        if !hit {
            continue;
        }
        // Deleting things nobody else relies on stays possible.
        if *method == Method::DELETE
            && (is(&["admin", "api", "import-sources", "*"])
                || is(&["admin", "api", "webhooks", "*"]))
        {
            return None;
        }
        if p == "/admin/api/me" && *method == Method::PATCH {
            break;
        }
        if p.starts_with("/admin/api/catalog/") && *method != Method::DELETE {
            continue;
        }
        return refuse(why);
    }
    if p == "/admin/api/me"
        && *method == Method::PATCH
        && body.is_some_and(|b| {
            b.contains_key("new_password")
                || b.contains_key("current_password")
                || b.contains_key("email")
        })
    {
        return refuse("The password and e-mail address of the demo accounts cannot be changed.");
    }
    // The portal's look can be tried out (it is put back at the next reset);
    // the company details and the brand's name stay.
    if p == "/admin/api/settings"
        && *method == Method::PATCH
        && body.is_some_and(|b| {
            b.contains_key("company")
                || b.get("branding")
                    .and_then(|x| x.as_object())
                    .is_some_and(|x| x.contains_key("display_name"))
        })
    {
        return refuse("The company details and the brand's name are the same for every visitor.");
    }
    if is(&["admin", "api", "access-requests", "*", "approve"])
        && body.is_none_or(|b| b.get("create_api_client") != Some(&Value::Bool(false)))
    {
        return refuse(
            "Approving with an API key would create a new key. Untick API access, or decline the request.",
        );
    }
    None
}

/// Routes whose refusal depends on the JSON body.
pub fn needs_body(method: &Method, path: &str) -> bool {
    (*method == Method::PATCH && (path == "/admin/api/me" || path == "/admin/api/settings"))
        || (*method == Method::POST
            && path.starts_with("/admin/api/access-requests/")
            && path.ends_with("/approve"))
}

/// A demo problem: marked with `x-obx-demo: true`.
pub fn problem(code: &str, detail: impl Into<String>) -> Problem {
    Problem::new(code, detail).extension("x-obx-demo", Value::Bool(true))
}

/// Writes that do not change what other visitors see.
const NOT_DIRTY: [&str; 4] = [
    "/admin/api/demo/login",
    "/admin/api/demo/reset",
    "/admin/api/session/login",
    "/admin/api/session/logout",
];

/// Runs before every route in demo mode: abuse limits per address, the
/// demo's refusals, the upload cap, and no indexing or shared caching.
pub async fn guard(State(app): State<App>, req: Request, next: Next) -> Response {
    if !app.cfg.demo {
        return next.run(req).await;
    }
    match guard_inner(app, req, next).await {
        Ok(r) | Err(r) => r,
    }
}

async fn guard_inner(
    app: App,
    req: Request,
    next: Next,
) -> std::result::Result<Response, Response> {
    let method = req.method().clone();
    let path = req.uri().path().to_string();
    let write = !matches!(method, Method::GET | Method::HEAD | Method::OPTIONS);
    let peer = req
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|c| c.0);
    let ip = client_ip(&app, req.headers(), peer);
    if path != "/healthz" && path != "/readyz" {
        let (bucket, n) = if path == "/admin/api/demo/login" {
            ("login", 10)
        } else if write {
            ("write", 40)
        } else {
            ("read", 300)
        };
        if app.limit(&format!("demo:{bucket}:{ip}"), n, 60).is_err() {
            let mut p = Problem::new(
                "rate_limited",
                "Too many requests to the demo from your address. Wait a minute and try again.",
            );
            p.retry_after = Some(60);
            return Err(p.into_response());
        }
    }
    let max = app.cfg.demo_max_upload_bytes;
    let mut req = req;
    if write {
        let len = req
            .headers()
            .get(header::CONTENT_LENGTH)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse::<u64>().ok());
        let chunked = req
            .headers()
            .get(header::TRANSFER_ENCODING)
            .and_then(|v| v.to_str().ok())
            .is_some_and(|v| v.to_ascii_lowercase().contains("chunked"));
        if len.is_some_and(|l| l > max) || (len.is_none() && chunked) {
            return Err(problem(
                "payload_too_large",
                format!(
                    "Uploads in the demo are limited to {} MB (send a Content-Length).",
                    (max as f64 / 1_048_576.0).round()
                ),
            )
            .into_response());
        }
    }
    let mut body: Option<Map<String, Value>> = None;
    if needs_body(&method, &path) {
        let (parts, b) = req.into_parts();
        let bytes = axum::body::to_bytes(b, max as usize)
            .await
            .unwrap_or_default();
        body = serde_json::from_slice::<Value>(&bytes)
            .ok()
            .and_then(|v| v.as_object().cloned());
        req = Request::from_parts(parts, Body::from(bytes));
    }
    if let Some((code, detail)) = refusal(&method, &path, body.as_ref()) {
        return Err(problem(code, detail).into_response());
    }
    let mut r = next.run(req).await;
    if write && r.status().as_u16() < 400 && !NOT_DIRTY.contains(&path.as_str()) {
        let _ = app
            .db
            .write(|tx| {
                if db::get_meta(tx, "demo_dirty")?.is_none() {
                    db::set_meta(tx, "demo_dirty", &db::now_str())?;
                }
                Ok(())
            })
            .await;
    }
    let h = r.headers_mut();
    h.insert(
        "x-robots-tag",
        HeaderValue::from_static("noindex, nofollow"),
    );
    // Files (also images visitors uploaded) never go into shared caches.
    if h.get(header::CACHE_CONTROL)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.to_ascii_lowercase().contains("public"))
    {
        h.insert(
            header::CACHE_CONTROL,
            HeaderValue::from_static("private, max-age=300"),
        );
    }
    Ok(r)
}

// ---- routes ----------------------------------------------------------------------------------

fn demo_only(app: &App) -> Result<()> {
    if app.cfg.demo {
        Ok(())
    } else {
        Err(Problem::new("not_found", "There is nothing here."))
    }
}

/// GET /admin/api/demo
pub async fn h_info(State(app): State<App>) -> Res {
    demo_only(&app)?;
    let a = app.clone();
    Ok(ok(&app.db.read(move |c| info(&a, c)).await?))
}

async fn verify_turnstile(app: &App, token: Option<&str>, ip: &str) -> Result<()> {
    let Some(secret) = app.cfg.demo_turnstile_secret.clone() else {
        return Ok(());
    };
    let Some(token) = token.filter(|t| !t.is_empty() && t.len() <= 4096) else {
        return Err(problem("forbidden", "Confirm that you are a person first."));
    };
    let mut form = vec![("secret", secret), ("response", token.to_string())];
    if !ip.is_empty() {
        form.push(("remoteip", ip.to_string()));
    }
    let client = crate::safeurl::client(false, std::time::Duration::from_secs(10));
    let ok = match client
        .post("https://challenges.cloudflare.com/turnstile/v0/siteverify")
        .form(&form)
        .send()
        .await
    {
        Ok(r) => r
            .json::<Value>()
            .await
            .ok()
            .and_then(|v| v["success"].as_bool())
            .unwrap_or(false),
        Err(e) => {
            tracing::warn!(error = %e, "demo: Turnstile check failed");
            false
        }
    };
    if ok {
        Ok(())
    } else {
        Err(problem(
            "forbidden",
            "The check that you are a person failed. Reload the page and try again.",
        ))
    }
}

/// POST /admin/api/demo/login `{"as": "retailer" | "brand"}`
pub async fn h_login(
    State(app): State<App>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    body: Bytes,
) -> Res {
    demo_only(&app)?;
    let b: Map<String, Value> = if body.iter().all(u8::is_ascii_whitespace) {
        Map::new()
    } else {
        crate::http::read_json_object(&headers, &body)?
    };
    let who = match b.get("as").and_then(|v| v.as_str()) {
        Some("retailer") => RETAILER_USER,
        Some("brand") => BRAND_USER,
        _ => {
            return Err(Problem::new(
                "validation_failed",
                "Send {\"as\": \"retailer\"} or {\"as\": \"brand\"}.",
            ));
        }
    };
    let ip = client_ip(&app, &headers, Some(peer));
    if app.limit(&format!("demo-login:{ip}"), 30, 600).is_err() {
        let mut p = Problem::new("rate_limited", "Too many demo sign-ins; try again later.");
        p.retry_after = Some(600);
        return Err(p);
    }
    verify_turnstile(&app, b.get("turnstile_token").and_then(|v| v.as_str()), &ip).await?;
    ensure(&app).await?;
    let h = headers.clone();
    let out = app
        .db
        .write(move |tx| {
            let Some(u) = crate::http::admin::load_user(tx, "id = ?", who)? else {
                let mut p = Problem::new(
                    "service_unavailable",
                    "The demo is being reset. Try again in a minute.",
                );
                p.retry_after = Some(60);
                return Err(p);
            };
            let (sid, csrf) = crate::http::admin::start_session(tx, &h, &u.id)?;
            let u = crate::http::admin::load_user(tx, "id = ?", &u.id)?.unwrap_or(u);
            let body = crate::http::admin::session_json(tx, Some(&u), &csrf, false)?;
            Ok((sid, csrf, body))
        })
        .await?;
    Ok(crate::http::admin::session_response(
        &app, 200, &out.2, &out.0, &out.1,
    ))
}

/// POST /admin/api/demo/reset: signed-in visitors, at most once per 10
/// minutes for everyone.
pub async fn h_reset(State(app): State<App>, method: Method, headers: HeaderMap) -> Res {
    demo_only(&app)?;
    crate::http::admin::admin_guard(&app, &headers, &method, "any").await?;
    rate_limit_window(&app, "demo-reset", 1, 600)?;
    reset(&app).await?;
    let a = app.clone();
    Ok(json_resp(202, &app.db.read(move |c| info(&a, c)).await?))
}

fn rate_limit_window(app: &App, key: &str, n: u32, secs: i64) -> Result<()> {
    app.limit(key, n, secs).map(|_| ()).map_err(|retry| {
        let mut p = Problem::new(
            "rate_limited",
            "The demo was reset a moment ago; try again later.",
        );
        p.retry_after = Some(retry as u64);
        p
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn refusal_rules() {
        let none: Option<&Map<String, Value>> = None;
        let obj = |v: Value| v.as_object().cloned().unwrap();
        type Case<'a> = (Method, &'a str, Option<Map<String, Value>>, Option<&'a str>);
        let cases: Vec<Case> = vec![
            (Method::GET, "/admin/api/portal/products", None, None),
            (
                Method::GET,
                "/admin/api/invites/abc",
                None,
                Some("forbidden"),
            ),
            (
                Method::POST,
                "/obx/v1/webhooks",
                None,
                Some("not_implemented"),
            ),
            (Method::GET, "/obx/v1/ingest", None, Some("not_implemented")),
            (
                Method::PUT,
                "/obx/v1/ingest/products/X",
                None,
                Some("not_implemented"),
            ),
            (Method::POST, "/obx/v1/usage", None, Some("not_implemented")),
            (Method::POST, "/admin/api/setup", None, Some("forbidden")),
            (
                Method::POST,
                "/admin/api/password/forgot",
                None,
                Some("forbidden"),
            ),
            (Method::DELETE, "/admin/api/me", None, Some("forbidden")),
            (
                Method::PATCH,
                "/admin/api/me",
                Some(obj(json!({"name": "X"}))),
                None,
            ),
            (
                Method::PATCH,
                "/admin/api/me",
                Some(obj(json!({"new_password": "x"}))),
                Some("forbidden"),
            ),
            (
                Method::POST,
                "/admin/api/import-sources",
                None,
                Some("forbidden"),
            ),
            (
                Method::POST,
                "/admin/api/import-sources/src_1/run",
                None,
                Some("forbidden"),
            ),
            (
                Method::DELETE,
                "/admin/api/import-sources/src_1",
                None,
                None,
            ),
            (
                Method::POST,
                "/admin/api/users/invites",
                None,
                Some("forbidden"),
            ),
            (
                Method::PATCH,
                "/admin/api/users/usr_demo_brand",
                None,
                Some("forbidden"),
            ),
            (Method::PATCH, "/admin/api/users/usr_other", None, None),
            (
                Method::PATCH,
                "/admin/api/retailers/rtl_demo_northwind",
                None,
                Some("forbidden"),
            ),
            (
                Method::PATCH,
                "/admin/api/retailers/rtl_demo_harbour",
                None,
                None,
            ),
            (
                Method::POST,
                "/admin/api/api-clients",
                None,
                Some("forbidden"),
            ),
            (
                Method::POST,
                "/admin/api/portal/api-clients/cli_1/rotate",
                None,
                Some("forbidden"),
            ),
            (
                Method::POST,
                "/admin/api/ingest-tokens",
                None,
                Some("forbidden"),
            ),
            (Method::POST, "/admin/api/webhooks", None, Some("forbidden")),
            (Method::DELETE, "/admin/api/webhooks/whk_1", None, None),
            (
                Method::DELETE,
                "/admin/api/catalog/products/MN-1001",
                None,
                Some("forbidden"),
            ),
            (
                Method::PATCH,
                "/admin/api/catalog/products/MN-1001",
                None,
                None,
            ),
            (
                Method::PATCH,
                "/admin/api/settings",
                Some(obj(json!({"branding": {"theme": {}}}))),
                None,
            ),
            (
                Method::PATCH,
                "/admin/api/settings",
                Some(obj(json!({"branding": {"display_name": "X"}}))),
                Some("forbidden"),
            ),
            (
                Method::PATCH,
                "/admin/api/settings",
                Some(obj(json!({"company": {}}))),
                Some("forbidden"),
            ),
            (
                Method::POST,
                "/admin/api/access-requests/acr_1/approve",
                None,
                Some("forbidden"),
            ),
            (
                Method::POST,
                "/admin/api/access-requests/acr_1/approve",
                Some(obj(json!({"create_api_client": false}))),
                None,
            ),
            (
                Method::POST,
                "/admin/api/access-requests/acr_1/reject",
                None,
                None,
            ),
            (Method::POST, "/admin/api/imports", None, None),
        ];
        for (m, p, b, want) in cases {
            let got = refusal(&m, p, b.as_ref().or(none));
            assert_eq!(got.as_ref().map(|r| r.0), want, "{m} {p}");
        }
    }

    #[test]
    fn next_reset() {
        let s = DemoState {
            phase: "ready".into(),
            reset_at: "2026-11-25T10:00:00.000000Z".into(),
            error: None,
        };
        let now = db::parse_time("2026-11-25T11:30:00Z").unwrap();
        assert_eq!(
            next_reset_at(60, Some(&s), now).as_deref(),
            Some("2026-11-25T12:00:00Z")
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn reset_sign_in_and_refuse() {
        let dir = std::env::temp_dir().join(format!("obx-demo-test-{}", crate::ids::new("t")));
        std::fs::create_dir_all(&dir).unwrap();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let mut cfg = crate::config::Config::for_test(&dir);
        cfg.public_url = format!("http://{addr}");
        cfg.port = addr.port();
        cfg.demo = true;
        cfg.setup_code = None;
        let app = App::new(cfg).await.unwrap();
        let st = reset(&app).await.unwrap();
        assert_eq!(st.phase, "ready", "{:?}", st.error);
        let (products, images, events): (i64, i64, i64) = app
            .db
            .read(|c| {
                Ok((
                    c.query_row("SELECT COUNT(*) FROM products WHERE visible = 1", [], |r| {
                        r.get(0)
                    })?,
                    c.query_row("SELECT COUNT(*) FROM branding_images", [], |r| r.get(0))?,
                    c.query_row("SELECT COUNT(*) FROM download_events", [], |r| r.get(0))?,
                ))
            })
            .await
            .unwrap();
        assert_eq!(products, 11);
        assert!(images > 0);
        assert_eq!(events, 140);
        let router = crate::http::router::router(app.clone());
        tokio::spawn(async move {
            axum::serve(
                listener,
                router.into_make_service_with_connect_info::<SocketAddr>(),
            )
            .await
            .unwrap();
        });
        let base = format!("http://{addr}");
        let http = reqwest::Client::new();
        let b: Value = http
            .get(format!("{base}/admin/api/public/branding"))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        assert_eq!(b["x-obx-demo"]["api"]["client_id"], CLIENT_ID);
        assert_eq!(b["x-obx-demo"]["ready"], true);
        let d: Value = http
            .get(format!("{base}/.well-known/obx"))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        let caps: Vec<&str> = d["capabilities"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|c| c.as_str())
            .collect();
        assert!(
            !caps.contains(&"webhooks") && !caps.contains(&"usage") && caps.contains(&"products")
        );
        for (who, role) in [("retailer", "retailer"), ("brand", "admin")] {
            let r = http
                .post(format!("{base}/admin/api/demo/login"))
                .header("x-csrf-token", "x")
                .header("cookie", "obx_csrf=x")
                .json(&json!({"as": who}))
                .send()
                .await
                .unwrap();
            assert_eq!(r.status(), 200, "demo login as {who}");
            assert_eq!(
                r.headers().get("x-robots-tag").unwrap(),
                "noindex, nofollow"
            );
            let cookies: Vec<String> = r
                .headers()
                .get_all("set-cookie")
                .iter()
                .filter_map(|v| v.to_str().ok())
                .map(|v| v.split(';').next().unwrap_or("").to_string())
                .collect();
            let s: Value = r.json().await.unwrap();
            assert_eq!(s["user"]["role"], role);
            let csrf = s["csrf_token"].as_str().unwrap().to_string();
            let cookie = cookies.join("; ");
            // A refused action: creating an API key.
            let r = http
                .post(format!("{base}/admin/api/portal/api-clients"))
                .header("cookie", &cookie)
                .header("x-csrf-token", &csrf)
                .json(&json!({"name": "mine"}))
                .send()
                .await
                .unwrap();
            assert_eq!(r.status(), 403);
            let p: Value = r.json().await.unwrap();
            assert_eq!(p["x-obx-demo"], true);
            assert_eq!(p["obx_error"], "forbidden");
        }
        // The public read-only key works.
        let t: Value = http
            .post(format!("{base}/obx/v1/oauth/token"))
            .basic_auth(CLIENT_ID, Some(CLIENT_SECRET))
            .form(&[("grant_type", "client_credentials")])
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        assert!(t["access_token"].is_string(), "{t}");
        // A second reset keeps the demo accounts' sessions and the fixture
        // images, and puts the catalog back.
        let st = reset(&app).await.unwrap();
        assert_eq!(st.phase, "ready", "{:?}", st.error);
        let (products, sessions, dirty): (i64, i64, Option<String>) = app
            .db
            .read(|c| {
                Ok((
                    c.query_row("SELECT COUNT(*) FROM products WHERE visible = 1", [], |r| {
                        r.get(0)
                    })?,
                    c.query_row("SELECT COUNT(*) FROM sessions", [], |r| r.get(0))?,
                    db::get_meta(c, "demo_dirty")?,
                ))
            })
            .await
            .unwrap();
        assert_eq!(products, 11);
        assert_eq!(sessions, 2);
        assert!(dirty.is_none());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
