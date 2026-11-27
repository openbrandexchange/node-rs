//! HTTP tests of exports, webhooks and usage against a running node (real
//! TCP, the MAISON NOOR fixtures).

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use serde_json::{Map, Value, json};

use crate::app::App;
use crate::model::KIND_BRAND;

struct Node {
    app: App,
    base: String,
    token: String,
    dir: std::path::PathBuf,
}

impl Drop for Node {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

async fn node() -> Node {
    let dir = std::env::temp_dir().join(format!("obx-exp-test-{}", crate::ids::new("t")));
    std::fs::create_dir_all(&dir).unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let base = format!("http://{addr}");
    let mut cfg = crate::config::Config::for_test(&dir);
    cfg.public_url = base.clone();
    cfg.port = addr.port();
    let app = App::new(cfg).await.unwrap();
    app.catalog_write(None, |w| {
        crate::db::set_meta(w.tx, "setup_done", "1")?;
        let mut doc = Map::new();
        doc.insert("name".into(), json!("MAISON NOOR"));
        doc.insert("status".into(), json!("published"));
        let (_, p) = w.upsert(KIND_BRAND, "maison-noor", doc, "");
        p.map_or(Ok(()), Err)
    })
    .await
    .unwrap();
    let fx = std::path::PathBuf::from(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/crates/obx-conformance/fixtures/maison-noor"
    ));
    let run = crate::imports::run_import_cli(
        &app,
        Some(fx.join("products.csv")),
        Some(fx.join("assets.csv")),
        Some(fx.join("images")),
        None,
        false,
        false,
    )
    .await
    .unwrap();
    assert_eq!(run["status"], "succeeded", "{run}");
    let (client_id, secret) = app
        .db
        .write(|tx| {
            let mut d = Map::new();
            d.insert("name".into(), json!("Retailer A"));
            let r = crate::http::admin::create_retailer(tx, &d)?;
            let (c, s) = crate::http::admin::create_api_client(
                tx,
                &r.id,
                "key",
                Some(vec![
                    "catalog:read".into(),
                    "media:read".into(),
                    "media:original".into(),
                    "usage:write".into(),
                ]),
                "admin",
            )?;
            Ok((c.client_id, s))
        })
        .await
        .unwrap();
    let router = crate::http::router::router(app.clone())
        .into_make_service_with_connect_info::<SocketAddr>();
    tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    crate::jobs::start_workers(app.clone());
    crate::webhooks::start(app.clone());
    let t: Value = reqwest::Client::new()
        .post(format!("{base}/obx/v1/oauth/token"))
        .form(&[
            ("grant_type", "client_credentials"),
            ("client_id", &client_id),
            ("client_secret", &secret),
        ])
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    Node {
        app,
        base,
        token: t["access_token"].as_str().expect("token").to_string(),
        dir,
    }
}

impl Node {
    fn req(&self, m: reqwest::Method, path: &str) -> reqwest::RequestBuilder {
        reqwest::Client::new()
            .request(m, format!("{}{path}", self.base))
            .bearer_auth(&self.token)
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn export_usage_and_webhooks() {
    let n = node().await;

    // ---- export with an Idempotency-Key
    let body = json!({"renditions": ["original"]});
    let r = n
        .req(reqwest::Method::POST, "/obx/v1/exports")
        .header("idempotency-key", "k1")
        .json(&body)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 202);
    assert!(r.headers().get("location").is_some());
    let e: Value = r.json().await.unwrap();
    let again: Value = n
        .req(reqwest::Method::POST, "/obx/v1/exports")
        .header("idempotency-key", "k1")
        .json(&body)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(again["id"], e["id"]);
    let other = n
        .req(reqwest::Method::POST, "/obx/v1/exports")
        .header("idempotency-key", "k1")
        .json(&json!({"renditions": ["thumb"]}))
        .send()
        .await
        .unwrap();
    assert_eq!(other.status(), 409);
    let id = e["id"].as_str().unwrap().to_string();
    let mut done = Value::Null;
    for _ in 0..200 {
        done = n
            .req(reqwest::Method::GET, &format!("/obx/v1/exports/{id}"))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        if done["status"] != "queued" && done["status"] != "running" {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    assert_eq!(done["status"], "succeeded", "{done}");
    assert!(
        crate::schemas::validate_strict("Export", &done).is_empty(),
        "{done}"
    );
    // The manifest by signed URL, without a token.
    let manifest = reqwest::get(done["manifest_url"].as_str().unwrap())
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    let lines: Vec<Value> = manifest
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    assert_eq!(lines[0]["type"], "header");
    for l in &lines {
        assert!(
            crate::schemas::validate("ExportManifestLine", l).is_empty(),
            "{l}"
        );
    }
    let products = lines.iter().filter(|l| l["type"] == "product").count();
    assert!(products > 0);
    assert_eq!(lines[0]["counts"]["products"], products);
    let files: Vec<&Value> = lines.iter().filter(|l| l["type"] == "file").collect();
    assert!(!files.is_empty());
    let part = &done["parts"][0];
    let zip_bytes = reqwest::get(part["url"].as_str().unwrap())
        .await
        .unwrap()
        .bytes()
        .await
        .unwrap();
    assert_eq!(
        hex::encode(<sha2::Sha256 as sha2::Digest>::digest(&zip_bytes)),
        part["sha256"].as_str().unwrap()
    );
    let mut z = zip::ZipArchive::new(std::io::Cursor::new(zip_bytes.to_vec())).unwrap();
    for f in files.iter().filter(|f| f["part"] == 1) {
        let mut buf = vec![];
        std::io::Read::read_to_end(
            &mut z.by_name(f["path"].as_str().unwrap()).unwrap(),
            &mut buf,
        )
        .unwrap();
        assert_eq!(
            hex::encode(<sha2::Sha256 as sha2::Digest>::digest(&buf)),
            f["sha256"].as_str().unwrap()
        );
        assert_eq!(
            f["path"].as_str().unwrap().split('/').nth(1),
            Some("original")
        );
    }
    // A Range read of a part.
    let r = n
        .req(
            reqwest::Method::GET,
            &format!("/obx/v1/exports/{id}/parts/1"),
        )
        .header("range", "bytes=0-9")
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 206);
    assert_eq!(r.bytes().await.unwrap().len(), 10);
    // Another export id → not found; tampered signature → forbidden.
    let r = n
        .req(reqwest::Method::GET, "/obx/v1/exports/job_nope")
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 404);
    let bad = done["manifest_url"]
        .as_str()
        .unwrap()
        .replace("sig=", "sig=0");
    assert_eq!(reqwest::get(bad).await.unwrap().status(), 403);

    // ---- usage
    let asset = files[0]["asset_id"].as_str().unwrap();
    let r: Value = n
        .req(reqwest::Method::POST, "/obx/v1/usage")
        .json(&json!({"events": [
            {"asset_id": asset, "rendition": "web", "event": "published", "channel": "webshop", "at": "2026-01-01T00:00:00Z"},
            {"asset_id": "ast_unknown", "event": "synced", "at": "2026-01-01T00:00:00Z"}]}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(r["accepted"], 1, "{r}");
    let usage: i64 = n
        .app
        .db
        .read(|c| Ok(c.query_row("SELECT COUNT(*) FROM download_events WHERE kind = 'usage' AND usage_event = 'published'", [], |r| r.get(0))?))
        .await
        .unwrap();
    assert_eq!(usage, 1);

    // ---- webhooks: a local receiver (OBX_ALLOW_PRIVATE_URLS on)
    type Got = Arc<Mutex<Vec<(axum::http::HeaderMap, Vec<u8>)>>>;
    let got: Got = Arc::default();
    let g = got.clone();
    let recv = axum::Router::new().route(
        "/hook",
        axum::routing::post(move |h: axum::http::HeaderMap, b: axum::body::Bytes| {
            let g = g.clone();
            async move {
                g.lock().unwrap().push((h, b.to_vec()));
                axum::http::StatusCode::NO_CONTENT
            }
        }),
    );
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let hook_url = format!("http://{}/hook", l.local_addr().unwrap());
    tokio::spawn(async move { axum::serve(l, recv).await.unwrap() });
    let r = n
        .req(reqwest::Method::POST, "/obx/v1/webhooks")
        .json(&json!({"url": hook_url, "events": ["changes.available", "export.completed"]}))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 201);
    let sub: Value = r.json().await.unwrap();
    let secret = sub["secret"].as_str().unwrap().to_string();
    assert!(secret.starts_with("whsec_"));
    let sid = sub["id"].as_str().unwrap();
    let t: Value = n
        .req(
            reqwest::Method::POST,
            &format!("/obx/v1/webhooks/{sid}/test"),
        )
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(t["delivered"], true, "{t}");
    {
        let g = got.lock().unwrap();
        let (h, b) = g.last().unwrap();
        let ev: Value = serde_json::from_slice(b).unwrap();
        assert_eq!(ev["type"], "webhook.test");
        assert_eq!(
            h["obx-webhook-id"].to_str().unwrap(),
            ev["id"].as_str().unwrap()
        );
        assert!(crate::webhook_proto::verify(
            &secret,
            h["obx-webhook-timestamp"].to_str().unwrap(),
            b,
            h["obx-webhook-signature"].to_str().unwrap(),
            chrono::Utc::now().timestamp(),
            300,
        ));
        assert!(crate::schemas::validate("WebhookEvent", &ev).is_empty());
    }
    let list: Value = n
        .req(reqwest::Method::GET, "/obx/v1/webhooks")
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(list["items"][0]["secret"].is_null());
    // A catalog change → changes.available is delivered by the loop.
    n.app
        .catalog_write(None, |w| {
            let mut doc = Map::new();
            doc.insert("name".into(), json!("MAISON NOOR Paris"));
            doc.insert("status".into(), json!("published"));
            let (_, p) = w.upsert(KIND_BRAND, "maison-noor", doc, "");
            p.map_or(Ok(()), Err)
        })
        .await
        .unwrap();
    let mut seen = false;
    for _ in 0..100 {
        seen = got.lock().unwrap().iter().any(|(_, b)| {
            serde_json::from_slice::<Value>(b).is_ok_and(|e| e["type"] == "changes.available")
        });
        if seen {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    assert!(seen, "no changes.available delivery");
    // Unsafe targets are refused even with private addresses allowed.
    let r = n
        .req(reqwest::Method::POST, "/obx/v1/webhooks")
        .json(&json!({"url": "https://169.254.169.254/latest", "events": ["grant.updated"]}))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 422);
    let r = n
        .req(reqwest::Method::POST, "/obx/v1/webhooks")
        .json(&json!({"url": hook_url, "events": ["import_run.completed"]}))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 422, "brand events are not for clients");
    let r = n
        .req(reqwest::Method::DELETE, &format!("/obx/v1/webhooks/{sid}"))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 204);
    let r = n
        .req(reqwest::Method::DELETE, &format!("/obx/v1/webhooks/{sid}"))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 404);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn failed_deliveries_are_retried_later() {
    let n = node().await;
    // A receiver that always fails.
    let recv = axum::Router::new().route(
        "/hook",
        axum::routing::post(|| async { axum::http::StatusCode::INTERNAL_SERVER_ERROR }),
    );
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let hook_url = format!("http://{}/hook", l.local_addr().unwrap());
    tokio::spawn(async move { axum::serve(l, recv).await.unwrap() });
    let id = n
        .app
        .db
        .write(move |tx| {
            tx.execute(
                "INSERT INTO webhooks (id, owner_type, owner_id, url, events, secret_enc, status, created_at) VALUES ('whk_t', 'brand', NULL, ?, 'ingest_job.completed', ?, 'active', ?)",
                rusqlite::params![hook_url, "x", crate::db::now_str()],
            )?;
            crate::webhooks::event_to(tx, "brand", None, "ingest_job.completed", &json!({}))?;
            Ok(tx.query_row("SELECT id FROM webhook_deliveries", [], |r| r.get::<_, String>(0))?)
        })
        .await
        .unwrap();
    // The secret is unreadable ("x" is not encrypted): the attempt fails
    // without a request and is rescheduled.
    crate::webhooks::deliver_due(&n.app).await;
    let (status, attempt, err): (String, i64, String) = n
        .app
        .db
        .read(move |c| {
            Ok(c.query_row(
                "SELECT status, attempt, error FROM webhook_deliveries WHERE id = ?",
                [&id],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )?)
        })
        .await
        .unwrap();
    assert_eq!((status.as_str(), attempt), ("pending", 1));
    assert!(err.contains("secret unreadable"), "{err}");
    let failing: Option<String> = n
        .app
        .db
        .read(|c| {
            Ok(c.query_row(
                "SELECT failing_since FROM webhooks WHERE id = 'whk_t'",
                [],
                |r| r.get(0),
            )?)
        })
        .await
        .unwrap();
    assert!(failing.is_some());
}

/// An export with `lang` (spec proposal 0010) writes its objects as the read
/// endpoints with `?lang=` do; a malformed tag is refused.
#[tokio::test(flavor = "multi_thread")]
async fn export_in_one_language() {
    let n = node().await;
    let bad = n
        .req(reqwest::Method::POST, "/obx/v1/exports")
        .json(&json!({"renditions": [], "lang": "en--GB"}))
        .send()
        .await
        .unwrap();
    assert_eq!(bad.status(), 422);
    let e: Value = n
        .req(reqwest::Method::POST, "/obx/v1/exports")
        .json(&json!({"renditions": [], "lang": "de"}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let id = e["id"].as_str().unwrap().to_string();
    let mut done = Value::Null;
    for _ in 0..200 {
        done = n
            .req(reqwest::Method::GET, &format!("/obx/v1/exports/{id}"))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        if done["status"] != "queued" && done["status"] != "running" {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    assert_eq!(done["status"], "succeeded", "{done}");
    let manifest = reqwest::get(done["manifest_url"].as_str().unwrap())
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    let lines: Vec<Value> = manifest
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    let p = lines
        .iter()
        .find(|l| l["type"] == "product" && l["data"]["style_number"] == "MN-1001")
        .expect("MN-1001 in the manifest");
    assert_eq!(
        p["data"]["materials"][0]["fibers"][0]["material"]["name"],
        json!({"de": "Merinowolle"})
    );
    let name_tag = p["data"]["language_fallbacks"]["/name"]
        .as_str()
        .expect("the name has no German text");
    assert_eq!(
        p["data"]["name"]
            .as_object()
            .unwrap()
            .keys()
            .collect::<Vec<_>>(),
        [name_tag]
    );
    for l in lines
        .iter()
        .filter(|l| l["type"] != "header" && l["type"] != "file")
    {
        assert!(l["data"]["language_fallbacks"].is_object(), "{l}");
        assert!(
            crate::schemas::validate("ExportManifestLine", l).is_empty(),
            "{l}"
        );
    }
}
