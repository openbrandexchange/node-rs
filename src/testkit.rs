//! A node for HTTP tests: a fresh data folder, the real router on a random
//! port, the job workers, an admin account with a session, retailers with
//! API keys and an upload key. node-go's `harness_test.go`, in Rust.

use std::net::SocketAddr;

use serde_json::{Map, Value, json};

use crate::app::App;
use crate::model::KIND_BRAND;

pub struct Node {
    pub app: App,
    pub base: String,
    pub http: reqwest::Client,
    dir: std::path::PathBuf,
}

impl Drop for Node {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

pub const ADMIN_EMAIL: &str = "admin@maison-noor.example";
pub const ADMIN_PASSWORD: &str = "noor-admin-2026!";

/// A logged-in browser session (cookies and the CSRF token).
pub struct Session {
    pub base: String,
    http: reqwest::Client,
    cookie: String,
    csrf: String,
}

impl Session {
    pub fn req(&self, m: reqwest::Method, path: &str) -> reqwest::RequestBuilder {
        self.http
            .request(m, format!("{}{path}", self.base))
            .header("cookie", &self.cookie)
            .header("x-csrf-token", &self.csrf)
    }

    /// The JSON answer of a call that must have the given status.
    pub async fn must(
        &self,
        status: u16,
        m: reqwest::Method,
        path: &str,
        body: Option<Value>,
    ) -> Value {
        let mut r = self.req(m.clone(), path);
        if let Some(b) = body {
            r = r.json(&b);
        }
        let resp = r.send().await.unwrap();
        let got = resp.status().as_u16();
        let text = resp.text().await.unwrap_or_default();
        assert_eq!(got, status, "{m} {path}: {text}");
        serde_json::from_str(&text).unwrap_or(Value::Null)
    }
}

impl Node {
    /// A node that is set up (brand `maison-noor`, admin account), serving
    /// on 127.0.0.1 with job workers running.
    pub async fn start() -> Node {
        let dir = std::env::temp_dir().join(format!("obx-rs-test-{}", crate::ids::new("t")));
        std::fs::create_dir_all(&dir).unwrap();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let base = format!("http://{addr}");
        let mut cfg = crate::config::Config::for_test(&dir);
        cfg.public_url = base.clone();
        cfg.port = addr.port();
        let app = App::new(cfg).await.unwrap();
        let hash = crate::secure::hash_password(ADMIN_PASSWORD);
        app.catalog_write(None, move |w| {
            crate::db::set_meta(w.tx, "setup_done", "1")?;
            let mut s = crate::settings::Settings::load(w.tx)?;
            s.company.name = "MAISON NOOR Group".into();
            s.branding.display_name = "MAISON NOOR".into();
            s.portal.languages = vec!["nl".into(), "en".into()];
            s.portal.default_language = "nl".into();
            s.save(w.tx)?;
            w.settings = s;
            w.tx.execute(
                "INSERT INTO users (id, email, name, role, status, language, password_hash, created_at) VALUES (?, ?, 'Iris Admin', 'admin', 'active', 'en', ?, ?)",
                rusqlite::params![crate::ids::new("usr"), ADMIN_EMAIL, hash, crate::db::now_str()],
            )?;
            let mut doc = Map::new();
            doc.insert("name".into(), json!("MAISON NOOR"));
            doc.insert("status".into(), json!("published"));
            let (_, p) = w.upsert(KIND_BRAND, "maison-noor", doc, "");
            p.map_or(Ok(()), Err)
        })
        .await
        .unwrap();
        let router = crate::http::router::router(app.clone())
            .into_make_service_with_connect_info::<SocketAddr>();
        tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
        crate::jobs::start_workers(app.clone());
        Node {
            app,
            base,
            http: reqwest::Client::new(),
            dir,
        }
    }

    /// Imports the MAISON NOOR fixtures (11 products, 46 variants, 35 images).
    pub async fn import_fixtures(&self) {
        let fx = std::path::PathBuf::from(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/crates/obx-conformance/fixtures/maison-noor"
        ));
        let run = crate::imports::run_import_cli(
            &self.app,
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
    }

    /// Logs in through the Admin API.
    pub async fn login(&self, email: &str, password: &str) -> Session {
        let r = self
            .http
            .post(format!("{}/admin/api/session/login", self.base))
            .header("x-csrf-token", "t")
            .header("cookie", "obx_csrf=t")
            .json(&json!({"email": email, "password": password}))
            .send()
            .await
            .unwrap();
        assert_eq!(r.status(), 200, "login: {:?}", r.text().await);
        let mut cookies = Vec::new();
        let mut csrf = String::new();
        for v in r.headers().get_all("set-cookie") {
            let c = v.to_str().unwrap().split(';').next().unwrap().to_string();
            if let Some(t) = c.strip_prefix("obx_csrf=") {
                csrf = t.to_string();
            }
            cookies.push(c);
        }
        let body: Value = r.json().await.unwrap();
        if csrf.is_empty() {
            csrf = body["csrf_token"].as_str().unwrap_or("").to_string();
        }
        Session {
            base: self.base.clone(),
            http: self.http.clone(),
            cookie: cookies.join("; "),
            csrf,
        }
    }

    pub async fn admin(&self) -> Session {
        self.login(ADMIN_EMAIL, ADMIN_PASSWORD).await
    }

    /// A retailer with an API key; (retailer id, client id, secret).
    pub async fn api_client(
        &self,
        name: &str,
        retailer: Map<String, Value>,
    ) -> (String, String, String) {
        let name = name.to_string();
        self.app
            .db
            .write(move |tx| {
                let mut d = retailer;
                d.insert("name".into(), json!(name));
                let r = crate::http::admin::create_retailer(tx, &d)?;
                let (c, s) =
                    crate::http::admin::create_api_client(tx, &r.id, "key", None, "admin")?;
                Ok((r.id, c.client_id, s))
            })
            .await
            .unwrap()
    }

    /// An upload key with every ingest scope.
    pub async fn ingest_token(&self) -> String {
        self.app
            .db
            .write(|tx| {
                let (_, s) = crate::http::admin::create_ingest_token(
                    tx,
                    "test",
                    vec![
                        "ingest:read".into(),
                        "ingest:write".into(),
                        "ingest:delete".into(),
                    ],
                    None,
                    None,
                )?;
                Ok(s)
            })
            .await
            .unwrap()
    }
}
