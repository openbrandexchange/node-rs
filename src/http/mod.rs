//! HTTP: shared helpers, the viewer (who is asking) and the router.

pub mod access;
pub mod admin;
pub mod feed;
pub mod ingest;
pub mod people;
pub mod portal;
pub mod portal_downloads;
pub mod protocol;
pub mod router;
pub mod ui;

use axum::http::HeaderMap;
use axum::response::Response;
use rusqlite::{Connection, OptionalExtension};
use serde::Serialize;
use serde_json::Value;

use crate::app::App;
use crate::catalog::grant_id_for;
use crate::problem::{Problem, Result};
use crate::settings::Settings;

#[allow(unused_imports)]
pub use obx_axum::{
    MAX_JSON_BODY, bearer, content_disposition, json, limit_param, ok, read_json, read_json_object,
    with_headers,
};

pub type Res = std::result::Result<Response, Problem>;

pub fn client_ip(app: &App, headers: &HeaderMap, peer: Option<std::net::SocketAddr>) -> String {
    if app.cfg.trust_proxy {
        if let Some(x) = headers.get("x-forwarded-for").and_then(|v| v.to_str().ok()) {
            return x.split(',').next().unwrap_or("").trim().to_string();
        }
    }
    peer.map(|p| p.ip().to_string()).unwrap_or_default()
}

/// 429 with Retry-After, or the RateLimit headers to add.
pub fn rate_limit(
    app: &App,
    key: &str,
    per_minute: u32,
) -> std::result::Result<[(String, String); 3], Problem> {
    match app.limit(key, per_minute, 60) {
        Ok((limit, remaining, reset)) => Ok([
            ("RateLimit-Limit".into(), limit.to_string()),
            ("RateLimit-Remaining".into(), remaining.to_string()),
            ("RateLimit-Reset".into(), reset.to_string()),
        ]),
        Err(retry) => {
            let mut p = Problem::new("rate_limited", "Too many requests; slow down.");
            p.retry_after = Some(retry as u64);
            Err(p)
        }
    }
}

// ---- viewers -------------------------------------------------------------------

/// Who reads the catalog: an API client, a retailer user or an admin.
#[derive(Debug, Clone, Default)]
pub struct Viewer {
    pub kind: String,
    pub retailer_id: String,
    pub retailer_name: String,
    /// None = all published brands.
    pub brand_ids: Option<Vec<String>>,
    pub original_allowed: bool,
    pub scopes: Vec<String>,
    pub client_row_id: String,
    pub client_name: String,
    pub user_id: String,
    pub user_name: String,
    /// The interface language of a signed-in user.
    pub language: String,
}

impl Viewer {
    pub fn admin() -> Viewer {
        Viewer {
            kind: "admin".into(),
            original_allowed: true,
            ..Default::default()
        }
    }

    /// A brand administrator looking at the portal (never counted in statistics).
    pub fn preview(&self) -> bool {
        self.kind == "admin"
    }

    pub fn tag(&self) -> String {
        match self.kind.as_str() {
            "client" => format!("c.{}", self.client_row_id),
            "user" => format!("u.{}", self.user_id),
            _ => "a".into(),
        }
    }

    pub fn sees_brand(&self, brand_id: &str) -> bool {
        self.brand_ids
            .as_ref()
            .is_none_or(|b| b.iter().any(|x| x == brand_id))
    }

    pub fn has_scope(&self, s: &str) -> bool {
        self.scopes.iter().any(|x| x == s)
    }

    /// ` AND col IN (...)` and its arguments.
    pub fn brand_filter(&self, col: &str) -> (String, Vec<String>) {
        match &self.brand_ids {
            None => (String::new(), vec![]),
            Some(b) if b.is_empty() => (" AND 1 = 0".into(), vec![]),
            Some(b) => (
                format!(" AND {col} IN {}", crate::db::in_list(b.len())),
                b.clone(),
            ),
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct RetailerRow {
    pub id: String,
    pub name: String,
    pub status: String,
    pub grant_updated_at: String,
    pub created_at: String,
    pub updated_at: String,
    pub reference: Option<String>,
    pub website: Option<String>,
    pub vat_number: Option<String>,
    pub country: Option<String>,
    pub notes: Option<String>,
    pub last_activity_at: Option<String>,
    pub brand_ids: Option<Vec<String>>,
    pub allow_original: Option<bool>,
}

pub fn load_retailer(c: &Connection, id: &str) -> Result<Option<RetailerRow>> {
    Ok(c.query_row(
        "SELECT id, name, status, grant_updated_at, created_at, updated_at, reference, website, vat_number, country, notes, last_activity_at, brand_ids, allow_original FROM retailers WHERE id = ?",
        [id],
        |r| {
            let b: Option<String> = r.get(12)?;
            Ok(RetailerRow {
                id: r.get(0)?,
                name: r.get(1)?,
                status: r.get(2)?,
                grant_updated_at: r.get(3)?,
                created_at: r.get(4)?,
                updated_at: r.get(5)?,
                reference: r.get(6)?,
                website: r.get(7)?,
                vat_number: r.get(8)?,
                country: r.get(9)?,
                notes: r.get(10)?,
                last_activity_at: r.get(11)?,
                brand_ids: b.map(|s| serde_json::from_str(&s).unwrap_or_default()),
                allow_original: r.get::<_, Option<i64>>(13)?.map(|v| v == 1),
            })
        },
    )
    .optional()?)
}

pub fn original_allowed(s: &Settings, r: &RetailerRow) -> bool {
    s.portal.allow_original_download && r.allow_original.unwrap_or(true)
}

pub fn grant_of(s: &Settings, r: &RetailerRow) -> Value {
    let orig = original_allowed(s, r);
    let mut scopes = vec!["catalog:read", "media:read"];
    if orig {
        scopes.push("media:original");
    }
    scopes.push("usage:write");
    serde_json::json!({
        "id": grant_id_for(&r.id),
        "retailer": {"id": r.id, "name": r.name},
        "brand_ids": r.brand_ids,
        "scopes": scopes,
        "original_allowed": orig,
        "status": if r.status == "active" { "active" } else { "revoked" },
        "updated_at": r.grant_updated_at,
    })
}

pub fn grant_scopes(s: &Settings, r: &RetailerRow) -> Vec<String> {
    grant_of(s, r)["scopes"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap().to_string())
        .collect()
}
