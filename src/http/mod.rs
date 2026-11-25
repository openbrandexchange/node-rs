//! HTTP: shared helpers, the viewer (who is asking) and the router.

pub mod access;
pub mod admin;
pub mod feed;
pub mod ingest;
pub mod protocol;
pub mod router;
pub mod ui;

use std::collections::HashMap;

use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use rusqlite::{Connection, OptionalExtension};
use serde::Serialize;
use serde_json::Value;

use crate::app::App;
use crate::catalog::grant_id_for;
use crate::problem::{Problem, Result};
use crate::settings::Settings;

pub const MAX_JSON_BODY: usize = 4 << 20;

/// A JSON response with `Cache-Control: no-store`.
pub fn json<T: Serialize>(status: u16, v: &T) -> Response {
    let body = serde_json::to_vec(v).unwrap_or_default();
    let mut r = (StatusCode::from_u16(status).unwrap_or(StatusCode::OK), body).into_response();
    r.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    r.headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    r
}

pub fn ok<T: Serialize>(v: &T) -> Response {
    json(200, v)
}

pub type Res = std::result::Result<Response, Problem>;

/// Parses a JSON body (application/json, merge-patch or any +json).
pub fn read_json(headers: &HeaderMap, body: &[u8], limit: usize) -> Result<Value> {
    if let Some(ct) = headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
    {
        let mt = ct
            .split(';')
            .next()
            .unwrap_or("")
            .trim()
            .to_ascii_lowercase();
        if !mt.is_empty()
            && mt != "application/json"
            && mt != "application/merge-patch+json"
            && !mt.ends_with("+json")
        {
            return Err(Problem::new(
                "unsupported_media_type",
                "Send application/json.",
            ));
        }
    }
    if body.len() > limit {
        return Err(Problem::new(
            "payload_too_large",
            "The request body is too large.",
        ));
    }
    if body.iter().all(|b| b.is_ascii_whitespace()) {
        return Err(Problem::new("invalid_request", "A JSON body is required."));
    }
    serde_json::from_slice(body).map_err(|e| {
        Problem::new(
            "invalid_request",
            format!("The body is not valid JSON: {e}"),
        )
    })
}

pub fn read_json_object(
    headers: &HeaderMap,
    body: &[u8],
) -> Result<serde_json::Map<String, Value>> {
    match read_json(headers, body, MAX_JSON_BODY)? {
        Value::Object(m) => Ok(m),
        _ => Err(Problem::new(
            "invalid_request",
            "The body must be a JSON object.",
        )),
    }
}

/// The `limit` query parameter: default, clamped to max; not an integer or
/// below 1 is invalid_request.
pub fn limit_param(q: &HashMap<String, String>, def: usize, max: usize) -> Result<usize> {
    let Some(s) = q.get("limit") else {
        return Ok(def);
    };
    if !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit()) {
        let n: u128 = s.parse().unwrap_or(u128::MAX);
        if n >= 1 {
            return Ok((n.min(max as u128)) as usize);
        }
    }
    Err(Problem::new(
        "invalid_request",
        format!("limit must be an integer of at least 1 (at most {max} is used)."),
    )
    .field("", "invalid_request", "limit"))
}

pub fn bearer(h: &HeaderMap) -> Option<String> {
    let v = h.get(header::AUTHORIZATION)?.to_str().ok()?;
    if v.len() > 7 && v[..7].eq_ignore_ascii_case("bearer ") {
        Some(v[7..].trim().to_string())
    } else {
        None
    }
}

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

pub fn with_headers(mut r: Response, hs: &[(String, String)]) -> Response {
    for (k, v) in hs {
        if let (Ok(k), Ok(v)) = (
            axum::http::HeaderName::try_from(k.as_str()),
            HeaderValue::from_str(v),
        ) {
            r.headers_mut().insert(k, v);
        }
    }
    r
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
    pub user_id: String,
}

impl Viewer {
    pub fn admin() -> Viewer {
        Viewer {
            kind: "admin".into(),
            original_allowed: true,
            ..Default::default()
        }
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

/// `inline; filename="…"` (RFC 6266 with a UTF-8 variant when needed).
pub fn content_disposition(kind: &str, name: &str) -> String {
    let mut s: String = name
        .replace('\\', "/")
        .rsplit('/')
        .next()
        .unwrap_or("")
        .chars()
        .map(|c| {
            if (c as u32) < 0x20 || c == '\x7f' || "\":*?<>|".contains(c) {
                '_'
            } else {
                c
            }
        })
        .collect();
    s = s.trim().trim_start_matches('.').to_string();
    if s.is_empty() {
        s = "file".into();
    }
    if s.is_ascii() {
        return format!("{kind}; filename=\"{s}\"");
    }
    let fallback: String = s
        .chars()
        .map(|c| if c.is_ascii() { c } else { '_' })
        .collect();
    let enc: String = s
        .bytes()
        .map(|b| {
            if b.is_ascii_alphanumeric() || b"-._~".contains(&b) {
                (b as char).to_string()
            } else {
                format!("%{b:02X}")
            }
        })
        .collect();
    format!("{kind}; filename=\"{fallback}\"; filename*=UTF-8''{enc}")
}
