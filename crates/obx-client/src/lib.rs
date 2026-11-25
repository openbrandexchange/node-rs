//! A client for the Open Brand Exchange protocol API, for retailer software
//! that reads a brand's catalog.
//!
//! It requests and renews access tokens itself (OAuth2 client credentials),
//! retries once with a fresh token after `invalid_token`, honours
//! `Retry-After` on `rate_limited` (up to a limit), and turns every error
//! answer into the server's [`Problem`].
//!
//! ```no_run
//! # async fn run() -> Result<(), obx_client::Error> {
//! use obx_client::Client;
//!
//! let c = Client::new("https://brand.example", "obxc_…", "obxs_…")?;
//! let mut cursor = None;
//! loop {
//!     let page = c.changes(cursor.as_deref(), 500).await?;
//!     for ch in &page.changes {
//!         println!("{} {} {}", ch["type"], ch["op"], ch["id"]);
//!     }
//!     cursor = Some(page.next_cursor);
//!     if !page.has_more { break; }
//! }
//! # Ok(()) }
//! ```
#![forbid(unsafe_code)]

use std::time::{Duration, Instant};

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tokio::sync::Mutex;

pub use obx_types::Problem;

/// Errors of a call.
#[derive(Debug)]
pub enum Error {
    /// The server answered with a problem document (or an OAuth2 error,
    /// mapped to `invalid_client` / `invalid_scope` / ...).
    Problem(Box<ProblemDoc>),
    /// Network, TLS or a body that is not what the spec says.
    Transport(String),
}

/// A problem document as received.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ProblemDoc {
    #[serde(default)]
    pub status: u16,
    #[serde(default)]
    pub obx_error: String,
    #[serde(default)]
    pub title: String,
    #[serde(default)]
    pub detail: Option<String>,
    #[serde(default)]
    pub errors: Vec<Value>,
}

impl Error {
    /// The OBX error code of a problem answer.
    pub fn code(&self) -> Option<&str> {
        match self {
            Error::Problem(p) => Some(&p.obx_error),
            Error::Transport(_) => None,
        }
    }
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Problem(p) => write!(
                f,
                "{} ({}): {}",
                p.obx_error,
                p.status,
                p.detail.as_deref().unwrap_or(&p.title)
            ),
            Error::Transport(e) => write!(f, "transport: {e}"),
        }
    }
}

impl std::error::Error for Error {}

impl From<reqwest::Error> for Error {
    fn from(e: reqwest::Error) -> Error {
        Error::Transport(e.to_string())
    }
}

impl From<url::ParseError> for Error {
    fn from(e: url::ParseError) -> Error {
        Error::Transport(e.to_string())
    }
}

pub type Result<T> = std::result::Result<T, Error>;

/// A page of a keyset-paginated list.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Page<T> {
    pub items: Vec<T>,
    #[serde(default)]
    pub next_cursor: Option<String>,
}

/// A page of the change feed.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ChangesPage {
    pub changes: Vec<Value>,
    pub next_cursor: String,
    pub has_more: bool,
    pub phase: String,
}

/// One result of a GTIN lookup.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct GtinResult {
    pub input: String,
    pub gtin: Option<String>,
    /// `matched`, `unmatched` or `invalid`.
    pub status: String,
    pub product_id: Option<String>,
    pub variant_id: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct GtinLookup {
    pub results: Vec<GtinResult>,
    pub products: Vec<Value>,
}

#[derive(Deserialize)]
struct TokenResponse {
    access_token: String,
    expires_in: u64,
}

/// Products filter of [`Client::products`].
#[derive(Debug, Clone, Default)]
pub struct ProductQuery {
    pub brand_id: Option<String>,
    pub updated_since: Option<String>,
    pub ids: Vec<String>,
    pub cursor: Option<String>,
    pub limit: Option<u32>,
}

/// A client of one node, with one API key.
pub struct Client {
    http: reqwest::Client,
    base: url::Url,
    client_id: String,
    secret: String,
    scope: Option<String>,
    token: Mutex<Option<(String, Instant)>>,
    max_wait: Duration,
}

impl Client {
    /// `base` is the node's URL (where `/.well-known/obx` lives).
    pub fn new(base: &str, client_id: &str, client_secret: &str) -> Result<Client> {
        let http = reqwest::Client::builder()
            .user_agent(concat!("obx-client/", env!("CARGO_PKG_VERSION")))
            .timeout(Duration::from_secs(120))
            .build()?;
        Client::with_http(http, base, client_id, client_secret)
    }

    /// With an own reqwest client (proxies, timeouts, TLS roots).
    pub fn with_http(
        http: reqwest::Client,
        base: &str,
        client_id: &str,
        client_secret: &str,
    ) -> Result<Client> {
        let mut base = url::Url::parse(base)?;
        if !base.path().ends_with('/') {
            let p = format!("{}/", base.path());
            base.set_path(&p);
        }
        Ok(Client {
            http,
            base,
            client_id: client_id.into(),
            secret: client_secret.into(),
            scope: None,
            token: Mutex::new(None),
            max_wait: Duration::from_secs(60),
        })
    }

    /// Requests only these scopes (space separated) instead of all granted.
    pub fn with_scope(mut self, scope: &str) -> Client {
        self.scope = Some(scope.into());
        self
    }

    /// The longest `Retry-After` the client waits out by itself (default 60 s);
    /// a longer one is returned as `rate_limited`.
    pub fn with_max_wait(mut self, d: Duration) -> Client {
        self.max_wait = d;
        self
    }

    fn url(&self, path: &str) -> Result<url::Url> {
        Ok(self.base.join(path.trim_start_matches('/'))?)
    }

    async fn problem(resp: reqwest::Response) -> Error {
        let status = resp.status().as_u16();
        let text = resp.text().await.unwrap_or_default();
        let v: Value = serde_json::from_str(&text).unwrap_or(Value::Null);
        if let Some(code) = v.get("error").and_then(|e| e.as_str()) {
            return Error::Problem(Box::new(ProblemDoc {
                status,
                obx_error: code.into(),
                title: code.into(),
                detail: v
                    .get("error_description")
                    .and_then(|d| d.as_str())
                    .map(String::from),
                errors: vec![],
            }));
        }
        match serde_json::from_value::<ProblemDoc>(v) {
            Ok(mut p) if !p.obx_error.is_empty() => {
                p.status = status;
                Error::Problem(Box::new(p))
            }
            _ => Error::Transport(format!(
                "HTTP {status}: {}",
                text.chars().take(200).collect::<String>()
            )),
        }
    }

    /// A fresh access token (`POST /obx/v1/oauth/token`).
    pub async fn token(&self) -> Result<String> {
        let mut t = self.token.lock().await;
        if let Some((tok, until)) = t.as_ref() {
            if Instant::now() < *until {
                return Ok(tok.clone());
            }
        }
        let mut form = vec![("grant_type", "client_credentials")];
        if let Some(s) = &self.scope {
            form.push(("scope", s));
        }
        let resp = self
            .http
            .post(self.url("/obx/v1/oauth/token")?)
            .basic_auth(
                form_encode(&self.client_id),
                Some(form_encode(&self.secret)),
            )
            .form(&form)
            .send()
            .await?;
        if !resp.status().is_success() {
            return Err(Client::problem(resp).await);
        }
        let tr: TokenResponse = resp.json().await?;
        let ttl = Duration::from_secs(tr.expires_in.saturating_sub(60).max(1));
        *t = Some((tr.access_token.clone(), Instant::now() + ttl));
        Ok(tr.access_token)
    }

    async fn send(
        &self,
        rb: impl Fn(&str) -> reqwest::RequestBuilder,
    ) -> Result<reqwest::Response> {
        let mut retried_token = false;
        let mut waited = Duration::ZERO;
        loop {
            let tok = self.token().await?;
            let resp = rb(&tok).send().await?;
            if resp.status().is_success() || resp.status().as_u16() == 304 {
                return Ok(resp);
            }
            if resp.status().as_u16() == 429 {
                let secs = resp
                    .headers()
                    .get("retry-after")
                    .and_then(|v| v.to_str().ok())
                    .and_then(|v| v.parse::<u64>().ok())
                    .unwrap_or(1);
                let d = Duration::from_secs(secs);
                if waited + d <= self.max_wait {
                    waited += d;
                    tokio::time::sleep(d).await;
                    continue;
                }
            }
            let err = Client::problem(resp).await;
            if err.code() == Some("invalid_token") && !retried_token {
                retried_token = true;
                *self.token.lock().await = None;
                continue;
            }
            return Err(err);
        }
    }

    /// GET a protocol path and decode the JSON answer.
    pub async fn get_json<T: DeserializeOwned>(
        &self,
        path: &str,
        query: &[(&str, String)],
    ) -> Result<T> {
        let u = self.url(path)?;
        let resp = self
            .send(|tok| self.http.get(u.clone()).bearer_auth(tok).query(query))
            .await?;
        Ok(resp.json().await?)
    }

    /// The discovery document (no token needed).
    pub async fn discovery(&self) -> Result<Value> {
        let resp = self.http.get(self.url("/.well-known/obx")?).send().await?;
        if !resp.status().is_success() {
            return Err(Client::problem(resp).await);
        }
        Ok(resp.json().await?)
    }

    /// What this API key may see (`GET /obx/v1/grant`).
    pub async fn grant(&self) -> Result<Value> {
        self.get_json("/obx/v1/grant", &[]).await
    }

    pub async fn brands(&self) -> Result<Vec<Value>> {
        Ok(self
            .get_json::<Page<Value>>("/obx/v1/brands", &[])
            .await?
            .items)
    }

    pub async fn brand(&self, id: &str) -> Result<Value> {
        self.get_json(&format!("/obx/v1/brands/{}", seg(id)), &[])
            .await
    }

    /// One page of products (ProductDetail with variants and assets).
    pub async fn products(&self, q: &ProductQuery) -> Result<Page<Value>> {
        let mut query: Vec<(&str, String)> = Vec::new();
        if let Some(b) = &q.brand_id {
            query.push(("brand_id", b.clone()));
        }
        if let Some(u) = &q.updated_since {
            query.push(("updated_since", u.clone()));
        }
        if !q.ids.is_empty() {
            query.push(("ids", q.ids.join(",")));
        }
        if let Some(c) = &q.cursor {
            query.push(("cursor", c.clone()));
        }
        if let Some(l) = q.limit {
            query.push(("limit", l.to_string()));
        }
        self.get_json("/obx/v1/products", &query).await
    }

    pub async fn product(&self, id: &str) -> Result<Value> {
        self.get_json(&format!("/obx/v1/products/{}", seg(id)), &[])
            .await
    }

    /// Up to 2000 GTINs (POST `/obx/v1/products:by-gtin`).
    pub async fn by_gtin(&self, gtins: &[String]) -> Result<GtinLookup> {
        let u = self.url("/obx/v1/products:by-gtin")?;
        let body = serde_json::json!({ "gtins": gtins });
        let resp = self
            .send(|tok| self.http.post(u.clone()).bearer_auth(tok).json(&body))
            .await?;
        Ok(resp.json().await?)
    }

    /// One page of the change feed (`None` starts the snapshot).
    pub async fn changes(&self, cursor: Option<&str>, limit: u32) -> Result<ChangesPage> {
        let mut q = vec![("limit", limit.to_string())];
        if let Some(c) = cursor {
            q.push(("cursor", c.to_string()));
        }
        self.get_json("/obx/v1/changes", &q).await
    }

    pub async fn asset(&self, id: &str) -> Result<Value> {
        self.get_json(&format!("/obx/v1/assets/{}", seg(id)), &[])
            .await
    }

    /// The bytes of a rendition (`original`, `web`, `square`, `thumb`).
    pub async fn rendition(&self, asset_id: &str, name: &str) -> Result<bytes::Bytes> {
        let u = self.url(&format!(
            "/obx/v1/assets/{}/renditions/{}",
            seg(asset_id),
            seg(name)
        ))?;
        let resp = self
            .send(|tok| self.http.get(u.clone()).bearer_auth(tok))
            .await?;
        Ok(resp.bytes().await?)
    }

    /// Asks a brand for access (no API key needed); the AccessRequest.
    pub async fn request_access(
        http: &reqwest::Client,
        base: &str,
        input: &Value,
    ) -> Result<Value> {
        let u = url::Url::parse(base)?.join("obx/v1/access-requests")?;
        let resp = http.post(u).json(input).send().await?;
        if !resp.status().is_success() {
            return Err(Client::problem(resp).await);
        }
        Ok(resp.json().await?)
    }

    /// Polls an access request with the token it returned; the credentials
    /// appear once, after approval.
    pub async fn access_request(
        http: &reqwest::Client,
        base: &str,
        id: &str,
        poll_token: &str,
    ) -> Result<Value> {
        let u = url::Url::parse(base)?.join(&format!("obx/v1/access-requests/{}", seg(id)))?;
        let resp = http.get(u).bearer_auth(poll_token).send().await?;
        if !resp.status().is_success() {
            return Err(Client::problem(resp).await);
        }
        Ok(resp.json().await?)
    }
}

/// One path segment, percent-encoded.
fn seg(s: &str) -> String {
    url::form_urlencoded::byte_serialize(s.as_bytes())
        .collect::<String>()
        .replace('+', "%20")
}

/// RFC 6749 §2.3.1: client credentials are form-encoded inside Basic.
fn form_encode(s: &str) -> String {
    url::form_urlencoded::byte_serialize(s.as_bytes()).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn segments() {
        assert_eq!(seg("prd_1"), "prd_1");
        assert_eq!(seg("a b/c"), "a%20b%2Fc");
        let c = Client::new("https://n.example/base", "a", "b").unwrap();
        assert_eq!(
            c.url("/obx/v1/products").unwrap().as_str(),
            "https://n.example/base/obx/v1/products"
        );
    }
}
