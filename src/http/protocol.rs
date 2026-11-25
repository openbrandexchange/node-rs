//! The OBX Protocol (protocol.md): discovery, OAuth2 client credentials,
//! grant, brands, products, GTIN lookup, assets and renditions.

use std::collections::{BTreeMap, HashMap};
use std::net::SocketAddr;

use axum::body::{Body, Bytes};
use axum::extract::{ConnectInfo, Path, Query, State};
use axum::http::{HeaderMap, HeaderValue, Method, StatusCode, header};
use axum::response::{IntoResponse, Response};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use rusqlite::{Connection, OptionalExtension, params};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use super::*;
use crate::app::{OBX_VERSION, SOFTWARE, SPEC_VERSION, VERSION};
use crate::catalog::{expired, normalize_gtin};
use crate::model::*;
use crate::store::blob_key;

pub const ALL_SCOPES: [&str; 4] = [
    "catalog:read",
    "media:read",
    "media:original",
    "usage:write",
];
const ACCESS_TOKEN_TTL: i64 = 3600;

#[derive(Serialize, Deserialize)]
struct Claims {
    c: String,
    v: i64,
    s: String,
    e: i64,
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct ApiClient {
    pub id: String,
    pub client_id: String,
    pub secret_hash: String,
    pub retailer_id: String,
    pub name: String,
    pub status: String,
    pub created_by: String,
    pub created_at: String,
    pub version: i64,
    pub scopes: Vec<String>,
    pub last_used_at: Option<String>,
}

pub fn load_client(c: &Connection, where_: &str, arg: &str) -> Result<Option<ApiClient>> {
    Ok(c.query_row(
        &format!("SELECT id, client_id, secret_hash, retailer_id, name, status, created_by, created_at, secret_version, scopes, last_used_at FROM api_clients WHERE {where_}"),
        [arg],
        |r| {
            Ok(ApiClient {
                id: r.get(0)?,
                client_id: r.get(1)?,
                secret_hash: r.get(2)?,
                retailer_id: r.get(3)?,
                name: r.get(4)?,
                status: r.get(5)?,
                created_by: r.get(6)?,
                created_at: r.get(7)?,
                version: r.get(8)?,
                scopes: r.get::<_, String>(9)?.split_whitespace().map(String::from).collect(),
                last_used_at: r.get(10)?,
            })
        },
    )
    .optional()?)
}

fn effective_scopes(s: &Settings, c: &ApiClient, r: &RetailerRow) -> Vec<String> {
    let allowed = grant_scopes(s, r);
    c.scopes
        .iter()
        .filter(|x| allowed.contains(x))
        .cloned()
        .collect()
}

fn oauth_error(status: u16, code: &str, desc: &str) -> Response {
    let mut r = json(status, &json!({"error": code, "error_description": desc}));
    if status == 401 {
        r.headers_mut().insert(
            header::WWW_AUTHENTICATE,
            HeaderValue::from_static("Basic realm=\"obx\""),
        );
    }
    r
}

fn issue_token(app: &App, client_row: &str, version: i64, scopes: &[String]) -> String {
    let payload = URL_SAFE_NO_PAD.encode(
        serde_json::to_vec(&Claims {
            c: client_row.into(),
            v: version,
            s: scopes.join(" "),
            e: chrono::Utc::now().timestamp() + ACCESS_TOKEN_TTL,
        })
        .unwrap(),
    );
    format!("obxa_{payload}.{}", app.keys.sign("access-token", &payload))
}

pub async fn token(
    State(app): State<App>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let ip = client_ip(&app, &headers, Some(peer));
    if let Err(p) = rate_limit(&app, &format!("token:{ip}"), 30) {
        return p.into_response();
    }
    let form: HashMap<String, String> = url::form_urlencoded::parse(&body).into_owned().collect();
    if form.get("grant_type").map(String::as_str) != Some("client_credentials") {
        return oauth_error(
            400,
            "unsupported_grant_type",
            "Only client_credentials is supported.",
        );
    }
    let (mut id, mut secret) = (String::new(), String::new());
    if let Some(v) = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
    {
        if v.len() > 6 && v[..6].eq_ignore_ascii_case("basic ") {
            if let Some(dec) = base64::engine::general_purpose::STANDARD
                .decode(v[6..].trim())
                .ok()
                .and_then(|b| String::from_utf8(b).ok())
            {
                if let Some((a, b)) = dec.split_once(':') {
                    let un = |s: &str| {
                        url::form_urlencoded::parse(format!("x={s}").as_bytes())
                            .next()
                            .map(|(_, v)| v.into_owned())
                            .unwrap_or_default()
                    };
                    id = un(&a.replace('+', "%2B"));
                    secret = un(&b.replace('+', "%2B"));
                }
            }
        }
    }
    if id.is_empty() {
        id = form.get("client_id").cloned().unwrap_or_default();
        secret = form.get("client_secret").cloned().unwrap_or_default();
    }
    if id.is_empty() || secret.is_empty() {
        return oauth_error(401, "invalid_client", "Client authentication failed.");
    }
    let scope = form.get("scope").cloned().unwrap_or_default();
    let a = app.clone();
    let out = app
        .db
        .read(move |c| {
            let Some(cl) = load_client(c, "client_id = ?", &id)? else {
                return Ok(Err((401, "invalid_client", String::new())));
            };
            if !crate::secure::eq(&cl.secret_hash, &crate::secure::hash_token(&secret))
                || cl.status != "active"
            {
                return Ok(Err((401, "invalid_client", String::new())));
            }
            let Some(ret) = load_retailer(c, &cl.retailer_id)?.filter(|r| r.status == "active")
            else {
                return Ok(Err((401, "invalid_client", String::new())));
            };
            let s = Settings::load(c)?;
            let eff = effective_scopes(&s, &cl, &ret);
            let mut scopes = eff.clone();
            if !scope.trim().is_empty() {
                scopes = Vec::new();
                for x in scope.split_whitespace() {
                    if !eff.iter().any(|e| e == x) {
                        return Ok(Err((
                            400,
                            "invalid_scope",
                            format!("Scope {x} is not available to this client."),
                        )));
                    }
                    scopes.push(x.to_string());
                }
            }
            scopes.sort();
            Ok(Ok((cl, scopes)))
        })
        .await;
    match out {
        Err(p) => p.into_response(),
        Ok(Err((st, code, desc))) => oauth_error(
            st,
            code,
            if desc.is_empty() {
                "Client authentication failed."
            } else {
                &desc
            },
        ),
        Ok(Ok((cl, scopes))) => {
            let id = cl.id.clone();
            let _ =
                a.db.write(move |tx| {
                    tx.execute(
                        "UPDATE api_clients SET last_used_at = ? WHERE id = ?",
                        params![crate::db::now_str(), id],
                    )?;
                    Ok(())
                })
                .await;
            ok(&json!({
                "access_token": issue_token(&a, &cl.id, cl.version, &scopes),
                "token_type": "Bearer",
                "expires_in": ACCESS_TOKEN_TTL,
                "scope": scopes.join(" "),
            }))
        }
    }
}

fn viewer_for_client(
    c: &Connection,
    cl: Option<ApiClient>,
    token_scopes: &[String],
) -> Result<Viewer> {
    let Some(cl) = cl.filter(|c| c.status == "active") else {
        return Err(Problem::new("access_revoked", "This API key was revoked."));
    };
    let Some(ret) = load_retailer(c, &cl.retailer_id)?.filter(|r| r.status == "active") else {
        return Err(Problem::new(
            "access_revoked",
            "Access for this retailer was revoked.",
        ));
    };
    let s = Settings::load(c)?;
    let eff = effective_scopes(&s, &cl, &ret);
    let scopes: Vec<String> = token_scopes
        .iter()
        .filter(|t| eff.contains(t))
        .cloned()
        .collect();
    Ok(Viewer {
        kind: "client".into(),
        retailer_id: ret.id.clone(),
        retailer_name: ret.name.clone(),
        brand_ids: ret.brand_ids.clone(),
        original_allowed: scopes.iter().any(|s| s == "media:original")
            && original_allowed(&s, &ret),
        scopes,
        client_row_id: cl.id,
        user_id: String::new(),
    })
}

pub fn viewer_from_token(app: &App, c: &Connection, tok: &str) -> Result<Viewer> {
    let invalid = || Problem::new("invalid_token", "The access token is invalid or expired.");
    let body = tok.strip_prefix("obxa_").ok_or_else(invalid)?;
    let (payload, sig) = body.rsplit_once('.').ok_or_else(invalid)?;
    if payload.is_empty() || !app.keys.verify("access-token", payload, sig) {
        return Err(invalid());
    }
    let cl: Claims = URL_SAFE_NO_PAD
        .decode(payload)
        .ok()
        .and_then(|b| serde_json::from_slice(&b).ok())
        .ok_or_else(invalid)?;
    if cl.e < chrono::Utc::now().timestamp() {
        return Err(invalid());
    }
    let client = load_client(c, "id = ?", &cl.c)?;
    let Some(client) = client.filter(|x| x.status == "active") else {
        return Err(Problem::new("access_revoked", "This API key was revoked."));
    };
    if client.version != cl.v {
        return Err(Problem::new(
            "invalid_token",
            "The access token was issued before the client secret was rotated; request a new token.",
        ));
    }
    let scopes: Vec<String> = cl.s.split_whitespace().map(String::from).collect();
    viewer_for_client(c, Some(client), &scopes)
}

/// A viewer from a signed-URL tag: `a` (admin), `c.<client>` or `u.<user>`.
pub fn viewer_from_tag(c: &Connection, tag: &str) -> Result<Viewer> {
    if tag == "a" {
        return Ok(Viewer::admin());
    }
    if let Some(id) = tag.strip_prefix("c.") {
        let cl = load_client(c, "id = ?", id)?;
        let scopes = cl.as_ref().map(|c| c.scopes.clone()).unwrap_or_default();
        return viewer_for_client(c, cl, &scopes);
    }
    if let Some(id) = tag.strip_prefix("u.") {
        return super::admin::viewer_for_user_id(c, id);
    }
    Err(Problem::new("unauthorized", "Invalid link."))
}

/// Authenticates a protocol call and applies the per-client rate limit.
pub async fn protocol_auth(
    app: &App,
    headers: &HeaderMap,
    scope: &str,
    renditions: bool,
) -> Result<(Viewer, [(String, String); 3])> {
    let Some(tok) = bearer(headers) else {
        return Err(Problem::new(
            "unauthorized",
            "Send an access token: Authorization: Bearer <token>.",
        ));
    };
    let a = app.clone();
    let v = app.db.read(move |c| viewer_from_token(&a, c, &tok)).await?;
    let hs = rate_limit(
        app,
        &format!("api:{}", v.client_row_id),
        if renditions { 3000 } else { 600 },
    )?;
    if !scope.is_empty() && !v.has_scope(scope) {
        return Err(Problem::new(
            "insufficient_scope",
            format!("This call needs the {scope} scope."),
        ));
    }
    Ok((v, hs))
}

// ---- rendering --------------------------------------------------------------------

pub fn render_plain(rep: &str, updated_at: &str) -> Value {
    let mut v: Value = serde_json::from_str(rep).unwrap_or(json!({}));
    if let Some(m) = v.as_object_mut() {
        m.insert("updated_at".into(), Value::String(updated_at.into()));
    }
    v
}

/// An asset for viewer v: fresh signed URLs, no original unless allowed.
pub fn render_asset(app: &App, rep: &str, updated_at: &str, v: &Viewer) -> Value {
    let mut a = render_plain(rep, updated_at);
    let id = a["id"].as_str().unwrap_or("").to_string();
    if let Some(rs) = a.get_mut("renditions").and_then(|r| r.as_object_mut()) {
        if !v.original_allowed {
            rs.remove("original");
        }
        for (name, r) in rs.iter_mut() {
            let (u, exp) =
                app.signed_url(&format!("/obx/v1/assets/{id}/renditions/{name}"), &v.tag());
            r["url"] = Value::String(u);
            r["url_expires_at"] = Value::String(exp);
        }
    }
    a
}

pub fn asset_visible_now(expires_at: Option<&str>) -> bool {
    !expired(expires_at, chrono::Utc::now())
}

/// ProductDetail of each visible product id, in the order given.
pub fn product_details(
    app: &App,
    c: &Connection,
    v: &Viewer,
    ids: &[String],
) -> Result<Vec<Value>> {
    if ids.is_empty() {
        return Ok(vec![]);
    }
    let (bf, bargs) = v.brand_filter("brand_id");
    let mut args: Vec<String> = ids.to_vec();
    args.extend(bargs);
    let q = format!(
        "SELECT id, rep, updated_at FROM products WHERE visible = 1 AND id IN {}{bf}",
        crate::db::in_list(ids.len())
    );
    let mut st = c.prepare(&q)?;
    let mut by_id: BTreeMap<String, Value> = BTreeMap::new();
    for row in st.query_map(rusqlite::params_from_iter(args.iter()), |r| {
        Ok((
            r.get::<_, String>(0)?,
            r.get::<_, String>(1)?,
            r.get::<_, String>(2)?,
        ))
    })? {
        let (id, rep, up) = row?;
        let mut p = render_plain(&rep, &up);
        p["variants"] = json!([]);
        p["assets"] = json!([]);
        by_id.insert(id, p);
    }
    if by_id.is_empty() {
        return Ok(vec![]);
    }
    let pids: Vec<String> = by_id.keys().cloned().collect();
    let inl = crate::db::in_list(pids.len());
    let mut st = c.prepare(&format!(
        "SELECT product_id, rep, updated_at FROM variants WHERE visible = 1 AND product_id IN {inl} ORDER BY product_id, external_id"
    ))?;
    for row in st.query_map(rusqlite::params_from_iter(pids.iter()), |r| {
        Ok((
            r.get::<_, String>(0)?,
            r.get::<_, String>(1)?,
            r.get::<_, String>(2)?,
        ))
    })? {
        let (pid, rep, up) = row?;
        if let Some(p) = by_id.get_mut(&pid) {
            p["variants"]
                .as_array_mut()
                .unwrap()
                .push(render_plain(&rep, &up));
        }
    }
    let mut st = c.prepare(&format!(
        "SELECT product_id, rep, updated_at, expires_at FROM assets WHERE visible = 1 AND product_id IN {inl} ORDER BY product_id, CASE WHEN color_code IS NULL THEN 0 ELSE 1 END, color_code, position"
    ))?;
    for row in st.query_map(rusqlite::params_from_iter(pids.iter()), |r| {
        Ok((
            r.get::<_, String>(0)?,
            r.get::<_, String>(1)?,
            r.get::<_, String>(2)?,
            r.get::<_, Option<String>>(3)?,
        ))
    })? {
        let (pid, rep, up, exp) = row?;
        if !asset_visible_now(exp.as_deref()) {
            continue;
        }
        if let Some(p) = by_id.get_mut(&pid) {
            p["assets"]
                .as_array_mut()
                .unwrap()
                .push(render_asset(app, &rep, &up, v));
        }
    }
    for p in by_id.values_mut() {
        if let Some(vs) = p["variants"].as_array_mut() {
            vs.sort_by(|a, b| a["external_id"].as_str().cmp(&b["external_id"].as_str()));
        }
    }
    Ok(ids.iter().filter_map(|id| by_id.remove(id)).collect())
}

fn product_etag(p: &Value) -> String {
    let mut parts = vec![p["updated_at"].as_str().unwrap_or("").to_string()];
    for v in p["variants"].as_array().into_iter().flatten() {
        parts.push(format!(
            "{}{}",
            v["id"].as_str().unwrap_or(""),
            v["updated_at"].as_str().unwrap_or("")
        ));
    }
    for a in p["assets"].as_array().into_iter().flatten() {
        let n = a["renditions"].as_object().map(|r| r.len()).unwrap_or(0);
        parts.push(format!(
            "{}{}{}",
            a["id"].as_str().unwrap_or(""),
            a["updated_at"].as_str().unwrap_or(""),
            n
        ));
    }
    crate::catalog::hash_hex(parts.join("|").as_bytes())[..32].to_string()
}

// ---- handlers ------------------------------------------------------------------------

pub fn capabilities(s: &Settings) -> Vec<&'static str> {
    let mut c = vec![
        "changes",
        "products",
        "by_gtin",
        "renditions",
        "exports",
        "webhooks",
        "usage",
    ];
    if s.portal.access_requests_enabled {
        c.push("access_requests");
    }
    c.extend(["ingest", "ingest.server_renditions", "portal"]);
    c
}

pub async fn discovery(State(app): State<App>) -> Res {
    if !app.setup_done().await {
        return Err(Problem::new(
            "setup_required",
            "This node has not completed first-run setup.",
        )
        .with_status(503));
    }
    let a = app.clone();
    let (s, brands) = app
        .db
        .read(|c| {
            let s = Settings::load(c)?;
            let mut st =
                c.prepare("SELECT id, rep FROM brands WHERE visible = 1 ORDER BY name, id")?;
            let brands = st
                .query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))?
                .filter_map(|x| x.ok())
                .map(|(id, rep)| {
                    let b: Value = serde_json::from_str(&rep).unwrap_or(json!({}));
                    json!({"id": id, "name": b["name"], "logo_url": b["logo_url"]})
                })
                .collect::<Vec<_>>();
            Ok((s, brands))
        })
        .await?;
    let base = &a.cfg.public_url;
    let logo = (!s.logo_sha.is_empty())
        .then(|| format!("{base}/admin/api/public/logo?v={}", &s.logo_sha[..16]));
    let mut r = ok(&json!({
        "obx_version": OBX_VERSION,
        "spec_version": SPEC_VERSION,
        "node": {"software": SOFTWARE, "version": VERSION},
        "publisher": {
            "id": a.node_id, "name": s.display_name(), "logo_url": logo, "accent_color": s.branding.accent_color,
            "website": s.company.website, "contact_email": s.company.contact_email, "welcome_text": s.branding.welcome_text,
        },
        "api_base": format!("{base}/obx/v1"),
        "portal_url": format!("{base}/"),
        "auth": {
            "token_endpoint": format!("{base}/obx/v1/oauth/token"),
            "scopes_supported": ALL_SCOPES,
            "token_endpoint_auth_methods_supported": ["client_secret_basic", "client_secret_post"],
        },
        "access_requests_url": s.portal.access_requests_enabled.then(|| format!("{base}/obx/v1/access-requests")),
        "ingest_url": format!("{base}/obx/v1/ingest"),
        "capabilities": capabilities(&s),
        "brands": brands,
        "languages": s.content_languages(),
        "limits": {"changes_page_max": 500, "products_page_max": 100, "gtin_lookup_max": 2000,
                   "tombstone_retention_days": a.cfg.change_retention_days},
    }));
    r.headers_mut().insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("public, max-age=300"),
    );
    Ok(r)
}

pub async fn grant(State(app): State<App>, headers: HeaderMap) -> Res {
    let (v, hs) = protocol_auth(&app, &headers, "", false).await?;
    let g = app
        .db
        .read(move |c| {
            let s = Settings::load(c)?;
            let r = load_retailer(c, &v.retailer_id)?
                .ok_or_else(|| Problem::internal("retailer missing"))?;
            Ok(grant_of(&s, &r))
        })
        .await?;
    Ok(with_headers(ok(&g), &hs))
}

pub async fn brands(State(app): State<App>, headers: HeaderMap) -> Res {
    let (v, hs) = protocol_auth(&app, &headers, "catalog:read", false).await?;
    let items = app
        .db
        .read(move |c| {
            let (bf, args) = v.brand_filter("id");
            let mut st = c.prepare(&format!(
                "SELECT rep, updated_at FROM brands WHERE visible = 1{bf} ORDER BY id"
            ))?;
            let r = st
                .query_map(rusqlite::params_from_iter(args.iter()), |r| {
                    Ok(render_plain(
                        &r.get::<_, String>(0)?,
                        &r.get::<_, String>(1)?,
                    ))
                })?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            Ok(r)
        })
        .await?;
    Ok(with_headers(ok(&json!({"items": items})), &hs))
}

pub async fn brand(State(app): State<App>, Path(id): Path<String>, headers: HeaderMap) -> Res {
    let (v, hs) = protocol_auth(&app, &headers, "catalog:read", false).await?;
    let b = app
        .db
        .read(move |c| {
            let r = crate::catalog::load_row_by_id(c, KIND_BRAND, &id)?;
            Ok(r.filter(|r| r.visible && v.sees_brand(&r.id))
                .map(|r| render_plain(&r.rep, &r.updated_at)))
        })
        .await?;
    match b {
        Some(b) => Ok(with_headers(ok(&b), &hs)),
        None => Err(Problem::new("not_found", "Brand not found.")),
    }
}

#[derive(Serialize, Deserialize)]
struct ProductsCursor {
    a: String,
}

pub async fn products(
    State(app): State<App>,
    Query(q): Query<HashMap<String, String>>,
    headers: HeaderMap,
) -> Res {
    let (v, hs) = protocol_auth(&app, &headers, "catalog:read", false).await?;
    let limit = limit_param(&q, 25, 100)?;
    let mut where_ = String::from("WHERE visible = 1");
    let mut args: Vec<String> = Vec::new();
    if let Some(c) = q.get("cursor").filter(|c| !c.is_empty()) {
        let cur: ProductsCursor = app
            .decode_cursor("products", c)
            .ok_or_else(|| Problem::new("cursor_invalid", "The cursor is not valid."))?;
        where_.push_str(" AND id > ?");
        args.push(cur.a);
    }
    if let Some(ids) = q.get("ids").map(|s| s.trim()).filter(|s| !s.is_empty()) {
        let list: Vec<String> = ids.split(',').map(|s| s.trim().to_string()).collect();
        if list.len() > 100 {
            return Err(Problem::new("limit_exceeded", "At most 100 ids."));
        }
        where_.push_str(&format!(" AND id IN {}", crate::db::in_list(list.len())));
        args.extend(list);
    }
    if let Some(b) = q.get("brand_id").filter(|s| !s.is_empty()) {
        where_.push_str(" AND brand_id = ?");
        args.push(b.clone());
    }
    if let Some(us) = q.get("updated_since").filter(|s| !s.is_empty()) {
        let t = crate::db::parse_time(us).ok_or_else(|| {
            Problem::new(
                "invalid_request",
                "updated_since must be an RFC 3339 timestamp.",
            )
        })?;
        where_.push_str(" AND touched_at >= ?");
        args.push(crate::db::fmt_time(t));
    }
    let (bf, bargs) = v.brand_filter("brand_id");
    where_.push_str(&bf);
    args.extend(bargs);
    let a = app.clone();
    let (items, next) = app
        .db
        .read(move |c| {
            let mut st = c.prepare(&format!(
                "SELECT id FROM products {where_} ORDER BY id LIMIT {}",
                limit + 1
            ))?;
            let mut ids = st
                .query_map(rusqlite::params_from_iter(args.iter()), |r| {
                    r.get::<_, String>(0)
                })?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            let mut next = None;
            if ids.len() > limit {
                ids.truncate(limit);
                next = Some(a.encode_cursor(
                    "products",
                    &ProductsCursor {
                        a: ids[limit - 1].clone(),
                    },
                ));
            }
            Ok((product_details(&a, c, &v, &ids)?, next))
        })
        .await?;
    Ok(with_headers(
        ok(&json!({"items": items, "next_cursor": next})),
        &hs,
    ))
}

pub async fn product(State(app): State<App>, Path(id): Path<String>, headers: HeaderMap) -> Res {
    let (v, hs) = protocol_auth(&app, &headers, "catalog:read", false).await?;
    let a = app.clone();
    let mut items = app
        .db
        .read(move |c| product_details(&a, c, &v, &[id]))
        .await?;
    let Some(p) = items.pop() else {
        return Err(Problem::new("not_found", "Product not found."));
    };
    let etag = format!("\"{}\"", product_etag(&p));
    if let Some(m) = headers
        .get(header::IF_NONE_MATCH)
        .and_then(|v| v.to_str().ok())
    {
        if m == etag || m == "*" {
            let mut r = StatusCode::NOT_MODIFIED.into_response();
            r.headers_mut()
                .insert(header::ETAG, HeaderValue::from_str(&etag).unwrap());
            return Ok(with_headers(r, &hs));
        }
    }
    let mut r = ok(&p);
    r.headers_mut()
        .insert(header::ETAG, HeaderValue::from_str(&etag).unwrap());
    Ok(with_headers(r, &hs))
}

/// GTIN lookup (protocol.md §7).
pub fn lookup_gtins(app: &App, c: &Connection, v: &Viewer, inputs: &[String]) -> Result<Value> {
    let mut results: Vec<Value> = Vec::new();
    let mut seen = std::collections::HashSet::new();
    let mut norms = Vec::new();
    for raw in inputs {
        let t = raw.trim().to_string();
        let cleaned: String = t
            .chars()
            .filter(|c| !matches!(c, ' ' | '\t' | '\u{a0}'))
            .collect();
        let mut input = t.clone();
        if input.len() > 64 {
            input = input.chars().take(64).collect();
        }
        match normalize_gtin(&cleaned) {
            Some(n) => {
                if !seen.insert(n.clone()) {
                    continue;
                }
                norms.push(n.clone());
                results.push(json!({"input": input, "gtin": n, "status": "unmatched", "product_id": null, "variant_id": null}));
            }
            None => {
                if !seen.insert(format!("invalid:{t}")) {
                    continue;
                }
                results.push(json!({"input": input, "gtin": null, "status": "invalid", "product_id": null, "variant_id": null}));
            }
        }
    }
    let mut by_gtin: HashMap<String, (String, String)> = HashMap::new();
    for chunk in norms.chunks(500) {
        let (bf, bargs) = v.brand_filter("brand_id");
        let mut args: Vec<String> = chunk.to_vec();
        args.extend(bargs);
        let mut st = c.prepare(&format!(
            "SELECT gtin, id, product_id FROM variants WHERE visible = 1 AND gtin IN {}{bf}",
            crate::db::in_list(chunk.len())
        ))?;
        for row in st.query_map(rusqlite::params_from_iter(args.iter()), |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, String>(2)?,
            ))
        })? {
            let (g, vid, pid) = row?;
            by_gtin.insert(g, (vid, pid));
        }
    }
    let mut pids: Vec<String> = Vec::new();
    for r in results.iter_mut() {
        let Some(g) = r["gtin"].as_str() else {
            continue;
        };
        if let Some((vid, pid)) = by_gtin.get(g) {
            r["status"] = json!("matched");
            r["variant_id"] = json!(vid);
            r["product_id"] = json!(pid);
            if !pids.contains(pid) {
                pids.push(pid.clone());
            }
        }
    }
    Ok(json!({"results": results, "products": product_details(app, c, v, &pids)?}))
}

pub async fn by_gtin(
    State(app): State<App>,
    method: Method,
    Query(q): Query<HashMap<String, String>>,
    headers: HeaderMap,
    body: Bytes,
) -> Res {
    let (v, hs) = protocol_auth(&app, &headers, "catalog:read", false).await?;
    let inputs: Vec<String> = if method == Method::GET {
        let raw = q.get("gtin").cloned().unwrap_or_default();
        if raw.trim().is_empty() {
            return Err(Problem::new("invalid_request", "Pass ?gtin=a,b,c."));
        }
        let l: Vec<String> = raw.split(',').map(String::from).collect();
        if l.len() > 100 {
            return Err(Problem::new(
                "limit_exceeded",
                "At most 100 GTINs with GET; use POST for up to 2000.",
            ));
        }
        l
    } else {
        let b = read_json(&headers, &body, 1 << 20)?;
        let Some(list) = b.get("gtins").and_then(|g| g.as_array()) else {
            return Err(Problem::new("invalid_request", "Send {\"gtins\": [...]}."));
        };
        if list.len() > 2000 {
            return Err(Problem::new(
                "limit_exceeded",
                "At most 2000 GTINs per request.",
            ));
        }
        let mut out = Vec::new();
        for g in list {
            match g {
                Value::String(s) => out.push(s.clone()),
                Value::Number(n) => out.push(n.to_string()),
                _ => return Err(Problem::new("invalid_request", "gtins must be strings.")),
            }
        }
        out
    };
    let a = app.clone();
    let res = app
        .db
        .read(move |c| lookup_gtins(&a, c, &v, &inputs))
        .await?;
    Ok(with_headers(ok(&res), &hs))
}

pub fn visible_asset(c: &Connection, v: &Viewer, id: &str) -> Result<Option<crate::catalog::Row>> {
    let Some(r) = crate::catalog::load_row_by_id(c, KIND_ASSET, id)? else {
        return Ok(None);
    };
    if !r.visible || !v.sees_brand(&r.brand_id) {
        return Ok(None);
    }
    let rep: Value = serde_json::from_str(&r.rep).unwrap_or(json!({}));
    if !asset_visible_now(rep["rights"]["expires_at"].as_str()) {
        return Ok(None);
    }
    Ok(Some(r))
}

pub async fn asset(State(app): State<App>, Path(id): Path<String>, headers: HeaderMap) -> Res {
    let (v, hs) = protocol_auth(&app, &headers, "media:read", false).await?;
    let a = app.clone();
    let out = app
        .db
        .read(move |c| {
            Ok(visible_asset(c, &v, &id)?.map(|r| render_asset(&a, &r.rep, &r.updated_at, &v)))
        })
        .await?;
    match out {
        Some(x) => Ok(with_headers(ok(&x), &hs)),
        None => Err(Problem::new("not_found", "Asset not found.")),
    }
}

pub fn rendition_filename(filename: &str, name: &str) -> String {
    let base = match filename.rfind('.') {
        Some(i) if i > 0 => &filename[..i],
        _ => filename,
    };
    format!("{base}_{name}.jpg")
}

pub async fn rendition(
    State(app): State<App>,
    Path((id, name)): Path<(String, String)>,
    Query(q): Query<HashMap<String, String>>,
    headers: HeaderMap,
    method: Method,
) -> Res {
    let path = format!("/obx/v1/assets/{id}/renditions/{name}");
    let (v, hs) = if bearer(&headers).is_none() && q.get("sig").is_some_and(|s| !s.is_empty()) {
        let tag = app.verify_signed(&path, &q).ok_or_else(|| {
            Problem::new(
                "forbidden",
                "This link has expired or does not match its signature; read the asset again for a fresh link.",
            )
        })?;
        let v = app.db.read(move |c| viewer_from_tag(c, &tag)).await?;
        let hs = if v.kind == "client" {
            rate_limit(&app, &format!("api:{}", v.client_row_id), 3000)?.to_vec()
        } else {
            vec![]
        };
        (v, hs)
    } else {
        let (v, hs) = protocol_auth(&app, &headers, "media:read", true).await?;
        (v, hs.to_vec())
    };
    if !RENDITION_NAMES.contains(&name.as_str()) {
        return Err(Problem::new("not_found", "Unknown rendition."));
    }
    let v2 = v.clone();
    let row = app.db.read(move |c| visible_asset(c, &v2, &id)).await?;
    let Some(row) = row else {
        return Err(Problem::new("not_found", "Asset not found."));
    };
    if name == "original" && !v.original_allowed {
        return Err(Problem::new(
            "original_not_allowed",
            "Original files are not available to you.",
        ));
    }
    let rep: AssetRep = serde_json::from_str(&row.rep).map_err(Problem::internal)?;
    let Some(rend) = rep.renditions.as_ref().and_then(|r| r.get(&name)) else {
        return Err(Problem::new("not_found", "Rendition not found."));
    };
    let fname = if name == "original" {
        rep.filename.clone()
    } else {
        rendition_filename(&rep.filename, &name)
    };
    let r = serve_blob(
        &app,
        &headers,
        &method,
        &rend.sha256,
        &rend.content_type,
        &content_disposition("inline", &fname),
    )
    .await?;
    Ok(with_headers(r, &hs))
}

fn parse_range(h: &str, size: u64) -> Option<std::ops::Range<u64>> {
    let spec = h.strip_prefix("bytes=")?;
    if spec.contains(',') {
        return None;
    }
    let (a, b) = spec.split_once('-')?;
    let (start, end) = if a.is_empty() {
        let n: u64 = b.parse().ok()?;
        if n == 0 {
            return None;
        }
        (size.saturating_sub(n), size)
    } else {
        let s: u64 = a.parse().ok()?;
        let e: u64 = if b.is_empty() {
            size
        } else {
            (b.parse::<u64>().ok()? + 1).min(size)
        };
        (s, e)
    };
    (start < end && start < size).then_some(start..end)
}

/// Serves a stored blob with ETag, Range and If-None-Match.
pub async fn serve_blob(
    app: &App,
    headers: &HeaderMap,
    method: &Method,
    sha: &str,
    ct: &str,
    disposition: &str,
) -> Res {
    let etag = format!("\"{sha}\"");
    let mut base = axum::http::Response::builder()
        .header(header::CONTENT_TYPE, ct)
        .header(header::ETAG, &etag)
        .header("OBX-Content-SHA256", sha)
        .header(header::ACCEPT_RANGES, "bytes")
        .header(header::CACHE_CONTROL, "private, max-age=3600")
        .header("X-Content-Type-Options", "nosniff");
    if !disposition.is_empty() {
        base = base.header(header::CONTENT_DISPOSITION, disposition);
    }
    if let Some(m) = headers
        .get(header::IF_NONE_MATCH)
        .and_then(|v| v.to_str().ok())
    {
        if m.split(',').any(|x| x.trim() == etag || x.trim() == "*") {
            return Ok(base.status(304).body(Body::empty()).unwrap());
        }
    }
    let Some(data) = app
        .store
        .get(&blob_key(sha))
        .await
        .map_err(Problem::internal)?
    else {
        return Err(Problem::new("not_found", "File not found."));
    };
    let size = data.len() as u64;
    if let Some(rh) = headers.get(header::RANGE).and_then(|v| v.to_str().ok()) {
        let if_range_ok = headers
            .get(header::IF_RANGE)
            .and_then(|v| v.to_str().ok())
            .is_none_or(|v| v == etag);
        if if_range_ok {
            match parse_range(rh, size) {
                Some(r) => {
                    let part = data.slice(r.start as usize..r.end as usize);
                    let b = base
                        .status(206)
                        .header(
                            header::CONTENT_RANGE,
                            format!("bytes {}-{}/{size}", r.start, r.end - 1),
                        )
                        .header(header::CONTENT_LENGTH, part.len());
                    let body = if method == Method::HEAD {
                        Body::empty()
                    } else {
                        Body::from(part)
                    };
                    return Ok(b.body(body).unwrap());
                }
                None => {
                    return Ok(base
                        .status(416)
                        .header(header::CONTENT_RANGE, format!("bytes */{size}"))
                        .body(Body::empty())
                        .unwrap());
                }
            }
        }
    }
    let b = base.status(200).header(header::CONTENT_LENGTH, size);
    let body = if method == Method::HEAD {
        Body::empty()
    } else {
        Body::from(data)
    };
    Ok(b.body(body).unwrap())
}
