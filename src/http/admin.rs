//! The Node Admin API used by admin-ui (openapi/node-admin.yaml): first-run
//! setup, sessions, settings, catalog, retailers, API keys, upload keys,
//! access requests and invitations.

use std::collections::HashMap;
use std::net::SocketAddr;

use axum::body::Bytes;
use axum::extract::{ConnectInfo, Path, Query, State};
use axum::http::{HeaderMap, HeaderValue, Method, StatusCode, header};
use axum::response::{IntoResponse, Response};
use rusqlite::{Connection, OptionalExtension, params};
use serde_json::{Map, Value, json};

use super::*;
use crate::model::*;
use crate::secure;

pub const SESSION_COOKIE: &str = "obx_session";
pub const CSRF_COOKIE: &str = "obx_csrf";
const SESSION_TTL_DAYS: i64 = 30;
const INVITE_TTL_DAYS: i64 = 7;

/// The 25 interface languages of admin-ui.
pub const UI_LANGS: [&str; 25] = [
    "bg", "cs", "da", "de", "el", "en", "es", "et", "fi", "fr", "ga", "hr", "hu", "it", "lt", "lv",
    "mt", "nb", "nl", "pl", "pt", "ro", "sk", "sl", "sv",
];

/// The best interface language for a tag or Accept-Language header.
pub fn supported_lang(raw: &str) -> String {
    for part in raw.split(',') {
        let tag = part.split(';').next().unwrap_or("").trim().to_lowercase();
        let base = tag.split(['-', '_']).next().unwrap_or("");
        let base = if base == "no" || base == "nn" {
            "nb"
        } else {
            base
        };
        if UI_LANGS.contains(&base) {
            return base.to_string();
        }
    }
    "en".into()
}

#[derive(Debug, Clone)]
pub struct User {
    pub id: String,
    pub email: String,
    pub name: String,
    pub role: String,
    pub status: String,
    pub language: String,
    pub created_at: String,
    pub retailer_id: Option<String>,
    pub password_hash: Option<String>,
    pub invite_expires_at: Option<String>,
    pub last_login_at: Option<String>,
}

impl User {
    pub fn json(&self) -> Value {
        json!({"id": self.id, "email": self.email, "name": self.name, "role": self.role, "retailer_id": self.retailer_id,
            "status": self.status, "language": self.language, "last_login_at": self.last_login_at,
            "invite_expires_at": self.invite_expires_at, "created_at": self.created_at})
    }
}

pub fn load_user(c: &Connection, where_: &str, arg: &str) -> Result<Option<User>> {
    Ok(c.query_row(
        &format!("SELECT id, email, name, role, status, language, created_at, retailer_id, password_hash, invite_expires_at, last_login_at FROM users WHERE {where_}"),
        [arg],
        |r| {
            Ok(User {
                id: r.get(0)?,
                email: r.get(1)?,
                name: r.get(2)?,
                role: r.get(3)?,
                status: r.get(4)?,
                language: r.get(5)?,
                created_at: r.get(6)?,
                retailer_id: r.get(7)?,
                password_hash: r.get(8)?,
                invite_expires_at: r.get(9)?,
                last_login_at: r.get(10)?,
            })
        },
    )
    .optional()?)
}

pub fn viewer_for_user(c: &Connection, u: &User) -> Result<Viewer> {
    if u.role == "admin" {
        return Ok(Viewer {
            kind: "admin".into(),
            original_allowed: true,
            user_id: u.id.clone(),
            ..Default::default()
        });
    }
    let Some(rid) = &u.retailer_id else {
        return Err(Problem::new("forbidden", "This account has no retailer."));
    };
    let Some(ret) = load_retailer(c, rid)?.filter(|r| r.status == "active") else {
        return Err(Problem::new(
            "account_blocked",
            "Access for your company was blocked.",
        ));
    };
    let s = Settings::load(c)?;
    Ok(Viewer {
        kind: "user".into(),
        retailer_id: ret.id.clone(),
        retailer_name: ret.name.clone(),
        brand_ids: ret.brand_ids.clone(),
        original_allowed: original_allowed(&s, &ret),
        user_id: u.id.clone(),
        ..Default::default()
    })
}

pub fn viewer_for_user_id(c: &Connection, id: &str) -> Result<Viewer> {
    match load_user(c, "id = ?", id)? {
        Some(u) if u.status == "active" => viewer_for_user(c, &u),
        _ => Err(Problem::new("access_revoked", "This account is blocked.")),
    }
}

#[derive(Debug, Clone)]
pub struct Session {
    pub id_hash: String,
    pub csrf: String,
    pub user: User,
}

pub fn cookie(headers: &HeaderMap, name: &str) -> Option<String> {
    for h in headers.get_all(header::COOKIE) {
        for part in h.to_str().ok()?.split(';') {
            if let Some((k, v)) = part.trim().split_once('=') {
                if k == name {
                    return Some(v.to_string());
                }
            }
        }
    }
    None
}

pub fn set_cookie(app: &App, r: &mut Response, name: &str, value: &str, max_age: i64) {
    let secure = if app.cfg.secure() { "; Secure" } else { "" };
    let c = format!("{name}={value}; Path=/; Max-Age={max_age}; HttpOnly; SameSite=Lax{secure}");
    if let Ok(v) = HeaderValue::from_str(&c) {
        r.headers_mut().append(header::SET_COOKIE, v);
    }
}

pub fn load_session(c: &Connection, headers: &HeaderMap) -> Result<Option<Session>> {
    let Some(v) = cookie(headers, SESSION_COOKIE).filter(|v| !v.is_empty()) else {
        return Ok(None);
    };
    let h = secure::hash_token(&v);
    let row: Option<(String, String, String)> = c
        .query_row(
            "SELECT csrf, user_id, expires_at FROM sessions WHERE id_hash = ?",
            [&h],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .optional()?;
    let Some((csrf, user_id, expires)) = row else {
        return Ok(None);
    };
    if crate::db::parse_time(&expires).is_none_or(|t| t < chrono::Utc::now()) {
        return Ok(None);
    }
    let Some(u) = load_user(c, "id = ?", &user_id)?.filter(|u| u.status == "active") else {
        return Ok(None);
    };
    if u.role == "retailer" {
        let ok = match &u.retailer_id {
            Some(rid) => load_retailer(c, rid)?.is_some_and(|r| r.status == "active"),
            None => false,
        };
        if !ok {
            return Ok(None);
        }
    }
    Ok(Some(Session {
        id_hash: h,
        csrf,
        user: u,
    }))
}

fn check_csrf(method: &Method, headers: &HeaderMap, s: Option<&Session>) -> Result<()> {
    if matches!(*method, Method::GET | Method::HEAD | Method::OPTIONS) {
        return Ok(());
    }
    let Some(h) = headers
        .get("x-csrf-token")
        .and_then(|v| v.to_str().ok())
        .filter(|v| !v.is_empty())
    else {
        return Err(Problem::new(
            "csrf_failed",
            "Missing X-CSRF-Token header; reload the page.",
        ));
    };
    let want = match s {
        Some(s) => Some(s.csrf.clone()),
        None => cookie(headers, CSRF_COOKIE),
    };
    if want.is_none_or(|w| !secure::eq(h, &w)) {
        return Err(Problem::new(
            "csrf_failed",
            "The security token is wrong; reload the page.",
        ));
    }
    Ok(())
}

/// The admin API gate: setup done (except "setup"), session cookie, CSRF on
/// unsafe methods, and the role ("public", "setup", "any", "admin").
pub async fn admin_guard(
    app: &App,
    headers: &HeaderMap,
    method: &Method,
    role: &str,
) -> Result<Option<Session>> {
    if role != "setup" && !app.setup_done().await {
        return Err(Problem::new(
            "setup_required",
            "Complete the first-run setup first.",
        ));
    }
    let h = headers.clone();
    let s = app.db.read(move |c| load_session(c, &h)).await?;
    if bearer(headers).is_some() && s.is_none() && role != "public" && role != "setup" {
        return Err(Problem::new(
            "unauthorized",
            "The admin API accepts only session cookies.",
        ));
    }
    check_csrf(method, headers, s.as_ref())?;
    match role {
        "admin" | "any" => {
            let Some(sess) = &s else {
                return Err(Problem::new("unauthorized", "Please log in."));
            };
            if role == "admin" && sess.user.role != "admin" {
                return Err(Problem::new(
                    "forbidden",
                    "Only brand administrators can do this.",
                ));
            }
        }
        _ => {}
    }
    Ok(s)
}

fn session_json(
    c: &Connection,
    s: Option<&User>,
    csrf: &str,
    setup_required: bool,
) -> Result<Value> {
    let mut out = json!({"authenticated": s.is_some(), "csrf_token": csrf, "setup_required": setup_required, "user": null, "retailer": null});
    if let Some(u) = s {
        out["user"] = u.json();
        if let Some(rid) = &u.retailer_id {
            if let Some(r) = load_retailer(c, rid)? {
                out["retailer"] = json!({"id": r.id, "name": r.name});
            }
        }
    }
    Ok(out)
}

fn start_session(tx: &Connection, headers: &HeaderMap, user_id: &str) -> Result<(String, String)> {
    if let Some(old) = cookie(headers, SESSION_COOKIE) {
        tx.execute(
            "DELETE FROM sessions WHERE id_hash = ?",
            [secure::hash_token(&old)],
        )?;
    }
    let id = secure::random_string(32);
    let csrf = secure::random_string(24);
    let now = crate::db::now_str();
    let exp = crate::db::fmt_time(chrono::Utc::now() + chrono::Duration::days(SESSION_TTL_DAYS));
    tx.execute(
        "INSERT INTO sessions (id_hash, user_id, csrf, created_at, expires_at, last_seen_at) VALUES (?, ?, ?, ?, ?, ?)",
        params![secure::hash_token(&id), user_id, csrf, now, exp, now],
    )?;
    tx.execute(
        "UPDATE users SET last_login_at = ? WHERE id = ?",
        params![now, user_id],
    )?;
    Ok((id, csrf))
}

fn session_response(
    app: &App,
    status: u16,
    body: &Value,
    session_id: &str,
    csrf: &str,
) -> Response {
    let mut r = json(status, body);
    let age = SESSION_TTL_DAYS * 86400;
    set_cookie(app, &mut r, SESSION_COOKIE, session_id, age);
    set_cookie(app, &mut r, CSRF_COOKIE, csrf, age);
    r
}

pub fn valid_email(e: &str) -> bool {
    let Some(at) = e.rfind('@') else { return false };
    at > 0
        && at + 3 < e.len()
        && e[at..].contains('.')
        && e.len() <= 254
        && !e.contains([' ', '\t', '\r', '\n', '<', '>', ',', ';', '"'])
}

pub fn norm_email(e: &str) -> String {
    e.trim().to_lowercase()
}

fn is_hex_color(s: &str) -> bool {
    s.len() == 7 && s.starts_with('#') && s[1..].bytes().all(|c| c.is_ascii_hexdigit())
}

fn str_of(m: &Map<String, Value>, k: &str) -> String {
    m.get(k).and_then(|v| v.as_str()).unwrap_or("").to_string()
}

// ---- setup and sessions ----------------------------------------------------------

pub async fn setup_get(State(app): State<App>) -> Res {
    Ok(ok(&json!({"required": !app.setup_done().await})))
}

pub async fn setup_post(
    State(app): State<App>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    method: Method,
    headers: HeaderMap,
    body: Bytes,
) -> Res {
    admin_guard(&app, &headers, &method, "setup").await?;
    let ip = client_ip(&app, &headers, Some(peer));
    if let Err(retry) = app.limit(&format!("setup:{ip}"), 10, 900) {
        let mut p = Problem::new("rate_limited", "Too many attempts.");
        p.retry_after = Some(retry as u64);
        return Err(p);
    }
    if app.setup_done().await {
        return Err(Problem::new(
            "setup_completed",
            "This node is already set up.",
        ));
    }
    let b = read_json_object(&headers, &body)?;
    let empty = Map::new();
    let company = b
        .get("company")
        .and_then(|v| v.as_object())
        .unwrap_or(&empty)
        .clone();
    let admin = b
        .get("admin")
        .and_then(|v| v.as_object())
        .unwrap_or(&empty)
        .clone();
    let code = str_of(&b, "setup_code");
    let want = app
        .db
        .read(|c| crate::db::get_meta(c, "setup_code_hash"))
        .await?
        .unwrap_or_default();
    let candidates = [
        code.trim().to_string(),
        code.trim().to_uppercase(),
        code.trim().to_uppercase().replace([' ', '-'], ""),
    ];
    let matched = !want.is_empty()
        && candidates.iter().any(|c| {
            secure::eq(&want, &secure::hash_token(c))
                || (c.len() == 12
                    && secure::eq(
                        &want,
                        &secure::hash_token(&format!("{}-{}-{}", &c[..4], &c[4..8], &c[8..])),
                    ))
        });
    if !matched {
        return Err(Problem::new(
            "forbidden",
            "The setup code is not correct. You find it in the node's log.",
        ));
    }
    let mut p = Problem::new("validation_failed", "Please check the highlighted fields.");
    let name = str_of(&company, "name").trim().to_string();
    if name.is_empty() || name.len() > 200 {
        p = p.field("/company/name", "validation_failed", "required");
    }
    let lang = obx_format::importfmt::normalize_lang(&str_of(&company, "default_language"));
    if !obx_format::importfmt::valid_lang(&lang) {
        p = p.field(
            "/company/default_language",
            "validation_failed",
            "language like nl or en",
        );
    }
    let admin_name = str_of(&admin, "name").trim().to_string();
    if admin_name.is_empty() {
        p = p.field("/admin/name", "validation_failed", "required");
    }
    let email = norm_email(&str_of(&admin, "email"));
    if !valid_email(&email) {
        p = p.field("/admin/email", "validation_failed", "invalid e-mail");
    }
    let password = str_of(&admin, "password");
    if let Some(reason) = secure::password_problem(&password) {
        p = p.field("/admin/password", "validation_failed", reason);
    }
    let accent = str_of(&company, "accent_color");
    if !accent.is_empty() && !is_hex_color(&accent) {
        p = p.field("/company/accent_color", "validation_failed", "#rrggbb");
    }
    let contact = norm_email(&str_of(&company, "contact_email"));
    if !contact.is_empty() && !valid_email(&contact) {
        p = p.field(
            "/company/contact_email",
            "validation_failed",
            "invalid e-mail",
        );
    }
    let website = str_of(&company, "website");
    if !website.is_empty() && !website.starts_with("http") {
        p = p.field("/company/website", "validation_failed", "absolute URL");
    }
    if !p.errors.is_empty() {
        return Err(p);
    }
    let hash = tokio::task::spawn_blocking(move || secure::hash_password(&password))
        .await
        .map_err(Problem::internal)?;
    let mut s = Settings::default();
    s.company.name = name.clone();
    s.branding.display_name = name.clone();
    if !website.is_empty() {
        s.company.website = Some(website);
    }
    if !contact.is_empty() {
        s.company.contact_email = Some(contact);
    }
    if !accent.is_empty() {
        s.branding.accent_color = Some(accent.to_uppercase());
    }
    s.portal.default_language = lang.clone();
    let mut langs = vec![lang.clone()];
    for l in company
        .get("languages")
        .and_then(|v| v.as_array())
        .into_iter()
        .flatten()
    {
        let l = obx_format::importfmt::normalize_lang(l.as_str().unwrap_or(""));
        if obx_format::importfmt::valid_lang(&l) && !langs.contains(&l) {
            langs.push(l);
        }
    }
    s.portal.languages = langs;
    let mut brand_name = str_of(&company, "first_brand_name").trim().to_string();
    if brand_name.is_empty() {
        brand_name = name.clone();
    }
    let uid = crate::ids::new("usr");
    let ulang = supported_lang(&lang);
    let h2 = headers.clone();
    let (sid, csrf, out) = app
        .catalog_write(None, move |w| {
            if crate::db::get_meta(w.tx, "setup_done")?.as_deref() == Some("1") {
                return Err(Problem::new("setup_completed", "This node is already set up."));
            }
            s.save(w.tx)?;
            w.settings = s;
            let mut slug = obx_format::importfmt::slug(&brand_name);
            if slug.is_empty() {
                slug = "brand".into();
            }
            let mut doc = Map::new();
            doc.insert("name".into(), json!(brand_name));
            doc.insert("status".into(), json!("published"));
            if let (_, Some(p)) = w.upsert(KIND_BRAND, &slug, doc, "") {
                return Err(p);
            }
            let now = crate::db::now_str();
            w.tx.execute(
                "INSERT INTO users (id, email, name, role, status, language, password_hash, created_at) VALUES (?, ?, ?, 'admin', 'active', ?, ?, ?)",
                params![uid, email, admin_name, ulang, hash, now],
            )?;
            crate::db::set_meta(w.tx, "setup_done", "1")?;
            w.tx.execute("DELETE FROM meta WHERE key = 'setup_code_plain_once'", [])?;
            let (sid, csrf) = start_session(w.tx, &h2, &uid)?;
            let u = load_user(w.tx, "id = ?", &uid)?.unwrap();
            let out = session_json(w.tx, Some(&u), &csrf, false)?;
            Ok((sid, csrf, out))
        })
        .await?;
    tracing::info!(company = %name, "first-run setup completed");
    Ok(session_response(&app, 201, &out, &sid, &csrf))
}

pub async fn session_get(State(app): State<App>, method: Method, headers: HeaderMap) -> Res {
    let s = admin_guard(&app, &headers, &method, "setup").await?;
    let done = app.setup_done().await;
    let csrf = match &s {
        Some(s) => s.csrf.clone(),
        None => cookie(&headers, CSRF_COOKIE)
            .filter(|c| c.len() >= 20)
            .unwrap_or_else(|| secure::random_string(24)),
    };
    let c2 = csrf.clone();
    let out = app
        .db
        .read(move |c| session_json(c, s.as_ref().map(|s| &s.user), &c2, !done))
        .await?;
    let mut r = ok(&out);
    set_cookie(&app, &mut r, CSRF_COOKIE, &csrf, SESSION_TTL_DAYS * 86400);
    Ok(r)
}

pub async fn login(
    State(app): State<App>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    method: Method,
    headers: HeaderMap,
    body: Bytes,
) -> Res {
    admin_guard(&app, &headers, &method, "public").await?;
    let b = read_json_object(&headers, &body)?;
    let email = norm_email(&str_of(&b, "email"));
    let password = str_of(&b, "password");
    let ip = client_ip(&app, &headers, Some(peer));
    for k in [format!("login-ip:{ip}"), format!("login-email:{email}")] {
        if let Err(retry) = app.limit(&k, 30, 900) {
            let mut p = Problem::new("rate_limited", "Too many login attempts; try again later.");
            p.retry_after = Some(retry as u64);
            return Err(p);
        }
    }
    let e2 = email.clone();
    let u = app.db.read(move |c| load_user(c, "email = ?", &e2)).await?;
    let invalid = || {
        Problem::new(
            "invalid_credentials",
            "The e-mail address or password is not correct.",
        )
    };
    let Some(u) = u.filter(|u| u.password_hash.is_some() && password.len() <= 200) else {
        let pw = password.clone();
        let _ = tokio::task::spawn_blocking(move || secure::dummy_password_check(&pw)).await;
        return Err(invalid());
    };
    let (h, pw) = (u.password_hash.clone().unwrap(), password.clone());
    let good = tokio::task::spawn_blocking(move || secure::check_password(&h, &pw))
        .await
        .unwrap_or(false);
    if !good {
        return Err(invalid());
    }
    if u.status == "blocked" {
        return Err(Problem::new("account_blocked", "This account is blocked."));
    }
    if u.role == "retailer" {
        let rid = u.retailer_id.clone().unwrap_or_default();
        let active = app
            .db
            .read(move |c| Ok(load_retailer(c, &rid)?.is_some_and(|r| r.status == "active")))
            .await?;
        if !active {
            return Err(Problem::new(
                "account_blocked",
                "Access for your company is blocked.",
            ));
        }
    }
    let h2 = headers.clone();
    let (sid, csrf, out) = app
        .db
        .write(move |tx| {
            let (sid, csrf) = start_session(tx, &h2, &u.id)?;
            let out = session_json(tx, Some(&u), &csrf, false)?;
            Ok((sid, csrf, out))
        })
        .await?;
    Ok(session_response(&app, 200, &out, &sid, &csrf))
}

pub async fn logout(State(app): State<App>, method: Method, headers: HeaderMap) -> Res {
    admin_guard(&app, &headers, &method, "public").await?;
    if let Some(v) = cookie(&headers, SESSION_COOKIE) {
        app.db
            .write(move |tx| {
                tx.execute(
                    "DELETE FROM sessions WHERE id_hash = ?",
                    [secure::hash_token(&v)],
                )?;
                Ok(())
            })
            .await?;
    }
    let mut r = StatusCode::NO_CONTENT.into_response();
    set_cookie(&app, &mut r, SESSION_COOKIE, "", 0);
    Ok(r)
}

pub async fn public_branding(State(app): State<App>, method: Method, headers: HeaderMap) -> Res {
    admin_guard(&app, &headers, &method, "setup").await?;
    let done = app.setup_done().await;
    let base = app.cfg.public_url.clone();
    let out = app
        .db
        .read(move |c| {
            let s = Settings::load(c)?;
            let mut st = c.prepare("SELECT id, name FROM brands WHERE visible = 1 ORDER BY name")?;
            let brands = st
                .query_map([], |r| Ok(json!({"id": r.get::<_, String>(0)?, "name": r.get::<_, String>(1)?})))?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            let langs = s.content_languages();
            let logo = (!s.logo_sha.is_empty()).then(|| format!("{base}/admin/api/public/logo?v={}", &s.logo_sha[..16]));
            Ok(json!({"name": s.display_name(), "logo_url": logo, "accent_color": s.branding.accent_color,
                "welcome_text": s.branding.welcome_text, "languages": langs, "default_language": langs[0],
                "access_requests_enabled": s.portal.access_requests_enabled, "setup_required": !done, "brands": brands,
                "portal_name": s.branding.portal_name, "favicon_url": null, "theme": s.branding.theme, "login": null}))
        })
        .await?;
    Ok(ok(&out))
}

pub async fn public_logo(State(app): State<App>, method: Method, headers: HeaderMap) -> Res {
    let s = app.settings().await?;
    if s.logo_sha.is_empty() {
        return Err(Problem::new("not_found", "No logo."));
    }
    let mut r =
        super::protocol::serve_blob(&app, &headers, &method, &s.logo_sha, &s.logo_type, "").await?;
    r.headers_mut().insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("public, max-age=86400"),
    );
    Ok(r)
}

// ---- settings --------------------------------------------------------------------------

fn settings_json(app: &App, s: &Settings) -> Value {
    let mut m = to_value(s);
    if let Some(o) = m.as_object_mut() {
        for k in ["logo_sha", "logo_type", "favicon_sha", "favicon_type"] {
            o.remove(k);
        }
    }
    let base = &app.cfg.public_url;
    m["branding"]["logo_url"] = json!(
        (!s.logo_sha.is_empty())
            .then(|| format!("{base}/admin/api/public/logo?v={}", &s.logo_sha[..16]))
    );
    m["branding"]["favicon_url"] = Value::Null;
    m["node"] = json!({"public_url": base, "discovery_url": format!("{base}/.well-known/obx"), "software": crate::app::SOFTWARE,
        "version": crate::app::VERSION, "email_configured": false, "renditions_server_generated": true,
        "max_upload_bytes": crate::app::MAX_UPLOAD_BYTES,
        "custom_domain_help": "Point a DNS record for your domain at this server, make sure HTTPS works for it (Caddy in front does this), and set `OBX_PUBLIC_URL` to the new address."});
    m
}

pub async fn settings_get(State(app): State<App>, method: Method, headers: HeaderMap) -> Res {
    admin_guard(&app, &headers, &method, "admin").await?;
    let s = app.settings().await?;
    Ok(ok(&settings_json(&app, &s)))
}

fn apply_settings_patch(cur: &Settings, mut patch: Map<String, Value>) -> Result<Settings> {
    patch.remove("node");
    if let Some(Value::Object(b)) = patch.get_mut("branding") {
        b.remove("logo_url");
        b.remove("favicon_url");
    }
    let mut base = to_value(cur);
    crate::catalog::merge_patch(&mut base, &Value::Object(patch));
    let mut next: Settings = serde_json::from_value(base)
        .map_err(|e| Problem::new("validation_failed", format!("Settings are not valid: {e}")))?;
    next.logo_sha = cur.logo_sha.clone();
    next.logo_type = cur.logo_type.clone();
    let mut p = Problem::new("validation_failed", "Please check the highlighted fields.");
    if next.company.name.trim().is_empty() {
        p = p.field("/company/name", "validation_failed", "required");
    }
    if next.branding.display_name.is_empty() {
        next.branding.display_name = next.company.name.clone();
    }
    if next
        .branding
        .accent_color
        .as_deref()
        .is_some_and(|c| !is_hex_color(c))
    {
        p = p.field("/branding/accent_color", "validation_failed", "#rrggbb");
    }
    if next
        .company
        .contact_email
        .as_deref()
        .is_some_and(|e| !valid_email(&norm_email(e)))
    {
        p = p.field(
            "/company/contact_email",
            "validation_failed",
            "invalid e-mail",
        );
    }
    if let Some(c) = next.company.country.as_mut() {
        *c = c.to_uppercase();
        if c.len() != 2 {
            p = p.field("/company/country", "validation_failed", "two-letter code");
        }
    }
    if next
        .company
        .website
        .as_deref()
        .is_some_and(|w| !w.starts_with("http"))
    {
        p = p.field("/company/website", "validation_failed", "absolute URL");
    }
    if next.portal.languages.is_empty() {
        p = p.field(
            "/portal/languages",
            "validation_failed",
            "at least one language",
        );
    }
    for l in next.portal.languages.iter_mut() {
        *l = obx_format::importfmt::normalize_lang(l);
        if !obx_format::importfmt::valid_lang(l) {
            p = p.clone().field(
                "/portal/languages",
                "validation_failed",
                "language like nl or de-CH",
            );
        }
    }
    next.portal.default_language =
        obx_format::importfmt::normalize_lang(&next.portal.default_language);
    if next.portal.default_language.is_empty() {
        if let Some(f) = next.portal.languages.first() {
            next.portal.default_language = f.clone();
        }
    }
    if !next
        .portal
        .languages
        .contains(&next.portal.default_language)
    {
        next.portal
            .languages
            .insert(0, next.portal.default_language.clone());
    }
    if next.defaults.ingest_status != "published" && next.defaults.ingest_status != "unpublished" {
        p = p.field(
            "/defaults/ingest_status",
            "validation_failed",
            "published or unpublished",
        );
    }
    for e in crate::schemas::validate("Rights", &to_value(&next.defaults.rights)) {
        p = p.field(
            &format!("/defaults/rights{}", e.pointer),
            "validation_failed",
            e.message,
        );
    }
    if next.defaults.rights.license == "custom"
        && next
            .defaults
            .rights
            .license_text
            .as_deref()
            .is_none_or(|t| t.trim().is_empty())
    {
        p = p.field(
            "/defaults/rights/license_text",
            "validation_failed",
            "required for a custom licence",
        );
    }
    for (ptr, v) in [
        (
            "/retention/download_events_days",
            next.retention.download_events_days,
        ),
        ("/retention/audit_log_days", next.retention.audit_log_days),
        (
            "/retention/access_requests_days",
            next.retention.access_requests_days,
        ),
    ] {
        if !(30..=3650).contains(&v) {
            p = p.field(ptr, "validation_failed", "between 30 and 3650 days");
        }
    }
    if !p.errors.is_empty() {
        return Err(p);
    }
    Ok(next)
}

/// Saves settings with their effects: default rights changed → recompute
/// assets; original downloads toggled → grant entries with resync.
pub async fn save_settings(app: &App, cur: Settings, next: Settings) -> Result<()> {
    let rights_changed = to_json(&cur.defaults.rights) != to_json(&next.defaults.rights);
    let orig_changed = cur.portal.allow_original_download != next.portal.allow_original_download;
    app.catalog_write(None, move |w| {
        next.save(w.tx)?;
        w.settings = next;
        if rights_changed {
            w.recompute_all_assets()?;
        }
        if orig_changed {
            let ids: Vec<String> = {
                let mut st =
                    w.tx.prepare("SELECT id FROM retailers WHERE status = 'active'")?;

                st.query_map([], |r| r.get(0))?
                    .collect::<rusqlite::Result<Vec<_>>>()?
            };
            for id in ids {
                w.tx.execute(
                    "UPDATE retailers SET grant_updated_at = ? WHERE id = ?",
                    params![w.now, id],
                )?;
                w.emit_grant(&id, true)?;
            }
        }
        Ok(())
    })
    .await
}

pub async fn settings_patch(
    State(app): State<App>,
    method: Method,
    headers: HeaderMap,
    body: Bytes,
) -> Res {
    admin_guard(&app, &headers, &method, "admin").await?;
    let patch = read_json_object(&headers, &body)?;
    let cur = app.settings().await?;
    let next = apply_settings_patch(&cur, patch)?;
    save_settings(&app, cur, next).await?;
    let s = app.settings().await?;
    Ok(ok(&settings_json(&app, &s)))
}

pub async fn logo_put(
    State(app): State<App>,
    method: Method,
    headers: HeaderMap,
    body: Bytes,
) -> Res {
    admin_guard(&app, &headers, &method, "admin").await?;
    if body.len() > 5 << 20 {
        return Err(Problem::new(
            "payload_too_large",
            "The logo can be at most 5 MB.",
        ));
    }
    let b = app.put_blob(body, None).await?;
    if b.content_type == "image/tiff" {
        return Err(Problem::new(
            "unsupported_media_type",
            "Use a PNG, JPEG or WebP logo.",
        ));
    }
    let cur = app.settings().await?;
    let mut next = cur.clone();
    next.logo_sha = b.sha256;
    next.logo_type = b.content_type;
    save_settings(&app, cur, next).await?;
    Ok(ok(&settings_json(&app, &app.settings().await?)))
}

pub async fn logo_delete(State(app): State<App>, method: Method, headers: HeaderMap) -> Res {
    admin_guard(&app, &headers, &method, "admin").await?;
    let cur = app.settings().await?;
    let mut next = cur.clone();
    next.logo_sha.clear();
    next.logo_type.clear();
    save_settings(&app, cur, next).await?;
    Ok(ok(&settings_json(&app, &app.settings().await?)))
}

// ---- catalog -----------------------------------------------------------------------------

pub async fn catalog_brands(State(app): State<App>, method: Method, headers: HeaderMap) -> Res {
    admin_guard(&app, &headers, &method, "admin").await?;
    let items = app
        .db
        .read(|c| {
            let s = Settings::load(c)?;
            let rows = crate::catalog::load_rows(c, KIND_BRAND, "ORDER BY name, id", &[])?;
            let mut out = Vec::new();
            for r in rows {
                let n: i64 = c.query_row(
                    "SELECT COUNT(*) FROM products WHERE brand_id = ?",
                    [&r.id],
                    |x| x.get(0),
                )?;
                let mut rec = crate::catalog::record(c, &r, &s);
                rec["product_count"] = json!(n);
                out.push(rec);
            }
            Ok(out)
        })
        .await?;
    Ok(ok(&json!({"items": items})))
}

pub async fn catalog_product(
    State(app): State<App>,
    Path((seg, ext)): Path<(String, String)>,
    method: Method,
    headers: HeaderMap,
) -> Res {
    admin_guard(&app, &headers, &method, "admin").await?;
    if seg != "products" {
        return Err(Problem::new(
            "method_not_allowed",
            "Read variants and assets through their product.",
        ));
    }
    let out = app
        .db
        .read(move |c| {
            let s = Settings::load(c)?;
            let Some(p) = crate::catalog::load_row(c, KIND_PRODUCT, &ext)? else {
                return Ok(None);
            };
            let vs = crate::catalog::load_rows(
                c,
                KIND_VARIANT,
                "WHERE product_id = ? ORDER BY external_id",
                &[&p.id],
            )?;
            let w = format!("WHERE product_id = ?{}", crate::catalog::ASSET_ORDER);
            let as_ = crate::catalog::load_rows(c, KIND_ASSET, &w, &[&p.id])?;
            let mut rec = crate::catalog::record(c, &p, &s);
            rec["variants"] = Value::Array(
                vs.iter()
                    .map(|v| crate::catalog::record(c, v, &s))
                    .collect(),
            );
            rec["assets"] = Value::Array(
                as_.iter()
                    .map(|a| crate::catalog::record(c, a, &s))
                    .collect(),
            );
            Ok(Some(rec))
        })
        .await?;
    out.map(|o| ok(&o))
        .ok_or_else(|| Problem::new("not_found", "Product not found."))
}

pub async fn catalog_products(
    State(app): State<App>,
    Query(q): Query<HashMap<String, String>>,
    method: Method,
    headers: HeaderMap,
) -> Res {
    admin_guard(&app, &headers, &method, "admin").await?;
    let limit = limit_param(&q, 50, 200)?;
    let search = q
        .get("q")
        .map(|s| s.trim().to_lowercase())
        .filter(|s| !s.is_empty());
    let after = q
        .get("cursor")
        .and_then(|c| app.decode_cursor::<Value>("admin-products", c));
    let a = app.clone();
    let out = app
        .db
        .read(move |c| {
            let s = Settings::load(c)?;
            let mut w = String::from("WHERE 1 = 1");
            let mut args: Vec<String> = vec![];
            if let Some(sq) = search {
                w.push_str(" AND search_text LIKE ?");
                args.push(format!("%{sq}%"));
            }
            let total: i64 = c.query_row(
                &format!("SELECT COUNT(*) FROM products {w}"),
                rusqlite::params_from_iter(args.iter()),
                |r| r.get(0),
            )?;
            if let Some(cur) = after {
                w.push_str(" AND (style_number > ? OR (style_number = ? AND id > ?))");
                let sn = cur["s"].as_str().unwrap_or("").to_string();
                args.push(sn.clone());
                args.push(sn);
                args.push(cur["i"].as_str().unwrap_or("").to_string());
            }
            let q = format!(
                "SELECT id FROM products {w} ORDER BY style_number, id LIMIT {}",
                limit + 1
            );
            let mut st = c.prepare(&q)?;
            let ids = st
                .query_map(rusqlite::params_from_iter(args.iter()), |r| {
                    r.get::<_, String>(0)
                })?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            let mut items = Vec::new();
            let mut last = None;
            for id in ids.iter().take(limit) {
                if let Some(r) = crate::catalog::load_row_by_id(c, KIND_PRODUCT, id)? {
                    let d: ProductData = serde_json::from_str(&r.data).unwrap_or_default();
                    last = Some(json!({"s": d.style_number, "i": r.id}));
                    let n = |q: &str| c.query_row(q, [&r.id], |x| x.get::<_, i64>(0));
                    let vc = n("SELECT COUNT(*) FROM variants WHERE product_id = ?")?;
                    let ac = n("SELECT COUNT(*) FROM assets WHERE product_id = ?")?;
                    let pc = n("SELECT COUNT(*) FROM assets WHERE product_id = ? AND (pending = 1 OR live_files IS NULL)")?;
                    let live: Option<String> = c
                        .query_row(
                            &format!("SELECT live_files FROM assets WHERE product_id = ? AND live_files IS NOT NULL{} LIMIT 1", crate::catalog::ASSET_ORDER),
                            [&r.id],
                            |x| x.get(0),
                        )
                        .optional()?;
                    let thumb = live
                        .and_then(|l| serde_json::from_str::<Value>(&l).ok())
                        .and_then(|f| f["thumb"]["sha256"].as_str().map(|sha| format!("{}/admin/api/files/{sha}", a.cfg.public_url)));
                    let _ = &s;
                    items.push(json!({"id": r.id, "external_id": r.external_id, "brand_external_id": d.brand_external_id,
                        "style_number": d.style_number, "name": d.name, "status": r.status,
                        "visibility": if r.visible { "visible" } else { "hidden" }, "variant_count": vc, "asset_count": ac,
                        "pending_asset_count": pc, "thumb_url": thumb, "updated_at": r.record_updated_at}));
                }
            }
            let next = if ids.len() > limit {
                last.map(|l| a.encode_cursor("admin-products", &l))
            } else {
                None
            };
            Ok(json!({"items": items, "next_cursor": next, "total": total}))
        })
        .await?;
    Ok(ok(&out))
}

fn kind_of(seg: &str) -> Result<&'static str> {
    kind_from_segment(seg).ok_or_else(|| Problem::new("not_found", "Not found."))
}

pub async fn catalog_put(
    State(app): State<App>,
    Path((seg, ext)): Path<(String, String)>,
    method: Method,
    headers: HeaderMap,
    body: Bytes,
) -> Res {
    admin_guard(&app, &headers, &method, "admin").await?;
    let kind = kind_of(&seg)?;
    super::ingest::put_record(
        &app,
        kind,
        ext,
        &headers,
        &body,
        None,
        format!("{}/admin/api/catalog/{seg}", app.cfg.public_url),
    )
    .await
}

pub async fn catalog_patch(
    State(app): State<App>,
    Path((seg, ext)): Path<(String, String)>,
    method: Method,
    headers: HeaderMap,
    body: Bytes,
) -> Res {
    admin_guard(&app, &headers, &method, "admin").await?;
    super::ingest::patch_record(&app, kind_of(&seg)?, ext, &headers, &body, None).await
}

pub async fn catalog_delete(
    State(app): State<App>,
    Path((seg, ext)): Path<(String, String)>,
    method: Method,
    headers: HeaderMap,
) -> Res {
    admin_guard(&app, &headers, &method, "admin").await?;
    super::ingest::delete_record(&app, kind_of(&seg)?, ext, None).await
}

pub async fn catalog_asset_order(
    State(app): State<App>,
    Path(ext): Path<String>,
    method: Method,
    headers: HeaderMap,
    body: Bytes,
) -> Res {
    admin_guard(&app, &headers, &method, "admin").await?;
    super::ingest::asset_order(&app, ext, &headers, &body, None).await
}

pub async fn catalog_put_file(
    State(app): State<App>,
    Path((ext, name)): Path<(String, String)>,
    method: Method,
    headers: HeaderMap,
    body: Bytes,
) -> Res {
    admin_guard(&app, &headers, &method, "admin").await?;
    super::ingest::put_file(&app, ext, name, &headers, body, None).await
}

pub async fn catalog_head_blob(
    State(app): State<App>,
    Path(sha): Path<String>,
    method: Method,
    headers: HeaderMap,
) -> Res {
    admin_guard(&app, &headers, &method, "admin").await?;
    Ok(super::ingest::head_blob(&app, &sha).await)
}

pub async fn catalog_put_blob(
    State(app): State<App>,
    Path(sha): Path<String>,
    method: Method,
    headers: HeaderMap,
    body: Bytes,
) -> Res {
    admin_guard(&app, &headers, &method, "admin").await?;
    super::ingest::put_blob(&app, &sha, body).await
}

/// An admin's own files (previews of unpublished images).
pub async fn admin_file(
    State(app): State<App>,
    Path(sha): Path<String>,
    method: Method,
    headers: HeaderMap,
) -> Res {
    admin_guard(&app, &headers, &method, "admin").await?;
    let Some(b) = app.get_blob(&sha).await? else {
        return Err(Problem::new("not_found", "File not found."));
    };
    super::protocol::serve_blob(&app, &headers, &method, &b.sha256, &b.content_type, "").await
}

// ---- retailers ---------------------------------------------------------------------------

fn retailer_json(c: &Connection, r: &RetailerRow) -> Result<Value> {
    let users: i64 = c.query_row(
        "SELECT COUNT(*) FROM users WHERE retailer_id = ?",
        [&r.id],
        |x| x.get(0),
    )?;
    let clients: i64 = c.query_row(
        "SELECT COUNT(*) FROM api_clients WHERE retailer_id = ? AND status = 'active'",
        [&r.id],
        |x| x.get(0),
    )?;
    Ok(
        json!({"id": r.id, "name": r.name, "reference": r.reference, "website": r.website, "vat_number": r.vat_number,
        "country": r.country, "notes": r.notes, "status": r.status, "brand_ids": r.brand_ids, "allow_original": r.allow_original,
        "user_count": users, "api_client_count": clients, "last_activity_at": r.last_activity_at, "created_at": r.created_at}),
    )
}

fn retailer_input(c: &Connection, doc: &Map<String, Value>, r: &mut RetailerRow) -> Result<()> {
    if let Some(v) = doc.get("name") {
        let s = v.as_str().unwrap_or("").trim().to_string();
        if s.is_empty() || s.len() > 200 {
            return Err(
                Problem::new("validation_failed", "A name is required.").field(
                    "/name",
                    "validation_failed",
                    "required",
                ),
            );
        }
        r.name = s;
    }
    for (k, max) in [
        ("reference", 100),
        ("website", 2048),
        ("vat_number", 32),
        ("country", 2),
        ("notes", 5000),
    ] {
        let Some(v) = doc.get(k) else { continue };
        let val = match v {
            Value::Null => None,
            Value::String(s) if s.len() <= max || k == "country" => {
                Some(s.trim().to_string()).filter(|s| !s.is_empty())
            }
            _ => {
                return Err(Problem::new(
                    "validation_failed",
                    format!("{k} must be text of at most {max} characters."),
                )
                .field(&format!("/{k}"), "validation_failed", "invalid"));
            }
        };
        let val = if k == "country" {
            match val.map(|s| s.to_uppercase()) {
                Some(u) if u.len() != 2 => {
                    return Err(Problem::new(
                        "validation_failed",
                        "country must be a two-letter code.",
                    )
                    .field("/country", "validation_failed", "invalid"));
                }
                x => x,
            }
        } else {
            val
        };
        match k {
            "reference" => r.reference = val,
            "website" => r.website = val,
            "vat_number" => r.vat_number = val,
            "country" => r.country = val,
            _ => r.notes = val,
        }
    }
    if let Some(v) = doc.get("status") {
        let s = v.as_str().unwrap_or("");
        if s != "active" && s != "blocked" {
            return Err(
                Problem::new("validation_failed", "status must be active or blocked.").field(
                    "/status",
                    "validation_failed",
                    "invalid",
                ),
            );
        }
        r.status = s.into();
    }
    if let Some(v) = doc.get("brand_ids") {
        match v {
            Value::Null => r.brand_ids = None,
            Value::Array(a) => {
                let mut list = Vec::new();
                for x in a {
                    let s = x.as_str().unwrap_or("");
                    let ok: Option<String> = c
                        .query_row("SELECT id FROM brands WHERE id = ?", [s], |r| r.get(0))
                        .optional()?;
                    if ok.is_none() {
                        return Err(Problem::new(
                            "validation_failed",
                            format!("Unknown brand {s:?}."),
                        )
                        .field(
                            "/brand_ids",
                            "validation_failed",
                            "unknown brand",
                        ));
                    }
                    list.push(s.to_string());
                }
                list.sort();
                r.brand_ids = Some(list);
            }
            _ => {
                return Err(
                    Problem::new("validation_failed", "brand_ids must be a list or null.").field(
                        "/brand_ids",
                        "validation_failed",
                        "invalid",
                    ),
                );
            }
        }
    }
    if let Some(v) = doc.get("allow_original") {
        match v {
            Value::Null => r.allow_original = None,
            Value::Bool(b) => r.allow_original = Some(*b),
            _ => {
                return Err(Problem::new(
                    "validation_failed",
                    "allow_original must be true, false or null.",
                )
                .field("/allow_original", "validation_failed", "invalid"));
            }
        }
    }
    Ok(())
}

pub fn create_retailer(c: &Connection, doc: &Map<String, Value>) -> Result<RetailerRow> {
    if !doc.contains_key("name") {
        return Err(
            Problem::new("validation_failed", "A name is required.").field(
                "/name",
                "validation_failed",
                "required",
            ),
        );
    }
    let now = crate::db::now_str();
    let mut r = RetailerRow {
        id: crate::ids::new("rtl"),
        name: String::new(),
        status: "active".into(),
        grant_updated_at: now.clone(),
        created_at: now.clone(),
        updated_at: now.clone(),
        reference: None,
        website: None,
        vat_number: None,
        country: None,
        notes: None,
        last_activity_at: None,
        brand_ids: None,
        allow_original: None,
    };
    retailer_input(c, doc, &mut r)?;
    c.execute(
        "INSERT INTO retailers (id, name, reference, website, vat_number, country, notes, status, brand_ids, allow_original, created_at, updated_at, grant_updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        params![r.id, r.name, r.reference, r.website, r.vat_number, r.country, r.notes, r.status,
            r.brand_ids.as_ref().map(|b| serde_json::to_string(b).unwrap()), r.allow_original.map(|b| b as i64), now, now, now],
    )?;
    Ok(r)
}

pub async fn retailers(
    State(app): State<App>,
    Query(q): Query<HashMap<String, String>>,
    method: Method,
    headers: HeaderMap,
) -> Res {
    admin_guard(&app, &headers, &method, "admin").await?;
    let limit = limit_param(&q, 50, 200)?;
    let a = app.clone();
    let out = app
        .db
        .read(move |c| {
            let mut w = String::from("WHERE 1 = 1");
            let mut args: Vec<String> = vec![];
            if let Some(s) = q
                .get("q")
                .map(|s| s.trim().to_lowercase())
                .filter(|s| !s.is_empty())
            {
                w.push_str(" AND (LOWER(name) LIKE ? OR LOWER(COALESCE(reference, '')) LIKE ?)");
                args.push(format!("%{s}%"));
                args.push(format!("%{s}%"));
            }
            if let Some(s) = q.get("status").filter(|s| !s.is_empty()) {
                w.push_str(" AND status = ?");
                args.push(s.clone());
            }
            if let Some(cs) = q.get("cursor").filter(|s| !s.is_empty()) {
                let cur: Value = a
                    .decode_cursor("retailers", cs)
                    .ok_or_else(|| Problem::new("cursor_invalid", "The cursor is not valid."))?;
                w.push_str(" AND (LOWER(name) > ? OR (LOWER(name) = ? AND id > ?))");
                let n = cur["n"].as_str().unwrap_or("").to_string();
                args.push(n.clone());
                args.push(n);
                args.push(cur["i"].as_str().unwrap_or("").to_string());
            }
            let mut st = c.prepare(&format!(
                "SELECT id FROM retailers {w} ORDER BY LOWER(name), id LIMIT {}",
                limit + 1
            ))?;
            let ids = st
                .query_map(rusqlite::params_from_iter(args.iter()), |r| {
                    r.get::<_, String>(0)
                })?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            let mut items = Vec::new();
            let mut last = None;
            for id in ids.iter().take(limit) {
                if let Some(r) = load_retailer(c, id)? {
                    items.push(retailer_json(c, &r)?);
                    last = Some(r);
                }
            }
            let next = match (ids.len() > limit, last) {
                (true, Some(l)) => Some(
                    a.encode_cursor("retailers", &json!({"n": l.name.to_lowercase(), "i": l.id})),
                ),
                _ => None,
            };
            Ok(json!({"items": items, "next_cursor": next}))
        })
        .await?;
    Ok(ok(&out))
}

pub async fn retailer_create(
    State(app): State<App>,
    method: Method,
    headers: HeaderMap,
    body: Bytes,
) -> Res {
    admin_guard(&app, &headers, &method, "admin").await?;
    let doc = read_json_object(&headers, &body)?;
    let out = app
        .db
        .write(move |tx| {
            let r = create_retailer(tx, &doc)?;
            retailer_json(tx, &r)
        })
        .await?;
    Ok(json(201, &out))
}

pub async fn retailer_get(
    State(app): State<App>,
    Path(id): Path<String>,
    method: Method,
    headers: HeaderMap,
) -> Res {
    admin_guard(&app, &headers, &method, "admin").await?;
    let out = app
        .db
        .read(move |c| {
            load_retailer(c, &id)?
                .map(|r| retailer_json(c, &r))
                .transpose()
        })
        .await?;
    out.map(|o| ok(&o))
        .ok_or_else(|| Problem::new("not_found", "Retailer not found."))
}

pub async fn retailer_patch(
    State(app): State<App>,
    Path(id): Path<String>,
    method: Method,
    headers: HeaderMap,
    body: Bytes,
) -> Res {
    admin_guard(&app, &headers, &method, "admin").await?;
    let doc = read_json_object(&headers, &body)?;
    let out = app
        .catalog_write(None, move |w| {
            let Some(mut ret) = load_retailer(w.tx, &id)? else { return Err(Problem::new("not_found", "Retailer not found.")) };
            let before = ret.clone();
            retailer_input(w.tx, &doc, &mut ret)?;
            let grant_changed = before.brand_ids != ret.brand_ids
                || before.allow_original != ret.allow_original
                || (before.status != ret.status && ret.status == "active");
            let now = w.now.clone();
            let grant_at = if grant_changed || before.status != ret.status { now.clone() } else { ret.grant_updated_at.clone() };
            w.tx.execute(
                "UPDATE retailers SET name = ?, reference = ?, website = ?, vat_number = ?, country = ?, notes = ?, status = ?, brand_ids = ?, allow_original = ?, updated_at = ?, grant_updated_at = ? WHERE id = ?",
                params![ret.name, ret.reference, ret.website, ret.vat_number, ret.country, ret.notes, ret.status,
                    ret.brand_ids.as_ref().map(|b| serde_json::to_string(b).unwrap()), ret.allow_original.map(|b| b as i64), now, grant_at, ret.id],
            )?;
            if ret.status == "blocked" && before.status != "blocked" {
                w.tx.execute("DELETE FROM sessions WHERE user_id IN (SELECT id FROM users WHERE retailer_id = ?)", [&ret.id])?;
            }
            if grant_changed || before.status != ret.status {
                w.emit_grant(&ret.id, grant_changed)?;
            }
            let r = load_retailer(w.tx, &ret.id)?.unwrap();
            retailer_json(w.tx, &r)
        })
        .await?;
    Ok(ok(&out))
}

// ---- API clients -------------------------------------------------------------------------

pub fn api_client_json(c: &super::protocol::ApiClient) -> Value {
    json!({"id": c.id, "client_id": c.client_id, "name": c.name, "retailer_id": c.retailer_id, "scopes": c.scopes,
        "status": c.status, "created_at": c.created_at, "last_used_at": c.last_used_at})
}

pub fn create_api_client(
    c: &Connection,
    retailer_id: &str,
    name: &str,
    scopes: Option<Vec<String>>,
    created_by: &str,
) -> Result<(super::protocol::ApiClient, String)> {
    let name = name.trim();
    if name.is_empty() || name.len() > 200 {
        return Err(
            Problem::new("validation_failed", "A name is required.").field(
                "/name",
                "validation_failed",
                "required",
            ),
        );
    }
    let Some(ret) = load_retailer(c, retailer_id)? else {
        return Err(
            Problem::new("validation_failed", "Unknown retailer.").field(
                "/retailer_id",
                "validation_failed",
                "unknown retailer",
            ),
        );
    };
    let s = Settings::load(c)?;
    let scopes = scopes.unwrap_or_else(|| {
        let mut v = vec!["catalog:read".to_string(), "media:read".to_string()];
        if original_allowed(&s, &ret) {
            v.push("media:original".into());
        }
        v
    });
    let mut clean: Vec<String> = Vec::new();
    for x in scopes {
        if !super::protocol::ALL_SCOPES.contains(&x.as_str()) {
            return Err(
                Problem::new("validation_failed", format!("Unknown scope {x:?}.")).field(
                    "/scopes",
                    "validation_failed",
                    "unknown scope",
                ),
            );
        }
        if !clean.contains(&x) {
            clean.push(x);
        }
    }
    clean.sort();
    let secret = secure::token("obxs_");
    let cl = super::protocol::ApiClient {
        id: crate::ids::new("cli"),
        client_id: format!("obxc_{}", secure::random_string(16)),
        secret_hash: secure::hash_token(&secret),
        retailer_id: retailer_id.into(),
        name: name.into(),
        status: "active".into(),
        created_by: created_by.into(),
        created_at: crate::db::now_str(),
        version: 1,
        scopes: clean,
        last_used_at: None,
    };
    c.execute(
        "INSERT INTO api_clients (id, client_id, secret_hash, secret_version, retailer_id, name, scopes, status, created_by, created_at) VALUES (?, ?, ?, 1, ?, ?, ?, 'active', ?, ?)",
        params![cl.id, cl.client_id, cl.secret_hash, cl.retailer_id, cl.name, cl.scopes.join(" "), created_by, cl.created_at],
    )?;
    Ok((cl, secret))
}

fn client_with_secret(app: &App, c: &super::protocol::ApiClient, secret: &str) -> Value {
    let base = &app.cfg.public_url;
    json!({"client": api_client_json(c), "client_secret": secret, "token_endpoint": format!("{base}/obx/v1/oauth/token"),
        "discovery_url": format!("{base}/.well-known/obx")})
}

pub async fn api_clients(
    State(app): State<App>,
    Query(q): Query<HashMap<String, String>>,
    method: Method,
    headers: HeaderMap,
) -> Res {
    admin_guard(&app, &headers, &method, "admin").await?;
    let rid = q.get("retailer_id").cloned().unwrap_or_default();
    let items = app
        .db
        .read(move |c| {
            let (w, args): (&str, Vec<String>) = if rid.is_empty() {
                ("", vec![])
            } else {
                (" WHERE retailer_id = ?", vec![rid])
            };
            let mut st = c.prepare(&format!(
                "SELECT id FROM api_clients{w} ORDER BY created_at"
            ))?;
            let ids = st
                .query_map(rusqlite::params_from_iter(args.iter()), |r| {
                    r.get::<_, String>(0)
                })?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            let mut out = vec![];
            for id in ids {
                if let Some(cl) = super::protocol::load_client(c, "id = ?", &id)? {
                    out.push(api_client_json(&cl));
                }
            }
            Ok(out)
        })
        .await?;
    Ok(ok(&json!({"items": items})))
}

pub async fn api_client_create(
    State(app): State<App>,
    method: Method,
    headers: HeaderMap,
    body: Bytes,
) -> Res {
    admin_guard(&app, &headers, &method, "admin").await?;
    let b = read_json_object(&headers, &body)?;
    let rid = str_of(&b, "retailer_id");
    let name = str_of(&b, "name");
    let scopes: Option<Vec<String>> = b.get("scopes").and_then(|v| v.as_array()).map(|a| {
        a.iter()
            .filter_map(|x| x.as_str().map(String::from))
            .collect()
    });
    let (cl, secret) = app
        .db
        .write(move |tx| create_api_client(tx, &rid, &name, scopes, "admin"))
        .await?;
    Ok(json(201, &client_with_secret(&app, &cl, &secret)))
}

pub fn rotate_secret(c: &Connection, id: &str) -> Result<String> {
    let secret = secure::token("obxs_");
    c.execute(
        "UPDATE api_clients SET secret_hash = ?, secret_version = secret_version + 1 WHERE id = ?",
        params![secure::hash_token(&secret), id],
    )?;
    c.execute(
        "UPDATE access_requests SET claimed = 1, client_secret_enc = NULL WHERE api_client_id = ? AND client_secret_enc IS NOT NULL",
        [id],
    )?;
    Ok(secret)
}

pub async fn api_client_rotate(
    State(app): State<App>,
    Path(id): Path<String>,
    method: Method,
    headers: HeaderMap,
) -> Res {
    admin_guard(&app, &headers, &method, "admin").await?;
    let (cl, secret) = app
        .db
        .write(move |tx| {
            let Some(mut cl) =
                super::protocol::load_client(tx, "id = ?", &id)?.filter(|c| c.status == "active")
            else {
                return Err(Problem::new("not_found", "API key not found."));
            };
            let s = rotate_secret(tx, &cl.id)?;
            cl.version += 1;
            Ok((cl, s))
        })
        .await?;
    Ok(ok(&client_with_secret(&app, &cl, &secret)))
}

pub async fn api_client_revoke(
    State(app): State<App>,
    Path(id): Path<String>,
    method: Method,
    headers: HeaderMap,
) -> Res {
    admin_guard(&app, &headers, &method, "admin").await?;
    app.db
        .write(move |tx| {
            if super::protocol::load_client(tx, "id = ?", &id)?.is_none() {
                return Err(Problem::new("not_found", "API key not found."));
            }
            tx.execute("UPDATE api_clients SET status = 'revoked' WHERE id = ?", [&id])?;
            tx.execute("UPDATE webhooks SET status = 'disabled' WHERE owner_type = 'client' AND owner_id = ?", [&id])?;
            Ok(())
        })
        .await?;
    Ok(StatusCode::NO_CONTENT.into_response())
}

// ---- ingest tokens -----------------------------------------------------------------------

pub async fn ingest_tokens(State(app): State<App>, method: Method, headers: HeaderMap) -> Res {
    admin_guard(&app, &headers, &method, "admin").await?;
    let items = app
        .db
        .read(|c| {
            let mut st = c.prepare("SELECT id FROM ingest_tokens ORDER BY created_at")?;
            let ids = st
                .query_map([], |r| r.get::<_, String>(0))?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            let mut out = vec![];
            for id in ids {
                if let Some(t) = super::ingest::load_token(c, "id = ?", &id)? {
                    out.push(t.json());
                }
            }
            Ok(out)
        })
        .await?;
    Ok(ok(&json!({"items": items})))
}

pub fn create_ingest_token(
    c: &Connection,
    name: &str,
    scopes: Vec<String>,
    brands: Option<Vec<String>>,
    expires_at: Option<String>,
) -> Result<(super::ingest::IngestToken, String)> {
    let name = name.trim();
    if name.is_empty() || name.len() > 200 {
        return Err(
            Problem::new("validation_failed", "A name is required.").field(
                "/name",
                "validation_failed",
                "required",
            ),
        );
    }
    if scopes.is_empty() {
        return Err(
            Problem::new("validation_failed", "Choose at least one scope.").field(
                "/scopes",
                "validation_failed",
                "required",
            ),
        );
    }
    for s in &scopes {
        if !["ingest:read", "ingest:write", "ingest:delete"].contains(&s.as_str()) {
            return Err(
                Problem::new("validation_failed", format!("Unknown scope {s:?}.")).field(
                    "/scopes",
                    "validation_failed",
                    "unknown scope",
                ),
            );
        }
    }
    let exp = match expires_at {
        None => None,
        Some(e) => Some(crate::db::fmt_time(crate::db::parse_time(&e).ok_or_else(
            || {
                Problem::new(
                    "validation_failed",
                    "expires_at must be an RFC 3339 timestamp.",
                )
                .field("/expires_at", "validation_failed", "invalid")
            },
        )?)),
    };
    let secret = secure::token("obxi_");
    let t = super::ingest::IngestToken {
        id: crate::ids::new("itk"),
        name: name.into(),
        prefix: secret[..12].into(),
        status: "active".into(),
        created_at: crate::db::now_str(),
        scopes,
        brand_external_ids: brands,
        expires_at: exp,
        last_used_at: None,
    };
    c.execute(
        "INSERT INTO ingest_tokens (id, name, prefix, token_hash, scopes, brand_external_ids, status, expires_at, created_at) VALUES (?, ?, ?, ?, ?, ?, 'active', ?, ?)",
        params![t.id, t.name, t.prefix, secure::hash_token(&secret), t.scopes.join(" "),
            t.brand_external_ids.as_ref().map(|b| serde_json::to_string(b).unwrap()), t.expires_at, t.created_at],
    )?;
    Ok((t, secret))
}

pub async fn ingest_token_create(
    State(app): State<App>,
    method: Method,
    headers: HeaderMap,
    body: Bytes,
) -> Res {
    admin_guard(&app, &headers, &method, "admin").await?;
    let b = read_json_object(&headers, &body)?;
    let list = |k: &str| -> Option<Vec<String>> {
        b.get(k).and_then(|v| v.as_array()).map(|a| {
            a.iter()
                .filter_map(|x| x.as_str().map(String::from))
                .collect()
        })
    };
    let (name, scopes, brands) = (
        str_of(&b, "name"),
        list("scopes").unwrap_or_default(),
        list("brand_external_ids"),
    );
    let exp = b
        .get("expires_at")
        .and_then(|v| v.as_str())
        .map(String::from);
    let (t, secret) = app
        .db
        .write(move |tx| create_ingest_token(tx, &name, scopes, brands, exp))
        .await?;
    Ok(json(
        201,
        &json!({"token": t.json(), "secret": secret, "ingest_url": format!("{}/obx/v1/ingest", app.cfg.public_url)}),
    ))
}

pub async fn ingest_token_rotate(
    State(app): State<App>,
    Path(id): Path<String>,
    method: Method,
    headers: HeaderMap,
) -> Res {
    admin_guard(&app, &headers, &method, "admin").await?;
    let (t, secret) = app
        .db
        .write(move |tx| {
            let Some(mut t) =
                super::ingest::load_token(tx, "id = ?", &id)?.filter(|t| t.status == "active")
            else {
                return Err(Problem::new("not_found", "Token not found."));
            };
            let secret = secure::token("obxi_");
            t.prefix = secret[..12].into();
            tx.execute(
                "UPDATE ingest_tokens SET token_hash = ?, prefix = ? WHERE id = ?",
                params![secure::hash_token(&secret), t.prefix, t.id],
            )?;
            Ok((t, secret))
        })
        .await?;
    Ok(ok(
        &json!({"token": t.json(), "secret": secret, "ingest_url": format!("{}/obx/v1/ingest", app.cfg.public_url)}),
    ))
}

pub async fn ingest_token_revoke(
    State(app): State<App>,
    Path(id): Path<String>,
    method: Method,
    headers: HeaderMap,
) -> Res {
    admin_guard(&app, &headers, &method, "admin").await?;
    let n = app
        .db
        .write(move |tx| {
            Ok(tx.execute(
                "UPDATE ingest_tokens SET status = 'revoked' WHERE id = ?",
                [&id],
            )?)
        })
        .await?;
    if n == 0 {
        return Err(Problem::new("not_found", "Token not found."));
    }
    Ok(StatusCode::NO_CONTENT.into_response())
}

// ---- users and invitations ---------------------------------------------------------------

pub fn invite_user(
    app: &App,
    c: &Connection,
    email: &str,
    name: &str,
    role: &str,
    retailer_id: Option<String>,
    lang: &str,
) -> Result<Value> {
    let email = norm_email(email);
    if !valid_email(&email) {
        return Err(
            Problem::new("validation_failed", "Enter a valid e-mail address.").field(
                "/email",
                "validation_failed",
                "invalid e-mail",
            ),
        );
    }
    if load_user(c, "email = ?", &email)?.is_some() {
        return Err(Problem::new(
            "conflict",
            format!("{email} already has an account."),
        ));
    }
    if role != "admin" && role != "retailer" {
        return Err(
            Problem::new("validation_failed", "role must be admin or retailer.").field(
                "/role",
                "validation_failed",
                "invalid",
            ),
        );
    }
    let retailer_id = if role == "retailer" {
        let Some(rid) = retailer_id else {
            return Err(Problem::new(
                "validation_failed",
                "Choose the retailer this person works for.",
            )
            .field("/retailer_id", "validation_failed", "required"));
        };
        if load_retailer(c, &rid)?.is_none() {
            return Err(
                Problem::new("validation_failed", "Unknown retailer.").field(
                    "/retailer_id",
                    "validation_failed",
                    "unknown retailer",
                ),
            );
        }
        Some(rid)
    } else {
        None
    };
    let lang = if lang.is_empty() {
        Settings::load(c)?.portal.default_language
    } else {
        lang.to_string()
    };
    let lang = supported_lang(&lang);
    let name = if name.trim().is_empty() {
        email.split('@').next().unwrap_or("").to_string()
    } else {
        name.trim().to_string()
    };
    let token = secure::random_string(32);
    let exp = crate::db::fmt_time(chrono::Utc::now() + chrono::Duration::days(INVITE_TTL_DAYS));
    let id = crate::ids::new("usr");
    let now = crate::db::now_str();
    c.execute(
        "INSERT INTO users (id, email, name, role, retailer_id, status, language, invite_hash, invite_expires_at, created_at) VALUES (?, ?, ?, ?, ?, 'invited', ?, ?, ?, ?)",
        params![id, email, name, role, retailer_id, lang, secure::hash_token(&token), exp, now],
    )?;
    let u = load_user(c, "id = ?", &id)?.unwrap();
    let link = format!("{}/invite/{token}", app.cfg.public_url);
    tracing::info!(user = %u.id, "invitation created; e-mail is not configured, share the link from the admin");
    if app.cfg.mail_log_bodies {
        tracing::info!(to = %email, link = %link, "invitation e-mail");
    }
    Ok(json!({"user": u.json(), "invite_url": link, "expires_at": exp, "email_sent": false}))
}

pub async fn user_invite(
    State(app): State<App>,
    method: Method,
    headers: HeaderMap,
    body: Bytes,
) -> Res {
    admin_guard(&app, &headers, &method, "admin").await?;
    let b = read_json_object(&headers, &body)?;
    let a = app.clone();
    let out = app
        .db
        .write(move |tx| {
            invite_user(
                &a,
                tx,
                &str_of(&b, "email"),
                &str_of(&b, "name"),
                &str_of(&b, "role"),
                b.get("retailer_id")
                    .and_then(|v| v.as_str())
                    .map(String::from),
                &str_of(&b, "language"),
            )
        })
        .await?;
    Ok(json(201, &out))
}

pub async fn users(
    State(app): State<App>,
    Query(q): Query<HashMap<String, String>>,
    method: Method,
    headers: HeaderMap,
) -> Res {
    admin_guard(&app, &headers, &method, "admin").await?;
    let items = app
        .db
        .read(move |c| {
            let (w, args): (&str, Vec<String>) = match q.get("retailer_id") {
                Some(r) if !r.is_empty() => (" WHERE retailer_id = ?", vec![r.clone()]),
                _ => match q.get("role") {
                    Some(r) if !r.is_empty() => (" WHERE role = ?", vec![r.clone()]),
                    _ => ("", vec![]),
                },
            };
            let mut st = c.prepare(&format!("SELECT id FROM users{w} ORDER BY created_at"))?;
            let ids = st
                .query_map(rusqlite::params_from_iter(args.iter()), |r| {
                    r.get::<_, String>(0)
                })?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            let mut out = vec![];
            for id in ids {
                if let Some(u) = load_user(c, "id = ?", &id)? {
                    out.push(u.json());
                }
            }
            Ok(out)
        })
        .await?;
    Ok(ok(&json!({"items": items, "next_cursor": null})))
}

pub async fn invite_get(
    State(app): State<App>,
    Path(token): Path<String>,
    method: Method,
    headers: HeaderMap,
) -> Res {
    admin_guard(&app, &headers, &method, "public").await?;
    let h = secure::hash_token(&token);
    let u = app
        .db
        .read(move |c| load_user(c, "invite_hash = ?", &h))
        .await?;
    match u.filter(|u| {
        u.invite_expires_at
            .as_deref()
            .and_then(crate::db::parse_time)
            .is_some_and(|t| t > chrono::Utc::now())
    }) {
        Some(u) => Ok(ok(
            &json!({"email": u.email, "name": u.name, "role": u.role, "language": u.language}),
        )),
        None => Err(Problem::new(
            "invite_invalid",
            "This invitation link is unknown, used or expired.",
        )),
    }
}

pub async fn invite_accept(
    State(app): State<App>,
    Path(token): Path<String>,
    method: Method,
    headers: HeaderMap,
    body: Bytes,
) -> Res {
    admin_guard(&app, &headers, &method, "public").await?;
    let b = read_json_object(&headers, &body)?;
    let password = str_of(&b, "password");
    if let Some(reason) = secure::password_problem(&password) {
        return Err(Problem::new("validation_failed", reason).field(
            "/password",
            "validation_failed",
            reason,
        ));
    }
    let hash = tokio::task::spawn_blocking(move || secure::hash_password(&password))
        .await
        .map_err(Problem::internal)?;
    let h = secure::hash_token(&token);
    let h2 = headers.clone();
    let (sid, csrf, out) = app
        .db
        .write(move |tx| {
            let Some(u) = load_user(tx, "invite_hash = ?", &h)?
                .filter(|u| u.invite_expires_at.as_deref().and_then(crate::db::parse_time).is_some_and(|t| t > chrono::Utc::now()))
            else {
                return Err(Problem::new("invite_invalid", "This invitation link is unknown, used or expired."));
            };
            let name = b.get("name").and_then(|v| v.as_str()).map(str::trim).filter(|s| !s.is_empty()).unwrap_or(&u.name).to_string();
            let lang = b.get("language").and_then(|v| v.as_str()).map(supported_lang).unwrap_or(u.language.clone());
            tx.execute(
                "UPDATE users SET password_hash = ?, status = 'active', invite_hash = NULL, invite_expires_at = NULL, name = ?, language = ? WHERE id = ?",
                params![hash, name, lang, u.id],
            )?;
            let (sid, csrf) = start_session(tx, &h2, &u.id)?;
            let u = load_user(tx, "id = ?", &u.id)?.unwrap();
            let out = session_json(tx, Some(&u), &csrf, false)?;
            Ok((sid, csrf, out))
        })
        .await?;
    Ok(session_response(&app, 200, &out, &sid, &csrf))
}

// ---- access requests ---------------------------------------------------------------------

pub async fn access_requests(
    State(app): State<App>,
    Query(q): Query<HashMap<String, String>>,
    method: Method,
    headers: HeaderMap,
) -> Res {
    admin_guard(&app, &headers, &method, "admin").await?;
    let limit = limit_param(&q, 50, 200)?;
    let a = app.clone();
    let out = app
        .db
        .read(move |c| {
            let mut w = String::from("WHERE 1 = 1");
            let mut args: Vec<String> = vec![];
            if let Some(s) = q.get("status").filter(|s| !s.is_empty()) {
                w.push_str(" AND status = ?");
                args.push(s.clone());
            }
            if let Some(cs) = q.get("cursor").filter(|s| !s.is_empty()) {
                let cur: Value = a
                    .decode_cursor("access-requests", cs)
                    .ok_or_else(|| Problem::new("cursor_invalid", "The cursor is not valid."))?;
                w.push_str(" AND (created_at < ? OR (created_at = ? AND id < ?))");
                let ca = cur["c"].as_str().unwrap_or("").to_string();
                args.push(ca.clone());
                args.push(ca);
                args.push(cur["i"].as_str().unwrap_or("").to_string());
            }
            let mut st = c.prepare(&format!(
                "SELECT id FROM access_requests {w} ORDER BY created_at DESC, id DESC LIMIT {}",
                limit + 1
            ))?;
            let ids = st
                .query_map(rusqlite::params_from_iter(args.iter()), |r| {
                    r.get::<_, String>(0)
                })?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            let mut items = vec![];
            let mut last = None;
            for id in ids.iter().take(limit) {
                if let Some(ar) = super::access::load(c, id)? {
                    items.push(ar.admin_json());
                    last = Some(ar);
                }
            }
            let next = match (ids.len() > limit, last) {
                (true, Some(l)) => {
                    Some(a.encode_cursor("access-requests", &json!({"c": l.created_at, "i": l.id})))
                }
                _ => None,
            };
            Ok(json!({"items": items, "next_cursor": next}))
        })
        .await?;
    Ok(ok(&out))
}

pub async fn access_request(
    State(app): State<App>,
    Path(id): Path<String>,
    method: Method,
    headers: HeaderMap,
) -> Res {
    admin_guard(&app, &headers, &method, "admin").await?;
    let ar = app.db.read(move |c| super::access::load(c, &id)).await?;
    ar.map(|a| ok(&a.admin_json()))
        .ok_or_else(|| Problem::new("not_found", "Access request not found."))
}

fn optional_object(headers: &HeaderMap, body: &[u8]) -> Result<Map<String, Value>> {
    if body.iter().all(|b| b.is_ascii_whitespace()) {
        return Ok(Map::new());
    }
    read_json_object(headers, body)
}

pub async fn access_approve(
    State(app): State<App>,
    Path(id): Path<String>,
    method: Method,
    headers: HeaderMap,
    body: Bytes,
) -> Res {
    admin_guard(&app, &headers, &method, "admin").await?;
    let raw = optional_object(&headers, &body)?;
    let a = app.clone();
    let out = app
        .db
        .write(move |tx| {
            let Some(ar) = super::access::load(tx, &id)? else { return Err(Problem::new("not_found", "Access request not found.")) };
            if ar.status != "pending" {
                return Err(Problem::new("conflict", format!("This request was already {}.", ar.status)));
            }
            let invite = raw.get("invite_portal_user").and_then(|v| v.as_bool()).unwrap_or(ar.wants("portal"));
            let create_client = raw.get("create_api_client").and_then(|v| v.as_bool()).unwrap_or(ar.wants("api"));
            let brand_ids: Option<Value> = if raw.contains_key("brand_ids") {
                raw.get("brand_ids").cloned()
            } else {
                ar.requested_brand_ids.as_ref().filter(|b| !b.is_empty()).map(|b| json!(b))
            };
            let retailer_id = match raw.get("retailer_id").and_then(|v| v.as_str()) {
                Some(rid) => match load_retailer(tx, rid)? {
                    Some(r) => r.id,
                    None => return Err(Problem::new("validation_failed", "Unknown retailer.")),
                },
                None => {
                    let mut input = Map::new();
                    for k in ["name", "reference", "website", "vat_number", "country"] {
                        input.insert(k.into(), ar.retailer.get(k).cloned().unwrap_or(Value::Null));
                    }
                    if let Some(b) = &brand_ids {
                        if !b.is_null() {
                            input.insert("brand_ids".into(), b.clone());
                        }
                    }
                    create_retailer(tx, &input)?.id
                }
            };
            let mut out = json!({});
            let email = ar.contact.get("email").and_then(|v| v.as_str()).unwrap_or("").to_string();
            let cname = ar.contact.get("name").and_then(|v| v.as_str()).unwrap_or("").to_string();
            let lang = ar.contact.get("language").and_then(|v| v.as_str()).unwrap_or("").to_string();
            let mut invited = false;
            if invite && !email.is_empty() {
                if let Ok(res) = invite_user(&a, tx, &email, &cname, "retailer", Some(retailer_id.clone()), &lang) {
                    out["invite"] = res;
                    invited = true;
                }
            }
            let (mut secret_enc, mut client_row) = (None, None);
            if create_client {
                let rname = ar.retailer.get("name").and_then(|v| v.as_str()).unwrap_or("");
                let (cl, secret) = create_api_client(tx, &retailer_id, &format!("API {rname}"), None, "access_request")?;
                secret_enc = Some(a.keys.encrypt(secret.as_bytes()));
                client_row = Some(cl.id.clone());
                out["api_client"] = api_client_json(&cl);
            }
            let n = tx.execute(
                "UPDATE access_requests SET status = 'approved', decided_at = ?, retailer_id = ?, api_client_id = ?, client_secret_enc = ?, invited = ? WHERE id = ? AND status = 'pending'",
                params![crate::db::now_str(), retailer_id, client_row, secret_enc, invited as i64, ar.id],
            )?;
            if n != 1 {
                return Err(Problem::new("conflict", "This request was decided meanwhile."));
            }
            out["access_request"] = super::access::load(tx, &ar.id)?.unwrap().admin_json();
            let r = load_retailer(tx, &retailer_id)?.unwrap();
            out["retailer"] = retailer_json(tx, &r)?;
            Ok(out)
        })
        .await?;
    Ok(ok(&out))
}

pub async fn access_reject(
    State(app): State<App>,
    Path(id): Path<String>,
    method: Method,
    headers: HeaderMap,
    body: Bytes,
) -> Res {
    admin_guard(&app, &headers, &method, "admin").await?;
    let raw = optional_object(&headers, &body)?;
    let reason = raw
        .get("reason")
        .and_then(|v| v.as_str())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());
    if reason.as_ref().is_some_and(|r| r.len() > 2000) {
        return Err(Problem::new(
            "validation_failed",
            "The reason can be at most 2000 characters.",
        ));
    }
    let out = app
        .db
        .write(move |tx| {
            let Some(ar) = super::access::load(tx, &id)? else { return Err(Problem::new("not_found", "Access request not found.")) };
            let n = tx.execute(
                "UPDATE access_requests SET status = 'rejected', decided_at = ?, reason = ? WHERE id = ? AND status = 'pending'",
                params![crate::db::now_str(), reason, ar.id],
            )?;
            if n != 1 {
                return Err(Problem::new("conflict", format!("This request was already {}.", ar.status)));
            }
            Ok(super::access::load(tx, &ar.id)?.unwrap().admin_json())
        })
        .await?;
    Ok(ok(&out))
}

/// GET /admin/api/stats: download statistics are not recorded yet; the
/// shape is node-go's with zero counts.
pub async fn stats(State(app): State<App>, method: Method, headers: HeaderMap) -> Res {
    admin_guard(&app, &headers, &method, "admin").await?;
    let counts = app
        .db
        .read(|c| {
            let n = |q: &str| c.query_row(q, [], |r| r.get::<_, i64>(0));
            Ok(
                json!({"products": n("SELECT COUNT(*) FROM products WHERE visible = 1")?,
                "assets": n("SELECT COUNT(*) FROM assets WHERE visible = 1")?,
                "retailers": n("SELECT COUNT(*) FROM retailers WHERE status = 'active'")?}),
            )
        })
        .await?;
    Ok(ok(
        &json!({"totals": {"downloads": 0, "files": 0, "bytes": 0, "retailers_active": 0}, "catalog": counts,
        "by_day": [], "top_products": [], "top_retailers": [], "by_kind": []}),
    ))
}

// ---- the signed-in person -------------------------------------------------------------

pub async fn me_patch(
    State(app): State<App>,
    method: Method,
    headers: HeaderMap,
    body: Bytes,
) -> Res {
    let s = admin_guard(&app, &headers, &method, "any")
        .await?
        .expect("session");
    let b = read_json_object(&headers, &body)?;
    let mut u = s.user.clone();
    if let Some(n) = b.get("name") {
        let n = n.as_str().unwrap_or("").trim().to_string();
        if n.is_empty() || n.len() > 200 {
            return Err(Problem::new("validation_failed", "A name is required."));
        }
        u.name = n;
    }
    if let Some(l) = b.get("language").and_then(|v| v.as_str()) {
        u.language = supported_lang(l);
    }
    let mut new_hash = None;
    if let Some(np) = b
        .get("new_password")
        .and_then(|v| v.as_str())
        .map(String::from)
    {
        let cur = b
            .get("current_password")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let h = u.password_hash.clone().unwrap_or_default();
        let good =
            tokio::task::spawn_blocking(move || !h.is_empty() && secure::check_password(&h, &cur))
                .await
                .unwrap_or(false);
        if !good {
            return Err(Problem::new(
                "invalid_credentials",
                "Your current password is not correct.",
            ));
        }
        if let Some(reason) = secure::password_problem(&np) {
            return Err(Problem::new("validation_failed", reason).field(
                "/new_password",
                "validation_failed",
                reason,
            ));
        }
        new_hash = Some(
            tokio::task::spawn_blocking(move || secure::hash_password(&np))
                .await
                .map_err(Problem::internal)?,
        );
    }
    let csrf = s.csrf.clone();
    let out = app
        .db
        .write(move |tx| {
            if let Some(h) = new_hash {
                tx.execute(
                    "UPDATE users SET password_hash = ? WHERE id = ?",
                    params![h, u.id],
                )?;
                tx.execute(
                    "DELETE FROM sessions WHERE user_id = ? AND id_hash <> ?",
                    params![u.id, s.id_hash],
                )?;
            }
            tx.execute(
                "UPDATE users SET name = ?, language = ? WHERE id = ?",
                params![u.name, u.language, u.id],
            )?;
            let u = load_user(tx, "id = ?", &u.id)?.unwrap();
            session_json(tx, Some(&u), &csrf, false)
        })
        .await?;
    Ok(ok(&out))
}

/// GET /admin/api/portal/viewer: who is looking at the portal and what
/// they see (the retailer portal itself is on the roadmap).
pub async fn portal_viewer(State(app): State<App>, method: Method, headers: HeaderMap) -> Res {
    let s = admin_guard(&app, &headers, &method, "any")
        .await?
        .expect("session");
    let base = app.cfg.public_url.clone();
    let out = app
        .db
        .read(move |c| {
            let v = viewer_for_user(c, &s.user)?;
            let (bf, args) = v.brand_filter("id");
            let mut st = c.prepare(&format!("SELECT rep, updated_at FROM brands WHERE visible = 1{bf} ORDER BY name"))?;
            let brands = st
                .query_map(rusqlite::params_from_iter(args.iter()), |r| {
                    Ok(super::protocol::render_plain(&r.get::<_, String>(0)?, &r.get::<_, String>(1)?))
                })?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            let st = Settings::load(c)?;
            let retailer = (!v.retailer_id.is_empty()).then(|| json!({"id": v.retailer_id, "name": v.retailer_name}));
            let logo = (!st.logo_sha.is_empty()).then(|| format!("{base}/admin/api/public/logo?v={}", &st.logo_sha[..16]));
            Ok(json!({"preview": v.kind == "admin", "retailer": retailer, "brands": brands,
                "original_allowed": v.original_allowed, "article_data_export": st.portal.allow_article_data_export,
                "api_self_service": st.portal.retailer_api_self_service, "selection_count": 0,
                "branding": {"name": st.display_name(), "logo_url": logo, "accent_color": st.branding.accent_color,
                    "welcome_text": st.branding.welcome_text, "languages": st.content_languages()}}))
        })
        .await?;
    Ok(ok(&out))
}

// ---- scheduled imports and brand webhooks (URL policy only, for now) --------------------

pub async fn empty_list(State(app): State<App>, method: Method, headers: HeaderMap) -> Res {
    admin_guard(&app, &headers, &method, "admin").await?;
    Ok(ok(&json!({"items": [], "next_cursor": null})))
}

/// POST /admin/api/import-sources: the URL is checked (unsafe_url); saving
/// scheduled imports is not implemented yet.
pub async fn import_source_create(
    State(app): State<App>,
    method: Method,
    headers: HeaderMap,
    body: Bytes,
) -> Res {
    admin_guard(&app, &headers, &method, "admin").await?;
    let b = read_json_object(&headers, &body)?;
    let url = b
        .get("config")
        .and_then(|c| c.get("url"))
        .and_then(|u| u.as_str())
        .unwrap_or("")
        .to_string();
    if !url.is_empty() {
        crate::safeurl::check(&url, app.cfg.allow_private_urls).await?;
    }
    Err(Problem::new(
        "not_implemented",
        "Scheduled imports are not available in this release yet; upload files under Imports.",
    ))
}

/// POST /admin/api/webhooks: the URL is checked (unsafe_url); brand
/// webhooks are not implemented yet.
pub async fn brand_webhook_create(
    State(app): State<App>,
    method: Method,
    headers: HeaderMap,
    body: Bytes,
) -> Res {
    admin_guard(&app, &headers, &method, "admin").await?;
    let b = read_json_object(&headers, &body)?;
    let url = b
        .get("url")
        .and_then(|u| u.as_str())
        .unwrap_or("")
        .to_string();
    crate::safeurl::check(&url, app.cfg.allow_private_urls).await?;
    Err(Problem::new(
        "not_implemented",
        "Webhooks are not available in this release yet.",
    ))
}
