//! People and their data: password reset, account edit/block/delete,
//! re-sent invitations, retailer deletion, personal-data export (GDPR
//! articles 15 and 20) and self-service erasure.

use std::net::SocketAddr;

use axum::body::Bytes;
use axum::extract::{ConnectInfo, Path, State};
use axum::http::{HeaderMap, HeaderValue, Method, StatusCode, header};
use axum::response::{IntoResponse, Response};
use rusqlite::{Connection, params};
use serde_json::{Map, Value, json};

use super::admin::{
    SESSION_COOKIE, Session, User, admin_guard, load_user, norm_email, session_json,
    session_response, set_cookie, start_session,
};
use super::*;
use crate::mail;
use crate::secure;

const RESET_TTL_SECS: i64 = 3600;
pub const INVITE_TTL_DAYS: i64 = 7;

fn rate(app: &App, key: &str, n: u32, window: i64, what: &str) -> Result<()> {
    if let Err(retry) = app.limit(key, n, window) {
        let mut p = Problem::new("rate_limited", format!("Too many {what}; try again later."));
        p.retry_after = Some(retry as u64);
        return Err(p);
    }
    Ok(())
}

/// Sends the invitation e-mail of an `invite_user` result after its
/// transaction committed, and sets `email_sent`.
pub async fn send_invite_mail(app: &App, out: &mut Value) {
    let (Some(to), Some(url)) = (
        out["user"]["email"].as_str().map(String::from),
        out["invite_url"].as_str().map(String::from),
    ) else {
        return;
    };
    let lang = out["user"]["language"].as_str().unwrap_or("en").to_string();
    let mut vars = vec![
        (
            "name",
            out["user"]["name"].as_str().unwrap_or("").to_string(),
        ),
        ("url", url),
    ];
    if let Some(t) = out["expires_at"].as_str().and_then(crate::db::parse_time) {
        vars.push(("expires", mail::mail_date(t)));
    }
    let sent = mail::send_mail(app, &to, &lang, mail::MAIL_INVITE, &vars).await;
    out["email_sent"] = json!(sent);
}

// ---- password reset ---------------------------------------------------------------------

/// A one-time reset link for the account (the CLI and the e-mail).
pub fn reset_link(app: &App, c: &Connection, email: &str) -> Result<(User, String)> {
    let Some(u) = load_user(c, "email = ?", &norm_email(email))? else {
        return Err(Problem::new(
            "not_found",
            format!("No account with e-mail {email}."),
        ));
    };
    let token = secure::random_string(32);
    let exp = crate::db::fmt_time(chrono::Utc::now() + chrono::Duration::seconds(RESET_TTL_SECS));
    c.execute(
        "UPDATE users SET reset_hash = ?, reset_expires_at = ? WHERE id = ?",
        params![secure::hash_token(&token), exp, u.id],
    )?;
    Ok((u, format!("{}/reset-password/{token}", app.cfg.public_url)))
}

/// Sets a password directly (CLI) and ends every session.
pub fn set_password(c: &Connection, email: &str, hash: &str) -> Result<()> {
    let Some(u) = load_user(c, "email = ?", &norm_email(email))? else {
        return Err(Problem::new(
            "not_found",
            format!("No account with e-mail {email}."),
        ));
    };
    let status = if u.status == "invited" {
        "active"
    } else {
        u.status.as_str()
    };
    c.execute(
        "UPDATE users SET password_hash = ?, status = ?, reset_hash = NULL, reset_expires_at = NULL, invite_hash = NULL, invite_expires_at = NULL WHERE id = ?",
        params![hash, status, u.id],
    )?;
    c.execute("DELETE FROM sessions WHERE user_id = ?", [&u.id])?;
    Ok(())
}

/// POST /admin/api/password/forgot: always 202, so the answer never tells
/// whether an address has an account.
pub async fn forgot(
    State(app): State<App>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    method: Method,
    headers: HeaderMap,
    body: Bytes,
) -> Res {
    admin_guard(&app, &headers, &method, "public").await?;
    let ip = client_ip(&app, &headers, Some(peer));
    rate(
        &app,
        &format!("forgot:{ip}"),
        5,
        900,
        "password reset requests",
    )?;
    let b = read_json_object(&headers, &body)?;
    let email = norm_email(b.get("email").and_then(|v| v.as_str()).unwrap_or(""));
    let a = app.clone();
    let found = app
        .db
        .write(move |tx| match load_user(tx, "email = ?", &email)? {
            Some(u) if u.status == "active" => Ok(Some(reset_link(&a, tx, &email)?)),
            _ => Ok(None),
        })
        .await?;
    if let Some((u, url)) = found {
        mail::send_mail_later(
            &app,
            u.email.clone(),
            u.language.clone(),
            mail::MAIL_PASSWORD_RESET,
            vec![("name", u.name.clone()), ("url", url)],
        );
    }
    Ok(StatusCode::ACCEPTED.into_response())
}

/// POST /admin/api/password/reset: a new password with the one-time token;
/// signs in and ends every other session.
pub async fn reset(
    State(app): State<App>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    method: Method,
    headers: HeaderMap,
    body: Bytes,
) -> Res {
    admin_guard(&app, &headers, &method, "public").await?;
    let ip = client_ip(&app, &headers, Some(peer));
    rate(&app, &format!("reset:{ip}"), 10, 900, "attempts")?;
    let b = read_json_object(&headers, &body)?;
    let token = b
        .get("token")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let password = b
        .get("password")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let invalid = || {
        Problem::new(
            "invite_invalid",
            "This link is not valid any more. Ask for a new one.",
        )
    };
    let th = secure::hash_token(&token);
    let th2 = th.clone();
    let u = app
        .db
        .read(move |c| load_user(c, "reset_hash = ?", &th2))
        .await?;
    let Some(u) = u.filter(|u| {
        !token.is_empty()
            && u.status != "blocked"
            && u.reset_expires_at
                .as_deref()
                .and_then(crate::db::parse_time)
                .is_some_and(|t| t > chrono::Utc::now())
    }) else {
        return Err(invalid());
    };
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
    let h2 = headers.clone();
    let (sid, csrf, out) = app
        .db
        .write(move |tx| {
            let n = tx.execute(
                "UPDATE users SET password_hash = ?, reset_hash = NULL, reset_expires_at = NULL, status = 'active' WHERE id = ? AND reset_hash = ?",
                params![hash, u.id, th],
            )?;
            if n != 1 {
                return Err(invalid());
            }
            tx.execute("DELETE FROM sessions WHERE user_id = ?", [&u.id])?;
            let (sid, csrf) = start_session(tx, &h2, &u.id)?;
            let u = load_user(tx, "id = ?", &u.id)?.unwrap();
            let out = session_json(tx, Some(&u), &csrf, false)?;
            Ok((sid, csrf, out))
        })
        .await?;
    Ok(session_response(&app, 200, &out, &sid, &csrf))
}

// ---- accounts -----------------------------------------------------------------------------

fn last_admin_guard(c: &Connection, u: &User, me: &User) -> Result<()> {
    if u.id == me.id {
        return Err(Problem::new(
            "conflict",
            "You cannot block or delete your own account.",
        ));
    }
    if u.role == "admin" && u.status == "active" {
        let n: i64 = c.query_row(
            "SELECT COUNT(*) FROM users WHERE role = 'admin' AND status = 'active' AND id <> ?",
            [&u.id],
            |r| r.get(0),
        )?;
        if n == 0 {
            return Err(Problem::new(
                "conflict",
                "This is the last active administrator.",
            ));
        }
    }
    Ok(())
}

fn must_user(c: &Connection, id: &str) -> Result<User> {
    load_user(c, "id = ?", id)?.ok_or_else(|| Problem::new("not_found", "Account not found."))
}

/// PATCH /admin/api/users/{id}: name, and status active or blocked.
pub async fn user_patch(
    State(app): State<App>,
    Path(id): Path<String>,
    method: Method,
    headers: HeaderMap,
    body: Bytes,
) -> Res {
    let s = admin_guard(&app, &headers, &method, "admin")
        .await?
        .expect("session");
    let b = read_json_object(&headers, &body)?;
    let out = app
        .db
        .write(move |tx| {
            let mut u = must_user(tx, &id)?;
            if let Some(n) = b.get("name") {
                let n = n.as_str().unwrap_or("").trim().to_string();
                if n.is_empty() || n.len() > 200 {
                    return Err(Problem::new("validation_failed", "A name is required."));
                }
                u.name = n;
            }
            if let Some(st) = b.get("status") {
                match st.as_str() {
                    Some("blocked") => {
                        last_admin_guard(tx, &u, &s.user)?;
                        u.status = "blocked".into();
                        tx.execute("DELETE FROM sessions WHERE user_id = ?", [&u.id])?;
                    }
                    Some("active") => {
                        if u.status == "blocked" {
                            u.status = if u.password_hash.is_some() {
                                "active"
                            } else {
                                "invited"
                            }
                            .into();
                        }
                    }
                    _ => {
                        return Err(Problem::new(
                            "validation_failed",
                            "status must be active or blocked.",
                        ));
                    }
                }
            }
            tx.execute(
                "UPDATE users SET name = ?, status = ? WHERE id = ?",
                params![u.name, u.status, u.id],
            )?;
            Ok(must_user(tx, &u.id)?.json())
        })
        .await?;
    Ok(ok(&out))
}

/// Deletes a person: account, sessions, prepared downloads and pending
/// e-mails; their name leaves the statistics and their e-mail address the
/// audit log. Returns the download jobs whose files must go.
fn erase_user(c: &Connection, u: &User) -> Result<Vec<String>> {
    let downloads = download_ids(c, "owner_id = ?", &u.id)?;
    for q in [
        "DELETE FROM sessions WHERE user_id = ?",
        "UPDATE download_events SET actor_id = NULL, actor_name = NULL WHERE actor_id = ?",
        "UPDATE audit_log SET actor_name = NULL, actor_email = NULL WHERE actor_id = ?",
        "DELETE FROM job_items WHERE job_id IN (SELECT id FROM jobs WHERE kind = 'download' AND owner_type = 'user' AND owner_id = ?)",
        "DELETE FROM jobs WHERE kind = 'download' AND owner_type = 'user' AND owner_id = ?",
    ] {
        c.execute(q, [&u.id])?;
    }
    c.execute("DELETE FROM mail_outbox WHERE recipient = ?", [&u.email])?;
    c.execute("DELETE FROM users WHERE id = ?", [&u.id])?;
    Ok(downloads)
}

fn download_ids(c: &Connection, where_: &str, arg: &str) -> Result<Vec<String>> {
    let mut st = c.prepare(&format!(
        "SELECT id FROM jobs WHERE kind = 'download' AND owner_type = 'user' AND {where_}"
    ))?;
    let ids = st
        .query_map([arg], |r| r.get::<_, String>(0))?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(ids)
}

async fn delete_download_files(app: &App, ids: Vec<String>) {
    for id in ids {
        let _ = app.store.delete(&format!("downloads/{id}.zip")).await;
    }
}

/// DELETE /admin/api/users/{id}
pub async fn user_delete(
    State(app): State<App>,
    Path(id): Path<String>,
    method: Method,
    headers: HeaderMap,
) -> Res {
    let s = admin_guard(&app, &headers, &method, "admin")
        .await?
        .expect("session");
    let files = app
        .db
        .write(move |tx| {
            let u = must_user(tx, &id)?;
            last_admin_guard(tx, &u, &s.user)?;
            erase_user(tx, &u)
        })
        .await?;
    delete_download_files(&app, files).await;
    Ok(StatusCode::NO_CONTENT.into_response())
}

/// POST /admin/api/users/{id}/resend-invite: a new link (the old one stops
/// working), sent again.
pub async fn user_resend_invite(
    State(app): State<App>,
    Path(id): Path<String>,
    method: Method,
    headers: HeaderMap,
) -> Res {
    admin_guard(&app, &headers, &method, "admin").await?;
    let base = app.cfg.public_url.clone();
    let mut out = app
        .db
        .write(move |tx| {
            let u = must_user(tx, &id)?;
            if u.status != "invited" {
                return Err(Problem::new("conflict", "This account is already active."));
            }
            let token = secure::random_string(32);
            let exp = crate::db::fmt_time(chrono::Utc::now() + chrono::Duration::days(INVITE_TTL_DAYS));
            tx.execute(
                "UPDATE users SET invite_hash = ?, invite_expires_at = ? WHERE id = ?",
                params![secure::hash_token(&token), exp, u.id],
            )?;
            let u = must_user(tx, &u.id)?;
            Ok(json!({"user": u.json(), "invite_url": format!("{base}/invite/{token}"), "expires_at": exp, "email_sent": false}))
        })
        .await?;
    send_invite_mail(&app, &mut out).await;
    Ok(ok(&out))
}

/// DELETE /admin/api/retailers/{id}: everything personal goes (accounts,
/// keys, webhooks, access requests, prepared downloads, pending e-mails);
/// statistics keep the company name, audit entries the action.
pub async fn retailer_delete(
    State(app): State<App>,
    Path(id): Path<String>,
    method: Method,
    headers: HeaderMap,
) -> Res {
    admin_guard(&app, &headers, &method, "admin").await?;
    let files = app
        .db
        .write(move |tx| {
            if load_retailer(tx, &id)?.is_none() {
                return Err(Problem::new("not_found", "Retailer not found."));
            }
            let files = download_ids(tx, "owner_id IN (SELECT id FROM users WHERE retailer_id = ?)", &id)?;
            for q in [
                "DELETE FROM sessions WHERE user_id IN (SELECT id FROM users WHERE retailer_id = ?)",
                "DELETE FROM mail_outbox WHERE recipient IN (SELECT email FROM users WHERE retailer_id = ?)",
                "UPDATE audit_log SET actor_name = NULL, actor_email = NULL WHERE actor_id IN (SELECT id FROM users WHERE retailer_id = ?)",
                "DELETE FROM job_items WHERE job_id IN (SELECT id FROM jobs WHERE kind = 'download' AND owner_type = 'user' AND owner_id IN (SELECT id FROM users WHERE retailer_id = ?))",
                "DELETE FROM jobs WHERE kind = 'download' AND owner_type = 'user' AND owner_id IN (SELECT id FROM users WHERE retailer_id = ?)",
                "DELETE FROM access_requests WHERE retailer_id = ?",
                "DELETE FROM webhook_deliveries WHERE webhook_id IN (SELECT id FROM webhooks WHERE owner_type = 'client' AND owner_id IN (SELECT id FROM api_clients WHERE retailer_id = ?))",
                "DELETE FROM webhooks WHERE owner_type = 'client' AND owner_id IN (SELECT id FROM api_clients WHERE retailer_id = ?)",
                "DELETE FROM api_clients WHERE retailer_id = ?",
                "DELETE FROM users WHERE retailer_id = ?",
                "UPDATE download_events SET actor_id = NULL, actor_name = NULL WHERE retailer_id = ?",
                "DELETE FROM retailers WHERE id = ?",
            ] {
                tx.execute(q, [&id])?;
            }
            Ok(files)
        })
        .await?;
    delete_download_files(&app, files).await;
    Ok(StatusCode::NO_CONTENT.into_response())
}

// ---- personal data ------------------------------------------------------------------------

/// TEXT columns that hold JSON.
const JSON_COLS: [&str; 8] = [
    "brand_ids",
    "scopes",
    "events",
    "access",
    "requested_brand_ids",
    "details",
    "contact",
    "retailer",
];

fn query_maps(c: &Connection, q: &str, args: &[&str]) -> Result<Vec<Value>> {
    let mut st = c.prepare(q)?;
    let cols: Vec<String> = st.column_names().map(|s| s.to_string()).collect();
    let rows = st
        .query_map(rusqlite::params_from_iter(args.iter()), |r| {
            let mut m = Map::new();
            for (i, col) in cols.iter().enumerate() {
                let v = match r.get_ref(i)? {
                    rusqlite::types::ValueRef::Null => Value::Null,
                    rusqlite::types::ValueRef::Integer(n) => json!(n),
                    rusqlite::types::ValueRef::Real(f) => json!(f),
                    rusqlite::types::ValueRef::Text(t) | rusqlite::types::ValueRef::Blob(t) => {
                        let s = String::from_utf8_lossy(t).into_owned();
                        if (JSON_COLS.contains(&col.as_str()) || col == "selection")
                            && (s.starts_with('[') || s.starts_with('{'))
                        {
                            serde_json::from_str(&s).unwrap_or(Value::String(s))
                        } else {
                            Value::String(s)
                        }
                    }
                };
                m.insert(col.clone(), v);
            }
            Ok(Value::Object(m))
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(rows)
}

const USER_COLS: &str = "id, email, name, role, retailer_id, status, language, created_at, last_login_at, invite_expires_at";

/// Everything stored about one retailer, or None.
pub fn retailer_data(c: &Connection, id: &str) -> Result<Option<Map<String, Value>>> {
    let ret = query_maps(
        c,
        "SELECT id, name, reference, website, vat_number, country, notes, status, brand_ids, allow_original, created_at, updated_at, last_activity_at FROM retailers WHERE id = ?",
        &[id],
    )?;
    let Some(r) = ret.into_iter().next() else {
        return Ok(None);
    };
    let mut out = Map::new();
    out.insert("retailer".into(), r);
    for (k, q) in [
        ("users", format!("SELECT {USER_COLS} FROM users WHERE retailer_id = ? ORDER BY created_at")),
        ("api_clients", "SELECT id, client_id, name, scopes, status, created_by, created_at, last_used_at FROM api_clients WHERE retailer_id = ? ORDER BY created_at".into()),
        ("webhooks", "SELECT id, url, events, status, created_at, last_delivery_at, last_status FROM webhooks WHERE owner_type = 'client' AND owner_id IN (SELECT id FROM api_clients WHERE retailer_id = ?) ORDER BY created_at".into()),
        ("access_requests", "SELECT id, status, retailer, contact, access, message, created_at, decided_at, reason FROM access_requests WHERE retailer_id = ? ORDER BY created_at".into()),
        ("download_events", "SELECT at, kind, actor_type, actor_id, actor_name, variant, style_number, asset_id, usage_event, files, bytes FROM download_events WHERE retailer_id = ? ORDER BY at".into()),
        ("audit_log", "SELECT at, actor_name, action, method, route, target_type, target_id, status FROM audit_log WHERE actor_id IN (SELECT id FROM users WHERE retailer_id = ?) ORDER BY at".into()),
    ] {
        out.insert(k.into(), Value::Array(query_maps(c, &q, &[id])?));
    }
    Ok(Some(out))
}

/// Everything stored about one account, or None.
pub fn user_data(c: &Connection, id: &str) -> Result<Option<Map<String, Value>>> {
    let u = query_maps(
        c,
        &format!("SELECT {USER_COLS}, selection, selection_updated_at FROM users WHERE id = ?"),
        &[id],
    )?;
    let Some(u) = u.into_iter().next() else {
        return Ok(None);
    };
    let email = u["email"].as_str().unwrap_or("").to_string();
    let mut out = Map::new();
    out.insert("retailer".into(), Value::Null);
    if let Some(rid) = u["retailer_id"].as_str() {
        if let Some(r) = query_maps(c, "SELECT id, name FROM retailers WHERE id = ?", &[rid])?
            .into_iter()
            .next()
        {
            out.insert("retailer".into(), r);
        }
    }
    out.insert("user".into(), u);
    let like = format!("%{email}%");
    for (k, q, args) in [
        (
            "sessions",
            "SELECT created_at, last_seen_at, expires_at FROM sessions WHERE user_id = ? ORDER BY created_at",
            vec![id],
        ),
        (
            "downloads",
            "SELECT id, status, created_at, finished_at, expires_at FROM jobs WHERE kind = 'download' AND owner_type = 'user' AND owner_id = ? ORDER BY created_at",
            vec![id],
        ),
        (
            "download_events",
            "SELECT at, kind, retailer_name, variant, style_number, asset_id, files, bytes FROM download_events WHERE actor_id = ? ORDER BY at",
            vec![id],
        ),
        (
            "audit_log",
            "SELECT at, action, method, route, target_type, target_id, status FROM audit_log WHERE actor_id = ? OR (target_type = 'user' AND target_id = ?) ORDER BY at",
            vec![id, id],
        ),
        (
            "access_requests",
            "SELECT id, status, retailer, contact, access, message, created_at, decided_at FROM access_requests WHERE contact LIKE ? ORDER BY created_at",
            vec![like.as_str()],
        ),
    ] {
        out.insert(k.into(), Value::Array(query_maps(c, q, &args)?));
    }
    Ok(Some(out))
}

/// The export document (the same format in every OBX portal).
pub fn envelope(c: &Connection, mut data: Map<String, Value>) -> Result<Value> {
    let st = crate::settings::Settings::load(c)?;
    data.insert("format".into(), json!("obx-personal-data-export/1"));
    data.insert("exported_at".into(), json!(crate::db::now_str()));
    data.insert(
        "controller".into(),
        json!({"name": st.company.name, "contact_email": st.company.contact_email, "website": st.company.website}),
    );
    data.insert(
        "retention".into(),
        serde_json::to_value(&st.retention).unwrap_or_default(),
    );
    data.insert("note".into(), json!("Everything this portal stores about you. Passwords, sessions and access keys are stored only as irreversible hashes and are not included."));
    Ok(Value::Object(data))
}

fn attachment(name: &str, v: &Value) -> Response {
    let mut r = ok(v);
    let file = format!("{name}-{}.json", chrono::Utc::now().format("%Y-%m-%d"));
    if let Ok(h) = HeaderValue::from_str(&content_disposition("attachment", &file)) {
        r.headers_mut().insert(header::CONTENT_DISPOSITION, h);
    }
    r
}

/// GET /admin/api/retailers/{id}/export
pub async fn retailer_export(
    State(app): State<App>,
    Path(id): Path<String>,
    method: Method,
    headers: HeaderMap,
) -> Res {
    admin_guard(&app, &headers, &method, "admin").await?;
    let i = id.clone();
    let v = app
        .db
        .read(move |c| match retailer_data(c, &i)? {
            Some(d) => envelope(c, d),
            None => Err(Problem::new("not_found", "Retailer not found.")),
        })
        .await?;
    Ok(attachment(&format!("personal-data-{id}"), &v))
}

/// GET /admin/api/users/{id}/export
pub async fn user_export(
    State(app): State<App>,
    Path(id): Path<String>,
    method: Method,
    headers: HeaderMap,
) -> Res {
    admin_guard(&app, &headers, &method, "admin").await?;
    let i = id.clone();
    let v = app
        .db
        .read(move |c| match user_data(c, &i)? {
            Some(d) => envelope(c, d),
            None => Err(Problem::new("not_found", "Account not found.")),
        })
        .await?;
    Ok(attachment(&format!("personal-data-{id}"), &v))
}

/// GET /admin/api/me/export: "download my data" for anyone signed in.
pub async fn me_export(State(app): State<App>, method: Method, headers: HeaderMap) -> Res {
    let s: Session = admin_guard(&app, &headers, &method, "any")
        .await?
        .expect("session");
    let v = app
        .db
        .read(move |c| match user_data(c, &s.user.id)? {
            Some(d) => envelope(c, d),
            None => Err(Problem::new("not_found", "Account not found.")),
        })
        .await?;
    Ok(attachment("my-data", &v))
}

/// DELETE /admin/api/me: a retailer's person deletes their own account;
/// brand administrators are removed by another administrator.
pub async fn me_delete(State(app): State<App>, method: Method, headers: HeaderMap) -> Res {
    let s: Session = admin_guard(&app, &headers, &method, "any")
        .await?
        .expect("session");
    if s.user.role == "admin" {
        return Err(Problem::new(
            "forbidden",
            "Administrators are removed by another administrator under Settings → Team.",
        ));
    }
    let files = app.db.write(move |tx| erase_user(tx, &s.user)).await?;
    delete_download_files(&app, files).await;
    let mut r = StatusCode::NO_CONTENT.into_response();
    set_cookie(&app, &mut r, SESSION_COOKIE, "", 0);
    Ok(r)
}

/// Personal data for the CLI: a retailer (id) or an account (e-mail).
pub fn personal_data_cli(c: &Connection, email: &str, retailer_id: &str) -> Result<Value> {
    let data = if !retailer_id.is_empty() {
        retailer_data(c, retailer_id)?
            .ok_or_else(|| Problem::new("not_found", format!("retailer {retailer_id} not found")))?
    } else {
        let u = load_user(c, "email = ?", &norm_email(email))?
            .ok_or_else(|| Problem::new("not_found", format!("no account with e-mail {email}")))?;
        user_data(c, &u.id)?.unwrap_or_default()
    };
    envelope(c, data)
}

// ---- import template --------------------------------------------------------------------------

/// The canonical CSV template with two example rows (node-go's).
const IMPORT_TEMPLATE: &str = "brand,style_number,name:en,name:nl,description:en,description:nl,item_type,target_group,season,collection,materials,contains_animal_origin,care,country_of_origin,feature:fit,feature:neckline,gtin,sku,color_code,color_name:en,color_name:nl,color_family,size,size_system,weight_kg\r\n\
Your Brand,ST-1001,Crew neck sweater,Trui met ronde hals,Soft knit sweater.,Zachte gebreide trui.,sweater,unisex,AW26,Essentials,main: 100% merino_wool,no,wash_30_very_mild|do_not_bleach|dry_flat,PT,regular,crew,2000000000015,ST-1001-NVY-M,NVY,Navy,Marineblauw,blue,M,INT,0.42\r\n\
Your Brand,ST-1001,Crew neck sweater,Trui met ronde hals,Soft knit sweater.,Zachte gebreide trui.,sweater,unisex,AW26,Essentials,main: 100% merino_wool,no,wash_30_very_mild|do_not_bleach|dry_flat,PT,regular,crew,2000000000022,ST-1001-NVY-L,NVY,Navy,Marineblauw,blue,L,INT,0.46\r\n";

/// GET /admin/api/import-template.csv
pub async fn import_template(State(app): State<App>, method: Method, headers: HeaderMap) -> Res {
    admin_guard(&app, &headers, &method, "admin").await?;
    let mut r = (StatusCode::OK, format!("\u{feff}{IMPORT_TEMPLATE}")).into_response();
    let h = r.headers_mut();
    h.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/csv; charset=utf-8"),
    );
    h.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    h.insert(
        header::CONTENT_DISPOSITION,
        HeaderValue::from_static("attachment; filename=\"products-template.csv\""),
    );
    Ok(r)
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use tower::ServiceExt;

    #[test]
    fn template_has_two_rows() {
        assert_eq!(IMPORT_TEMPLATE.matches("\r\n").count(), 3);
    }

    struct T {
        app: App,
        router: axum::Router,
        dir: std::path::PathBuf,
    }

    impl T {
        async fn new() -> T {
            let dir =
                std::env::temp_dir().join(format!("obx-people-test-{}", crate::ids::new("t")));
            std::fs::create_dir_all(&dir).unwrap();
            let app = App::new(crate::config::Config::for_test(&dir))
                .await
                .unwrap();
            let hash = secure::hash_password("correct horse battery");
            app.db
                .write(move |tx| {
                    crate::db::set_meta(tx, "setup_done", "1")?;
                    for (id, email, role) in [("usr_a", "admin@x.example", "admin"), ("usr_b", "second@x.example", "admin")] {
                        tx.execute(
                            "INSERT INTO users (id, email, name, role, status, language, password_hash, created_at) VALUES (?, ?, 'Ada', ?, 'active', 'en', ?, ?)",
                            params![id, email, role, hash, crate::db::now_str()],
                        )?;
                    }
                    Ok(())
                })
                .await
                .unwrap();
            let router = crate::http::router::router(app.clone());
            T { app, router, dir }
        }

        async fn call(
            &self,
            method: &str,
            uri: &str,
            cookie: Option<&(String, String)>,
            body: Value,
        ) -> (u16, Value, HeaderMap) {
            let mut b = axum::http::Request::builder()
                .method(method)
                .uri(uri)
                .header("content-type", "application/json");
            if let Some((sid, csrf)) = cookie {
                b = b
                    .header("cookie", format!("obx_session={sid}; obx_csrf={csrf}"))
                    .header("x-csrf-token", csrf);
            } else {
                b = b.header("cookie", "obx_csrf=c").header("x-csrf-token", "c");
            }
            let mut req = b
                .body(if body.is_null() {
                    Body::empty()
                } else {
                    Body::from(body.to_string())
                })
                .unwrap();
            req.extensions_mut()
                .insert(axum::extract::ConnectInfo(SocketAddr::from((
                    [127, 0, 0, 1],
                    1,
                ))));
            let r = self.router.clone().oneshot(req).await.unwrap();
            let status = r.status().as_u16();
            let h = r.headers().clone();
            let bytes = axum::body::to_bytes(r.into_body(), 1 << 24).await.unwrap();
            (
                status,
                serde_json::from_slice(&bytes).unwrap_or(Value::Null),
                h,
            )
        }

        async fn login(&self, email: &str, pw: &str) -> (String, String) {
            let (st, _, h) = self
                .call(
                    "POST",
                    "/admin/api/session/login",
                    None,
                    json!({"email": email, "password": pw}),
                )
                .await;
            assert_eq!(st, 200);
            let mut sid = String::new();
            let mut csrf = String::new();
            for c in h.get_all(header::SET_COOKIE) {
                let c = c.to_str().unwrap();
                let kv = c.split(';').next().unwrap();
                if let Some(v) = kv.strip_prefix("obx_session=") {
                    sid = v.into();
                }
                if let Some(v) = kv.strip_prefix("obx_csrf=") {
                    csrf = v.into();
                }
            }
            (sid, csrf)
        }

        async fn audit_actions(&self) -> Vec<String> {
            self.app
                .db
                .read(|c| Ok(crate::audit::rows(c, "ORDER BY at, id", &[])?))
                .await
                .unwrap()
                .iter()
                .map(|e| format!("{} {}", e["action"].as_str().unwrap(), e["status"]))
                .collect()
        }
    }

    impl Drop for T {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn password_reset_by_email() {
        let t = T::new().await;
        let (st, _, _) = t
            .call(
                "POST",
                "/admin/api/password/forgot",
                None,
                json!({"email": "nobody@x.example"}),
            )
            .await;
        assert_eq!(st, 202, "unknown addresses look the same");
        let (st, _, _) = t
            .call(
                "POST",
                "/admin/api/password/forgot",
                None,
                json!({"email": "Admin@X.example"}),
            )
            .await;
        assert_eq!(st, 202);
        let mut mail = None;
        for _ in 0..100 {
            if let Some(m) = t
                .app
                .mail
                .last()
                .into_iter()
                .find(|m| m.to == "admin@x.example")
            {
                mail = Some(m);
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        let mail = mail.expect("reset mail");
        assert!(t.app.mail.last().iter().all(|m| m.to != "nobody@x.example"));
        assert!(mail.subject.starts_with("Choose a new password"));
        let link = mail
            .body
            .lines()
            .find(|l| l.contains("/reset-password/"))
            .unwrap();
        let token = link.rsplit('/').next().unwrap().to_string();
        let (st, v, _) = t
            .call(
                "POST",
                "/admin/api/password/reset",
                None,
                json!({"token": token, "password": "short"}),
            )
            .await;
        assert_eq!(
            (st, v["obx_error"].as_str()),
            (422, Some("validation_failed"))
        );
        let (st, v, _) = t
            .call(
                "POST",
                "/admin/api/password/reset",
                None,
                json!({"token": token, "password": "a brand new passphrase"}),
            )
            .await;
        assert_eq!(st, 200, "{v}");
        assert_eq!(v["authenticated"], json!(true));
        let (st, v, _) = t
            .call(
                "POST",
                "/admin/api/password/reset",
                None,
                json!({"token": token, "password": "a brand new passphrase"}),
            )
            .await;
        assert_eq!(
            (st, v["obx_error"].as_str()),
            (400, Some("invite_invalid")),
            "the link works once"
        );
        t.login("admin@x.example", "a brand new passphrase").await;
        let (st, _, _) = t
            .call(
                "POST",
                "/admin/api/session/login",
                None,
                json!({"email": "admin@x.example", "password": "correct horse battery"}),
            )
            .await;
        assert_eq!(st, 401);
        let actions = t.audit_actions().await;
        assert!(
            actions.contains(&"password.reset 200".to_string()),
            "{actions:?}"
        );
        assert!(
            actions.contains(&"session.login 200".to_string()),
            "{actions:?}"
        );
        assert!(
            actions.contains(&"session.login 401".to_string()),
            "{actions:?}"
        );
        assert!(
            !actions.iter().any(|a| a.starts_with("password.forgot")),
            "{actions:?}"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn accounts_invites_and_personal_data() {
        let t = T::new().await;
        let me = t.login("admin@x.example", "correct horse battery").await;
        // Invite: the e-mail goes to the log driver (not configured → email_sent false).
        let (st, v, _) = t
            .call(
                "POST",
                "/admin/api/users/invites",
                Some(&me),
                json!({"email": "new@x.example", "role": "admin", "language": "nl"}),
            )
            .await;
        assert_eq!(st, 201, "{v}");
        assert_eq!(v["email_sent"], json!(false));
        let uid = v["user"]["id"].as_str().unwrap().to_string();
        let m = t
            .app
            .mail
            .last()
            .into_iter()
            .find(|m| m.to == "new@x.example")
            .expect("invite mail");
        assert!(m.body.contains(v["invite_url"].as_str().unwrap()));
        assert!(m.body.contains("Kies je wachtwoord"));
        let (st, v2, _) = t
            .call(
                "POST",
                &format!("/admin/api/users/{uid}/resend-invite"),
                Some(&me),
                Value::Null,
            )
            .await;
        assert_eq!(st, 200);
        assert_ne!(v2["invite_url"], v["invite_url"]);
        let (st, v, _) = t
            .call(
                "PATCH",
                &format!("/admin/api/users/{uid}"),
                Some(&me),
                json!({"status": "blocked", "name": "Bea"}),
            )
            .await;
        assert_eq!(
            (st, v["status"].as_str(), v["name"].as_str()),
            (200, Some("blocked"), Some("Bea"))
        );
        let (st, _, _) = t
            .call(
                "PATCH",
                &format!("/admin/api/users/{uid}"),
                Some(&me),
                json!({"status": "active"}),
            )
            .await;
        assert_eq!(st, 200);
        // Guards: not yourself; last active admin.
        let (st, _, _) = t
            .call("DELETE", "/admin/api/users/usr_a", Some(&me), Value::Null)
            .await;
        assert_eq!(st, 409);
        let (st, _, _) = t
            .call("DELETE", "/admin/api/users/usr_b", Some(&me), Value::Null)
            .await;
        assert_eq!(st, 204);
        let (st, _, h) = t
            .call("GET", "/admin/api/me/export", Some(&me), Value::Null)
            .await;
        assert_eq!(st, 200);
        assert!(
            h.get(header::CONTENT_DISPOSITION)
                .unwrap()
                .to_str()
                .unwrap()
                .contains("my-data-")
        );
        let (st, v, _) = t
            .call(
                "GET",
                "/admin/api/users/usr_a/export",
                Some(&me),
                Value::Null,
            )
            .await;
        assert_eq!(
            (st, v["format"].as_str()),
            (200, Some("obx-personal-data-export/1"))
        );
        assert!(v["audit_log"].as_array().unwrap().len() >= 2);
        let (st, _, _) = t
            .call("DELETE", "/admin/api/me", Some(&me), Value::Null)
            .await;
        assert_eq!(
            st, 403,
            "administrators are removed by another administrator"
        );
        let (st, v, _) = t
            .call(
                "GET",
                "/admin/api/audit-log?limit=2",
                Some(&me),
                Value::Null,
            )
            .await;
        assert_eq!(st, 200);
        assert_eq!(v["items"].as_array().unwrap().len(), 2);
        let next = v["next_cursor"].as_str().unwrap().to_string();
        let (st, v, _) = t
            .call(
                "GET",
                &format!("/admin/api/audit-log?cursor={next}&outcome=failed"),
                Some(&me),
                Value::Null,
            )
            .await;
        assert_eq!(st, 200);
        assert!(
            v["items"]
                .as_array()
                .unwrap()
                .iter()
                .all(|e| e["succeeded"] == json!(false))
        );
        let actions = t.audit_actions().await;
        for want in [
            "users.invites.create 201",
            "users.resend-invite 200",
            "users.update 200",
            "users.delete 204",
            "users.delete 409",
            "me.export.read 200",
            "users.export 200",
            "me.delete 403",
        ] {
            assert!(actions.contains(&want.to_string()), "{want} in {actions:?}");
        }
        let (st, _, _) = t
            .call(
                "GET",
                "/admin/api/import-template.csv",
                Some(&me),
                Value::Null,
            )
            .await;
        assert_eq!(st, 200);
        let (st, _, _) = t
            .call(
                "DELETE",
                "/admin/api/retailers/ret_missing",
                Some(&me),
                Value::Null,
            )
            .await;
        assert_eq!(st, 404);
        let (st, _, _) = t.call("GET", "/metrics", None, Value::Null).await;
        assert_eq!(st, 200, "metrics are on in tests");
    }
}
