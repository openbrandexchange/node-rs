//! The audit log: who changed what, when, with which outcome. Every Admin
//! API write is recorded, plus reads that export personal data and every
//! login attempt. It never stores request bodies, secrets, passwords or IP
//! addresses. Rows, action names and the JSON shape are node-go's.

use std::cell::RefCell;
use std::collections::HashMap;

use axum::extract::{MatchedPath, RawPathParams, Request};
use axum::middleware::Next;
use axum::response::Response;
use rusqlite::{Connection, params};
use serde_json::{Value, json};

use crate::app::App;
use crate::db;

#[derive(Debug, Clone, Default)]
pub struct Actor {
    pub id: String,
    pub name: String,
    pub email: String,
    pub role: String,
}

impl Actor {
    pub fn of(u: &crate::http::admin::User) -> Actor {
        Actor {
            id: u.id.clone(),
            name: u.name.clone(),
            email: u.email.clone(),
            role: u.role.clone(),
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct Entry {
    /// user | anonymous | cli
    pub actor_type: String,
    pub actor: Option<Actor>,
    pub action: String,
    pub method: String,
    pub route: String,
    pub target_type: String,
    pub target_id: String,
    pub status: u16,
    pub request_id: String,
    pub details: Option<Value>,
}

fn null_if_empty(s: &str) -> Option<&str> {
    (!s.is_empty()).then_some(s)
}

/// Writes an entry inside an open connection or transaction.
pub fn write(c: &Connection, e: &Entry) -> rusqlite::Result<()> {
    let a = e.actor.clone().unwrap_or_default();
    let actor_type = if !e.actor_type.is_empty() {
        e.actor_type.as_str()
    } else if e.actor.is_some() {
        "user"
    } else {
        "anonymous"
    };
    c.execute(
        "INSERT INTO audit_log (id, at, actor_type, actor_id, actor_name, actor_email, actor_role, action, method, route, target_type, target_id, status, request_id, details) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        params![
            crate::ids::new("aud"),
            db::now_str(),
            actor_type,
            null_if_empty(&a.id),
            null_if_empty(&a.name),
            null_if_empty(&a.email),
            null_if_empty(&a.role),
            e.action,
            e.method,
            e.route,
            null_if_empty(&e.target_type),
            null_if_empty(&e.target_id),
            if e.status == 0 { 200 } else { e.status },
            null_if_empty(&e.request_id),
            e.details.as_ref().map(|d| d.to_string()),
        ],
    )?;
    Ok(())
}

/// Records an entry; a failure is logged, never returned (the audit log
/// must not break the action itself).
pub async fn record(app: &App, e: Entry) {
    let action = e.action.clone();
    if let Err(err) = app
        .db
        .write(move |tx| {
            write(tx, &e)?;
            Ok(())
        })
        .await
    {
        tracing::error!(action, error = %err, "audit log write failed");
    }
}

/// An action done on the command line.
pub fn cli_entry(action: &str, target_type: &str, target_id: &str) -> Entry {
    Entry {
        actor_type: "cli".into(),
        action: action.into(),
        method: "CLI".into(),
        route: format!("node-rs {action}"),
        target_type: target_type.into(),
        target_id: target_id.into(),
        status: 200,
        ..Default::default()
    }
}

// ---- recording Admin API requests ------------------------------------------------------

tokio::task_local! {
    /// Set by the admin guard once a request is let through: Some(actor).
    static PASSED: RefCell<Option<Option<Actor>>>;
}

/// Called by the admin guard when it lets a request through.
pub fn guard_passed(user: Option<&crate::http::admin::User>) {
    let _ = PASSED.try_with(|p| *p.borrow_mut() = Some(user.map(Actor::of)));
}

/// The request id of the request (set by the outer layer).
#[derive(Clone)]
pub struct RequestId(pub String);

/// Requests that change only the caller's own working state, plus login,
/// which is recorded explicitly with its outcome.
fn not_audited(p: &str) -> bool {
    [
        "/admin/api/portal/selection",
        "/admin/api/portal/download-jobs",
        "/admin/api/portal/gtin-lookup",
        "/admin/api/password/forgot",
        "/admin/api/session/login",
    ]
    .iter()
    .any(|x| p.starts_with(x))
}

/// Whether a request is recorded: every Admin API write, and reads that
/// export personal data.
pub fn auditable(method: &str, pattern: &str) -> bool {
    if !pattern.starts_with("/admin/api/")
        || pattern == "/admin/api/{*rest}"
        || not_audited(pattern)
    {
        return false;
    }
    match method {
        "GET" | "HEAD" => pattern.ends_with("/export"),
        "OPTIONS" => false,
        _ => true,
    }
}

/// The route pattern in node-go's spelling: `{seg}` filled in, parameters
/// named as in node-admin.yaml.
pub fn node_pattern(pattern: &str, params: &[(String, String)]) -> String {
    let get = |k: &str| params.iter().find(|(n, _)| n == k).map(|(_, v)| v.as_str());
    let mut out = Vec::new();
    for seg in pattern.split('/') {
        let s = match seg {
            "{seg}" => get("seg").unwrap_or(seg).to_string(),
            "{ext}" => "{external_id}".into(),
            "{sha}" => "{sha256}".into(),
            "{name}" => "{rendition}".into(),
            "{n}" => "{number}".into(),
            s => s.to_string(),
        };
        out.push(s);
    }
    out.join("/")
}

/// A route pattern as a stable action name:
/// "PATCH /admin/api/retailers/{id}" → "retailers.update",
/// "POST /admin/api/access-requests/{id}/approve" → "access-requests.approve".
pub fn action(method: &str, pattern: &str) -> (String, String) {
    let p = pattern
        .strip_prefix("/admin/api")
        .unwrap_or(pattern)
        .trim_matches('/');
    let segs: Vec<&str> = p.split('/').collect();
    let plain: Vec<&str> = segs
        .iter()
        .copied()
        .filter(|s| !s.starts_with('{'))
        .collect();
    let mut target_type = String::new();
    if let Some(first) = plain.first() {
        let mut t = *first;
        if t == "catalog" && plain.len() > 1 {
            t = plain[1];
        }
        target_type = t.strip_suffix('s').unwrap_or(t).to_string();
    }
    let joined = plain.join("/");
    let special = match joined.as_str() {
        "session/login" => Some("session.login"),
        "session/logout" => Some("session.logout"),
        "setup" => Some("setup.complete"),
        "password/reset" => Some("password.reset"),
        "password/forgot" => Some("password.forgot"),
        _ => None,
    };
    if let Some(s) = special {
        return (s.into(), "user".into());
    }
    let n = segs.len();
    if n >= 2 && !segs[n - 1].starts_with('{') && segs[n - 2].starts_with('{') {
        let mut parts: Vec<&str> = plain[..plain.len() - 1].to_vec();
        parts.push(segs[n - 1]);
        return (parts.join("."), target_type);
    }
    let verb = match method {
        "POST" => "create".to_string(),
        "PUT" | "PATCH" => "update".into(),
        "DELETE" => "delete".into(),
        "GET" | "HEAD" => "read".into(),
        m => m.to_lowercase(),
    };
    let mut parts: Vec<String> = plain.iter().map(|s| s.to_string()).collect();
    parts.push(verb);
    (parts.join("."), target_type)
}

/// The first path parameter of the (node-go) pattern; one-time tokens are
/// never recorded.
fn target(pattern: &str, params: &[(String, String)]) -> String {
    for seg in pattern.split('/') {
        if let Some(name) = seg.strip_prefix('{').and_then(|s| s.strip_suffix('}')) {
            if name == "token" || name == "seg" {
                continue;
            }
            if let Some((_, v)) = params.iter().find(|(n, _)| n == name) {
                if !v.is_empty() {
                    return v.clone();
                }
            }
        }
    }
    String::new()
}

/// Route layer: records an auditable Admin API request after the handler
/// ran (only when the admin guard let it through).
pub async fn middleware(
    axum::extract::State(app): axum::extract::State<App>,
    matched: Option<MatchedPath>,
    req: Request,
    next: Next,
) -> Response {
    use axum::extract::FromRequestParts;
    let (mut parts, body) = req.into_parts();
    let params = RawPathParams::from_request_parts(&mut parts, &())
        .await
        .ok();
    let req = Request::from_parts(parts, body);
    let method = req.method().as_str().to_string();
    let Some(pattern) = matched.map(|m| m.as_str().to_string()) else {
        return next.run(req).await;
    };
    if !auditable(&method, &pattern) {
        return next.run(req).await;
    }
    let params: Vec<(String, String)> = params
        .map(|p| {
            p.iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect()
        })
        .unwrap_or_default();
    let rid = req
        .extensions()
        .get::<RequestId>()
        .map(|r| r.0.clone())
        .unwrap_or_default();
    let cell = RefCell::new(None);
    let (resp, passed) = PASSED
        .scope(cell, async move {
            let r = next.run(req).await;
            (r, PASSED.with(|p| p.borrow_mut().take()))
        })
        .await;
    if let Some(actor) = passed {
        let route = node_pattern(&pattern, &params);
        let (action, target_type) = action(&method, &route);
        // Raw params use the node-rs names; map them to the route's names.
        let renamed: Vec<(String, String)> = params
            .iter()
            .map(|(k, v)| {
                let k = match k.as_str() {
                    "ext" => "external_id",
                    "sha" => "sha256",
                    "name" => "rendition",
                    "n" => "number",
                    k => k,
                };
                (k.to_string(), v.clone())
            })
            .collect();
        let e = Entry {
            actor,
            target_id: target(&route, &renamed),
            action,
            method,
            route,
            target_type,
            status: resp.status().as_u16(),
            request_id: rid,
            ..Default::default()
        };
        record(&app, e).await;
    }
    resp
}

// ---- reading ------------------------------------------------------------------------------

pub fn rows(c: &Connection, tail: &str, args: &[String]) -> rusqlite::Result<Vec<Value>> {
    let mut st = c.prepare(&format!("SELECT id, at, actor_type, actor_id, actor_name, actor_email, actor_role, action, method, route, target_type, target_id, status, request_id, details FROM audit_log {tail}"))?;
    let out = st
        .query_map(rusqlite::params_from_iter(args.iter()), |r| {
            let status: i64 = r.get(12)?;
            let details: Option<String> = r.get(14)?;
            Ok(json!({
                "id": r.get::<_, String>(0)?, "at": r.get::<_, String>(1)?,
                "actor": {"type": r.get::<_, String>(2)?, "id": r.get::<_, Option<String>>(3)?, "name": r.get::<_, Option<String>>(4)?,
                    "role": r.get::<_, Option<String>>(6)?, "email": r.get::<_, Option<String>>(5)?},
                "action": r.get::<_, String>(7)?, "method": r.get::<_, String>(8)?, "route": r.get::<_, String>(9)?,
                "target_type": r.get::<_, Option<String>>(10)?, "target_id": r.get::<_, Option<String>>(11)?,
                "status": status, "succeeded": status < 400, "request_id": r.get::<_, Option<String>>(13)?, "ip": null,
                "details": details.and_then(|d| serde_json::from_str::<Value>(&d).ok()),
            }))
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(out)
}

#[derive(serde::Serialize, serde::Deserialize)]
struct Cursor {
    at: String,
    id: String,
}

/// GET /admin/api/audit-log: newest first. Filters: action, actor_id,
/// target_id, outcome=succeeded|failed.
pub async fn h_list(
    axum::extract::State(app): axum::extract::State<App>,
    axum::extract::Query(q): axum::extract::Query<HashMap<String, String>>,
    method: axum::http::Method,
    headers: axum::http::HeaderMap,
) -> crate::http::Res {
    crate::http::admin::admin_guard(&app, &headers, &method, "admin").await?;
    let limit = crate::http::limit_param(&q, 50, 200)?;
    let mut wh = vec!["1 = 1".to_string()];
    let mut args: Vec<String> = vec![];
    for f in ["action", "actor_id", "target_id"] {
        if let Some(v) = q.get(f).filter(|v| !v.is_empty()) {
            wh.push(format!("{f} = ?"));
            args.push(v.clone());
        }
    }
    match q.get("outcome").map(String::as_str) {
        Some("failed") => wh.push("status >= 400".into()),
        Some("succeeded") => wh.push("status < 400".into()),
        _ => {}
    }
    if let Some(c) = q.get("cursor").filter(|c| !c.is_empty()) {
        let cur: Cursor = app.decode_cursor("audit", c).ok_or_else(|| {
            crate::problem::Problem::new("cursor_invalid", "The cursor is not valid.")
        })?;
        wh.push("(at < ? OR (at = ? AND id < ?))".into());
        args.extend([cur.at.clone(), cur.at, cur.id]);
    }
    let tail = format!(
        "WHERE {} ORDER BY at DESC, id DESC LIMIT {}",
        wh.join(" AND "),
        limit + 1
    );
    let mut items = app.db.read(move |c| Ok(rows(c, &tail, &args)?)).await?;
    let mut next = Value::Null;
    if items.len() > limit {
        items.truncate(limit);
        let last = &items[limit - 1];
        next = json!(app.encode_cursor(
            "audit",
            &Cursor {
                at: last["at"].as_str().unwrap_or("").into(),
                id: last["id"].as_str().unwrap_or("").into()
            }
        ));
    }
    Ok(crate::http::ok(
        &json!({"items": items, "next_cursor": next}),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn action_names() {
        assert_eq!(
            action("PATCH", "/admin/api/retailers/{id}"),
            ("retailers.update".into(), "retailer".into())
        );
        assert_eq!(
            action("POST", "/admin/api/access-requests/{id}/approve"),
            ("access-requests.approve".into(), "access-request".into())
        );
        assert_eq!(
            action("GET", "/admin/api/retailers/{id}/export"),
            ("retailers.export".into(), "retailer".into())
        );
        assert_eq!(action("POST", "/admin/api/setup").0, "setup.complete");
        let p = node_pattern(
            "/admin/api/catalog/{seg}/{ext}",
            &[
                ("seg".into(), "products".into()),
                ("ext".into(), "P1".into()),
            ],
        );
        assert_eq!(p, "/admin/api/catalog/products/{external_id}");
        assert_eq!(
            action("PUT", &p),
            ("catalog.products.update".into(), "product".into())
        );
        assert_eq!(target(&p, &[("external_id".into(), "P1".into())]), "P1");
        assert_eq!(
            target(
                "/admin/api/invites/{token}/accept",
                &[("token".into(), "secret".into())]
            ),
            ""
        );
        assert!(auditable("DELETE", "/admin/api/me"));
        assert!(!auditable("GET", "/admin/api/retailers"));
        assert!(auditable("GET", "/admin/api/me/export"));
        assert!(!auditable("PUT", "/admin/api/portal/selection"));
        assert!(!auditable("POST", "/admin/api/session/login"));
    }
}
