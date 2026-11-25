//! Access requests (protocol.md §4.1): an unauthenticated request, status
//! polling with the request token, credentials exactly once.

use std::net::SocketAddr;

use axum::body::Bytes;
use axum::extract::{ConnectInfo, Path, State};
use axum::http::HeaderMap;
use rusqlite::{Connection, OptionalExtension, params};
use serde_json::{Map, Value, json};

use super::*;
use crate::secure;

#[derive(Debug, Clone)]
pub struct AccessRequest {
    pub id: String,
    pub status: String,
    pub token_hash: String,
    pub created_at: String,
    pub retailer: Map<String, Value>,
    pub contact: Map<String, Value>,
    pub access: Vec<String>,
    pub requested_brand_ids: Option<Vec<String>>,
    pub message: Option<String>,
    pub decided_at: Option<String>,
    pub reason: Option<String>,
    pub retailer_id: Option<String>,
    pub api_client_id: Option<String>,
    pub secret_enc: Option<String>,
    pub claimed: bool,
    pub invited: bool,
}

impl AccessRequest {
    pub fn wants(&self, w: &str) -> bool {
        self.access.iter().any(|x| x == w)
    }

    pub fn admin_json(&self) -> Value {
        json!({"id": self.id, "status": self.status, "created_at": self.created_at, "decided_at": self.decided_at,
            "reason": self.reason, "retailer": self.retailer, "contact": self.contact, "access": self.access,
            "requested_brand_ids": self.requested_brand_ids, "message": self.message, "retailer_id": self.retailer_id,
            "source_ip_country": null})
    }
}

pub fn load(c: &Connection, id: &str) -> Result<Option<AccessRequest>> {
    Ok(c.query_row(
        "SELECT id, status, token_hash, created_at, retailer, contact, access, requested_brand_ids, message, decided_at, reason, retailer_id, api_client_id, client_secret_enc, claimed, invited FROM access_requests WHERE id = ?",
        [id],
        |r| {
            let obj = |s: String| serde_json::from_str::<Map<String, Value>>(&s).unwrap_or_default();
            Ok(AccessRequest {
                id: r.get(0)?,
                status: r.get(1)?,
                token_hash: r.get(2)?,
                created_at: r.get(3)?,
                retailer: obj(r.get(4)?),
                contact: obj(r.get(5)?),
                access: serde_json::from_str(&r.get::<_, String>(6)?).unwrap_or_default(),
                requested_brand_ids: r.get::<_, Option<String>>(7)?.and_then(|s| serde_json::from_str(&s).ok()),
                message: r.get(8)?,
                decided_at: r.get(9)?,
                reason: r.get(10)?,
                retailer_id: r.get(11)?,
                api_client_id: r.get(12)?,
                secret_enc: r.get(13)?,
                claimed: r.get::<_, i64>(14)? == 1,
                invited: r.get::<_, i64>(15)? == 1,
            })
        },
    )
    .optional()?)
}

fn s(m: &Map<String, Value>, k: &str) -> String {
    m.get(k)
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .trim()
        .to_string()
}

fn opt(m: &Map<String, Value>, k: &str) -> Value {
    match m.get(k).and_then(|v| v.as_str()).map(str::trim) {
        Some(x) if !x.is_empty() => json!(x),
        _ => Value::Null,
    }
}

pub async fn create(
    State(app): State<App>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    body: Bytes,
) -> Res {
    let ip = client_ip(&app, &headers, Some(peer));
    if let Err(retry) = app.limit(&format!("access-request:{ip}"), 5, 3600) {
        let mut p = Problem::new(
            "rate_limited",
            "Too many access requests from this address; try again later.",
        );
        p.retry_after = Some(retry as u64);
        return Err(p);
    }
    let st = app.settings().await?;
    if !st.portal.access_requests_enabled {
        return Err(Problem::new(
            "forbidden",
            "This brand does not accept access requests.",
        ));
    }
    let doc = read_json_object(&headers, &body)?;
    let errs = crate::schemas::validate("AccessRequestInput", &Value::Object(doc.clone()));
    if !errs.is_empty() {
        let mut p = Problem::new("validation_failed", "The request body is not valid.");
        for e in errs {
            p = p.field(&e.pointer, "validation_failed", e.message);
        }
        return Err(p);
    }
    let empty = Map::new();
    let retailer = doc
        .get("retailer")
        .and_then(|v| v.as_object())
        .unwrap_or(&empty);
    let contact = doc
        .get("contact")
        .and_then(|v| v.as_object())
        .unwrap_or(&empty);
    let mut access: Vec<String> = doc
        .get("access")
        .and_then(|v| v.as_array())
        .map(|a| {
            a.iter()
                .filter_map(|x| x.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default();
    if access.is_empty() {
        access = vec!["portal".into()];
    }
    let brands: Option<String> = doc
        .get("requested_brand_ids")
        .and_then(|v| v.as_array())
        .map(|a| {
            serde_json::to_string(&a.iter().filter_map(|x| x.as_str()).collect::<Vec<_>>()).unwrap()
        });
    let token = secure::token("obxr_");
    let id = crate::ids::new("acr");
    let now = crate::db::now_str();
    let clean_ret = json!({"name": s(retailer, "name"), "reference": opt(retailer, "reference"), "website": opt(retailer, "website"),
        "vat_number": opt(retailer, "vat_number"), "country": opt(retailer, "country")});
    let mut lang = opt(contact, "language");
    if lang.is_null() {
        lang = json!(super::admin::supported_lang(
            headers
                .get("accept-language")
                .and_then(|v| v.to_str().ok())
                .unwrap_or("")
        ));
    }
    let clean_contact = json!({"name": s(contact, "name"), "email": s(contact, "email").to_lowercase(),
        "phone": opt(contact, "phone"), "language": lang});
    let msg = doc
        .get("message")
        .and_then(|v| v.as_str())
        .map(str::trim)
        .filter(|m| !m.is_empty())
        .map(String::from);
    let (i, th, n) = (id.clone(), secure::hash_token(&token), now.clone());
    let (cr, cc, ac) = (
        clean_ret.to_string(),
        clean_contact.to_string(),
        serde_json::to_string(&access).unwrap(),
    );
    app.db
        .write(move |tx| {
            tx.execute(
                "INSERT INTO access_requests (id, status, token_hash, retailer, contact, access, requested_brand_ids, message, created_at) VALUES (?, 'pending', ?, ?, ?, ?, ?, ?, ?)",
                params![i, th, cr, cc, ac, brands, msg, n],
            )?;
            Ok(())
        })
        .await?;
    tracing::info!(access_request = %id, retailer = %clean_ret["name"], "new access request");
    {
        let retailer = clean_ret["name"].as_str().unwrap_or("").to_string();
        let cname = clean_contact["name"].as_str().unwrap_or("").to_string();
        let to = clean_contact["email"].as_str().unwrap_or("").to_string();
        let clang = clean_contact["language"]
            .as_str()
            .unwrap_or("en")
            .to_string();
        if !to.is_empty() {
            crate::mail::send_mail_later(
                &app,
                to,
                clang,
                crate::mail::MAIL_ACCESS_REQUEST_RECEIVED,
                vec![("name", cname.clone())],
            );
        }
        let a = app.clone();
        tokio::spawn(async move {
            let admins = a
                .db
                .read(|c| {
                    let mut st = c.prepare("SELECT email, name, language FROM users WHERE role = 'admin' AND status = 'active'")?;
                    let r = st
                        .query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?, r.get::<_, String>(2)?)))?
                        .collect::<rusqlite::Result<Vec<_>>>()?;
                    Ok(r)
                })
                .await
                .unwrap_or_default();
            let url = format!("{}/admin/requests", a.cfg.public_url);
            for (email, name, lang) in admins {
                let vars = [
                    ("name", name),
                    ("retailer", retailer.clone()),
                    ("contact", cname.clone()),
                    ("url", url.clone()),
                ];
                crate::mail::send_mail(
                    &a,
                    &email,
                    &lang,
                    crate::mail::MAIL_ACCESS_REQUEST_NEW,
                    &vars,
                )
                .await;
            }
        });
    }
    Ok(json(
        202,
        &json!({"id": id, "status": "pending", "created_at": now, "decided_at": null, "reason": null, "request_token": token,
            "status_url": format!("{}/obx/v1/access-requests/{id}", app.cfg.public_url), "portal": null, "credentials": null}),
    ))
}

pub async fn status(State(app): State<App>, Path(id): Path<String>, headers: HeaderMap) -> Res {
    let Some(tok) = bearer(&headers) else {
        return Err(Problem::new(
            "unauthorized",
            "Send the request_token as Bearer token.",
        ));
    };
    rate_limit(&app, &format!("access-status:{id}"), 20)?;
    let a = app.clone();
    let out = app
        .db
        .write(move |tx| {
            let Some(ar) = load(tx, &id)?.filter(|ar| secure::eq(&ar.token_hash, &secure::hash_token(&tok))) else {
                return Ok(None);
            };
            let base = &a.cfg.public_url;
            let mut out = json!({"id": ar.id, "status": ar.status, "created_at": ar.created_at, "decided_at": ar.decided_at,
                "reason": ar.reason, "status_url": format!("{base}/obx/v1/access-requests/{}", ar.id), "portal": null, "credentials": null});
            if ar.status == "approved" {
                if ar.wants("portal") {
                    out["portal"] = json!({"invited": ar.invited, "login_url": format!("{base}/login")});
                }
                if let Some(cid) = &ar.api_client_id {
                    if let Some(c) = super::protocol::load_client(tx, "id = ?", cid)? {
                        let mut secret = None;
                        let mut claimed = ar.claimed;
                        if !ar.claimed {
                            if let Some(enc) = &ar.secret_enc {
                                let n = tx.execute(
                                    "UPDATE access_requests SET claimed = 1, client_secret_enc = NULL WHERE id = ? AND claimed = 0",
                                    [&ar.id],
                                )?;
                                if n == 1 {
                                    secret = a.keys.decrypt(enc).and_then(|b| String::from_utf8(b).ok());
                                }
                                claimed = true;
                            }
                        }
                        out["credentials"] = json!({"client_id": c.client_id, "client_secret": secret,
                            "token_endpoint": format!("{base}/obx/v1/oauth/token"), "scopes": c.scopes, "claimed": claimed});
                    }
                }
            }
            Ok(Some(out))
        })
        .await?;
    out.map(|o| ok(&o))
        .ok_or_else(|| Problem::new("not_found", "Access request not found."))
}
