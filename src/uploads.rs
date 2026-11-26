//! Resumable multipart uploads (ingest.md §4, method 3) for originals above
//! `max_upload_bytes`: create, send parts of `part_bytes` (re-sending a part
//! replaces it), resume with GET, complete (size and sha256 are checked).
//! Parts are kept in the blob store under `uploads/<id>/<n>`.

#![allow(clippy::result_large_err)]

use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::IntoResponse;
use rusqlite::{Connection, OptionalExtension, params};
use serde_json::{Value, json};

use crate::app::{App, MAX_OBJECT_BYTES, PART_BYTES};
use crate::http::ingest::{ingest_auth, is_sha256};
use crate::http::{Res, json as json_resp, ok, read_json_object};
use crate::problem::{Problem, Result};

#[derive(Debug, Clone)]
struct Upload {
    id: String,
    sha256: String,
    content_type: String,
    status: String,
    expires_at: String,
    bytes: i64,
    part_bytes: i64,
    parts_total: i64,
    received: Vec<i64>,
}

impl Upload {
    fn plan(&self) -> obx_format::upload::PartPlan {
        obx_format::upload::PartPlan::new(self.bytes as u64, self.part_bytes as u64)
    }

    fn json(&self) -> Value {
        json!({"id": self.id, "sha256": self.sha256, "bytes": self.bytes, "content_type": self.content_type,
            "part_bytes": self.part_bytes, "parts_total": self.parts_total, "received_parts": self.received,
            "status": self.status, "expires_at": self.expires_at})
    }
}

fn load(c: &Connection, id: &str, owner: &str) -> Result<Option<Upload>> {
    let r = c
        .query_row(
            "SELECT id, sha256, content_type, status, expires_at, owner, bytes, part_bytes, parts_total, received FROM uploads WHERE id = ?",
            [id],
            |r| {
                Ok((
                    Upload {
                        id: r.get(0)?,
                        sha256: r.get(1)?,
                        content_type: r.get(2)?,
                        status: r.get(3)?,
                        expires_at: r.get(4)?,
                        bytes: r.get(6)?,
                        part_bytes: r.get(7)?,
                        parts_total: r.get(8)?,
                        received: serde_json::from_str(&r.get::<_, String>(9)?).unwrap_or_default(),
                    },
                    r.get::<_, String>(5)?,
                ))
            },
        )
        .optional()?;
    let Some((mut u, o)) = r.filter(|(_, o)| o == owner) else {
        return Ok(None);
    };
    let _ = o;
    if u.status == "open"
        && crate::db::parse_time(&u.expires_at).is_some_and(|t| t < chrono::Utc::now())
    {
        u.status = "expired".into();
    }
    Ok(Some(u))
}

async fn load_upload(app: &App, id: &str, owner: &str) -> Result<Option<Upload>> {
    let (id, owner) = (id.to_string(), owner.to_string());
    app.db.read(move |c| load(c, &id, &owner)).await
}

fn part_key(id: &str, n: i64) -> String {
    format!("uploads/{id}/{n}")
}

async fn delete_parts(app: &App, u: &Upload) {
    for n in 1..=u.parts_total {
        let _ = app.store.delete(&part_key(&u.id, n)).await;
    }
}

async fn set_status(app: &App, id: &str, status: &'static str) {
    let id = id.to_string();
    let _ = app
        .db
        .write(move |tx| {
            tx.execute(
                "UPDATE uploads SET status = ? WHERE id = ?",
                params![status, id],
            )?;
            Ok(())
        })
        .await;
}

/// POST /obx/v1/ingest/uploads
pub async fn h_create(State(app): State<App>, headers: HeaderMap, body: Bytes) -> Res {
    let t = ingest_auth(&app, &headers, "ingest:write").await?;
    let b = read_json_object(&headers, &body)?;
    let sha = b
        .get("sha256")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let bytes = b.get("bytes").and_then(|v| v.as_i64()).unwrap_or(0);
    let ct = b
        .get("content_type")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    if !is_sha256(&sha) || bytes < 1 {
        return Err(Problem::new(
            "validation_failed",
            "sha256 (lowercase hex) and bytes are required.",
        ));
    }
    if !matches!(
        ct.as_str(),
        "image/jpeg" | "image/png" | "image/webp" | "image/tiff"
    ) {
        return Err(Problem::new(
            "unsupported_media_type",
            "Only JPEG, PNG, WebP and TIFF images are accepted.",
        ));
    }
    if bytes as u64 > MAX_OBJECT_BYTES {
        return Err(Problem::new(
            "payload_too_large",
            format!("Files are limited to {MAX_OBJECT_BYTES} bytes."),
        ));
    }
    if let Some(b) = app.get_blob(&sha).await? {
        return Ok(ok(&b));
    }
    let pb = PART_BYTES as i64;
    let u = Upload {
        id: crate::ids::new("upl"),
        sha256: sha,
        content_type: ct,
        status: "open".into(),
        expires_at: crate::db::fmt_time(chrono::Utc::now() + chrono::Duration::hours(24)),
        bytes,
        part_bytes: pb,
        parts_total: (bytes + pb - 1) / pb,
        received: vec![],
    };
    let (u2, owner) = (u.clone(), format!("ingest:{}", t.id));
    app.db
        .write(move |tx| {
            tx.execute(
                "INSERT INTO uploads (id, sha256, bytes, content_type, part_bytes, parts_total, received, status, expires_at, owner) VALUES (?, ?, ?, ?, ?, ?, '[]', 'open', ?, ?)",
                params![u2.id, u2.sha256, u2.bytes, u2.content_type, u2.part_bytes, u2.parts_total, u2.expires_at, owner],
            )?;
            Ok(())
        })
        .await?;
    Ok(json_resp(201, &u.json()))
}

/// GET /obx/v1/ingest/uploads/{id}
pub async fn h_get(State(app): State<App>, Path(id): Path<String>, headers: HeaderMap) -> Res {
    let t = ingest_auth(&app, &headers, "ingest:read").await?;
    let u = load_upload(&app, &id, &format!("ingest:{}", t.id))
        .await?
        .ok_or_else(|| Problem::new("not_found", "Upload not found."))?;
    Ok(ok(&u.json()))
}

/// DELETE /obx/v1/ingest/uploads/{id}
pub async fn h_delete(State(app): State<App>, Path(id): Path<String>, headers: HeaderMap) -> Res {
    let t = ingest_auth(&app, &headers, "ingest:write").await?;
    let u = load_upload(&app, &id, &format!("ingest:{}", t.id))
        .await?
        .ok_or_else(|| Problem::new("not_found", "Upload not found."))?;
    set_status(&app, &u.id, "aborted").await;
    delete_parts(&app, &u).await;
    Ok(StatusCode::NO_CONTENT.into_response())
}

/// PUT /obx/v1/ingest/uploads/{id}/parts/{n}
pub async fn h_part(
    State(app): State<App>,
    Path((id, n)): Path<(String, u32)>,
    headers: HeaderMap,
    body: Bytes,
) -> Res {
    let t = ingest_auth(&app, &headers, "ingest:write").await?;
    let u = load_upload(&app, &id, &format!("ingest:{}", t.id))
        .await?
        .filter(|u| u.status == "open")
        .ok_or_else(|| Problem::new("not_found", "Upload not found or no longer open."))?;
    let n = n as i64;
    u.plan()
        .check_part(n.max(0) as u64, body.len() as u64)
        .map_err(|e| Problem::new(e.code, e.detail))?;
    app.store
        .put(&part_key(&u.id, n), body)
        .await
        .map_err(Problem::internal)?;
    let uid = u.id.clone();
    let received = app
        .db
        .write(move |tx| {
            let r: String =
                tx.query_row("SELECT received FROM uploads WHERE id = ?", [&uid], |r| {
                    r.get(0)
                })?;
            let mut list: Vec<i64> = serde_json::from_str(&r).unwrap_or_default();
            if !list.contains(&n) {
                list.push(n);
            }
            list.sort();
            tx.execute(
                "UPDATE uploads SET received = ? WHERE id = ?",
                params![serde_json::to_string(&list).unwrap(), uid],
            )?;
            Ok(list)
        })
        .await?;
    Ok(ok(&Upload { received, ..u }.json()))
}

/// POST /obx/v1/ingest/uploads/{id}/complete
pub async fn h_complete(State(app): State<App>, Path(id): Path<String>, headers: HeaderMap) -> Res {
    let t = ingest_auth(&app, &headers, "ingest:write").await?;
    let u = load_upload(&app, &id, &format!("ingest:{}", t.id))
        .await?
        .filter(|u| u.status == "open")
        .ok_or_else(|| Problem::new("not_found", "Upload not found or no longer open."))?;
    let received: Vec<u64> = u.received.iter().map(|&i| i as u64).collect();
    u.plan()
        .check_complete(&received)
        .map_err(|e| Problem::new(e.code, e.detail))?;
    let mut data = Vec::with_capacity(u.bytes as usize);
    for i in 1..=u.parts_total {
        match app
            .store
            .get(&part_key(&u.id, i))
            .await
            .map_err(Problem::internal)?
        {
            Some(b) => data.extend_from_slice(&b),
            None => {
                return Err(Problem::new(
                    "upload_incomplete",
                    format!("Part {i} is missing; upload it again."),
                ));
            }
        }
    }
    let sha = crate::secure::sha256_hex(&data);
    if sha != u.sha256 || data.len() as i64 != u.bytes {
        set_status(&app, &u.id, "aborted").await;
        delete_parts(&app, &u).await;
        return Err(Problem::new(
            "checksum_mismatch",
            format!(
                "The assembled file has sha256 {sha}, not {}; the upload was aborted.",
                u.sha256
            ),
        ));
    }
    let b = app.put_blob(Bytes::from(data), Some(&sha)).await?;
    set_status(&app, &u.id, "completed").await;
    delete_parts(&app, &u).await;
    Ok(ok(&b))
}
