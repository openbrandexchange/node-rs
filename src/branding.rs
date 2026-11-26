//! Portal appearance on the node: the favicon, the branding images (login
//! background, start-page blocks) and their public URLs. Validation and the
//! neutral default live in `obx_types::appearance`.

use std::collections::HashSet;

use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, HeaderValue, Method, StatusCode, header};
use axum::response::IntoResponse;
use rusqlite::{Connection, params};
use serde_json::{Value, json};

use crate::app::App;
use crate::http::admin::{admin_guard, save_settings, settings_json};
use crate::http::{Res, json as json_resp, ok};
use crate::problem::{Problem, Result};
use crate::settings::Settings;
use obx_types::appearance as look;

/// The ids of the stored branding images.
pub fn image_set(c: &Connection) -> Result<HashSet<String>> {
    let mut st = c.prepare("SELECT id FROM branding_images")?;
    let s = st
        .query_map([], |r| r.get::<_, String>(0))?
        .collect::<rusqlite::Result<HashSet<_>>>()?;
    Ok(s)
}

fn branding_value(s: &Settings) -> Value {
    serde_json::to_value(&s.branding).unwrap_or(Value::Null)
}

/// `branding.home` with `image_url` next to every image id.
pub fn resolved_home(c: &Connection, s: &Settings) -> Result<Value> {
    let set = image_set(c)?;
    Ok(look::resolved_home(&branding_value(s), |id| {
        set.contains(id)
    }))
}

/// `branding.login` with `background_image_url`.
pub fn public_login(c: &Connection, s: &Settings) -> Result<Value> {
    let set = image_set(c)?;
    Ok(look::public_login(&branding_value(s), |id| {
        set.contains(id)
    }))
}

pub fn favicon_url(base: &str, s: &Settings) -> Option<String> {
    (!s.favicon_sha.is_empty())
        .then(|| format!("{base}/admin/api/public/favicon?v={}", &s.favicon_sha[..16]))
}

/// The uploaded file: the `file` part of a multipart body, or the raw body.
pub async fn upload_body(headers: &HeaderMap, body: Bytes) -> Result<Bytes> {
    let ct = headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    if !ct.to_ascii_lowercase().starts_with("multipart/form-data") {
        return Ok(body);
    }
    let boundary = multer::parse_boundary(ct)
        .map_err(|_| Problem::new("invalid_request", "The multipart body cannot be read."))?;
    let stream = futures::stream::once(async move { Ok::<Bytes, std::io::Error>(body) });
    let mut mp = multer::Multipart::new(stream, boundary);
    while let Some(f) = mp
        .next_field()
        .await
        .map_err(|_| Problem::new("invalid_request", "The multipart body cannot be read."))?
    {
        if f.name() == Some("file") {
            return f.bytes().await.map_err(|_| {
                Problem::new("invalid_request", "The multipart body cannot be read.")
            });
        }
    }
    Err(Problem::new(
        "validation_failed",
        "Send the image in the multipart field file.",
    )
    .field("/file", "validation_failed", "required"))
}

/// PUT /admin/api/settings/favicon: a square PNG or WebP of at most 1 MB.
pub async fn favicon_put(
    State(app): State<App>,
    method: Method,
    headers: HeaderMap,
    body: Bytes,
) -> Res {
    admin_guard(&app, &headers, &method, "admin").await?;
    if body.len() > look::MAX_FAVICON_BYTES + (64 << 10) {
        return Err(Problem::new(
            "payload_too_large",
            "The favicon can be at most 1 MB.",
        ));
    }
    let data = upload_body(&headers, body).await?;
    if data.len() > look::MAX_FAVICON_BYTES {
        return Err(Problem::new(
            "payload_too_large",
            "The favicon can be at most 1 MB.",
        ));
    }
    let b = app.put_blob(data, None).await?;
    if b.content_type != "image/png" && b.content_type != "image/webp" {
        return Err(Problem::new(
            "unsupported_media_type",
            "Use a PNG or WebP favicon.",
        ));
    }
    if b.width.is_none() || b.width != b.height {
        return Err(
            Problem::new("validation_failed", "The favicon must be square.").field(
                "/file",
                "validation_failed",
                "square image",
            ),
        );
    }
    let cur = app.settings().await?;
    let mut next = cur.clone();
    next.favicon_sha = b.sha256;
    next.favicon_type = b.content_type;
    save_settings(&app, cur, next).await?;
    Ok(ok(&settings_json(&app, &app.settings().await?)))
}

pub async fn favicon_delete(State(app): State<App>, method: Method, headers: HeaderMap) -> Res {
    admin_guard(&app, &headers, &method, "admin").await?;
    let cur = app.settings().await?;
    let mut next = cur.clone();
    next.favicon_sha.clear();
    next.favicon_type.clear();
    save_settings(&app, cur, next).await?;
    Ok(ok(&settings_json(&app, &app.settings().await?)))
}

/// GET /admin/api/public/favicon: the brand's favicon, never a vendor's.
pub async fn public_favicon(State(app): State<App>, method: Method, headers: HeaderMap) -> Res {
    let s = app.settings().await?;
    if s.favicon_sha.is_empty() {
        return Err(Problem::new("not_found", "No favicon."));
    }
    let mut r = crate::http::protocol::serve_blob(
        &app,
        &headers,
        &method,
        &s.favicon_sha,
        &s.favicon_type,
        "",
    )
    .await?;
    r.headers_mut().insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("public, max-age=86400"),
    );
    Ok(r)
}

#[derive(Debug, Clone)]
struct Image {
    id: String,
    sha: String,
    content_type: String,
    width: i64,
    height: i64,
    bytes: i64,
}

impl Image {
    fn json(&self, used: Option<bool>) -> Value {
        let mut v = json!({"id": self.id, "url": look::image_url(&self.id), "width": self.width,
            "height": self.height, "bytes": self.bytes, "content_type": self.content_type});
        if let Some(u) = used {
            v["used"] = json!(u);
        }
        v
    }
}

fn load_images(c: &Connection, where_: &str, args: &[&str]) -> Result<Vec<Image>> {
    let mut st = c.prepare(&format!(
        "SELECT id, sha256, content_type, width, height, bytes FROM branding_images {where_}"
    ))?;
    let r = st
        .query_map(rusqlite::params_from_iter(args.iter()), |r| {
            Ok(Image {
                id: r.get(0)?,
                sha: r.get(1)?,
                content_type: r.get(2)?,
                width: r.get(3)?,
                height: r.get(4)?,
                bytes: r.get(5)?,
            })
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(r)
}

/// GET /admin/api/settings/images (with `used`)
pub async fn images(State(app): State<App>, method: Method, headers: HeaderMap) -> Res {
    admin_guard(&app, &headers, &method, "admin").await?;
    let items = app
        .db
        .read(|c| {
            let s = Settings::load(c)?;
            let used: HashSet<String> = look::image_refs(&branding_value(&s))
                .into_iter()
                .map(|(_, id)| id)
                .collect();
            Ok(load_images(c, "ORDER BY id DESC", &[])?
                .iter()
                .map(|i| i.json(Some(used.contains(&i.id))))
                .collect::<Vec<_>>())
        })
        .await?;
    Ok(ok(&json!({"items": items})))
}

/// POST /admin/api/settings/images (multipart, field `file`)
pub async fn image_upload(
    State(app): State<App>,
    method: Method,
    headers: HeaderMap,
    body: Bytes,
) -> Res {
    admin_guard(&app, &headers, &method, "admin").await?;
    if body.len() > look::MAX_IMAGE_BYTES + (64 << 10) {
        return Err(Problem::new(
            "payload_too_large",
            "An image can be at most 10 MB.",
        ));
    }
    let multipart = headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.to_ascii_lowercase().starts_with("multipart/form-data"));
    if !multipart {
        return Err(Problem::new(
            "unsupported_media_type",
            "Send multipart/form-data with the image in the field file.",
        ));
    }
    let n: i64 = app
        .db
        .read(|c| Ok(c.query_row("SELECT COUNT(*) FROM branding_images", [], |r| r.get(0))?))
        .await?;
    let max = if app.cfg.demo {
        crate::demo::MAX_IMAGES
    } else {
        look::MAX_IMAGES
    };
    if n as usize >= max {
        return Err(Problem::new(
            "limit_exceeded",
            format!(
                "This node keeps at most {max} branding images{}; delete unused ones first.",
                if app.cfg.demo {
                    " (the demo's limit)"
                } else {
                    ""
                }
            ),
        )
        .with_status(409));
    }
    let data = upload_body(&headers, body).await?;
    if data.len() > look::MAX_IMAGE_BYTES {
        return Err(Problem::new(
            "payload_too_large",
            "An image can be at most 10 MB.",
        ));
    }
    let b = app.put_blob(data, None).await?;
    if !["image/png", "image/jpeg", "image/webp"].contains(&b.content_type.as_str()) {
        return Err(Problem::new(
            "unsupported_media_type",
            "Use a PNG, JPEG or WebP image.",
        ));
    }
    let (Some(w), Some(h)) = (b.width, b.height) else {
        return Err(Problem::new(
            "validation_failed",
            "The image cannot be read.",
        ));
    };
    if w > look::MAX_IMAGE_SIDE || h > look::MAX_IMAGE_SIDE {
        let d = format!("at most {} px per side", look::MAX_IMAGE_SIDE);
        return Err(Problem::new(
            "validation_failed",
            format!(
                "The image can be at most {} pixels per side.",
                look::MAX_IMAGE_SIDE
            ),
        )
        .field("/file", "validation_failed", d));
    }
    let img = Image {
        id: crate::ids::new("img"),
        sha: b.sha256.clone(),
        content_type: b.content_type.clone(),
        width: w,
        height: h,
        bytes: b.bytes,
    };
    let i2 = img.clone();
    app.db
        .write(move |tx| {
            tx.execute(
                "INSERT INTO branding_images (id, sha256, content_type, width, height, bytes, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
                params![i2.id, i2.sha, i2.content_type, i2.width, i2.height, i2.bytes, crate::db::now_str()],
            )?;
            Ok(())
        })
        .await?;
    Ok(json_resp(201, &img.json(None)))
}

/// DELETE /admin/api/settings/images/{id}: refused while it is in use.
pub async fn image_delete(
    State(app): State<App>,
    Path(id): Path<String>,
    method: Method,
    headers: HeaderMap,
) -> Res {
    admin_guard(&app, &headers, &method, "admin").await?;
    app.db
        .write(move |tx| {
            let s = Settings::load(tx)?;
            if let Some((ptr, _)) = look::image_refs(&branding_value(&s))
                .into_iter()
                .find(|(_, i)| *i == id)
            {
                return Err(Problem::new(
                    "conflict",
                    format!("The image is still used at {ptr}; remove it from the appearance settings first."),
                ));
            }
            if tx.execute("DELETE FROM branding_images WHERE id = ?", [&id])? == 0 {
                return Err(Problem::new("not_found", "No such image."));
            }
            Ok(())
        })
        .await?;
    Ok(StatusCode::NO_CONTENT.into_response())
}

/// GET /admin/api/public/images/{id}: no login needed (login page); ids are
/// never reused, so the answer is cached immutably.
pub async fn public_image(
    State(app): State<App>,
    Path(id): Path<String>,
    method: Method,
    headers: HeaderMap,
) -> Res {
    let img = app
        .db
        .read(move |c| Ok(load_images(c, "WHERE id = ?", &[&id])?.pop()))
        .await?
        .ok_or_else(|| Problem::new("not_found", "No such image."))?;
    let mut r =
        crate::http::protocol::serve_blob(&app, &headers, &method, &img.sha, &img.content_type, "")
            .await?;
    r.headers_mut().insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("public, max-age=31536000, immutable"),
    );
    Ok(r)
}
