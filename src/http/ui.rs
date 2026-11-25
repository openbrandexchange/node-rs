//! The bundled admin-ui (ui/dist, vendored from openbrandexchange/admin-ui):
//! the brand admin and the retailer portal, a single-page app.

use axum::body::Body;
use axum::http::{HeaderMap, Method, StatusCode, Uri, header};
use axum::response::{IntoResponse, Response};
use rust_embed::Embed;

use crate::problem::Problem;

#[derive(Embed)]
#[folder = "ui/dist/"]
struct Dist;

/// A file of the bundled admin-ui build (for example `locales/nl.json`).
pub fn dist_file(name: &str) -> Option<std::borrow::Cow<'static, [u8]>> {
    Dist::get(name).map(|f| f.data)
}

fn file(name: &str, cache: &str) -> Option<Response> {
    let f = Dist::get(name)?;
    let mime = mime_guess::from_path(name).first_or_octet_stream();
    Some(
        axum::http::Response::builder()
            .header(header::CONTENT_TYPE, mime.as_ref())
            .header(header::CACHE_CONTROL, cache)
            .body(Body::from(f.data.into_owned()))
            .unwrap(),
    )
}

pub async fn serve(method: Method, uri: Uri, headers: HeaderMap) -> Response {
    if method != Method::GET && method != Method::HEAD {
        return Problem::new("method_not_allowed", "Only GET is supported here.").into_response();
    }
    let path = uri.path();
    if path.starts_with("/.well-known/") {
        return StatusCode::NOT_FOUND.into_response();
    }
    // Path::clean equivalent: no "..", no empty segments.
    let segs: Vec<&str> = path
        .split('/')
        .filter(|s| !s.is_empty() && *s != ".")
        .collect();
    if segs.contains(&"..") {
        return StatusCode::NOT_FOUND.into_response();
    }
    let name = segs.join("/");
    if !name.is_empty() && name != "index.html" {
        let cache = if name.starts_with("assets/") {
            "public, max-age=31536000, immutable"
        } else {
            "no-cache"
        };
        if let Some(r) = file(&name, cache) {
            return r;
        }
        let build = name.starts_with("assets/") || name.starts_with("locales/");
        let accept = headers
            .get(header::ACCEPT)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        let has_ext = segs.last().is_some_and(|s| s.contains('.'));
        if build || (has_ext && !accept.contains("text/html")) {
            return StatusCode::NOT_FOUND.into_response();
        }
    }
    match file("index.html", "no-cache") {
        Some(mut r) => {
            r.headers_mut().insert(
                header::CONTENT_TYPE,
                "text/html; charset=utf-8".parse().unwrap(),
            );
            r
        }
        None => StatusCode::NOT_FOUND.into_response(),
    }
}
