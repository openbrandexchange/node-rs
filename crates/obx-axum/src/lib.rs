//! HTTP helpers for serving the Open Brand Exchange protocol with
//! [axum](https://docs.rs/axum): [`Problem`] answers as
//! `application/problem+json` (via the `axum` feature of `obx-types`), JSON
//! bodies and responses, the `limit` parameter, Bearer tokens, `Range`
//! parsing, `Content-Disposition`, an in-memory fixed-window
//! [`RateLimiter`] with `RateLimit-*` headers, and the security and
//! `OBX-Version` headers of security.md §4 ([`security_headers`]).
//!
//! ```
//! use axum::http::HeaderMap;
//! use obx_axum::{security_headers, Surface};
//!
//! let mut h = HeaderMap::new();
//! security_headers(&mut h, Surface::Protocol, true);
//! assert_eq!(h["obx-version"], "0.3");
//! assert_eq!(h["x-content-type-options"], "nosniff");
//! ```
#![forbid(unsafe_code)]

use std::collections::HashMap;
use std::sync::Mutex;

use axum::http::{HeaderMap, HeaderName, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use serde::Serialize;
use serde_json::Value;

pub use obx_types::{Problem, Result};

/// The largest JSON body read by default.
pub const MAX_JSON_BODY: usize = 4 << 20;

/// The CSP of an HTML user interface: scripts and styles only from the
/// node itself, no framing.
pub const UI_CSP: &str = "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data: blob:; connect-src 'self'; font-src 'self'; object-src 'none'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'";
/// The CSP of API responses and files: nothing runs.
pub const API_CSP: &str = "default-src 'none'; frame-ancestors 'none'; sandbox";

/// What a response belongs to, for [`security_headers`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Surface {
    /// `/obx/v1/*` and `/.well-known/obx`: adds `OBX-Version`.
    Protocol,
    /// Other JSON APIs and file downloads.
    Api,
    /// HTML pages and their assets.
    Ui,
}

/// Sets the security headers of security.md §4 (and `OBX-Version` on the
/// protocol); `hsts` when the node is served over HTTPS.
pub fn security_headers(h: &mut HeaderMap, surface: Surface, hsts: bool) {
    let set = |h: &mut HeaderMap, k: &'static str, v: &'static str| {
        h.insert(HeaderName::from_static(k), HeaderValue::from_static(v));
    };
    set(h, "x-content-type-options", "nosniff");
    set(h, "referrer-policy", "strict-origin-when-cross-origin");
    set(h, "x-frame-options", "DENY");
    set(
        h,
        "permissions-policy",
        "camera=(), microphone=(), geolocation=(), payment=(), usb=()",
    );
    if hsts {
        set(h, "strict-transport-security", "max-age=31536000");
    }
    match surface {
        Surface::Ui => {
            set(h, "content-security-policy", UI_CSP);
            set(h, "cross-origin-opener-policy", "same-origin");
        }
        Surface::Api | Surface::Protocol => set(h, "content-security-policy", API_CSP),
    }
    if surface == Surface::Protocol {
        set(h, "obx-version", obx_types::OBX_VERSION);
    }
}

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

/// A 200 JSON response.
pub fn ok<T: Serialize>(v: &T) -> Response {
    json(200, v)
}

/// Adds headers (invalid names or values are skipped).
pub fn with_headers(mut r: Response, hs: &[(String, String)]) -> Response {
    for (k, v) in hs {
        if let (Ok(k), Ok(v)) = (HeaderName::try_from(k.as_str()), HeaderValue::from_str(v)) {
            r.headers_mut().insert(k, v);
        }
    }
    r
}

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

/// [`read_json`] that requires an object.
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

/// The token of `Authorization: Bearer <token>`.
pub fn bearer(h: &HeaderMap) -> Option<String> {
    let v = h.get(header::AUTHORIZATION)?.to_str().ok()?;
    if v.len() > 7 && v[..7].eq_ignore_ascii_case("bearer ") {
        Some(v[7..].trim().to_string())
    } else {
        None
    }
}

/// One `bytes=` range of a `Range` header within `size` bytes (half-open);
/// None for several ranges or one that cannot be satisfied.
pub fn parse_range(h: &str, size: u64) -> Option<std::ops::Range<u64>> {
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
            (b.parse::<u64>().ok()?.saturating_add(1)).min(size)
        };
        (s, e)
    };
    (start < end && start < size).then_some(start..end)
}

/// A file name safe for a download: no path, no control or reserved
/// characters, no leading dots; "file" when nothing is left.
pub fn sanitize_filename(name: &str) -> String {
    let s: String = name
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
    let s = s.trim().trim_start_matches('.').to_string();
    if s.is_empty() { "file".into() } else { s }
}

/// `inline; filename="…"` or `attachment; …` (RFC 6266, with a UTF-8
/// variant when needed).
pub fn content_disposition(kind: &str, name: &str) -> String {
    let s = sanitize_filename(name);
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

/// Fixed windows per key, in memory (one process).
#[derive(Debug, Default)]
pub struct RateLimiter {
    m: Mutex<HashMap<String, (i64, u32)>>,
}

/// The state after a request was counted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Allowed {
    pub limit: u32,
    pub remaining: u32,
    /// Seconds until the window resets.
    pub reset: i64,
}

impl Allowed {
    /// `RateLimit-Limit`, `-Remaining` and `-Reset`.
    pub fn headers(&self) -> [(String, String); 3] {
        [
            ("RateLimit-Limit".into(), self.limit.to_string()),
            ("RateLimit-Remaining".into(), self.remaining.to_string()),
            ("RateLimit-Reset".into(), self.reset.to_string()),
        ]
    }
}

impl RateLimiter {
    pub fn new() -> RateLimiter {
        RateLimiter::default()
    }

    /// Counts one request of `key` at `now` (Unix seconds); Err(seconds to
    /// wait) when `per_window` requests were already made in this window.
    pub fn check(
        &self,
        key: &str,
        per_window: u32,
        window_secs: i64,
        now: i64,
    ) -> std::result::Result<Allowed, i64> {
        let per_window = per_window.max(1);
        let mut m = self.m.lock().unwrap_or_else(|p| p.into_inner());
        if m.len() > 100_000 {
            m.retain(|_, (start, _)| now - *start < window_secs);
        }
        let e = m.entry(key.to_string()).or_insert((now, 0));
        if now - e.0 >= window_secs {
            *e = (now, 0);
        }
        let reset = window_secs - (now - e.0);
        if e.1 >= per_window {
            return Err(reset.max(1));
        }
        e.1 += 1;
        Ok(Allowed {
            limit: per_window,
            remaining: per_window - e.1,
            reset,
        })
    }

    /// [`check`](Self::check) as a `rate_limited` problem with Retry-After.
    pub fn problem(
        &self,
        key: &str,
        per_window: u32,
        window_secs: i64,
        now: i64,
    ) -> Result<Allowed> {
        self.check(key, per_window, window_secs, now)
            .map_err(|retry| {
                let mut p = Problem::new("rate_limited", "Too many requests; slow down.");
                p.retry_after = Some(retry as u64);
                p
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ranges() {
        assert_eq!(parse_range("bytes=0-9", 100), Some(0..10));
        assert_eq!(parse_range("bytes=-10", 100), Some(90..100));
        assert_eq!(parse_range("bytes=90-", 100), Some(90..100));
        assert_eq!(parse_range("bytes=100-", 100), None);
        assert_eq!(parse_range("bytes=0-1,4-5", 100), None);
        assert_eq!(parse_range("bytes=0-18446744073709551615", 10), Some(0..10));
    }

    #[test]
    fn dispositions() {
        assert_eq!(
            content_disposition("attachment", "../a\"b.jpg"),
            "attachment; filename=\"a_b.jpg\""
        );
        assert_eq!(
            content_disposition("inline", "...."),
            "inline; filename=\"file\""
        );
        assert!(content_disposition("inline", "é.jpg").contains("filename*=UTF-8''%C3%A9.jpg"));
    }

    #[test]
    fn limiter() {
        let l = RateLimiter::new();
        assert_eq!(l.check("k", 2, 60, 0).unwrap().remaining, 1);
        assert!(l.check("k", 2, 60, 1).is_ok());
        assert_eq!(l.check("k", 2, 60, 2), Err(58));
        assert!(l.check("k", 2, 60, 60).is_ok());
    }

    #[test]
    fn limit_parameter() {
        let mut q = HashMap::new();
        assert_eq!(limit_param(&q, 50, 200).unwrap(), 50);
        q.insert("limit".to_string(), "9999".to_string());
        assert_eq!(limit_param(&q, 50, 200).unwrap(), 200);
        q.insert("limit".to_string(), "0".to_string());
        assert!(limit_param(&q, 50, 200).is_err());
    }
}
