//! Signatures of the Open Brand Exchange protocol.
//!
//! * [`UrlSigner`]: short-lived signed URLs for asset bytes (protocol.md
//!   §5.5.1). Signing is *windowed*: every request in the same window gets
//!   the very same URL, so HTTP caches and CDNs hit, and the expiry is the
//!   real end of the URL (between one and two windows away). The cache key of
//!   the bytes is their `sha256`, never the URL. An intact signature whose
//!   expiry has passed is [`VerifyError::Expired`] (`url_expired` in spec
//!   0.4, `forbidden` before); anything else is [`VerifyError::Invalid`].
//! * [`webhook_signature`] / [`verify_webhook`]: the `OBX-Signature`
//!   header of webhook deliveries (protocol.md §9).
//!
//! The URL format (`?exp=&v=&sig=`, HMAC over `GET\n<path>\n<exp>\n<viewer>`)
//! is node-go's, so URLs from either node verify on the other.
//!
//! ```
//! use obx_auth::Keys;
//! use obx_sign::UrlSigner;
//!
//! let s = UrlSigner::new(Keys::new(b"a master secret of at least 32 bytes!!"), "https://node.example");
//! let now = 1_800_000_000;
//! let a = s.sign_at("/obx/v1/assets/ast_1/renditions/web", "c.cli_1", now);
//! let b = s.sign_at("/obx/v1/assets/ast_1/renditions/web", "c.cli_1", now + 60);
//! assert_eq!(a.url, b.url); // same window, same URL
//! let q = obx_sign::query_of(&a.url);
//! let v = s.verify_at("/obx/v1/assets/ast_1/renditions/web", &q, now).unwrap();
//! assert_eq!(v.viewer, "c.cli_1");
//! ```
#![forbid(unsafe_code)]

use std::collections::HashMap;

use hmac::{Hmac, Mac};
use obx_auth::Keys;
use sha2::Sha256;

/// The default signing window: URLs stay the same for an hour and expire
/// one to two hours after they were handed out.
pub const DEFAULT_WINDOW_SECS: i64 = 3600;
/// The shortest lifetime the spec allows for a signed URL.
pub const MIN_LIFETIME_SECS: i64 = 300;
/// The longest lifetime the spec allows for a signed URL.
pub const MAX_LIFETIME_SECS: i64 = 24 * 3600;

/// A signed URL and its expiry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedUrl {
    pub url: String,
    /// Unix seconds.
    pub expires: i64,
}

impl SignedUrl {
    /// The expiry as RFC 3339 (`url_expires_at`).
    pub fn expires_rfc3339(&self) -> String {
        rfc3339(self.expires)
    }
}

/// A valid signature: who it was signed for and when it ends.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Verified {
    /// The viewer tag the URL was signed for ("" when none).
    pub viewer: String,
    /// Unix seconds.
    pub expires: i64,
}

impl Verified {
    /// `max-age` for the bytes: never past the URL's expiry.
    pub fn max_age(&self, now: i64, cap: i64) -> i64 {
        (self.expires - now).clamp(0, cap)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerifyError {
    /// Missing, changed or foreign signature, or an expiry too far ahead.
    Invalid,
    /// The signature is intact but its expiry has passed.
    Expired,
}

/// Signs and verifies asset URLs of one node.
#[derive(Debug, Clone)]
pub struct UrlSigner {
    keys: Keys,
    base: String,
    window: i64,
}

impl UrlSigner {
    /// A signer with the default window; `base` is the node's public URL.
    pub fn new(keys: Keys, base: impl Into<String>) -> UrlSigner {
        UrlSigner {
            keys,
            base: base.into().trim_end_matches('/').to_string(),
            window: DEFAULT_WINDOW_SECS,
        }
    }

    /// The window length in seconds (clamped so the lifetime stays within
    /// the spec's 5 minutes to 24 hours).
    pub fn with_window(mut self, secs: i64) -> UrlSigner {
        self.window = secs.clamp(MIN_LIFETIME_SECS, MAX_LIFETIME_SECS / 2);
        self
    }

    fn sig(&self, path: &str, viewer: &str, exp: i64) -> String {
        self.keys
            .sign("url", &format!("GET\n{path}\n{exp}\n{viewer}"))
    }

    /// The expiry of a URL signed at `now`: the end of the next window.
    pub fn expiry_at(&self, now: i64) -> i64 {
        (now.div_euclid(self.window) + 2) * self.window
    }

    /// Signs `path` for `viewer` now.
    pub fn sign(&self, path: &str, viewer: &str) -> SignedUrl {
        self.sign_at(path, viewer, unix_now())
    }

    pub fn sign_at(&self, path: &str, viewer: &str, now: i64) -> SignedUrl {
        let exp = self.expiry_at(now);
        let mut q = url::form_urlencoded::Serializer::new(String::new());
        q.append_pair("exp", &exp.to_string());
        if !viewer.is_empty() {
            q.append_pair("v", viewer);
        }
        q.append_pair("sig", &self.sig(path, viewer, exp));
        SignedUrl {
            url: format!("{}{path}?{}", self.base, q.finish()),
            expires: exp,
        }
    }

    pub fn verify(&self, path: &str, q: &HashMap<String, String>) -> Result<Verified, VerifyError> {
        self.verify_at(path, q, unix_now())
    }

    /// Checks the `exp`, `v` and `sig` query parameters of a request for
    /// `path`.
    pub fn verify_at(
        &self,
        path: &str,
        q: &HashMap<String, String>,
        now: i64,
    ) -> Result<Verified, VerifyError> {
        let sig = q
            .get("sig")
            .filter(|s| !s.is_empty())
            .ok_or(VerifyError::Invalid)?;
        let exp: i64 = q
            .get("exp")
            .and_then(|e| e.parse().ok())
            .ok_or(VerifyError::Invalid)?;
        let viewer = q.get("v").cloned().unwrap_or_default();
        if !obx_auth::eq(&sig.to_lowercase(), &self.sig(path, &viewer, exp)) {
            return Err(VerifyError::Invalid);
        }
        if exp > now + MAX_LIFETIME_SECS + 3600 {
            return Err(VerifyError::Invalid);
        }
        if exp < now {
            return Err(VerifyError::Expired);
        }
        Ok(Verified {
            viewer,
            expires: exp,
        })
    }
}

/// The query parameters of a URL.
pub fn query_of(url: &str) -> HashMap<String, String> {
    url::Url::parse(url)
        .map(|u| u.query_pairs().into_owned().collect())
        .unwrap_or_default()
}

fn unix_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Unix seconds as RFC 3339 in UTC (`2026-01-02T03:04:05Z`).
pub fn rfc3339(t: i64) -> String {
    let days = t.div_euclid(86400);
    let secs = t.rem_euclid(86400);
    // Civil date from days since 1970-01-01 (Howard Hinnant's algorithm).
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z",
        secs / 3600,
        secs % 3600 / 60,
        secs % 60
    )
}

/// `v1=<hex>`: HMAC-SHA256 of `<timestamp>.<raw body>` with the webhook's
/// secret (protocol.md §9).
pub fn webhook_signature(secret: &str, timestamp: &str, body: &[u8]) -> String {
    let mut m = <Hmac<Sha256> as Mac>::new_from_slice(secret.as_bytes()).expect("hmac key");
    m.update(timestamp.as_bytes());
    m.update(b".");
    m.update(body);
    format!("v1={}", hex::encode(m.finalize().into_bytes()))
}

/// Checks a received webhook signature header (constant time).
pub fn verify_webhook(secret: &str, timestamp: &str, body: &[u8], header: &str) -> bool {
    obx_auth::eq(header.trim(), &webhook_signature(secret, timestamp, body))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn signer() -> UrlSigner {
        UrlSigner::new(Keys::new(b"0123456789abcdef0123456789abcdef"), "http://n")
    }

    #[test]
    fn window_and_expiry() {
        let s = signer();
        let now = 1_800_000_123;
        let u = s.sign_at("/p", "a", now);
        assert!(
            u.expires - now >= DEFAULT_WINDOW_SECS && u.expires - now <= 2 * DEFAULT_WINDOW_SECS
        );
        assert_eq!(u.expires % DEFAULT_WINDOW_SECS, 0);
        let q = query_of(&u.url);
        assert_eq!(s.verify_at("/p", &q, now).unwrap().viewer, "a");
        assert_eq!(s.verify_at("/other", &q, now), Err(VerifyError::Invalid));
        assert_eq!(
            s.verify_at("/p", &q, u.expires + 1),
            Err(VerifyError::Expired)
        );
        let mut q2 = q.clone();
        q2.insert("v".into(), "c.someone".into());
        assert_eq!(s.verify_at("/p", &q2, now), Err(VerifyError::Invalid));
        q2 = q.clone();
        q2.remove("sig");
        assert_eq!(s.verify_at("/p", &q2, now), Err(VerifyError::Invalid));
    }

    #[test]
    fn dates() {
        assert_eq!(rfc3339(0), "1970-01-01T00:00:00Z");
        assert_eq!(rfc3339(951_782_400), "2000-02-29T00:00:00Z");
        assert_eq!(rfc3339(1_798_761_599), "2026-12-31T23:59:59Z");
    }

    #[test]
    fn webhook_vector() {
        let v: serde_json::Value =
            serde_json::from_str(include_str!("../tests/webhook-signature-vector.json")).unwrap();
        let (secret, ts, body) = (
            v["secret"].as_str().unwrap(),
            v["timestamp"].as_str().unwrap(),
            v["raw_body"].as_str().unwrap().as_bytes(),
        );
        assert_eq!(
            webhook_signature(secret, ts, body),
            v["header"].as_str().unwrap()
        );
        assert!(verify_webhook(
            secret,
            ts,
            body,
            v["header"].as_str().unwrap()
        ));
        assert!(!verify_webhook(
            secret,
            ts,
            b"{}",
            v["header"].as_str().unwrap()
        ));
    }
}
