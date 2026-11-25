//! Webhook wire format (protocol.md §10), independent of storage and HTTP
//! framework: event names, the event envelope, signing and verification.

use hmac::{Hmac, Mac};
use sha2::Sha256;

/// Events an API client may subscribe to.
pub const CLIENT_EVENTS: [&str; 3] = ["changes.available", "grant.updated", "export.completed"];
/// Events the brand's own (admin) webhooks may subscribe to.
pub const BRAND_EVENTS: [&str; 3] = [
    "access_request.created",
    "import_run.completed",
    "ingest_job.completed",
];
/// The event a test delivery sends.
pub const TEST_EVENT: &str = "webhook.test";

pub const HEADER_ID: &str = "OBX-Webhook-Id";
pub const HEADER_TIMESTAMP: &str = "OBX-Webhook-Timestamp";
pub const HEADER_SIGNATURE: &str = "OBX-Webhook-Signature";
/// Prefix of a subscription secret.
pub const SECRET_PREFIX: &str = "whsec_";

/// A WebhookEvent document.
pub fn event(id: &str, typ: &str, created_at: &str, data: serde_json::Value) -> serde_json::Value {
    serde_json::json!({"id": id, "type": typ, "created_at": created_at, "data": data})
}

/// `v1=<hex HMAC-SHA256(secret, timestamp "." body)>`.
pub fn signature(secret: &str, timestamp: &str, body: &[u8]) -> String {
    let mut m = <Hmac<Sha256> as Mac>::new_from_slice(secret.as_bytes()).expect("hmac key");
    m.update(timestamp.as_bytes());
    m.update(b".");
    m.update(body);
    format!("v1={}", hex::encode(m.finalize().into_bytes()))
}

/// Checks a signature header (any of several comma-separated `v1=`
/// values) in constant time, and that the timestamp is within `tolerance`
/// seconds of `now`.
#[allow(dead_code)] // for receivers and tests; moves to the shared signing crate
pub fn verify(
    secret: &str,
    timestamp: &str,
    body: &[u8],
    header: &str,
    now: i64,
    tolerance: i64,
) -> bool {
    let Ok(ts) = timestamp.parse::<i64>() else {
        return false;
    };
    if (now - ts).abs() > tolerance {
        return false;
    }
    header.split(',').any(|part| {
        let Some(h) = part.trim().strip_prefix("v1=") else {
            return false;
        };
        let Ok(got) = hex::decode(h) else {
            return false;
        };
        let mut m = <Hmac<Sha256> as Mac>::new_from_slice(secret.as_bytes()).expect("hmac key");
        m.update(timestamp.as_bytes());
        m.update(b".");
        m.update(body);
        m.verify_slice(&got).is_ok()
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sign_and_verify() {
        let s = signature("whsec_x", "1700000000", b"{}");
        assert!(verify("whsec_x", "1700000000", b"{}", &s, 1700000010, 300));
        assert!(verify(
            "whsec_x",
            "1700000000",
            b"{}",
            &format!("v1=00, {s}"),
            1700000000,
            300
        ));
        assert!(!verify("whsec_y", "1700000000", b"{}", &s, 1700000000, 300));
        assert!(!verify(
            "whsec_x",
            "1700000000",
            b"{ }",
            &s,
            1700000000,
            300
        ));
        assert!(!verify("whsec_x", "1700000000", b"{}", &s, 1700009999, 300));
        assert!(!verify("whsec_x", "x", b"{}", &s, 1700000000, 300));
        assert_eq!(
            s,
            crate::secure::webhook_signature("whsec_x", "1700000000", b"{}")
        );
    }
}
