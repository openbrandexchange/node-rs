//! Usage wire format (protocol.md §11), independent of storage and HTTP
//! framework.

use serde::Deserialize;

use crate::db;

/// One reported event (UsageEvent; channel is accepted and not stored,
/// like node-go).
#[derive(Debug, Clone, Deserialize)]
pub struct UsageEvent {
    pub asset_id: String,
    #[serde(default)]
    pub rendition: Option<String>,
    pub event: String,
    #[serde(default)]
    pub at: String,
    #[serde(default)]
    pub count: Option<i64>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Usage {
    #[serde(default)]
    pub events: Vec<UsageEvent>,
}

/// The stored time of a reported event: its own time unless unparsable or
/// more than an hour in the future.
pub fn event_time(at: &str, now: chrono::DateTime<chrono::Utc>) -> String {
    match db::parse_time(at) {
        Some(t) if t < now + chrono::Duration::hours(1) => db::fmt_time(t),
        _ => db::fmt_time(now),
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn event_times() {
        let now = chrono::Utc::now();
        assert_eq!(
            super::event_time("2026-01-02T03:04:05Z", now),
            "2026-01-02T03:04:05.000000Z"
        );
        assert_eq!(super::event_time("nonsense", now), crate::db::fmt_time(now));
        let future = crate::db::fmt_time(now + chrono::Duration::hours(3));
        assert_eq!(super::event_time(&future, now), crate::db::fmt_time(now));
    }
}
