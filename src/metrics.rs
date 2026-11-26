//! Prometheus metrics (text format, no dependency): HTTP request counts and
//! latencies per route pattern, plus gauges read from the database on scrape.
//! The metric names are node-go's, so dashboards keep working.

use std::collections::BTreeMap;
use std::fmt::Write;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};

use crate::app::App;
use crate::problem::Problem;

const BUCKETS: [f64; 12] = [
    0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0,
];

#[derive(Default)]
struct Histogram {
    counts: [u64; BUCKETS.len()],
    sum: f64,
    n: u64,
}

#[derive(Default)]
struct State {
    /// (route, method, code) → count
    requests: BTreeMap<(String, String, u16), u64>,
    hist: BTreeMap<String, Histogram>,
}

pub struct Metrics {
    state: Mutex<State>,
    started: Instant,
}

/// The route pattern of a request, put in the response extensions by the
/// router so the outer layer can label the request.
#[derive(Clone)]
pub struct RouteLabel(pub String);

/// The label for a matched route pattern; catch-alls are "unmatched", the
/// web UI is "ui", so the label set stays bounded.
pub fn route_label(matched: Option<&str>) -> String {
    match matched {
        None => "ui".into(),
        Some("/obx/{*rest}" | "/admin/api/{*rest}") => "unmatched".into(),
        Some(p) => p.into(),
    }
}

impl Metrics {
    pub fn new() -> Metrics {
        Metrics {
            state: Mutex::new(State::default()),
            started: Instant::now(),
        }
    }

    pub fn observe(&self, method: &str, route: &str, code: u16, d: Duration) {
        let method = match method {
            "GET" | "HEAD" | "POST" | "PUT" | "PATCH" | "DELETE" | "OPTIONS" => method,
            _ => "other",
        };
        let mut s = self.state.lock().unwrap();
        *s.requests
            .entry((route.to_string(), method.to_string(), code))
            .or_default() += 1;
        let h = s.hist.entry(route.to_string()).or_default();
        let secs = d.as_secs_f64();
        if let Some(i) = BUCKETS.iter().position(|b| secs <= *b) {
            h.counts[i] += 1;
        }
        h.sum += secs;
        h.n += 1;
    }

    fn write(&self, b: &mut String) {
        let s = self.state.lock().unwrap();
        b.push_str("# HELP obx_http_requests_total HTTP requests by method, route pattern and status code.\n# TYPE obx_http_requests_total counter\n");
        for ((route, method, code), n) in &s.requests {
            let _ = writeln!(
                b,
                "obx_http_requests_total{{method={},route={},code=\"{code}\"}} {n}",
                q(method),
                q(route)
            );
        }
        b.push_str("# HELP obx_http_request_duration_seconds HTTP request latency by route pattern.\n# TYPE obx_http_request_duration_seconds histogram\n");
        for (route, h) in &s.hist {
            let mut cum = 0;
            for (i, le) in BUCKETS.iter().enumerate() {
                cum += h.counts[i];
                let _ = writeln!(
                    b,
                    "obx_http_request_duration_seconds_bucket{{route={},le=\"{le}\"}} {cum}",
                    q(route)
                );
            }
            let _ = writeln!(
                b,
                "obx_http_request_duration_seconds_bucket{{route={},le=\"+Inf\"}} {}",
                q(route),
                h.n
            );
            let _ = writeln!(
                b,
                "obx_http_request_duration_seconds_sum{{route={}}} {}",
                q(route),
                h.sum
            );
            let _ = writeln!(
                b,
                "obx_http_request_duration_seconds_count{{route={}}} {}",
                q(route),
                h.n
            );
        }
        let _ = writeln!(
            b,
            "# HELP obx_uptime_seconds Seconds since the process started.\n# TYPE obx_uptime_seconds gauge\nobx_uptime_seconds {}",
            self.started.elapsed().as_secs()
        );
    }
}

/// A quoted Prometheus label value.
fn q(s: &str) -> String {
    format!(
        "\"{}\"",
        s.replace('\\', "\\\\")
            .replace('"', "\\\"")
            .replace('\n', "\\n")
    )
}

fn gauges(c: &rusqlite::Connection, b: &mut String) {
    let _ = writeln!(
        b,
        "# HELP obx_build_info Build information.\n# TYPE obx_build_info gauge\nobx_build_info{{version={},database=\"sqlite\",software={}}} 1",
        q(crate::app::VERSION),
        q(crate::app::SOFTWARE)
    );
    b.push_str("# HELP obx_jobs Background jobs by kind and status.\n# TYPE obx_jobs gauge\n");
    if let Ok(mut st) = c.prepare("SELECT kind, status, COUNT(*) FROM jobs WHERE status IN ('queued', 'running', 'failed') GROUP BY kind, status ORDER BY kind, status") {
        if let Ok(rows) = st.query_map([], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, i64>(2)?,
            ))
        }) {
            for (k, s, n) in rows.flatten() {
                let _ = writeln!(b, "obx_jobs{{kind={},status={}}} {n}", q(&k), q(&s));
            }
        }
    }
    let mut one = |name: &str, help: &str, sql: &str| {
        if let Ok(n) = c.query_row(sql, [], |r| r.get::<_, i64>(0)) {
            let _ = writeln!(b, "# HELP {name} {help}\n# TYPE {name} gauge\n{name} {n}");
        }
    };
    one(
        "obx_webhook_deliveries_pending",
        "Webhook deliveries waiting to be sent or retried.",
        "SELECT COUNT(*) FROM webhook_deliveries WHERE status = 'pending'",
    );
    one(
        "obx_mail_outbox_pending",
        "E-mails waiting for a retry.",
        "SELECT COUNT(*) FROM mail_outbox WHERE status = 'pending'",
    );
    one(
        "obx_changes_latest_seq",
        "Latest change feed sequence number.",
        "SELECT COALESCE(MAX(seq), 0) FROM changes",
    );
    one(
        "obx_renditions_failed",
        "Originals whose web versions could not be made.",
        "SELECT COUNT(*) FROM render_errors",
    );
    b.push_str("# HELP obx_catalog_visible Published objects visible to retailers.\n# TYPE obx_catalog_visible gauge\n");
    for t in ["brands", "products", "variants", "assets"] {
        if let Ok(n) = c.query_row(
            &format!("SELECT COUNT(*) FROM {t} WHERE visible = 1"),
            [],
            |r| r.get::<_, i64>(0),
        ) {
            let _ = writeln!(
                b,
                "obx_catalog_visible{{type={}}} {n}",
                q(t.trim_end_matches('s'))
            );
        }
    }
    if let Some(rss) = resident_bytes() {
        let _ = writeln!(
            b,
            "# HELP process_resident_memory_bytes Resident memory size in bytes.\n# TYPE process_resident_memory_bytes gauge\nprocess_resident_memory_bytes {rss}"
        );
    }
}

/// Resident set size from /proc (Linux only).
fn resident_bytes() -> Option<u64> {
    let s = std::fs::read_to_string("/proc/self/statm").ok()?;
    let pages: u64 = s.split_whitespace().nth(1)?.parse().ok()?;
    Some(pages * 4096)
}

/// GET /metrics: off unless `OBX_METRICS`; with `OBX_METRICS_TOKEN`,
/// scrapers send it as a bearer token (compared in constant time).
pub async fn handler(
    axum::extract::State(app): axum::extract::State<App>,
    headers: HeaderMap,
) -> Response {
    if !app.cfg.metrics {
        return Problem::new("not_found", "Metrics are off (set OBX_METRICS=true).")
            .into_response();
    }
    if let Some(t) = &app.cfg.metrics_token {
        let got = crate::http::bearer(&headers).unwrap_or_default();
        if !crate::secure::eq(&got, t) {
            let mut r = Problem::new("unauthorized", "Send the metrics token.").into_response();
            r.headers_mut().insert(
                header::WWW_AUTHENTICATE,
                HeaderValue::from_static("Bearer realm=\"metrics\""),
            );
            return r;
        }
    }
    let mut b = String::new();
    app.metrics.write(&mut b);
    let g = app
        .db
        .read(|c| {
            let mut s = String::new();
            gauges(c, &mut s);
            Ok(s)
        })
        .await
        .unwrap_or_default();
    b.push_str(&g);
    let mut r = (StatusCode::OK, b).into_response();
    r.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/plain; version=0.0.4; charset=utf-8"),
    );
    r.headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    r
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn text_format() {
        let m = Metrics::new();
        m.observe("GET", "/obx/v1/products", 200, Duration::from_millis(7));
        m.observe("BREW", "ui", 404, Duration::from_secs(60));
        let mut b = String::new();
        m.write(&mut b);
        assert!(b.contains(
            "obx_http_requests_total{method=\"GET\",route=\"/obx/v1/products\",code=\"200\"} 1"
        ));
        assert!(
            b.contains("obx_http_requests_total{method=\"other\",route=\"ui\",code=\"404\"} 1")
        );
        assert!(b.contains(
            "obx_http_request_duration_seconds_bucket{route=\"/obx/v1/products\",le=\"0.01\"} 1"
        ));
        assert!(b.contains("obx_http_request_duration_seconds_bucket{route=\"ui\",le=\"+Inf\"} 1"));
        assert_eq!(route_label(Some("/obx/{*rest}")), "unmatched");
    }
}
