//! RFC 9457 problem documents with the OBX error codes (protocol.md §11).

use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
pub struct FieldError {
    pub pointer: Option<String>,
    pub obx_error: String,
    pub detail: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct Problem {
    #[serde(rename = "type")]
    pub kind: String,
    pub title: String,
    pub status: u16,
    pub detail: Option<String>,
    pub obx_error: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub errors: Vec<FieldError>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub retry_after: Option<u64>,
}

pub type Result<T> = std::result::Result<T, Problem>;

pub fn status_of(code: &str) -> u16 {
    match code {
        "invalid_request" | "limit_exceeded" | "cursor_invalid" | "invite_invalid" => 400,
        "unauthorized" | "invalid_token" | "access_revoked" | "invalid_credentials" => 401,
        "insufficient_scope"
        | "forbidden"
        | "original_not_allowed"
        | "csrf_failed"
        | "account_blocked" => 403,
        "not_found" => 404,
        "method_not_allowed" => 405,
        "conflict"
        | "idempotency_key_reused"
        | "gtin_conflict"
        | "position_conflict"
        | "upload_incomplete"
        | "mass_unpublish_refused"
        | "setup_required"
        | "setup_completed" => 409,
        "cursor_expired" | "export_expired" => 410,
        "precondition_failed" => 412,
        "payload_too_large" => 413,
        "unsupported_media_type" => 415,
        "validation_failed"
        | "invalid_gtin"
        | "checksum_mismatch"
        | "blob_missing"
        | "unknown_parent"
        | "files_missing"
        | "import_invalid"
        | "workbook_invalid"
        | "workbook_unsafe"
        | "workbook_sheet_missing"
        | "workbook_too_large"
        | "unsafe_url" => 422,
        "rate_limited" => 429,
        "not_implemented" => 501,
        "service_unavailable" => 503,
        _ => 500,
    }
}

fn title_of(code: &str) -> &'static str {
    match code {
        "invalid_request" => "Invalid request",
        "validation_failed" => "Validation failed",
        "unauthorized" => "Authentication required",
        "invalid_token" => "Invalid or expired token",
        "idempotency_key_reused" => "Idempotency-Key reused with another request",
        "access_revoked" => "Access revoked",
        "insufficient_scope" => "Insufficient scope",
        "forbidden" => "Forbidden",
        "not_found" => "Not found",
        "method_not_allowed" => "Method not allowed",
        "conflict" => "Conflict",
        "precondition_failed" => "Precondition failed",
        "payload_too_large" => "Payload too large",
        "unsupported_media_type" => "Unsupported media type",
        "rate_limited" => "Too many requests",
        "limit_exceeded" => "Limit exceeded",
        "cursor_invalid" => "Invalid cursor",
        "cursor_expired" => "Cursor expired",
        "export_expired" => "Export expired",
        "original_not_allowed" => "Original not allowed",
        "invalid_gtin" => "Invalid GTIN",
        "gtin_conflict" => "GTIN already in use",
        "position_conflict" => "Position already in use",
        "checksum_mismatch" => "Checksum mismatch",
        "blob_missing" => "File not uploaded",
        "upload_incomplete" => "Upload incomplete",
        "unknown_parent" => "Unknown parent",
        "files_missing" => "Files missing",
        "import_invalid" => "Import file invalid",
        "mass_unpublish_refused" => "Mass unpublish refused",
        "workbook_invalid" => "Workbook cannot be read",
        "workbook_unsafe" => "Workbook has macros or external links",
        "workbook_sheet_missing" => "No products or assets sheet",
        "workbook_too_large" => "Workbook too large",
        "unsafe_url" => "Unsafe URL",
        "csrf_failed" => "CSRF check failed",
        "invalid_credentials" => "Invalid e-mail or password",
        "account_blocked" => "Account blocked",
        "setup_required" => "Setup required",
        "setup_completed" => "Setup already completed",
        "invite_invalid" => "Invitation or link invalid",
        "not_implemented" => "Not implemented",
        "service_unavailable" => "Service unavailable",
        _ => "Internal error",
    }
}

impl Problem {
    pub fn new(code: &str, detail: impl Into<String>) -> Problem {
        let d: String = detail.into();
        Problem {
            kind: format!("https://openbrandexchange.com/errors/{code}"),
            title: title_of(code).into(),
            status: status_of(code),
            detail: if d.is_empty() { None } else { Some(d) },
            obx_error: code.into(),
            errors: Vec::new(),
            retry_after: None,
        }
    }

    /// Adds a field error (JSON Pointer or CSV locator; "" = whole document).
    pub fn field(mut self, pointer: &str, code: &str, detail: impl Into<String>) -> Problem {
        self.errors.push(FieldError {
            pointer: Some(pointer.into()),
            obx_error: code.into(),
            detail: detail.into(),
        });
        self
    }

    pub fn with_status(mut self, status: u16) -> Problem {
        self.status = status;
        self
    }

    pub fn internal(e: impl std::fmt::Display) -> Problem {
        tracing::error!(error = %e, "request failed");
        Problem::new("internal_error", "An unexpected error occurred.")
    }

    pub fn detail_str(&self) -> &str {
        self.detail.as_deref().unwrap_or("")
    }
}

impl std::fmt::Display for Problem {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.obx_error, self.detail_str())
    }
}

/// Any other error is an internal error: it is logged and the client sees
/// only "An unexpected error occurred." (so `?` works on storage errors).
/// For that reason Problem itself does not implement `std::error::Error`.
impl<E: std::error::Error> From<E> for Problem {
    fn from(e: E) -> Problem {
        Problem::internal(e)
    }
}

#[cfg(feature = "axum")]
impl axum::response::IntoResponse for Problem {
    fn into_response(self) -> axum::response::Response {
        use axum::http::{HeaderValue, StatusCode, header};
        let status = StatusCode::from_u16(self.status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
        let body = serde_json::to_vec(&self).unwrap_or_default();
        let mut r = (status, body).into_response();
        let h = r.headers_mut();
        h.insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/problem+json"),
        );
        h.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
        if let Some(s) = self.retry_after {
            h.insert(header::RETRY_AFTER, HeaderValue::from(s));
        }
        r
    }
}

/// A plain error type for internal failures (storage, I/O).
pub mod anyhow_lite {
    #[derive(Debug)]
    pub struct Error(pub String);
    impl std::fmt::Display for Error {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str(&self.0)
        }
    }
    impl std::error::Error for Error {}
}
