//! Export wire format (protocol.md §9), independent of storage and HTTP
//! framework: the request, part and result documents, stored-object keys
//! and zip entry naming.

use serde::{Deserialize, Serialize};

/// The largest zip part (protocol.md §9).
pub const PART_MAX: u64 = 2 << 30;
/// How long a finished export stays readable.
pub const EXPORT_TTL_HOURS: i64 = 48;

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ExportFilter {
    #[serde(default)]
    pub brand_ids: Option<Vec<String>>,
    #[serde(default)]
    pub product_ids: Option<Vec<String>>,
    #[serde(default)]
    pub gtins: Option<Vec<String>>,
    #[serde(default)]
    pub updated_since: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ExportRequest {
    #[serde(default)]
    pub filter: ExportFilter,
    #[serde(default)]
    pub renditions: Vec<String>,
    #[serde(default)]
    pub include_data: Option<bool>,
    /// Language selection (protocol.md §2.3): a tag or `universal`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lang: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ExportPart {
    pub number: usize,
    pub bytes: u64,
    pub sha256: String,
    pub files: usize,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ExportResult {
    #[serde(default)]
    pub parts: Vec<ExportPart>,
    #[serde(default)]
    pub cursor: String,
}

/// Makes a style number usable as a zip folder name.
pub fn safe_zip_segment(s: &str) -> String {
    let s = s.replace(['/', '\\'], "_").replace("..", "_");
    sanitize_filename(&s)
}

/// node-go sanitizeFilename: the last path segment without control and
/// reserved characters, no leading dots, never empty.
pub fn sanitize_filename(s: &str) -> String {
    let s = s.replace('\\', "/");
    let base = s.rsplit('/').next().unwrap_or("");
    let out: String = base
        .chars()
        .map(|c| {
            if (c as u32) < 0x20 || c == '\x7f' || "\":*?<>|".contains(c) {
                '_'
            } else {
                c
            }
        })
        .collect();
    let out = out.trim().trim_start_matches('.').to_string();
    if out.is_empty() { "file".into() } else { out }
}

/// The stored key of an export's manifest.
pub fn manifest_key(export_id: &str) -> String {
    format!("exports/{export_id}/manifest.ndjson")
}

/// The stored key of part n (from 1) of an export.
pub fn part_key(export_id: &str, n: usize) -> String {
    format!("exports/{export_id}/part-{n}.zip")
}

/// The download name of part n.
pub fn part_filename(export_id: &str, n: usize) -> String {
    format!("obx-export-{export_id}-part-{n}.zip")
}

/// The zip entry of an asset file: `<style_number>/<rendition>/<filename>`.
pub fn entry_path(style_number: &str, rendition: &str, filename: &str) -> String {
    format!(
        "{}/{rendition}/{}",
        safe_zip_segment(style_number),
        sanitize_filename(filename)
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names() {
        assert_eq!(safe_zip_segment("../a/b"), "__a_b");
        assert_eq!(safe_zip_segment(".."), "_");
        assert_eq!(sanitize_filename("x\\y/..z.jpg"), "z.jpg");
        assert_eq!(sanitize_filename("a:b"), "a_b");
        assert!(!safe_zip_segment("a/../../etc").contains('/'));
        assert_eq!(entry_path("MN/1", "web", "../x.jpg"), "MN_1/web/x.jpg");
        assert_eq!(part_key("job_1", 2), "exports/job_1/part-2.zip");
    }
}
