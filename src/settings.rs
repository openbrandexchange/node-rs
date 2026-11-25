//! The brand's own settings (company, branding, portal options, default
//! rights), stored as JSON in `meta.settings` exactly as node-go stored them.

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::model::{LocalizedText, Rights};

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct Company {
    pub name: String,
    pub website: Option<String>,
    pub contact_email: Option<String>,
    pub country: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct Branding {
    pub display_name: String,
    pub logo_url: Option<String>,
    pub accent_color: Option<String>,
    pub welcome_text: Option<LocalizedText>,
    pub portal_name: Option<LocalizedText>,
    pub favicon_url: Option<String>,
    pub theme: Option<serde_json::Map<String, Value>>,
    pub login: Option<serde_json::Map<String, Value>>,
    pub home: Option<serde_json::Map<String, Value>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct Portal {
    pub access_requests_enabled: bool,
    pub allow_original_download: bool,
    pub allow_article_data_export: bool,
    pub retailer_api_self_service: bool,
    pub languages: Vec<String>,
    pub default_language: String,
}

impl Default for Portal {
    fn default() -> Portal {
        Portal {
            access_requests_enabled: true,
            allow_original_download: true,
            allow_article_data_export: true,
            retailer_api_self_service: false,
            languages: vec!["en".into()],
            default_language: "en".into(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct Defaults {
    pub rights: Rights,
    pub ingest_status: String,
}

impl Default for Defaults {
    fn default() -> Defaults {
        Defaults {
            rights: Rights::default(),
            ingest_status: "published".into(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct Retention {
    pub download_events_days: i64,
    pub audit_log_days: i64,
    pub access_requests_days: i64,
}

impl Default for Retention {
    fn default() -> Retention {
        Retention {
            download_events_days: 730,
            audit_log_days: 365,
            access_requests_days: 365,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct Settings {
    pub company: Company,
    pub branding: Branding,
    pub portal: Portal,
    pub defaults: Defaults,
    pub retention: Retention,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub logo_sha: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub logo_type: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub favicon_sha: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub favicon_type: String,
}

impl Settings {
    pub fn load(c: &rusqlite::Connection) -> crate::problem::Result<Settings> {
        let raw = crate::db::get_meta(c, "settings")?;
        let mut s: Settings = raw
            .and_then(|r| serde_json::from_str(&r).ok())
            .unwrap_or_default();
        if s.defaults.ingest_status.is_empty() {
            s.defaults.ingest_status = "published".into();
        }
        if s.defaults.rights.license.is_empty() {
            s.defaults.rights = Rights::default();
        }
        Ok(s)
    }

    pub fn save(&self, c: &rusqlite::Connection) -> crate::problem::Result<()> {
        crate::db::set_meta(
            c,
            "settings",
            &serde_json::to_string(self).expect("settings json"),
        )
    }

    /// The content languages, the default first.
    pub fn content_languages(&self) -> Vec<String> {
        let mut out = Vec::new();
        if !self.portal.default_language.is_empty() {
            out.push(self.portal.default_language.clone());
        }
        for l in &self.portal.languages {
            if *l != self.portal.default_language {
                out.push(l.clone());
            }
        }
        if out.is_empty() {
            out.push("en".into());
        }
        out
    }

    pub fn display_name(&self) -> &str {
        if self.branding.display_name.is_empty() {
            &self.company.name
        } else {
            &self.branding.display_name
        }
    }
}
