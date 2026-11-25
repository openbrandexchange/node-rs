//! Types of the [Open Brand Exchange](https://openbrandexchange.com) (OBX)
//! protocol, version 0.3: the objects a node publishes and accepts
//! ([`model`]), RFC 9457 problem documents with the OBX error codes
//! ([`problem`]), object ids ([`ids`]), GTINs ([`gtin`]), the spec's
//! vocabularies ([`vocab`]) and, with the default `validate` feature,
//! validation against the spec's JSON Schemas ([`schemas`]).
//!
//! These crates are storage- and framework-agnostic: they are the shared
//! core of the reference node (`node-rs`) and of any other OBX
//! implementation. The optional `axum` feature makes [`Problem`] an axum
//! response.
//!
//! ```
//! use obx_types::{gtin, Problem};
//!
//! assert_eq!(gtin::normalize("4006381333931").as_deref(), Some("04006381333931"));
//! let p = Problem::new("not_found", "Product not found.");
//! assert_eq!(p.status, 404);
//! ```
#![forbid(unsafe_code)]

pub mod gtin;
pub mod ids;
pub mod model;
pub mod problem;
#[cfg(feature = "validate")]
pub mod schemas;
pub mod vocab;

pub use problem::{FieldError, Problem, Result};

/// The version of the specification these types follow.
pub const SPEC_VERSION: &str = "0.3.1";
/// The value of the `OBX-Version` header (major.minor).
pub const OBX_VERSION: &str = "0.3";

/// OAuth2 scopes of the protocol API (protocol.md §4).
pub mod scopes {
    pub const CATALOG_READ: &str = "catalog:read";
    pub const MEDIA_READ: &str = "media:read";
    pub const MEDIA_ORIGINAL: &str = "media:original";
    pub const USAGE_WRITE: &str = "usage:write";
    /// Every scope, in the order discovery lists them.
    pub const ALL: [&str; 4] = [CATALOG_READ, MEDIA_READ, MEDIA_ORIGINAL, USAGE_WRITE];
}
