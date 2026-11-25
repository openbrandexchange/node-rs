//! Getting catalog data into an Open Brand Exchange node: the canonical
//! import format and resumable uploads, as pure functions without storage
//! or HTTP (a port of node-go's `internal/importfmt`).
//!
//! * [`importfmt`]: CSV tables and header names, materials, care codes,
//!   article data cells, image file names and zip entry checks.
//! * [`upload`]: the part plan of a resumable multipart upload.
//! * [`gtin`] and [`vocab`] are re-exported from `obx-types`.
//!
//! Conventions of the port:
//!
//! * Go's `(value, err)` is [`Result`] with [`Error`], whose message is the
//!   text node-go produces (callers prefix it as node-go does, e.g.
//!   `"materials: " + message`). Go's `(value, ok)` is `Option`.
//! * Go's `""` for "not given" is `Option<String>` (image role/view,
//!   footwear parts, certification licence).
//! * Values node-go writes into JSON documents are available as
//!   `serde_json::Value` in exactly node-go's shape:
//!   [`importfmt::materials_json`], [`importfmt::care_json`],
//!   [`importfmt::Footwear::to_json`], [`importfmt::Certification::to_json`]
//!   and [`importfmt::parse_feature`] (which returns the feature value
//!   itself). Numbers go through [`importfmt::json_number`], so an integral
//!   `f64` is written as Go writes it (`100`, not `100.0`); use it for
//!   measurements too.

#![forbid(unsafe_code)]

pub mod importfmt;
pub mod upload;

pub use obx_types::{gtin, vocab};

mod error;

pub use error::{Error, Result};
