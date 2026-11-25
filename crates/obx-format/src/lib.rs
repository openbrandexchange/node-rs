//! The OBX canonical import format, vocabularies and GTINs: a port of the
//! pure packages of node-go (`internal/importfmt` without xlsx.go,
//! `internal/vocab`, `internal/gtin`).
//!
//! * [`gtin`]: GTIN-14 normalisation and the GS1 check digit.
//! * [`vocab`]: the four vocabularies of `spec/vocabularies/*.json`,
//!   embedded and parsed once ([`vocab::parts`], [`vocab::materials`],
//!   [`vocab::qualifiers`], [`vocab::care`]).
//! * [`importfmt`]: CSV tables and header names, materials, care codes,
//!   article data cells, image file names and zip entry checks.
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

pub mod gtin;
pub mod importfmt;
pub mod vocab;

mod error;

pub use error::{Error, Result};
