//! The OBX canonical import format (spec `docs/import-format.md`):
//! products.csv, assets.csv, the image file name pattern, the materials
//! grammar, care codes and the article data cells. Port of node-go
//! `internal/importfmt` (without xlsx.go).

mod article;
mod csv;
mod images;
mod values;

pub use article::*;
pub use csv::*;
pub use images::*;
pub use values::*;
