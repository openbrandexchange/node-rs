//! Resumable multipart uploads (ingest.md §4, method 3): the part plan of an
//! upload session, independent of where the parts are kept.
//!
//! ```
//! use obx_ingest::upload::PartPlan;
//!
//! let p = PartPlan::new(20, 8);
//! assert_eq!(p.parts_total(), 3);
//! assert_eq!(p.check_part(3, 4).unwrap(), 4);
//! assert_eq!(p.check_part(2, 7).unwrap_err().code, "validation_failed");
//! assert_eq!(p.check_complete(&[1, 3]).unwrap_err().detail, "Parts missing: [2].");
//! ```

/// The default part size (8 MiB).
pub const PART_BYTES: u64 = 8 << 20;
/// The largest object a session may assemble (2 GiB).
pub const MAX_OBJECT_BYTES: u64 = 2 << 30;

/// A refused part or completion, with its OBX error code.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UploadError {
    pub code: &'static str,
    pub detail: String,
}

fn err(code: &'static str, detail: String) -> UploadError {
    UploadError { code, detail }
}

/// How an object of `bytes` is cut into parts of `part_bytes`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PartPlan {
    pub bytes: u64,
    pub part_bytes: u64,
}

impl PartPlan {
    pub fn new(bytes: u64, part_bytes: u64) -> PartPlan {
        PartPlan {
            bytes,
            part_bytes: part_bytes.max(1),
        }
    }

    /// Checks the declared size of a new session.
    pub fn check_size(bytes: u64, max: u64) -> Result<(), UploadError> {
        if bytes < 1 {
            return Err(err("validation_failed", "bytes must be at least 1.".into()));
        }
        if bytes > max {
            return Err(err(
                "payload_too_large",
                format!("Files are limited to {max} bytes."),
            ));
        }
        Ok(())
    }

    pub fn parts_total(&self) -> u64 {
        self.bytes.div_ceil(self.part_bytes)
    }

    /// The exact size part `n` (1-based) must have.
    pub fn part_len(&self, n: u64) -> u64 {
        if n == self.parts_total() {
            self.bytes - (self.parts_total() - 1) * self.part_bytes
        } else {
            self.part_bytes
        }
    }

    /// Checks part number and size; Ok(expected size).
    pub fn check_part(&self, n: u64, len: u64) -> Result<u64, UploadError> {
        let total = self.parts_total();
        if n < 1 || n > total {
            return Err(err(
                "validation_failed",
                format!("Part number must be 1..{total}."),
            ));
        }
        let want = self.part_len(n);
        if len > want {
            return Err(err(
                "payload_too_large",
                format!("The file is larger than {want} bytes."),
            ));
        }
        if len != want {
            return Err(err(
                "validation_failed",
                format!("Part {n} must be exactly {want} bytes (got {len})."),
            ));
        }
        Ok(want)
    }

    /// The parts not received yet, ascending.
    pub fn missing(&self, received: &[u64]) -> Vec<u64> {
        (1..=self.parts_total())
            .filter(|i| !received.contains(i))
            .collect()
    }

    /// `upload_incomplete` naming the missing parts.
    pub fn check_complete(&self, received: &[u64]) -> Result<(), UploadError> {
        let m = self.missing(received);
        if m.is_empty() {
            return Ok(());
        }
        let list: Vec<String> = m.iter().map(|i| i.to_string()).collect();
        Err(err(
            "upload_incomplete",
            format!("Parts missing: [{}].", list.join(" ")),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_multiple() {
        let p = PartPlan::new(16, 8);
        assert_eq!(p.parts_total(), 2);
        assert_eq!(p.part_len(2), 8);
        assert!(p.check_part(0, 8).is_err());
        assert!(p.check_part(3, 8).is_err());
        assert_eq!(p.check_part(1, 9).unwrap_err().code, "payload_too_large");
        assert!(p.check_complete(&[2, 1]).is_ok());
        assert_eq!(
            PartPlan::check_size(0, 10).unwrap_err().code,
            "validation_failed"
        );
        assert_eq!(
            PartPlan::check_size(11, 10).unwrap_err().code,
            "payload_too_large"
        );
    }
}
