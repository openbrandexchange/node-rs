//! Reading an import zip (a package or an images zip) safely: the entry
//! names are checked before anything is read (zip-slip: absolute paths,
//! drive letters, `..`, device names, symbolic links), the central
//! directory is checked against decompression-bomb limits (entry count,
//! total declared size, compression ratio), and every read counts the
//! inflated bytes, so an entry that inflates beyond its declared size is
//! refused instead of trusted.

use std::io::{Read, Seek};

use super::safe_entry;

/// The limits of an import zip.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ZipLimits {
    /// Most entries (directories included).
    pub max_entries: usize,
    /// Most bytes all entries may declare and inflate to, together.
    pub max_total_bytes: u64,
    /// An entry larger than `ratio_floor` may not be more than this many
    /// times its compressed size.
    pub max_ratio: u64,
    pub ratio_floor: u64,
}

/// The limits node-go applies to import zips (100,000 entries, 3,000 MiB
/// inflated), plus a ratio check: deflate cannot compress real data more
/// than about 1,032 times, so an entry above 64 MiB that claims more than
/// 1,000 times is refused.
pub const PACKAGE_LIMITS: ZipLimits = ZipLimits {
    max_entries: 100_000,
    max_total_bytes: 3000 << 20,
    max_ratio: 1000,
    ratio_floor: 64 << 20,
};

/// Why a zip cannot be read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ZipError {
    /// Not a readable zip file.
    Unreadable(String),
    /// An entry name or type that could escape the folder it is unpacked in.
    Unsafe(String),
    /// More entries than [`ZipLimits::max_entries`].
    TooManyEntries(usize),
    /// The entries declare or inflate to more than the limits allow.
    TooLarge(String),
}

impl std::fmt::Display for ZipError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ZipError::Unreadable(m) => write!(f, "the zip cannot be read: {m}"),
            ZipError::Unsafe(m) => write!(f, "unsafe zip entry: {m}"),
            ZipError::TooManyEntries(n) => write!(f, "the zip has more than {n} entries"),
            ZipError::TooLarge(m) => write!(f, "the zip is too large: {m}"),
        }
    }
}

impl std::error::Error for ZipError {}

/// One entry of the central directory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ZipEntry {
    pub index: usize,
    /// The name as stored (`/` or `\` separated).
    pub name: String,
    /// The declared uncompressed size.
    pub size: u64,
    pub compressed_size: u64,
    pub is_dir: bool,
}

/// An opened, checked zip.
pub struct ZipPackage<R: Read + Seek> {
    archive: zip::ZipArchive<R>,
    entries: Vec<ZipEntry>,
    limits: ZipLimits,
    inflated: u64,
}

impl<R: Read + Seek> std::fmt::Debug for ZipPackage<R> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ZipPackage")
            .field("entries", &self.entries.len())
            .field("inflated", &self.inflated)
            .finish()
    }
}

impl<R: Read + Seek> ZipPackage<R> {
    /// Opens a zip and checks every entry and the limits from the central
    /// directory, before anything is inflated.
    pub fn open(r: R, limits: ZipLimits) -> Result<ZipPackage<R>, ZipError> {
        let mut archive =
            zip::ZipArchive::new(r).map_err(|e| ZipError::Unreadable(e.to_string()))?;
        if archive.len() > limits.max_entries {
            return Err(ZipError::TooManyEntries(limits.max_entries));
        }
        let mut entries = Vec::with_capacity(archive.len());
        let mut total: u64 = 0;
        for i in 0..archive.len() {
            let e = archive
                .by_index_raw(i)
                .map_err(|e| ZipError::Unreadable(e.to_string()))?;
            let name = e
                .name()
                .map_err(|e| ZipError::Unreadable(e.to_string()))?
                .to_string();
            safe_entry(&name, e.is_symlink()).map_err(|err| ZipError::Unsafe(err.to_string()))?;
            if e.encrypted() {
                return Err(ZipError::Unreadable(format!(
                    "the entry {name} is encrypted"
                )));
            }
            let (u, c) = (e.size(), e.compressed_size());
            total = total.saturating_add(u);
            if total > limits.max_total_bytes {
                return Err(ZipError::TooLarge(format!(
                    "it unpacks to more than {} bytes",
                    limits.max_total_bytes
                )));
            }
            if u > limits.ratio_floor && u > limits.max_ratio.saturating_mul(c.max(1)) {
                return Err(ZipError::TooLarge(format!(
                    "{name} expands from {c} to {u} bytes (more than {} times)",
                    limits.max_ratio
                )));
            }
            entries.push(ZipEntry {
                index: i,
                is_dir: e.is_dir(),
                name,
                size: u,
                compressed_size: c,
            });
        }
        Ok(ZipPackage {
            archive,
            entries,
            limits,
            inflated: 0,
        })
    }

    /// The checked entries, in central-directory order.
    pub fn entries(&self) -> &[ZipEntry] {
        &self.entries
    }

    /// Inflates entry `index`, at most `limit` bytes (more is TooLarge).
    /// An entry that inflates beyond its declared size, or past the total
    /// limit of the package, is refused.
    pub fn read(&mut self, index: usize, limit: u64) -> Result<Vec<u8>, ZipError> {
        let Some(entry) = self.entries.iter().find(|e| e.index == index).cloned() else {
            return Err(ZipError::Unreadable(format!("no entry {index}")));
        };
        if entry.size > limit {
            return Err(ZipError::TooLarge(format!(
                "{} is larger than {limit} bytes",
                entry.name
            )));
        }
        let room = self.limits.max_total_bytes.saturating_sub(self.inflated);
        let mut f = self
            .archive
            .by_index(index)
            .map_err(|e| ZipError::Unreadable(e.to_string()))?;
        let mut data = Vec::new();
        let res = (&mut f)
            .take(entry.size.min(room).saturating_add(1))
            .read_to_end(&mut data);
        let n = data.len() as u64;
        self.inflated = self.inflated.saturating_add(n);
        if n > entry.size
            || self.inflated > self.limits.max_total_bytes
            || res
                .as_ref()
                .is_err_and(|e| beyond_declared(e, n, entry.size))
        {
            return Err(ZipError::TooLarge(format!(
                "{} expands beyond its declared size",
                entry.name
            )));
        }
        res.map_err(|e| ZipError::Unreadable(format!("{}: {e}", entry.name)))?;
        Ok(data)
    }
}

/// Whether a read error means the entry inflates beyond its declared size:
/// the zip reader says so, or it stopped at the declared size with a bad
/// checksum.
pub(crate) fn beyond_declared(e: &std::io::Error, n: u64, declared: u64) -> bool {
    e.to_string().contains("larger than its declared") || (n >= declared && declared > 0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Cursor, Write};

    fn build(entries: &[(&str, &[u8])]) -> Vec<u8> {
        let mut buf = Cursor::new(Vec::new());
        let mut z = zip::ZipWriter::new(&mut buf);
        for (n, d) in entries {
            z.start_file(*n, zip::write::SimpleFileOptions::default())
                .unwrap();
            z.write_all(d).unwrap();
        }
        z.finish().unwrap();
        buf.into_inner()
    }

    /// Stores raw entry names, which the zip writer would not allow.
    fn rename(mut data: Vec<u8>, from: &str, to: &str) -> Vec<u8> {
        assert_eq!(from.len(), to.len());
        let (f, t) = (from.as_bytes(), to.as_bytes());
        let mut i = 0;
        while i + f.len() <= data.len() {
            if &data[i..i + f.len()] == f {
                data[i..i + f.len()].copy_from_slice(t);
            }
            i += 1;
        }
        data
    }

    fn open(d: Vec<u8>) -> Result<ZipPackage<Cursor<Vec<u8>>>, ZipError> {
        ZipPackage::open(Cursor::new(d), PACKAGE_LIMITS)
    }

    #[test]
    fn reads_a_package() {
        let mut p = open(build(&[
            ("products.csv", b"style_number\nA\n"),
            ("images/A.jpg", b"x"),
        ]))
        .unwrap();
        assert_eq!(p.entries().len(), 2);
        assert_eq!(p.read(0, 1 << 20).unwrap(), b"style_number\nA\n");
        assert!(matches!(p.read(0, 3), Err(ZipError::TooLarge(_))));
    }

    #[test]
    fn refuses_zip_slip() {
        for bad in [
            "../x.csv",
            "/etc/pass",
            "C:/x.csvv",
            "a/../../bb",
            "aux.csv/x",
        ] {
            let good = "a".repeat(bad.len());
            let d = rename(build(&[(good.as_str(), b"x")]), &good, bad);
            assert!(matches!(open(d), Err(ZipError::Unsafe(_))), "{bad}");
        }
    }

    #[test]
    fn refuses_symlinks() {
        let mut buf = Cursor::new(Vec::new());
        let mut z = zip::ZipWriter::new(&mut buf);
        z.add_symlink(
            "images/link.jpg",
            "/etc/passwd",
            zip::write::SimpleFileOptions::default(),
        )
        .unwrap();
        z.finish().unwrap();
        assert!(matches!(open(buf.into_inner()), Err(ZipError::Unsafe(_))));
    }

    #[test]
    fn refuses_too_many_entries() {
        let names: Vec<String> = (0..11).map(|i| format!("{i}.txt")).collect();
        let e: Vec<(&str, &[u8])> = names.iter().map(|n| (n.as_str(), &b"x"[..])).collect();
        let limits = ZipLimits {
            max_entries: 10,
            ..PACKAGE_LIMITS
        };
        assert!(matches!(
            ZipPackage::open(Cursor::new(build(&e)), limits),
            Err(ZipError::TooManyEntries(10))
        ));
    }

    #[test]
    fn refuses_a_bomb() {
        // 2 MiB of zeros compress to about 2 KiB: over a 1 MiB floor at a
        // ratio of 100 the declared size alone refuses it.
        let zeros = vec![0u8; 2 << 20];
        let d = build(&[("products.csv", &zeros)]);
        let limits = ZipLimits {
            max_ratio: 100,
            ratio_floor: 1 << 20,
            ..PACKAGE_LIMITS
        };
        assert!(matches!(
            ZipPackage::open(Cursor::new(d.clone()), limits),
            Err(ZipError::TooLarge(_))
        ));
        // The total limit.
        let limits = ZipLimits {
            max_total_bytes: 1 << 20,
            ..PACKAGE_LIMITS
        };
        assert!(matches!(
            ZipPackage::open(Cursor::new(d), limits),
            Err(ZipError::TooLarge(_))
        ));
    }

    /// An entry that declares a small size but inflates to more is
    /// refused when read, not trusted.
    #[test]
    fn refuses_a_lying_size() {
        let big = vec![b'a'; 100_000];
        let mut d = build(&[("products.csv", &big)]);
        // Rewrite the declared uncompressed size (local header and central
        // directory) to 1000.
        let n = b"products.csv";
        let mut i = 0;
        while i + 4 <= d.len() {
            if &d[i..i + 4] == b"PK\x03\x04" && d.get(i + 30..i + 30 + n.len()) == Some(n) {
                d[i + 22..i + 26].copy_from_slice(&1000u32.to_le_bytes());
            }
            if &d[i..i + 4] == b"PK\x01\x02" && d.get(i + 46..i + 46 + n.len()) == Some(n) {
                d[i + 24..i + 28].copy_from_slice(&1000u32.to_le_bytes());
            }
            i += 1;
        }
        let mut p = open(d).unwrap();
        assert_eq!(p.entries()[0].size, 1000);
        let r = p.read(0, 1 << 20);
        assert!(
            matches!(r, Err(ZipError::TooLarge(_))),
            "{:?}",
            r.map(|d| d.len())
        );
    }

    #[test]
    fn not_a_zip() {
        assert!(matches!(
            open(b"style_number\n".to_vec()),
            Err(ZipError::Unreadable(_))
        ));
    }
}
