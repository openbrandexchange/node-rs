//! A streaming zip writer for downloads: entries are stored (images are
//! compressed already), written front to back to any `Write` (an HTTP body,
//! a file), with Zip64 records when an archive or an offset passes 4 GiB or
//! 65,535 entries. Every entry's bytes are known when it is added, so the
//! local header carries the CRC and sizes and no data descriptor is needed.

use std::io::{self, Write};

struct Central {
    name: Vec<u8>,
    crc: u32,
    size: u64,
    offset: u64,
    dos_time: u16,
    dos_date: u16,
}

pub struct ZipOut<W: Write> {
    w: W,
    offset: u64,
    entries: Vec<Central>,
    dos_time: u16,
    dos_date: u16,
}

const MAX32: u64 = 0xFFFF_FFFF;

fn dos(t: chrono::DateTime<chrono::Utc>) -> (u16, u16) {
    use chrono::{Datelike, Timelike};
    let time = ((t.hour() as u16) << 11) | ((t.minute() as u16) << 5) | (t.second() as u16 / 2);
    let year = (t.year().clamp(1980, 2107) - 1980) as u16;
    let date = (year << 9) | ((t.month() as u16) << 5) | t.day() as u16;
    (time, date)
}

impl<W: Write> ZipOut<W> {
    pub fn new(w: W) -> ZipOut<W> {
        let (dos_time, dos_date) = dos(chrono::Utc::now());
        ZipOut {
            w,
            offset: 0,
            entries: Vec::new(),
            dos_time,
            dos_date,
        }
    }

    fn put(&mut self, b: &[u8]) -> io::Result<()> {
        self.w.write_all(b)?;
        self.offset += b.len() as u64;
        Ok(())
    }

    /// Adds one stored entry.
    pub fn add(&mut self, name: &str, data: &[u8]) -> io::Result<()> {
        let crc = crc32fast::hash(data);
        let size = data.len() as u64;
        let offset = self.offset;
        let zip64 = size >= MAX32;
        let mut h = Vec::with_capacity(30 + name.len() + 20);
        h.extend_from_slice(&0x0403_4b50u32.to_le_bytes());
        h.extend_from_slice(&(if zip64 { 45u16 } else { 20u16 }).to_le_bytes());
        h.extend_from_slice(&0x0800u16.to_le_bytes()); // UTF-8 names
        h.extend_from_slice(&0u16.to_le_bytes()); // stored
        h.extend_from_slice(&self.dos_time.to_le_bytes());
        h.extend_from_slice(&self.dos_date.to_le_bytes());
        h.extend_from_slice(&crc.to_le_bytes());
        let s32 = if zip64 { MAX32 as u32 } else { size as u32 };
        h.extend_from_slice(&s32.to_le_bytes());
        h.extend_from_slice(&s32.to_le_bytes());
        h.extend_from_slice(&(name.len() as u16).to_le_bytes());
        h.extend_from_slice(&(if zip64 { 20u16 } else { 0u16 }).to_le_bytes());
        h.extend_from_slice(name.as_bytes());
        if zip64 {
            h.extend_from_slice(&1u16.to_le_bytes());
            h.extend_from_slice(&16u16.to_le_bytes());
            h.extend_from_slice(&size.to_le_bytes());
            h.extend_from_slice(&size.to_le_bytes());
        }
        self.put(&h)?;
        self.put(data)?;
        self.entries.push(Central {
            name: name.as_bytes().to_vec(),
            crc,
            size,
            offset,
            dos_time: self.dos_time,
            dos_date: self.dos_date,
        });
        Ok(())
    }

    /// Writes the central directory; returns the writer and the archive size.
    pub fn finish(mut self) -> io::Result<(W, u64)> {
        let cd_start = self.offset;
        let entries = std::mem::take(&mut self.entries);
        for e in &entries {
            let need_size = e.size >= MAX32;
            let need_off = e.offset >= MAX32;
            let mut extra = Vec::new();
            if need_size || need_off {
                let mut body = Vec::new();
                if need_size {
                    body.extend_from_slice(&e.size.to_le_bytes());
                    body.extend_from_slice(&e.size.to_le_bytes());
                }
                if need_off {
                    body.extend_from_slice(&e.offset.to_le_bytes());
                }
                extra.extend_from_slice(&1u16.to_le_bytes());
                extra.extend_from_slice(&(body.len() as u16).to_le_bytes());
                extra.extend_from_slice(&body);
            }
            let v: u16 = if extra.is_empty() { 20 } else { 45 };
            let mut h = Vec::with_capacity(46 + e.name.len() + extra.len());
            h.extend_from_slice(&0x0201_4b50u32.to_le_bytes());
            h.extend_from_slice(&(0x0300u16 | v).to_le_bytes()); // made by Unix
            h.extend_from_slice(&v.to_le_bytes());
            h.extend_from_slice(&0x0800u16.to_le_bytes());
            h.extend_from_slice(&0u16.to_le_bytes());
            h.extend_from_slice(&e.dos_time.to_le_bytes());
            h.extend_from_slice(&e.dos_date.to_le_bytes());
            h.extend_from_slice(&e.crc.to_le_bytes());
            let s32 = if need_size {
                MAX32 as u32
            } else {
                e.size as u32
            };
            h.extend_from_slice(&s32.to_le_bytes());
            h.extend_from_slice(&s32.to_le_bytes());
            h.extend_from_slice(&(e.name.len() as u16).to_le_bytes());
            h.extend_from_slice(&(extra.len() as u16).to_le_bytes());
            h.extend_from_slice(&0u16.to_le_bytes()); // comment
            h.extend_from_slice(&0u16.to_le_bytes()); // disk
            h.extend_from_slice(&0u16.to_le_bytes()); // internal attrs
            h.extend_from_slice(&(0o100644u32 << 16).to_le_bytes());
            let o32 = if need_off {
                MAX32 as u32
            } else {
                e.offset as u32
            };
            h.extend_from_slice(&o32.to_le_bytes());
            h.extend_from_slice(&e.name);
            h.extend_from_slice(&extra);
            self.put(&h)?;
        }
        let cd_size = self.offset - cd_start;
        let n = entries.len() as u64;
        let zip64 = n >= 0xFFFF || cd_start >= MAX32 || cd_size >= MAX32;
        if zip64 {
            let eocd64 = self.offset;
            let mut h = Vec::with_capacity(76);
            h.extend_from_slice(&0x0606_4b50u32.to_le_bytes());
            h.extend_from_slice(&44u64.to_le_bytes());
            h.extend_from_slice(&45u16.to_le_bytes());
            h.extend_from_slice(&45u16.to_le_bytes());
            h.extend_from_slice(&0u32.to_le_bytes());
            h.extend_from_slice(&0u32.to_le_bytes());
            h.extend_from_slice(&n.to_le_bytes());
            h.extend_from_slice(&n.to_le_bytes());
            h.extend_from_slice(&cd_size.to_le_bytes());
            h.extend_from_slice(&cd_start.to_le_bytes());
            h.extend_from_slice(&0x0706_4b50u32.to_le_bytes());
            h.extend_from_slice(&0u32.to_le_bytes());
            h.extend_from_slice(&eocd64.to_le_bytes());
            h.extend_from_slice(&1u32.to_le_bytes());
            self.put(&h)?;
        }
        let mut h = Vec::with_capacity(22);
        h.extend_from_slice(&0x0605_4b50u32.to_le_bytes());
        h.extend_from_slice(&0u16.to_le_bytes());
        h.extend_from_slice(&0u16.to_le_bytes());
        let n16 = n.min(0xFFFF) as u16;
        h.extend_from_slice(&n16.to_le_bytes());
        h.extend_from_slice(&n16.to_le_bytes());
        h.extend_from_slice(&(cd_size.min(MAX32) as u32).to_le_bytes());
        h.extend_from_slice(&(cd_start.min(MAX32) as u32).to_le_bytes());
        h.extend_from_slice(&0u16.to_le_bytes());
        self.put(&h)?;
        self.w.flush()?;
        Ok((self.w, self.offset))
    }
}

/// `name`, `name-2`, `name-3`, ... (before the extension) for names already
/// in the archive.
pub fn unique_name(seen: &mut std::collections::HashSet<String>, path: &str) -> String {
    let mut p = path.to_string();
    let mut i = 2;
    while seen.contains(&p) {
        let slash = path.rfind('/').map_or(0, |s| s + 1);
        let (base, ext) = match path.rfind('.') {
            Some(j) if j > slash => (&path[..j], &path[j..]),
            _ => (path, ""),
        };
        p = format!("{base}-{i}{ext}");
        i += 1;
    }
    seen.insert(p.clone());
    p
}

/// A path segment safe inside a zip (no separators, no `..`).
pub fn safe_segment(s: &str) -> String {
    obx_axum::sanitize_filename(&s.replace(['/', '\\'], "_").replace("..", "_"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;

    #[test]
    fn readable_by_the_zip_crate() {
        let mut z = ZipOut::new(Vec::new());
        z.add("A/one.jpg", b"hello").unwrap();
        z.add("two.csv", b"").unwrap();
        z.add("caf\u{e9}.txt", &vec![7u8; 70_000]).unwrap();
        let (buf, n) = z.finish().unwrap();
        assert_eq!(n as usize, buf.len());
        let mut a = zip::ZipArchive::new(std::io::Cursor::new(buf)).unwrap();
        assert_eq!(a.len(), 3);
        let mut s = String::new();
        a.by_name("A/one.jpg")
            .unwrap()
            .read_to_string(&mut s)
            .unwrap();
        assert_eq!(s, "hello");
        assert_eq!(a.by_name("caf\u{e9}.txt").unwrap().size(), 70_000);
    }

    #[test]
    fn names() {
        let mut seen = Default::default();
        assert_eq!(unique_name(&mut seen, "a/x.jpg"), "a/x.jpg");
        assert_eq!(unique_name(&mut seen, "a/x.jpg"), "a/x-2.jpg");
        assert_eq!(unique_name(&mut seen, "a/x.jpg"), "a/x-3.jpg");
        assert_eq!(unique_name(&mut seen, "a.b/x"), "a.b/x");
        assert_eq!(unique_name(&mut seen, "a.b/x"), "a.b/x-2");
        assert_eq!(safe_segment("../MN/1"), "__MN_1");
    }
}
