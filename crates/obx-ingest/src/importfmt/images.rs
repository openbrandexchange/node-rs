//! Image file names (import-format.md §2.1) and package entries (§3).

use crate::error::{Error, Result, quote};

/// The roles of protocol.md §5.4.
pub const ROLES: &[&str] = &[
    "packshot",
    "model",
    "detail",
    "ghost",
    "flatlay",
    "scene",
    "swatch",
    "size_chart",
    "other",
];

/// The views of protocol.md §5.4.
pub const VIEWS: &[&str] = &[
    "front",
    "back",
    "side",
    "left",
    "right",
    "top",
    "bottom",
    "tilted_left",
    "tilted_right",
    "inside",
    "detail",
    "other",
];

/// The image extensions of the format (lowercase, without dot).
pub const IMAGE_EXTS: &[&str] = &["jpg", "jpeg", "png", "webp", "tif", "tiff"];

/// Reports whether `s` is a role key.
pub fn is_role(s: &str) -> bool {
    ROLES.contains(&s)
}

/// Reports whether `s` is a view key.
pub fn is_view(s: &str) -> bool {
    VIEWS.contains(&s)
}

/// Go `path.Base`.
fn path_base(p: &str) -> &str {
    if p.is_empty() {
        return ".";
    }
    let t = p.trim_end_matches('/');
    if t.is_empty() {
        return "/";
    }
    match t.rfind('/') {
        Some(i) => &t[i + 1..],
        None => t,
    }
}

/// Go `path.Ext`: the suffix from the last '.' of the last element.
fn path_ext(p: &str) -> &str {
    for (i, b) in p.bytes().enumerate().rev() {
        match b {
            b'/' => return "",
            b'.' => return &p[i..],
            _ => {}
        }
    }
    ""
}

fn is_image_ext(ext: &str) -> bool {
    let e = ext.strip_prefix('.').unwrap_or(ext).to_lowercase();
    IMAGE_EXTS.contains(&e.as_str())
}

/// Reports whether a file name has an image extension.
pub fn is_image(name: &str) -> bool {
    is_image_ext(path_ext(name))
}

/// A parsed image file name. `role` and `view` are `None` when not given
/// (the importer then uses role `packshot` and view `null`); `color` is as
/// written (`ALL` in any case means every colour, decided by the caller).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImageName {
    pub style: String,
    pub color: String,
    pub position: u32,
    pub role: Option<String>,
    pub view: Option<String>,
}

/// Parses `{style}_{color}_{position}[_{qualifier}…].{ext}` from the right
/// (import-format.md §2.1): qualifiers are popped while more than three
/// parts remain (a two-part key such as `size_chart` first, while more than
/// four remain), then applied right to left, each filling only what is
/// still empty, so the rightmost role or view wins. A folder (`/` or `\`)
/// is ignored.
pub fn parse_image_name(name: &str) -> Result<ImageName> {
    let normalized = name.replace('\\', "/");
    let base = path_base(&normalized);
    let ext = path_ext(base);
    if !is_image_ext(ext) {
        return Err(Error::new(format!(
            "{base} is not an image file (jpg, png, webp, tif)"
        )));
    }
    let stem = &base[..base.len() - ext.len()];
    let mut parts: Vec<&str> = stem.split('_').collect();
    let mut quals: Vec<String> = Vec::new(); // left to right
    loop {
        let n = parts.len();
        if n > 4 {
            let two = format!(
                "{}_{}",
                parts[n - 2].to_lowercase(),
                parts[n - 1].to_lowercase()
            );
            if is_role(&two) || is_view(&two) {
                quals.insert(0, two);
                parts.truncate(n - 2);
                continue;
            }
        }
        if n > 3 {
            let last = parts[n - 1].to_lowercase();
            if is_role(&last) || is_view(&last) {
                quals.insert(0, last);
                parts.truncate(n - 1);
                continue;
            }
        }
        break;
    }
    if parts.len() < 3 {
        return Err(Error::new(format!(
            "{base} does not follow {{style}}_{{color}}_{{position}}.jpg (position missing)"
        )));
    }
    let n = parts.len();
    let pos_str = parts[n - 1];
    let position = pos_str
        .parse::<u32>()
        .ok()
        .filter(|&p| (1..=999).contains(&p) && p.to_string() == pos_str)
        .ok_or_else(|| {
            Error::new(format!(
                "{base} does not follow {{style}}_{{color}}_{{position}}.jpg (position must be 1-999)"
            ))
        })?;
    let color = parts[n - 2].to_string();
    let style = parts[..n - 2].join("_");
    if style.is_empty() || color.is_empty() {
        return Err(Error::new(format!(
            "{base} does not follow {{style}}_{{color}}_{{position}}.jpg"
        )));
    }
    let (role, view) = role_and_view(&quals);
    Ok(ImageName {
        style,
        color,
        position,
        role,
        view,
    })
}

/// Applies qualifiers right to left, each filling only what is still
/// empty. `other` is the view when the name also has another role,
/// otherwise the role; `detail` sets both.
fn role_and_view(quals: &[String]) -> (Option<String>, Option<String>) {
    let other_is_view = quals.iter().any(|q| q != "other" && is_role(q));
    let (mut role, mut view): (Option<String>, Option<String>) = (None, None);
    for q in quals.iter().rev() {
        if q == "detail" {
            role.get_or_insert_with(|| "detail".into());
            view.get_or_insert_with(|| "detail".into());
        } else if q == "other" {
            if other_is_view {
                view.get_or_insert_with(|| "other".into());
            } else {
                role.get_or_insert_with(|| "other".into());
            }
        } else if is_role(q) {
            role.get_or_insert_with(|| q.clone());
        } else {
            view.get_or_insert_with(|| q.clone());
        }
    }
    (role, view)
}

/// Reports whether a package entry is junk that must be skipped
/// (`__MACOSX/`, names starting with `.`, `Thumbs.db`, `desktop.ini`).
pub fn ignored(name: &str) -> bool {
    let name = name.replace('\\', "/");
    if name.starts_with("__MACOSX/") || name.contains("/__MACOSX/") {
        return true;
    }
    let base = path_base(&name);
    base.starts_with('.') || base == "Thumbs.db" || base == "desktop.ini"
}

const WINDOWS_DEVICES: &[&str] = &[
    "con", "prn", "aux", "nul", "com1", "com2", "com3", "com4", "lpt1", "lpt2", "lpt3",
];

/// Checks a zip entry against zip-slip and similar tricks: NUL bytes,
/// absolute paths, drive letters, `..` segments, Windows device names and
/// symbolic links (`is_symlink`: the entry's Unix mode is a symlink, e.g.
/// `zip::read::ZipFile::is_symlink()`).
pub fn safe_entry(name: &str, is_symlink: bool) -> Result<()> {
    if name.contains('\0') {
        return Err(Error::new("entry name contains a NUL byte"));
    }
    let n = name.replace('\\', "/");
    if n.starts_with('/') {
        return Err(Error::new(format!(
            "entry {} has an absolute path",
            quote(name)
        )));
    }
    if n.len() >= 2 && n.as_bytes()[1] == b':' {
        return Err(Error::new(format!(
            "entry {} has a drive letter",
            quote(name)
        )));
    }
    for seg in n.split('/') {
        if seg == ".." {
            return Err(Error::new(format!("entry {} contains '..'", quote(name))));
        }
        let lower = seg.to_lowercase();
        let base = lower.split('.').next().unwrap_or("");
        if WINDOWS_DEVICES.contains(&base) {
            return Err(Error::new(format!(
                "entry {} uses a device name",
                quote(name)
            )));
        }
    }
    if is_symlink {
        return Err(Error::new(format!(
            "entry {} is a symbolic link",
            quote(name)
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_image_names() {
        type Case<'a> = (
            &'a str,
            &'a str,
            &'a str,
            Option<&'a str>,
            Option<&'a str>,
            u32,
        );
        let cases: &[Case] = &[
            ("MN-1001_NVY_1.jpg", "MN-1001", "NVY", None, None, 1),
            (
                "MN-1001_NVY_2_back.jpg",
                "MN-1001",
                "NVY",
                None,
                Some("back"),
                2,
            ),
            (
                "MN-1003_RST_3_model.png",
                "MN-1003",
                "RST",
                Some("model"),
                None,
                3,
            ),
            (
                "AB_12_34_BLK_2_packshot_back.JPG",
                "AB_12_34",
                "BLK",
                Some("packshot"),
                Some("back"),
                2,
            ),
            (
                "MN-1004_IND_3_detail.jpg",
                "MN-1004",
                "IND",
                Some("detail"),
                Some("detail"),
                3,
            ),
            (
                "MN-1005_COG_2_tilted_left.webp",
                "MN-1005",
                "COG",
                None,
                Some("tilted_left"),
                2,
            ),
            (
                "dir\\sub/MN-1_A_7_other.tif",
                "MN-1",
                "A",
                Some("other"),
                None,
                7,
            ),
        ];
        for &(name, style, color, role, view, pos) in cases {
            let n = parse_image_name(name).unwrap_or_else(|e| panic!("{name}: {e}"));
            assert_eq!(
                n,
                ImageName {
                    style: style.into(),
                    color: color.into(),
                    position: pos,
                    role: role.map(String::from),
                    view: view.map(String::from),
                },
                "{name}"
            );
        }
        for bad in [
            "MN-1001_NVY_front.jpg",
            "MN-1001_NVY_01.jpg",
            "MN-1001_NVY_1.gif",
            "MN-1001_NVY_1000.jpg",
            "_NVY_1.jpg",
            "MN-1001_NVY_+1.jpg",
        ] {
            assert!(parse_image_name(bad).is_err(), "{bad} accepted");
        }
        assert!(is_image("a/b.JPEG") && !is_image("a.jpg/b") && !is_image("x.gif"));
    }

    #[test]
    fn safe_entries() {
        assert!(safe_entry("ok/MN-1_A_1.jpg", false).is_ok());
        for bad in [
            "../evil.jpg",
            "/abs.jpg",
            "C:/x.jpg",
            "a/CON.jpg",
            "a\\..\\b.jpg",
            "a\0b",
        ] {
            assert!(safe_entry(bad, false).is_err(), "{bad:?} accepted");
        }
        assert!(safe_entry("ok.jpg", true).is_err());
        assert!(ignored("__MACOSX/._x.jpg"));
        assert!(ignored("a/.DS_Store"));
        assert!(ignored("x\\__MACOSX\\y.jpg"));
        assert!(ignored("Thumbs.db"));
        assert!(!ignored("a/b.jpg"));
    }
}
