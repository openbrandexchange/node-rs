//! Renditions (protocol.md §5.5): web ≤ 2000 px, square on white, thumb ≤
//! 600 px, JPEG, sRGB, transparency flattened on white, never upscaled.

use image::{DynamicImage, GenericImageView, ImageReader, Rgb, RgbImage, imageops};

pub const WEB_MAX: u32 = 2000;
pub const THUMB_MAX: u32 = 600;
pub const MAX_PIXELS: u64 = 100_000_000;
pub const JPEG_QUALITY: u8 = 85;

pub fn sniff(head: &[u8]) -> Option<&'static str> {
    if head.len() >= 3 && head[..3] == [0xFF, 0xD8, 0xFF] {
        Some("image/jpeg")
    } else if head.len() >= 8 && &head[..8] == b"\x89PNG\r\n\x1a\n" {
        Some("image/png")
    } else if head.len() >= 12 && &head[..4] == b"RIFF" && &head[8..12] == b"WEBP" {
        Some("image/webp")
    } else if head.len() >= 4 && (&head[..4] == b"II*\x00" || &head[..4] == b"MM\x00*") {
        Some("image/tiff")
    } else {
        None
    }
}

/// Width and height from the file header (no decoding).
pub fn dimensions(data: &[u8]) -> Option<(u32, u32)> {
    ImageReader::new(std::io::Cursor::new(data))
        .with_guessed_format()
        .ok()?
        .into_dimensions()
        .ok()
}

pub struct Rendition {
    pub name: &'static str,
    pub data: Vec<u8>,
    pub width: u32,
    pub height: u32,
}

pub fn fit(w: u32, h: u32, limit: u32) -> (u32, u32) {
    if w <= limit && h <= limit {
        return (w, h);
    }
    if w >= h {
        let nh = (h as f64 * limit as f64 / w as f64 + 0.5) as u32;
        (limit, nh.max(1))
    } else {
        let nw = (w as f64 * limit as f64 / h as f64 + 0.5) as u32;
        (nw.max(1), limit)
    }
}

fn jpeg_orientation(b: &[u8]) -> u8 {
    let mut i = 2;
    while i + 4 <= b.len() {
        if b[i] != 0xFF {
            return 1;
        }
        let marker = b[i + 1];
        if marker == 0xDA || marker == 0xD9 {
            return 1;
        }
        let size = u16::from_be_bytes([b[i + 2], b[i + 3]]) as usize;
        if size < 2 || i + 2 + size > b.len() {
            return 1;
        }
        let seg = &b[i + 4..i + 2 + size];
        if marker == 0xE1 && seg.len() > 14 && &seg[..6] == b"Exif\x00\x00" {
            return exif_orientation(&seg[6..]);
        }
        i += 2 + size;
    }
    1
}

fn exif_orientation(t: &[u8]) -> u8 {
    if t.len() < 8 {
        return 1;
    }
    let le = match &t[..2] {
        b"II" => true,
        b"MM" => false,
        _ => return 1,
    };
    let u16_at = |o: usize| {
        if le {
            u16::from_le_bytes([t[o], t[o + 1]])
        } else {
            u16::from_be_bytes([t[o], t[o + 1]])
        }
    };
    let u32_at = |o: usize| {
        let a = [t[o], t[o + 1], t[o + 2], t[o + 3]];
        if le {
            u32::from_le_bytes(a)
        } else {
            u32::from_be_bytes(a)
        }
    };
    let off = u32_at(4) as usize;
    if off + 2 > t.len() {
        return 1;
    }
    let n = u16_at(off) as usize;
    for k in 0..n {
        let e = off + 2 + k * 12;
        if e + 12 > t.len() {
            return 1;
        }
        if u16_at(e) == 0x0112 {
            let v = u16_at(e + 8);
            return if (1..=8).contains(&v) { v as u8 } else { 1 };
        }
    }
    1
}

fn orient(img: DynamicImage, o: u8) -> DynamicImage {
    match o {
        2 => img.fliph(),
        3 => img.rotate180(),
        4 => img.flipv(),
        5 => img.rotate90().fliph(),
        6 => img.rotate90(),
        7 => img.rotate270().fliph(),
        8 => img.rotate270(),
        _ => img,
    }
}

fn flatten(img: &DynamicImage) -> RgbImage {
    if !img.color().has_alpha() {
        return img.to_rgb8();
    }
    let rgba = img.to_rgba8();
    let mut out = RgbImage::new(rgba.width(), rgba.height());
    for (x, y, p) in rgba.enumerate_pixels() {
        let a = p[3] as u32;
        let mix = |c: u8| ((c as u32 * a + 255 * (255 - a) + 127) / 255) as u8;
        out.put_pixel(x, y, Rgb([mix(p[0]), mix(p[1]), mix(p[2])]));
    }
    out
}

fn resize(src: &RgbImage, w: u32, h: u32) -> RgbImage {
    if src.width() == w && src.height() == h {
        return src.clone();
    }
    imageops::resize(src, w, h, imageops::FilterType::CatmullRom)
}

fn jpeg(img: &RgbImage) -> Result<Vec<u8>, String> {
    let mut out = Vec::new();
    image::codecs::jpeg::JpegEncoder::new_with_quality(&mut out, JPEG_QUALITY)
        .encode_image(img)
        .map_err(|e| e.to_string())?;
    Ok(out)
}

/// web, square and thumb of an original.
pub fn render(original: &[u8]) -> Result<Vec<Rendition>, String> {
    let (w, h) = dimensions(original).ok_or("cannot read image")?;
    if w as u64 * h as u64 > MAX_PIXELS {
        return Err("image exceeds the pixel limit".into());
    }
    let mut img =
        image::load_from_memory(original).map_err(|e| format!("cannot decode image: {e}"))?;
    if sniff(original) == Some("image/jpeg") {
        img = orient(img, jpeg_orientation(original));
    }
    let (sw, sh) = img.dimensions();
    let flat = flatten(&img);
    let (ww, wh) = fit(sw, sh, WEB_MAX);
    let web = resize(&flat, ww, wh);
    let side = ww.max(wh);
    let mut sq = RgbImage::from_pixel(side, side, Rgb([255, 255, 255]));
    imageops::replace(
        &mut sq,
        &web,
        ((side - ww) / 2) as i64,
        ((side - wh) / 2) as i64,
    );
    let (tw, th) = fit(sw, sh, THUMB_MAX);
    let thumb = resize(&web, tw, th);
    let mut out = Vec::new();
    for (name, im) in [("web", &web), ("square", &sq), ("thumb", &thumb)] {
        out.push(Rendition {
            name,
            data: jpeg(im)?,
            width: im.width(),
            height: im.height(),
        });
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    #[test]
    fn renders_fixture() {
        let data = std::fs::read(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/spec/fixtures/maison-noor/images/MN-1002_OLV_1_front.png"
        ))
        .unwrap();
        let r = super::render(&data).unwrap();
        assert_eq!((r[0].width, r[0].height), (1600, 2000));
        assert_eq!((r[1].width, r[1].height), (2000, 2000));
        assert_eq!((r[2].width, r[2].height), (480, 600));
    }
}
