//! Portal appearance (node-admin.md, spec 0.3.x): validation of
//! `branding.theme`, `branding.login` and `branding.home`, and the
//! **neutral default** (spec draft amendment for 0.4): every member of the
//! theme and the login page resolves on its own to the brand's value or a
//! neutral default, never to a vendor's look.
//!
//! Unknown members and block types are kept as they are (forward
//! compatibility); only known members are validated.
//!
//! ```
//! use serde_json::json;
//! use obx_types::appearance::{resolve, validate};
//!
//! let b = json!({"accent_color": "#7a3b2e", "theme": {"body_font": "jost"}});
//! let look = resolve(&b);
//! assert_eq!(look["colors"]["primary"], "#7a3b2e");
//! assert_eq!(look["colors"]["background"], "#faf9f7");
//! assert_eq!(look["body_font"], "jost");
//! let errs = validate(&json!({"theme": {"radius": "huge"}}), |_| true);
//! assert_eq!(errs.errors[0].pointer.as_deref(), Some("/branding/theme/radius"));
//! ```

use serde_json::{Map, Value, json};

use crate::Problem;

pub const MAX_BRANDING_JSON: usize = 64 << 10;
pub const MAX_TEXT: usize = 2000;
pub const MAX_BODY: usize = 10000;
pub const MAX_HOME_BLOCKS: usize = 30;
pub const MAX_BLOCK_ID: usize = 40;
/// How many branding images a node keeps.
pub const MAX_IMAGES: usize = 200;
pub const MAX_IMAGE_BYTES: usize = 10 << 20;
pub const MAX_IMAGE_SIDE: i64 = 8000;
pub const MAX_FAVICON_BYTES: usize = 1 << 20;

pub const FONTS: [&str; 11] = [
    "system",
    "inter",
    "dm-sans",
    "manrope",
    "work-sans",
    "jost",
    "space-grotesk",
    "fraunces",
    "playfair-display",
    "libre-baskerville",
    "cormorant-garamond",
];

const THEME_ENUMS: [(&str, &[&str]); 7] = [
    ("color_scheme", &["light", "dark", "auto"]),
    ("heading_font", &FONTS),
    ("body_font", &FONTS),
    ("radius", &["none", "small", "medium", "large"]),
    ("grid_density", &["compact", "comfortable", "editorial"]),
    ("card_style", &["plain", "bordered", "elevated"]),
    ("image_fit", &["contain", "cover"]),
];

pub const COLORS: [&str; 5] = ["primary", "secondary", "background", "surface", "text"];

/// The neutral defaults (node-admin.md, "Neutral default").
pub fn defaults() -> Value {
    json!({
        "color_scheme": "light",
        "colors": {"primary": "#1f2937", "secondary": "#4b5563", "background": "#faf9f7", "surface": "#ffffff", "text": "#1a1a1a"},
        "heading_font": "system", "body_font": "system", "radius": "medium", "grid_density": "comfortable",
        "card_style": "plain", "image_fit": "contain", "image_background": "#ffffff", "login_layout": "centered",
    })
}

/// Dark-scheme defaults of background, surface and text.
pub fn dark_defaults() -> Value {
    json!({"background": "#121212", "surface": "#1c1c1c", "text": "#f2f0ec"})
}

pub fn is_hex_color(s: &str) -> bool {
    s.len() == 7 && s.starts_with('#') && s[1..].bytes().all(|b| b.is_ascii_hexdigit())
}

fn str_in<'a>(v: &'a Value, allowed: &[&str]) -> Option<&'a str> {
    v.as_str().filter(|s| allowed.contains(s))
}

/// The look a node resolves from a stored `branding` object, member by
/// member; invalid or missing values fall back to the neutral default.
/// `auto` stays `auto` (the reader decides), with light-scheme colours.
pub fn resolve(branding: &Value) -> Value {
    let mut out = defaults();
    let theme = &branding["theme"];
    for (k, allowed) in THEME_ENUMS {
        if let Some(v) = str_in(&theme[k], allowed) {
            out[k] = json!(v);
        }
    }
    if out["color_scheme"] == "dark" {
        for (k, v) in dark_defaults().as_object().into_iter().flatten() {
            out["colors"][k] = v.clone();
        }
    }
    if let Some(a) = branding["accent_color"]
        .as_str()
        .filter(|a| is_hex_color(a))
    {
        out["colors"]["primary"] = json!(a);
    }
    for k in COLORS {
        if let Some(c) = theme["colors"][k].as_str().filter(|c| is_hex_color(c)) {
            out["colors"][k] = json!(c);
        }
    }
    if let Some(c) = theme["image_background"]
        .as_str()
        .filter(|c| is_hex_color(c))
    {
        out["image_background"] = json!(c);
    }
    if let Some(l) = str_in(&branding["login"]["layout"], &["centered", "split"]) {
        out["login_layout"] = json!(l);
    }
    out
}

#[derive(Clone, Copy)]
enum Kind {
    Text,
    Body,
    Image,
    Link,
    Plain(usize),
    Email,
    Enum(&'static [&'static str]),
}

fn block_rules(t: &str) -> Option<Vec<(&'static str, Kind)>> {
    use Kind::*;
    Some(match t {
        "hero" => vec![
            ("image", Image),
            ("title", Text),
            ("text", Text),
            ("button_label", Text),
            ("link", Link),
            ("align", Enum(&["left", "center"])),
            ("height", Enum(&["medium", "large"])),
            ("overlay", Enum(&["none", "dark", "light"])),
        ],
        "tiles" => vec![("title", Text)],
        "text" => vec![("title", Text), ("body", Body)],
        "image_text" => vec![
            ("image", Image),
            ("title", Text),
            ("text", Text),
            ("button_label", Text),
            ("link", Link),
            ("image_side", Enum(&["left", "right"])),
        ],
        "products" => vec![("title", Text)],
        "announcement" => vec![
            ("text", Text),
            ("tone", Enum(&["neutral", "info", "success"])),
        ],
        "contact" => vec![
            ("title", Text),
            ("name", Plain(200)),
            ("email", Email),
            ("phone", Plain(50)),
        ],
        _ => return None,
    })
}

fn valid_lang(l: &str) -> bool {
    let mut parts = l.split('-');
    let first = parts.next().unwrap_or("");
    (2..=3).contains(&first.len())
        && first.bytes().all(|b| b.is_ascii_lowercase())
        && parts.all(|p| (2..=8).contains(&p.len()) && p.bytes().all(|b| b.is_ascii_alphanumeric()))
}

fn valid_email(e: &str) -> bool {
    let e = e.trim();
    let Some((a, d)) = e.split_once('@') else {
        return false;
    };
    !a.is_empty()
        && d.contains('.')
        && !d.starts_with('.')
        && !d.ends_with('.')
        && !e.contains(char::is_whitespace)
        && e.len() <= 254
}

/// PortalLink: a portal path starting with one `/` or an https URL with a host.
pub fn valid_portal_link(s: &str) -> bool {
    if s.len() > MAX_TEXT || s.contains(char::is_whitespace) || s.contains('\0') {
        return false;
    }
    if let Some(rest) = s.strip_prefix('/') {
        return !rest.starts_with('/') && !rest.starts_with('\\');
    }
    s.strip_prefix("https://")
        .is_some_and(|r| !r.is_empty() && !r.starts_with('/'))
}

fn valid_image_id(s: &str) -> bool {
    (1..=64).contains(&s.len())
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}

struct Check<'a, F: Fn(&str) -> bool> {
    p: Problem,
    image_exists: &'a F,
    fatal: bool,
}

impl<F: Fn(&str) -> bool> Check<'_, F> {
    fn err(&mut self, ptr: &str, detail: &str) {
        self.p = std::mem::replace(&mut self.p, Problem::new("validation_failed", "")).field(
            ptr,
            "validation_failed",
            detail,
        );
    }

    fn member(&mut self, ptr: &str, obj: &Map<String, Value>, key: &str, k: Kind) {
        let Some(v) = obj.get(key).filter(|v| !v.is_null()) else {
            return;
        };
        let ptr = format!("{ptr}/{key}");
        match k {
            Kind::Enum(e) => {
                if str_in(v, e).is_none() {
                    self.err(&ptr, &format!("one of {}", e.join(", ")));
                }
            }
            Kind::Text | Kind::Body => {
                let limit = if matches!(k, Kind::Body) {
                    MAX_BODY
                } else {
                    MAX_TEXT
                };
                let Some(m) = v.as_object() else {
                    self.err(&ptr, "per-language text like {\"en\": \"...\"}");
                    return;
                };
                for (lang, t) in m {
                    if !valid_lang(lang) {
                        self.err(&format!("{ptr}/{lang}"), "language like nl or de-CH");
                        continue;
                    }
                    match t {
                        Value::Null => {}
                        Value::String(s) if s.chars().count() <= limit => {}
                        Value::String(_) => self.err(
                            &format!("{ptr}/{lang}"),
                            &format!("at most {limit} characters"),
                        ),
                        _ => self.err(&format!("{ptr}/{lang}"), "text"),
                    }
                }
            }
            Kind::Plain(limit) => {
                if !v.as_str().is_some_and(|s| s.chars().count() <= limit) {
                    self.err(&ptr, &format!("text of at most {limit} characters"));
                }
            }
            Kind::Email => {
                if !v.as_str().is_some_and(|s| valid_email(&s.to_lowercase())) {
                    self.err(&ptr, "invalid e-mail");
                }
            }
            Kind::Link => {
                if !v.as_str().is_some_and(valid_portal_link) {
                    self.err(&ptr, "a portal path starting with / or an https:// URL");
                }
            }
            Kind::Image => {
                if !v
                    .as_str()
                    .is_some_and(|s| valid_image_id(s) && (self.image_exists)(s))
                {
                    self.err(
                        &ptr,
                        "unknown image (upload it with POST /admin/api/settings/images)",
                    );
                }
            }
        }
    }

    fn theme(&mut self, t: &Map<String, Value>) {
        for (k, e) in THEME_ENUMS {
            self.member("/branding/theme", t, k, Kind::Enum(e));
        }
        if let Some(v) = t.get("image_background").filter(|v| !v.is_null()) {
            if !v.as_str().is_some_and(is_hex_color) {
                self.err("/branding/theme/image_background", "#rrggbb");
            }
        }
        match t.get("colors") {
            None | Some(Value::Null) => {}
            Some(Value::Object(cs)) => {
                for k in COLORS {
                    if let Some(v) = cs.get(k).filter(|v| !v.is_null()) {
                        if !v.as_str().is_some_and(is_hex_color) {
                            self.err(&format!("/branding/theme/colors/{k}"), "#rrggbb");
                        }
                    }
                }
            }
            Some(_) => self.err("/branding/theme/colors", "object or null"),
        }
    }

    fn home(&mut self, h: &Map<String, Value>) {
        let blocks = match h.get("blocks") {
            None | Some(Value::Null) => return,
            Some(Value::Array(b)) => b,
            Some(_) => {
                self.err("/branding/home/blocks", "array");
                return;
            }
        };
        if blocks.len() > MAX_HOME_BLOCKS {
            self.err(
                "/branding/home/blocks",
                &format!("at most {MAX_HOME_BLOCKS} blocks"),
            );
        }
        let mut seen = std::collections::HashSet::new();
        for (i, rb) in blocks.iter().enumerate() {
            let ptr = format!("/branding/home/blocks/{i}");
            let Some(blk) = rb.as_object() else {
                self.err(&ptr, "object");
                continue;
            };
            let id = blk.get("id").and_then(|v| v.as_str()).unwrap_or("");
            if id.trim().is_empty() {
                self.err(&format!("{ptr}/id"), "required");
            } else if id.chars().count() > MAX_BLOCK_ID {
                self.err(
                    &format!("{ptr}/id"),
                    &format!("at most {MAX_BLOCK_ID} characters"),
                );
            } else if !seen.insert(id.to_string()) {
                self.err(&format!("{ptr}/id"), "used by another block");
            }
            let typ = blk.get("type").and_then(|v| v.as_str()).unwrap_or("");
            if typ.is_empty() {
                self.err(&format!("{ptr}/type"), "required");
                continue;
            }
            let Some(rules) = block_rules(typ) else {
                let ok = typ.len() <= 40
                    && typ.as_bytes()[0].is_ascii_lowercase()
                    && typ
                        .bytes()
                        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_');
                if !ok {
                    self.err(
                        &format!("{ptr}/type"),
                        "a block type like hero or image_text",
                    );
                }
                continue;
            };
            for (k, r) in rules {
                self.member(&ptr, blk, k, r);
            }
            match typ {
                "tiles" => self.tiles(&ptr, blk),
                "products" => self.products(&ptr, blk),
                _ => {}
            }
        }
    }

    fn tiles(&mut self, ptr: &str, blk: &Map<String, Value>) {
        let items = blk.get("items").and_then(|v| v.as_array());
        if !items.is_some_and(|i| (1..=12).contains(&i.len())) {
            self.err(&format!("{ptr}/items"), "1 to 12 tiles");
        }
        for (j, it) in items.into_iter().flatten().enumerate() {
            let iptr = format!("{ptr}/items/{j}");
            let Some(it) = it.as_object() else {
                self.err(&iptr, "object");
                continue;
            };
            self.member(&iptr, it, "image", Kind::Image);
            self.member(&iptr, it, "title", Kind::Text);
            self.member(&iptr, it, "link", Kind::Link);
        }
        if let Some(v) = blk.get("columns").filter(|v| !v.is_null()) {
            if !int(v).is_some_and(|n| (2..=4).contains(&n)) {
                self.err(&format!("{ptr}/columns"), "2, 3 or 4");
            }
        }
    }

    fn products(&mut self, ptr: &str, blk: &Map<String, Value>) {
        if let Some(v) = blk.get("style_numbers").filter(|v| !v.is_null()) {
            let list = v.as_array();
            if !list.is_some_and(|l| l.len() <= 24) {
                self.err(
                    &format!("{ptr}/style_numbers"),
                    "a list of at most 24 style numbers",
                );
            }
            for (j, s) in list.into_iter().flatten().enumerate() {
                if !s
                    .as_str()
                    .is_some_and(|s| !s.is_empty() && s.chars().count() <= 100)
                {
                    self.err(
                        &format!("{ptr}/style_numbers/{j}"),
                        "style number of 1 to 100 characters",
                    );
                }
            }
        }
        if let Some(v) = blk.get("query").filter(|v| !v.is_null()) {
            let ok = v.as_str().is_some_and(|q| {
                q.len() <= MAX_TEXT
                    && !q.contains(['?', '#'])
                    && !q.contains(char::is_whitespace)
                    && valid_query(q)
            });
            if !ok {
                self.err(
                    &format!("{ptr}/query"),
                    "the query string of /admin/api/portal/products without ?",
                );
            }
        }
        if let Some(v) = blk.get("max").filter(|v| !v.is_null()) {
            if !int(v).is_some_and(|n| (1..=24).contains(&n)) {
                self.err(&format!("{ptr}/max"), "1 to 24");
            }
        }
    }
}

/// Go's url.ParseQuery: rejects `;` and malformed percent escapes.
fn valid_query(q: &str) -> bool {
    if q.contains(';') {
        return false;
    }
    let b = q.as_bytes();
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' {
            if !(b.get(i + 1).is_some_and(u8::is_ascii_hexdigit)
                && b.get(i + 2).is_some_and(u8::is_ascii_hexdigit))
            {
                return false;
            }
            i += 3;
            continue;
        }
        i += 1;
    }
    true
}

fn int(v: &Value) -> Option<i64> {
    v.as_i64()
        .or_else(|| v.as_f64().filter(|f| f.fract() == 0.0).map(|f| f as i64))
}

/// The outcome of [`validate`]: the field errors as one problem, and whether
/// a known member has a shape the settings cannot hold (then the patch must
/// be refused before anything else is checked).
pub struct Validation {
    pub problem: Problem,
    pub errors: Vec<crate::FieldError>,
    pub fatal: bool,
}

impl Validation {
    pub fn ok(&self) -> bool {
        self.errors.is_empty()
    }
}

/// Validates the appearance members of a (merged) `branding` object;
/// `image_exists` tells whether an image id is stored on the node.
pub fn validate(branding: &Value, image_exists: impl Fn(&str) -> bool) -> Validation {
    let mut c = Check {
        p: Problem::new(
            "validation_failed",
            "The appearance settings are not valid.",
        ),
        image_exists: &image_exists,
        fatal: false,
    };
    if let Some(b) = branding.as_object() {
        for k in ["theme", "login", "home"] {
            if let Some(v) = b.get(k).filter(|v| !v.is_null()) {
                if !v.is_object() {
                    c.err(&format!("/branding/{k}"), "object or null");
                    c.fatal = true;
                }
            }
        }
        if serde_json::to_vec(b).map(|r| r.len()).unwrap_or(0) > MAX_BRANDING_JSON {
            c.err(
                "/branding",
                &format!("at most {MAX_BRANDING_JSON} bytes of JSON"),
            );
        }
        if let Some(t) = b.get("theme").and_then(|t| t.as_object()) {
            c.theme(t);
        }
        if let Some(l) = b.get("login").and_then(|l| l.as_object()) {
            c.member(
                "/branding/login",
                l,
                "layout",
                Kind::Enum(&["centered", "split"]),
            );
            c.member("/branding/login", l, "background_image", Kind::Image);
            c.member("/branding/login", l, "title", Kind::Text);
            c.member("/branding/login", l, "text", Kind::Text);
        }
        if let Some(h) = b.get("home").and_then(|h| h.as_object()) {
            c.home(h);
        }
    }
    let errors = c.p.errors.clone();
    Validation {
        problem: c.p,
        errors,
        fatal: c.fatal,
    }
}

/// Every branding image id referenced (with its JSON pointer): the login
/// background and the `image` of every block and tile, of any block type.
pub fn image_refs(branding: &Value) -> Vec<(String, String)> {
    let mut out = Vec::new();
    if let Some(id) = branding["login"]["background_image"]
        .as_str()
        .filter(|s| !s.is_empty())
    {
        out.push(("/branding/login/background_image".into(), id.to_string()));
    }
    for (i, blk) in branding["home"]["blocks"]
        .as_array()
        .into_iter()
        .flatten()
        .enumerate()
    {
        let ptr = format!("/branding/home/blocks/{i}");
        if let Some(id) = blk["image"].as_str().filter(|s| !s.is_empty()) {
            out.push((format!("{ptr}/image"), id.to_string()));
        }
        for (j, it) in blk["items"].as_array().into_iter().flatten().enumerate() {
            if let Some(id) = it["image"].as_str().filter(|s| !s.is_empty()) {
                out.push((format!("{ptr}/items/{j}/image"), id.to_string()));
            }
        }
    }
    out
}

/// The public URL path of a branding image.
pub fn image_url(id: &str) -> String {
    format!("/admin/api/public/images/{id}")
}

fn with_image_url(obj: &Map<String, Value>, key: &str, exists: &impl Fn(&str) -> bool) -> Value {
    let mut out = obj.clone();
    let u = obj
        .get(key)
        .and_then(|v| v.as_str())
        .filter(|id| exists(id))
        .map(image_url);
    out.insert(format!("{key}_url"), json!(u));
    Value::Object(out)
}

/// `login` with `background_image_url` (null when no login is set).
pub fn public_login(branding: &Value, exists: impl Fn(&str) -> bool) -> Value {
    match branding["login"].as_object() {
        Some(l) => with_image_url(l, "background_image", &exists),
        None => Value::Null,
    }
}

/// `home` with `image_url` next to every image id.
pub fn resolved_home(branding: &Value, exists: impl Fn(&str) -> bool) -> Value {
    let Some(home) = branding["home"].as_object() else {
        return Value::Null;
    };
    let mut out = home.clone();
    let Some(blocks) = home.get("blocks").and_then(|b| b.as_array()) else {
        return Value::Object(out);
    };
    let rb: Vec<Value> = blocks
        .iter()
        .map(|b| {
            let Some(blk) = b.as_object() else {
                return b.clone();
            };
            let mut blk = if blk.contains_key("image") {
                with_image_url(blk, "image", &exists)
            } else {
                Value::Object(blk.clone())
            };
            if let Some(items) = blk["items"].as_array().cloned() {
                blk["items"] = Value::Array(
                    items
                        .iter()
                        .map(|it| match it.as_object() {
                            Some(m) => with_image_url(m, "image", &exists),
                            None => it.clone(),
                        })
                        .collect(),
                );
            }
            blk
        })
        .collect();
    out.insert("blocks".into(), Value::Array(rb));
    Value::Object(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn neutral_default_vectors() {
        let f: Value =
            serde_json::from_str(include_str!("../tests/branding-fallback.json")).unwrap();
        assert_eq!(f["defaults"], defaults());
        assert_eq!(f["dark_defaults"], dark_defaults());
        for c in f["cases"].as_array().unwrap() {
            assert_eq!(resolve(&c["settings"]), c["resolved"], "{}", c["name"]);
        }
    }

    #[test]
    fn defaults_are_neutral() {
        // greys, black and white: r = g = b within a small tolerance
        let d = defaults();
        let mut all: Vec<String> = COLORS
            .iter()
            .map(|k| d["colors"][k].as_str().unwrap().to_string())
            .collect();
        all.extend(
            dark_defaults()
                .as_object()
                .unwrap()
                .values()
                .map(|v| v.as_str().unwrap().to_string()),
        );
        all.push(d["image_background"].as_str().unwrap().into());
        for c in all {
            let ch: Vec<i64> = (0..3)
                .map(|i| i64::from_str_radix(&c[1 + 2 * i..3 + 2 * i], 16).unwrap())
                .collect();
            let spread = ch.iter().max().unwrap() - ch.iter().min().unwrap();
            assert!(spread <= 40, "{c} is not neutral");
        }
    }

    #[test]
    fn validation() {
        let b = json!({
            "theme": {"radius": "huge", "colors": {"primary": "red"}, "x-acme": 1},
            "login": {"layout": "split", "background_image": "img_missing"},
            "home": {"blocks": [
                {"id": "a", "type": "hero", "link": "//evil.example"},
                {"id": "a", "type": "future_block", "anything": true},
                {"id": "t", "type": "tiles", "items": []},
                {"id": "p", "type": "products", "query": "a=1?b", "max": 30}
            ]}
        });
        let v = validate(&b, |id| id == "img_ok");
        let ptrs: Vec<&str> = v
            .errors
            .iter()
            .filter_map(|e| e.pointer.as_deref())
            .collect();
        assert_eq!(
            ptrs,
            vec![
                "/branding/theme/radius",
                "/branding/theme/colors/primary",
                "/branding/login/background_image",
                "/branding/home/blocks/0/link",
                "/branding/home/blocks/1/id",
                "/branding/home/blocks/2/items",
                "/branding/home/blocks/3/query",
                "/branding/home/blocks/3/max",
            ]
        );
        assert!(!v.fatal);
        assert!(validate(&json!({"theme": "dark"}), |_| true).fatal);
        assert!(
            validate(&json!({"login": {"background_image": "img_ok"}}), |id| id
                == "img_ok")
            .ok()
        );
    }

    #[test]
    fn links_and_queries() {
        assert!(valid_portal_link("/products?q=1"));
        assert!(valid_portal_link("https://brand.example/x"));
        assert!(!valid_portal_link("//x"));
        assert!(!valid_portal_link("/\\x"));
        assert!(!valid_portal_link("http://x"));
        assert!(!valid_portal_link("javascript:alert(1)"));
        assert!(valid_query("item_type=jacket&q=waxed"));
        assert!(!valid_query("a=%zz"));
        assert!(!valid_query("a=%2"));
        assert!(!valid_query("a=1;b=2"));
    }

    #[test]
    fn images_resolve() {
        let b = json!({"login": {"background_image": "img_1"}, "home": {"blocks": [
            {"id": "h", "type": "hero", "image": "img_1"},
            {"id": "t", "type": "tiles", "items": [{"image": "img_gone"}]}]}});
        let ex = |id: &str| id == "img_1";
        assert_eq!(
            public_login(&b, ex)["background_image_url"],
            "/admin/api/public/images/img_1"
        );
        let h = resolved_home(&b, ex);
        assert_eq!(
            h["blocks"][0]["image_url"],
            "/admin/api/public/images/img_1"
        );
        assert!(h["blocks"][1]["items"][0]["image_url"].is_null());
        assert_eq!(image_refs(&b).len(), 3);
    }
}
