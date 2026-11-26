//! HTTP integration tests on a running node (node-go's protocol_test.go,
//! ingest_test.go and load_test.go): the protocol read through the
//! `obx-client` crate, the spec's ingest replay through `obx-conformance`,
//! and the load test (`NODE_RS_LOAD_TEST=1`).

use std::time::{Duration, Instant};

use serde_json::{Map, Value, json};

use crate::testkit::Node;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn maison_noor_protocol_through_obx_client() {
    let n = Node::start().await;
    n.import_fixtures().await;
    let (_, id, secret) = n.api_client("Harbour", Map::new()).await;
    let c = obx_client::Client::new(&n.base, &id, &secret).unwrap();

    let d = c.discovery().await.unwrap();
    assert_eq!(d["spec_version"], obx_types::SPEC_VERSION);
    let g = c.grant().await.unwrap();
    assert_eq!(g["status"], "active");
    assert_eq!(c.brands().await.unwrap().len(), 2);

    // Keyset pages over every product.
    let mut q = obx_client::ProductQuery {
        limit: Some(4),
        ..Default::default()
    };
    let mut styles = Vec::new();
    loop {
        let p = c.products(&q).await.unwrap();
        styles.extend(
            p.items
                .iter()
                .map(|x| x["style_number"].as_str().unwrap().to_string()),
        );
        match p.next_cursor {
            Some(cur) => q.cursor = Some(cur),
            None => break,
        }
    }
    assert_eq!(styles.len(), 11);
    let mn1001 = c
        .by_gtin(&[
            "2000100101025".into(),
            "12345".into(),
            "2000999901010".into(),
        ])
        .await
        .unwrap();
    let st: Vec<&str> = mn1001.results.iter().map(|r| r.status.as_str()).collect();
    assert_eq!(st, ["matched", "invalid", "unmatched"]);
    let p = &mn1001.products[0];
    assert_eq!(p["style_number"], "MN-1001");
    assert_eq!(p["variants"].as_array().unwrap().len(), 8);
    assert_eq!(p["assets"].as_array().unwrap().len(), 4);

    // The bytes behind a rendition are what the asset says.
    let a = &p["assets"][0];
    let web = c.rendition(a["id"].as_str().unwrap(), "web").await.unwrap();
    assert_eq!(
        crate::secure::sha256_hex(&web),
        a["renditions"]["web"]["sha256"].as_str().unwrap()
    );

    // The change feed: a full snapshot, then live.
    let mut cursor: Option<String> = None;
    let mut snapshot = 0;
    loop {
        let page = c.changes(cursor.as_deref(), 37).await.unwrap();
        if page.phase == "snapshot" {
            snapshot += page.changes.len();
        }
        cursor = Some(page.next_cursor.clone());
        if page.phase == "live" && !page.has_more {
            break;
        }
    }
    assert_eq!(snapshot, 2 + 11 + 46 + 35);

    // A wrong secret is refused with the OAuth2 error.
    let bad = obx_client::Client::new(&n.base, &id, "obxs_wrong").unwrap();
    assert_eq!(
        bad.brands().await.unwrap_err().code(),
        Some("invalid_client")
    );
}

/// The spec's ingest script replayed over HTTP with an upload key.
struct HttpIngest<'a> {
    n: &'a Node,
    token: String,
    api: obx_client::Client,
    cursor: Option<String>,
}

impl HttpIngest<'_> {
    fn block<T>(&self, f: impl std::future::Future<Output = T>) -> T {
        tokio::task::block_in_place(|| tokio::runtime::Handle::current().block_on(f))
    }
}

fn seg(kind: &str) -> String {
    format!("{kind}s")
}

impl obx_conformance::IngestTarget for HttpIngest<'_> {
    fn put_blob(&mut self, sha256: &str, bytes: &[u8]) -> Result<(), String> {
        let r = self.block(
            self.n
                .http
                .put(format!("{}/obx/v1/ingest/blobs/{sha256}", self.n.base))
                .bearer_auth(&self.token)
                .body(bytes.to_vec())
                .send(),
        );
        let r = r.map_err(|e| e.to_string())?;
        r.status()
            .is_success()
            .then_some(())
            .ok_or_else(|| format!("HTTP {}", r.status()))
    }

    fn apply(
        &mut self,
        op: &obx_conformance::Operation,
    ) -> Result<(String, Option<String>), String> {
        let url = format!(
            "{}/obx/v1/ingest/{}/{}",
            self.n.base,
            seg(&op.kind),
            op.external_id
        );
        let h = &self.n.http;
        let req = match op.op.as_str() {
            "upsert" => h.put(&url).json(op.data.as_ref().unwrap_or(&Value::Null)),
            "delete" => h.delete(&url),
            "publish" | "unpublish" | "patch" => {
                let body = op.data.clone().unwrap_or_else(|| {
                    json!({"status": if op.op == "publish" { "published" } else { "unpublished" }})
                });
                h.patch(&url)
                    .header("content-type", "application/merge-patch+json")
                    .body(body.to_string())
            }
            o => return Err(format!("unknown op {o}")),
        };
        let resp = self
            .block(req.bearer_auth(&self.token).send())
            .map_err(|e| e.to_string())?;
        let v: Value = self.block(resp.json()).unwrap_or(Value::Null);
        let (result, code) = if let Some(r) = v.get("result").and_then(|r| r.as_str()) {
            (
                r.to_string(),
                v["error"]["obx_error"].as_str().map(String::from),
            )
        } else {
            (
                "error".to_string(),
                v["obx_error"].as_str().map(String::from),
            )
        };
        if op.kind == "asset" && op.op == "upsert" && result != "error" {
            let deadline = Instant::now() + Duration::from_secs(60);
            while Instant::now() < deadline {
                let rec: Value = self
                    .block(async {
                        h.get(&url)
                            .bearer_auth(&self.token)
                            .send()
                            .await?
                            .json()
                            .await
                    })
                    .unwrap_or(Value::Null);
                if rec["visibility"] != "pending_files" {
                    break;
                }
                std::thread::sleep(Duration::from_millis(100));
            }
        }
        Ok((result, code))
    }

    fn new_changes(&mut self) -> Result<Vec<(String, String, String)>, String> {
        let mut out = Vec::new();
        loop {
            let page = self
                .block(self.api.changes(self.cursor.as_deref(), 500))
                .map_err(|e| e.to_string())?;
            if page.phase == "live" {
                out.extend(page.changes.iter().map(|c| {
                    (
                        c["type"].as_str().unwrap_or("").to_string(),
                        c["op"].as_str().unwrap_or("").to_string(),
                        c["external_id"].as_str().unwrap_or("").to_string(),
                    )
                }));
            }
            self.cursor = Some(page.next_cursor);
            if page.phase == "live" && !page.has_more {
                return Ok(out);
            }
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn ingest_replay_of_the_spec() {
    let n = Node::start().await;
    let token = n.ingest_token().await;
    let (_, id, secret) = n.api_client("Replay", Map::new()).await;
    let api = obx_client::Client::new(&n.base, &id, &secret).unwrap();
    let mut t = HttpIngest {
        n: &n,
        token,
        api,
        cursor: None,
    };
    let diffs = obx_conformance::replay(&mut t);
    assert!(diffs.is_empty(), "{diffs:#?}");
}

/// node-go's load test: 10,000 products (60,000 variants, 40,000 images),
/// the hot read paths against budgets that catch a missing index or an N+1.
/// `NODE_RS_LOAD_TEST=1 cargo test --release load_test -- --nocapture`;
/// `NODE_RS_LOAD_PRODUCTS` scales it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn load_test() {
    if std::env::var("NODE_RS_LOAD_TEST").is_err() {
        eprintln!("set NODE_RS_LOAD_TEST=1 to run the load test");
        return;
    }
    let products: usize = std::env::var("NODE_RS_LOAD_PRODUCTS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(10_000);
    let n = Node::start().await;
    let t0 = Instant::now();
    let mut shas = Vec::new();
    for f in obx_conformance::files("maison-noor/images/")
        .into_iter()
        .take(4)
    {
        let data = obx_conformance::file(&f).unwrap().into_owned();
        let b = n
            .app
            .put_blob(bytes::Bytes::from(data), None)
            .await
            .unwrap();
        n.app.render_original(&b.sha256).await.unwrap();
        shas.push(b.sha256);
    }
    let colors = ["BLK", "NVY", "OAT"];
    let sizes = ["S", "M", "L"];
    let seasons = ["SS26", "AW26", "SS27"];
    let types = ["t_shirt", "sweater", "jacket", "trousers", "dress"];
    let mut gtins = Vec::new();
    for from in (0..products).step_by(100) {
        let shas = shas.clone();
        let mut batch_gtins = Vec::new();
        for i in from..(from + 100).min(products) {
            for c in 0..2 {
                for s in 0..3 {
                    let base = format!("20{i:07}{c}{s}0");
                    batch_gtins.push(format!("{base}{}", ean13_check(&base)));
                }
            }
        }
        gtins.extend(batch_gtins.iter().cloned());
        n.app
            .catalog_write(None, move |w| {
                let obj = |v: Value| v.as_object().unwrap().clone();
                if from == 0 {
                    let (_, p) = w.upsert("brand", "loadbrand", obj(json!({"name": "Load Brand"})), "");
                    if let Some(p) = p {
                        return Err(p);
                    }
                }
                let mut g = batch_gtins.into_iter();
                for i in from..(from + 100).min(products) {
                    let style = format!("LD-{i:05}");
                    let (_, p) = w.upsert("product", &style, obj(json!({"brand_external_id": "loadbrand", "style_number": style,
                        "name": {"en": format!("Load product {i}"), "nl": format!("Laadproduct {i}")},
                        "item_type": types[i % 5], "target_group": "unisex", "season": seasons[i % 3]})), "");
                    if let Some(p) = p {
                        return Err(p);
                    }
                    for c in 0..2 {
                        for size in sizes {
                            let gt = g.next().unwrap();
                            let (_, p) = w.upsert("variant", &gt, obj(json!({"product_external_id": style, "gtin": gt,
                                "color": {"code": colors[(i + c) % 3]}, "size": size})), "");
                            if let Some(p) = p {
                                return Err(p);
                            }
                        }
                    }
                    for pos in 1..=4usize {
                        let col = colors[(i + (pos - 1) / 2) % 3];
                        let (_, p) = w.upsert("asset", &format!("{style}_{col}_{pos}"), obj(json!({"product_external_id": style,
                            "color_code": col, "role": "packshot", "position": pos,
                            "files": {"original": {"sha256": shas[(i + pos) % shas.len()]}}})), "");
                        if let Some(p) = p {
                            return Err(p);
                        }
                    }
                }
                Ok(())
            })
            .await
            .unwrap();
    }
    let (nv, na): (i64, i64) = n
        .app
        .db
        .read(|c| {
            Ok((
                c.query_row("SELECT COUNT(*) FROM variants WHERE visible = 1", [], |r| {
                    r.get(0)
                })?,
                c.query_row("SELECT COUNT(*) FROM assets WHERE visible = 1", [], |r| {
                    r.get(0)
                })?,
            ))
        })
        .await
        .unwrap();
    eprintln!(
        "seeded {products} products, {nv} variants, {na} assets in {:?}",
        t0.elapsed()
    );
    assert_eq!((nv, na), (products as i64 * 6, products as i64 * 4));

    let admin = n.admin().await;
    let (_, id, secret) = n.api_client("Load Retailer", Map::new()).await;
    let api = obx_client::Client::new(&n.base, &id, &secret).unwrap();
    let mut results: std::collections::BTreeMap<&str, Vec<Duration>> = Default::default();
    let mut rng = 1u64;
    let mut rnd = |m: usize| {
        rng = rng
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        ((rng >> 33) as usize) % m
    };
    use reqwest::Method as M;
    macro_rules! measure {
        ($name:expr, $runs:expr, $body:expr) => {
            for i in 0..$runs {
                let _ = i;
                let t = Instant::now();
                $body(i).await;
                results.entry($name).or_default().push(t.elapsed());
            }
        };
    }
    measure!("portal browse: first page", 30, |_| admin.must(
        200,
        M::GET,
        "/admin/api/portal/products",
        None
    ));
    for i in 0..30 {
        let t = Instant::now();
        admin
            .must(
                200,
                M::GET,
                &format!(
                    "/admin/api/portal/products?season={}&item_type={}",
                    seasons[i % 3],
                    types[i % 5]
                ),
                None,
            )
            .await;
        results
            .entry("portal browse: filter season+type")
            .or_default()
            .push(t.elapsed());
    }
    for _ in 0..30 {
        let q = format!("/admin/api/portal/products?q=LD-{:05}", rnd(products));
        let t = Instant::now();
        admin.must(200, M::GET, &q, None).await;
        results
            .entry("portal search: style number")
            .or_default()
            .push(t.elapsed());
    }
    measure!("portal search: word", 30, |_| admin.must(
        200,
        M::GET,
        "/admin/api/portal/products?q=laadproduct",
        None
    ));
    measure!("portal facets", 30, |_| admin.must(
        200,
        M::GET,
        "/admin/api/portal/facets",
        None
    ));
    let mut cursor = String::new();
    for _ in 0..50 {
        let q = if cursor.is_empty() {
            "/admin/api/portal/products".to_string()
        } else {
            format!(
                "/admin/api/portal/products?cursor={}",
                url::form_urlencoded::byte_serialize(cursor.as_bytes()).collect::<String>()
            )
        };
        let t = Instant::now();
        let page = admin.must(200, M::GET, &q, None).await;
        results
            .entry("portal browse: next page (walk 50 pages)")
            .or_default()
            .push(t.elapsed());
        cursor = page["next_cursor"].as_str().unwrap_or("").to_string();
    }
    for _ in 0..50 {
        let t = Instant::now();
        let list = admin
            .must(
                200,
                M::GET,
                &format!("/admin/api/portal/products?q=LD-{:05}", rnd(products)),
                None,
            )
            .await;
        if let Some(id) = list["items"][0]["id"].as_str() {
            admin
                .must(
                    200,
                    M::GET,
                    &format!("/admin/api/portal/products/{id}"),
                    None,
                )
                .await;
        }
        results
            .entry("portal product page")
            .or_default()
            .push(t.elapsed());
    }
    for _ in 0..40 {
        let list: Vec<String> = (0..100).map(|_| gtins[rnd(gtins.len())].clone()).collect();
        let t = Instant::now();
        admin
            .must(
                200,
                M::POST,
                "/admin/api/portal/gtin-lookup",
                Some(json!({"gtins": list})),
            )
            .await;
        results
            .entry("portal EAN list (100 EANs)")
            .or_default()
            .push(t.elapsed());
    }
    let mut cur: Option<String> = None;
    let mut pages = 0;
    loop {
        let t = Instant::now();
        let p = api.changes(cur.as_deref(), 500).await.unwrap();
        results
            .entry("/changes page (limit 500, full snapshot)")
            .or_default()
            .push(t.elapsed());
        pages += 1;
        cur = Some(p.next_cursor);
        if !p.has_more {
            break;
        }
    }
    for _ in 0..200 {
        let g = gtins[rnd(gtins.len())].clone();
        let t = Instant::now();
        let _: Value = api
            .get_json("/obx/v1/products:by-gtin", &[("gtin", g)])
            .await
            .unwrap();
        results
            .entry("/products:by-gtin GET (1 EAN)")
            .or_default()
            .push(t.elapsed());
    }
    for _ in 0..20 {
        let list: Vec<String> = (0..500).map(|_| gtins[rnd(gtins.len())].clone()).collect();
        let t = Instant::now();
        api.by_gtin(&list).await.unwrap();
        results
            .entry("/products:by-gtin POST (500 EANs)")
            .or_default()
            .push(t.elapsed());
    }
    for _ in 0..30 {
        let t = Instant::now();
        api.products(&obx_client::ProductQuery {
            limit: Some(100),
            ..Default::default()
        })
        .await
        .unwrap();
        results
            .entry("/products list page (limit 100)")
            .or_default()
            .push(t.elapsed());
    }
    measure!("admin catalog list", 30, |_| admin.must(
        200,
        M::GET,
        "/admin/api/catalog/products",
        None
    ));

    let ms = |d: Duration| format!("{:.1} ms", d.as_secs_f64() * 1000.0);
    let mut report =
        String::from("\n| Request | runs | p50 | p95 | max |\n|---|---:|---:|---:|---:|\n");
    let mut failures = Vec::new();
    for (name, d) in results.iter_mut() {
        d.sort();
        let (p50, mut p95, mx) = (d[d.len() / 2], d[d.len() * 95 / 100], d[d.len() - 1]);
        if d.len() < 20 {
            p95 = mx;
        }
        report.push_str(&format!(
            "| {name} | {} | {} | {} | {} |\n",
            d.len(),
            ms(p50),
            ms(p95),
            ms(mx)
        ));
        let budget = if name.contains("(1 EAN)") {
            Duration::from_millis(50)
        } else if name.contains("EANs") || name.contains("/changes") {
            Duration::from_millis(800)
        } else {
            Duration::from_millis(300)
        };
        if p95 > budget {
            failures.push(format!("{name}: p95 {} > {}", ms(p95), ms(budget)));
        }
    }
    eprintln!("load test: {products} products, {pages} change pages{report}");
    assert!(failures.is_empty(), "{failures:#?}");
}

fn ean13_check(base: &str) -> u32 {
    let sum: u32 = base
        .bytes()
        .enumerate()
        .map(|(j, b)| {
            let d = (b - b'0') as u32;
            if j % 2 == 1 { d * 3 } else { d }
        })
        .sum();
    (10 - sum % 10) % 10
}

fn png(w: u32, h: u32, shade: u8) -> Vec<u8> {
    let img = image::RgbImage::from_pixel(w, h, image::Rgb([shade, 90, 120]));
    let mut out = std::io::Cursor::new(Vec::new());
    img.write_to(&mut out, image::ImageFormat::Png).unwrap();
    out.into_inner()
}

fn multipart(data: &[u8]) -> (String, Vec<u8>) {
    let b = "obxboundary7d3";
    let mut body = format!(
        "--{b}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"x.png\"\r\nContent-Type: image/png\r\n\r\n"
    )
    .into_bytes();
    body.extend_from_slice(data);
    body.extend_from_slice(format!("\r\n--{b}--\r\n").as_bytes());
    (format!("multipart/form-data; boundary={b}"), body)
}

fn without_nulls(v: &Value) -> Value {
    match v {
        Value::Object(m) => Value::Object(
            m.iter()
                .filter(|(_, x)| !x.is_null())
                .map(|(k, x)| (k.clone(), without_nulls(x)))
                .collect(),
        ),
        Value::Array(a) => Value::Array(a.iter().map(without_nulls).collect()),
        x => x.clone(),
    }
}

/// node-go's TestPortalAppearance: the spec's full showroom round trip.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn portal_appearance_round_trip() {
    use reqwest::Method as M;
    let n = Node::start().await;
    let admin = n.admin().await;
    let raw = String::from_utf8(
        obx_conformance::file("examples/BrandingSettings.full.json")
            .unwrap()
            .into_owned(),
    )
    .unwrap();
    let mut fixture = raw.clone();
    let mut ids = std::collections::BTreeMap::new();
    let mut shade = 0u8;
    for id in regex::Regex::new(r#""(img_[a-z_]+)""#)
        .unwrap()
        .captures_iter(&raw)
        .map(|c| c[1].to_string())
    {
        if ids.contains_key(&id) {
            continue;
        }
        shade += 1;
        let (ct, body) = multipart(&png(64, 32, shade));
        let r = admin
            .req(M::POST, "/admin/api/settings/images")
            .header("content-type", ct)
            .body(body)
            .send()
            .await
            .unwrap();
        assert_eq!(r.status(), 201);
        let m: Value = r.json().await.unwrap();
        let new = m["id"].as_str().unwrap().to_string();
        assert_eq!(m["url"], format!("/admin/api/public/images/{new}"));
        assert_eq!(
            (m["width"].as_i64(), m["height"].as_i64()),
            (Some(64), Some(32))
        );
        ids.insert(id, new);
    }
    for (old, new) in &ids {
        fixture = fixture.replace(&format!("\"{old}\""), &format!("\"{new}\""));
    }
    let fixture: Value = serde_json::from_str(&fixture).unwrap();
    let got = admin
        .must(
            200,
            M::PATCH,
            "/admin/api/settings",
            Some(json!({"branding": fixture})),
        )
        .await;
    let again = admin.must(200, M::GET, "/admin/api/settings", None).await;
    for m in [&got, &again] {
        let b = &m["branding"];
        assert!(b.get("favicon_url").is_some());
        for (k, want) in without_nulls(&fixture).as_object().unwrap() {
            assert_eq!(without_nulls(&b[k]), *want, "branding.{k}");
        }
    }
    let pb: Value = n
        .http
        .get(format!("{}/admin/api/public/branding", n.base))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(pb.get("home").is_none(), "home is not public");
    let login = &pb["login"];
    let bg = login["background_image"].as_str().unwrap();
    assert_eq!(
        login["background_image_url"],
        format!("/admin/api/public/images/{bg}")
    );
    let img = n
        .http
        .get(format!("{}/admin/api/public/images/{bg}", n.base))
        .send()
        .await
        .unwrap();
    assert_eq!(img.status(), 200);
    assert!(
        img.headers()["cache-control"]
            .to_str()
            .unwrap()
            .contains("immutable")
    );
    let v = admin
        .must(200, M::GET, "/admin/api/portal/viewer", None)
        .await;
    let blocks = v["branding"]["home"]["blocks"].as_array().unwrap();
    assert!(blocks.iter().any(|b| {
        b["image_url"]
            .as_str()
            .is_some_and(|u| u.starts_with("/admin/api/public/images/"))
    }));
    // An image in use cannot be deleted; an invalid member is a 422 with a pointer.
    admin
        .must(
            409,
            M::DELETE,
            &format!("/admin/api/settings/images/{bg}"),
            None,
        )
        .await;
    let p = admin
        .must(
            422,
            M::PATCH,
            "/admin/api/settings",
            Some(json!({"branding": {"theme": {"radius": "huge"}}})),
        )
        .await;
    assert_eq!(p["errors"][0]["pointer"], "/branding/theme/radius");
    // The favicon: square PNG or WebP only.
    let (ct, body) = multipart(&png(32, 16, 1));
    let r = admin
        .req(M::PUT, "/admin/api/settings/favicon")
        .header("content-type", ct)
        .body(body)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 422);
    let s = admin
        .req(M::PUT, "/admin/api/settings/favicon")
        .header("content-type", "image/png")
        .body(png(32, 32, 1))
        .send()
        .await
        .unwrap();
    assert_eq!(s.status(), 200);
    let s: Value = s.json().await.unwrap();
    let fav = s["branding"]["favicon_url"].as_str().unwrap().to_string();
    assert_eq!(n.http.get(fav).send().await.unwrap().status(), 200);
}
