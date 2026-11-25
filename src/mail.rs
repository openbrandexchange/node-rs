//! E-mail: plain-text messages in the 25 interface languages (the `email.*`
//! texts of the bundled admin-ui), sent over SMTP (`OBX_SMTP_URL`) or, without
//! it, written to the log. A message that cannot be sent is stored encrypted
//! in `mail_outbox` and retried with backoff; the layout, the retry schedule
//! and the outbox rows are node-go's.

use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use regex::Regex;
use rusqlite::params;
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader};

use crate::app::App;
use crate::db;

// The kinds of e-mail the node sends. Each is an `email.<kind>` group in the
// admin-ui locale files: subject, body, button and optional extra lines.
pub const MAIL_INVITE: &str = "invite";
pub const MAIL_ACCESS_REQUEST_RECEIVED: &str = "accessRequestReceived";
pub const MAIL_ACCESS_REQUEST_NEW: &str = "accessRequestNew";
pub const MAIL_ACCESS_APPROVED: &str = "accessApproved";
pub const MAIL_ACCESS_REJECTED: &str = "accessRejected";
/// A background download is ready (vars: name, files, expires, url).
#[allow(dead_code)] // sent by the portal's download jobs
pub const MAIL_ZIP_READY: &str = "zipReady";
pub const MAIL_PASSWORD_RESET: &str = "passwordReset";

/// The wait before each retry; after the last one the e-mail is given up.
const BACKOFF_SECS: [i64; 7] = [60, 300, 900, 3600, 3 * 3600, 6 * 3600, 12 * 3600];

/// English fallbacks (a copy of admin-ui's en.json) for keys the vendored
/// locale files lack.
const BUILTIN: &[(&str, &str)] = &[
    ("email.greeting", "Hello {{name}},"),
    ("email.greetingNoName", "Hello,"),
    ("email.signoff", "Kind regards,\n{{brand}}"),
    (
        "email.footer",
        "You receive this email because of your account or request at {{portal}}.",
    ),
    (
        "email.linkFallback",
        "Button not working? Copy this address into your browser: {{url}}",
    ),
    (
        "email.invite.subject",
        "{{brand}} invites you to {{portal}}",
    ),
    (
        "email.invite.body",
        "{{brand}} has created an account for you. There you can find their final product images and article data, and download them whenever you need.",
    ),
    ("email.invite.button", "Choose your password"),
    (
        "email.invite.expiry",
        "This link works once and is valid until {{expires}}.",
    ),
    (
        "email.invite.ignore",
        "Not expecting this? Then you can ignore this email.",
    ),
    (
        "email.accessRequestReceived.subject",
        "We received your request for {{portal}}",
    ),
    (
        "email.accessRequestReceived.body",
        "Thank you for your request to {{brand}}. We will check it and email you as soon as it has been reviewed.",
    ),
    (
        "email.accessRequestNew.subject",
        "New access request from {{retailer}}",
    ),
    (
        "email.accessRequestNew.body",
        "{{contact}} from {{retailer}} has asked for access to {{portal}}.",
    ),
    ("email.accessRequestNew.button", "Review the request"),
    (
        "email.accessApproved.subject",
        "Your access to {{portal}} is ready",
    ),
    (
        "email.accessApproved.body",
        "{{brand}} has approved your request.",
    ),
    ("email.accessApproved.button", "Open the portal"),
    (
        "email.accessApproved.apiNote",
        "Your software can now collect its API key using the request number it received.",
    ),
    (
        "email.accessRejected.subject",
        "About your request for {{portal}}",
    ),
    (
        "email.accessRejected.body",
        "Unfortunately {{brand}} cannot give you access at the moment.",
    ),
    ("email.accessRejected.reason", "Explanation: {{reason}}"),
    (
        "email.accessRejected.contact",
        "Questions? Reply to this email or contact {{brand}}.",
    ),
    (
        "email.zipReady.subject",
        "Your download from {{portal}} is ready",
    ),
    (
        "email.zipReady.body",
        "The zip you asked for ({{files}} files) is ready.",
    ),
    ("email.zipReady.button", "Download"),
    (
        "email.zipReady.expiry",
        "The file is available until {{expires}}.",
    ),
    (
        "email.passwordReset.subject",
        "Choose a new password for {{portal}}",
    ),
    (
        "email.passwordReset.body",
        "Someone asked to reset the password of your account. Choose a new one with the button below.",
    ),
    ("email.passwordReset.button", "Choose a new password"),
    (
        "email.passwordReset.expiry",
        "This link works once and is valid for one hour.",
    ),
    (
        "email.passwordReset.ignore",
        "Didn't ask for this? Then you can ignore this email; your password stays the same.",
    ),
];

/// The local word for the retailer portal when the locale files have none.
const PORTAL_WORDS: &[(&str, &str)] = &[
    ("bg", "Портал за търговци"),
    ("cs", "Portál pro prodejce"),
    ("da", "Forhandlerportal"),
    ("de", "Händlerportal"),
    ("el", "Πύλη μεταπωλητών"),
    ("en", "Brand portal"),
    ("es", "Portal para distribuidores"),
    ("et", "Edasimüüjate portaal"),
    ("fi", "Jälleenmyyjäportaali"),
    ("fr", "Espace revendeurs"),
    ("ga", "Tairseach miondíoltóirí"),
    ("hr", "Portal za trgovce"),
    ("hu", "Viszonteladói portál"),
    ("it", "Area rivenditori"),
    ("lt", "Prekybininkų portalas"),
    ("lv", "Tirgotāju portāls"),
    ("mt", "Portal għall-bejjiegħa"),
    ("nb", "Forhandlerportal"),
    ("nl", "Beeldbank"),
    ("pl", "Portal dla sprzedawców"),
    ("pt", "Portal de revendedores"),
    ("ro", "Portal pentru revânzători"),
    ("sk", "Portál pre predajcov"),
    ("sl", "Portal za trgovce"),
    ("sv", "Återförsäljarportal"),
];

// ---- locale texts ---------------------------------------------------------------

type Flat = HashMap<String, String>;

fn flatten(prefix: &str, v: &serde_json::Value, out: &mut Flat) {
    match v {
        serde_json::Value::Object(m) => {
            for (k, c) in m {
                let key = if prefix.is_empty() {
                    k.clone()
                } else {
                    format!("{prefix}.{k}")
                };
                flatten(&key, c, out);
            }
        }
        serde_json::Value::String(s) => {
            out.insert(prefix.to_string(), s.clone());
        }
        _ => {}
    }
}

fn locale(lang: &str) -> Arc<Flat> {
    static CACHE: OnceLock<Mutex<HashMap<String, Arc<Flat>>>> = OnceLock::new();
    let cache = CACHE.get_or_init(Default::default);
    if let Some(m) = cache.lock().unwrap().get(lang) {
        return m.clone();
    }
    let mut m = Flat::new();
    if let Some(f) = crate::http::ui::dist_file(&format!("locales/{lang}.json")) {
        if let Ok(v) = serde_json::from_slice::<serde_json::Value>(&f) {
            flatten("", &v, &mut m);
        }
    }
    let m = Arc::new(m);
    cache.lock().unwrap().insert(lang.to_string(), m.clone());
    m
}

/// The localized string for key in lang (English fallback, then built in).
pub fn text(lang: &str, key: &str) -> String {
    let lang = crate::http::admin::supported_lang(lang);
    for l in [lang.as_str(), "en"] {
        if let Some(v) = locale(l).get(key).filter(|v| !v.is_empty()) {
            return v.clone();
        }
    }
    BUILTIN
        .iter()
        .find(|(k, _)| *k == key)
        .map(|(_, v)| v.to_string())
        .unwrap_or_default()
}

fn placeholder() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"\{\{\s*([a-z_]+)\s*\}\}|\{([a-z_]+)\}").unwrap())
}

/// Fills in `{{name}}` / `{name}` placeholders. A value ending in a full stop
/// (a company name like "MAISON NOOR B.V.") swallows the full stop the
/// sentence puts right after it.
pub fn interpolate(s: &str, vars: &HashMap<String, String>) -> String {
    let mut b = String::new();
    let mut last = 0;
    for c in placeholder().captures_iter(s) {
        let m = c.get(0).unwrap();
        b.push_str(&s[last..m.start()]);
        last = m.end();
        let k = c.get(1).or_else(|| c.get(2)).unwrap().as_str();
        match vars.get(k) {
            None => b.push_str(m.as_str()),
            Some(v) => {
                b.push_str(v);
                if v.ends_with('.') && s[last..].starts_with('.') {
                    last += 1;
                }
            }
        }
    }
    b.push_str(&s[last..]);
    b
}

/// The UTC date of an e-mail, the same in every language.
pub fn mail_date(t: chrono::DateTime<chrono::Utc>) -> String {
    t.format("%Y-%m-%d").to_string()
}

/// "<Brand> · <local word>": the brand's own portal name (language fallback
/// rule) or the glossary word of the locale files.
pub fn portal_name(s: &crate::settings::Settings, lang: &str) -> String {
    let name = s.display_name().to_string();
    let mut word = crate::catalog::pick(
        s.branding.portal_name.as_ref(),
        lang,
        &s.content_languages(),
    )
    .trim()
    .to_string();
    let base = crate::http::admin::supported_lang(lang);
    if word.is_empty() {
        word = locale(&base)
            .get("glossary.portal")
            .cloned()
            .unwrap_or_default();
    }
    if word.is_empty() {
        word = PORTAL_WORDS
            .iter()
            .find(|(l, _)| *l == base)
            .map(|(_, w)| w.to_string())
            .unwrap_or_else(|| "Brand portal".into());
    }
    if name.is_empty() {
        word
    } else {
        format!("{name} · {word}")
    }
}

/// Subject and body of an e-mail. Layout: greeting, body, optional lines
/// (reason, apiNote), the button text with the link (`url`), expiry, ignore,
/// contact, sign-off, footer. A line with an unfilled placeholder is left out.
pub fn render(
    s: &crate::settings::Settings,
    lang: &str,
    kind: &str,
    vars: &[(&str, String)],
) -> (String, String) {
    let lang = crate::http::admin::supported_lang(lang);
    let mut v: HashMap<String, String> = vars
        .iter()
        .filter(|(_, x)| !x.is_empty())
        .map(|(k, x)| (k.to_string(), x.clone()))
        .collect();
    if !v.contains_key("portal") {
        v.insert("portal".into(), portal_name(s, &lang));
    }
    if !v.contains_key("brand") && !s.display_name().is_empty() {
        v.insert("brand".into(), s.display_name().to_string());
    }
    let line = |key: &str| -> String {
        let t = text(&lang, key);
        if t.is_empty() {
            return String::new();
        }
        let out = interpolate(&t, &v);
        if placeholder().is_match(&out) {
            String::new()
        } else {
            out
        }
    };
    let mut parts: Vec<String> = Vec::new();
    let mut add = |t: String| {
        if !t.trim().is_empty() {
            parts.push(t);
        }
    };
    if v.contains_key("name") {
        add(line("email.greeting"));
    } else {
        add(line("email.greetingNoName"));
    }
    add(line(&format!("email.{kind}.body")));
    add(line(&format!("email.{kind}.reason")));
    if v.contains_key("api") {
        add(line(&format!("email.{kind}.apiNote")));
    }
    if let Some(u) = v.get("url") {
        let b = line(&format!("email.{kind}.button"));
        if b.is_empty() {
            add(u.clone());
        } else {
            add(format!("{b}:\n{u}"));
        }
    }
    add(line(&format!("email.{kind}.expiry")));
    add(line(&format!("email.{kind}.ignore")));
    add(line(&format!("email.{kind}.contact")));
    add(line("email.signoff"));
    let body = format!("{}\n\n-- \n{}\n", parts.join("\n\n"), line("email.footer"));
    (line(&format!("email.{kind}.subject")), body)
}

// ---- transport -----------------------------------------------------------------

/// A message captured by the log driver (tests and development).
#[allow(dead_code)] // read by tests
#[derive(Debug, Clone)]
pub struct SentMail {
    pub to: String,
    pub subject: String,
    pub body: String,
}

/// The mail transport: SMTP, or the log (no `OBX_SMTP_URL`).
pub struct Mailer {
    smtp_url: Option<String>,
    from: String,
    log_bodies: bool,
    sent: Mutex<VecDeque<SentMail>>,
}

impl Mailer {
    pub fn new(cfg: &crate::config::Config) -> Mailer {
        Mailer {
            smtp_url: cfg.smtp_url.clone(),
            from: cfg.mail_from.clone(),
            log_bodies: cfg.mail_log_bodies,
            sent: Mutex::new(VecDeque::new()),
        }
    }

    /// Whether e-mail really leaves the node.
    pub fn configured(&self) -> bool {
        self.smtp_url.is_some()
    }

    /// The last messages of the log driver (at most 100).
    #[allow(dead_code)] // tests
    pub fn last(&self) -> Vec<SentMail> {
        self.sent.lock().unwrap().iter().cloned().collect()
    }

    pub async fn send(&self, to: &str, subject: &str, body: &str) -> Result<(), String> {
        let Some(url) = &self.smtp_url else {
            {
                let mut s = self.sent.lock().unwrap();
                s.push_back(SentMail {
                    to: to.into(),
                    subject: subject.into(),
                    body: body.into(),
                });
                if s.len() > 100 {
                    s.pop_front();
                }
            }
            if self.log_bodies {
                tracing::info!(
                    to,
                    subject,
                    body,
                    "e-mail (not sent: OBX_SMTP_URL is not set)"
                );
            } else {
                tracing::info!(
                    to,
                    subject,
                    "e-mail (not sent: OBX_SMTP_URL is not set; set OBX_MAIL_LOG_BODIES=true in development to log bodies)"
                );
            }
            return Ok(());
        };
        let msg = message(&self.from, to, subject, body);
        tokio::time::timeout(
            Duration::from_secs(60),
            smtp_send(url, &self.from, to, &msg),
        )
        .await
        .map_err(|_| "smtp: timed out".to_string())?
    }
}

/// RFC 2047 Q-encoding of a header value (only when it is not plain ASCII),
/// in encoded words of at most 75 characters.
fn q_encode(s: &str) -> String {
    if s.bytes().all(|b| (0x20..0x7f).contains(&b)) {
        return s.to_string();
    }
    let mut words = Vec::new();
    let mut cur = String::new();
    for ch in s.chars() {
        let mut enc = String::new();
        if ch == ' ' {
            enc.push('_');
        } else if ch.is_ascii_alphanumeric() || "!*+-/".contains(ch) {
            enc.push(ch);
        } else {
            let mut buf = [0u8; 4];
            for b in ch.encode_utf8(&mut buf).bytes() {
                enc.push_str(&format!("={b:02X}"));
            }
        }
        if cur.len() + enc.len() > 75 - 12 {
            words.push(std::mem::take(&mut cur));
        }
        cur.push_str(&enc);
    }
    if !cur.is_empty() {
        words.push(cur);
    }
    words
        .iter()
        .map(|w| format!("=?utf-8?q?{w}?="))
        .collect::<Vec<_>>()
        .join(" ")
}

fn domain_of(addr: &str) -> &str {
    match addr.rfind('@') {
        Some(i) => addr[i + 1..].trim_matches(|c| c == '>' || c == ' '),
        None => "localhost",
    }
}

/// The message as sent with DATA: headers, CRLF line ends, dot-stuffed.
fn message(from: &str, to: &str, subject: &str, body: &str) -> String {
    let date = chrono::Utc::now().format("%a, %d %b %Y %H:%M:%S +0000");
    let mut m = format!(
        "From: {from}\r\nTo: {to}\r\nSubject: {}\r\nDate: {date}\r\nMessage-ID: <{}@{}>\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Transfer-Encoding: 8bit\r\n\r\n",
        q_encode(subject),
        crate::ids::new("msg"),
        domain_of(from)
    );
    for line in body.replace("\r\n", "\n").split('\n') {
        if line.starts_with('.') {
            m.push('.');
        }
        m.push_str(line);
        m.push_str("\r\n");
    }
    m
}

struct Smtp<S> {
    r: BufReader<S>,
}

impl<S: AsyncRead + AsyncWrite + Unpin> Smtp<S> {
    /// One reply: (code, lines).
    async fn reply(&mut self) -> Result<(u16, Vec<String>), String> {
        let mut lines = Vec::new();
        loop {
            let mut l = String::new();
            let n = self
                .r
                .read_line(&mut l)
                .await
                .map_err(|e| format!("smtp: {e}"))?;
            if n == 0 {
                return Err("smtp: the server closed the connection".into());
            }
            if l.len() > 4096 || lines.len() > 100 {
                return Err("smtp: reply too long".into());
            }
            let l = l.trim_end().to_string();
            if l.len() < 3 {
                return Err(format!("smtp: bad reply {l:?}"));
            }
            let code: u16 = l[..3]
                .parse()
                .map_err(|_| format!("smtp: bad reply {l:?}"))?;
            let more = l.as_bytes().get(3) == Some(&b'-');
            lines.push(l.get(4..).unwrap_or("").to_string());
            if !more {
                return Ok((code, lines));
            }
        }
    }

    async fn expect(&mut self, want: u16, what: &str) -> Result<Vec<String>, String> {
        let (code, lines) = self.reply().await?;
        if code != want {
            return Err(format!("smtp {what}: {code} {}", lines.join(" ")));
        }
        Ok(lines)
    }

    async fn cmd(&mut self, line: &str, want: u16, what: &str) -> Result<Vec<String>, String> {
        self.r
            .get_mut()
            .write_all(format!("{line}\r\n").as_bytes())
            .await
            .map_err(|e| format!("smtp: {e}"))?;
        self.expect(want, what).await
    }

    async fn ehlo(&mut self, me: &str) -> Result<Vec<String>, String> {
        self.cmd(&format!("EHLO {me}"), 250, "EHLO").await
    }

    /// AUTH, MAIL FROM, RCPT TO, DATA and QUIT.
    async fn deliver(
        &mut self,
        user: Option<(String, String)>,
        from: &str,
        to: &str,
        msg: &str,
    ) -> Result<(), String> {
        if let Some((u, p)) = user {
            use base64::Engine;
            let plain =
                base64::engine::general_purpose::STANDARD.encode(format!("\0{u}\0{p}").as_bytes());
            self.cmd(&format!("AUTH PLAIN {plain}"), 235, "auth")
                .await
                .map_err(|_| "smtp auth failed".to_string())?;
        }
        self.cmd(&format!("MAIL FROM:<{from}>"), 250, "MAIL FROM")
            .await?;
        self.cmd(&format!("RCPT TO:<{to}>"), 250, "RCPT TO").await?;
        self.cmd("DATA", 354, "DATA").await?;
        let w = self.r.get_mut();
        w.write_all(msg.as_bytes())
            .await
            .map_err(|e| format!("smtp: {e}"))?;
        w.write_all(b".\r\n")
            .await
            .map_err(|e| format!("smtp: {e}"))?;
        self.expect(250, "DATA").await?;
        let _ = self.cmd("QUIT", 221, "QUIT").await;
        Ok(())
    }
}

fn tls_connector() -> Result<tokio_rustls::TlsConnector, String> {
    let mut roots = rustls::RootCertStore::empty();
    for c in rustls_native_certs::load_native_certs().certs {
        let _ = roots.add(c);
    }
    let cfg = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])
    .map_err(|e| e.to_string())?
    .with_root_certificates(roots)
    .with_no_client_auth();
    Ok(tokio_rustls::TlsConnector::from(Arc::new(cfg)))
}

fn valid_header_addr(s: &str) -> bool {
    !s.is_empty() && !s.contains(['\r', '\n', '<', '>'])
}

async fn smtp_send(raw_url: &str, from: &str, to: &str, msg: &str) -> Result<(), String> {
    if !valid_header_addr(from) || !valid_header_addr(to) {
        return Err("smtp: invalid address".into());
    }
    let u = url::Url::parse(raw_url).map_err(|_| "invalid OBX_SMTP_URL".to_string())?;
    let host = u.host_str().ok_or("invalid OBX_SMTP_URL")?.to_string();
    let implicit = u.scheme() == "smtps";
    let port = u.port().unwrap_or(if implicit { 465 } else { 587 });
    let pd = |s: &str| {
        percent_encoding::percent_decode_str(s)
            .decode_utf8_lossy()
            .into_owned()
    };
    let user =
        (!u.username().is_empty()).then(|| (pd(u.username()), pd(u.password().unwrap_or(""))));
    let insecure = u.query_pairs().any(|(k, v)| k == "insecure" && v == "true");
    let server_name = rustls::pki_types::ServerName::try_from(host.clone())
        .map_err(|_| "invalid OBX_SMTP_URL host".to_string())?;
    let tcp = tokio::time::timeout(
        Duration::from_secs(20),
        tokio::net::TcpStream::connect((host.as_str(), port)),
    )
    .await
    .map_err(|_| "smtp connect: timed out".to_string())?
    .map_err(|e| format!("smtp connect: {e}"))?;
    let me = "localhost";
    if implicit {
        let tls = tls_connector()?
            .connect(server_name, tcp)
            .await
            .map_err(|e| format!("smtp tls: {e}"))?;
        let mut s = Smtp {
            r: BufReader::new(tls),
        };
        s.expect(220, "greeting").await?;
        s.ehlo(me).await?;
        return s.deliver(user, from, to, msg).await;
    }
    let mut s = Smtp {
        r: BufReader::new(tcp),
    };
    s.expect(220, "greeting").await?;
    let ext = s.ehlo(me).await?;
    let starttls = ext
        .iter()
        .any(|l| l.split_whitespace().next() == Some("STARTTLS"));
    if starttls {
        s.cmd("STARTTLS", 220, "STARTTLS").await?;
        let tcp = s.r.into_inner();
        let tls = tls_connector()?
            .connect(server_name, tcp)
            .await
            .map_err(|e| format!("smtp starttls: {e}"))?;
        let mut s = Smtp {
            r: BufReader::new(tls),
        };
        s.ehlo(me).await?;
        return s.deliver(user, from, to, msg).await;
    }
    if user.is_some() && !insecure && host != "localhost" && host != "127.0.0.1" {
        return Err("smtp server offers no STARTTLS; refusing to send credentials in clear text (add ?insecure=true for a local relay)".into());
    }
    s.deliver(user, from, to, msg).await
}

// ---- sending and the outbox -------------------------------------------------------

/// Renders the `email.<kind>` texts in lang and sends the message. A failure
/// is queued for retries. Returns whether a real e-mail was sent.
pub async fn send_mail(
    app: &App,
    to: &str,
    lang: &str,
    kind: &str,
    vars: &[(&str, String)],
) -> bool {
    if to.is_empty() {
        return false;
    }
    let s = match app.settings().await {
        Ok(s) => s,
        Err(_) => return false,
    };
    let (subject, body) = render(&s, lang, kind, vars);
    match app.mail.send(to, &subject, &body).await {
        Ok(()) => app.mail.configured(),
        Err(e) => {
            tracing::warn!(kind, error = %e, "e-mail could not be sent; it will be retried");
            queue(app, to, &subject, &body, kind, &e).await;
            false
        }
    }
}

/// Sends in the background (the request does not wait).
pub fn send_mail_later(
    app: &App,
    to: String,
    lang: String,
    kind: &'static str,
    vars: Vec<(&'static str, String)>,
) {
    let a = app.clone();
    tokio::spawn(async move {
        send_mail(&a, &to, &lang, kind, &vars).await;
    });
}

fn truncate(s: &str, n: usize) -> String {
    s.chars().take(n).collect()
}

fn after(secs: i64) -> String {
    db::fmt_time(chrono::Utc::now() + chrono::Duration::seconds(secs))
}

/// Stores a failed e-mail for retries. The body holds one-time links, so it
/// is encrypted and removed once sent or given up.
async fn queue(app: &App, to: &str, subject: &str, body: &str, kind: &str, cause: &str) {
    let enc = app.keys.encrypt(body.as_bytes());
    let (to, subject, kind, cause) = (
        to.to_string(),
        subject.to_string(),
        kind.to_string(),
        truncate(cause, 500),
    );
    let r = app
        .db
        .write(move |tx| {
            tx.execute(
                "INSERT INTO mail_outbox (id, recipient, subject, body_enc, kind, status, attempts, next_attempt_at, last_error, created_at) VALUES (?, ?, ?, ?, ?, 'pending', 1, ?, ?, ?)",
                params![crate::ids::new("mal"), to, subject, enc, kind, after(BACKOFF_SECS[0]), cause, db::now_str()],
            )?;
            Ok(())
        })
        .await;
    if let Err(e) = r {
        tracing::error!(error = %e, "e-mail could not be queued for a retry");
    }
}

/// Sends due e-mails from the outbox (housekeeping).
pub async fn retry_due(app: &App) {
    let due = app
        .db
        .read(|c| {
            let mut st = c.prepare("SELECT id, recipient, subject, body_enc, kind, attempts FROM mail_outbox WHERE status = 'pending' AND next_attempt_at <= ? ORDER BY next_attempt_at LIMIT 20")?;
            let rows = st
                .query_map([db::now_str()], |r| {
                    Ok((
                        r.get::<_, String>(0)?,
                        r.get::<_, String>(1)?,
                        r.get::<_, String>(2)?,
                        r.get::<_, String>(3)?,
                        r.get::<_, String>(4)?,
                        r.get::<_, i64>(5)?,
                    ))
                })?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            Ok(rows)
        })
        .await
        .unwrap_or_default();
    for (id, to, subject, enc, kind, attempts) in due {
        let res = match app
            .keys
            .decrypt(&enc)
            .and_then(|b| String::from_utf8(b).ok())
        {
            Some(body) => app.mail.send(&to, &subject, &body).await,
            None => Err("the stored body cannot be decrypted (another secret key?)".into()),
        };
        let a = attempts;
        let w = app
            .db
            .write(move |tx| {
                match res {
                    Ok(()) => {
                        tx.execute("UPDATE mail_outbox SET status = 'sent', body_enc = '', sent_at = ?, last_error = NULL WHERE id = ?", params![db::now_str(), id])?;
                        tracing::info!(kind, attempts = a + 1, "e-mail sent after a retry");
                    }
                    Err(e) if a as usize >= BACKOFF_SECS.len() => {
                        tx.execute("UPDATE mail_outbox SET status = 'failed', body_enc = '', attempts = attempts + 1, last_error = ? WHERE id = ?", params![truncate(&e, 500), id])?;
                        tracing::error!(kind, attempts = a + 1, error = %e, "e-mail given up after retries");
                    }
                    Err(e) => {
                        tx.execute("UPDATE mail_outbox SET attempts = attempts + 1, next_attempt_at = ?, last_error = ? WHERE id = ?", params![after(BACKOFF_SECS[a as usize]), truncate(&e, 500), id])?;
                    }
                }
                Ok(())
            })
            .await;
        if let Err(e) = w {
            tracing::warn!(error = %e, "mail outbox update failed");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn interpolate_swallows_double_stop() {
        let v: HashMap<String, String> =
            [("brand".to_string(), "MAISON NOOR B.V.".to_string())].into();
        assert_eq!(
            interpolate("Thanks, {{brand}}.", &v),
            "Thanks, MAISON NOOR B.V."
        );
        assert_eq!(
            interpolate("{brand} and {{ missing }}", &v),
            "MAISON NOOR B.V. and {{ missing }}"
        );
    }

    #[test]
    fn render_leaves_out_unfilled_lines() {
        let mut s = crate::settings::Settings::default();
        s.company.name = "MAISON NOOR".into();
        let (subj, body) = render(&s, "en", MAIL_ACCESS_REJECTED, &[("name", "Ada".into())]);
        assert_eq!(subj, "About your request for MAISON NOOR · Brand portal");
        assert!(body.starts_with("Hello Ada,\n\nUnfortunately MAISON NOOR cannot"));
        assert!(!body.contains("Explanation"));
        assert!(body.contains("\n\n-- \nYou receive this email"));
        let (_, body) = render(
            &s,
            "nl",
            MAIL_INVITE,
            &[
                ("url", "https://x/invite/t".into()),
                ("expires", "2026-12-01".into()),
            ],
        );
        assert!(body.starts_with("Hallo,\n\nMAISON NOOR heeft een account"));
        assert!(body.contains("Kies je wachtwoord:\nhttps://x/invite/t"));
        assert!(body.contains("2026-12-01"));
    }

    #[test]
    fn every_language_has_every_mail() {
        for l in crate::http::admin::UI_LANGS {
            for k in [
                MAIL_INVITE,
                MAIL_ACCESS_REQUEST_RECEIVED,
                MAIL_ACCESS_REQUEST_NEW,
                MAIL_ACCESS_APPROVED,
                MAIL_ACCESS_REJECTED,
                MAIL_ZIP_READY,
                MAIL_PASSWORD_RESET,
            ] {
                assert!(
                    !locale(l)
                        .get(&format!("email.{k}.subject"))
                        .cloned()
                        .unwrap_or_default()
                        .is_empty(),
                    "{l} {k}"
                );
            }
        }
    }

    #[test]
    fn message_headers_and_dot_stuffing() {
        let m = message("p@x.example", "r@y.example", "Toegang · klaar", "a\n.b\n");
        assert!(m.contains("Subject: =?utf-8?q?Toegang_=C2=B7_klaar?=\r\n"));
        assert!(m.contains("\r\n\r\na\r\n..b\r\n"));
        assert!(m.contains("@x.example>\r\n"));
        assert_eq!(q_encode("plain"), "plain");
    }

    /// A tiny SMTP server: no TLS, records the conversation.
    #[tokio::test]
    async fn smtp_conversation() {
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = l.local_addr().unwrap().port();
        let srv = tokio::spawn(async move {
            let (s, _) = l.accept().await.unwrap();
            let mut r = BufReader::new(s);
            r.get_mut().write_all(b"220 hi\r\n").await.unwrap();
            let mut log = String::new();
            let mut data = false;
            loop {
                let mut line = String::new();
                if r.read_line(&mut line).await.unwrap() == 0 {
                    break;
                }
                log.push_str(&line);
                if data {
                    if line == ".\r\n" {
                        data = false;
                        r.get_mut().write_all(b"250 ok\r\n").await.unwrap();
                    }
                    continue;
                }
                let reply: &[u8] = if line.starts_with("EHLO") {
                    b"250-hi\r\n250 AUTH PLAIN\r\n"
                } else if line.starts_with("AUTH") {
                    b"235 ok\r\n"
                } else if line.starts_with("DATA") {
                    data = true;
                    b"354 go\r\n"
                } else if line.starts_with("QUIT") {
                    r.get_mut().write_all(b"221 bye\r\n").await.unwrap();
                    break;
                } else {
                    b"250 ok\r\n"
                };
                r.get_mut().write_all(reply).await.unwrap();
            }
            log
        });
        let url = format!("smtp://u%40x:p+w@127.0.0.1:{port}");
        let msg = message("p@x.example", "r@y.example", "Hi", "body");
        smtp_send(&url, "p@x.example", "r@y.example", &msg)
            .await
            .unwrap();
        let log = srv.await.unwrap();
        use base64::Engine;
        let want = base64::engine::general_purpose::STANDARD.encode("\0u@x\0p+w");
        assert!(log.contains(&format!("AUTH PLAIN {want}")), "{log}");
        assert!(log.contains("MAIL FROM:<p@x.example>"));
        assert!(log.contains("RCPT TO:<r@y.example>"));
    }

    #[tokio::test]
    async fn smtp_refuses_cleartext_credentials() {
        let l = tokio::net::TcpListener::bind("127.0.0.2:0").await.unwrap();
        let port = l.local_addr().unwrap().port();
        tokio::spawn(async move {
            let (s, _) = l.accept().await.unwrap();
            let mut r = BufReader::new(s);
            r.get_mut().write_all(b"220 hi\r\n").await.unwrap();
            let mut line = String::new();
            r.read_line(&mut line).await.unwrap();
            r.get_mut().write_all(b"250 hi\r\n").await.unwrap();
            let _ = r.read_line(&mut line).await;
        });
        // Only localhost and 127.0.0.1 get credentials in the clear.
        let url = format!("smtp://u:p@127.0.0.2:{port}");
        let msg = message("p@x.example", "r@y.example", "Hi", "body");
        let e = smtp_send(&url, "p@x.example", "r@y.example", &msg)
            .await
            .unwrap_err();
        assert!(e.contains("STARTTLS"), "{e}");
    }
}
