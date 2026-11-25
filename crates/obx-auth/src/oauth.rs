//! OAuth2 client credentials (RFC 6749 §4.4) as the OBX token endpoint
//! accepts them: HTTP Basic (with the form-encoding of §2.3.1) or
//! `client_id`/`client_secret` in the form body.

use base64::Engine;
use std::collections::HashMap;

/// The client id and secret of a token request, None when neither form is
/// present or one of them is empty.
pub fn client_credentials(
    authorization: Option<&str>,
    form: &HashMap<String, String>,
) -> Option<(String, String)> {
    let (mut id, mut secret) = (String::new(), String::new());
    if let Some(v) = authorization
        && v.len() > 6
        && v[..6].eq_ignore_ascii_case("basic ")
        && let Some(dec) = base64::engine::general_purpose::STANDARD
            .decode(v[6..].trim())
            .ok()
            .and_then(|b| String::from_utf8(b).ok())
        && let Some((a, b)) = dec.split_once(':')
    {
        id = form_decode(a);
        secret = form_decode(b);
    }
    if id.is_empty() {
        id = form.get("client_id").cloned().unwrap_or_default();
        secret = form.get("client_secret").cloned().unwrap_or_default();
    }
    (!id.is_empty() && !secret.is_empty()).then_some((id, secret))
}

/// application/x-www-form-urlencoded decoding of one value; a literal `+`
/// in Basic credentials is kept (clients rarely encode it).
fn form_decode(s: &str) -> String {
    url::form_urlencoded::parse(format!("x={}", s.replace('+', "%2B")).as_bytes())
        .next()
        .map(|(_, v)| v.into_owned())
        .unwrap_or_default()
}

/// The form fields of a token request body.
pub fn parse_form(body: &[u8]) -> HashMap<String, String> {
    url::form_urlencoded::parse(body).into_owned().collect()
}

/// The RFC 6749 §5.2 error body.
pub fn error_body(code: &str, description: &str) -> serde_json::Value {
    serde_json::json!({"error": code, "error_description": description})
}

/// The scopes to grant: all `available` ones when `requested` is blank,
/// otherwise exactly the requested ones (sorted); Err names the first
/// requested scope that is not available.
pub fn grant_scopes(requested: &str, available: &[String]) -> Result<Vec<String>, String> {
    let mut out: Vec<String> = if requested.trim().is_empty() {
        available.to_vec()
    } else {
        let mut v = Vec::new();
        for x in requested.split_whitespace() {
            if !available.iter().any(|a| a == x) {
                return Err(x.to_string());
            }
            v.push(x.to_string());
        }
        v
    };
    out.sort();
    out.dedup();
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn basic_and_post() {
        let b = base64::engine::general_purpose::STANDARD.encode("obxc_a:s%3Ae+t");
        let got = client_credentials(Some(&format!("Basic {b}")), &HashMap::new());
        assert_eq!(got, Some(("obxc_a".into(), "s:e+t".into())));
        let mut f = HashMap::new();
        f.insert("client_id".to_string(), "x".to_string());
        assert_eq!(client_credentials(None, &f), None);
        f.insert("client_secret".to_string(), "y".to_string());
        assert_eq!(client_credentials(None, &f), Some(("x".into(), "y".into())));
    }

    #[test]
    fn scopes() {
        let av = vec!["catalog:read".to_string(), "media:read".to_string()];
        assert_eq!(grant_scopes(" ", &av).unwrap(), av);
        assert_eq!(grant_scopes("media:read", &av).unwrap(), vec!["media:read"]);
        assert_eq!(
            grant_scopes("media:original", &av).unwrap_err(),
            "media:original"
        );
    }
}
