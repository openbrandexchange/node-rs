//! Access tokens (`obxa_<payload>.<signature>`): self-contained, signed with
//! the `access-token` key, bound to the client's secret version so a
//! rotation ends every token issued before it.

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde::{Deserialize, Serialize};

use crate::Keys;

/// The prefix of every access token.
pub const PREFIX: &str = "obxa_";
/// The lifetime node-go and node-rs give an access token, in seconds.
pub const TTL_SECS: i64 = 3600;

#[derive(Serialize, Deserialize)]
struct Claims {
    c: String,
    v: i64,
    s: String,
    e: i64,
}

/// The claims of an access token.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccessToken {
    /// The API client's row id.
    pub client: String,
    /// The client's secret version when the token was issued.
    pub version: i64,
    /// The granted scopes.
    pub scopes: Vec<String>,
    /// Expiry, Unix seconds.
    pub expires: i64,
}

impl AccessToken {
    /// The token string.
    pub fn issue(&self, keys: &Keys) -> String {
        let payload = URL_SAFE_NO_PAD.encode(
            serde_json::to_vec(&Claims {
                c: self.client.clone(),
                v: self.version,
                s: self.scopes.join(" "),
                e: self.expires,
            })
            .expect("claims"),
        );
        format!("{PREFIX}{payload}.{}", keys.sign("access-token", &payload))
    }

    /// The claims of a token with a valid signature that has not expired at
    /// `now` (Unix seconds); None otherwise. The caller still checks that
    /// the client is active and its secret version matches.
    pub fn verify(keys: &Keys, token: &str, now: i64) -> Option<AccessToken> {
        let body = token.strip_prefix(PREFIX)?;
        let (payload, sig) = body.rsplit_once('.')?;
        if payload.is_empty() || !keys.verify("access-token", payload, sig) {
            return None;
        }
        let c: Claims = serde_json::from_slice(&URL_SAFE_NO_PAD.decode(payload).ok()?).ok()?;
        if c.e < now {
            return None;
        }
        Some(AccessToken {
            client: c.c,
            version: c.v,
            scopes: c.s.split_whitespace().map(String::from).collect(),
            expires: c.e,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn expired_and_tampered_tokens_fail() {
        let k = Keys::new(b"0123456789abcdef0123456789abcdef");
        let t = AccessToken {
            client: "cli_1".into(),
            version: 2,
            scopes: vec!["catalog:read".into(), "media:read".into()],
            expires: 100,
        };
        let s = t.issue(&k);
        assert_eq!(AccessToken::verify(&k, &s, 50), Some(t));
        assert!(AccessToken::verify(&k, &s, 101).is_none());
        let mut bad = s.clone();
        bad.insert(6, 'x');
        assert!(AccessToken::verify(&k, &bad, 50).is_none());
        assert!(AccessToken::verify(&k, "obxa_.", 50).is_none());
    }
}
