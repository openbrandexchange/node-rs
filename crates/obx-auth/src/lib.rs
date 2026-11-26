//! Secrets of an Open Brand Exchange node: random tokens and their hashes,
//! constant-time comparison, argon2id passwords, keys derived from one
//! master secret (HMAC signatures, AES-256-GCM encryption at rest), the
//! access-token format, OAuth2 client-credentials parsing and signed,
//! opaque cursors.
//!
//! Hashes, key derivation and the ciphertext format match the Go reference
//! node (node-go), so its data stays valid.
//!
//! ```
//! use obx_auth::{AccessToken, Keys};
//!
//! let keys = Keys::new(b"a master secret of at least 32 bytes!!");
//! let t = AccessToken { client: "cli_1".into(), version: 1, scopes: vec!["catalog:read".into()], expires: i64::MAX };
//! let s = t.issue(&keys);
//! assert_eq!(AccessToken::verify(&keys, &s, 0).unwrap().client, "cli_1");
//! assert!(AccessToken::verify(&Keys::new(b"another secret"), &s, 0).is_none());
//! ```
#![forbid(unsafe_code)]

pub mod cursor;
pub mod oauth;
pub mod token;

pub use cursor::CursorCodec;
pub use token::AccessToken;

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use argon2::{Algorithm, Argon2, Params, Version};
use base64::Engine;
use base64::engine::general_purpose::{STANDARD_NO_PAD, URL_SAFE_NO_PAD};
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};

type HmacSha256 = Hmac<Sha256>;

const ARGON_MEMORY: u32 = 19 * 1024;
const ARGON_TIME: u32 = 2;
const ARGON_THREADS: u32 = 1;
const ARGON_KEY_LEN: usize = 32;

/// Label prefix of every derived key. node-go's label, kept so signatures and
/// encrypted values written by node-go stay valid.
const KEY_LABEL: &str = "obx-node-go/";

pub fn random_string(n: usize) -> String {
    let b: Vec<u8> = (0..n).map(|_| rand::random::<u8>()).collect();
    URL_SAFE_NO_PAD.encode(b)
}

/// A secret with a recognisable prefix (`obxi_`, `obxs_`, ...).
pub fn token(prefix: &str) -> String {
    format!("{prefix}{}", random_string(32))
}

pub fn sha256_hex(b: &[u8]) -> String {
    hex::encode(Sha256::digest(b))
}

pub fn hash_token(t: &str) -> String {
    sha256_hex(t.as_bytes())
}

/// Constant-time comparison (the time depends only on the lengths).
pub fn eq(a: &str, b: &str) -> bool {
    use subtle::ConstantTimeEq;
    a.len() == b.len() && bool::from(a.as_bytes().ct_eq(b.as_bytes()))
}

fn argon(m: u32, t: u32, p: u32, len: usize) -> Argon2<'static> {
    Argon2::new(
        Algorithm::Argon2id,
        Version::V0x13,
        Params::new(m, t, p, Some(len)).expect("argon2 params"),
    )
}

pub fn hash_password(pw: &str) -> String {
    let salt: [u8; 16] = rand::random();
    let mut key = [0u8; ARGON_KEY_LEN];
    argon(ARGON_MEMORY, ARGON_TIME, ARGON_THREADS, ARGON_KEY_LEN)
        .hash_password_into(pw.as_bytes(), &salt, &mut key)
        .expect("argon2");
    format!(
        "$argon2id$v=19$m={ARGON_MEMORY},t={ARGON_TIME},p={ARGON_THREADS}${}${}",
        STANDARD_NO_PAD.encode(salt),
        STANDARD_NO_PAD.encode(key)
    )
}

pub fn check_password(hash: &str, pw: &str) -> bool {
    let parts: Vec<&str> = hash.split('$').collect();
    if parts.len() != 6 || parts[1] != "argon2id" {
        return false;
    }
    let mut m = 0;
    let mut t = 0;
    let mut p = 0;
    for kv in parts[3].split(',') {
        match kv.split_once('=') {
            Some(("m", v)) => m = v.parse().unwrap_or(0),
            Some(("t", v)) => t = v.parse().unwrap_or(0),
            Some(("p", v)) => p = v.parse().unwrap_or(0),
            _ => return false,
        }
    }
    let (Ok(salt), Ok(want)) = (
        STANDARD_NO_PAD.decode(parts[4]),
        STANDARD_NO_PAD.decode(parts[5]),
    ) else {
        return false;
    };
    if m == 0 || t == 0 || p == 0 || want.is_empty() {
        return false;
    }
    let Ok(params) = Params::new(m, t, p, Some(want.len())) else {
        return false;
    };
    let mut got = vec![0u8; want.len()];
    if Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
        .hash_password_into(pw.as_bytes(), &salt, &mut got)
        .is_err()
    {
        return false;
    }
    use subtle::ConstantTimeEq;
    bool::from(got.ct_eq(&want))
}

/// Spends the same time as a password check (unknown e-mail addresses).
pub fn dummy_password_check(pw: &str) {
    let mut key = [0u8; ARGON_KEY_LEN];
    let _ = argon(ARGON_MEMORY, ARGON_TIME, ARGON_THREADS, ARGON_KEY_LEN).hash_password_into(
        pw.as_bytes(),
        b"obx-dummy-salt!!",
        &mut key,
    );
}

const COMMON_PASSWORDS: &[&str] = &[
    "password1234",
    "1234567890",
    "12345678910",
    "qwertyuiop",
    "password123",
    "iloveyou12",
    "welcome123",
    "adminadmin",
    "administrator",
    "letmein123",
    "changeme123",
    "0123456789",
    "1q2w3e4r5t",
    "qwerty1234",
];

/// A reason the password is not acceptable, or None.
pub fn password_problem(pw: &str) -> Option<&'static str> {
    if pw.chars().count() < 10 {
        return Some("Use at least 10 characters.");
    }
    if pw.len() > 72 {
        return Some("Use at most 72 characters.");
    }
    if COMMON_PASSWORDS.contains(&pw.to_lowercase().as_str()) {
        return Some("This password is too common. Choose another one.");
    }
    None
}

/// Keys derived from one master secret: `HMAC-SHA256(master, label + purpose)`.
#[derive(Clone)]
pub struct Keys {
    master: Vec<u8>,
    label: String,
}

impl std::fmt::Debug for Keys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Keys(..)")
    }
}

impl Keys {
    /// Keys with node-go's derivation label (`obx-node-go/`).
    pub fn new(secret: &[u8]) -> Keys {
        Keys::with_label(secret, KEY_LABEL)
    }

    /// Keys with an own derivation label, for an implementation that never
    /// shares data with node-go.
    pub fn with_label(secret: &[u8], label: &str) -> Keys {
        Keys {
            master: secret.to_vec(),
            label: label.to_string(),
        }
    }

    fn derive(&self, purpose: &str) -> [u8; 32] {
        let mut m = <HmacSha256 as Mac>::new_from_slice(&self.master).expect("hmac key");
        m.update(self.label.as_bytes());
        m.update(purpose.as_bytes());
        m.finalize().into_bytes().into()
    }

    /// Lowercase hex HMAC-SHA256 of msg with the key for purpose.
    pub fn sign(&self, purpose: &str, msg: &str) -> String {
        let mut m = <HmacSha256 as Mac>::new_from_slice(&self.derive(purpose)).expect("hmac key");
        m.update(msg.as_bytes());
        hex::encode(m.finalize().into_bytes())
    }

    pub fn verify(&self, purpose: &str, msg: &str, sig: &str) -> bool {
        eq(&self.sign(purpose, msg), &sig.to_lowercase())
    }

    /// AES-256-GCM, `v1.` + base64url(nonce || ciphertext).
    pub fn encrypt(&self, plain: &[u8]) -> String {
        let c = Aes256Gcm::new_from_slice(&self.derive("encrypt")).expect("aes key");
        let nonce: [u8; 12] = rand::random();
        let mut out = nonce.to_vec();
        out.extend(
            c.encrypt(Nonce::from_slice(&nonce), plain)
                .expect("encrypt"),
        );
        format!("v1.{}", URL_SAFE_NO_PAD.encode(out))
    }

    pub fn decrypt(&self, s: &str) -> Option<Vec<u8>> {
        let raw = URL_SAFE_NO_PAD.decode(s.strip_prefix("v1.")?).ok()?;
        if raw.len() < 12 {
            return None;
        }
        let c = Aes256Gcm::new_from_slice(&self.derive("encrypt")).ok()?;
        c.decrypt(Nonce::from_slice(&raw[..12]), &raw[12..]).ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn password_round_trip() {
        let h = hash_password("correct horse battery");
        assert!(check_password(&h, "correct horse battery"));
        assert!(!check_password(&h, "wrong horse battery"));
    }

    #[test]
    fn encrypt_round_trip() {
        let k = Keys::new(b"0123456789abcdef0123456789abcdef");
        let c = k.encrypt(b"hello");
        assert_eq!(k.decrypt(&c).unwrap(), b"hello");
        assert!(
            Keys::new(b"another key another key another k")
                .decrypt(&c)
                .is_none()
        );
    }
}
