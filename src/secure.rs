//! Passwords, tokens, signatures and encryption at rest. Hashes, key
//! derivation and the ciphertext format match node-go, so a node-go data
//! directory keeps working.

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

pub fn eq(a: &str, b: &str) -> bool {
    let (a, b) = (a.as_bytes(), b.as_bytes());
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b).fold(0u8, |d, (x, y)| d | (x ^ y)) == 0
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
    got.iter().zip(&want).fold(0u8, |d, (x, y)| d | (x ^ y)) == 0
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

#[derive(Clone)]
pub struct Keys {
    master: Vec<u8>,
}

impl Keys {
    pub fn new(secret: &[u8]) -> Keys {
        Keys {
            master: secret.to_vec(),
        }
    }

    fn derive(&self, purpose: &str) -> [u8; 32] {
        let mut m = <HmacSha256 as Mac>::new_from_slice(&self.master).expect("hmac key");
        m.update(KEY_LABEL.as_bytes());
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

/// `v1=<hex>` signature of a webhook delivery (protocol.md §9).
#[allow(dead_code)] // webhooks are on the roadmap; the signature is tested
pub fn webhook_signature(secret: &str, timestamp: &str, body: &[u8]) -> String {
    let mut m = <HmacSha256 as Mac>::new_from_slice(secret.as_bytes()).expect("hmac key");
    m.update(timestamp.as_bytes());
    m.update(b".");
    m.update(body);
    format!("v1={}", hex::encode(m.finalize().into_bytes()))
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

    #[test]
    fn webhook_vector() {
        let v: serde_json::Value = serde_json::from_str(include_str!(
            "../spec/fixtures/examples/webhook-signature-vector.json"
        ))
        .unwrap();
        let sig = webhook_signature(
            v["secret"].as_str().unwrap(),
            v["timestamp"].as_str().unwrap(),
            v["raw_body"].as_str().unwrap().as_bytes(),
        );
        assert_eq!(sig, v["header"].as_str().unwrap());
    }
}
