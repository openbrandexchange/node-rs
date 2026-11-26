//! Opaque, signed cursors: `base64url(json).<sig>`, where the signature is
//! the first 32 hex digits of HMAC(`cursor/<kind>/<node>`, payload). A
//! cursor cannot be forged, moved to another list or to another node.

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde::{Serialize, de::DeserializeOwned};

use crate::Keys;

/// The longest cursor accepted.
pub const MAX_LEN: usize = 4096;

/// Encodes and decodes the cursors of one node.
#[derive(Clone, Debug)]
pub struct CursorCodec {
    keys: Keys,
    node_id: String,
}

impl CursorCodec {
    pub fn new(keys: Keys, node_id: impl Into<String>) -> CursorCodec {
        CursorCodec {
            keys,
            node_id: node_id.into(),
        }
    }

    fn sig(&self, kind: &str, payload: &str) -> String {
        self.keys
            .sign(&format!("cursor/{kind}/{}", self.node_id), payload)[..32]
            .to_string()
    }

    pub fn encode<T: Serialize>(&self, kind: &str, v: &T) -> String {
        let payload = URL_SAFE_NO_PAD.encode(serde_json::to_vec(v).expect("cursor"));
        let sig = self.sig(kind, &payload);
        format!("{payload}.{sig}")
    }

    /// None for a cursor that is malformed, too long or signed for another
    /// kind or node.
    pub fn decode<T: DeserializeOwned>(&self, kind: &str, c: &str) -> Option<T> {
        if c.len() > MAX_LEN {
            return None;
        }
        let (payload, sig) = c.rsplit_once('.')?;
        if payload.is_empty() || !crate::eq(sig, &self.sig(kind, payload)) {
            return None;
        }
        serde_json::from_slice(&URL_SAFE_NO_PAD.decode(payload).ok()?).ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bound_to_kind_and_node() {
        let k = Keys::new(b"0123456789abcdef0123456789abcdef");
        let a = CursorCodec::new(k.clone(), "nod_a");
        let c = a.encode("products", &serde_json::json!({"o": 5}));
        let v: serde_json::Value = a.decode("products", &c).unwrap();
        assert_eq!(v["o"], 5);
        assert!(a.decode::<serde_json::Value>("changes", &c).is_none());
        assert!(
            CursorCodec::new(k, "nod_b")
                .decode::<serde_json::Value>("products", &c)
                .is_none()
        );
    }
}
