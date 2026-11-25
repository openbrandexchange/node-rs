//! Object ids: a prefix and a ULID-like 26-character Crockford base32 value
//! (48-bit milliseconds, 80 bits of randomness, monotonic within a
//! millisecond), the same shape node-go used.

use std::sync::Mutex;

const ALPHABET: &[u8; 32] = b"0123456789abcdefghjkmnpqrstvwxyz";

static LAST: Mutex<(u64, [u8; 10])> = Mutex::new((0, [0; 10]));

pub fn new(prefix: &str) -> String {
    let now = chrono::Utc::now().timestamp_millis() as u64;
    let (ms, r) = {
        let mut last = LAST.lock().unwrap();
        if now <= last.0 {
            let mut r = last.1;
            for i in (0..r.len()).rev() {
                r[i] = r[i].wrapping_add(1);
                if r[i] != 0 {
                    break;
                }
            }
            last.1 = r;
            (last.0, r)
        } else {
            let r: [u8; 10] = rand::random();
            *last = (now, r);
            (now, r)
        }
    };
    let mut b = [0u8; 16];
    b[..6].copy_from_slice(&ms.to_be_bytes()[2..]);
    b[6..].copy_from_slice(&r);
    format!("{prefix}_{}", encode(&b))
}

fn encode(b: &[u8; 16]) -> String {
    let v = u128::from_be_bytes(*b);
    let mut out = [0u8; 26];
    for (i, o) in out.iter_mut().enumerate() {
        let shift = 5 * (25 - i);
        *o = ALPHABET[((v >> shift) & 31) as usize];
    }
    String::from_utf8(out.to_vec()).unwrap()
}

#[cfg(test)]
mod tests {
    #[test]
    fn ids_are_ordered_and_unique() {
        let a = super::new("prd");
        let b = super::new("prd");
        assert!(a < b, "{a} < {b}");
        assert_eq!(a.len(), 4 + 26);
    }
}
