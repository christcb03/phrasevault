//! Base62 fractional sibling-order keys — spec §5.3.
//!
//! Keys are opaque sortable ASCII strings over the fixed alphabet
//! `0-9 A-Z a-z` (which sorts correctly bytewise). Invariant: generated keys
//! never end in `0` (the smallest digit), which guarantees a key can always
//! be generated strictly between any two existing keys.

use crate::error::{PvfsError, Result};

const ALPHABET: &[u8; 62] = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
const BASE: usize = 62;

fn digit_index(c: u8) -> Option<usize> {
    ALPHABET.iter().position(|&a| a == c)
}

fn digit_at(s: &str, i: usize) -> usize {
    s.as_bytes()
        .get(i)
        .and_then(|&c| digit_index(c))
        .unwrap_or(0)
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct OrderKey(String);

impl OrderKey {
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Validate an externally supplied key: non-empty, alphabet-only,
    /// no trailing '0'.
    pub fn parse(s: &str) -> Result<OrderKey> {
        if s.is_empty() {
            return Err(bad("order_key", "must not be empty"));
        }
        if let Some(c) = s.bytes().find(|c| digit_index(*c).is_none()) {
            return Err(bad(
                "order_key",
                &format!("invalid character 0x{c:02x} (base62 only)"),
            ));
        }
        if s.ends_with('0') {
            return Err(bad("order_key", "must not end in '0'"));
        }
        Ok(OrderKey(s.to_string()))
    }

    /// The midpoint key for an empty sibling list.
    pub fn middle() -> OrderKey {
        OrderKey("U".to_string())
    }

    /// A key strictly between `a` and `b` (lexicographically).
    /// `a = None` means the lower bound; `b = None` means the upper bound.
    pub fn between(a: Option<&OrderKey>, b: Option<&OrderKey>) -> Result<OrderKey> {
        let a_str = a.map(|k| k.0.as_str()).unwrap_or("");
        if let Some(b) = b {
            if a_str >= b.0.as_str() {
                return Err(bad(
                    "order_key",
                    &format!("between() requires a < b (got {a_str:?} >= {:?})", b.0),
                ));
            }
        }
        let mut out = String::new();
        let mut i = 0usize;
        let mut upper_unbounded = b.is_none();
        let b_str = b.map(|k| k.0.as_str()).unwrap_or("");
        loop {
            let da = digit_at(a_str, i);
            let db = if upper_unbounded {
                BASE
            } else {
                digit_at(b_str, i)
            };
            if da == db {
                out.push(ALPHABET[da] as char);
                i += 1;
                continue;
            }
            if db - da > 1 {
                out.push(ALPHABET[(da + db) / 2] as char);
                return Ok(OrderKey(out));
            }
            // db == da + 1: commit da, then find something > a[i+1..]
            out.push(ALPHABET[da] as char);
            i += 1;
            loop {
                let dn = digit_at(a_str, i);
                if dn >= BASE - 1 {
                    out.push(ALPHABET[dn] as char);
                    i += 1;
                } else {
                    out.push(ALPHABET[(dn + BASE + 1) / 2] as char);
                    return Ok(OrderKey(out));
                }
            }
        }
    }

    /// A key after the current maximum (append-at-end).
    pub fn after(max: Option<&OrderKey>) -> Result<OrderKey> {
        match max {
            None => Ok(OrderKey::middle()),
            Some(m) => OrderKey::between(Some(m), None),
        }
    }
}

impl std::fmt::Display for OrderKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

fn bad(field: &str, reason: &str) -> PvfsError {
    PvfsError::BadInput {
        field: field.to_string(),
        reason: reason.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn k(s: &str) -> OrderKey {
        OrderKey::parse(s).unwrap()
    }

    #[test]
    fn middle_and_after() {
        assert_eq!(OrderKey::after(None).unwrap().as_str(), "U");
        let a = OrderKey::after(Some(&k("U"))).unwrap();
        assert!(a.as_str() > "U");
        let b = OrderKey::after(Some(&a)).unwrap();
        assert!(b.as_str() > a.as_str());
    }

    #[test]
    fn between_properties() {
        let cases = [
            ("", "U"),
            ("4", "5"),
            ("4z", "5"),
            ("4", "40V"),
            ("U", "V"),
            ("Uz", "V"),
            ("A", "z"),
            ("4zz", "5"),
        ];
        for (a, b) in cases {
            let lo = if a.is_empty() { None } else { Some(k(a)) };
            let m = OrderKey::between(lo.as_ref(), Some(&k(b))).unwrap();
            assert!(
                (a.is_empty() || m.as_str() > a) && m.as_str() < b,
                "{a:?} < {m} < {b:?} violated"
            );
            assert!(!m.as_str().ends_with('0'), "{m} ends in 0");
        }
    }

    #[test]
    fn between_many_iterations_stays_ordered() {
        // repeatedly bisect the same gap — keys grow but stay strictly ordered
        let mut lo = k("A");
        let hi = k("B");
        for _ in 0..50 {
            let m = OrderKey::between(Some(&lo), Some(&hi)).unwrap();
            assert!(m.as_str() > lo.as_str() && m.as_str() < hi.as_str());
            lo = m;
        }
    }

    #[test]
    fn validation() {
        assert!(OrderKey::parse("").is_err());
        assert!(OrderKey::parse("a 1").is_err());
        assert!(OrderKey::parse("a0").is_err());
        assert!(OrderKey::parse("U").is_ok());
    }

    #[test]
    fn equal_inputs_rejected() {
        assert!(OrderKey::between(Some(&k("U")), Some(&k("U"))).is_err());
        assert!(OrderKey::between(Some(&k("V")), Some(&k("U"))).is_err());
    }
}
