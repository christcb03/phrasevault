//! PVFS Canonical Encoding (PCE) — spec §3.
//!
//! One logical value has exactly one valid byte sequence:
//! - u64: 8 bytes little-endian
//! - bool: 0x00 / 0x01
//! - bytes: u32 LE length prefix + raw bytes
//! - string: UTF-8 encoded as bytes
//! - option<T>: 0x00 none | 0x01 + T
//!
//! No maps, no padding, fixed field order per composite.

use crate::error::{PvfsError, Result};

/// Canonical encoder.
#[derive(Default)]
pub struct Enc {
    buf: Vec<u8>,
}

impl Enc {
    pub fn new() -> Self {
        Enc { buf: Vec::new() }
    }

    pub fn u64(&mut self, v: u64) -> &mut Self {
        self.buf.extend_from_slice(&v.to_le_bytes());
        self
    }

    pub fn boolean(&mut self, v: bool) -> &mut Self {
        self.buf.push(if v { 0x01 } else { 0x00 });
        self
    }

    pub fn bytes(&mut self, v: &[u8]) -> &mut Self {
        // Hard cap is the u32 prefix itself (spec §3); usize on 64-bit can exceed it.
        debug_assert!(v.len() <= u32::MAX as usize);
        let len = v.len().min(u32::MAX as usize) as u32;
        self.buf.extend_from_slice(&len.to_le_bytes());
        self.buf.extend_from_slice(&v[..len as usize]);
        self
    }

    pub fn string(&mut self, v: &str) -> &mut Self {
        self.bytes(v.as_bytes())
    }

    pub fn opt_string(&mut self, v: Option<&str>) -> &mut Self {
        match v {
            None => {
                self.buf.push(0x00);
            }
            Some(s) => {
                self.buf.push(0x01);
                self.string(s);
            }
        }
        self
    }

    pub fn finish(self) -> Vec<u8> {
        self.buf
    }
}

/// Canonical decoder. Reports field + byte offset on failure (§13.3).
pub struct Dec<'a> {
    data: &'a [u8],
    pos: usize,
    what: &'a str,
}

impl<'a> Dec<'a> {
    pub fn new(data: &'a [u8], what: &'a str) -> Self {
        Dec { data, pos: 0, what }
    }

    fn err(&self, detail: &str) -> PvfsError {
        PvfsError::Encoding {
            what: self.what.to_string(),
            offset: self.pos,
            detail: detail.to_string(),
        }
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        if self.pos + n > self.data.len() {
            return Err(self.err(&format!(
                "needed {n} bytes, only {} remain",
                self.data.len() - self.pos
            )));
        }
        let s = &self.data[self.pos..self.pos + n];
        self.pos += n;
        Ok(s)
    }

    pub fn u64(&mut self) -> Result<u64> {
        let b = self.take(8)?;
        let mut a = [0u8; 8];
        a.copy_from_slice(b);
        Ok(u64::from_le_bytes(a))
    }

    pub fn boolean(&mut self) -> Result<bool> {
        let b = self.take(1)?;
        match b[0] {
            0x00 => Ok(false),
            0x01 => Ok(true),
            other => Err(self.err(&format!("invalid bool byte 0x{other:02x}"))),
        }
    }

    pub fn bytes(&mut self) -> Result<Vec<u8>> {
        let lb = self.take(4)?;
        let mut a = [0u8; 4];
        a.copy_from_slice(lb);
        let len = u32::from_le_bytes(a) as usize;
        Ok(self.take(len)?.to_vec())
    }

    pub fn string(&mut self) -> Result<String> {
        let start = self.pos;
        let raw = self.bytes()?;
        String::from_utf8(raw).map_err(|e| PvfsError::Encoding {
            what: self.what.to_string(),
            offset: start,
            detail: format!("invalid UTF-8: {e}"),
        })
    }

    pub fn opt_string(&mut self) -> Result<Option<String>> {
        let tag = self.take(1)?;
        match tag[0] {
            0x00 => Ok(None),
            0x01 => Ok(Some(self.string()?)),
            other => Err(self.err(&format!("invalid option tag 0x{other:02x}"))),
        }
    }

    /// Bytes not yet consumed — lets a decoder accept an optional trailing
    /// field added by a later version (e.g. `AclSet.expires_at`, doc 13 Q-E1).
    pub fn remaining(&self) -> usize {
        self.data.len() - self.pos
    }

    /// Assert the input is fully consumed (canonical: no trailing bytes).
    pub fn finish(self) -> Result<()> {
        if self.pos != self.data.len() {
            return Err(PvfsError::Encoding {
                what: self.what.to_string(),
                offset: self.pos,
                detail: format!("{} trailing bytes", self.data.len() - self.pos),
            });
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn primitives_roundtrip_and_are_byte_stable() {
        let mut e = Enc::new();
        e.u64(7)
            .boolean(true)
            .bytes(b"ab")
            .string("hé")
            .opt_string(None)
            .opt_string(Some("x"));
        let b1 = e.finish();

        let mut e2 = Enc::new();
        e2.u64(7)
            .boolean(true)
            .bytes(b"ab")
            .string("hé")
            .opt_string(None)
            .opt_string(Some("x"));
        assert_eq!(b1, e2.finish(), "encoding must be deterministic");

        let mut d = Dec::new(&b1, "test");
        assert_eq!(d.u64().unwrap(), 7);
        assert!(d.boolean().unwrap());
        assert_eq!(d.bytes().unwrap(), b"ab");
        assert_eq!(d.string().unwrap(), "hé");
        assert_eq!(d.opt_string().unwrap(), None);
        assert_eq!(d.opt_string().unwrap(), Some("x".to_string()));
        d.finish().unwrap();
    }

    #[test]
    fn known_bytes() {
        let mut e = Enc::new();
        e.u64(1).boolean(false).string("A");
        assert_eq!(
            e.finish(),
            vec![1, 0, 0, 0, 0, 0, 0, 0, 0x00, 1, 0, 0, 0, b'A']
        );
    }

    #[test]
    fn decode_errors_carry_offset() {
        // truncated u64
        let d = Dec::new(&[1, 2, 3], "t").u64();
        match d {
            Err(PvfsError::Encoding { offset, .. }) => assert_eq!(offset, 0),
            other => panic!("expected Encoding error, got {other:?}"),
        }
        // trailing garbage
        let buf = {
            let mut e = Enc::new();
            e.u64(1);
            let mut v = e.finish();
            v.push(0xFF);
            v
        };
        let mut d = Dec::new(&buf, "t");
        d.u64().unwrap();
        assert!(d.finish().is_err());
    }
}
