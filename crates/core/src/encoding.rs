//! Canonical encoding "CVE" (SPEC §2): little-endian fixed integers,
//! `u32`-length-prefixed byte strings and lists, `u8` enum discriminants,
//! no padding, no field tags.

use crate::constants::MAX_ITEM_BYTES;
use crate::error::DecodeError;
use cv_crypto::field::{Fr, fr_from_canonical, fr_to_bytes};

#[derive(Default)]
pub struct Writer {
    buf: Vec<u8>,
}

impl Writer {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn len(&self) -> usize {
        self.buf.len()
    }
    pub fn is_empty(&self) -> bool {
        self.buf.is_empty()
    }
    pub fn into_inner(self) -> Vec<u8> {
        self.buf
    }
    pub fn u8(&mut self, v: u8) {
        self.buf.push(v);
    }
    pub fn u32(&mut self, v: u32) {
        self.buf.extend_from_slice(&v.to_le_bytes());
    }
    pub fn u64(&mut self, v: u64) {
        self.buf.extend_from_slice(&v.to_le_bytes());
    }
    pub fn fixed(&mut self, v: &[u8]) {
        self.buf.extend_from_slice(v);
    }
    pub fn bytes(&mut self, v: &[u8]) {
        self.u32(v.len() as u32);
        self.buf.extend_from_slice(v);
    }
    pub fn string(&mut self, v: &str) {
        self.bytes(v.as_bytes());
    }
    pub fn list_len(&mut self, n: usize) {
        self.u32(n as u32);
    }
    pub fn fr(&mut self, f: &Fr) {
        self.buf.extend_from_slice(&fr_to_bytes(f));
    }
}

pub struct Reader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }
    pub fn position(&self) -> usize {
        self.pos
    }
    pub fn remaining(&self) -> usize {
        self.data.len() - self.pos
    }
    fn take(&mut self, n: usize) -> Result<&'a [u8], DecodeError> {
        if self.remaining() < n {
            return Err(DecodeError::Eof);
        }
        let s = &self.data[self.pos..self.pos + n];
        self.pos += n;
        Ok(s)
    }
    pub fn u8(&mut self) -> Result<u8, DecodeError> {
        Ok(self.take(1)?[0])
    }
    pub fn u32(&mut self) -> Result<u32, DecodeError> {
        Ok(u32::from_le_bytes(self.take(4)?.try_into().unwrap()))
    }
    pub fn u64(&mut self) -> Result<u64, DecodeError> {
        Ok(u64::from_le_bytes(self.take(8)?.try_into().unwrap()))
    }
    pub fn fixed<const N: usize>(&mut self) -> Result<[u8; N], DecodeError> {
        Ok(self.take(N)?.try_into().unwrap())
    }
    pub fn fixed_boxed<const N: usize>(&mut self) -> Result<Box<[u8; N]>, DecodeError> {
        Ok(Box::new(self.fixed::<N>()?))
    }
    /// Length-prefixed bytes, at most `max` long.
    pub fn bytes(&mut self, max: usize) -> Result<Vec<u8>, DecodeError> {
        let n = self.u32()? as usize;
        if n > max {
            return Err(DecodeError::TooLong(n, max));
        }
        Ok(self.take(n)?.to_vec())
    }
    pub fn string(&mut self, max: usize) -> Result<String, DecodeError> {
        let b = self.bytes(max)?;
        String::from_utf8(b).map_err(|_| DecodeError::Utf8)
    }
    /// A list count, bounded by `max` and by the bytes actually present
    /// (every element is at least one byte).
    pub fn list_len(&mut self, max: usize) -> Result<usize, DecodeError> {
        let n = self.u32()? as usize;
        if n > max {
            return Err(DecodeError::TooLong(n, max));
        }
        if n > self.remaining() {
            return Err(DecodeError::Eof);
        }
        Ok(n)
    }
    pub fn fr(&mut self) -> Result<Fr, DecodeError> {
        let b = self.fixed::<32>()?;
        fr_from_canonical(&b).ok_or(DecodeError::NonCanonicalField)
    }
    /// Must be called at the end: rejects trailing bytes.
    pub fn finish(self) -> Result<(), DecodeError> {
        if self.remaining() == 0 {
            Ok(())
        } else {
            Err(DecodeError::Trailing)
        }
    }
}

/// Upper bound used for any `bytes` field without a tighter limit.
pub const MAX_BYTES_FIELD: usize = MAX_ITEM_BYTES;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn primitives_roundtrip() {
        let mut w = Writer::new();
        w.u8(7);
        w.u32(0x0d_bb_a0);
        w.u64(1000);
        w.bytes(b"hi");
        w.string("Yes");
        w.fr(&Fr::from(7u64));
        let b = w.into_inner();
        let mut r = Reader::new(&b);
        assert_eq!(r.u8().unwrap(), 7);
        assert_eq!(r.u32().unwrap(), 0x0d_bb_a0);
        assert_eq!(r.u64().unwrap(), 1000);
        assert_eq!(r.bytes(10).unwrap(), b"hi");
        assert_eq!(r.string(10).unwrap(), "Yes");
        assert_eq!(r.fr().unwrap(), Fr::from(7u64));
        r.finish().unwrap();
    }

    #[test]
    fn rejections() {
        let mut r = Reader::new(&[1, 2]);
        assert_eq!(r.u32(), Err(DecodeError::Eof));
        let mut r = Reader::new(&[3, 0, 0, 0, 0xff, 0xfe, 0xfd]);
        assert_eq!(r.string(10), Err(DecodeError::Utf8));
        let mut r = Reader::new(&[3, 0, 0, 0, b'a', b'b', b'c']);
        assert_eq!(r.bytes(2), Err(DecodeError::TooLong(3, 2)));
        let r = Reader::new(&[0]);
        assert_eq!(r.finish(), Err(DecodeError::Trailing));
        let mut r = Reader::new(&[0xff, 0xff, 0xff, 0xff]);
        assert_eq!(
            r.list_len(1 << 20),
            Err(DecodeError::TooLong(0xffff_ffff, 1 << 20))
        );
    }
}
