//! BLAKE3 wrappers (SPEC §1.1, §3.2).

/// Context prefix for every `derive_key` use in the protocol.
pub const CONTEXT_PREFIX: &str = "cryptovote/v1/";

/// Plain 32-byte BLAKE3 hash.
pub fn blake3_hash(data: &[u8]) -> [u8; 32] {
    *blake3::hash(data).as_bytes()
}

/// Streaming plain hash over several slices (no length framing; callers pass
/// already-canonical bytes).
pub fn blake3_concat(parts: &[&[u8]]) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    for p in parts {
        h.update(p);
    }
    *h.finalize().as_bytes()
}

/// `H_B(tag; data) = blake3::derive_key("cryptovote/v1/" || tag, data)`.
pub fn tagged(tag: &str, data: &[u8]) -> [u8; 32] {
    blake3::derive_key(&format!("{CONTEXT_PREFIX}{tag}"), data)
}

/// `H_B64(tag; data)`: first 64 bytes of the `derive_key` XOF.
pub fn tagged64(tag: &str, data: &[u8]) -> [u8; 64] {
    let mut h = blake3::Hasher::new_derive_key(&format!("{CONTEXT_PREFIX}{tag}"));
    h.update(data);
    let mut out = [0u8; 64];
    h.finalize_xof().fill(&mut out);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tagged64_prefix_is_tagged() {
        let a = tagged("rand", b"xyz");
        let b = tagged64("rand", b"xyz");
        assert_eq!(&b[..32], &a[..]);
    }
}
