//! BN254 scalar field helpers (SPEC §1.2, §3.1).

use ark_ff::{BigInteger, PrimeField};

pub use ark_bn254::Fr;

/// Canonical 32-byte little-endian encoding.
pub fn fr_to_bytes(f: &Fr) -> [u8; 32] {
    let v = f.into_bigint().to_bytes_le();
    let mut out = [0u8; 32];
    out[..v.len()].copy_from_slice(&v);
    out
}

/// Decode a canonical encoding; `None` if the value is not `< r`.
pub fn fr_from_canonical(b: &[u8; 32]) -> Option<Fr> {
    let f = Fr::from_le_bytes_mod_order(b);
    (fr_to_bytes(&f) == *b).then_some(f)
}

/// `fr_mod(b) = int_le(b) mod r`.
pub fn fr_mod(b: &[u8; 32]) -> Fr {
    Fr::from_le_bytes_mod_order(b)
}

/// `tag_field(tag)`: little-endian integer of the ASCII bytes (SPEC §3.1).
pub fn tag_field(tag: &str) -> Fr {
    assert!(tag.len() <= 31, "tag must fit in a field element");
    Fr::from_le_bytes_mod_order(tag.as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tag_values_match_spec() {
        assert_eq!(tag_field("ballot"), Fr::from(128021909234018u64));
        assert_eq!(tag_field("support"), Fr::from(32776920251790707u64));
        assert_eq!(tag_field("author"), Fr::from(125822819399009u64));
        assert_eq!(tag_field("node"), Fr::from(1701080942u64));
        assert_eq!(tag_field("keyparty"), Fr::from(8751745738712114539u64));
    }

    #[test]
    fn canonical_roundtrip_and_rejection() {
        let f = Fr::from(7u64);
        let b = fr_to_bytes(&f);
        assert_eq!(b[0], 7);
        assert_eq!(fr_from_canonical(&b), Some(f));
        // r itself is not canonical
        let r_bytes: [u8; 32] = [
            0x01, 0x00, 0x00, 0xf0, 0x93, 0xf5, 0xe1, 0x43, 0x91, 0x70, 0xb9, 0x79, 0x48, 0xe8,
            0x33, 0x28, 0x5d, 0x58, 0x81, 0x81, 0xb6, 0x45, 0x50, 0xb8, 0x29, 0xa0, 0x31, 0xe1,
            0x72, 0x4e, 0x64, 0x30,
        ];
        assert!(fr_from_canonical(&r_bytes).is_none());
        assert_eq!(fr_mod(&r_bytes), Fr::from(0u64));
    }
}
