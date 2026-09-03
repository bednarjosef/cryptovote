//! Exponent EC-ElGamal on Ristretto255 (SPEC §1.7, §11).

use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT as G;
use curve25519_dalek::ristretto::CompressedRistretto;
pub use curve25519_dalek::{RistrettoPoint, Scalar};
use rand::RngCore;

pub fn scalar_from_bytes(b: &[u8; 32]) -> Option<Scalar> {
    Option::from(Scalar::from_canonical_bytes(*b))
}

pub fn scalar_wide(b: &[u8; 64]) -> Scalar {
    Scalar::from_bytes_mod_order_wide(b)
}

pub fn scalar_to_bytes(s: &Scalar) -> [u8; 32] {
    s.to_bytes()
}

pub fn point_from_bytes(b: &[u8; 32]) -> Option<RistrettoPoint> {
    CompressedRistretto::from_slice(b).ok()?.decompress()
}

pub fn point_to_bytes(p: &RistrettoPoint) -> [u8; 32] {
    p.compress().to_bytes()
}

pub fn random_scalar<R: RngCore>(rng: &mut R) -> Scalar {
    let mut wide = [0u8; 64];
    rng.fill_bytes(&mut wide);
    scalar_wide(&wide)
}

/// `(sk, pk = sk · G)`.
pub fn keygen<R: RngCore>(rng: &mut R) -> (Scalar, RistrettoPoint) {
    let sk = random_scalar(rng);
    (sk, sk * G)
}

pub fn public_key(sk: &Scalar) -> RistrettoPoint {
    sk * G
}

/// `PK = Σ pk_i` (identity for an empty set).
pub fn aggregate(pks: &[RistrettoPoint]) -> RistrettoPoint {
    pks.iter().fold(RistrettoPoint::default(), |acc, p| acc + p)
}

/// `(c1, c2) = (r·G, m·G + r·PK)`.
pub fn encrypt(pk: &RistrettoPoint, m: u64, r: &Scalar) -> (RistrettoPoint, RistrettoPoint) {
    (r * G, Scalar::from(m) * G + r * pk)
}

/// `M = c2 − SK·c1`; returns `m < max` with `m·G == M`, else `None`.
pub fn decrypt(
    sk_sum: &Scalar,
    c1: &RistrettoPoint,
    c2: &RistrettoPoint,
    max: usize,
) -> Option<usize> {
    let m_point = c2 - sk_sum * c1;
    let mut acc = RistrettoPoint::default();
    for m in 0..max {
        if acc == m_point {
            return Some(m);
        }
        acc += G;
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::SeedableRng;

    #[test]
    fn aggregate_keys_roundtrip() {
        let mut rng = rand_chacha::ChaCha20Rng::from_seed([1u8; 32]);
        let parties: Vec<(Scalar, RistrettoPoint)> = (0..3).map(|_| keygen(&mut rng)).collect();
        let pk = aggregate(&parties.iter().map(|p| p.1).collect::<Vec<_>>());
        let r = random_scalar(&mut rng);
        let (c1, c2) = encrypt(&pk, 5, &r);
        let sk_sum: Scalar = parties.iter().map(|p| p.0).sum();
        assert_eq!(decrypt(&sk_sum, &c1, &c2, 64), Some(5));
        assert_eq!(decrypt(&sk_sum, &c1, &c2, 5), None, "out of range");
        assert_eq!(
            decrypt(&parties[0].0, &c1, &c2, 64),
            None,
            "one share is not enough"
        );
        // Deterministic randomness → identical ciphertext.
        assert_eq!(encrypt(&pk, 5, &r), (c1, c2));
        // Serialization.
        let b = point_to_bytes(&c1);
        assert_eq!(point_from_bytes(&b), Some(c1));
        assert!(point_from_bytes(&[0xffu8; 32]).is_none());
        assert!(scalar_from_bytes(&[0xffu8; 32]).is_none());
        // Empty party set: identity key, plaintext-equivalent.
        let (c1, c2) = encrypt(&aggregate(&[]), 3, &r);
        assert_eq!(decrypt(&Scalar::ZERO, &c1, &c2, 64), Some(3));
    }
}
