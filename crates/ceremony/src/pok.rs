//! The two checks the whole ceremony is built from (SPEC §18.2).
//!
//! Every step of the ceremony multiplies parameters by a secret the
//! contributor chose. Two things must be shown about such a step, and both
//! reduce to pairings:
//!
//! * **`same_ratio`** — that two group elements stand in the same ratio as
//!   two others. `e(a₀, b₁) = e(a₁, b₀)` holds exactly when `a₁/a₀ = b₁/b₀`
//!   as exponents, so a pairing compares an exponent nobody knows against
//!   another exponent nobody knows.
//! * **`Pok`** — that the contributor *knew* the exponent it applied, rather
//!   than deriving its elements from someone else's. Without it a contributor
//!   could replay a previous participant's contribution and appear to have
//!   added entropy while adding none.
//!
//! The point `r` a `Pok` is taken against comes from the challenge — the
//! digest of everything contributed so far — so it cannot be known before the
//! previous step is published.

use ark_bn254::{Bn254, Fr, G1Affine, G1Projective, G2Affine, G2Projective};
use ark_ec::pairing::Pairing;
use ark_ec::{AffineRepr, CurveGroup, VariableBaseMSM};
use ark_ff::UniformRand;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use rand::{CryptoRng, RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;

/// Domain separators, so a proof for one secret is not a proof for another.
pub const TAU: u8 = 0;
pub const ALPHA: u8 = 1;
pub const BETA: u8 = 2;
pub const DELTA: u8 = 3;

/// `e(a.0, b.1) == e(a.1, b.0)`: "`a.1/a.0` and `b.1/b.0` are the same
/// exponent". A zero denominator makes the claim vacuous, so it is rejected.
pub fn same_ratio(a: (G1Affine, G1Affine), b: (G2Affine, G2Affine)) -> bool {
    if a.0.is_zero() || b.0.is_zero() {
        return false;
    }
    Bn254::pairing(a.0, b.1) == Bn254::pairing(a.1, b.0)
}

/// A G2 point determined by a digest and nothing else: the random oracle of
/// §18.2. Nobody knows its discrete logarithm, and nobody can predict it
/// before the digest exists.
pub fn point_from_digest(digest: &[u8; 32], purpose: u8) -> G2Affine {
    let mut h = blake3::Hasher::new_derive_key("cryptovote/v1/ceremony/point");
    h.update(digest);
    h.update(&[purpose]);
    let seed: [u8; 32] = *h.finalize().as_bytes();
    G2Projective::rand(&mut ChaCha20Rng::from_seed(seed)).into_affine()
}

/// Scalars for a batched check, derived from a digest of everything being
/// checked. They must not be predictable while the response is still being
/// written, or a contributor could aim a bad vector at a known combination —
/// hence the digest of the *response*, not of the challenge.
pub fn batch_scalars(digest: &[u8; 32], purpose: u8, n: usize) -> Vec<Fr> {
    let mut h = blake3::Hasher::new_derive_key("cryptovote/v1/ceremony/batch");
    h.update(digest);
    h.update(&[purpose]);
    let mut rng = ChaCha20Rng::from_seed(*h.finalize().as_bytes());
    (0..n).map(|_| Fr::rand(&mut rng)).collect()
}

pub fn merge_g1(v: &[G1Affine], c: &[Fr]) -> G1Affine {
    G1Projective::msm(v, c)
        .expect("equal lengths")
        .into_affine()
}

pub fn merge_g2(v: &[G2Affine], c: &[Fr]) -> G2Affine {
    G2Projective::msm(v, c)
        .expect("equal lengths")
        .into_affine()
}

/// Proof that the contributor knows the `x` it multiplied by (SPEC §18.2).
///
/// `s` is a G1 point of the contributor's choosing, `sx = x·s`, and
/// `rx = x·r` for the `r` the challenge fixes. Checking that `(s, sx)` and
/// `(r, rx)` share a ratio proves the same `x` is behind both; because `r`
/// could not be known in advance, producing `rx` requires knowing `x`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize)]
pub struct Pok {
    pub s: G1Affine,
    pub sx: G1Affine,
    pub rx: G2Affine,
}

impl Pok {
    pub fn prove<R: RngCore + CryptoRng>(
        x: &Fr,
        challenge: &[u8; 32],
        purpose: u8,
        rng: &mut R,
    ) -> Pok {
        let s = G1Projective::rand(rng);
        let sx = s * x;
        let rx = point_from_digest(challenge, purpose) * x;
        Pok {
            s: s.into_affine(),
            sx: sx.into_affine(),
            rx: rx.into_affine(),
        }
    }

    pub fn verify(&self, challenge: &[u8; 32], purpose: u8) -> bool {
        !self.s.is_zero()
            && !self.sx.is_zero()
            && !self.rx.is_zero()
            && same_ratio((self.s, self.sx), self.ratio(challenge, purpose))
    }

    /// The G2 pair whose exponent ratio is `x`, for checking that some other
    /// parameter moved by exactly `x` and not by something else.
    pub fn ratio(&self, challenge: &[u8; 32], purpose: u8) -> (G2Affine, G2Affine) {
        (point_from_digest(challenge, purpose), self.rx)
    }
}

/// Check that `v` is a geometric series in the exponent — `v[i+1] = x·v[i]`
/// for every `i`, where `x` is the exponent ratio of `by`. One MSM and one
/// pairing check instead of `v.len()` pairings: a bad entry survives only if
/// the batch scalars cancel it, which needs the digest to have been known in
/// advance.
pub fn is_geometric(
    v: &[G1Affine],
    by: (G2Affine, G2Affine),
    digest: &[u8; 32],
    purpose: u8,
) -> bool {
    if v.len() < 2 {
        return true;
    }
    let c = batch_scalars(digest, purpose, v.len() - 1);
    same_ratio((merge_g1(&v[..v.len() - 1], &c), merge_g1(&v[1..], &c)), by)
}

/// `is_geometric` for a G2 vector: the ratio pair is then in G1.
pub fn is_geometric_g2(
    v: &[G2Affine],
    by: (G1Affine, G1Affine),
    digest: &[u8; 32],
    purpose: u8,
) -> bool {
    if v.len() < 2 {
        return true;
    }
    let c = batch_scalars(digest, purpose, v.len() - 1);
    same_ratio(by, (merge_g2(&v[..v.len() - 1], &c), merge_g2(&v[1..], &c)))
}

/// Check that every `new[i]` is `prev[i]` scaled by the exponent ratio of
/// `by`, in one pairing.
pub fn is_scaled_by(
    prev: &[G1Affine],
    new: &[G1Affine],
    by: (G2Affine, G2Affine),
    digest: &[u8; 32],
    purpose: u8,
) -> bool {
    if prev.len() != new.len() {
        return false;
    }
    if prev.is_empty() {
        return true;
    }
    let c = batch_scalars(digest, purpose, prev.len());
    same_ratio((merge_g1(prev, &c), merge_g1(new, &c)), by)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ff::{Field, One};

    fn rng() -> ChaCha20Rng {
        ChaCha20Rng::from_seed([7u8; 32])
    }

    #[test]
    fn same_ratio_holds_only_for_the_same_exponent() {
        let mut r = rng();
        let x = Fr::rand(&mut r);
        let g1 = G1Affine::generator();
        let g2 = G2Affine::generator();
        assert!(same_ratio(
            (g1, (g1 * x).into_affine()),
            (g2, (g2 * x).into_affine())
        ));
        let y = x + Fr::one();
        assert!(!same_ratio(
            (g1, (g1 * x).into_affine()),
            (g2, (g2 * y).into_affine())
        ));
    }

    #[test]
    fn pok_proves_knowledge_and_is_bound_to_the_challenge() {
        let mut r = rng();
        let x = Fr::rand(&mut r);
        let challenge = [1u8; 32];
        let p = Pok::prove(&x, &challenge, TAU, &mut r);
        assert!(p.verify(&challenge, TAU));
        // Another challenge, or another purpose, is another statement.
        assert!(!p.verify(&[2u8; 32], TAU));
        assert!(!p.verify(&challenge, ALPHA));
    }

    #[test]
    fn geometric_series_check_catches_one_bad_entry() {
        let mut r = rng();
        let x = Fr::rand(&mut r);
        let digest = [3u8; 32];
        let mut powers = vec![G1Affine::generator()];
        let mut cur = Fr::one();
        for _ in 1..8 {
            cur *= x;
            powers.push((G1Affine::generator() * cur).into_affine());
        }
        let by = (
            G2Affine::generator(),
            (G2Affine::generator() * x).into_affine(),
        );
        assert!(is_geometric(&powers, by, &digest, TAU));
        let mut bad = powers.clone();
        bad[5] = (bad[5] * Fr::from(2u64)).into_affine();
        assert!(!is_geometric(&bad, by, &digest, TAU));
    }

    #[test]
    fn scaling_check_catches_a_vector_that_did_not_move() {
        let mut r = rng();
        let x = Fr::rand(&mut r);
        let digest = [4u8; 32];
        let prev: Vec<G1Affine> = (0..5)
            .map(|_| G1Projective::rand(&mut r).into_affine())
            .collect();
        let new: Vec<G1Affine> = prev.iter().map(|p| (*p * x).into_affine()).collect();
        let by = (
            G2Affine::generator(),
            (G2Affine::generator() * x).into_affine(),
        );
        assert!(is_scaled_by(&prev, &new, by, &digest, DELTA));
        let mut half = new.clone();
        half[2] = (half[2] * x.inverse().unwrap()).into_affine();
        assert!(!is_scaled_by(&prev, &half, by, &digest, DELTA));
    }
}
