//! Phase 1 — powers of tau (SPEC §18.3).
//!
//! Phase 1 knows nothing about the circuit. It produces `[τⁱ]₁`, `[τⁱ]₂`,
//! `[ατⁱ]₁`, `[βτⁱ]₁` and `[β]₂` for a secret `τ, α, β` nobody knows, up to a
//! degree that bounds the size of circuit the result can serve. Each
//! contributor multiplies in its own `τⱼ, αⱼ, βⱼ` and proves it did so; the
//! secret behind the result is the product over all contributors, so it stays
//! unknown as long as **one** contributor destroyed its own and did not
//! collude — no threshold, no quorum, no committee that has to stay honest
//! afterwards.
//!
//! An accumulator is checked standalone: the properties phase 2 relies on
//! (the powers really are consecutive powers of one `τ`, and `τ` is the same
//! secret in both groups) are re-derived from the accumulator itself rather
//! than assumed from the chain that produced it. The remaining condition —
//! that `τ` is not a root of the circuit domain's vanishing polynomial —
//! depends on the circuit, so `phase2::prepare` checks it.

use ark_bn254::{Fr, G1Affine, G1Projective, G2Affine};
use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::{One, UniformRand, Zero};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use rand::{CryptoRng, RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;

use crate::Error;
use crate::pok::{ALPHA, BETA, Pok, TAU, is_geometric, is_geometric_g2, same_ratio};

/// Purposes for the batched checks, disjoint from the `Pok` purposes.
const B_TAU_G1: u8 = 16;
const B_TAU_G2: u8 = 17;
const B_ALPHA: u8 = 18;
const B_BETA: u8 = 19;

/// The phase-1 parameters after some number of contributions.
#[derive(Clone, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize)]
pub struct Accumulator {
    /// `[τⁱ]₁` for `i = 0 ..= 2d−2`. The top half is what the `h` query of a
    /// circuit of degree `d` needs (`τⁱ·(τᵈ−1)`).
    pub tau_g1: Vec<G1Affine>,
    /// `[τⁱ]₂` for `i = 0 ..= d−1`.
    pub tau_g2: Vec<G2Affine>,
    /// `[ατⁱ]₁` for `i = 0 ..= d−1`.
    pub alpha_tau_g1: Vec<G1Affine>,
    /// `[βτⁱ]₁` for `i = 0 ..= d−1`.
    pub beta_tau_g1: Vec<G1Affine>,
    /// `[β]₂`.
    pub beta_g2: G2Affine,
}

/// What a contributor publishes alongside the new accumulator.
#[derive(Clone, Copy, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize)]
pub struct Phase1Pok {
    pub tau: Pok,
    pub alpha: Pok,
    pub beta: Pok,
}

impl Accumulator {
    /// The starting point: `τ = α = β = 1`, every element a generator. It has
    /// no secret in it at all, which is why it can be written down rather
    /// than trusted — the first contributor is the first to add one.
    pub fn new(degree: usize) -> Accumulator {
        assert!(degree.is_power_of_two() && degree >= 2, "degree");
        Accumulator {
            tau_g1: vec![G1Affine::generator(); 2 * degree - 1],
            tau_g2: vec![G2Affine::generator(); degree],
            alpha_tau_g1: vec![G1Affine::generator(); degree],
            beta_tau_g1: vec![G1Affine::generator(); degree],
            beta_g2: G2Affine::generator(),
        }
    }

    pub fn degree(&self) -> usize {
        self.tau_g2.len()
    }

    /// BLAKE3 of the canonical compressed encoding. This is the challenge the
    /// next contributor answers, and the name every attestation signs.
    pub fn digest(&self) -> [u8; 32] {
        let mut bytes = Vec::new();
        self.serialize_compressed(&mut bytes)
            .expect("serialize accumulator");
        *blake3::hash(&bytes).as_bytes()
    }

    fn shape_ok(&self) -> bool {
        let d = self.degree();
        d.is_power_of_two()
            && d >= 2
            && self.tau_g1.len() == 2 * d - 1
            && self.alpha_tau_g1.len() == d
            && self.beta_tau_g1.len() == d
    }

    /// Everything phase 2 assumes about an accumulator, checked from the
    /// accumulator alone (SPEC §18.3). Cheap: a handful of pairings over
    /// batched sums, whatever the degree.
    pub fn check_structure(&self) -> Result<(), Error> {
        if !self.shape_ok() {
            return Err(Error::Invalid("accumulator has the wrong shape"));
        }
        let (g1, g2) = (G1Affine::generator(), G2Affine::generator());
        if self.tau_g1[0] != g1 || self.tau_g2[0] != g2 {
            return Err(Error::Invalid(
                "accumulator does not start at the generator",
            ));
        }
        if self.tau_g1.iter().any(|p| p.is_zero())
            || self.tau_g2.iter().any(|p| p.is_zero())
            || self.alpha_tau_g1.iter().any(|p| p.is_zero())
            || self.beta_tau_g1.iter().any(|p| p.is_zero())
            || self.beta_g2.is_zero()
        {
            return Err(Error::Invalid("accumulator contains the identity"));
        }
        // τ is the same secret in G1 and G2, and so is β.
        if !same_ratio((g1, self.tau_g1[1]), (g2, self.tau_g2[1])) {
            return Err(Error::Invalid("τ differs between G1 and G2"));
        }
        if !same_ratio((g1, self.beta_tau_g1[0]), (g2, self.beta_g2)) {
            return Err(Error::Invalid("β differs between G1 and G2"));
        }
        // Consecutive powers of one τ, in both groups and under α and β.
        let d = self.digest();
        let tau_in_g2 = (g2, self.tau_g2[1]);
        if !is_geometric(&self.tau_g1, tau_in_g2, &d, B_TAU_G1) {
            return Err(Error::Invalid("[τⁱ]₁ is not a series in τ"));
        }
        if !is_geometric_g2(&self.tau_g2, (g1, self.tau_g1[1]), &d, B_TAU_G2) {
            return Err(Error::Invalid("[τⁱ]₂ is not a series in τ"));
        }
        if !is_geometric(&self.alpha_tau_g1, tau_in_g2, &d, B_ALPHA) {
            return Err(Error::Invalid("[ατⁱ]₁ is not a series in τ"));
        }
        if !is_geometric(&self.beta_tau_g1, tau_in_g2, &d, B_BETA) {
            return Err(Error::Invalid("[βτⁱ]₁ is not a series in τ"));
        }
        Ok(())
    }
}

/// Apply `(τⱼ, αⱼ, βⱼ)` to an accumulator. Split out so that a beacon step,
/// whose randomness is public, is the same operation as a secret one.
fn apply(acc: &Accumulator, tau: Fr, alpha: Fr, beta: Fr) -> Accumulator {
    let mut powers = Vec::with_capacity(acc.tau_g1.len());
    let mut cur = Fr::one();
    for _ in 0..acc.tau_g1.len() {
        powers.push(cur);
        cur *= tau;
    }
    let d = acc.degree();
    let scale_g1 = |v: &[G1Affine], s: &[Fr]| -> Vec<G1Affine> {
        let projective: Vec<G1Projective> =
            v.iter().zip(s).map(|(p, k)| *p * k).collect::<Vec<_>>();
        G1Projective::normalize_batch(&projective)
    };
    let alpha_scalars: Vec<Fr> = powers[..d].iter().map(|p| *p * alpha).collect();
    let beta_scalars: Vec<Fr> = powers[..d].iter().map(|p| *p * beta).collect();
    let tau_g2 = ark_bn254::G2Projective::normalize_batch(
        &acc.tau_g2
            .iter()
            .zip(&powers[..d])
            .map(|(p, k)| *p * k)
            .collect::<Vec<_>>(),
    );
    Accumulator {
        tau_g1: scale_g1(&acc.tau_g1, &powers),
        tau_g2,
        alpha_tau_g1: scale_g1(&acc.alpha_tau_g1, &alpha_scalars),
        beta_tau_g1: scale_g1(&acc.beta_tau_g1, &beta_scalars),
        beta_g2: (acc.beta_g2 * beta).into_affine(),
    }
}

fn secrets<R: RngCore + CryptoRng>(rng: &mut R) -> (Fr, Fr, Fr) {
    let mut draw = || loop {
        let x = Fr::rand(rng);
        if !x.is_zero() && x != Fr::one() {
            return x;
        }
    };
    (draw(), draw(), draw())
}

/// Contribute to phase 1. The caller's `rng` is the whole security of this
/// step: whatever it produces must be unguessable and must not survive the
/// process.
pub fn contribute<R: RngCore + CryptoRng>(
    acc: &Accumulator,
    challenge: &[u8; 32],
    rng: &mut R,
) -> (Accumulator, Phase1Pok) {
    let (tau, alpha, beta) = secrets(rng);
    let next = apply(acc, tau, alpha, beta);
    let pok = Phase1Pok {
        tau: Pok::prove(&tau, challenge, TAU, rng),
        alpha: Pok::prove(&alpha, challenge, ALPHA, rng),
        beta: Pok::prove(&beta, challenge, BETA, rng),
    };
    (next, pok)
}

/// The randomness of a beacon step, derived from a public value so that
/// anyone can recompute the step exactly (SPEC §18.5).
pub fn beacon_rng(challenge: &[u8; 32], source: &[u8]) -> ChaCha20Rng {
    let mut h = blake3::Hasher::new_derive_key("cryptovote/v1/ceremony/beacon");
    h.update(challenge);
    h.update(source);
    ChaCha20Rng::from_seed(*h.finalize().as_bytes())
}

/// A beacon step: a contribution whose randomness is public. It adds no
/// secret and no honesty to the ceremony — its only job is to fix the final
/// parameters to a value nobody could have steered towards.
pub fn contribute_beacon(
    acc: &Accumulator,
    challenge: &[u8; 32],
    source: &[u8],
) -> (Accumulator, Phase1Pok) {
    contribute(acc, challenge, &mut beacon_rng(challenge, source))
}

/// Check one step: that `next` is `prev` moved by a secret the contributor
/// knew, and that `next` is still a well-formed accumulator.
pub fn verify(
    prev: &Accumulator,
    next: &Accumulator,
    pok: &Phase1Pok,
    challenge: &[u8; 32],
) -> Result<(), Error> {
    if prev.degree() != next.degree() || !prev.shape_ok() {
        return Err(Error::Invalid("degree changed between steps"));
    }
    if prev.digest() != *challenge {
        return Err(Error::Invalid("step answers a different challenge"));
    }
    if !pok.tau.verify(challenge, TAU)
        || !pok.alpha.verify(challenge, ALPHA)
        || !pok.beta.verify(challenge, BETA)
    {
        return Err(Error::Invalid(
            "contributor did not prove it knew its secret",
        ));
    }
    // Each parameter moved by exactly the secret that was proven, and not by
    // some other value: the ratio the proof pins down is reused here.
    if !same_ratio(
        (prev.tau_g1[1], next.tau_g1[1]),
        pok.tau.ratio(challenge, TAU),
    ) {
        return Err(Error::Invalid("τ did not move by the proven secret"));
    }
    if !same_ratio(
        (prev.alpha_tau_g1[0], next.alpha_tau_g1[0]),
        pok.alpha.ratio(challenge, ALPHA),
    ) {
        return Err(Error::Invalid("α did not move by the proven secret"));
    }
    if !same_ratio(
        (prev.beta_tau_g1[0], next.beta_tau_g1[0]),
        pok.beta.ratio(challenge, BETA),
    ) {
        return Err(Error::Invalid("β did not move by the proven secret"));
    }
    // β in G2 moved by the same secret. The G1 half of the proof supplies the
    // ratio, because both sides being compared are in G2.
    if !same_ratio((pok.beta.s, pok.beta.sx), (prev.beta_g2, next.beta_g2)) {
        return Err(Error::Invalid("β in G2 did not move by the proven secret"));
    }
    next.check_structure()
}

/// Check a beacon step by recomputing it. Nothing is taken on trust: the same
/// public value must produce the same accumulator, byte for byte.
pub fn verify_beacon(
    prev: &Accumulator,
    next: &Accumulator,
    pok: &Phase1Pok,
    challenge: &[u8; 32],
    source: &[u8],
) -> Result<(), Error> {
    let (expect, expect_pok) = contribute_beacon(prev, challenge, source);
    if &expect != next || &expect_pok != pok {
        return Err(Error::Invalid(
            "beacon step does not match its public value",
        ));
    }
    verify(prev, next, pok, challenge)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rng(seed: u8) -> ChaCha20Rng {
        ChaCha20Rng::from_seed([seed; 32])
    }

    #[test]
    fn a_chain_of_contributions_verifies() {
        let mut acc = Accumulator::new(8);
        assert!(acc.check_structure().is_ok());
        for seed in 1..4u8 {
            let challenge = acc.digest();
            let (next, pok) = contribute(&acc, &challenge, &mut rng(seed));
            verify(&acc, &next, &pok, &challenge).expect("step verifies");
            acc = next;
        }
        let challenge = acc.digest();
        let (next, pok) = contribute_beacon(&acc, &challenge, b"block hash");
        verify_beacon(&acc, &next, &pok, &challenge, b"block hash").expect("beacon verifies");
        // A beacon claimed to come from a different value is caught.
        assert!(verify_beacon(&acc, &next, &pok, &challenge, b"other").is_err());
    }

    #[test]
    fn a_replayed_contribution_is_rejected() {
        let acc = Accumulator::new(8);
        let challenge = acc.digest();
        let (next, pok) = contribute(&acc, &challenge, &mut rng(1));
        // Someone who did not contribute takes the previous step's numbers and
        // presents them as their own against the new challenge.
        let challenge2 = next.digest();
        let (next2, _) = contribute(&next, &challenge2, &mut rng(2));
        assert!(verify(&next, &next2, &pok, &challenge2).is_err());
    }

    #[test]
    fn a_contribution_that_did_not_move_everything_is_rejected() {
        let acc = Accumulator::new(8);
        let challenge = acc.digest();
        let (mut next, pok) = contribute(&acc, &challenge, &mut rng(1));
        // Leave one power of τ behind: the batched series check must catch it.
        next.tau_g1[5] = acc.tau_g1[5];
        assert!(verify(&acc, &next, &pok, &challenge).is_err());
    }

    #[test]
    fn a_zero_contribution_is_rejected() {
        let acc = Accumulator::new(8);
        let challenge = acc.digest();
        let dead = apply(&acc, Fr::zero(), Fr::one(), Fr::one());
        let pok = Phase1Pok {
            tau: Pok::prove(&Fr::zero(), &challenge, TAU, &mut rng(1)),
            alpha: Pok::prove(&Fr::one(), &challenge, ALPHA, &mut rng(2)),
            beta: Pok::prove(&Fr::one(), &challenge, BETA, &mut rng(3)),
        };
        assert!(verify(&acc, &dead, &pok, &challenge).is_err());
    }
}
