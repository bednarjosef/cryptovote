//! Verifiable timed commitment to a Ristretto scalar (SPEC §10.3–§10.5):
//! Shamir 33-of-64 shares, each in an RSW puzzle, 32 of them opened by a
//! Fiat–Shamir challenge, Lagrange consistency of the rest with `pk`.

use crate::elgamal::{
    RistrettoPoint, Scalar, point_from_bytes, point_to_bytes, public_key, random_scalar,
    scalar_from_bytes,
};
use crate::puzzle::{
    PartyPublic, Puzzle, bigint256, check_opening, make_puzzle, solve_puzzle, verify_exponentiation,
};
use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT as G;
use num_bigint_dig::BigUint;
use rand::{CryptoRng, RngCore};

pub const VTC_N: usize = 64;
pub const VTC_T: usize = 33;
pub const VTC_OPEN: usize = 32;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum VtcError {
    #[error("proof of exponentiation fails")]
    Exponentiation,
    #[error("wrong number of commitments, puzzles or openings")]
    Counts,
    #[error("share commitment is not a valid point")]
    Point,
    #[error("opened share {0} is inconsistent with its commitment or puzzle")]
    Opening(usize),
    #[error("unopened share {0} is inconsistent with pk (Lagrange check)")]
    Lagrange(usize),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Opening {
    pub share: [u8; 32],
    pub r: BigUint,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Commitment {
    pub share_commitments: Vec<[u8; 32]>,
    pub puzzles: Vec<Puzzle>,
    /// For the challenge set `I` in ascending index order.
    pub openings: Vec<Opening>,
}

/// Shamir shares `f(1..=64)` of `sk` with a random degree-32 polynomial.
pub fn shamir_shares<R: RngCore + CryptoRng>(sk: &Scalar, rng: &mut R) -> Vec<Scalar> {
    let mut coeffs = vec![*sk];
    for _ in 1..VTC_T {
        coeffs.push(random_scalar(rng));
    }
    (1..=VTC_N as u64)
        .map(|j| {
            let x = Scalar::from(j);
            coeffs.iter().rev().fold(Scalar::ZERO, |acc, c| acc * x + c)
        })
        .collect()
}

/// Lagrange coefficients at 0 for the 1-based indices in `set`.
pub fn lagrange_at_zero(set: &[usize]) -> Vec<Scalar> {
    set.iter()
        .map(|&i| {
            let xi = Scalar::from(i as u64);
            set.iter()
                .filter(|&&k| k != i)
                .fold(Scalar::ONE, |acc, &k| {
                    let xk = Scalar::from(k as u64);
                    acc * xk * (xk - xi).invert()
                })
        })
        .collect()
}

/// The Fiat–Shamir transcript (SPEC §10.3 step 3).
pub fn transcript(
    vote_id: &[u8; 32],
    pk: &[u8; 32],
    p: &PartyPublic,
    commitments: &[[u8; 32]],
    puzzles: &[Puzzle],
) -> Vec<u8> {
    let mut t = Vec::new();
    t.extend_from_slice(vote_id);
    t.extend_from_slice(pk);
    for x in [&p.n, &p.g, &p.h, &p.poe] {
        t.extend_from_slice(&bigint256(x).unwrap_or([0u8; 256]));
    }
    t.extend_from_slice(&p.t.to_le_bytes());
    for c in commitments {
        t.extend_from_slice(c);
    }
    for z in puzzles {
        t.extend_from_slice(&bigint256(&z.u).unwrap_or([0u8; 256]));
        t.extend_from_slice(&z.ct);
    }
    t
}

/// 32 distinct indices in `1..=64` from the derive_key XOF, ascending.
pub fn challenge_set(transcript: &[u8]) -> Vec<usize> {
    let mut xof = blake3::Hasher::new_derive_key("cryptovote/v1/vtc-challenge");
    xof.update(transcript);
    let mut reader = xof.finalize_xof();
    let mut set = Vec::with_capacity(VTC_OPEN);
    let mut byte = [0u8; 1];
    while set.len() < VTC_OPEN {
        reader.fill(&mut byte);
        let idx = 1 + (byte[0] as usize % VTC_N);
        if !set.contains(&idx) {
            set.push(idx);
        }
    }
    set.sort_unstable();
    set
}

/// Commit to `sk` (SPEC §10.3, party side).
pub fn commit<R: RngCore + CryptoRng>(
    sk: &Scalar,
    vote_id: &[u8; 32],
    p: &PartyPublic,
    rng: &mut R,
) -> Commitment {
    let pk = point_to_bytes(&public_key(sk));
    let shares = shamir_shares(sk, rng);
    let share_commitments: Vec<[u8; 32]> =
        shares.iter().map(|s| point_to_bytes(&(s * G))).collect();
    let mut puzzles = Vec::with_capacity(VTC_N);
    let mut rs = Vec::with_capacity(VTC_N);
    for s in &shares {
        let (z, r) = make_puzzle(p, &s.to_bytes(), rng);
        puzzles.push(z);
        rs.push(r);
    }
    let set = challenge_set(&transcript(vote_id, &pk, p, &share_commitments, &puzzles));
    let openings = set
        .iter()
        .map(|&j| Opening {
            share: shares[j - 1].to_bytes(),
            r: rs[j - 1].clone(),
        })
        .collect();
    Commitment {
        share_commitments,
        puzzles,
        openings,
    }
}

/// Verify a commitment against `pk` (SPEC §10.3, everyone).
pub fn verify_commitment(
    vote_id: &[u8; 32],
    pk: &RistrettoPoint,
    p: &PartyPublic,
    c: &Commitment,
) -> Result<(), VtcError> {
    if !verify_exponentiation(p) {
        return Err(VtcError::Exponentiation);
    }
    if c.share_commitments.len() != VTC_N
        || c.puzzles.len() != VTC_N
        || c.openings.len() != VTC_OPEN
    {
        return Err(VtcError::Counts);
    }
    let points: Vec<RistrettoPoint> = c
        .share_commitments
        .iter()
        .map(point_from_bytes)
        .collect::<Option<_>>()
        .ok_or(VtcError::Point)?;
    let set = challenge_set(&transcript(
        vote_id,
        &point_to_bytes(pk),
        p,
        &c.share_commitments,
        &c.puzzles,
    ));
    for (k, &j) in set.iter().enumerate() {
        let o = &c.openings[k];
        let share = scalar_from_bytes(&o.share).ok_or(VtcError::Opening(j))?;
        if share * G != points[j - 1] || !check_opening(p, &c.puzzles[j - 1], &o.share, &o.r) {
            return Err(VtcError::Opening(j));
        }
    }
    // Paper's condition 1: every unopened share together with the opened ones reconstructs pk.
    for j in 1..=VTC_N {
        if set.contains(&j) {
            continue;
        }
        let mut s = set.clone();
        s.push(j);
        let lambdas = lagrange_at_zero(&s);
        let sum: RistrettoPoint = s
            .iter()
            .zip(lambdas.iter())
            .map(|(&i, l)| l * points[i - 1])
            .sum();
        if sum != *pk {
            return Err(VtcError::Lagrange(j));
        }
    }
    Ok(())
}

/// Force open (SPEC §10.5): solve unopened puzzles one at a time until one
/// honest share reconstructs a secret matching `pk`.
pub fn force_open(
    vote_id: &[u8; 32],
    pk: &RistrettoPoint,
    p: &PartyPublic,
    c: &Commitment,
) -> Option<Scalar> {
    let set = challenge_set(&transcript(
        vote_id,
        &point_to_bytes(pk),
        p,
        &c.share_commitments,
        &c.puzzles,
    ));
    let opened: Vec<(usize, Scalar)> = set
        .iter()
        .zip(c.openings.iter())
        .filter_map(|(&j, o)| scalar_from_bytes(&o.share).map(|s| (j, s)))
        .collect();
    if opened.len() != VTC_OPEN {
        return None;
    }
    for j in 1..=VTC_N {
        if set.contains(&j) {
            continue;
        }
        let Some(bytes) = solve_puzzle(p, &c.puzzles[j - 1]) else {
            continue;
        };
        let Some(share) = scalar_from_bytes(&bytes) else {
            continue;
        };
        let Some(expected) = point_from_bytes(&c.share_commitments[j - 1]) else {
            continue;
        };
        if share * G != expected {
            continue;
        }
        let mut indices: Vec<usize> = opened.iter().map(|(i, _)| *i).collect();
        indices.push(j);
        let lambdas = lagrange_at_zero(&indices);
        let shares: Vec<Scalar> = opened
            .iter()
            .map(|(_, s)| *s)
            .chain(std::iter::once(share))
            .collect();
        let sk: Scalar = shares.iter().zip(lambdas.iter()).map(|(s, l)| s * l).sum();
        if public_key(&sk) == *pk {
            return Some(sk);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::elgamal::keygen;
    use crate::puzzle::generate_party;
    use rand::SeedableRng;

    #[test]
    fn shamir_reconstructs_from_any_33() {
        let mut rng = rand_chacha::ChaCha20Rng::from_seed([4u8; 32]);
        let sk = random_scalar(&mut rng);
        let shares = shamir_shares(&sk, &mut rng);
        let idx: Vec<usize> = (5..=37).collect();
        let l = lagrange_at_zero(&idx);
        let rec: Scalar = idx
            .iter()
            .zip(l.iter())
            .map(|(&i, l)| shares[i - 1] * l)
            .sum();
        assert_eq!(rec, sk);
        let idx: Vec<usize> = (1..=32).collect();
        let l = lagrange_at_zero(&idx);
        let rec: Scalar = idx
            .iter()
            .zip(l.iter())
            .map(|(&i, l)| shares[i - 1] * l)
            .sum();
        assert_ne!(rec, sk, "32 shares are not enough");
        let set = challenge_set(b"abc");
        assert_eq!(set.len(), VTC_OPEN);
        assert!(
            set.windows(2).all(|w| w[0] < w[1]) && set.iter().all(|&i| (1..=VTC_N).contains(&i))
        );
        assert_ne!(challenge_set(b"abd"), set);
    }

    #[test]
    fn commit_verify_and_force_open_with_tiny_delay() {
        let mut rng = rand_chacha::ChaCha20Rng::from_seed([5u8; 32]);
        let (pubp, _) = generate_party(&mut rng, 32);
        let (sk, pk) = keygen(&mut rng);
        let vote_id = [0xabu8; 32];
        let c = commit(&sk, &vote_id, &pubp, &mut rng);
        assert_eq!(verify_commitment(&vote_id, &pk, &pubp, &c), Ok(()));
        // Wrong pk, wrong vote id (challenge set changes), tampered opening, tampered commitment.
        let (_, other_pk) = keygen(&mut rng);
        assert!(verify_commitment(&vote_id, &other_pk, &pubp, &c).is_err());
        assert!(verify_commitment(&[0u8; 32], &pk, &pubp, &c).is_err());
        let mut bad = c.clone();
        bad.openings[0].share[0] ^= 1;
        assert!(matches!(
            verify_commitment(&vote_id, &pk, &pubp, &bad),
            Err(VtcError::Opening(_))
        ));
        let mut bad = c.clone();
        let set = challenge_set(&transcript(
            &vote_id,
            &point_to_bytes(&pk),
            &pubp,
            &c.share_commitments,
            &c.puzzles,
        ));
        let unopened = (1..=VTC_N).find(|j| !set.contains(j)).unwrap();
        bad.share_commitments[unopened - 1] = point_to_bytes(&other_pk);
        // Changing a commitment changes the transcript, so either the challenge set moved
        // (openings then mismatch) or the Lagrange check catches it; either way: rejected.
        assert!(verify_commitment(&vote_id, &pk, &pubp, &bad).is_err());
        // Forced opening recovers sk (T = 32 squarings per puzzle here).
        assert_eq!(force_open(&vote_id, &pk, &pubp, &c), Some(sk));
    }
}
