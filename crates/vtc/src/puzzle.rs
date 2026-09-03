//! RSW time-lock puzzles over a party-generated RSA modulus, and the
//! Wesolowski proof of exponentiation for `h = g^(2^T)` (SPEC §10.1–§10.2).

use cv_crypto::aead;
use cv_crypto::hash::{blake3_hash, tagged};
use num_bigint_dig::prime::probably_prime;
use num_bigint_dig::{BigUint, ModInverse, RandBigInt, RandPrime};
use num_traits::{One, Zero};
use rand::{CryptoRng, RngCore};

/// `num-bigint-dig` speaks rand 0.9; the workspace uses rand 0.8. This
/// adapter forwards randomness without changing it.
struct Rng09<'a, R: RngCore + CryptoRng>(&'a mut R);

impl<R: RngCore + CryptoRng> rand09::RngCore for Rng09<'_, R> {
    fn next_u32(&mut self) -> u32 {
        self.0.next_u32()
    }
    fn next_u64(&mut self) -> u64 {
        self.0.next_u64()
    }
    fn fill_bytes(&mut self, dst: &mut [u8]) {
        self.0.fill_bytes(dst)
    }
}

impl<R: RngCore + CryptoRng> rand09::CryptoRng for Rng09<'_, R> {}

pub const MODULUS_BITS: usize = 2048;
pub const PRIME_BITS: usize = 1024;
pub const CHALLENGE_BITS: usize = 256;
pub const MILLER_RABIN_ROUNDS: usize = 64;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PuzzleError {
    #[error("integer does not fit in 256 bytes")]
    TooLarge,
    #[error("modulus is not a 2048-bit odd integer")]
    BadModulus,
    #[error("element outside [2, N-1]")]
    BadElement,
}

/// Public puzzle parameters of one party.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PartyPublic {
    pub n: BigUint,
    pub g: BigUint,
    pub h: BigUint,
    pub t: u64,
    pub poe: BigUint,
}

/// The party's trapdoor (kept private; may be discarded after commitment).
#[derive(Clone)]
pub struct PartySecret {
    pub phi: BigUint,
}

pub fn bigint256(x: &BigUint) -> Result<[u8; 256], PuzzleError> {
    let b = x.to_bytes_be();
    if b.len() > 256 {
        return Err(PuzzleError::TooLarge);
    }
    let mut out = [0u8; 256];
    out[256 - b.len()..].copy_from_slice(&b);
    Ok(out)
}

pub fn from_bigint256(b: &[u8; 256]) -> BigUint {
    BigUint::from_bytes_be(b)
}

impl PartyPublic {
    /// Structural checks of SPEC §6.6.
    pub fn check_structure(&self) -> Result<(), PuzzleError> {
        let two = BigUint::from(2u32);
        if self.n.bits() != MODULUS_BITS || (&self.n % &two).is_zero() {
            return Err(PuzzleError::BadModulus);
        }
        let max = &self.n - BigUint::one();
        for x in [&self.g, &self.h] {
            if *x < two || *x > max {
                return Err(PuzzleError::BadElement);
            }
        }
        // π = g^⌊2^T / l⌋ is legitimately 1 when 2^T < l (tiny dev delays).
        if self.poe.is_zero() || self.poe > max {
            return Err(PuzzleError::BadElement);
        }
        Ok(())
    }
}

/// Generate a party's modulus and delay parameters (SPEC §10.1).
pub fn generate_party<R: RngCore + CryptoRng>(rng: &mut R, t: u64) -> (PartyPublic, PartySecret) {
    let mut rng = Rng09(rng);
    let (p, q) = loop {
        let p = rng.gen_prime(PRIME_BITS);
        let q = rng.gen_prime(PRIME_BITS);
        let n = &p * &q;
        if p != q && n.bits() == MODULUS_BITS {
            break (p, q);
        }
    };
    let n = &p * &q;
    let phi = (&p - BigUint::one()) * (&q - BigUint::one());
    let two = BigUint::from(2u32);
    let g = loop {
        let x = rng.gen_biguint_below(&n);
        let g = x.modpow(&two, &n);
        if g >= two {
            break g;
        }
    };
    let h = g.modpow(&two.modpow(&BigUint::from(t), &phi), &n);
    let poe = prove_exponentiation(&n, &g, &h, t, &phi);
    (PartyPublic { n, g, h, t, poe }, PartySecret { phi })
}

/// Smallest probable prime ≥ the 256-bit integer of the digest (SPEC §10.2).
pub fn hash_to_prime(digest: &[u8; 32]) -> BigUint {
    let mut c = BigUint::from_bytes_be(digest);
    if (&c % BigUint::from(2u32)).is_zero() {
        c += BigUint::one();
    }
    while !probably_prime(&c, MILLER_RABIN_ROUNDS) {
        c += BigUint::from(2u32);
    }
    c
}

fn poe_challenge(n: &BigUint, g: &BigUint, h: &BigUint, t: u64) -> BigUint {
    let mut data = Vec::with_capacity(3 * 256 + 8);
    for x in [n, g, h] {
        data.extend_from_slice(&bigint256(x).unwrap_or([0u8; 256]));
    }
    data.extend_from_slice(&t.to_le_bytes());
    hash_to_prime(&tagged("vtc-poe", &data))
}

/// `π = g^⌊2^T / l⌋` computed with the trapdoor as `g^((2^T mod φ − 2^T mod l) · l⁻¹ mod φ)`.
pub fn prove_exponentiation(
    n: &BigUint,
    g: &BigUint,
    h: &BigUint,
    t: u64,
    phi: &BigUint,
) -> BigUint {
    let l = poe_challenge(n, g, h, t);
    let two = BigUint::from(2u32);
    let t_big = BigUint::from(t);
    let r_l = two.modpow(&t_big, &l);
    let e = two.modpow(&t_big, phi);
    let l_inv = l
        .clone()
        .mod_inverse(phi)
        .expect("l is prime and does not divide φ")
        .to_biguint()
        .expect("positive");
    let q = ((e + phi - (&r_l % phi)) % phi * l_inv) % phi;
    g.modpow(&q, n)
}

/// `π^l · g^(2^T mod l) ≡ h (mod N)`.
pub fn verify_exponentiation(p: &PartyPublic) -> bool {
    let l = poe_challenge(&p.n, &p.g, &p.h, p.t);
    let r_l = BigUint::from(2u32).modpow(&BigUint::from(p.t), &l);
    (p.poe.modpow(&l, &p.n) * p.g.modpow(&r_l, &p.n)) % &p.n == p.h
}

/// A time-lock puzzle of a 32-byte value (SPEC §10.2).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Puzzle {
    pub u: BigUint,
    pub ct: [u8; 48],
}

fn puzzle_key(y: &BigUint) -> [u8; 32] {
    blake3_hash(&bigint256(y).unwrap_or([0u8; 256]))
}

fn seal_share(u: &BigUint, y: &BigUint, share: &[u8; 32]) -> [u8; 48] {
    let ct = aead::seal(
        &puzzle_key(y),
        &[0u8; 24],
        &bigint256(u).unwrap_or([0u8; 256]),
        share,
    );
    ct.try_into().expect("32 + 16 bytes")
}

/// Create the puzzle of `share` with fresh randomness `r ∈ [1, N−1]`.
pub fn make_puzzle<R: RngCore + CryptoRng>(
    p: &PartyPublic,
    share: &[u8; 32],
    rng: &mut R,
) -> (Puzzle, BigUint) {
    let mut rng = Rng09(rng);
    let r = loop {
        let r = rng.gen_biguint_below(&p.n);
        if !r.is_zero() {
            break r;
        }
    };
    let u = p.g.modpow(&r, &p.n);
    let y = p.h.modpow(&r, &p.n);
    let ct = seal_share(&u, &y, share);
    (Puzzle { u, ct }, r)
}

/// Verifier side: check an opened puzzle against `(share, r)`.
pub fn check_opening(p: &PartyPublic, puzzle: &Puzzle, share: &[u8; 32], r: &BigUint) -> bool {
    if r.is_zero() || *r >= p.n {
        return false;
    }
    let u = p.g.modpow(r, &p.n);
    if u != puzzle.u {
        return false;
    }
    let y = p.h.modpow(r, &p.n);
    seal_share(&u, &y, share) == puzzle.ct
}

/// Solver side: `T` sequential squarings, then open the ciphertext.
pub fn solve_puzzle(p: &PartyPublic, puzzle: &Puzzle) -> Option<[u8; 32]> {
    let mut y = puzzle.u.clone();
    for _ in 0..p.t {
        y = (&y * &y) % &p.n;
    }
    let pt = aead::open(
        &puzzle_key(&y),
        &[0u8; 24],
        &bigint256(&puzzle.u).ok()?,
        &puzzle.ct,
    )?;
    pt.try_into().ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::SeedableRng;

    #[test]
    fn party_generation_poe_and_puzzle_with_tiny_delay() {
        let mut rng = rand_chacha::ChaCha20Rng::from_seed([2u8; 32]);
        let (pubp, secret) = generate_party(&mut rng, 64);
        pubp.check_structure().unwrap();
        assert!(verify_exponentiation(&pubp));
        // Tampered h or T fails the proof of exponentiation.
        let mut bad = pubp.clone();
        bad.h += BigUint::one();
        assert!(!verify_exponentiation(&bad));
        let mut bad = pubp.clone();
        bad.t += 1;
        assert!(!verify_exponentiation(&bad));
        // A puzzle opens with the trapdoor-side randomness and by solving.
        let share = [0x33u8; 32];
        let (puz, r) = make_puzzle(&pubp, &share, &mut rng);
        assert!(check_opening(&pubp, &puz, &share, &r));
        assert!(!check_opening(&pubp, &puz, &[0x34u8; 32], &r));
        assert!(!check_opening(
            &pubp,
            &puz,
            &share,
            &(r.clone() + BigUint::one())
        ));
        assert_eq!(solve_puzzle(&pubp, &puz), Some(share));
        let mut wrong_t = pubp.clone();
        wrong_t.t = 63;
        assert_eq!(solve_puzzle(&wrong_t, &puz), None);
        // h really is g^(2^T): recompute via the trapdoor.
        let e = BigUint::from(2u32).modpow(&BigUint::from(64u32), &secret.phi);
        assert_eq!(pubp.g.modpow(&e, &pubp.n), pubp.h);
        // bigint256 round trip.
        let b = bigint256(&pubp.n).unwrap();
        assert_eq!(from_bigint256(&b), pubp.n);
        assert!(hash_to_prime(&[0u8; 32]) >= BigUint::from(2u32));
    }
}
