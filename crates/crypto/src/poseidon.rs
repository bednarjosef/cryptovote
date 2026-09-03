//! Poseidon over BN254 `Fr` (SPEC §1.3): width 3, α = 5, 8 full + 57 partial
//! rounds, constants from the Grain-LFSR procedure of the reference
//! implementation as computed by `ark-crypto-primitives`.

use ark_bn254::Fr;
use ark_crypto_primitives::crh::poseidon::{CRH, TwoToOneCRH};
use ark_crypto_primitives::crh::{CRHScheme, TwoToOneCRHScheme};
use ark_crypto_primitives::sponge::poseidon::{PoseidonConfig, find_poseidon_ark_and_mds};
use std::sync::OnceLock;

pub const PRIME_BITS: u64 = 254;
pub const RATE: usize = 2;
pub const CAPACITY: usize = 1;
pub const FULL_ROUNDS: usize = 8;
pub const PARTIAL_ROUNDS: usize = 57;
pub const ALPHA: u64 = 5;

/// The protocol's Poseidon parameters (computed once).
pub fn config() -> &'static PoseidonConfig<Fr> {
    static CONFIG: OnceLock<PoseidonConfig<Fr>> = OnceLock::new();
    CONFIG.get_or_init(|| {
        let (ark, mds) = find_poseidon_ark_and_mds::<Fr>(
            PRIME_BITS,
            RATE,
            FULL_ROUNDS as u64,
            PARTIAL_ROUNDS as u64,
            0,
        );
        PoseidonConfig::new(FULL_ROUNDS, PARTIAL_ROUNDS, ALPHA, mds, ark, RATE, CAPACITY)
    })
}

/// `poseidon(x_1, …, x_k)`: sponge absorb of all inputs, squeeze one element.
pub fn hash(inputs: &[Fr]) -> Fr {
    CRH::<Fr>::evaluate(config(), inputs).expect("poseidon CRH cannot fail")
}

/// `poseidon(l, r)` via the two-to-one CRH; equal to `hash(&[l, r])`.
pub fn hash2(left: &Fr, right: &Fr) -> Fr {
    TwoToOneCRH::<Fr>::evaluate(config(), left, right).expect("poseidon 2-to-1 cannot fail")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn two_to_one_equals_sponge_of_two() {
        let a = Fr::from(3u64);
        let b = Fr::from(4u64);
        assert_eq!(hash2(&a, &b), hash(&[a, b]));
        assert_ne!(hash2(&a, &b), hash2(&b, &a));
        // Known property of the unpadded sponge: a trailing zero input is
        // absorbed into an untouched rate slot, so arity-1 and arity-2-with-zero
        // hashes coincide. This is why the protocol never uses the arity-1 hash
        // (the identity commitment carries a domain tag, SPEC §3.1).
        assert_eq!(hash(&[a]), hash(&[a, Fr::from(0u64)]));
        assert_ne!(hash(&[a, Fr::from(1u64)]), hash(&[a, Fr::from(0u64)]));
    }
}
