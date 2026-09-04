//! Groth16 over BN254 for the membership circuit (SPEC §1.4).
//!
//! The circuit-specific setup is a trust assumption (ASSUMPTIONS A24). The
//! development setup below is derived from a public seed and is therefore
//! **insecure**: anyone can forge proofs against it. It exists so that dev
//! mode and tests run without a ceremony. Release deployments load keys
//! produced by a ceremony and pin the verifying-key hash.

use ark_bn254::{Bn254, Fr};
use ark_groth16::{
    Groth16, PreparedVerifyingKey, Proof, ProvingKey, VerifyingKey, prepare_verifying_key,
};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use rand::{CryptoRng, RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;
use std::sync::OnceLock;

use crate::circuit::MembershipCircuit;

/// Seed of the development setup. Public by construction: **insecure**.
pub const DEV_SETUP_SEED: [u8; 32] = *b"cryptovote dev groth16 setup !!!";

pub const PROOF_BYTES: usize = 128;

/// What a verifier needs: the verifying key (and its prepared form).
#[derive(Clone)]
pub struct MembershipVerifier {
    pub vk: VerifyingKey<Bn254>,
    pub pvk: PreparedVerifyingKey<Bn254>,
}

impl MembershipVerifier {
    pub fn from_vk(vk: VerifyingKey<Bn254>) -> Self {
        let pvk = prepare_verifying_key(&vk);
        MembershipVerifier { vk, pvk }
    }

    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        vk_from_bytes(bytes).map(Self::from_vk)
    }
}

/// Prover side: proving key plus the verifier.
pub struct MembershipKeys {
    pub pk: ProvingKey<Bn254>,
    pub verifier: MembershipVerifier,
}

impl MembershipKeys {
    pub fn from_proving_key(pk: ProvingKey<Bn254>) -> Self {
        let verifier = MembershipVerifier::from_vk(pk.vk.clone());
        MembershipKeys { pk, verifier }
    }

    pub fn vk(&self) -> &VerifyingKey<Bn254> {
        &self.verifier.vk
    }
}

/// Run the circuit-specific setup with the given randomness.
pub fn setup<R: RngCore + CryptoRng>(rng: &mut R) -> MembershipKeys {
    let pk = Groth16::<Bn254>::generate_random_parameters_with_reduction(
        MembershipCircuit::blank(),
        rng,
    )
    .expect("membership circuit setup");
    MembershipKeys::from_proving_key(pk)
}

/// The deterministic development setup (INSECURE — dev mode only).
pub fn dev_keys() -> &'static MembershipKeys {
    static KEYS: OnceLock<MembershipKeys> = OnceLock::new();
    KEYS.get_or_init(|| setup(&mut ChaCha20Rng::from_seed(DEV_SETUP_SEED)))
}

/// Proving failed: the witness does not satisfy the statement.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("witness does not satisfy the membership statement")]
pub struct Unsatisfiable;

/// Check that the witness satisfies the circuit (cheap compared to proving).
pub fn is_satisfied(circuit: &MembershipCircuit) -> bool {
    use ark_relations::gr1cs::{ConstraintSynthesizer, ConstraintSystem};
    let cs = ConstraintSystem::<Fr>::new_ref();
    circuit.clone().generate_constraints(cs.clone()).is_ok() && cs.is_satisfied().unwrap_or(false)
}

pub fn prove<R: RngCore + CryptoRng>(
    pk: &ProvingKey<Bn254>,
    circuit: MembershipCircuit,
    rng: &mut R,
) -> Result<[u8; PROOF_BYTES], Unsatisfiable> {
    if !is_satisfied(&circuit) {
        return Err(Unsatisfiable);
    }
    let proof =
        Groth16::<Bn254>::create_random_proof_with_reduction(circuit, pk, rng).expect("proving");
    let mut out = Vec::with_capacity(PROOF_BYTES);
    proof
        .serialize_compressed(&mut out)
        .expect("serialize proof");
    Ok(out
        .try_into()
        .expect("Groth16 BN254 compressed proof is 128 bytes"))
}

/// Verify a proof against the five public inputs. Malformed proof bytes
/// (non-canonical or off-curve points) verify as `false`.
pub fn verify(
    pvk: &PreparedVerifyingKey<Bn254>,
    public_inputs: &[Fr],
    proof: &[u8; PROOF_BYTES],
) -> bool {
    let Ok(proof) = Proof::<Bn254>::deserialize_compressed(&proof[..]) else {
        return false;
    };
    Groth16::<Bn254>::verify_proof(pvk, &proof, public_inputs).unwrap_or(false)
}

pub fn vk_to_bytes(vk: &VerifyingKey<Bn254>) -> Vec<u8> {
    let mut out = Vec::new();
    vk.serialize_compressed(&mut out).expect("serialize vk");
    out
}

pub fn vk_from_bytes(bytes: &[u8]) -> Option<VerifyingKey<Bn254>> {
    VerifyingKey::<Bn254>::deserialize_compressed(bytes).ok()
}

pub fn pk_to_bytes(pk: &ProvingKey<Bn254>) -> Vec<u8> {
    let mut out = Vec::new();
    pk.serialize_uncompressed(&mut out).expect("serialize pk");
    out
}

pub fn pk_from_bytes(bytes: &[u8]) -> Option<ProvingKey<Bn254>> {
    ProvingKey::<Bn254>::deserialize_uncompressed(bytes).ok()
}

/// Number of constraints of the membership circuit (for reporting).
pub fn constraint_count() -> usize {
    use ark_relations::gr1cs::{ConstraintSynthesizer, ConstraintSystem};
    let cs = ConstraintSystem::<Fr>::new_ref();
    MembershipCircuit::blank()
        .generate_constraints(cs.clone())
        .expect("synthesize");
    cs.num_constraints()
}

/// Re-randomize a valid proof into a different, equally valid proof (Groth16
/// malleability). Used by tests to demonstrate why content ids exclude the
/// proof (ASSUMPTIONS A3).
pub fn rerandomize<R: RngCore + CryptoRng>(
    vk: &VerifyingKey<Bn254>,
    proof: &[u8; PROOF_BYTES],
    rng: &mut R,
) -> Option<[u8; PROOF_BYTES]> {
    let p = Proof::<Bn254>::deserialize_compressed(&proof[..]).ok()?;
    let p2 = Groth16::<Bn254>::rerandomize_proof(vk, &p, rng);
    let mut out = Vec::with_capacity(PROOF_BYTES);
    p2.serialize_compressed(&mut out).ok()?;
    out.try_into().ok()
}

// --- What the ceremony is for -------------------------------------------
//
// Everything below works only against the *development* key, and only
// because its setup randomness comes from a seed printed at the top of this
// file. It is here so that the failure a ceremony prevents can be written
// down as a test instead of described in prose: with the setup's secret
// numbers, anyone produces a proof of a statement that is false, and no
// verifier anywhere can tell it from an honest proof. There is no equivalent
// function for ceremony parameters, because nobody holds the numbers.

/// The development setup's toxic waste, recovered by replaying the seeded
/// RNG in the order `ark_groth16` draws from it.
struct DevWaste {
    alpha: Fr,
    beta: Fr,
    gamma: Fr,
    delta: Fr,
    g1: ark_bn254::G1Projective,
    g2: ark_bn254::G2Projective,
}

fn dev_waste() -> DevWaste {
    use ark_ff::UniformRand;
    let mut rng = ChaCha20Rng::from_seed(DEV_SETUP_SEED);
    let w = DevWaste {
        alpha: Fr::rand(&mut rng),
        beta: Fr::rand(&mut rng),
        gamma: Fr::rand(&mut rng),
        delta: Fr::rand(&mut rng),
        g1: ark_bn254::G1Projective::rand(&mut rng),
        g2: ark_bn254::G2Projective::rand(&mut rng),
    };
    use ark_ec::CurveGroup;
    assert_eq!(
        (w.g1 * w.alpha).into_affine(),
        dev_keys().vk().alpha_g1,
        "the recovered development toxic waste does not match the development key"
    );
    w
}

/// Forge a proof of **any** statement against the development verifying key.
///
/// This is what holding the setup's secrets means: not a subtle weakening,
/// but membership proofs for registry leaves that do not exist — ballots cast
/// as people who never voted, byte-indistinguishable from honest ones and
/// undetectable at any later date. Available here only because the
/// development seed is public; the point of a ceremony is that no such
/// function can be written for the parameters a deployment actually uses.
pub fn dev_forge(public_inputs: &[Fr]) -> [u8; PROOF_BYTES] {
    use ark_ec::{AffineRepr, CurveGroup};
    use ark_ff::{Field, UniformRand};

    let w = dev_waste();
    let vk = dev_keys().vk();
    // Deterministic, so a forged ballot is reproducible in a test.
    let mut h = blake3::Hasher::new_derive_key("cryptovote/v1/dev-forge");
    for x in public_inputs {
        let mut b = Vec::new();
        x.serialize_compressed(&mut b).expect("serialize input");
        h.update(&b);
    }
    let mut rng = ChaCha20Rng::from_seed(*h.finalize().as_bytes());
    let (a, b) = (Fr::rand(&mut rng), Fr::rand(&mut rng));

    // The verification equation, in the exponent over e(g1, g2):
    //     a·b = α·β + γ·ic + δ·c
    // Pick A and B freely, then solve for C. `ic` is not known as a scalar,
    // but the point it multiplies is published, so C can still be formed.
    let mut ic = vk.gamma_abc_g1[0].into_group();
    for (x, p) in public_inputs.iter().zip(&vk.gamma_abc_g1[1..]) {
        ic += *p * x;
    }
    let d_inv = w.delta.inverse().expect("delta is nonzero");
    let proof = Proof::<Bn254> {
        a: (w.g1 * a).into_affine(),
        b: (w.g2 * b).into_affine(),
        c: (w.g1 * ((a * b - w.alpha * w.beta) * d_inv) - ic * (w.gamma * d_inv)).into_affine(),
    };
    let mut out = Vec::with_capacity(PROOF_BYTES);
    proof
        .serialize_compressed(&mut out)
        .expect("serialize proof");
    out.try_into().expect("128 bytes")
}

#[cfg(test)]
mod forgery_tests {
    use super::*;

    #[test]
    fn toxic_waste_proves_a_statement_nobody_can_satisfy() {
        // Five public inputs made up out of thin air: no registry, no leaf,
        // no secret, no witness. The verifier accepts them anyway.
        let inputs: Vec<Fr> = (1..=5u64).map(Fr::from).collect();
        let forged = dev_forge(&inputs);
        assert!(
            verify(&dev_keys().verifier.pvk, &inputs, &forged),
            "a compromised setup forges membership at will"
        );
        // And it is a forgery of *that* statement only, which is why a forger
        // has to mint a fresh proof per ballot — not a limit worth anything.
        let other: Vec<Fr> = (2..=6u64).map(Fr::from).collect();
        assert!(!verify(&dev_keys().verifier.pvk, &other, &forged));
    }
}
