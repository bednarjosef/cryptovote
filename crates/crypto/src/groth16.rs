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

pub struct MembershipKeys {
    pub pk: ProvingKey<Bn254>,
    pub vk: VerifyingKey<Bn254>,
    pub pvk: PreparedVerifyingKey<Bn254>,
}

impl MembershipKeys {
    pub fn from_proving_key(pk: ProvingKey<Bn254>) -> Self {
        let vk = pk.vk.clone();
        let pvk = prepare_verifying_key(&vk);
        MembershipKeys { pk, vk, pvk }
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
