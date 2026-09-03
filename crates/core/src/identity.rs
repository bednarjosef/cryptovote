//! Identity commitment, nullifiers, and the membership statement (SPEC §3.1, §5).

use crate::constants::REGISTRY_DEPTH;
use crate::items::{Id, Proof};
use cv_crypto::circuit::MembershipCircuit;
use cv_crypto::field::{Fr, fr_mod, fr_to_bytes, tag_field};
use cv_crypto::groth16::{self, MembershipKeys, MembershipVerifier};
use cv_crypto::hash::tagged;
use cv_crypto::poseidon;
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;

pub const TAG_BALLOT: &str = "ballot";
pub const TAG_SUPPORT: &str = "support";
pub const TAG_AUTHOR: &str = "author";
pub const TAG_NODE: &str = "node";
pub const TAG_KEYPARTY: &str = "keyparty";
/// Domain tag of the identity commitment (SPEC §3.1): the sponge has no
/// length padding, so `poseidon(s)` would equal `poseidon(s, 0)`, a Merkle
/// node with an empty right child.
pub const TAG_COMMIT: &str = "commit";

/// `C = poseidon(s, tag_field("commit"))`.
pub fn commitment(secret: &Fr) -> Fr {
    poseidon::hash(&[*secret, tag_field(TAG_COMMIT)])
}

/// `nullifier(s, tag, id) = poseidon(s, tag_field(tag), id)`.
pub fn nullifier(secret: &Fr, tag: &str, id: &Fr) -> Fr {
    poseidon::hash(&[*secret, tag_field(tag), *id])
}

/// The public part of the membership statement (SPEC §5).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MembershipStatement {
    pub root: Fr,
    pub nullifier: Fr,
    pub tag: Fr,
    pub id: Fr,
    pub signal: Fr,
}

impl MembershipStatement {
    /// Build the statement for an item: `tag` by name, `id` as the 32-byte
    /// reference (or `None` for the two-argument nullifiers), `signal` from
    /// the item's content id.
    pub fn new(root: Fr, nullifier: Fr, tag: &str, id: Option<&Id>, content_id: &Id) -> Self {
        MembershipStatement {
            root,
            nullifier,
            tag: tag_field(tag),
            id: id.map(fr_mod).unwrap_or(Fr::from(0u64)),
            signal: fr_mod(content_id),
        }
    }

    pub fn public_inputs(&self) -> [Fr; 5] {
        [self.root, self.nullifier, self.tag, self.id, self.signal]
    }
}

/// Private inputs of the membership statement.
#[derive(Clone, Debug)]
pub struct MembershipWitness {
    pub secret: Fr,
    pub index: u32,
    pub siblings: [Fr; REGISTRY_DEPTH],
}

/// Deterministic proof randomness: `H_B("proof-rand"; s_bytes || content_id)` (A20).
pub fn proof_rng(secret: &Fr, content_id: &Id) -> ChaCha20Rng {
    let mut data = fr_to_bytes(secret).to_vec();
    data.extend_from_slice(content_id);
    ChaCha20Rng::from_seed(tagged("proof-rand", &data))
}

pub fn prove_membership(
    keys: &MembershipKeys,
    statement: &MembershipStatement,
    witness: &MembershipWitness,
    content_id: &Id,
) -> Result<Proof, groth16::Unsatisfiable> {
    let circuit = MembershipCircuit {
        root: statement.root,
        nullifier: statement.nullifier,
        tag: statement.tag,
        id: statement.id,
        signal: statement.signal,
        secret: witness.secret,
        siblings: witness.siblings,
        index: witness.index,
    };
    let mut rng = proof_rng(&witness.secret, content_id);
    Ok(Proof(groth16::prove(&keys.pk, circuit, &mut rng)?))
}

pub fn verify_membership(
    verifier: &MembershipVerifier,
    statement: &MembershipStatement,
    proof: &Proof,
) -> bool {
    groth16::verify(&verifier.pvk, &statement.public_inputs(), &proof.0)
}
