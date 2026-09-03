//! The membership circuit (SPEC §5): one R1CS statement for every
//! proof-bearing item. Kept minimal on purpose: leaf = poseidon(s, "commit"), a depth-32
//! Poseidon Merkle path, nullifier = poseidon(s, tag, id), and a squared
//! public `signal` that binds the item content.

use ark_bn254::Fr;
use ark_crypto_primitives::crh::poseidon::constraints::{
    CRHGadget, CRHParametersVar, TwoToOneCRHGadget,
};
use ark_crypto_primitives::crh::{CRHSchemeGadget, TwoToOneCRHSchemeGadget};
use ark_r1cs_std::alloc::AllocVar;
use ark_r1cs_std::boolean::Boolean;
use ark_r1cs_std::eq::EqGadget;
use ark_r1cs_std::fields::FieldVar;
use ark_r1cs_std::fields::fp::FpVar;
use ark_r1cs_std::select::CondSelectGadget;
use ark_relations::gr1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};

use crate::poseidon;

pub const DEPTH: usize = 32;

/// `tag_field("commit")` (SPEC §3.1).
pub const COMMIT_TAG: u64 = 127996156276579;

#[derive(Clone, Debug)]
pub struct MembershipCircuit {
    // public inputs, in this order
    pub root: Fr,
    pub nullifier: Fr,
    pub tag: Fr,
    pub id: Fr,
    pub signal: Fr,
    // private witness
    pub secret: Fr,
    pub siblings: [Fr; DEPTH],
    pub index: u32,
}

impl MembershipCircuit {
    /// A structurally complete circuit with zero values (for parameter setup).
    pub fn blank() -> Self {
        MembershipCircuit {
            root: Fr::from(0u64),
            nullifier: Fr::from(0u64),
            tag: Fr::from(0u64),
            id: Fr::from(0u64),
            signal: Fr::from(0u64),
            secret: Fr::from(0u64),
            siblings: [Fr::from(0u64); DEPTH],
            index: 0,
        }
    }
}

impl ConstraintSynthesizer<Fr> for MembershipCircuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        let params = CRHParametersVar::<Fr>::new_constant(cs.clone(), poseidon::config())?;

        let root = FpVar::new_input(cs.clone(), || Ok(self.root))?;
        let nullifier = FpVar::new_input(cs.clone(), || Ok(self.nullifier))?;
        let tag = FpVar::new_input(cs.clone(), || Ok(self.tag))?;
        let id = FpVar::new_input(cs.clone(), || Ok(self.id))?;
        let signal = FpVar::new_input(cs.clone(), || Ok(self.signal))?;

        let secret = FpVar::new_witness(cs.clone(), || Ok(self.secret))?;
        let siblings = (0..DEPTH)
            .map(|i| FpVar::new_witness(cs.clone(), || Ok(self.siblings[i])))
            .collect::<Result<Vec<_>, _>>()?;
        let bits = (0..DEPTH)
            .map(|i| Boolean::new_witness(cs.clone(), || Ok((self.index >> i) & 1 == 1)))
            .collect::<Result<Vec<_>, _>>()?;

        // leaf = poseidon(s, "commit"); walk up the tree (bit = 1 means "current node is the right child").
        let commit_tag = FpVar::Constant(Fr::from(COMMIT_TAG));
        let mut cur = CRHGadget::<Fr>::evaluate(&params, &[secret.clone(), commit_tag])?;
        for i in 0..DEPTH {
            let left = FpVar::conditionally_select(&bits[i], &siblings[i], &cur)?;
            let right = FpVar::conditionally_select(&bits[i], &cur, &siblings[i])?;
            cur = TwoToOneCRHGadget::<Fr>::evaluate(&params, &left, &right)?;
        }
        cur.enforce_equal(&root)?;

        // nullifier = poseidon(s, tag, id)
        let n = CRHGadget::<Fr>::evaluate(&params, &[secret, tag, id])?;
        n.enforce_equal(&nullifier)?;

        // Bind the signal (one multiplication constraint; result unused).
        let _signal_sq = signal.square()?;
        Ok(())
    }
}
