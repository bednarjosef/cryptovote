//! The Groth16 parameter ceremony (SPEC §18).
//!
//! Groth16 verification is fast and its proofs are 128 bytes because the
//! verifier's work is folded into parameters generated once, from secret
//! numbers. Whoever knows those numbers can produce a proof of a statement
//! that is false — here, a membership proof for a registry leaf they do not
//! hold, which is a ballot cast as somebody who exists but did not vote, and
//! it is *indistinguishable* from an honest one. No later check catches it.
//!
//! The ceremony removes the single party who would otherwise know them. Each
//! contributor folds in its own randomness and proves it did so without ever
//! revealing it; the number behind the finished parameters is the product of
//! everyone's, so it stays unknown unless **every** contributor kept their
//! share and colluded. One honest contributor in each phase is enough, and no
//! one has to stay honest afterwards — there is nothing left to be honest
//! about once the ceremony ends.
//!
//! This is the one place in the workspace where the property being defended
//! cannot be checked after the fact. Everything else the protocol does is
//! verifiable from the Log; a compromised ceremony leaves no evidence at all.
//! `Transcript::replay` is therefore the whole of the assurance: it lets any
//! stranger re-derive the finished keys from the published steps and see
//! exactly whose entropy went into them.
#![forbid(unsafe_code)]

pub mod phase1;
pub mod phase2;
pub mod pok;
pub mod transcript;

use ark_bn254::Fr;
use ark_relations::gr1cs::ConstraintSynthesizer;
use cv_crypto::groth16::{MembershipKeys, vk_to_bytes};

use phase1::{Accumulator, Phase1Pok};
use phase2::Phase2;
use pok::Pok;
use transcript::{
    KIND_PHASE1_ACC, KIND_PHASE1_STEP, KIND_PHASE2_PARAMS, KIND_PHASE2_STEP, Step, decode,
};

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum Error {
    #[error("invalid ceremony step: {0}")]
    Invalid(&'static str),
    #[error("{0}")]
    Malformed(&'static str),
    #[error("this phase 1 goes up to degree {have}; the circuit needs {need}")]
    DegreeTooSmall { have: usize, need: usize },
    #[error("the transcript is empty: no contribution to either phase")]
    Empty,
}

/// One line of the report a replay produces.
#[derive(Clone, Debug)]
pub struct StepSummary {
    pub phase: u8,
    pub index: u32,
    pub beacon: Option<Vec<u8>>,
    pub name: String,
    pub attested_by: Option<[u8; 32]>,
    pub response: [u8; 32],
}

/// What a replay establishes about a ceremony. A ceremony still in progress
/// reports what it has: contributors must be able to check the chain they are
/// about to extend, and the last thing anyone should be asked to do is
/// contribute to a transcript nobody could verify yet.
#[derive(Clone, Debug)]
pub struct Report {
    pub degree: usize,
    /// `None` until `prepare` has fixed which circuit these parameters serve.
    pub circuit_digest: Option<[u8; 32]>,
    pub steps: Vec<StepSummary>,
    /// `None` until phase 2 exists; the keys do not until then.
    pub vk_hash: Option<[u8; 32]>,
}

impl Report {
    /// Contributions that added a secret. Beacon steps are excluded: they add
    /// unpredictability, not entropy nobody knows.
    pub fn secret_contributions(&self, phase: u8) -> usize {
        self.steps
            .iter()
            .filter(|s| s.phase == phase && s.beacon.is_none())
            .count()
    }

    /// A ceremony is finished when both phases exist and each has at least
    /// one contribution that added a secret. A phase closed with nothing but
    /// a beacon has a publicly computable trapdoor and is not a ceremony.
    pub fn usable(&self) -> Result<(), Error> {
        if self.vk_hash.is_none() {
            return Err(Error::Invalid("phase 2 has not started"));
        }
        if self.secret_contributions(1) == 0 {
            return Err(Error::Invalid(
                "phase 1 has no secret contribution: its trapdoor is public",
            ));
        }
        if self.secret_contributions(2) == 0 {
            return Err(Error::Invalid(
                "phase 2 has no secret contribution: its δ is public",
            ));
        }
        Ok(())
    }
}

/// A whole ceremony as published: the accumulators and parameters at each
/// step, and the step records that justify the moves between them.
#[derive(Clone, Debug, Default)]
pub struct Transcript {
    /// Phase-1 accumulators; `[0]` is the starting one, all generators.
    pub phase1: Vec<Vec<u8>>,
    pub phase1_steps: Vec<Vec<u8>>,
    /// Phase-2 parameters; `[0]` is what `prepare` gives.
    pub phase2: Vec<Vec<u8>>,
    pub phase2_steps: Vec<Vec<u8>>,
}

impl Transcript {
    /// Re-derive the keys from the published steps, checking every one.
    ///
    /// This is the only thing that makes a ceremony worth anything: not that
    /// the contributors were trustworthy, but that a stranger can confirm
    /// each of them really did fold something in, that nothing was inserted
    /// or reordered, and that these keys — and no others — are what came out.
    pub fn replay<C: ConstraintSynthesizer<Fr>>(
        &self,
        circuit: C,
    ) -> Result<(Option<MembershipKeys>, Report), Error> {
        if self.phase1.is_empty() {
            return Err(Error::Empty);
        }
        if self.phase1.len() != self.phase1_steps.len() + 1
            || (!self.phase2.is_empty() && self.phase2.len() != self.phase2_steps.len() + 1)
        {
            return Err(Error::Malformed("transcript has a step without a response"));
        }
        let mut steps = Vec::new();

        // Phase 1. The starting accumulator is not trusted either: it is
        // recomputed from the degree, so it can hold nothing.
        let mut acc: Accumulator = decode(KIND_PHASE1_ACC, &self.phase1[0])?;
        let degree = acc.degree();
        if !degree.is_power_of_two() || degree < 2 {
            return Err(Error::Invalid("degree is not a power of two"));
        }
        if acc != Accumulator::new(degree) {
            return Err(Error::Invalid("phase 1 does not start from the generators"));
        }
        for (i, raw) in self.phase1_steps.iter().enumerate() {
            let step: Step<Phase1Pok> = decode(KIND_PHASE1_STEP, raw)?;
            let next: Accumulator = decode(KIND_PHASE1_ACC, &self.phase1[i + 1])?;
            check_step(&step, 1, i as u32, &acc.digest(), &next.digest())?;
            if step.is_beacon() {
                phase1::verify_beacon(&acc, &next, &step.pok, &step.challenge, &step.beacon)?;
            } else {
                phase1::verify(&acc, &next, &step.pok, &step.challenge)?;
            }
            steps.push(summarize(&step));
            acc = next;
        }

        // Phase 2, if it has started. Its starting point is a function of the
        // phase-1 result and the circuit, with no secret in it, so it is
        // recomputed rather than read.
        if self.phase2.is_empty() {
            return Ok((
                None,
                Report {
                    degree,
                    circuit_digest: None,
                    steps,
                    vk_hash: None,
                },
            ));
        }
        let mut params: Phase2 = decode(KIND_PHASE2_PARAMS, &self.phase2[0])?;
        phase2::verify_initial(&acc, circuit, &params)?;
        for (i, raw) in self.phase2_steps.iter().enumerate() {
            let step: Step<Pok> = decode(KIND_PHASE2_STEP, raw)?;
            let next: Phase2 = decode(KIND_PHASE2_PARAMS, &self.phase2[i + 1])?;
            check_step(&step, 2, i as u32, &params.digest(), &next.digest())?;
            if step.is_beacon() {
                phase2::verify_beacon(&params, &next, &step.pok, &step.challenge, &step.beacon)?;
            } else {
                phase2::verify(&params, &next, &step.pok, &step.challenge)?;
            }
            steps.push(summarize(&step));
            params = next;
        }

        let circuit_digest = Some(params.circuit_digest);
        let keys = params.into_keys();
        let vk_hash = Some(*blake3::hash(&vk_to_bytes(keys.vk())).as_bytes());
        Ok((
            Some(keys),
            Report {
                degree,
                circuit_digest,
                steps,
                vk_hash,
            },
        ))
    }
}

fn check_step<P: ark_serialize::CanonicalSerialize + ark_serialize::CanonicalDeserialize>(
    step: &Step<P>,
    phase: u8,
    index: u32,
    challenge: &[u8; 32],
    response: &[u8; 32],
) -> Result<(), Error> {
    if step.phase != phase || step.index != index {
        return Err(Error::Invalid("step is not in the position it claims"));
    }
    if &step.challenge != challenge || &step.response != response {
        return Err(Error::Invalid("step does not describe the files around it"));
    }
    if step.attestation.is_some() && step.attested_by().is_none() {
        return Err(Error::Invalid("attestation does not verify"));
    }
    Ok(())
}

fn summarize<P: ark_serialize::CanonicalSerialize + ark_serialize::CanonicalDeserialize>(
    step: &Step<P>,
) -> StepSummary {
    StepSummary {
        phase: step.phase,
        index: step.index,
        beacon: step.is_beacon().then(|| step.beacon.clone()),
        name: step.name.clone(),
        attested_by: step.attested_by(),
        response: step.response,
    }
}

/// Prove and verify one real membership statement with the finished keys, and
/// check that a statement the witness does not satisfy fails. Cheap, and it
/// catches the whole class of ways a ceremony can end with parameters that
/// verify against each other but do not fit the circuit.
pub fn self_test(keys: &MembershipKeys) -> Result<(), Error> {
    use cv_core::identity::{
        MembershipStatement, MembershipWitness, TAG_BALLOT, commitment, nullifier,
        prove_membership, verify_membership,
    };
    use cv_core::registry::RegistryTree;

    let secret = Fr::from(20260904u64);
    let mut tree = RegistryTree::new();
    tree.push(Fr::from(1u64));
    let index = tree.push(commitment(&secret));
    let siblings = tree.path(index).expect("leaf is in the tree");
    let content_id = [0x5au8; 32];
    let statement = MembershipStatement::new(
        tree.root(),
        nullifier(&secret, TAG_BALLOT, &Fr::from(0u64)),
        TAG_BALLOT,
        None,
        &content_id,
    );
    let witness = MembershipWitness {
        secret,
        index,
        siblings,
    };
    let proof = prove_membership(keys, &statement, &witness, &content_id)
        .map_err(|_| Error::Invalid("the self-test witness does not satisfy the circuit"))?;
    if !verify_membership(&keys.verifier, &statement, &proof) {
        return Err(Error::Invalid(
            "the finished keys do not verify a proof they just made",
        ));
    }
    let mut false_statement = statement;
    false_statement.nullifier += Fr::from(1u64);
    if verify_membership(&keys.verifier, &false_statement, &proof) {
        return Err(Error::Invalid("the finished keys verify a false statement"));
    }
    Ok(())
}
