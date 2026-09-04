//! A ceremony end to end: contribute, verify every step, replay the
//! transcript, and use the keys that come out.

use ark_bn254::{Bn254, Fr};
use ark_ff::{Field, One, UniformRand};
use ark_groth16::Groth16;
use ark_r1cs_std::alloc::AllocVar;
use ark_r1cs_std::eq::EqGadget;
use ark_r1cs_std::fields::fp::FpVar;
use ark_relations::gr1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
use ark_serialize::CanonicalSerialize;
use cv_ceremony::phase1::{self, Accumulator, Phase1Pok};
use cv_ceremony::phase2::{self, Phase2};
use cv_ceremony::pok::Pok;
use cv_ceremony::transcript::{
    KIND_PHASE1_ACC, KIND_PHASE1_STEP, KIND_PHASE2_PARAMS, KIND_PHASE2_STEP, Step, encode,
};
use cv_ceremony::{Transcript, self_test};
use cv_crypto::circuit::MembershipCircuit;
use cv_crypto::groth16::{self as g16, vk_to_bytes};
use cv_crypto::sig::SigningKey;
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;

fn rng(seed: u8) -> ChaCha20Rng {
    ChaCha20Rng::from_seed([seed; 32])
}

/// A circuit small enough to run the whole ceremony in milliseconds:
/// `x³ = y` for a public `y`.
#[derive(Clone)]
struct Cube {
    y: Fr,
    x: Fr,
}

impl Cube {
    fn blank() -> Self {
        Cube {
            y: Fr::one(),
            x: Fr::one(),
        }
    }
}

impl ConstraintSynthesizer<Fr> for Cube {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        let y = FpVar::new_input(cs.clone(), || Ok(self.y))?;
        let x = FpVar::new_witness(cs.clone(), || Ok(self.x))?;
        let x2 = &x * &x;
        let x3 = &x2 * &x;
        x3.enforce_equal(&y)?;
        Ok(())
    }
}

/// Build a whole ceremony for `circuit` and return the transcript.
fn run_ceremony<C: ConstraintSynthesizer<Fr>>(
    degree: usize,
    circuit: C,
    contributors: u8,
) -> Transcript {
    let mut t = Transcript::default();
    let mut acc = Accumulator::new(degree);
    t.phase1.push(encode(KIND_PHASE1_ACC, &acc));
    for i in 0..contributors {
        let challenge = acc.digest();
        let (next, pok) = phase1::contribute(&acc, &challenge, &mut rng(i + 1));
        let mut step = Step::new(1, i as u32, challenge, next.digest(), pok);
        step.name = format!("contributor {i}");
        step.sign(&SigningKey::from_seed(&[i + 100; 32]));
        t.phase1_steps.push(encode(KIND_PHASE1_STEP, &step));
        t.phase1.push(encode(KIND_PHASE1_ACC, &next));
        acc = next;
    }
    // Phase 1 closes on a beacon.
    let challenge = acc.digest();
    let (next, pok) = phase1::contribute_beacon(&acc, &challenge, b"bitcoin block 900000");
    let mut step = Step::new(1, contributors as u32, challenge, next.digest(), pok);
    step.beacon = b"bitcoin block 900000".to_vec();
    t.phase1_steps.push(encode(KIND_PHASE1_STEP, &step));
    t.phase1.push(encode(KIND_PHASE1_ACC, &next));
    acc = next;

    let mut params = phase2::prepare(&acc, circuit).expect("prepare");
    t.phase2.push(encode(KIND_PHASE2_PARAMS, &params));
    for i in 0..contributors {
        let challenge = params.digest();
        let (next, pok) = phase2::contribute(&params, &challenge, &mut rng(i + 50));
        let mut step = Step::new(2, i as u32, challenge, next.digest(), pok);
        step.name = format!("contributor {i}");
        t.phase2_steps.push(encode(KIND_PHASE2_STEP, &step));
        t.phase2.push(encode(KIND_PHASE2_PARAMS, &next));
        params = next;
    }
    let challenge = params.digest();
    let (next, pok) = phase2::contribute_beacon(&params, &challenge, b"bitcoin block 900144");
    let mut step = Step::new(2, contributors as u32, challenge, next.digest(), pok);
    step.beacon = b"bitcoin block 900144".to_vec();
    t.phase2_steps.push(encode(KIND_PHASE2_STEP, &step));
    t.phase2.push(encode(KIND_PHASE2_PARAMS, &next));
    t
}

#[test]
fn parameters_from_a_ceremony_prove_and_verify() {
    let t = run_ceremony(8, Cube::blank(), 3);
    let (keys, report) = t.replay(Cube::blank()).expect("transcript replays");
    let keys = keys.expect("a finished ceremony has keys");
    report
        .usable()
        .expect("both phases have a secret contribution");
    assert_eq!(report.secret_contributions(1), 3);
    assert_eq!(report.secret_contributions(2), 3);
    assert_eq!(
        report.steps.len(),
        8,
        "three contributions and a beacon, twice"
    );
    // Every phase-1 step here was attested; the beacon was not.
    assert_eq!(
        report
            .steps
            .iter()
            .filter(|s| s.attested_by.is_some())
            .count(),
        3
    );

    let x = Fr::from(7u64);
    let y = x * x * x;
    let proof =
        Groth16::<Bn254>::create_random_proof_with_reduction(Cube { y, x }, &keys.pk, &mut rng(9))
            .expect("prove");
    assert!(Groth16::<Bn254>::verify_proof(&keys.verifier.pvk, &proof, &[y]).unwrap());
    // A different public input is a different statement.
    assert!(!Groth16::<Bn254>::verify_proof(&keys.verifier.pvk, &proof, &[y + Fr::one()]).unwrap());
}

#[test]
fn every_contribution_changes_the_keys() {
    let a = run_ceremony(8, Cube::blank(), 2);
    let b = run_ceremony(8, Cube::blank(), 3);
    let ka = a.replay(Cube::blank()).unwrap().0.unwrap();
    let kb = b.replay(Cube::blank()).unwrap().0.unwrap();
    assert_ne!(vk_to_bytes(ka.vk()), vk_to_bytes(kb.vk()));

    // Proofs do not carry across ceremonies: this is what makes the pinned
    // verifying-key hash the thing that matters at a deployment.
    let x = Fr::from(3u64);
    let y = x * x * x;
    let proof =
        Groth16::<Bn254>::create_random_proof_with_reduction(Cube { y, x }, &ka.pk, &mut rng(9))
            .unwrap();
    assert!(Groth16::<Bn254>::verify_proof(&ka.verifier.pvk, &proof, &[y]).unwrap());
    assert!(!Groth16::<Bn254>::verify_proof(&kb.verifier.pvk, &proof, &[y]).unwrap());
}

#[test]
fn a_step_that_did_not_happen_is_caught() {
    let good = run_ceremony(8, Cube::blank(), 2);

    // Drop the middle phase-1 contribution but keep its accumulator.
    let mut skipped = good.clone();
    skipped.phase1.remove(1);
    skipped.phase1_steps.remove(1);
    assert!(skipped.replay(Cube::blank()).is_err());

    // Reorder two phase-1 steps.
    let mut swapped = good.clone();
    swapped.phase1.swap(1, 2);
    assert!(swapped.replay(Cube::blank()).is_err());

    // Truncate the ceremony to its first contributor, keeping the rest of the
    // step records: the digests no longer line up.
    let mut truncated = good.clone();
    truncated.phase1.truncate(2);
    assert!(truncated.replay(Cube::blank()).is_err());

    // Claim the beacon came from a value it did not.
    let mut lying_beacon = good.clone();
    let last = lying_beacon.phase1_steps.len() - 1;
    let mut step: Step<Phase1Pok> =
        cv_ceremony::transcript::decode(KIND_PHASE1_STEP, &lying_beacon.phase1_steps[last])
            .unwrap();
    step.beacon = b"a block that was never mined".to_vec();
    lying_beacon.phase1_steps[last] = encode(KIND_PHASE1_STEP, &step);
    assert!(lying_beacon.replay(Cube::blank()).is_err());
}

#[test]
fn a_forged_attestation_is_caught() {
    let mut t = run_ceremony(8, Cube::blank(), 2);
    let mut step: Step<Phase1Pok> =
        cv_ceremony::transcript::decode(KIND_PHASE1_STEP, &t.phase1_steps[0]).unwrap();
    // Someone else's name over the same step.
    step.attestation.as_mut().unwrap().public_key = [3u8; 32];
    t.phase1_steps[0] = encode(KIND_PHASE1_STEP, &step);
    assert!(t.replay(Cube::blank()).is_err());
}

#[test]
fn parameters_are_bound_to_one_circuit() {
    let t = run_ceremony(8, Cube::blank(), 1);
    // The same transcript replayed against another circuit must not produce
    // keys: phase 2 fixed the R1CS it was prepared for.
    #[derive(Clone)]
    struct Square {
        y: Fr,
        x: Fr,
    }
    impl ConstraintSynthesizer<Fr> for Square {
        fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
            let y = FpVar::new_input(cs.clone(), || Ok(self.y))?;
            let x = FpVar::new_witness(cs.clone(), || Ok(self.x))?;
            (&x * &x).enforce_equal(&y)?;
            Ok(())
        }
    }
    assert!(
        t.replay(Square {
            y: Fr::one(),
            x: Fr::one()
        })
        .is_err()
    );
}

#[test]
fn a_phase_two_step_may_not_touch_the_fixed_parameters() {
    let t = run_ceremony(8, Cube::blank(), 1);
    let mut broken = t.clone();
    let mut params: Phase2 =
        cv_ceremony::transcript::decode(KIND_PHASE2_PARAMS, &broken.phase2[1]).unwrap();
    params.alpha_g1 = (params.alpha_g1 * Fr::from(2u64)).into();
    broken.phase2[1] = encode(KIND_PHASE2_PARAMS, &params);
    assert!(broken.replay(Cube::blank()).is_err());

    // And it may not leave the h query where it was while moving δ.
    let mut lazy = t.clone();
    let before: Phase2 =
        cv_ceremony::transcript::decode(KIND_PHASE2_PARAMS, &lazy.phase2[0]).unwrap();
    let mut after: Phase2 =
        cv_ceremony::transcript::decode(KIND_PHASE2_PARAMS, &lazy.phase2[1]).unwrap();
    after.h_query = before.h_query.clone();
    lazy.phase2[1] = encode(KIND_PHASE2_PARAMS, &after);
    assert!(lazy.replay(Cube::blank()).is_err());
}

/// The real thing: the membership circuit of SPEC §5, at the degree a
/// deployment needs, proving a real registry membership statement. Minutes
/// rather than seconds — a gate to run before a real ceremony, not on every
/// change: `cargo test -p cv-ceremony --release -- --ignored`.
#[test]
#[ignore = "runs the full degree-16384 ceremony; minutes"]
fn the_membership_ceremony_produces_working_keys() {
    let degree = phase2::domain_size_for(MembershipCircuit::blank()).expect("domain");
    let t = run_ceremony(degree, MembershipCircuit::blank(), 2);
    let (keys, report) = t.replay(MembershipCircuit::blank()).expect("replay");
    let keys = keys.expect("a finished ceremony has keys");
    report.usable().expect("usable");
    self_test(&keys).expect("the keys prove and verify a real membership statement");

    assert_eq!(report.degree, degree);
    assert_ne!(
        report.vk_hash,
        Some(*blake3::hash(&vk_to_bytes(g16::dev_keys().vk())).as_bytes()),
        "a ceremony key is not the development key"
    );

    // A ballot proved under ceremony keys must not verify under the dev key,
    // and vice versa. This is why the verifying key is pinned.
    let mut bytes = Vec::new();
    keys.vk().serialize_compressed(&mut bytes).unwrap();
    assert_eq!(bytes.len(), vk_to_bytes(g16::dev_keys().vk()).len());
}

/// Several public inputs and a wire used by more than one constraint: the
/// shape the membership circuit has, at a size that runs in milliseconds.
/// The per-public-input extra row of the libsnark reduction is indexed by
/// `num_constraints + i`, so a circuit with one input would not notice if it
/// were wrong.
#[derive(Clone)]
struct Chain {
    xs: [Fr; 3],
    w: Fr,
}

impl Chain {
    fn blank() -> Self {
        Chain {
            xs: [Fr::one(); 3],
            w: Fr::one(),
        }
    }
    fn satisfying(w: u64) -> Self {
        let w = Fr::from(w);
        Chain {
            xs: [w * w, w * w * w, w * w * w * w],
            w,
        }
    }
}

impl ConstraintSynthesizer<Fr> for Chain {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        let inputs: Vec<FpVar<Fr>> = self
            .xs
            .iter()
            .map(|x| FpVar::new_input(cs.clone(), || Ok(*x)))
            .collect::<Result<_, _>>()?;
        let w = FpVar::new_witness(cs.clone(), || Ok(self.w))?;
        let mut acc = &w * &w;
        for x in &inputs {
            acc.enforce_equal(x)?;
            acc = &acc * &w;
        }
        Ok(())
    }
}

#[test]
fn a_circuit_with_several_public_inputs_gets_working_keys() {
    let t = run_ceremony(16, Chain::blank(), 2);
    let keys = t.replay(Chain::blank()).expect("replay").0.unwrap();
    let c = Chain::satisfying(5);
    let public = c.xs.to_vec();
    let proof =
        Groth16::<Bn254>::create_random_proof_with_reduction(c, &keys.pk, &mut rng(3)).unwrap();
    assert!(Groth16::<Bn254>::verify_proof(&keys.verifier.pvk, &proof, &public).unwrap());
    // Move one public input: the proof is for the other statement.
    let mut wrong = public.clone();
    wrong[1] += Fr::one();
    assert!(!Groth16::<Bn254>::verify_proof(&keys.verifier.pvk, &proof, &wrong).unwrap());
}

#[test]
fn a_ceremony_too_small_for_the_circuit_is_refused() {
    let acc = Accumulator::new(8);
    let err = phase2::prepare(&acc, MembershipCircuit::blank()).unwrap_err();
    assert!(matches!(
        err,
        cv_ceremony::Error::DegreeTooSmall { have: 8, .. }
    ));
}

#[test]
fn a_replayed_phase_two_secret_is_rejected() {
    let params = {
        let mut acc = Accumulator::new(8);
        let challenge = acc.digest();
        let (next, _) = phase1::contribute(&acc, &challenge, &mut rng(1));
        acc = next;
        phase2::prepare(&acc, Cube::blank()).unwrap()
    };
    let c1 = params.digest();
    let (p1, pok1) = phase2::contribute(&params, &c1, &mut rng(2));
    let c2 = p1.digest();
    let (p2, _) = phase2::contribute(&p1, &c2, &mut rng(3));
    // The first contributor's proof does not justify the second step.
    assert!(phase2::verify(&p1, &p2, &pok1, &c2).is_err());
    // Nor does a proof made against the right challenge for a different δ.
    let (_, pok_other) = phase2::contribute(&p1, &c2, &mut rng(4));
    assert!(phase2::verify(&p1, &p2, &pok_other, &c2).is_err());
}

#[test]
fn the_transcript_pins_the_keys_that_came_out_of_it() {
    let t = run_ceremony(8, Cube::blank(), 2);
    let (_, a) = t.replay(Cube::blank()).unwrap();
    let (_, b) = t.replay(Cube::blank()).unwrap();
    assert_eq!(a.vk_hash, b.vk_hash, "replay is deterministic");
    let one_more = run_ceremony(8, Cube::blank(), 2);
    assert_eq!(one_more.replay(Cube::blank()).unwrap().1.vk_hash, a.vk_hash);
    assert!(a.vk_hash.is_some());
}

#[test]
fn the_pok_of_one_purpose_is_not_a_pok_of_another() {
    let mut r = rng(11);
    let x = Fr::rand(&mut r);
    let challenge = [5u8; 32];
    let p = Pok::prove(&x, &challenge, cv_ceremony::pok::TAU, &mut r);
    assert!(p.verify(&challenge, cv_ceremony::pok::TAU));
    assert!(!p.verify(&challenge, cv_ceremony::pok::DELTA));
    assert!(x.inverse().is_some());
}

#[test]
fn a_ceremony_in_progress_can_be_checked_before_it_is_extended() {
    // Phase 1 only, no `prepare` yet. A contributor must be able to verify
    // the chain they are about to add to; refusing to say anything until the
    // ceremony is finished would mean contributing blind.
    let mut t = Transcript::default();
    let mut acc = Accumulator::new(8);
    t.phase1.push(encode(KIND_PHASE1_ACC, &acc));
    for i in 0..2u8 {
        let challenge = acc.digest();
        let (next, pok) = phase1::contribute(&acc, &challenge, &mut rng(i + 1));
        let step = Step::new(1, i as u32, challenge, next.digest(), pok);
        t.phase1_steps.push(encode(KIND_PHASE1_STEP, &step));
        t.phase1.push(encode(KIND_PHASE1_ACC, &next));
        acc = next;
    }
    let (keys, report) = t.replay(Cube::blank()).expect("phase 1 alone verifies");
    assert!(keys.is_none() && report.vk_hash.is_none());
    assert_eq!(report.secret_contributions(1), 2);
    assert!(report.usable().is_err(), "not finished, so not usable");

    // A tampered step is caught just as well before phase 2 exists.
    let mut broken = t.clone();
    broken.phase1.swap(1, 2);
    assert!(broken.replay(Cube::blank()).is_err());
}

#[test]
fn a_phase_closed_with_only_a_beacon_is_refused() {
    // A beacon's randomness is public, so a phase made of nothing but beacons
    // has a trapdoor anyone can recompute. It replays fine — every step is
    // valid — and is still not a ceremony.
    let mut t = Transcript::default();
    let acc = Accumulator::new(8);
    t.phase1.push(encode(KIND_PHASE1_ACC, &acc));
    let challenge = acc.digest();
    let (next, pok) = phase1::contribute_beacon(&acc, &challenge, b"a public value");
    let mut step = Step::new(1, 0, challenge, next.digest(), pok);
    step.beacon = b"a public value".to_vec();
    t.phase1_steps.push(encode(KIND_PHASE1_STEP, &step));
    t.phase1.push(encode(KIND_PHASE1_ACC, &next));

    let mut params = phase2::prepare(&next, Cube::blank()).unwrap();
    t.phase2.push(encode(KIND_PHASE2_PARAMS, &params));
    let challenge = params.digest();
    let (p2, pok) = phase2::contribute(&params, &challenge, &mut rng(9));
    let step = Step::new(2, 0, challenge, p2.digest(), pok);
    t.phase2_steps.push(encode(KIND_PHASE2_STEP, &step));
    t.phase2.push(encode(KIND_PHASE2_PARAMS, &p2));
    params = p2;
    let _ = params;

    let (_, report) = t.replay(Cube::blank()).expect("every step is valid");
    assert_eq!(report.secret_contributions(1), 0);
    assert!(report.usable().is_err());
}
