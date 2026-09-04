//! Phase 2 — the circuit-specific half (SPEC §18.4).
//!
//! Phase 1 leaves powers of a secret `τ` and the two secrets `α, β`. Phase 2
//! turns those into a proving and verifying key for **one** circuit, and
//! randomises the one remaining secret, `δ`, that the phase-1 output does not
//! contain.
//!
//! The split exists because the key contains sums like `βuᵢ(τ) + αvᵢ(τ) +
//! wᵢ(τ)`: once that sum is formed, no later participant can multiply `α` or
//! `β` into it, because the parts are no longer separable. So `α, β, τ` are
//! fixed first (phase 1, circuit-independent and reusable), the sum is formed
//! by a computation anyone can repeat (`prepare`, no secrets at all), and
//! only `δ` is left to randomise (phase 2, per circuit).
//!
//! **Both phases matter.** Whoever knows `δ` can forge a proof of any
//! statement; so can whoever knows `τ, α, β`, because a single `[x/δ]₁` term
//! whose `x` they can compute hands them `[1/δ]₁`. One honest contributor is
//! needed in each phase, not in one of the two.
//!
//! `γ` is fixed to 1, as in every deployed Groth16 ceremony: the public-input
//! terms it scales are all published anyway, and dividing them by a secret
//! adds nothing an attacker does not already have.

use ark_bn254::{Fr, G1Affine, G1Projective, G2Affine, G2Projective};
use ark_ec::{AffineRepr, CurveGroup, VariableBaseMSM};
use ark_ff::{Field, One, UniformRand, Zero};
use ark_groth16::{ProvingKey, VerifyingKey};
use ark_poly::{EvaluationDomain, GeneralEvaluationDomain};
use ark_relations::gr1cs::{
    ConstraintSynthesizer, ConstraintSystem, OptimizationGoal, R1CS_PREDICATE_LABEL, SynthesisMode,
};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use cv_crypto::groth16::MembershipKeys;
use rand::{CryptoRng, RngCore};

use crate::Error;
use crate::phase1::{Accumulator, beacon_rng};
use crate::pok::{DELTA, Pok, is_scaled_by, same_ratio};

const B_H: u8 = 32;
const B_L: u8 = 33;

/// The phase-2 parameters after some number of contributions. Everything but
/// `delta_g1`, `delta_g2`, `h_query` and `l_query` is fixed by `prepare` and
/// may never move again.
#[derive(Clone, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize)]
pub struct Phase2 {
    /// Binds these parameters to one R1CS. Parameters for a circuit with one
    /// constraint removed would prove a weaker statement just as happily.
    pub circuit_digest: [u8; 32],
    pub alpha_g1: G1Affine,
    pub beta_g1: G1Affine,
    pub beta_g2: G2Affine,
    pub gamma_g2: G2Affine,
    pub gamma_abc_g1: Vec<G1Affine>,
    pub a_query: Vec<G1Affine>,
    pub b_g1_query: Vec<G1Affine>,
    pub b_g2_query: Vec<G2Affine>,
    pub delta_g1: G1Affine,
    pub delta_g2: G2Affine,
    pub h_query: Vec<G1Affine>,
    pub l_query: Vec<G1Affine>,
}

/// BLAKE3 over the R1CS: sizes first, then every coefficient of every matrix
/// in order.
fn circuit_digest(
    num_instance: usize,
    num_witness: usize,
    matrices: &[ark_relations::utils::matrix::Matrix<Fr>],
) -> [u8; 32] {
    let mut h = blake3::Hasher::new_derive_key("cryptovote/v1/ceremony/circuit");
    h.update(&(num_instance as u64).to_le_bytes());
    h.update(&(num_witness as u64).to_le_bytes());
    for m in matrices {
        h.update(&(m.len() as u64).to_le_bytes());
        for row in m {
            h.update(&(row.len() as u64).to_le_bytes());
            for (coeff, index) in row {
                let mut b = Vec::new();
                coeff.serialize_compressed(&mut b).expect("serialize Fr");
                h.update(&b);
                h.update(&(*index as u64).to_le_bytes());
            }
        }
    }
    *h.finalize().as_bytes()
}

/// Lagrange coefficients at `τ`, in the group. The vector `([τⁱ]) i < d` is
/// the domain's DFT of the vector `([Lᵢ(τ)])`, so one inverse FFT over group
/// elements turns powers of a secret nobody knows into evaluations of the
/// Lagrange basis at that same secret.
/// (The four inverse FFTs are what `prepare` spends its time on: a couple of
/// minutes at the degree the membership circuit needs. It runs once per
/// ceremony and once inside every verification of it.)
fn lagrange<T>(domain: &GeneralEvaluationDomain<Fr>, powers: Vec<T>) -> Vec<T>
where
    T: ark_poly::domain::DomainCoeff<Fr>,
{
    let mut v = powers;
    domain.ifft_in_place(&mut v);
    v
}

/// The evaluation-domain size a circuit needs — and therefore the degree its
/// phase 1 has to reach. `cv-ceremony new` prints it so that a ceremony is
/// not started at a size the circuit cannot use.
pub fn domain_size_for<C: ConstraintSynthesizer<Fr>>(circuit: C) -> Option<usize> {
    let cs = ConstraintSystem::new_ref();
    cs.set_optimization_goal(OptimizationGoal::Constraints);
    cs.set_mode(SynthesisMode::Setup);
    circuit.generate_constraints(cs.clone()).ok()?;
    cs.finalize();
    GeneralEvaluationDomain::<Fr>::new(cs.num_constraints() + cs.num_instance_variables())
        .map(|d| d.size())
}

/// Turn a phase-1 accumulator into the starting phase-2 parameters for one
/// circuit, with `δ = 1`. Deterministic and secret-free: every verifier runs
/// exactly this and compares, which is what makes the step trustworthy.
pub fn prepare<C: ConstraintSynthesizer<Fr>>(
    acc: &Accumulator,
    circuit: C,
) -> Result<Phase2, Error> {
    acc.check_structure()?;
    let cs = ConstraintSystem::new_ref();
    cs.set_optimization_goal(OptimizationGoal::Constraints);
    cs.set_mode(SynthesisMode::Setup);
    circuit
        .generate_constraints(cs.clone())
        .map_err(|_| Error::Invalid("circuit does not synthesize"))?;
    cs.finalize();

    let num_instance = cs.num_instance_variables();
    let num_witness = cs.num_witness_variables();
    let num_constraints = cs.num_constraints();
    let qap_num_variables = (num_instance - 1) + num_witness;
    let all = cs
        .to_matrices()
        .map_err(|_| Error::Invalid("circuit produced no matrices"))?;
    let matrices = &all[R1CS_PREDICATE_LABEL];

    let domain = GeneralEvaluationDomain::<Fr>::new(num_constraints + num_instance)
        .ok_or(Error::Invalid("circuit is too large for any domain"))?;
    let d = domain.size();
    if acc.degree() < d {
        return Err(Error::DegreeTooSmall {
            have: acc.degree(),
            need: d,
        });
    }
    // The domain's vanishing polynomial is Xᵈ − 1. If τᵈ = 1 it vanishes at
    // τ, the whole h query is the identity, and the parameters are unsound —
    // so this is checked rather than assumed, even though a random τ lands
    // there with probability d/r.
    if acc.tau_g1[d] == G1Affine::generator() {
        return Err(Error::Invalid(
            "τ is a root of the domain's vanishing polynomial",
        ));
    }

    let lag_g1 = lagrange(
        &domain,
        acc.tau_g1[..d].iter().map(|p| p.into_group()).collect(),
    );
    let lag_g2 = lagrange(
        &domain,
        acc.tau_g2[..d].iter().map(|p| p.into_group()).collect(),
    );
    let lag_alpha = lagrange(
        &domain,
        acc.alpha_tau_g1[..d]
            .iter()
            .map(|p| p.into_group())
            .collect(),
    );
    let lag_beta = lagrange(
        &domain,
        acc.beta_tau_g1[..d]
            .iter()
            .map(|p| p.into_group())
            .collect(),
    );

    // uᵢ(τ), vᵢ(τ) and βuᵢ(τ) + αvᵢ(τ) + wᵢ(τ), one entry per wire.
    //
    // The matrices arrive by constraint, but every wire's value is a sum over
    // the constraints it appears in, so they are transposed once and each
    // wire becomes a single multi-scalar multiplication. Written the obvious
    // way — one scalar multiplication per non-zero coefficient — this loop
    // dominated everything else: inlining linear combinations leaves the
    // membership circuit with hundreds of thousands of them.
    let n = qap_num_variables + 1;
    let lag_g1 = G1Projective::normalize_batch(&lag_g1);
    let lag_g2 = G2Projective::normalize_batch(&lag_g2);
    let lag_alpha = G1Projective::normalize_batch(&lag_alpha);
    let lag_beta = G1Projective::normalize_batch(&lag_beta);

    let mut a_terms: Vec<Vec<(usize, Fr)>> = vec![Vec::new(); n];
    let mut b_terms: Vec<Vec<(usize, Fr)>> = vec![Vec::new(); n];
    let mut c_terms: Vec<Vec<(usize, Fr)>> = vec![Vec::new(); n];
    for j in 0..num_constraints {
        for (coeff, index) in &matrices[0][j] {
            a_terms[*index].push((j, *coeff));
        }
        for (coeff, index) in &matrices[1][j] {
            b_terms[*index].push((j, *coeff));
        }
        for (coeff, index) in &matrices[2][j] {
            c_terms[*index].push((j, *coeff));
        }
    }

    let msm_g1 = |terms: &[(&[G1Affine], &[(usize, Fr)])]| -> G1Projective {
        let mut bases = Vec::new();
        let mut scalars = Vec::new();
        for (lag, ts) in terms {
            for (j, coeff) in *ts {
                bases.push(lag[*j]);
                scalars.push(*coeff);
            }
        }
        G1Projective::msm(&bases, &scalars).expect("equal lengths")
    };

    let mut a = Vec::with_capacity(n);
    let mut b_g1 = Vec::with_capacity(n);
    let mut b_g2 = Vec::with_capacity(n);
    let mut abc = Vec::with_capacity(n);
    for i in 0..n {
        let mut ai = msm_g1(&[(&lag_g1, &a_terms[i])]);
        // βuᵢ + αvᵢ + wᵢ in one multiplication: the A terms against [βτ], the
        // B terms against [ατ], the C terms against [τ].
        let mut abci = msm_g1(&[
            (&lag_beta, &a_terms[i]),
            (&lag_alpha, &b_terms[i]),
            (&lag_g1, &c_terms[i]),
        ]);
        // The libsnark reduction gives each public input its own extra row,
        // so that the A polynomials stay linearly independent.
        if i < num_instance {
            ai += lag_g1[num_constraints + i];
            abci += lag_beta[num_constraints + i];
        }
        a.push(ai);
        abc.push(abci);
        b_g1.push(msm_g1(&[(&lag_g1, &b_terms[i])]));
        let (bases, scalars): (Vec<G2Affine>, Vec<Fr>) = b_terms[i]
            .iter()
            .map(|(j, coeff)| (lag_g2[*j], *coeff))
            .unzip();
        b_g2.push(G2Projective::msm(&bases, &scalars).expect("equal lengths"));
    }

    // [τⁱ·t(τ)]₁ with t(X) = Xᵈ − 1, the vanishing polynomial of the domain.
    let h: Vec<G1Projective> = (0..d - 1)
        .map(|i| acc.tau_g1[i + d].into_group() - acc.tau_g1[i].into_group())
        .collect();

    let abc = G1Projective::normalize_batch(&abc);
    Ok(Phase2 {
        circuit_digest: circuit_digest(num_instance, num_witness, matrices),
        alpha_g1: acc.alpha_tau_g1[0],
        beta_g1: acc.beta_tau_g1[0],
        beta_g2: acc.beta_g2,
        gamma_g2: G2Affine::generator(),
        gamma_abc_g1: abc[..num_instance].to_vec(),
        a_query: G1Projective::normalize_batch(&a),
        b_g1_query: G1Projective::normalize_batch(&b_g1),
        b_g2_query: G2Projective::normalize_batch(&b_g2),
        delta_g1: G1Affine::generator(),
        delta_g2: G2Affine::generator(),
        h_query: G1Projective::normalize_batch(&h),
        l_query: abc[num_instance..].to_vec(),
    })
}

impl Phase2 {
    pub fn digest(&self) -> [u8; 32] {
        let mut bytes = Vec::new();
        self.serialize_compressed(&mut bytes)
            .expect("serialize parameters");
        *blake3::hash(&bytes).as_bytes()
    }

    /// The parts `prepare` fixed. A contribution may only touch `δ` and the
    /// two queries divided by it.
    fn fixed_eq(&self, other: &Phase2) -> bool {
        self.circuit_digest == other.circuit_digest
            && self.alpha_g1 == other.alpha_g1
            && self.beta_g1 == other.beta_g1
            && self.beta_g2 == other.beta_g2
            && self.gamma_g2 == other.gamma_g2
            && self.gamma_abc_g1 == other.gamma_abc_g1
            && self.a_query == other.a_query
            && self.b_g1_query == other.b_g1_query
            && self.b_g2_query == other.b_g2_query
    }

    /// Assemble the arkworks proving key. The verifying key comes with it;
    /// `MembershipKeys` derives the prepared form.
    pub fn into_keys(self) -> MembershipKeys {
        MembershipKeys::from_proving_key(ProvingKey {
            vk: VerifyingKey {
                alpha_g1: self.alpha_g1,
                beta_g2: self.beta_g2,
                gamma_g2: self.gamma_g2,
                delta_g2: self.delta_g2,
                gamma_abc_g1: self.gamma_abc_g1,
            },
            beta_g1: self.beta_g1,
            delta_g1: self.delta_g1,
            a_query: self.a_query,
            b_g1_query: self.b_g1_query,
            b_g2_query: self.b_g2_query,
            h_query: self.h_query,
            l_query: self.l_query,
        })
    }
}

/// Contribute to phase 2: multiply `δ` in, divide the two queries that carry
/// `1/δ` by the same amount.
pub fn contribute<R: RngCore + CryptoRng>(
    p: &Phase2,
    challenge: &[u8; 32],
    rng: &mut R,
) -> (Phase2, Pok) {
    let delta = loop {
        let x = Fr::rand(rng);
        if !x.is_zero() && x != Fr::one() {
            break x;
        }
    };
    let inv = delta.inverse().expect("nonzero");
    let mut next = p.clone();
    next.delta_g1 = (p.delta_g1 * delta).into_affine();
    next.delta_g2 = (p.delta_g2 * delta).into_affine();
    next.h_query =
        G1Projective::normalize_batch(&p.h_query.iter().map(|q| *q * inv).collect::<Vec<_>>());
    next.l_query =
        G1Projective::normalize_batch(&p.l_query.iter().map(|q| *q * inv).collect::<Vec<_>>());
    let pok = Pok::prove(&delta, challenge, DELTA, rng);
    (next, pok)
}

/// A beacon step: the same operation with public randomness (SPEC §18.5).
pub fn contribute_beacon(p: &Phase2, challenge: &[u8; 32], source: &[u8]) -> (Phase2, Pok) {
    contribute(p, challenge, &mut beacon_rng(challenge, source))
}

/// Check that the starting parameters really are what `prepare` produces for
/// this accumulator and this circuit.
pub fn verify_initial<C: ConstraintSynthesizer<Fr>>(
    acc: &Accumulator,
    circuit: C,
    claimed: &Phase2,
) -> Result<(), Error> {
    if &prepare(acc, circuit)? != claimed {
        return Err(Error::Invalid(
            "starting parameters are not the ones this accumulator and circuit give",
        ));
    }
    Ok(())
}

/// Check one phase-2 step.
pub fn verify(prev: &Phase2, next: &Phase2, pok: &Pok, challenge: &[u8; 32]) -> Result<(), Error> {
    if !prev.fixed_eq(next) {
        return Err(Error::Invalid("step changed parameters it may not touch"));
    }
    if prev.h_query.len() != next.h_query.len() || prev.l_query.len() != next.l_query.len() {
        return Err(Error::Invalid("step changed the size of a query"));
    }
    if prev.digest() != *challenge {
        return Err(Error::Invalid("step answers a different challenge"));
    }
    if !pok.verify(challenge, DELTA) {
        return Err(Error::Invalid(
            "contributor did not prove it knew its secret",
        ));
    }
    let ratio = pok.ratio(challenge, DELTA);
    if next.delta_g1.is_zero() || next.delta_g2.is_zero() {
        return Err(Error::Invalid("δ is the identity"));
    }
    if !same_ratio((prev.delta_g1, next.delta_g1), ratio) {
        return Err(Error::Invalid("δ did not move by the proven secret"));
    }
    if !same_ratio(
        (G1Affine::generator(), next.delta_g1),
        (G2Affine::generator(), next.delta_g2),
    ) {
        return Err(Error::Invalid("δ differs between G1 and G2"));
    }
    // The queries carry 1/δ, so they must move the other way, by exactly the
    // same secret: prev = δⱼ · next.
    let d = next.digest();
    if !is_scaled_by(&next.h_query, &prev.h_query, ratio, &d, B_H) {
        return Err(Error::Invalid("the h query was not divided by δ"));
    }
    if !is_scaled_by(&next.l_query, &prev.l_query, ratio, &d, B_L) {
        return Err(Error::Invalid("the l query was not divided by δ"));
    }
    Ok(())
}

/// Check a beacon step by recomputing it from its public value.
pub fn verify_beacon(
    prev: &Phase2,
    next: &Phase2,
    pok: &Pok,
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
