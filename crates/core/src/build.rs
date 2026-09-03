//! Participant-side constructors for proof-bearing items (SPEC §6). Pure
//! functions from a secret, a registry path and the referenced objects to
//! canonical items; the client library wraps them with storage and network.

use crate::identity::*;
use crate::items::*;
use cv_crypto::field::Fr;
use cv_crypto::groth16::{MembershipKeys, Unsatisfiable};
use cv_crypto::sig::{Domain, SigningKey};

/// An enrolled participant's proving material.
#[derive(Clone, Debug)]
pub struct Participant {
    pub secret: Fr,
    /// The Issuer whose Registry this material proves membership of.
    pub issuer_key: [u8; 32],
    pub registry_root: Fr,
    pub index: u32,
    pub siblings: [Fr; crate::constants::REGISTRY_DEPTH],
}

impl Participant {
    fn witness(&self) -> MembershipWitness {
        MembershipWitness {
            secret: self.secret,
            index: self.index,
            siblings: self.siblings,
        }
    }
}

const ZERO_PROOF: Proof = Proof([0u8; 128]);

/// Build a ballot for `vote` with the given payload (SPEC §6.4). Under
/// `secrecy = none` the payload is the one-byte option index. The result is
/// deterministic: identical bytes on every call (A20).
pub fn build_ballot(
    keys: &MembershipKeys,
    p: &Participant,
    vote: &VoteDefinition,
    payload: Vec<u8>,
) -> Result<Ballot, Unsatisfiable> {
    let vote_id = vote.vote_id();
    let n = nullifier(&p.secret, TAG_BALLOT, &cv_crypto::field::fr_mod(&vote_id));
    let mut b = Ballot {
        vote_id,
        nullifier: n,
        payload,
        proof: ZERO_PROOF,
    };
    let content_id = b.content_id();
    let stmt =
        MembershipStatement::new(p.registry_root, n, TAG_BALLOT, Some(&vote_id), &content_id);
    b.proof = prove_membership(keys, &stmt, &p.witness(), &content_id)?;
    Ok(b)
}

pub fn plaintext_ballot(
    keys: &MembershipKeys,
    p: &Participant,
    vote: &VoteDefinition,
    option_index: u8,
) -> Result<Ballot, Unsatisfiable> {
    build_ballot(keys, p, vote, vec![option_index])
}

/// SPEC §6.3.
pub fn build_support(
    keys: &MembershipKeys,
    p: &Participant,
    initiative_id: &Id,
) -> Result<Support, Unsatisfiable> {
    let n = nullifier(
        &p.secret,
        TAG_SUPPORT,
        &cv_crypto::field::fr_mod(initiative_id),
    );
    let mut s = Support {
        initiative_id: *initiative_id,
        nullifier: n,
        proof: ZERO_PROOF,
    };
    let content_id = s.content_id();
    let stmt = MembershipStatement::new(
        p.registry_root,
        n,
        TAG_SUPPORT,
        Some(initiative_id),
        &content_id,
    );
    s.proof = prove_membership(keys, &stmt, &p.witness(), &content_id)?;
    Ok(s)
}

/// SPEC §6.2. `threshold_n` must be the protocol value for the root.
pub fn build_initiative(
    keys: &MembershipKeys,
    p: &Participant,
    text: String,
    threshold_n: u32,
    support_deadline_block: u32,
    secrecy: Secrecy,
) -> Result<Initiative, Unsatisfiable> {
    // Scoped to the Issuer: a pseudonym inside one electorate, and nothing
    // that links the same person's initiatives across electorates (A50).
    let author = nullifier(
        &p.secret,
        TAG_AUTHOR,
        &cv_crypto::field::fr_mod(&p.issuer_key),
    );
    let mut i = Initiative {
        text,
        issuer_key: p.issuer_key,
        registry_root: p.registry_root,
        threshold_n,
        support_deadline_block,
        secrecy,
        author,
        proof: ZERO_PROOF,
    };
    let content_id = i.content_id();
    let stmt = MembershipStatement::new(
        p.registry_root,
        author,
        TAG_AUTHOR,
        Some(&p.issuer_key),
        &content_id,
    );
    i.proof = prove_membership(keys, &stmt, &p.witness(), &content_id)?;
    Ok(i)
}

/// SPEC §6.7.
#[allow(clippy::too_many_arguments)]
pub fn build_node_registration(
    keys: &MembershipKeys,
    p: &Participant,
    node_key: [u8; 32],
    mix_key: [u8; 32],
    endpoint: String,
    operator: String,
    country: [u8; 2],
    asn: u32,
) -> Result<NodeRegistration, Unsatisfiable> {
    // One node registration per person **per electorate** (A50), so someone
    // enrolled with two Issuers can serve both without invalidating either.
    let n = nullifier(
        &p.secret,
        TAG_NODE,
        &cv_crypto::field::fr_mod(&p.issuer_key),
    );
    let mut r = NodeRegistration {
        node_key,
        mix_key,
        endpoint,
        operator,
        country,
        asn,
        issuer_key: p.issuer_key,
        registry_root: p.registry_root,
        nullifier: n,
        proof: ZERO_PROOF,
    };
    let content_id = r.content_id();
    let stmt = MembershipStatement::new(
        p.registry_root,
        n,
        TAG_NODE,
        Some(&p.issuer_key),
        &content_id,
    );
    r.proof = prove_membership(keys, &stmt, &p.witness(), &content_id)?;
    Ok(r)
}

/// Sign a VoteDefinition with an authority key (SPEC §6.1). The signature
/// field of `origin` is overwritten.
pub fn sign_vote_definition(authority: &SigningKey, mut v: VoteDefinition) -> VoteDefinition {
    v.origin = Origin::Authority {
        authority_key: authority.public_key(),
        signature: [0u8; 64],
    };
    let vote_id = v.vote_id();
    v.origin = Origin::Authority {
        authority_key: authority.public_key(),
        signature: authority.sign(Domain::Vote, &vote_id),
    };
    v
}

/// Register as a key party (SPEC §6.6): generates the party's modulus, the
/// ElGamal key pair and the timed commitment. Returns the item and the
/// secret `sk` the party must keep to publish its share after close.
pub fn build_keyparty<R: rand::RngCore + rand::CryptoRng>(
    keys: &MembershipKeys,
    p: &Participant,
    vote_id: &Id,
    delay_t: u64,
    rng: &mut R,
) -> Result<(KeyParty, [u8; 32]), Unsatisfiable> {
    let (pubp, _secret) = cv_vtc::generate_party(rng, delay_t);
    let (sk, pk) = cv_vtc::keygen(rng);
    let c = cv_vtc::commit(&sk, vote_id, &pubp, rng);
    let big = |x: &cv_vtc::BigUint| Box::new(cv_vtc::bigint256(x).expect("2048-bit values fit"));
    let n = nullifier(&p.secret, TAG_KEYPARTY, &cv_crypto::field::fr_mod(vote_id));
    let mut kp = KeyParty {
        vote_id: *vote_id,
        pk: cv_vtc::point_to_bytes(&pk),
        modulus: big(&pubp.n),
        g: big(&pubp.g),
        h: big(&pubp.h),
        poe: big(&pubp.poe),
        delay_t,
        share_commitments: c.share_commitments,
        puzzles: c
            .puzzles
            .iter()
            .map(|z| Puzzle {
                u: big(&z.u),
                ct: z.ct,
            })
            .collect(),
        openings: c
            .openings
            .iter()
            .map(|o| Opening {
                share: o.share,
                r: big(&o.r),
            })
            .collect(),
        registry_root: p.registry_root,
        nullifier: n,
        proof: ZERO_PROOF,
    };
    let content_id = kp.content_id();
    let stmt =
        MembershipStatement::new(p.registry_root, n, TAG_KEYPARTY, Some(vote_id), &content_id);
    kp.proof = prove_membership(keys, &stmt, &p.witness(), &content_id)?;
    Ok((kp, sk.to_bytes()))
}

/// Encrypted ballot for a `keyparties` vote (SPEC §6.4, §11.2).
pub fn keyparties_ballot(
    keys: &MembershipKeys,
    p: &Participant,
    vote: &VoteDefinition,
    parties: &[(Id, [u8; 32])],
    option: u8,
) -> Result<Ballot, Unsatisfiable> {
    let mut parties: Vec<(Id, [u8; 32])> = parties.to_vec();
    parties.sort();
    parties.dedup_by(|a, b| a.0 == b.0);
    let vote_id = vote.vote_id();
    let r = crate::keyparties::ballot_randomness(&p.secret, &vote_id);
    let pks: Vec<[u8; 32]> = parties.iter().map(|x| x.1).collect();
    let (c1, c2) =
        crate::keyparties::encrypt_option(&pks, option, &r).expect("party keys were validated");
    let payload = KeyPartiesPayload {
        party_ids: parties.iter().map(|x| x.0).collect(),
        c1,
        c2,
    }
    .encode();
    build_ballot(keys, p, vote, payload)
}
