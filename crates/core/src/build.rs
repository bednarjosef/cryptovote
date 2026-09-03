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
    let author = nullifier(&p.secret, TAG_AUTHOR, &Fr::from(0u64));
    let mut i = Initiative {
        text,
        registry_root: p.registry_root,
        threshold_n,
        support_deadline_block,
        secrecy,
        author,
        proof: ZERO_PROOF,
    };
    let content_id = i.content_id();
    let stmt = MembershipStatement::new(p.registry_root, author, TAG_AUTHOR, None, &content_id);
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
    let n = nullifier(&p.secret, TAG_NODE, &Fr::from(0u64));
    let mut r = NodeRegistration {
        node_key,
        mix_key,
        endpoint,
        operator,
        country,
        asn,
        registry_root: p.registry_root,
        nullifier: n,
        proof: ZERO_PROOF,
    };
    let content_id = r.content_id();
    let stmt = MembershipStatement::new(p.registry_root, n, TAG_NODE, None, &content_id);
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

/// SPEC §6.8.
pub fn build_witness(node: &SigningKey, content_id: Id, vote_id: Id) -> Witness {
    let mut payload = content_id.to_vec();
    payload.extend_from_slice(&vote_id);
    Witness {
        content_id,
        vote_id,
        node_key: node.public_key(),
        signature: node.sign(Domain::Witness, &payload),
    }
}
