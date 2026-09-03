//! Intrinsic validity rules (SPEC §6). This is the one implementation used by
//! nodes, clients and verifiers. Timing rules (anchors, deadlines) live in
//! `tally`; this module answers "is this item well-formed and proven".

use crate::constants::*;
use crate::context::Context;
use crate::identity::*;
use crate::items::*;
use cv_crypto::field::Fr;
use cv_crypto::sig::{Domain, verify};

/// Why an item is not valid. `MissingReference` means "not decidable yet":
/// the node keeps the item in its orphan pool (SPEC §7.2).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum Invalid {
    #[error("referenced object not known: {0}")]
    MissingReference(Reference),
    #[error("bad structure: {0}")]
    Structure(&'static str),
    #[error("registry root unknown")]
    UnknownRegistry,
    #[error("authority key not recognized")]
    UnknownAuthority,
    #[error("signature does not verify")]
    BadSignature,
    #[error("membership proof does not verify")]
    BadProof,
    #[error("derived vote definition does not match the initiative")]
    DerivationMismatch,
    #[error("dev-mode-only construct in a non-dev context")]
    DevOnly,
    #[error("not implemented in this phase: {0}")]
    NotImplemented(&'static str),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Reference {
    Vote(Id),
    Initiative(Id),
    KeyParty(Id),
    NodeRegistration([u8; 32]),
    Registry(Fr),
    Header(u32),
    /// The initiative's threshold is not (yet) reached in this view.
    DerivedVote(Id),
}

impl std::fmt::Display for Reference {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Reference::Vote(id) => write!(f, "vote {}", hex4(id)),
            Reference::Initiative(id) => write!(f, "initiative {}", hex4(id)),
            Reference::KeyParty(id) => write!(f, "key party {}", hex4(id)),
            Reference::NodeRegistration(k) => write!(f, "node registration {}", hex4(k)),
            Reference::Registry(_) => write!(f, "registry snapshot"),
            Reference::Header(h) => write!(f, "block header at height {h}"),
            Reference::DerivedVote(id) => write!(f, "derived vote of initiative {}", hex4(id)),
        }
    }
}

fn hex4(b: &[u8]) -> String {
    b.iter()
        .take(4)
        .map(|x| format!("{x:02x}"))
        .collect::<String>()
        + "…"
}

/// Validate any item against its context.
pub fn validate(item: &Item, ctx: &impl Context) -> Result<(), Invalid> {
    match item {
        Item::VoteDefinition(v) => validate_vote(v, ctx),
        Item::Initiative(v) => validate_initiative(v, ctx),
        Item::Support(v) => validate_support(v, ctx),
        Item::Ballot(v) => validate_ballot(v, ctx),
        Item::Anchor(v) => validate_anchor(v, ctx),
        Item::KeyParty(v) => validate_keyparty(v, ctx),
        Item::NodeRegistration(v) => validate_node_registration(v, ctx),
        Item::Witness(v) => validate_witness(v, ctx),
        Item::Share(v) => validate_share(v, ctx),
    }
}

fn require_registry(ctx: &impl Context, root: &Fr) -> Result<u64, Invalid> {
    ctx.registry(root)
        .map(|r| r.leaf_count)
        .ok_or(Invalid::MissingReference(Reference::Registry(*root)))
}

fn check_membership(
    ctx: &impl Context,
    root: Fr,
    nullifier: Fr,
    tag: &str,
    id: Option<&Id>,
    content_id: &Id,
    proof: &Proof,
) -> Result<(), Invalid> {
    let stmt = MembershipStatement::new(root, nullifier, tag, id, content_id);
    if verify_membership(ctx.membership_keys(), &stmt, proof) {
        Ok(())
    } else {
        Err(Invalid::BadProof)
    }
}

/// SPEC §6.1.
pub fn validate_vote(v: &VoteDefinition, ctx: &impl Context) -> Result<(), Invalid> {
    if v.question.is_empty() {
        return Err(Invalid::Structure("empty question"));
    }
    if v.options.len() < 2 || v.options.len() > MAX_OPTIONS {
        return Err(Invalid::Structure("option count"));
    }
    if v.options.iter().any(|o| o.is_empty()) {
        return Err(Invalid::Structure("empty option"));
    }
    for (i, a) in v.options.iter().enumerate() {
        if v.options[..i].contains(a) {
            return Err(Invalid::Structure("duplicate option"));
        }
    }
    if v.open_block >= v.close_block || v.close_block - v.open_block > MAX_VOTE_BLOCKS {
        return Err(Invalid::Structure("open/close blocks"));
    }
    require_registry(ctx, &v.registry_root)?;
    match &v.origin {
        Origin::Authority {
            authority_key,
            signature,
        } => {
            if !ctx.deployment().authority_keys.contains(authority_key) {
                return Err(Invalid::UnknownAuthority);
            }
            if !verify(authority_key, Domain::Vote, &v.vote_id(), signature) {
                return Err(Invalid::BadSignature);
            }
            Ok(())
        }
        Origin::Initiative { initiative_id } => {
            ctx.initiative(initiative_id)
                .ok_or(Invalid::MissingReference(Reference::Initiative(
                    *initiative_id,
                )))?;
            let derived = ctx
                .derived_vote(initiative_id)
                .ok_or(Invalid::MissingReference(Reference::DerivedVote(
                    *initiative_id,
                )))?;
            if &derived == v {
                Ok(())
            } else {
                Err(Invalid::DerivationMismatch)
            }
        }
    }
}

/// SPEC §6.2.
pub fn validate_initiative(v: &Initiative, ctx: &impl Context) -> Result<(), Invalid> {
    if v.text.is_empty() {
        return Err(Invalid::Structure("empty text"));
    }
    let size = require_registry(ctx, &v.registry_root)?;
    if v.threshold_n != initiative_threshold(size) {
        return Err(Invalid::Structure("threshold_N is not the protocol value"));
    }
    check_membership(
        ctx,
        v.registry_root,
        v.author,
        TAG_AUTHOR,
        None,
        &v.content_id(),
        &v.proof,
    )
}

/// SPEC §6.3.
pub fn validate_support(v: &Support, ctx: &impl Context) -> Result<(), Invalid> {
    let init = ctx
        .initiative(&v.initiative_id)
        .ok_or(Invalid::MissingReference(Reference::Initiative(
            v.initiative_id,
        )))?;
    check_membership(
        ctx,
        init.registry_root,
        v.nullifier,
        TAG_SUPPORT,
        Some(&v.initiative_id),
        &v.content_id(),
        &v.proof,
    )
}

/// SPEC §6.4.
pub fn validate_ballot(v: &Ballot, ctx: &impl Context) -> Result<(), Invalid> {
    let vote = ctx
        .vote(&v.vote_id)
        .ok_or(Invalid::MissingReference(Reference::Vote(v.vote_id)))?;
    match vote.secrecy {
        Secrecy::None => {
            if v.payload.len() != 1 {
                return Err(Invalid::Structure("plaintext payload must be one byte"));
            }
            if v.payload[0] as usize >= vote.options.len() {
                return Err(Invalid::Structure("option index out of range"));
            }
        }
        Secrecy::KeyParties => {
            let p = KeyPartiesPayload::decode(&v.payload)
                .map_err(|_| Invalid::Structure("keyparties payload"))?;
            for id in &p.party_ids {
                let kp = ctx
                    .keyparty(id)
                    .ok_or(Invalid::MissingReference(Reference::KeyParty(*id)))?;
                if kp.vote_id != v.vote_id {
                    return Err(Invalid::Structure("key party belongs to another vote"));
                }
            }
            // Point canonicity is checked in Phase 10 (`crypto::elgamal`).
        }
    }
    check_membership(
        ctx,
        vote.registry_root,
        v.nullifier,
        TAG_BALLOT,
        Some(&v.vote_id),
        &v.content_id(),
        &v.proof,
    )
}

/// SPEC §6.5 — proof verification is Phase 5; structure and dev gating here.
pub fn validate_anchor(v: &Anchor, ctx: &impl Context) -> Result<(), Invalid> {
    if v.leaves.is_empty() || v.leaves.len() > MAX_ANCHOR_LEAVES {
        return Err(Invalid::Structure("anchor leaf count"));
    }
    if v.leaves.windows(2).any(|w| w[0] >= w[1]) {
        return Err(Invalid::Structure("anchor leaves not strictly ascending"));
    }
    match &v.proof {
        AnchorProof::Dev { height } => {
            if !ctx.dev_mode() {
                return Err(Invalid::DevOnly);
            }
            ctx.block_merkle_root(*height)
                .ok_or(Invalid::MissingReference(Reference::Header(*height)))?;
            Ok(())
        }
        AnchorProof::Ots { .. } | AnchorProof::Direct { .. } => {
            Err(Invalid::NotImplemented("anchor proofs (Phase 5)"))
        }
    }
}

/// SPEC §6.6 — Phase 10.
pub fn validate_keyparty(v: &KeyParty, ctx: &impl Context) -> Result<(), Invalid> {
    let vote = ctx
        .vote(&v.vote_id)
        .ok_or(Invalid::MissingReference(Reference::Vote(v.vote_id)))?;
    if vote.secrecy != Secrecy::KeyParties {
        return Err(Invalid::Structure("vote has no key parties"));
    }
    if v.registry_root != vote.registry_root {
        return Err(Invalid::Structure("registry root differs from the vote"));
    }
    if v.delay_t > T_MAX {
        return Err(Invalid::Structure("delay above T_MAX"));
    }
    Err(Invalid::NotImplemented(
        "verifiable timed commitment (Phase 10)",
    ))
}

/// SPEC §6.7.
pub fn validate_node_registration(v: &NodeRegistration, ctx: &impl Context) -> Result<(), Invalid> {
    if v.endpoint.is_empty() || v.endpoint.len() > MAX_ENDPOINT_BYTES {
        return Err(Invalid::Structure("endpoint length"));
    }
    require_registry(ctx, &v.registry_root)?;
    check_membership(
        ctx,
        v.registry_root,
        v.nullifier,
        TAG_NODE,
        None,
        &v.content_id(),
        &v.proof,
    )
}

/// SPEC §6.8.
pub fn validate_witness(v: &Witness, ctx: &impl Context) -> Result<(), Invalid> {
    ctx.vote(&v.vote_id)
        .ok_or(Invalid::MissingReference(Reference::Vote(v.vote_id)))?;
    ctx.node_registration(&v.node_key)
        .ok_or(Invalid::MissingReference(Reference::NodeRegistration(
            v.node_key,
        )))?;
    let mut payload = v.content_id.to_vec();
    payload.extend_from_slice(&v.vote_id);
    if verify(&v.node_key, Domain::Witness, &payload, &v.signature) {
        Ok(())
    } else {
        Err(Invalid::BadSignature)
    }
}

/// SPEC §6.9 — Phase 10.
pub fn validate_share(v: &Share, ctx: &impl Context) -> Result<(), Invalid> {
    let kp = ctx
        .keyparty(&v.keyparty_id)
        .ok_or(Invalid::MissingReference(Reference::KeyParty(
            v.keyparty_id,
        )))?;
    if kp.vote_id != v.vote_id {
        return Err(Invalid::Structure(
            "share vote id differs from the key party",
        ));
    }
    Err(Invalid::NotImplemented("share check sk·G == pk (Phase 10)"))
}
