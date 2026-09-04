//! Intrinsic validity rules (SPEC §6). This is the one implementation used by
//! nodes, clients and verifiers. Timing rules (anchors, deadlines) live in
//! `tally`; this module answers "is this item well-formed and proven".

use crate::constants::*;
use crate::context::{Context, RegistryInfo};
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
    #[error("registry root unknown for this issuer")]
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
    #[error("anchor proof does not resolve to the claimed block")]
    BadAnchorProof,
    #[error("anchor proof is not yet in Bitcoin (pending calendar attestation)")]
    Unverified,
    #[error("key party commitment: {0}")]
    KeyParty(String),
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Reference {
    Vote(Id),
    Initiative(Id),
    KeyParty(Id),
    NodeRegistration([u8; 32]),
    /// A Registry snapshot of one Issuer, by `(issuer_key, root)`.
    Registry([u8; 32], Fr),
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
            Reference::Registry(issuer, _) => {
                write!(f, "registry snapshot of issuer {}", hex4(issuer))
            }
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
        Item::Share(v) => validate_share(v, ctx),
    }
}

/// A registry root is usable by an item only through the Issuer the item
/// names: the snapshot with that root must carry that Issuer's signature
/// (SPEC §4.3). Returns the electorate size.
fn require_registry(
    ctx: &impl Context,
    issuer_key: &[u8; 32],
    root: &Fr,
) -> Result<RegistryInfo, Invalid> {
    ctx.registry(issuer_key, root)
        .ok_or(Invalid::MissingReference(Reference::Registry(
            *issuer_key,
            *root,
        )))
}

/// A secret vote must bind every ballot to a floor of key parties; a public
/// one has none to bind (SPEC §6.1). Without a floor, a ballot may declare an
/// empty party set, whose aggregate key is the identity point — the ciphertext
/// is then `option · G`, readable by anyone the moment it is cast, which is
/// exactly the leak `keyparties` exists to prevent (A52).
fn check_min_parties(secrecy: Secrecy, min_parties: u32) -> Result<(), Invalid> {
    let ok = match secrecy {
        Secrecy::None => min_parties == 0,
        Secrecy::KeyParties => min_parties >= 1 && min_parties <= MAX_KEY_PARTIES as u32,
    };
    if ok {
        Ok(())
    } else {
        Err(Invalid::Structure(
            "min_parties does not match the secrecy mode",
        ))
    }
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
    if verify_membership(ctx.membership_verifier(), &stmt, proof) {
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
    check_min_parties(v.secrecy, v.min_parties)?;
    let registry = require_registry(ctx, &v.issuer_key, &v.registry_root)?;
    match &v.origin {
        Origin::Authority {
            authority_key,
            signature,
        } => {
            // Who may call a vote over an electorate is the Issuer's to say,
            // in the snapshot it signs — not a constant compiled into nodes.
            // An empty list means this electorate holds no top-down votes at
            // all; only initiatives can produce one (A57).
            if !registry.authority_keys.contains(authority_key) {
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
    let size = require_registry(ctx, &v.issuer_key, &v.registry_root)?.leaf_count;
    if v.threshold_n != initiative_threshold(size) {
        return Err(Invalid::Structure("threshold_N is not the protocol value"));
    }
    check_min_parties(v.secrecy, v.min_parties)?;
    check_membership(
        ctx,
        v.registry_root,
        v.author,
        TAG_AUTHOR,
        Some(&v.issuer_key),
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
            // The Issuer sets the floor; the voter cannot opt out of it (A52).
            // Intrinsic on the ballot's own bytes, so no late-surfacing anchor
            // can retroactively strand a ballot that was valid when cast (A38).
            if (p.party_ids.len() as u32) < vote.min_parties {
                return Err(Invalid::Structure("fewer key parties than min_parties"));
            }
            for id in &p.party_ids {
                let kp = ctx
                    .keyparty(id)
                    .ok_or(Invalid::MissingReference(Reference::KeyParty(*id)))?;
                if kp.vote_id != v.vote_id {
                    return Err(Invalid::Structure("key party belongs to another vote"));
                }
            }
            if cv_vtc::point_from_bytes(&p.c1).is_none()
                || cv_vtc::point_from_bytes(&p.c2).is_none()
            {
                return Err(Invalid::Structure("non-canonical ciphertext point"));
            }
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

/// Does an anchor proof really put `root` in the Bitcoin block at its own
/// claimed height, whose transaction Merkle root is `block_root`? (SPEC §6.5.)
///
/// The one implementation of this rule: nodes and the verifier reach it
/// through [`validate_anchor`], and a voter's client calls it directly to
/// check the anchor it was handed as evidence that its own ballot is in.
pub fn check_anchor_proof(
    proof: &AnchorProof,
    root: &[u8; 32],
    block_root: &[u8; 32],
    dev_mode: bool,
) -> Result<(), Invalid> {
    match proof {
        AnchorProof::Dev { .. } => {
            if dev_mode {
                Ok(())
            } else {
                Err(Invalid::DevOnly)
            }
        }
        AnchorProof::Ots { ots, height } => {
            // TRUST: OTS calendars for liveness only (whitepaper §2) — the proof is recomputed here.
            let ts = cv_crypto::ots::parse(root, ots)
                .map_err(|_| Invalid::Structure("ots proof does not parse"))?;
            let att = cv_crypto::ots::attestations(&ts);
            if att
                .bitcoin
                .iter()
                .any(|(h, d)| h == height && d.as_slice() == block_root)
            {
                Ok(())
            } else if att.bitcoin.is_empty() && !att.pending.is_empty() {
                Err(Invalid::Unverified)
            } else {
                Err(Invalid::BadAnchorProof)
            }
        }
        AnchorProof::Direct {
            raw_tx,
            partial_merkle_tree,
            ..
        } => cv_crypto::spv::verify_direct(raw_tx, partial_merkle_tree, root, block_root)
            .map_err(|_| Invalid::BadAnchorProof),
    }
}

/// SPEC §6.5.
pub fn validate_anchor(v: &Anchor, ctx: &impl Context) -> Result<(), Invalid> {
    if v.leaves.is_empty() || v.leaves.len() > MAX_ANCHOR_LEAVES {
        return Err(Invalid::Structure("anchor leaf count"));
    }
    if v.leaves.windows(2).any(|w| w[0] >= w[1]) {
        return Err(Invalid::Structure("anchor leaves not strictly ascending"));
    }
    let height = v.proof.height();
    // TRUST: Bitcoin for ordering (whitepaper §2); the header must be known and confirmed.
    let block_root = ctx
        .block_merkle_root(height)
        .ok_or(Invalid::MissingReference(Reference::Header(height)))?;
    let root = cv_crypto::merkle::anchor_root(&v.leaves).expect("non-empty leaves");
    check_anchor_proof(&v.proof, &root, &block_root, ctx.dev_mode())
}

/// SPEC §6.6.
pub fn validate_keyparty(v: &KeyParty, ctx: &impl Context) -> Result<(), Invalid> {
    let vote = ctx
        .vote(&v.vote_id)
        .ok_or(Invalid::MissingReference(Reference::Vote(v.vote_id)))?;
    if vote.secrecy != Secrecy::KeyParties {
        return Err(Invalid::Structure("vote has no key parties"));
    }
    // The party's electorate is the vote's: same Issuer, same root.
    if v.registry_root != vote.registry_root {
        return Err(Invalid::Structure("registry root differs from the vote"));
    }
    if v.delay_t > T_CAP {
        return Err(Invalid::Structure("delay above T_cap"));
    }
    crate::keyparties::verify_keyparty(v).map_err(Invalid::KeyParty)?;
    check_membership(
        ctx,
        v.registry_root,
        v.nullifier,
        TAG_KEYPARTY,
        Some(&v.vote_id),
        &v.content_id(),
        &v.proof,
    )
}

/// SPEC §6.7.
pub fn validate_node_registration(v: &NodeRegistration, ctx: &impl Context) -> Result<(), Invalid> {
    if v.endpoint.is_empty() || v.endpoint.len() > MAX_ENDPOINT_BYTES {
        return Err(Invalid::Structure("endpoint length"));
    }
    require_registry(ctx, &v.issuer_key, &v.registry_root)?;
    check_membership(
        ctx,
        v.registry_root,
        v.nullifier,
        TAG_NODE,
        Some(&v.issuer_key),
        &v.content_id(),
        &v.proof,
    )
}

/// SPEC §6.9.
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
    if crate::keyparties::verify_share(&kp, &v.sk) {
        Ok(())
    } else {
        Err(Invalid::Structure("share does not open to the party's pk"))
    }
}
