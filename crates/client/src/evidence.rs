//! What a voter can establish about their own ballot without believing any
//! node (whitepaper §12).
//!
//! "Your ballot is anchored" is the one answer a voter acts on — it is what
//! tells them to stop resending. Taken from a node's word it is worthless: a
//! node that dropped the ballot can simply claim it landed, and the voter
//! stops trying. So the claim is never believed here. The client asks for the
//! anchor and the inclusion proof, recomputes the Merkle root from the anchor
//! itself, checks its own ballot is a leaf of it, and — given block headers —
//! checks the anchor's Bitcoin proof with the same function nodes and the
//! verifier use (`cv_core::validate::check_anchor_proof`).

use crate::light::{ClientError, NodeClient};
use cv_core::crypto::merkle::{InclusionProof, anchor_root, verify_inclusion};
use cv_core::items::*;
use cv_core::snapshot::Headers;
use cv_core::validate::check_anchor_proof;

/// How far the check got. Anything less than `Bitcoin` is not a deadline.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AnchorCheck {
    /// The ballot is in the anchor's Merkle root **and** that root is in the
    /// Bitcoin block the anchor names, checked against the caller's headers.
    Bitcoin,
    /// The ballot is in the anchor's Merkle root, but no headers were given,
    /// so the Bitcoin half is still only the anchor's own claim.
    MerkleOnly,
    /// Dev-mode anchor, accepted because the caller asked for dev mode.
    /// Means nothing at all.
    Dev,
}

/// Evidence the voter can keep, recheck offline, and show to anyone.
#[derive(Debug, Clone)]
pub struct AnchorEvidence {
    pub anchor_id: Id,
    pub content_id: Id,
    pub height: u32,
    /// Merkle root recomputed from the anchor's own leaves.
    pub root: [u8; 32],
    pub proof: InclusionProof,
    pub check: AnchorCheck,
}

impl AnchorEvidence {
    /// Recheck without talking to anyone (the point of keeping it).
    pub fn recheck(&self) -> bool {
        verify_inclusion(&self.proof, &self.content_id) && self.proof.root == self.root
    }
}

/// Look for an anchor that really contains `content_id`. `None` means the
/// node offered nothing that survives checking — which is the same thing the
/// voter should do about it either way: keep resending.
///
/// `headers` supplies `merkle_root(height)` for the Bitcoin check; without it
/// the result is `MerkleOnly`. `allow_dev` accepts dev-mode anchors and must
/// be false anywhere the answer matters.
pub async fn anchor_evidence(
    node: &NodeClient,
    content_id: &Id,
    headers: Option<&dyn Headers>,
    allow_dev: bool,
) -> Result<Option<AnchorEvidence>, ClientError> {
    for summary in node.anchors().await? {
        let Ok(anchor_id) = hex::decode(&summary.content_id) else {
            continue;
        };
        let Ok(anchor_id): Result<Id, _> = anchor_id.try_into() else {
            continue;
        };
        let Some(json) = node.anchor_proof(&anchor_id, content_id).await? else {
            continue;
        };
        // The anchor item is fetched by content id, so it is the anchor the
        // proof claims to be about and not something the node made up.
        let Some(Item::Anchor(anchor)) = node.item(&anchor_id).await? else {
            continue;
        };
        let Some(proof) = decode_proof(&json) else {
            continue;
        };
        let Some(root) = anchor_root(&anchor.leaves) else {
            continue;
        };
        // Recomputed from the anchor's leaves — not taken from the proof.
        if proof.root != root
            || proof.leaf_count as usize != anchor.leaves.len()
            || anchor.leaves.binary_search(content_id).is_err()
            || !verify_inclusion(&proof, content_id)
        {
            continue;
        }
        let height = anchor.proof.height();
        let check = match headers.map(|h| h.merkle_root(height)) {
            Some(Some(block_root)) => {
                if check_anchor_proof(&anchor.proof, &root, &block_root, allow_dev).is_err() {
                    continue;
                }
                if matches!(anchor.proof, AnchorProof::Dev { .. }) {
                    AnchorCheck::Dev
                } else {
                    AnchorCheck::Bitcoin
                }
            }
            // Headers were offered but do not reach this height yet: the
            // anchor may be real, but nothing here proves it.
            Some(None) => continue,
            None => {
                if matches!(anchor.proof, AnchorProof::Dev { .. }) {
                    if !allow_dev {
                        continue;
                    }
                    AnchorCheck::Dev
                } else {
                    AnchorCheck::MerkleOnly
                }
            }
        };
        return Ok(Some(AnchorEvidence {
            anchor_id,
            content_id: *content_id,
            height,
            root,
            proof,
            check,
        }));
    }
    Ok(None)
}

fn decode_proof(json: &cv_core::wire::InclusionProofJson) -> Option<InclusionProof> {
    let root: Id = hex::decode(&json.root).ok()?.try_into().ok()?;
    let mut siblings = Vec::with_capacity(json.siblings.len());
    for s in &json.siblings {
        siblings.push(hex::decode(s).ok()?.try_into().ok()?);
    }
    Some(InclusionProof {
        root,
        leaf_count: json.leaf_count,
        index: json.index,
        siblings,
    })
}

/// Bitcoin headers from a file the voter obtained themselves (SPEC §15
/// header format) — the only way the Bitcoin half of a confirmation means
/// anything, since the node serving the anchor cannot be the one vouching
/// for the chain.
pub struct FileHeaders(pub cv_core::headers::HeaderChain);

impl Headers for FileHeaders {
    fn merkle_root(&self, height: u32) -> Option<[u8; 32]> {
        self.0
            .header_at(height)
            .map(cv_core::crypto::spv::merkle_root)
    }
    fn tip_height(&self) -> Option<u32> {
        Some(self.0.tip().0)
    }
}
