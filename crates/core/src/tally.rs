//! Counting rule (SPEC §12) and initiative → vote derivation (SPEC §13).
//! Pure functions over a `LogView`; the same code runs in nodes and in the
//! verifier.

use crate::constants::*;
use crate::context::Context;
use crate::crypto::field::fr_to_bytes;
use crate::items::*;
use std::collections::{BTreeMap, BTreeSet};

/// Read access to the Log as the counting rule sees it. Implementations
/// only return intrinsically valid items (the Log stores nothing else; the
/// snapshot loader validates on load).
pub trait LogView: Context {
    fn ballots_of(&self, vote_id: &Id) -> Vec<Ballot>;
    fn supports_of(&self, initiative_id: &Id) -> Vec<Support>;
    fn witnesses_of(&self, content_id: &Id) -> Vec<Witness>;
    fn keyparties_of(&self, vote_id: &Id) -> Vec<KeyParty>;
    fn shares_of(&self, keyparty_id: &Id) -> Vec<Share>;
    /// Lowest height of any valid anchor covering the item.
    fn anchored_height(&self, content_id: &Id) -> Option<u32>;
    /// Whether any valid anchor exists at or below `height`.
    fn any_anchor_at_or_before(&self, height: u32) -> bool;
    fn tip_height(&self) -> Option<u32>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Guarantee {
    /// Every counted ballot is under a Bitcoin-anchored root at height ≤ close.
    Anchored,
    /// No anchor exists for the vote; ballots were admitted by ≥ W witness
    /// signatures (whitepaper §9 degraded mode).
    Fallback,
}

impl std::fmt::Display for Guarantee {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Guarantee::Anchored => "anchored",
            Guarantee::Fallback => {
                "FALLBACK (witness signatures; colluding nodes could have backdated)"
            }
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    Result {
        guarantee: Guarantee,
        counts: Vec<u64>,
        counted: u64,
    },
    BelowMinimum {
        guarantee: Guarantee,
        counted: u64,
    },
    /// `keyparties` only: the header tip is not past `close_block`.
    NotClosed,
    /// `keyparties` only: shares still missing.
    Pending {
        guarantee: Guarantee,
        missing_shares: Vec<Id>,
    },
}

/// Duplicate rule (SPEC §7.1) over the *timely* items of one scope: groups
/// with a single content id keep one item; groups with differing content ids
/// are dropped entirely.
pub fn unique_by_nullifier<T: Clone>(
    items: &[T],
    nullifier: impl Fn(&T) -> [u8; 32],
    content_id: impl Fn(&T) -> Id,
) -> Vec<T> {
    let mut groups: BTreeMap<[u8; 32], Vec<&T>> = BTreeMap::new();
    for it in items {
        groups.entry(nullifier(it)).or_default().push(it);
    }
    groups
        .into_values()
        .filter_map(|g| {
            let first = content_id(g[0]);
            if g.iter().all(|x| content_id(x) == first) {
                Some(g[0].clone())
            } else {
                None
            }
        })
        .collect()
}

/// Ballots that are inside the deadline, and under which guarantee.
fn timely_ballots(
    view: &impl LogView,
    vd: &VoteDefinition,
    ballots: Vec<Ballot>,
) -> (Guarantee, Vec<Ballot>) {
    let anchored: Vec<Ballot> = ballots
        .iter()
        .filter(|b| {
            view.anchored_height(&b.content_id())
                .is_some_and(|h| h <= vd.close_block)
        })
        .cloned()
        .collect();
    if !anchored.is_empty() || view.any_anchor_at_or_before(vd.close_block) {
        return (Guarantee::Anchored, anchored);
    }
    // Whitepaper §9 fallback: ≥ W distinct registered nodes witnessed the ballot.
    let witnessed = ballots
        .into_iter()
        .filter(|b| {
            let cid = b.content_id();
            let signers: BTreeSet<[u8; 32]> = view
                .witnesses_of(&cid)
                .into_iter()
                .filter(|w| {
                    w.vote_id == vd.vote_id() && view.node_registration(&w.node_key).is_some()
                })
                .map(|w| w.node_key)
                .collect();
            signers.len() >= WITNESS_THRESHOLD_W
        })
        .collect();
    (Guarantee::Fallback, witnessed)
}

/// SPEC §12. `None` if the vote is unknown.
pub fn tally(view: &impl LogView, vote_id: &Id) -> Option<Outcome> {
    let vd = view.vote(vote_id)?;
    let ballots = view.ballots_of(vote_id);
    let (guarantee, timely) = timely_ballots(view, &vd, ballots);
    let unique = unique_by_nullifier(&timely, |b| fr_to_bytes(&b.nullifier), |b| b.content_id());
    let mut counts = vec![0u64; vd.options.len()];
    match vd.secrecy {
        Secrecy::None => {
            for b in &unique {
                if let [idx] = b.payload.as_slice() {
                    if (*idx as usize) < counts.len() {
                        counts[*idx as usize] += 1;
                    }
                }
            }
        }
        Secrecy::KeyParties => {
            if view.tip_height().is_none_or(|t| t <= vd.close_block) {
                return Some(Outcome::NotClosed);
            }
            // Declared parties must have been anchored before open_block (A38).
            let unique: Vec<(Ballot, KeyPartiesPayload)> = unique
                .into_iter()
                .filter_map(|b| KeyPartiesPayload::decode(&b.payload).ok().map(|p| (b, p)))
                .filter(|(_, p)| {
                    p.party_ids
                        .iter()
                        .all(|id| view.anchored_height(id).is_some_and(|h| h < vd.open_block))
                })
                .collect();
            let needed: BTreeSet<Id> = unique
                .iter()
                .flat_map(|(_, p)| p.party_ids.iter().copied())
                .collect();
            let shares: BTreeMap<Id, [u8; 32]> = needed
                .iter()
                .filter_map(|kp| view.shares_of(kp).into_iter().next().map(|s| (*kp, s.sk)))
                .collect();
            let missing: Vec<Id> = needed
                .iter()
                .filter(|kp| !shares.contains_key(*kp))
                .copied()
                .collect();
            if !missing.is_empty() {
                return Some(Outcome::Pending {
                    guarantee,
                    missing_shares: missing,
                });
            }
            for (_, p) in &unique {
                if let Some(idx) = crate::keyparties::decrypt(&p, &shares, vd.options.len()) {
                    counts[idx] += 1;
                }
            }
        }
    }
    let counted: u64 = counts.iter().sum();
    if counted < vd.min_ballots as u64 {
        return Some(Outcome::BelowMinimum { guarantee, counted });
    }
    Some(Outcome::Result {
        guarantee,
        counts,
        counted,
    })
}

/// SPEC §13. `None` if the initiative is unknown or below threshold.
pub fn derive_vote(view: &impl LogView, initiative_id: &Id) -> Option<VoteDefinition> {
    let init = view.initiative(initiative_id)?;
    let supports = view.supports_of(initiative_id);
    let timely: Vec<Support> = supports
        .into_iter()
        .filter(|s| {
            view.anchored_height(&s.content_id())
                .is_some_and(|h| h <= init.support_deadline_block)
        })
        .collect();
    let unique = unique_by_nullifier(&timely, |s| fr_to_bytes(&s.nullifier), |s| s.content_id());
    if (unique.len() as u32) < init.threshold_n {
        return None;
    }
    let open = init.support_deadline_block + INITIATIVE_OPEN_DELAY;
    Some(VoteDefinition {
        question: init.text.clone(),
        options: vec!["Yes".into(), "No".into()],
        registry_root: init.registry_root,
        open_block: open,
        close_block: open + INITIATIVE_VOTE_BLOCKS,
        min_ballots: MIN_BALLOTS,
        secrecy: init.secrecy,
        origin: Origin::Initiative {
            initiative_id: *initiative_id,
        },
    })
}
