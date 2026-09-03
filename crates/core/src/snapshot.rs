//! Loading a SPEC §15 snapshot into an in-memory view that implements
//! `Context` and `LogView`: what the verifier (and tests) tally over.

use crate::DecodeError;
use crate::constants::MAX_ITEM_BYTES;
use crate::context::{Context, Deployment, RegistryInfo};
use crate::crypto::field::{Fr, fr_to_bytes};
use crate::crypto::groth16::MembershipVerifier;
use crate::encoding::{Reader, Writer};
use crate::items::*;
use crate::registry::RegistrySnapshot;
use crate::tally::LogView;
use crate::validate::{Invalid, validate};
use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;

pub const SNAPSHOT_MAGIC: &[u8; 8] = b"CVSNAP01";

/// Header access the snapshot view needs (the verifier supplies a header file).
pub trait Headers: Send + Sync {
    fn merkle_root(&self, height: u32) -> Option<[u8; 32]>;
    fn tip_height(&self) -> Option<u32>;
}

pub fn encode_snapshot(registries: &[RegistrySnapshot], items: &[Vec<u8>]) -> Vec<u8> {
    let mut w = Writer::new();
    w.fixed(SNAPSHOT_MAGIC);
    w.list_len(registries.len());
    for r in registries {
        w.bytes(&r.encode());
    }
    w.list_len(items.len());
    for i in items {
        w.bytes(i);
    }
    w.into_inner()
}

pub fn decode_snapshot(bytes: &[u8]) -> Result<(Vec<RegistrySnapshot>, Vec<Vec<u8>>), DecodeError> {
    let mut r = Reader::new(bytes);
    if r.fixed::<8>()? != *SNAPSHOT_MAGIC {
        return Err(DecodeError::Structure);
    }
    let n = r.list_len(1 << 20)?;
    let mut regs = Vec::with_capacity(n);
    for _ in 0..n {
        regs.push(RegistrySnapshot::decode(&r.bytes(1024)?)?);
    }
    let n = r.list_len(1 << 28)?;
    let mut items = Vec::with_capacity(n);
    for _ in 0..n {
        items.push(r.bytes(MAX_ITEM_BYTES)?);
    }
    r.finish()?;
    Ok((regs, items))
}

/// Report of a snapshot load.
#[derive(Debug, Default, Clone)]
pub struct LoadReport {
    pub accepted: usize,
    pub invalid: Vec<(Id, Invalid)>,
    pub unresolved: usize,
    pub registries_rejected: usize,
}

pub struct SnapshotView {
    deployment: Deployment,
    verifier: Arc<MembershipVerifier>,
    headers: Arc<dyn Headers>,
    registries: HashMap<Fr, RegistryInfo>,
    items: HashMap<Id, Item>,
    votes: HashMap<Id, VoteDefinition>,
    initiatives: HashMap<Id, Initiative>,
    ballots_by_vote: HashMap<Id, Vec<Id>>,
    supports_by_initiative: HashMap<Id, Vec<Id>>,
    keyparties_by_vote: HashMap<Id, Vec<Id>>,
    shares_by_keyparty: HashMap<Id, Vec<Id>>,
    witnesses_by_content: HashMap<Id, Vec<Id>>,
    nodes_by_key: HashMap<[u8; 32], Id>,
    node_nullifiers: HashMap<[u8; 32], Vec<Id>>,
    anchor_height: BTreeMap<Id, u32>,
    anchor_heights: Vec<u32>,
    pub report: LoadReport,
}

impl SnapshotView {
    pub fn empty(
        deployment: Deployment,
        verifier: Arc<MembershipVerifier>,
        headers: Arc<dyn Headers>,
    ) -> Self {
        SnapshotView {
            deployment,
            verifier,
            headers,
            registries: HashMap::new(),
            items: HashMap::new(),
            votes: HashMap::new(),
            initiatives: HashMap::new(),
            ballots_by_vote: HashMap::new(),
            supports_by_initiative: HashMap::new(),
            keyparties_by_vote: HashMap::new(),
            shares_by_keyparty: HashMap::new(),
            witnesses_by_content: HashMap::new(),
            nodes_by_key: HashMap::new(),
            node_nullifiers: HashMap::new(),
            anchor_height: BTreeMap::new(),
            anchor_heights: Vec::new(),
            report: LoadReport::default(),
        }
    }

    /// Decode and validate a snapshot. Items are admitted in dependency
    /// order by repeating passes until no further item validates.
    pub fn load(
        bytes: &[u8],
        deployment: Deployment,
        verifier: Arc<MembershipVerifier>,
        headers: Arc<dyn Headers>,
    ) -> Result<Self, DecodeError> {
        let (registries, items) = decode_snapshot(bytes)?;
        let mut view = Self::empty(deployment, verifier, headers);
        for r in registries {
            view.add_registry(r);
        }
        let mut pending: Vec<Item> = Vec::with_capacity(items.len());
        for b in items {
            match Item::decode(&b) {
                Ok(item) => pending.push(item),
                Err(e) => return Err(e),
            }
        }
        view.admit_all(pending);
        Ok(view)
    }

    pub fn add_registry(&mut self, r: RegistrySnapshot) {
        // TRUST: Issuer for the electorate (whitepaper §2).
        if r.verify(&self.deployment.issuer_key) {
            self.registries.insert(
                r.root,
                RegistryInfo {
                    leaf_count: r.leaf_count,
                },
            );
        } else {
            self.report.registries_rejected += 1;
        }
    }

    /// Validate and index items, repeating passes for dependency order.
    pub fn admit_all(&mut self, mut pending: Vec<Item>) {
        loop {
            let mut next = Vec::new();
            let before = pending.len();
            for item in pending {
                let cid = item.content_id();
                if self.items.contains_key(&cid) {
                    continue;
                }
                match validate(&item, self) {
                    Ok(()) => {
                        self.index(item);
                        self.report.accepted += 1;
                    }
                    Err(Invalid::MissingReference(_)) => next.push(item),
                    Err(e) => self.report.invalid.push((cid, e)),
                }
            }
            if next.is_empty() || next.len() == before {
                self.report.unresolved = next.len();
                break;
            }
            pending = next;
        }
    }

    /// Validate and index one item (tests).
    pub fn admit(&mut self, item: Item) -> Result<(), Invalid> {
        if self.items.contains_key(&item.content_id()) {
            return Ok(());
        }
        validate(&item, self)?;
        self.index(item);
        Ok(())
    }

    fn index(&mut self, item: Item) {
        let cid = item.content_id();
        match &item {
            Item::VoteDefinition(v) => {
                self.votes.insert(cid, v.clone());
            }
            Item::Initiative(i) => {
                self.initiatives.insert(cid, i.clone());
            }
            Item::Support(s) => self
                .supports_by_initiative
                .entry(s.initiative_id)
                .or_default()
                .push(cid),
            Item::Ballot(b) => self.ballots_by_vote.entry(b.vote_id).or_default().push(cid),
            Item::Anchor(a) => {
                let h = a.proof.height();
                self.anchor_heights.push(h);
                for leaf in &a.leaves {
                    let e = self.anchor_height.entry(*leaf).or_insert(h);
                    if h < *e {
                        *e = h;
                    }
                }
            }
            Item::KeyParty(k) => self
                .keyparties_by_vote
                .entry(k.vote_id)
                .or_default()
                .push(cid),
            Item::NodeRegistration(r) => {
                self.nodes_by_key.insert(r.node_key, cid);
                self.node_nullifiers
                    .entry(fr_to_bytes(&r.nullifier))
                    .or_default()
                    .push(cid);
            }
            Item::Witness(w) => self
                .witnesses_by_content
                .entry(w.content_id)
                .or_default()
                .push(cid),
            Item::Share(s) => self
                .shares_by_keyparty
                .entry(s.keyparty_id)
                .or_default()
                .push(cid),
        }
        self.items.insert(cid, item);
    }

    pub fn len(&self) -> usize {
        self.items.len()
    }

    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }

    pub fn vote_ids(&self) -> Vec<Id> {
        let mut v: Vec<Id> = self.votes.keys().copied().collect();
        v.sort();
        v
    }

    pub fn initiative_ids(&self) -> Vec<Id> {
        let mut v: Vec<Id> = self.initiatives.keys().copied().collect();
        v.sort();
        v
    }

    fn collect<T>(&self, ids: Option<&Vec<Id>>, f: impl Fn(&Item) -> Option<T>) -> Vec<T> {
        ids.map(|v| {
            v.iter()
                .filter_map(|id| self.items.get(id).and_then(&f))
                .collect()
        })
        .unwrap_or_default()
    }
}

impl Context for SnapshotView {
    fn deployment(&self) -> &Deployment {
        &self.deployment
    }
    fn membership_verifier(&self) -> &MembershipVerifier {
        &self.verifier
    }
    fn registry(&self, root: &Fr) -> Option<RegistryInfo> {
        self.registries.get(root).copied()
    }
    fn vote(&self, id: &Id) -> Option<VoteDefinition> {
        self.votes.get(id).cloned()
    }
    fn initiative(&self, id: &Id) -> Option<Initiative> {
        self.initiatives.get(id).cloned()
    }
    fn keyparty(&self, id: &Id) -> Option<KeyParty> {
        match self.items.get(id) {
            Some(Item::KeyParty(k)) => Some(k.clone()),
            _ => None,
        }
    }
    fn node_registration(&self, node_key: &[u8; 32]) -> Option<NodeRegistration> {
        let cid = self.nodes_by_key.get(node_key)?;
        let Item::NodeRegistration(r) = self.items.get(cid)? else {
            return None;
        };
        let group = self.node_nullifiers.get(&fr_to_bytes(&r.nullifier))?;
        if group.iter().any(|g| g != cid) {
            return None;
        }
        Some(r.clone())
    }
    fn derived_vote(&self, initiative_id: &Id) -> Option<VoteDefinition> {
        crate::tally::derive_vote(self, initiative_id)
    }
    fn block_merkle_root(&self, height: u32) -> Option<[u8; 32]> {
        self.headers.merkle_root(height)
    }
}

impl LogView for SnapshotView {
    fn ballots_of(&self, vote_id: &Id) -> Vec<Ballot> {
        self.collect(self.ballots_by_vote.get(vote_id), |i| {
            if let Item::Ballot(b) = i {
                Some(b.clone())
            } else {
                None
            }
        })
    }
    fn supports_of(&self, initiative_id: &Id) -> Vec<Support> {
        self.collect(self.supports_by_initiative.get(initiative_id), |i| {
            if let Item::Support(s) = i {
                Some(s.clone())
            } else {
                None
            }
        })
    }
    fn witnesses_of(&self, content_id: &Id) -> Vec<Witness> {
        self.collect(self.witnesses_by_content.get(content_id), |i| {
            if let Item::Witness(w) = i {
                Some(w.clone())
            } else {
                None
            }
        })
    }
    fn keyparties_of(&self, vote_id: &Id) -> Vec<KeyParty> {
        self.collect(self.keyparties_by_vote.get(vote_id), |i| {
            if let Item::KeyParty(k) = i {
                Some(k.clone())
            } else {
                None
            }
        })
    }
    fn shares_of(&self, keyparty_id: &Id) -> Vec<Share> {
        self.collect(self.shares_by_keyparty.get(keyparty_id), |i| {
            if let Item::Share(s) = i {
                Some(s.clone())
            } else {
                None
            }
        })
    }
    fn anchored_height(&self, content_id: &Id) -> Option<u32> {
        self.anchor_height.get(content_id).copied()
    }
    fn any_anchor_at_or_before(&self, height: u32) -> bool {
        self.anchor_heights.iter().any(|h| *h <= height)
    }
    fn tip_height(&self) -> Option<u32> {
        self.headers.tip_height()
    }
}
