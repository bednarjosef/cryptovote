//! The Log (SPEC §6–§7): append-only set of validated items.

use crate::headers::HeaderSource;
use crate::store::{Store, StoreError};
use cv_core::DecodeError;
use cv_core::context::{Context, Deployment, RegistryInfo};
use cv_core::crypto::field::{Fr, fr_to_bytes};
use cv_core::crypto::groth16::{MembershipKeys, MembershipVerifier};
use cv_core::crypto::hash::blake3_hash;
use cv_core::crypto::merkle::{InclusionProof, prove_inclusion};
use cv_core::items::*;
use cv_core::registry::{RegistrySnapshot, RegistryTree, decode_leaves, encode_leaves};
use cv_core::tally::LogView;
use cv_core::validate::{Invalid, Reference, validate};
use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::sync::{Arc, OnceLock};

/// Bound on the orphan pool (SPEC §7.2).
pub const MAX_ORPHANS: usize = 10_000;
/// Nullifier scope for node registrations (no vote/initiative).
pub const NODE_SCOPE: Id = [0u8; 32];
pub use cv_core::snapshot::SNAPSHOT_MAGIC;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Accepted {
    /// Stored and to be relayed.
    New {
        content_id: Id,
        item_type: ItemType,
        seq: u64,
    },
    /// Exact bytes already stored.
    AlreadyHave,
    /// Same content id with different proof bytes: kept the existing one.
    Equivalent { content_id: Id },
    /// Held in the orphan pool until the reference arrives.
    Orphaned(Reference),
}

#[derive(Debug, thiserror::Error)]
pub enum Rejected {
    #[error("malformed item: {0}")]
    Malformed(#[from] DecodeError),
    #[error("invalid item: {0}")]
    Invalid(#[from] Invalid),
    #[error("{0}")]
    Storage(#[from] StoreError),
}

#[derive(Debug, thiserror::Error)]
pub enum RegistryError {
    #[error("issuer signature does not verify")]
    BadSignature,
    #[error("leaf count does not match the leaves file")]
    LeafCount,
    #[error("root does not match the leaves")]
    Root,
    #[error("{0}")]
    Storage(#[from] StoreError),
    #[error("malformed: {0}")]
    Malformed(#[from] DecodeError),
}

/// What a light client asks about its own ballot (whitepaper §12).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BallotStatus {
    pub content_id: Id,
    pub anchored_height: Option<u32>,
}

struct RegistryEntry {
    snapshot: RegistrySnapshot,
    leaves: Vec<Fr>,
    tree: OnceLock<RegistryTree>,
}

#[derive(Default)]
struct OrphanPool {
    by_ref: HashMap<Reference, Vec<Vec<u8>>>,
    order: VecDeque<(Reference, Id)>,
    seen: HashSet<Id>,
}

impl OrphanPool {
    fn push(&mut self, reference: Reference, bytes: Vec<u8>) {
        let h = blake3_hash(&bytes);
        if !self.seen.insert(h) {
            return;
        }
        self.by_ref
            .entry(reference.clone())
            .or_default()
            .push(bytes);
        self.order.push_back((reference, h));
        while self.order.len() > MAX_ORPHANS {
            let (r, h) = self.order.pop_front().unwrap();
            self.seen.remove(&h);
            if let Some(v) = self.by_ref.get_mut(&r) {
                v.retain(|b| blake3_hash(b) != h);
                if v.is_empty() {
                    self.by_ref.remove(&r);
                }
            }
        }
    }

    fn take(&mut self, reference: &Reference) -> Vec<Vec<u8>> {
        let v = self.by_ref.remove(reference).unwrap_or_default();
        for b in &v {
            self.seen.remove(&blake3_hash(b));
        }
        self.order.retain(|(r, _)| r != reference);
        v
    }

    fn take_matching(&mut self, f: impl Fn(&Reference) -> bool) -> Vec<Vec<u8>> {
        let keys: Vec<Reference> = self.by_ref.keys().filter(|r| f(r)).cloned().collect();
        keys.iter().flat_map(|k| self.take(k)).collect()
    }

    fn len(&self) -> usize {
        self.order.len()
    }
}

#[derive(Default)]
struct VoteIndex {
    ballots: Vec<Id>,
    keyparties: Vec<Id>,
}

pub struct Log {
    deployment: Deployment,
    keys: Arc<MembershipKeys>,
    store: Box<dyn Store>,
    headers: Arc<dyn HeaderSource>,
    next_seq: u64,
    // items by content id (one representative per content id)
    items: HashMap<Id, Item>,
    hash_of: HashMap<Id, (Id, u64)>,
    by_hash: HashMap<Id, Id>,
    order: BTreeMap<u64, Id>,
    registries: HashMap<Fr, RegistryEntry>,
    votes: HashMap<Id, VoteDefinition>,
    initiatives: HashMap<Id, Initiative>,
    by_vote: HashMap<Id, VoteIndex>,
    supports_by_initiative: HashMap<Id, Vec<Id>>,
    nullifiers: HashMap<(Id, [u8; 32]), Vec<Id>>,
    nodes_by_key: HashMap<[u8; 32], Id>,
    anchors: Vec<Id>,
    anchor_height: HashMap<Id, u32>,
    witnesses_by_content: HashMap<Id, Vec<Id>>,
    shares_by_keyparty: HashMap<Id, Vec<Id>>,
    orphans: OrphanPool,
    archived: HashMap<Id, Vec<u8>>,
    relay: Vec<Vec<u8>>,
}

impl Log {
    /// Open a Log over a store, replaying persisted items (already validated
    /// when they were stored, so validation is skipped on replay).
    pub fn open(
        deployment: Deployment,
        keys: Arc<MembershipKeys>,
        store: Box<dyn Store>,
        headers: Arc<dyn HeaderSource>,
    ) -> Result<Self, Rejected> {
        let mut log = Log {
            deployment,
            keys,
            store,
            headers,
            next_seq: 1,
            items: HashMap::new(),
            hash_of: HashMap::new(),
            by_hash: HashMap::new(),
            order: BTreeMap::new(),
            registries: HashMap::new(),
            votes: HashMap::new(),
            initiatives: HashMap::new(),
            by_vote: HashMap::new(),
            supports_by_initiative: HashMap::new(),
            nullifiers: HashMap::new(),
            nodes_by_key: HashMap::new(),
            anchors: Vec::new(),
            anchor_height: HashMap::new(),
            witnesses_by_content: HashMap::new(),
            shares_by_keyparty: HashMap::new(),
            orphans: OrphanPool::default(),
            archived: HashMap::new(),
            relay: Vec::new(),
        };
        for (key, bytes) in log.store.meta_with_prefix("registry/")? {
            if key.ends_with("/snapshot") {
                let snapshot = RegistrySnapshot::decode(&bytes)?;
                let leaves_key = key.replace("/snapshot", "/leaves");
                let leaves = decode_leaves(&log.store.get_meta(&leaves_key)?.unwrap_or_default())?;
                log.registries.insert(
                    snapshot.root,
                    RegistryEntry {
                        snapshot,
                        leaves,
                        tree: OnceLock::new(),
                    },
                );
            }
        }
        for (key, bytes) in log.store.meta_with_prefix("archived/")? {
            if let Ok(id) = hex::decode(key.trim_start_matches("archived/")) {
                if id.len() == 32 {
                    log.archived.insert(id.try_into().unwrap(), bytes);
                }
            }
        }
        for (seq, bytes) in log.store.items()? {
            let item = Item::decode(&bytes)?;
            log.index(item, blake3_hash(&bytes), seq);
            log.next_seq = seq + 1;
        }
        Ok(log)
    }

    pub fn deployment(&self) -> &Deployment {
        &self.deployment
    }

    pub fn headers(&self) -> &Arc<dyn HeaderSource> {
        &self.headers
    }

    pub fn len(&self) -> usize {
        self.items.len()
    }

    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }

    pub fn orphan_count(&self) -> usize {
        self.orphans.len()
    }

    // ------------------------------------------------------------------ registry

    /// Add an Issuer-signed Registry snapshot with its leaves file.
    pub fn add_registry(
        &mut self,
        snapshot: RegistrySnapshot,
        leaves: Vec<Fr>,
    ) -> Result<(), RegistryError> {
        // TRUST: Issuer for the electorate (whitepaper §2) — only the signature is checked.
        if !snapshot.verify(&self.deployment.issuer_key) {
            return Err(RegistryError::BadSignature);
        }
        if snapshot.leaf_count != leaves.len() as u64 {
            return Err(RegistryError::LeafCount);
        }
        let tree = RegistryTree::from_leaves(leaves.clone());
        if tree.root() != snapshot.root {
            return Err(RegistryError::Root);
        }
        let root = snapshot.root;
        let key = format!("registry/{}", hex::encode(fr_to_bytes(&root)));
        self.store
            .put_meta(&format!("{key}/snapshot"), &snapshot.encode())?;
        self.store
            .put_meta(&format!("{key}/leaves"), &encode_leaves(&leaves))?;
        let entry = RegistryEntry {
            snapshot,
            leaves,
            tree: OnceLock::new(),
        };
        entry.tree.set(tree).ok();
        self.registries.insert(root, entry);
        for bytes in self.orphans.take(&Reference::Registry(root)) {
            let _ = self.insert(&bytes);
        }
        Ok(())
    }

    pub fn registry_snapshot(&self, root: &Fr) -> Option<&RegistrySnapshot> {
        self.registries.get(root).map(|e| &e.snapshot)
    }

    pub fn registry_leaves(&self, root: &Fr) -> Option<&[Fr]> {
        self.registries.get(root).map(|e| e.leaves.as_slice())
    }

    pub fn registry_tree(&self, root: &Fr) -> Option<&RegistryTree> {
        self.registries.get(root).map(|e| {
            e.tree
                .get_or_init(|| RegistryTree::from_leaves(e.leaves.clone()))
        })
    }

    pub fn registry_roots(&self) -> Vec<Fr> {
        self.registries.keys().copied().collect()
    }

    // ------------------------------------------------------------------ insert

    /// Insert item bytes. `New` results (including cascaded orphans) are
    /// queued for relay; drain them with `take_relay`.
    pub fn insert(&mut self, bytes: &[u8]) -> Result<Accepted, Rejected> {
        let item_hash = blake3_hash(bytes);
        if self.by_hash.contains_key(&item_hash) {
            return Ok(Accepted::AlreadyHave);
        }
        let item = Item::decode(bytes)?;
        let content_id = item.content_id();
        if self.items.contains_key(&content_id) {
            return Ok(Accepted::Equivalent { content_id });
        }
        match validate(&item, self) {
            Ok(()) => {}
            Err(Invalid::MissingReference(r)) => {
                self.orphans.push(r.clone(), bytes.to_vec());
                return Ok(Accepted::Orphaned(r));
            }
            Err(e) => return Err(Rejected::Invalid(e)),
        }
        let seq = self.next_seq;
        self.next_seq += 1;
        self.store.put_item(seq, bytes)?;
        let item_type = item.item_type();
        self.index(item, item_hash, seq);
        self.relay.push(bytes.to_vec());
        self.retry_orphans_for(&content_id, item_type);
        Ok(Accepted::New {
            content_id,
            item_type,
            seq,
        })
    }

    /// Bytes of every item stored since the last call (for gossip).
    pub fn take_relay(&mut self) -> Vec<Vec<u8>> {
        std::mem::take(&mut self.relay)
    }

    /// Re-validate orphans whose references may now resolve (headers advanced).
    pub fn headers_changed(&mut self) {
        let tip = self.headers.tip_height();
        let pending = self
            .orphans
            .take_matching(|r| matches!(r, Reference::Header(h) if Some(*h) <= tip));
        for bytes in pending {
            let _ = self.insert(&bytes);
        }
    }

    fn retry_orphans_for(&mut self, content_id: &Id, item_type: ItemType) {
        if matches!(
            item_type,
            ItemType::Support | ItemType::Anchor | ItemType::Initiative
        ) {
            self.derive_votes();
        }
        let mut pending = Vec::new();
        match item_type {
            ItemType::VoteDefinition => {
                pending.extend(self.orphans.take(&Reference::Vote(*content_id)))
            }
            ItemType::Initiative => {
                pending.extend(self.orphans.take(&Reference::Initiative(*content_id)))
            }
            ItemType::KeyParty => {
                pending.extend(self.orphans.take(&Reference::KeyParty(*content_id)))
            }
            ItemType::NodeRegistration => {
                if let Some(Item::NodeRegistration(r)) = self.items.get(content_id) {
                    let key = r.node_key;
                    pending.extend(self.orphans.take(&Reference::NodeRegistration(key)));
                }
            }
            ItemType::Support | ItemType::Anchor => {
                pending.extend(
                    self.orphans
                        .take_matching(|r| matches!(r, Reference::DerivedVote(_))),
                );
            }
            _ => {}
        }
        for bytes in pending {
            let _ = self.insert(&bytes);
        }
    }

    /// Publish the deterministically derived VoteDefinition of every
    /// initiative whose threshold is reached (SPEC §13). Identical bytes on
    /// every node, so it gossips like any other item.
    fn derive_votes(&mut self) {
        let ids: Vec<Id> = self.initiatives.keys().copied().collect();
        for id in ids {
            if let Some(vd) = cv_core::tally::derive_vote(self, &id) {
                if !self.votes.contains_key(&vd.vote_id()) {
                    let _ = self.insert(&Item::VoteDefinition(vd).encode());
                }
            }
        }
    }

    fn index(&mut self, item: Item, item_hash: Id, seq: u64) {
        let content_id = item.content_id();
        self.hash_of.insert(content_id, (item_hash, seq));
        self.by_hash.insert(item_hash, content_id);
        self.order.insert(seq, item_hash);
        match &item {
            Item::VoteDefinition(v) => {
                self.votes.insert(content_id, v.clone());
                self.by_vote.entry(content_id).or_default();
            }
            Item::Initiative(i) => {
                self.initiatives.insert(content_id, i.clone());
                self.supports_by_initiative.entry(content_id).or_default();
            }
            Item::Support(s) => {
                self.supports_by_initiative
                    .entry(s.initiative_id)
                    .or_default()
                    .push(content_id);
                self.nullifiers
                    .entry((s.initiative_id, fr_to_bytes(&s.nullifier)))
                    .or_default()
                    .push(content_id);
            }
            Item::Ballot(b) => {
                self.by_vote
                    .entry(b.vote_id)
                    .or_default()
                    .ballots
                    .push(content_id);
                self.nullifiers
                    .entry((b.vote_id, fr_to_bytes(&b.nullifier)))
                    .or_default()
                    .push(content_id);
            }
            Item::Anchor(a) => {
                let h = a.proof.height();
                for leaf in &a.leaves {
                    let e = self.anchor_height.entry(*leaf).or_insert(h);
                    if h < *e {
                        *e = h;
                    }
                }
                self.anchors.push(content_id);
            }
            Item::KeyParty(k) => {
                self.by_vote
                    .entry(k.vote_id)
                    .or_default()
                    .keyparties
                    .push(content_id);
                self.nullifiers
                    .entry((k.vote_id, fr_to_bytes(&k.nullifier)))
                    .or_default()
                    .push(content_id);
            }
            Item::NodeRegistration(r) => {
                self.nodes_by_key.insert(r.node_key, content_id);
                self.nullifiers
                    .entry((NODE_SCOPE, fr_to_bytes(&r.nullifier)))
                    .or_default()
                    .push(content_id);
            }
            Item::Witness(w) => {
                self.witnesses_by_content
                    .entry(w.content_id)
                    .or_default()
                    .push(content_id);
            }
            Item::Share(s) => {
                self.shares_by_keyparty
                    .entry(s.keyparty_id)
                    .or_default()
                    .push(content_id);
            }
        }
        self.items.insert(content_id, item);
    }

    // ------------------------------------------------------------------ queries

    pub fn get(&self, content_id: &Id) -> Option<&Item> {
        self.items.get(content_id)
    }

    pub fn get_by_hash(&self, item_hash: &Id) -> Option<&Item> {
        self.by_hash.get(item_hash).and_then(|c| self.items.get(c))
    }

    pub fn has_hash(&self, item_hash: &Id) -> bool {
        self.by_hash.contains_key(item_hash)
    }

    /// `(seq, item_hash)` of items with `seq > since`, in order.
    pub fn inventory(&self, since: u64, limit: usize) -> Vec<(u64, Id)> {
        self.order
            .range(since + 1..)
            .take(limit)
            .map(|(s, h)| (*s, *h))
            .collect()
    }

    pub fn latest_seq(&self) -> u64 {
        self.next_seq - 1
    }

    pub fn votes(&self) -> impl Iterator<Item = (&Id, &VoteDefinition)> {
        self.votes.iter()
    }

    pub fn initiatives(&self) -> impl Iterator<Item = (&Id, &Initiative)> {
        self.initiatives.iter()
    }

    pub fn ballots_of(&self, vote_id: &Id) -> Vec<&Ballot> {
        self.by_vote
            .get(vote_id)
            .map(|v| {
                v.ballots
                    .iter()
                    .filter_map(|id| match self.items.get(id) {
                        Some(Item::Ballot(b)) => Some(b),
                        _ => None,
                    })
                    .collect()
            })
            .unwrap_or_default()
    }

    pub fn keyparties_of(&self, vote_id: &Id) -> Vec<&KeyParty> {
        self.by_vote
            .get(vote_id)
            .map(|v| {
                v.keyparties
                    .iter()
                    .filter_map(|id| match self.items.get(id) {
                        Some(Item::KeyParty(k)) => Some(k),
                        _ => None,
                    })
                    .collect()
            })
            .unwrap_or_default()
    }

    pub fn shares_of(&self, keyparty_id: &Id) -> Vec<&Share> {
        self.shares_by_keyparty
            .get(keyparty_id)
            .map(|v| {
                v.iter()
                    .filter_map(|id| match self.items.get(id) {
                        Some(Item::Share(s)) => Some(s),
                        _ => None,
                    })
                    .collect()
            })
            .unwrap_or_default()
    }

    pub fn supports_of(&self, initiative_id: &Id) -> Vec<&Support> {
        self.supports_by_initiative
            .get(initiative_id)
            .map(|v| {
                v.iter()
                    .filter_map(|id| match self.items.get(id) {
                        Some(Item::Support(s)) => Some(s),
                        _ => None,
                    })
                    .collect()
            })
            .unwrap_or_default()
    }

    pub fn anchors(&self) -> Vec<&Anchor> {
        self.anchors
            .iter()
            .filter_map(|id| match self.items.get(id) {
                Some(Item::Anchor(a)) => Some(a),
                _ => None,
            })
            .collect()
    }

    pub fn witnesses_of(&self, content_id: &Id) -> Vec<&Witness> {
        self.witnesses_by_content
            .get(content_id)
            .map(|v| {
                v.iter()
                    .filter_map(|id| match self.items.get(id) {
                        Some(Item::Witness(w)) => Some(w),
                        _ => None,
                    })
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Content ids of all node registrations (valid or not; callers apply
    /// the duplicate rule through `Context::node_registration`).
    pub fn registered_node_ids(&self) -> Vec<Id> {
        self.nodes_by_key.values().copied().collect()
    }

    /// Lowest height of any valid anchor covering the item (SPEC §12 step 1).
    pub fn anchored_height(&self, content_id: &Id) -> Option<u32> {
        self.anchor_height.get(content_id).copied()
    }

    /// Light-client query "by nullifier": every ballot with this nullifier and
    /// whether it is anchored (whitepaper §12 client responsibility).
    pub fn ballot_status(&self, vote_id: &Id, nullifier: &Fr) -> Vec<BallotStatus> {
        self.nullifiers
            .get(&(*vote_id, fr_to_bytes(nullifier)))
            .map(|ids| {
                ids.iter()
                    .map(|id| BallotStatus {
                        content_id: *id,
                        anchored_height: self.anchored_height(id),
                    })
                    .collect()
            })
            .unwrap_or_default()
    }

    /// All content ids sharing a nullifier within a scope (duplicate rule input).
    pub fn nullifier_group(&self, scope: &Id, nullifier: &Fr) -> &[Id] {
        self.nullifiers
            .get(&(*scope, fr_to_bytes(nullifier)))
            .map(|v| v.as_slice())
            .unwrap_or(&[])
    }

    /// Inclusion proof of `content_id` in the anchor `anchor_id` (SPEC §8).
    pub fn inclusion_proof(&self, anchor_id: &Id, content_id: &Id) -> Option<InclusionProof> {
        let Item::Anchor(a) = self.items.get(anchor_id)? else {
            return None;
        };
        let index = a.leaves.binary_search(content_id).ok()?;
        prove_inclusion(&a.leaves, index)
    }

    /// Anchors (content ids) that cover an item.
    pub fn anchors_covering(&self, content_id: &Id) -> Vec<Id> {
        self.anchors
            .iter()
            .filter(|id| matches!(self.items.get(*id), Some(Item::Anchor(a)) if a.leaves.binary_search(content_id).is_ok()))
            .copied()
            .collect()
    }

    /// Content ids of all valid items not yet covered by any anchor in this
    /// Log (what an incremental anchorer anchors next, SPEC §6.5).
    pub fn unanchored_content_ids(&self) -> Vec<Id> {
        let mut ids: Vec<Id> = self
            .items
            .iter()
            .filter(|(id, item)| {
                !matches!(item, Item::Anchor(_)) && !self.anchor_height.contains_key(*id)
            })
            .map(|(id, _)| *id)
            .collect();
        ids.sort();
        ids
    }

    // ------------------------------------------------------------------ pruning

    /// Record an archived result and drop the vote's ballots, key parties
    /// and shares (SPEC §7.3). Returns the number of items removed.
    pub fn prune_vote(
        &mut self,
        vote_id: &Id,
        archived_result: &[u8],
    ) -> Result<usize, StoreError> {
        self.store.put_meta(
            &format!("archived/{}", hex::encode(vote_id)),
            archived_result,
        )?;
        self.archived.insert(*vote_id, archived_result.to_vec());
        let Some(idx) = self.by_vote.remove(vote_id) else {
            return Ok(0);
        };
        let mut removed = 0;
        let mut ids = idx.ballots.clone();
        for kp in &idx.keyparties {
            ids.push(*kp);
            if let Some(shares) = self.shares_by_keyparty.remove(kp) {
                ids.extend(shares);
            }
        }
        for id in ids {
            if let Some(item) = self.items.remove(&id) {
                if let Some((h, seq)) = self.hash_of.remove(&id) {
                    self.by_hash.remove(&h);
                    self.order.remove(&seq);
                    self.store.delete_item(seq)?;
                }
                match item {
                    Item::Ballot(b) => {
                        self.nullifiers
                            .remove(&(b.vote_id, fr_to_bytes(&b.nullifier)));
                    }
                    Item::KeyParty(k) => {
                        self.nullifiers
                            .remove(&(k.vote_id, fr_to_bytes(&k.nullifier)));
                    }
                    _ => {}
                }
                removed += 1;
            }
        }
        self.by_vote.insert(*vote_id, VoteIndex::default());
        Ok(removed)
    }

    pub fn archived_result(&self, vote_id: &Id) -> Option<&[u8]> {
        self.archived.get(vote_id).map(|v| v.as_slice())
    }

    // ------------------------------------------------------------------ node metadata

    /// Node-level persistent state (pending anchor submissions etc.).
    pub fn put_meta(&self, key: &str, bytes: &[u8]) -> Result<(), StoreError> {
        self.store.put_meta(&format!("node/{key}"), bytes)
    }

    pub fn get_meta(&self, key: &str) -> Result<Option<Vec<u8>>, StoreError> {
        self.store.get_meta(&format!("node/{key}"))
    }

    pub fn delete_meta(&self, key: &str) -> Result<(), StoreError> {
        self.store.put_meta(&format!("node/{key}"), &[])
    }

    pub fn meta_with_prefix(&self, prefix: &str) -> Result<Vec<(String, Vec<u8>)>, StoreError> {
        Ok(self
            .store
            .meta_with_prefix(&format!("node/{prefix}"))?
            .into_iter()
            .filter(|(_, v)| !v.is_empty())
            .map(|(k, v)| (k.trim_start_matches("node/").to_string(), v))
            .collect())
    }

    // ------------------------------------------------------------------ export

    /// Snapshot of every registry header and item (SPEC §15).
    pub fn export_snapshot(&self) -> Vec<u8> {
        let regs: Vec<RegistrySnapshot> = self
            .registries
            .values()
            .map(|e| e.snapshot.clone())
            .collect();
        let items: Vec<Vec<u8>> = self
            .order
            .values()
            .map(|hash| self.items[&self.by_hash[hash]].encode())
            .collect();
        cv_core::snapshot::encode_snapshot(&regs, &items)
    }

    pub fn any_anchor_at_or_before(&self, height: u32) -> bool {
        self.anchors().iter().any(|a| a.proof.height() <= height)
    }
}

impl Context for Log {
    fn deployment(&self) -> &Deployment {
        &self.deployment
    }
    fn membership_verifier(&self) -> &MembershipVerifier {
        &self.keys.verifier
    }
    fn registry(&self, root: &Fr) -> Option<RegistryInfo> {
        self.registries.get(root).map(|e| RegistryInfo {
            leaf_count: e.snapshot.leaf_count,
        })
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
        // Duplicate rule (SPEC §7.1): a differing registration under the same
        // nullifier invalidates all of them.
        let group = self.nullifier_group(&NODE_SCOPE, &r.nullifier);
        if group.iter().any(|g| g != cid) {
            return None;
        }
        Some(r.clone())
    }
    fn derived_vote(&self, initiative_id: &Id) -> Option<VoteDefinition> {
        cv_core::tally::derive_vote(self, initiative_id)
    }
    fn block_merkle_root(&self, height: u32) -> Option<[u8; 32]> {
        self.headers.merkle_root(height)
    }
}

impl LogView for Log {
    fn ballots_of(&self, vote_id: &Id) -> Vec<Ballot> {
        Log::ballots_of(self, vote_id)
            .into_iter()
            .cloned()
            .collect()
    }
    fn supports_of(&self, initiative_id: &Id) -> Vec<Support> {
        Log::supports_of(self, initiative_id)
            .into_iter()
            .cloned()
            .collect()
    }
    fn witnesses_of(&self, content_id: &Id) -> Vec<Witness> {
        Log::witnesses_of(self, content_id)
            .into_iter()
            .cloned()
            .collect()
    }
    fn keyparties_of(&self, vote_id: &Id) -> Vec<KeyParty> {
        Log::keyparties_of(self, vote_id)
            .into_iter()
            .cloned()
            .collect()
    }
    fn shares_of(&self, keyparty_id: &Id) -> Vec<Share> {
        Log::shares_of(self, keyparty_id)
            .into_iter()
            .cloned()
            .collect()
    }
    fn anchored_height(&self, content_id: &Id) -> Option<u32> {
        Log::anchored_height(self, content_id)
    }
    fn any_anchor_at_or_before(&self, height: u32) -> bool {
        Log::any_anchor_at_or_before(self, height)
    }
    fn tip_height(&self) -> Option<u32> {
        self.headers.tip_height()
    }
}

/// Adapter so a `HeaderSource` can serve a `SnapshotView`.
pub struct HeadersAdapter(pub Arc<dyn HeaderSource>);

impl cv_core::snapshot::Headers for HeadersAdapter {
    fn merkle_root(&self, height: u32) -> Option<[u8; 32]> {
        self.0.merkle_root(height)
    }
    fn tip_height(&self) -> Option<u32> {
        self.0.tip_height()
    }
}
