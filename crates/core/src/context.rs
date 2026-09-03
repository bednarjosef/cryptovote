//! What validation needs to know about the world: referenced objects,
//! deployment constants, and the dev-mode flag.

use crate::items::*;
use cv_crypto::field::Fr;
use cv_crypto::groth16::MembershipKeys;
use std::collections::HashMap;

/// A known Registry snapshot (only what validation needs).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RegistryInfo {
    pub leaf_count: u64,
}

/// Deployment constants.
#[derive(Clone, Debug)]
pub struct Deployment {
    /// `// TRUST: authority keys for *creating* votes only (whitepaper §7)`.
    pub authority_keys: Vec<[u8; 32]>,
    /// `// TRUST: Issuer for the electorate (whitepaper §2)`.
    pub issuer_key: [u8; 32],
    /// One flag for every insecure shortcut (SPEC §14). Binaries print a
    /// warning at startup when it is set.
    pub dev_mode: bool,
}

/// Lookup interface used by the validity rules. Implemented by the Log
/// (node), by the snapshot loader (verifier), and by `MemoryContext` (tests,
/// simulation).
pub trait Context {
    fn deployment(&self) -> &Deployment;
    fn membership_keys(&self) -> &MembershipKeys;
    fn registry(&self, root: &Fr) -> Option<RegistryInfo>;
    fn vote(&self, id: &Id) -> Option<VoteDefinition>;
    fn initiative(&self, id: &Id) -> Option<Initiative>;
    fn keyparty(&self, id: &Id) -> Option<KeyParty>;
    /// A valid, non-duplicated NodeRegistration by its Ed25519 key.
    fn node_registration(&self, node_key: &[u8; 32]) -> Option<NodeRegistration>;
    /// The VoteDefinition derived from an initiative (SPEC §13), if its
    /// threshold has been reached in this context's view.
    fn derived_vote(&self, initiative_id: &Id) -> Option<VoteDefinition>;
    /// Merkle root of the Bitcoin block at `height`, if the header is known
    /// and usable (SPEC §9).
    fn block_merkle_root(&self, height: u32) -> Option<[u8; 32]>;
    fn dev_mode(&self) -> bool {
        self.deployment().dev_mode
    }
}

/// In-memory context for tests and the simulation.
pub struct MemoryContext {
    pub deployment: Deployment,
    pub keys: &'static MembershipKeys,
    pub registries: HashMap<Fr, RegistryInfo>,
    pub votes: HashMap<Id, VoteDefinition>,
    pub initiatives: HashMap<Id, Initiative>,
    pub keyparties: HashMap<Id, KeyParty>,
    pub nodes: HashMap<[u8; 32], NodeRegistration>,
    pub derived: HashMap<Id, VoteDefinition>,
    pub headers: HashMap<u32, [u8; 32]>,
}

impl MemoryContext {
    pub fn new(deployment: Deployment, keys: &'static MembershipKeys) -> Self {
        MemoryContext {
            deployment,
            keys,
            registries: HashMap::new(),
            votes: HashMap::new(),
            initiatives: HashMap::new(),
            keyparties: HashMap::new(),
            nodes: HashMap::new(),
            derived: HashMap::new(),
            headers: HashMap::new(),
        }
    }

    pub fn add_registry(&mut self, root: Fr, leaf_count: u64) {
        self.registries.insert(root, RegistryInfo { leaf_count });
    }

    pub fn add_vote(&mut self, v: VoteDefinition) -> Id {
        let id = v.vote_id();
        self.votes.insert(id, v);
        id
    }

    pub fn add_initiative(&mut self, i: Initiative) -> Id {
        let id = i.content_id();
        self.initiatives.insert(id, i);
        id
    }
}

impl Context for MemoryContext {
    fn deployment(&self) -> &Deployment {
        &self.deployment
    }
    fn membership_keys(&self) -> &MembershipKeys {
        self.keys
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
        self.keyparties.get(id).cloned()
    }
    fn node_registration(&self, node_key: &[u8; 32]) -> Option<NodeRegistration> {
        self.nodes.get(node_key).cloned()
    }
    fn derived_vote(&self, initiative_id: &Id) -> Option<VoteDefinition> {
        self.derived.get(initiative_id).cloned()
    }
    fn block_merkle_root(&self, height: u32) -> Option<[u8; 32]> {
        self.headers.get(&height).copied()
    }
}
