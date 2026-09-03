//! Issuer reference implementation (whitepaper §5) with a **mock eID
//! backend for development**: any eID string is accepted. A real deployment
//! replaces `MockEid` with the state eID authentication and keeps everything
//! else.
//!
//! `// TRUST: Issuer for the electorate (whitepaper §2)` — this is the one
//! privileged actor; it never sees or touches anything but commitments.
#![forbid(unsafe_code)]

pub mod server;

use cv_core::crypto::field::{Fr, fr_from_canonical, fr_to_bytes};
use cv_core::crypto::sig::SigningKey;
use cv_core::registry::{RegistrySnapshot, RegistryTree};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;

#[derive(Debug, thiserror::Error)]
pub enum IssuerError {
    #[error("eID authentication failed")]
    Auth,
    #[error("commitment is not a canonical field element")]
    Commitment,
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("state file: {0}")]
    State(String),
}

/// Development-only eID backend: accepts any non-empty identifier.
pub trait EidBackend: Send + Sync {
    fn authenticate(&self, eid: &str) -> bool;
}

pub struct MockEid;

impl EidBackend for MockEid {
    fn authenticate(&self, eid: &str) -> bool {
        // INSECURE: no real identity check. Dev mode only.
        !eid.is_empty()
    }
}

#[derive(Serialize, Deserialize)]
struct State {
    key_seed: String,
    epoch: u64,
    leaves: Vec<String>,
    by_eid: HashMap<String, u32>,
}

pub struct Issuer {
    key: SigningKey,
    tree: RegistryTree,
    by_eid: HashMap<String, u32>,
    epoch: u64,
    backend: Box<dyn EidBackend>,
}

impl Issuer {
    pub fn new(key: SigningKey, backend: Box<dyn EidBackend>) -> Self {
        Issuer {
            key,
            tree: RegistryTree::new(),
            by_eid: HashMap::new(),
            epoch: 1,
            backend,
        }
    }

    pub fn dev(seed: [u8; 32]) -> Self {
        eprintln!(
            "WARNING: issuer running with the MOCK eID backend — anyone can enroll. Dev mode only."
        );
        Self::new(SigningKey::from_seed(&seed), Box::new(MockEid))
    }

    pub fn public_key(&self) -> [u8; 32] {
        self.key.public_key()
    }

    pub fn epoch(&self) -> u64 {
        self.epoch
    }

    pub fn leaf_count(&self) -> u64 {
        self.tree.leaf_count()
    }

    pub fn tree(&self) -> &RegistryTree {
        &self.tree
    }

    /// Enroll (or re-enroll: replacement in place, whitepaper §5).
    /// Returns `(index, replaced)`.
    pub fn enroll(&mut self, eid: &str, commitment: Fr) -> Result<(u32, bool), IssuerError> {
        if !self.backend.authenticate(eid) {
            return Err(IssuerError::Auth);
        }
        if let Some(&index) = self.by_eid.get(eid) {
            self.tree.set(index, commitment);
            self.epoch += 1;
            return Ok((index, true));
        }
        let index = self.tree.push(commitment);
        self.by_eid.insert(eid.to_string(), index);
        self.epoch += 1;
        Ok((index, false))
    }

    pub fn snapshot(&self) -> RegistrySnapshot {
        RegistrySnapshot::sign(&self.key, self.epoch, &self.tree)
    }

    pub fn leaves(&self) -> &[Fr] {
        self.tree.leaves()
    }

    pub fn save(&self, path: &Path) -> Result<(), IssuerError> {
        let st = State {
            key_seed: hex::encode(self.key.seed()),
            epoch: self.epoch,
            leaves: self
                .tree
                .leaves()
                .iter()
                .map(|l| hex::encode(fr_to_bytes(l)))
                .collect(),
            by_eid: self.by_eid.clone(),
        };
        std::fs::write(
            path,
            serde_json::to_vec_pretty(&st).map_err(|e| IssuerError::State(e.to_string()))?,
        )?;
        Ok(())
    }

    pub fn load(path: &Path, backend: Box<dyn EidBackend>) -> Result<Self, IssuerError> {
        let st: State = serde_json::from_slice(&std::fs::read(path)?)
            .map_err(|e| IssuerError::State(e.to_string()))?;
        let seed: [u8; 32] = hex::decode(&st.key_seed)
            .ok()
            .and_then(|v| v.try_into().ok())
            .ok_or_else(|| IssuerError::State("bad key seed".into()))?;
        let mut leaves = Vec::with_capacity(st.leaves.len());
        for l in &st.leaves {
            let b: [u8; 32] = hex::decode(l)
                .ok()
                .and_then(|v| v.try_into().ok())
                .ok_or_else(|| IssuerError::State("bad leaf".into()))?;
            leaves.push(fr_from_canonical(&b).ok_or(IssuerError::Commitment)?);
        }
        Ok(Issuer {
            key: SigningKey::from_seed(&seed),
            tree: RegistryTree::from_leaves(leaves),
            by_eid: st.by_eid,
            epoch: st.epoch,
            backend,
        })
    }
}

/// Decode a commitment submitted as hex.
pub fn parse_commitment(hex_str: &str) -> Result<Fr, IssuerError> {
    let b: [u8; 32] = hex::decode(hex_str)
        .ok()
        .and_then(|v| v.try_into().ok())
        .ok_or(IssuerError::Commitment)?;
    fr_from_canonical(&b).ok_or(IssuerError::Commitment)
}
