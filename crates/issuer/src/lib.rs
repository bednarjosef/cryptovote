//! Issuer reference implementation (whitepaper §5).
//!
//! An Issuer is any operator of a Registry: it decides who counts as one
//! eligible person, and signs root snapshots for that electorate. The
//! protocol does not privilege any of them — items name the `issuer_key`
//! they rely on and every result displays it (SPEC §4.3, §6.1).
//!
//! Everything specific to *how* a person is verified sits behind
//! [`VerificationBackend`]. The core here is backend-agnostic: it takes a
//! verdict, keeps `C`, the dedup key and a timestamp, and publishes a new
//! signed root. Only the mock backend ships in this repository; adapters for
//! real verification methods belong in separate crates.
//!
//! `// TRUST: the Issuer an item names, for that item's electorate
//! (whitepaper §2)` — the one privileged actor for a vote, and it never sees
//! or touches anything but commitments.
#![forbid(unsafe_code)]

pub mod server;

use cv_core::crypto::field::{Fr, fr_from_canonical, fr_to_bytes};
use cv_core::crypto::sig::SigningKey;
use cv_core::registry::{RegistrySnapshot, RegistryTree};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, thiserror::Error)]
pub enum IssuerError {
    #[error("enrollment rejected: {0}")]
    Rejected(String),
    #[error("backend verdict unusable: {0}")]
    Backend(&'static str),
    #[error("commitment is not a canonical field element")]
    Commitment,
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("state file: {0}")]
    State(String),
}

/// What an enrollment asks of the Issuer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnrollmentRequest<'a> {
    /// The identity commitment `C` to place in the Registry (SPEC §4.1).
    pub commitment: Fr,
    /// Opaque credential material for the backend: a token, a signed
    /// assertion, a session id — whatever that verification method uses.
    /// Nothing outside the backend looks inside it.
    pub credential: &'a str,
}

/// A backend's verdict on one enrollment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verification {
    /// The person is verified. `dedup_key` is stable for that person across
    /// enrollments: it is what makes a re-enrollment a *replacement* rather
    /// than a second leaf, and it is the only thing the Issuer stores about
    /// who they are.
    Verified {
        dedup_key: String,
    },
    Rejected {
        reason: String,
    },
}

/// The one thing an Issuer needs from an identity-verification method.
///
/// How a person is proven real and unique — a national eID, an in-person
/// check, a document-and-liveness provider, a web of trust — is entirely the
/// Issuer's business, and is the boundary of Sybil resistance for that
/// electorate. Adapters live in their own crates; this repository ships only
/// [`MockBackend`].
pub trait VerificationBackend: Send + Sync {
    fn verify(&self, request: &EnrollmentRequest) -> Verification;
}

/// Development backend: accepts any non-empty credential and uses it as the
/// dedup key. INSECURE — there is no identity check at all.
pub struct MockBackend;

impl VerificationBackend for MockBackend {
    fn verify(&self, request: &EnrollmentRequest) -> Verification {
        if request.credential.is_empty() {
            Verification::Rejected {
                reason: "empty credential".into(),
            }
        } else {
            Verification::Verified {
                dedup_key: request.credential.to_string(),
            }
        }
    }
}

/// Where an enrollment landed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Enrolled {
    pub index: u32,
    /// The person already had a leaf; it was overwritten (whitepaper §5).
    pub replaced: bool,
}

/// Everything the Issuer keeps about one leaf: who it belongs to (as an
/// opaque dedup key) and when it was last written. `C` itself is the tree
/// leaf at the same index.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Record {
    pub dedup_key: String,
    pub enrolled_unix: u64,
}

#[derive(Serialize, Deserialize)]
struct State {
    key_seed: String,
    epoch: u64,
    leaves: Vec<String>,
    records: Vec<Record>,
    #[serde(default)]
    authority_keys: Vec<String>,
}

pub struct Issuer {
    key: SigningKey,
    tree: RegistryTree,
    records: Vec<Record>,
    by_dedup: HashMap<String, u32>,
    epoch: u64,
    /// Who may call top-down votes over this electorate (SPEC §4.3). Empty is
    /// the default and means none: this electorate votes only on initiatives
    /// its own members raise. An Issuer that calls its own votes adds its own
    /// key here.
    authority_keys: Vec<[u8; 32]>,
    backend: Box<dyn VerificationBackend>,
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

impl Issuer {
    pub fn new(key: SigningKey, backend: Box<dyn VerificationBackend>) -> Self {
        Issuer {
            key,
            tree: RegistryTree::new(),
            records: Vec::new(),
            by_dedup: HashMap::new(),
            epoch: 1,
            authority_keys: Vec::new(),
            backend,
        }
    }

    pub fn dev(seed: [u8; 32]) -> Self {
        eprintln!(
            "WARNING: issuer running with the MOCK verification backend — anyone can enroll. Dev mode only."
        );
        Self::new(SigningKey::from_seed(&seed), Box::new(MockBackend))
    }

    /// This Issuer's identity: the key every item of its electorate names.
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

    pub fn records(&self) -> &[Record] {
        &self.records
    }

    /// Enroll: ask the backend, then insert `C` as a new leaf or replace the
    /// leaf this person already has (whitepaper §5). Either way the epoch
    /// advances, so `snapshot()` publishes a new signed root.
    pub fn enroll(&mut self, request: &EnrollmentRequest) -> Result<Enrolled, IssuerError> {
        // TRUST: the Issuer decides who is one eligible person (whitepaper §2).
        let dedup_key = match self.backend.verify(request) {
            Verification::Verified { dedup_key } => dedup_key,
            Verification::Rejected { reason } => return Err(IssuerError::Rejected(reason)),
        };
        if dedup_key.is_empty() {
            // Would make every enrollment the same person.
            return Err(IssuerError::Backend("empty dedup key"));
        }
        let now = unix_now();
        let enrolled = if let Some(&index) = self.by_dedup.get(&dedup_key) {
            self.tree.set(index, request.commitment);
            self.records[index as usize].enrolled_unix = now;
            Enrolled {
                index,
                replaced: true,
            }
        } else {
            let index = self.tree.push(request.commitment);
            self.records.push(Record {
                dedup_key: dedup_key.clone(),
                enrolled_unix: now,
            });
            self.by_dedup.insert(dedup_key, index);
            Enrolled {
                index,
                replaced: false,
            }
        };
        self.epoch += 1;
        Ok(enrolled)
    }

    pub fn snapshot(&self) -> RegistrySnapshot {
        RegistrySnapshot::sign(
            &self.key,
            self.epoch,
            &self.tree,
            self.authority_keys.clone(),
        )
    }

    pub fn authority_keys(&self) -> &[[u8; 32]] {
        &self.authority_keys
    }

    /// Replace the set of vote creators this electorate accepts. The epoch
    /// advances so the next `snapshot()` is a new signed statement of it —
    /// a key removed here cannot create votes against later snapshots.
    pub fn set_authority_keys(&mut self, keys: Vec<[u8; 32]>) {
        self.authority_keys = keys;
        self.epoch += 1;
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
            records: self.records.clone(),
            authority_keys: self.authority_keys.iter().map(hex::encode).collect(),
        };
        std::fs::write(
            path,
            serde_json::to_vec_pretty(&st).map_err(|e| IssuerError::State(e.to_string()))?,
        )?;
        Ok(())
    }

    pub fn load(path: &Path, backend: Box<dyn VerificationBackend>) -> Result<Self, IssuerError> {
        let st: State = serde_json::from_slice(&std::fs::read(path)?)
            .map_err(|e| IssuerError::State(e.to_string()))?;
        let seed: [u8; 32] = hex::decode(&st.key_seed)
            .ok()
            .and_then(|v| v.try_into().ok())
            .ok_or_else(|| IssuerError::State("bad key seed".into()))?;
        if st.records.len() != st.leaves.len() {
            return Err(IssuerError::State("records do not match leaves".into()));
        }
        let mut leaves = Vec::with_capacity(st.leaves.len());
        for l in &st.leaves {
            let b: [u8; 32] = hex::decode(l)
                .ok()
                .and_then(|v| v.try_into().ok())
                .ok_or_else(|| IssuerError::State("bad leaf".into()))?;
            leaves.push(fr_from_canonical(&b).ok_or(IssuerError::Commitment)?);
        }
        let by_dedup = st
            .records
            .iter()
            .enumerate()
            .map(|(i, r)| (r.dedup_key.clone(), i as u32))
            .collect();
        Ok(Issuer {
            key: SigningKey::from_seed(&seed),
            tree: RegistryTree::from_leaves(leaves),
            records: st.records,
            by_dedup,
            epoch: st.epoch,
            authority_keys: st
                .authority_keys
                .iter()
                .filter_map(|k| hex::decode(k).ok()?.try_into().ok())
                .collect(),
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
