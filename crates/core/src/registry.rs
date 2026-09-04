//! Registry: sparse depth-32 Poseidon Merkle tree and the Issuer-signed
//! snapshot (SPEC §4).

use crate::constants::{MAX_AUTHORITY_KEYS, REGISTRY_DEPTH};
use crate::encoding::{Reader, Writer};
use crate::error::DecodeError;
use cv_crypto::field::Fr;
use cv_crypto::poseidon;
use cv_crypto::sig::{Domain, SigningKey, verify};
use std::sync::OnceLock;

/// `E_0 = Fr(0)`, `E_{k+1} = poseidon(E_k, E_k)`.
pub fn empty_hashes() -> &'static [Fr; REGISTRY_DEPTH + 1] {
    static E: OnceLock<[Fr; REGISTRY_DEPTH + 1]> = OnceLock::new();
    E.get_or_init(|| {
        let mut e = [Fr::from(0u64); REGISTRY_DEPTH + 1];
        for k in 0..REGISTRY_DEPTH {
            e[k + 1] = poseidon::hash2(&e[k], &e[k]);
        }
        e
    })
}

/// In-memory sparse Merkle tree; level 0 holds the leaves in index order.
#[derive(Clone, Debug)]
pub struct RegistryTree {
    levels: Vec<Vec<Fr>>,
}

impl Default for RegistryTree {
    fn default() -> Self {
        Self::new()
    }
}

impl RegistryTree {
    pub fn new() -> Self {
        RegistryTree {
            levels: vec![Vec::new(); REGISTRY_DEPTH + 1],
        }
    }

    pub fn from_leaves(leaves: Vec<Fr>) -> Self {
        let mut t = Self::new();
        for l in leaves {
            t.push(l);
        }
        t
    }

    pub fn leaf_count(&self) -> u64 {
        self.levels[0].len() as u64
    }

    pub fn leaves(&self) -> &[Fr] {
        &self.levels[0]
    }

    fn node(&self, level: usize, idx: usize) -> Fr {
        self.levels[level]
            .get(idx)
            .copied()
            .unwrap_or(empty_hashes()[level])
    }

    pub fn root(&self) -> Fr {
        self.node(REGISTRY_DEPTH, 0)
    }

    /// Append a leaf; returns its index.
    pub fn push(&mut self, leaf: Fr) -> u32 {
        let index = self.levels[0].len();
        assert!((index as u64) < (1u64 << REGISTRY_DEPTH), "registry full");
        self.levels[0].push(leaf);
        self.recompute_path(index);
        index as u32
    }

    /// Replace the leaf at `index` (device replacement, SPEC §4.2).
    pub fn set(&mut self, index: u32, leaf: Fr) {
        let index = index as usize;
        assert!(index < self.levels[0].len(), "index out of range");
        self.levels[0][index] = leaf;
        self.recompute_path(index);
    }

    fn recompute_path(&mut self, index: usize) {
        let mut idx = index;
        for k in 0..REGISTRY_DEPTH {
            let parent = idx >> 1;
            let h = poseidon::hash2(&self.node(k, 2 * parent), &self.node(k, 2 * parent + 1));
            if parent < self.levels[k + 1].len() {
                self.levels[k + 1][parent] = h;
            } else {
                debug_assert_eq!(parent, self.levels[k + 1].len());
                self.levels[k + 1].push(h);
            }
            idx = parent;
        }
    }

    /// Sibling path for a leaf (level 0 first).
    pub fn path(&self, index: u32) -> Option<[Fr; REGISTRY_DEPTH]> {
        let index = index as usize;
        if index >= self.levels[0].len() {
            return None;
        }
        let mut sib = [Fr::from(0u64); REGISTRY_DEPTH];
        let mut idx = index;
        for (k, s) in sib.iter_mut().enumerate() {
            *s = self.node(k, idx ^ 1);
            idx >>= 1;
        }
        Some(sib)
    }
}

/// Recompute a root from a leaf and its sibling path (the rule the circuit enforces).
pub fn root_from_path(leaf: Fr, index: u32, siblings: &[Fr; REGISTRY_DEPTH]) -> Fr {
    let mut cur = leaf;
    for (k, s) in siblings.iter().enumerate() {
        cur = if (index >> k) & 1 == 1 {
            poseidon::hash2(s, &cur)
        } else {
            poseidon::hash2(&cur, s)
        };
    }
    cur
}

/// Issuer-signed snapshot header (SPEC §4.3). It names its own Issuer:
/// several Issuers coexist and each item on the Log says which one it means.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RegistrySnapshot {
    pub epoch: u64,
    pub leaf_count: u64,
    pub root: Fr,
    pub issuer_key: [u8; 32],
    /// Keys the Issuer accepts as creators of top-down votes over this
    /// electorate (SPEC §4.3, §6.1). Empty means none: only initiatives can
    /// produce a vote. An Issuer that also calls its own votes lists itself.
    pub authority_keys: Vec<[u8; 32]>,
    pub signature: [u8; 64],
}

impl RegistrySnapshot {
    fn payload(epoch: u64, leaf_count: u64, root: &Fr, authority_keys: &[[u8; 32]]) -> Vec<u8> {
        let mut w = Writer::new();
        w.u64(epoch);
        w.u64(leaf_count);
        w.fr(root);
        w.list_len(authority_keys.len());
        for k in authority_keys {
            w.fixed(k);
        }
        w.into_inner()
    }

    pub fn sign(
        issuer: &SigningKey,
        epoch: u64,
        tree: &RegistryTree,
        authority_keys: Vec<[u8; 32]>,
    ) -> Self {
        let root = tree.root();
        let leaf_count = tree.leaf_count();
        let signature = issuer.sign(
            Domain::Registry,
            &Self::payload(epoch, leaf_count, &root, &authority_keys),
        );
        RegistrySnapshot {
            epoch,
            leaf_count,
            root,
            issuer_key: issuer.public_key(),
            authority_keys,
            signature,
        }
    }

    /// `// TRUST: the Issuer an item names, for that item's electorate
    /// (whitepaper §2, §5)` — all that is checked here is that the snapshot
    /// carries a valid signature by the `issuer_key` it names. Whether that
    /// Issuer is worth trusting is a question for whoever reads the result,
    /// which is why every result displays it.
    pub fn verify(&self) -> bool {
        verify(
            &self.issuer_key,
            Domain::Registry,
            &Self::payload(
                self.epoch,
                self.leaf_count,
                &self.root,
                &self.authority_keys,
            ),
            &self.signature,
        )
    }

    /// Signed by this specific Issuer (deployment policy, SPEC §4.3).
    pub fn verify_by(&self, expected_issuer: &[u8; 32]) -> bool {
        &self.issuer_key == expected_issuer && self.verify()
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.u64(self.epoch);
        w.u64(self.leaf_count);
        w.fr(&self.root);
        w.fixed(&self.issuer_key);
        w.list_len(self.authority_keys.len());
        for k in &self.authority_keys {
            w.fixed(k);
        }
        w.fixed(&self.signature);
        w.into_inner()
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        let (s, used) = Self::decode_prefix(bytes)?;
        if used != bytes.len() {
            return Err(DecodeError::Trailing);
        }
        Ok(s)
    }

    /// Decode a snapshot from the start of `bytes` and report how many it
    /// used. The snapshot is variable-length now that it carries
    /// `authority_keys`, so a caller with more data after it (the leaves file,
    /// §4.3) cannot slice at a constant offset.
    pub fn decode_prefix(bytes: &[u8]) -> Result<(Self, usize), DecodeError> {
        let mut r = Reader::new(bytes);
        let epoch = r.u64()?;
        let leaf_count = r.u64()?;
        let root = r.fr()?;
        let issuer_key = r.fixed()?;
        let n = r.list_len(MAX_AUTHORITY_KEYS)?;
        let mut authority_keys = Vec::with_capacity(n);
        for _ in 0..n {
            authority_keys.push(r.fixed()?);
        }
        let s = RegistrySnapshot {
            epoch,
            leaf_count,
            root,
            issuer_key,
            authority_keys,
            signature: r.fixed()?,
        };
        Ok((s, r.position()))
    }
}

/// Leaves file: 32-byte canonical field elements, concatenated.
pub fn encode_leaves(leaves: &[Fr]) -> Vec<u8> {
    let mut w = Writer::new();
    for l in leaves {
        w.fr(l);
    }
    w.into_inner()
}

pub fn decode_leaves(bytes: &[u8]) -> Result<Vec<Fr>, DecodeError> {
    if bytes.len() % 32 != 0 {
        return Err(DecodeError::Trailing);
    }
    let mut r = Reader::new(bytes);
    let mut out = Vec::with_capacity(bytes.len() / 32);
    while r.remaining() > 0 {
        out.push(r.fr()?);
    }
    Ok(out)
}
