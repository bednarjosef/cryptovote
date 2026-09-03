//! The participant's device state: the secret `s` (which never leaves the
//! device — here a file, in production the secure element) and its
//! enrollment. `// TRUST: the voter's device for its own ballot only
//! (whitepaper §2)`.

use cv_core::build::Participant;
use cv_core::crypto::field::{Fr, fr_from_canonical, fr_to_bytes};
use cv_core::identity::commitment;
use cv_core::registry::RegistryTree;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::path::Path;

/// One registry the device is enrolled in. A person may legitimately hold a
/// leaf in several registries (whitepaper §5): nullifiers are scoped per vote
/// and votes name one Issuer, so this creates no double voting anywhere.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Enrollment {
    pub issuer_url: String,
    /// The Issuer's Ed25519 key (hex) — what items name.
    pub issuer_key: String,
    pub index: u32,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct Stored {
    secret: String,
    #[serde(default)]
    enrollments: Vec<Enrollment>,
    /// Guard node kept for months (whitepaper §12), Phase 7.
    guard: Option<String>,
    guard_since_unix: Option<u64>,
    /// vote id (hex) → key-party secret (hex), kept until the share is published.
    #[serde(default)]
    keyparty_secrets: std::collections::BTreeMap<String, String>,
}

#[derive(Clone, Debug)]
pub struct Device {
    pub secret: Fr,
    pub enrollments: Vec<Enrollment>,
    pub guard: Option<String>,
    pub guard_since_unix: Option<u64>,
    pub keyparty_secrets: std::collections::BTreeMap<String, String>,
}

impl Device {
    /// Fresh secret: 64 random bytes reduced mod r (SPEC §4.1).
    pub fn generate<R: RngCore + rand::CryptoRng>(rng: &mut R) -> Self {
        let mut wide = [0u8; 64];
        rng.fill_bytes(&mut wide);
        use ark_ff::PrimeField;
        let secret = Fr::from_le_bytes_mod_order(&wide);
        Device {
            secret,
            enrollments: Vec::new(),
            guard: None,
            guard_since_unix: None,
            keyparty_secrets: Default::default(),
        }
    }

    pub fn commitment(&self) -> Fr {
        commitment(&self.secret)
    }

    pub fn load(path: &Path) -> anyhow::Result<Self> {
        let st: Stored = serde_json::from_slice(&std::fs::read(path)?)?;
        let b: [u8; 32] = hex::decode(&st.secret)?
            .try_into()
            .map_err(|_| anyhow::anyhow!("bad secret"))?;
        let secret =
            fr_from_canonical(&b).ok_or_else(|| anyhow::anyhow!("non-canonical secret"))?;
        Ok(Device {
            secret,
            enrollments: st.enrollments,
            guard: st.guard,
            guard_since_unix: st.guard_since_unix,
            keyparty_secrets: st.keyparty_secrets,
        })
    }

    pub fn save(&self, path: &Path) -> anyhow::Result<()> {
        let st = Stored {
            secret: hex::encode(fr_to_bytes(&self.secret)),
            enrollments: self.enrollments.clone(),
            guard: self.guard.clone(),
            guard_since_unix: self.guard_since_unix,
            keyparty_secrets: self.keyparty_secrets.clone(),
        };
        std::fs::write(path, serde_json::to_vec_pretty(&st)?)?;
        Ok(())
    }

    /// Proving material for one Issuer's registry given its full leaf list:
    /// finds the device's leaf and computes its sibling path.
    pub fn participant(&self, issuer_key: &[u8; 32], leaves: &[Fr]) -> Option<Participant> {
        let c = self.commitment();
        let index = leaves.iter().position(|l| *l == c)? as u32;
        let tree = RegistryTree::from_leaves(leaves.to_vec());
        Some(Participant {
            secret: self.secret,
            issuer_key: *issuer_key,
            registry_root: tree.root(),
            index,
            siblings: tree.path(index)?,
        })
    }

    /// Record (or refresh) an enrollment with one Issuer.
    pub fn record_enrollment(&mut self, issuer_url: &str, issuer_key: &str, index: u32) {
        let e = Enrollment {
            issuer_url: issuer_url.to_string(),
            issuer_key: issuer_key.to_string(),
            index,
        };
        match self
            .enrollments
            .iter_mut()
            .find(|x| x.issuer_key == e.issuer_key)
        {
            Some(existing) => *existing = e,
            None => self.enrollments.push(e),
        }
    }
}
