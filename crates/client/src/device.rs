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

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Enrollment {
    pub issuer_url: String,
    pub index: u32,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct Stored {
    secret: String,
    enrollment: Option<Enrollment>,
    /// Guard node kept for months (whitepaper §12), Phase 7.
    guard: Option<String>,
    guard_since_unix: Option<u64>,
}

#[derive(Clone, Debug)]
pub struct Device {
    pub secret: Fr,
    pub enrollment: Option<Enrollment>,
    pub guard: Option<String>,
    pub guard_since_unix: Option<u64>,
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
            enrollment: None,
            guard: None,
            guard_since_unix: None,
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
            enrollment: st.enrollment,
            guard: st.guard,
            guard_since_unix: st.guard_since_unix,
        })
    }

    pub fn save(&self, path: &Path) -> anyhow::Result<()> {
        let st = Stored {
            secret: hex::encode(fr_to_bytes(&self.secret)),
            enrollment: self.enrollment.clone(),
            guard: self.guard.clone(),
            guard_since_unix: self.guard_since_unix,
        };
        std::fs::write(path, serde_json::to_vec_pretty(&st)?)?;
        Ok(())
    }

    /// Proving material for a registry given its full leaf list: finds the
    /// device's leaf and computes its sibling path.
    pub fn participant(&self, leaves: &[Fr]) -> Option<Participant> {
        let c = self.commitment();
        let index = leaves.iter().position(|l| *l == c)? as u32;
        let tree = RegistryTree::from_leaves(leaves.to_vec());
        Some(Participant {
            secret: self.secret,
            registry_root: tree.root(),
            index,
            siblings: tree.path(index)?,
        })
    }
}
