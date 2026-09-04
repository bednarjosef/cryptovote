//! The ceremony transcript: what each contributor publishes, and how anyone
//! replays the whole thing from scratch (SPEC §18.6).
//!
//! Nothing here is trusted. A transcript is a chain of files: each step
//! answers the digest of the one before it, so the order is fixed by the
//! contents and a step cannot be moved, dropped or inserted afterwards
//! without every later digest changing. Replaying it re-derives the final
//! keys; if the keys you were handed are not the ones the transcript
//! produces, the transcript is not where they came from.
//!
//! An attestation is optional and adds nothing cryptographic. It is what
//! turns "one of these contributors was honest" from a hope into a claim
//! someone's name is attached to.

use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use cv_crypto::sig::{Domain, SigningKey, verify};

use crate::Error;

pub const MAGIC: &[u8; 12] = b"CVCEREMONY1\n";
pub const KIND_PHASE1_ACC: u8 = 1;
pub const KIND_PHASE1_STEP: u8 = 2;
pub const KIND_PHASE2_PARAMS: u8 = 3;
pub const KIND_PHASE2_STEP: u8 = 4;

/// A contributor's signature over the step it made.
#[derive(Clone, Copy, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize)]
pub struct Attestation {
    pub public_key: [u8; 32],
    pub signature: [u8; 64],
}

/// One step of the ceremony: which challenge it answered, what it produced,
/// the proof that it knew its secret, and who says they made it.
#[derive(Clone, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize)]
pub struct Step<P: CanonicalSerialize + CanonicalDeserialize> {
    pub phase: u8,
    pub index: u32,
    pub challenge: [u8; 32],
    pub response: [u8; 32],
    /// Empty for a secret contribution; the public value for a beacon step.
    pub beacon: Vec<u8>,
    pub name: String,
    pub attestation: Option<Attestation>,
    pub pok: P,
}

impl<P: CanonicalSerialize + CanonicalDeserialize> Step<P> {
    pub fn new(phase: u8, index: u32, challenge: [u8; 32], response: [u8; 32], pok: P) -> Self {
        Step {
            phase,
            index,
            challenge,
            response,
            beacon: Vec::new(),
            name: String::new(),
            attestation: None,
            pok,
        }
    }

    /// What an attestation signs: the position in the chain and both digests,
    /// so a signature cannot be lifted onto another step.
    pub fn payload(&self) -> Vec<u8> {
        let mut m = vec![self.phase];
        m.extend_from_slice(&self.index.to_le_bytes());
        m.extend_from_slice(&self.challenge);
        m.extend_from_slice(&self.response);
        m.extend_from_slice(&(self.beacon.len() as u32).to_le_bytes());
        m.extend_from_slice(&self.beacon);
        m.extend_from_slice(self.name.as_bytes());
        m
    }

    pub fn sign(&mut self, key: &SigningKey) {
        let signature = key.sign(Domain::Ceremony, &self.payload());
        self.attestation = Some(Attestation {
            public_key: key.public_key(),
            signature,
        });
    }

    /// The key that vouches for this step, if one does and its signature is
    /// good. A bad signature is reported as no attestation at all by
    /// `Transcript::replay`, which refuses it outright.
    pub fn attested_by(&self) -> Option<[u8; 32]> {
        let a = self.attestation?;
        verify(
            &a.public_key,
            Domain::Ceremony,
            &self.payload(),
            &a.signature,
        )
        .then_some(a.public_key)
    }

    pub fn is_beacon(&self) -> bool {
        !self.beacon.is_empty()
    }
}

/// `MAGIC || kind || canonical compressed payload`.
pub fn encode(kind: u8, value: &impl CanonicalSerialize) -> Vec<u8> {
    let mut out = MAGIC.to_vec();
    out.push(kind);
    value
        .serialize_compressed(&mut out)
        .expect("serialize ceremony file");
    out
}

pub fn decode<T: CanonicalDeserialize>(kind: u8, bytes: &[u8]) -> Result<T, Error> {
    if bytes.len() < MAGIC.len() + 1 || &bytes[..MAGIC.len()] != MAGIC {
        return Err(Error::Malformed("not a ceremony file"));
    }
    if bytes[MAGIC.len()] != kind {
        return Err(Error::Malformed("ceremony file is of the wrong kind"));
    }
    T::deserialize_compressed(&bytes[MAGIC.len() + 1..])
        .map_err(|_| Error::Malformed("ceremony file does not decode"))
}
