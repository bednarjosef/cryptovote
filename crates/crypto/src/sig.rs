//! Ed25519 with domain-prefixed messages (SPEC §1.6).

use ed25519_dalek::{Signature, Signer, Verifier};

/// Signature purposes; each has its own message prefix.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Domain {
    /// Authority signing a VoteDefinition: payload = vote_id.
    Vote,
    /// Issuer signing a Registry root: payload = epoch || leaf_count || root.
    Registry,
    /// Node transport messages (Phase 7).
    Transport,
}

impl Domain {
    pub fn prefix(self) -> &'static [u8] {
        match self {
            Domain::Vote => b"cryptovote/v1/sig/vote",
            Domain::Registry => b"cryptovote/v1/sig/registry",
            Domain::Transport => b"cryptovote/v1/sig/transport",
        }
    }

    pub fn message(self, payload: &[u8]) -> Vec<u8> {
        let mut m = Vec::with_capacity(self.prefix().len() + payload.len());
        m.extend_from_slice(self.prefix());
        m.extend_from_slice(payload);
        m
    }
}

/// An Ed25519 signing key.
#[derive(Clone)]
pub struct SigningKey(ed25519_dalek::SigningKey);

impl std::fmt::Debug for SigningKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "SigningKey(pub {})",
            self.0
                .verifying_key()
                .to_bytes()
                .iter()
                .take(4)
                .map(|b| format!("{b:02x}"))
                .collect::<String>()
        )
    }
}

impl SigningKey {
    pub fn from_seed(seed: &[u8; 32]) -> Self {
        SigningKey(ed25519_dalek::SigningKey::from_bytes(seed))
    }

    pub fn generate<R: rand::CryptoRng + rand::RngCore>(rng: &mut R) -> Self {
        SigningKey(ed25519_dalek::SigningKey::generate(rng))
    }

    pub fn seed(&self) -> [u8; 32] {
        self.0.to_bytes()
    }

    pub fn public_key(&self) -> [u8; 32] {
        self.0.verifying_key().to_bytes()
    }

    pub fn sign(&self, domain: Domain, payload: &[u8]) -> [u8; 64] {
        self.0.sign(&domain.message(payload)).to_bytes()
    }
}

/// Verify a domain-prefixed signature. Returns `false` for malformed keys.
pub fn verify(public_key: &[u8; 32], domain: Domain, payload: &[u8], signature: &[u8; 64]) -> bool {
    let Ok(vk) = ed25519_dalek::VerifyingKey::from_bytes(public_key) else {
        return false;
    };
    let sig = Signature::from_bytes(signature);
    vk.verify(&domain.message(payload), &sig).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sign_verify_and_domain_separation() {
        let sk = SigningKey::from_seed(&[9u8; 32]);
        let pk = sk.public_key();
        let sig = sk.sign(Domain::Vote, b"payload");
        assert!(verify(&pk, Domain::Vote, b"payload", &sig));
        assert!(!verify(&pk, Domain::Transport, b"payload", &sig));
        assert!(!verify(&pk, Domain::Vote, b"payloae", &sig));
        assert!(!verify(&[0u8; 32], Domain::Vote, b"payload", &sig) || pk == [0u8; 32]);
    }
}
