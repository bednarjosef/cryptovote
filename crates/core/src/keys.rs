//! Which membership verifying key this build trusts (SPEC §18.7).
//!
//! A ceremony removes the party who could forge membership proofs. It only
//! does that for people who *use the key it produced*: an attacker who can
//! hand a voter a different verifying key does not need anyone's toxic waste,
//! because they can run a one-person setup and keep it. So the ceremony is
//! worth exactly as much as the pin — the point at which software refuses a
//! key it was not expecting.
//!
//! The pin can come from two places, and release mode requires one of them:
//!
//! * `MEMBERSHIP_VK_BLAKE3`, compiled in. This is the strong form: the value
//!   travels with the binary a voter installed, and changing it means
//!   shipping different software.
//! * `--vk-hash` on the command line, like `--checkpoint-header`. Weaker —
//!   it trusts whoever wrote the command line — but it is what a deployment
//!   has before it has forked and rebuilt, and it still refuses a key
//!   substituted underneath a running deployment.
//!
//! Neither is a substitute for reading the ceremony transcript. The pin says
//! "this is the key I meant"; only `cv-ceremony verify` says where that key
//! came from and who contributed to it.

use cv_crypto::groth16::{MembershipVerifier, vk_to_bytes};
use cv_crypto::hash::blake3_hash;

/// BLAKE3 of the canonical compressed verifying key this build accepts.
///
/// `None` here, because this repository ships no ceremony: nobody has run
/// one for any deployment, and a hash invented now would be a hash of the
/// development key, which anyone can forge against. A deployment sets it to
/// the value `cv-ceremony finalize` printed for its own ceremony, and from
/// then on its binaries cannot be pointed at any other key.
pub const MEMBERSHIP_VK_BLAKE3: Option<[u8; 32]> = None;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum KeyPinError {
    #[error(
        "release mode will not run without knowing which membership verifying key to trust: \
         pass --vk-hash <hex> (the value `cv-ceremony finalize` printed for your ceremony), \
         or build with MEMBERSHIP_VK_BLAKE3 set. Without it, keys from a setup someone ran \
         alone are accepted as readily as keys from a ceremony, and forged ballots are \
         indistinguishable from real ones"
    )]
    NoPin,
    #[error(
        "--vk-hash {given} contradicts the key pinned into this build ({pinned}); \
         the build's pin wins and this deployment is misconfigured"
    )]
    Conflict { pinned: String, given: String },
    #[error(
        "this is not the verifying key this deployment trusts: expected {expected}, loaded \
         {loaded}. Either the key file is not the one your ceremony produced, or someone \
         has replaced it"
    )]
    Mismatch { expected: String, loaded: String },
}

/// BLAKE3 of a verifying key, the value that gets pinned.
pub fn vk_hash(verifier: &MembershipVerifier) -> [u8; 32] {
    blake3_hash(&vk_to_bytes(&verifier.vk))
}

/// Check a loaded key against whatever this deployment pins. Returns the hash
/// it matched, for binaries to print.
pub fn check_pin(
    verifier: &MembershipVerifier,
    from_command_line: Option<[u8; 32]>,
) -> Result<[u8; 32], KeyPinError> {
    let expected = match (MEMBERSHIP_VK_BLAKE3, from_command_line) {
        (Some(pinned), Some(given)) if pinned != given => {
            return Err(KeyPinError::Conflict {
                pinned: hex::encode(pinned),
                given: hex::encode(given),
            });
        }
        (Some(pinned), _) => pinned,
        (None, Some(given)) => given,
        (None, None) => return Err(KeyPinError::NoPin),
    };
    let loaded = vk_hash(verifier);
    if loaded != expected {
        return Err(KeyPinError::Mismatch {
            expected: hex::encode(expected),
            loaded: hex::encode(loaded),
        });
    }
    Ok(loaded)
}

#[cfg(test)]
mod tests {
    use super::*;
    use cv_crypto::groth16::dev_keys;

    #[test]
    fn a_key_is_accepted_only_against_its_own_hash() {
        let v = &dev_keys().verifier;
        let h = vk_hash(v);
        assert_eq!(check_pin(v, Some(h)), Ok(h));
        assert!(matches!(
            check_pin(v, Some([0u8; 32])),
            Err(KeyPinError::Mismatch { .. })
        ));
    }

    #[test]
    fn release_mode_refuses_to_guess() {
        // With no compiled-in pin and no --vk-hash there is nothing to check
        // against, and silently accepting the file would make the ceremony
        // pointless.
        assert_eq!(
            MEMBERSHIP_VK_BLAKE3, None,
            "this repository ships no ceremony"
        );
        assert!(matches!(
            check_pin(&dev_keys().verifier, None),
            Err(KeyPinError::NoPin)
        ));
    }
}
