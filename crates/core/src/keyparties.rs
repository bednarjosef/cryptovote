//! `secrecy = keyparties` decryption hook (SPEC §11.3). Implemented in
//! Phase 10 by the `cv-vtc` crate; until then every encrypted ballot is
//! undecryptable and the tally reports zero counts for such votes.

use crate::items::{Id, KeyPartiesPayload};
use std::collections::BTreeMap;

/// Decrypt one ballot payload given the shares of its declared parties.
/// Returns the option index, or `None` if the plaintext is not a valid index.
pub fn decrypt(
    _payload: &KeyPartiesPayload,
    _shares: &BTreeMap<Id, [u8; 32]>,
    _options: usize,
) -> Option<usize> {
    // Phase 10: SK = Σ sk_i; M = c2 − SK·c1; table lookup of m·G.
    None
}
