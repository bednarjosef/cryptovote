//! `secrecy = keyparties` cryptography (SPEC §10–§11), following
//! Thyagarajan et al., "Verifiable Timed Signatures Made Practical"
//! (CCS 2020), adapted to a discrete-log secret; deviations in SPEC §10.6.
//!
//! This is the one construction in the workspace assembled from lower-level
//! crates rather than taken whole from a library (Hard rule 1 carve-out).
//! Every arithmetic primitive comes from a crate: `curve25519-dalek`
//! (Ristretto255), `num-bigint-dig` (big integers, prime generation,
//! Miller–Rabin), BLAKE3 and XChaCha20-Poly1305 through `cv-crypto`.
//! **It must be audited before any binding use.**
#![forbid(unsafe_code)]

pub mod elgamal;
pub mod puzzle;
pub mod vtc;

pub use elgamal::*;
pub use puzzle::*;
pub use vtc::*;

pub use num_bigint_dig::BigUint;
