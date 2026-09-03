//! Thin wrappers over the primitive crates. No cryptographic primitive is
//! implemented here (Hard rule 1); every function delegates to a crate
//! listed in `DEPENDENCIES.md`. The only composed construction in the
//! workspace (the verifiable timed commitment, SPEC §10) lives in `vtc`
//! (Phase 10).
#![forbid(unsafe_code)]

pub mod circuit;
pub mod field;
pub mod groth16;
pub mod hash;
pub mod merkle;
pub mod ots;
pub mod poseidon;
pub mod sig;
pub mod spv;
