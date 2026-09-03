//! Thin wrappers over the primitive crates. No cryptographic primitive is
//! implemented here (Hard rule 1); every function delegates to a crate
//! listed in `DEPENDENCIES.md`.
#![forbid(unsafe_code)]

pub mod field;
pub mod hash;
pub mod merkle;
pub mod sig;
