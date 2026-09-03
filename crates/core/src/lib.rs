//! The single implementation of the protocol rules (SPEC.md): types,
//! canonical serialization, content ids, validity rules and tally.
//! Node, client and verifier all call into this crate; nothing here is
//! duplicated elsewhere.
#![forbid(unsafe_code)]

pub mod build;
pub mod constants;
pub mod context;
pub mod encoding;
pub mod error;
pub mod identity;
pub mod items;
pub mod registry;
pub mod validate;
pub mod wire;

pub use cv_crypto as crypto;
pub use error::DecodeError;
pub use items::*;
