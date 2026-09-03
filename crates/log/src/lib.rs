//! Log storage: an append-only set of self-validating items with the set
//! semantics of SPEC §7 (duplicates by content id, orphan pool, pruning),
//! indexes for the light-client queries of whitepaper §12, and the
//! `Context` the validity rules need.
#![forbid(unsafe_code)]

pub mod headers;
pub mod log;
pub mod store;

pub use log::*;
