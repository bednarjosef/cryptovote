//! Participant-side library: light client over the node API, enrollment,
//! ballots, initiatives, supports (Phase 6), mix client and Tor (Phase 7),
//! UniFFI bindings (Phase 7).
#![forbid(unsafe_code)]

pub mod device;
#[cfg(feature = "ffi")]
pub mod ffi;
pub mod light;
pub mod mix;
pub mod participant;
#[cfg(feature = "tor")]
pub mod tor;

#[cfg(feature = "ffi")]
uniffi::setup_scaffolding!();
