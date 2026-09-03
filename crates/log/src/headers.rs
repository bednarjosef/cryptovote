//! Bitcoin header sources for nodes: the validated `HeaderChain` (from
//! `cv-core`) behind a `HeaderSource`, and the dev-only mock chain driven by
//! the local clock.

use cv_core::crypto::spv;
pub use cv_core::headers::{HEADERS_MAGIC, HeaderChain, HeaderError};
use std::sync::{Mutex, RwLock};
use std::time::Instant;

/// Whatever validation needs from Bitcoin (SPEC §9).
pub trait HeaderSource: Send + Sync {
    /// Merkle root (internal byte order) of a *usable* block at `height`.
    fn merkle_root(&self, height: u32) -> Option<[u8; 32]>;
    /// Height of the highest usable header.
    fn tip_height(&self) -> Option<u32>;
}

/// Shareable header chain usable as a `HeaderSource`.
pub struct SharedHeaderChain(pub RwLock<HeaderChain>);

impl SharedHeaderChain {
    pub fn new(chain: HeaderChain) -> Self {
        SharedHeaderChain(RwLock::new(chain))
    }
}

impl HeaderSource for SharedHeaderChain {
    fn merkle_root(&self, height: u32) -> Option<[u8; 32]> {
        let c = self.0.read().unwrap();
        if height > c.usable_tip()? {
            return None;
        }
        c.header_at(height).map(spv::merkle_root)
    }

    fn tip_height(&self) -> Option<u32> {
        self.0.read().unwrap().usable_tip()
    }
}

/// **Dev mode only.** A fake chain driven by the local clock: one block
/// every `block_seconds`, merkle roots derived from the height. Anyone can
/// "anchor" anything at any height, so this provides no ordering guarantee.
pub struct MockChain {
    genesis_height: u32,
    start: Instant,
    block_seconds: f64,
    fixed_tip: Mutex<Option<u32>>,
}

impl MockChain {
    pub fn new(genesis_height: u32, block_seconds: f64) -> Self {
        MockChain {
            genesis_height,
            start: Instant::now(),
            block_seconds,
            fixed_tip: Mutex::new(None),
        }
    }

    /// Pin the tip (tests, simulation) instead of following the clock.
    pub fn set_tip(&self, height: u32) {
        *self.fixed_tip.lock().unwrap() = Some(height);
    }

    pub fn mock_root(height: u32) -> [u8; 32] {
        cv_core::crypto::hash::tagged("mock-header", &height.to_le_bytes())
    }
}

impl HeaderSource for MockChain {
    fn merkle_root(&self, height: u32) -> Option<[u8; 32]> {
        (height <= self.tip_height()?).then(|| Self::mock_root(height))
    }

    fn tip_height(&self) -> Option<u32> {
        if let Some(t) = *self.fixed_tip.lock().unwrap() {
            return Some(t);
        }
        let elapsed = self.start.elapsed().as_secs_f64() / self.block_seconds;
        Some(self.genesis_height + elapsed as u32)
    }
}
