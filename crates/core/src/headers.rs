//! Validated Bitcoin header chain from a checkpoint (SPEC §9, §15). Shared
//! by nodes and the verifier.

use crate::DecodeError;
use crate::encoding::{Reader, Writer};
use cv_crypto::spv::{self, BlockHeader};

pub const HEADERS_MAGIC: &[u8; 8] = b"CVHDR001";

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum HeaderError {
    #[error("header does not link to the previous one")]
    Link,
    #[error("proof of work does not meet the header's target")]
    Pow,
    #[error("difficulty change outside a retarget boundary or beyond the 4x clamp")]
    Difficulty,
}

/// Headers from a checkpoint onward, each checked for linkage and proof of
/// work. `// TRUST: Bitcoin (honest-majority hashpower) for ordering (§2)`;
/// the *source* of headers is trusted for liveness only.
#[derive(Clone, Debug)]
pub struct HeaderChain {
    start_height: u32,
    headers: Vec<BlockHeader>,
    confirmations: u32,
}

impl HeaderChain {
    /// `checkpoint` is a deployment constant and is not re-validated.
    pub fn new(start_height: u32, checkpoint: BlockHeader, confirmations: u32) -> Self {
        HeaderChain {
            start_height,
            headers: vec![checkpoint],
            confirmations,
        }
    }

    pub fn start_height(&self) -> u32 {
        self.start_height
    }

    pub fn confirmations(&self) -> u32 {
        self.confirmations
    }

    pub fn tip(&self) -> (u32, &BlockHeader) {
        (
            self.start_height + self.headers.len() as u32 - 1,
            self.headers.last().unwrap(),
        )
    }

    pub fn header_at(&self, height: u32) -> Option<&BlockHeader> {
        height
            .checked_sub(self.start_height)
            .and_then(|i| self.headers.get(i as usize))
    }

    /// Height of the highest header with `confirmations` descendants.
    pub fn usable_tip(&self) -> Option<u32> {
        let (tip, _) = self.tip();
        let usable = tip.checked_sub(self.confirmations)?;
        (usable >= self.start_height).then_some(usable)
    }

    pub fn append(&mut self, h: BlockHeader) -> Result<u32, HeaderError> {
        let (tip_height, prev) = self.tip();
        if !spv::links_to(prev, &h) {
            return Err(HeaderError::Link);
        }
        if !spv::valid_pow(&h) {
            return Err(HeaderError::Pow);
        }
        let next_height = tip_height + 1;
        if h.bits != prev.bits {
            // Retargets happen only every 2016 blocks and change the target
            // by at most 4x in either direction (A44).
            if next_height % 2016 != 0 {
                return Err(HeaderError::Difficulty);
            }
            let (old, new) = (prev.target(), h.target());
            if new > old.max_transition_threshold_unchecked()
                || new < old.min_transition_threshold()
            {
                return Err(HeaderError::Difficulty);
            }
        }
        self.headers.push(h);
        Ok(next_height)
    }

    /// Drop headers above `height` (reorg handling).
    pub fn truncate(&mut self, height: u32) {
        let keep = (height + 1).saturating_sub(self.start_height).max(1) as usize;
        self.headers.truncate(keep);
    }

    /// SPEC §15 `Headers` file.
    pub fn to_file(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.fixed(HEADERS_MAGIC);
        w.u32(self.start_height);
        w.list_len(self.headers.len());
        for h in &self.headers {
            w.fixed(&spv::encode_header(h));
        }
        w.into_inner()
    }

    pub fn from_file(bytes: &[u8], confirmations: u32) -> Result<Self, DecodeError> {
        let mut r = Reader::new(bytes);
        if r.fixed::<8>()? != *HEADERS_MAGIC {
            return Err(DecodeError::Structure);
        }
        let start_height = r.u32()?;
        let n = r.list_len(10_000_000)?;
        if n == 0 {
            return Err(DecodeError::Structure);
        }
        let first = spv::decode_header(&r.fixed::<80>()?).ok_or(DecodeError::Structure)?;
        let mut chain = HeaderChain::new(start_height, first, confirmations);
        for _ in 1..n {
            let h = spv::decode_header(&r.fixed::<80>()?).ok_or(DecodeError::Structure)?;
            chain.append(h).map_err(|_| DecodeError::Structure)?;
        }
        r.finish()?;
        Ok(chain)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chain_append_confirmations_and_file() {
        let g = spv::mine_test_header([0u8; 32], [1u8; 32], 1);
        let mut c = HeaderChain::new(1000, g, 2);
        assert_eq!(c.usable_tip(), None);
        let mut prev = spv::block_hash(&g);
        for i in 1..=5u32 {
            let h = spv::mine_test_header(prev, [i as u8; 32], i);
            assert_eq!(c.append(h).unwrap(), 1000 + i);
            prev = spv::block_hash(&h);
        }
        assert_eq!(c.tip().0, 1005);
        assert_eq!(c.usable_tip(), Some(1003));
        let bad = spv::mine_test_header([9u8; 32], [1u8; 32], 9);
        assert_eq!(c.append(bad), Err(HeaderError::Link));
        let file = c.to_file();
        let back = HeaderChain::from_file(&file, 2).unwrap();
        assert_eq!(back.tip().0, 1005);
        assert!(HeaderChain::from_file(&file[..100], 2).is_err());
        c.truncate(1002);
        assert_eq!(c.tip().0, 1002);
    }
}
