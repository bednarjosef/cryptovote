//! Protocol constants (SPEC §14).

pub const PROTOCOL_VERSION: u8 = 1;

pub const REGISTRY_DEPTH: usize = 32;
pub const MAX_OPTIONS: usize = 64;
pub const MAX_VOTE_BLOCKS: u32 = 52_560;
pub const MAX_ITEM_BYTES: usize = 8 * 1024 * 1024;
pub const MAX_ANCHOR_LEAVES: usize = 1_000_000;
pub const MAX_KEY_PARTIES: usize = 32;
pub const MAX_STRING_BYTES: usize = 65_536;
pub const MAX_ENDPOINT_BYTES: usize = 256;

/// Verifiable timed commitment parameters (SPEC §10.6 D6).
pub const VTC_N: usize = 64;
pub const VTC_T: usize = 33;
pub const VTC_OPEN: usize = 32;
/// Assumed fastest sequential 2048-bit modular squaring rate (per second).
pub const S_MAX_RSA: u64 = 1 << 26;
/// Hard cap on a key party's delay: the delay of three times the longest
/// permitted vote (whitepaper §14 `T_cap`).
pub const T_CAP: u64 = 3 * (MAX_VOTE_BLOCKS as u64) * 600 * S_MAX_RSA * 3 / 2;

pub const MIN_BALLOTS: u32 = 100;
pub const WITNESS_THRESHOLD_W: usize = 7;
pub const INITIATIVE_OPEN_DELAY: u32 = 144;
pub const INITIATIVE_VOTE_BLOCKS: u32 = 1008;
pub const MIN_CONFIRMATIONS: u32 = 6;

pub const MIX_HOPS: usize = 3;
pub const MIX_HOLD_SECONDS: u64 = 3;
pub const MIX_HOLD_MESSAGES: usize = 8;
pub const MIX_HOLD_CAP_SECONDS: u64 = 60;
pub const PATHS_PER_BALLOT: usize = 2;
pub const GUARD_ROTATION_DAYS: u64 = 90;
pub const OTS_CALENDARS_PER_SUBMISSION: usize = 3;

/// `initiative_threshold(size) = ceil(size / 100)` (1 % of the Registry).
pub fn initiative_threshold(registry_size: u64) -> u32 {
    registry_size.div_ceil(100).min(u32::MAX as u64) as u32
}

/// `required_delay(blocks) = blocks × 600 × S_MAX_RSA × 3 / 2` (SPEC §10.4).
pub fn required_delay(blocks: u32) -> u64 {
    (blocks as u64) * 600 * S_MAX_RSA * 3 / 2
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn threshold_and_delay() {
        assert_eq!(initiative_threshold(12_000_000), 120_000);
        assert_eq!(initiative_threshold(1), 1);
        assert_eq!(initiative_threshold(0), 0);
        assert_eq!(required_delay(1152), 69_578_470_195_200);
        assert_eq!(T_CAP, required_delay(3 * MAX_VOTE_BLOCKS));
    }
}
