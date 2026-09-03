//! Bitcoin SPV helpers (SPEC §1.9, §9) over the `bitcoin` crate: header
//! decoding and proof-of-work, direct-anchor verification (OP_RETURN + partial
//! Merkle tree), and a regtest-difficulty header miner for tests.

use bitcoin::block::Header;
use bitcoin::consensus::encode::{deserialize, serialize};
use bitcoin::hashes::Hash;
use bitcoin::merkle_tree::PartialMerkleTree;
use bitcoin::script::{Instruction, PushBytesBuf};
use bitcoin::{BlockHash, CompactTarget, ScriptBuf, Transaction, TxMerkleNode, Txid};

pub use bitcoin::block::Header as BlockHeader;

pub const HEADER_BYTES: usize = 80;
pub const OP_RETURN_PREFIX: &[u8; 4] = b"CVOT";

pub fn decode_header(bytes: &[u8]) -> Option<Header> {
    if bytes.len() != HEADER_BYTES {
        return None;
    }
    deserialize(bytes).ok()
}

pub fn encode_header(h: &Header) -> [u8; HEADER_BYTES] {
    serialize(h).try_into().expect("80-byte header")
}

/// Block hash in internal byte order.
pub fn block_hash(h: &Header) -> [u8; 32] {
    h.block_hash().to_byte_array()
}

/// Merkle root in internal byte order (what OTS attestations compare against).
pub fn merkle_root(h: &Header) -> [u8; 32] {
    h.merkle_root.to_byte_array()
}

/// Proof of work against the header's own target.
pub fn valid_pow(h: &Header) -> bool {
    h.validate_pow(h.target()).is_ok()
}

pub fn links_to(prev: &Header, h: &Header) -> bool {
    h.prev_blockhash == prev.block_hash()
}

/// `OP_RETURN "CVOT" || root` output script for direct anchors.
pub fn op_return_script(root: &[u8; 32]) -> ScriptBuf {
    let mut data = OP_RETURN_PREFIX.to_vec();
    data.extend_from_slice(root);
    ScriptBuf::new_op_return(PushBytesBuf::try_from(data).expect("36 bytes fit"))
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SpvError {
    #[error("transaction does not decode")]
    Tx,
    #[error("no OP_RETURN output carrying the anchor root")]
    NoCommitment,
    #[error("partial merkle tree does not decode or is inconsistent")]
    MerkleProof,
    #[error("merkle proof does not match the block")]
    WrongBlock,
    #[error("merkle proof does not include the transaction")]
    TxNotIncluded,
}

/// Verify a direct anchor: `raw_tx` commits to `root` in an OP_RETURN output
/// and `partial_merkle_tree` proves its inclusion in the block whose merkle
/// root is `block_merkle_root`.
pub fn verify_direct(
    raw_tx: &[u8],
    partial_merkle_tree: &[u8],
    root: &[u8; 32],
    block_merkle_root: &[u8; 32],
) -> Result<(), SpvError> {
    let tx: Transaction = deserialize(raw_tx).map_err(|_| SpvError::Tx)?;
    let expected = op_return_script(root);
    if !tx.output.iter().any(|o| o.script_pubkey == expected) {
        // Also accept an OP_RETURN whose single push equals the data (same bytes).
        let mut data = OP_RETURN_PREFIX.to_vec();
        data.extend_from_slice(root);
        let found = tx.output.iter().any(|o| {
            o.script_pubkey.is_op_return()
                && o.script_pubkey.instructions().skip(1).any(|i| matches!(i, Ok(Instruction::PushBytes(p)) if p.as_bytes() == data.as_slice()))
        });
        if !found {
            return Err(SpvError::NoCommitment);
        }
    }
    let pmt: PartialMerkleTree =
        deserialize(partial_merkle_tree).map_err(|_| SpvError::MerkleProof)?;
    let mut matches: Vec<Txid> = Vec::new();
    let mut indexes: Vec<u32> = Vec::new();
    let computed: TxMerkleNode = pmt
        .extract_matches(&mut matches, &mut indexes)
        .map_err(|_| SpvError::MerkleProof)?;
    if computed.to_byte_array() != *block_merkle_root {
        return Err(SpvError::WrongBlock);
    }
    if !matches.contains(&tx.compute_txid()) {
        return Err(SpvError::TxNotIncluded);
    }
    Ok(())
}

/// Build the partial Merkle tree proving `index` among `txids`.
pub fn partial_merkle_tree(txids: &[[u8; 32]], index: usize) -> Vec<u8> {
    let ids: Vec<Txid> = txids.iter().map(|t| Txid::from_byte_array(*t)).collect();
    let flags: Vec<bool> = (0..ids.len()).map(|i| i == index).collect();
    serialize(&PartialMerkleTree::from_txids(&ids, &flags))
}

pub fn txid(raw_tx: &[u8]) -> Option<[u8; 32]> {
    let tx: Transaction = deserialize(raw_tx).ok()?;
    Some(tx.compute_txid().to_byte_array())
}

/// Bitcoin merkle root over a list of txids (internal byte order).
pub fn tx_merkle_root(txids: &[[u8; 32]]) -> [u8; 32] {
    let ids: Vec<Txid> = txids.iter().map(|t| Txid::from_byte_array(*t)).collect();
    bitcoin::merkle_tree::calculate_root(ids.into_iter())
        .map(|r| r.to_byte_array())
        .unwrap_or([0u8; 32])
}

/// Regtest difficulty (`0x207fffff`): any header with this target needs a
/// trivial amount of work. **Tests only**; real chains are checked against
/// their own targets.
pub const REGTEST_BITS: u32 = 0x207f_ffff;

/// Mine a header on top of `prev_hash` at regtest difficulty (tests).
pub fn mine_test_header(prev_hash: [u8; 32], merkle_root: [u8; 32], time: u32) -> Header {
    let mut h = Header {
        version: bitcoin::block::Version::TWO,
        prev_blockhash: BlockHash::from_byte_array(prev_hash),
        merkle_root: TxMerkleNode::from_byte_array(merkle_root),
        time,
        bits: CompactTarget::from_consensus(REGTEST_BITS),
        nonce: 0,
    };
    while !valid_pow(&h) {
        h.nonce += 1;
    }
    h
}

/// A minimal transaction with one OP_RETURN output committing to `root`
/// (for tests and for anchorers preparing a direct anchor).
pub fn commitment_transaction(root: &[u8; 32]) -> Vec<u8> {
    use bitcoin::absolute::LockTime;
    use bitcoin::transaction::Version;
    use bitcoin::{Amount, TxOut};
    let tx = Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![],
        output: vec![TxOut {
            value: Amount::ZERO,
            script_pubkey: op_return_script(root),
        }],
    };
    serialize(&tx)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn headers_and_direct_anchor_roundtrip() {
        let root = [0x11u8; 32];
        let tx = commitment_transaction(&root);
        let id = txid(&tx).unwrap();
        let other = [0x22u8; 32];
        let txids = vec![other, id, [0x33u8; 32]];
        let mroot = tx_merkle_root(&txids);
        let pmt = partial_merkle_tree(&txids, 1);
        assert_eq!(verify_direct(&tx, &pmt, &root, &mroot), Ok(()));
        assert_eq!(
            verify_direct(&tx, &pmt, &[0u8; 32], &mroot),
            Err(SpvError::NoCommitment)
        );
        assert_eq!(
            verify_direct(&tx, &pmt, &root, &[0u8; 32]),
            Err(SpvError::WrongBlock)
        );
        let wrong = partial_merkle_tree(&txids, 0);
        assert_eq!(
            verify_direct(&tx, &wrong, &root, &mroot),
            Err(SpvError::TxNotIncluded)
        );

        let h0 = mine_test_header([0u8; 32], mroot, 1);
        assert!(valid_pow(&h0));
        let h1 = mine_test_header(block_hash(&h0), [5u8; 32], 2);
        assert!(links_to(&h0, &h1));
        assert!(!links_to(&h1, &h0));
        let bytes = encode_header(&h1);
        assert_eq!(decode_header(&bytes).unwrap(), h1);
        assert!(decode_header(&bytes[..79]).is_none());
        assert_eq!(merkle_root(&h0), mroot);
    }
}
