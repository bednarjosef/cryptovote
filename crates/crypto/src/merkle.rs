//! Anchor Merkle tree over sorted content ids (SPEC §8), via `rs_merkle`.

use rs_merkle::{Hasher, MerkleProof, MerkleTree};

/// BLAKE3 hasher with domain-separated leaves and nodes; an odd node is
/// carried up unchanged.
#[derive(Clone, Debug)]
pub struct AnchorHasher;

impl Hasher for AnchorHasher {
    type Hash = [u8; 32];

    fn hash(data: &[u8]) -> [u8; 32] {
        *blake3::hash(data).as_bytes()
    }

    fn concat_and_hash(left: &[u8; 32], right: Option<&[u8; 32]>) -> [u8; 32] {
        match right {
            None => *left,
            Some(r) => {
                let mut h = blake3::Hasher::new();
                h.update(&[0x01]);
                h.update(left);
                h.update(r);
                *h.finalize().as_bytes()
            }
        }
    }
}

/// `leaf_hash(id) = blake3(0x00 || id)`.
pub fn leaf_hash(id: &[u8; 32]) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(&[0x00]);
    h.update(id);
    *h.finalize().as_bytes()
}

fn tree(leaves: &[[u8; 32]]) -> MerkleTree<AnchorHasher> {
    let hashes: Vec<[u8; 32]> = leaves.iter().map(leaf_hash).collect();
    MerkleTree::<AnchorHasher>::from_leaves(&hashes)
}

/// Root over the given (already sorted, unique) content ids. `None` if empty.
pub fn anchor_root(leaves: &[[u8; 32]]) -> Option<[u8; 32]> {
    if leaves.is_empty() {
        return None;
    }
    tree(leaves).root()
}

/// Inclusion proof for one leaf (SPEC §8 `AnchorProof`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InclusionProof {
    pub root: [u8; 32],
    pub leaf_count: u32,
    pub index: u32,
    pub siblings: Vec<[u8; 32]>,
}

pub fn prove_inclusion(leaves: &[[u8; 32]], index: usize) -> Option<InclusionProof> {
    if index >= leaves.len() {
        return None;
    }
    let t = tree(leaves);
    let proof = t.proof(&[index]);
    Some(InclusionProof {
        root: t.root()?,
        leaf_count: leaves.len() as u32,
        index: index as u32,
        siblings: proof.proof_hashes().to_vec(),
    })
}

pub fn verify_inclusion(proof: &InclusionProof, id: &[u8; 32]) -> bool {
    let p = MerkleProof::<AnchorHasher>::new(proof.siblings.clone());
    p.verify(
        proof.root,
        &[proof.index as usize],
        &[leaf_hash(id)],
        proof.leaf_count as usize,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn spec_vectors() {
        let mut ids: Vec<[u8; 32]> = ["a", "b", "c"]
            .iter()
            .map(|x| *blake3::hash(x.as_bytes()).as_bytes())
            .collect();
        ids.sort();
        let hex = |b: &[u8; 32]| b.iter().map(|x| format!("{x:02x}")).collect::<String>();
        assert_eq!(
            hex(&ids[0]),
            "10e5cf3d3c8a4f9f3468c8cc58eea84892a22fdadbc1acb22410190044c1d553"
        );
        assert_eq!(
            hex(&leaf_hash(&ids[0])),
            "ddc979d8eed4bd09f1a3b785b5a10348bfac8c69ddaaf276b8306f8a517da712"
        );
        assert_eq!(
            hex(&anchor_root(&ids[..1]).unwrap()),
            "ddc979d8eed4bd09f1a3b785b5a10348bfac8c69ddaaf276b8306f8a517da712"
        );
        assert_eq!(
            hex(&anchor_root(&ids[..2]).unwrap()),
            "41075119209dbf5a0f18209eb48af545fc96002b5d13fdf4e1abbbf1c0ef03f5"
        );
        assert_eq!(
            hex(&anchor_root(&ids).unwrap()),
            "43aba690ee8b8ffc76eebc2b134cb0df5bfb4f547198a88ab31d16d52a334cf8"
        );
        assert!(anchor_root(&[]).is_none());
    }

    #[test]
    fn inclusion_proofs() {
        let ids: Vec<[u8; 32]> = (0u8..7).map(|i| [i; 32]).collect();
        for i in 0..ids.len() {
            let p = prove_inclusion(&ids, i).unwrap();
            assert!(verify_inclusion(&p, &ids[i]));
            assert!(!verify_inclusion(&p, &[0xffu8; 32]));
            let mut bad = p.clone();
            bad.index = (bad.index + 1) % ids.len() as u32;
            assert!(!verify_inclusion(&bad, &ids[i]));
        }
        assert!(prove_inclusion(&ids, 7).is_none());
    }
}
