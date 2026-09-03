//! Phase 2: registry tree, Poseidon parameters, membership proofs.

use ark_ff::PrimeField;
use cv_core::crypto::field::{Fr, fr_mod, tag_field};
use cv_core::crypto::groth16::{self, dev_keys};
use cv_core::crypto::poseidon;
use cv_core::crypto::sig::SigningKey;
use cv_core::identity::*;
use cv_core::items::Proof;
use cv_core::registry::*;
use std::path::PathBuf;
use std::time::Instant;

fn dec(f: &Fr) -> String {
    f.into_bigint().to_string()
}

fn vectors_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/vectors")
}

/// Write the file if missing (or if `CV_WRITE_VECTORS` is set); otherwise
/// require equality. This pins constants against accidental drift.
fn pin(name: &str, value: &serde_json::Value) {
    let path = vectors_dir().join(name);
    let pretty = serde_json::to_string_pretty(value).unwrap();
    if !path.exists() || std::env::var_os("CV_WRITE_VECTORS").is_some() {
        std::fs::write(&path, pretty).unwrap();
        return;
    }
    let existing: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
    assert_eq!(
        &existing, value,
        "{name} changed — parameters or circuit drifted"
    );
}

#[test]
fn poseidon_parameters_are_pinned() {
    let cfg = poseidon::config();
    let a = Fr::from(1u64);
    let b = Fr::from(2u64);
    let c = Fr::from(3u64);
    let v = serde_json::json!({
        "field": "BN254 scalar field (r = 21888242871839275222246405745257275088548364400416034343698204186575808495617)",
        "prime_bits": 254, "rate": 2, "capacity": 1, "full_rounds": 8, "partial_rounds": 57, "alpha": 5,
        "ark": cfg.ark.iter().map(|row| row.iter().map(dec).collect::<Vec<_>>()).collect::<Vec<_>>(),
        "mds": cfg.mds.iter().map(|row| row.iter().map(dec).collect::<Vec<_>>()).collect::<Vec<_>>(),
        "vectors": {
            "poseidon(1)": dec(&poseidon::hash(&[a])),
            "poseidon(1,2)": dec(&poseidon::hash(&[a, b])),
            "poseidon(1,2,3)": dec(&poseidon::hash(&[a, b, c])),
            "poseidon(1,0) (equals poseidon(1): no length padding)": dec(&poseidon::hash(&[a, Fr::from(0u64)])),
            "commitment(s=1) = poseidon(1, tag_field(commit))": dec(&commitment(&a)),
            "tag_field(commit)": dec(&tag_field(TAG_COMMIT)),
            "nullifier(s=1, ballot, id=2)": dec(&nullifier(&a, TAG_BALLOT, &b)),
            "empty_root_depth_32": dec(&empty_hashes()[32]),
            "tag_field(ballot)": dec(&tag_field(TAG_BALLOT)),
        }
    });
    pin("poseidon.json", &v);
    assert_eq!(cfg.ark.len(), 65);
    assert_eq!(cfg.mds.len(), 3);
}

#[test]
fn registry_tree_roots_and_paths() {
    let empty = RegistryTree::new();
    assert_eq!(empty.root(), empty_hashes()[32]);

    let leaves: Vec<Fr> = (1..=1000u64).map(|i| commitment(&Fr::from(i))).collect();
    let tree = RegistryTree::from_leaves(leaves.clone());
    assert_eq!(tree.leaf_count(), 1000);
    for index in [0u32, 1, 2, 511, 512, 998, 999] {
        let path = tree.path(index).unwrap();
        assert_eq!(
            root_from_path(leaves[index as usize], index, &path),
            tree.root()
        );
        assert_ne!(
            root_from_path(leaves[(index as usize + 1) % 1000], index, &path),
            tree.root()
        );
    }
    assert!(tree.path(1000).is_none());

    // Replacement at an index equals rebuilding from the new leaf list.
    let mut updated = tree.clone();
    let new_leaf = commitment(&Fr::from(424242u64));
    updated.set(7, new_leaf);
    let mut leaves2 = leaves.clone();
    leaves2[7] = new_leaf;
    assert_eq!(updated.root(), RegistryTree::from_leaves(leaves2).root());
    assert_ne!(updated.root(), tree.root());

    // Leaves file round trip.
    assert_eq!(decode_leaves(&encode_leaves(&leaves)).unwrap(), leaves);
    assert!(decode_leaves(&[0u8; 33]).is_err());

    // Snapshot signing.
    let issuer = SigningKey::from_seed(&[3u8; 32]);
    let snap = RegistrySnapshot::sign(&issuer, 5, &tree);
    assert!(snap.verify(&issuer.public_key()));
    assert!(!snap.verify(&SigningKey::from_seed(&[4u8; 32]).public_key()));
    assert_eq!(RegistrySnapshot::decode(&snap.encode()).unwrap(), snap);
    let mut bad = snap.clone();
    bad.leaf_count += 1;
    assert!(!bad.verify(&issuer.public_key()));
}

fn member(tree: &RegistryTree, secret: Fr, index: u32) -> MembershipWitness {
    MembershipWitness {
        secret,
        index,
        siblings: tree.path(index).unwrap(),
    }
}

#[test]
fn membership_proofs_verify_and_wrong_statements_fail() {
    let t0 = Instant::now();
    let keys = dev_keys();
    let setup_time = t0.elapsed();
    let constraints = groth16::constraint_count();

    let secrets: Vec<Fr> = (1..=64u64).map(|i| fr_mod(&[i as u8; 32])).collect();
    let tree = RegistryTree::from_leaves(secrets.iter().map(commitment).collect());
    let s = secrets[37];
    let vote_id = [0xabu8; 32];
    let content_id = [0xcdu8; 32];
    let n = nullifier(&s, TAG_BALLOT, &fr_mod(&vote_id));
    let stmt = MembershipStatement::new(tree.root(), n, TAG_BALLOT, Some(&vote_id), &content_id);
    let wit = member(&tree, s, 37);

    let t1 = Instant::now();
    let proof = prove_membership(keys, &stmt, &wit, &content_id).unwrap();
    let prove_time = t1.elapsed();
    let t2 = Instant::now();
    assert!(verify_membership(keys, &stmt, &proof));
    let verify_time = t2.elapsed();
    eprintln!(
        "membership circuit: {constraints} constraints; dev setup {:.2?}; prove {:.2?}; verify {:.2?}",
        setup_time, prove_time, verify_time
    );
    assert!(prove_time.as_secs() < 60, "proving is pathologically slow");

    // Wrong root, nullifier, tag, id, signal → reject.
    let mut bad = stmt;
    bad.root = empty_hashes()[32];
    assert!(!verify_membership(keys, &bad, &proof));
    let mut bad = stmt;
    bad.nullifier = nullifier(&s, TAG_BALLOT, &fr_mod(&[0u8; 32]));
    assert!(!verify_membership(keys, &bad, &proof));
    let mut bad = stmt;
    bad.tag = tag_field(TAG_SUPPORT);
    assert!(!verify_membership(keys, &bad, &proof));
    let mut bad = stmt;
    bad.id = Fr::from(0u64);
    assert!(!verify_membership(keys, &bad, &proof));
    let mut bad = stmt;
    bad.signal = fr_mod(&[0xceu8; 32]);
    assert!(!verify_membership(keys, &bad, &proof));

    // A non-member cannot prove (proof for a wrong path/root does not verify).
    let outsider = fr_mod(&[99u8; 32]);
    let n2 = nullifier(&outsider, TAG_BALLOT, &fr_mod(&vote_id));
    let stmt2 = MembershipStatement::new(tree.root(), n2, TAG_BALLOT, Some(&vote_id), &content_id);
    let wit2 = MembershipWitness {
        secret: outsider,
        index: 37,
        siblings: tree.path(37).unwrap(),
    };
    assert!(prove_membership(keys, &stmt2, &wit2, &content_id).is_err());

    // Malformed proof bytes verify as false, never panic.
    assert!(!verify_membership(keys, &stmt, &Proof([0u8; 128])));
    assert!(!verify_membership(keys, &stmt, &Proof([0xffu8; 128])));
    let mut flipped = proof.clone();
    flipped.0[5] ^= 1;
    assert!(!verify_membership(keys, &stmt, &flipped));

    // Deterministic proof randomness: identical bytes on re-derivation (A20).
    let again = prove_membership(keys, &stmt, &wit, &content_id).unwrap();
    assert_eq!(again, proof);
    let other_content = prove_membership(keys, &stmt, &wit, &[0xceu8; 32]).unwrap();
    assert_ne!(other_content, proof);

    // Two-argument nullifiers (id = 0) work with the same circuit.
    let p = nullifier(&s, TAG_AUTHOR, &Fr::from(0u64));
    let stmt3 = MembershipStatement::new(tree.root(), p, TAG_AUTHOR, None, &content_id);
    let proof3 = prove_membership(keys, &stmt3, &wit, &content_id).unwrap();
    assert!(verify_membership(keys, &stmt3, &proof3));

    // Pin the development verifying key and constraint count.
    let vk_hash = cv_core::crypto::hash::blake3_hash(&groth16::vk_to_bytes(&keys.vk));
    pin(
        "circuit.json",
        &serde_json::json!({
            "circuit": "membership (SPEC §5)",
            "constraints": constraints,
            "public_inputs": ["root", "nullifier", "tag", "id", "signal"],
            "dev_setup_seed_utf8": std::str::from_utf8(&groth16::DEV_SETUP_SEED).unwrap(),
            "dev_vk_blake3": hex::encode(vk_hash),
            "warning": "the development setup is INSECURE; release builds must load ceremony keys",
        }),
    );
    // VK round trip.
    let vk2 = groth16::vk_from_bytes(&groth16::vk_to_bytes(&keys.vk)).unwrap();
    assert_eq!(groth16::vk_to_bytes(&vk2), groth16::vk_to_bytes(&keys.vk));
}
