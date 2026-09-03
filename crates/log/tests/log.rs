//! Log semantics: dedup by bytes and by content id, rejection of invalid
//! items, orphans resolving when references arrive, differing duplicates,
//! pruning, persistence.

use cv_core::build::*;
use cv_core::context::Deployment;
use cv_core::crypto::field::{Fr, fr_mod};
use cv_core::crypto::groth16::{self, dev_keys};
use cv_core::crypto::sig::SigningKey;
use cv_core::identity::commitment;
use cv_core::items::*;
use cv_core::registry::{RegistrySnapshot, RegistryTree};
use cv_core::validate::Reference;
use cv_log::headers::MockChain;
use cv_log::store::{MemoryStore, RedbStore, Store};
use cv_log::*;
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use std::sync::Arc;

struct Fixture {
    tree: RegistryTree,
    secrets: Vec<Fr>,
    authority: SigningKey,
    issuer: SigningKey,
    snapshot: RegistrySnapshot,
    vote: VoteDefinition,
    chain: Arc<MockChain>,
}

fn fixture() -> Fixture {
    let secrets: Vec<Fr> = (1..=12u64).map(|i| fr_mod(&[i as u8; 32])).collect();
    let tree = RegistryTree::from_leaves(secrets.iter().map(commitment).collect());
    let authority = SigningKey::from_seed(&[0x42u8; 32]);
    let issuer = SigningKey::from_seed(&[0x11u8; 32]);
    let snapshot = RegistrySnapshot::sign(&issuer, 1, &tree);
    let vote = sign_vote_definition(
        &authority,
        VoteDefinition {
            question: "Q?".into(),
            options: vec!["Yes".into(), "No".into()],
            issuer_key: issuer.public_key(),
            registry_root: tree.root(),
            open_block: 100,
            close_block: 200,
            min_ballots: 1,
            secrecy: Secrecy::None,
            origin: Origin::Initiative {
                initiative_id: [0; 32],
            },
        },
    );
    let chain = Arc::new(MockChain::new(100, 1.0));
    chain.set_tip(150);
    Fixture {
        tree,
        secrets,
        authority,
        issuer,
        snapshot,
        vote,
        chain,
    }
}

fn deployment(f: &Fixture) -> Deployment {
    Deployment {
        authority_keys: vec![f.authority.public_key()],
        issuer_keys: vec![f.issuer.public_key()],
        dev_mode: true,
    }
}

fn open_log(f: &Fixture, store: Box<dyn Store>) -> Log {
    Log::open(
        deployment(f),
        Arc::new(groth16::setup(&mut ChaCha20Rng::from_seed(
            groth16::DEV_SETUP_SEED,
        ))),
        store,
        f.chain.clone(),
    )
    .unwrap()
}

fn participant(f: &Fixture, i: usize) -> Participant {
    Participant {
        secret: f.secrets[i],
        issuer_key: f.issuer.public_key(),
        registry_root: f.tree.root(),
        index: i as u32,
        siblings: f.tree.path(i as u32).unwrap(),
    }
}

fn is_new(a: &Accepted) -> bool {
    matches!(a, Accepted::New { .. })
}

#[test]
fn insert_dedup_orphans_duplicates_prune() {
    let f = fixture();
    let mut log = open_log(&f, Box::new(MemoryStore::new()));

    // A ballot before its vote definition is an orphan, not an error.
    let p = participant(&f, 1);
    let ballot = plaintext_ballot(dev_keys(), &p, &f.vote, 0).unwrap();
    let ballot_bytes = Item::Ballot(ballot.clone()).encode();
    assert!(matches!(
        log.insert(&ballot_bytes).unwrap(),
        Accepted::Orphaned(Reference::Vote(_))
    ));
    assert_eq!(log.orphan_count(), 1);

    // The vote definition before its registry is an orphan too.
    let vote_bytes = Item::VoteDefinition(f.vote.clone()).encode();
    assert!(matches!(
        log.insert(&vote_bytes).unwrap(),
        Accepted::Orphaned(Reference::Registry(..))
    ));

    // Registry arrives. An Issuer this node does not carry is refused …
    let other_issuer = SigningKey::from_seed(&[9u8; 32]);
    assert!(matches!(
        log.add_registry(
            RegistrySnapshot::sign(&other_issuer, 1, &f.tree),
            f.tree.leaves().to_vec()
        ),
        Err(RegistryError::UnknownIssuer)
    ));
    // … and so is a snapshot that does not carry the signature it claims.
    let mut forged = f.snapshot.clone();
    forged.signature[0] ^= 1;
    assert!(matches!(
        log.add_registry(forged, f.tree.leaves().to_vec()),
        Err(RegistryError::BadSignature)
    ));
    log.add_registry(f.snapshot.clone(), f.tree.leaves().to_vec())
        .unwrap();
    assert_eq!(log.orphan_count(), 0);
    assert_eq!(log.len(), 2);
    let relayed = log.take_relay();
    assert_eq!(relayed.len(), 2);
    assert!(relayed.contains(&vote_bytes) && relayed.contains(&ballot_bytes));

    // Exact retransmission: AlreadyHave; re-randomized proof: Equivalent; neither relayed.
    assert_eq!(log.insert(&ballot_bytes).unwrap(), Accepted::AlreadyHave);
    let mut rng = ChaCha20Rng::from_seed([1u8; 32]);
    let rr = Ballot {
        proof: Proof(
            groth16::rerandomize(&dev_keys().verifier.vk, &ballot.proof.0, &mut rng).unwrap(),
        ),
        ..ballot.clone()
    };
    assert_eq!(
        log.insert(&Item::Ballot(rr).encode()).unwrap(),
        Accepted::Equivalent {
            content_id: ballot.content_id()
        }
    );
    assert!(log.take_relay().is_empty());
    assert_eq!(log.len(), 2);

    // Invalid items are rejected and not relayed.
    let tampered = Ballot {
        payload: vec![1],
        ..ballot.clone()
    };
    assert!(matches!(
        log.insert(&Item::Ballot(tampered).encode()),
        Err(Rejected::Invalid(_))
    ));
    assert!(matches!(
        log.insert(&[1, 2, 3]),
        Err(Rejected::Malformed(_))
    ));
    assert!(log.take_relay().is_empty());

    // A differing duplicate (same nullifier, other option) is stored; the
    // nullifier group reports both, which the tally treats as a double action.
    let other = plaintext_ballot(dev_keys(), &p, &f.vote, 1).unwrap();
    assert!(is_new(
        &log.insert(&Item::Ballot(other.clone()).encode()).unwrap()
    ));
    let group = log.nullifier_group(&f.vote.vote_id(), &ballot.nullifier);
    assert_eq!(group.len(), 2);
    assert!(group.contains(&ballot.content_id()) && group.contains(&other.content_id()));

    // Light-client status: not anchored yet; after a dev anchor, anchored at its height.
    let vid = f.vote.vote_id();
    let st = log.ballot_status(&vid, &ballot.nullifier);
    assert_eq!(st.len(), 2);
    assert!(st.iter().all(|s| s.anchored_height.is_none()));
    let mut leaves = log.unanchored_content_ids();
    assert!(leaves.contains(&ballot.content_id()));
    leaves.sort();
    let anchor = Anchor {
        leaves: leaves.clone(),
        proof: AnchorProof::Dev { height: 120 },
    };
    let anchor_id = anchor.content_id();
    assert!(is_new(&log.insert(&Item::Anchor(anchor).encode()).unwrap()));
    assert_eq!(log.anchored_height(&ballot.content_id()), Some(120));
    assert!(log.unanchored_content_ids().is_empty());
    let later = Anchor {
        leaves: vec![ballot.content_id()],
        proof: AnchorProof::Dev { height: 130 },
    };
    assert!(is_new(&log.insert(&Item::Anchor(later).encode()).unwrap()));
    assert_eq!(
        log.anchored_height(&ballot.content_id()),
        Some(120),
        "earliest height wins"
    );
    let proof = log
        .inclusion_proof(&anchor_id, &ballot.content_id())
        .unwrap();
    assert!(cv_core::crypto::merkle::verify_inclusion(
        &proof,
        &ballot.content_id()
    ));
    assert_eq!(log.anchors_covering(&ballot.content_id()).len(), 2);

    // An anchor at a height the chain does not have yet is an orphan until headers advance.
    let future = Anchor {
        leaves: vec![other.content_id()],
        proof: AnchorProof::Dev { height: 500 },
    };
    assert!(matches!(
        log.insert(&Item::Anchor(future).encode()).unwrap(),
        Accepted::Orphaned(Reference::Header(500))
    ));
    f.chain.set_tip(600);
    log.headers_changed();
    assert_eq!(log.orphan_count(), 0);
    assert_eq!(log.anchored_height(&other.content_id()), Some(120));

    // Inventory and snapshot.
    let inv = log.inventory(0, 100);
    assert_eq!(inv.len(), log.len());
    assert!(inv.windows(2).all(|w| w[0].0 < w[1].0));
    let snap = log.export_snapshot();
    assert_eq!(&snap[..8], b"CVSNAP01");

    // Pruning removes ballots but keeps the definition, anchors and the archived result.
    assert_eq!(log.ballots_of(&vid).len(), 2);
    let removed = log.prune_vote(&vid, b"result").unwrap();
    assert_eq!(removed, 2);
    assert!(log.ballots_of(&vid).is_empty());
    assert!(log.get(&vid).is_some());
    assert_eq!(log.anchors().len(), 3);
    assert_eq!(log.archived_result(&vid), Some(&b"result"[..]));
}

#[test]
fn node_registration_duplicates_and_witnesses() {
    let f = fixture();
    let mut log = open_log(&f, Box::new(MemoryStore::new()));
    log.add_registry(f.snapshot.clone(), f.tree.leaves().to_vec())
        .unwrap();
    log.insert(&Item::VoteDefinition(f.vote.clone()).encode())
        .unwrap();
    let p = participant(&f, 2);
    let k1 = SigningKey::from_seed(&[0x21u8; 32]);
    let k2 = SigningKey::from_seed(&[0x22u8; 32]);
    let mk = |key: &SigningKey, endpoint: &str| {
        build_node_registration(
            dev_keys(),
            &p,
            key.public_key(),
            [0; 32],
            endpoint.into(),
            "op".into(),
            *b"CZ",
            1,
        )
        .unwrap()
    };
    let r1 = mk(&k1, "a:1");
    assert!(is_new(
        &log.insert(&Item::NodeRegistration(r1.clone()).encode())
            .unwrap()
    ));
    use cv_core::context::Context;
    assert!(log.node_registration(&k1.public_key()).is_some());
    // The same person registers a different key in the same electorate: both
    // registrations become invalid (SPEC §7.1).
    let r2 = mk(&k2, "b:2");
    assert!(is_new(
        &log.insert(&Item::NodeRegistration(r2).encode()).unwrap()
    ));
    assert!(log.node_registration(&k1.public_key()).is_none());
    assert!(log.node_registration(&k2.public_key()).is_none());
}

#[test]
fn redb_persistence_survives_reopen() {
    let f = fixture();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("log.redb");
    let (vid, n_items, seq) = {
        let mut log = open_log(&f, Box::new(RedbStore::open(&path).unwrap()));
        log.add_registry(f.snapshot.clone(), f.tree.leaves().to_vec())
            .unwrap();
        log.insert(&Item::VoteDefinition(f.vote.clone()).encode())
            .unwrap();
        for i in 1..4 {
            let b =
                plaintext_ballot(dev_keys(), &participant(&f, i), &f.vote, (i % 2) as u8).unwrap();
            assert!(is_new(&log.insert(&Item::Ballot(b).encode()).unwrap()));
        }
        (f.vote.vote_id(), log.len(), log.latest_seq())
    };
    let log = open_log(&f, Box::new(RedbStore::open(&path).unwrap()));
    assert_eq!(log.len(), n_items);
    assert_eq!(log.latest_seq(), seq);
    assert_eq!(log.ballots_of(&vid).len(), 3);
    let id = (f.issuer.public_key(), f.tree.root());
    assert!(log.registry_snapshot(&id).is_some());
    assert_eq!(log.registry_leaves(&id).unwrap().len(), 12);
    assert_eq!(log.registry_tree(&id).unwrap().root(), f.tree.root());
    // The same root under an Issuer this node never heard of is a different
    // registry, and is not there.
    assert!(log.registry_snapshot(&([7u8; 32], f.tree.root())).is_none());
}
