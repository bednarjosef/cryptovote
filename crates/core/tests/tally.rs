//! Phase 5/6: the counting rule over the union of anchors, duplicates,
//! OTS/direct anchor validation, and initiative derivation. Anchors are the
//! only clock — there is no fallback to fall back to (A16).

use cv_core::DecodeError;
use cv_core::build::*;
use cv_core::constants::*;
use cv_core::context::Deployment;
use cv_core::crypto::field::{Fr, fr_mod};
use cv_core::crypto::groth16::{self, dev_keys};
use cv_core::crypto::merkle::anchor_root;
use cv_core::crypto::ots;
use cv_core::crypto::sig::SigningKey;
use cv_core::crypto::spv;
use cv_core::identity::commitment;
use cv_core::items::*;
use cv_core::registry::{RegistrySnapshot, RegistryTree};
use cv_core::snapshot::{Headers, SnapshotView, encode_snapshot};
use cv_core::tally::*;
use cv_core::validate::*;
use opentimestamps::attestation::Attestation;
use opentimestamps::op::Op;
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

/// Test header source: merkle roots by height, settable tip.
struct TestHeaders {
    roots: Mutex<BTreeMap<u32, [u8; 32]>>,
    tip: Mutex<Option<u32>>,
}

impl TestHeaders {
    fn new(tip: u32) -> Self {
        TestHeaders {
            roots: Mutex::new(BTreeMap::new()),
            tip: Mutex::new(Some(tip)),
        }
    }
    fn set_root(&self, h: u32, root: [u8; 32]) {
        self.roots.lock().unwrap().insert(h, root);
    }
    fn set_tip(&self, t: u32) {
        *self.tip.lock().unwrap() = Some(t);
    }
}

impl Headers for TestHeaders {
    fn merkle_root(&self, height: u32) -> Option<[u8; 32]> {
        if height > (*self.tip.lock().unwrap())? {
            return None;
        }
        Some(
            *self
                .roots
                .lock()
                .unwrap()
                .entry(height)
                .or_insert_with(|| [height as u8; 32]),
        )
    }
    fn tip_height(&self) -> Option<u32> {
        *self.tip.lock().unwrap()
    }
}

struct World {
    tree: RegistryTree,
    secrets: Vec<Fr>,
    authority: SigningKey,
    snapshot: RegistrySnapshot,
    vote: VoteDefinition,
    headers: Arc<TestHeaders>,
    keys: Arc<groth16::MembershipKeys>,
    deployment: Deployment,
}

fn world(dev_mode: bool) -> World {
    let secrets: Vec<Fr> = (1..=24u64).map(|i| fr_mod(&[i as u8; 32])).collect();
    let tree = RegistryTree::from_leaves(secrets.iter().map(commitment).collect());
    let authority = SigningKey::from_seed(&[0x42u8; 32]);
    let issuer = SigningKey::from_seed(&[0x11u8; 32]);
    let snapshot = RegistrySnapshot::sign(&issuer, 1, &tree, vec![authority.public_key()]);
    let vote = sign_vote_definition(
        &authority,
        VoteDefinition {
            question: "Tally?".into(),
            options: vec!["A".into(), "B".into(), "C".into()],
            issuer_key: issuer.public_key(),
            registry_root: tree.root(),
            open_block: 100,
            close_block: 200,
            min_ballots: 2,
            secrecy: Secrecy::None,
            min_parties: 0,
            origin: Origin::Initiative {
                initiative_id: [0; 32],
            },
        },
    );
    let headers = Arc::new(TestHeaders::new(300));
    let keys = Arc::new(groth16::setup(&mut ChaCha20Rng::from_seed(
        groth16::DEV_SETUP_SEED,
    )));
    let deployment = Deployment {
        issuer_keys: vec![issuer.public_key()],
        dev_mode,
    };
    World {
        tree,
        secrets,
        authority,
        snapshot,
        vote,
        headers,
        keys,
        deployment,
    }
}

fn view(w: &World) -> SnapshotView {
    let mut v = SnapshotView::empty(
        w.deployment.clone(),
        Arc::new(w.keys.verifier.clone()),
        w.headers.clone(),
    );
    v.add_registry(w.snapshot.clone());
    v.admit(Item::VoteDefinition(w.vote.clone())).unwrap();
    v
}

fn participant(w: &World, i: usize) -> Participant {
    Participant {
        secret: w.secrets[i],
        issuer_key: w.snapshot.issuer_key,
        registry_root: w.tree.root(),
        index: i as u32,
        siblings: w.tree.path(i as u32).unwrap(),
    }
}

fn ballot(w: &World, i: usize, option: u8) -> Ballot {
    plaintext_ballot(dev_keys(), &participant(w, i), &w.vote, option).unwrap()
}

fn dev_anchor(ids: &[Id], height: u32) -> Item {
    let mut leaves = ids.to_vec();
    leaves.sort();
    Item::Anchor(Anchor {
        leaves,
        proof: AnchorProof::Dev { height },
    })
}

#[test]
fn counting_rule_over_union_of_anchors() {
    let w = world(true);
    let mut v = view(&w);
    let vid = w.vote.vote_id();
    let b: Vec<Ballot> = (1..=8).map(|i| ballot(&w, i, (i % 3) as u8)).collect();
    for x in &b {
        v.admit(Item::Ballot(x.clone())).unwrap();
    }
    // Nothing anchored yet: nothing is timely, because an anchor is the only
    // thing that makes a ballot timely (A16).
    assert_eq!(tally(&v, &vid), Some(Outcome::BelowMinimum { counted: 0 }));

    // Anchor 1 (height 150 ≤ close) covers b0..b3; anchor 2 (height 199) covers b3..b5; anchor 3 (height 201 > close) covers b6, b7.
    let ids: Vec<Id> = b.iter().map(|x| x.content_id()).collect();
    v.admit(dev_anchor(&ids[0..4], 150)).unwrap();
    v.admit(dev_anchor(&ids[3..6], 199)).unwrap();
    v.admit(dev_anchor(&ids[6..8], 201)).unwrap();
    let Some(Outcome::Result { counts, counted }) = tally(&v, &vid) else {
        panic!()
    };
    assert_eq!(
        counted, 6,
        "b0..b5 under some anchor ≤ close; b6, b7 only after close"
    );
    // options: i%3 for i=1..6 → 1,2,0,1,2,0 → counts [2,2,2]
    assert_eq!(counts, vec![2, 2, 2]);

    // Late anchor for b6 at height 200 (== close) makes it count.
    v.admit(dev_anchor(&ids[6..7], 200)).unwrap();
    let Some(Outcome::Result { counted, .. }) = tally(&v, &vid) else {
        panic!()
    };
    assert_eq!(counted, 7);

    // Differing duplicate anchored before close: both of that person's ballots drop.
    let dup = ballot(&w, 1, 2);
    v.admit(Item::Ballot(dup.clone())).unwrap();
    v.admit(dev_anchor(&[dup.content_id()], 160)).unwrap();
    let Some(Outcome::Result {
        counted, counts, ..
    }) = tally(&v, &vid)
    else {
        panic!()
    };
    assert_eq!(counted, 6);
    assert_eq!(
        counts[1], 2,
        "participant 1's original vote for B is gone (was 3)"
    );
    // A differing duplicate anchored only after close changes nothing (A4).
    let dup2 = ballot(&w, 2, 0);
    v.admit(Item::Ballot(dup2.clone())).unwrap();
    v.admit(dev_anchor(&[dup2.content_id()], 250)).unwrap();
    let Some(Outcome::Result { counted, .. }) = tally(&v, &vid) else {
        panic!()
    };
    assert_eq!(counted, 6);
    // Below minimum.
    let mut w2 = world(true);
    w2.vote.min_ballots = 100;
    w2.vote = sign_vote_definition(&w2.authority, w2.vote.clone());
    let mut v2 = view(&w2);
    let bb = ballot(&w2, 1, 0);
    v2.admit(Item::Ballot(bb.clone())).unwrap();
    v2.admit(dev_anchor(&[bb.content_id()], 150)).unwrap();
    assert_eq!(
        tally(&v2, &w2.vote.vote_id()),
        Some(Outcome::BelowMinimum { counted: 1 })
    );
    assert_eq!(tally(&v2, &[9; 32]), None);
}

/// There is no way to be counted other than being anchored in Bitcoin. The
/// §9 witness fallback is gone: a node's signature was never a clock, and
/// seven of them were seven signatures, not seven people (A16).
#[test]
fn without_an_anchor_nothing_counts() {
    let w = world(true);
    let mut v = view(&w);
    let vid = w.vote.vote_id();
    let b1 = ballot(&w, 1, 0);
    let b2 = ballot(&w, 2, 1);
    v.admit(Item::Ballot(b1.clone())).unwrap();
    v.admit(Item::Ballot(b2.clone())).unwrap();

    // Registered nodes exist and the Log is healthy; the vote is simply not
    // anchored, so it has no result to give.
    for i in 0..3usize {
        let node = SigningKey::from_seed(&[0x30 + i as u8; 32]);
        let reg = build_node_registration(
            dev_keys(),
            &participant(&w, 10 + i),
            node.public_key(),
            [0; 32],
            "x:1".into(),
            "o".into(),
            *b"CZ",
            1,
        )
        .unwrap();
        v.admit(Item::NodeRegistration(reg)).unwrap();
    }
    assert_eq!(
        tally(&v, &vid),
        Some(Outcome::BelowMinimum { counted: 0 }),
        "no anchor, no count — whatever any node says"
    );
    // The 0x08 item type that used to carry those attestations no longer
    // decodes at all.
    let mut bytes = Item::Ballot(b1.clone()).encode();
    bytes[1] = 0x08;
    assert_eq!(Item::decode(&bytes), Err(DecodeError::ItemType(0x08)));

    // One anchor from anyone — no permission, no registration — and both
    // ballots count.
    v.admit(dev_anchor(&[b1.content_id(), b2.content_id()], 150))
        .unwrap();
    assert_eq!(
        tally(&v, &vid),
        Some(Outcome::Result {
            counts: vec![1, 1, 0],
            counted: 2
        })
    );
}

#[test]
fn ots_and_direct_anchor_validation() {
    let w = world(false);
    let mut v = view(&w);
    let b1 = ballot(&w, 1, 0);
    v.admit(Item::Ballot(b1.clone())).unwrap();
    let leaves = vec![b1.content_id()];
    let root = anchor_root(&leaves).unwrap();

    // Dev anchors are rejected outside dev mode.
    assert_eq!(v.admit(dev_anchor(&leaves, 150)), Err(Invalid::DevOnly));

    // OTS: the proof must end in the block's merkle root at the claimed height.
    let ops = [
        Op::Append(vec![0xAA; 16]),
        Op::Sha256,
        Op::Prepend(vec![0xBB; 32]),
        Op::Sha256,
    ];
    let final_digest = ops.iter().fold(root.to_vec(), |d, op| op.execute(&d));
    let block_root: [u8; 32] = final_digest.clone().try_into().unwrap();
    w.headers.set_root(150, block_root);
    let good = ots::serialize(&ots::linear(
        &root,
        &ops,
        Attestation::Bitcoin { height: 150 },
    ));
    let anchor = |ots_bytes: Vec<u8>, height: u32| {
        Item::Anchor(Anchor {
            leaves: leaves.clone(),
            proof: AnchorProof::Ots {
                height,
                ots: ots_bytes,
            },
        })
    };
    assert_eq!(v.admit(anchor(good.clone(), 150)), Ok(()));
    assert_eq!(v.anchored_height(&b1.content_id()), Some(150));
    // Wrong height / wrong digest / pending → not accepted.
    assert_eq!(
        validate(&anchor(good.clone(), 151), &v),
        Err(Invalid::BadAnchorProof)
    );
    w.headers.set_root(152, [0xEE; 32]);
    let wrong = ots::serialize(&ots::linear(
        &root,
        &ops,
        Attestation::Bitcoin { height: 152 },
    ));
    assert_eq!(
        validate(&anchor(wrong, 152), &v),
        Err(Invalid::BadAnchorProof)
    );
    let pending = ots::serialize(&ots::linear(
        &root,
        &ops[..2],
        Attestation::Pending {
            uri: "https://calendar.example".into(),
        },
    ));
    assert_eq!(
        validate(&anchor(pending, 150), &v),
        Err(Invalid::Unverified)
    );
    assert!(matches!(
        validate(&anchor(good.clone(), 999), &v),
        Err(Invalid::MissingReference(Reference::Header(999)))
    ));
    assert!(matches!(
        validate(&anchor(vec![1, 2, 3], 150), &v),
        Err(Invalid::Structure(_))
    ));

    // Direct: OP_RETURN commitment + partial merkle tree against the block.
    let tx = spv::commitment_transaction(&root);
    let txids = vec![[0x01; 32], spv::txid(&tx).unwrap(), [0x02; 32], [0x03; 32]];
    let block_root = spv::tx_merkle_root(&txids);
    w.headers.set_root(160, block_root);
    let pmt = spv::partial_merkle_tree(&txids, 1);
    let direct = Item::Anchor(Anchor {
        leaves: leaves.clone(),
        proof: AnchorProof::Direct {
            height: 160,
            raw_tx: tx.clone(),
            partial_merkle_tree: pmt.clone(),
        },
    });
    assert_eq!(validate(&direct, &v), Ok(()));
    let bad = Item::Anchor(Anchor {
        leaves: leaves.clone(),
        proof: AnchorProof::Direct {
            height: 150,
            raw_tx: tx,
            partial_merkle_tree: pmt,
        },
    });
    assert_eq!(validate(&bad, &v), Err(Invalid::BadAnchorProof));
}

#[test]
fn initiative_derivation_and_snapshot_roundtrip() {
    let w = world(true);
    w.headers.set_tip(400);
    let mut v = view(&w);
    let n = initiative_threshold(w.tree.leaf_count());
    assert_eq!(n, 1);
    // Force a threshold of 3 by using a bigger registry size in the initiative? The
    // protocol value for 24 leaves is 1; use two initiatives to exercise both cases.
    let author = participant(&w, 5);
    let init = build_initiative(
        dev_keys(),
        &author,
        "Ban leaf blowers".into(),
        n,
        300,
        Secrecy::None,
        0,
    )
    .unwrap();
    let init_id = init.content_id();
    v.admit(Item::Initiative(init.clone())).unwrap();
    assert_eq!(derive_vote(&v, &init_id), None, "no anchored supports yet");
    let s1 = build_support(dev_keys(), &participant(&w, 6), &init_id).unwrap();
    v.admit(Item::Support(s1.clone())).unwrap();
    assert_eq!(derive_vote(&v, &init_id), None, "support not anchored");
    v.admit(dev_anchor(&[s1.content_id()], 301)).unwrap();
    assert_eq!(
        derive_vote(&v, &init_id),
        None,
        "anchored after the deadline"
    );
    v.admit(dev_anchor(&[s1.content_id()], 299)).unwrap();
    let derived = derive_vote(&v, &init_id).unwrap();
    assert_eq!(derived.open_block, 300 + INITIATIVE_OPEN_DELAY);
    assert_eq!(
        derived.close_block,
        derived.open_block + INITIATIVE_VOTE_BLOCKS
    );
    assert_eq!(derived.options, vec!["Yes", "No"]);
    assert_eq!(
        derived.origin,
        Origin::Initiative {
            initiative_id: init_id
        }
    );
    // The derived definition validates as an item; a tampered one does not.
    assert_eq!(v.admit(Item::VoteDefinition(derived.clone())), Ok(()));
    let mut tampered = derived.clone();
    tampered.question.push('!');
    assert_eq!(
        validate(&Item::VoteDefinition(tampered), &v),
        Err(Invalid::DerivationMismatch)
    );

    // Snapshot round trip through the verifier loader, items in scrambled order.
    let b1 = ballot(&w, 1, 0);
    let b2 = ballot(&w, 2, 1);
    let anchor = dev_anchor(&[b1.content_id(), b2.content_id()], 150);
    let items: Vec<Vec<u8>> = vec![
        anchor.encode(),
        Item::Ballot(b2.clone()).encode(),
        Item::Support(s1.clone()).encode(),
        Item::VoteDefinition(derived.clone()).encode(),
        Item::Ballot(b1.clone()).encode(),
        Item::VoteDefinition(w.vote.clone()).encode(),
        Item::Initiative(init.clone()).encode(),
        dev_anchor(&[s1.content_id()], 299).encode(),
        Item::Ballot(Ballot {
            payload: vec![9],
            ..b1.clone()
        })
        .encode(), // invalid
    ];
    let bytes = encode_snapshot(std::slice::from_ref(&w.snapshot), &items);
    let loaded = SnapshotView::load(
        &bytes,
        w.deployment.clone(),
        Arc::new(w.keys.verifier.clone()),
        w.headers.clone(),
    )
    .unwrap();
    assert_eq!(loaded.report.accepted, 8);
    assert_eq!(loaded.report.invalid.len(), 1);
    assert_eq!(loaded.report.unresolved, 0);
    assert_eq!(loaded.vote_ids().len(), 2);
    let Some(Outcome::Result { counts, .. }) = tally(&loaded, &w.vote.vote_id()) else {
        panic!()
    };
    assert_eq!(counts, vec![1, 1, 0]);
    assert!(
        SnapshotView::load(
            &bytes[..20],
            w.deployment.clone(),
            Arc::new(w.keys.verifier.clone()),
            w.headers.clone()
        )
        .is_err()
    );
}
