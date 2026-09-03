//! Phase 8: the verifier recomputes results from a snapshot and prints the
//! guarantee level (anchored / fallback).

use cv_core::build::*;
use cv_core::context::Deployment;
use cv_core::crypto::field::{Fr, fr_mod};
use cv_core::crypto::groth16::{self, dev_keys};
use cv_core::crypto::sig::SigningKey;
use cv_core::identity::commitment;
use cv_core::items::*;
use cv_core::registry::{RegistrySnapshot, RegistryTree};
use cv_core::snapshot::encode_snapshot;
use cv_verifier::{Config, MockHeaders, verify};
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use std::sync::Arc;

struct World {
    tree: RegistryTree,
    secrets: Vec<Fr>,
    snapshot: RegistrySnapshot,
    vote: VoteDefinition,
    deployment: Deployment,
}

fn world() -> World {
    let secrets: Vec<Fr> = (1..=20u64).map(|i| fr_mod(&[i as u8; 32])).collect();
    let tree = RegistryTree::from_leaves(secrets.iter().map(commitment).collect());
    let authority = SigningKey::from_seed(&[0x42u8; 32]);
    let issuer = SigningKey::from_seed(&[0x11u8; 32]);
    let snapshot = RegistrySnapshot::sign(&issuer, 1, &tree);
    let vote = sign_vote_definition(
        &authority,
        VoteDefinition {
            question: "Verify?".into(),
            options: vec!["A".into(), "B".into()],
            issuer_key: issuer.public_key(),
            registry_root: tree.root(),
            open_block: 100,
            close_block: 200,
            min_ballots: 2,
            secrecy: Secrecy::None,
            origin: Origin::Initiative {
                initiative_id: [0; 32],
            },
        },
    );
    let deployment = Deployment {
        authority_keys: vec![authority.public_key()],
        issuer_keys: vec![issuer.public_key()],
        dev_mode: true,
    };
    World {
        tree,
        secrets,
        snapshot,
        vote,
        deployment,
    }
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

fn config(w: &World) -> Config {
    Config {
        deployment: w.deployment.clone(),
        verifier: Arc::new(
            groth16::setup(&mut ChaCha20Rng::from_seed(groth16::DEV_SETUP_SEED)).verifier,
        ),
    }
}

fn dev_anchor(ids: &[Id], height: u32) -> Vec<u8> {
    let mut leaves = ids.to_vec();
    leaves.sort();
    Item::Anchor(Anchor {
        leaves,
        proof: AnchorProof::Dev { height },
    })
    .encode()
}

#[test]
fn anchored_result_and_guarantee_label() {
    let w = world();
    let vid = w.vote.vote_id();
    let ballots: Vec<Ballot> = (1..=5)
        .map(|i| plaintext_ballot(dev_keys(), &participant(&w, i), &w.vote, (i % 2) as u8).unwrap())
        .collect();
    let ids: Vec<Id> = ballots.iter().map(|b| b.content_id()).collect();
    let mut items: Vec<Vec<u8>> = ballots
        .iter()
        .map(|b| Item::Ballot(b.clone()).encode())
        .collect();
    items.push(dev_anchor(&ids[..4], 150));
    items.push(dev_anchor(&ids[4..], 250)); // after close: ballot 5 does not count
    items.push(Item::VoteDefinition(w.vote.clone()).encode());
    items.push(vec![1, 2, 3]); // garbage: snapshot rejected as malformed
    let bad = encode_snapshot(std::slice::from_ref(&w.snapshot), &items);
    assert!(verify(&bad, Arc::new(MockHeaders { tip: 300 }), config(&w), None).is_err());
    items.pop();
    let snap = encode_snapshot(std::slice::from_ref(&w.snapshot), &items);
    let report = verify(&snap, Arc::new(MockHeaders { tip: 300 }), config(&w), None).unwrap();
    assert_eq!(report.items_accepted, 8);
    assert_eq!(report.items_invalid, 0);
    assert_eq!(report.votes.len(), 1);
    let v = &report.votes[0];
    assert_eq!(v.vote_id, hex::encode(vid));
    assert_eq!(v.outcome, "result");
    assert_eq!(v.counts, Some(vec![2, 2])); // ballots 1..4: options 1,0,1,0
    assert_eq!(v.counted, Some(4));
    let text = cv_verifier::render(&report);
    assert!(text.contains("RESULT (every counted ballot anchored in Bitcoin)"));
    assert!(text.contains("WARNING: dev mode"));
    // Filtering by vote id and by an unknown id.
    assert_eq!(
        verify(
            &snap,
            Arc::new(MockHeaders { tip: 300 }),
            config(&w),
            Some(vid)
        )
        .unwrap()
        .votes
        .len(),
        1
    );
    assert_eq!(
        verify(
            &snap,
            Arc::new(MockHeaders { tip: 300 }),
            config(&w),
            Some([9; 32])
        )
        .unwrap()
        .votes
        .len(),
        0
    );
}

/// Without an anchor there is no result to report, however many nodes vouch
/// for the ballots: the §9 fallback is gone (A16).
#[test]
fn unanchored_ballots_are_not_counted() {
    let w = world();
    let b1 = plaintext_ballot(dev_keys(), &participant(&w, 1), &w.vote, 0).unwrap();
    let b2 = plaintext_ballot(dev_keys(), &participant(&w, 2), &w.vote, 1).unwrap();
    let mut items = vec![
        Item::VoteDefinition(w.vote.clone()).encode(),
        Item::Ballot(b1.clone()).encode(),
        Item::Ballot(b2.clone()).encode(),
    ];
    for i in 0..3usize {
        let k = SigningKey::from_seed(&[0x30 + i as u8; 32]);
        let reg = build_node_registration(
            dev_keys(),
            &participant(&w, 10 + i),
            k.public_key(),
            [0; 32],
            "x:1".into(),
            "o".into(),
            *b"CZ",
            1,
        )
        .unwrap();
        items.push(Item::NodeRegistration(reg).encode());
    }
    let snap = encode_snapshot(std::slice::from_ref(&w.snapshot), &items);
    let report = verify(&snap, Arc::new(MockHeaders { tip: 300 }), config(&w), None).unwrap();
    let v = &report.votes[0];
    assert_eq!(v.outcome, "below_minimum");
    assert_eq!(v.counted, Some(0));

    // Anchored by one node — any node — and the same snapshot has a result.
    items.push(dev_anchor(&[b1.content_id(), b2.content_id()], 150));
    let snap = encode_snapshot(std::slice::from_ref(&w.snapshot), &items);
    let report = verify(&snap, Arc::new(MockHeaders { tip: 300 }), config(&w), None).unwrap();
    assert_eq!(report.votes[0].outcome, "result");
    assert_eq!(report.votes[0].counts, Some(vec![1, 1]));
}
