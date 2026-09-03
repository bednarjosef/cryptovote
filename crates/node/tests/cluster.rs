//! Phase 4: a cluster of 5 nodes converges to the same set; invalid items are
//! rejected and not relayed; identical duplicates dedupe; differing duplicates
//! are both stored so the nullifier is invalidated by the tally.

use cv_client::light::NodeClient;
use cv_core::build::*;
use cv_core::context::Deployment;
use cv_core::crypto::field::{Fr, fr_mod};
use cv_core::crypto::groth16::{self, dev_keys};
use cv_core::crypto::sig::SigningKey;
use cv_core::identity::commitment;
use cv_core::items::*;
use cv_core::registry::{RegistrySnapshot, RegistryTree};
use cv_core::wire::SubmitResponse;
use cv_log::Log;
use cv_log::headers::MockChain;
use cv_log::store::MemoryStore;
use cv_node::{NodeConfig, NodeHandle, start};
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use std::collections::HashSet;
use std::sync::Arc;
use std::time::{Duration, Instant};

struct Fixture {
    tree: RegistryTree,
    secrets: Vec<Fr>,
    snapshot: RegistrySnapshot,
    vote: VoteDefinition,
    deployment: Deployment,
    chain: Arc<MockChain>,
}

fn fixture() -> Fixture {
    let secrets: Vec<Fr> = (1..=16u64).map(|i| fr_mod(&[i as u8; 32])).collect();
    let tree = RegistryTree::from_leaves(secrets.iter().map(commitment).collect());
    let authority = SigningKey::from_seed(&[0x42u8; 32]);
    let issuer = SigningKey::from_seed(&[0x11u8; 32]);
    let snapshot = RegistrySnapshot::sign(&issuer, 1, &tree);
    let vote = sign_vote_definition(
        &authority,
        VoteDefinition {
            question: "Cluster?".into(),
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
    let deployment = Deployment {
        authority_keys: vec![authority.public_key()],
        issuer_keys: vec![issuer.public_key()],
        dev_mode: true,
    };
    Fixture {
        tree,
        secrets,
        snapshot,
        vote,
        deployment,
        chain,
    }
}

fn participant(f: &Fixture, i: usize) -> Participant {
    Participant {
        secret: f.secrets[i],
        issuer_key: f.snapshot.issuer_key,
        registry_root: f.tree.root(),
        index: i as u32,
        siblings: f.tree.path(i as u32).unwrap(),
    }
}

async fn spawn_node(f: &Fixture, name: &str, keys: Arc<groth16::MembershipKeys>) -> NodeHandle {
    let log = Log::open(
        f.deployment.clone(),
        keys,
        Box::new(MemoryStore::new()),
        f.chain.clone(),
    )
    .unwrap();
    start(
        NodeConfig {
            name: name.into(),
            gossip_interval: Duration::from_millis(150),
            ..NodeConfig::default()
        },
        log,
    )
    .await
    .unwrap()
}

async fn hash_sets(clients: &[NodeClient]) -> Vec<HashSet<Id>> {
    let mut out = Vec::new();
    for c in clients {
        out.push(c.all_hashes().await.unwrap().into_iter().collect());
    }
    out
}

async fn wait_converged(clients: &[NodeClient], expected: usize) -> Vec<HashSet<Id>> {
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        let sets = hash_sets(clients).await;
        if sets.iter().all(|s| s.len() == expected) && sets.windows(2).all(|w| w[0] == w[1]) {
            return sets;
        }
        assert!(
            Instant::now() < deadline,
            "cluster did not converge: sizes {:?}",
            sets.iter().map(|s| s.len()).collect::<Vec<_>>()
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn five_nodes_converge_reject_invalid_and_dedupe() {
    let f = fixture();
    let keys = Arc::new(groth16::setup(&mut ChaCha20Rng::from_seed(
        groth16::DEV_SETUP_SEED,
    )));
    let mut handles = Vec::new();
    for i in 0..5 {
        handles.push(spawn_node(&f, &format!("n{i}"), keys.clone()).await);
    }
    // Line topology n0 - n1 - n2 - n3 - n4, both directions.
    for i in 0..5 {
        if i > 0 {
            handles[i].node.add_peer(handles[i - 1].url());
        }
        if i + 1 < 5 {
            handles[i].node.add_peer(handles[i + 1].url());
        }
    }
    let clients: Vec<NodeClient> = handles.iter().map(|h| NodeClient::new(h.url())).collect();

    // Registry goes to node 0 only; the vote to node 0; ballots round-robin.
    clients[0]
        .post_registry(&f.snapshot, f.tree.leaves())
        .await
        .unwrap();
    let vid = f.vote.vote_id();
    assert!(matches!(
        clients[0]
            .submit_item(&Item::VoteDefinition(f.vote.clone()))
            .await
            .unwrap(),
        SubmitResponse::New { .. }
    ));
    let mut ballots = Vec::new();
    for i in 1..=6 {
        let b = plaintext_ballot(dev_keys(), &participant(&f, i), &f.vote, (i % 2) as u8).unwrap();
        let resp = clients[i % 5]
            .submit_item(&Item::Ballot(b.clone()))
            .await
            .unwrap();
        assert!(
            matches!(
                resp,
                SubmitResponse::New { .. } | SubmitResponse::Orphaned { .. }
            ),
            "{resp:?}"
        );
        ballots.push(b);
    }
    let mut leaves: Vec<Id> = ballots.iter().map(|b| b.content_id()).collect();
    leaves.sort();
    let anchor = Anchor {
        leaves,
        proof: AnchorProof::Dev { height: 120 },
    };
    clients[3].submit_item(&Item::Anchor(anchor)).await.unwrap();

    // 1 vote + 6 ballots + 1 anchor on every node.
    let sets = wait_converged(&clients, 8).await;
    assert_eq!(sets[0].len(), 8);
    for c in &clients {
        assert_eq!(
            c.registries().await.unwrap().len(),
            1,
            "registry propagated by pull"
        );
        assert_eq!(c.vote_ballots(&vid).await.unwrap().len(), 6);
        let st = c.ballot_status(&vid, &ballots[0].nullifier).await.unwrap();
        assert_eq!(st.len(), 1);
        assert_eq!(st[0].anchored_height, Some(120));
    }

    // Invalid item: rejected by the receiving node and never relayed.
    let tampered = Ballot {
        payload: vec![1 - ballots[0].payload[0]],
        ..ballots[0].clone()
    };
    assert!(matches!(
        clients[2]
            .submit_item(&Item::Ballot(tampered))
            .await
            .unwrap(),
        SubmitResponse::Rejected { .. }
    ));
    // Byte-identical retransmission: AlreadyHave everywhere.
    assert_eq!(
        clients[4]
            .submit_item(&Item::Ballot(ballots[0].clone()))
            .await
            .unwrap(),
        SubmitResponse::AlreadyHave
    );
    // Re-randomized proof: Equivalent, not stored again.
    let mut rng = ChaCha20Rng::from_seed([2u8; 32]);
    let rr = Ballot {
        proof: Proof(
            groth16::rerandomize(&keys.verifier.vk, &ballots[0].proof.0, &mut rng).unwrap(),
        ),
        ..ballots[0].clone()
    };
    assert!(matches!(
        clients[1].submit_item(&Item::Ballot(rr)).await.unwrap(),
        SubmitResponse::Equivalent { .. }
    ));
    tokio::time::sleep(Duration::from_millis(600)).await;
    let sets = hash_sets(&clients).await;
    assert!(
        sets.iter().all(|s| s.len() == 8),
        "invalid/duplicate items must not spread: {:?}",
        sets.iter().map(|s| s.len()).collect::<Vec<_>>()
    );

    // Differing duplicate: stored and relayed; every node lists two ballots under the nullifier.
    let other = plaintext_ballot(dev_keys(), &participant(&f, 1), &f.vote, 0).unwrap();
    assert_ne!(other.content_id(), ballots[0].content_id());
    assert!(matches!(
        clients[4]
            .submit_item(&Item::Ballot(other.clone()))
            .await
            .unwrap(),
        SubmitResponse::New { .. }
    ));
    wait_converged(&clients, 9).await;
    for c in &clients {
        let st = c.ballot_status(&vid, &ballots[0].nullifier).await.unwrap();
        assert_eq!(
            st.len(),
            2,
            "both differing duplicates are visible for the tally to invalidate"
        );
    }

    // Snapshot export from any node decodes to the same item set.
    let snap = clients[2].snapshot().await.unwrap();
    assert_eq!(&snap[..8], b"CVSNAP01");
    let status = clients[0].status().await.unwrap();
    assert!(status.dev_mode);
    assert_eq!(status.items, 9);

    for h in handles {
        h.shutdown().await;
    }
}
