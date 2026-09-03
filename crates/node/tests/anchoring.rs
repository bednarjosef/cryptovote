//! Phase 5: the anchorer role. Dev anchors on the mock chain, and the free
//! OpenTimestamps path end to end against a mock calendar: submit, pending,
//! upgrade, verify against the block header, publish.

use axum::Router;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::routing::{get, post};
use cv_client::light::NodeClient;
use cv_core::build::*;
use cv_core::context::Deployment;
use cv_core::crypto::field::{Fr, fr_mod};
use cv_core::crypto::groth16::{self, dev_keys};
use cv_core::crypto::ots;
use cv_core::crypto::sig::SigningKey;
use cv_core::identity::commitment;
use cv_core::items::*;
use cv_core::registry::{RegistrySnapshot, RegistryTree};
use cv_log::Log;
use cv_log::headers::{HeaderSource, MockChain};
use cv_log::store::MemoryStore;
use cv_node::anchor::{AnchorConfig, AnchorMode};
use cv_node::{NodeConfig, start};
use opentimestamps::attestation::Attestation;
use opentimestamps::op::Op;
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

struct Fixture {
    tree: RegistryTree,
    secrets: Vec<Fr>,
    snapshot: RegistrySnapshot,
    vote: VoteDefinition,
    deployment: Deployment,
}

fn fixture(dev_mode: bool) -> Fixture {
    let secrets: Vec<Fr> = (1..=8u64).map(|i| fr_mod(&[i as u8; 32])).collect();
    let tree = RegistryTree::from_leaves(secrets.iter().map(commitment).collect());
    let authority = SigningKey::from_seed(&[0x42u8; 32]);
    let issuer = SigningKey::from_seed(&[0x11u8; 32]);
    let snapshot = RegistrySnapshot::sign(&issuer, 1, &tree);
    let vote = sign_vote_definition(
        &authority,
        VoteDefinition {
            question: "Anchor?".into(),
            options: vec!["Yes".into(), "No".into()],
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
    let deployment = Deployment {
        authority_keys: vec![authority.public_key()],
        issuer_key: issuer.public_key(),
        dev_mode,
    };
    Fixture {
        tree,
        secrets,
        snapshot,
        vote,
        deployment,
    }
}

fn participant(f: &Fixture, i: usize) -> Participant {
    Participant {
        secret: f.secrets[i],
        registry_root: f.tree.root(),
        index: i as u32,
        siblings: f.tree.path(i as u32).unwrap(),
    }
}

fn keys() -> Arc<groth16::MembershipKeys> {
    Arc::new(groth16::setup(&mut ChaCha20Rng::from_seed(
        groth16::DEV_SETUP_SEED,
    )))
}

async fn wait_anchored(client: &NodeClient, vote_id: &Id, n: &Fr) -> u32 {
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        let st = client.ballot_status(vote_id, n).await.unwrap();
        if let Some(h) = st.first().and_then(|s| s.anchored_height) {
            return h;
        }
        assert!(Instant::now() < deadline, "ballot never got anchored");
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn dev_anchorer_anchors_new_items_on_the_mock_chain() {
    let f = fixture(true);
    let chain = Arc::new(MockChain::new(100, 1.0));
    chain.set_tip(150);
    let mut log = Log::open(
        f.deployment.clone(),
        keys(),
        Box::new(MemoryStore::new()),
        chain.clone(),
    )
    .unwrap();
    log.add_registry(f.snapshot.clone(), f.tree.leaves().to_vec())
        .unwrap();
    log.insert(&Item::VoteDefinition(f.vote.clone()).encode())
        .unwrap();
    let b = plaintext_ballot(dev_keys(), &participant(&f, 1), &f.vote, 1).unwrap();
    log.insert(&Item::Ballot(b.clone()).encode()).unwrap();
    let config = NodeConfig {
        name: "dev-anchorer".into(),
        anchor: AnchorConfig {
            mode: AnchorMode::Dev,
            interval: Duration::from_millis(200),
            ..AnchorConfig::default()
        },
        ..NodeConfig::default()
    };
    let h = start(config, log).await.unwrap();
    let client = NodeClient::new(h.url());
    assert_eq!(
        wait_anchored(&client, &f.vote.vote_id(), &b.nullifier).await,
        150
    );
    let anchors = client.anchors().await.unwrap();
    assert!(anchors.iter().any(|a| a.kind == "dev" && a.height == 150));
    h.shutdown().await;
}

// --- mock OpenTimestamps calendar -------------------------------------------

#[derive(Default)]
struct CalendarState {
    url: String,
    /// commitment digest (hex) -> submitted digest
    commitments: BTreeMap<String, Vec<u8>>,
    mined_height: Option<u32>,
}

type Shared = Arc<Mutex<CalendarState>>;

async fn digest(State(st): State<Shared>, body: axum::body::Bytes) -> Vec<u8> {
    let mut st = st.lock().unwrap();
    let nonce = Op::Append(vec![0xC0, 0xFF, 0xEE]);
    let commitment = nonce.execute(&body);
    st.commitments
        .insert(hex::encode(&commitment), body.to_vec());
    ots::serialize(&ots::linear(
        &body,
        &[nonce],
        Attestation::Pending {
            uri: st.url.clone(),
        },
    ))
}

async fn timestamp(
    State(st): State<Shared>,
    Path(hex_commitment): Path<String>,
) -> (StatusCode, Vec<u8>) {
    let st = st.lock().unwrap();
    let Some(height) = st.mined_height else {
        return (StatusCode::NOT_FOUND, Vec::new());
    };
    if !st.commitments.contains_key(&hex_commitment) {
        return (StatusCode::NOT_FOUND, Vec::new());
    }
    let commitment = hex::decode(&hex_commitment).unwrap();
    (
        StatusCode::OK,
        ots::serialize(&ots::linear(
            &commitment,
            &[Op::Sha256],
            Attestation::Bitcoin {
                height: height as usize,
            },
        )),
    )
}

/// The block's merkle root the calendar's proof will end in.
fn expected_block_root(commitment: &[u8]) -> [u8; 32] {
    Op::Sha256.execute(commitment).try_into().unwrap()
}

/// Header source the test controls (release-mode style: no dev shortcuts).
struct TestHeaders {
    roots: Mutex<BTreeMap<u32, [u8; 32]>>,
    tip: u32,
}

impl HeaderSource for TestHeaders {
    fn merkle_root(&self, height: u32) -> Option<[u8; 32]> {
        (height <= self.tip)
            .then(|| self.roots.lock().unwrap().get(&height).copied())
            .flatten()
    }
    fn tip_height(&self) -> Option<u32> {
        Some(self.tip)
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn ots_anchorer_submits_upgrades_verifies_and_publishes() {
    // Mock calendar.
    let state: Shared = Arc::new(Mutex::new(CalendarState::default()));
    let app = Router::new()
        .route("/digest", post(digest))
        .route("/timestamp/{c}", get(timestamp))
        .with_state(state.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let cal_url = format!("http://{}", listener.local_addr().unwrap());
    state.lock().unwrap().url = cal_url.clone();
    let cal_task = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

    // Release-style node (dev_mode = false): dev anchors would be rejected.
    let f = fixture(false);
    let headers = Arc::new(TestHeaders {
        roots: Mutex::new(BTreeMap::new()),
        tip: 300,
    });
    let mut log = Log::open(
        f.deployment.clone(),
        keys(),
        Box::new(MemoryStore::new()),
        headers.clone(),
    )
    .unwrap();
    log.add_registry(f.snapshot.clone(), f.tree.leaves().to_vec())
        .unwrap();
    log.insert(&Item::VoteDefinition(f.vote.clone()).encode())
        .unwrap();
    let b = plaintext_ballot(dev_keys(), &participant(&f, 2), &f.vote, 0).unwrap();
    log.insert(&Item::Ballot(b.clone()).encode()).unwrap();
    let config = NodeConfig {
        name: "ots-anchorer".into(),
        anchor: AnchorConfig {
            mode: AnchorMode::Ots,
            interval: Duration::from_millis(200),
            calendars: vec![cal_url.clone()],
            min_calendars: 1,
        },
        ..NodeConfig::default()
    };
    let h = start(config, log).await.unwrap();
    let client = NodeClient::new(h.url());

    // The node submits a root; the calendar answers with a pending attestation.
    let deadline = Instant::now() + Duration::from_secs(20);
    let commitment = loop {
        let pending = cv_node::anchor::pending_submissions(&h.node);
        if !pending.is_empty() {
            let st = state.lock().unwrap();
            if let Some((c, _)) = st.commitments.iter().next() {
                break hex::decode(c).unwrap();
            }
        }
        assert!(
            Instant::now() < deadline,
            "no submission reached the calendar"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    };
    // While pending, nothing is anchored (a pending proof is unverified).
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert!(
        client
            .ballot_status(&f.vote.vote_id(), &b.nullifier)
            .await
            .unwrap()[0]
            .anchored_height
            .is_none()
    );
    assert!(client.anchors().await.unwrap().is_empty());

    // "Bitcoin confirms": the calendar has a Bitcoin attestation at 150, and
    // our header at 150 carries the matching merkle root.
    headers
        .roots
        .lock()
        .unwrap()
        .insert(150, expected_block_root(&commitment));
    state.lock().unwrap().mined_height = Some(150);
    assert_eq!(
        wait_anchored(&client, &f.vote.vote_id(), &b.nullifier).await,
        150
    );
    let anchors = client.anchors().await.unwrap();
    assert_eq!(anchors.len(), 1);
    assert_eq!(anchors[0].kind, "ots");
    assert!(
        cv_node::anchor::pending_submissions(&h.node).is_empty(),
        "completed submissions are cleared"
    );

    // The published anchor re-verifies from scratch against the same headers.
    let anchor_id: Id = hex::decode(&anchors[0].content_id)
        .unwrap()
        .try_into()
        .unwrap();
    let item = client.item(&anchor_id).await.unwrap().unwrap();
    {
        let log = h.node.log.lock().unwrap();
        assert_eq!(cv_core::validate::validate(&item, &*log), Ok(()));
    }

    h.shutdown().await;
    cal_task.abort();
}
