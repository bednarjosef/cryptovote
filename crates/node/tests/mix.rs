//! Phase 7: a ballot reaches the Log through 3 hops, through 1 hop, with a
//! hop crashing mid-hold, and with Tor unreachable; decoys are dropped.

use cv_client::device::Device;
use cv_client::light::NodeClient;
use cv_client::mix::{MixClient, TorSetup};
use cv_core::build::*;
use cv_core::context::Deployment;
use cv_core::crypto::field::{Fr, fr_mod};
use cv_core::crypto::groth16;
use cv_core::crypto::mix::MixSecret;
use cv_core::crypto::sig::SigningKey;
use cv_core::identity::commitment;
use cv_core::items::*;
use cv_core::registry::{RegistrySnapshot, RegistryTree};
use cv_log::Log;
use cv_log::headers::MockChain;
use cv_log::store::{MemoryStore, RedbStore, Store};
use cv_node::anchor::{AnchorConfig, AnchorMode};
use cv_node::mix::MixConfig;
use cv_node::{NodeConfig, NodeHandle, start};
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

struct Fixture {
    tree: RegistryTree,
    secrets: Vec<Fr>,
    snapshot: RegistrySnapshot,
    vote: VoteDefinition,
    deployment: Deployment,
    chain: Arc<MockChain>,
    keys: Arc<groth16::MembershipKeys>,
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
            question: "Mix?".into(),
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
    let chain = Arc::new(MockChain::new(100, 1.0));
    chain.set_tip(150);
    let deployment = Deployment {
        authority_keys: vec![authority.public_key()],
        issuer_key: issuer.public_key(),
        dev_mode: true,
    };
    let keys = Arc::new(groth16::setup(&mut ChaCha20Rng::from_seed(
        groth16::DEV_SETUP_SEED,
    )));
    Fixture {
        tree,
        secrets,
        snapshot,
        vote,
        deployment,
        chain,
        keys,
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

fn device(f: &Fixture, i: usize) -> Device {
    Device {
        secret: f.secrets[i],
        enrollment: None,
        guard: None,
        guard_since_unix: None,
        keyparty_secrets: Default::default(),
    }
}

struct HopSpec {
    name: &'static str,
    node_key: SigningKey,
    mix: MixSecret,
    operator: &'static str,
    country: &'static [u8; 2],
    asn: u32,
}

fn hop_spec(
    i: u8,
    name: &'static str,
    operator: &'static str,
    country: &'static [u8; 2],
    asn: u32,
) -> HopSpec {
    HopSpec {
        name,
        node_key: SigningKey::from_seed(&[0x50 + i; 32]),
        mix: MixSecret::from_seed([0x60 + i; 32]),
        operator,
        country,
        asn,
    }
}

fn mix_cfg(spec: &HopSpec, hold_min_ms: u64, k: u64, cap_ms: u64) -> MixConfig {
    MixConfig {
        secret: Some(spec.mix.clone()),
        hold_min: Duration::from_millis(hold_min_ms),
        hold_k: k,
        hold_cap: Duration::from_millis(cap_ms),
        tick: Duration::from_millis(50),
    }
}

async fn spawn(
    f: &Fixture,
    name: &str,
    listen: SocketAddr,
    store: Box<dyn Store>,
    mix: MixConfig,
    anchor: bool,
) -> NodeHandle {
    let mut log = Log::open(f.deployment.clone(), f.keys.clone(), store, f.chain.clone()).unwrap();
    log.add_registry(f.snapshot.clone(), f.tree.leaves().to_vec())
        .unwrap();
    log.insert(&Item::VoteDefinition(f.vote.clone()).encode())
        .unwrap();
    let anchor = if anchor {
        AnchorConfig {
            mode: AnchorMode::Dev,
            interval: Duration::from_millis(150),
            ..AnchorConfig::default()
        }
    } else {
        AnchorConfig::default()
    };
    start(
        NodeConfig {
            name: name.into(),
            listen,
            gossip_interval: Duration::from_millis(150),
            anchor,
            mix,
            ..NodeConfig::default()
        },
        log,
    )
    .await
    .unwrap()
}

fn any() -> SocketAddr {
    "127.0.0.1:0".parse().unwrap()
}

/// Full-mesh peering.
fn mesh(handles: &[NodeHandle]) {
    for a in handles {
        for b in handles {
            if a.addr != b.addr {
                a.node.add_peer(b.url());
            }
        }
    }
}

/// Publish the registrations of the given hops (participants 10, 11, …).
async fn register(f: &Fixture, client: &NodeClient, specs: &[(&HopSpec, SocketAddr)]) {
    for (i, (spec, addr)) in specs.iter().enumerate() {
        let reg = build_node_registration(
            &f.keys,
            &participant(f, 10 + i),
            spec.node_key.public_key(),
            spec.mix.public(),
            addr.to_string(),
            spec.operator.into(),
            *spec.country,
            spec.asn,
        )
        .unwrap();
        client
            .submit_item(&Item::NodeRegistration(reg))
            .await
            .unwrap();
    }
    // Wait until the node lists them all.
    let deadline = Instant::now() + Duration::from_secs(10);
    while client.nodes().await.unwrap().len() < specs.len() {
        assert!(Instant::now() < deadline, "registrations did not appear");
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn ballot_through_three_hops_and_decoys_dropped() {
    let f = fixture();
    // Five hops: the guard plus two disjoint pairs, so both paths can be 3 hops long.
    let specs = [
        hop_spec(1, "A", "op-a", b"CZ", 1),
        hop_spec(2, "B", "op-b", b"DE", 2),
        hop_spec(3, "C", "op-c", b"AT", 3),
        hop_spec(4, "D", "op-d", b"PL", 4),
        hop_spec(5, "E", "op-e", b"FR", 5),
    ];
    let mut handles = Vec::new();
    for (i, s) in specs.iter().enumerate() {
        handles.push(
            spawn(
                &f,
                s.name,
                any(),
                Box::new(MemoryStore::new()),
                mix_cfg(s, 100, 1, 600),
                i == 4,
            )
            .await,
        );
    }
    mesh(&handles);
    let client = NodeClient::new(handles[0].url());
    let regs: Vec<(&HopSpec, SocketAddr)> = specs
        .iter()
        .zip(handles.iter())
        .map(|(s, h)| (s, h.addr))
        .collect();
    register(&f, &client, &regs).await;
    tokio::time::sleep(Duration::from_millis(400)).await; // let registrations gossip to all hops

    let mc = MixClient::new(client.clone(), TorSetup::Disabled);
    let mut dev = device(&f, 1);
    let report = mc
        .cast_with_retry(
            &mut dev,
            &f.keys,
            &f.vote.vote_id(),
            1,
            Duration::from_secs(20),
            3,
        )
        .await
        .unwrap();
    assert_eq!(report.privacy.hops, 3, "{}", report.privacy);
    assert_eq!(report.privacy.paths, 2);
    assert!(!report.privacy.tor);
    assert_eq!(report.attempts, 1);
    assert_eq!(report.anchored_height, Some(150));
    assert!(dev.guard.is_some(), "guard persisted on the device");
    // Second cast keeps the guard.
    let guard = dev.guard.clone();
    let mut dev2 = dev.clone();
    let _ = mc.send_decoy(&mut dev2).await.unwrap();
    assert_eq!(dev2.guard, guard);

    // Decoys never reach the Log.
    let before = client.status().await.unwrap().items;
    for _ in 0..3 {
        assert!(mc.send_decoy(&mut dev).await.unwrap());
    }
    tokio::time::sleep(Duration::from_millis(1500)).await;
    assert_eq!(client.status().await.unwrap().items, before);

    for h in handles {
        h.shutdown().await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn ballot_through_one_hop_when_only_one_node_is_registered() {
    let f = fixture();
    let spec = hop_spec(1, "solo", "op", b"CZ", 1);
    let h = spawn(
        &f,
        "solo",
        any(),
        Box::new(MemoryStore::new()),
        mix_cfg(&spec, 100, 1, 400),
        true,
    )
    .await;
    let client = NodeClient::new(h.url());
    register(&f, &client, &[(&spec, h.addr)]).await;
    let mc = MixClient::new(client.clone(), TorSetup::Disabled);
    let mut dev = device(&f, 2);
    let report = mc
        .cast_with_retry(
            &mut dev,
            &f.keys,
            &f.vote.vote_id(),
            0,
            Duration::from_secs(20),
            3,
        )
        .await
        .unwrap();
    assert_eq!(report.privacy.hops, 1, "{}", report.privacy);
    assert_eq!(report.anchored_height, Some(150));
    assert!(report.privacy.to_string().starts_with("partial"));
    h.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn hop_crashing_mid_hold_forwards_after_restart() {
    let f = fixture();
    let specs = [
        hop_spec(1, "A", "op-a", b"CZ", 1),
        hop_spec(2, "B", "op-b", b"DE", 2),
        hop_spec(3, "C", "op-c", b"AT", 3),
    ];
    let dir = tempfile::tempdir().unwrap();
    let b_store = dir.path().join("b.redb");
    // B holds for a long time (3 s minimum, 4 s cap); A and C are fast.
    let a = spawn(
        &f,
        "A",
        any(),
        Box::new(MemoryStore::new()),
        mix_cfg(&specs[0], 50, 1, 200),
        false,
    )
    .await;
    let b = spawn(
        &f,
        "B",
        any(),
        Box::new(RedbStore::open(&b_store).unwrap()),
        mix_cfg(&specs[1], 3000, 100, 4000),
        false,
    )
    .await;
    let c = spawn(
        &f,
        "C",
        any(),
        Box::new(MemoryStore::new()),
        mix_cfg(&specs[2], 50, 1, 200),
        true,
    )
    .await;
    let b_addr = b.addr;
    a.node.add_peer(c.url());
    c.node.add_peer(a.url());
    b.node.add_peer(a.url());
    a.node.add_peer(b.url());
    let client = NodeClient::new(a.url());
    register(
        &f,
        &client,
        &[
            (&specs[0], a.addr),
            (&specs[1], b_addr),
            (&specs[2], c.addr),
        ],
    )
    .await;
    tokio::time::sleep(Duration::from_millis(500)).await;

    // Force the route A -> B -> C by making A the guard and using a 3-hop path.
    let mc = MixClient {
        hops_per_path: 3,
        paths: 1,
        ..MixClient::new(client.clone(), TorSetup::Disabled)
    };
    let mut dev = device(&f, 3);
    dev.guard = Some(hex::encode(specs[0].node_key.public_key()));
    dev.guard_since_unix = Some(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs(),
    );
    let vd = f.vote.clone();
    let p = participant(&f, 3);
    let ballot = plaintext_ballot(&f.keys, &p, &vd, 1).unwrap();
    let (privacy, _) = mc
        .send_item(&mut dev, Item::Ballot(ballot.clone()).encode(), &[])
        .await
        .unwrap();
    assert_eq!(privacy.hops, 3);

    // B receives the packet from A and holds it; crash B while holding.
    let deadline = Instant::now() + Duration::from_secs(5);
    while cv_node::mix::queue_len(&b.node) == 0 {
        assert!(Instant::now() < deadline, "B never received the packet");
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(
        client
            .ballot_status(&vd.vote_id(), &ballot.nullifier)
            .await
            .unwrap()
            .is_empty(),
        "not published yet"
    );
    b.shutdown().await;
    tokio::time::sleep(Duration::from_millis(300)).await;

    // Restart B on the same address with the same store: the queued packet is forwarded.
    let b2 = spawn(
        &f,
        "B2",
        b_addr,
        Box::new(RedbStore::open(&b_store).unwrap()),
        mix_cfg(&specs[1], 100, 1, 500),
        false,
    )
    .await;
    b2.node.add_peer(a.url());
    assert_eq!(
        cv_node::mix::queue_len(&b2.node),
        1,
        "queue restored from disk"
    );
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        let st = NodeClient::new(c.url())
            .ballot_status(&vd.vote_id(), &ballot.nullifier)
            .await
            .unwrap();
        if st.first().and_then(|s| s.anchored_height).is_some() {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "ballot never arrived after the hop restart"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert_eq!(cv_node::mix::queue_len(&b2.node), 0);
    a.shutdown().await;
    b2.shutdown().await;
    c.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn tor_unreachable_falls_back_to_direct_and_says_so() {
    let f = fixture();
    let spec = hop_spec(7, "solo", "op", b"CZ", 1);
    let h = spawn(
        &f,
        "solo",
        any(),
        Box::new(MemoryStore::new()),
        mix_cfg(&spec, 50, 1, 300),
        true,
    )
    .await;
    let client = NodeClient::new(h.url());
    register(&f, &client, &[(&spec, h.addr)]).await;
    let mc = MixClient::new(
        client.clone(),
        TorSetup::Failed("bootstrap timed out".into()),
    );
    assert!(mc.tor_error.as_deref().unwrap().contains("unreachable"));
    let mut dev = device(&f, 4);
    let report = mc
        .cast_with_retry(
            &mut dev,
            &f.keys,
            &f.vote.vote_id(),
            1,
            Duration::from_secs(20),
            3,
        )
        .await
        .unwrap();
    assert!(!report.privacy.tor);
    assert!(
        report.privacy.to_string().contains("NO Tor"),
        "{}",
        report.privacy
    );
    assert_eq!(report.anchored_height, Some(150));
    // No registered hops at all: direct submission, indicator says DIRECT.
    let f2 = fixture();
    let h2 = spawn(
        &f2,
        "bare",
        any(),
        Box::new(MemoryStore::new()),
        MixConfig::default(),
        true,
    )
    .await;
    let mc2 = MixClient::new(NodeClient::new(h2.url()), TorSetup::Disabled);
    let mut dev = device(&f2, 5);
    let report = mc2
        .cast_with_retry(
            &mut dev,
            &f2.keys,
            &f2.vote.vote_id(),
            0,
            Duration::from_secs(20),
            3,
        )
        .await
        .unwrap();
    assert_eq!(report.privacy.hops, 0);
    assert!(report.privacy.to_string().starts_with("DIRECT"));
    assert_eq!(report.anchored_height, Some(150));
    h.shutdown().await;
    h2.shutdown().await;
}
