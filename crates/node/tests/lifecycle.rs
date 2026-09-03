//! Phase 6: full lifecycle in dev mode — mock issuer, enrollment over HTTP,
//! an authority vote with ballots cast through the client library, dev
//! anchoring, the tally, a double vote, and an initiative that reaches its
//! threshold and produces a derived vote that people then vote on.

use cv_client::device::Device;
use cv_client::light::NodeClient;
use cv_client::participant::ParticipantClient;
use cv_core::build::sign_vote_definition;
use cv_core::context::Deployment;
use cv_core::crypto::field::fr_from_canonical;
use cv_core::crypto::groth16;
use cv_core::crypto::sig::SigningKey;
use cv_core::items::*;
use cv_core::wire::SubmitResponse;
use cv_issuer::Issuer;
use cv_log::Log;
use cv_log::headers::MockChain;
use cv_log::store::MemoryStore;
use cv_node::anchor::{AnchorConfig, AnchorMode};
use cv_node::{NodeConfig, start};
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Wait until this exact ballot (by content id) is anchored, not merely any
/// ballot under the same nullifier.
async fn wait_ballot_anchored(client: &NodeClient, vote_id: &Id, ballot: &Ballot) -> u32 {
    let deadline = Instant::now() + Duration::from_secs(20);
    let cid = hex::encode(ballot.content_id());
    loop {
        let st = client
            .ballot_status(vote_id, &ballot.nullifier)
            .await
            .unwrap();
        if let Some(h) = st
            .iter()
            .find(|s| s.content_id == cid)
            .and_then(|s| s.anchored_height)
        {
            return h;
        }
        assert!(Instant::now() < deadline, "ballot {cid} never anchored");
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn full_lifecycle_in_dev_mode() {
    let keys = Arc::new(groth16::setup(&mut ChaCha20Rng::from_seed(
        groth16::DEV_SETUP_SEED,
    )));
    let issuer = Issuer::dev([0x11u8; 32]);
    let issuer_key = issuer.public_key();
    let authority = SigningKey::from_seed(&[0x42u8; 32]);
    let chain = Arc::new(MockChain::new(100, 1.0));
    chain.set_tip(150);

    // Node with the dev anchorer.
    let deployment = Deployment {
        authority_keys: vec![authority.public_key()],
        issuer_key,
        dev_mode: true,
    };
    let log = Log::open(
        deployment,
        keys.clone(),
        Box::new(MemoryStore::new()),
        chain.clone(),
    )
    .unwrap();
    let node = start(
        NodeConfig {
            name: "lifecycle".into(),
            anchor: AnchorConfig {
                mode: AnchorMode::Dev,
                interval: Duration::from_millis(150),
                ..AnchorConfig::default()
            },
            ..NodeConfig::default()
        },
        log,
    )
    .await
    .unwrap();
    let node_url = node.url();
    // Issuer publishes to the node after every enrollment.
    let issuer = cv_issuer::server::start(
        issuer,
        "127.0.0.1:0".parse().unwrap(),
        vec![node_url.clone()],
        None,
    )
    .await
    .unwrap();
    let pc = ParticipantClient::new(NodeClient::new(node_url.clone()), keys.clone());

    // 12 people enroll (mock eID accepts anyone); one re-enrolls (replacement).
    let mut rng = ChaCha20Rng::from_seed([7u8; 32]);
    let mut devices: Vec<Device> = (0..12).map(|_| Device::generate(&mut rng)).collect();
    for (i, d) in devices.iter_mut().enumerate() {
        let r = pc
            .enroll(d, &issuer.url(), &format!("eid-{i}"))
            .await
            .unwrap();
        assert_eq!(r.index, i as u32);
        assert!(!r.replaced);
    }
    let mut replacement = Device::generate(&mut rng);
    let r = pc
        .enroll(&mut replacement, &issuer.url(), "eid-11")
        .await
        .unwrap();
    assert_eq!(r.index, 11);
    assert!(r.replaced);
    devices[11] = replacement;
    let regs = pc.node.registries().await.unwrap();
    let latest = regs.iter().max_by_key(|r| r.epoch).unwrap();
    assert_eq!(latest.leaf_count, 12);
    let root = fr_from_canonical(&hex::decode(&latest.root).unwrap().try_into().unwrap()).unwrap();

    // Authority vote.
    let vote = sign_vote_definition(
        &authority,
        VoteDefinition {
            question: "Should the bridge be built?".into(),
            options: vec!["Yes".into(), "No".into(), "Abstain".into()],
            registry_root: root,
            open_block: 100,
            close_block: 200,
            min_ballots: 3,
            secrecy: Secrecy::None,
            origin: Origin::Initiative {
                initiative_id: [0; 32],
            },
        },
    );
    let vid = vote.vote_id();
    assert!(matches!(
        pc.node
            .submit_item(&Item::VoteDefinition(vote.clone()))
            .await
            .unwrap(),
        SubmitResponse::New { .. }
    ));

    // 10 people vote; everyone confirms their nullifier under an anchor.
    let mut expected = [0u64; 3];
    for (i, d) in devices.iter().enumerate().take(10) {
        let option = (i % 3) as u8;
        let (ballot, resp) = pc.cast(d, &vid, option).await.unwrap();
        assert!(matches!(resp, SubmitResponse::New { .. }));
        assert_eq!(ParticipantClient::receipt(&ballot).len(), 8);
        let h = pc
            .confirm(&vid, &ballot.nullifier, Duration::from_secs(20))
            .await
            .unwrap();
        assert_eq!(h, Some(150));
        expected[option as usize] += 1;
    }
    // Person 3 (who voted option 0) votes again with a different option: double action.
    let (dup, resp) = pc.cast(&devices[3], &vid, 1).await.unwrap();
    assert!(matches!(resp, SubmitResponse::New { .. }));
    wait_ballot_anchored(&pc.node, &vid, &dup).await;
    expected[0] -= 1;
    // A retransmission is byte-identical and deduplicated.
    let (_, resp) = pc.cast(&devices[4], &vid, 1).await.unwrap();
    assert_eq!(resp, SubmitResponse::AlreadyHave);

    let result = pc.result(&vid).await.unwrap().unwrap();
    assert_eq!(result.outcome, "result");
    assert_eq!(result.guarantee.as_deref(), Some("anchored"));
    assert_eq!(result.counts.unwrap(), expected.to_vec());
    assert_eq!(result.counted, Some(9));

    // Below minimum: a second authority vote with one ballot.
    let small = sign_vote_definition(
        &authority,
        VoteDefinition {
            question: "Small?".into(),
            min_ballots: 5,
            ..vote.clone()
        },
    );
    pc.node
        .submit_item(&Item::VoteDefinition(small.clone()))
        .await
        .unwrap();
    let (b, _) = pc.cast(&devices[0], &small.vote_id(), 0).await.unwrap();
    pc.confirm(&small.vote_id(), &b.nullifier, Duration::from_secs(20))
        .await
        .unwrap()
        .unwrap();
    let r = pc.result(&small.vote_id()).await.unwrap().unwrap();
    assert_eq!(r.outcome, "below_minimum");
    assert_eq!(r.counted, Some(1));

    // Initiative: threshold for 12 leaves is 1 %, i.e. one support.
    let (init, resp) = pc
        .create_initiative(
            &devices[5],
            &root,
            "Ban leaf blowers".into(),
            180,
            Secrecy::None,
        )
        .await
        .unwrap();
    assert!(matches!(resp, SubmitResponse::New { .. }));
    let init_id = init.content_id();
    let (s1, _) = pc.support(&devices[6], &init_id).await.unwrap();
    let (s2, _) = pc.support(&devices[7], &init_id).await.unwrap();
    assert_ne!(s1.nullifier, s2.nullifier);
    // Supports get anchored (tip 150 ≤ deadline 180) and the node derives the vote by itself.
    let deadline = std::time::Instant::now() + Duration::from_secs(20);
    let derived_id = loop {
        let inits = pc.initiatives().await.unwrap();
        let mine = inits
            .iter()
            .find(|i| i.initiative_id == hex::encode(init_id))
            .unwrap();
        if let Some(d) = &mine.derived_vote_id {
            assert_eq!(mine.supports, 2);
            break hex::decode(d).unwrap().try_into().unwrap();
        }
        assert!(std::time::Instant::now() < deadline, "vote was not derived");
        tokio::time::sleep(Duration::from_millis(100)).await;
    };
    let derived = pc
        .node
        .vote(&derived_id)
        .await
        .unwrap()
        .expect("derived vote is on the Log");
    assert_eq!(derived.question, "Ban leaf blowers");
    assert_eq!(derived.open_block, 180 + 144);
    assert_eq!(
        derived.origin,
        Origin::Initiative {
            initiative_id: init_id
        }
    );
    assert_eq!(derived.min_ballots, 100);

    // People vote on the derived vote; the chain advances past its open block.
    chain.set_tip(400);
    for d in devices.iter().take(4) {
        let (b, _) = pc.cast(d, &derived_id, 0).await.unwrap();
        assert_eq!(
            pc.confirm(&derived_id, &b.nullifier, Duration::from_secs(20))
                .await
                .unwrap(),
            Some(400)
        );
    }
    let r = pc.result(&derived_id).await.unwrap().unwrap();
    assert_eq!(
        r.outcome, "below_minimum",
        "derived votes use the protocol min_ballots of 100"
    );
    assert_eq!(r.counted, Some(4));
    assert_eq!(r.guarantee.as_deref(), Some("anchored"));

    issuer.shutdown();
    node.shutdown().await;
}
