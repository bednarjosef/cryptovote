//! Phase 10: a `secrecy = keyparties` vote end to end — parties register
//! with timed commitments, ballots are encrypted to the aggregate key, the
//! result is pending until every share exists, one party publishes
//! voluntarily and the other is forced open by the solver.

use cv_client::device::Device;
use cv_client::light::NodeClient;
use cv_client::participant::ParticipantClient;
use cv_core::build::sign_vote_definition;
use cv_core::context::Deployment;
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

const DEV_DELAY: u64 = 64;

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
async fn keyparties_vote_end_to_end() {
    let keys = Arc::new(groth16::setup(&mut ChaCha20Rng::from_seed(
        groth16::DEV_SETUP_SEED,
    )));
    let mut issuer = Issuer::dev([0x11u8; 32]);
    let authority = SigningKey::from_seed(&[0x42u8; 32]);
    let chain = Arc::new(MockChain::new(50, 1.0));
    chain.set_tip(90); // before open_block: key parties register now
    let deployment = Deployment {
        authority_keys: vec![authority.public_key()],
        issuer_key: issuer.public_key(),
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
            name: "kp".into(),
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
    let client = NodeClient::new(node.url());
    let mut pc = ParticipantClient::new(client.clone(), keys.clone());
    pc.dev = true;

    let mut rng = ChaCha20Rng::from_seed([9u8; 32]);
    let mut devices: Vec<Device> = (0..6).map(|_| Device::generate(&mut rng)).collect();
    for (i, d) in devices.iter().enumerate() {
        issuer.enroll(&format!("eid-{i}"), d.commitment()).unwrap();
    }
    client
        .post_registry(&issuer.snapshot(), issuer.leaves())
        .await
        .unwrap();
    let root = issuer.snapshot().root;
    let vote = sign_vote_definition(
        &authority,
        VoteDefinition {
            question: "Secret?".into(),
            options: vec!["Yes".into(), "No".into(), "Maybe".into()],
            registry_root: root,
            open_block: 100,
            close_block: 200,
            min_ballots: 1,
            secrecy: Secrecy::KeyParties,
            origin: Origin::Initiative {
                initiative_id: [0; 32],
            },
        },
    );
    let vid = vote.vote_id();
    client
        .submit_item(&Item::VoteDefinition(vote.clone()))
        .await
        .unwrap();

    // Two key parties register (2048-bit moduli, tiny dev delay) and get anchored before open.
    let t0 = Instant::now();
    let (kp1, r1) = pc
        .register_keyparty(&mut devices[0], &vid, DEV_DELAY)
        .await
        .unwrap();
    let (kp2, r2) = pc
        .register_keyparty(&mut devices[1], &vid, DEV_DELAY)
        .await
        .unwrap();
    eprintln!("two key-party registrations took {:.1?}", t0.elapsed());
    assert!(matches!(r1, SubmitResponse::New { .. }) && matches!(r2, SubmitResponse::New { .. }));
    // A tampered registration is rejected.
    let mut bad = kp2.clone();
    bad.h[255] ^= 1;
    assert!(matches!(
        client.submit_item(&Item::KeyParty(bad)).await.unwrap(),
        SubmitResponse::Rejected { .. }
    ));
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        let kps = client.keyparties(&vid).await.unwrap();
        if kps.len() == 2 && kps.iter().all(|k| k.anchored_height == Some(90)) {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "key parties not anchored: {kps:?}"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    // The vote opens; three people cast encrypted ballots; a fourth double-votes.
    chain.set_tip(150);
    let options = [0u8, 2, 2];
    for (i, option) in options.iter().enumerate() {
        let (b, resp) = pc.cast(&devices[2 + i], &vid, *option).await.unwrap();
        assert!(matches!(resp, SubmitResponse::New { .. }));
        let payload = KeyPartiesPayload::decode(&b.payload).unwrap();
        assert_eq!(payload.party_ids.len(), 2);
        assert!(
            pc.confirm(&vid, &b.nullifier, Duration::from_secs(20))
                .await
                .unwrap()
                .is_some()
        );
        // Same ballot again is byte-identical (deterministic ElGamal randomness).
        let (b2, resp) = pc.cast(&devices[2 + i], &vid, *option).await.unwrap();
        assert_eq!(Item::Ballot(b2).encode(), Item::Ballot(b.clone()).encode());
        assert_eq!(resp, SubmitResponse::AlreadyHave);
    }
    let (dup, _) = pc.cast(&devices[5], &vid, 1).await.unwrap();
    wait_ballot_anchored(&client, &vid, &dup).await;
    let (dup2, _) = pc.cast(&devices[5], &vid, 0).await.unwrap();
    wait_ballot_anchored(&client, &vid, &dup2).await;

    // Before close nothing can be decrypted, whatever shares exist.
    let r = pc.result(&vid).await.unwrap().unwrap();
    assert_eq!(r.outcome, "not_closed");

    // After close: pending until every declared share is present.
    chain.set_tip(250);
    let r = pc.result(&vid).await.unwrap().unwrap();
    assert_eq!(r.outcome, "pending");
    assert_eq!(r.missing_shares.len(), 2);
    // Party 1 publishes voluntarily.
    assert!(matches!(
        pc.publish_share(&devices[0], &vid, &kp1.content_id())
            .await
            .unwrap(),
        SubmitResponse::New { .. }
    ));
    // A wrong share is rejected.
    let wrong = Share {
        vote_id: vid,
        keyparty_id: kp2.content_id(),
        sk: [1u8; 32],
    };
    assert!(matches!(
        client.submit_item(&Item::Share(wrong)).await.unwrap(),
        SubmitResponse::Rejected { .. }
    ));
    let r = pc.result(&vid).await.unwrap().unwrap();
    assert_eq!(r.outcome, "pending");
    assert_eq!(r.missing_shares, vec![hex::encode(kp2.content_id())]);
    // Party 2 vanished: a solver forces its commitment open.
    let missing = cv_node::solver::missing_shares(&node.node);
    assert_eq!(missing.len(), 1);
    let t1 = Instant::now();
    let n = node.node.clone();
    let kp = missing[0].clone();
    let forced = tokio::task::spawn_blocking(move || cv_node::solver::solve_one(&n, &kp))
        .await
        .unwrap();
    assert!(forced.is_some());
    eprintln!("forced opening (T = {DEV_DELAY}) took {:.1?}", t1.elapsed());
    assert!(cv_node::solver::missing_shares(&node.node).is_empty());

    let r = pc.result(&vid).await.unwrap().unwrap();
    assert_eq!(r.outcome, "result", "{r:?}");
    assert_eq!(r.guarantee.as_deref(), Some("anchored"));
    assert_eq!(
        r.counts,
        Some(vec![1, 0, 2]),
        "double voter excluded, others decrypted"
    );
    assert_eq!(r.counted, Some(3));

    // Independent verification from a snapshot agrees.
    let snap = client.snapshot().await.unwrap();
    let report = cv_verifier::verify(
        &snap,
        Arc::new(cv_verifier::MockHeaders { tip: 250 }),
        cv_verifier::Config {
            deployment: Deployment {
                authority_keys: vec![authority.public_key()],
                issuer_key: issuer.public_key(),
                dev_mode: true,
            },
            verifier: Arc::new(keys.verifier.clone()),
        },
        Some(vid),
    )
    .unwrap();
    assert_eq!(report.votes[0].counts, Some(vec![1, 0, 2]));
    assert_eq!(report.items_invalid, 0);
    node.shutdown().await;
}
