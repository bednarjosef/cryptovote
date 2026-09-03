//! End-to-end simulation on one machine (dev mode): N participants, M nodes
//! (all mix hops, one anchorer), one authority vote and one initiative that
//! derives a vote — plus a **second Issuer** whose smaller electorate runs a
//! vote of its own, so the multi-Issuer path is exercised end to end.
//! Ballots travel through the mix; results are recomputed by the independent
//! verifier from a snapshot and compared with the ground truth the
//! simulation knows.
#![forbid(unsafe_code)]

use cv_client::device::Device;
use cv_client::light::NodeClient;
use cv_client::mix::{MixClient, TorSetup};
use cv_client::participant::ParticipantClient;
use cv_core::build::{build_node_registration, sign_vote_definition};
use cv_core::context::Deployment;
use cv_core::crypto::groth16::{self, MembershipKeys};
use cv_core::crypto::mix::MixSecret;
use cv_core::crypto::sig::SigningKey;
use cv_core::items::*;
use cv_issuer::{EnrollmentRequest, Issuer};
use cv_log::Log;
use cv_log::headers::MockChain;
use cv_log::store::MemoryStore;
use cv_node::anchor::{AnchorConfig, AnchorMode};
use cv_node::mix::MixConfig;
use cv_node::{NodeConfig, NodeHandle, start};
use cv_verifier::{Config as VerifierConfig, MockHeaders, verify};
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha20Rng;
use std::sync::Arc;
use std::time::{Duration, Instant};

#[derive(Clone, Debug)]
pub struct SimConfig {
    pub participants: usize,
    pub nodes: usize,
    pub seed: u64,
    /// Send ballots through the mix (otherwise direct submission).
    pub mix: bool,
    pub confirm_window: Duration,
}

impl Default for SimConfig {
    fn default() -> Self {
        SimConfig {
            participants: 20,
            nodes: 5,
            seed: 1,
            mix: true,
            confirm_window: Duration::from_secs(30),
        }
    }
}

#[derive(Clone, Debug)]
pub struct VoteCheck {
    pub vote_id: String,
    /// The Issuer that defined this vote's electorate, as the verifier reports it.
    pub issuer_key: String,
    pub question: String,
    pub expected_counts: Vec<u64>,
    pub verifier_outcome: String,
    pub verifier_counts: Option<Vec<u64>>,
    pub verifier_counted: Option<u64>,
    pub matches: bool,
}

#[derive(Clone, Debug)]
pub struct SimReport {
    pub participants: usize,
    pub nodes: usize,
    pub authority_vote: VoteCheck,
    pub derived_vote: VoteCheck,
    /// A vote of the second Issuer's electorate (same people, other registry).
    pub second_issuer_vote: VoteCheck,
    pub privacy_levels: Vec<String>,
    pub items_in_snapshot: usize,
    pub elapsed: Duration,
    pub ok: bool,
}

async fn wait_for<F, Fut>(what: &str, timeout: Duration, mut f: F) -> anyhow::Result<()>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = bool>,
{
    let deadline = Instant::now() + timeout;
    while !f().await {
        if Instant::now() > deadline {
            anyhow::bail!("timed out waiting for {what}");
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    Ok(())
}

#[allow(clippy::needless_range_loop)]
pub async fn run(cfg: SimConfig) -> anyhow::Result<SimReport> {
    let t0 = Instant::now();
    anyhow::ensure!(
        cfg.participants >= 8 && cfg.nodes >= 1,
        "need at least 8 participants and 1 node"
    );
    let mut rng = ChaCha20Rng::seed_from_u64(cfg.seed);
    let keys: Arc<MembershipKeys> = Arc::new(groth16::setup(&mut ChaCha20Rng::from_seed(
        groth16::DEV_SETUP_SEED,
    )));
    // Two Issuers: a large electorate and a smaller one that some of the same
    // people also belong to (whitepaper §5 "Multiple Issuers").
    let mut issuer = Issuer::dev([0x11u8; 32]);
    let mut issuer_b = Issuer::dev([0x22u8; 32]);
    let authority = SigningKey::from_seed(&[0x42u8; 32]);
    let deployment = Deployment {
        // No issuer allowlist: this node carries any Issuer's registry, and
        // every item says which one it means.
        authority_keys: vec![authority.public_key()],
        issuer_keys: Vec::new(),
        dev_mode: true,
    };
    let chain = Arc::new(MockChain::new(100, 1.0));
    chain.set_tip(150);

    // Nodes: full mesh, node 0 anchors, every node is a mix hop.
    let mix_secrets: Vec<MixSecret> = (0..cfg.nodes)
        .map(|_| MixSecret::generate(&mut rng))
        .collect();
    let node_keys: Vec<SigningKey> = (0..cfg.nodes)
        .map(|_| SigningKey::generate(&mut rng))
        .collect();
    let mut handles: Vec<NodeHandle> = Vec::new();
    for i in 0..cfg.nodes {
        let log = Log::open(
            deployment.clone(),
            keys.clone(),
            Box::new(MemoryStore::new()),
            chain.clone(),
        )?;
        let anchor = if i == 0 {
            AnchorConfig {
                mode: AnchorMode::Dev,
                interval: Duration::from_millis(200),
                ..AnchorConfig::default()
            }
        } else {
            AnchorConfig::default()
        };
        let mix = MixConfig {
            secret: Some(mix_secrets[i].clone()),
            hold_min: Duration::from_millis(100),
            hold_k: 1,
            hold_cap: Duration::from_millis(600),
            tick: Duration::from_millis(50),
        };
        let config = NodeConfig {
            name: format!("sim-node-{i}"),
            gossip_interval: Duration::from_millis(150),
            anchor,
            mix,
            ..NodeConfig::default()
        };
        handles.push(start(config, log).await?);
    }
    for a in &handles {
        for b in &handles {
            if a.addr != b.addr {
                a.node.add_peer(b.url());
            }
        }
    }
    let clients: Vec<NodeClient> = handles.iter().map(|h| NodeClient::new(h.url())).collect();

    // Participants enroll with the (mock-backend) issuers; both registries are
    // published to node 0. The second electorate is a subset of the first: the
    // same person legitimately holds a leaf in both.
    let mut devices: Vec<Device> = (0..cfg.participants)
        .map(|_| Device::generate(&mut rng))
        .collect();
    let second_electorate = cfg.participants.min(8);
    for (i, d) in devices.iter_mut().enumerate() {
        let credential = format!("person-{i}");
        let request = EnrollmentRequest {
            commitment: d.commitment(),
            credential: &credential,
        };
        issuer.enroll(&request)?;
        if i < second_electorate {
            issuer_b.enroll(&request)?;
        }
    }
    let snapshot = issuer.snapshot();
    let leaves = issuer.leaves().to_vec();
    clients[0].post_registry(&snapshot, &leaves).await?;
    let snapshot_b = issuer_b.snapshot();
    let leaves_b = issuer_b.leaves().to_vec();
    clients[0].post_registry(&snapshot_b, &leaves_b).await?;
    let issuer_key = issuer.public_key();
    let issuer_b_key = issuer_b.public_key();
    let root = snapshot.root;
    let pc = |i: usize| ParticipantClient {
        // Dev mode: accept the mock chain's dev anchors as confirmation.
        dev: true,
        ..ParticipantClient::new(clients[i % cfg.nodes].clone(), keys.clone())
    };

    // Node operators (the first M participants) register their nodes as mix hops.
    for i in 0..cfg.nodes {
        let p = devices[i].participant(&issuer_key, &leaves).unwrap();
        let reg = build_node_registration(
            &keys,
            &p,
            node_keys[i].public_key(),
            mix_secrets[i].public(),
            handles[i].addr.to_string(),
            format!("operator-{i}"),
            [b'A' + (i % 26) as u8, b'A' + ((i / 26) % 26) as u8],
            1000 + i as u32,
        )?;
        clients[0].submit_item(&Item::NodeRegistration(reg)).await?;
    }
    for c in &clients {
        let c = c.clone();
        wait_for("registrations to gossip", Duration::from_secs(20), || {
            let c = c.clone();
            async move {
                c.nodes()
                    .await
                    .map(|n| n.len() == cfg.nodes)
                    .unwrap_or(false)
                    && c.registries().await.map(|r| r.len() == 2).unwrap_or(false)
            }
        })
        .await?;
    }

    // Authority vote.
    let vote = sign_vote_definition(
        &authority,
        VoteDefinition {
            question: "Should the bridge be built?".into(),
            options: vec!["Yes".into(), "No".into(), "Abstain".into()],
            issuer_key,
            registry_root: root,
            open_block: 100,
            close_block: 200,
            min_ballots: 1,
            secrecy: Secrecy::None,
            origin: Origin::Initiative {
                initiative_id: [0; 32],
            },
        },
    );
    let vid = vote.vote_id();
    clients[0]
        .submit_item(&Item::VoteDefinition(vote.clone()))
        .await?;
    for c in &clients {
        let c = c.clone();
        wait_for("vote to gossip", Duration::from_secs(20), || {
            let c = c.clone();
            async move { c.vote(&vid).await.ok().flatten().is_some() }
        })
        .await?;
    }

    // Everyone votes; participant 1 double-votes (excluded), participant 2 abstains.
    let mut expected = vec![0u64; 3];
    let mut privacy_levels = Vec::new();
    for i in 0..cfg.participants {
        if i == 2 {
            continue;
        }
        let option = rng.gen_range(0..3u8);
        let node_client = clients[i % cfg.nodes].clone();
        if cfg.mix {
            let mc = MixClient {
                dev: true,
                ..MixClient::new(node_client, TorSetup::Disabled)
            };
            let r = mc
                .cast_with_retry(&mut devices[i], &keys, &vid, option, cfg.confirm_window, 3)
                .await?;
            anyhow::ensure!(
                r.anchored_height.is_some(),
                "participant {i}'s ballot was never anchored"
            );
            privacy_levels.push(r.privacy.to_string());
        } else {
            let p = pc(i);
            let (b, _) = p.cast(&devices[i], &vid, option).await?;
            anyhow::ensure!(
                p.confirm(&vid, &b.nullifier, cfg.confirm_window)
                    .await?
                    .is_some(),
                "participant {i}'s ballot was never anchored"
            );
        }
        if i == 1 {
            let other = (option + 1) % 3;
            let p = pc(i);
            let (b, _) = p.cast(&devices[i], &vid, other).await?;
            p.confirm(&vid, &b.nullifier, cfg.confirm_window).await?;
            // Both of participant 1's ballots are anchored: neither counts.
        } else {
            expected[option as usize] += 1;
        }
    }

    // The second Issuer's electorate runs a vote of its own. The same people
    // vote in both: nullifiers are scoped per vote and `vote_id` covers
    // `issuer_key`, so the two electorates never interfere.
    let vote_b = sign_vote_definition(
        &authority,
        VoteDefinition {
            question: "Should the association buy a boat?".into(),
            options: vec!["Yes".into(), "No".into()],
            issuer_key: issuer_b_key,
            registry_root: snapshot_b.root,
            open_block: 100,
            close_block: 200,
            min_ballots: 1,
            secrecy: Secrecy::None,
            origin: Origin::Initiative {
                initiative_id: [0; 32],
            },
        },
    );
    let vid_b = vote_b.vote_id();
    clients[0]
        .submit_item(&Item::VoteDefinition(vote_b.clone()))
        .await?;
    for c in &clients {
        let c = c.clone();
        wait_for(
            "the second issuer's vote to gossip",
            Duration::from_secs(20),
            || {
                let c = c.clone();
                async move { c.vote(&vid_b).await.ok().flatten().is_some() }
            },
        )
        .await?;
    }
    let mut expected_b = vec![0u64; 2];
    for i in 0..second_electorate {
        let option = rng.gen_range(0..2u8);
        let p = pc(i);
        let (b, _) = p.cast(&devices[i], &vid_b, option).await?;
        anyhow::ensure!(
            p.confirm(&vid_b, &b.nullifier, cfg.confirm_window)
                .await?
                .is_some(),
            "participant {i}'s ballot in the second issuer's vote was never anchored"
        );
        expected_b[option as usize] += 1;
    }

    // Initiative by participant 3, supported by 4..=6 → derived vote.
    let (init, _) = pc(3)
        .create_initiative(
            &devices[3],
            &issuer_key,
            &root,
            "Ban leaf blowers".into(),
            180,
            Secrecy::None,
        )
        .await?;
    let init_id = init.content_id();
    for i in 4..=6 {
        pc(i).support(&devices[i], &init_id).await?;
    }
    let mut derived_id: Option<Id> = None;
    wait_for(
        "initiative to derive a vote",
        Duration::from_secs(30),
        || {
            let p = pc(0);
            let iid = hex::encode(init_id);
            async move {
                match p.initiatives().await {
                    Ok(list) => list
                        .iter()
                        .any(|i| i.initiative_id == iid && i.derived_vote_id.is_some()),
                    Err(_) => false,
                }
            }
        },
    )
    .await?;
    for i in pc(0).initiatives().await? {
        if i.initiative_id == hex::encode(init_id) {
            derived_id = i
                .derived_vote_id
                .map(|d| hex::decode(d).unwrap().try_into().unwrap());
        }
    }
    let derived_id = derived_id.ok_or_else(|| anyhow::anyhow!("no derived vote"))?;
    let derived = clients[0]
        .vote(&derived_id)
        .await?
        .ok_or_else(|| anyhow::anyhow!("derived vote missing"))?;
    chain.set_tip(derived.open_block + 10);
    for c in &clients {
        let c = c.clone();
        wait_for("derived vote to gossip", Duration::from_secs(20), || {
            let c = c.clone();
            async move { c.vote(&derived_id).await.ok().flatten().is_some() }
        })
        .await?;
    }
    let mut expected_derived = vec![0u64; 2];
    let voters_on_derived = cfg.participants.min(10);
    for i in 0..voters_on_derived {
        let option = rng.gen_range(0..2u8);
        let p = pc(i);
        let (b, _) = p.cast(&devices[i], &derived_id, option).await?;
        anyhow::ensure!(
            p.confirm(&derived_id, &b.nullifier, cfg.confirm_window)
                .await?
                .is_some(),
            "derived-vote ballot never anchored"
        );
        expected_derived[option as usize] += 1;
    }

    // Independent verification from the last node's snapshot.
    let snap = clients[cfg.nodes - 1].snapshot().await?;
    let report = verify(
        &snap,
        Arc::new(MockHeaders {
            tip: derived.open_block + 10,
        }),
        VerifierConfig {
            deployment: deployment.clone(),
            verifier: Arc::new(keys.verifier.clone()),
        },
        None,
    )
    .map_err(|e| anyhow::anyhow!(e))?;
    let check = |id: &Id, expected: &[u64], question: &str| -> VoteCheck {
        let r = report.votes.iter().find(|v| v.vote_id == hex::encode(id));
        let issuer_key = r.map(|v| v.issuer_key.clone()).unwrap_or_default();
        let (outcome, counts, counted) = match r {
            Some(v) => (v.outcome.clone(), v.counts.clone(), v.counted),
            None => ("missing".to_string(), None, None),
        };
        let total: u64 = expected.iter().sum();
        let matches = match outcome.as_str() {
            "result" => counts.as_deref() == Some(expected),
            "below_minimum" => counted == Some(total),
            _ => false,
        };
        VoteCheck {
            vote_id: hex::encode(id),
            issuer_key,
            question: question.into(),
            expected_counts: expected.to_vec(),
            verifier_outcome: outcome,
            verifier_counts: counts,
            verifier_counted: counted,
            matches,
        }
    };
    let authority_vote = check(&vid, &expected, &vote.question);
    let derived_vote = check(&derived_id, &expected_derived, &derived.question);
    let second_issuer_vote = check(&vid_b, &expected_b, &vote_b.question);
    let ok = authority_vote.matches
        && derived_vote.matches
        && second_issuer_vote.matches
        && second_issuer_vote.issuer_key == hex::encode(issuer_b_key)
        && authority_vote.issuer_key == hex::encode(issuer_key)
        && report.items_invalid == 0;
    for h in handles {
        h.shutdown().await;
    }
    Ok(SimReport {
        participants: cfg.participants,
        nodes: cfg.nodes,
        authority_vote,
        derived_vote,
        second_issuer_vote,
        privacy_levels,
        items_in_snapshot: report.items_accepted,
        elapsed: t0.elapsed(),
        ok,
    })
}

pub fn render(r: &SimReport) -> String {
    let mut s = String::new();
    s.push_str(&format!(
        "simulation: {} participants, {} nodes, {:.1?}\n",
        r.participants, r.nodes, r.elapsed
    ));
    for v in [&r.authority_vote, &r.derived_vote, &r.second_issuer_vote] {
        s.push_str(&format!(
            "  vote {} (issuer {}) \"{}\": expected {:?}; verifier {} counts {:?} counted {:?} → {}\n",
            &v.vote_id[..8],
            v.issuer_key.get(..8).unwrap_or("?"),
            v.question,
            v.expected_counts,
            v.verifier_outcome,
            v.verifier_counts,
            v.verifier_counted,
            if v.matches { "MATCH" } else { "MISMATCH" }
        ));
    }
    if !r.privacy_levels.is_empty() {
        let mut levels = r.privacy_levels.clone();
        levels.sort();
        levels.dedup();
        s.push_str(&format!("  privacy levels achieved: {levels:?}\n"));
    }
    s.push_str(&format!(
        "  items in snapshot: {}\n  overall: {}\n",
        r.items_in_snapshot,
        if r.ok { "OK" } else { "FAILED" }
    ));
    s
}
