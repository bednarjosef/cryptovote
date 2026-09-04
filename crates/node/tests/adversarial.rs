//! What a hostile node, a hostile Issuer or a hostile submitter can and
//! cannot do. The premise throughout: the voter reaches **one** honest node,
//! everything else in the network is against them.
//!
//! Correctness never depends on a node behaving: every item is self-validating
//! (whitepaper §6), the deadline comes from Bitcoin (§9), and the result is
//! recomputed by an independent verifier from a snapshot (§15). These tests
//! run a real three-node cluster over HTTP and try to break exactly that.

use axum::extract::{Path, State};
use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use cv_client::device::Device;
use cv_client::light::{ClientError, NodeClient};
use cv_client::participant::{ParticipantClient, ParticipantError};
use cv_core::build::*;
use cv_core::context::Deployment;
use cv_core::crypto::field::{Fr, fr_mod};
use cv_core::crypto::groth16::{self, dev_keys};
use cv_core::crypto::merkle::{InclusionProof, verify_inclusion};
use cv_core::crypto::sig::SigningKey;
use cv_core::identity::commitment;
use cv_core::items::*;
use cv_core::registry::{RegistrySnapshot, RegistryTree};
use cv_core::wire::SubmitResponse;
use cv_log::Log;
use cv_log::headers::MockChain;
use cv_log::store::MemoryStore;
use cv_node::anchor::{AnchorConfig, AnchorMode};
use cv_node::{NodeConfig, NodeHandle, start};
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use std::sync::Arc;
use std::time::{Duration, Instant};

const VOTERS: usize = 16;

struct World {
    secrets: Vec<Fr>,
    tree: RegistryTree,
    issuer: SigningKey,
    snapshot: RegistrySnapshot,
    authority: SigningKey,
    vote: VoteDefinition,
    deployment: Deployment,
    chain: Arc<MockChain>,
}

fn world() -> World {
    let secrets: Vec<Fr> = (1..=VOTERS as u64)
        .map(|i| fr_mod(&[i as u8; 32]))
        .collect();
    let tree = RegistryTree::from_leaves(secrets.iter().map(commitment).collect());
    let issuer = SigningKey::from_seed(&[0x11u8; 32]);
    let authority = SigningKey::from_seed(&[0x42u8; 32]);
    let snapshot = RegistrySnapshot::sign(&issuer, 1, &tree, vec![authority.public_key()]);
    // No Issuer allowlist: the nodes carry any registry anyone publishes,
    // which is the harder case to defend.
    let deployment = Deployment {
        issuer_keys: Vec::new(),
        dev_mode: true,
    };
    let vote = sign_vote_definition(
        &authority,
        VoteDefinition {
            question: "Should the bridge be built?".into(),
            options: vec!["Yes".into(), "No".into()],
            issuer_key: issuer.public_key(),
            registry_root: tree.root(),
            open_block: 100,
            close_block: 200,
            min_ballots: 1,
            secrecy: Secrecy::None,
            min_parties: 0,
            origin: Origin::Initiative {
                initiative_id: [0; 32],
            },
        },
    );
    let chain = Arc::new(MockChain::new(100, 1.0));
    chain.set_tip(150);
    World {
        secrets,
        tree,
        issuer,
        snapshot,
        authority,
        vote,
        deployment,
        chain,
    }
}

fn participant(w: &World, i: usize) -> Participant {
    Participant {
        secret: w.secrets[i],
        issuer_key: w.issuer.public_key(),
        registry_root: w.tree.root(),
        index: i as u32,
        siblings: w.tree.path(i as u32).unwrap(),
    }
}

fn keys() -> Arc<groth16::MembershipKeys> {
    Arc::new(groth16::setup(&mut ChaCha20Rng::from_seed(
        groth16::DEV_SETUP_SEED,
    )))
}

/// Node 0 is the one honest node: it anchors. The others only relay.
async fn cluster(w: &World, n: usize) -> Vec<NodeHandle> {
    let keys = keys();
    let mut handles = Vec::new();
    for i in 0..n {
        let log = Log::open(
            w.deployment.clone(),
            keys.clone(),
            Box::new(MemoryStore::new()),
            w.chain.clone(),
        )
        .unwrap();
        let anchor = if i == 0 {
            AnchorConfig {
                mode: AnchorMode::Dev,
                interval: Duration::from_millis(200),
                ..AnchorConfig::default()
            }
        } else {
            AnchorConfig::default()
        };
        handles.push(
            start(
                NodeConfig {
                    name: format!("n{i}"),
                    gossip_interval: Duration::from_millis(150),
                    anchor,
                    ..NodeConfig::default()
                },
                log,
            )
            .await
            .unwrap(),
        );
    }
    for a in &handles {
        for b in &handles {
            if a.addr != b.addr {
                a.node.add_peer(b.url());
            }
        }
    }
    handles
}

async fn wait_for(what: &str, mut f: impl AsyncFnMut() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(30);
    while !f().await {
        assert!(Instant::now() < deadline, "timed out waiting for {what}");
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

async fn wait_anchored(c: &NodeClient, vote_id: &Id, n: &Fr) -> u32 {
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        let st = c.ballot_status(vote_id, n).await.unwrap();
        if let Some(h) = st.iter().filter_map(|s| s.anchored_height).min() {
            return h;
        }
        assert!(Instant::now() < deadline, "ballot was never anchored");
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

fn blake3_leaf(x: &[u8]) -> Id {
    cv_core::crypto::hash::blake3_hash(x)
}

fn rejected(r: &SubmitResponse) -> bool {
    matches!(r, SubmitResponse::Rejected { .. })
}

fn counts_of(node: &NodeHandle, vote_id: &Id) -> Option<Vec<u64>> {
    let log = node.node.log.lock().unwrap();
    match cv_core::tally::tally(&*log, vote_id)? {
        cv_core::tally::Outcome::Result { counts, .. } => Some(counts),
        _ => None,
    }
}

/// Every forgery a hostile submitter or relay can attempt, against a cluster
/// where only one node is assumed honest.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn forged_items_are_refused_by_every_node() {
    let w = world();
    let nodes = cluster(&w, 3).await;
    let clients: Vec<NodeClient> = nodes.iter().map(|h| NodeClient::new(h.url())).collect();
    let honest = &clients[0];
    let hostile = &clients[2];

    // Public data can enter anywhere; it is signed, so the path does not matter.
    hostile
        .post_registry(&w.snapshot, w.tree.leaves())
        .await
        .unwrap();
    hostile
        .submit_item(&Item::VoteDefinition(w.vote.clone()))
        .await
        .unwrap();
    let vid = w.vote.vote_id();
    for c in &clients {
        let c = c.clone();
        wait_for("the vote to reach every node", async || {
            c.vote(&vid).await.ok().flatten().is_some()
        })
        .await;
    }

    // Five honest voters, submitting through whichever node they happen to hit.
    let mut expected = vec![0u64; 2];
    let mut ballots = Vec::new();
    for i in 1..=5usize {
        let option = (i % 2) as u8;
        let b = plaintext_ballot(dev_keys(), &participant(&w, i), &w.vote, option).unwrap();
        clients[i % clients.len()]
            .submit_item(&Item::Ballot(b.clone()))
            .await
            .unwrap();
        expected[option as usize] += 1;
        ballots.push(b);
    }
    for b in &ballots {
        wait_anchored(honest, &vid, &b.nullifier).await;
    }

    // 1. Flip a voter's option, keep their proof: the proof commits to the
    //    content id, so the ballot no longer proves anything (A3).
    let tampered = Ballot {
        payload: vec![1 - ballots[0].payload[0]],
        ..ballots[0].clone()
    };
    assert!(rejected(
        &hostile.submit_item(&Item::Ballot(tampered)).await.unwrap()
    ));

    // 2. Re-randomize the proof of a ballot already on the Log. Groth16 proofs
    //    are malleable, so this *is* a different item — but the content id
    //    excludes the proof, so it is a retransmission, not a second action,
    //    and the voter's ballot is not knocked out (A3).
    let mut rng = ChaCha20Rng::from_seed([13u8; 32]);
    let rr = groth16::rerandomize(&dev_keys().verifier.vk, &ballots[0].proof.0, &mut rng).unwrap();
    let malleable = Ballot {
        proof: Proof(rr),
        ..ballots[0].clone()
    };
    assert!(matches!(
        hostile.submit_item(&Item::Ballot(malleable)).await.unwrap(),
        SubmitResponse::Equivalent { .. }
    ));

    // 3. A proof made up out of thin air, for a ballot no node has seen:
    //    rejected outright, so voter 6's option never enters the count.
    let unseen = plaintext_ballot(dev_keys(), &participant(&w, 6), &w.vote, 0).unwrap();
    let forged = Ballot {
        proof: Proof([7u8; 128]),
        ..unseen.clone()
    };
    assert!(rejected(
        &hostile.submit_item(&Item::Ballot(forged)).await.unwrap()
    ));
    assert!(
        honest
            .ballot_status(&vid, &unseen.nullifier)
            .await
            .unwrap()
            .is_empty()
    );

    // 3b. The same junk aimed at a ballot the Log already holds is not even
    //     considered: the content id is what identifies an item, so the honest
    //     bytes stay put and the junk is dropped (A3).
    let junk = Ballot {
        proof: Proof([7u8; 128]),
        ..ballots[1].clone()
    };
    assert!(matches!(
        hostile.submit_item(&Item::Ballot(junk)).await.unwrap(),
        SubmitResponse::Equivalent { .. }
    ));
    let Some(Item::Ballot(stored)) = honest.item(&ballots[1].content_id()).await.unwrap() else {
        panic!("the honest ballot is still there");
    };
    assert_eq!(stored, ballots[1], "with its own proof, untouched");

    // 4. Replay a ballot into another vote of the same registry: the proof is
    //    bound to the vote id, so it does not carry over.
    let other = sign_vote_definition(
        &w.authority,
        VoteDefinition {
            question: "Something else?".into(),
            ..w.vote.clone()
        },
    );
    hostile
        .submit_item(&Item::VoteDefinition(other.clone()))
        .await
        .unwrap();
    let replay = Ballot {
        vote_id: other.vote_id(),
        ..ballots[2].clone()
    };
    assert!(rejected(
        &hostile.submit_item(&Item::Ballot(replay)).await.unwrap()
    ));

    // 5. A vote definition signed by a key that is not an authority.
    let impostor = sign_vote_definition(
        &SigningKey::from_seed(&[0xEEu8; 32]),
        VoteDefinition {
            question: "Free money?".into(),
            ..w.vote.clone()
        },
    );
    assert!(rejected(
        &hostile
            .submit_item(&Item::VoteDefinition(impostor))
            .await
            .unwrap()
    ));

    // 6. A vote over a registry root the named Issuer never signed: unresolved
    //    forever, never counted.
    let unsigned_root = sign_vote_definition(
        &w.authority,
        VoteDefinition {
            registry_root: Fr::from(999u64),
            ..w.vote.clone()
        },
    );
    assert!(matches!(
        hostile
            .submit_item(&Item::VoteDefinition(unsigned_root))
            .await
            .unwrap(),
        SubmitResponse::Orphaned { .. }
    ));

    // 7. The item type that used to let nodes vouch for timing (0x08) does
    //    not exist any more: there is nothing for a node to sign (A16).
    let mut retired = Item::Ballot(ballots[0].clone()).encode();
    retired[1] = 0x08;
    assert!(rejected(&hostile.submit(retired).await.unwrap()));

    // 8. An anchor at a height with no header, and an anchor over an id that is
    //    not on the Log. Anchors only hand out heights: they can neither admit
    //    a ballot that does not exist nor invalidate one that does.
    let future = Anchor {
        leaves: vec![ballots[0].content_id()],
        proof: AnchorProof::Dev { height: 900_000 },
    };
    assert!(matches!(
        hostile.submit_item(&Item::Anchor(future)).await.unwrap(),
        SubmitResponse::Orphaned { .. }
    ));
    let ghost = Anchor {
        leaves: vec![[0x99u8; 32]],
        proof: AnchorProof::Dev { height: 150 },
    };
    hostile.submit_item(&Item::Anchor(ghost)).await.unwrap();

    // 9. Voter 1 votes a second time with a different option. Both of *their*
    //    ballots drop out (§7.1) — and nobody else's does.
    let double = plaintext_ballot(dev_keys(), &participant(&w, 1), &w.vote, 0).unwrap();
    assert_eq!(double.nullifier, ballots[0].nullifier);
    hostile
        .submit_item(&Item::Ballot(double.clone()))
        .await
        .unwrap();
    wait_anchored(honest, &vid, &double.nullifier).await;
    expected[ballots[0].payload[0] as usize] -= 1;

    // Every node agrees, and agrees with the truth: nothing above moved a count.
    for h in &nodes {
        let h_url = h.url();
        let expected = expected.clone();
        wait_for(&format!("{h_url} to converge"), async || {
            counts_of(h, &vid) == Some(expected.clone())
        })
        .await;
    }

    // And the independent verifier, run over the honest node's snapshot,
    // recomputes the same numbers from scratch.
    let report = verify_snapshot(honest, &w).await;
    let counted = report
        .votes
        .iter()
        .find(|v| v.vote_id == hex::encode(vid))
        .expect("the vote is in the report");
    assert_eq!(counted.counts.as_ref(), Some(&expected));
    assert_eq!(counted.issuer_key, hex::encode(w.issuer.public_key()));

    for h in nodes {
        h.shutdown().await;
    }
}

async fn verify_snapshot(client: &NodeClient, w: &World) -> cv_verifier::Report {
    let snap = client.snapshot().await.unwrap();
    cv_verifier::verify(
        &snap,
        Arc::new(cv_verifier::MockHeaders { tip: 250 }),
        cv_verifier::Config {
            deployment: w.deployment.clone(),
            verifier: Arc::new(keys().verifier.clone()),
        },
        None,
    )
    .unwrap()
}

/// An Issuer is trusted by whoever recognises it — "rogue" only means "one
/// you have never heard of", and anyone may publish a registry. What has to
/// hold is **isolation**: an Issuer you do not recognise gets its own
/// electorate and nothing more. It cannot add a voter to, remove a voter
/// from, or otherwise touch an electorate you do recognise, and every result
/// says which Issuer it is over, so the two are never confusable.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_unrecognised_issuer_is_isolated_from_another_electorate() {
    let w = world();
    let nodes = cluster(&w, 2).await;
    let clients: Vec<NodeClient> = nodes.iter().map(|h| NodeClient::new(h.url())).collect();
    let honest = &clients[0];

    honest
        .post_registry(&w.snapshot, w.tree.leaves())
        .await
        .unwrap();
    honest
        .submit_item(&Item::VoteDefinition(w.vote.clone()))
        .await
        .unwrap();
    let vid = w.vote.vote_id();

    // One honest voter in the real vote.
    let real = plaintext_ballot(dev_keys(), &participant(&w, 1), &w.vote, 0).unwrap();
    honest
        .submit_item(&Item::Ballot(real.clone()))
        .await
        .unwrap();
    wait_anchored(honest, &vid, &real.nullifier).await;

    // The attacker stands up their own Issuer: a two-leaf registry holding
    // themselves and (without asking) an honest voter's commitment.
    let rogue_issuer = SigningKey::from_seed(&[0x66u8; 32]);
    let attacker = fr_mod(&[0xC0u8; 32]);
    let rogue_tree =
        RegistryTree::from_leaves(vec![commitment(&attacker), commitment(&w.secrets[1])]);
    // The rogue Issuer names the same authority, so its electorate really can
    // hold a vote — the point of the test is that it is a *different* one.
    let rogue_snapshot = RegistrySnapshot::sign(
        &rogue_issuer,
        1,
        &rogue_tree,
        vec![w.authority.public_key()],
    );
    honest
        .post_registry(&rogue_snapshot, rogue_tree.leaves())
        .await
        .unwrap();

    // Their own vote over their own registry is fine — and separate.
    let rogue_vote = sign_vote_definition(
        &w.authority,
        VoteDefinition {
            issuer_key: rogue_issuer.public_key(),
            registry_root: rogue_tree.root(),
            ..w.vote.clone()
        },
    );
    assert!(matches!(
        honest
            .submit_item(&Item::VoteDefinition(rogue_vote.clone()))
            .await
            .unwrap(),
        SubmitResponse::New { .. }
    ));
    assert_ne!(
        rogue_vote.vote_id(),
        vid,
        "same question, other Issuer, other vote"
    );

    let rogue_participant = |secret: Fr, index: u32| Participant {
        secret,
        issuer_key: rogue_issuer.public_key(),
        registry_root: rogue_tree.root(),
        index,
        siblings: rogue_tree.path(index).unwrap(),
    };

    // A. A ballot proven against the rogue registry, aimed at the real vote.
    let p = rogue_participant(attacker, 0);
    let cross = build_ballot(dev_keys(), &p, &w.vote, vec![0]).unwrap();
    assert!(rejected(
        &honest.submit_item(&Item::Ballot(cross)).await.unwrap()
    ));

    // B. The real Issuer's root, claimed under the rogue Issuer's key, and the
    //    rogue root claimed under the real Issuer's key. Both name a registry
    //    that does not exist; neither ever becomes a vote.
    for (issuer_key, registry_root) in [
        (rogue_issuer.public_key(), w.tree.root()),
        (w.issuer.public_key(), rogue_tree.root()),
    ] {
        let stolen = sign_vote_definition(
            &w.authority,
            VoteDefinition {
                issuer_key,
                registry_root,
                ..w.vote.clone()
            },
        );
        assert!(matches!(
            honest
                .submit_item(&Item::VoteDefinition(stolen))
                .await
                .unwrap(),
            SubmitResponse::Orphaned { .. }
        ));
    }

    // C. The honest voter is in both registries — legitimately, since anyone
    //    may enrol with more than one Issuer. Their two ballots are unlinkable
    //    and neither displaces the other.
    let in_rogue = build_ballot(
        dev_keys(),
        &rogue_participant(w.secrets[1], 1),
        &rogue_vote,
        vec![1],
    )
    .unwrap();
    assert_ne!(in_rogue.nullifier, real.nullifier);
    honest
        .submit_item(&Item::Ballot(in_rogue.clone()))
        .await
        .unwrap();
    wait_anchored(honest, &rogue_vote.vote_id(), &in_rogue.nullifier).await;

    // The real vote is untouched, and the report says whose electorate each
    // result is over, so a reader can dismiss the rogue one on sight.
    let report = verify_snapshot(honest, &w).await;
    let real_result = report
        .votes
        .iter()
        .find(|v| v.vote_id == hex::encode(vid))
        .unwrap();
    assert_eq!(real_result.counts, Some(vec![1, 0]));
    assert_eq!(real_result.issuer_key, hex::encode(w.issuer.public_key()));
    let rogue_result = report
        .votes
        .iter()
        .find(|v| v.vote_id == hex::encode(rogue_vote.vote_id()))
        .unwrap();
    assert_eq!(
        rogue_result.issuer_key,
        hex::encode(rogue_issuer.public_key())
    );
    assert_eq!(report.items_invalid, 0);

    for h in nodes {
        h.shutdown().await;
    }
}

// ---------------------------------------------------------------------------
// A node that lies to the voter.

#[derive(Clone)]
struct Liar {
    /// Served for *every* item query, whatever was asked for.
    item: Vec<u8>,
    snapshot: RegistrySnapshot,
    leaves: Vec<Fr>,
    /// A fabricated "your ballot is anchored" story: a claimed status, an
    /// anchor that does not contain the ballot, and an inclusion proof for it.
    fake_anchor: Option<(Anchor, InclusionProof)>,
}

fn octets(bytes: Vec<u8>) -> Response {
    ([(header::CONTENT_TYPE, "application/octet-stream")], bytes).into_response()
}

/// A hostile node: answers every query with material of its own and silently
/// drops whatever it is given, while claiming to have accepted it.
async fn spawn_liar(liar: Liar) -> (String, tokio::task::JoinHandle<()>) {
    let app = Router::new()
        .route(
            "/v1/items/{id}",
            get(|State(l): State<Liar>| async move { octets(l.item.clone()) }),
        )
        .route(
            "/v1/items",
            post(|| async {
                Json(SubmitResponse::New {
                    content_id: hex::encode([0u8; 32]),
                    item_type: "Ballot".into(),
                    seq: 1,
                })
            }),
        )
        .route(
            "/v1/registry/{issuer}/{root}/snapshot",
            get(|State(l): State<Liar>| async move { octets(l.snapshot.encode()) }),
        )
        .route(
            "/v1/registry/{issuer}/{root}/leaves",
            get(|State(l): State<Liar>| async move {
                octets(cv_core::registry::encode_leaves(&l.leaves))
            }),
        )
        // The path a client actually asks for (A58), served out of the liar's
        // own tree rather than the one the Issuer signed.
        .route(
            "/v1/registry/{issuer}/{root}/path/{commitment}",
            get(
                |State(l): State<Liar>, Path((_, _, c)): Path<(String, String, String)>| async move {
                    let Some(c) = hex::decode(&c)
                        .ok()
                        .and_then(|v| v.try_into().ok())
                        .and_then(|b: [u8; 32]| cv_core::crypto::field::fr_from_canonical(&b))
                    else {
                        return StatusCode::NOT_FOUND.into_response();
                    };
                    let tree = cv_core::registry::RegistryTree::from_leaves(l.leaves.clone());
                    let Some(index) = l.leaves.iter().position(|x| *x == c) else {
                        return StatusCode::NOT_FOUND.into_response();
                    };
                    let Some(siblings) = tree.path(index as u32) else {
                        return StatusCode::NOT_FOUND.into_response();
                    };
                    let mut w = cv_core::encoding::Writer::new();
                    w.u32(index as u32);
                    for sib in &siblings {
                        w.fr(sib);
                    }
                    octets(w.into_inner())
                },
            ),
        )
        .route(
            "/v1/votes/{id}/nullifier/{n}",
            get(|State(l): State<Liar>| async move {
                Json(match &l.fake_anchor {
                    // "It is in, at height 150. Stop resending."
                    Some((a, _)) => vec![cv_core::wire::BallotStatusJson {
                        content_id: hex::encode(a.leaves[0]),
                        anchored_height: Some(a.proof.height()),
                    }],
                    None => Vec::new(),
                })
            }),
        )
        .route(
            "/v1/anchors",
            get(|State(l): State<Liar>| async move {
                Json(match &l.fake_anchor {
                    Some((a, _)) => vec![cv_core::wire::AnchorSummary {
                        content_id: hex::encode(a.content_id()),
                        height: a.proof.height(),
                        leaf_count: a.leaves.len(),
                        kind: "dev".into(),
                    }],
                    None => Vec::new(),
                })
            }),
        )
        .route(
            "/v1/anchors/{id}/proof/{cid}",
            get(|State(l): State<Liar>| async move {
                match &l.fake_anchor {
                    Some((_, p)) => Json(Some(cv_core::wire::InclusionProofJson {
                        root: hex::encode(p.root),
                        leaf_count: p.leaf_count,
                        index: p.index,
                        siblings: p.siblings.iter().map(hex::encode).collect(),
                    })),
                    None => Json(None),
                }
            }),
        )
        .with_state(liar);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let task = tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    (url, task)
}

fn device(w: &World, i: usize) -> Device {
    Device {
        secret: w.secrets[i],
        enrollments: Vec::new(),
        guard: None,
        guard_since_unix: None,
        keyparty_secrets: Default::default(),
    }
}

/// One node lying to one voter. It can waste their time; it cannot make them
/// cast a ballot they did not mean, prove membership of a tree it invented, or
/// keep their ballot out of the count once they reach a single honest node
/// (whitepaper §12).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_lying_node_cannot_redirect_or_bury_a_ballot() {
    let w = world();
    let nodes = cluster(&w, 1).await;
    let honest = NodeClient::new(nodes[0].url());
    honest
        .post_registry(&w.snapshot, w.tree.leaves())
        .await
        .unwrap();
    honest
        .submit_item(&Item::VoteDefinition(w.vote.clone()))
        .await
        .unwrap();
    let vid = w.vote.vote_id();

    // The lie: the same question with the options swapped, signed by the real
    // authority, plus a registry whose leaves the liar chose. A voter who
    // believed it would cast "Yes" as a "No" in a vote nobody counts.
    let decoy = sign_vote_definition(
        &w.authority,
        VoteDefinition {
            options: vec!["No".into(), "Yes".into()],
            ..w.vote.clone()
        },
    );
    let mut forged_leaves = w.tree.leaves().to_vec();
    forged_leaves[3] = commitment(&fr_mod(&[0xC0u8; 32]));
    let (liar_url, liar_task) = spawn_liar(Liar {
        item: Item::VoteDefinition(decoy.clone()).encode(),
        // A genuine, correctly signed snapshot — with leaves that are not its.
        snapshot: w.snapshot.clone(),
        leaves: forged_leaves,
        fake_anchor: None,
    })
    .await;
    let liar = NodeClient::new(liar_url.clone());
    let pc_liar = ParticipantClient::new(liar.clone(), keys());

    // 1. Asked for the real vote, the liar answers with the decoy: caught,
    //    because the answer does not hash to the id that was asked for.
    assert!(matches!(
        liar.vote(&vid).await,
        Err(ClientError::WrongItem(_))
    ));
    assert!(pc_liar.cast(&device(&w, 1), &vid, 0).await.is_err());

    // 2. The liar serves a path out of its own tree. It rebuilds *its* root,
    //    not the one the Issuer signed, so the device refuses to prove
    //    membership against it (A58).
    assert!(matches!(
        pc_liar
            .participant(&device(&w, 1), &w.issuer.public_key(), &w.tree.root())
            .await,
        Err(ParticipantError::ForgedLeaves)
    ));

    // 3. A snapshot signed by some other key is not this Issuer's registry.
    let rogue = SigningKey::from_seed(&[0x66u8; 32]);
    let (url2, task2) = spawn_liar(Liar {
        item: Item::VoteDefinition(decoy).encode(),
        snapshot: RegistrySnapshot::sign(&rogue, 1, &w.tree, vec![w.authority.public_key()]),
        leaves: w.tree.leaves().to_vec(),
        fake_anchor: None,
    })
    .await;
    assert!(matches!(
        NodeClient::new(url2)
            .registry(&w.issuer.public_key(), &w.tree.root())
            .await,
        Err(ClientError::BadRegistry(_))
    ));

    // 4. Censorship. The voter builds the right ballot (from the honest node's
    //    copy of the vote) and hands it to the liar, which says "accepted" and
    //    drops it. The voter watches for their own nullifier, sees nothing, and
    //    goes elsewhere — the one defence the whitepaper asks of a client.
    let ballot = plaintext_ballot(dev_keys(), &participant(&w, 1), &w.vote, 0).unwrap();
    let claim = liar
        .submit_item(&Item::Ballot(ballot.clone()))
        .await
        .unwrap();
    assert!(
        matches!(claim, SubmitResponse::New { .. }),
        "the liar claims to have taken it: {claim:?}"
    );
    assert_eq!(
        pc_liar
            .confirm(&vid, &ballot.nullifier, Duration::from_secs(1))
            .await
            .unwrap(),
        None,
        "and the voter can tell that it did not"
    );
    honest
        .submit_item(&Item::Ballot(ballot.clone()))
        .await
        .unwrap();
    let height = wait_anchored(&honest, &vid, &ballot.nullifier).await;

    // 4b. The nastier version of the same attack: rather than stay silent, a
    //     node that dropped the ballot *claims* it is anchored, and backs the
    //     claim with an anchor of its own and a well-formed inclusion proof
    //     for a leaf that is not the voter's ballot. Believing it would end
    //     the retries, which is exactly what the attacker wants.
    let decoy_leaf = blake3_leaf(b"not your ballot");
    let mut fake_leaves = vec![decoy_leaf, blake3_leaf(b"filler")];
    fake_leaves.sort();
    let fake = Anchor {
        leaves: fake_leaves.clone(),
        proof: AnchorProof::Dev { height: 150 },
    };
    let fake_proof = cv_core::crypto::merkle::prove_inclusion(
        &fake_leaves,
        fake_leaves.iter().position(|l| *l == decoy_leaf).unwrap(),
    )
    .unwrap();
    let (liar2_url, liar2_task) = spawn_liar(Liar {
        item: Item::Anchor(fake.clone()).encode(),
        snapshot: w.snapshot.clone(),
        leaves: w.tree.leaves().to_vec(),
        fake_anchor: Some((fake, fake_proof)),
    })
    .await;
    let liar2 = NodeClient::new(liar2_url);
    // The node says so, loudly …
    let claimed = liar2.ballot_status(&vid, &ballot.nullifier).await.unwrap();
    assert_eq!(claimed.first().and_then(|s| s.anchored_height), Some(150));
    // … and it is worth nothing: the anchor it offers does not contain this
    // ballot, so the client keeps resending.
    let pc_liar2 = ParticipantClient {
        dev: true,
        ..ParticipantClient::new(liar2.clone(), keys())
    };
    assert_eq!(
        pc_liar2
            .confirm_evidence(&ballot, Duration::from_millis(500))
            .await
            .unwrap()
            .map(|e| e.height),
        None,
        "a fabricated anchor is not a confirmation"
    );

    // 4c. Even a real anchor is not a confirmation outside dev mode: a Dev
    //     proof carries no Bitcoin at all.
    let pc_release = ParticipantClient::new(honest.clone(), keys());
    assert!(
        pc_release
            .confirm_evidence(&ballot, Duration::from_millis(500))
            .await
            .unwrap()
            .is_none(),
        "dev anchors are not evidence unless dev mode is asked for"
    );

    // 4d. From the honest node the evidence checks out, and the voter can
    //     recheck it later without asking anyone.
    let pc_dev = ParticipantClient {
        dev: true,
        ..ParticipantClient::new(honest.clone(), keys())
    };
    let evidence = pc_dev
        .confirm_evidence(&ballot, Duration::from_secs(20))
        .await
        .unwrap()
        .expect("the honest node's anchor really contains the ballot");
    assert_eq!(evidence.height, 150);
    assert!(evidence.recheck());

    // 5. What makes the censorship provable rather than deniable: the voter
    //    holds an inclusion proof of their ballot in an anchored Merkle root,
    //    and anyone can check it without asking any node anything.
    let anchors = honest.anchors().await.unwrap();
    let cid = ballot.content_id();
    let mut proof: Option<InclusionProof> = None;
    for a in &anchors {
        let anchor_id: Id = hex::decode(&a.content_id).unwrap().try_into().unwrap();
        if let Some(p) = honest.anchor_proof(&anchor_id, &cid).await.unwrap() {
            proof = Some(InclusionProof {
                root: hex::decode(&p.root).unwrap().try_into().unwrap(),
                leaf_count: p.leaf_count,
                index: p.index,
                siblings: p
                    .siblings
                    .iter()
                    .map(|s| hex::decode(s).unwrap().try_into().unwrap())
                    .collect(),
            });
            break;
        }
    }
    let proof = proof.expect("the anchor that covers the ballot");
    assert!(verify_inclusion(&proof, &cid));
    assert!(!verify_inclusion(&proof, &[0xAAu8; 32]));

    // The count is what the voter cast, at the height the anchor gave it.
    assert_eq!(height, 150);
    assert_eq!(counts_of(&nodes[0], &vid), Some(vec![1, 0]));

    liar_task.abort();
    task2.abort();
    liar2_task.abort();
    for h in nodes {
        h.shutdown().await;
    }
}
