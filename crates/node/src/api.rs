//! HTTP API (`/v1/...`): item submission and retrieval, inventory for gossip,
//! light-client queries by vote and by nullifier, anchors and inclusion
//! proofs, registry files, headers tip, snapshot export.

use crate::Node;
use axum::body::Bytes;
use axum::extract::{Path, Query, State};
use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use cv_core::crypto::field::{Fr, fr_from_canonical, fr_to_bytes};
use cv_core::items::*;
use cv_core::registry::{RegistrySnapshot, decode_leaves, encode_leaves};
use cv_core::wire::*;
use cv_log::Accepted;
use serde::Deserialize;
use std::sync::Arc;

pub fn router(node: Arc<Node>) -> Router {
    Router::new()
        .route("/v1/status", get(status))
        .route("/v1/items", post(submit))
        .route("/v1/items/{id}", get(get_item))
        .route("/v1/items/by-hash/{hash}", get(get_by_hash))
        .route("/v1/inventory", get(inventory))
        .route("/v1/votes", get(votes))
        .route("/v1/votes/{id}/ballots", get(vote_ballots))
        .route("/v1/votes/{id}/result", get(vote_result))
        .route("/v1/votes/{id}/keyparties", get(vote_keyparties))
        .route("/v1/initiatives", get(initiatives))
        .route("/v1/nodes", get(nodes))
        .route("/v1/mix", post(mix_submit))
        .route("/v1/votes/{id}/nullifier/{n}", get(nullifier_status))
        .route("/v1/anchors", get(anchors))
        .route("/v1/anchors/{id}/proof/{cid}", get(anchor_proof))
        .route(
            "/v1/registry",
            get(registries)
                .post(post_registry)
                .layer(axum::extract::DefaultBodyLimit::max(
                    cv_core::constants::MAX_REGISTRY_BODY_BYTES,
                )),
        )
        .route(
            "/v1/registry/{issuer}/{root}/snapshot",
            get(registry_snapshot),
        )
        .route("/v1/registry/{issuer}/{root}/leaves", get(registry_leaves))
        .route(
            "/v1/registry/{issuer}/{root}/path/{commitment}",
            get(registry_path),
        )
        .route("/v1/headers/tip", get(tip))
        .route("/v1/snapshot", get(snapshot))
        // Axum's default body limit is 2 MiB, well under `MAX_ITEM_BYTES`, so
        // without this the HTTP layer silently contradicts the protocol and
        // rejects items the validity rules accept (A59). Registry uploads set
        // their own, larger limit above. Request timeouts and rate limiting are
        // a reverse proxy's job and are not attempted here.
        .layer(axum::extract::DefaultBodyLimit::max(
            cv_core::constants::MAX_ITEM_BYTES,
        ))
        .with_state(node)
}

fn parse_id(s: &str) -> Option<Id> {
    hex::decode(s).ok().and_then(|v| v.try_into().ok())
}

fn parse_fr(s: &str) -> Option<Fr> {
    fr_from_canonical(&parse_id(s)?)
}

fn octets(bytes: Vec<u8>) -> Response {
    ([(header::CONTENT_TYPE, "application/octet-stream")], bytes).into_response()
}

fn not_found() -> Response {
    StatusCode::NOT_FOUND.into_response()
}

async fn status(State(node): State<Arc<Node>>) -> Json<Status> {
    let log = node.log.lock().unwrap();
    Json(Status {
        name: node.name.clone(),
        dev_mode: log.deployment().dev_mode,
        items: log.len(),
        orphans: log.orphan_count(),
        latest_seq: log.latest_seq(),
        tip_height: log.headers().tip_height(),
        peers: node.peers(),
    })
}

pub fn submit_response(
    r: Result<Accepted, cv_log::Rejected>,
) -> (StatusCode, Json<SubmitResponse>) {
    match r {
        Ok(Accepted::New {
            content_id,
            item_type,
            seq,
        }) => (
            StatusCode::OK,
            Json(SubmitResponse::New {
                content_id: hex::encode(content_id),
                item_type: format!("{item_type:?}"),
                seq,
            }),
        ),
        Ok(Accepted::AlreadyHave) => (StatusCode::OK, Json(SubmitResponse::AlreadyHave)),
        Ok(Accepted::Equivalent { content_id }) => (
            StatusCode::OK,
            Json(SubmitResponse::Equivalent {
                content_id: hex::encode(content_id),
            }),
        ),
        Ok(Accepted::Orphaned(r)) => (
            StatusCode::ACCEPTED,
            Json(SubmitResponse::Orphaned {
                reference: r.to_string(),
            }),
        ),
        Err(e) => (
            StatusCode::BAD_REQUEST,
            Json(SubmitResponse::Rejected {
                reason: e.to_string(),
            }),
        ),
    }
}

async fn submit(State(node): State<Arc<Node>>, body: Bytes) -> (StatusCode, Json<SubmitResponse>) {
    let n = node.clone();
    let r = tokio::task::spawn_blocking(move || n.submit(&body))
        .await
        .expect("submit task");
    submit_response(r)
}

async fn get_item(State(node): State<Arc<Node>>, Path(id): Path<String>) -> Response {
    let Some(id) = parse_id(&id) else {
        return not_found();
    };
    let log = node.log.lock().unwrap();
    match log.get(&id) {
        Some(item) => octets(item.encode()),
        None => not_found(),
    }
}

async fn get_by_hash(State(node): State<Arc<Node>>, Path(hash): Path<String>) -> Response {
    let Some(h) = parse_id(&hash) else {
        return not_found();
    };
    let log = node.log.lock().unwrap();
    match log.get_by_hash(&h) {
        Some(item) => octets(item.encode()),
        None => not_found(),
    }
}

#[derive(Deserialize)]
struct InventoryQuery {
    #[serde(default)]
    since: u64,
    #[serde(default = "default_limit")]
    limit: usize,
}

fn default_limit() -> usize {
    1000
}

async fn inventory(
    State(node): State<Arc<Node>>,
    Query(q): Query<InventoryQuery>,
) -> Json<Inventory> {
    let log = node.log.lock().unwrap();
    Json(Inventory {
        latest_seq: log.latest_seq(),
        items: log
            .inventory(q.since, q.limit.min(10_000))
            .into_iter()
            .map(|(s, h)| (s, hex::encode(h)))
            .collect(),
    })
}

async fn votes(State(node): State<Arc<Node>>) -> Json<Vec<VoteSummary>> {
    let log = node.log.lock().unwrap();
    let mut out: Vec<VoteSummary> = log
        .votes()
        .map(|(id, v)| VoteSummary {
            vote_id: hex::encode(id),
            issuer_key: hex::encode(v.issuer_key),
            question: v.question.clone(),
            options: v.options.clone(),
            open_block: v.open_block,
            close_block: v.close_block,
            min_ballots: v.min_ballots,
            min_parties: v.min_parties,
            secrecy: format!("{:?}", v.secrecy).to_lowercase(),
            ballots: log.ballots_of(id).len(),
        })
        .collect();
    out.sort_by(|a, b| a.vote_id.cmp(&b.vote_id));
    Json(out)
}

async fn vote_ballots(State(node): State<Arc<Node>>, Path(id): Path<String>) -> Response {
    let Some(id) = parse_id(&id) else {
        return not_found();
    };
    let log = node.log.lock().unwrap();
    let out: Vec<BallotStatusJson> = log
        .ballots_of(&id)
        .iter()
        .map(|b| {
            let cid = b.content_id();
            BallotStatusJson {
                content_id: hex::encode(cid),
                anchored_height: log.anchored_height(&cid),
            }
        })
        .collect();
    Json(out).into_response()
}

async fn nullifier_status(
    State(node): State<Arc<Node>>,
    Path((id, n)): Path<(String, String)>,
) -> Response {
    let (Some(id), Some(n)) = (parse_id(&id), parse_fr(&n)) else {
        return not_found();
    };
    let log = node.log.lock().unwrap();
    let out: Vec<BallotStatusJson> = log
        .ballot_status(&id, &n)
        .into_iter()
        .map(|s| BallotStatusJson {
            content_id: hex::encode(s.content_id),
            anchored_height: s.anchored_height,
        })
        .collect();
    Json(out).into_response()
}

async fn anchors(State(node): State<Arc<Node>>) -> Json<Vec<AnchorSummary>> {
    let log = node.log.lock().unwrap();
    Json(
        log.anchors()
            .iter()
            .map(|a| AnchorSummary {
                content_id: hex::encode(a.content_id()),
                height: a.proof.height(),
                leaf_count: a.leaves.len(),
                kind: match a.proof {
                    AnchorProof::Ots { .. } => "ots",
                    AnchorProof::Direct { .. } => "direct",
                    AnchorProof::Dev { .. } => "dev",
                }
                .into(),
            })
            .collect(),
    )
}

async fn anchor_proof(
    State(node): State<Arc<Node>>,
    Path((id, cid)): Path<(String, String)>,
) -> Response {
    let (Some(id), Some(cid)) = (parse_id(&id), parse_id(&cid)) else {
        return not_found();
    };
    let log = node.log.lock().unwrap();
    match log.inclusion_proof(&id, &cid) {
        Some(p) => Json(InclusionProofJson {
            root: hex::encode(p.root),
            leaf_count: p.leaf_count,
            index: p.index,
            siblings: p.siblings.iter().map(hex::encode).collect(),
        })
        .into_response(),
        None => not_found(),
    }
}

async fn registries(State(node): State<Arc<Node>>) -> Json<Vec<RegistrySummary>> {
    let log = node.log.lock().unwrap();
    let mut out: Vec<RegistrySummary> = log
        .registry_ids()
        .iter()
        .filter_map(|id| log.registry_snapshot(id))
        .map(|s| RegistrySummary {
            issuer_key: hex::encode(s.issuer_key),
            root: hex::encode(fr_to_bytes(&s.root)),
            epoch: s.epoch,
            leaf_count: s.leaf_count,
        })
        .collect();
    out.sort_by(|a, b| (&a.issuer_key, &a.root).cmp(&(&b.issuer_key, &b.root)));
    Json(out)
}

/// Body: the snapshot followed by the leaves file. The snapshot is
/// variable-length (it carries `authority_keys`), so its own decoder reports
/// where it ends rather than the boundary being a constant.
async fn post_registry(State(node): State<Arc<Node>>, body: Bytes) -> Response {
    let (snapshot, used) = match RegistrySnapshot::decode_prefix(&body) {
        Ok(s) => s,
        Err(e) => return (StatusCode::BAD_REQUEST, e.to_string()).into_response(),
    };
    let leaves = match decode_leaves(&body[used..]) {
        Ok(l) => l,
        Err(e) => return (StatusCode::BAD_REQUEST, e.to_string()).into_response(),
    };
    let n = node.clone();
    match tokio::task::spawn_blocking(move || n.add_registry(snapshot, leaves))
        .await
        .expect("registry task")
    {
        Ok(()) => StatusCode::OK.into_response(),
        Err(e) => (StatusCode::BAD_REQUEST, e.to_string()).into_response(),
    }
}

async fn registry_snapshot(
    State(node): State<Arc<Node>>,
    Path((issuer, root)): Path<(String, String)>,
) -> Response {
    let (Some(issuer), Some(root)) = (parse_id(&issuer), parse_fr(&root)) else {
        return not_found();
    };
    let log = node.log.lock().unwrap();
    match log.registry_snapshot(&(issuer, root)) {
        Some(s) => octets(s.encode()),
        None => not_found(),
    }
}

async fn registry_leaves(
    State(node): State<Arc<Node>>,
    Path((issuer, root)): Path<(String, String)>,
) -> Response {
    let (Some(issuer), Some(root)) = (parse_id(&issuer), parse_fr(&root)) else {
        return not_found();
    };
    let log = node.log.lock().unwrap();
    match log.registry_leaves(&(issuer, root)) {
        Some(l) => octets(encode_leaves(l)),
        None => not_found(),
    }
}

/// One person's Merkle path: `index(u32) || siblings(32 × Fr)`, 1 028 bytes
/// whatever the electorate's size.
///
/// The whole leaves file is the alternative, and at national scale it is
/// hundreds of megabytes per ballot cast. Nothing is lost by not sending it:
/// the client recomputes the root from `(commitment, index, siblings)` and
/// compares it with the root the Issuer signed, so a node that lies about
/// either the index or a sibling produces a root that does not match, exactly
/// as a forged leaves file would (A58).
async fn registry_path(
    State(node): State<Arc<Node>>,
    Path((issuer, root, commitment)): Path<(String, String, String)>,
) -> Response {
    let (Some(issuer), Some(root), Some(c)) =
        (parse_id(&issuer), parse_fr(&root), parse_fr(&commitment))
    else {
        return not_found();
    };
    let log = node.log.lock().unwrap();
    let Some(leaves) = log.registry_leaves(&(issuer, root)) else {
        return not_found();
    };
    let Some(index) = leaves.iter().position(|l| *l == c) else {
        return not_found();
    };
    let Some(tree) = log.registry_tree(&(issuer, root)) else {
        return not_found();
    };
    let Some(siblings) = tree.path(index as u32) else {
        return not_found();
    };
    let mut w = cv_core::encoding::Writer::new();
    w.u32(index as u32);
    for sib in &siblings {
        w.fr(sib);
    }
    octets(w.into_inner())
}

async fn tip(State(node): State<Arc<Node>>) -> Json<Tip> {
    let log = node.log.lock().unwrap();
    Json(Tip {
        height: log.headers().tip_height(),
    })
}

async fn snapshot(State(node): State<Arc<Node>>) -> Response {
    let log = node.log.lock().unwrap();
    octets(log.export_snapshot())
}

async fn vote_result(State(node): State<Arc<Node>>, Path(id): Path<String>) -> Response {
    let Some(id) = parse_id(&id) else {
        return not_found();
    };
    let log = node.log.lock().unwrap();
    let Some(vd) = cv_core::context::Context::vote(&*log, &id) else {
        return not_found();
    };
    match cv_core::tally::tally(&*log, &id) {
        Some(outcome) => Json(outcome.to_wire(&id, &vd)).into_response(),
        None => not_found(),
    }
}

async fn initiatives(State(node): State<Arc<Node>>) -> Json<Vec<InitiativeSummary>> {
    let log = node.log.lock().unwrap();
    let mut out: Vec<InitiativeSummary> = log
        .initiatives()
        .map(|(id, i)| InitiativeSummary {
            initiative_id: hex::encode(id),
            issuer_key: hex::encode(i.issuer_key),
            text: i.text.clone(),
            threshold_n: i.threshold_n,
            support_deadline_block: i.support_deadline_block,
            secrecy: format!("{:?}", i.secrecy).to_lowercase(),
            supports: log.supports_of(id).len(),
            derived_vote_id: cv_core::tally::derive_vote(&*log, id)
                .map(|v| hex::encode(v.vote_id())),
        })
        .collect();
    out.sort_by(|a, b| a.initiative_id.cmp(&b.initiative_id));
    Json(out)
}

/// Valid, non-duplicated node registrations (for hop selection).
async fn nodes(State(node): State<Arc<Node>>) -> Json<Vec<NodeSummary>> {
    let log = node.log.lock().unwrap();
    let mut out: Vec<NodeSummary> = log
        .registered_node_ids()
        .into_iter()
        .filter_map(|id| match log.get(&id) {
            Some(Item::NodeRegistration(r)) => {
                cv_core::context::Context::node_registration(&*log, &r.node_key)
            }
            _ => None,
        })
        .map(|r| NodeSummary {
            node_key: hex::encode(r.node_key),
            issuer_key: hex::encode(r.issuer_key),
            mix_key: hex::encode(r.mix_key),
            endpoint: r.endpoint.clone(),
            operator: r.operator.clone(),
            country: String::from_utf8_lossy(&r.country).into_owned(),
            asn: r.asn,
        })
        .collect();
    out.sort_by(|a, b| a.node_key.cmp(&b.node_key));
    Json(out)
}

async fn mix_submit(State(node): State<Arc<Node>>, body: Bytes) -> Response {
    match crate::mix::accept(&node, &body) {
        Ok(()) => StatusCode::ACCEPTED.into_response(),
        Err(crate::mix::MixAcceptError::NotAHop) => {
            (StatusCode::NOT_FOUND, "not a mix hop").into_response()
        }
        Err(e) => (StatusCode::BAD_REQUEST, e.to_string()).into_response(),
    }
}

/// Key parties of a vote after the duplicate rule (SPEC §7.1), with their
/// anchoring height and whether a share is known.
async fn vote_keyparties(State(node): State<Arc<Node>>, Path(id): Path<String>) -> Response {
    let Some(id) = parse_id(&id) else {
        return not_found();
    };
    let log = node.log.lock().unwrap();
    let all: Vec<KeyParty> = log.keyparties_of(&id).into_iter().cloned().collect();
    let unique = cv_core::tally::unique_by_nullifier(
        &all,
        |k| fr_to_bytes(&k.nullifier),
        |k| k.content_id(),
    );
    let mut out: Vec<KeyPartySummary> = unique
        .iter()
        .map(|k| {
            let cid = k.content_id();
            KeyPartySummary {
                keyparty_id: hex::encode(cid),
                pk: hex::encode(k.pk),
                delay_t: k.delay_t,
                anchored_height: log.anchored_height(&cid),
                has_share: !log.shares_of(&cid).is_empty(),
            }
        })
        .collect();
    out.sort_by(|a, b| a.keyparty_id.cmp(&b.keyparty_id));
    Json(out).into_response()
}
