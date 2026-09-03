//! Anchorer role (whitepaper §9): periodically commit the root of everything
//! not yet anchored into Bitcoin — for free through OpenTimestamps calendars
//! (default), or in dev mode through the mock chain. Direct anchors are
//! prepared here and published from externally broadcast transactions.

use crate::Node;
use cv_core::crypto::merkle::anchor_root;
use cv_core::crypto::ots;
use cv_core::items::*;
use cv_log::Accepted;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::watch;

/// Public calendars run by independent operators (whitepaper §14: submit to
/// at least three).
pub const DEFAULT_CALENDARS: &[&str] = &[
    "https://a.pool.opentimestamps.org",
    "https://b.pool.opentimestamps.org",
    "https://a.pool.eternitywall.com",
    "https://ots.btc.catallaxy.com",
];

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AnchorMode {
    Off,
    /// Dev mode only: publish `Dev` anchors at the mock chain's tip.
    Dev,
    /// Submit roots to OTS calendars and publish once Bitcoin-attested.
    Ots,
}

#[derive(Clone, Debug)]
pub struct AnchorConfig {
    pub mode: AnchorMode,
    pub interval: Duration,
    pub calendars: Vec<String>,
    /// Minimum calendars that must accept a submission.
    pub min_calendars: usize,
}

impl Default for AnchorConfig {
    fn default() -> Self {
        AnchorConfig {
            mode: AnchorMode::Off,
            interval: Duration::from_secs(3600),
            calendars: DEFAULT_CALENDARS.iter().map(|s| s.to_string()).collect(),
            min_calendars: 1,
        }
    }
}

/// A root submitted to calendars, waiting for Bitcoin attestations.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PendingSubmission {
    pub root: String,
    pub leaves: Vec<String>,
    /// Serialized timestamps (hex), one per calendar that accepted.
    pub timestamps: Vec<String>,
    pub created_unix: u64,
}

fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

pub async fn anchor_loop(
    node: Arc<Node>,
    config: AnchorConfig,
    client: reqwest::Client,
    mut shutdown: watch::Receiver<bool>,
) {
    if config.mode == AnchorMode::Off {
        return;
    }
    loop {
        let r = match config.mode {
            AnchorMode::Dev => dev_anchor_once(&node).await,
            AnchorMode::Ots => ots_anchor_once(&node, &config, &client).await,
            AnchorMode::Off => Ok(()),
        };
        if let Err(e) = r {
            tracing::warn!(node = %node.name, "anchoring round failed: {e}");
        }
        tokio::select! {
            _ = shutdown.changed() => break,
            _ = tokio::time::sleep(config.interval) => {}
        }
    }
}

/// Everything valid and not yet anchored, minus what is already pending.
fn next_leaves(node: &Node, exclude: &[Id]) -> Vec<Id> {
    let log = node.log.lock().unwrap();
    let mut leaves: Vec<Id> = log
        .unanchored_content_ids()
        .into_iter()
        .filter(|id| !exclude.contains(id))
        .collect();
    leaves.sort();
    leaves.dedup();
    leaves
}

async fn dev_anchor_once(node: &Arc<Node>) -> anyhow::Result<()> {
    // INSECURE: the mock chain is the local clock; only meaningful in dev mode.
    let leaves = next_leaves(node, &[]);
    if leaves.is_empty() {
        return Ok(());
    }
    let height = node
        .log
        .lock()
        .unwrap()
        .headers()
        .tip_height()
        .ok_or_else(|| anyhow::anyhow!("no tip"))?;
    let item = Item::Anchor(Anchor {
        leaves,
        proof: AnchorProof::Dev { height },
    });
    publish(node, item).await
}

async fn publish(node: &Arc<Node>, item: Item) -> anyhow::Result<()> {
    let n = node.clone();
    let bytes = item.encode();
    match tokio::task::spawn_blocking(move || n.submit(&bytes)).await? {
        Ok(Accepted::New { content_id, .. }) => {
            tracing::info!(node = %node.name, anchor = %hex::encode(content_id), "published anchor");
            Ok(())
        }
        Ok(other) => {
            tracing::debug!(node = %node.name, "anchor not new: {other:?}");
            Ok(())
        }
        Err(e) => Err(anyhow::anyhow!("own anchor rejected: {e}")),
    }
}

fn pending_key(root: &str) -> String {
    format!("ots/pending/{root}")
}

pub fn pending_submissions(node: &Node) -> Vec<PendingSubmission> {
    let log = node.log.lock().unwrap();
    log.meta_with_prefix("ots/pending/")
        .unwrap_or_default()
        .into_iter()
        .filter_map(|(_, v)| serde_json::from_slice(&v).ok())
        .collect()
}

/// Submit a digest to one calendar; returns the calendar's (pending) timestamp.
/// `// TRUST: OTS calendars for liveness only (whitepaper §2)`.
pub async fn submit_to_calendar(
    client: &reqwest::Client,
    calendar: &str,
    digest: &[u8; 32],
) -> anyhow::Result<Vec<u8>> {
    let resp = client
        .post(format!("{}/digest", calendar.trim_end_matches('/')))
        .header("Accept", "application/vnd.opentimestamps.v1")
        .header("User-Agent", "cryptovote-node")
        .body(digest.to_vec())
        .send()
        .await?;
    if !resp.status().is_success() {
        anyhow::bail!("calendar {calendar} returned {}", resp.status());
    }
    let bytes = resp.bytes().await?.to_vec();
    ots::parse(digest, &bytes)
        .map_err(|e| anyhow::anyhow!("calendar {calendar}: unparsable timestamp: {e}"))?;
    Ok(bytes)
}

/// Ask the calendar for the completed timestamp of a commitment digest.
pub async fn fetch_upgrade(
    client: &reqwest::Client,
    calendar_uri: &str,
    commitment: &[u8],
) -> anyhow::Result<Option<Vec<u8>>> {
    let resp = client
        .get(format!(
            "{}/timestamp/{}",
            calendar_uri.trim_end_matches('/'),
            hex::encode(commitment)
        ))
        .header("Accept", "application/vnd.opentimestamps.v1")
        .header("User-Agent", "cryptovote-node")
        .send()
        .await?;
    if resp.status().as_u16() == 404 {
        return Ok(None);
    }
    if !resp.status().is_success() {
        anyhow::bail!("calendar returned {}", resp.status());
    }
    Ok(Some(resp.bytes().await?.to_vec()))
}

async fn ots_anchor_once(
    node: &Arc<Node>,
    config: &AnchorConfig,
    client: &reqwest::Client,
) -> anyhow::Result<()> {
    // 1. Try to complete pending submissions.
    let pending = pending_submissions(node);
    let mut in_flight: Vec<Id> = Vec::new();
    for p in &pending {
        let root: [u8; 32] = hex::decode(&p.root)?
            .try_into()
            .map_err(|_| anyhow::anyhow!("bad root"))?;
        let leaves: Vec<Id> = p
            .leaves
            .iter()
            .map(|l| hex::decode(l).ok().and_then(|v| v.try_into().ok()))
            .collect::<Option<_>>()
            .ok_or_else(|| anyhow::anyhow!("bad leaves"))?;
        in_flight.extend(leaves.iter().copied());
        let mut done = false;
        for ts_hex in &p.timestamps {
            let Ok(bytes) = hex::decode(ts_hex) else {
                continue;
            };
            let Ok(mut ts) = ots::parse(&root, &bytes) else {
                continue;
            };
            // Find pending attestations and try to upgrade each.
            let pendings = pending_commitments(&ts);
            for (uri, commitment) in pendings {
                match fetch_upgrade(client, &uri, &commitment).await {
                    Ok(Some(up)) => {
                        if let Ok(completed) = ots::parse(&commitment, &up) {
                            ots::upgrade(&mut ts, &completed);
                        }
                    }
                    Ok(None) => {}
                    Err(e) => tracing::debug!(node = %node.name, "upgrade fetch failed: {e}"),
                }
            }
            let att = ots::attestations(&ts);
            for (height, digest) in &att.bitcoin {
                let known = node.log.lock().unwrap().headers().merkle_root(*height);
                match known {
                    Some(root_at_height) if root_at_height.as_slice() == digest.as_slice() => {
                        let item = Item::Anchor(Anchor {
                            leaves: leaves.clone(),
                            proof: AnchorProof::Ots {
                                height: *height,
                                ots: ots::serialize(&ts),
                            },
                        });
                        publish(node, item).await?;
                        done = true;
                        break;
                    }
                    Some(_) => {
                        tracing::warn!(node = %node.name, height, "OTS attestation digest does not match our header")
                    }
                    None => {
                        tracing::debug!(node = %node.name, height, "OTS attested; waiting for the header")
                    }
                }
            }
            if done {
                break;
            }
            // Persist the (possibly upgraded) timestamp.
            let mut p2 = p.clone();
            p2.timestamps = vec![hex::encode(ots::serialize(&ts))];
            let log = node.log.lock().unwrap();
            log.put_meta(&pending_key(&p.root), &serde_json::to_vec(&p2)?)?;
        }
        if done {
            node.log
                .lock()
                .unwrap()
                .delete_meta(&pending_key(&p.root))?;
        }
    }

    // 2. Submit a new root for everything not yet covered.
    let leaves = next_leaves(node, &in_flight);
    if leaves.is_empty() {
        return Ok(());
    }
    let root = anchor_root(&leaves).expect("non-empty");
    let mut timestamps = Vec::new();
    for cal in &config.calendars {
        match submit_to_calendar(client, cal, &root).await {
            Ok(ts) => timestamps.push(hex::encode(ts)),
            Err(e) => tracing::warn!(node = %node.name, calendar = %cal, "submission failed: {e}"),
        }
    }
    if timestamps.len() < config.min_calendars {
        anyhow::bail!(
            "only {} of {} calendars accepted the digest",
            timestamps.len(),
            config.calendars.len()
        );
    }
    let p = PendingSubmission {
        root: hex::encode(root),
        leaves: leaves.iter().map(hex::encode).collect(),
        timestamps,
        created_unix: now_unix(),
    };
    node.log
        .lock()
        .unwrap()
        .put_meta(&pending_key(&p.root), &serde_json::to_vec(&p)?)?;
    tracing::info!(node = %node.name, root = %p.root, leaves = leaves.len(), "submitted root to calendars");
    Ok(())
}

/// `(calendar uri, commitment digest)` of every pending attestation.
fn pending_commitments(ts: &opentimestamps::timestamp::Timestamp) -> Vec<(String, Vec<u8>)> {
    use opentimestamps::attestation::Attestation;
    use opentimestamps::timestamp::{Step, StepData};
    fn walk(s: &Step, out: &mut Vec<(String, Vec<u8>)>) {
        if let StepData::Attestation(Attestation::Pending { uri }) = &s.data {
            out.push((uri.clone(), s.output.clone()));
        }
        for n in &s.next {
            walk(n, out);
        }
    }
    let mut out = Vec::new();
    walk(&ts.first_step, &mut out);
    out
}

/// Direct path, step 1: the leaves to commit and the `OP_RETURN` script the
/// operator must include in a Bitcoin transaction.
pub fn prepare_direct(node: &Node) -> Option<(Vec<Id>, [u8; 32], Vec<u8>)> {
    let leaves = next_leaves(node, &[]);
    if leaves.is_empty() {
        return None;
    }
    let root = anchor_root(&leaves)?;
    let script = cv_core::crypto::spv::op_return_script(&root).to_bytes();
    Some((leaves, root, script))
}

/// Direct path, step 2: build the Anchor item from the confirmed transaction.
pub fn direct_anchor_item(
    leaves: Vec<Id>,
    height: u32,
    raw_tx: Vec<u8>,
    partial_merkle_tree: Vec<u8>,
) -> Item {
    Item::Anchor(Anchor {
        leaves,
        proof: AnchorProof::Direct {
            height,
            raw_tx,
            partial_merkle_tree,
        },
    })
}
