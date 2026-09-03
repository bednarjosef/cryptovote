//! Mix hop role (whitepaper §12): accept onion packets, peel one layer,
//! hold each message for `max(hold_min, until k other messages arrived)`
//! capped at `hold_cap`, then forward in shuffled order. The queue is
//! persisted in the node's store so a hop that crashes mid-hold forwards
//! after restart. The network layer never affects correctness: whatever
//! comes out of the exit is validated like any other submission.

use crate::Node;
use cv_core::context::Context;
use cv_core::crypto::mix::{MixSecret, Processed, is_decoy, process};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::sync::watch;

#[derive(Clone)]
pub struct MixConfig {
    pub secret: Option<MixSecret>,
    pub hold_min: Duration,
    pub hold_k: u64,
    pub hold_cap: Duration,
    pub tick: Duration,
}

impl Default for MixConfig {
    fn default() -> Self {
        MixConfig {
            secret: None,
            hold_min: Duration::from_secs(cv_core::constants::MIX_HOLD_SECONDS),
            hold_k: cv_core::constants::MIX_HOLD_MESSAGES as u64,
            hold_cap: Duration::from_secs(cv_core::constants::MIX_HOLD_CAP_SECONDS),
            tick: Duration::from_millis(250),
        }
    }
}

impl std::fmt::Debug for MixConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MixConfig")
            .field("enabled", &self.secret.is_some())
            .field("hold_min", &self.hold_min)
            .field("hold_k", &self.hold_k)
            .field("hold_cap", &self.hold_cap)
            .finish()
    }
}

/// Counters that drive the adaptive hold.
#[derive(Default)]
pub struct MixState {
    pub arrivals: AtomicU64,
    seq: AtomicU64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Queued {
    seq: u64,
    kind: String,
    bytes: String,
    next: String,
    arrived_ms: u64,
    arrivals_at: u64,
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

#[derive(Debug, thiserror::Error)]
pub enum MixAcceptError {
    #[error("this node is not a mix hop")]
    NotAHop,
    #[error("{0}")]
    Packet(#[from] cv_core::crypto::mix::MixError),
    #[error("storage: {0}")]
    Storage(String),
}

/// Peel one layer and queue the result.
pub fn accept(node: &Node, packet: &[u8]) -> Result<(), MixAcceptError> {
    let secret = node
        .config
        .mix
        .secret
        .as_ref()
        .ok_or(MixAcceptError::NotAHop)?;
    let processed = process(packet, secret)?;
    let (kind, bytes, next) = match processed {
        Processed::Forward { packet, next } => ("forward", packet, hex::encode(next)),
        Processed::Final { payload } => ("final", payload, String::new()),
    };
    let arrivals = node.mix_state.arrivals.fetch_add(1, Ordering::SeqCst) + 1;
    let seq = node.mix_state.seq.fetch_add(1, Ordering::SeqCst) + 1;
    let q = Queued {
        seq,
        kind: kind.into(),
        bytes: hex::encode(bytes),
        next,
        arrived_ms: now_ms(),
        arrivals_at: arrivals,
    };
    let log = node.log.lock().unwrap();
    log.put_meta(
        &format!("mix/queue/{seq:020}"),
        &serde_json::to_vec(&q).unwrap(),
    )
    .map_err(|e| MixAcceptError::Storage(e.to_string()))?;
    Ok(())
}

fn load_queue(node: &Node) -> Vec<Queued> {
    let log = node.log.lock().unwrap();
    log.meta_with_prefix("mix/queue/")
        .unwrap_or_default()
        .into_iter()
        .filter_map(|(_, v)| serde_json::from_slice(&v).ok())
        .collect()
}

pub fn queue_len(node: &Node) -> usize {
    load_queue(node).len()
}

/// On startup: continue sequence numbers after what was persisted.
pub fn restore(node: &Node) {
    let q = load_queue(node);
    let max = q.iter().map(|e| e.seq).max().unwrap_or(0);
    node.mix_state.seq.store(max, Ordering::SeqCst);
    if !q.is_empty() {
        tracing::info!(node = %node.name, queued = q.len(), "mix queue restored from disk");
    }
}

pub async fn mix_loop(
    node: Arc<Node>,
    client: reqwest::Client,
    mut shutdown: watch::Receiver<bool>,
) {
    if node.config.mix.secret.is_none() {
        return;
    }
    let cfg = node.config.mix.clone();
    loop {
        let now = now_ms();
        let arrivals = node.mix_state.arrivals.load(Ordering::SeqCst);
        let mut due: Vec<Queued> = load_queue(&node)
            .into_iter()
            .filter(|q| {
                let age = Duration::from_millis(now.saturating_sub(q.arrived_ms));
                let others = arrivals.saturating_sub(q.arrivals_at);
                age >= cfg.hold_cap || (age >= cfg.hold_min && others >= cfg.hold_k)
            })
            .collect();
        // Shuffle (Fisher–Yates with OS randomness) so output order reveals nothing about input order.
        {
            use rand::seq::SliceRandom;
            due.shuffle(&mut rand::rngs::OsRng);
        }
        for q in due {
            {
                let log = node.log.lock().unwrap();
                let _ = log.delete_meta(&format!("mix/queue/{:020}", q.seq));
            }
            let Ok(bytes) = hex::decode(&q.bytes) else {
                continue;
            };
            if q.kind == "final" {
                if is_decoy(&bytes) {
                    tracing::debug!(node = %node.name, "dropped decoy");
                    continue;
                }
                let n = node.clone();
                let r = tokio::task::spawn_blocking(move || n.submit(&bytes)).await;
                tracing::debug!(node = %node.name, "exit published item: {r:?}");
            } else {
                let Ok(next) = hex::decode(&q.next).map(|v| v.try_into().unwrap_or([0u8; 32]))
                else {
                    continue;
                };
                let endpoint = node
                    .log
                    .lock()
                    .unwrap()
                    .node_registration(&next)
                    .map(|r| r.endpoint);
                match endpoint {
                    Some(ep) => {
                        let url = format!("http://{ep}/v1/mix");
                        let client = client.clone();
                        let name = node.name.clone();
                        tokio::spawn(async move {
                            if let Err(e) = client.post(url).body(bytes).send().await {
                                tracing::warn!(node = %name, "forward failed: {e}");
                            }
                        });
                    }
                    None => {
                        tracing::warn!(node = %node.name, "next hop not registered; dropping packet")
                    }
                }
            }
        }
        tokio::select! {
            _ = shutdown.changed() => break,
            _ = tokio::time::sleep(cfg.tick) => {}
        }
    }
}
