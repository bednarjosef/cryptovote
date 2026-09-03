//! Gossip: push every new item to all peers; periodically pull inventories
//! and registries from peers and fetch what is missing. Plain HTTP; the
//! network layer never affects correctness (whitepaper §12).

use crate::Node;
use cv_core::crypto::field::fr_to_bytes;
use cv_core::registry::{RegistrySnapshot, decode_leaves};
use cv_core::wire::{Inventory, RegistrySummary};
use std::sync::Arc;
use tokio::sync::{mpsc, watch};

pub async fn push_loop(
    node: Arc<Node>,
    mut rx: mpsc::UnboundedReceiver<Vec<u8>>,
    client: reqwest::Client,
    mut shutdown: watch::Receiver<bool>,
) {
    loop {
        tokio::select! {
            _ = shutdown.changed() => break,
            item = rx.recv() => {
                let Some(bytes) = item else { break };
                for peer in node.peers() {
                    let client = client.clone();
                    let bytes = bytes.clone();
                    tokio::spawn(async move {
                        let _ = client.post(format!("{peer}/v1/items")).body(bytes).send().await;
                    });
                }
            }
        }
    }
}

pub async fn pull_loop(
    node: Arc<Node>,
    client: reqwest::Client,
    mut shutdown: watch::Receiver<bool>,
) {
    let interval = node.config.gossip_interval;
    loop {
        for peer in node.peers() {
            if let Err(e) = sync_peer(&node, &client, &peer).await {
                tracing::debug!(node = %node.name, %peer, "pull failed: {e}");
            }
        }
        tokio::select! {
            _ = shutdown.changed() => break,
            _ = tokio::time::sleep(interval) => {}
        }
    }
}

async fn sync_peer(node: &Arc<Node>, client: &reqwest::Client, peer: &str) -> anyhow::Result<()> {
    // Registries first: items may depend on them.
    let regs: Vec<RegistrySummary> = client
        .get(format!("{peer}/v1/registry"))
        .send()
        .await?
        .json()
        .await?;
    for r in regs {
        let known = {
            let log = node.log.lock().unwrap();
            log.registry_roots()
                .iter()
                .any(|root| hex::encode(fr_to_bytes(root)) == r.root)
        };
        if known {
            continue;
        }
        let snap = client
            .get(format!("{peer}/v1/registry/{}/snapshot", r.root))
            .send()
            .await?
            .bytes()
            .await?;
        let leaves = client
            .get(format!("{peer}/v1/registry/{}/leaves", r.root))
            .send()
            .await?
            .bytes()
            .await?;
        let snapshot = RegistrySnapshot::decode(&snap)?;
        let leaves = decode_leaves(&leaves)?;
        let n = node.clone();
        let _ = tokio::task::spawn_blocking(move || n.add_registry(snapshot, leaves)).await?;
    }

    let since = node
        .pull_state
        .lock()
        .unwrap()
        .get(peer)
        .copied()
        .unwrap_or(0);
    let inv: Inventory = client
        .get(format!("{peer}/v1/inventory?since={since}&limit=500"))
        .send()
        .await?
        .json()
        .await?;
    let mut last = since;
    for (seq, hash_hex) in inv.items {
        last = seq;
        let Ok(h) = hex::decode(&hash_hex) else {
            continue;
        };
        let Ok(h): Result<[u8; 32], _> = h.try_into() else {
            continue;
        };
        if node.log.lock().unwrap().has_hash(&h) {
            continue;
        }
        let resp = client
            .get(format!("{peer}/v1/items/by-hash/{hash_hex}"))
            .send()
            .await?;
        if !resp.status().is_success() {
            continue;
        }
        let bytes = resp.bytes().await?.to_vec();
        let n = node.clone();
        let _ = tokio::task::spawn_blocking(move || n.submit(&bytes)).await?;
    }
    node.pull_state
        .lock()
        .unwrap()
        .insert(peer.to_string(), last);
    Ok(())
}
