//! Solver role (whitepaper §10): force open every key party's timed
//! commitment as soon as it appears, so results never depend on a party's
//! cooperation. One sequential job per party; publishes a `Share`.

use crate::Node;
use cv_core::crypto::field::fr_to_bytes;
use cv_core::items::*;
use cv_core::tally::unique_by_nullifier;
use std::collections::HashSet;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::watch;

#[derive(Clone, Debug)]
pub struct SolverConfig {
    pub enabled: bool,
    pub parallel: usize,
    pub poll: Duration,
}

impl Default for SolverConfig {
    fn default() -> Self {
        SolverConfig {
            enabled: false,
            parallel: 2,
            poll: Duration::from_secs(5),
        }
    }
}

/// Key parties without a share, not counting duplicates under one nullifier.
pub fn missing_shares(node: &Node) -> Vec<KeyParty> {
    let log = node.log.lock().unwrap();
    let all: Vec<KeyParty> = log.all_keyparties().into_iter().cloned().collect();
    let mut out = Vec::new();
    for vote_id in all.iter().map(|k| k.vote_id).collect::<HashSet<_>>() {
        let of_vote: Vec<KeyParty> = all
            .iter()
            .filter(|k| k.vote_id == vote_id)
            .cloned()
            .collect();
        for kp in unique_by_nullifier(&of_vote, |k| fr_to_bytes(&k.nullifier), |k| k.content_id()) {
            if log.shares_of(&kp.content_id()).is_empty() {
                out.push(kp);
            }
        }
    }
    out
}

/// Force open one party and publish the share. Blocking (T squarings).
pub fn solve_one(node: &Node, kp: &KeyParty) -> Option<Id> {
    let sk = cv_core::keyparties::force_open(kp)?;
    let share = Share {
        vote_id: kp.vote_id,
        keyparty_id: kp.content_id(),
        sk,
    };
    let id = share.content_id();
    match node.submit(&Item::Share(share).encode()) {
        Ok(_) => Some(id),
        Err(e) => {
            tracing::warn!(node = %node.name, "forced share rejected: {e}");
            None
        }
    }
}

pub async fn solver_loop(
    node: Arc<Node>,
    config: SolverConfig,
    mut shutdown: watch::Receiver<bool>,
) {
    if !config.enabled {
        return;
    }
    let in_progress: Arc<Mutex<HashSet<Id>>> = Arc::new(Mutex::new(HashSet::new()));
    loop {
        let running = in_progress.lock().unwrap().len();
        if running < config.parallel {
            for kp in missing_shares(&node)
                .into_iter()
                .take(config.parallel - running)
            {
                let id = kp.content_id();
                if !in_progress.lock().unwrap().insert(id) {
                    continue;
                }
                let n = node.clone();
                let ip = in_progress.clone();
                tokio::task::spawn_blocking(move || {
                    tracing::info!(node = %n.name, party = %hex::encode(id), delay = kp.delay_t, "forcing open a key party commitment");
                    let r = solve_one(&n, &kp);
                    tracing::info!(node = %n.name, party = %hex::encode(id), "forced opening finished: {r:?}");
                    ip.lock().unwrap().remove(&id);
                });
            }
        }
        tokio::select! {
            _ = shutdown.changed() => break,
            _ = tokio::time::sleep(config.poll) => {}
        }
    }
}
