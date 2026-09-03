//! Node: stores and relays the Log, serves light clients and verifiers.
//! Roles added in later phases: anchorer (5), mix hop (7), solver (10).
#![forbid(unsafe_code)]

pub mod anchor;
pub mod api;
pub mod gossip;
pub mod headers_http;

use cv_core::crypto::field::Fr;
use cv_core::registry::RegistrySnapshot;
use cv_log::{Accepted, Log, RegistryError, Rejected};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::{mpsc, watch};

pub type SharedLog = Arc<Mutex<Log>>;

#[derive(Clone, Debug)]
pub struct NodeConfig {
    pub name: String,
    pub listen: SocketAddr,
    pub peers: Vec<String>,
    pub gossip_interval: Duration,
    /// Also gossip to endpoints found in NodeRegistration items.
    pub gossip_to_registered: bool,
    pub anchor: anchor::AnchorConfig,
}

impl Default for NodeConfig {
    fn default() -> Self {
        NodeConfig {
            name: "node".into(),
            listen: "127.0.0.1:0".parse().unwrap(),
            peers: Vec::new(),
            gossip_interval: Duration::from_secs(10),
            gossip_to_registered: false,
            anchor: anchor::AnchorConfig::default(),
        }
    }
}

pub struct Node {
    pub name: String,
    pub log: SharedLog,
    pub config: NodeConfig,
    peers: Mutex<Vec<String>>,
    relay_tx: mpsc::UnboundedSender<Vec<u8>>,
    /// Per-peer highest sequence number pulled so far.
    pub(crate) pull_state: Mutex<HashMap<String, u64>>,
}

impl Node {
    /// Insert bytes into the Log and queue anything new for relay.
    /// Blocking (verifies proofs); call from `spawn_blocking` in async code.
    pub fn submit(&self, bytes: &[u8]) -> Result<Accepted, Rejected> {
        let mut log = self.log.lock().unwrap();
        let r = log.insert(bytes);
        self.flush_relay(&mut log);
        r
    }

    pub fn add_registry(
        &self,
        snapshot: RegistrySnapshot,
        leaves: Vec<Fr>,
    ) -> Result<(), RegistryError> {
        let mut log = self.log.lock().unwrap();
        let r = log.add_registry(snapshot, leaves);
        self.flush_relay(&mut log);
        r
    }

    /// Re-check header-dependent orphans (called when the chain advances).
    pub fn headers_changed(&self) {
        let mut log = self.log.lock().unwrap();
        log.headers_changed();
        self.flush_relay(&mut log);
    }

    fn flush_relay(&self, log: &mut Log) {
        for bytes in log.take_relay() {
            let _ = self.relay_tx.send(bytes);
        }
    }

    pub fn add_peer(&self, url: impl Into<String>) {
        let url = url.into();
        let mut peers = self.peers.lock().unwrap();
        if !peers.contains(&url) {
            peers.push(url);
        }
    }

    pub fn peers(&self) -> Vec<String> {
        let mut peers = self.peers.lock().unwrap().clone();
        if self.config.gossip_to_registered {
            let log = self.log.lock().unwrap();
            for id in log.registered_node_ids() {
                if let Some(cv_core::items::Item::NodeRegistration(r)) = log.get(&id) {
                    let url = format!("http://{}", r.endpoint);
                    if !peers.contains(&url) {
                        peers.push(url);
                    }
                }
            }
        }
        peers
    }
}

pub struct NodeHandle {
    pub addr: SocketAddr,
    pub node: Arc<Node>,
    shutdown: watch::Sender<bool>,
    tasks: Vec<tokio::task::JoinHandle<()>>,
}

impl NodeHandle {
    pub fn url(&self) -> String {
        format!("http://{}", self.addr)
    }

    pub async fn shutdown(self) {
        let _ = self.shutdown.send(true);
        for t in self.tasks {
            let _ = t.await;
        }
    }
}

/// Start the HTTP API and the gossip tasks.
pub async fn start(config: NodeConfig, log: Log) -> anyhow::Result<NodeHandle> {
    if log.deployment().dev_mode {
        // Printed on every start so that nobody mistakes a dev node for a real one.
        eprintln!(
            "WARNING [{}]: dev mode — mock Bitcoin clock, insecure Groth16 setup, dev anchors accepted. \
             Nothing this node does is trustworthy.",
            config.name
        );
        tracing::warn!(node = %config.name, "dev mode enabled: insecure shortcuts active");
    }
    let (relay_tx, relay_rx) = mpsc::unbounded_channel();
    let node = Arc::new(Node {
        name: config.name.clone(),
        log: Arc::new(Mutex::new(log)),
        peers: Mutex::new(config.peers.clone()),
        relay_tx,
        pull_state: Mutex::new(HashMap::new()),
        config: config.clone(),
    });
    let listener = tokio::net::TcpListener::bind(config.listen).await?;
    let addr = listener.local_addr()?;
    let (shutdown_tx, shutdown_rx) = watch::channel(false);

    let app = api::router(node.clone());
    let mut rx = shutdown_rx.clone();
    let server = tokio::spawn(async move {
        let _ = axum::serve(listener, app)
            .with_graceful_shutdown(async move {
                let _ = rx.changed().await;
            })
            .await;
    });
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .build()?;
    let push = tokio::spawn(gossip::push_loop(
        node.clone(),
        relay_rx,
        client.clone(),
        shutdown_rx.clone(),
    ));
    let pull = tokio::spawn(gossip::pull_loop(
        node.clone(),
        client.clone(),
        shutdown_rx.clone(),
    ));
    let anchorer = tokio::spawn(anchor::anchor_loop(
        node.clone(),
        config.anchor.clone(),
        client,
        shutdown_rx,
    ));
    tracing::info!(node = %config.name, %addr, "node started");
    Ok(NodeHandle {
        addr,
        node,
        shutdown: shutdown_tx,
        tasks: vec![server, push, pull, anchorer],
    })
}
