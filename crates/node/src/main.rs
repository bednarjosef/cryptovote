//! `cv-node` binary.
#![forbid(unsafe_code)]

use clap::Parser;
use cv_core::context::Deployment;
use cv_core::crypto::groth16::{self, MembershipKeys};
use cv_core::registry::{RegistrySnapshot, decode_leaves};
use cv_log::Log;
use cv_log::headers::MockChain;
use cv_log::store::{MemoryStore, RedbStore, Store};
use cv_node::{NodeConfig, start};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

#[derive(Parser, Debug)]
#[command(name = "cv-node", about = "CryptoVote node: stores and relays the Log")]
struct Args {
    /// Address to listen on.
    #[arg(long, default_value = "127.0.0.1:8440")]
    listen: SocketAddr,
    /// Data directory (redb store). Omit with --memory for an in-memory Log.
    #[arg(long)]
    data_dir: Option<PathBuf>,
    #[arg(long)]
    memory: bool,
    /// Peer base URLs (repeatable).
    #[arg(long = "peer")]
    peers: Vec<String>,
    /// Node name for logs.
    #[arg(long, default_value = "node")]
    name: String,
    /// Authority public keys allowed to create votes (hex, repeatable).
    #[arg(long = "authority-key")]
    authority_keys: Vec<String>,
    /// Issuer public key (hex).
    #[arg(long)]
    issuer_key: String,
    /// DEV MODE: mock Bitcoin clock, insecure Groth16 setup, dev anchors.
    #[arg(long)]
    dev: bool,
    /// Dev mode: genesis height of the mock chain.
    #[arg(long, default_value_t = 100)]
    mock_genesis: u32,
    /// Dev mode: seconds per mock block.
    #[arg(long, default_value_t = 10.0)]
    mock_block_seconds: f64,
    /// Registry snapshot file (SPEC §4.3) to load at start.
    #[arg(long)]
    registry_snapshot: Option<PathBuf>,
    /// Registry leaves file to load at start.
    #[arg(long)]
    registry_leaves: Option<PathBuf>,
    /// Gossip pull interval in seconds.
    #[arg(long, default_value_t = 10)]
    gossip_interval: u64,
    /// Also gossip to endpoints of registered nodes.
    #[arg(long)]
    gossip_to_registered: bool,
}

fn parse_key(s: &str) -> anyhow::Result<[u8; 32]> {
    let v = hex::decode(s)?;
    v.try_into()
        .map_err(|_| anyhow::anyhow!("key must be 32 bytes of hex"))
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env().add_directive("info".parse()?),
        )
        .init();
    let args = Args::parse();
    let deployment = Deployment {
        authority_keys: args
            .authority_keys
            .iter()
            .map(|k| parse_key(k))
            .collect::<Result<_, _>>()?,
        issuer_key: parse_key(&args.issuer_key)?,
        dev_mode: args.dev,
    };
    if !args.dev {
        anyhow::bail!(
            "release mode needs a Bitcoin header source and ceremony keys (Phase 5); run with --dev for now"
        );
    }
    let keys: Arc<MembershipKeys> = Arc::new(groth16::setup(
        &mut <rand_chacha::ChaCha20Rng as rand::SeedableRng>::from_seed(groth16::DEV_SETUP_SEED),
    ));
    let headers = Arc::new(MockChain::new(args.mock_genesis, args.mock_block_seconds));
    let store: Box<dyn Store> = if args.memory || args.data_dir.is_none() {
        Box::new(MemoryStore::new())
    } else {
        let dir = args.data_dir.clone().unwrap();
        std::fs::create_dir_all(&dir)?;
        Box::new(RedbStore::open(&dir.join("log.redb"))?)
    };
    let mut log = Log::open(deployment, keys, store, headers.clone())?;
    if let (Some(s), Some(l)) = (&args.registry_snapshot, &args.registry_leaves) {
        let snapshot = RegistrySnapshot::decode(&std::fs::read(s)?)?;
        let leaves = decode_leaves(&std::fs::read(l)?)?;
        log.add_registry(snapshot, leaves)?;
    }
    let config = NodeConfig {
        name: args.name,
        listen: args.listen,
        peers: args.peers,
        gossip_interval: Duration::from_secs(args.gossip_interval),
        gossip_to_registered: args.gossip_to_registered,
    };
    let handle = start(config, log).await?;
    println!("cv-node listening on {}", handle.url());
    // Re-check header-dependent orphans as the mock clock advances.
    let node = handle.node.clone();
    let ticker = tokio::spawn(async move {
        loop {
            tokio::time::sleep(Duration::from_secs(5)).await;
            node.headers_changed();
        }
    });
    tokio::signal::ctrl_c().await?;
    ticker.abort();
    handle.shutdown().await;
    Ok(())
}
