//! `cv-node` binary.
#![forbid(unsafe_code)]

use clap::{Parser, Subcommand};
use cv_core::context::Deployment;
use cv_core::crypto::groth16::{self, MembershipKeys};
use cv_core::registry::{RegistrySnapshot, decode_leaves};
use cv_log::Log;
use cv_log::headers::{HeaderSource, MockChain, SharedHeaderChain};
use cv_log::store::{MemoryStore, RedbStore, Store};
use cv_node::anchor::{AnchorConfig, AnchorMode, DEFAULT_CALENDARS};
use cv_node::headers_http::{DEFAULT_HEADERS_API, HeaderSync, parse_checkpoint};
use cv_node::{NodeConfig, start};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

#[derive(Parser, Debug)]
#[command(name = "cv-node", about = "CryptoVote node: stores and relays the Log")]
struct Args {
    #[command(subcommand)]
    command: Option<Command>,
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
    /// Issuers whose registries this node carries (hex, repeatable).
    /// Omit to carry any Issuer's registry; items always name their own.
    #[arg(long = "issuer-key")]
    issuer_keys: Vec<String>,
    /// DEV MODE: mock Bitcoin clock, insecure Groth16 setup, dev anchors.
    #[arg(long)]
    dev: bool,
    /// Dev mode: genesis height of the mock chain.
    #[arg(long, default_value_t = 100)]
    mock_genesis: u32,
    /// Dev mode: seconds per mock block.
    #[arg(long, default_value_t = 10.0)]
    mock_block_seconds: f64,
    /// Release mode: directory with `membership.pk` and `membership.vk` from a ceremony.
    #[arg(long)]
    keys_dir: Option<PathBuf>,
    /// Release mode: Esplora-style API for Bitcoin headers.
    #[arg(long, default_value = DEFAULT_HEADERS_API)]
    headers_api: String,
    /// Release mode: BLAKE3 of the membership verifying key this deployment
    /// trusts, as `cv-ceremony finalize` printed it. Not needed if the build
    /// has `MEMBERSHIP_VK_BLAKE3` set; refused if it contradicts it.
    #[arg(long)]
    vk_hash: Option<String>,
    /// Release mode: checkpoint height (deployment constant).
    #[arg(long)]
    checkpoint_height: Option<u32>,
    /// Release mode: checkpoint header, 80 bytes hex (deployment constant).
    #[arg(long)]
    checkpoint_header: Option<String>,
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
    /// Anchorer role: ots | dev | off. On by default, because an anchor is
    /// the only clock the protocol has: a vote nobody anchors cannot be
    /// counted. Anyone may anchor, anchors need no permission and cover
    /// everyone's items, so one node doing it serves the whole network.
    #[arg(long, default_value = "on")]
    anchor: String,
    /// Anchoring interval in seconds (whitepaper §14: hourly).
    #[arg(long, default_value_t = 3600)]
    anchor_interval: u64,
    /// OTS calendar base URLs (repeatable; default: four public calendars).
    #[arg(long = "calendar")]
    calendars: Vec<String>,
    /// Seed (hex) of this node's Ed25519 identity key — the `node_key` in its
    /// NodeRegistration. Omit and the node keeps a generated one in its store.
    #[arg(long)]
    node_key_seed: Option<String>,
    /// Mix hop role: seed (hex) of this node's X25519 mix key (the public key
    /// goes in the NodeRegistration). Omit and the node keeps a generated key
    /// in its own store — being a hop is on by default.
    #[arg(long)]
    mix_secret_seed: Option<String>,
    /// Do not act as a mix hop (relaying ballots for other people's privacy).
    #[arg(long)]
    no_mix: bool,
    /// Mix hold parameters (whitepaper §14): minimum seconds, other messages, cap seconds.
    #[arg(long, default_value_t = 3)]
    mix_hold_secs: u64,
    #[arg(long, default_value_t = 8)]
    mix_hold_messages: u64,
    #[arg(long, default_value_t = 60)]
    mix_hold_cap_secs: u64,
    /// Solver role: force open key-party commitments (one sequential job per party).
    #[arg(long)]
    solver: bool,
    #[arg(long, default_value_t = 2)]
    solver_parallel: usize,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Direct anchor, step 1: print the root and OP_RETURN script for everything a node has not anchored yet.
    PrepareDirectAnchor {
        #[arg(long)]
        node: String,
        /// Where to save the leaf list needed for step 2.
        #[arg(long)]
        leaves_out: PathBuf,
    },
    /// Direct anchor, step 2: publish an Anchor item from a confirmed transaction.
    PublishDirectAnchor {
        #[arg(long)]
        node: String,
        #[arg(long)]
        leaves: PathBuf,
        #[arg(long)]
        height: u32,
        /// Raw transaction, hex.
        #[arg(long)]
        raw_tx: String,
        /// Partial Merkle tree (merkleblock), hex.
        #[arg(long)]
        merkle_proof: String,
    },
}

fn parse_key(s: &str) -> anyhow::Result<[u8; 32]> {
    let v = hex::decode(s)?;
    v.try_into()
        .map_err(|_| anyhow::anyhow!("key must be 32 bytes of hex"))
}

async fn run_subcommand(cmd: Command) -> anyhow::Result<()> {
    let client = reqwest::Client::new();
    match cmd {
        Command::PrepareDirectAnchor { node, leaves_out } => {
            // Ask the node for its unanchored ids through the snapshot is heavy; use the votes' ballots instead.
            let resp: Vec<cv_core::wire::VoteSummary> = client
                .get(format!("{node}/v1/votes"))
                .send()
                .await?
                .json()
                .await?;
            let mut leaves: Vec<[u8; 32]> = Vec::new();
            for v in resp {
                let ballots: Vec<cv_core::wire::BallotStatusJson> = client
                    .get(format!("{node}/v1/votes/{}/ballots", v.vote_id))
                    .send()
                    .await?
                    .json()
                    .await?;
                for b in ballots.into_iter().filter(|b| b.anchored_height.is_none()) {
                    leaves.push(
                        hex::decode(b.content_id)?
                            .try_into()
                            .map_err(|_| anyhow::anyhow!("bad id"))?,
                    );
                }
            }
            leaves.sort();
            leaves.dedup();
            if leaves.is_empty() {
                println!("nothing to anchor");
                return Ok(());
            }
            let root = cv_core::crypto::merkle::anchor_root(&leaves).unwrap();
            std::fs::write(&leaves_out, leaves.concat())?;
            println!(
                "leaves: {} (saved to {})",
                leaves.len(),
                leaves_out.display()
            );
            println!("root: {}", hex::encode(root));
            println!(
                "OP_RETURN script (hex): {}",
                hex::encode(cv_core::crypto::spv::op_return_script(&root).to_bytes())
            );
            println!(
                "Broadcast a transaction with that output, wait for {} confirmations, then run publish-direct-anchor.",
                cv_core::constants::MIN_CONFIRMATIONS
            );
        }
        Command::PublishDirectAnchor {
            node,
            leaves,
            height,
            raw_tx,
            merkle_proof,
        } => {
            let bytes = std::fs::read(&leaves)?;
            let leaves: Vec<[u8; 32]> = bytes
                .chunks_exact(32)
                .map(|c| c.try_into().unwrap())
                .collect();
            let item = cv_node::anchor::direct_anchor_item(
                leaves,
                height,
                hex::decode(raw_tx)?,
                hex::decode(merkle_proof)?,
            );
            let resp: cv_core::wire::SubmitResponse = client
                .post(format!("{node}/v1/items"))
                .body(item.encode())
                .send()
                .await?
                .json()
                .await?;
            println!("{resp:?}");
        }
    }
    Ok(())
}

/// A key the node generates once and keeps in its own store, so its
/// NodeRegistration stays valid across restarts.
fn persistent_seed(log: &Log, name: &str) -> anyhow::Result<[u8; 32]> {
    if let Some(b) = log.get_meta(name)? {
        if let Ok(seed) = <[u8; 32]>::try_from(b.as_slice()) {
            return Ok(seed);
        }
    }
    let mut seed = [0u8; 32];
    use rand::RngCore;
    rand::rngs::OsRng.fill_bytes(&mut seed);
    log.put_meta(name, &seed)?;
    Ok(seed)
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive("info".parse()?)
                // arkworks opens a tracing span per R1CS constraint under the
                // target "gr1cs". Left at `info` those spans dominate: the
                // dev Groth16 setup goes from a fraction of a second to
                // minutes, and the node never finishes starting. Raise it by
                // hand (RUST_LOG=gr1cs=info) only to debug the circuit.
                .add_directive("gr1cs=warn".parse()?),
        )
        .init();
    let args = Args::parse();
    if let Some(cmd) = args.command {
        return run_subcommand(cmd).await;
    }
    let deployment = Deployment {
        issuer_keys: args
            .issuer_keys
            .iter()
            .map(|k| parse_key(k))
            .collect::<Result<_, _>>()?,
        dev_mode: args.dev,
    };
    let (keys, headers, header_sync): (
        Arc<MembershipKeys>,
        Arc<dyn HeaderSource>,
        Option<HeaderSync>,
    ) = if args.dev {
        let keys = Arc::new(groth16::setup(
            &mut <rand_chacha::ChaCha20Rng as rand::SeedableRng>::from_seed(
                groth16::DEV_SETUP_SEED,
            ),
        ));
        (
            keys,
            Arc::new(MockChain::new(args.mock_genesis, args.mock_block_seconds)),
            None,
        )
    } else {
        let dir = args
            .keys_dir
            .clone()
            .ok_or_else(|| anyhow::anyhow!("release mode needs --keys-dir with ceremony keys"))?;
        let pk = groth16::pk_from_bytes(&std::fs::read(dir.join("membership.pk"))?)
            .ok_or_else(|| anyhow::anyhow!("bad proving key"))?;
        let keys = Arc::new(MembershipKeys::from_proving_key(pk));
        // The ceremony is worth nothing to anyone who will load whatever key
        // they are handed (SPEC §18.7).
        let vk_hash = args.vk_hash.as_deref().map(parse_key).transpose()?;
        let pinned = cv_core::keys::check_pin(&keys.verifier, vk_hash)?;
        tracing::info!("membership verifying key {}", hex::encode(pinned));
        let (h, hh) = (
            args.checkpoint_height
                .ok_or_else(|| anyhow::anyhow!("release mode needs --checkpoint-height"))?,
            args.checkpoint_header
                .clone()
                .ok_or_else(|| anyhow::anyhow!("release mode needs --checkpoint-header"))?,
        );
        let chain = Arc::new(SharedHeaderChain::new(parse_checkpoint(h, &hh)?));
        let sync = HeaderSync::new(
            chain.clone(),
            args.headers_api.clone(),
            reqwest::Client::new(),
        );
        (keys, chain, Some(sync))
    };
    let store: Box<dyn Store> = if args.memory || args.data_dir.is_none() {
        Box::new(MemoryStore::new())
    } else {
        let dir = args.data_dir.clone().unwrap();
        std::fs::create_dir_all(&dir)?;
        Box::new(RedbStore::open(&dir.join("log.redb"))?)
    };
    let mut log = Log::open(deployment, keys, store, headers)?;
    if let (Some(s), Some(l)) = (&args.registry_snapshot, &args.registry_leaves) {
        let snapshot = RegistrySnapshot::decode(&std::fs::read(s)?)?;
        let leaves = decode_leaves(&std::fs::read(l)?)?;
        log.add_registry(snapshot, leaves)?;
    }
    let node_key = match &args.node_key_seed {
        Some(seed) => cv_core::crypto::sig::SigningKey::from_seed(&parse_key(seed)?),
        None => cv_core::crypto::sig::SigningKey::from_seed(&persistent_seed(&log, "node-seed")?),
    };
    let mode = match args.anchor.as_str() {
        "off" => AnchorMode::Off,
        // "on" means the real thing in a real deployment, and the mock
        // anchorer under --dev (where there is no Bitcoin to reach).
        "on" if args.dev => AnchorMode::Dev,
        "on" => AnchorMode::Ots,
        "dev" if args.dev => AnchorMode::Dev,
        "dev" => anyhow::bail!("--anchor dev requires --dev"),
        "ots" => AnchorMode::Ots,
        other => anyhow::bail!("unknown anchor mode {other}"),
    };
    let calendars = if args.calendars.is_empty() {
        DEFAULT_CALENDARS.iter().map(|s| s.to_string()).collect()
    } else {
        args.calendars.clone()
    };
    let config = NodeConfig {
        solver: cv_node::solver::SolverConfig {
            enabled: args.solver,
            parallel: args.solver_parallel,
            ..Default::default()
        },
        mix: cv_node::mix::MixConfig {
            // A mix network is only as good as the number of hops in it, so
            // every node is a hop unless it opts out. The key is persisted
            // with the Log, so the node keeps the same mix key across
            // restarts and its NodeRegistration stays valid.
            secret: match (&args.mix_secret_seed, args.no_mix) {
                (_, true) => None,
                (Some(seed), _) => {
                    Some(cv_core::crypto::mix::MixSecret::from_seed(parse_key(seed)?))
                }
                (None, _) => Some(cv_core::crypto::mix::MixSecret::from_seed(persistent_seed(
                    &log, "mix-seed",
                )?)),
            },
            hold_min: Duration::from_secs(args.mix_hold_secs),
            hold_k: args.mix_hold_messages,
            hold_cap: Duration::from_secs(args.mix_hold_cap_secs),
            ..Default::default()
        },
        name: args.name,
        listen: args.listen,
        peers: args.peers,
        gossip_interval: Duration::from_secs(args.gossip_interval),
        gossip_to_registered: args.gossip_to_registered,
        anchor: AnchorConfig {
            mode,
            interval: Duration::from_secs(args.anchor_interval),
            calendars,
            min_calendars: 1,
        },
    };
    let handle = start(config, log).await?;
    println!("cv-node listening on {}", handle.url());
    println!("node key: {}", hex::encode(node_key.public_key()));
    match &handle.node.config.mix.secret {
        Some(secret) => {
            println!("mix hop:  on, mix key {}", hex::encode(secret.public()));
            println!(
                "to be chosen as a hop, the operator publishes a registration:\n  \
                 cv-client register-node --node-key {} --mix-key {} --endpoint <host:port>",
                hex::encode(node_key.public_key()),
                hex::encode(secret.public())
            );
        }
        None => println!("mix hop:  off (--no-mix)"),
    }
    let node = handle.node.clone();
    let (stop_tx, stop_rx) = tokio::sync::watch::channel(false);
    let header_task = if let Some(sync) = header_sync {
        let n = node.clone();
        Some(tokio::spawn(sync.run(
            Duration::from_secs(60),
            move || n.headers_changed(),
            stop_rx.clone(),
        )))
    } else {
        None
    };
    // Re-check header-dependent orphans as the clock advances.
    let ticker = tokio::spawn(async move {
        loop {
            tokio::time::sleep(Duration::from_secs(5)).await;
            node.headers_changed();
        }
    });
    tokio::signal::ctrl_c().await?;
    let _ = stop_tx.send(true);
    ticker.abort();
    if let Some(t) = header_task {
        t.abort();
    }
    handle.shutdown().await;
    Ok(())
}
