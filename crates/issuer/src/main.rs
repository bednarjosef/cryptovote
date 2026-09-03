//! `cv-issuer` binary: development issuer with the mock eID backend.
#![forbid(unsafe_code)]

use clap::Parser;
use cv_issuer::{Issuer, MockEid};
use std::net::SocketAddr;
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(
    name = "cv-issuer",
    about = "CryptoVote issuer (development: mock eID backend)"
)]
struct Args {
    #[arg(long, default_value = "127.0.0.1:8450")]
    listen: SocketAddr,
    /// State file (JSON) to persist enrollments and the signing key.
    #[arg(long)]
    state: Option<PathBuf>,
    /// Seed of the issuer's Ed25519 key (hex, 32 bytes). Random if omitted and no state file exists.
    #[arg(long)]
    key_seed: Option<String>,
    /// Nodes to publish the registry to (repeatable).
    #[arg(long = "node")]
    nodes: Vec<String>,
    /// Required: acknowledges that the mock eID backend accepts anyone.
    #[arg(long)]
    dev: bool,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env().add_directive("info".parse()?),
        )
        .init();
    let args = Args::parse();
    if !args.dev {
        anyhow::bail!("only the mock eID backend exists; run with --dev (development only)");
    }
    let issuer = match (&args.state, &args.key_seed) {
        (Some(p), _) if p.exists() => Issuer::load(p, Box::new(MockEid))?,
        (_, Some(seed)) => {
            let seed: [u8; 32] = hex::decode(seed)?
                .try_into()
                .map_err(|_| anyhow::anyhow!("seed must be 32 bytes"))?;
            Issuer::dev(seed)
        }
        _ => {
            let mut seed = [0u8; 32];
            use rand::RngCore;
            rand::rngs::OsRng.fill_bytes(&mut seed);
            Issuer::dev(seed)
        }
    };
    println!("issuer public key: {}", hex::encode(issuer.public_key()));
    let handle = cv_issuer::server::start(issuer, args.listen, args.nodes, args.state).await?;
    println!("cv-issuer listening on {}", handle.url());
    tokio::signal::ctrl_c().await?;
    handle.shutdown();
    Ok(())
}
