//! `cv-verifier` CLI: `cv-verifier --snapshot log.snap --headers headers.bin --vk membership.vk`
#![forbid(unsafe_code)]

use clap::Parser;
use cv_core::context::Deployment;
use cv_core::crypto::groth16::MembershipVerifier;
use cv_core::headers::HeaderChain;
use cv_core::snapshot::Headers;
use cv_verifier::{ChainHeaders, Config, MockHeaders, dev_verifier, render, verify};
use std::path::PathBuf;
use std::sync::Arc;

#[derive(Parser, Debug)]
#[command(
    name = "cv-verifier",
    about = "Recompute vote results from a Log snapshot and Bitcoin headers"
)]
struct Args {
    /// Snapshot file (SPEC §15), e.g. from `curl NODE/v1/snapshot`.
    #[arg(long)]
    snapshot: PathBuf,
    /// Header file (SPEC §15). Required unless --dev.
    #[arg(long)]
    headers: Option<PathBuf>,
    /// Only consider registries of these Issuers (hex, repeatable). Omit to
    /// consider every Issuer in the snapshot; each result names its own.
    #[arg(long = "issuer-key")]
    issuer_keys: Vec<String>,
    /// Authority public keys (hex, repeatable).
    /// Verifying key file (compressed arkworks encoding). Required unless --dev.
    #[arg(long)]
    vk: Option<PathBuf>,
    /// DEV MODE: mock headers up to --mock-tip and the insecure dev verifying key.
    #[arg(long)]
    dev: bool,
    #[arg(long, default_value_t = 1_000_000)]
    mock_tip: u32,
    /// Only this vote (hex id).
    #[arg(long)]
    vote: Option<String>,
    /// Print the report as JSON.
    #[arg(long)]
    json: bool,
    /// Write the dev verifying key to this file and exit.
    #[arg(long)]
    export_dev_vk: Option<PathBuf>,
}

fn key(s: &str) -> anyhow::Result<[u8; 32]> {
    hex::decode(s)?
        .try_into()
        .map_err(|_| anyhow::anyhow!("expected 32 bytes of hex"))
}

fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    if let Some(p) = &args.export_dev_vk {
        std::fs::write(p, cv_core::crypto::groth16::vk_to_bytes(&dev_verifier().vk))?;
        println!(
            "dev verifying key written to {} (INSECURE, dev only)",
            p.display()
        );
        return Ok(());
    }
    let deployment = Deployment {
        issuer_keys: args
            .issuer_keys
            .iter()
            .map(|k| key(k))
            .collect::<Result<_, _>>()?,
        dev_mode: args.dev,
    };
    let verifier = match (&args.vk, args.dev) {
        (Some(p), _) => MembershipVerifier::from_bytes(&std::fs::read(p)?)
            .ok_or_else(|| anyhow::anyhow!("bad verifying key"))?,
        (None, true) => dev_verifier(),
        (None, false) => anyhow::bail!("--vk is required outside dev mode"),
    };
    let headers: Arc<dyn Headers> = match (&args.headers, args.dev) {
        (Some(p), _) => Arc::new(ChainHeaders(HeaderChain::from_file(&std::fs::read(p)?, 0)?)),
        (None, true) => Arc::new(MockHeaders { tip: args.mock_tip }),
        (None, false) => anyhow::bail!("--headers is required outside dev mode"),
    };
    let only = args.vote.as_deref().map(key).transpose()?;
    let snapshot = std::fs::read(&args.snapshot)?;
    let report = verify(
        &snapshot,
        headers,
        Config {
            deployment,
            verifier: Arc::new(verifier),
        },
        only,
    )
    .map_err(|e| anyhow::anyhow!(e))?;
    if args.json {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        print!("{}", render(&report));
    }
    Ok(())
}
