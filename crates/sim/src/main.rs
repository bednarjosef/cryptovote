//! `cv-sim`: end-to-end simulation on one machine (dev mode).
#![forbid(unsafe_code)]

use clap::Parser;
use cv_sim::{SimConfig, render, run};
use std::time::Duration;

#[derive(Parser, Debug)]
#[command(
    name = "cv-sim",
    about = "Simulate a full vote and initiative end to end (dev mode)"
)]
struct Args {
    #[arg(long, default_value_t = 20)]
    participants: usize,
    #[arg(long, default_value_t = 5)]
    nodes: usize,
    #[arg(long, default_value_t = 1)]
    seed: u64,
    /// Submit ballots directly instead of through the mix.
    #[arg(long)]
    no_mix: bool,
    #[arg(long, default_value_t = 30)]
    confirm_window_secs: u64,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env().add_directive("warn".parse()?),
        )
        .init();
    let a = Args::parse();
    let report = run(SimConfig {
        participants: a.participants,
        nodes: a.nodes,
        seed: a.seed,
        mix: !a.no_mix,
        confirm_window: Duration::from_secs(a.confirm_window_secs),
    })
    .await?;
    print!("{}", render(&report));
    if !report.ok {
        std::process::exit(1);
    }
    Ok(())
}
