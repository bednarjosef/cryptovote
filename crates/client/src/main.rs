//! `cv-client` CLI wrapper around the participant library (for testing).
#![forbid(unsafe_code)]

use clap::{Parser, Subcommand};
use cv_client::device::Device;
use cv_client::light::NodeClient;
use cv_client::participant::ParticipantClient;
use cv_core::crypto::field::{fr_from_canonical, fr_to_bytes};
use cv_core::crypto::groth16;
use cv_core::items::Secrecy;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

#[derive(Parser, Debug)]
#[command(name = "cv-client", about = "CryptoVote participant CLI")]
struct Args {
    /// Device file holding the secret and enrollment.
    #[arg(long, default_value = "device.json")]
    device: PathBuf,
    /// Node base URL.
    #[arg(long, default_value = "http://127.0.0.1:8440")]
    node: String,
    /// Dev mode: use the insecure development proving keys.
    #[arg(long)]
    dev: bool,
    /// Release: directory with `membership.pk`.
    #[arg(long)]
    keys_dir: Option<PathBuf>,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Create a new device secret.
    Init,
    /// Enroll with an issuer.
    Enroll {
        #[arg(long)]
        issuer: String,
        #[arg(long)]
        eid: String,
    },
    /// List votes on the node.
    Votes,
    /// Cast a ballot and wait until it is anchored.
    Vote {
        #[arg(long)]
        vote: String,
        #[arg(long)]
        option: u8,
        #[arg(long, default_value_t = 120)]
        wait_secs: u64,
    },
    /// Show the status of this device's ballot in a vote.
    Status {
        #[arg(long)]
        vote: String,
    },
    /// Show a vote's result as the node computes it.
    Result {
        #[arg(long)]
        vote: String,
    },
    /// Publish an initiative.
    Initiative {
        #[arg(long)]
        text: String,
        #[arg(long)]
        deadline_block: u32,
        #[arg(long, default_value = "none")]
        secrecy: String,
    },
    /// List initiatives.
    Initiatives,
    /// Support an initiative.
    Support {
        #[arg(long)]
        initiative: String,
    },
}

fn id(hex_str: &str) -> anyhow::Result<[u8; 32]> {
    hex::decode(hex_str)?
        .try_into()
        .map_err(|_| anyhow::anyhow!("expected 32-byte hex id"))
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    if let Command::Init = args.command {
        let d = Device::generate(&mut rand::rngs::OsRng);
        d.save(&args.device)?;
        println!(
            "device created at {} (commitment {})",
            args.device.display(),
            hex::encode(fr_to_bytes(&d.commitment()))
        );
        return Ok(());
    }
    let keys = if args.dev {
        eprintln!("WARNING: dev mode — insecure development proving keys");
        Arc::new(groth16::setup(
            &mut <rand_chacha::ChaCha20Rng as rand::SeedableRng>::from_seed(
                groth16::DEV_SETUP_SEED,
            ),
        ))
    } else {
        let dir = args
            .keys_dir
            .clone()
            .ok_or_else(|| anyhow::anyhow!("need --dev or --keys-dir"))?;
        let pk = groth16::pk_from_bytes(&std::fs::read(dir.join("membership.pk"))?)
            .ok_or_else(|| anyhow::anyhow!("bad proving key"))?;
        Arc::new(groth16::MembershipKeys::from_proving_key(pk))
    };
    let mut device = Device::load(&args.device)?;
    let pc = ParticipantClient::new(NodeClient::new(args.node.clone()), keys);
    match args.command {
        Command::Init => unreachable!(),
        Command::Enroll { issuer, eid } => {
            let r = pc.enroll(&mut device, &issuer, &eid).await?;
            device.save(&args.device)?;
            println!(
                "enrolled: index {} epoch {} root {} replaced {}",
                r.index, r.epoch, r.root, r.replaced
            );
        }
        Command::Votes => {
            for v in pc.node.votes().await? {
                println!(
                    "{} [{}] {} options={:?} open={} close={} ballots={}",
                    v.vote_id,
                    v.secrecy,
                    v.question,
                    v.options,
                    v.open_block,
                    v.close_block,
                    v.ballots
                );
            }
        }
        Command::Vote {
            vote,
            option,
            wait_secs,
        } => {
            let vid = id(&vote)?;
            let (ballot, resp) = pc.cast(&device, &vid, option).await?;
            println!("submitted: {resp:?}");
            println!("nullifier: {}", hex::encode(fr_to_bytes(&ballot.nullifier)));
            println!("receipt:   {}", ParticipantClient::receipt(&ballot));
            match pc
                .confirm(&vid, &ballot.nullifier, Duration::from_secs(wait_secs))
                .await?
            {
                Some(h) => println!("anchored at height {h}"),
                None => {
                    println!("not anchored within {wait_secs}s (keep the device on; it will retry)")
                }
            }
        }
        Command::Status { vote } => {
            let vid = id(&vote)?;
            let vd = pc
                .node
                .vote(&vid)
                .await?
                .ok_or_else(|| anyhow::anyhow!("unknown vote"))?;
            let n = cv_core::identity::nullifier(
                &device.secret,
                cv_core::identity::TAG_BALLOT,
                &cv_core::crypto::field::fr_mod(&vid),
            );
            let _ = fr_from_canonical(&fr_to_bytes(&vd.registry_root));
            for s in pc.node.ballot_status(&vid, &n).await? {
                println!(
                    "ballot {} anchored_height={:?}",
                    s.content_id, s.anchored_height
                );
            }
        }
        Command::Result { vote } => {
            let vid = id(&vote)?;
            match pc.result(&vid).await? {
                Some(r) => println!("{}", serde_json::to_string_pretty(&r)?),
                None => println!("unknown vote"),
            }
        }
        Command::Initiative {
            text,
            deadline_block,
            secrecy,
        } => {
            let secrecy = match secrecy.as_str() {
                "none" => Secrecy::None,
                "keyparties" => Secrecy::KeyParties,
                s => anyhow::bail!("unknown secrecy {s}"),
            };
            let regs = pc.node.registries().await?;
            let latest = regs
                .iter()
                .max_by_key(|r| r.epoch)
                .ok_or_else(|| anyhow::anyhow!("node has no registry"))?;
            let root =
                fr_from_canonical(&id(&latest.root)?).ok_or_else(|| anyhow::anyhow!("bad root"))?;
            let (i, resp) = pc
                .create_initiative(&device, &root, text, deadline_block, secrecy)
                .await?;
            println!("initiative {}: {resp:?}", hex::encode(i.content_id()));
        }
        Command::Initiatives => {
            for i in pc.initiatives().await? {
                println!(
                    "{} supports={}/{} deadline={} derived_vote={:?} {}",
                    i.initiative_id,
                    i.supports,
                    i.threshold_n,
                    i.support_deadline_block,
                    i.derived_vote_id,
                    i.text
                );
            }
        }
        Command::Support { initiative } => {
            let (s, resp) = pc.support(&device, &id(&initiative)?).await?;
            println!("support {}: {resp:?}", hex::encode(s.content_id()));
        }
    }
    Ok(())
}
