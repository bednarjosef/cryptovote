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
    /// Bitcoin headers (SPEC §15 file) used to check that an anchor covering
    /// your ballot is really in Bitcoin. Without it, a confirmation only
    /// proves your ballot is in the anchor's Merkle root.
    #[arg(long)]
    headers: Option<PathBuf>,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Create a new device secret.
    Init,
    /// Enroll with an Issuer (`--issuer` is its base URL).
    Enroll {
        #[arg(long)]
        issuer: String,
        /// Credential for that Issuer's verification backend (any non-empty
        /// string under the dev mock backend).
        #[arg(long)]
        credential: String,
    },
    /// List the registries (Issuers) the node carries.
    Registries,
    /// List votes on the node.
    Votes,
    /// Cast a ballot and wait until it is anchored. Goes through the mix by
    /// default (three hops, two paths), falling back to direct submission if
    /// no hops are available — the privacy actually achieved is printed.
    Vote {
        #[arg(long)]
        vote: String,
        #[arg(long)]
        option: u8,
        #[arg(long, default_value_t = 120)]
        wait_secs: u64,
        /// Submit straight to the node instead of through the mix. Faster,
        /// and it shows that node your IP next to your ballot.
        #[arg(long)]
        no_mix: bool,
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
        /// Issuer whose registry defines the electorate (hex key). Defaults
        /// to the node's newest registry.
        #[arg(long)]
        issuer: Option<String>,
        #[arg(long)]
        deadline_block: u32,
        #[arg(long, default_value = "none")]
        secrecy: String,
    },
    /// Publish a registration for a node you run, so other people's clients
    /// can pick it as a mix hop. Anyone enrolled with any Issuer can do this;
    /// the Issuer is not asked and does not learn of it. One per person per
    /// electorate.
    RegisterNode {
        /// The node's Ed25519 key, printed by `cv-node` at startup.
        #[arg(long)]
        node_key: String,
        /// The node's X25519 mix key, printed by `cv-node` at startup.
        #[arg(long)]
        mix_key: String,
        /// "host:port" or "xxx.onion:port" clients can reach it on.
        #[arg(long)]
        endpoint: String,
        #[arg(long, default_value = "unnamed")]
        operator: String,
        /// ISO 3166-1 alpha-2, self-declared; used only for hop diversity.
        #[arg(long, default_value = "ZZ")]
        country: String,
        #[arg(long, default_value_t = 0)]
        asn: u32,
        /// Which electorate to register in (hex issuer key). Defaults to the
        /// node's newest registry.
        #[arg(long)]
        issuer: Option<String>,
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
    let headers: Option<Arc<dyn cv_core::snapshot::Headers>> = match &args.headers {
        Some(p) => Some(Arc::new(cv_client::evidence::FileHeaders(
            cv_core::headers::HeaderChain::from_file(&std::fs::read(p)?, 0)?,
        ))),
        None => {
            if !args.dev {
                eprintln!(
                    "note: no --headers, so a confirmation proves inclusion in an anchor's \
                     Merkle root but not that the root is in Bitcoin"
                );
            }
            None
        }
    };
    let mut device = Device::load(&args.device)?;
    let mut pc = ParticipantClient::new(NodeClient::new(args.node.clone()), keys);
    pc.dev = args.dev;
    pc.headers = headers;
    match args.command {
        Command::Init => unreachable!(),
        Command::Enroll { issuer, credential } => {
            let r = pc.enroll(&mut device, &issuer, &credential).await?;
            device.save(&args.device)?;
            println!(
                "enrolled with issuer {}: index {} epoch {} root {} replaced {}",
                r.issuer_key, r.index, r.epoch, r.root, r.replaced
            );
        }
        Command::Registries => {
            for r in pc.node.registries().await? {
                println!(
                    "issuer {} root {} epoch {} leaves {}",
                    r.issuer_key, r.root, r.epoch, r.leaf_count
                );
            }
        }
        Command::Votes => {
            for v in pc.node.votes().await? {
                println!(
                    "{} [{}] issuer={} {} options={:?} open={} close={} ballots={}",
                    v.vote_id,
                    v.secrecy,
                    v.issuer_key,
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
            no_mix,
        } => {
            let vid = id(&vote)?;
            let ballot = if no_mix {
                let (ballot, resp) = pc.cast(&device, &vid, option).await?;
                println!("submitted directly: {resp:?}");
                ballot
            } else {
                // Through the mix, which retries on fresh paths until the
                // anchor checks out (or the window runs out).
                let mc = cv_client::mix::MixClient {
                    dev: args.dev,
                    headers: pc.headers.clone(),
                    ..cv_client::mix::MixClient::new(
                        NodeClient::new(args.node.clone()),
                        cv_client::mix::TorSetup::Disabled,
                    )
                };
                let report = mc
                    .cast_with_retry(
                        &mut device,
                        &pc.keys,
                        &vid,
                        option,
                        Duration::from_secs(wait_secs),
                        3,
                    )
                    .await?;
                device.save(&args.device)?;
                println!(
                    "submitted through the mix: {} (attempt {})",
                    report.privacy, report.attempts
                );
                report.ballot
            };
            println!("nullifier: {}", hex::encode(fr_to_bytes(&ballot.nullifier)));
            println!("receipt:   {}", ParticipantClient::receipt(&ballot));
            match pc
                .confirm_evidence(&ballot, Duration::from_secs(wait_secs))
                .await?
            {
                Some(e) => {
                    // Checked here, not taken from the node.
                    println!(
                        "anchored at height {} in anchor {} ({:?})",
                        e.height,
                        hex::encode(e.anchor_id),
                        e.check
                    );
                }
                None => println!(
                    "no checkable anchor within {wait_secs}s — your ballot is not in yet; \
                     keep the device on, it will resend (identical bytes, so resending is safe)"
                ),
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
                Some(r) => {
                    // Whose electorate this result is over (whitepaper §5).
                    println!("issuer: {}", r.issuer_key);
                    println!("{}", serde_json::to_string_pretty(&r)?);
                }
                None => println!("unknown vote"),
            }
        }
        Command::Initiative {
            text,
            issuer,
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
                .filter(|r| issuer.as_ref().is_none_or(|k| &r.issuer_key == k))
                .max_by_key(|r| r.epoch)
                .ok_or_else(|| anyhow::anyhow!("node has no registry for that issuer"))?;
            let issuer_key = id(&latest.issuer_key)?;
            let root =
                fr_from_canonical(&id(&latest.root)?).ok_or_else(|| anyhow::anyhow!("bad root"))?;
            let (i, resp) = pc
                .create_initiative(&device, &issuer_key, &root, text, deadline_block, secrecy)
                .await?;
            println!(
                "initiative {} (issuer {}): {resp:?}",
                hex::encode(i.content_id()),
                latest.issuer_key
            );
        }
        Command::RegisterNode {
            node_key,
            mix_key,
            endpoint,
            operator,
            country,
            asn,
            issuer,
        } => {
            let regs = pc.node.registries().await?;
            let latest = regs
                .iter()
                .filter(|r| issuer.as_ref().is_none_or(|k| &r.issuer_key == k))
                .max_by_key(|r| r.epoch)
                .ok_or_else(|| anyhow::anyhow!("node has no registry for that issuer"))?;
            let country: [u8; 2] = country
                .as_bytes()
                .try_into()
                .map_err(|_| anyhow::anyhow!("country must be two letters"))?;
            let (reg, resp) = pc
                .register_node(
                    &device,
                    &id(&latest.issuer_key)?,
                    &fr_from_canonical(&id(&latest.root)?)
                        .ok_or_else(|| anyhow::anyhow!("bad root"))?,
                    id(&node_key)?,
                    id(&mix_key)?,
                    endpoint,
                    operator,
                    country,
                    asn,
                )
                .await?;
            println!(
                "registered node {} in issuer {}'s electorate: {resp:?}",
                hex::encode(reg.content_id()),
                latest.issuer_key
            );
        }
        Command::Initiatives => {
            for i in pc.initiatives().await? {
                println!(
                    "{} issuer={} supports={}/{} deadline={} derived_vote={:?} {}",
                    i.initiative_id,
                    i.issuer_key,
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
