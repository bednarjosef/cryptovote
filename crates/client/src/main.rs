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
    /// Route submissions over Tor. Failure to bootstrap is reported in the
    /// privacy line, never silently ignored.
    #[arg(long)]
    tor: bool,
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
        /// Key parties every ballot in the derived vote must encrypt to.
        /// Ignored (and forced to 0) under `--secrecy none`; under
        /// `keyparties` a ballot declaring fewer is invalid, so set it no
        /// higher than the number of parties you expect to volunteer.
        #[arg(long, default_value_t = 1)]
        min_parties: u32,
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
    /// Volunteer as a key party for a `secrecy: keyparties` vote, so that its
    /// ballots cannot be read before the deadline unless you collude too.
    /// Anyone eligible to vote in it may do this; the Issuer is not asked and
    /// does not learn of it. One per person per vote.
    ///
    /// Register with `--tor`: the item proves membership in zero knowledge and
    /// names nobody, but a plain submission still shows a node your address.
    RegisterKeyParty {
        #[arg(long)]
        vote: String,
        /// Sequential squarings before anyone can force your share open. Must
        /// be at least `required_delay(close_block - anchor_height)` or clients
        /// will not select you (relaxed under --dev).
        #[arg(long)]
        delay_t: u64,
    },
    /// Publish your key-party share after a vote closes, so the result can be
    /// counted without anyone having to force your commitment open.
    PublishShare {
        #[arg(long)]
        vote: String,
        /// Your key party's content id, printed by `register-key-party`.
        #[arg(long)]
        keyparty: String,
    },
    /// List initiatives.
    Initiatives,
    /// Support an initiative.
    Support {
        #[arg(long)]
        initiative: String,
    },
}

/// A mix client honouring `--tor`. Bootstrap failure is carried in the
/// returned client's `tor_error` and shows up in every `PrivacyLevel`, so a
/// submission never silently loses the protection the user asked for.
async fn mix_client(
    node: &str,
    dev: bool,
    use_tor: bool,
    pc: &ParticipantClient,
) -> cv_client::mix::MixClient {
    #[cfg(feature = "tor")]
    let tor = if use_tor {
        match cv_client::tor::TorTransport::bootstrap(Duration::from_secs(60)).await {
            Ok(t) => cv_client::mix::TorSetup::Ready(t),
            Err(e) => cv_client::mix::TorSetup::Failed(e.to_string()),
        }
    } else {
        cv_client::mix::TorSetup::Disabled
    };
    #[cfg(not(feature = "tor"))]
    let tor = if use_tor {
        cv_client::mix::TorSetup::Failed("built without the tor feature".into())
    } else {
        cv_client::mix::TorSetup::Disabled
    };
    cv_client::mix::MixClient {
        dev,
        headers: pc.headers.clone(),
        ..cv_client::mix::MixClient::new(NodeClient::new(node.to_string()), tor)
    }
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
                let mc = mix_client(&args.node, args.dev, args.tor, &pc).await;
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
        Command::RegisterKeyParty { vote, delay_t } => {
            let vid = id(&vote)?;
            let mc = mix_client(&args.node, args.dev, args.tor, &pc).await;
            let (kp, privacy) = pc
                .register_keyparty(&mc, &mut device, &vid, delay_t)
                .await?;
            device.save(&args.device)?;
            println!("key party {}", hex::encode(kp.content_id()));
            println!("privacy:   {privacy}");
            println!(
                "Publish your share after close with:\n  \
                 cv-client publish-share --vote {} --keyparty {}",
                vote,
                hex::encode(kp.content_id())
            );
        }
        Command::PublishShare { vote, keyparty } => {
            let vid = id(&vote)?;
            let kpid = id(&keyparty)?;
            let mc = mix_client(&args.node, args.dev, args.tor, &pc).await;
            let privacy = pc.publish_share(&mc, &mut device, &vid, &kpid).await?;
            device.save(&args.device)?;
            println!("share published; privacy: {privacy}");
        }
        Command::Initiative {
            text,
            issuer,
            deadline_block,
            secrecy,
            min_parties,
        } => {
            let secrecy = match secrecy.as_str() {
                "none" => Secrecy::None,
                "keyparties" => Secrecy::KeyParties,
                s => anyhow::bail!("unknown secrecy {s}"),
            };
            let min_parties = match secrecy {
                Secrecy::None => 0,
                Secrecy::KeyParties => min_parties,
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
                .create_initiative(
                    &device,
                    &issuer_key,
                    &root,
                    text,
                    deadline_block,
                    secrecy,
                    min_parties,
                )
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
