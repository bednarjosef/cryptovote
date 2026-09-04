//! `cv-ceremony` — run and check the Groth16 parameter ceremony (SPEC §18).
//!
//! A ceremony is a directory of files. Each contributor takes the directory,
//! adds one accumulator and one step record, and passes it on; anyone can
//! `verify` it at any point, and `finalize` turns a finished one into the
//! `membership.pk` / `membership.vk` a release deployment loads.
#![forbid(unsafe_code)]

use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand};
use cv_ceremony::phase1::{self, Accumulator};
use cv_ceremony::phase2::{self, Phase2};
use cv_ceremony::transcript::{
    KIND_PHASE1_ACC, KIND_PHASE1_STEP, KIND_PHASE2_PARAMS, KIND_PHASE2_STEP, Step, decode, encode,
};
use cv_ceremony::{Report, Transcript, self_test};
use cv_crypto::circuit::MembershipCircuit;
use cv_crypto::groth16::{pk_to_bytes, vk_to_bytes};
use cv_crypto::sig::SigningKey;
use rand::{RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;
use std::path::{Path, PathBuf};

#[derive(Parser, Debug)]
#[command(
    name = "cv-ceremony",
    about = "Run and check the Groth16 parameter ceremony for the membership circuit"
)]
struct Args {
    /// The ceremony directory.
    #[arg(long, default_value = "ceremony")]
    dir: PathBuf,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Start a ceremony: write the first accumulator, which holds no secret.
    New {
        /// Degree of phase 1. Defaults to the smallest that fits the
        /// membership circuit; larger also works and serves bigger circuits.
        #[arg(long)]
        degree: Option<usize>,
    },
    /// Add a contribution to whichever phase the directory is in.
    Contribute {
        /// Name to publish alongside the step. Anonymity is allowed; a name
        /// is what makes "one of them was honest" a claim someone owns.
        #[arg(long, default_value = "")]
        name: String,
        /// Extra entropy of your own, mixed with the operating system's.
        /// Neither source is trusted alone.
        #[arg(long)]
        entropy: Option<String>,
        /// 32-byte hex seed of an Ed25519 key to attest with.
        #[arg(long)]
        sign_seed: Option<String>,
    },
    /// Close a phase with a public beacon: a value nobody could predict when
    /// the ceremony began, so the parameters cannot have been steered.
    Beacon {
        /// Bitcoin block height whose hash is the beacon.
        #[arg(long)]
        block: Option<u32>,
        /// That block's hash, 32 bytes of hex.
        #[arg(long)]
        block_hash: Option<String>,
        /// Any other public value, if you are not using Bitcoin.
        #[arg(long)]
        source: Option<String>,
    },
    /// Move from phase 1 to phase 2: fix the circuit these parameters serve.
    Prepare,
    /// Replay the whole directory and report what it establishes.
    Verify {
        /// Fail unless the finished verifying key hashes to this.
        #[arg(long)]
        expect_vk_hash: Option<String>,
    },
    /// Replay, prove and verify a real statement with the result, and write
    /// `membership.pk` and `membership.vk`.
    Finalize {
        #[arg(long)]
        out: PathBuf,
    },
}

fn hex32(s: &str) -> Result<[u8; 32]> {
    hex::decode(s)?
        .try_into()
        .map_err(|_| anyhow::anyhow!("expected 32 bytes of hex"))
}

fn p1_acc(dir: &Path, i: usize) -> PathBuf {
    dir.join(format!("p1-{i:03}.acc"))
}
fn p1_step(dir: &Path, i: usize) -> PathBuf {
    dir.join(format!("p1-{i:03}.step"))
}
fn p2_params(dir: &Path, i: usize) -> PathBuf {
    dir.join(format!("p2-{i:03}.params"))
}
fn p2_step(dir: &Path, i: usize) -> PathBuf {
    dir.join(format!("p2-{i:03}.step"))
}

/// Read the directory into a transcript, stopping at the first gap.
fn load(dir: &Path) -> Result<Transcript> {
    let mut t = Transcript::default();
    let mut i = 0;
    while let Ok(bytes) = std::fs::read(p1_acc(dir, i)) {
        if i > 0 {
            t.phase1_steps.push(
                std::fs::read(p1_step(dir, i))
                    .with_context(|| format!("{} is missing", p1_step(dir, i).display()))?,
            );
        }
        t.phase1.push(bytes);
        i += 1;
    }
    if t.phase1.is_empty() {
        bail!("{} holds no ceremony (run `new` first)", dir.display());
    }
    let mut i = 0;
    while let Ok(bytes) = std::fs::read(p2_params(dir, i)) {
        if i > 0 {
            t.phase2_steps.push(
                std::fs::read(p2_step(dir, i))
                    .with_context(|| format!("{} is missing", p2_step(dir, i).display()))?,
            );
        }
        t.phase2.push(bytes);
        i += 1;
    }
    Ok(t)
}

/// Randomness for a contribution: the operating system's, mixed with
/// whatever the contributor supplies. A ceremony is only as good as this —
/// an RNG someone else can predict is the same as no contribution at all.
fn contribution_rng(extra: Option<&str>) -> ChaCha20Rng {
    let mut os = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut os);
    let mut h = blake3::Hasher::new_derive_key("cryptovote/v1/ceremony/entropy");
    h.update(&os);
    h.update(extra.unwrap_or_default().as_bytes());
    h.update(
        &std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or_default()
            .to_le_bytes(),
    );
    ChaCha20Rng::from_seed(*h.finalize().as_bytes())
}

fn print_report(r: &Report) {
    println!("degree {}", r.degree);
    match r.circuit_digest {
        Some(c) => println!("circuit {}", hex::encode(c)),
        None => println!("circuit not fixed yet (phase 2 has not started)"),
    }
    for s in &r.steps {
        let kind = match &s.beacon {
            Some(b) => format!("beacon   {}", String::from_utf8_lossy(b)),
            None => format!(
                "contribution {}",
                if s.name.is_empty() {
                    "(anonymous)"
                } else {
                    &s.name
                }
            ),
        };
        let who = match s.attested_by {
            Some(k) => format!("  attested by {}", hex::encode(&k[..8])),
            None => String::new(),
        };
        println!(
            "  phase {} step {:>3}  {}{}  -> {}",
            s.phase,
            s.index,
            kind,
            who,
            hex::encode(&s.response[..8])
        );
    }
    match r.vk_hash {
        Some(h) => println!("verifying key BLAKE3 {}", hex::encode(h)),
        None => println!("no verifying key yet"),
    }
    let (a, b) = (r.secret_contributions(1), r.secret_contributions(2));
    println!(
        "{a} secret contribution(s) to phase 1, {b} to phase 2.\n\
         These parameters are forgeable only if every contributor to a phase kept\n\
         its secret and they all colluded. Beacon steps add unpredictability, not\n\
         secrecy, and do not count."
    );
    match r.usable() {
        Ok(()) => {}
        Err(e) => println!("NOT USABLE: {e}"),
    }
}

fn main() -> Result<()> {
    let args = Args::parse();
    let dir = &args.dir;
    match args.command {
        Command::New { degree } => {
            let need = phase2::domain_size_for(MembershipCircuit::blank())
                .context("the membership circuit has no evaluation domain")?;
            let degree = degree.unwrap_or(need);
            if !degree.is_power_of_two() || degree < need {
                bail!("degree must be a power of two and at least {need}");
            }
            std::fs::create_dir_all(dir)?;
            if p1_acc(dir, 0).exists() {
                bail!("{} already holds a ceremony", dir.display());
            }
            let acc = Accumulator::new(degree);
            std::fs::write(p1_acc(dir, 0), encode(KIND_PHASE1_ACC, &acc))?;
            println!(
                "started a ceremony of degree {degree} in {}\n\
                 the membership circuit needs {need}\n\
                 the first accumulator is all generators: it holds no secret, which is\n\
                 why it does not have to be trusted",
                dir.display()
            );
        }

        Command::Contribute {
            name,
            entropy,
            sign_seed,
        } => {
            let t = load(dir)?;
            let mut rng = contribution_rng(entropy.as_deref());
            if t.phase2.is_empty() {
                let i = t.phase1.len();
                let prev: Accumulator = decode(KIND_PHASE1_ACC, &t.phase1[i - 1])?;
                let challenge = prev.digest();
                let (next, pok) = phase1::contribute(&prev, &challenge, &mut rng);
                phase1::verify(&prev, &next, &pok, &challenge)
                    .context("the contribution this machine just made does not verify")?;
                let mut step = Step::new(1, (i - 1) as u32, challenge, next.digest(), pok);
                step.name = name;
                if let Some(seed) = &sign_seed {
                    step.sign(&SigningKey::from_seed(&hex32(seed)?));
                }
                std::fs::write(p1_acc(dir, i), encode(KIND_PHASE1_ACC, &next))?;
                std::fs::write(p1_step(dir, i), encode(KIND_PHASE1_STEP, &step))?;
                println!(
                    "phase 1 contribution {} written\nresponse {}",
                    i - 1,
                    hex::encode(next.digest())
                );
            } else {
                let i = t.phase2.len();
                let prev: Phase2 = decode(KIND_PHASE2_PARAMS, &t.phase2[i - 1])?;
                let challenge = prev.digest();
                let (next, pok) = phase2::contribute(&prev, &challenge, &mut rng);
                phase2::verify(&prev, &next, &pok, &challenge)
                    .context("the contribution this machine just made does not verify")?;
                let mut step = Step::new(2, (i - 1) as u32, challenge, next.digest(), pok);
                step.name = name;
                if let Some(seed) = &sign_seed {
                    step.sign(&SigningKey::from_seed(&hex32(seed)?));
                }
                std::fs::write(p2_params(dir, i), encode(KIND_PHASE2_PARAMS, &next))?;
                std::fs::write(p2_step(dir, i), encode(KIND_PHASE2_STEP, &step))?;
                println!(
                    "phase 2 contribution {} written\nresponse {}",
                    i - 1,
                    hex::encode(next.digest())
                );
            }
            println!(
                "the secret this machine used is gone from memory when the process exits;\n\
                 nothing wrote it to disk. Whether it survives anywhere else — swap, a VM\n\
                 snapshot, a hypervisor — is the part nobody can check for you."
            );
        }

        Command::Beacon {
            block,
            block_hash,
            source,
        } => {
            let source = match (block, &block_hash, &source) {
                (Some(h), Some(hash), None) => {
                    let _ = hex32(hash)?;
                    format!("bitcoin {h} {hash}")
                }
                (None, None, Some(s)) => s.clone(),
                _ => bail!("give either --block with --block-hash, or --source"),
            };
            let t = load(dir)?;
            if t.phase2.is_empty() {
                let i = t.phase1.len();
                let prev: Accumulator = decode(KIND_PHASE1_ACC, &t.phase1[i - 1])?;
                let challenge = prev.digest();
                let (next, pok) = phase1::contribute_beacon(&prev, &challenge, source.as_bytes());
                let mut step = Step::new(1, (i - 1) as u32, challenge, next.digest(), pok);
                step.beacon = source.as_bytes().to_vec();
                std::fs::write(p1_acc(dir, i), encode(KIND_PHASE1_ACC, &next))?;
                std::fs::write(p1_step(dir, i), encode(KIND_PHASE1_STEP, &step))?;
            } else {
                let i = t.phase2.len();
                let prev: Phase2 = decode(KIND_PHASE2_PARAMS, &t.phase2[i - 1])?;
                let challenge = prev.digest();
                let (next, pok) = phase2::contribute_beacon(&prev, &challenge, source.as_bytes());
                let mut step = Step::new(2, (i - 1) as u32, challenge, next.digest(), pok);
                step.beacon = source.as_bytes().to_vec();
                std::fs::write(p2_params(dir, i), encode(KIND_PHASE2_PARAMS, &next))?;
                std::fs::write(p2_step(dir, i), encode(KIND_PHASE2_STEP, &step))?;
            }
            println!(
                "beacon step written from \"{source}\"\n\
                 anyone can recompute this step exactly; it adds no secret, only the\n\
                 guarantee that the final parameters were not chosen"
            );
        }

        Command::Prepare => {
            let t = load(dir)?;
            if !t.phase2.is_empty() {
                bail!("phase 2 has already started");
            }
            if t.phase1.len() < 2 {
                bail!("phase 1 has no contributions yet");
            }
            let acc: Accumulator = decode(KIND_PHASE1_ACC, t.phase1.last().unwrap())?;
            let params = phase2::prepare(&acc, MembershipCircuit::blank())?;
            std::fs::write(p2_params(dir, 0), encode(KIND_PHASE2_PARAMS, &params))?;
            println!(
                "phase 2 started for the membership circuit\ncircuit {}\n\
                 this step has no secret in it: every verifier recomputes it from the\n\
                 phase 1 result and the circuit, and compares",
                hex::encode(params.circuit_digest)
            );
        }

        Command::Verify { expect_vk_hash } => {
            let t = load(dir)?;
            let (_, report) = t.replay(MembershipCircuit::blank())?;
            print_report(&report);
            if let Some(h) = expect_vk_hash {
                if report.vk_hash != Some(hex32(&h)?) {
                    bail!("the verifying key is NOT the one expected");
                }
                println!("the verifying key is the one expected");
            }
        }

        Command::Finalize { out } => {
            let t = load(dir)?;
            let (keys, report) = t.replay(MembershipCircuit::blank())?;
            report.usable()?;
            let keys = keys.expect("a usable report has keys");
            self_test(&keys)?;
            std::fs::create_dir_all(&out)?;
            std::fs::write(out.join("membership.pk"), pk_to_bytes(&keys.pk))?;
            std::fs::write(out.join("membership.vk"), vk_to_bytes(keys.vk()))?;
            print_report(&report);
            let h = report.vk_hash.expect("a usable report has a key");
            let bytes = h
                .iter()
                .map(|b| format!("0x{b:02x}"))
                .collect::<Vec<_>>()
                .chunks(8)
                .map(|c| c.join(", "))
                .collect::<Vec<_>>()
                .join(",\n        ");
            println!(
                "\nself-test passed: these keys proved and verified a real membership\n\
                 statement, and refused a false one.\n\n\
                 written to {}\n\n\
                 Now pin the key in the software people will run, or the ceremony buys\n\
                 nothing: an attacker who can hand out a different verifying key does\n\
                 not need anybody's toxic waste. In crates/core/src/keys.rs:\n\n    \
                 pub const MEMBERSHIP_VK_BLAKE3: Option<[u8; 32]> = Some([\n        {}\n    ]);\n\n\
                 until then, every release binary needs --vk-hash {}",
                out.display(),
                bytes,
                hex::encode(h)
            );
        }
    }
    Ok(())
}
