//! The verifier (whitepaper §15): recomputes any result from a Log snapshot
//! (SPEC §15) and Bitcoin headers, and prints under which guarantee level
//! it was computed. Kept small on purpose: it depends only on `cv-core`,
//! whose `SnapshotView` validates the items and whose `tally` is the
//! counting rule. Everything here is glue.
#![forbid(unsafe_code)]

#[cfg(feature = "wasm")]
pub mod wasm;

use cv_core::context::Deployment;
use cv_core::crypto::groth16::MembershipVerifier;
use cv_core::crypto::spv;
use cv_core::headers::HeaderChain;
use cv_core::items::Id;
use cv_core::snapshot::{Headers, SnapshotView};
use cv_core::tally::{derive_vote, tally};
use cv_core::wire::ResultJson;
use serde::Serialize;
use std::sync::Arc;

/// Bitcoin headers exactly as the user supplied them (SPEC §15 file). The
/// user chooses the chain; no confirmation delay is applied here.
pub struct ChainHeaders(pub HeaderChain);

impl Headers for ChainHeaders {
    fn merkle_root(&self, height: u32) -> Option<[u8; 32]> {
        self.0.header_at(height).map(spv::merkle_root)
    }
    fn tip_height(&self) -> Option<u32> {
        Some(self.0.tip().0)
    }
}

/// **Dev mode only**: pretend every height up to `tip` exists. Dev anchors
/// do not check merkle roots, so any value works. Never use for real votes.
pub struct MockHeaders {
    pub tip: u32,
}

impl Headers for MockHeaders {
    fn merkle_root(&self, height: u32) -> Option<[u8; 32]> {
        (height <= self.tip)
            .then(|| cv_core::crypto::hash::tagged("mock-header", &height.to_le_bytes()))
    }
    fn tip_height(&self) -> Option<u32> {
        Some(self.tip)
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct InitiativeReport {
    pub initiative_id: String,
    /// Whose Registry defines this initiative's electorate.
    pub issuer_key: String,
    pub text: String,
    pub threshold_n: u32,
    pub derived_vote_id: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct Report {
    pub dev_mode: bool,
    pub headers_tip: Option<u32>,
    pub items_accepted: usize,
    pub items_invalid: usize,
    pub items_unresolved: usize,
    pub registries_rejected: usize,
    pub votes: Vec<ResultJson>,
    pub initiatives: Vec<InitiativeReport>,
}

pub struct Config {
    pub deployment: Deployment,
    pub verifier: Arc<MembershipVerifier>,
}

/// Recompute every vote's result (or just `only_vote`) from public data.
pub fn verify(
    snapshot: &[u8],
    headers: Arc<dyn Headers>,
    config: Config,
    only_vote: Option<Id>,
) -> Result<Report, String> {
    let tip = headers.tip_height();
    let dev_mode = config.deployment.dev_mode;
    let view = SnapshotView::load(snapshot, config.deployment, config.verifier, headers)
        .map_err(|e| format!("snapshot: {e}"))?;
    let mut votes = Vec::new();
    for id in view.vote_ids() {
        if only_vote.is_some_and(|v| v != id) {
            continue;
        }
        let Some(vd) = cv_core::context::Context::vote(&view, &id) else {
            continue;
        };
        if let Some(outcome) = tally(&view, &id) {
            votes.push(outcome.to_wire(&id, &vd));
        }
    }
    let initiatives = view
        .initiative_ids()
        .into_iter()
        .filter_map(|id| {
            let init = cv_core::context::Context::initiative(&view, &id)?;
            Some(InitiativeReport {
                initiative_id: hex::encode(id),
                issuer_key: hex::encode(init.issuer_key),
                text: init.text,
                threshold_n: init.threshold_n,
                derived_vote_id: derive_vote(&view, &id).map(|v| hex::encode(v.vote_id())),
            })
        })
        .collect();
    Ok(Report {
        dev_mode,
        headers_tip: tip,
        items_accepted: view.report.accepted,
        items_invalid: view.report.invalid.len(),
        items_unresolved: view.report.unresolved,
        registries_rejected: view.report.registries_rejected,
        votes,
        initiatives,
    })
}

/// The development verifying key (INSECURE; matches the dev proving key).
pub fn dev_verifier() -> MembershipVerifier {
    use rand::SeedableRng;
    cv_core::crypto::groth16::setup(&mut rand_chacha::ChaCha20Rng::from_seed(
        cv_core::crypto::groth16::DEV_SETUP_SEED,
    ))
    .verifier
}

/// Human-readable rendering of a report.
pub fn render(report: &Report) -> String {
    let mut out = String::new();
    if report.dev_mode {
        out.push_str("WARNING: dev mode — mock headers and insecure dev proving keys; nothing here is trustworthy.\n");
    }
    out.push_str(&format!(
        "snapshot: {} items accepted, {} invalid, {} unresolved; {} registries rejected; headers tip {:?}\n",
        report.items_accepted, report.items_invalid, report.items_unresolved, report.registries_rejected, report.headers_tip
    ));
    for v in &report.votes {
        out.push_str(&format!(
            "\nvote {} [{}] {}\n",
            v.vote_id, v.secrecy, v.question
        ));
        // Who defined this electorate: a result means nothing without it.
        out.push_str(&format!("  issuer: {}\n", v.issuer_key));
        match v.outcome.as_str() {
            "result" => {
                // Every counted ballot is anchored in Bitcoin at or before
                // close_block; there is no weaker mode to disclose (A16).
                out.push_str("  RESULT (every counted ballot anchored in Bitcoin)\n");
                for (o, c) in v.options.iter().zip(v.counts.iter().flatten()) {
                    out.push_str(&format!("    {o}: {c}\n"));
                }
                out.push_str(&format!("  counted ballots: {}\n", v.counted.unwrap_or(0)));
            }
            "below_minimum" => out.push_str(&format!(
                "  no result: {} anchored ballots, below min_ballots\n",
                v.counted.unwrap_or(0)
            )),
            "not_closed" => out.push_str("  not closed yet by the supplied headers\n"),
            "pending" => out.push_str(&format!(
                "  pending: {} key-party share(s) missing\n",
                v.missing_shares.len()
            )),
            other => out.push_str(&format!("  {other}\n")),
        }
    }
    for i in &report.initiatives {
        out.push_str(&format!(
            "\ninitiative {} (threshold {}): {} → derived vote {:?}\n",
            i.initiative_id, i.threshold_n, i.text, i.derived_vote_id
        ));
        out.push_str(&format!("  issuer: {}\n", i.issuer_key));
    }
    out
}
