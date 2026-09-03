//! Phase 9: the simulation's verifier result matches the ground truth.

use cv_sim::{SimConfig, run};
use std::time::Duration;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn simulation_matches_ground_truth() {
    let report = run(SimConfig {
        participants: 10,
        nodes: 5,
        seed: 7,
        mix: true,
        confirm_window: Duration::from_secs(30),
    })
    .await
    .unwrap();
    eprintln!("{}", cv_sim::render(&report));
    assert!(report.authority_vote.matches, "{:?}", report.authority_vote);
    assert_eq!(report.authority_vote.verifier_outcome, "result");
    assert_eq!(report.authority_vote.guarantee.as_deref(), Some("anchored"));
    assert!(report.derived_vote.matches, "{:?}", report.derived_vote);
    assert_eq!(
        report.derived_vote.verifier_outcome, "below_minimum",
        "derived votes need 100 ballots"
    );
    // Five hops: both paths are three hops long; no Tor in the simulation.
    assert!(
        report
            .privacy_levels
            .iter()
            .all(|p| p.starts_with("partial: 3 mix hop")),
        "{:?}",
        report.privacy_levels
    );
    assert!(report.ok);
}
