# Progress

## Phase 0 — Specification  (2026-09-03)

Deliverables: `SPEC.md`, `ASSUMPTIONS.md`, `DEPENDENCIES.md`, `BLOCKERS.md`,
workspace skeleton (`Cargo.toml`, `crates/{core,crypto,log,node,client,verifier,issuer,sim}`).

- Read the whitepaper in full. Specified canonical byte formats for all Log
  items (plus `Witness`, the carrier for the §9 fallback), the hash domain
  tags in both Poseidon and BLAKE3 form, validity checklists, the counting
  rule and initiative derivation as pseudocode, puzzle-parameter derivation,
  protocol constants, snapshot format, and test vectors for the items that do
  not need a proof system (VoteDefinition, Anchor, Witness, tagged hashes,
  Merkle tree). Proof-bearing vectors come from the implementation in Phases 1–2.
- Verified every candidate crate on crates.io and read the source of the
  non-obvious ones (`kyn-vdf`, `opentimestamps`, `ark-crypto-primitives`,
  `sphinx-packet`). All primitive crates resolve and compile together
  (`cargo build --workspace`, 175 crates, exit 0).
- **Found one blocker** (`BLOCKERS.md #1`): a voter cannot encrypt under
  `K = H(g^(2^T))` without doing the sequential work, because the class group
  has no trapdoor. Recommended resolution: drand `tlock` timed release
  (Option A). Phase 3 and the opening half of Phases 6/8 wait on that decision;
  everything else is unblocked.
- 32 recorded assumptions, the most consequential being A3 (ids exclude the
  proof, because Groth16 proofs are malleable), A7 (derived votes open at
  deadline + delay, not at the threshold anchor), A2 (puzzle seed includes the
  open block's hash), A15 (anchors carry their leaf lists).

Tests: skeleton only (`cargo test --workspace` passes trivially).

Next: Phase 1 — types, canonical encoding, round-trip tests and the vectors of
SPEC §17, after the BLOCKER #1 decision (Phase 1 does not depend on it, but
the `Solution` and `Ballot` ciphertext types do).
