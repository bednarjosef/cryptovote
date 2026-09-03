# CryptoVote

Reference implementation of the protocol in `whitepaper.md` (v0.3): frequent
anonymous votes and citizen initiatives with trustless integrity, Bitcoin
anchoring for the deadline, a mix network for sender privacy, and an
independent verifier. `SPEC.md` is the byte-exact specification; every
deviation from the whitepaper is recorded in `ASSUMPTIONS.md`; crate choices
in `DEPENDENCIES.md`; progress per phase in `PROGRESS.md`.

**Status.** Phases 0–9 are implemented and tested under `secrecy = none`
(plaintext option index, public running count). `secrecy = keyparties`
(SPEC §10–§11: EC-ElGamal under an aggregate key with verifiable timed
commitments) is specified and wired into the types and the counting rule but
its cryptography (Phase 10) is not implemented yet.

Everything you can run today is **development mode**: a mock Bitcoin clock,
an insecure Groth16 setup derived from a public seed, a mock eID issuer that
enrolls anyone, and dev anchors. Every binary prints a warning when started
that way. Nothing produced in dev mode is trustworthy.

## Layout

| Crate | Binary | What it is |
|---|---|---|
| `crates/core` (`cv-core`) | — | Types, canonical encoding, identity, validity rules, counting rule, snapshot view, header chain. The one implementation of the rules. |
| `crates/crypto` (`cv-crypto`) | — | Thin wrappers over primitive crates (BLAKE3, Poseidon, Groth16, Ed25519, Merkle, OTS, SPV, Sphinx). |
| `crates/log` (`cv-log`) | — | Log storage (memory or redb), set semantics, orphan pool, indexes, pruning. |
| `crates/node` | `cv-node` | Node: HTTP API, gossip, anchorer (OTS / direct / dev), mix hop, witness. |
| `crates/client` | `cv-client` | Participant library (device, enrollment, casting, mix client, Tor, UniFFI) and CLI. |
| `crates/verifier` | `cv-verifier` | Small verifier: CLI and WebAssembly. |
| `crates/issuer` | `cv-issuer` | Issuer with a mock eID backend (dev). |
| `crates/sim` | `cv-sim` | End-to-end simulation on one machine. |

## Build and test

```
cargo build --workspace --release
cargo test --workspace            # ~3 minutes; proving keys are generated once per process
```

The verifier for the browser:

```
rustup target add wasm32-unknown-unknown
cargo build -p cv-verifier --lib --target wasm32-unknown-unknown --features wasm --release
# target/wasm32-unknown-unknown/release/cv_verifier.wasm exports verify_snapshot(snapshot, headers, config_json)
```

## Simulation

```
cargo run --release -p cv-sim -- --participants 20 --nodes 5
```

Runs an issuer, five nodes (all mix hops, one anchorer), enrolls the
participants, holds an authority vote (with a double voter and an abstainer),
runs an initiative that reaches its threshold and derives a vote, votes on
that too, then takes a snapshot from the last node, recomputes the results
with the verifier and compares them with the ground truth. Exit code 1 on
mismatch.

## Running the pieces by hand (dev mode)

```
# 1. Issuer (mock eID). Prints its public key.
cargo run --release -p cv-issuer -- --dev --listen 127.0.0.1:8450 --key-seed 1111111111111111111111111111111111111111111111111111111111111111 --node http://127.0.0.1:8440

# 2. A node with the dev anchorer (use the issuer key printed above; the authority key is any Ed25519 key you sign definitions with).
cargo run --release -p cv-node -- --dev --listen 127.0.0.1:8440 --data-dir ./data/node1 \
    --issuer-key <ISSUER_KEY_HEX> --authority-key <AUTHORITY_KEY_HEX> --anchor dev --anchor-interval 10

# 3. A participant.
cargo run --release -p cv-client -- --dev --device alice.json init
cargo run --release -p cv-client -- --dev --device alice.json enroll --issuer http://127.0.0.1:8450 --eid alice
cargo run --release -p cv-client -- --dev --device alice.json votes
cargo run --release -p cv-client -- --dev --device alice.json vote --vote <VOTE_ID> --option 0
cargo run --release -p cv-client -- --dev result --vote <VOTE_ID>

# 4. Verify independently from a snapshot.
curl -s http://127.0.0.1:8440/v1/snapshot > log.snap
cargo run --release -p cv-verifier -- --dev --snapshot log.snap --issuer-key <ISSUER_KEY_HEX> --authority-key <AUTHORITY_KEY_HEX>
```

Vote definitions are created by signing with an authority key; there is no
CLI for that yet (the simulation and tests use `cv_core::build::sign_vote_definition`).
Initiatives are created with `cv-client initiative` and supported with
`cv-client support`; a node derives the vote automatically once the threshold
of anchored supports is reached.

More nodes: start them with `--peer http://127.0.0.1:8440`; gossip is push
plus periodic pull. To act as a mix hop a node needs `--mix-secret-seed` and
its operator must publish a `NodeRegistration` (endpoint, mix key, operator,
country, ASN) with their participant secret; `cv-client` can be extended for
this, the tests show the call.

## Release mode

Release mode refuses the shortcuts. It needs:

- Groth16 keys from a ceremony (`--keys-dir` with `membership.pk`; the
  verifier takes `--vk`). The development key's hash is pinned in
  `crates/core/tests/vectors/circuit.json`.
- Bitcoin headers: `--checkpoint-height`/`--checkpoint-header` (deployment
  constants) and an Esplora-style API (`--headers-api`, default
  mempool.space). Headers are checked for linkage and proof of work; the API
  is trusted for liveness only.
- Anchoring: `--anchor ots` submits every new root to the public
  OpenTimestamps calendars (`--calendar` to override), polls for upgrades, and
  publishes the Anchor once it verifies against the node's own header.
  Direct anchors: `cv-node prepare-direct-anchor` prints the `OP_RETURN`
  script; after the transaction confirms, `cv-node publish-direct-anchor`.
- Tor: the client library bootstraps Arti (`cast_ballot` in the UniFFI API,
  `MixClient` in Rust) and falls back to direct HTTP with the privacy
  indicator saying so.

## Mobile bindings

`cv-client` exposes `device_create`, `device_enroll`, `cast_ballot`,
`vote_result_json` through UniFFI (feature `ffi`, on by default). Generate
Kotlin/Swift bindings with `uniffi-bindgen` against the built library, e.g.
`cargo run -p uniffi-bindgen -- generate --library target/release/libcv_client.so --language kotlin --out-dir bindings`.

## Where things are decided

- `SPEC.md` — formats, tags, validity checklists, counting rule, key parties.
- `ASSUMPTIONS.md` — every choice the whitepaper left open (A1–A45).
- `BLOCKERS.md` — the §7 contradiction and its resolution.
- `DEPENDENCIES.md` — why each crate, and what was rejected.
- Trust boundaries are marked in code with `// TRUST: … (whitepaper §N)`.
