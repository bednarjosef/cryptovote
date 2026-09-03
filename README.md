# CryptoVote

Reference implementation of the protocol in `whitepaper.md` (v0.5): frequent
anonymous votes and citizen initiatives with trustless integrity, Bitcoin
anchoring for the deadline, a mix network for sender privacy, and an
independent verifier. `SPEC.md` is the byte-exact specification; every
deviation from the whitepaper is recorded in `ASSUMPTIONS.md`; crate choices
in `DEPENDENCIES.md`; progress per phase in `PROGRESS.md`.

**Anchoring is the only clock.** A ballot counts if and only if it is inside
a Merkle root timestamped into Bitcoin at or before the vote's `close_block`.
Every node anchors by default (`--anchor off` opts out): anchoring is
permissionless, costs nothing through OpenTimestamps, and an anchor covers
everyone's items whoever made it — so one node doing it serves the whole
network, and a dishonest node's anchor is exactly as good as an honest one's
because it is checked against Bitcoin rather than believed. A vote that
nobody anchors has no result; there is no weaker mode to fall back to
(`ASSUMPTIONS.md` A16).

**Status.** Phases 0–10 are implemented and tested: `secrecy = none`
(plaintext option index, public running count) and `secrecy = keyparties`
(SPEC §10–§11: EC-ElGamal under the aggregate key of volunteer key parties,
each committing to its share with a verifiable timed commitment that anyone
can force open). The VTC construction in `crates/vtc` is the only
cryptographic construction assembled here from primitive crates; it must be
audited before any binding use.

Everything you can run today is **development mode**: a mock Bitcoin clock,
an insecure Groth16 setup derived from a public seed, an issuer whose mock
verification backend enrolls anyone, and dev anchors. Every binary prints a warning when started
that way. Nothing produced in dev mode is trustworthy.

## Layout

| Crate | Binary | What it is |
|---|---|---|
| `crates/core` (`cv-core`) | — | Types, canonical encoding, identity, validity rules, counting rule, snapshot view, header chain. The one implementation of the rules. |
| `crates/crypto` (`cv-crypto`) | — | Thin wrappers over primitive crates (BLAKE3, Poseidon, Groth16, Ed25519, Merkle, OTS, SPV, Sphinx). |
| `crates/log` (`cv-log`) | — | Log storage (memory or redb), set semantics, orphan pool, indexes, pruning. |
| `crates/node` | `cv-node` | Node: HTTP API, gossip, anchorer (OTS / direct / dev), mix hop. |
| `crates/client` | `cv-client` | Participant library (device, enrollment, casting, mix client, Tor, UniFFI) and CLI. |
| `crates/verifier` | `cv-verifier` | Small verifier: CLI and WebAssembly. |
| `crates/issuer` | `cv-issuer` | Issuer: registry, signed roots, and one `VerificationBackend` trait. Ships the mock backend only (dev). |
| `crates/sim` | `cv-sim` | End-to-end simulation on one machine. |
| `crates/vtc` (`cv-vtc`) | — | `secrecy = keyparties`: exponent ElGamal on Ristretto255, RSW puzzles with proof of exponentiation, Shamir cut-and-choose timed commitment. |

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

## Issuers

An Issuer is any operator of a registry, identified by the Ed25519 key it
signs roots with. Several coexist: every `VoteDefinition`, `Initiative` and
`NodeRegistration` names the `issuer_key` whose electorate it relies on, and a
registry root only counts for an item if the snapshot with that root carries
that Issuer's signature. Because a result means nothing without knowing whose
electorate it is over, the verifier and the client print the Issuer next to
every result. A person may hold a leaf in several registries; nullifiers are
scoped per vote and `vote_id` covers `issuer_key`, so no one can vote twice in
any electorate (`ASSUMPTIONS.md` A47).

How an Issuer decides who is one eligible person is behind a single trait:

```rust
pub trait VerificationBackend: Send + Sync {
    fn verify(&self, request: &EnrollmentRequest) -> Verification; // Verified { dedup_key } | Rejected { reason }
}
```

The Issuer core is backend-agnostic: on `Verified` it adds `C` as a new leaf
or overwrites the leaf that `dedup_key` already names (device replacement),
then publishes a new signed root. It keeps only `C`, the dedup key and a
timestamp. Only the mock backend (dev: accepts any non-empty credential)
ships here; adapters for real verification methods belong in their own crates.

## Simulation

```
cargo run --release -p cv-sim -- --participants 20 --nodes 5
```

Runs two issuers, five nodes (all mix hops, one anchorer), enrolls the
participants, holds an authority vote (with a double voter and an abstainer),
runs a second vote over the second Issuer's smaller electorate (the same
people, another registry), runs an initiative that reaches its threshold and
derives a vote, votes on that too, then takes a snapshot from the last node,
recomputes the results with the verifier and compares them with the ground
truth. Exit code 1 on mismatch.

## Running the pieces by hand (dev mode)

```
# 1. Issuer (mock verification backend). Prints its public key — that is the `issuer_key` items name.
cargo run --release -p cv-issuer -- --dev --listen 127.0.0.1:8450 --key-seed 1111111111111111111111111111111111111111111111111111111111111111 --node http://127.0.0.1:8440

# 2. A node with the dev anchorer. --issuer-key is repeatable and optional: it restricts which
#    Issuers' registries this node stores. Omit it to carry any. The authority key is any Ed25519
#    key you sign vote definitions with.
cargo run --release -p cv-node -- --dev --listen 127.0.0.1:8440 --data-dir ./data/node1 \
    --issuer-key <ISSUER_KEY_HEX> --authority-key <AUTHORITY_KEY_HEX> --anchor dev --anchor-interval 10

# 3. A participant.
cargo run --release -p cv-client -- --dev --device alice.json init
cargo run --release -p cv-client -- --dev --device alice.json enroll --issuer http://127.0.0.1:8450 --credential alice
cargo run --release -p cv-client -- --dev --device alice.json registries   # which Issuers this node carries
cargo run --release -p cv-client -- --dev --device alice.json votes
cargo run --release -p cv-client -- --dev --device alice.json vote --vote <VOTE_ID> --option 0
# "anchored" is checked, not taken from the node: the client fetches the anchor, recomputes its
# Merkle root, and requires your ballot to be a leaf of it. Add --headers <file> (SPEC §15 header
# file, obtained yourself) and it also checks that root is really in Bitcoin.
cargo run --release -p cv-client -- --dev result --vote <VOTE_ID>

# 4. Verify independently from a snapshot.
curl -s http://127.0.0.1:8440/v1/snapshot > log.snap
# --issuer-key is optional here too; without it the verifier reports every Issuer in the snapshot.
cargo run --release -p cv-verifier -- --dev --snapshot log.snap --authority-key <AUTHORITY_KEY_HEX>
```

Key parties: `ParticipantClient::register_keyparty` (before `open_block`)
and `publish_share` (after close); nodes started with `--solver` force open
any commitment whose share has not appeared. Vote definitions are created
by signing with an authority key; there is no CLI for that yet (the simulation and tests use `cv_core::build::sign_vote_definition`).
Initiatives are created with `cv-client initiative` and supported with
`cv-client support`; a node derives the vote automatically once the threshold
of anchored supports is reached.

More nodes: start them with `--peer http://127.0.0.1:8440`; gossip is push
plus periodic pull.

**Running a node needs nobody's permission** — no registration, no Issuer.
Storing, validating, relaying, serving clients and anchoring are open to
anyone. A `NodeRegistration` is only needed to be *chosen as a mix hop* by
other people's clients. It is a zero-knowledge proof that the operator is one
person in some registry (the Issuer is not asked and never learns of it), one
per person per electorate. **Nothing in the counting rule depends on a node's
identity**: no node, and no number of nodes, has any say in a result.

Every node is a mix hop by default: it keeps its own mix and identity keys in
its store and prints them at startup, so the operator publishes them with

```
cargo run --release -p cv-client -- --dev --device alice.json register-node \
    --node-key <NODE_KEY> --mix-key <MIX_KEY> --endpoint 127.0.0.1:8440 --operator me --country CZ --asn 6830
```

`--no-mix` opts a node out. A full three-hop path with two hop-disjoint
paths needs five registered hops; with fewer, or with hops that share an
operator, ASN or country, the client still sends and tells you what it got
("3 mix hop(s), 2 path(s), same country").

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
- `ASSUMPTIONS.md` — every choice the whitepaper left open (A1–A48).
- `BLOCKERS.md` — the §7 contradiction and its resolution.
- `DEPENDENCIES.md` — why each crate, and what was rejected.
- Trust boundaries are marked in code with `// TRUST: … (whitepaper §N)`.
