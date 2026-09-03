# Assumptions and resolutions

Every place where the whitepaper is silent, ambiguous, or (in one case)
internally inconsistent, with the choice made and why. Numbered `A<n>` and
referenced from `SPEC.md`. Genuine blockers are in `BLOCKERS.md`.

## Hashing and identity

**A1 — Two instantiations of `H`.** Poseidon (BN254 `Fr`, width 3) for every
value that is proven in zero knowledge (`C = H(s)`, nullifiers, `P`); BLAKE3
for everything else (ids, `K`, `r`, seeds). Tags are mapped into `Fr` as the
little-endian integer of their ASCII bytes; 32-byte ids are mapped by
`int_le mod r`. The whitepaper writes `H(s, "node")` and `H(s, "author")`
with two arguments and `H(s, "ballot", vote_id)` with three; the circuit uses
one fixed-arity `poseidon(s, tag, id)` with `id = 0` for the two-argument
cases, so a single circuit serves all items.

**A11 — Registry tree.** Sparse binary tree of fixed depth 32 (≈ 4.3 × 10⁹
leaves, enough for any continent; proving cost is 32 Poseidon hashes).
Empty leaf = `Fr(0)`. Leaf indices are assigned by the Issuer in enrollment
order; replacement writes the new `C` at the person's existing index, so a
person never has two leaves in one snapshot (whitepaper §5). The snapshot is
`(epoch, leaf_count, root)` signed by the Issuer's Ed25519 key plus the raw
leaf list; `registry_size(root) = leaf_count` is what the 1 % initiative
threshold is computed from.

**A24 — Groth16 trusted setup.** The whitepaper allows Groth16. Its
circuit-specific setup is a trust assumption the whitepaper does not list.
Dev mode generates the parameters from a fixed seed (insecure, labelled).
Release builds load parameters from a file whose verifying-key hash is pinned
in the source; producing that file (an MPC ceremony) is outside this
repository. Recorded here so it is not forgotten.

## Items, ids and duplicates

**A3 — Proof malleability vs. the byte-identical rule.** Groth16 proofs can
be re-randomized by anyone into a different, still-valid proof for the same
statement. Under a literal reading of §6 ("byte-identical → retransmission;
different → double action"), any relay could invalidate any honest ballot it
sees by re-randomizing its proof and forwarding both versions. Resolution:
every proof-bearing item has an `item_id` = BLAKE3 of its bytes *without the
proof*; the duplicate rule, anchor leaves and the client's "my nullifier is
anchored" check all use `item_id`. The proof binds the content through the
public `signal = fr_mod(item_id)`, so content cannot be altered either. The
whitepaper's determinism requirement (§8) is still met: the device stores and
retransmits exact bytes, and proof randomness is derived from `s` (A20).

**A4 — Only timely items participate in the duplicate rule.** A differing
duplicate that is *not* anchored before the deadline cannot invalidate one
that is. Otherwise a voter could retract a counted ballot after close by
publishing a conflicting one, and the result would never be final.
Consequence: a voter who gets two different ballots anchored before close
loses both (§6 as written).

**A9 — Author pseudonyms are not nullifiers.** `P = H(s, "author")` is
*meant* to repeat across a person's initiatives (§11 "track record"), so the
§6 duplicate rule does not apply to Initiatives.

**A10 — Node registrations cannot rotate keys.** `n = H(s, "node")` allows one
registration per person; publishing a second, different one invalidates both
(§6). Key rotation is left to a later version.

**A17 — Unresolved references.** Validation needs referenced objects (the
vote's root for a ballot, the initiative for a support, the header for an
anchor). Because gossip is unordered, such items are held in a bounded orphan
pool and re-validated when the reference arrives; they are not relayed until
valid. Honest nodes holding the same references agree, as §6 requires.

**A18 — `vote_id` excludes the signature.** `vote_id = BLAKE3(all fields
except the authority signature)`, so the vote's identity does not depend on
signature bytes; the authority signs `vote_id` under a domain prefix. All
Ed25519 messages in the protocol are domain-prefixed (§1.6 of SPEC).

**A22 — `threshold_N` is carried but not chosen.** The Initiative item lists
`N` (whitepaper §6) but §11 makes `N` a protocol parameter. An item whose `N`
differs from `ceil(registry_size / 100)` is invalid.

**A23 — `support_deadline_block` is author-chosen** and unconstrained
(a stale deadline only makes the initiative unreachable).

**A29 — NodeRegistration carries `registry_root`** (needed to verify its
proof; not listed in §6) and self-declared `operator`, `country`, `asn` for
the §12 diversity rules. These affect hop selection only (privacy), never
correctness, and are marked with a `TRUST` comment.

**A30 — Solutions.** All valid solutions for a vote have the same `y`; the
first valid one seen is kept. `solution_id` excludes the Wesolowski proof.

## Anchoring and counting

**A5 — `open_block` does not gate counting.** A ballot counts if anchored at
*any* height ≤ `close_block`. Ballots cannot exist before their VoteDefinition
anyway, and a rule "anchored at height ≥ open_block" would interact badly with
delta anchoring (A15). `open_block` is used for puzzle sizing and as the
earliest time the client casts.

**A6 — "Published before the Solution".** The Log has no order, so "before"
can only be measured through anchors. Given anchoring at ≤ `close_block` and a
puzzle sized to finish after `close_block`, the condition is implied and is
not evaluated separately.

**A14 — Headers.** A node uses a header only once it has 6 descendants; the
verifier takes its header file as the user's choice of chain. Header sources
(Electrum or HTTP) are trusted for liveness only; PoW and linkage are checked.
The chain starts at a checkpoint that is a deployment constant.

**A15 — The Anchor item carries its leaf list.** §6 says "Merkle inclusion
proofs on request", which would leave the leaf sets held only by the
anchorer; if it disappears nobody can prove inclusion. Carrying the sorted
list of `item_id`s makes anchors self-contained and lets any node serve proofs.
Anchorers are expected to anchor only items not covered by their previous
anchors ("delta anchoring"); the counting rule is a union over anchors so this
is equivalent to §9 and keeps items small. Leaves may be ids of any item type.

**A16 — Witness item.** §9's fallback ("signed as seen-before-close by ≥ W
registered nodes") needs the signatures on the Log for the verifier to see
them, so item type `Witness` exists. It is the §9 mechanism, not a new
feature. Fallback applies to a vote iff no valid anchor at height ≤
`close_block` covers any of its ballots (and no such anchor exists at all);
results are then labelled `FALLBACK`.

**A31 — Direct anchors** put `"CVOT" || root` in an `OP_RETURN` output and
prove inclusion with a standard partial Merkle tree.

**A32 — Verifier input** is a snapshot file (all items) plus a header file.

## Initiatives

**A7 — Derived `open_block` comes from the deadline, not the threshold
anchor.** §7 says `open_block = threshold-anchor block + fixed delay`. The
"threshold-anchor block" is the height of the anchor that first brought the
support count to `N`, which changes if an anchor for an *earlier* block is
published later (proofs can be published at any time). Every ballot cast to
the previously derived `vote_id` would then be orphaned — a free denial of
service for any anchorer. Resolution: `open_block = support_deadline_block +
144`, `close_block = open_block + 1008`, `min_ballots = 100`. The derived
definition is then a stable function of the initiative alone, gated by the
(monotone, up to A4) predicate "≥ N supports anchored by the deadline".

**A8 — Options of an initiative vote are `["Yes", "No"]`.** The Initiative
item has no options field in §6; the text becomes the question.

**A21 — Registry root of a derived vote** is the initiative's root (the only
root that is deterministically available).

## Puzzle and encryption (subject to BLOCKERS.md #1)

**A2 — Puzzle inputs include `blockhash(open_block)`.** `D` and `g` derived
from `vote_id` alone are known as soon as the definition is published, so a
solver could start the sequential computation weeks before `open_block` and
finish before `close_block`. Mixing the hash of block `open_block` into the
discriminant seed makes the computation impossible to start early.

**A13 — `S_MAX = 2^20` squarings/s, `M = 3/2`** (integer formula
`(close − open) × 600 × 2^20 × 3 / 2`). Whitepaper leaves `S_MAX` open.
Dev mode uses `T = 1024`.

**A19 — The ciphertext carries its nonce.** `r = H(s, "rand", vote_id)` is
secret-derived, so the decryptor cannot recompute it; the 24-byte nonce
(`r[0..24]`) is prefixed to the AEAD output. Associated data is
`vote_id || nullifier`. Plaintext is one byte (option index).

**A20 — Deterministic proofs.** Groth16 proving is randomized; the client
seeds its RNG from `H_B("proof-rand"; s || …)` and stores the produced bytes, so
retransmissions are byte-identical as §8 requires.

## Engineering choices

**A12 — Limits.** `MAX_OPTIONS = 64`, string ≤ 64 KiB, item ≤ 8 MiB, anchor
≤ 10⁶ leaves, vote length ≤ 52 560 blocks. Needed for a well-defined
canonical format and bounded validation cost.

**A25 — Crate names** are `cv-core`, `cv-crypto`, `cv-log`, … in
`crates/core`, `crates/crypto`, `crates/log`, … because `core` and `log` clash
with the Rust `core` crate and the ubiquitous `log` crate.

**A26 — Transport.** Gossip and light-client queries use plain HTTP
(`axum`/`reqwest`) rather than libp2p: simpler, testable, and the network
layer is privacy-only (§12). Sphinx packets and Tor are layered on top for
the mix path (Phase 7).

**A27 — Storage** is `redb` (pure Rust, single file, ACID) for the Log and
the disk-backed mix queues.

**A28 — Receipt** is 8 Crockford-base32 characters of `H_B("receipt"; n || c)`.
