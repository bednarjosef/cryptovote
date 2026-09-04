# Assumptions and resolutions

Every place where the whitepaper is silent, ambiguous, or (in one case)
internally inconsistent, with the choice made and why. Numbered `A<n>` and
referenced from `SPEC.md`. The resolved blocker is in `BLOCKERS.md`; the
secrecy design that replaced whitepaper §7 is in `SPEC.md` §10–§11 and
A35–A40 below.

## Hashing and identity

**A1 — Two instantiations of `H`.** Poseidon (BN254 `Fr`, width 3) for every
value that is proven in zero knowledge (`C = H(s)`, nullifiers, `P`); BLAKE3
for everything else (ids, `K`, `r`, seeds). Tags are mapped into `Fr` as the
little-endian integer of their ASCII bytes; 32-byte ids are mapped by
`int_le mod r`. The whitepaper writes `H(s, "node")` and `H(s, "author")`
with two arguments and `H(s, "ballot", vote_id)` with three; the circuit uses
one fixed-arity `poseidon(s, tag, id)` with `id = 0` for the two-argument
cases, so a single circuit serves all items.

**A41 — Identity commitment carries a domain tag.** The arkworks Poseidon
sponge has no length padding: absorbing `[x]` and `[x, 0]` leaves the same
state, so `poseidon(x) = poseidon(x, 0) = node(x, EMPTY_LEAF)`. With
`C = poseidon(s)` a public leaf value would be the "secret" of a commitment
equal to a tree node. The fixed 32-level walk happens to make that unusable
for forging membership, but the collision is gratuitous, so
`C = poseidon(s, tag_field("commit"))` and the arity-1 hash is not used at
all. (Found by a test in Phase 2.)

**A11 — Registry tree.** Sparse binary tree of fixed depth 32 (≈ 4.3 × 10⁹
leaves, enough for any continent; proving cost is 32 Poseidon hashes).
Empty leaf = `Fr(0)`. Leaf indices are assigned by the Issuer in enrollment
order; replacement writes the new `C` at the person's existing index, so a
person never has two leaves in one snapshot (whitepaper §5). The snapshot is
`(epoch, leaf_count, root)` signed by the Issuer's Ed25519 key plus the raw
leaf list; `registry_size(root) = leaf_count` is what the 1 % initiative
threshold is computed from.

**A47 — Several Issuers, named by each item.** Whitepaper v0.4 §5 makes the
Issuer a *role*, not a singleton: any operator of a registry is one, and the
protocol privileges none of them. Resolution: `VoteDefinition`, `Initiative`
and `NodeRegistration` each carry an `issuer_key` (Ed25519, immediately before
`registry_root`), and a `registry_root` is usable by an item only if a
snapshot with that root carries a valid signature by *that* key — snapshots
are indexed by `(issuer_key, root)`, since two Issuers may publish the same
root. `vote_id` covers `issuer_key`, so the same question over two registries
is two votes. There is no global list of blessed Issuers in the validity
rules: nodes and verifiers may be told which registries to *store*
(`--issuer-key`, repeatable, empty = any), which decides what a node serves,
never what is valid. The consequence is deliberate: anyone can stand up an
Issuer with a one-leaf registry, so a result is meaningless without knowing
whose electorate it is over — which is why the verifier and the client print
the Issuer next to every result.

Nullifier scoping is unchanged and is what makes several registries safe: a
ballot, support or key-party nullifier is `poseidon(s, tag, id)` with `id` the
vote or initiative, so a person enrolled by three Issuers still has exactly
one nullifier per vote. The two `id = 0` nullifiers stay global on purpose.
A node registration is one per person across the whole network, whichever
Issuer enrolled them (registering twice under two Issuers is self-defeating
under A10, which is the intended reading of "one node per person"), and the
author pseudonym links a person's initiatives across registries exactly as it
already links them within one (A9). Scoping either of them by Issuer would
mean changing the circuit's public `id` input for no gain.

**A48 — One interface for identity verification.** How an Issuer decides that
a person is real and unique is that Issuer's business and the boundary of
Sybil resistance for its electorate (whitepaper §5), so `cv-issuer` exposes
exactly one thing: `VerificationBackend::verify(request) ->
Verified { dedup_key } | Rejected { reason }`. The request is the commitment
`C` plus an opaque `credential` string that only the backend interprets. The
core is backend-agnostic: on `Verified` it inserts `C` as a new leaf, or
overwrites the leaf of the person that `dedup_key` already names, then
publishes a new signed root. It stores only `C`, the dedup key and a
timestamp — never a name, a document, or anything the backend saw. An empty
dedup key is refused, since it would make every enrollment the same person.
Only the mock backend (dev mode: accepts any non-empty credential and uses it
as the dedup key) ships here; adapters for real verification methods belong
in their own crates, and no specific provider is named anywhere in this
repository.

**A49 — Superseded by A16.** Scoping fallback witnesses to the vote's own
electorate was the right repair for the Sybil hole multiple Issuers opened in
whitepaper §9, and it held for a day. Then the mechanism itself went: see A16
for why a node's signature is not a clock at any scope.

**A50 — Everything is scoped to an electorate; nothing is global.** With one
Issuer it did not matter that the node-registration nullifier and the author
pseudonym used `id = 0`: one registry, one meaning. With several (A47) a
global `id = 0` was wrong twice over. It linked a person's node and
pseudonym across every registry they belong to, for no benefit. And it forced
a choice: someone enrolled with two Issuers could hold **one** node
registration in total, so registering under one electorate silently disabled
them in the other — and a second registration would collide with their own
first one and, under the duplicate rule (A10), destroy both. Resolution: both
use `id = fr_mod(issuer_key)`. One node per person per electorate, one
pseudonym per person per electorate, no cross-electorate linkage. The circuit
is unchanged: `id` is a public input it never interprets.

With the witness fallback gone (A16), the remaining use of a node
registration is mix-hop selection, and per-electorate is the right
granularity for that too: the diversity a client wants is diversity among the
people of the electorate it is voting in.

**A51 — Baseline network assumption: no node has any power.** Everything from
here on assumes the network has enough registered hops for a three-hop path,
and at least one honest node reachable by the voter that anchors (or relays to
someone who does). There is no majority, quorum or committee anywhere: with
the witness fallback removed (A16), nothing a node signs affects a result, so
the count does not depend on how many nodes are honest — only on whether the
voter's ballot reached **one** of them before `close_block`, which the voter
can check for themselves (Phase 11b). Nodes may all anchor, including
dishonest ones: an anchor is verified against Bitcoin, so a dishonest
anchorer can only help (by anchoring) or abstain (by not), never harm.

Below the baseline, privacy degrades (the client reports how far it got and
falls back to direct submission) and liveness can fail (a ballot that reaches
no honest node is not counted, and the voter sees that it was not). Neither
can produce a wrong result: an eclipsed voter is a missing ballot, never a
forged one.

**A24 — Groth16 trusted setup.** The whitepaper allows Groth16. Its
circuit-specific setup is a trust assumption the whitepaper does not list,
and it is the only one in this protocol that cannot be checked after the
fact: whoever knows the setup's secrets forges membership proofs, which is
ballots cast as people who exist and did not vote, indistinguishable from
honest ballots forever. Everything else here is recomputable from the Log; a
forged proof is not.

The ceremony that removes that party is now specified (SPEC §18) and
implemented (`crates/ceremony`, A60). What remains assumed is what a ceremony
cannot prove: that **at least one contributor per phase** drew unguessable
randomness, destroyed it, and did not collude with all the others. Nobody can
demonstrate having deleted a number, so the assumption is unfalsifiable by
construction — the ceremony's whole contribution is to replace "trust this
one party" with "all of these named people would have had to conspire", and
to let any stranger check who they were and that each really did contribute
(`cv-ceremony verify`).

Dev mode still generates parameters from a fixed public seed and is labelled
insecure everywhere; `cv_crypto::groth16::dev_forge` recovers that seed's
toxic waste and forges at will, so the failure is a test rather than a
paragraph. Release builds refuse to start without a pinned verifying-key hash
(A62), because a ceremony protects only the people who use the key it
produced.

**Why keep Groth16 at all**, when proof systems exist that need no ceremony?
Because every ballot carries its proof, forever: the Log stores it, anchors
cover it, and the verifier checks every one. At 128 bytes, ten million
ballots are 1.3 GB of proof; the setup-free alternatives are 2 KB
(Halo2/IPA) to 100 KB (STARK) per proof, which is 20 GB to a terabyte, with
verification to match. That is the whole reason the trust assumption is
accepted rather than designed away.

The alternative worth revisiting is a **universal** setup — PLONK-family,
KZG — whose reference string is circuit-independent. It costs roughly 4×
the proof size (still hundreds of bytes, not kilobytes) and buys two things
this design would like: the existing Perpetual Powers of Tau transcript can
be adopted wholesale, so the ceremony becomes someone else's much larger
one, and the circuit can then change without holding another. That is a
proof-system decision, not a ceremony one, and it is the right question to
settle *before* a real ceremony is held, because a new circuit under Groth16
means starting phase 2 again.

## Items, ids and duplicates

**A3 — Proof malleability vs. the byte-identical rule.** Groth16 proofs can
be re-randomized by anyone into a different, still-valid proof for the same
statement. Under a literal reading of §6 ("byte-identical → retransmission;
different → double action"), any relay could invalidate any honest ballot it
sees by re-randomizing its proof and forwarding both versions. Resolution:
every proof-bearing item has a **content id** = BLAKE3 of its bytes *without
the proof*; the duplicate rule ("same nullifier, same content id" = retransmission,
"same nullifier, different content id" = double action), anchor leaves and the
client's "my nullifier is anchored" check all use the content id. The proof binds the content through the
public `signal = fr_mod(content_id)`, so content cannot be altered either. The
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
can only be measured through anchors. There is no Solution item any more
(A35); under `keyparties` decryption is gated on the verifier's header tip
being past `close_block` and on every needed share being present, and only
ballots anchored at ≤ `close_block` are decrypted, so the condition has no
separate analogue.

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

**A16 — The §9 witness fallback is removed; anchors are the only clock.**
Whitepaper §9 allows a degraded mode: if a vote has no anchor, `W = 7`
registered nodes may sign "I held this ballot before close" and the result is
published labelled `FALLBACK`. This was implemented (item type `0x08`) and
then deleted, for three reasons.

A signature is not a clock. `W` signatures are `W` keys, and keys are cheap;
what was supposed to make them expensive is that each belongs to a registered
person. With several Issuers (A47) that stopped being true — anyone can stand
up an Issuer, enrol seven of themselves and mint the quorum — and scoping the
witnesses to the vote's own electorate (the earlier fix) only narrowed the
attack to that electorate's own node operators, who are exactly the people
with the most to gain from backdating. It also made the protocol's guarantee
conditional: every consumer of a result had to understand two levels and
decide what a `FALLBACK` one was worth.

Anchors need none of that. Anchoring is permissionless and unpriced (an
OpenTimestamps calendar aggregates thousands of roots into one transaction),
an anchor covers everyone's items regardless of who made it, and it is
verified against Bitcoin rather than believed — so a dishonest node's anchor
is exactly as good as an honest one's, and the worst any node can do is not
anchor. One node anchoring serves the entire network. The failure mode the
fallback existed for — nobody anchored for a whole voting period — now yields
no result instead of a weakly-attested one, which is the right answer and one
that any single volunteer prevents.

Consequences: item type `0x08` is retired (decoding it is an error), the
`Guarantee` level and the `guarantee` field are gone, `WITNESS_THRESHOLD_W`
and the `Witness` signature domain are gone, and node identity has no role in
counting at all. What a node is for is storing, validating, relaying,
anchoring, and optionally being a mix hop — none of which needs anyone's
permission, and none of which is trusted (A51).

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
144`, `close_block = open_block + 1008`, `min_ballots = 100`, `secrecy` copied
from the Initiative (A39). The derived
definition is then a stable function of the initiative alone, gated by the
(monotone, up to A4) predicate "≥ N supports anchored by the deadline".

**A8 — Options of an initiative vote are `["Yes", "No"]`.** The Initiative
item has no options field in §6; the text becomes the question.

**A21 — Registry root of a derived vote** is the initiative's root (the only
root that is deterministically available).

## Secrecy: key parties (replaces whitepaper §7; decision recorded in BLOCKERS.md #1)

**A35 — Per-vote `secrecy` field, `none` first.** Whitepaper §7's shared
puzzle key is not realizable (BLOCKERS.md #1). Each VoteDefinition carries
`secrecy ∈ {none, keyparties}`. Under `none` the ballot carries the option
index in the clear and the running count is public by design; this mode is
implemented first and Phases 3–9 are completed on it. Under `keyparties`
(Phase 10) ballots are exponent-ElGamal ciphertexts under the aggregate key of
the vote's registered key parties, each of which time-locks its secret key in
a verifiable timed commitment (VTC). The `Solution` item, `puzzle_T`, and the
`discriminant`/`generator` tags are gone; `KeyParty` (0x06) and `Share` (0x09)
items exist instead.

**A36 — Secrecy assumption.** Secrecy until `close_block` holds if at least
one key party declared by a ballot is honest (keeps its share secret and
chose a sufficient delay). Full collusion of all key parties yields only an
early *anonymous* count; it never reveals identities and cannot affect
integrity, ordering, or the result.

**A37 — Sybil liveness cost.** An attacker holding `k` credentials can
register `k` key parties (one per person and vote, enforced by the
`poseidon(s, "keyparty", vote_id)` nullifier) and withhold their shares,
forcing defenders to spend `k` parallel `T`-length sequential computations
before the result appears. This is a liveness cost only, bounded by the
Issuer's Sybil resistance.

**A38 — Ballots declare their party set.** Whitepaper §10 says `PK` is
"fixed at `open_block`" over all valid KeyParty items. A key party's
registration can be anchored before `open_block` while its Anchor item is
published only after ballots were cast — not as an attack but as the normal
case, since an OpenTimestamps proof completes about an hour after the block.
If `PK` were "all parties anchored before open", every ballot cast before the
last such anchor surfaced would decrypt to garbage. So
each ballot lists the `keyparty_id`s it encrypted to (sorted, ≤ 32), and
decryption of that ballot needs exactly those shares. The counting rule
requires each declared party to have been anchored before `open_block`
(otherwise the ballot is discarded), which bounds the attack of A37 to parties
registered in time. The delay requirement `T_i ≥ required_delay(close − h_a)`
and the duplicate rule are applied by the *client* when choosing parties and
reported by verifiers as a secrecy label; they are not counting conditions,
because a late-surfacing anchor could otherwise retroactively invalidate a
party and strand the ballots that declared it.

**A42 — `Share` references the KeyParty by content id**, not by `pk_i` as
whitepaper §6 lists, so two registrations that happen to carry the same `pk`
cannot be confused; `pk_i` is available through the referenced item.

**A39 — Secrecy of initiative-derived votes** is chosen by the initiative's
author: the Initiative item carries a `secrecy` byte that is copied into the
derived VoteDefinition. (A protocol constant would have to flip when
`keyparties` ships; an author choice needs no flag day.)

**A40 — VTC parameters and deviations from the paper.** Ristretto255 for
ElGamal (already in the dependency tree through Ed25519, prime order, no
cofactor handling); RSW puzzles over a party-generated 2048-bit RSA modulus
with a Wesolowski proof of exponentiation for `h = g^(2^T)`; Shamir threshold
33 of 64 shares, 32 opened by a Fiat–Shamir challenge, soundness
`1/C(64,32) ≈ 2^−60.7`; no range proofs or homomorphic packing because a single
honest unopened puzzle already reconstructs the secret together with the 32
opened shares. Every deviation from Thyagarajan et al. (CCS 2020) is listed in
SPEC §10.6. Rule 1 carve-out: the VTC is the only construction assembled here
from primitive crates (big integers, primality tests, RSA key generation,
Ristretto255, BLAKE3, AEAD).

**A13 — Delay sizing.** `required_delay(blocks) = blocks × 600 × S_MAX_RSA ×
3/2` with `S_MAX_RSA = 2^26` sequential 2048-bit squarings per second (the
whitepaper leaves `S_max` open; FPGA results from the 2019–2020 VDF Alliance
competition were ≈ 25 ns per 1024-bit squaring, so 2^26/s is a conservative
ASIC bound for 2048-bit). A one-week vote whose parties register one day
before open needs `T ≈ 7 × 10^13`; a commodity solver at ~10^6 squarings/s
would need about two years to force open, which is why voluntary publication
after close is the normal path and forced opening is the deterrent. Hard cap
`T_CAP = required_delay(3 × MAX_VOTE_BLOCKS)` (whitepaper §14). Dev mode allows
tiny delays.

**A19 — Ballot payload.** Under `none`, one byte. Under `keyparties`, the
sorted party list plus two Ristretto points (64 bytes); the ElGamal
randomness is `scalar_wide(H_B64("rand"; s || vote_id))`, so the payload is
deterministic and retransmissions are byte-identical as whitepaper §8
requires. No nonce or AEAD is involved on the ballot itself.

**A20 — Deterministic proofs.** Groth16 proving is randomized; the client
seeds its RNG from `H_B("proof-rand"; s || content_id)` and stores the produced
bytes, so retransmissions are byte-identical as §8 requires.

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

**A43 — Direct anchors are operator-driven.** Broadcasting a Bitcoin
transaction needs a funded wallet, which the reference node does not embed.
The node offers `prepare-direct-anchor` (prints the root and the `OP_RETURN`
script for everything not yet anchored) and `publish-direct-anchor` (builds
the Anchor item from the confirmed raw transaction and its merkleblock
proof). Verification of direct anchors is fully implemented.

**A44 — Difficulty rules in the header chain.** Every header is checked for
linkage and proof of work against its own target. Full retarget validation
needs the window's first header; the chain enforces that the target changes
only at 2016-block boundaries and by at most the 4× consensus clamp, which
bounds what a lying header source could do (a header at the wrong difficulty
is rejected; a valid-but-stale chain only delays anchors). Nodes additionally
wait for 6 confirmations before using a header.

**A45 — Mix details not fixed by the whitepaper.** A hop's Sphinx address
is its registered Ed25519 node key; a hop resolves the next address to an
endpoint through its own Log, so routing needs no extra directory. The last
hop of a path is the exit and submits the payload to its Log. Every packet
has the same 2 KiB payload regardless of route length or item size; items
larger than that (key-party registrations) go direct. Decoys are payloads
starting with a fixed marker that exits drop silently. Status queries by
nullifier go through the same transport as the ballot (Tor when available)
so they do not link the voter's IP to the nullifier. Both paths of a
dual-path send share the guard and are otherwise hop-disjoint when enough
nodes exist. Node operators' `operator`, `country`, `asn` are self-declared
(A29). The whitepaper's `max(3 s, 8 messages)` hold is implemented per
message: forwarded once it is at least 3 s old *and* 8 later messages have
arrived, or at 60 s regardless, in shuffled batches; the queue is persisted
so a hop that crashes mid-hold forwards after restart.

**A46 — Key-party implementation details.** Registration generates two
1024-bit primes and 64 puzzles (about 8 s per party on this machine in a
dev build); the party's `φ` is discarded after the commitment. The proof of
exponentiation is `π = 1` when `2^T < l` (dev delays), so the structural
check admits `π ∈ [1, N−1]`. The node's solver role starts one sequential
job per party as soon as the registration is on the Log (whitepaper §10
"solvers start at once"), bounded by `--solver-parallel`; the reference
solver uses `num-bigint-dig` squarings (measured 1.95 × 10⁵ per second on
the development machine, 345× below `S_MAX_RSA = 2^26`), so real delays take
far longer than the vote — see A53. The client relaxes the delay requirement
only in dev mode (`ParticipantClient::dev`).

**A52 — `min_parties` is a floor, not a default.** A `keyparties` ballot may
declare any subset of the vote's key parties, and an *empty* one aggregates to
the identity point: `c2 = option · G + r · 0 = option · G`, which anyone reads
by the same table lookup the tally uses. That is a public ballot inside a
secret vote — a direct failure of G4, independent of coercion (which the
whitepaper already excludes from scope, §16.1). So the VoteDefinition carries
`min_parties`, set by the Issuer, `0` under `none` and `1..=MAX_KEY_PARTIES`
under `keyparties`, and a ballot declaring fewer is invalid.

The check is on the ballot's own bytes only. It could instead have compared
against the parties actually available, but that number depends on which
anchors have surfaced, so a late-surfacing anchor would retroactively
invalidate ballots that were correct when cast — the stranding A38 exists to
avoid. The cost of the weaker check is that a coerced voter may still choose
*which* parties to name; the cost of the floor itself is castability, since a
vote whose volunteers never reach `min_parties` cannot be voted in at all.
Clients fail loudly in that case (`ParticipantError::TooFewKeyParties`) rather
than silently dropping to a smaller set.

**A53 — Solvers force open only declared parties.** The counting rule needs
the shares of `∪ b.party_ids` over the counted ballots and no others (SPEC
§12), so a key party nobody encrypted to is never on the path to a result.
Solving every registration instead would let anyone register key parties in
bulk and bill the network one `T`-length sequential job apiece — A37's
liveness cost, but unbounded, since such a registration would not have to
survive client selection to be expensive. The node's solver therefore skips
parties no ballot named.

**A54 — Forced opening is a guarantee of existence, not of timeliness.**
`required_delay` is sized so that hardware at `S_MAX_RSA` cannot finish before
`close_block`; a solver `k`× slower than that therefore finishes about
`k × 1.5` vote-lengths after the party registered. Measured on the development
machine, the reference solver runs at 1.95 × 10⁵ squarings/s against an
assumed `2^26`, i.e. `k ≈ 345`: an 8-day vote's `required_delay` of
6.96 × 10¹³ squarings is 12 days at `S_MAX_RSA` and about 11 years here. An
optimised Montgomery implementation closes perhaps one order of magnitude of
that, not three.

So whitepaper §10's "liveness never depends on key parties" holds only in the
limit. In operation, a `keyparties` vote gets its result because every party
publishes voluntarily at close; a single party that vanishes stalls the vote
until somebody with hardware near `S_MAX_RSA` finishes, and nothing in the
protocol obliges anyone to own such hardware. This is a named infrastructure
assumption in the same sense as the OpenTimestamps calendars (A43), not a
property the cryptography provides. Lowering `S_MAX_RSA` to a rate volunteers
can match is not a fix: it lowers the bar for an adversary with real hardware
to read the running count early, which is the attack the delay exists to
prevent.

**A55 — Key-party selection inherits the Issuers' Sybil resistance, and no
more.** A key party proves membership in the vote's registry, so registrations
are limited by that Issuer's willingness to enrol people. But an Issuer is
just an Ed25519 key that signs a root (§4.3), and nodes accept any registry
they are configured to store, so "how many key parties can one actor
register" is bounded by nothing the protocol checks. Two consequences, both
recorded rather than fixed:

- **Grinding.** Clients select the `MAX_KEY_PARTIES` lowest `keyparty_id`s,
  and that id is `blake3` of item bytes the party controls; re-randomising one
  puzzle costs a single modular exponentiation. A party can aim at the
  selected set, and enough parties can occupy all of it.
- **Flooding.** Any selection rule over an open pool has this shape. Ordering
  by an unpredictable beacon (a Bitcoin block hash at `open_block`, say) would
  stop grinding, since the value does not exist when parties register — but an
  actor holding a fraction `f` of registrations still captures every one of
  `n` slots with probability about `fⁿ`, which is near 1 once they are most of
  the pool. Unbiasable selection and Sybil resistance are different problems,
  and only the first is solvable by a selection rule.

Key-party secrecy is therefore bounded by the social recognition of Issuers:
it holds against anyone who cannot mint credentials wholesale under a registry
that nodes and voters accept. Removing the bound needs a construction with no
committee at all (whitepaper §17).

**A56 — A key party is anonymous on the Log but not on the wire.** The
`KeyParty` item names nobody: membership is proved in zero knowledge, and the
nullifier `poseidon(s, "keyparty", vote_id)` is scoped by both tag and vote, so
it links neither to that person's ballot in the same vote nor to anything they
do in another (A50). Two things leak outside the item:

- **The address that submits it.** A registration is ~32 KB and does not fit a
  Sphinx payload (`MAX_MESSAGE_LEN` ≈ 2 KB), so it cannot be mixed; it goes
  direct, over Tor when the client has it (`--tor`). A `Share` is 97 bytes and
  does go through the mix, among ballot traffic. Registering and later opening
  are two observable acts by one party, which is why they do not take the same
  path.
- **Self-disclosure.** Announcing "I am a key party for this vote" is what
  makes the role accountable, and it is also what makes the person coercible.
  The protocol supports either choice and takes neither: whitepaper §16.6 no
  longer recommends publicising it.

The vote's creator is deliberately *not* auto-registered as a key party. It
would guarantee `min_parties ≥ 1` is satisfiable and give one publicly
accountable guarantor, but every key party can stall a vote by withholding its
share (A54), so it would hand whoever defines a vote a veto over its result —
a power the trust table says they do not have. A `keyparties` vote with too few
volunteers is uncastable instead, which is a failure the Issuer can see coming
rather than one it can cause.

**A57 — The Issuer names who may call votes over its electorate.** A
`VoteDefinition` of Authority origin used to be checked against
`AUTHORITY_KEYS`, a deployment constant. Two things were wrong with that.
Nothing tied an authority to an Issuer, so any key a deployment recognised
could call a vote over *any* electorate, whose Issuer neither consented nor
was told. And it was a constant compiled into nodes and verifiers: anyone
could become an Issuer with no permission at all, but adding a vote caller
meant shipping software to the whole network.

The list now lives in the Registry snapshot, inside the signed payload, so it
is the Issuer's statement about its own electorate and revoking a caller is an
ordinary re-publish at the next epoch. A state that both defines the electorate
and calls its votes lists its own key, and the two roles collapse into one
without the protocol having to assume they always do. A deployment that wants
an electoral commission genuinely independent of the population register lists
the commission instead, and then the separation is a checkable fact rather
than a convention.

**Empty means initiatives only.** An Issuer that names nobody has an
electorate in which no top-down vote can exist; the only way a vote arises is
an Initiative its own members raise and support past the threshold (§13). This
is the default for a new Issuer, so calling votes over other people's
electorates is not something one forgets to turn off.

What this does *not* do is make an Authority trustworthy. It is still trusted
for creating votes, and the Issuer that names it is still trusted for the
electorate; a government holding both keys has exactly the powers it had
before. The change removes a way for unrelated parties to interfere and
removes a centralisation point, not a trust assumption.

**A58 — A client fetches its own Merkle path, not the electorate.** The
membership proof needs one leaf's 32 siblings. The client used to download the
whole leaves file and rebuild the tree, which is 32 bytes per registered person
— 320 MB for ten million — on every cast, from a phone. It now fetches
`GET /v1/registry/{issuer}/{root}/path/{commitment}`: `index(u32) || siblings`,
1 028 bytes whatever the electorate's size.

Nothing is given up. The old check was that the served leaves rebuild the
signed root; the new one is that the served path rebuilds it, from
`root_from_path(commitment, index, siblings)`. A node that lies about the index
or any sibling produces a root that does not match the Issuer's signature, and
is caught in the same place for the same reason. What the client no longer
learns is every other person's commitment, which it had no use for.

An Issuer still publishes the full leaves file once per epoch, and
`POST /v1/registry` carries it in one body, capped at
`MAX_REGISTRY_BODY_BYTES` (512 MiB) — enough for a continental electorate.
Nodes serve `…/leaves` unchanged for anyone who wants to rebuild the tree
themselves, which is how the root is audited.

**A59 — Limits stated by the protocol must be reachable through the transport
that carries it.** Two were not:

- Axum's default request body limit is 2 MiB, well under `MAX_ITEM_BYTES`
  (8 MiB), so the HTTP layer quietly rejected items the validity rules accept —
  and, before A58, made a registry above roughly 65 000 people impossible to
  publish at all (measured: 65 000 leaves accepted, 100 000 refused with 413).
  Both routes now declare limits taken from the protocol's own constants.
- `MAX_ANCHOR_LEAVES` was 1 000 000, i.e. 30 MiB of leaves inside an item
  capped at 8 MiB. No anchor near it could ever encode, so the real ceiling was
  262 144 and the constant described nothing. It is now 200 000, comfortably
  under the item cap. Several anchors per block were always fine — §12 takes
  the earliest height covering an item, whoever published it — so the smaller
  figure costs nothing.

Request timeouts and rate limiting are deliberately not attempted in-process;
they belong to a reverse proxy, and pretending otherwise would suggest a node
is safe to expose directly.

**A28 — Receipt** is 8 Crockford-base32 characters of `H_B("receipt"; n || c)`.

**A60 — The ceremony is implemented here, and it is the second exception to
Hard rule 1.** No cryptographic primitive is implemented in this repository;
the ceremony is not a primitive but it is a construction assembled from them
(pairings, group exponentiation, BLAKE3), like `cv-vtc`, and it carries the
same warning: it must be audited before a binding ceremony is run with it.

It is implemented rather than delegated because there is nothing to delegate
to. The maintained MPC implementations are `snarkjs` (JavaScript, `.zkey`)
and the bellman-era `powersoftau`/`phase2` crates (unmaintained, a different
field library). Neither speaks arkworks R1CS, and interoperating would mean
exporting this circuit to circom's format and matching its wire ordering
exactly — the same amount of unaudited code, in a place where a mistake is
harder to see. Reusing an existing **phase 1** is a different and better
proposition: the Perpetual Powers of Tau transcript for BN254 has far more
contributors than this project will attract, its phase 1 is
circuit-independent, and an importer for its format is perhaps 200 lines. It
is not done here because the format cannot be verified against a real file
without downloading multi-gigabyte transcripts, and guessing at a binary
layout is exactly the kind of mistake this file exists to record. A
deployment that wants the stronger phase 1 should write that importer and
skip `cv-ceremony new`.

**A61 — More ballots than the electorate has leaves is reported, not
counted.** A vote names one `registry_root` and every ballot proves
membership in it, so `counted ≤ leaf_count` is an invariant of the counting
rule; one leaf yields one nullifier per vote, and a person with two leaves is
two leaves. `tally` therefore returns `Outcome::Impossible` rather than a
result when the invariant breaks, and the verifier prints what it means:
either the Groth16 parameters are compromised and proofs are being forged, or
the Issuer signed a `leaf_count` its own tree does not have.

This is a backstop, not a defence, and it is important to be honest about how
weak it is. It fires only after a forger has cast more ballots than there are
people, so a forger who stays inside the turnout headroom — filling in for
the people who did not vote, which in a real electorate is most of them — is
invisible to it and to everything else. It costs one lookup, it makes
large-scale stuffing publicly self-evident rather than merely suspected, and
it is the only trace forgery leaves anywhere in the Log. `A24` is still the
thing that keeps ballots honest.

**A62 — Release mode refuses to run without a pinned verifying-key hash.**
Before this, release mode demanded ceremony keys and then loaded whatever
file it was pointed at, which is the same security as no ceremony: an
attacker who can place a key file (or a `--keys-dir`) runs their own
one-person setup and keeps the secret. Binaries now take the expected BLAKE3
of the verifying key from `MEMBERSHIP_VK_BLAKE3` compiled into the build, or
from `--vk-hash` as a deployment constant like `--checkpoint-header`, and
refuse to start with neither. `MEMBERSHIP_VK_BLAKE3` is `None` in this
repository because no ceremony has been run for any deployment; a deployment
sets it after its own and ships that build.