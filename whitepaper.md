# A Trust-Minimized Protocol for Frequent Anonymous Voting

**Working title. Draft v0.2 — September 2026**

---

## Abstract

This document specifies a voting protocol intended for frequent (weekly or monthly) votes and citizen initiatives at national or continental scale, cast from personal phones. Integrity is trustless: no party can add, remove, alter, or read a ballot before the deadline, and anyone can recompute the result from public data. Ballot secrecy rests on cryptography and on a sender-hiding network layer rather than on any committee. The protocol has no token, no miners, and no fees for voters. It requires exactly two trusted components, both stated explicitly: a state identity issuer that decides who is an eligible person, and the voter's own device.

---

## 1. Goals and non-goals

**Goals**

- G1. One eligible person, at most one counted ballot per vote.
- G2. Nobody, including any group of operators, can forge, drop, alter, or backdate a ballot.
- G3. Nobody can learn how any person voted, or whether a given person voted.
- G4. Nobody can read any ballot before the deadline.
- G5. Anyone can verify the result from public data with a small, independently implementable verifier.
- G6. The vote resolves correctly at any turnout, and with any number of nodes (including one).
- G7. Voters pay nothing, and by default nobody pays anything. There is no token.
- G8. Eligible persons can put a question to a vote by collecting a threshold of anonymous supports.

**Non-goals (explicitly out of scope for v0.1)**

- Coercion resistance and receipt-freeness. A voter who wishes to prove how they voted can do so.
- Protection against malware on the voter's own device beyond cast-as-intended checks.
- Protection against a global passive network adversary.
- Binding use for high-stakes elections. The protocol targets frequent, lower-stakes decisions.

---

## 2. Trust assumptions

Everything not listed here is trustless.

| Component | What is trusted | What it cannot do |
|---|---|---|
| **Issuer** (state eID authority) | Correctly decides who is one eligible person and publishes the registry honestly. | Cast, read, drop, or link any ballot; move any deadline; alter any result. |
| **Voter's device** | Casts the option the voter chose and protects the voter's secret. | Anything beyond that one voter's own ballot. |
| **Bitcoin** | Provides an unforgeable public ordering of anchored roots (standard assumption: honest majority of hash power). | Read or alter ballots. Used only as a clock. |
| **OpenTimestamps calendars** | Trusted **only for liveness**: that at least one of several independent calendars aggregates submitted hashes into Bitcoin in a timely way. | Forge, backdate, or omit-without-detection any timestamp; every proof they return is verified against Bitcoin directly. |
| **Cryptographic assumptions** | Soundness and zero-knowledge of the proof system; hardness of sequential squaring in class groups; collision resistance of the hash. | — |
| **Mix nodes and Tor** | Trusted **only for privacy**, never for correctness. Full collusion of a voter's entire path degrades that voter's anonymity, not the result. | Affect the tally in any way. |

---

## 3. Actors

- **Issuer.** Verifies real-world identity once and maintains the Registry (§5). Has no other role.
- **Participant.** A person holding a secret `s` on their device. Can vote, author initiatives, support initiatives, and register a node.
- **Node.** Any machine storing and relaying the Log (§6). Optionally acts as a mix hop, an anchorer, or a solver. Anyone may run one.
- **Anchorer.** A node that gets a root of its Log view committed into Bitcoin, by default for free through OpenTimestamps calendars, optionally by paying for a direct transaction.
- **Solver.** Anyone who computes a vote's time-lock puzzle solution.
- **Verifier.** Anyone who recomputes a result from the Log.

No actor other than the Issuer has any privilege.

---

## 4. Primitives

All primitives are used as black boxes and named here so that an implementation is exact.

- `H(·)` — collision-resistant hash (e.g. Poseidon inside circuits, BLAKE3 outside).
- **Merkle tree** — binary hash tree over Registry leaves; root `R`.
- **Membership proof system** — a zero-knowledge proof `π` for the statement:
  *"I know `s` such that `H(s)` is a leaf in the tree with root `R`, and `n = H(s, tag, id)`."*
  Proof size is constant (a few hundred bytes); verification is milliseconds; proving on a phone is seconds. (Semaphore-style construction; Groth16 or Halo2/Noir.)
- **Time-lock puzzle** — repeated squaring in the class group of an imaginary quadratic field with discriminant `D` derived from public data. No trapdoor exists for anyone. Solution `y = g^(2^T)` is accompanied by a Wesolowski proof, verifiable in milliseconds.
- `Enc_K(·)` — authenticated symmetric encryption (e.g. XChaCha20-Poly1305).
- **Onion encryption** — layered public-key encryption to mix hops (Sphinx packet format).
- **Bitcoin SPV** — verification that a transaction is included in a block at a given height, using block headers only.
- **OpenTimestamps (OTS) proof** — a chain of hash operations from a submitted digest up to a Bitcoin transaction. Verifying an OTS proof reduces to recomputing the hash chain and one SPV check; no calendar is trusted for the verification.

---

## 5. Identity and the Registry

**Enrollment (once per person).**

1. The device generates a random secret `s` and stores it in the secure element. `s` never leaves the device.
2. The device computes the identity commitment `C = H(s)`.
3. The participant authenticates to the Issuer with their state eID and submits `C`.
4. The Issuer adds `C` as a leaf of the Registry.

**Registry publication.** The Issuer periodically publishes the complete leaf list and a signed root `R_t`. Nodes store the leaf list; anyone can recompute `R_t`. Each vote fixes one specific root (§7), so the eligible set for a vote is frozen and public.

**Replacement.** A participant who loses their device re-enrolls; the Issuer atomically replaces the old leaf with the new `C`. Because votes fix a root snapshot, a person can never hold two leaves in the same snapshot.

**What the Issuer learns.** That a given eID enrolled a given `C`. This is equivalent to a voter roll. `C` is never used on the Log directly; all actions are proven in zero knowledge against the tree, so the Issuer cannot link `C` to any ballot, support, or initiative.

---

## 6. The Log

The Log is a replicated, append-only **set** of self-validating items. There is no global ordering and no consensus among nodes; order is supplied only where needed by Bitcoin anchors (§9).

**Item types**

| Item | Contents |
|---|---|
| `VoteDefinition` | See §7. |
| `Initiative` | Text, author pseudonym `P`, proof, Registry root, support threshold `N`, support deadline block. |
| `Support` | `initiative_id`, nullifier `n = H(s, "support", initiative_id)`, proof `π`. |
| `Ballot` | See §8. |
| `Anchor` | Merkle root of a ballot set, plus either an OTS proof (default) or a direct Bitcoin `txid`; Merkle inclusion proofs on request. |
| `Solution` | `vote_id`, puzzle output `y`, Wesolowski proof. |
| `NodeRegistration` | Node public key, nullifier `n = H(s, "node")`, proof `π`. |

**Validity.** Every item is checked by every node on receipt against fixed rules (proof verifies, referenced objects exist, nullifier unseen, etc.). Invalid items are dropped and not relayed. Valid items are gossiped to all peers. Because validity is intrinsic to the item, honest nodes cannot disagree about it.

**Duplicates.** Two items with the same nullifier:
- **Byte-identical** → one is a retransmission; keep one.
- **Different** → a double action; **all** items with that nullifier are invalid for the tally.

**Pruning.** After a vote's result is verified and archived, nodes may discard its ballots, keeping the result and the anchored roots. Archival nodes keep everything.

---

## 7. Vote definitions

A `VoteDefinition` contains:

```
vote_id        = H(all fields below)
question       : text
options        : list of strings (≥ 2)
registry_root  : R_t   (frozen eligible set)
open_block     : Bitcoin block height at which ballots become valid
close_block    : Bitcoin block height; ballots must be anchored at or before it
min_ballots    : minimum valid ballots for a result to be published
puzzle_T       : number of sequential squarings
origin         : either an authority signature, or an initiative_id that reached threshold
```

**Puzzle parameters** are derived, never chosen:

```
D        = class-group discriminant derived from H(vote_id, "discriminant")
g        = group element derived from H(vote_id, "generator")
K        = H(y)  where y = g^(2^T)          (the ballot encryption key)
puzzle_T = (close_block − open_block) × 600 s × S_max × M
```

where `S_max` is the assumed squarings-per-second of the fastest hardware anyone could build and `M ≥ 1.5` is a safety margin. Any participant can derive `K`'s *encryption* input cheaply (encryption uses `g` and `T`, not `y`); only *decryption* requires the sequential work.

**Two ways a vote is created**

1. **Authority.** A recognized public key (e.g. a parliament) signs a definition.
2. **Initiative.** When an `Initiative` has ≥ `N` distinct valid `Support` items anchored before its support deadline, a `VoteDefinition` is **derived deterministically** from the initiative (its text becomes the question; `open_block` = threshold-anchor block + fixed delay). No one authors it, so no one can alter the wording or timing.

---

## 8. Ballots

To vote in `vote_id`, the device:

1. Computes the nullifier `n = H(s, "ballot", vote_id)`.
2. Derives deterministic randomness `r = H(s, "rand", vote_id)`.
3. Encrypts the chosen option index: `c = Enc_K(option; r)` using the puzzle-derived key.
4. Produces `π` proving membership in `registry_root` and correct derivation of `n`.
5. Emits `Ballot = { vote_id, n, c, π }`.

Because `r` is derived from `s` and `vote_id`, every retransmission is byte-identical (§6 duplicates rule).

**A ballot is counted iff**

- `π` verifies against the vote's `registry_root`;
- `n` is unique among ballots for `vote_id` (§6);
- the ballot is included in some `Anchor` at Bitcoin height ≤ `close_block` (§9);
- the ballot's full bytes were published on the Log before the vote's `Solution` was published;
- after decryption, the plaintext is a valid option index.

The proof is public and the nullifier is per-vote, so ballots from the same person in different votes are unlinkable, and are unlinkable to that person's initiatives and supports.

---

## 9. Deadline and anchoring

**Anchoring.** Any node may, at any time, build a Merkle root over all valid ballots it currently holds and get that root committed into Bitcoin. Two paths exist:

1. **OpenTimestamps (default, free).** The node submits the root to several independent public OTS calendars. Each calendar aggregates all digests it receives into a single Bitcoin transaction (typically within an hour) and returns a proof. The node publishes an `Anchor` item carrying the root and the OTS proof once the proof is complete. The calendars pay the Bitcoin fee; neither the node nor any voter pays anything.
2. **Direct (optional, paid).** The node publishes the root inside its own Bitcoin transaction and publishes an `Anchor` item with the `txid`. This costs a few dollars and removes any dependency on calendar uptime.

In both cases verification is identical: recompute the hash chain (OTS) or read the transaction (direct), then check block inclusion by SPV. Calendars are never trusted for verification; an `Anchor` whose proof does not resolve to a Bitcoin block is simply invalid.

**Counting rule.** A ballot counts if it appears under **any** valid anchor at height ≤ `close_block`, regardless of which path produced the anchor. The tally is over the union of all anchored sets. Consequently:

- An anchorer that omits ballots harms nothing as long as any other anchorer includes them.
- An anchorer cannot include a ballot that did not yet exist, so nothing can be backdated.
- An anchorer cannot make an invalid ballot valid.
- One honest anchorer suffices for a correct result.

**Calendar outage.** If all calendars are unreachable or slow, the free path stalls but nothing breaks: any node may fall back to a direct anchor, and a single such anchor before `close_block` secures every ballot it covers. Nodes should submit to at least three calendars and should treat a pending (not yet Bitcoin-confirmed) OTS proof as unverified.

**Fallback (degraded mode).** If no anchor of either kind exists for a vote, nodes fall back to witness signatures: a ballot counts if signed as seen-before-close by ≥ `W` registered nodes. This mode is weaker (colluding nodes could backdate) and results computed under it are labelled as such.

**Deadline precision.** The close is exact in the sense that all verifiers agree which ballots are inside it. It may drift from wall-clock time by the variance of Bitcoin block arrival (typically under two hours over a week).

---

## 10. Opening and tally

1. From `open_block` onward, anyone may begin the sequential computation `y = g^(2^T)`.
2. The first solver publishes `Solution = { vote_id, y, proof }`. Anyone verifies the proof in milliseconds.
3. Everyone derives `K = H(y)` and decrypts every counted ballot.
4. Ballots whose plaintext is not a valid option index are discarded.
5. The result is the count per option. If counted ballots < `min_ballots`, no result is published.

The result is a pure function of public data. Any verifier can recompute it; no `Result` item is authoritative.

**Timing.** The puzzle is sized so that even the fastest plausible solver finishes after `close_block`. If a solver finishes early, they gain a private preview of a partial count; the deadline and result are unaffected. If solvers finish late, the result appears late. Neither affects correctness.

---

## 11. Initiatives

- Any participant may publish an `Initiative` under a **persistent author pseudonym** `P = H(s, "author")`, with a proof that `P` is derived from an `s` whose commitment is in the Registry. `P` is unlinkable to the author's ballots and supports, but constant across their initiatives, allowing a track record.
- Any participant may publish one `Support` per initiative (nullifier `H(s, "support", initiative_id)`). Supports are anonymous and are checked for eligibility and uniqueness exactly like ballots.
- When ≥ `N` valid supports are anchored before the support deadline, the vote is created deterministically (§7). `N` is a protocol parameter (e.g. a percentage of the Registry size at the initiative's root).

---

## 12. Network and privacy layer

The network layer affects **only privacy**, never correctness.

**Nodes.** Store and gossip the Log; serve it to phones and verifiers. Phones are light clients: they never trust a single node and verify anchors by SPV.

**Mix.** A ballot travels to the Log through up to three hops:

- The device selects hops from **registered** nodes (one `NodeRegistration` per person, §6) under diversity rules: distinct operators, distinct autonomous systems, distinct countries.
- The device keeps one **guard** (entry) node for months, so exposure risk does not accumulate across weekly votes.
- The ballot is onion-encrypted; each hop learns only its predecessor and successor.
- Each hop holds a message for `max(a few seconds, until k other messages have arrived)`, capped at a hard maximum, then forwards in shuffled order. Queues are disk-backed.
- If fewer than three eligible hops exist, the path is shortened; with one node, the device sends directly. **The vote always goes through.**

**Tor.** The connection to the first hop is routed through embedded Tor (Arti) **by default**, with automatic fallback to a direct connection if Tor is unreachable.

**Client responsibility.** The device keeps the ballot until it observes its own nullifier under an anchored root. If not observed within a window, it re-sends through a fresh path. By default it sends through two independent paths at once; the Log deduplicates. Devices may emit indistinguishable decoy messages during a vote so that observers cannot tell whether a person voted.

**Privacy indicator.** The client displays the protection level actually achieved (full path + Tor / partial / direct) and never degrades silently.

---

## 13. Security summary

| Adversary | Can | Cannot |
|---|---|---|
| Issuer | Enroll or refuse to enroll persons; see who enrolled. | Cast, read, link, drop ballots; alter results; move deadlines. |
| Any single node | Refuse to relay. | Anything else. |
| Majority of nodes | Degrade availability; attempt deanonymization via traffic if they also hold a voter's full path; backdate ballots **only** in fallback mode. | Forge, drop (given one honest node), or alter counted ballots; change results; open ballots early. |
| Any anchorer | Choose what to include in its own anchor. | Backdate, validate, or invalidate any ballot. |
| OTS calendars (all colluding) | Delay or refuse service, stalling the free path until someone anchors directly. | Forge or backdate a proof; affect any ballot or result. |
| Fastest puzzle solver | Privately see a partial count slightly before close. | Change any ballot or the deadline. |
| Full mix-path collusion for one voter | Link that voter's IP to their ballot. | Affect the result. |
| Malware on a voter's device | Miscast that voter's ballot. | Affect any other voter. |

---

## 14. Default parameters (v0.1)

| Parameter | Default |
|---|---|
| Mix hops | 3 (fewer if unavailable) |
| Hop delay | 3 s or until 8 other messages, max 60 s |
| Paths per ballot | 2 |
| Guard rotation | 90 days |
| Puzzle margin `M` | 1.5 |
| `min_ballots` | 100 |
| Anchoring cadence (per anchorer) | hourly during open votes |
| OTS calendars per submission | 3 (independent operators) |
| Fallback witness threshold `W` | 7 registered nodes |
| Initiative threshold `N` | 1 % of Registry size |

---

## 15. Implementation

- **Core library in Rust**: proof generation/verification, puzzle, encryption, Log validation, mix client, OTS proof verification, Bitcoin SPV. Compiled to a server binary (node), a mobile library via UniFFI (iOS/Android), and WebAssembly (browser verifier). One implementation of the validity rules for all three.
- **Circuit** in Noir or Circom; kept minimal (membership + nullifier derivation only).
- **Apps**: native Kotlin/Swift or Flutter shells; the UI never touches cryptography.
- **Specification first**: this protocol, plus byte-exact formats and test vectors, so that independent verifiers in any language agree with the reference. The reference verifier is intentionally small enough to be read in full.
- **Cast-as-intended check**: the device displays a short code derived from `(n, c)`; a second device or a web verifier can confirm that exactly that ballot appears on the Log.

---

## 16. Known limitations

1. **Coercion and vote buying.** A voter can reveal `s`-derived witnesses to prove how they voted. Acceptable for frequent low-stakes votes; not for high-stakes elections.
2. **Device compromise.** Malware can miscast a ballot. Mitigated only by cast-as-intended checks.
3. **Issuer trust.** The Issuer defines the electorate. Everything else is verifiable; this is not.
4. **Network-level adversary.** An observer controlling ISPs and most registered nodes can attempt statistical timing correlation. Delays, decoys, and guards raise the cost; they do not eliminate it.
5. **Public ballot contents after opening.** Because contents become public, any metadata leak is a full leak for that ballot. This is the price of removing trustees.
6. **Timing fuzziness.** The close drifts with Bitcoin block variance; results appear when the puzzle is solved, not exactly at close.

---

## 17. Future work

- **Delegation** (liquid democracy): signed, revocable, per-topic delegation resolved at tally time, with direct votes overriding.
- **Everlasting privacy**: perfectly hiding commitments on the Log with separately held, eventually deleted encryptions.
- **Coercion resistance**: fake-credential schemes (JCJ/Civitas family) adapted to the nullifier design.
- **Sortition-based ordering**: replacing Bitcoin anchoring with a randomly drawn committee of verified participants, once such consensus is practical at scale.
- **Multiple identity roots**: web-of-trust or proof-of-personhood roots alongside state eID, selectable per vote.

---

*This draft describes a protocol, not a deployed system. Every cryptographic component named here should be independently audited before any binding use.*
