# A Trust-Minimized Protocol for Frequent Anonymous Voting

**Working title. Draft v0.5 — September 2026**

---

## Abstract

This document specifies a voting protocol intended for frequent (weekly or monthly) votes and citizen initiatives at national or continental scale, cast from personal phones. Integrity is trustless: no party can add, remove, alter, or read a ballot before the deadline, and anyone can recompute the result from public data. Ballot anonymity rests on cryptography and on a sender-hiding network layer. Secrecy of the running count until the deadline rests on an open set of volunteer key parties, of which only one needs to be honest, and anyone (including the voter) may be one. The protocol has no token, no miners, and no fees for voters. It requires exactly two trusted components for correctness, both stated explicitly: a state identity issuer that decides who is an eligible person, and the voter's own device.

---

## 1. Goals and non-goals

**Goals**

- G1. One eligible person, at most one counted ballot per vote.
- G2. Nobody, including any group of operators, can forge, drop, alter, or backdate a ballot.
- G3. Nobody can learn how any person voted, or whether a given person voted.
- G4. When a vote is configured for secrecy, nobody can read any ballot before the deadline unless every volunteer key party colludes.
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
| **Issuer** (any registry operator: a state eID authority, a KYC-backed operator, or a test operator) | Correctly decides who is one eligible person and publishes its registry honestly. Each vote names the Issuer it relies on. | Cast, read, drop, or link any ballot; move any deadline; alter any result. |
| **Voter's device** | Casts the option the voter chose and protects the voter's secret. | Anything beyond that one voter's own ballot. |
| **Bitcoin** | Provides an unforgeable public ordering of anchored roots (standard assumption: honest majority of hash power). | Read or alter ballots. Used only as a clock. |
| **OpenTimestamps calendars** | Trusted **only for liveness**: that at least one of several independent calendars aggregates submitted hashes into Bitcoin in a timely way. | Forge, backdate, or omit-without-detection any timestamp; every proof they return is verified against Bitcoin directly. |
| **Key parties** (votes with `secrecy: keyparties`) | Trusted **only for pre-deadline secrecy**, and only collectively: the running count stays hidden if **at least one** registered key party is honest. Anyone may register, including the voter. | Read identities; forge, drop, or alter ballots; delay the result (their shares can be forced open by anyone). Full collusion yields only an early anonymous count. |
| **Cryptographic assumptions** | Soundness and zero-knowledge of the proof system; hardness of sequential squaring modulo an RSA integer; discrete log on the elliptic curve; collision resistance of the hash. | — |
| **Mix nodes and Tor** | Trusted **only for privacy**, never for correctness. Full collusion of a voter's entire path degrades that voter's anonymity, not the result. | Affect the tally in any way. |

---

## 3. Actors

- **Issuer.** Verifies real-world identity once and maintains a Registry (§5), identified by its signing key `issuer_key`. Several Issuers may coexist; each vote names exactly one. Has no other role.
- **Participant.** A person holding a secret `s` on their device. Can vote, author initiatives, support initiatives, register a node, and register as a key party.
- **Node.** Any machine storing and relaying the Log (§6). Optionally acts as a mix hop, an anchorer, or a solver. Anyone may run one.
- **Key party.** A participant who, for one vote, publishes a public key share and a timed commitment of the matching secret (§10). Votes configured for secrecy are encrypted to the aggregate of all key parties' keys.
- **Anchorer.** A node that gets a root of its Log view committed into Bitcoin, by default for free through OpenTimestamps calendars, optionally by paying for a direct transaction.
- **Solver.** Anyone who forces open a key party's timed commitment by sequential computation, guaranteeing that results never depend on a key party's cooperation.
- **Verifier.** Anyone who recomputes a result from the Log.

No actor other than the Issuer has any privilege.

---

## 4. Primitives

All primitives are used as black boxes and named here so that an implementation is exact.

- `H(·)` — collision-resistant hash: Poseidon over BN254 inside circuits, BLAKE3 outside, with domain-separation contexts as tags.
- **Merkle tree** — sparse binary Poseidon tree of depth 32 over Registry leaves; root `R`.
- **Membership proof system** — a zero-knowledge proof `π` (Groth16 over BN254) for the statement:
  *"I know `s` such that `H(s)` is a leaf in the tree with root `R`, and `n = H(s, tag, id)`."*
  One fixed-arity circuit serves ballots, supports, initiatives, node registrations, and key-party registrations; the third input scopes the nullifier (to a vote, an initiative, or a Registry), so nothing a person does in one electorate is linkable to what they do in another. A public input binds the proof to the item's content hash. Proof size is constant (a few hundred bytes); verification is milliseconds; proving on a phone is seconds.
- **EC-ElGamal** — additively keyed public-key encryption on an elliptic curve: keys `pk_i = sk_i · G` aggregate as `PK = Σ pk_i`, and decryption under `PK` requires `Σ sk_i`.
- **Verifiable timed commitment (VTC)** — a commitment to `sk_i` that (a) the committer can create quickly using the trapdoor of an RSA modulus they generated, (b) anyone can force open with `T` sequential squarings and no trapdoor, and (c) carries a proof that it opens to the discrete log of a stated `pk_i`. Construction per Thyagarajan et al., "Verifiable Timed Signatures Made Practical" (CCS 2020).
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

**Registry publication.** The Issuer periodically publishes the complete leaf list and a root `R_t` signed by `issuer_key`. Nodes store the leaf list; anyone can recompute `R_t`. Each vote fixes one specific `(issuer_key, R_t)` pair (§7), so the eligible set for a vote is frozen, public, and attributable to a named Issuer.

**Multiple Issuers.** The protocol does not privilege any Issuer. A state eID registry, a community registry with its own verification method, and a test registry are all just different `issuer_key`s. Verifiers display the Issuer next to every result, so the question "who defined this electorate?" always has a public answer. A person may hold a leaf in several registries; nullifiers are scoped per vote and votes are scoped per Issuer, so this creates no double voting within any electorate.

**Verification is the Issuer's own business.** The protocol only sees signed roots. How an Issuer decides that a person is real and unique (a national eID, in-person checks, a document-and-liveness provider, a web of trust, anything else) is entirely up to that Issuer, and it is the boundary of the system's Sybil resistance for that electorate. The reference Issuer exposes a single interface, "verify this enrollment and return a stable dedup key or a rejection," so that any method can be plugged in. Whatever the method, an Issuer should retain only `C`, the dedup key, and a timestamp.

**Replacement.** A participant who loses their device re-enrolls; the Issuer recognises them by the dedup key and atomically replaces the old leaf with the new `C`. Because votes fix a root snapshot, a person can never hold two leaves in the same snapshot.

**What the Issuer learns.** That a given verified identity enrolled a given `C`. This is equivalent to a voter roll. `C` is never used on the Log directly; all actions are proven in zero knowledge against the tree, so the Issuer cannot link `C` to any ballot, support, or initiative.

---

## 6. The Log

The Log is a replicated, append-only **set** of self-validating items. There is no global ordering and no consensus among nodes; order is supplied only where needed by Bitcoin anchors (§9).

**Item types**

| Item | Contents |
|---|---|
| `VoteDefinition` | See §7. |
| `Initiative` | Text, author pseudonym `P`, proof, `issuer_key`, Registry root, support threshold `N`, support deadline block. |
| `Support` | `initiative_id`, nullifier `n = H(s, "support", initiative_id)`, proof `π`. |
| `Ballot` | See §8. |
| `Anchor` | Sorted leaf list and Merkle root of a ballot set, plus either an OTS proof (default) or a direct Bitcoin `txid`. Anchors are expected to be incremental. |
| `KeyParty` | `vote_id`, `pk_i`, VTC of `sk_i` with delay `T_i`, consistency proof, nullifier `n = H(s, "keyparty", vote_id)`, proof `π`. |
| `Share` | `vote_id`, `pk_i`, the opened `sk_i` (published by the party or forced by a solver). |
| `NodeRegistration` | Node public key, `issuer_key`, Registry root, nullifier `n = H(s, "node", issuer_key)`, proof `π`. One per person per Registry. Needed only to be selected as a mix hop (§12); storing, relaying and anchoring need no registration at all. |

**Validity.** Every item is checked by every node on receipt against fixed rules (proof verifies, referenced objects exist, nullifier unseen, etc.). Invalid items are dropped and not relayed. Valid items are gossiped to all peers. Because validity is intrinsic to the item, honest nodes cannot disagree about it.

**Item identity.** An item's id is the hash of its content **excluding** the proof bytes (Groth16 proofs are re-randomizable, so proof bytes must not affect identity). The proof is bound to the content through a public input.

**Duplicates.** Two items with the same nullifier:
- **Same item id** → one is a retransmission; keep one.
- **Different item ids** → a double action; **all** items with that nullifier are invalid for the tally.

Only items anchored at or before the relevant deadline take part in the duplicate rule, so a result can never be retracted by something published after close.

**Pruning.** After a vote's result is verified and archived, nodes may discard its ballots, keeping the result and the anchored roots. Archival nodes keep everything.

---

## 7. Vote definitions

A `VoteDefinition` contains:

```
vote_id        = H(all fields below)
question       : text
options        : list of strings (≥ 2)
issuer_key     : signing key of the Issuer whose registry defines the electorate
registry_root  : R_t   (frozen eligible set; must carry a valid signature by issuer_key)
open_block     : Bitcoin block height at which ballots become valid
close_block    : Bitcoin block height; ballots must be anchored at or before it
min_ballots    : minimum valid ballots for a result to be published
secrecy        : none | keyparties
origin         : either an authority signature, or an initiative_id that reached threshold
```

**Secrecy modes.**

- `none` — ballots carry the option index in plaintext. The running count is public by design. No key parties exist.
- `keyparties` — ballots are encrypted to the aggregate key of all registered key parties (§10). Nothing can be read before close unless every key party colludes.

Verifiers display the mode alongside any result.

**Two ways a vote is created**

1. **Authority.** A recognized public key (e.g. a parliament) signs a definition.
2. **Initiative.** When an `Initiative` has ≥ `N` distinct valid `Support` items anchored before its support deadline, a `VoteDefinition` is **derived deterministically** from the initiative: its text becomes the question, and `open_block = support_deadline + 144` (about one day), so that a late-published earlier anchor cannot change the derived `vote_id`. No one authors it, so no one can alter the wording or timing.

---

## 8. Ballots

To vote in `vote_id`, the device:

1. Computes the nullifier `n = H(s, "ballot", vote_id)`.
2. Forms the payload `c`:
   - `secrecy: none` → `c = option index`.
   - `secrecy: keyparties` → `c = ElGamal_PK(option; r)` with deterministic randomness `r = H(s, "rand", vote_id)`, where `PK` is the aggregate key of all valid `KeyParty` items for this vote (§10).
3. Produces `π` proving membership in `registry_root` and correct derivation of `n`, bound to the content hash of `(vote_id, n, c)`.
4. Emits `Ballot = { vote_id, n, c, π }`.

Because `r` is derived from `s` and `vote_id`, every retransmission has the same item id (§6 duplicates rule).

**A ballot is counted iff**

- `π` verifies against the vote's `registry_root`, and that root carries a valid signature by the vote's `issuer_key`;
- `n` is unique among ballots for `vote_id` (§6);
- the ballot is included in some `Anchor` at Bitcoin height ≤ `close_block` (§9);
- the plaintext (after decryption, if encrypted) is a valid option index.

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

**No fallback.** An anchor is the only clock. Earlier drafts allowed a degraded mode in which, if no anchor existed for a vote, a ballot could count on the signatures of `W` registered nodes attesting they had seen it before close. That is removed. A signature is not a clock: `W` signatures are `W` keys, and what was supposed to make keys scarce — one registration per registered person — stops holding as soon as anyone may operate a Registry (§5), since an adversary can enrol `W` of themselves. Restricting the signers to the vote's own electorate only narrows the attack to the node operators of that electorate, who are the parties with the most to gain from backdating. Anchoring needs none of this: it is permissionless, costs nothing through the calendars, covers everyone's items whoever produced it, and is verified against Bitcoin rather than believed. A vote that nobody anchors therefore yields **no result**, which any single volunteer prevents, rather than a weakly attested one that every reader must learn to discount.

**Deadline precision.** The close is exact in the sense that all verifiers agree which ballots are inside it. It may drift from wall-clock time by the variance of Bitcoin block arrival (typically under two hours over a week).

---

## 10. Key parties, opening, and tally

This section applies to `secrecy: keyparties`. Under `secrecy: none`, the tally is simply the count of valid anchored ballots per option.

**Registration (before `open_block`).** Any participant may register as a key party for a vote by publishing a `KeyParty` item:

1. Generate an EC key pair `(sk_i, pk_i)` and an RSA modulus `N_i` whose factorization only they know.
2. Create a VTC of `sk_i` under `N_i` with delay `T_i`, using the trapdoor so this is fast.
3. Attach a consistency proof that the VTC opens to the discrete log of `pk_i`.
4. Attach the membership proof and nullifier `H(s, "keyparty", vote_id)`: one registration per person per vote.

A `KeyParty` item is valid iff its proofs verify, it is anchored at height `< open_block`, and

```
T_i ≥ (close_block − anchor_height_of_KeyParty) × 600 s × S_max × M      and      T_i ≤ T_cap
```

where `S_max` is the assumed squarings-per-second of the fastest hardware anyone could build and `M` is a safety margin. A party that registers early simply needs a longer delay. Because a weak or malformed `N_i` only weakens that party's own share, no proof of modulus quality is required.

**Aggregate key.** `PK = Σ pk_i` over all valid `KeyParty` items for the vote. It is fixed at `open_block` and is what every ballot encrypts to.

**Opening.** Decryption requires `SK = Σ sk_i`, i.e. every share. Shares become public in either of two ways:

- **Voluntary.** After `close_block`, a party publishes a `Share` item containing `sk_i`. Honest parties do this, making the result available immediately at close.
- **Forced.** From the moment a `KeyParty` item exists, any solver may begin forcing its VTC open (`T_i` sequential squarings on one core; one job per party, never per ballot). Solvers start at once as a matter of course, so every share is available by about `close_block` even if its party vanishes.

A `Share` is valid iff `sk_i · G = pk_i`. No further proof is needed.

**Tally.**

1. Once every share for the vote is present and the height is `> close_block`, compute `SK` and decrypt every counted ballot.
2. Discard ballots whose plaintext is not a valid option index.
3. The result is the count per option. If counted ballots < `min_ballots`, no result is published.

The result is a pure function of public data. Any verifier can recompute it; no `Result` item is authoritative.

**Properties.**

- Secrecy until close holds if **any one** key party is honest, since all shares are needed. A voter who wants certainty registers as a key party for that vote.
- Liveness never depends on key parties, since every share can be forced by anyone.
- If every key party colludes, or if all shares are forced early by hardware faster than `S_max × M`, the attacker learns only the running count of anonymous ballots. Identities and integrity are unaffected.
- An attacker holding `k` credentials can register `k` uncooperative parties, costing solvers `k` parallel `T`-length jobs. This is a bounded liveness cost, not a secrecy or integrity risk.

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

- The device selects hops from **registered** nodes (one `NodeRegistration` per person per Registry, §6) under diversity rules: distinct operators, distinct autonomous systems, distinct countries. Where the network cannot supply that — a deployment whose nodes sit in one country, say — the device takes the most diverse path available and reports which it got, rather than silently shortening the path.
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
| Any number of nodes, however large a majority | Degrade availability; attempt deanonymization via traffic if they also hold a voter's full path. | Forge, drop (given one honest node), backdate, or alter counted ballots; change results; open encrypted ballots early. Nothing a node signs enters the count, so no quorum of them has any standing. |
| Any anchorer | Choose what to include in its own anchor. | Backdate, validate, or invalidate any ballot. |
| OTS calendars (all colluding) | Delay or refuse service, stalling the free path until someone anchors directly. | Forge or backdate a proof; affect any ballot or result. |
| Any single key party | Publish or withhold its own share (withholding only delays until a solver forces it). | Read anything alone; affect any ballot or the deadline. |
| All key parties colluding, or a solver with hardware beyond `S_max × M` | See the anonymous running count before close. | Learn who voted how; forge, drop, or alter ballots; move the deadline. |
| Full mix-path collusion for one voter | Link that voter's IP to their ballot. | Affect the result. |
| Malware on a voter's device | Miscast that voter's ballot. | Affect any other voter. |

---

## 14. Default parameters

| Parameter | Default |
|---|---|
| Mix hops | 3 (fewer if unavailable) |
| Hop delay | 3 s or until 8 other messages, max 60 s |
| Paths per ballot | 2 |
| Guard rotation | 90 days |
| Timing margin `M` | 1.5 |
| `T_cap` | 3 × the longest vote length permitted by the authority |
| Initiative open delay | `support_deadline + 144` blocks |
| `min_ballots` | 100 |
| Anchoring cadence (per anchorer) | hourly during open votes |
| OTS calendars per submission | 3 (independent operators) |
| Initiative threshold `N` | 1 % of Registry size |

---

## 15. Implementation

- **Core library in Rust**: proof generation/verification, EC-ElGamal, VTC creation/forcing/verification, Log validation, mix client, OTS proof verification, Bitcoin SPV. Compiled to a server binary (node), a mobile library via UniFFI (iOS/Android), and WebAssembly (browser verifier). One implementation of the validity rules for all three.
- **Circuit**: one Groth16 circuit over BN254 (arkworks); kept minimal (membership + nullifier derivation + content binding only).
- **Rollout**: `secrecy: none` is implemented and tested end to end first; `keyparties` is added as a separate crate. The VTC is the only component implemented from a paper rather than taken from a maintained library, and it must be audited before binding use.
- **Apps**: native Kotlin/Swift or Flutter shells; the UI never touches cryptography.
- **Specification first**: this protocol, plus byte-exact formats and test vectors, so that independent verifiers in any language agree with the reference. The reference verifier is intentionally small enough to be read in full.
- **Cast-as-intended check**: the device displays a short code derived from `(n, c)`; a second device or a web verifier can confirm that exactly that ballot appears on the Log.

---

## 16. Known limitations

1. **Coercion and vote buying.** A voter can reveal `s`-derived witnesses to prove how they voted. Acceptable for frequent low-stakes votes; not for high-stakes elections.
2. **Device compromise.** Malware can miscast a ballot. Mitigated only by cast-as-intended checks.
3. **Issuer trust.** The Issuer defines the electorate. Everything else is verifiable; this is not.
4. **Network-level adversary.** An observer controlling ISPs and most registered nodes can attempt statistical timing correlation. Delays, decoys, and guards raise the cost; they do not eliminate it.
5. **Public ballot contents after opening.** In both secrecy modes, individual ballot contents are public after close (immediately under `none`, after opening under `keyparties`). Any metadata leak is therefore a full leak for that ballot. Homomorphic tallying (§17) would remove this.
6. **Secrecy before close is trust-minimized, not trustless.** It fails only if every key party colludes, but that is an assumption about people, not mathematics. Anyone can remove the assumption for themselves by registering as a key party.
7. **Timing fuzziness.** The close drifts with Bitcoin block variance. Under `keyparties`, results appear when the last share is available: immediately if all parties publish, otherwise when the slowest forced opening completes, which is sized to land at about close.

---

## 17. Future work

- **Delegation** (liquid democracy): signed, revocable, per-topic delegation resolved at tally time, with direct votes overriding.
- **Everlasting privacy**: perfectly hiding commitments on the Log with separately held, eventually deleted encryptions.
- **Homomorphic tallying**: exponential ElGamal with per-ballot validity proofs so that only per-option totals are ever decrypted and individual ballots never open.
- **Trustless secrecy**: delay encryption (Burdges–De Feo, EUROCRYPT 2021) or homomorphic time-lock puzzles in class groups would remove the key-party assumption entirely; neither has a production-grade implementation today, and the former requires a one-time trusted setup ceremony.
- **Coercion resistance**: fake-credential schemes (JCJ/Civitas family) adapted to the nullifier design.
- **Sortition-based ordering**: replacing Bitcoin anchoring with a randomly drawn committee of verified participants, once such consensus is practical at scale.
- **Non-institutional identity roots**: web-of-trust or proof-of-personhood Issuers, which the `issuer_key` mechanism already accommodates once such a backend exists.

---

*This draft describes a protocol, not a deployed system. Every cryptographic component named here should be independently audited before any binding use.*
