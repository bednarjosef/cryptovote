# Blockers

Issues that cannot be resolved by choosing a simpler option, per the brief's
"When you are unsure" rule. Each needs a decision from the protocol author.

## #1 — Ballot encryption under `K = H(y)` is not realizable with a trapdoorless puzzle  (RESOLVED 2026-09-03)

**Decision (protocol author):** whitepaper §7 is confirmed wrong. Neither
option A (drand) nor option B (drop G4). A third option, **key parties**, is
adopted: a per-vote `secrecy ∈ {none, keyparties}` field; `none` (plaintext
option index, public running count) ships first and Phases 3–9 are completed
on it; `keyparties` follows: anyone registers before `open_block` with an EC
public key and a verifiable timed commitment (Thyagarajan et al., CCS 2020) to
its secret key, one registration per person and vote by nullifier; ballots
are EC-ElGamal under the aggregate key; decryption needs every share; parties
publish shares after close or anyone force-opens the commitment. Full design:
`SPEC.md` §10–§11, assumptions A35–A40. The class-group VDF and `kyn-vdf`
are dropped. The analysis below is kept for the record.

**Where:** whitepaper §7 ("Any participant can derive K's *encryption* input
cheaply (encryption uses `g` and `T`, not `y`); only *decryption* requires the
sequential work"), §8 step 3 (`c = Enc_K(option; r)`), §10 steps 1–3.

**The contradiction.** `Enc_K` is authenticated *symmetric* encryption
(XChaCha20-Poly1305 per §4). To produce `c` the device must know `K = H(y)`,
hence `y = g^(2^T)`. In a class group nobody holds a trapdoor (§4: "No trapdoor
exists for anyone"), so the *only* way to obtain `y` is the sequential
computation itself, which is sized to take longer than the whole voting
period on the fastest hardware (§10). The phone therefore cannot encrypt.
Knowing `g` and `T` is not an "encryption input" for any symmetric scheme.

The obstruction is not a detail of the chosen crate. Any scheme where the
voter (who knows only public `g, T`) produces a ciphertext that the holder of
`y` can open cheaply is a public-key encryption whose public key is `(g, T)`
and whose secret key is `y`. Computing a public key from `(g, T)` without `y`
would require deriving `g^(2^T)`-dependent data without the delay, which is
exactly what the delay assumption forbids (it is Diffie–Hellman against a
public key that does not exist yet). The classic Rivest–Shamir–Wagner
construction avoids this only because the *puzzle creator* holds the RSA
trapdoor; here the creator is the voter, and giving every voter the trapdoor
removes the delay for everyone.

**Consequences for the whitepaper as written.** G4 ("nobody can read any
ballot before the deadline") cannot be met by §7–§8 with the class-group
puzzle. Everything else — identity, Log, anchoring, duplicates, initiatives,
mix, verifier — is unaffected and is fully specified in `SPEC.md`.

**Options.**

| | Option | What changes | Trust added | Feasibility |
|---|---|---|---|---|
| A | **Timed-release via drand `tlock`** (identity-based encryption to a future beacon round; the round's BLS signature is the decryption key) | `puzzle_T` becomes `release_round`; `Solution` carries the 48-byte round signature (anyone fetches it, everyone verifies it against the fixed drand public key); ballots are `tlock` ciphertexts (~150 bytes) with deterministic randomness from `r`; class-group crate dropped | drand "League of Entropy" threshold (~20 independent operators) trusted **only for secrecy before the round**; it cannot cast, drop, link, or reorder anything; if it halts, ballots stay sealed (liveness) | Maintained crates exist (`tlock 0.0.10`, `tlock_age`, `drand-core 0.0.19`, all July 2026). Deadline drift: the release round is a wall-clock time chosen ≥ the expected time of `close_block` plus a margin; ballots anchored after `close_block` are excluded by §9 regardless. |
| B | **Drop G4 for v0.1** (ballots carry the option index in the clear, or encrypted under a key published at definition time) | Ciphertext becomes plaintext; no `Solution` item; running totals are visible during the vote | none | trivial; contradicts G4 and §16.5's framing; a stated non-goal would have to be added |
| C | **Homomorphic timed commitments in class groups** (CL-framework linearly-homomorphic timed commitments: one sequential computation opens the *sum* of all ballots, never an individual ballot) | Ballot is a CL commitment to a one-hot vector plus a zero-knowledge well-formedness proof over class-group elements; tally by homomorphic aggregation; individual ballots never decrypted (privacy improves) | none | Research-grade. No production crate (`class-groups` is 0.0.2-alpha with no proofs). The well-formedness proof would have to be written here — forbidden by Hard rule 1 — and audited. Months of work. |
| D | **Per-ballot puzzles** (each voter generates its own RSA modulus with a known trapdoor, or a class-group puzzle) | `T` sequential squarings **per ballot** at opening | none | Infeasible: opening N ballots costs N × (vote duration) of sequential work; a `T` small enough to open millions of ballots makes each ballot readable minutes after it is cast. |

**Recommendation.** Option A. It is the smallest change that keeps G4, keeps
Bitcoin as the only clock for *ordering*, keeps "no token, no fees, no
committee among the voting infrastructure", and uses maintained primitives.
The added trust is external, public, and limited to pre-deadline secrecy, and
must be added to the §2 table. If the author prefers zero external trust,
Option B is the only implementable alternative today, and G4 must be moved to
non-goals.

**Was blocked until decided:** Phase 3 and the opening half of the counting
rule. Now unblocked; nothing remains open.

## No other blockers

Every other primitive named in the whitepaper has a suitable maintained crate
(see `DEPENDENCIES.md`).
