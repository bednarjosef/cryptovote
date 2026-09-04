# Dependencies

Hard rule 1: no cryptographic primitive is implemented in this repository.
Each crate below was checked on crates.io on 2026-09-03 for existence, latest
version, last update, and (by reading its source) that it does what is needed.
Versions are pinned in the workspace `Cargo.toml`.

## Cryptographic primitives

| Crate | Version | Used for | Why this one | Status / risk |
|---|---|---|---|---|
| `blake3` | 1.8.7 | `H` outside circuits, ids, `K`, `derive_key` domain separation | Whitepaper names BLAKE3; official implementation; `derive_key` gives standard domain separation | Actively maintained (Aug 2026) |
| `ark-bn254`, `ark-ff`, `ark-ec`, `ark-std`, `ark-serialize` | 0.6.0 | Field/curve arithmetic and canonical serialization for the proof system | Whitepaper allows Groth16; arkworks is the maintained pure-Rust Groth16 ecosystem, compiles to WASM and mobile | Maintained (Apr 2026) |
| `ark-relations`, `ark-r1cs-std`, `ark-snark`, `ark-groth16` | 0.6.0 | R1CS circuit description, Groth16 prove/verify | Same ecosystem; verification is milliseconds, proving seconds on a phone (whitepaper §4) | Groth16 needs a per-circuit trusted setup (ASSUMPTIONS A24) |
| `ark-poly` | 0.6.0 | Evaluation domains and the inverse FFT the ceremony runs over group elements (SPEC §18.4) | Same ecosystem, already present transitively; its FFT is generic over any type that can be scaled by a field element, which is exactly what turns published powers of `τ` into Lagrange coefficients at `τ` | Maintained (Apr 2026) |
| `ark-crypto-primitives` | 0.6.0 (`crh`, `merkle_tree`, `sponge`, `constraints`) | Poseidon (native + gadget), Poseidon parameter generation (`find_poseidon_ark_and_mds`, Grain LFSR as in the reference), Merkle path gadget | Poseidon in-circuit per whitepaper §4; native and constraint versions share one parameter set | Maintained (Apr 2026) |
| `chacha20poly1305` | 0.11.0 | `Enc_K` = XChaCha20-Poly1305 | Whitepaper §4 example; RustCrypto, audited | Maintained (Aug 2026) |
| `ed25519-dalek` | 2.2.0 | Authority, Issuer, node signatures | Standard, audited. 3.0.0 (Jul 2026) exists; 2.x pinned because the rest of the ecosystem (sphinx-packet, arti) still resolves on it; revisit in Phase 7 | Maintained |
| `x25519-dalek` | 2.x (matching `sphinx-packet`) | Mix hop keys | Required by the Sphinx crate's API | Maintained |
| `sphinx-packet` | 0.7.0 | Onion packets to mix hops | Nym's maintained Sphinx implementation; pure Rust; the only maintained Sphinx crate | Maintained (Jul 2026) |
| `bitcoin` | 0.32.x | Header parsing, PoW validation, txid, `PartialMerkleTree` SPV, OP_RETURN parsing | rust-bitcoin, the reference Rust implementation | Maintained (Jul 2026) |
| `opentimestamps` | 0.2.0 | Parsing OTS timestamps and executing their op chains | The only OTS format crate (`ots` 0.1.3 is its 2017 predecessor). Only parsing and `Op::execute` are used; the Bitcoin check is done with `bitcoin` | Last release Apr 2023; the OTS format is frozen, so low risk. Calendar submission is plain HTTP and lives in `node` |
| `rs_merkle` | 1.5.0 | Anchor Merkle tree and inclusion proofs | Small, generic over the hasher, exact algorithm specified in SPEC §8 | Maintained (Feb 2025) |
| `rand`, `rand_chacha` | 0.8 / 0.3 | RNG for keys; ChaCha20 for seeded (deterministic) proof randomness | Versions matching arkworks' `rand_core` | Maintained |

## Key parties (Phase 10, secrecy = keyparties)

| Crate | Version | Used for | Why this one | Status |
|---|---|---|---|---|
| `curve25519-dalek` | 5.0.0 | Ristretto255 points and scalars for exponent ElGamal, share commitments, Lagrange interpolation | Prime-order group; audited; no `rand_core` feature needed (scalars come from our own 64-byte samples) | Maintained (Jul 2026) |
| `num-bigint-dig` (`prime` feature) | 0.9.1 | 2048-bit modular arithmetic, `gen_prime` (1024-bit primes), Miller–Rabin `probably_prime` for `hash_to_prime`, `mod_inverse`, sequential squaring | The big-integer crate the `rsa` crate is built on; has prime generation and primality testing built in; pure Rust | Maintained (Nov 2025). Uses rand 0.9; a small RNG adapter bridges the workspace's rand 0.8 |
| `num-traits`, `num-integer` | 0.2 / 0.1 | Traits for the above | — | Maintained |
| `rand` 0.9 (as `rand09`) | 0.9 | Only the `RngCore`/`CryptoRng` traits for the adapter above | — | Maintained |
| `chacha20poly1305` | 0.11.0 | AEAD of puzzle shares | Already used | — |

The VTC construction itself (SPEC §10) lives in `crates/vtc` (`cv-vtc`) and is
assembled from these crates under the explicit Rule 1 carve-out; nothing
lower-level than a group operation, a modular exponentiation or a primality
test is written there. It must be audited before binding use.

## No longer needed

| Crate | Reason |
|---|---|
| `kyn-vdf` 0.1.1 | The class-group time-lock puzzle was dropped with whitepaper §7 (BLOCKERS.md #1). Removed from the workspace so a one-month-old single-author crate is not in the trust base. |

## Rejected for the class-group puzzle (historical)

| Crate | Reason |
|---|---|
| `class_group` 0.6.1 (ZenGo) | GMP + PARI via `bindgen`; no WASM; unmaintained since Feb 2023 |
| `vdf` / `classgroup` 0.1.0 (POA) | GMP FFI; unmaintained since 2019 |
| `vdf-rs` / `vdf-classgroup` 0.2.0 | Maintained fork of the above, still GMP FFI; no WASM verifier (Hard rule: verifier must build to WASM). Viable as an optional faster *solver* backend later |
| `class-groups` 0.0.2-alpha | Constant-time class-group arithmetic (crypto-bigint), no VDF/Wesolowski; alpha |
| `bicycl-rs` 0.2.5 | Bindings to the BICYCL C++ library; no WASM |

## Considered for BLOCKERS.md #1 and not chosen

| Crate | Version | Notes |
|---|---|---|
| `tlock`, `tlock_age` | 0.0.10 (Jul 2026) | Timed-release encryption to drand rounds (IBE on BLS12-381) |
| `drand-core` | 0.0.19 (Jul 2026) | drand client and beacon verification |
| `drand-verify` | 0.6.2 (Dec 2023) | Alternative verifier (Nois) |

## Infrastructure (added in the phase that needs them)

| Crate | Version | Phase | Purpose / why |
|---|---|---|---|
| `redb` | 4.2 | 4, 7 | Pure-Rust embedded ACID store for the Log and disk-backed mix queues; no C deps |
| `axum` | 0.8 | 4 | HTTP server for gossip and light-client queries (ASSUMPTIONS A26) |
| `reqwest` | 0.13 (`rustls` via aws-lc-rs) | 4, 5 | HTTP client (peers, OTS calendars over HTTPS, Esplora header API) |
| `tokio` | 1.53 | 4 | Async runtime (required by axum, arti) |
| `electrum-client` | 0.25 | 5 | Optional Bitcoin header source |
| `arti-client`, `tor-rtcompat` | 0.46 (`tokio`, `rustls`) | 7 | Embedded Tor (whitepaper §12); bootstrap with a timeout, automatic fallback to direct HTTP reported in the privacy indicator |
| `hyper`, `hyper-util`, `http-body-util` | 1.x / 0.1 / 0.1 | 7 | Plain HTTP/1.1 over an Arti `DataStream` (reqwest cannot use a custom stream) |
| `uniffi` | 0.32 (proc-macros) | 7 | iOS/Android bindings for the client library (`cv-client` feature `ffi`, on by default; bindings generated with `uniffi-bindgen`) |
| `wasm-bindgen` | 0.2 | 8 | Browser verifier (`cv-verifier` feature `wasm`); `getrandom` 0.2/0.3/0.4 get their wasm features enabled for the wasm32 target only |
| `clap`, `serde`, `serde_json`, `thiserror`, `anyhow`, `hex`, `tracing` | current | 1+ | CLI, config files, errors, logging |

## Toolchain

Rust 1.94 (edition 2024, `rust-version = 1.85`).
No `nargo`/`circom` toolchain is needed: the circuit is written as arkworks
R1CS (whitepaper §15 lists Noir/Circom as examples; Groth16 over an R1CS
description is the same class of construction and keeps the build inside
`cargo`).

## Constructions assembled here

Hard rule 1 forbids implementing primitives, not protocols built from them.
Two protocols are assembled in this repository, and both must be audited
before binding use:

| Crate | What it composes | Why it is not a dependency |
|---|---|---|
| `cv-vtc` | Verifiable timed commitments (SPEC §10) from `curve25519-dalek` and `num-bigint-dig` | No crate implements the construction (BLOCKERS #1) |
| `cv-ceremony` | The Groth16 parameter ceremony (SPEC §18) from arkworks pairings, `ark-poly` and `blake3` | No maintained MPC implementation speaks arkworks R1CS: `snarkjs` is JavaScript over circom's format, and the bellman-era `powersoftau`/`phase2` crates are unmaintained and built on another field library. Interoperating would mean exporting this circuit to circom and matching its wire ordering exactly — the same quantity of unaudited code, somewhere a mistake is harder to see (ASSUMPTIONS A60) |

## Advisories

`cargo audit` runs clean (exit 0) against `.cargo/audit.toml`, which ignores exactly one
advisory. Every entry there needs a reachability argument, recorded here:

| Advisory | Crate | Why it is ignored |
|---|---|---|
| RUSTSEC-2023-0071 (medium) | `rsa` 0.9.10 | Marvin attack: RSA key recovery through a decryption timing sidechannel. Reached only via `arti-client → tor-keymgr → tor-key-forge → ssh-key-fork-arti`. No CryptoVote code uses the `rsa` crate — the timed commitments do their own arithmetic with `num-bigint-dig`, and the protocol holds no RSA private key that an attacker could submit ciphertexts to and time. No fixed version exists upstream. Revisit when arti drops it or `rsa` ships a fix. |

Three crates are flagged unmaintained and none is a direct dependency:
`bincode` 2.0.1 (RUSTSEC-2025-0141), `derivative` 2.2.0 (RUSTSEC-2024-0388)
and `paste` 1.0.15 (RUSTSEC-2024-0436). They carry no known vulnerability;
they are listed so that a future advisory against one is recognised as
already-known ground rather than a surprise.
