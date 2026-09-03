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
| `ark-crypto-primitives` | 0.6.0 (`crh`, `merkle_tree`, `sponge`, `constraints`) | Poseidon (native + gadget), Poseidon parameter generation (`find_poseidon_ark_and_mds`, Grain LFSR as in the reference), Merkle path gadget | Poseidon in-circuit per whitepaper §4; native and constraint versions share one parameter set | Maintained (Apr 2026) |
| `kyn-vdf` | 0.1.1 (exact pin) | Class-group discriminant derivation (Chia `create_discriminant`), form arithmetic (NUDUPL/NUCOMP), Chia BQFC form serialization, Wesolowski verification | The only pure-Rust, WASM-compatible class-group VDF crate. Verifier-only by design, but it exposes `Form::square`, `compose`, `pow`, `get_b`, so *solving* is `T` calls to `square` and the proof is one `pow` with exponent `⌊2^T / B⌋` — composition of crate operations, no arithmetic written here. Test-vector compatible with Chia's reference, so a fast C++/ASM prover (`chiavdf`) can be swapped in for production solving | **Young**: released Aug 2026, single author, 88 downloads. Mitigations: exact pin, Chia vectors, zero unsafe, 1.5 kLoC that can be audited. **Whether the puzzle is used at all depends on BLOCKERS.md #1.** |
| `chacha20poly1305` | 0.11.0 | `Enc_K` = XChaCha20-Poly1305 | Whitepaper §4 example; RustCrypto, audited | Maintained (Aug 2026) |
| `ed25519-dalek` | 2.2.0 | Authority, Issuer, node signatures | Standard, audited. 3.0.0 (Jul 2026) exists; 2.x pinned because the rest of the ecosystem (sphinx-packet, arti) still resolves on it; revisit in Phase 7 | Maintained |
| `x25519-dalek` | 2.x (matching `sphinx-packet`) | Mix hop keys | Required by the Sphinx crate's API | Maintained |
| `sphinx-packet` | 0.7.0 | Onion packets to mix hops | Nym's maintained Sphinx implementation; pure Rust; the only maintained Sphinx crate | Maintained (Jul 2026) |
| `bitcoin` | 0.32.x | Header parsing, PoW validation, txid, `PartialMerkleTree` SPV, OP_RETURN parsing | rust-bitcoin, the reference Rust implementation | Maintained (Jul 2026) |
| `opentimestamps` | 0.2.0 | Parsing OTS timestamps and executing their op chains | The only OTS format crate (`ots` 0.1.3 is its 2017 predecessor). Only parsing and `Op::execute` are used; the Bitcoin check is done with `bitcoin` | Last release Apr 2023; the OTS format is frozen, so low risk. Calendar submission is plain HTTP and lives in `node` |
| `rs_merkle` | 1.5.0 | Anchor Merkle tree and inclusion proofs | Small, generic over the hasher, exact algorithm specified in SPEC §8 | Maintained (Feb 2025) |
| `rand`, `rand_chacha` | 0.8 / 0.3 | RNG for keys; ChaCha20 for seeded (deterministic) proof randomness | Versions matching arkworks' `rand_core` | Maintained |

## Rejected for the class-group puzzle

| Crate | Reason |
|---|---|
| `class_group` 0.6.1 (ZenGo) | GMP + PARI via `bindgen`; no WASM; unmaintained since Feb 2023 |
| `vdf` / `classgroup` 0.1.0 (POA) | GMP FFI; unmaintained since 2019 |
| `vdf-rs` / `vdf-classgroup` 0.2.0 | Maintained fork of the above, still GMP FFI; no WASM verifier (Hard rule: verifier must build to WASM). Viable as an optional faster *solver* backend later |
| `class-groups` 0.0.2-alpha | Constant-time class-group arithmetic (crypto-bigint), no VDF/Wesolowski; alpha |
| `bicycl-rs` 0.2.5 | Bindings to the BICYCL C++ library; no WASM |

## Candidates for BLOCKERS.md #1 (not yet added)

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
| `reqwest` | 0.13 | 4, 5 | HTTP client (peers, OTS calendars, header API) |
| `tokio` | 1.53 | 4 | Async runtime (required by axum, arti) |
| `electrum-client` | 0.25 | 5 | Optional Bitcoin header source |
| `arti-client`, `tor-rtcompat` | 0.46 | 7 | Embedded Tor (whitepaper §12) |
| `uniffi` | 0.32 | 7 | iOS/Android bindings for the client library |
| `wasm-bindgen` | 0.2 | 8 | Browser verifier |
| `clap`, `serde`, `serde_json`, `thiserror`, `anyhow`, `hex`, `tracing` | current | 1+ | CLI, config files, errors, logging |

## Toolchain

Rust 1.94 (edition 2024, `rust-version = 1.85` required by `kyn-vdf`).
No `nargo`/`circom` toolchain is needed: the circuit is written as arkworks
R1CS (whitepaper §15 lists Noir/Circom as examples; Groth16 over an R1CS
description is the same class of construction and keeps the build inside
`cargo`).
