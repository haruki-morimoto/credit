# Credits (`XCR`) Security Architecture & Verification Guide

**Version:** 0.3 · **Workspace:** 12 Zero-Dependency Core Crates + Optional Native `egui` Desktop (`#![forbid(unsafe_code)]`)

---

## 1. Memory Safety & Supply-Chain Isolation

- **Workspace-Wide `#![forbid(unsafe_code)]`:** Enforced in the root `Cargo.toml` across every library, node binary, CLI client, web gateway, native desktop app, and test target, ruling out memory-corruption classes such as buffer overruns, use-after-free bugs, and data races.
- **Zero External Dependencies Across All 12 Core Crates (`default-members`):** Every cryptographic primitive (`RFC 6234` SHA-256, `RFC 7748` X25519, `RFC 8032` Twisted Edwards Curve25519, WOTS+/Merkle post-quantum signatures, Noise quadruple-DH AEAD, `MLSAG` RingCT, `FROST` threshold Schnorr, and 672-byte Logarithmic Bulletproofs), wire decoder, write-ahead log, and UDP/HTTP transport is 100% self-contained `std` Rust with zero external `crates.io` dependencies on headless validator servers. Only the optional desktop GUI (`crates/credit-desktop`) pulls `eframe`/`egui`.
- **`XCRENC01` Memory-Hard Keystores & Threshold Custody:** Local wallets support iterated SHA-256 memory-hard AEAD encryption (`ZeroizingSeed` wipe-on-drop), `K-of-N` `GF(256)` Shamir Guardian Shares, `FROST` `K-of-N` threshold signing (where the full secret key is never reconstructed), and single-QR air-gapped cold signing.

---

## 2. Cryptographic & Side-Channel Hardening

- **Branchless Constant-Time Curve25519 (`crates/credit-crypto/src/edwards.rs`):** Windowed 4-bit scalar multiplication scans all 16 lookup entries via arithmetic bitmasks (`sel25519`) and executes unified `add-2008-hwcd` extended Twisted Edwards addition on every nibble, mitigating cache-timing and branch-prediction leakage of blinding factors and stealth keys.
- **Constant-Time Equality (`ct_eq_slice`):** All AEAD authentication tags, handshake transcripts, and compressed curve point comparisons accumulate bitwise XOR differences without early-exit branches.
- **Forward-Secret P2P Sessions (`crates/credit-crypto/src/aead.rs`):** Peer-to-peer links combine ephemeral-ephemeral (`ee`), ephemeral-static (`ie_rs`, `is_re`), and static-static (`ss`) Diffie-Hellman shared secrets with a 64-packet sliding anti-replay window.
- **Strict Domain Separation:** Every hash, commitment, nullifier, Merkle branch, and Fiat-Shamir challenge prefixes length-delimited context tags (`XCR.<MODULE>.<PURPOSE>.V1`) to prevent cross-protocol collisions.

---

## 3. Protocol Threat Model & Verified Defenses

| Threat Scenario | Protocol Defense | Verified By |
| :--- | :--- | :--- |
| **Double-Spend Equivocation** | Honest validators atomically lock `(sender, nonce) -> tx_id` before voting; `< 1/3` Byzantine weight cannot reach `floor(2W/3) + 1` quorum | `credit-consensus`, `credit-bench-fuzz` |
| **Confidential Inflation / Overflow** | 672-byte 64-bit `BulletproofRange64` paired with homomorphic Curve25519 excess Schnorr verification | `credit-zk` |
| **Split-Brain Shared State** | 3-round pipelined BFT DAG requires transitive `>= 2f + 1` support across rounds `r+1` and `r+2` | `credit-consensus`, `credit-bench-fuzz` |
| **Sybil PoNC Share Flooding / Forged Weight** | `EpochShareDag` validates memory-hard `execute_ponc_vm` digests and clamps `verified_weight <= canonical_cpu_share_weight`, while `QuorumCommittee` caps single-node BFT voting weight at `<= 1/3` | `credit-ponc`, `credit-consensus` |
| **Shielded Pool Double-Spend** | Curve25519 `MLSAG` RingCT enforces unique Key Images ($I = x H_p(P)$) and exact Pedersen commitment sum balance | `credit-sdk`, `credit-storage` |
| **Ledger Bloat from Expired Escrows** | Automatic epoch pruning of settled/expired HTLCs, closed DEX orders, and finalized campaigns keeps validator RAM flat and blockless | `credit-storage`, `credit-node` |
| **Phase-2 Oracle Manipulation** | `GlobalBasketOracle` applies a quorum-weighted median plus a `+/- 0.25%` per-epoch step circuit breaker | `credit-consensus`, `credit-bench-fuzz` |
| **Unexpected Power Loss / Torn Write** | `XCRWAL01` checks 16-byte SHA-256 frame MACs on startup and truncates incomplete trailing records | `credit-storage`, `credit-cli` |
| **Coercion / Phishing Key Drain** | `Savings Vault` enforces a 24-hour withdrawal cooling window with instant `emergency_cancel` recovery | `credit-types`, `credit-sdk` |
| **Malformed Network Payloads** | Length-bounded decoders across all wire, RPC, WAL, and ZK formats tested against malformed/bit-flipped inputs | `credit-bench-fuzz` |

---

## 4. Verification Commands

```bash
# Execute all unit tests, 2,500+ randomized decoder/ZK fuzz iterations,
# 2-of-7 Byzantine adversary simulations, and multi-process P2P cluster tests
cargo test --workspace

# Verify zero compiler and Clippy warnings across all targets
cargo clippy --workspace --all-targets -- -D warnings
```

---

## 5. Responsible Disclosure

If you discover a cryptographic, consensus, or networking vulnerability during review or Testnet evaluation, please report it responsibly with minimal reproduction details so a verified fix can be prepared for all node operators.
