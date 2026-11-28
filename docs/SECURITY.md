# Credits (`XCR`) Security Architecture & Verification Guide

**Version:** 0.3 · **Workspace:** All 12 Crates (`#![forbid(unsafe_code)]`)

---

## 1. Memory Safety & Supply-Chain Isolation

- **Workspace-Wide `#![forbid(unsafe_code)]`:** Enforced in the root `Cargo.toml` across every library, node binary, CLI client, web gateway, and test target, ruling out memory-corruption classes such as buffer overruns, use-after-free bugs, and data races.
- **Zero External Dependencies (`std`-Only Rust):** Every cryptographic primitive (`RFC 6234` SHA-256, `RFC 7748` X25519, `RFC 8032` Twisted Edwards Curve25519, WOTS+/Merkle post-quantum signatures, Noise quadruple-DH AEAD, and 672-byte Logarithmic Bulletproofs), wire decoder, write-ahead log, and UDP/HTTP transport is self-contained and auditable in one repository without external `crates.io` supply-chain exposure.

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
| **Sybil PoNC Share Flooding** | `EpochShareDag` validates memory-hard `execute_ponc_vm` digests, parent links, and difficulty targets | `credit-ponc`, `credit-bench-fuzz` |
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
