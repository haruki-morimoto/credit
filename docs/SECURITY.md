# Credits (`XCR`) Security Architecture & Verification Guide

**Version:** 0.3 · **Workspace:** 13 Zero-Dependency Server/Protocol Crates + Native `egui`/`wgpu` Desktop

---

## 1. Memory Safety & Supply-Chain Isolation

- **`#![forbid(unsafe_code)]` Across Protocol, Node, CLI, Gateway & Desktop:** Enforced across all 12 protocol/application crates and `credit-desktop` (which uses safe `wgpu` WGSL compute shaders across DirectX 12, Metal, and Vulkan). Only the minimal `crates/credit-gpu-sys` platform crate encapsulates Linux headless `dlopen`/`dlsym` (`libOpenCL.so.1`) behind a safe `HeadlessLinuxGpu` interface, returning `None` cleanly on CPU-only hosts.
- **Zero External Dependencies on Validator Servers (`default-members`):** All cryptographic primitives (`RFC 6234` SHA-256, `RFC 7748` X25519, `RFC 8032` Twisted Edwards Curve25519, WOTS+/Merkle post-quantum signatures, Noise quadruple-DH AEAD, `MLSAG` RingCT, `FROST` threshold Schnorr, and 672-byte Logarithmic Bulletproofs), wire codecs, write-ahead logs, and UDP/HTTP transports compile with zero external `crates.io` dependencies on validator servers.
- **`XCRENC01` Keystores, Signed Updates & Scoped Proxies:** Local wallets support iterated SHA-256 memory-hard AEAD encryption (`ZeroizingSeed` wipe-on-drop), Shamir backup shares, `FROST` threshold signing, non-withdrawal `RoleProxy` delegation, and offline Curve25519 Schnorr + SHA-256 verification on all automatic desktop updates (`XCR_UPDATE_V1`).

---

## 2. Cryptographic & Side-Channel Hardening

- **Branchless Constant-Time Curve25519 (`crates/credit-crypto/src/edwards.rs`):** Windowed 4-bit scalar multiplication scans all 16 lookup entries via arithmetic bitmasks (`sel25519`) and executes unified `add-2008-hwcd` extended Twisted Edwards addition on every nibble to mitigate cache-timing and branch-prediction side channels.
- **Constant-Time Equality (`ct_eq_slice`):** Authentication tags, handshake transcripts, update digests, and curve point comparisons accumulate bitwise XOR differences without early-exit branches.
- **Forward-Secret P2P Sessions (`crates/credit-crypto/src/aead.rs`):** Peer-to-peer links combine ephemeral-ephemeral (`ee`), ephemeral-static (`ie_rs`, `is_re`), and static-static (`ss`) Diffie-Hellman shared secrets with a 64-packet sliding anti-replay window.
- **Domain Separation:** Every hash, commitment, nullifier, Merkle branch, and Fiat-Shamir challenge prefixes length-delimited context tags (`XCR.<MODULE>.<PURPOSE>.V1`).

---

## 3. Protocol Threat Model & Mitigations

| Threat Scenario | Protocol Mitigation | Verified By |
| :--- | :--- | :--- |
| **Double-Spend Equivocation** | Honest validators atomically lock `(sender, nonce) -> tx_id` before voting; `< 1/3` Byzantine weight cannot reach `floor(2W/3) + 1` quorum | `credit-consensus`, `credit-bench-fuzz` |
| **Confidential Inflation / Overflow** | 672-byte 64-bit `BulletproofRange64` paired with homomorphic Curve25519 excess Schnorr verification | `credit-zk` |
| **Split-Brain Shared State** | 3-round pipelined BFT DAG requires transitive `>= 2f + 1` support across rounds `r+1` and `r+2` | `credit-consensus`, `credit-bench-fuzz` |
| **PoNC Share Flooding / Forged Weight** | `EpochShareDag` verifies `execute_ponc_vm` digests and `canonical_cpu_share_weight`, while `QuorumCommittee` caps single-node BFT voting weight at `<= 1/3` | `credit-ponc`, `credit-consensus` |
| **Shielded Pool Double-Spend** | Curve25519 `MLSAG` RingCT enforces unique Key Images ($I = x H_p(P)$) and Pedersen commitment balance | `credit-sdk`, `credit-storage` |
| **State Growth from Settled Contracts** | Automatic epoch pruning of expired/settled HTLCs, closed DEX orders, and finalized campaigns | `credit-storage`, `credit-node` |
| **Phase-2 Oracle Manipulation** | `GlobalBasketOracle` applies a quorum-weighted median plus a `+/- 0.25%` per-epoch step limit | `credit-consensus`, `credit-bench-fuzz` |
| **Unexpected Power Loss / Torn Write** | `XCRWAL01` verifies 16-byte SHA-256 frame MACs on startup and truncates incomplete trailing records | `credit-storage`, `credit-cli` |
| **Unauthorized Large Withdrawals** | `Safety Vault` enforces a 24-hour cooling window with immediate `emergency_cancel` recovery | `credit-types`, `credit-desktop` |
| **Tampered Update Binaries** | `XCR_UPDATE_V1` enforces `https://` transport, pinned Curve25519 Schnorr signature, and SHA-256 binary match before staging or launch | `credit-sdk`, `credit-desktop` |

---

## 4. Verification Commands

```bash
# Run unit tests, 2,500+ randomized decoder/ZK fuzz iterations,
# 2-of-7 Byzantine simulations, and multi-process P2P cluster tests
cargo test --workspace

# Verify zero compiler and Clippy warnings across all targets
cargo clippy --workspace --all-targets -- -D warnings
```

---

## 5. Responsible Disclosure

We sincerely appreciate independent security reviews. If you identify a potential cryptographic, consensus, networking, or wallet issue, please share a minimal reproduction privately with the maintainers so a verified fix can be prepared responsibly for all users and node operators.
