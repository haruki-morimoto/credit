# <img src="assets/brand/credit-symbol.svg" width="28" height="28" align="top" alt="Credits Symbol" /> Credits (`XCR`)

**An open, bearer-sovereign electronic currency designed for sub-second finality, accessible participation, everyday privacy, and practical global commerce.**

---

## Overview

Credits (`XCR`, symbol `∀` / Double-Bar V) is an open-source monetary protocol written in Rust. All 13 core protocol, headless GPU, node, CLI, and gateway crates compile with zero external `crates.io` dependencies (`default-members`), complemented by a native `egui` and `wgpu` desktop application (`crates/credit-desktop`) for everyday wallet management, multi-currency holdings, peer-to-peer exchange, and background network participation.

| Property | Specification |
| :--- | :--- |
| **Ticker & Symbol** | `XCR` · Double-Bar V (`∀` plain-text fallback — *"For All"*) |
| **Base Precision** | `1 XCR = 100 Chips = 1,000,000 bits` (`u64` integer arithmetic) |
| **Mainnet Genesis (`Epoch 0`)** | **Friday, 1 January 2027 at `00:00:00 UTC`** *(Chain ID `xcr-mainnet-2027`)* |
| **Initial Allocation** | **`∀ 0.000000 XCR`** — 100% earned from `Epoch 0` through network participation |
| **Settlement Finality** | `~150–250 ms` (1-RTT single-owner Fast Path) · `~450 ms` (3-round shared-state BFT DAG) |
| **Fee Structure** | Sub-tenth-cent target · **`70%` workers / `15%` Security Endurance Pool / `15%` burned** |
| **Safety & License** | `#![forbid(unsafe_code)]` across protocol & desktop crates · Rust `2024` · `MIT OR Apache-2.0` |

---

## Core Design Principles

1. **Fair Launch & Accessible Participation (`PoNC`)**
   - Every Credit is earned from `Epoch 0` with no premine, venture allocation, or initial token sale.
   - Everyday laptops and desktops participate through a memory-hard CPU virtual machine and packet relay, while GPUs and dedicated servers earn proportional rewards for zero-knowledge transaction proving when network traffic is active (`0W` idle when quiet).
   - A protocol-native **Epoch Share-DAG** distributes rewards proportionally every 60 seconds without requiring third-party mining pools.

2. **Sub-Second Finality & Sustainable Economics**
   - Single-owner transfers settle in **one UDP round-trip (`~150–250 ms`)** across horizontally sharded committees without mempool front-running.
   - Transaction fees split `70%` to active workers, `15%` into an on-chain `SecurityEndurancePool` (releasing `1 / 525,600` per minute over a rolling one-year horizon), and `15%` permanently burned.

3. **Default Privacy with Voluntary Compliance**
   - Layer 1 preserves direct bearer ownership (no protocol-level freeze or blacklist keys) using X25519 stealth addresses, Curve25519 Pedersen commitments, **672-byte Logarithmic Bulletproofs**, and an optional RingCT Shielded Pool with read-only auditor viewing keys (`xcrview1_`).
   - When paying regulated merchants or institutions, wallets may attach client-side **Zero-Knowledge Proofs of Innocence** and end-to-end encrypted **ISO-20022** commercial receipts without disclosing account balances or history.

4. **Phased Purchasing-Power Stability**
   - **Phase 1 (Bootstrap):** Predictable, oracle-free disinflationary issuance while global node distribution and liquidity mature.
   - **Phase 2 (Global Basket):** Unlocks $\ge 200\%$ over-collateralized Reserve Vaults guided by an integer PID controller referencing a trimmed-median **9-Pillar Civilization Basket**.

5. **Self-Custody, Multi-Currency Wallet & Built-In Exchange**
   - **Pocket & Safety Vault:** Pairs an instant daily **Spending Pocket** (including 3 zero-fee daily transfers) with a 24-hour time-locked **Safety Vault** (`emergency_cancel` protection against unauthorized withdrawals), `XCRENC01` encrypted keystores, Shamir backup shares, `FROST` threshold signing, and offline QR cold signing.
   - **Multi-Asset & Sovereign Exchange:** Supports fixed-supply Layer-1 Native Assets (with optional Babel fee payment), an on-chain Limit Orderbook, Constant-Product AMM liquidity pools, a Hybrid Smart Router, non-withdrawal `DexTradeOnly` market-making proxies, cross-chain HTLC atomic swaps (`BTC`, Lightning `BOLT-11`, and EVM tokens), and `2-of-3` `CredScript` peer-to-peer fiat escrows.

---

## Workspace Architecture

| Crate | Purpose |
| :--- | :--- |
| `crates/credit-types` | Fixed-point `Amount` math, `70/15/15` `FeeSplit`, `SecurityEndurancePool`, `Pocket & Vault` state |
| `crates/credit-crypto` | RFC 6234 SHA-256, RFC 7748 X25519 stealth keys, Twisted Edwards Curve25519, Noise AEAD, WOTS+ |
| `crates/credit-ponc` | Memory-hard CPU Virtual Machine (`CpuVm`), recursive ZK share scaling, `EpochShareDag` |
| `crates/credit-zk` | `PedersenCommitment`, 672B `BulletproofRange64`, `SuccinctEpochProof`, Privacy Pools, ISO-20022 |
| `crates/credit-consensus` | Quorum election, 1-RTT Fast Path, `ShardedFastPathCluster`, 3-round BFT DAG, governance, Reserve Vaults |
| `crates/credit-net` | Authenticated `XCR1` framing, `UdpQuicEndpoint`, Kademlia DHT, encrypted P2P mesh & RPC |
| `crates/credit-storage` | Crash-safe `XCRWAL01` write-ahead log (`fsync`), torn-write recovery, `DormantArchiveRegistry` |
| `crates/credit-sdk` | `CreditWallet`, QR encoder, `XCRENC01` keystore, Shamir/FROST, `CredScript`, HTLC & `BOLT-11` toolkit |
| `crates/credit-gpu-sys` | Zero-dependency headless Linux OpenCL `dlopen` FFI bridge with automatic CPU fallback |
| `crates/credit-node` | Unified node binary (`genesis-status`, `peer` P2P mesh, `compact-wal`, and `daemon`) |
| `crates/credit-cli` | Command-line wallet, multi-asset, DEX, atomic swap, release-signing, and audit client |
| `crates/credit-gateway` | Zero-dependency HTTP/1.1 web wallet, POS terminal, checkout widget, webhooks & `--explorer` |
| `crates/credit-desktop` | Native `egui` + `wgpu` Desktop Multi-Currency Wallet, Sovereign Exchange, Vault & background node |
| `crates/credit-bench-fuzz` | Decoder/ZK fuzz campaigns (`2,500+` iterations) and `2-of-7` Byzantine fault simulations |

---

## Quickstart

### Option A — Verified Binary Install

```bash
# Linux (x86_64) & macOS (Apple Silicon arm64 / Intel x86_64) — verifies SHA-256 before install
curl -fsSL https://raw.githubusercontent.com/haruki-morimoto/credit/main/scripts/install.sh | sh
```

```powershell
# Windows CLI tools (x86_64 PowerShell) — verifies SHA-256 before install
irm https://raw.githubusercontent.com/haruki-morimoto/credit/main/scripts/install.ps1 | iex

# Windows Desktop App (Multi-Currency Wallet, Exchange, Safety Vault & Background Node)
powershell -ExecutionPolicy Bypass -File .\scripts\install-desktop.ps1
```

### Option B — Build from Source (`cargo` 1.85+)

```bash
# 1. Run the workspace unit, fuzz, and multi-process P2P test suite
cargo test --workspace

# 2. Check the 1 January 2027 00:00 UTC Mainnet Genesis status and countdown
cargo run -p credit-node -- genesis-status

# 3. Pre-join the 2027-01-01T00:00:00Z Mainnet Standby Mesh
cargo run --release -p credit-node -- peer --mainnet --bind 0.0.0.0:9500 --data-dir ./mainnet-peer --threads 4
```

### Public Testnet (`xcr-testnet-beta-2027`)

Public bootstrap validators operate in North America (`162.243.166.102:9501`), Europe (`167.71.138.246:9501`), and Asia (`139.59.229.45:9501`), alongside a read-only Testnet Explorer at `http://162.243.166.102:8080`.

```bash
# Join the public Testnet and earn epoch rewards into ./testnet-peer/miner.wallet
cargo run --release -p credit-node -- peer --testnet --bind 0.0.0.0:9501 --data-dir ./testnet-peer

# Launch the local Browser Wallet & Merchant POS Terminal
cargo run --release -p credit-gateway -- --testnet --wallet ./testnet-peer/miner.wallet --http 127.0.0.1:8090

# Send a private stealth transfer or register a @name.xcr handle via CLI
cargo run --release -p credit-cli -- handle-register --testnet --wallet ./testnet-peer/miner.wallet --handle @alice.xcr
cargo run --release -p credit-cli -- pay-free --testnet --wallet ./testnet-peer/miner.wallet --to @alice.xcr --amount 1.00
```

---

## Documentation

- [**Getting Started Guide**](docs/GETTING_STARTED.md) — Clear setup instructions for **Credits Desktop**, multi-currency wallet management, the Safety Vault, built-in Exchange, and signed updates.
- [**Technical Whitepaper**](docs/WHITEPAPER.md) — End-to-end monetary, consensus, cryptographic, and self-custody specification.
- [**Architecture & Monetary Blueprint**](docs/BLUEPRINT.md) — System overview, comparative tradeoffs, symbol rationale, and crate layout.
- [**Consensus & PoNC Specification**](docs/CONSENSUS_PONC.md) — Memory-hard VM, Share-DAG reward math, and dual settlement paths.
- [**Privacy & Edge Compliance**](docs/ZK_COMPLIANCE.md) — Stealth addresses, 672-byte Bulletproofs, Privacy Pools, and ISO-20022 receipts.
- [**Security & Verification Guide**](docs/SECURITY.md) — Memory safety, constant-time Curve25519 hardening, and threat model.

---

## Contributing & License

Thank you for taking the time to explore Credits. Constructive code reviews, security feedback, bug reports, and benchmark findings are always appreciated via GitHub Issues and Pull Requests.

Licensed under either of **Apache License, Version 2.0** or **MIT License**, at your option.
