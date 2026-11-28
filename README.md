# <img src="assets/brand/credit-symbol.svg" width="28" height="28" align="top" alt="Credits Symbol" /> Credits (`XCR`)

**Open, bearer-sovereign electronic currency — sub-second finality, fair participation from consumer laptops to prover servers, private by default, and compatible with everyday global commerce.**

---

## Overview

Credits (`XCR`, symbol `∀` / Double-Bar V) is an open-source monetary protocol written in pure, safe Rust (`#![forbid(unsafe_code)]`), where all **12 core protocol, node, CLI, and gateway crates have zero external crate dependencies** (`default-members`), paired with an optional native `egui` desktop wallet & background miner (`crates/credit-desktop`). It is designed to bring the simplicity, privacy, and finality of physical cash to the internet without sacrificing regulatory compatibility or long-term sustainability.

| Property | Specification |
| :--- | :--- |
| **Ticker & Symbol** | `XCR` · Double-Bar V (`∀` plain-text fallback — *"For All"*) |
| **Base Precision** | `1 XCR = 100 Chips = 1,000,000 bits` (`u64` integer arithmetic, zero floating-point drift) |
| **Mainnet Genesis (`Epoch 0`)** | **Friday, 1 January 2027 at `00:00:00 UTC`** *(Chain ID `xcr-mainnet-2027`)* |
| **Initial Premine / Allocation** | **`∀ 0.000000 XCR`** — 100% earned from Block 0 via network participation |
| **Settlement Finality** | `~150–250 ms` (1-RTT single-owner Fast Path) · `~450 ms` (3-round shared-state BFT DAG) |
| **Fee Structure** | Sub-tenth-cent target · **`70%` workers / `15%` Security Endurance Pool / `15%` burned** |
| **Codebase Guarantees** | `#![forbid(unsafe_code)]` · `std`-only Rust (`edition = "2024"`) · `MIT OR Apache-2.0` |

---

## Core Design Principles

1. **Fair Launch & Accessible Participation (`PoNC`)**
   - Every Credit is earned from `Epoch 0` with zero premine, zero venture allocation, and zero initial coin offering.
   - **Consumer CPUs to Prover Servers:** Everyday laptops participate from Day 1 through cache-hard virtual machine compute and packet relay, while dedicated servers naturally earn proportional shares for recursive zero-knowledge state proving as transaction volume grows.
   - **Pool-Free Rewards:** A protocol-native Epoch Share-DAG distributes rewards proportionally every 60 seconds, removing the need for custodial mining pools.

2. **Sub-Second Finality & Self-Sustaining Economics**
   - Single-owner transfers settle in **one UDP round-trip (`~150–250 ms`)** across horizontally sharded committees with zero mempool front-running (zero MEV).
   - Micro-fees split `70%` to active workers, `15%` into an on-chain `SecurityEndurancePool` (releasing `1 / 525,600` per minute over a rolling one-year horizon to fund quiet periods), and `15%` permanently burned to deter wash-spam.

3. **Default Privacy with Edge Compliance**
   - Layer 1 preserves pure bearer ownership with zero freeze or blacklist keys, using X25519 stealth addresses (`1-byte` view tags), homomorphic Curve25519 Pedersen commitments, and **672-byte Logarithmic Bulletproofs**.
   - When transacting with regulated merchants or institutions, wallets can attach client-side **Zero-Knowledge Proofs of Innocence** (Privacy Pools) and end-to-end encrypted **ISO-20022** commercial receipts without revealing personal balances or history.

4. **Phased Purchasing-Power Stability (`Option C`)**
   - **Phase 1 (Bootstrap):** Scarce, oracle-free disinflationary issuance while global node dispersion and liquidity mature.
   - **Phase 2 (Global Basket):** Unlocks strictly **$\ge 200\%$ over-collateralized** Reserve Vaults steered by a deterministic integer PID controller toward a trimmed-median **9-Pillar Civilization Basket** (Shelter, Food, Energy, Healthcare, Education, Compute, Scientific Research, Emergency Resilience, and Entertainment).

5. **Human-Centered Self-Custody & Programmable Bearer Commerce (`Pocket & Vault`)**
   - Combines a hardware Passkey **Spending Pocket** for instant daily payments with a 24-hour time-locked **Savings Vault** (`emergency_cancel` protection against coercion or phishing), `XCRENC01` memory-hard encrypted keystores, `K-of-N` **`GF(256)` Shamir Guardian Recovery**, **`FROST` `K-of-N` Threshold Schnorr Multi-Sig** (`0B` on-chain overhead, key never reconstructed), **single-QR air-gapped offline cold signing** (`xcrunsigned1_` / `xcrsigned1_`), and post-quantum WOTS+/Merkle guardian keys.
   - Native Layer-1 **`CredScript` Smart Vaults** (`P2SH` inheritance & multi-party escrows, `0` re-entrancy), **Monero/Zcash `MLSAG` RingCT Shielded Pool** (`xcrview1_` read-only auditor keys & `xcrtxproof1_` DLEQ payment proofs), **Uniswap `x * y = k` Constant-Product AMM + Hybrid Orderbook/AMM Smart Router**, **Chainlink-style Trimmed-Median Quorum Oracles & Fiat Invoice Settlement**, **Tron-style Daily Free `Bandwidth` Quota (`3` `0`-fee transfers/day)**, **Stellar `ClaimableBalances` (unregistered onboarding), Viral `RedPackets` (`xcrdrop1_`), & Verifiable `ProofOfBurn`**, **Solana `Durable Cold Nonces` (`xcrdurable1_`) & `/api/blink` Action Cards**, **Polkadot Non-Withdrawal `RoleProxies`**, **ERC-4337 Scoped Session Keys & Paymaster Sponsorship** (`xcrsk1_`), **Cardano Native Bearer Multi-Assets & `Babel Fees`**, **HTLC Cross-Chain Atomic Swaps** (`BOLT-11` Lightning & `swaps/CreditAtomicSwap.sol`), and a **JSON-RPC 2.0 Developer API (`POST /rpc`)**.

---

## Workspace Architecture

| Crate | Purpose |
| :--- | :--- |
| `crates/credit-types` | Fixed-point `Amount` math, `70/15/15` `FeeSplit`, `SecurityEndurancePool`, `Pocket & Vault` state |
| `crates/credit-crypto` | RFC 6234 SHA-256, RFC 7748 X25519 stealth keys & memos, Twisted Edwards Curve25519, Noise AEAD, WOTS+ |
| `crates/credit-ponc` | Memory-hard CPU Virtual Machine (`CpuVm`), recursive ZK share scaling, pool-free `EpochShareDag` |
| `crates/credit-zk` | Homomorphic `PedersenCommitment`, 672B `BulletproofRange64`, `SuccinctEpochProof`, Privacy Pools, ISO-20022 |
| `crates/credit-consensus` | Quorum election, 1-RTT Fast Path, `ShardedFastPathCluster`, 3-round BFT DAG, `>=85%` governance, Phase-2 vaults |
| `crates/credit-net` | Authenticated `XCR1` framing, `UdpQuicEndpoint`, Kademlia DHT + NAT detection, encrypted P2P mesh & RPC |
| `crates/credit-storage` | Crash-safe `XCRWAL01` write-ahead log (`fsync`), torn-write recovery, `DormantArchiveRegistry` (`<256B` revival) |
| `crates/credit-sdk` | `CreditWallet`, QR encoder, `xcrpay://` & vouchers, `XCRENC01` keystore, `GF(256)` Shamir, cold QR signing, subscriptions |
| `crates/credit-node` | Unified node binary (`genesis-status`, `peer` P2P mesh, `compact-wal`, `daemon`, and simulation) |
| `crates/credit-cli` | Wallet, QR & audit CLI (`pay`, `pay-multi`, `split-bill`, `split-backup`, `cold-sign`, `sub-run`, `watch`, `bench`) |
| `crates/credit-gateway` | Zero-dependency HTTP/1.1 web wallet, POS terminal, `/embed/xcr-checkout.js` widget, HMAC webhooks & `--explorer` |
| `crates/credit-desktop` | Native `egui` Desktop Wallet & 1-click automatic background PoNC node (`scripts/install-desktop.ps1`) |
| `crates/credit-bench-fuzz` | Decoder/ZK fuzz campaigns (`2,500+` iterations) and `2-of-7` Byzantine adversary simulations |

---

## Quickstart

### Option A — One-Line Verified Binary Install (No Rust Toolchain Needed)

```bash
# Linux (x86_64) & macOS (Apple Silicon arm64 / Intel x86_64) — verifies SHA-256 before install
curl -fsSL https://raw.githubusercontent.com/haruki-morimoto/credit/main/scripts/install.sh | sh
```

```powershell
# Windows (x86_64 PowerShell) — verifies SHA-256 before install
irm https://raw.githubusercontent.com/haruki-morimoto/credit/main/scripts/install.ps1 | iex

# Native Desktop App (Wallet + Automatic Background Earner + Desktop Shortcut)
powershell -ExecutionPolicy Bypass -File .\scripts\install-desktop.ps1
```

### Option B — Build from Source (`cargo` 1.85+, Zero External Dependencies)

```bash
# 1. Run the full unit, Byzantine fuzz, and multi-process P2P test suite
cargo test --workspace

# 2. Inspect the 1 January 2027 00:00 UTC Mainnet Genesis Gate & live countdown
cargo run -p credit-node -- genesis-status

# 3. Pre-join the 2027-01-01T00:00:00Z Mainnet Live Standby Mesh (scales across `--threads N` CPU cores)
cargo run --release -p credit-node -- peer --mainnet --bind 0.0.0.0:9500 --data-dir ./mainnet-peer --threads 4

# 4. Optional autonomous Bitcoin-block Epoch-0 unlocker daemon for 2027-01-01T00:00:00Z servers
python3 ./scripts/mainnet-genesis-watcher.py
```

### Join the Live Global Public Testnet (`xcr-testnet-beta-2027`)

Public bootstrap seed validators are live across North America (`162.243.166.102:9501`), Europe (`167.71.138.246:9501`), and Asia (`139.59.229.45:9501`), with a live read-only Testnet Explorer at `http://162.243.166.102:8080`. Passing `--testnet` auto-discovers the global mesh, creates `<data-dir>/miner.wallet`, and begins earning proportional Epoch Share-DAG rewards every 60 seconds:

```bash
# Join the live global Testnet & mine into ./testnet-peer/miner.wallet
cargo run --release -p credit-node -- peer --testnet --bind 0.0.0.0:9501 --data-dir ./testnet-peer

# Open the Browser Wallet & Merchant POS Terminal backed by your live Testnet wallet
cargo run --release -p credit-gateway -- --testnet --wallet ./testnet-peer/miner.wallet --http 127.0.0.1:8090

# Export your shareable X25519 Stealth URI, pay privately, and scan/claim via 1-byte view tags
cargo run --release -p credit-cli -- stealth-address --wallet ./testnet-peer/miner.wallet
cargo run --release -p credit-cli -- pay --testnet --wallet ./testnet-peer/miner.wallet --chips 250 --to xcrstealth1_...
cargo run --release -p credit-cli -- claim-stealth --testnet --wallet ./testnet-peer/miner.wallet

# Run the cross-ocean adversarial security audit or multi-core 672B Bulletproof benchmark
cargo run --release -p credit-cli -- attack-audit --testnet
cargo run --release -p credit-cli -- bench --testnet --txs 300 --streams 24

# Register an on-chain @name.xcr handle, trade on the Native DEX, or vote via Voltaire DReps
cargo run --release -p credit-cli -- handle-register --testnet --wallet ./testnet-peer/miner.wallet --handle @alice.xcr
cargo run --release -p credit-cli -- dex-book --testnet
cargo run --release -p credit-cli -- gov-list --testnet

# Convert BTC Lightning (BOLT-11) or ETH/ERC-20 (`swaps/CreditAtomicSwap.sol`) <-> XCR trustlessly
cargo run --release -p credit-cli -- ln-decode --invoice lnbc250u1...
cargo run --release -p credit-cli -- ln-swap-lock --testnet --wallet ./lp.wallet --to @alice.xcr --amount 50.00 --invoice lnbc250u1...

# Shielded RingCT Pool, Hybrid AMM/Orderbook Smart Router, Zero-Fee Bandwidth & Stellar Claimables
cargo run --release -p credit-cli -- view-key --wallet ./testnet-peer/miner.wallet
cargo run --release -p credit-cli -- shield-deposit --testnet --wallet ./testnet-peer/miner.wallet --amount 5.00
cargo run --release -p credit-cli -- pay-free --testnet --wallet ./testnet-peer/miner.wallet --to @alice.xcr --amount 1.00
cargo run --release -p credit-cli -- smart-swap --testnet --wallet ./testnet-peer/miner.wallet --asset-id <64-hex> --buy --amount 2.00
```

### Local Devnet Daemon, P2P Cluster & Web POS

```bash
# Single-node WAL daemon + CLI Bulletproof transfer
cargo run -p credit-node -- daemon --bind 127.0.0.1:9400 --data-dir ./credit-data
cargo run -p credit-cli -- init-wallet --wallet ./alice.wallet --node 127.0.0.1:9400
cargo run -p credit-cli -- pay --wallet ./alice.wallet --chips 495 --to coffee-shop --node 127.0.0.1:9400

# Local 3-peer encrypted P2P devnet cluster
cargo run -p credit-node -- peer --bind 127.0.0.1:9501 --data-dir ./peer1 --min-quorum-peers 3
cargo run -p credit-node -- peer --bind 127.0.0.1:9502 --data-dir ./peer2 --seed 127.0.0.1:9501 --min-quorum-peers 3
cargo run -p credit-node -- peer --bind 127.0.0.1:9503 --data-dir ./peer3 --seed 127.0.0.1:9501 --min-quorum-peers 3

# Interactive browser Consumer Wallet & Merchant POS Terminal (http://127.0.0.1:8080)
cargo run -p credit-gateway -- --http 127.0.0.1:8080 --data-dir ./gateway-data
```

---

## Documentation

- [**Beginner Getting Started Guide**](docs/GETTING_STARTED.md) — Plain-English setup for **Credits Desktop**, 24-word backups, CPU earning modes, free daily transfers, Gift Links, and the 24-Hour Savings Vault.
- [**Technical Whitepaper**](docs/WHITEPAPER.md) — End-to-end monetary, consensus, cryptographic, and self-custody specification.
- [**Architecture & Monetary Blueprint**](docs/BLUEPRINT.md) — System overview, comparative tradeoffs, symbol rationale, and crate layout.
- [**Consensus & PoNC Specification**](docs/CONSENSUS_PONC.md) — Memory-hard VM, pool-free Share-DAG math, and dual settlement paths.
- [**Privacy & Edge Compliance**](docs/ZK_COMPLIANCE.md) — Stealth addresses, 672-byte Bulletproofs, Privacy Pools, and ISO-20022 receipts.
- [**Security & Verification Guide**](docs/SECURITY.md) — Memory safety, constant-time Curve25519 hardening, and threat model.

---

## Contributing & License

Thank you for taking the time to read and evaluate Credits. Thoughtful code reviews, cryptographic audits, bug reports, and benchmark results are warmly welcomed via GitHub Issues and Pull Requests.

Licensed under either of **Apache License, Version 2.0** or **MIT License**, at your option.
