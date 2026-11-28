# Credits (`∀` / `XCR`): Technical Whitepaper

**Author:** Haruki Morimoto  
**Version:** 0.3 · **Mainnet Genesis Target:** 1 January 2027 (`00:00:00 UTC`)

---

## Abstract

Physical cash provides instant local finality, zero intermediary fees, everyday privacy, and direct bearer ownership, yet cannot move natively over the internet. Existing digital payment systems each trade away one or more of these qualities: traditional card and bank networks introduce multi-day settlement, percentage fees, and custodial freezes; early Proof-of-Work currencies offer fair issuance at the expense of multi-minute confirmation latency, specialized hardware concentration, and public ledger exposure; Proof-of-Stake networks rely on initial token distributions; opaque privacy coins face delisting from regulated commerce; and fiat-pegged stablecoins reintroduce centralized freeze keys and single-currency inflation.

**Credits (`XCR`, symbol `∀` / Double-Bar V)** brings these properties together in a single, self-sustaining protocol:
1. **Zero-Premine Fair Launch:** Every unit is earned from `Epoch 0` via **Proof of Network Compute (PoNC)** and a **Protocol-Native Epoch Share-DAG** that rewards solo consumer laptops without mining pools while scaling smoothly to dedicated zero-knowledge prover servers.
2. **Sub-Second Sharded Finality:** Single-owner `Spending Pocket` transfers settle irreversibly in **one UDP round-trip (`~150–250 ms`)** across horizontally sharded, compute-elected Byzantine committees, complemented by a 3-round pipelined BFT DAG (`~450 ms`) for shared multi-party state.
3. **Default Privacy with Edge Compliance:** Layer 1 enforces X25519 stealth addresses (`1-byte` view tags) and Curve25519 **672-byte Logarithmic Bulletproofs** with zero freeze keys, while client-side **Zero-Knowledge Proofs of Innocence** (Privacy Pools) and encrypted **ISO-20022** receipts let regulated counterparties verify clean fund provenance without exposing user balances.
4. **Long-Term Sustainability & Phased Stability:** Micro-fees split `70%` to active workers, `15%` into a one-year **Security Endurance Pool**, and `15%` permanently burned. Inactive accounts compress into stateless `<256-byte` **Archival Merkle Proofs** without confiscation, upgrades require **`>= 85%` PoNC compute supermajority**, and `Phase 2` unlocks $\ge 200\%$ over-collateralized **Reserve Vaults** tracking a **9-Pillar Civilization Basket**.

---

## 1. Monetary Unit, Symbol & Precision

- **Emblem (`assets/brand/credit-symbol.svg`):** **Double-Bar V** — pairing the universal quantifier **`∀` ("For All")** and **Verified Value** with classic double currency bars (`€`, `¥`, `₩`).
- **Supranational Ticker (`XCR`):** Follows the ISO 4217 `X`-prefix convention reserved for borderless, non-national monetary standards (`XAU`, `XDR`).
- **Fixed-Point Arithmetic (`u64`):** `1 Credit (XCR) = 100 Chips = 1,000,000 bits` (6 decimal places, zero IEEE-754 floating-point rounding drift).

---

## 2. Consensus: Decoupling Fair Compute from Real-Time Finality

### 2.1 Verifiable Zero-Premine Genesis (1 January 2027)
Mainnet `Epoch 0` (`xcr-mainnet-2027`) is scheduled for **Friday, 1 January 2027 at `00:00:00 UTC`** (`MAINNET_GENESIS_UNIX = 1,798,761,600`).

Binaries distributed prior to launch remain locked in `GenesisStandbyStatus::StandbyCountdown` (`credit-node genesis-status`), preventing early share generation before `1,798,761,600`. At `2027-01-01T00:00:00Z`, `epoch0_seed` is derived via domain-separated SHA-256 (`XCR.GENESIS.FAIR_LAUNCH_BEACON.V1`) from the **first Bitcoin block hash mined at or after `00:00:00 UTC`** alongside a contemporaneous global headline, ensuring `circulating_supply == 0.000000 XCR` at `Epoch 0`.

### 2.2 Proof of Network Compute & Epoch Share-DAG
During each 60-second epoch $E_k$, nodes submit verifiable shares across three complementary work tiers:
- **`CpuVm` (Consumer Laptops & Desktops):** Executes data-dependent 64-bit multiply-rotate-XOR loops over an L2/L3-cache scratchpad tailored to general-purpose CPUs.
- **`RecursiveZkState` (Dedicated Prover Servers):** Produces succinct epoch state-transition and supply-conservation proofs weighted by verified transaction throughput.
- **`EdgeRelay` (Low-Latency Routers):** Relays authenticated UDP/QUIC datagrams for edge participants.

Valid shares meeting the lower Share Target $T_{\text{share}}$ enter `EpochShareDag` directly on-chain. At epoch close, issuance $M(E_k)$, `70%` of transaction fees $F_{\text{worker}}(E_k)$, and the `SecurityEndurancePool` drip $D_{\text{endurance}}(E_k)$ are distributed proportionally across all contributors:

$$R_i(E_k) = \left( M(E_k) + F_{\text{worker}}(E_k) + D_{\text{endurance}}(E_k) \right) \cdot \frac{W_i}{\sum_j W_j}$$

### 2.3 Horizontally Sharded 1-RTT Fast Path & 3-Round BFT DAG
Validators elected from the sliding Share-DAG window are deterministically assigned via `epoch_seed` across $S = 2^b$ address-prefix shards (`ShardedFastPathCluster`). Because a single-owner `FastTransfer` mutates only the sender's `PocketState`, validators lock `(from, nonce)`, verify the 672-byte Bulletproof, journal to `XCRWAL01`, and co-sign a `FinalityCertificate` in **1 UDP round-trip (`~150–250 ms`)** with zero cross-shard contention and zero MEV. Shared `Vault` and `ReserveVault` transitions finalize via a 3-round pipelined BFT DAG (`BftDagEngine`, `~450 ms`).

---

## 3. Cryptography, 672-Byte Bulletproofs & Edge Compliance

1. **Unlinkable Stealth Addresses:** Ephemeral-static X25519 ECDH (`RFC 7748`) derives a one-time `Address` and a `1-byte` `view_tag` that allows recipient wallets to skip $255/256$ of unrelated outputs with a single byte check.
2. **Curve25519 Pedersen Commitments & Bulletproofs:** Amounts are committed on Twisted Edwards Curve25519 as $C = v B + \gamma H$. `BulletproofRange64` proves $v \in [0, 2^{64})$ in **672 bytes** via 6 Inner-Product Argument folding rounds, while `ConfidentialTransferProof` verifies $\sum C_{\text{in}} - \sum C_{\text{out}} - \text{fee}\cdot B = r_{\text{excess}} H$.
3. **Edge Proofs of Innocence & Encrypted ISO-20022 Memos:** Wallets construct client-side Merkle membership proofs (`ProofOfInnocence`) against public clean-deposit sets curated at the edge, paired with optional encrypted `ISO-20022` invoice/tax payloads readable strictly by sender and receiver.
4. **Lightweight Mobile Verification:** `EpochStateHeader` (`188 bytes`) + `SuccinctEpochProof` + $O(\log_2 N)$ Merkle branches allow `MobileLightClient` to verify account state in `< 200 bytes` of RAM.

---

## 4. Sovereign Self-Custody (`Pocket & Vault`) & Post-Quantum Readiness

- **Spending Pocket:** Hardware Passkey (`P-256` FaceID / TouchID) signing bounded by a configurable daily tap limit.
- **Savings Vault:** Protocol-enforced withdrawal cooling window (default `24 hours`) with instant `emergency_cancel` recovery, protected by post-quantum WOTS+/Merkle guardian keys.
- **4-Dot Credchip Status:** Surfaces live wallet readiness across `[Pocket · Vault · ZK · Node]`.

---

## 5. Self-Sustaining Longevity & Phased Stability

### 5.1 Closed-Loop `70 / 15 / 15` Fee Thermostat
Returning `100%` of fees immediately to validators would allow large operators to wash-trade at near-zero cost, whereas burning `30%` outright discards budget needed during quieter eras. Credits splits every fee via `FeeSplit` + `SecurityEndurancePool`:
- **`70%` Immediate Worker Reward:** Paid directly to the current epoch's Share-DAG contributors.
- **`15%` Security Endurance Pool:** Deposited into an autonomous reserve that drips `1 / 525,600` of its balance per minute (one-year exponential time constant) into future epochs, smoothing long-term security funding without extra inflation.
- **`15%` Permanent Supply Burn:** Arithmetically subtracted from `circulating_supply` (`net_issuance = minted - 0.15 * fees`), preserving a `30%` immediate anti-spam cost per round-trip.

### 5.2 Stateless Cold-Archival & Supermajority Compute Governance
- **Dormant Account Archival (`DormantArchiveRegistry`):** Accounts untouched for $\ge 2\text{ years}$ (`1,051,200` epochs) are never taxed or confiscated; they compact out of hot validator RAM into a 32-byte `ArchiveRoot` and revive in 1 RTT whenever the owner presents a `<256-byte` `ArchiveInclusionProof`.
- **Zero-Foundation Governance (`UpgradeGovernanceEngine`):** Protocol upgrades activate only after achieving **$\ge 85.00\%$ sustained PoNC Share-DAG compute support** across a 30-day signaling window followed by a mandatory 30-day user review grace period.

### 5.3 Phase 1 → Phase 2 Civilization Basket & Reserve Backing
- **Phase 1 (Bootstrap):** Smooth disinflationary emission approaching a `~0.5%/yr` security tail floor. Every `XCR` is earned strictly through verifiable PoNC work.
- **Phase 2 (Global Standard):** Once active independent compute nodes ($\ge 10,000$), autonomous systems ($\ge 500$), and deep liquidity epochs ($\ge 43,200$) cross deterministic thresholds, `EpochLifecycleEngine` unlocks **Over-Collateralized `ReserveVault`s** ($\ge 200\%$ mint collateralization, `150%` liquidation guard):
  - **Reserve Backing (Zero Unbacked Minting):** The protocol never prints unbacked `XCR` or funds external industries. Instead, holders voluntarily lock earned `XCR` collateral ($\ge 200\%$) inside `ReserveVaultEngine` to mint or retire liquidity, guided by a deterministic `i128` `PidRateController`.
  - **9-Pillar Purchasing-Power Index:** `GlobalBasketOracle` computes a Byzantine-trimmed weighted median across nine real-world cost pillars (used strictly as a price yardstick):

| Pillar | Weight | Scope (`∀` — Humans, Robotics & AI) |
| :--- | :---: | :--- |
| **Shelter & Materials** | `20%` | Housing, physical infrastructure, and construction inputs |
| **Food & Clean-Water Staples** | `17%` | Essential nutrition and potable water |
| **Energy (kWh & Clean Fuel)** | `15%` | Residential, industrial, robotics, and compute power |
| **Healthcare & Essential Medicine** | `13%` | Diagnostics, clinical care, and essential pharmaceuticals |
| **Education & Open Knowledge** | `9%` | Foundational schooling, vocational skills, and open datasets |
| **Compute, Robotics & Bandwidth** | `9%` | Standardized compute-hours, inference, and global transit |
| **Scientific Research & Frontier R&D** | `6%` | Laboratory instrumentation, materials/bio R&D, and open science |
| **Emergency Services, Safety & Resilience** | `6%` | Emergency response, public safety, and disaster recovery |
| **Entertainment, Culture & Recreation** | `5%` | Arts, media, sports, and community leisure |
