# Credits (`∀` / `XCR`): Technical Whitepaper

**Author:** Haruki Morimoto  
**Version:** 0.3 · **Mainnet Genesis Target:** 1 January 2027 (`00:00:00 UTC`)

---

## Abstract

Physical cash offers immediate local settlement, zero intermediary fees, routine privacy, and direct bearer custody, yet cannot be transmitted natively across the internet. Existing digital payment architectures each prioritize a subset of these qualities: traditional card and bank rails involve multi-day net settlement and intermediary custody; Proof-of-Work networks provide fair open issuance alongside multi-minute confirmation intervals and public ledgers; Proof-of-Stake systems require an initial token distribution; fully opaque ledgers face compliance barriers with regulated merchants; and fiat-referenced stablecoins rely on centralized reserve custodians and single-currency monetary policy.

**Credits (`XCR`, symbol `∀` / Double-Bar V)** is designed to bring these properties into balance within a single protocol:
1. **Fair Launch (`0` Premine):** Every unit is earned from `Epoch 0` via **Proof of Network Compute (PoNC)** and a **Protocol-Native Epoch Share-DAG** that rewards solo consumer computers every 60 seconds without mining pools, while scaling naturally to dedicated zero-knowledge prover servers.
2. **Sub-Second Sharded Finality:** Single-owner `Spending Pocket` transfers settle irreversibly in **one UDP round-trip (`~150–250 ms`)** across horizontally sharded, compute-elected Byzantine committees, paired with a 3-round pipelined BFT DAG (`~450 ms`) for shared multi-party state.
3. **Default Privacy with Voluntary Edge Compliance:** Layer 1 uses X25519 stealth addresses (`1-byte` view tags) and Curve25519 **672-byte Logarithmic Bulletproofs** with no protocol-level freeze keys, while client-side **Zero-Knowledge Proofs of Innocence** (Privacy Pools) and encrypted **ISO-20022** receipts let regulated counterparties verify clean fund provenance without exposing personal balances.
4. **Long-Term Sustainability & Phased Stability:** Micro-fees split `70%` to active workers, `15%` into a one-year **Security Endurance Pool**, and `15%` permanently burned. Inactive accounts compact into stateless `<256-byte` **Archival Merkle Proofs** without balance expiration, upgrades require **`>= 85%` PoNC compute supermajority**, and `Phase 2` enables $\ge 200\%$ over-collateralized **Reserve Vaults** referencing a **9-Pillar Civilization Basket**.

---

## 1. Monetary Unit, Symbol & Precision

- **Emblem (`assets/brand/credit-symbol.svg`):** **Double-Bar V** — pairing the universal quantifier **`∀` ("For All")** and **Verified Value** with traditional parallel currency bars (`€`, `¥`, `₩`).
- **Supranational Ticker (`XCR`):** Follows the ISO 4217 `X`-prefix convention used for non-national monetary standards (`XAU`, `XDR`).
- **Fixed-Point Arithmetic (`u64`):** `1 Credit (XCR) = 100 Chips = 1,000,000 bits` (6 decimal places, exact integer arithmetic).

---

## 2. Consensus: Decoupling Fair Compute from Real-Time Finality

### 2.1 Verifiable Fair-Launch Genesis (1 January 2027)
Mainnet `Epoch 0` (`xcr-mainnet-2027`) is scheduled for **Friday, 1 January 2027 at `00:00:00 UTC`** (`MAINNET_GENESIS_UNIX = 1,798,761,600`).

Prior to `1,798,761,600`, Mainnet nodes remain in `GenesisStandbyStatus::StandbyCountdown` (`credit-node genesis-status`), ensuring no shares can be pre-computed ahead of launch. At `2027-01-01T00:00:00Z`, Genesis Watchers (`scripts/mainnet-genesis-watcher.py`) verify $\ge 2$-of-$4$ independent Bitcoin API agreement on the **first Bitcoin block hash mined at or after `00:00:00 UTC`** (with parent timestamp `< 1,798,761,600`) to derive a shared deterministic `epoch0_seed` (`XCR.GENESIS.FAIR_LAUNCH_BEACON.V1`), beginning with `circulating_supply == 0.000000 XCR`.

### 2.2 Proof of Network Compute & Epoch Share-DAG
During each 60-second epoch $E_k$, nodes contribute verifiable shares across three tiers:
- **`CpuVm` (Consumer Laptops & Multi-Core Servers):** Executes data-dependent 64-bit multiply-rotate-XOR loops over an L2/L3-cache scratchpad on background threads (`Eco` / `Balanced` / `Max` in `credit-desktop`, or `--threads N` on servers). Continuous sub-bit difficulty weighting $w(s) = \lfloor (100 \cdot 256 \cdot 2^z) / d \rfloor$ scales rewards smoothly with contributed compute without rewarding process-splitting.
- **`RecursiveZkState` (GPU & Prover Nodes):** Produces succinct epoch state-folding proofs weighted by verified transaction throughput, remaining idle at `0W` when epoch transaction volume is zero.
- **`EdgeRelay` (Low-Latency Routers):** Relays authenticated UDP/QUIC datagrams for edge participants.

Valid shares meeting the Share Target $T_{\text{share}}$ enter `EpochShareDag` directly. At epoch close, issuance $M(E_k)$, `70%` of transaction fees $F_{\text{worker}}(E_k)$, and the `SecurityEndurancePool` drip $D_{\text{endurance}}(E_k)$ are distributed proportionally across contributors:

$$R_i(E_k) = \left( M(E_k) + F_{\text{worker}}(E_k) + D_{\text{endurance}}(E_k) \right) \cdot \frac{W_i}{\sum_j W_j}$$

### 2.3 Sharded 1-RTT Fast Path & 3-Round BFT DAG
Validators elected from the sliding Share-DAG window are deterministically assigned via `epoch_seed` across $S = 2^b$ address-prefix shards (`ShardedFastPathCluster`). Because a single-owner `FastTransfer` updates only the sender's `PocketState`, validators lock `(from, nonce)`, verify the 672-byte Bulletproof, journal to `XCRWAL01`, and co-sign a `FinalityCertificate` in **1 UDP round-trip (`~150–250 ms`)**. Shared `Vault` and `ReserveVault` transitions finalize through a 3-round pipelined BFT DAG (`BftDagEngine`, `~450 ms`).

---

## 3. Cryptography, Bulletproofs & Edge Compliance

1. **Unlinkable Stealth Addresses:** Ephemeral-static X25519 ECDH (`RFC 7748`) derives a one-time `Address` and a `1-byte` `view_tag` so recipient wallets can filter $255/256$ of unrelated outputs with a single byte check.
2. **Curve25519 Pedersen Commitments & Bulletproofs:** Amounts are committed on Twisted Edwards Curve25519 as $C = v B + \gamma H$. `BulletproofRange64` proves $v \in [0, 2^{64})$ in **672 bytes** via 6 Inner-Product Argument folding rounds, while `ConfidentialTransferProof` verifies $\sum C_{\text{in}} - \sum C_{\text{out}} - \text{fee}\cdot B = r_{\text{excess}} H$.
3. **Edge Proofs of Innocence & Encrypted ISO-20022 Memos:** Wallets construct client-side Merkle membership proofs (`ProofOfInnocence`) against public clean-deposit sets curated at the edge, paired with optional encrypted `ISO-20022` commercial receipts readable only by sender and receiver.
4. **Light Client Proofs & Opt-In RingCT Pool:** `EpochStateHeader` (`188 bytes`) + $O(\log_2 N)$ Merkle branches allow `MobileLightClient` verification in `< 200 bytes` of state, while an opt-in Curve25519 `MLSAG` RingCT Shielded Pool (`xcrview1_` auditor viewing keys and `xcrtxproof1_` payment proofs) offers full sender, receiver, and amount privacy without a trusted setup.

---

## 4. Self-Custody (`Pocket & Vault`), Multi-Currency Wallet & Exchange

- **Spending Pocket & Daily Free Bandwidth:** Hardware Passkey (`P-256`) signing bounded by a configurable daily limit, including `3` zero-fee (`∀ 0.000000 XCR`) daily transfers per registered Pocket.
- **Safety Vault & Threshold Custody:** Protocol-enforced withdrawal cooling window (default `24 hours`) with `emergency_cancel` recovery, `XCRENC01` encrypted keystores, `GF(256)` Shamir backup shares, `FROST` $K$-of-$N$ threshold Schnorr signatures, offline QR signing (`xcrdurable1_`), and post-quantum WOTS+/Merkle guardian keys.
- **Multi-Currency Commerce & Sovereign Exchange:** Native fixed-supply bearer assets, `CredScript` smart vaults (`2-of-3` peer-to-peer fiat escrows), `x * y = k` AMM pools + Limit Orderbook Hybrid Smart Router, non-withdrawal `RoleProxy` delegation, `BOLT-11` Lightning & EVM HTLC atomic swaps, and a unified multi-currency desktop application (`credit-desktop`).

---

## 5. Longevity & Phased Stability

### 5.1 Closed-Loop `70 / 15 / 15` Fee Allocation
Credits allocates every transaction fee deterministically via `FeeSplit` and `SecurityEndurancePool`:
- **`70%` Immediate Worker Reward:** Paid to the current epoch's Share-DAG contributors.
- **`15%` Security Endurance Pool:** Held in an on-chain reserve that releases `1 / 525,600` of its balance per minute (one-year exponential time constant) to smooth worker incentives across quiet periods.
- **`15%` Permanent Supply Burn:** Subtracted from `circulating_supply`, maintaining an immediate `30%` cost against circular self-spam.

### 5.2 Stateless Archival & Compute-Weighted Governance
- **Dormant Account Archival (`DormantArchiveRegistry`):** Accounts inactive for $\ge 2\text{ years}$ (`1,051,200` epochs) are never taxed or forfeited; they compact out of active validator RAM into a 32-byte `ArchiveRoot` and revive in 1 RTT with a `<256-byte` `ArchiveInclusionProof`.
- **Supermajority Governance (`UpgradeGovernanceEngine`):** Protocol upgrades activate only after sustaining **$\ge 85.00\%$ PoNC compute support** over a 30-day signaling window, followed by a 30-day user review grace period.

### 5.3 Phase 1 → Phase 2 Civilization Basket
- **Phase 1 (Bootstrap):** Smooth disinflationary issuance approaching a `~0.5%/yr` security tail floor.
- **Phase 2 (Global Standard):** Once independent compute nodes ($\ge 10,000$), autonomous systems ($\ge 500$), and deep liquidity epochs ($\ge 43,200$) meet deterministic thresholds, `EpochLifecycleEngine` enables **Over-Collateralized `ReserveVault`s** ($\ge 200\%$ mint collateralization, `150%` liquidation threshold) guided by an integer `PidRateController` referencing a trimmed-median **9-Pillar Purchasing-Power Index**:

| Pillar | Weight | Scope |
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
