# Credits (`XCR`) Consensus Specification: PoNC, Share-DAG & 1-RTT Finality

**Version:** 0.3 · **Crates:** `credit-ponc`, `credit-consensus`

---

## 1. Design Objectives

Credits is structured around four consensus goals:
1. **Fair Launch (`Genesis Supply = 0`):** Every unit is earned through verifiable participation from `Epoch 0` without pre-allocated stakes.
2. **Accessible Participation & Useful Scaling:** Consumer CPUs earn steady rewards without joining mining pools, while GPUs and servers earn proportional weight for zero-knowledge proving and packet relay as transaction demand grows.
3. **Sub-Second Deterministic Finality (`~150–250 ms`):** Everyday payment confirmation operates independently of 60-second epoch boundaries.
4. **Balanced Micro-Fees (`70 / 15 / 15`):** Keeps standard transfer fees low (after 3 free daily transfers per account) while discouraging circular self-spam (`30%` immediate cost) and smoothing multi-year security funding.

---

## 2. Layer A: Proof of Network Compute (PoNC)

PoNC separates **Sybil-resistant participation** from **real-time transaction ordering**. Within each 60-second epoch $E_k$, participants submit verifiable work shares across three complementary tiers:

### 2.1 Base Tier — Memory-Hard CPU Virtual Machine (`CpuVm`)
- **Target Hardware:** Consumer laptops, desktops, and standard servers.
- **Scratchpad Initialization:** Given epoch seed $S_k \in \{0,1\}^{256}$ and participant address $A$, the VM initializes an L2/L3-cache-sized 64-bit word array $M[0..W-1]$ via domain-separated SHA-256 expansion (`XCR.PONC.SCRATCH.V1`).
- **Execution Loop:** Runs $R$ data-dependent rounds combining 64-bit wrapping multiplication, rotate-XOR mixing, and pseudo-random scratchpad read-modify-write addressing suited to general-purpose CPU caches and integer ALUs.

### 2.2 Scale-Out Tier — Two-Track GPU & Server `RecursiveZkState` Proving
- **Two-Track Hardware Architecture:**
  - **Headless Linux Servers (`credit-gpu-sys` → `credit-node`):** Uses zero external `crates.io` dependencies; dynamically probes `libOpenCL.so.1` via `dlopen` (supporting NVIDIA, AMD, and Intel headless drivers without X11/OpenGL) behind a safe `HeadlessLinuxGpu` interface while `credit-node` enforces `#![forbid(unsafe_code)]`, falling back cleanly to CPU when no GPU is present.
  - **Consumer Desktops (`wgpu` in `credit-desktop`):** Runs a `#![forbid(unsafe_code)]` WGSL compute shader across DirectX 12, Apple Metal, and Vulkan.
- **Demand-Driven Operation (`0W` Idle When Quiet):** Executes an 8-round RFC 6234 SHA-256 state-folding proof (`execute_zk_fold_from_context`, `MIN_ZK_ZERO_BITS = 6`) only when `verified_tx_count > 0` in the current epoch, earning weight (`canonical_zk_share_weight`) proportional to verified transaction throughput and verifiable in `< 0.05 ms` on any CPU.

### 2.3 Edge Tier — Low-Latency UDP/QUIC Relay (`EdgeRelay`)
- **Target Hardware:** Geographically distributed nodes providing authenticated packet relay verified by downstream quorum co-signatures.

---

## 3. Protocol-Native Epoch Share-DAG & Proportional Scaling

In single-winner block protocols, infrequent block rewards encourage solo operators to join custodial pools. Credits uses an on-chain **Epoch Share-DAG** so participants earn smoothly in proportion to contributed compute:

1. **Continuous Sub-Bit Difficulty Weighting (`canonical_cpu_share_weight`):** Any share $s$ whose `execute_ponc_vm` digest $H(s)$ has $z \ge 3$ leading zero bits is valid, with weight derived from both $z$ and the next 8-bit mantissa $d \in [256, 511]$:

$$w(s) = \left\lfloor \frac{100 \cdot 256 \cdot 2^{\min(z, 36)}}{d} \right\rfloor$$

2. **Non-Blocking Multi-Core Scaling & Top-2 Retention (`upsert_best_cpu_share`):** Background worker threads (`--threads N`, or `Eco / Balanced / Max` in `credit-desktop`) evaluate `execute_ponc_vm` continuously without blocking `1-RTT` UDP settlement. `EpochShareDag` retains each worker's top-2 highest-weight shares (`MAX_CPU_SHARES_PER_WORKER = 2`), reducing single-epoch variance while keeping `EpochSeal` messages compact (`< 1,200 bytes`).
3. **Proportional Layer-1 Payouts:** At the close of epoch $E_k$, issuance $M(E_k)$, `70%` of collected fees $F_{\text{worker}}(E_k)$, and the one-year exponential drip $D_{\text{endurance}}(E_k) = \lfloor P_{\text{pool}} / 525{,}600 \rfloor$ from `SecurityEndurancePool` are distributed proportionally:

$$R_i(E_k) = \left( M(E_k) + F_{\text{worker}}(E_k) + D_{\text{endurance}}(E_k) \right) \cdot \frac{\sum_{s \in S_i} w(s)}{\sum_{s \in S_{\text{all}}} w(s)}$$

4. **Solo Accessibility & Process-Splitting Neutrality:** A single-thread laptop reaches $z \ge 3$ within milliseconds to earn regular 60-second payouts without a pool, multi-core systems earn proportionally higher weight, and splitting one CPU across multiple node identities confers no extra reward.

---

## 4. Layer B: Compute-Elected Quorum & Dual Settlement Paths

At the close of epoch $E_k$, contributors with verified Share-DAG weight form the **Epoch Signing Committee** $Q_{k+1}$ with total voting weight $W_{\text{total}}$ (capping any single node's BFT *voting* weight at $\le 1/3$ when $\ge 3$ independent validators are active, while leaving `XCR` reward payouts uncapped) and Byzantine quorum threshold:

$$W_{\text{quorum}} = \left\lfloor \frac{2 W_{\text{total}}}{3} \right\rfloor + 1$$

### 4.1 Path 1 — Single-Owner 1-RTT Fast Path (`~150–250 ms`)
Single-owner `PocketState` transfers require non-equivocation rather than global ordering across unrelated accounts:
1. **Broadcast (`0.5 RTT`):** The sender transmits a signed `FastTransfer` over UDP/QUIC to the assigned shard committee.
2. **Lock & Co-Sign (`0.5 RTT`):** Each validator checks the signature, daily `Pocket` limit, `fee >= base_fee`, and `(from, nonce)` uniqueness, then locks `(from, nonce)` and returns a `ValidatorVote`.
3. **Finality (`1 RTT Total`):** Once votes summing to $\ge W_{\text{quorum}}$ arrive, the `FinalityCertificate` is final.

### 4.2 Path 2 — 3-Round Pipelined BFT DAG (`~450 ms`)
Operations touching shared multi-party state — such as `Savings Vault` recovery or Phase-2 `ReserveVault` positions — are ordered through an uncertified pipelined BFT DAG (`BftDagEngine`), reaching deterministic finality in **3 message rounds**.

---

## 5. Emission, Security Endurance Pool & Fee-Burn Balance

- **Genesis Allocation:** `0.000000 XCR` (`0 bits`), gated until `2027-01-01T00:00:00Z` (`MAINNET_GENESIS_UNIX = 1,798,761,600`) and unlocked automatically via $\ge 2$-of-$4$ Bitcoin block API consensus (`scripts/mainnet-genesis-watcher.py` → `credit-cli unlock-genesis`).
- **Phase 1 Disinflation:** Epoch issuance $M(E_k)$ tapers smoothly toward a `~0.5%` annual security tail floor.
- **Closed-Loop `70 / 15 / 15` Fee Split:**
  - **`70%` Immediate Worker Pool:** Paid to active Share-DAG contributors in the current epoch.
  - **`15%` `SecurityEndurancePool`:** Held in an on-chain reserve releasing `1 / 525,600` per 1-minute epoch to support quiet periods.
  - **`15%` Permanent Burn:** Subtracted from `circulating_supply` (`burned = fee - worker - endurance`).
