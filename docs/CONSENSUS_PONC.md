# Credits (`XCR`) Consensus Specification: PoNC, Share-DAG & 1-RTT Finality

**Version:** 0.3 · **Crates:** `credit-ponc`, `credit-consensus`

---

## 1. Design Objectives

Credits is designed around four consensus goals:
1. **Zero-Premine Fair Launch (`Genesis Supply = 0`):** Every unit is earned through verifiable participation from `Epoch 0` without insider or pre-staked allocations.
2. **Accessible Participation → Useful Scaling:** Consumer CPUs earn continuous rewards without joining mining pools, while dedicated servers earn proportional weight for useful recursive zero-knowledge proving and high-bandwidth relay as throughput grows.
3. **Sub-Second Deterministic Finality (`~150–250 ms`):** Everyday payment confirmation is decoupled from 60-second epoch intervals.
4. **Closed-Loop Micro-Fees (`70 / 15 / 15`):** Keeps ordinary transfer fees near `~0.05–0.1 cents` equivalent while deterring validator self-spam (`30%` immediate loss) and smoothing multi-year security funding.

---

## 2. Layer A: Proof of Network Compute (PoNC)

PoNC separates **Sybil-resistant participation** from **real-time transaction ordering**. Within each 60-second epoch $E_k$, participants submit verifiable work shares across three complementary tiers:

### 2.1 Base Tier — Memory-Hard CPU Virtual Machine (`CpuVm`)
- **Target Hardware:** Consumer laptops, desktops, and home mini-PCs.
- **Scratchpad Initialization:** Given epoch seed $S_k \in \{0,1\}^{256}$ and participant address $A$, the VM initializes an L2/L3-cache-sized 64-bit word array $M[0..W-1]$ via domain-separated SHA-256 expansion (`XCR.PONC.SCRATCH.V1`).
- **Execution Loop:** Runs $R$ data-dependent rounds combining 64-bit wrapping multiplication, rotate-XOR mixing, and pseudo-random scratchpad read-modify-write addressing—favoring general-purpose CPU cache hierarchies and integer ALUs over fixed-function ASICs.

### 2.2 Scale-Out Tier — Recursive ZK State Proving (`RecursiveZkState`)
- **Target Hardware:** Multi-core prover servers as network volume scales.
- **Useful Work:** Aggregates confidential transfer proofs and shard state roots into succinct epoch transition proofs, earning weighted Share-DAG credits strictly when the proof verifies against finalized epoch commitments.

### 2.3 Edge Tier — Low-Latency UDP/QUIC Relay (`EdgeRelay`)
- **Target Hardware:** Geographically distributed routers providing authenticated packet fanout verified by downstream quorum co-signatures.

---

## 3. Protocol-Native Epoch Share-DAG

In traditional winner-take-all blockchains, only one miner every several minutes earns the block reward, pushing solo operators into custodial pools. Credits replaces single-winner blocks with an on-chain **Epoch Share-DAG**:

1. Any share $s$ whose PoNC digest $H(s)$ satisfies the lower **Share Target** $T_{\text{share}}$ enters `EpochShareDag`, referencing $1..k$ recent tips as parents.
2. At the close of epoch $E_k$, epoch issuance $M(E_k)$, `70%` of collected fees $F_{\text{worker}}(E_k)$, and the one-year exponential drip $D_{\text{endurance}}(E_k) = \lfloor P_{\text{pool}} / 525{,}600 \rfloor$ from `SecurityEndurancePool` are paid proportionally across all valid unique shares:

$$R_i(E_k) = \left( M(E_k) + F_{\text{worker}}(E_k) + D_{\text{endurance}}(E_k) \right) \cdot \frac{\sum_{s \in S_i} w(s)}{\sum_{s \in S_{\text{all}}} w(s)}$$

3. Solo participants receive deterministic payouts directly at Layer 1 without pool intermediaries or payout thresholds.

---

## 4. Layer B: Compute-Elected Quorum & Dual Settlement Paths

At the close of epoch $E_k$, contributors with verified Share-DAG weight and low-latency uptime form the **Epoch Signing Committee** $Q_{k+1}$ with total voting weight $W_{\text{total}}$ and Byzantine quorum threshold:

$$W_{\text{quorum}} = \left\lfloor \frac{2 W_{\text{total}}}{3} \right\rfloor + 1$$

### 4.1 Path 1 — Single-Owner 1-RTT Fast Path (`~150–250 ms`)
Most everyday payments spend from a single owner's `PocketState`, requiring non-equivocation rather than global ordering across unrelated accounts:
1. **Broadcast (`0.5 RTT`):** Sender transmits a signed `FastTransfer` over UDP/QUIC to the assigned shard committee.
2. **Lock & Co-Sign (`0.5 RTT`):** Each validator verifies the signature, daily `Pocket` limit, `fee >= base_fee`, and non-equivocation on `(from, nonce)`. If valid, it atomically locks `(from, nonce)` and returns a `ValidatorVote`.
3. **Finality (`1 RTT Total`):** Once votes summing to $\ge W_{\text{quorum}}$ arrive, the `FinalityCertificate` is immediately irreversible with zero mempool front-running (zero MEV).

### 4.2 Path 2 — 3-Round Pipelined BFT DAG (`~450 ms`)
Operations touching shared multi-party state—such as `Savings Vault` recovery or Phase-2 `ReserveVault` positions—order through an uncertified Mysticeti-style pipelined BFT DAG (`BftDagEngine`), reaching deterministic finality in **3 message rounds**.

---

## 5. Emission, Security Endurance Pool & Fee-Burn Equilibrium

- **Genesis Premine:** `0.000000 XCR` (`0 bits`).
- **Phase 1 Disinflation:** Epoch issuance $M(E_k)$ decays smoothly toward a `~0.5%` annual security tail floor.
- **Closed-Loop `70 / 15 / 15` Fee Split:**
  - **`70%` Immediate Worker Pool:** Paid to active Share-DAG contributors in the current epoch.
  - **`15%` `SecurityEndurancePool`:** Locked into an on-chain reserve that releases `1 / 525,600` per 1-minute epoch (one-year exponential decay), carrying peak-era fee revenue forward into quieter periods.
  - **`15%` Permanent Burn:** Subtracted from `circulating_supply` (`burned = fee - worker - endurance`), ensuring wash-spam incurs an immediate `30%` loss while offsetting tail issuance during periods of high commercial throughput.
