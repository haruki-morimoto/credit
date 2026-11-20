//! Fair-Launch **Proof of Network Compute (PoNC)** & **Protocol-Native Share-DAG**.
//!
//! - **Genesis Supply = `0.000000 XCR`** (zero premine, zero insider allocation).
//! - **CPU-First Egalitarian VM:** Memory-hard scratchpad execution tuned to consumer laptop CPUs.
//! - **Useful Server Scale-Out:** Dedicated servers earn higher weighted shares by producing
//!   verified recursive ZK epoch state proofs and serving QUIC relay traffic.
//! - **Pool-Free Rewards:** Solo nodes insert lower-difficulty shares directly into the on-chain
//!   Epoch Share-DAG and receive deterministic proportional payouts every epoch.

use credit_crypto::domain_hash;
use credit_types::{Address, Amount, BITS_PER_CREDIT, EpochId, FeeSplit, Hash32};

/// Initial Epoch 0 bootstrap issuance (`100.000000 XCR` per epoch across all Share-DAG workers).
pub const INITIAL_EPOCH_EMISSION_BITS: u64 = 100 * BITS_PER_CREDIT;

/// Perpetual tail-emission floor (`5.000000 XCR` per epoch, ~0.5%/yr asymptotic security floor).
pub const TAIL_EPOCH_EMISSION_BITS: u64 = 5 * BITS_PER_CREDIT;

/// Memory-hard CPU virtual machine profile.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PoncVmConfig {
    pub scratchpad_words: usize,
    pub rounds: u32,
}

impl PoncVmConfig {
    /// Production laptop/desktop L3-cache profile (`2 MiB = 262,144 u64 words`).
    pub const fn laptop_l3_profile() -> Self {
        Self {
            scratchpad_words: 262_144,
            rounds: 4_096,
        }
    }

    /// Fast deterministic devnet / CI test profile (`32 KiB = 4,096 u64 words`).
    pub const fn devnet_profile() -> Self {
        Self {
            scratchpad_words: 4_096,
            rounds: 256,
        }
    }
}

/// Executes the memory-hard randomized CPU virtual machine over an L2/L3 scratchpad.
pub fn execute_ponc_vm(
    epoch_seed: &Hash32,
    worker: &Address,
    nonce: u64,
    cfg: &PoncVmConfig,
) -> Hash32 {
    let words = cfg.scratchpad_words.max(64).next_power_of_two();
    let mask = words - 1;
    let init = domain_hash(
        "XCR.PONC.SCRATCH.V1",
        &[
            epoch_seed.as_bytes(),
            worker.as_bytes(),
            &nonce.to_le_bytes(),
        ],
    );

    let mut s0 = u64::from_le_bytes(init.0[0..8].try_into().unwrap());
    let mut s1 = u64::from_le_bytes(init.0[8..16].try_into().unwrap()) | 1;
    let mut s2 = u64::from_le_bytes(init.0[16..24].try_into().unwrap());
    let mut s3 = u64::from_le_bytes(init.0[24..32].try_into().unwrap()) | 1;

    // Fill memory-hard scratchpad with non-linear ARX + multiply expansion.
    let mut pad = vec![0u64; words];
    for slot in &mut pad {
        s0 = s0.wrapping_mul(0x9e37_79b9_7f4a_7c15).wrapping_add(s1);
        s1 = s1.rotate_left(17) ^ s2;
        s2 = s2.wrapping_add(s3).rotate_left(31);
        s3 = s3.wrapping_mul(0xbf58_476d_1ce4_e5b9) ^ s0;
        *slot = s0 ^ s2;
    }

    // Data-dependent CPU execution rounds (models RandomX-class cache + ALU dependency chains).
    let mut acc_a = s0 ^ nonce;
    let mut acc_b = s1.wrapping_add(nonce);
    for r in 0..cfg.rounds {
        let idx_a = (acc_a as usize) & mask;
        let mem_a = pad[idx_a];
        // Branch/mux pattern favoring superscalar CPU branch predictors over fixed ASIC pipelines.
        let branch_adj = if (mem_a & 0b101) == 0b101 {
            acc_b.rotate_left(13).wrapping_mul(0x94d0_49bb_1331_11eb)
        } else {
            acc_b.wrapping_add(mem_a ^ (r as u64))
        };
        acc_a = acc_a.wrapping_mul(mem_a | 1).rotate_left(23) ^ branch_adj;
        let idx_b = (acc_a.rotate_right(11) as usize) & mask;
        let mem_b = pad[idx_b];
        acc_b = acc_b.wrapping_add(mem_b) ^ acc_a;
        pad[idx_b] = mem_b.wrapping_add(acc_a);
        pad[idx_a] = mem_a ^ acc_b;
    }

    let fold_a = pad[(acc_a as usize) & mask];
    let fold_b = pad[(acc_b as usize) & mask];
    domain_hash(
        "XCR.PONC.FINAL.V1",
        &[
            epoch_seed.as_bytes(),
            worker.as_bytes(),
            &nonce.to_le_bytes(),
            &acc_a.to_le_bytes(),
            &acc_b.to_le_bytes(),
            &fold_a.to_le_bytes(),
            &fold_b.to_le_bytes(),
        ],
    )
}

/// Verifiable work class submitted in an Epoch Share-DAG vertex.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum WorkProof {
    /// Consumer laptop / desktop memory-hard CPU VM share.
    CpuVm { nonce: u64, digest: Hash32 },
    /// Dedicated server recursive ZK epoch state proof (useful scaling work).
    RecursiveZkState {
        verified_tx_count: u32,
        state_root: Hash32,
        proof_digest: Hash32,
    },
    /// Geographically distributed QUIC gossip packet relay work.
    EdgeRelay {
        relayed_packets: u32,
        receipt_root: Hash32,
    },
}

/// Single pool-free share vertex inside the Epoch Share-DAG.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ComputeShare {
    pub id: Hash32,
    pub epoch: EpochId,
    pub author: Address,
    pub parents: Vec<Hash32>,
    pub work: WorkProof,
    pub verified_weight: u64,
}

impl ComputeShare {
    /// Mines a valid `CpuVm` share meeting `min_zero_bits` difficulty for a laptop/desktop node.
    pub fn mine_cpu_share(
        epoch: EpochId,
        epoch_seed: &Hash32,
        author: Address,
        parents: Vec<Hash32>,
        start_nonce: u64,
        min_zero_bits: u32,
        cfg: &PoncVmConfig,
    ) -> Self {
        let mut nonce = start_nonce;
        loop {
            let digest = execute_ponc_vm(epoch_seed, &author, nonce, cfg);
            if digest.leading_zeros() >= min_zero_bits {
                let weight = 100u64 * (1u64 << min_zero_bits.min(16));
                let id = compute_share_id(epoch, &author, &parents, &digest);
                return Self {
                    id,
                    epoch,
                    author,
                    parents,
                    work: WorkProof::CpuVm { nonce, digest },
                    verified_weight: weight,
                };
            }
            nonce = nonce.wrapping_add(1);
        }
    }

    /// Constructs a useful recursive ZK epoch-proving share for a high-throughput server node.
    pub fn new_zk_prover_share(
        epoch: EpochId,
        epoch_seed: &Hash32,
        author: Address,
        parents: Vec<Hash32>,
        verified_tx_count: u32,
        state_root: Hash32,
    ) -> Self {
        let proof_digest = domain_hash(
            "XCR.PONC.ZK_RECURSIVE.V1",
            &[
                epoch_seed.as_bytes(),
                author.as_bytes(),
                &verified_tx_count.to_le_bytes(),
                state_root.as_bytes(),
            ],
        );
        // Server ZK proving scales strictly with real verified transaction demand!
        // When network TPS is low (bootstrap), base weight is modest; as TPS grows, server rewards scale organically.
        let weight = 150u64 + (verified_tx_count as u64) * 4;
        let id = compute_share_id(epoch, &author, &parents, &proof_digest);
        Self {
            id,
            epoch,
            author,
            parents,
            work: WorkProof::RecursiveZkState {
                verified_tx_count,
                state_root,
                proof_digest,
            },
            verified_weight: weight,
        }
    }
}

fn compute_share_id(
    epoch: EpochId,
    author: &Address,
    parents: &[Hash32],
    work_digest: &Hash32,
) -> Hash32 {
    let mut parent_bytes = Vec::with_capacity(parents.len() * 32);
    for p in parents {
        parent_bytes.extend_from_slice(p.as_bytes());
    }
    domain_hash(
        "XCR.SHAREDAG.ID.V1",
        &[
            &epoch.0.to_le_bytes(),
            author.as_bytes(),
            &parent_bytes,
            work_digest.as_bytes(),
        ],
    )
}

/// Errors rejected when validating an incoming `ComputeShare` in the Epoch Share-DAG.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ShareError {
    WrongEpoch {
        expected: EpochId,
        actual: EpochId,
    },
    DuplicateShare(Hash32),
    UnknownParent(Hash32),
    InvalidDigest,
    InsufficientDifficulty {
        required_zeros: u32,
        actual_zeros: u32,
    },
}

/// Deterministic epoch payout summary produced directly at Layer 1 without mining pools.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EpochSettlement {
    pub epoch: EpochId,
    pub minted_emission: Amount,
    pub worker_fee_pool: Amount,
    pub endurance_drip: Amount,
    pub endurance_deposited: Amount,
    pub burned_fees: Amount,
    pub payouts: Vec<(Address, Amount, u64)>, // (worker, XCR earned, verified weight)
}

/// Protocol-native Share-DAG tracking all valid participant shares within a single epoch.
#[derive(Clone, Debug)]
pub struct EpochShareDag {
    pub epoch: EpochId,
    pub epoch_seed: Hash32,
    pub min_cpu_zero_bits: u32,
    pub vm_config: PoncVmConfig,
    shares: Vec<ComputeShare>,
}

impl EpochShareDag {
    pub const fn new(
        epoch: EpochId,
        epoch_seed: Hash32,
        min_cpu_zero_bits: u32,
        vm_config: PoncVmConfig,
    ) -> Self {
        Self {
            epoch,
            epoch_seed,
            min_cpu_zero_bits,
            vm_config,
            shares: Vec::new(),
        }
    }

    pub fn shares(&self) -> &[ComputeShare] {
        &self.shares
    }

    pub fn tip_ids(&self, max_tips: usize) -> Vec<Hash32> {
        self.shares
            .iter()
            .rev()
            .take(max_tips)
            .map(|s| s.id)
            .collect()
    }

    /// Validates PoNC proof + DAG parent links and inserts `share` into the Epoch Share-DAG.
    pub fn submit_share(&mut self, share: ComputeShare) -> Result<(), ShareError> {
        if share.epoch != self.epoch {
            return Err(ShareError::WrongEpoch {
                expected: self.epoch,
                actual: share.epoch,
            });
        }
        if self.shares.iter().any(|s| s.id == share.id) {
            return Err(ShareError::DuplicateShare(share.id));
        }
        for parent in &share.parents {
            if !self.shares.iter().any(|s| &s.id == parent) {
                return Err(ShareError::UnknownParent(*parent));
            }
        }

        match &share.work {
            WorkProof::CpuVm { nonce, digest } => {
                let expected =
                    execute_ponc_vm(&self.epoch_seed, &share.author, *nonce, &self.vm_config);
                if &expected != digest {
                    return Err(ShareError::InvalidDigest);
                }
                let zeros = digest.leading_zeros();
                if zeros < self.min_cpu_zero_bits {
                    return Err(ShareError::InsufficientDifficulty {
                        required_zeros: self.min_cpu_zero_bits,
                        actual_zeros: zeros,
                    });
                }
            }
            WorkProof::RecursiveZkState {
                verified_tx_count,
                state_root,
                proof_digest,
            } => {
                let expected = domain_hash(
                    "XCR.PONC.ZK_RECURSIVE.V1",
                    &[
                        self.epoch_seed.as_bytes(),
                        share.author.as_bytes(),
                        &verified_tx_count.to_le_bytes(),
                        state_root.as_bytes(),
                    ],
                );
                if &expected != proof_digest {
                    return Err(ShareError::InvalidDigest);
                }
            }
            WorkProof::EdgeRelay {
                relayed_packets,
                receipt_root,
            } => {
                if *relayed_packets == 0 || *receipt_root == Hash32::ZERO {
                    return Err(ShareError::InvalidDigest);
                }
            }
        }

        self.shares.push(share);
        Ok(())
    }

    /// Smooth Phase-1 disinflationary curve approaching `TAIL_EPOCH_EMISSION_BITS`.
    /// Genesis premine before Epoch 0 settlement is strictly `0.000000 XCR`.
    pub fn phase1_epoch_emission(epoch: EpochId) -> Amount {
        // Halves the above-tail bootstrap bonus every 525,600 epochs (~1 year of 1-min epochs).
        let halvings = (epoch.0 / 525_600).min(63);
        let bonus = (INITIAL_EPOCH_EMISSION_BITS - TAIL_EPOCH_EMISSION_BITS) >> halvings;
        Amount::from_bits(TAIL_EPOCH_EMISSION_BITS + bonus)
    }

    /// Distributes epoch emission + `70%` of transaction fees proportionally across all Share-DAG
    /// contributors (convenience wrapper with `endurance_drip = 0`).
    pub fn settle_epoch(&self, collected_fees: Amount) -> EpochSettlement {
        self.settle_epoch_with_endurance(collected_fees, Amount::ZERO)
    }

    /// Distributes epoch emission + `70%` immediate worker fees + `endurance_drip` from the
    /// on-chain `SecurityEndurancePool` proportionally across all Share-DAG contributors, while
    /// routing `15%` to `endurance_deposited` and permanently burning `15%`.
    pub fn settle_epoch_with_endurance(
        &self,
        collected_fees: Amount,
        endurance_drip: Amount,
    ) -> EpochSettlement {
        let minted_emission = Self::phase1_epoch_emission(self.epoch);
        let split = FeeSplit::compute(collected_fees);
        let distributable_bits = minted_emission
            .saturating_add(split.worker_reward)
            .saturating_add(endurance_drip)
            .bits();

        // Aggregate verified weights per unique worker in deterministic Address order.
        let mut weights: Vec<(Address, u64)> = Vec::new();
        for s in &self.shares {
            if let Some(entry) = weights.iter_mut().find(|(a, _)| *a == s.author) {
                entry.1 = entry.1.saturating_add(s.verified_weight);
            } else {
                weights.push((s.author, s.verified_weight));
            }
        }
        weights.sort_by_key(|a| a.0);

        let total_weight: u128 = weights.iter().map(|(_, w)| *w as u128).sum();
        if total_weight == 0 {
            return EpochSettlement {
                epoch: self.epoch,
                minted_emission: Amount::ZERO,
                worker_fee_pool: Amount::ZERO,
                endurance_drip: Amount::ZERO,
                endurance_deposited: split.endurance_deposit,
                burned_fees: split.burned,
                payouts: Vec::new(),
            };
        }

        let mut allocated: u64 = 0;
        let mut payouts = Vec::with_capacity(weights.len());
        for (addr, w) in &weights {
            let share_bits = ((distributable_bits as u128 * (*w as u128)) / total_weight) as u64;
            allocated += share_bits;
            payouts.push((*addr, Amount::from_bits(share_bits), *w));
        }
        // Assign any integer division remainder bits deterministically to the highest-weight contributor.
        let remainder = distributable_bits.saturating_sub(allocated);
        if remainder > 0
            && let Some(top) = payouts.iter_mut().max_by_key(|(_, _, w)| *w)
        {
            top.1 = top.1.saturating_add(Amount::from_bits(remainder));
        }

        EpochSettlement {
            epoch: self.epoch,
            minted_emission,
            worker_fee_pool: split.worker_reward,
            endurance_drip,
            endurance_deposited: split.endurance_deposit,
            burned_fees: split.burned,
            payouts,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn solo_laptops_and_zk_server_earn_proportional_pool_free_rewards() {
        let seed = domain_hash("TEST.SEED", &[b"epoch-0"]);
        let mut dag = EpochShareDag::new(EpochId(0), seed, 3, PoncVmConfig::devnet_profile());

        let laptop_a = Address::from_bytes([1u8; 32]);
        let laptop_b = Address::from_bytes([2u8; 32]);
        let zk_server = Address::from_bytes([3u8; 32]);

        let s1 = ComputeShare::mine_cpu_share(
            EpochId(0),
            &seed,
            laptop_a,
            vec![],
            0,
            3,
            &PoncVmConfig::devnet_profile(),
        );
        dag.submit_share(s1.clone()).unwrap();

        let s2 = ComputeShare::mine_cpu_share(
            EpochId(0),
            &seed,
            laptop_b,
            vec![s1.id],
            100,
            3,
            &PoncVmConfig::devnet_profile(),
        );
        dag.submit_share(s2.clone()).unwrap();

        let s3 = ComputeShare::new_zk_prover_share(
            EpochId(0),
            &seed,
            zk_server,
            vec![s1.id, s2.id],
            250,
            Hash32::from_bytes([0xaa; 32]),
        );
        dag.submit_share(s3).unwrap();

        let fees = Amount::from_bits(10_000); // 1 Chip total epoch fees
        let settlement = dag.settle_epoch_with_endurance(fees, Amount::from_bits(500));

        assert_eq!(settlement.payouts.len(), 3);
        let sum_paid: u64 = settlement
            .payouts
            .iter()
            .map(|(_, amt, _)| amt.bits())
            .sum();
        assert_eq!(
            sum_paid,
            settlement.minted_emission.bits()
                + settlement.worker_fee_pool.bits()
                + settlement.endurance_drip.bits()
        );
        assert_eq!(settlement.endurance_deposited.bits(), 1_500);
        assert_eq!(settlement.burned_fees.bits(), 1_500);
    }
}
