//! Stage-2 **Horizontal Address-Prefix Quorum Sharding (`ShardedFastPathCluster`)**.
//!
//! Because single-owner `FastTransfer` payments only mutate the sender's `Spending Pocket`
//! (`tx.from`) and emit an unlinkable append-only `StealthOutput`, unrelated human payments
//! never contend on shared state:
//! - Partitioning the 256-bit `Address` space by its top `prefix_bits` (`S = 2^b` shards) routes
//!   every payment deterministically to `ShardId` with **zero cross-shard locks**.
//! - Validators are pseudo-randomly assigned across shards every epoch using `epoch_seed` so no
//!   miner cartel can target a specific shard.
//! - `execute_parallel_wave` processes all `S` shards concurrently across OS CPU threads via
//!   `std::thread::scope` and rolls per-shard roots into a single `global_shard_merkle_root`.

use std::thread;

use credit_crypto::{Keypair, PublicKey, domain_hash};
use credit_types::{Address, Amount, EpochId, Hash32, PocketState, Transaction, TransactionKind};

use crate::{ConsensusError, FastPathEngine, FinalityCertificate, QuorumCommittee, QuorumMember};

/// Deterministic power-of-two address-prefix sharding layout (`1..=256` shards).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ShardConfig {
    pub prefix_bits: u8,
}

impl ShardConfig {
    pub const fn new(prefix_bits: u8) -> Option<Self> {
        if prefix_bits <= 8 {
            Some(Self { prefix_bits })
        } else {
            None
        }
    }

    #[inline]
    pub const fn shard_count(&self) -> usize {
        1usize << self.prefix_bits
    }

    /// Maps any 256-bit `Address` to its owning `shard_id` (`0..shard_count`) in `O(1)`.
    #[inline]
    pub const fn shard_for_address(&self, addr: &Address) -> u16 {
        if self.prefix_bits == 0 {
            0
        } else {
            (addr.0[0] >> (8 - self.prefix_bits)) as u16
        }
    }
}

/// Summary commitment emitted by a single shard after settling a parallel wave of payments.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ShardSettlementRoot {
    pub shard_id: u16,
    pub settled_tx_count: u32,
    pub collected_fees: Amount,
    pub shard_tx_root: Hash32,
}

/// Result of executing a multi-shard wave of concurrent 1-RTT `FastTransfer`s across CPU cores.
#[derive(Clone, Debug)]
pub struct WaveExecutionSummary {
    pub certificates: Vec<(u16, Result<FinalityCertificate, ConsensusError>)>,
    pub shard_roots: Vec<ShardSettlementRoot>,
    pub global_shard_merkle_root: Hash32,
}

/// Shuffles and assigns `epoch` validators into `S` Byzantine-safe shard sub-committees using
/// `epoch_seed` so shard membership cannot be pre-targeted by an adversary.
pub fn assign_validators_to_shards(
    epoch: EpochId,
    epoch_seed: &Hash32,
    validators: &[QuorumMember],
    cfg: ShardConfig,
    min_validators_per_shard: usize,
) -> Vec<QuorumCommittee> {
    let shard_count = cfg.shard_count();
    if validators.is_empty() {
        return (0..shard_count)
            .map(|_| QuorumCommittee::new(epoch, Vec::new()))
            .collect();
    }

    // Score and permute validators unpredictably via `epoch_seed`:
    let mut ranked: Vec<(Hash32, QuorumMember)> = validators
        .iter()
        .cloned()
        .map(|m| {
            let ticket = domain_hash(
                "XCR.SHARD.PERMUTE.V1",
                &[
                    epoch_seed.as_bytes(),
                    &epoch.0.to_le_bytes(),
                    m.address.as_bytes(),
                ],
            );
            (ticket, m)
        })
        .collect();
    ranked.sort_by_key(|a| a.0);

    let ordered: Vec<QuorumMember> = ranked.into_iter().map(|(_, m)| m).collect();
    let per_shard = (ordered.len() / shard_count).max(min_validators_per_shard.min(ordered.len()));

    let mut committees = Vec::with_capacity(shard_count);
    for shard_idx in 0..shard_count {
        let start = (shard_idx * per_shard) % ordered.len();
        let mut sub_members = Vec::with_capacity(per_shard);
        for offset in 0..per_shard {
            sub_members.push(ordered[(start + offset) % ordered.len()].clone());
        }
        committees.push(QuorumCommittee::new(epoch, sub_members));
    }
    committees
}

/// Horizontally sharded 1-RTT Fast-Path execution cluster running `S` independent `FastPathEngine`s.
pub struct ShardedFastPathCluster {
    pub config: ShardConfig,
    shards: Vec<FastPathEngine>,
}

impl ShardedFastPathCluster {
    pub fn new(config: ShardConfig, committees: Vec<QuorumCommittee>) -> Self {
        assert_eq!(committees.len(), config.shard_count());
        let shards = committees.into_iter().map(FastPathEngine::new).collect();
        Self { config, shards }
    }

    /// Registers a `Spending Pocket` onto its deterministic home shard (`O(1)` prefix route).
    pub fn register_pocket(&mut self, pubkey: PublicKey, state: PocketState) -> (u16, Address) {
        let addr = pubkey.to_address();
        let shard_id = self.config.shard_for_address(&addr);
        self.shards[shard_id as usize].register_pocket(pubkey, state);
        (shard_id, addr)
    }

    pub fn pocket_state(&self, addr: &Address) -> Option<&PocketState> {
        let shard_id = self.config.shard_for_address(addr);
        self.shards[shard_id as usize].pocket_state(addr)
    }

    /// Routes an arbitrary batch of single-owner `FastTransfer` transactions to their home shards
    /// and settles all shards **in parallel across OS threads** without cross-shard locking.
    pub fn execute_parallel_wave(
        &mut self,
        transactions: &[Transaction],
        shard_signers: &mut [Vec<(Address, Keypair)>],
        day_index: u64,
    ) -> WaveExecutionSummary {
        let shard_count = self.config.shard_count();
        assert_eq!(shard_signers.len(), shard_count);

        let mut buckets: Vec<Vec<&Transaction>> = vec![Vec::new(); shard_count];
        for tx in transactions {
            let shard_id = match &tx.kind {
                TransactionKind::FastTransfer { from, .. } => self.config.shard_for_address(from),
                TransactionKind::VaultQueueWithdrawal { vault_owner, .. }
                | TransactionKind::VaultEmergencyCancel { vault_owner, .. } => {
                    self.config.shard_for_address(vault_owner)
                }
            };
            buckets[shard_id as usize].push(tx);
        }

        type ShardWorkerOutput = (
            u16,
            Vec<Result<FinalityCertificate, ConsensusError>>,
            ShardSettlementRoot,
        );
        let per_shard_results: Vec<ShardWorkerOutput> = thread::scope(|s| {
            let mut handles = Vec::with_capacity(shard_count);
            for (shard_idx, ((engine, signers), shard_txs)) in self
                .shards
                .iter_mut()
                .zip(shard_signers.iter_mut())
                .zip(buckets)
                .enumerate()
            {
                let shard_id = shard_idx as u16;
                handles.push(s.spawn(move || {
                    let mut results = Vec::with_capacity(shard_txs.len());
                    let mut settled_hashes = Vec::new();
                    let mut settled_tx_count = 0u32;

                    for tx in shard_txs {
                        let res = engine.execute_1rtt_transfer(tx, signers, day_index);
                        if let Ok(cert) = &res {
                            settled_tx_count += 1;
                            settled_hashes.extend_from_slice(cert.tx_id.as_bytes());
                        }
                        results.push(res);
                    }

                    let shard_tx_root = domain_hash(
                        "XCR.SHARD.TX_ROOT.V1",
                        &[
                            &shard_id.to_le_bytes(),
                            &settled_tx_count.to_le_bytes(),
                            &settled_hashes,
                        ],
                    );
                    let root = ShardSettlementRoot {
                        shard_id,
                        settled_tx_count,
                        collected_fees: engine.collected_epoch_fees,
                        shard_tx_root,
                    };
                    (shard_id, results, root)
                }));
            }

            handles
                .into_iter()
                .map(|h| h.join().expect("shard worker thread succeeded"))
                .collect()
        });

        let mut certificates = Vec::with_capacity(transactions.len());
        let mut shard_roots = Vec::with_capacity(shard_count);
        for (shard_id, res_list, root) in per_shard_results {
            for r in res_list {
                certificates.push((shard_id, r));
            }
            shard_roots.push(root);
        }

        let global_shard_merkle_root = compute_shard_merkle_root(&shard_roots);
        WaveExecutionSummary {
            certificates,
            shard_roots,
            global_shard_merkle_root,
        }
    }
}

/// Computes the binary Merkle root over all `S = 2^b` `ShardSettlementRoot`s.
pub fn compute_shard_merkle_root(roots: &[ShardSettlementRoot]) -> Hash32 {
    if roots.is_empty() {
        return Hash32::ZERO;
    }
    let mut layer: Vec<Hash32> = roots
        .iter()
        .map(|r| {
            domain_hash(
                "XCR.SHARD.LEAF.V1",
                &[
                    &r.shard_id.to_le_bytes(),
                    &r.settled_tx_count.to_le_bytes(),
                    &r.collected_fees.bits().to_le_bytes(),
                    r.shard_tx_root.as_bytes(),
                ],
            )
        })
        .collect();
    while layer.len() > 1 {
        let mut next = Vec::with_capacity(layer.len().div_ceil(2));
        for pair in layer.chunks(2) {
            let right = if pair.len() == 2 { pair[1] } else { pair[0] };
            next.push(domain_hash(
                "XCR.SHARD.NODE.V1",
                &[pair[0].as_bytes(), right.as_bytes()],
            ));
        }
        layer = next;
    }
    layer[0]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tx_signing_digest;
    use credit_crypto::SignatureScheme;

    #[test]
    fn four_shard_parallel_wave_executes_concurrently_and_rolls_up_merkle_root() {
        let cfg = ShardConfig::new(2).unwrap(); // 2^2 = 4 parallel address-prefix shards
        assert_eq!(cfg.shard_count(), 4);

        let v_keys: Vec<Keypair> = (1u8..=8)
            .map(|seed| Keypair::from_seed(SignatureScheme::Ed25519, [seed; 32]))
            .collect();
        let members: Vec<QuorumMember> = v_keys
            .iter()
            .map(|kp| QuorumMember {
                address: kp.address(),
                public_key: kp.public_key(),
                weight: 100,
                wan_rtt_ms: 170,
            })
            .collect();

        let epoch_seed = domain_hash("TEST.SHARD.SEED", &[b"epoch-1"]);
        let committees = assign_validators_to_shards(EpochId(1), &epoch_seed, &members, cfg, 4);

        // Build per-shard signer sets matching assigned sub-committees:
        let mut shard_signers: Vec<Vec<(Address, Keypair)>> = committees
            .iter()
            .map(|comm| {
                comm.members()
                    .iter()
                    .map(|m| {
                        let kp = v_keys
                            .iter()
                            .find(|k| k.address() == m.address)
                            .unwrap()
                            .clone();
                        (m.address, kp)
                    })
                    .collect()
            })
            .collect();

        let mut cluster = ShardedFastPathCluster::new(cfg, committees);

        // Create 12 independent user wallets distributed naturally across the 4 shards:
        let mut txs = Vec::with_capacity(12);
        for i in 0u8..12 {
            let mut sender_kp = Keypair::from_seed(SignatureScheme::PasskeyP256, [0x40 + i; 32]);
            let (_, sender_addr) = cluster.register_pocket(
                sender_kp.public_key(),
                PocketState::new(
                    Amount::from_credits(50).unwrap(),
                    Amount::from_credits(25).unwrap(),
                ),
            );
            let kind = TransactionKind::FastTransfer {
                from: sender_addr,
                to_stealth: Address::from_bytes([0x90 + i; 32]),
                stealth_view_tag: i,
                amount: Amount::from_credits(3).unwrap(),
                fee: Amount::from_bits(500),
                nonce: 0,
                commitment: Hash32::from_bytes([0xaa; 32]),
                innocence_nullifier: None,
            };
            let id = tx_signing_digest(&kind);
            let sig = sender_kp.sign(id.as_bytes()).to_bytes();
            txs.push(Transaction {
                id,
                kind,
                signature_bytes: sig,
            });
        }

        let summary = cluster.execute_parallel_wave(&txs, &mut shard_signers, 1);
        assert_eq!(summary.certificates.len(), 12);
        assert!(summary.certificates.iter().all(|(_, r)| r.is_ok()));

        let total_settled: u32 = summary.shard_roots.iter().map(|r| r.settled_tx_count).sum();
        assert_eq!(total_settled, 12);
        assert_ne!(summary.global_shard_merkle_root, Hash32::ZERO);
    }
}
