//! Rolling Compute-Elected Quorum, **1-RTT Single-Owner Fast Path (~150–250 ms)**,
//! **3-Round Uncertified Pipelined BFT DAG (~450 ms)**, and **Phase-2 Over-Collateralized
//! Reserve Vaults (`GlobalBasketOracle` + Integer `PidRateController`)**.

pub mod governance;
pub mod lifecycle;
pub mod reserve_vault;
pub mod sharding;

pub use governance::{
    DEFAULT_ACTIVATION_GRACE_EPOCHS, DEFAULT_SIGNALING_WINDOW_EPOCHS, ProposalState,
    SUPERMAJORITY_COMPUTE_BPS, UpgradeGovernanceEngine, UpgradeProposal,
};
pub use lifecycle::{
    EpochLifecycleEngine, EpochTransitionReport, GenesisStandbyStatus, MAINNET_GENESIS_ISO8601,
    MAINNET_GENESIS_UNIX, NetworkProfile, VerifiableGenesisBeacon,
};
pub use reserve_vault::{
    BasketObservation, GlobalBasketOracle, LIQUIDATION_THRESHOLD_BPS, MIN_MINT_COLLATERAL_BPS,
    PidRateController, ReserveError, ReserveVault, ReserveVaultEngine,
};
pub use sharding::{
    ShardConfig, ShardSettlementRoot, ShardedFastPathCluster, WaveExecutionSummary,
    assign_validators_to_shards, compute_shard_merkle_root,
};

use std::collections::BTreeMap;

use credit_crypto::{Keypair, PublicKey, Signature, domain_hash};
use credit_ponc::EpochSettlement;
use credit_types::{
    AccountError, Address, Amount, DynamicFeeController, EpochId, FeeSplit, Hash32, PocketState,
    Transaction, TransactionKind,
};

/// Computes the canonical signing digest for a Layer-1 `TransactionKind`.
pub fn tx_signing_digest(kind: &TransactionKind) -> Hash32 {
    match kind {
        TransactionKind::FastTransfer {
            from,
            to_stealth,
            stealth_view_tag,
            amount,
            fee,
            nonce,
            commitment,
            innocence_nullifier,
        } => {
            let null_bytes = innocence_nullifier.unwrap_or(Hash32::ZERO);
            let has_poi = [innocence_nullifier.is_some() as u8];
            domain_hash(
                "XCR.TX.FAST_TRANSFER.V1",
                &[
                    from.as_bytes(),
                    to_stealth.as_bytes(),
                    &[*stealth_view_tag],
                    &amount.bits().to_le_bytes(),
                    &fee.bits().to_le_bytes(),
                    &nonce.to_le_bytes(),
                    commitment.as_bytes(),
                    &has_poi,
                    null_bytes.as_bytes(),
                ],
            )
        }
        TransactionKind::VaultQueueWithdrawal {
            vault_owner,
            destination,
            amount,
            fee,
            nonce,
        } => domain_hash(
            "XCR.TX.VAULT_QUEUE.V1",
            &[
                vault_owner.as_bytes(),
                destination.as_bytes(),
                &amount.bits().to_le_bytes(),
                &fee.bits().to_le_bytes(),
                &nonce.to_le_bytes(),
            ],
        ),
        TransactionKind::VaultEmergencyCancel {
            vault_owner,
            withdrawal_id,
            fee,
            nonce,
        } => domain_hash(
            "XCR.TX.VAULT_CANCEL.V1",
            &[
                vault_owner.as_bytes(),
                &withdrawal_id.to_le_bytes(),
                &fee.bits().to_le_bytes(),
                &nonce.to_le_bytes(),
            ],
        ),
    }
}

/// Active validator elected from the sliding-window Epoch Share-DAG (no staking monopoly).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QuorumMember {
    pub address: Address,
    pub public_key: PublicKey,
    pub weight: u64,
    pub wan_rtt_ms: u16,
}

/// Meritocratic BFT signing committee for a given epoch.
#[derive(Clone, Debug)]
pub struct QuorumCommittee {
    pub epoch: EpochId,
    members: Vec<QuorumMember>,
    total_weight: u64,
}

impl QuorumCommittee {
    pub fn new(epoch: EpochId, mut members: Vec<QuorumMember>) -> Self {
        members.retain(|m| m.weight > 0);
        members.sort_by_key(|a| a.address);
        let total_weight = members.iter().map(|m| m.weight).sum();
        Self {
            epoch,
            members,
            total_weight,
        }
    }

    /// Elects the next epoch's BFT signing committee directly from a finalized PoNC `EpochSettlement`.
    pub fn elect_from_settlement(
        next_epoch: EpochId,
        settlement: &EpochSettlement,
        directory: &[(Address, PublicKey, u16)],
    ) -> Self {
        let mut members = Vec::with_capacity(settlement.payouts.len());
        for (addr, _reward, weight) in &settlement.payouts {
            if let Some((_, pk, rtt_ms)) = directory.iter().find(|(a, _, _)| a == addr) {
                members.push(QuorumMember {
                    address: *addr,
                    public_key: *pk,
                    weight: *weight,
                    wan_rtt_ms: *rtt_ms,
                });
            }
        }
        Self::new(next_epoch, members)
    }

    #[inline]
    pub fn members(&self) -> &[QuorumMember] {
        &self.members
    }

    #[inline]
    pub const fn total_weight(&self) -> u64 {
        self.total_weight
    }

    /// Byzantine fault-tolerant quorum threshold: `floor(2 * W / 3) + 1`.
    #[inline]
    pub const fn quorum_threshold(&self) -> u64 {
        (self.total_weight.saturating_mul(2)) / 3 + 1
    }

    /// Computes the exact 1-RTT WAN latency (in ms) when cumulative vote weight reaches `2f + 1`.
    pub fn fast_path_quorum_latency_ms(&self) -> u16 {
        if self.members.is_empty() {
            return 0;
        }
        let mut by_rtt = self.members.clone();
        by_rtt.sort_by_key(|m| m.wan_rtt_ms);
        let threshold = self.quorum_threshold();
        let mut acc = 0u64;
        for m in by_rtt {
            acc = acc.saturating_add(m.weight);
            if acc >= threshold {
                return m.wan_rtt_ms;
            }
        }
        0
    }
}

/// Individual validator co-signature on a 1-RTT Fast-Path payment.
#[derive(Clone, Debug)]
pub struct ValidatorVote {
    pub validator: Address,
    pub tx_id: Hash32,
    pub signature: Signature,
}

/// Deterministic 1-RTT settlement certificate (irreversible finality, zero mempool MEV).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FinalityCertificate {
    pub tx_id: Hash32,
    pub epoch: EpochId,
    pub signed_weight: u64,
    pub quorum_threshold: u64,
    pub finality_latency_ms: u16,
    pub fee_split: FeeSplit,
}

/// Errors encountered during 1-RTT Fast-Path validation or quorum aggregation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ConsensusError {
    NotFastPathTransaction,
    UnknownAccount(Address),
    InvalidClientSignature,
    EquivocationDetected {
        account: Address,
        nonce: u64,
        locked_tx: Hash32,
        conflicting_tx: Hash32,
    },
    FeeBelowMinimum {
        minimum: Amount,
        offered: Amount,
    },
    AccountFailure(AccountError),
    InsufficientQuorumWeight {
        collected: u64,
        required: u64,
    },
}

/// Single-owner 1-RTT Fast-Path settlement engine.
pub struct FastPathEngine {
    pub committee: QuorumCommittee,
    pub fee_controller: DynamicFeeController,
    accounts: BTreeMap<Address, (PublicKey, PocketState)>,
    non_equivocation_locks: BTreeMap<(Address, u64), Hash32>,
    pub collected_epoch_fees: Amount,
}

impl FastPathEngine {
    pub fn new(committee: QuorumCommittee) -> Self {
        Self {
            committee,
            fee_controller: DynamicFeeController::new_default(),
            accounts: BTreeMap::new(),
            non_equivocation_locks: BTreeMap::new(),
            collected_epoch_fees: Amount::ZERO,
        }
    }

    pub fn register_pocket(&mut self, pubkey: PublicKey, state: PocketState) -> Address {
        let addr = pubkey.to_address();
        self.accounts.insert(addr, (pubkey, state));
        addr
    }

    pub fn pocket_state(&self, addr: &Address) -> Option<&PocketState> {
        self.accounts.get(addr).map(|(_, st)| st)
    }

    /// Validates non-equivocation, client Passkey/account signature, Pocket limits, and collects
    /// 1-RTT quorum votes to produce an immediate `FinalityCertificate`.
    pub fn execute_1rtt_transfer(
        &mut self,
        tx: &Transaction,
        validator_signers: &mut [(Address, Keypair)],
        day_index: u64,
    ) -> Result<FinalityCertificate, ConsensusError> {
        let TransactionKind::FastTransfer {
            from,
            amount,
            fee,
            nonce,
            ..
        } = &tx.kind
        else {
            return Err(ConsensusError::NotFastPathTransaction);
        };

        let min_fee = self.fee_controller.base_fee();
        if *fee < min_fee {
            return Err(ConsensusError::FeeBelowMinimum {
                minimum: min_fee,
                offered: *fee,
            });
        }

        // Non-equivocation lock check BEFORE mutating state: prevents double-spend attempts across forks.
        if let Some(&existing_tx) = self.non_equivocation_locks.get(&(*from, *nonce))
            && existing_tx != tx.id
        {
            return Err(ConsensusError::EquivocationDetected {
                account: *from,
                nonce: *nonce,
                locked_tx: existing_tx,
                conflicting_tx: tx.id,
            });
        }

        let (account_pk, pocket) = self
            .accounts
            .get_mut(from)
            .ok_or(ConsensusError::UnknownAccount(*from))?;

        let sig = Signature::from_bytes(&tx.signature_bytes)
            .ok_or(ConsensusError::InvalidClientSignature)?;
        let digest = tx_signing_digest(&tx.kind);
        if tx.id != digest || !account_pk.verify(digest.as_bytes(), &sig) {
            return Err(ConsensusError::InvalidClientSignature);
        }

        // Lock `(from, nonce)` and collect 1-RTT validator votes.
        self.non_equivocation_locks.insert((*from, *nonce), tx.id);

        let vote_msg = domain_hash(
            "XCR.CONSENSUS.FAST_VOTE.V1",
            &[&self.committee.epoch.0.to_le_bytes(), tx.id.as_bytes()],
        );
        let mut signed_weight = 0u64;
        for (val_addr, val_kp) in validator_signers.iter_mut() {
            if let Some(member) = self
                .committee
                .members()
                .iter()
                .find(|m| m.address == *val_addr)
            {
                let vote_sig = val_kp.sign(vote_msg.as_bytes());
                if member.public_key.verify(vote_msg.as_bytes(), &vote_sig) {
                    signed_weight = signed_weight.saturating_add(member.weight);
                }
            }
        }

        let required = self.committee.quorum_threshold();
        if signed_weight < required {
            return Err(ConsensusError::InsufficientQuorumWeight {
                collected: signed_weight,
                required,
            });
        }

        let total_debit = amount
            .checked_add(*fee)
            .ok_or(ConsensusError::AccountFailure(AccountError::AmountOverflow))?;
        pocket
            .spend_fast(total_debit, *nonce, day_index)
            .map_err(ConsensusError::AccountFailure)?;

        self.collected_epoch_fees = self.collected_epoch_fees.saturating_add(*fee);
        let fee_split = FeeSplit::compute(*fee);

        Ok(FinalityCertificate {
            tx_id: tx.id,
            epoch: self.committee.epoch,
            signed_weight,
            quorum_threshold: required,
            finality_latency_ms: self.committee.fast_path_quorum_latency_ms(),
            fee_split,
        })
    }
}

/// Uncertified BFT DAG vertex for multi-party `Vault` & Phase-2 Reserve state (~450 ms, 3 rounds).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DagVertex {
    pub id: Hash32,
    pub round: u64,
    pub author: Address,
    pub parents: Vec<Hash32>,
    pub shared_tx_ids: Vec<Hash32>,
}

impl DagVertex {
    pub fn new(
        round: u64,
        author: Address,
        parents: Vec<Hash32>,
        shared_tx_ids: Vec<Hash32>,
    ) -> Self {
        let mut buf = Vec::with_capacity((parents.len() + shared_tx_ids.len()) * 32);
        for p in &parents {
            buf.extend_from_slice(p.as_bytes());
        }
        for t in &shared_tx_ids {
            buf.extend_from_slice(t.as_bytes());
        }
        let id = domain_hash(
            "XCR.BFTDAG.VERTEX.V1",
            &[&round.to_le_bytes(), author.as_bytes(), &buf],
        );
        Self {
            id,
            round,
            author,
            parents,
            shared_tx_ids,
        }
    }
}

/// 3-Round Mysticeti-style uncertified pipelined BFT DAG ordering shared Vault transactions.
pub struct BftDagEngine {
    committee: QuorumCommittee,
    vertices: BTreeMap<Hash32, DagVertex>,
}

impl BftDagEngine {
    pub fn new(committee: QuorumCommittee) -> Self {
        Self {
            committee,
            vertices: BTreeMap::new(),
        }
    }

    pub fn insert_vertex(&mut self, vertex: DagVertex) -> bool {
        if vertex.round > 0 {
            for p in &vertex.parents {
                if !self.vertices.contains_key(p) {
                    return false;
                }
            }
        }
        self.vertices.insert(vertex.id, vertex);
        true
    }

    /// Checks whether `anchor_id` at round `r` has achieved 3-round BFT commit finality
    /// (`round r` proposal -> `round r+1` quorum references -> `round r+2` quorum certificates).
    pub fn is_committed_3round(&self, anchor_id: &Hash32) -> bool {
        let Some(anchor) = self.vertices.get(anchor_id) else {
            return false;
        };
        let threshold = self.committee.quorum_threshold();

        // Round r+1 vertices directly referencing `anchor_id`.
        let r1_supporters: Vec<&DagVertex> = self
            .vertices
            .values()
            .filter(|v| v.round == anchor.round + 1 && v.parents.contains(anchor_id))
            .collect();
        let r1_weight: u64 = r1_supporters
            .iter()
            .filter_map(|v| self.member_weight(&v.author))
            .sum();
        if r1_weight < threshold {
            return false;
        }

        // Round r+2 vertices referencing at least one round r+1 supporter.
        let r2_weight: u64 = self
            .vertices
            .values()
            .filter(|v| {
                v.round == anchor.round + 2
                    && v.parents
                        .iter()
                        .any(|p| r1_supporters.iter().any(|s| &s.id == p))
            })
            .filter_map(|v| self.member_weight(&v.author))
            .sum();

        r2_weight >= threshold
    }

    fn member_weight(&self, author: &Address) -> Option<u64> {
        self.committee
            .members()
            .iter()
            .find(|m| &m.address == author)
            .map(|m| m.weight)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use credit_crypto::SignatureScheme;

    #[test]
    fn fast_path_1rtt_settles_and_blocks_double_spend_equivocation() {
        // 4-validator BFT committee (3f + 1 = 4, f = 1): quorum threshold is 267/400,
        // so the fastest 3 validators (135ms, 160ms, 185ms) finalize without waiting on 260ms!
        let v1 = Keypair::from_seed(SignatureScheme::Ed25519, [1u8; 32]);
        let v2 = Keypair::from_seed(SignatureScheme::Ed25519, [2u8; 32]);
        let v3 = Keypair::from_seed(SignatureScheme::Ed25519, [3u8; 32]);
        let v4 = Keypair::from_seed(SignatureScheme::Ed25519, [4u8; 32]);

        let committee = QuorumCommittee::new(
            EpochId(1),
            vec![
                QuorumMember {
                    address: v1.address(),
                    public_key: v1.public_key(),
                    weight: 100,
                    wan_rtt_ms: 135,
                },
                QuorumMember {
                    address: v2.address(),
                    public_key: v2.public_key(),
                    weight: 100,
                    wan_rtt_ms: 160,
                },
                QuorumMember {
                    address: v3.address(),
                    public_key: v3.public_key(),
                    weight: 100,
                    wan_rtt_ms: 185,
                },
                QuorumMember {
                    address: v4.address(),
                    public_key: v4.public_key(),
                    weight: 100,
                    wan_rtt_ms: 260,
                },
            ],
        );

        let mut engine = FastPathEngine::new(committee);
        let mut alice_kp = Keypair::from_seed(SignatureScheme::PasskeyP256, [0x44; 32]);
        let alice_addr = engine.register_pocket(
            alice_kp.public_key(),
            PocketState::new(
                Amount::from_credits(100).unwrap(),
                Amount::from_credits(50).unwrap(),
            ),
        );

        let kind_legit = TransactionKind::FastTransfer {
            from: alice_addr,
            to_stealth: Address::from_bytes([0x88; 32]),
            stealth_view_tag: 0x1a,
            amount: Amount::from_credits(10).unwrap(),
            fee: Amount::from_bits(1_000),
            nonce: 0,
            commitment: Hash32::from_bytes([0x55; 32]),
            innocence_nullifier: None,
        };
        let id_legit = tx_signing_digest(&kind_legit);
        let sig_legit = alice_kp.sign(id_legit.as_bytes()).to_bytes();
        let tx_legit = Transaction {
            id: id_legit,
            kind: kind_legit,
            signature_bytes: sig_legit,
        };

        let mut signers = vec![(v1.address(), v1), (v2.address(), v2), (v3.address(), v3)];
        let cert = engine
            .execute_1rtt_transfer(&tx_legit, &mut signers, 1)
            .unwrap();
        assert_eq!(cert.finality_latency_ms, 185);
        assert_eq!(cert.fee_split.worker_reward.bits(), 700);
        assert_eq!(cert.fee_split.endurance_deposit.bits(), 150);
        assert_eq!(cert.fee_split.burned.bits(), 150);

        // Attempt equivocating double-spend at nonce 0 to a different recipient:
        let kind_double = TransactionKind::FastTransfer {
            from: alice_addr,
            to_stealth: Address::from_bytes([0x99; 32]),
            stealth_view_tag: 0x2b,
            amount: Amount::from_credits(10).unwrap(),
            fee: Amount::from_bits(1_000),
            nonce: 0,
            commitment: Hash32::from_bytes([0x66; 32]),
            innocence_nullifier: None,
        };
        let id_double = tx_signing_digest(&kind_double);
        let sig_double = alice_kp.sign(id_double.as_bytes()).to_bytes();
        let tx_double = Transaction {
            id: id_double,
            kind: kind_double,
            signature_bytes: sig_double,
        };
        assert!(matches!(
            engine.execute_1rtt_transfer(&tx_double, &mut signers, 1),
            Err(ConsensusError::EquivocationDetected { .. })
        ));
    }
}
