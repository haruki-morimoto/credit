//! **Zero-Foundation Supermajority Compute Ratification (`UpgradeGovernanceEngine`)**.
//!
//! Enables Credits (`XCR`) to evolve over decades (e.g., adding next-generation post-quantum
//! signature schemes or tuning protocol bounds) with **zero admin keys, zero foundation multisig,
//! and zero coin-whale plutocracy**:
//! - Proposals require **sustained `>= 85.00%` (`8,500 bps`)** of verified PoNC Share-DAG compute
//!   weight over a full `voting_window_epochs` (default `43,200` epochs = 30 days).
//! - Once locked in, a mandatory **`grace_delay_epochs` (default `43,200` epochs = 30 days)**
//!   elapses before activation so every node operator and user has ample time to audit or upgrade.

use std::collections::BTreeMap;

use credit_types::{EpochId, Hash32};

/// Supermajority PoNC Share-DAG compute threshold required for lock-in (`85.00% = 8,500 bps`).
pub const SUPERMAJORITY_COMPUTE_BPS: u64 = 8_500;

/// Default 30-day signaling window (`43,200` 1-minute epochs).
pub const DEFAULT_SIGNALING_WINDOW_EPOCHS: u64 = 43_200;

/// Default 30-day post-lock-in user review & node upgrade grace period (`43,200` epochs).
pub const DEFAULT_ACTIVATION_GRACE_EPOCHS: u64 = 43_200;

/// Lifecycle state of a protocol upgrade proposal.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProposalState {
    Signaling {
        start_epoch: EpochId,
        end_epoch: EpochId,
    },
    LockedIn {
        activates_at_epoch: EpochId,
    },
    Activated {
        activated_at_epoch: EpochId,
    },
    Rejected {
        achieved_bps: u64,
    },
}

/// On-chain forkless upgrade proposal tracked by `UpgradeGovernanceEngine`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UpgradeProposal {
    pub id: Hash32,
    pub title: String,
    pub specification_hash: Hash32,
    pub grace_delay_epochs: u64,
    pub yes_compute_weight: u128,
    pub total_compute_weight: u128,
    pub state: ProposalState,
}

impl UpgradeProposal {
    /// Returns the cumulative PoNC Share-DAG approval ratio in basis points (`0..=10_000`).
    pub fn approval_bps(&self) -> u64 {
        if self.total_compute_weight == 0 {
            return 0;
        }
        ((self.yes_compute_weight * 10_000) / self.total_compute_weight) as u64
    }
}

/// Zero-foundation compute-signaling ratification tracker.
#[derive(Clone, Debug, Default)]
pub struct UpgradeGovernanceEngine {
    proposals: BTreeMap<Hash32, UpgradeProposal>,
}

impl UpgradeGovernanceEngine {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn register_proposal(
        &mut self,
        id: Hash32,
        title: String,
        specification_hash: Hash32,
        start_epoch: EpochId,
        signaling_window_epochs: u64,
        grace_delay_epochs: u64,
    ) -> bool {
        if self.proposals.contains_key(&id) || signaling_window_epochs == 0 {
            return false;
        }
        let end_epoch = EpochId(start_epoch.0.saturating_add(signaling_window_epochs));
        self.proposals.insert(
            id,
            UpgradeProposal {
                id,
                title,
                specification_hash,
                grace_delay_epochs,
                yes_compute_weight: 0,
                total_compute_weight: 0,
                state: ProposalState::Signaling {
                    start_epoch,
                    end_epoch,
                },
            },
        );
        true
    }

    /// Records verified PoNC Share-DAG signaling weights for `epoch` and transitions proposals
    /// deterministically across `Signaling -> LockedIn -> Activated` (or `Rejected`).
    pub fn on_epoch_finalized(
        &mut self,
        epoch: EpochId,
        total_epoch_weight: u64,
        signaling_yes_weights: &[(Hash32, u64)],
    ) {
        for prop in self.proposals.values_mut() {
            match prop.state {
                ProposalState::Signaling {
                    start_epoch,
                    end_epoch,
                } => {
                    if epoch >= start_epoch && epoch < end_epoch {
                        let yes = signaling_yes_weights
                            .iter()
                            .find(|(id, _)| *id == prop.id)
                            .map(|(_, w)| (*w).min(total_epoch_weight))
                            .unwrap_or(0);
                        prop.yes_compute_weight += yes as u128;
                        prop.total_compute_weight += total_epoch_weight as u128;
                    }
                    if epoch.0 + 1 >= end_epoch.0 && epoch >= start_epoch {
                        let bps = prop.approval_bps();
                        if prop.total_compute_weight > 0 && bps >= SUPERMAJORITY_COMPUTE_BPS {
                            prop.state = ProposalState::LockedIn {
                                activates_at_epoch: EpochId(
                                    end_epoch.0.saturating_add(prop.grace_delay_epochs),
                                ),
                            };
                        } else {
                            prop.state = ProposalState::Rejected { achieved_bps: bps };
                        }
                    }
                }
                ProposalState::LockedIn { activates_at_epoch } => {
                    if epoch >= activates_at_epoch {
                        prop.state = ProposalState::Activated {
                            activated_at_epoch: activates_at_epoch,
                        };
                    }
                }
                ProposalState::Activated { .. } | ProposalState::Rejected { .. } => {}
            }
        }
    }

    pub fn proposal(&self, id: &Hash32) -> Option<&UpgradeProposal> {
        self.proposals.get(id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn supermajority_85_percent_ratifies_after_grace_delay_and_rejects_70_percent() {
        let mut gov = UpgradeGovernanceEngine::new();
        let pq_upgrade = Hash32::from_bytes([0x01; 32]);
        let contentious = Hash32::from_bytes([0x02; 32]);

        assert!(gov.register_proposal(
            pq_upgrade,
            "XIP-01: Add Falcon-1024 Guardian Scheme".to_owned(),
            Hash32::from_bytes([0xaa; 32]),
            EpochId(10),
            4,
            5,
        ));
        assert!(gov.register_proposal(
            contentious,
            "XIP-02: Contentious Fee Change".to_owned(),
            Hash32::from_bytes([0xbb; 32]),
            EpochId(10),
            4,
            5,
        ));

        // Across epochs 10..14 (`4` epochs): XIP-01 gets 90% compute support; XIP-02 gets 70% (<85%):
        for ep in 10..=14 {
            gov.on_epoch_finalized(EpochId(ep), 1_000, &[(pq_upgrade, 900), (contentious, 700)]);
        }

        assert_eq!(
            gov.proposal(&pq_upgrade).unwrap().state,
            ProposalState::LockedIn {
                activates_at_epoch: EpochId(19)
            }
        );
        assert_eq!(
            gov.proposal(&contentious).unwrap().state,
            ProposalState::Rejected {
                achieved_bps: 7_000
            }
        );

        // Still in mandatory user review grace period at Epoch 18:
        gov.on_epoch_finalized(EpochId(18), 1_000, &[]);
        assert!(matches!(
            gov.proposal(&pq_upgrade).unwrap().state,
            ProposalState::LockedIn { .. }
        ));

        // Activates cleanly at Epoch 19!
        gov.on_epoch_finalized(EpochId(19), 1_000, &[]);
        assert_eq!(
            gov.proposal(&pq_upgrade).unwrap().state,
            ProposalState::Activated {
                activated_at_epoch: EpochId(19)
            }
        );
    }
}
