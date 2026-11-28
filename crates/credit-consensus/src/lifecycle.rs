//! Stage-5 **Verifiable Fair-Launch Genesis Ceremony (`VerifiableGenesisBeacon`)** and
//! **Autonomous Multi-Epoch Lifecycle Coordinator (`EpochLifecycleEngine`)**.
//!
//! Drives the continuous progression of Credits (`XCR`) from `Block 0` (`Supply == 0.000000 XCR`)
//! across PoNC Share-DAG epochs, dynamic micro-fee updates, closed-loop `70/15/15`
//! `SecurityEndurancePool` + `15%` fee-burn accounting, `>= 85%` compute governance, and the
//! deterministic **Option C `Phase 1 -> Phase 2` Global Cost-of-Living Basket crossover**.

use credit_crypto::{PublicKey, domain_hash};
use credit_ponc::{EpochSettlement, EpochShareDag};
use credit_types::{
    Address, Amount, DynamicFeeController, EpochId, Hash32, MaturityMetrics, MonetaryPhase,
    SecurityEndurancePool,
};

use crate::{
    BasketObservation, MIN_MINT_COLLATERAL_BPS, QuorumCommittee, ReserveVaultEngine,
    UpgradeGovernanceEngine,
};

/// Canonical Mainnet `Epoch 0` Fair-Launch unlock timestamp:
/// **Friday, 1 January 2027 at `00:00:00 UTC` (`1,798,761,600` Unix seconds)** — New Year's Day 2027 (`∀` — "For All").
pub const MAINNET_GENESIS_UNIX: u64 = 1_798_761_600;

/// Human-readable ISO-8601 UTC target for the 1 January 2027 Mainnet Genesis window.
pub const MAINNET_GENESIS_ISO8601: &str = "2027-01-01T00:00:00Z";

/// Domain-separated network profiles isolating Testnet/Devnet test coins from Mainnet `XCR`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NetworkProfile {
    Mainnet,
    TestnetBeta,
    LocalDevnet,
}

impl NetworkProfile {
    pub const fn chain_id(self) -> &'static str {
        match self {
            Self::Mainnet => "xcr-mainnet-2027",
            Self::TestnetBeta => "xcr-testnet-beta-2027",
            Self::LocalDevnet => "xcr-devnet-local",
        }
    }
}

/// Pre-launch standby gate ensuring distributed Mainnet binaries cannot mine `Epoch 0` early.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum GenesisStandbyStatus {
    StandbyCountdown {
        target_unix: u64,
        seconds_remaining: u64,
    },
    AwaitingPublicBeacon {
        target_unix: u64,
    },
    ReadyToLaunch(VerifiableGenesisBeacon),
}

/// Publicly auditable Genesis ceremony anchor proving nobody could pre-mine Epoch 0 in secret.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiableGenesisBeacon {
    /// Publicly verifiable external randomness anchor (first Bitcoin block mined >= 2027-01-01T00:00:00Z).
    pub external_randomness_hex: String,
    /// Contemporaneous public timestamp headline proving non-retroactive seed generation.
    pub public_headline: String,
    /// UTC launch timestamp (`RFC 3339` or Unix seconds).
    pub launch_timestamp_unix: u64,
}

impl VerifiableGenesisBeacon {
    /// Evaluates whether the **1 January 2027 (`1,798,761,600` UTC)** launch window has arrived
    /// and whether the public external randomness beacon has been observed.
    pub fn evaluate_genesis_standby(
        current_unix_secs: u64,
        external_randomness_hex: Option<&str>,
        public_headline: Option<&str>,
    ) -> GenesisStandbyStatus {
        if current_unix_secs < MAINNET_GENESIS_UNIX {
            return GenesisStandbyStatus::StandbyCountdown {
                target_unix: MAINNET_GENESIS_UNIX,
                seconds_remaining: MAINNET_GENESIS_UNIX - current_unix_secs,
            };
        }
        match (
            external_randomness_hex
                .map(str::trim)
                .filter(|s| !s.is_empty()),
            public_headline.map(str::trim).filter(|s| !s.is_empty()),
        ) {
            (Some(rand_hex), Some(headline)) => {
                GenesisStandbyStatus::ReadyToLaunch(VerifiableGenesisBeacon {
                    external_randomness_hex: rand_hex.to_owned(),
                    public_headline: headline.to_owned(),
                    launch_timestamp_unix: MAINNET_GENESIS_UNIX,
                })
            }
            _ => GenesisStandbyStatus::AwaitingPublicBeacon {
                target_unix: MAINNET_GENESIS_UNIX,
            },
        }
    }
    /// Deterministically derives the unpredictable `Epoch 0` PoNC VM seed from public commitments.
    pub fn derive_epoch0_seed(&self) -> Hash32 {
        domain_hash(
            "XCR.GENESIS.FAIR_LAUNCH_BEACON.V1",
            &[
                self.external_randomness_hex.as_bytes(),
                self.public_headline.as_bytes(),
                &self.launch_timestamp_unix.to_le_bytes(),
            ],
        )
    }

    /// Audits that a network state satisfies the Constitutional Zero-Premine Fair Launch invariant.
    pub fn verify_zero_premine(&self, phase: &MonetaryPhase) -> bool {
        if self.external_randomness_hex.trim().is_empty() || self.public_headline.trim().is_empty()
        {
            return false;
        }
        matches!(
            phase,
            MonetaryPhase::Phase1Bootstrap {
                epoch: EpochId(0),
                circulating_supply,
                total_burned,
            } if circulating_supply.is_zero() && total_burned.is_zero()
        )
    }
}

/// Summary emitted when `EpochLifecycleEngine` closes epoch `E_k` and transitions to `E_{k+1}`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EpochTransitionReport {
    pub closed_epoch: EpochId,
    pub next_epoch: EpochId,
    pub next_epoch_seed: Hash32,
    pub settlement: EpochSettlement,
    pub circulating_supply: Amount,
    pub total_burned: Amount,
    pub next_base_fee: Amount,
    pub phase2_just_unlocked: bool,
    pub active_phase: MonetaryPhase,
}

/// Autonomous multi-epoch protocol state coordinator managing Phase 1 -> Phase 2 evolution.
pub struct EpochLifecycleEngine {
    pub beacon: VerifiableGenesisBeacon,
    pub current_epoch: EpochId,
    pub current_epoch_seed: Hash32,
    pub circulating_supply: Amount,
    pub total_burned: Amount,
    pub endurance_pool: SecurityEndurancePool,
    pub governance: UpgradeGovernanceEngine,
    pub phase: MonetaryPhase,
    pub fee_controller: DynamicFeeController,
    pub reserve_engine: ReserveVaultEngine,
    pub active_committee: Option<QuorumCommittee>,
}

impl EpochLifecycleEngine {
    /// Initializes a brand-new network at `Epoch 0` with `0.000000 XCR` circulating supply.
    pub fn from_fair_genesis(beacon: VerifiableGenesisBeacon, initial_basket_micros: u64) -> Self {
        let current_epoch_seed = beacon.derive_epoch0_seed();
        let phase = MonetaryPhase::Phase1Bootstrap {
            epoch: EpochId(0),
            circulating_supply: Amount::ZERO,
            total_burned: Amount::ZERO,
        };
        assert!(
            beacon.verify_zero_premine(&phase),
            "Genesis beacon must contain non-empty public randomness and zero premine"
        );
        Self {
            beacon,
            current_epoch: EpochId(0),
            current_epoch_seed,
            circulating_supply: Amount::ZERO,
            total_burned: Amount::ZERO,
            endurance_pool: SecurityEndurancePool::new(),
            governance: UpgradeGovernanceEngine::new(),
            phase,
            fee_controller: DynamicFeeController::new_default(),
            reserve_engine: ReserveVaultEngine::new(initial_basket_micros),
            active_committee: None,
        }
    }

    /// Finalizes `share_dag` for `current_epoch`, distributes pool-free PoNC + `70%` fee +
    /// `SecurityEndurancePool` drip rewards, deposits `15%` into `endurance_pool`, burns `15%` of
    /// fees, updates dynamic base fees, elects the `E_{k+1}` committee, and triggers the
    /// irreversible **Phase 1 -> Phase 2 Global Basket crossover** once `metrics` mature.
    #[allow(clippy::too_many_arguments)]
    pub fn advance_epoch(
        &mut self,
        share_dag: &EpochShareDag,
        collected_epoch_fees: Amount,
        utilization_bps: u32,
        validator_directory: &[(Address, PublicKey, u16)],
        metrics: &MaturityMetrics,
        phase2_basket_obs: &[BasketObservation],
        phase2_market_price_micros: Option<u64>,
    ) -> EpochTransitionReport {
        assert_eq!(share_dag.epoch, self.current_epoch);

        let endurance_drip = self.endurance_pool.drip_for_epoch();
        let settlement =
            share_dag.settle_epoch_with_endurance(collected_epoch_fees, endurance_drip);
        self.endurance_pool.deposit(settlement.endurance_deposited);

        let total_share_weight: u64 = settlement.payouts.iter().map(|(_, _, w)| *w).sum();
        self.governance
            .on_epoch_finalized(self.current_epoch, total_share_weight, &[]);

        // Net supply change = `minted_emission - burned_fees` (since `70%` worker fees are recycled
        // from senders to workers, while `30%` is permanently destroyed!).
        self.circulating_supply = self
            .circulating_supply
            .saturating_add(settlement.minted_emission)
            .checked_sub(settlement.burned_fees)
            .unwrap_or(Amount::ZERO);
        self.total_burned = self.total_burned.saturating_add(settlement.burned_fees);

        self.fee_controller.on_window_utilization(utilization_bps);

        let closed_epoch = self.current_epoch;
        let next_epoch = EpochId(closed_epoch.0 + 1);
        let tips = share_dag.tip_ids(4);
        let mut tip_bytes = Vec::with_capacity(tips.len() * 32);
        for t in tips {
            tip_bytes.extend_from_slice(t.as_bytes());
        }
        let next_epoch_seed = domain_hash(
            "XCR.LIFECYCLE.NEXT_SEED.V1",
            &[
                self.current_epoch_seed.as_bytes(),
                &next_epoch.0.to_le_bytes(),
                &tip_bytes,
            ],
        );

        let committee =
            QuorumCommittee::elect_from_settlement(next_epoch, &settlement, validator_directory);
        let quorum_threshold = committee.quorum_threshold();
        self.active_committee = Some(committee);
        self.current_epoch = next_epoch;
        self.current_epoch_seed = next_epoch_seed;

        let was_unlocked = self.reserve_engine.phase2_unlocked;
        let now_unlocked = self.reserve_engine.try_unlock_phase2(metrics);
        let phase2_just_unlocked = !was_unlocked && now_unlocked;

        if now_unlocked {
            if !phase2_basket_obs.is_empty() {
                let _ = self.reserve_engine.oracle.update_from_quorum(
                    next_epoch,
                    phase2_basket_obs,
                    quorum_threshold,
                );
            }
            if let Some(mkt) = phase2_market_price_micros {
                let _ = self
                    .reserve_engine
                    .pid
                    .step(self.reserve_engine.oracle.basket_target_micros, mkt);
            }
            self.phase = MonetaryPhase::Phase2GlobalBasket {
                epoch: next_epoch,
                basket_index_micros: self.reserve_engine.oracle.basket_target_micros,
                min_collateral_ratio_bps: MIN_MINT_COLLATERAL_BPS,
            };
        } else {
            self.phase = MonetaryPhase::Phase1Bootstrap {
                epoch: next_epoch,
                circulating_supply: self.circulating_supply,
                total_burned: self.total_burned,
            };
        }

        EpochTransitionReport {
            closed_epoch,
            next_epoch,
            next_epoch_seed,
            settlement,
            circulating_supply: self.circulating_supply,
            total_burned: self.total_burned,
            next_base_fee: self.fee_controller.base_fee(),
            phase2_just_unlocked,
            active_phase: self.phase,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use credit_crypto::{Keypair, SignatureScheme};
    use credit_ponc::{ComputeShare, PoncVmConfig};

    #[test]
    fn genesis_ceremony_multi_epoch_burn_and_automatic_phase2_crossover() {
        // Pre-Genesis timestamps are strictly locked in standby countdown (zero early pre-mine!):
        assert_eq!(
            VerifiableGenesisBeacon::evaluate_genesis_standby(
                MAINNET_GENESIS_UNIX - 3_600,
                Some("00000000000000000002a7c4"),
                Some("Early attempt"),
            ),
            GenesisStandbyStatus::StandbyCountdown {
                target_unix: MAINNET_GENESIS_UNIX,
                seconds_remaining: 3_600,
            }
        );
        assert_eq!(NetworkProfile::Mainnet.chain_id(), "xcr-mainnet-2027");

        let GenesisStandbyStatus::ReadyToLaunch(beacon) =
            VerifiableGenesisBeacon::evaluate_genesis_standby(
                MAINNET_GENESIS_UNIX,
                Some("00000000000000000002a7c4c1e48d76c5a37902165a270156b7a8d72728a054"),
                Some("2027-01-01 00:00 UTC — Global Open Monetary Genesis"),
            )
        else {
            panic!("Genesis timestamp with valid public beacon must unlock Epoch 0");
        };
        let mut lifecycle = EpochLifecycleEngine::from_fair_genesis(beacon, 1_000_000);
        assert_eq!(lifecycle.circulating_supply, Amount::ZERO);

        let v1 = Keypair::from_seed(SignatureScheme::Ed25519, [1; 32]);
        let v2 = Keypair::from_seed(SignatureScheme::Ed25519, [2; 32]);
        let v3 = Keypair::from_seed(SignatureScheme::Ed25519, [3; 32]);
        let dir = vec![
            (v1.address(), v1.public_key(), 150u16),
            (v2.address(), v2.public_key(), 165u16),
            (v3.address(), v3.public_key(), 180u16),
        ];

        // Epoch 0: Early Phase-1 bootstrap (`50` nodes < `10,000` threshold)
        let vm_cfg = PoncVmConfig::devnet_profile();
        let mut dag0 = EpochShareDag::new(EpochId(0), lifecycle.current_epoch_seed, 3, vm_cfg);
        for (i, addr) in [v1.address(), v2.address(), v3.address()]
            .into_iter()
            .enumerate()
        {
            let sh = ComputeShare::mine_cpu_share(
                EpochId(0),
                &lifecycle.current_epoch_seed,
                addr,
                dag0.tip_ids(2),
                (i as u64) * 50,
                3,
                &vm_cfg,
            );
            dag0.submit_share(sh).unwrap();
        }
        let early_metrics = MaturityMetrics {
            active_compute_nodes: 50,
            distinct_autonomous_systems: 12,
            consecutive_deep_epochs: 1,
        };
        let r0 = lifecycle.advance_epoch(
            &dag0,
            Amount::from_bits(10_000), // 3,000 bits burned!
            5_000,
            &dir,
            &early_metrics,
            &[],
            None,
        );
        assert!(!r0.phase2_just_unlocked);
        assert_eq!(r0.total_burned, Amount::from_bits(1_500));
        assert_eq!(lifecycle.endurance_pool.balance, Amount::from_bits(1_500));
        assert_eq!(
            r0.circulating_supply,
            Amount::from_bits(100_000_000 - 1_500)
        );
        assert!(matches!(
            r0.active_phase,
            MonetaryPhase::Phase1Bootstrap { .. }
        ));

        // Epoch 1: Network crosses global decentralization maturity -> Phase 2 unlocks automatically!
        let mut dag1 = EpochShareDag::new(EpochId(1), lifecycle.current_epoch_seed, 3, vm_cfg);
        for (i, addr) in [v1.address(), v2.address(), v3.address()]
            .into_iter()
            .enumerate()
        {
            let sh = ComputeShare::mine_cpu_share(
                EpochId(1),
                &lifecycle.current_epoch_seed,
                addr,
                dag1.tip_ids(2),
                (i as u64) * 50,
                3,
                &vm_cfg,
            );
            dag1.submit_share(sh).unwrap();
        }
        let mature_metrics = MaturityMetrics {
            active_compute_nodes: 12_500,
            distinct_autonomous_systems: 640,
            consecutive_deep_epochs: 45_000,
        };
        let obs = vec![
            BasketObservation {
                validator: v1.address(),
                weight: 800,
                shelter_materials_micros: 1_001_000,
                food_staples_micros: 1_001_000,
                energy_kwh_micros: 1_001_000,
                healthcare_micros: 1_001_000,
                education_micros: 1_001_000,
                compute_bandwidth_micros: 1_001_000,
                scientific_research_micros: 1_001_000,
                emergency_resilience_micros: 1_001_000,
                entertainment_micros: 1_001_000,
            },
            BasketObservation {
                validator: v2.address(),
                weight: 800,
                shelter_materials_micros: 1_001_000,
                food_staples_micros: 1_001_000,
                energy_kwh_micros: 1_001_000,
                healthcare_micros: 1_001_000,
                education_micros: 1_001_000,
                compute_bandwidth_micros: 1_001_000,
                scientific_research_micros: 1_001_000,
                emergency_resilience_micros: 1_001_000,
                entertainment_micros: 1_001_000,
            },
            BasketObservation {
                validator: v3.address(),
                weight: 800,
                shelter_materials_micros: 1_001_000,
                food_staples_micros: 1_001_000,
                energy_kwh_micros: 1_001_000,
                healthcare_micros: 1_001_000,
                education_micros: 1_001_000,
                compute_bandwidth_micros: 1_001_000,
                scientific_research_micros: 1_001_000,
                emergency_resilience_micros: 1_001_000,
                entertainment_micros: 1_001_000,
            },
        ];
        let r1 = lifecycle.advance_epoch(
            &dag1,
            Amount::from_bits(20_000),
            6_200, // Slightly elevated utilization -> dynamic base fee nudges gently
            &dir,
            &mature_metrics,
            &obs,
            Some(995_000),
        );
        assert!(r1.phase2_just_unlocked);
        assert!(matches!(
            r1.active_phase,
            MonetaryPhase::Phase2GlobalBasket {
                basket_index_micros: 1_001_000,
                min_collateral_ratio_bps: 20_000,
                ..
            }
        ));
    }
}
