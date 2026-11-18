//! Core deterministic types, fixed-point `XCR` arithmetic, `Pocket & Vault` state
//! machines, 4-dot `CredchipStatus`, and phased monetary primitives for Credits (`XCR`).
//!
//! Layer 1 deliberately omits any `freeze` or `blacklist` fields on accounts so bearer
//! sovereignty is enforced structurally at the type level.

use core::fmt;

/// Official supranational-style ticker for Credits (`ISO 4217` `X`-prefix convention).
pub const TICKER: &str = "XCR";

/// Plain-text Unicode symbol fallback (`∀` — "For All", matching the Double-Bar V geometry).
pub const SYMBOL_FALLBACK: char = '∀';

/// Base integer precision: `1 Credit (XCR) = 1,000,000 bits` (6 decimal places).
pub const BITS_PER_CREDIT: u64 = 1_000_000;

/// Everyday sub-unit: `1 Chip (Centicredit) = 0.01 XCR = 10,000 bits`.
pub const BITS_PER_CHIP: u64 = 10_000;

/// Minimum protocol transfer fee (`10 bits = 0.000010 XCR`).
pub const MIN_BASE_FEE_BITS: u64 = 10;

/// Worker share of transaction fees (`70%` paid immediately to active epoch workers).
pub const FEE_WORKER_SHARE_BPS: u64 = 7_000;

/// Closed-loop Security Endurance Pool share (`15%` recycled smoothly over a 1-year half-life).
pub const FEE_ENDURANCE_SHARE_BPS: u64 = 1_500;

/// Exponential per-epoch drip divisor for `SecurityEndurancePool` (`525,600` 1-min epochs = 1 year).
pub const ENDURANCE_EPOCH_DRIP_DIVISOR: u64 = 525_600;

/// Fixed-point non-negative amount denominated in base `bits` (`10^-6 XCR`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Amount(u64);

impl Amount {
    pub const ZERO: Self = Self(0);

    #[inline]
    pub const fn from_bits(bits: u64) -> Self {
        Self(bits)
    }

    #[inline]
    pub const fn from_chips(chips: u64) -> Option<Self> {
        match chips.checked_mul(BITS_PER_CHIP) {
            Some(bits) => Some(Self(bits)),
            None => None,
        }
    }

    #[inline]
    pub const fn from_credits(credits: u64) -> Option<Self> {
        match credits.checked_mul(BITS_PER_CREDIT) {
            Some(bits) => Some(Self(bits)),
            None => None,
        }
    }

    #[inline]
    pub const fn bits(self) -> u64 {
        self.0
    }

    #[inline]
    pub const fn is_zero(self) -> bool {
        self.0 == 0
    }

    #[inline]
    pub const fn checked_add(self, rhs: Self) -> Option<Self> {
        match self.0.checked_add(rhs.0) {
            Some(v) => Some(Self(v)),
            None => None,
        }
    }

    #[inline]
    pub const fn checked_sub(self, rhs: Self) -> Option<Self> {
        match self.0.checked_sub(rhs.0) {
            Some(v) => Some(Self(v)),
            None => None,
        }
    }

    #[inline]
    pub const fn saturating_add(self, rhs: Self) -> Self {
        Self(self.0.saturating_add(rhs.0))
    }

    /// Formats with the plain-text Double-Bar V fallback symbol (`∀ 12.340000 XCR`).
    pub fn format_symbolic(self) -> String {
        let whole = self.0 / BITS_PER_CREDIT;
        let frac = self.0 % BITS_PER_CREDIT;
        format!("{SYMBOL_FALLBACK} {whole}.{frac:06} {TICKER}")
    }
}

impl fmt::Display for Amount {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let whole = self.0 / BITS_PER_CREDIT;
        let frac = self.0 % BITS_PER_CREDIT;
        write!(f, "{whole}.{frac:06} {TICKER}")
    }
}

/// 256-bit cryptographic digest used across commitments, DAG vertices, and Merkle roots.
#[derive(Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Hash32(pub [u8; 32]);

impl Hash32 {
    pub const ZERO: Self = Self([0u8; 32]);

    #[inline]
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    #[inline]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Counts leading zero bits in big-endian byte order for PoNC share difficulty checks.
    pub fn leading_zeros(&self) -> u32 {
        let mut count = 0u32;
        for &byte in &self.0 {
            if byte == 0 {
                count += 8;
            } else {
                count += byte.leading_zeros();
                break;
            }
        }
        count
    }

    pub fn to_hex(&self) -> String {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut out = String::with_capacity(64);
        for &b in &self.0 {
            out.push(HEX[(b >> 4) as usize] as char);
            out.push(HEX[(b & 0x0f) as usize] as char);
        }
        out
    }
}

impl fmt::Debug for Hash32 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Hash32({})", &self.to_hex()[..16])
    }
}

impl fmt::Display for Hash32 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_hex())
    }
}

/// Unfreezable 256-bit Layer-1 account or one-time stealth destination address.
#[derive(Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Address(pub [u8; 32]);

impl Address {
    #[inline]
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    #[inline]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    pub fn short_hex(&self) -> String {
        let full = Hash32(self.0).to_hex();
        format!("xcr1_{}", &full[..12])
    }
}

impl fmt::Debug for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Address({})", self.short_hex())
    }
}

impl fmt::Display for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.short_hex())
    }
}

/// Monotonically increasing PoNC / quorum epoch index (`Genesis = EpochId(0)`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct EpochId(pub u64);

/// Closed-loop `70% Worker / 15% Endurance Pool / 15% Burn` anti-gaming fee decomposition.
///
/// Any validator attempting to self-spam loses `30%` (`15%` Endurance lock + `15%` permanent burn)
/// immediately in the current epoch, while busy commercial eras pre-fund future years of node
/// security via `endurance_deposit`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FeeSplit {
    pub total: Amount,
    pub worker_reward: Amount,
    pub endurance_deposit: Amount,
    pub burned: Amount,
}

impl FeeSplit {
    /// Splits `fee` into `70%` immediate worker payout, `15%` `SecurityEndurancePool` deposit,
    /// and `15%` permanent supply burn.
    /// Bit conservation (`worker_reward + endurance_deposit + burned == total`) holds unconditionally.
    pub const fn compute(fee: Amount) -> Self {
        let bits = fee.bits();
        let worker_bits = (bits.saturating_mul(FEE_WORKER_SHARE_BPS)) / 10_000;
        let endurance_bits = (bits.saturating_mul(FEE_ENDURANCE_SHARE_BPS)) / 10_000;
        let burned_bits = bits - worker_bits - endurance_bits;
        Self {
            total: fee,
            worker_reward: Amount::from_bits(worker_bits),
            endurance_deposit: Amount::from_bits(endurance_bits),
            burned: Amount::from_bits(burned_bits),
        }
    }
}

/// On-chain **Security Endurance Pool** recycling `15%` of transaction fees across future epochs
/// along a smooth ~1-year exponential decay curve so security never starves during quiet eras.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SecurityEndurancePool {
    pub balance: Amount,
}

impl SecurityEndurancePool {
    pub const fn new() -> Self {
        Self {
            balance: Amount::ZERO,
        }
    }

    pub fn deposit(&mut self, incoming: Amount) {
        self.balance = self.balance.saturating_add(incoming);
    }

    /// Releases `1 / 525,600` (at least `1 bit` when non-empty) of the Endurance Pool to workers.
    pub fn drip_for_epoch(&mut self) -> Amount {
        if self.balance.is_zero() {
            return Amount::ZERO;
        }
        let drip_bits = (self.balance.bits() / ENDURANCE_EPOCH_DRIP_DIVISOR).max(1);
        let drip = Amount::from_bits(drip_bits);
        self.balance = self.balance.checked_sub(drip).unwrap_or(Amount::ZERO);
        drip
    }
}

/// Dynamic base-fee controller targeting ~50% capacity utilization while pinning micro-fees.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DynamicFeeController {
    base_fee_bits: u64,
    min_fee_bits: u64,
    target_utilization_bps: u32,
}

impl DynamicFeeController {
    pub const fn new_default() -> Self {
        Self {
            base_fee_bits: 100, // 0.000100 XCR
            min_fee_bits: MIN_BASE_FEE_BITS,
            target_utilization_bps: 5_000,
        }
    }

    #[inline]
    pub const fn base_fee(&self) -> Amount {
        Amount::from_bits(self.base_fee_bits)
    }

    /// Smoothly dampens or raises `base_fee_bits` by at most +/-12.5% per settlement window.
    pub fn on_window_utilization(&mut self, utilization_bps: u32) {
        let capped = utilization_bps.min(10_000);
        if capped > self.target_utilization_bps {
            let excess = (capped - self.target_utilization_bps) as u64;
            let delta = (self.base_fee_bits * excess) / (self.target_utilization_bps as u64 * 8);
            self.base_fee_bits = self.base_fee_bits.saturating_add(delta.max(1));
        } else if capped < self.target_utilization_bps {
            let slack = (self.target_utilization_bps - capped) as u64;
            let delta = (self.base_fee_bits * slack) / (self.target_utilization_bps as u64 * 8);
            self.base_fee_bits = self
                .base_fee_bits
                .saturating_sub(delta)
                .max(self.min_fee_bits);
        }
    }
}

/// 4-Dot Credchip visual status indicator surfaced on hardware cards and mobile wallets.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct CredchipStatus {
    /// Dot 1: Passkey Spending Pocket funded and ready for ~200 ms tap-to-pay.
    pub pocket_active: bool,
    /// Dot 2: Savings Vault withdrawal time-lock and PQ guardian root armed.
    pub vault_shielded: bool,
    /// Dot 3: Client-side ZK Proof of Innocence tree synced for regulated commerce.
    pub zk_proof_synced: bool,
    /// Dot 4: Local PoNC CPU / edge relay worker earning epoch micro-rewards.
    pub node_earning: bool,
}

impl CredchipStatus {
    pub const fn active_dots(&self) -> u8 {
        (self.pocket_active as u8)
            + (self.vault_shielded as u8)
            + (self.zk_proof_synced as u8)
            + (self.node_earning as u8)
    }
}

/// Errors produced by `Pocket` and `Vault` sovereign account transitions.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AccountError {
    InsufficientBalance {
        available: Amount,
        requested: Amount,
    },
    DailyPocketLimitExceeded {
        remaining_today: Amount,
        requested: Amount,
    },
    InvalidNonce {
        expected: u64,
        actual: u64,
    },
    AmountOverflow,
    WithdrawalNotFound(u64),
}

impl fmt::Display for AccountError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InsufficientBalance {
                available,
                requested,
            } => {
                write!(
                    f,
                    "insufficient balance: available {available}, requested {requested}"
                )
            }
            Self::DailyPocketLimitExceeded {
                remaining_today,
                requested,
            } => {
                write!(
                    f,
                    "daily Pocket tap limit exceeded: remaining {remaining_today}, requested {requested}"
                )
            }
            Self::InvalidNonce { expected, actual } => {
                write!(
                    f,
                    "invalid account nonce: expected {expected}, got {actual}"
                )
            }
            Self::AmountOverflow => f.write_str("fixed-point XCR amount overflow"),
            Self::WithdrawalNotFound(id) => write!(f, "pending Vault withdrawal #{id} not found"),
        }
    }
}

/// Hardware-Passkey (`secp256r1` FaceID/TouchID) instant-tap `Spending Pocket`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PocketState {
    pub balance: Amount,
    pub nonce: u64,
    pub daily_spent: Amount,
    pub daily_limit: Amount,
    pub current_day: u64,
}

impl PocketState {
    pub const fn new(balance: Amount, daily_limit: Amount) -> Self {
        Self {
            balance,
            nonce: 0,
            daily_spent: Amount::ZERO,
            daily_limit,
            current_day: 0,
        }
    }

    /// Executes a 1-RTT single-owner debit, enforcing nonce sequence and daily tap cap.
    pub fn spend_fast(
        &mut self,
        total_debit: Amount,
        nonce: u64,
        day_index: u64,
    ) -> Result<(), AccountError> {
        if nonce != self.nonce {
            return Err(AccountError::InvalidNonce {
                expected: self.nonce,
                actual: nonce,
            });
        }
        if day_index > self.current_day {
            self.current_day = day_index;
            self.daily_spent = Amount::ZERO;
        }
        let remaining_today = self
            .daily_limit
            .checked_sub(self.daily_spent)
            .unwrap_or(Amount::ZERO);
        if total_debit > remaining_today {
            return Err(AccountError::DailyPocketLimitExceeded {
                remaining_today,
                requested: total_debit,
            });
        }
        let next_balance =
            self.balance
                .checked_sub(total_debit)
                .ok_or(AccountError::InsufficientBalance {
                    available: self.balance,
                    requested: total_debit,
                })?;
        let next_daily = self
            .daily_spent
            .checked_add(total_debit)
            .ok_or(AccountError::AmountOverflow)?;

        self.balance = next_balance;
        self.daily_spent = next_daily;
        self.nonce += 1;
        Ok(())
    }

    pub fn credit(&mut self, incoming: Amount) -> Result<(), AccountError> {
        self.balance = self
            .balance
            .checked_add(incoming)
            .ok_or(AccountError::AmountOverflow)?;
        Ok(())
    }
}

/// Time-locked withdrawal queued inside a user's `Savings Vault`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PendingWithdrawal {
    pub id: u64,
    pub destination: Address,
    pub amount: Amount,
    pub unlock_at_ms: u64,
}

/// Wrench-attack-resistant `Savings Vault` with protocol-enforced cooling window
/// and Post-Quantum guardian Merkle root.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VaultState {
    pub balance: Amount,
    pub timelock_ms: u64,
    pub guardian_threshold: u8,
    pub pq_guardian_root: Hash32,
    pub next_withdrawal_id: u64,
    pub pending: Vec<PendingWithdrawal>,
}

impl VaultState {
    pub const fn new(
        balance: Amount,
        timelock_ms: u64,
        guardian_threshold: u8,
        pq_guardian_root: Hash32,
    ) -> Self {
        Self {
            balance,
            timelock_ms,
            guardian_threshold,
            pq_guardian_root,
            next_withdrawal_id: 1,
            pending: Vec::new(),
        }
    }

    /// Escrows `amount` into a time-locked withdrawal maturing at `now_ms + timelock_ms`.
    pub fn queue_withdrawal(
        &mut self,
        destination: Address,
        amount: Amount,
        now_ms: u64,
    ) -> Result<u64, AccountError> {
        let next_balance =
            self.balance
                .checked_sub(amount)
                .ok_or(AccountError::InsufficientBalance {
                    available: self.balance,
                    requested: amount,
                })?;
        let unlock_at_ms = now_ms
            .checked_add(self.timelock_ms)
            .ok_or(AccountError::AmountOverflow)?;
        let id = self.next_withdrawal_id;
        self.next_withdrawal_id += 1;
        self.balance = next_balance;
        self.pending.push(PendingWithdrawal {
            id,
            destination,
            amount,
            unlock_at_ms,
        });
        Ok(id)
    }

    /// Cancels an unmatured withdrawal under duress/phishing recovery, restoring `Vault` funds.
    pub fn emergency_cancel(&mut self, withdrawal_id: u64) -> Result<Amount, AccountError> {
        let pos = self
            .pending
            .iter()
            .position(|w| w.id == withdrawal_id)
            .ok_or(AccountError::WithdrawalNotFound(withdrawal_id))?;
        let cancelled = self.pending.remove(pos);
        self.balance = self
            .balance
            .checked_add(cancelled.amount)
            .ok_or(AccountError::AmountOverflow)?;
        Ok(cancelled.amount)
    }

    /// Releases all queued withdrawals whose cooling window has elapsed (`unlock_at_ms <= now_ms`).
    pub fn release_matured(&mut self, now_ms: u64) -> Vec<PendingWithdrawal> {
        let mut matured = Vec::new();
        let mut remaining = Vec::with_capacity(self.pending.len());
        for item in self.pending.drain(..) {
            if item.unlock_at_ms <= now_ms {
                matured.push(item);
            } else {
                remaining.push(item);
            }
        }
        self.pending = remaining;
        matured
    }
}

/// Objective on-chain decentralization metrics gating Phase 1 -> Phase 2 activation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MaturityMetrics {
    pub active_compute_nodes: u32,
    pub distinct_autonomous_systems: u32,
    pub consecutive_deep_epochs: u32,
}

impl MaturityMetrics {
    pub const MIN_NODES_FOR_PHASE2: u32 = 10_000;
    pub const MIN_ASNS_FOR_PHASE2: u32 = 500;
    pub const MIN_DEEP_EPOCHS: u32 = 43_200; // ~30 days of 1-minute epochs

    pub const fn can_activate_phase2(&self) -> bool {
        self.active_compute_nodes >= Self::MIN_NODES_FOR_PHASE2
            && self.distinct_autonomous_systems >= Self::MIN_ASNS_FOR_PHASE2
            && self.consecutive_deep_epochs >= Self::MIN_DEEP_EPOCHS
    }
}

/// Option C Phased Monetary Policy state.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MonetaryPhase {
    /// Phase 1: Zero-oracle scarce sound money earned 100% via PoNC from Genesis (`0 XCR` premine).
    Phase1Bootstrap {
        epoch: EpochId,
        circulating_supply: Amount,
        total_burned: Amount,
    },
    /// Phase 2: Unlocks >=200% over-collateralized Reserve Vaults tracking a Global CPI Basket.
    Phase2GlobalBasket {
        epoch: EpochId,
        basket_index_micros: u64,
        min_collateral_ratio_bps: u32,
    },
}

/// Layer-1 transaction payload variants.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TransactionKind {
    /// Single-owner 1-RTT Fast-Path payment (~150-250 ms deterministic settlement).
    FastTransfer {
        from: Address,
        to_stealth: Address,
        stealth_view_tag: u8,
        amount: Amount,
        fee: Amount,
        nonce: u64,
        commitment: Hash32,
        innocence_nullifier: Option<Hash32>,
    },
    /// Shared/stateful Vault time-locked withdrawal initiation (routes via 3-round BFT DAG).
    VaultQueueWithdrawal {
        vault_owner: Address,
        destination: Address,
        amount: Amount,
        fee: Amount,
        nonce: u64,
    },
    /// Emergency cancellation of a pending Vault withdrawal (routes via 3-round BFT DAG).
    VaultEmergencyCancel {
        vault_owner: Address,
        withdrawal_id: u64,
        fee: Amount,
        nonce: u64,
    },
}

/// Signed Layer-1 Credits transaction.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Transaction {
    pub id: Hash32,
    pub kind: TransactionKind,
    pub signature_bytes: Vec<u8>,
}

impl Transaction {
    /// Returns `true` if this transaction touches only single-owner `Pocket` state
    /// and therefore qualifies for 1-RTT Fast-Path finality (~150-250 ms, zero MEV).
    pub const fn is_single_owner_fast_path(&self) -> bool {
        matches!(self.kind, TransactionKind::FastTransfer { .. })
    }

    pub const fn fee(&self) -> Amount {
        match &self.kind {
            TransactionKind::FastTransfer { fee, .. }
            | TransactionKind::VaultQueueWithdrawal { fee, .. }
            | TransactionKind::VaultEmergencyCancel { fee, .. } => *fee,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn denominations_and_fee_split_conserve_every_bit() {
        let one_credit = Amount::from_credits(1).unwrap();
        let hundred_chips = Amount::from_chips(100).unwrap();
        assert_eq!(one_credit, hundred_chips);
        assert_eq!(one_credit.bits(), 1_000_000);
        assert_eq!(one_credit.format_symbolic(), "∀ 1.000000 XCR");

        for raw_fee in [10u64, 17, 99, 100, 1_000, 999_999] {
            let split = FeeSplit::compute(Amount::from_bits(raw_fee));
            assert_eq!(
                split
                    .worker_reward
                    .checked_add(split.endurance_deposit)
                    .unwrap()
                    .checked_add(split.burned)
                    .unwrap(),
                split.total
            );
        }

        let mut endurance = SecurityEndurancePool::new();
        endurance.deposit(Amount::from_credits(525_600).unwrap());
        let drip = endurance.drip_for_epoch();
        assert_eq!(drip, Amount::from_credits(1).unwrap());
    }

    #[test]
    fn pocket_limit_and_vault_emergency_cancel() {
        let mut pocket = PocketState::new(
            Amount::from_credits(500).unwrap(),
            Amount::from_credits(100).unwrap(),
        );
        pocket
            .spend_fast(Amount::from_credits(60).unwrap(), 0, 1)
            .unwrap();
        assert_eq!(
            pocket.spend_fast(Amount::from_credits(50).unwrap(), 1, 1),
            Err(AccountError::DailyPocketLimitExceeded {
                remaining_today: Amount::from_credits(40).unwrap(),
                requested: Amount::from_credits(50).unwrap(),
            })
        );

        let mut vault = VaultState::new(
            Amount::from_credits(10_000).unwrap(),
            86_400_000,
            2,
            Hash32::from_bytes([7u8; 32]),
        );
        let dest = Address::from_bytes([9u8; 32]);
        let wid = vault
            .queue_withdrawal(dest, Amount::from_credits(5_000).unwrap(), 1_000)
            .unwrap();
        assert_eq!(vault.balance, Amount::from_credits(5_000).unwrap());
        assert!(vault.release_matured(50_000).is_empty());

        let restored = vault.emergency_cancel(wid).unwrap();
        assert_eq!(restored, Amount::from_credits(5_000).unwrap());
        assert_eq!(vault.balance, Amount::from_credits(10_000).unwrap());
    }
}
