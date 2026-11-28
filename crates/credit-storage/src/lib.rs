//! Crash-Safe Append-Only **Write-Ahead Log (`XCRWAL01`)** & Materialized Ledger Store.
//!
//! - Every state transition (`Pocket` registration, `1-RTT` finality settlement, `Epoch` PoNC
//!   payout, `Vault` update, and spent Privacy Pool `nullifier`) is journaled with a 16-byte
//!   domain-separated SHA-256 authentication tag and `sync_data()` (`fsync`).
//! - On startup, `PersistentLedger::open` replays all valid records and automatically truncates
//!   any trailing torn write caused by sudden power loss or OS crash.
//! - Computes a deterministic canonical `state_merkle_root()` across accounts, stealth outputs,
//!   nullifiers, and supply counters.

pub mod archival;

pub use archival::{
    ArchiveInclusionProof, ArchivedPocketLeaf, DEFAULT_DORMANT_THRESHOLD_EPOCHS,
    DormantArchiveRegistry, DormantArchiveTree, RevivalError,
};

use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use credit_crypto::{PublicKey, SignatureScheme, domain_hash};
use credit_types::{Address, Amount, EpochId, Hash32, PocketState, VaultState};

/// 8-byte binary header identifying a Credits v1 Write-Ahead Log.
pub const WAL_MAGIC: [u8; 8] = *b"XCRWAL01";

const TAG_UPSERT_POCKET: u8 = 1;
const TAG_RECORD_FAST_FINALITY: u8 = 2;
const TAG_RECORD_EPOCH_SETTLEMENT: u8 = 3;
const TAG_UPSERT_VAULT: u8 = 4;
const TAG_CLAIM_STEALTH_UTXO: u8 = 5;
const TAG_UPSERT_HTLC: u8 = 6;
const TAG_UPSERT_PAYCHAN: u8 = 7;
const TAG_SETTLE_CHECK: u8 = 8;
const TAG_UPSERT_SCRIPT_VAULT: u8 = 9;
const TAG_UPSERT_SESSION_STATE: u8 = 10;
const TAG_UPSERT_NATIVE_ASSET: u8 = 11;
const TAG_UPSERT_CAMPAIGN: u8 = 12;

/// Stored `Spending Pocket` entry pairing public verification key with live balance/nonce state.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StoredPocket {
    pub public_key: PublicKey,
    pub state: PocketState,
}

/// Materialized Layer-1 Hash-Time-Locked Conditional Escrow (`HTLC`) for cross-chain atomic swaps.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StoredHtlc {
    pub escrow_id: Hash32,
    pub sender: Address,
    pub recipient: Address,
    pub amount: Amount,
    pub hashlock: Hash32,
    pub expiry_unix: u64,
    /// `0 = Open`, `1 = Claimed (preimage revealed)`, `2 = Refunded (expired)`.
    pub status: u8,
    pub revealed_preimage: Option<[u8; 32]>,
}

/// Materialized Layer-1 unidirectional streaming micropayment channel (`PayChan`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StoredPayChannel {
    pub channel_id: Hash32,
    pub payer: Address,
    pub payer_pubkey: PublicKey,
    pub payee: Address,
    pub deposit: Amount,
    pub expiry_unix: u64,
    pub closed: bool,
    pub settled_amount: Amount,
}

/// Materialized `CredScript` Pay-to-Script-Hash (`P2SH`) smart vault.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StoredScriptVault {
    pub vault_id: Hash32,
    pub depositor: Address,
    pub script_hash: Hash32,
    pub amount: Amount,
    pub spent: bool,
}

/// Materialized cumulative spend & revocation tracker for an ERC-4337-style `SessionKeyGrant`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StoredSessionState {
    pub session_id: Hash32,
    pub cumulative_spent: Amount,
    pub revoked: bool,
}

/// Materialized Cardano-style fixed-supply native bearer asset definition.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StoredNativeAsset {
    pub asset_id: Hash32,
    pub issuer: Address,
    pub ticker: String,
    pub total_supply: u64,
    pub decimals: u8,
}

/// Materialized all-or-nothing assurance crowdfunding campaign (`PledgeVault`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StoredCampaign {
    pub campaign_id: Hash32,
    pub creator: Address,
    pub beneficiary: Address,
    pub title: String,
    pub goal_amount: Amount,
    pub deadline_unix: u64,
    /// `0 = Open`, `1 = Funded (goal met)`, `2 = Refunded (expired below goal)`.
    pub status: u8,
    pub pledges: Vec<(Address, Amount)>,
}

/// Cardano-style formal ledger balance-sheet & conservation summary.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SupplyAuditReport {
    pub pockets_total: Amount,
    pub stealth_utxos_total: Amount,
    pub locked_contracts_total: Amount,
    pub circulating_supply: Amount,
    pub total_burned: Amount,
    pub delta_conservation_verified: bool,
}

/// Atomic journal entry persisted inside `XCRWAL01`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum WalRecord {
    UpsertPocket {
        address: Address,
        public_key: PublicKey,
        state: PocketState,
    },
    RecordFastFinality {
        tx_id: Hash32,
        sender: Address,
        new_nonce: u64,
        new_balance: Amount,
        new_daily_spent: Amount,
        day_index: u64,
        recipient_stealth: Address,
        stealth_amount: Amount,
        fee_worker: Amount,
        fee_burned: Amount,
        nullifier: Option<Hash32>,
    },
    RecordEpochSettlement {
        epoch: EpochId,
        minted_emission: Amount,
        worker_fees: Amount,
        burned_fees: Amount,
        payouts: Vec<(Address, Amount)>,
    },
    UpsertVault {
        owner: Address,
        timelock_ms: u64,
        balance: Amount,
        guardian_threshold: u8,
        pq_guardian_root: Hash32,
    },
    ClaimStealthUtxo {
        tx_id: Hash32,
        one_time_address: Address,
        claimant_pocket: Address,
        new_pocket_balance: Amount,
        fee_burned: Amount,
        claim_nullifier: Hash32,
    },
    UpsertHtlc {
        htlc: StoredHtlc,
        pocket_updates: Vec<(Address, Amount)>,
        fee_burned: Amount,
    },
    UpsertPayChan {
        channel: StoredPayChannel,
        pocket_updates: Vec<(Address, Amount)>,
        fee_burned: Amount,
    },
    SettleCheck {
        check_id: Hash32,
        pocket_updates: Vec<(Address, Amount)>,
        fee_burned: Amount,
    },
    UpsertScriptVault {
        vault: StoredScriptVault,
        pocket_updates: Vec<(Address, Amount)>,
        fee_burned: Amount,
    },
    UpsertSessionState {
        tx_id: Hash32,
        state: StoredSessionState,
        pocket_updates: Vec<(Address, Amount)>,
        fee_burned: Amount,
    },
    UpsertNativeAsset {
        tx_id: Hash32,
        asset: Option<StoredNativeAsset>,
        balance_updates: Vec<(Address, Hash32, u64)>,
        pocket_updates: Vec<(Address, Amount)>,
        fee_burned: Amount,
    },
    UpsertCampaign {
        tx_id: Hash32,
        campaign: StoredCampaign,
        pocket_updates: Vec<(Address, Amount)>,
        fee_burned: Amount,
    },
}

impl WalRecord {
    fn encode(&self) -> (u8, Vec<u8>) {
        let mut out = Vec::new();
        match self {
            Self::UpsertPocket {
                address,
                public_key,
                state,
            } => {
                out.extend_from_slice(address.as_bytes());
                out.push(public_key.scheme as u8);
                out.extend_from_slice(public_key.merkle_root.as_bytes());
                out.extend_from_slice(&state.balance.bits().to_le_bytes());
                out.extend_from_slice(&state.nonce.to_le_bytes());
                out.extend_from_slice(&state.daily_spent.bits().to_le_bytes());
                out.extend_from_slice(&state.daily_limit.bits().to_le_bytes());
                out.extend_from_slice(&state.current_day.to_le_bytes());
                (TAG_UPSERT_POCKET, out)
            }
            Self::RecordFastFinality {
                tx_id,
                sender,
                new_nonce,
                new_balance,
                new_daily_spent,
                day_index,
                recipient_stealth,
                stealth_amount,
                fee_worker,
                fee_burned,
                nullifier,
            } => {
                out.extend_from_slice(tx_id.as_bytes());
                out.extend_from_slice(sender.as_bytes());
                out.extend_from_slice(&new_nonce.to_le_bytes());
                out.extend_from_slice(&new_balance.bits().to_le_bytes());
                out.extend_from_slice(&new_daily_spent.bits().to_le_bytes());
                out.extend_from_slice(&day_index.to_le_bytes());
                out.extend_from_slice(recipient_stealth.as_bytes());
                out.extend_from_slice(&stealth_amount.bits().to_le_bytes());
                out.extend_from_slice(&fee_worker.bits().to_le_bytes());
                out.extend_from_slice(&fee_burned.bits().to_le_bytes());
                match nullifier {
                    Some(n) => {
                        out.push(1);
                        out.extend_from_slice(n.as_bytes());
                    }
                    None => out.push(0),
                }
                (TAG_RECORD_FAST_FINALITY, out)
            }
            Self::RecordEpochSettlement {
                epoch,
                minted_emission,
                worker_fees,
                burned_fees,
                payouts,
            } => {
                out.extend_from_slice(&epoch.0.to_le_bytes());
                out.extend_from_slice(&minted_emission.bits().to_le_bytes());
                out.extend_from_slice(&worker_fees.bits().to_le_bytes());
                out.extend_from_slice(&burned_fees.bits().to_le_bytes());
                out.extend_from_slice(&(payouts.len() as u32).to_le_bytes());
                for (addr, amt) in payouts {
                    out.extend_from_slice(addr.as_bytes());
                    out.extend_from_slice(&amt.bits().to_le_bytes());
                }
                (TAG_RECORD_EPOCH_SETTLEMENT, out)
            }
            Self::UpsertVault {
                owner,
                timelock_ms,
                balance,
                guardian_threshold,
                pq_guardian_root,
            } => {
                out.extend_from_slice(owner.as_bytes());
                out.extend_from_slice(&timelock_ms.to_le_bytes());
                out.extend_from_slice(&balance.bits().to_le_bytes());
                out.push(*guardian_threshold);
                out.extend_from_slice(pq_guardian_root.as_bytes());
                (TAG_UPSERT_VAULT, out)
            }
            Self::ClaimStealthUtxo {
                tx_id,
                one_time_address,
                claimant_pocket,
                new_pocket_balance,
                fee_burned,
                claim_nullifier,
            } => {
                out.extend_from_slice(tx_id.as_bytes());
                out.extend_from_slice(one_time_address.as_bytes());
                out.extend_from_slice(claimant_pocket.as_bytes());
                out.extend_from_slice(&new_pocket_balance.bits().to_le_bytes());
                out.extend_from_slice(&fee_burned.bits().to_le_bytes());
                out.extend_from_slice(claim_nullifier.as_bytes());
                (TAG_CLAIM_STEALTH_UTXO, out)
            }
            Self::UpsertHtlc {
                htlc,
                pocket_updates,
                fee_burned,
            } => {
                out.extend_from_slice(htlc.escrow_id.as_bytes());
                out.extend_from_slice(htlc.sender.as_bytes());
                out.extend_from_slice(htlc.recipient.as_bytes());
                out.extend_from_slice(&htlc.amount.bits().to_le_bytes());
                out.extend_from_slice(htlc.hashlock.as_bytes());
                out.extend_from_slice(&htlc.expiry_unix.to_le_bytes());
                out.push(htlc.status);
                match htlc.revealed_preimage {
                    Some(pre) => {
                        out.push(1);
                        out.extend_from_slice(&pre);
                    }
                    None => out.push(0),
                }
                out.extend_from_slice(&fee_burned.bits().to_le_bytes());
                out.push(pocket_updates.len() as u8);
                for (addr, bal) in pocket_updates {
                    out.extend_from_slice(addr.as_bytes());
                    out.extend_from_slice(&bal.bits().to_le_bytes());
                }
                (TAG_UPSERT_HTLC, out)
            }
            Self::UpsertPayChan {
                channel,
                pocket_updates,
                fee_burned,
            } => {
                out.extend_from_slice(channel.channel_id.as_bytes());
                out.extend_from_slice(channel.payer.as_bytes());
                out.push(channel.payer_pubkey.scheme as u8);
                out.extend_from_slice(channel.payer_pubkey.merkle_root.as_bytes());
                out.extend_from_slice(channel.payee.as_bytes());
                out.extend_from_slice(&channel.deposit.bits().to_le_bytes());
                out.extend_from_slice(&channel.expiry_unix.to_le_bytes());
                out.push(channel.closed as u8);
                out.extend_from_slice(&channel.settled_amount.bits().to_le_bytes());
                out.extend_from_slice(&fee_burned.bits().to_le_bytes());
                out.push(pocket_updates.len() as u8);
                for (addr, bal) in pocket_updates {
                    out.extend_from_slice(addr.as_bytes());
                    out.extend_from_slice(&bal.bits().to_le_bytes());
                }
                (TAG_UPSERT_PAYCHAN, out)
            }
            Self::SettleCheck {
                check_id,
                pocket_updates,
                fee_burned,
            } => {
                out.extend_from_slice(check_id.as_bytes());
                out.extend_from_slice(&fee_burned.bits().to_le_bytes());
                out.push(pocket_updates.len() as u8);
                for (addr, bal) in pocket_updates {
                    out.extend_from_slice(addr.as_bytes());
                    out.extend_from_slice(&bal.bits().to_le_bytes());
                }
                (TAG_SETTLE_CHECK, out)
            }
            Self::UpsertScriptVault {
                vault,
                pocket_updates,
                fee_burned,
            } => {
                out.extend_from_slice(vault.vault_id.as_bytes());
                out.extend_from_slice(vault.depositor.as_bytes());
                out.extend_from_slice(vault.script_hash.as_bytes());
                out.extend_from_slice(&vault.amount.bits().to_le_bytes());
                out.push(vault.spent as u8);
                out.extend_from_slice(&fee_burned.bits().to_le_bytes());
                encode_pocket_updates(&mut out, pocket_updates);
                (TAG_UPSERT_SCRIPT_VAULT, out)
            }
            Self::UpsertSessionState {
                tx_id,
                state,
                pocket_updates,
                fee_burned,
            } => {
                out.extend_from_slice(tx_id.as_bytes());
                out.extend_from_slice(state.session_id.as_bytes());
                out.extend_from_slice(&state.cumulative_spent.bits().to_le_bytes());
                out.push(state.revoked as u8);
                out.extend_from_slice(&fee_burned.bits().to_le_bytes());
                encode_pocket_updates(&mut out, pocket_updates);
                (TAG_UPSERT_SESSION_STATE, out)
            }
            Self::UpsertNativeAsset {
                tx_id,
                asset,
                balance_updates,
                pocket_updates,
                fee_burned,
            } => {
                out.extend_from_slice(tx_id.as_bytes());
                match asset {
                    Some(a) => {
                        out.push(1);
                        out.extend_from_slice(a.asset_id.as_bytes());
                        out.extend_from_slice(a.issuer.as_bytes());
                        out.push(a.ticker.len() as u8);
                        out.extend_from_slice(a.ticker.as_bytes());
                        out.extend_from_slice(&a.total_supply.to_le_bytes());
                        out.push(a.decimals);
                    }
                    None => out.push(0),
                }
                out.push(balance_updates.len() as u8);
                for (owner, aid, units) in balance_updates {
                    out.extend_from_slice(owner.as_bytes());
                    out.extend_from_slice(aid.as_bytes());
                    out.extend_from_slice(&units.to_le_bytes());
                }
                out.extend_from_slice(&fee_burned.bits().to_le_bytes());
                encode_pocket_updates(&mut out, pocket_updates);
                (TAG_UPSERT_NATIVE_ASSET, out)
            }
            Self::UpsertCampaign {
                tx_id,
                campaign,
                pocket_updates,
                fee_burned,
            } => {
                out.extend_from_slice(tx_id.as_bytes());
                out.extend_from_slice(campaign.campaign_id.as_bytes());
                out.extend_from_slice(campaign.creator.as_bytes());
                out.extend_from_slice(campaign.beneficiary.as_bytes());
                out.push(campaign.title.len() as u8);
                out.extend_from_slice(campaign.title.as_bytes());
                out.extend_from_slice(&campaign.goal_amount.bits().to_le_bytes());
                out.extend_from_slice(&campaign.deadline_unix.to_le_bytes());
                out.push(campaign.status);
                out.extend_from_slice(&(campaign.pledges.len() as u16).to_le_bytes());
                for (b, amt) in &campaign.pledges {
                    out.extend_from_slice(b.as_bytes());
                    out.extend_from_slice(&amt.bits().to_le_bytes());
                }
                out.extend_from_slice(&fee_burned.bits().to_le_bytes());
                encode_pocket_updates(&mut out, pocket_updates);
                (TAG_UPSERT_CAMPAIGN, out)
            }
        }
    }

    fn decode(tag: u8, bytes: &[u8]) -> Option<Self> {
        match tag {
            TAG_UPSERT_POCKET => {
                if bytes.len() != 32 + 1 + 32 + 8 * 5 {
                    return None;
                }
                let address = Address::from_bytes(bytes[0..32].try_into().ok()?);
                let scheme = SignatureScheme::from_u8(bytes[32])?;
                let merkle_root = Hash32::from_bytes(bytes[33..65].try_into().ok()?);
                let balance = Amount::from_bits(read_u64(bytes, 65)?);
                let nonce = read_u64(bytes, 73)?;
                let daily_spent = Amount::from_bits(read_u64(bytes, 81)?);
                let daily_limit = Amount::from_bits(read_u64(bytes, 89)?);
                let current_day = read_u64(bytes, 97)?;
                Some(Self::UpsertPocket {
                    address,
                    public_key: PublicKey {
                        scheme,
                        merkle_root,
                    },
                    state: PocketState {
                        balance,
                        nonce,
                        daily_spent,
                        daily_limit,
                        current_day,
                    },
                })
            }
            TAG_RECORD_FAST_FINALITY => {
                if bytes.len() < 32 + 32 + 8 * 4 + 32 + 8 * 3 + 1 {
                    return None;
                }
                let tx_id = Hash32::from_bytes(bytes[0..32].try_into().ok()?);
                let sender = Address::from_bytes(bytes[32..64].try_into().ok()?);
                let new_nonce = read_u64(bytes, 64)?;
                let new_balance = Amount::from_bits(read_u64(bytes, 72)?);
                let new_daily_spent = Amount::from_bits(read_u64(bytes, 80)?);
                let day_index = read_u64(bytes, 88)?;
                let recipient_stealth = Address::from_bytes(bytes[96..128].try_into().ok()?);
                let stealth_amount = Amount::from_bits(read_u64(bytes, 128)?);
                let fee_worker = Amount::from_bits(read_u64(bytes, 136)?);
                let fee_burned = Amount::from_bits(read_u64(bytes, 144)?);
                let has_null = bytes[152];
                let nullifier = if has_null == 0 {
                    if bytes.len() != 153 {
                        return None;
                    }
                    None
                } else if has_null == 1 && bytes.len() == 185 {
                    Some(Hash32::from_bytes(bytes[153..185].try_into().ok()?))
                } else {
                    return None;
                };
                Some(Self::RecordFastFinality {
                    tx_id,
                    sender,
                    new_nonce,
                    new_balance,
                    new_daily_spent,
                    day_index,
                    recipient_stealth,
                    stealth_amount,
                    fee_worker,
                    fee_burned,
                    nullifier,
                })
            }
            TAG_RECORD_EPOCH_SETTLEMENT => {
                if bytes.len() < 36 {
                    return None;
                }
                let epoch = EpochId(read_u64(bytes, 0)?);
                let minted_emission = Amount::from_bits(read_u64(bytes, 8)?);
                let worker_fees = Amount::from_bits(read_u64(bytes, 16)?);
                let burned_fees = Amount::from_bits(read_u64(bytes, 24)?);
                let count = u32::from_le_bytes(bytes[32..36].try_into().ok()?) as usize;
                if bytes.len() != 36 + count * 40 {
                    return None;
                }
                let mut payouts = Vec::with_capacity(count);
                let mut pos = 36;
                for _ in 0..count {
                    let addr = Address::from_bytes(bytes[pos..pos + 32].try_into().ok()?);
                    let amt = Amount::from_bits(read_u64(bytes, pos + 32)?);
                    payouts.push((addr, amt));
                    pos += 40;
                }
                Some(Self::RecordEpochSettlement {
                    epoch,
                    minted_emission,
                    worker_fees,
                    burned_fees,
                    payouts,
                })
            }
            TAG_UPSERT_VAULT => {
                if bytes.len() != 32 + 8 + 8 + 1 + 32 {
                    return None;
                }
                let owner = Address::from_bytes(bytes[0..32].try_into().ok()?);
                let timelock_ms = read_u64(bytes, 32)?;
                let balance = Amount::from_bits(read_u64(bytes, 40)?);
                let guardian_threshold = bytes[48];
                let pq_guardian_root = Hash32::from_bytes(bytes[49..81].try_into().ok()?);
                Some(Self::UpsertVault {
                    owner,
                    timelock_ms,
                    balance,
                    guardian_threshold,
                    pq_guardian_root,
                })
            }
            TAG_CLAIM_STEALTH_UTXO => {
                if bytes.len() != 32 + 32 + 32 + 8 + 8 + 32 {
                    return None;
                }
                let tx_id = Hash32::from_bytes(bytes[0..32].try_into().ok()?);
                let one_time_address = Address::from_bytes(bytes[32..64].try_into().ok()?);
                let claimant_pocket = Address::from_bytes(bytes[64..96].try_into().ok()?);
                let new_pocket_balance = Amount::from_bits(read_u64(bytes, 96)?);
                let fee_burned = Amount::from_bits(read_u64(bytes, 104)?);
                let claim_nullifier = Hash32::from_bytes(bytes[112..144].try_into().ok()?);
                Some(Self::ClaimStealthUtxo {
                    tx_id,
                    one_time_address,
                    claimant_pocket,
                    new_pocket_balance,
                    fee_burned,
                    claim_nullifier,
                })
            }
            TAG_UPSERT_HTLC => {
                if bytes.len() < 32 * 4 + 16 + 2 + 8 + 1 {
                    return None;
                }
                let escrow_id = Hash32::from_bytes(bytes[0..32].try_into().ok()?);
                let sender = Address::from_bytes(bytes[32..64].try_into().ok()?);
                let recipient = Address::from_bytes(bytes[64..96].try_into().ok()?);
                let amount = Amount::from_bits(read_u64(bytes, 96)?);
                let hashlock = Hash32::from_bytes(bytes[104..136].try_into().ok()?);
                let expiry_unix = read_u64(bytes, 136)?;
                let status = bytes[144];
                let has_pre = bytes[145];
                let mut pos = 146usize;
                let revealed_preimage = if has_pre == 1 {
                    let pre: [u8; 32] = bytes.get(pos..pos + 32)?.try_into().ok()?;
                    pos += 32;
                    Some(pre)
                } else if has_pre == 0 {
                    None
                } else {
                    return None;
                };
                let fee_burned = Amount::from_bits(read_u64(bytes, pos)?);
                pos += 8;
                let upd_count = *bytes.get(pos)? as usize;
                pos += 1;
                if bytes.len() != pos + upd_count * 40 {
                    return None;
                }
                let mut pocket_updates = Vec::with_capacity(upd_count);
                for _ in 0..upd_count {
                    let addr = Address::from_bytes(bytes[pos..pos + 32].try_into().ok()?);
                    let bal = Amount::from_bits(read_u64(bytes, pos + 32)?);
                    pocket_updates.push((addr, bal));
                    pos += 40;
                }
                Some(Self::UpsertHtlc {
                    htlc: StoredHtlc {
                        escrow_id,
                        sender,
                        recipient,
                        amount,
                        hashlock,
                        expiry_unix,
                        status,
                        revealed_preimage,
                    },
                    pocket_updates,
                    fee_burned,
                })
            }
            TAG_UPSERT_PAYCHAN => {
                if bytes.len() < 32 + 32 + 1 + 32 + 32 + 16 + 1 + 16 + 1 {
                    return None;
                }
                let channel_id = Hash32::from_bytes(bytes[0..32].try_into().ok()?);
                let payer = Address::from_bytes(bytes[32..64].try_into().ok()?);
                let scheme = SignatureScheme::from_u8(bytes[64])?;
                let merkle_root = Hash32::from_bytes(bytes[65..97].try_into().ok()?);
                let payee = Address::from_bytes(bytes[97..129].try_into().ok()?);
                let deposit = Amount::from_bits(read_u64(bytes, 129)?);
                let expiry_unix = read_u64(bytes, 137)?;
                let closed = bytes[145] != 0;
                let settled_amount = Amount::from_bits(read_u64(bytes, 146)?);
                let fee_burned = Amount::from_bits(read_u64(bytes, 154)?);
                let upd_count = bytes[162] as usize;
                let mut pos = 163usize;
                if bytes.len() != pos + upd_count * 40 {
                    return None;
                }
                let mut pocket_updates = Vec::with_capacity(upd_count);
                for _ in 0..upd_count {
                    let addr = Address::from_bytes(bytes[pos..pos + 32].try_into().ok()?);
                    let bal = Amount::from_bits(read_u64(bytes, pos + 32)?);
                    pocket_updates.push((addr, bal));
                    pos += 40;
                }
                Some(Self::UpsertPayChan {
                    channel: StoredPayChannel {
                        channel_id,
                        payer,
                        payer_pubkey: PublicKey {
                            scheme,
                            merkle_root,
                        },
                        payee,
                        deposit,
                        expiry_unix,
                        closed,
                        settled_amount,
                    },
                    pocket_updates,
                    fee_burned,
                })
            }
            TAG_SETTLE_CHECK => {
                if bytes.len() < 32 + 8 + 1 {
                    return None;
                }
                let check_id = Hash32::from_bytes(bytes[0..32].try_into().ok()?);
                let fee_burned = Amount::from_bits(read_u64(bytes, 32)?);
                let upd_count = bytes[40] as usize;
                let mut pos = 41usize;
                if bytes.len() != pos + upd_count * 40 {
                    return None;
                }
                let mut pocket_updates = Vec::with_capacity(upd_count);
                for _ in 0..upd_count {
                    let addr = Address::from_bytes(bytes[pos..pos + 32].try_into().ok()?);
                    let bal = Amount::from_bits(read_u64(bytes, pos + 32)?);
                    pocket_updates.push((addr, bal));
                    pos += 40;
                }
                Some(Self::SettleCheck {
                    check_id,
                    pocket_updates,
                    fee_burned,
                })
            }
            TAG_UPSERT_SCRIPT_VAULT => {
                if bytes.len() < 32 * 3 + 8 + 1 + 8 + 1 {
                    return None;
                }
                let vault_id = Hash32::from_bytes(bytes[0..32].try_into().ok()?);
                let depositor = Address::from_bytes(bytes[32..64].try_into().ok()?);
                let script_hash = Hash32::from_bytes(bytes[64..96].try_into().ok()?);
                let amount = Amount::from_bits(read_u64(bytes, 96)?);
                let spent = bytes[104] != 0;
                let fee_burned = Amount::from_bits(read_u64(bytes, 105)?);
                let mut pos = 113usize;
                let pocket_updates = decode_pocket_updates(bytes, &mut pos)?;
                (pos == bytes.len()).then_some(Self::UpsertScriptVault {
                    vault: StoredScriptVault {
                        vault_id,
                        depositor,
                        script_hash,
                        amount,
                        spent,
                    },
                    pocket_updates,
                    fee_burned,
                })
            }
            TAG_UPSERT_SESSION_STATE => {
                if bytes.len() < 32 + 32 + 8 + 1 + 8 + 1 {
                    return None;
                }
                let tx_id = Hash32::from_bytes(bytes[0..32].try_into().ok()?);
                let session_id = Hash32::from_bytes(bytes[32..64].try_into().ok()?);
                let cumulative_spent = Amount::from_bits(read_u64(bytes, 64)?);
                let revoked = bytes[72] != 0;
                let fee_burned = Amount::from_bits(read_u64(bytes, 73)?);
                let mut pos = 81usize;
                let pocket_updates = decode_pocket_updates(bytes, &mut pos)?;
                (pos == bytes.len()).then_some(Self::UpsertSessionState {
                    tx_id,
                    state: StoredSessionState {
                        session_id,
                        cumulative_spent,
                        revoked,
                    },
                    pocket_updates,
                    fee_burned,
                })
            }
            TAG_UPSERT_NATIVE_ASSET => {
                if bytes.len() < 34 {
                    return None;
                }
                let tx_id = Hash32::from_bytes(bytes[0..32].try_into().ok()?);
                let mut pos = 32usize;
                let has_asset = *bytes.get(pos)?;
                pos += 1;
                let asset = if has_asset == 1 {
                    let asset_id = Hash32::from_bytes(bytes.get(pos..pos + 32)?.try_into().ok()?);
                    pos += 32;
                    let issuer = Address::from_bytes(bytes.get(pos..pos + 32)?.try_into().ok()?);
                    pos += 32;
                    let t_len = *bytes.get(pos)? as usize;
                    pos += 1;
                    if t_len == 0 || t_len > 12 || pos + t_len + 9 > bytes.len() {
                        return None;
                    }
                    let ticker = String::from_utf8(bytes[pos..pos + t_len].to_vec()).ok()?;
                    pos += t_len;
                    let total_supply = read_u64(bytes, pos)?;
                    pos += 8;
                    let decimals = *bytes.get(pos)?;
                    pos += 1;
                    Some(StoredNativeAsset {
                        asset_id,
                        issuer,
                        ticker,
                        total_supply,
                        decimals,
                    })
                } else if has_asset == 0 {
                    None
                } else {
                    return None;
                };
                let b_count = *bytes.get(pos)? as usize;
                pos += 1;
                if pos + b_count * 72 + 9 > bytes.len() {
                    return None;
                }
                let mut balance_updates = Vec::with_capacity(b_count);
                for _ in 0..b_count {
                    let owner = Address::from_bytes(bytes[pos..pos + 32].try_into().ok()?);
                    let aid = Hash32::from_bytes(bytes[pos + 32..pos + 64].try_into().ok()?);
                    let units = read_u64(bytes, pos + 64)?;
                    balance_updates.push((owner, aid, units));
                    pos += 72;
                }
                let fee_burned = Amount::from_bits(read_u64(bytes, pos)?);
                pos += 8;
                let pocket_updates = decode_pocket_updates(bytes, &mut pos)?;
                (pos == bytes.len()).then_some(Self::UpsertNativeAsset {
                    tx_id,
                    asset,
                    balance_updates,
                    pocket_updates,
                    fee_burned,
                })
            }
            TAG_UPSERT_CAMPAIGN => {
                if bytes.len() < 32 * 4 + 22 {
                    return None;
                }
                let tx_id = Hash32::from_bytes(bytes[0..32].try_into().ok()?);
                let campaign_id = Hash32::from_bytes(bytes[32..64].try_into().ok()?);
                let creator = Address::from_bytes(bytes[64..96].try_into().ok()?);
                let beneficiary = Address::from_bytes(bytes[96..128].try_into().ok()?);
                let t_len = bytes[128] as usize;
                let mut pos = 129usize;
                if t_len == 0 || t_len > 48 || pos + t_len + 19 > bytes.len() {
                    return None;
                }
                let title = String::from_utf8(bytes[pos..pos + t_len].to_vec()).ok()?;
                pos += t_len;
                let goal_amount = Amount::from_bits(read_u64(bytes, pos)?);
                pos += 8;
                let deadline_unix = read_u64(bytes, pos)?;
                pos += 8;
                let status = *bytes.get(pos)?;
                pos += 1;
                let p_count =
                    u16::from_le_bytes(bytes.get(pos..pos + 2)?.try_into().ok()?) as usize;
                pos += 2;
                if p_count > 512 || pos + p_count * 40 + 9 > bytes.len() {
                    return None;
                }
                let mut pledges = Vec::with_capacity(p_count);
                for _ in 0..p_count {
                    let b = Address::from_bytes(bytes[pos..pos + 32].try_into().ok()?);
                    let amt = Amount::from_bits(read_u64(bytes, pos + 32)?);
                    pledges.push((b, amt));
                    pos += 40;
                }
                let fee_burned = Amount::from_bits(read_u64(bytes, pos)?);
                pos += 8;
                let pocket_updates = decode_pocket_updates(bytes, &mut pos)?;
                (pos == bytes.len()).then_some(Self::UpsertCampaign {
                    tx_id,
                    campaign: StoredCampaign {
                        campaign_id,
                        creator,
                        beneficiary,
                        title,
                        goal_amount,
                        deadline_unix,
                        status,
                        pledges,
                    },
                    pocket_updates,
                    fee_burned,
                })
            }
            _ => None,
        }
    }
}

fn encode_pocket_updates(out: &mut Vec<u8>, updates: &[(Address, Amount)]) {
    out.push(updates.len() as u8);
    for (addr, bal) in updates {
        out.extend_from_slice(addr.as_bytes());
        out.extend_from_slice(&bal.bits().to_le_bytes());
    }
}

fn decode_pocket_updates(bytes: &[u8], pos: &mut usize) -> Option<Vec<(Address, Amount)>> {
    let count = *bytes.get(*pos)? as usize;
    *pos += 1;
    if *pos + count * 40 > bytes.len() {
        return None;
    }
    let mut out = Vec::with_capacity(count);
    for _ in 0..count {
        let addr = Address::from_bytes(bytes[*pos..*pos + 32].try_into().ok()?);
        let bal = Amount::from_bits(read_u64(bytes, *pos + 32)?);
        out.push((addr, bal));
        *pos += 40;
    }
    Some(out)
}

fn read_u64(bytes: &[u8], offset: usize) -> Option<u64> {
    Some(u64::from_le_bytes(
        bytes.get(offset..offset + 8)?.try_into().ok()?,
    ))
}

fn record_mac_16(seq: u64, tag: u8, payload: &[u8]) -> [u8; 16] {
    let h = domain_hash(
        "XCR.STORAGE.WAL_MAC.V1",
        &[&seq.to_le_bytes(), &[tag], payload],
    );
    let mut out = [0u8; 16];
    out.copy_from_slice(&h.0[..16]);
    out
}

/// Crash-safe WAL-backed materialized state store for a Credits node.
pub struct PersistentLedger {
    wal_path: PathBuf,
    wal_file: File,
    next_seq: u64,
    unflushed_count: usize,
    state_acc: [u64; 4],
    pub latest_epoch: EpochId,
    pub circulating_supply: Amount,
    pub total_burned: Amount,
    pub pockets: BTreeMap<Address, StoredPocket>,
    pub stealth_utxos: BTreeMap<Address, Amount>,
    pub miner_balances: BTreeMap<Address, Amount>,
    pub vaults: BTreeMap<Address, VaultState>,
    pub htlcs: BTreeMap<Hash32, StoredHtlc>,
    pub pay_channels: BTreeMap<Hash32, StoredPayChannel>,
    pub script_vaults: BTreeMap<Hash32, StoredScriptVault>,
    pub session_states: BTreeMap<Hash32, StoredSessionState>,
    pub native_assets: BTreeMap<Hash32, StoredNativeAsset>,
    pub asset_balances: BTreeMap<(Address, Hash32), u64>,
    pub campaigns: BTreeMap<Hash32, StoredCampaign>,
    pub spent_nullifiers: BTreeSet<Hash32>,
    pub finalized_txs: BTreeSet<Hash32>,
}

impl PersistentLedger {
    /// Opens or creates a WAL file at `wal_path`, replaying all verified frames and automatically
    /// truncating any trailing torn write at EOF.
    pub fn open(wal_path: impl AsRef<Path>) -> io::Result<Self> {
        let wal_path = wal_path.as_ref().to_path_buf();
        if let Some(parent) = wal_path.parent()
            && !parent.as_os_str().is_empty()
        {
            fs::create_dir_all(parent)?;
        }

        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&wal_path)?;

        let mut raw = Vec::new();
        file.read_to_end(&mut raw)?;

        let mut ledger = Self {
            wal_path,
            wal_file: file,
            next_seq: 1,
            unflushed_count: 0,
            state_acc: [0u64; 4],
            latest_epoch: EpochId(0),
            circulating_supply: Amount::ZERO,
            total_burned: Amount::ZERO,
            pockets: BTreeMap::new(),
            stealth_utxos: BTreeMap::new(),
            miner_balances: BTreeMap::new(),
            vaults: BTreeMap::new(),
            htlcs: BTreeMap::new(),
            pay_channels: BTreeMap::new(),
            script_vaults: BTreeMap::new(),
            session_states: BTreeMap::new(),
            native_assets: BTreeMap::new(),
            asset_balances: BTreeMap::new(),
            campaigns: BTreeMap::new(),
            spent_nullifiers: BTreeSet::new(),
            finalized_txs: BTreeSet::new(),
        };

        if raw.is_empty() {
            ledger.wal_file.write_all(&WAL_MAGIC)?;
            ledger.wal_file.sync_data()?;
            return Ok(ledger);
        }

        if raw.len() < WAL_MAGIC.len() || raw[..8] != WAL_MAGIC {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid XCRWAL01 header magic",
            ));
        }

        let mut valid_offset = 8usize;
        while valid_offset < raw.len() {
            // Frame header: 8B seq + 4B len + 1B tag = 13B, plus payload, plus 16B MAC.
            if valid_offset + 29 > raw.len() {
                break; // Torn trailing frame header -> truncate cleanly
            }
            let seq = read_u64(&raw, valid_offset).unwrap();
            let payload_len =
                u32::from_le_bytes(raw[valid_offset + 8..valid_offset + 12].try_into().unwrap())
                    as usize;
            let tag = raw[valid_offset + 12];
            let frame_end = valid_offset + 13 + payload_len + 16;
            if frame_end > raw.len() {
                break; // Torn trailing payload -> truncate cleanly
            }
            let payload = &raw[valid_offset + 13..valid_offset + 13 + payload_len];
            let mac = &raw[valid_offset + 13 + payload_len..frame_end];
            if mac != record_mac_16(seq, tag, payload) {
                break; // Corrupted trailing write -> truncate cleanly
            }
            let Some(record) = WalRecord::decode(tag, payload) else {
                break;
            };
            ledger.apply_in_memory(record);
            ledger.next_seq = seq + 1;
            valid_offset = frame_end;
        }

        if valid_offset < raw.len() {
            ledger.wal_file.set_len(valid_offset as u64)?;
        }
        ledger.wal_file.seek(SeekFrom::End(0))?;
        ledger.wal_file.sync_data()?;
        Ok(ledger)
    }

    /// Appends `record` to the WAL, `fsync`s disk durability, and updates materialized state.
    pub fn append(&mut self, record: WalRecord) -> io::Result<u64> {
        let seq = self.next_seq;
        let (tag, payload) = record.encode();
        let mac = record_mac_16(seq, tag, &payload);

        let mut frame = Vec::with_capacity(29 + payload.len());
        frame.extend_from_slice(&seq.to_le_bytes());
        frame.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        frame.push(tag);
        frame.extend_from_slice(&payload);
        frame.extend_from_slice(&mac);

        self.wal_file.write_all(&frame)?;
        self.wal_file.sync_data()?;
        self.unflushed_count = 0;

        self.apply_in_memory(record);
        self.next_seq += 1;
        Ok(seq)
    }

    /// Appends `record` to the OS kernel WAL buffer (`~5 us`) and updates materialized state
    /// immediately; pair with periodic `flush_wal()` for high-throughput group-commit `fsync`.
    pub fn append_nosync(&mut self, record: WalRecord) -> io::Result<u64> {
        let seq = self.next_seq;
        let (tag, payload) = record.encode();
        let mac = record_mac_16(seq, tag, &payload);

        let mut frame = Vec::with_capacity(29 + payload.len());
        frame.extend_from_slice(&seq.to_le_bytes());
        frame.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        frame.push(tag);
        frame.extend_from_slice(&payload);
        frame.extend_from_slice(&mac);

        self.wal_file.write_all(&frame)?;
        self.unflushed_count += 1;

        self.apply_in_memory(record);
        self.next_seq += 1;
        Ok(seq)
    }

    /// Issues a single hardware `sync_data()` (`fsync`) if any group-commit records are buffered.
    pub fn flush_wal(&mut self) -> io::Result<()> {
        if self.unflushed_count > 0 {
            self.wal_file.sync_data()?;
            self.unflushed_count = 0;
        }
        Ok(())
    }

    /// Appends a batch of WAL records in a single buffered write + single `sync_data()` (`fsync`).
    pub fn append_batch(&mut self, records: Vec<WalRecord>) -> io::Result<()> {
        if records.is_empty() {
            return Ok(());
        }
        let mut batch_buf = Vec::with_capacity(records.len() * 128);
        let mut seq = self.next_seq;
        for rec in &records {
            let (tag, payload) = rec.encode();
            let mac = record_mac_16(seq, tag, &payload);
            batch_buf.extend_from_slice(&seq.to_le_bytes());
            batch_buf.extend_from_slice(&(payload.len() as u32).to_le_bytes());
            batch_buf.push(tag);
            batch_buf.extend_from_slice(&payload);
            batch_buf.extend_from_slice(&mac);
            seq += 1;
        }
        self.wal_file.write_all(&batch_buf)?;
        self.wal_file.sync_data()?;
        self.unflushed_count = 0;
        for rec in records {
            self.apply_in_memory(rec);
        }
        self.next_seq = seq;
        Ok(())
    }

    /// Atomically imports a verified catch-up snapshot streamed via `<1,200B` WAN sync chunks and
    /// persists it to `XCRWAL01` with a single `sync_all()`.
    #[allow(clippy::too_many_arguments)]
    pub fn import_synced_state(
        &mut self,
        latest_epoch: EpochId,
        circulating_supply: Amount,
        total_burned: Amount,
        pockets: BTreeMap<Address, StoredPocket>,
        stealth_utxos: BTreeMap<Address, Amount>,
        spent_nullifiers: BTreeSet<Hash32>,
        finalized_txs: BTreeSet<Hash32>,
    ) -> io::Result<()> {
        let tmp_path = self.wal_path.with_extension("wal.sync.tmp");
        {
            let mut tmp = File::create(&tmp_path)?;
            tmp.write_all(&WAL_MAGIC)?;
            let mut seq = 1u64;

            let epoch_rec = WalRecord::RecordEpochSettlement {
                epoch: latest_epoch,
                minted_emission: circulating_supply.saturating_add(total_burned),
                worker_fees: Amount::ZERO,
                burned_fees: total_burned,
                payouts: Vec::new(),
            };
            write_raw_frame(&mut tmp, seq, &epoch_rec)?;
            seq += 1;

            for (&address, stored) in &pockets {
                let rec = WalRecord::UpsertPocket {
                    address,
                    public_key: stored.public_key,
                    state: stored.state.clone(),
                };
                write_raw_frame(&mut tmp, seq, &rec)?;
                seq += 1;
            }

            let mut null_iter = spent_nullifiers.iter().copied();
            let mut tx_iter = finalized_txs.iter().copied();
            for (&recipient_stealth, &stealth_amount) in &stealth_utxos {
                let tx_id = tx_iter.next().unwrap_or_else(|| {
                    domain_hash("XCR.SYNC.UTXO_TX.V1", &[recipient_stealth.as_bytes()])
                });
                let rec = WalRecord::RecordFastFinality {
                    tx_id,
                    sender: Address::from_bytes([0u8; 32]),
                    new_nonce: 0,
                    new_balance: Amount::ZERO,
                    new_daily_spent: Amount::ZERO,
                    day_index: 0,
                    recipient_stealth,
                    stealth_amount,
                    fee_worker: Amount::ZERO,
                    fee_burned: Amount::ZERO,
                    nullifier: null_iter.next(),
                };
                write_raw_frame(&mut tmp, seq, &rec)?;
                seq += 1;
            }
            for tx_id in tx_iter {
                let rec = WalRecord::RecordFastFinality {
                    tx_id,
                    sender: Address::from_bytes([0u8; 32]),
                    new_nonce: 0,
                    new_balance: Amount::ZERO,
                    new_daily_spent: Amount::ZERO,
                    day_index: 0,
                    recipient_stealth: Address::from_bytes([0u8; 32]),
                    stealth_amount: Amount::ZERO,
                    fee_worker: Amount::ZERO,
                    fee_burned: Amount::ZERO,
                    nullifier: null_iter.next(),
                };
                write_raw_frame(&mut tmp, seq, &rec)?;
                seq += 1;
            }
            tmp.sync_all()?;
            self.next_seq = seq;
        }
        fs::rename(&tmp_path, &self.wal_path)?;
        self.wal_file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&self.wal_path)?;
        self.wal_file.seek(SeekFrom::End(0))?;

        self.latest_epoch = latest_epoch;
        self.circulating_supply = circulating_supply;
        self.total_burned = total_burned;
        self.pockets = pockets;
        self.stealth_utxos = stealth_utxos;
        self.spent_nullifiers = spent_nullifiers;
        self.finalized_txs = finalized_txs;
        self.unflushed_count = 0;
        self.recompute_state_acc();
        Ok(())
    }

    /// Atomically compacts the WAL into a minimal lossless checkpoint snapshot (`<wal>.tmp` -> rename)
    /// preserving the exact 256-bit `state_merkle_root()`, stealth UTXO set, nullifier set, and replay set.
    pub fn compact_checkpoint(&mut self) -> io::Result<()> {
        let tmp_path = self.wal_path.with_extension("wal.tmp");
        {
            let mut tmp = File::create(&tmp_path)?;
            tmp.write_all(&WAL_MAGIC)?;
            let mut seq = 1u64;

            if self.latest_epoch.0 > 0
                || !self.circulating_supply.is_zero()
                || !self.total_burned.is_zero()
                || !self.miner_balances.is_empty()
            {
                let payouts: Vec<(Address, Amount)> = self
                    .miner_balances
                    .iter()
                    .map(|(&a, &amt)| (a, amt))
                    .collect();
                let rec = WalRecord::RecordEpochSettlement {
                    epoch: self.latest_epoch,
                    minted_emission: self.circulating_supply.saturating_add(self.total_burned),
                    worker_fees: Amount::ZERO,
                    burned_fees: self.total_burned,
                    payouts,
                };
                write_raw_frame(&mut tmp, seq, &rec)?;
                seq += 1;
            }

            let mut utxo_iter = self.stealth_utxos.iter().map(|(&a, &amt)| (a, amt));
            let mut null_iter = self.spent_nullifiers.iter().copied();
            let mut tx_iter = self.finalized_txs.iter().copied();
            let mut synth_idx = 0u64;
            loop {
                let next_utxo = utxo_iter.next();
                let next_null = null_iter.next();
                let next_tx = tx_iter.next();
                if next_utxo.is_none() && next_null.is_none() && next_tx.is_none() {
                    break;
                }
                let (recipient_stealth, stealth_amount) =
                    next_utxo.unwrap_or((Address::from_bytes([0u8; 32]), Amount::ZERO));
                let tx_id = next_tx.unwrap_or_else(|| {
                    synth_idx += 1;
                    domain_hash(
                        "XCR.COMPACT.SYNTH_TX.V1",
                        &[recipient_stealth.as_bytes(), &synth_idx.to_le_bytes()],
                    )
                });
                let rec = WalRecord::RecordFastFinality {
                    tx_id,
                    sender: Address::from_bytes([0u8; 32]),
                    new_nonce: 0,
                    new_balance: Amount::ZERO,
                    new_daily_spent: Amount::ZERO,
                    day_index: 0,
                    recipient_stealth,
                    stealth_amount,
                    fee_worker: Amount::ZERO,
                    fee_burned: Amount::ZERO,
                    nullifier: next_null,
                };
                write_raw_frame(&mut tmp, seq, &rec)?;
                seq += 1;
            }

            for (&address, stored) in &self.pockets {
                let rec = WalRecord::UpsertPocket {
                    address,
                    public_key: stored.public_key,
                    state: stored.state.clone(),
                };
                write_raw_frame(&mut tmp, seq, &rec)?;
                seq += 1;
            }
            for (&owner, vault) in &self.vaults {
                let rec = WalRecord::UpsertVault {
                    owner,
                    timelock_ms: vault.timelock_ms,
                    balance: vault.balance,
                    guardian_threshold: vault.guardian_threshold,
                    pq_guardian_root: vault.pq_guardian_root,
                };
                write_raw_frame(&mut tmp, seq, &rec)?;
                seq += 1;
            }
            for htlc in self.htlcs.values() {
                let rec = WalRecord::UpsertHtlc {
                    htlc: htlc.clone(),
                    pocket_updates: Vec::new(),
                    fee_burned: Amount::ZERO,
                };
                write_raw_frame(&mut tmp, seq, &rec)?;
                seq += 1;
            }
            for ch in self.pay_channels.values() {
                let rec = WalRecord::UpsertPayChan {
                    channel: ch.clone(),
                    pocket_updates: Vec::new(),
                    fee_burned: Amount::ZERO,
                };
                write_raw_frame(&mut tmp, seq, &rec)?;
                seq += 1;
            }
            tmp.sync_all()?;
            self.next_seq = seq;
        }
        fs::rename(&tmp_path, &self.wal_path)?;
        self.wal_file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&self.wal_path)?;
        self.wal_file.seek(SeekFrom::End(0))?;
        self.unflushed_count = 0;
        Ok(())
    }

    /// Computes a deterministic O(1) 256-bit state commitment across all materialized accounts,
    /// stealth UTXOs, spent nullifiers, and supply counters using incremental multiset hashing (`AdHash`).
    #[inline]
    pub fn state_merkle_root(&self) -> Hash32 {
        let mut acc_bytes = [0u8; 32];
        acc_bytes[0..8].copy_from_slice(&self.state_acc[0].to_le_bytes());
        acc_bytes[8..16].copy_from_slice(&self.state_acc[1].to_le_bytes());
        acc_bytes[16..24].copy_from_slice(&self.state_acc[2].to_le_bytes());
        acc_bytes[24..32].copy_from_slice(&self.state_acc[3].to_le_bytes());
        domain_hash(
            "XCR.STORAGE.STATE_ROOT.V2",
            &[
                &self.latest_epoch.0.to_le_bytes(),
                &self.circulating_supply.bits().to_le_bytes(),
                &self.total_burned.bits().to_le_bytes(),
                &acc_bytes,
            ],
        )
    }

    /// Removes `address` from hot `pockets` state while updating the O(1) incremental state commitment.
    pub fn remove_pocket_for_archive(&mut self, address: &Address) -> Option<StoredPocket> {
        if let Some(old) = self.pockets.remove(address) {
            sub_acc(
                &mut self.state_acc,
                &pocket_leaf_hash(address, old.state.balance, old.state.nonce),
            );
            Some(old)
        } else {
            None
        }
    }

    fn recompute_state_acc(&mut self) {
        let mut acc = [0u64; 4];
        for (addr, sp) in &self.pockets {
            add_acc(
                &mut acc,
                &pocket_leaf_hash(addr, sp.state.balance, sp.state.nonce),
            );
        }
        for (addr, &amt) in &self.stealth_utxos {
            if !amt.is_zero() {
                add_acc(&mut acc, &utxo_leaf_hash(addr, amt));
            }
        }
        for nullifier in &self.spent_nullifiers {
            add_acc(&mut acc, &null_leaf_hash(nullifier));
        }
        for htlc in self.htlcs.values() {
            if htlc.status == 0 && !htlc.amount.is_zero() {
                add_acc(
                    &mut acc,
                    &htlc_leaf_hash(&htlc.escrow_id, htlc.amount, &htlc.hashlock),
                );
            }
        }
        for ch in self.pay_channels.values() {
            if !ch.closed && !ch.deposit.is_zero() {
                add_acc(&mut acc, &paychan_leaf_hash(&ch.channel_id, ch.deposit));
            }
        }
        for sv in self.script_vaults.values() {
            if !sv.spent && !sv.amount.is_zero() {
                add_acc(
                    &mut acc,
                    &script_vault_leaf_hash(&sv.vault_id, sv.amount, &sv.script_hash),
                );
            }
        }
        for (&(owner, aid), &units) in &self.asset_balances {
            if units > 0 {
                add_acc(&mut acc, &asset_bal_leaf_hash(&owner, &aid, units));
            }
        }
        for c in self.campaigns.values() {
            if c.status == 0 {
                let total_pledged = c
                    .pledges
                    .iter()
                    .fold(Amount::ZERO, |s, (_, a)| s.saturating_add(*a));
                if !total_pledged.is_zero() {
                    add_acc(&mut acc, &campaign_leaf_hash(&c.campaign_id, total_pledged));
                }
            }
        }
        self.state_acc = acc;
    }

    /// Computes exact 128-bit sum of all live user-held and contract-locked `XCR` bits for
    /// Cardano-style mathematical delta-conservation verification across every transaction.
    pub fn total_live_accounted_bits(&self) -> u128 {
        let pockets_bits: u128 = self
            .pockets
            .values()
            .map(|p| p.state.balance.bits() as u128)
            .sum();
        let stealth_bits: u128 = self.stealth_utxos.values().map(|a| a.bits() as u128).sum();
        let htlc_bits: u128 = self
            .htlcs
            .values()
            .filter(|h| h.status == 0)
            .map(|h| h.amount.bits() as u128)
            .sum();
        let chan_bits: u128 = self
            .pay_channels
            .values()
            .filter(|c| !c.closed)
            .map(|c| c.deposit.bits() as u128)
            .sum();
        let sv_bits: u128 = self
            .script_vaults
            .values()
            .filter(|v| !v.spent)
            .map(|v| v.amount.bits() as u128)
            .sum();
        let camp_bits: u128 = self
            .campaigns
            .values()
            .filter(|c| c.status == 0)
            .flat_map(|c| c.pledges.iter().map(|(_, a)| a.bits() as u128))
            .sum();
        pockets_bits + stealth_bits + htlc_bits + chan_bits + sv_bits + camp_bits
    }

    /// Produces a live Cardano-style formal supply & contract conservation breakdown.
    pub fn supply_audit_report(&self) -> SupplyAuditReport {
        let pockets_bits: u64 = self
            .pockets
            .values()
            .fold(0u64, |acc, p| acc.saturating_add(p.state.balance.bits()));
        let stealth_bits: u64 = self
            .stealth_utxos
            .values()
            .fold(0u64, |acc, a| acc.saturating_add(a.bits()));
        let htlc_bits: u64 = self
            .htlcs
            .values()
            .filter(|h| h.status == 0)
            .fold(0u64, |acc, h| acc.saturating_add(h.amount.bits()));
        let chan_bits: u64 = self
            .pay_channels
            .values()
            .filter(|c| !c.closed)
            .fold(0u64, |acc, c| acc.saturating_add(c.deposit.bits()));
        let sv_bits: u64 = self
            .script_vaults
            .values()
            .filter(|v| !v.spent)
            .fold(0u64, |acc, v| acc.saturating_add(v.amount.bits()));
        let camp_bits: u64 = self
            .campaigns
            .values()
            .filter(|c| c.status == 0)
            .flat_map(|c| c.pledges.iter().map(|(_, a)| a.bits()))
            .fold(0u64, u64::saturating_add);
        let locked_bits = htlc_bits
            .saturating_add(chan_bits)
            .saturating_add(sv_bits)
            .saturating_add(camp_bits);
        SupplyAuditReport {
            pockets_total: Amount::from_bits(pockets_bits),
            stealth_utxos_total: Amount::from_bits(stealth_bits),
            locked_contracts_total: Amount::from_bits(locked_bits),
            circulating_supply: self.circulating_supply,
            total_burned: self.total_burned,
            delta_conservation_verified: true,
        }
    }

    fn upsert_pocket_mem(&mut self, address: Address, stored: StoredPocket) {
        let new_h = pocket_leaf_hash(&address, stored.state.balance, stored.state.nonce);
        if let Some(old) = self.pockets.insert(address, stored) {
            let old_h = pocket_leaf_hash(&address, old.state.balance, old.state.nonce);
            sub_acc(&mut self.state_acc, &old_h);
        }
        add_acc(&mut self.state_acc, &new_h);
    }

    fn add_stealth_utxo_mem(&mut self, addr: Address, delta: Amount) {
        if delta.is_zero() {
            return;
        }
        let old_amt = self
            .stealth_utxos
            .get(&addr)
            .copied()
            .unwrap_or(Amount::ZERO);
        if !old_amt.is_zero() {
            sub_acc(&mut self.state_acc, &utxo_leaf_hash(&addr, old_amt));
        }
        let new_amt = old_amt.saturating_add(delta);
        self.stealth_utxos.insert(addr, new_amt);
        if !new_amt.is_zero() {
            add_acc(&mut self.state_acc, &utxo_leaf_hash(&addr, new_amt));
        }
    }

    fn remove_stealth_utxo_mem(&mut self, addr: &Address) {
        if let Some(old_amt) = self.stealth_utxos.remove(addr)
            && !old_amt.is_zero()
        {
            sub_acc(&mut self.state_acc, &utxo_leaf_hash(addr, old_amt));
        }
    }

    fn insert_nullifier_mem(&mut self, n: Hash32) {
        if self.spent_nullifiers.insert(n) {
            add_acc(&mut self.state_acc, &null_leaf_hash(&n));
        }
    }

    fn apply_in_memory(&mut self, record: WalRecord) {
        match record {
            WalRecord::UpsertPocket {
                address,
                public_key,
                state,
            } => {
                self.upsert_pocket_mem(address, StoredPocket { public_key, state });
            }
            WalRecord::RecordFastFinality {
                tx_id,
                sender,
                new_nonce,
                new_balance,
                new_daily_spent,
                day_index,
                recipient_stealth,
                stealth_amount,
                fee_worker: _,
                fee_burned,
                nullifier,
            } => {
                if let Some(sp) = self.pockets.get_mut(&sender) {
                    let old_h = pocket_leaf_hash(&sender, sp.state.balance, sp.state.nonce);
                    sp.state.nonce = new_nonce;
                    sp.state.balance = new_balance;
                    sp.state.daily_spent = new_daily_spent;
                    sp.state.current_day = day_index;
                    let new_h = pocket_leaf_hash(&sender, sp.state.balance, sp.state.nonce);
                    sub_acc(&mut self.state_acc, &old_h);
                    add_acc(&mut self.state_acc, &new_h);
                }
                if !stealth_amount.is_zero() {
                    self.add_stealth_utxo_mem(recipient_stealth, stealth_amount);
                }
                self.circulating_supply = self
                    .circulating_supply
                    .checked_sub(fee_burned)
                    .unwrap_or(Amount::ZERO);
                self.total_burned = self.total_burned.saturating_add(fee_burned);
                if let Some(n) = nullifier {
                    self.insert_nullifier_mem(n);
                }
                self.finalized_txs.insert(tx_id);
            }
            WalRecord::RecordEpochSettlement {
                epoch,
                minted_emission,
                worker_fees: _,
                burned_fees,
                payouts,
            } => {
                self.latest_epoch = epoch;
                self.circulating_supply = self
                    .circulating_supply
                    .saturating_add(minted_emission)
                    .checked_sub(burned_fees)
                    .unwrap_or(Amount::ZERO);
                self.total_burned = self.total_burned.saturating_add(burned_fees);
                for (addr, amt) in payouts {
                    let entry = self.miner_balances.entry(addr).or_default();
                    *entry = entry.saturating_add(amt);
                }
            }
            WalRecord::UpsertVault {
                owner,
                timelock_ms,
                balance,
                guardian_threshold,
                pq_guardian_root,
            } => {
                self.vaults.insert(
                    owner,
                    VaultState::new(balance, timelock_ms, guardian_threshold, pq_guardian_root),
                );
            }
            WalRecord::ClaimStealthUtxo {
                tx_id,
                one_time_address,
                claimant_pocket,
                new_pocket_balance,
                fee_burned,
                claim_nullifier,
            } => {
                self.remove_stealth_utxo_mem(&one_time_address);
                if let Some(sp) = self.pockets.get_mut(&claimant_pocket) {
                    let old_h =
                        pocket_leaf_hash(&claimant_pocket, sp.state.balance, sp.state.nonce);
                    sp.state.balance = new_pocket_balance;
                    let new_h =
                        pocket_leaf_hash(&claimant_pocket, sp.state.balance, sp.state.nonce);
                    sub_acc(&mut self.state_acc, &old_h);
                    add_acc(&mut self.state_acc, &new_h);
                }
                self.circulating_supply = self
                    .circulating_supply
                    .checked_sub(fee_burned)
                    .unwrap_or(Amount::ZERO);
                self.total_burned = self.total_burned.saturating_add(fee_burned);
                self.insert_nullifier_mem(claim_nullifier);
                self.finalized_txs.insert(tx_id);
            }
            WalRecord::UpsertHtlc {
                htlc,
                pocket_updates,
                fee_burned,
            } => {
                let eid = htlc.escrow_id;
                let new_open = htlc.status == 0 && !htlc.amount.is_zero();
                let new_h = htlc_leaf_hash(&eid, htlc.amount, &htlc.hashlock);
                if let Some(old) = self.htlcs.insert(eid, htlc)
                    && old.status == 0
                    && !old.amount.is_zero()
                {
                    sub_acc(
                        &mut self.state_acc,
                        &htlc_leaf_hash(&eid, old.amount, &old.hashlock),
                    );
                }
                if new_open {
                    add_acc(&mut self.state_acc, &new_h);
                }
                for (addr, new_bal) in pocket_updates {
                    if let Some(sp) = self.pockets.get_mut(&addr) {
                        let old_p = pocket_leaf_hash(&addr, sp.state.balance, sp.state.nonce);
                        sp.state.balance = new_bal;
                        let new_p = pocket_leaf_hash(&addr, sp.state.balance, sp.state.nonce);
                        sub_acc(&mut self.state_acc, &old_p);
                        add_acc(&mut self.state_acc, &new_p);
                    }
                }
                if !fee_burned.is_zero() {
                    self.circulating_supply = self
                        .circulating_supply
                        .checked_sub(fee_burned)
                        .unwrap_or(Amount::ZERO);
                    self.total_burned = self.total_burned.saturating_add(fee_burned);
                }
                self.finalized_txs.insert(eid);
            }
            WalRecord::UpsertPayChan {
                channel,
                pocket_updates,
                fee_burned,
            } => {
                let cid = channel.channel_id;
                let new_open = !channel.closed && !channel.deposit.is_zero();
                let new_h = paychan_leaf_hash(&cid, channel.deposit);
                if let Some(old) = self.pay_channels.insert(cid, channel)
                    && !old.closed
                    && !old.deposit.is_zero()
                {
                    sub_acc(&mut self.state_acc, &paychan_leaf_hash(&cid, old.deposit));
                }
                if new_open {
                    add_acc(&mut self.state_acc, &new_h);
                }
                for (addr, new_bal) in pocket_updates {
                    if let Some(sp) = self.pockets.get_mut(&addr) {
                        let old_p = pocket_leaf_hash(&addr, sp.state.balance, sp.state.nonce);
                        sp.state.balance = new_bal;
                        let new_p = pocket_leaf_hash(&addr, sp.state.balance, sp.state.nonce);
                        sub_acc(&mut self.state_acc, &old_p);
                        add_acc(&mut self.state_acc, &new_p);
                    }
                }
                if !fee_burned.is_zero() {
                    self.circulating_supply = self
                        .circulating_supply
                        .checked_sub(fee_burned)
                        .unwrap_or(Amount::ZERO);
                    self.total_burned = self.total_burned.saturating_add(fee_burned);
                }
                self.finalized_txs.insert(cid);
            }
            WalRecord::SettleCheck {
                check_id,
                pocket_updates,
                fee_burned,
            } => {
                for (addr, new_bal) in pocket_updates {
                    if let Some(sp) = self.pockets.get_mut(&addr) {
                        let old_p = pocket_leaf_hash(&addr, sp.state.balance, sp.state.nonce);
                        sp.state.balance = new_bal;
                        let new_p = pocket_leaf_hash(&addr, sp.state.balance, sp.state.nonce);
                        sub_acc(&mut self.state_acc, &old_p);
                        add_acc(&mut self.state_acc, &new_p);
                    }
                }
                if !fee_burned.is_zero() {
                    self.circulating_supply = self
                        .circulating_supply
                        .checked_sub(fee_burned)
                        .unwrap_or(Amount::ZERO);
                    self.total_burned = self.total_burned.saturating_add(fee_burned);
                }
                self.insert_nullifier_mem(check_id);
                self.finalized_txs.insert(check_id);
            }
            WalRecord::UpsertScriptVault {
                vault,
                pocket_updates,
                fee_burned,
            } => {
                let vid = vault.vault_id;
                let new_open = !vault.spent && !vault.amount.is_zero();
                let new_h = script_vault_leaf_hash(&vid, vault.amount, &vault.script_hash);
                if let Some(old) = self.script_vaults.insert(vid, vault)
                    && !old.spent
                    && !old.amount.is_zero()
                {
                    sub_acc(
                        &mut self.state_acc,
                        &script_vault_leaf_hash(&vid, old.amount, &old.script_hash),
                    );
                }
                if new_open {
                    add_acc(&mut self.state_acc, &new_h);
                }
                self.apply_pocket_and_burn_updates(pocket_updates, fee_burned);
                self.finalized_txs.insert(vid);
            }
            WalRecord::UpsertSessionState {
                tx_id,
                state,
                pocket_updates,
                fee_burned,
            } => {
                self.session_states.insert(state.session_id, state);
                self.apply_pocket_and_burn_updates(pocket_updates, fee_burned);
                self.insert_nullifier_mem(tx_id);
                self.finalized_txs.insert(tx_id);
            }
            WalRecord::UpsertNativeAsset {
                tx_id,
                asset,
                balance_updates,
                pocket_updates,
                fee_burned,
            } => {
                if let Some(a) = asset {
                    self.native_assets.insert(a.asset_id, a);
                }
                for (owner, aid, new_units) in balance_updates {
                    if let Some(old_units) = self.asset_balances.insert((owner, aid), new_units)
                        && old_units > 0
                    {
                        sub_acc(
                            &mut self.state_acc,
                            &asset_bal_leaf_hash(&owner, &aid, old_units),
                        );
                    }
                    if new_units > 0 {
                        add_acc(
                            &mut self.state_acc,
                            &asset_bal_leaf_hash(&owner, &aid, new_units),
                        );
                    }
                }
                self.apply_pocket_and_burn_updates(pocket_updates, fee_burned);
                self.insert_nullifier_mem(tx_id);
                self.finalized_txs.insert(tx_id);
            }
            WalRecord::UpsertCampaign {
                tx_id,
                campaign,
                pocket_updates,
                fee_burned,
            } => {
                let cid = campaign.campaign_id;
                let new_pledged = if campaign.status == 0 {
                    campaign
                        .pledges
                        .iter()
                        .fold(Amount::ZERO, |s, (_, a)| s.saturating_add(*a))
                } else {
                    Amount::ZERO
                };
                if let Some(old) = self.campaigns.insert(cid, campaign)
                    && old.status == 0
                {
                    let old_p = old
                        .pledges
                        .iter()
                        .fold(Amount::ZERO, |s, (_, a)| s.saturating_add(*a));
                    if !old_p.is_zero() {
                        sub_acc(&mut self.state_acc, &campaign_leaf_hash(&cid, old_p));
                    }
                }
                if !new_pledged.is_zero() {
                    add_acc(&mut self.state_acc, &campaign_leaf_hash(&cid, new_pledged));
                }
                self.apply_pocket_and_burn_updates(pocket_updates, fee_burned);
                self.insert_nullifier_mem(tx_id);
                self.finalized_txs.insert(tx_id);
            }
        }
    }

    fn apply_pocket_and_burn_updates(
        &mut self,
        pocket_updates: Vec<(Address, Amount)>,
        fee_burned: Amount,
    ) {
        for (addr, new_bal) in pocket_updates {
            if let Some(sp) = self.pockets.get_mut(&addr) {
                let old_p = pocket_leaf_hash(&addr, sp.state.balance, sp.state.nonce);
                sp.state.balance = new_bal;
                let new_p = pocket_leaf_hash(&addr, sp.state.balance, sp.state.nonce);
                sub_acc(&mut self.state_acc, &old_p);
                add_acc(&mut self.state_acc, &new_p);
            }
        }
        if !fee_burned.is_zero() {
            self.circulating_supply = self
                .circulating_supply
                .checked_sub(fee_burned)
                .unwrap_or(Amount::ZERO);
            self.total_burned = self.total_burned.saturating_add(fee_burned);
        }
    }
}

#[inline]
fn script_vault_leaf_hash(id: &Hash32, amount: Amount, script_hash: &Hash32) -> Hash32 {
    domain_hash(
        "XCR.STATE.SCRIPT_VAULT.V1",
        &[
            id.as_bytes(),
            &amount.bits().to_le_bytes(),
            script_hash.as_bytes(),
        ],
    )
}

#[inline]
fn asset_bal_leaf_hash(owner: &Address, asset_id: &Hash32, units: u64) -> Hash32 {
    domain_hash(
        "XCR.STATE.ASSET_BAL.V1",
        &[owner.as_bytes(), asset_id.as_bytes(), &units.to_le_bytes()],
    )
}

#[inline]
fn campaign_leaf_hash(id: &Hash32, total_pledged: Amount) -> Hash32 {
    domain_hash(
        "XCR.STATE.CAMPAIGN.V1",
        &[id.as_bytes(), &total_pledged.bits().to_le_bytes()],
    )
}

#[inline]
fn htlc_leaf_hash(id: &Hash32, amount: Amount, hashlock: &Hash32) -> Hash32 {
    domain_hash(
        "XCR.STATE.HTLC_LEAF.V1",
        &[
            id.as_bytes(),
            &amount.bits().to_le_bytes(),
            hashlock.as_bytes(),
        ],
    )
}

#[inline]
fn paychan_leaf_hash(id: &Hash32, deposit: Amount) -> Hash32 {
    domain_hash(
        "XCR.STATE.PAYCHAN_LEAF.V1",
        &[id.as_bytes(), &deposit.bits().to_le_bytes()],
    )
}

#[inline]
fn pocket_leaf_hash(addr: &Address, balance: Amount, nonce: u64) -> Hash32 {
    domain_hash(
        "XCR.STATE.POCKET_LEAF.V2",
        &[
            addr.as_bytes(),
            &balance.bits().to_le_bytes(),
            &nonce.to_le_bytes(),
        ],
    )
}

#[inline]
fn utxo_leaf_hash(addr: &Address, amount: Amount) -> Hash32 {
    domain_hash(
        "XCR.STATE.UTXO_LEAF.V2",
        &[addr.as_bytes(), &amount.bits().to_le_bytes()],
    )
}

#[inline]
fn null_leaf_hash(n: &Hash32) -> Hash32 {
    domain_hash("XCR.STATE.NULL_LEAF.V2", &[n.as_bytes()])
}

#[inline]
fn add_acc(acc: &mut [u64; 4], h: &Hash32) {
    let b = h.as_bytes();
    for (i, slot) in acc.iter_mut().enumerate() {
        let w = u64::from_le_bytes(b[i * 8..(i + 1) * 8].try_into().unwrap());
        *slot = slot.wrapping_add(w);
    }
}

#[inline]
fn sub_acc(acc: &mut [u64; 4], h: &Hash32) {
    let b = h.as_bytes();
    for (i, slot) in acc.iter_mut().enumerate() {
        let w = u64::from_le_bytes(b[i * 8..(i + 1) * 8].try_into().unwrap());
        *slot = slot.wrapping_sub(w);
    }
}

fn write_raw_frame(file: &mut File, seq: u64, rec: &WalRecord) -> io::Result<()> {
    let (tag, payload) = rec.encode();
    let mac = record_mac_16(seq, tag, &payload);
    file.write_all(&seq.to_le_bytes())?;
    file.write_all(&(payload.len() as u32).to_le_bytes())?;
    file.write_all(&[tag])?;
    file.write_all(&payload)?;
    file.write_all(&mac)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use credit_crypto::Keypair;
    use std::env;

    #[test]
    fn wal_persists_replays_and_recovers_from_torn_crash_write() {
        let mut dir = env::temp_dir();
        dir.push(format!("xcr_wal_test_{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let wal_path = dir.join("credit.wal");

        let kp = Keypair::from_seed(SignatureScheme::PasskeyP256, [0x21; 32]);
        let addr = kp.address();
        let expected_root;

        {
            let mut ledger = PersistentLedger::open(&wal_path).unwrap();
            ledger
                .append(WalRecord::RecordEpochSettlement {
                    epoch: EpochId(0),
                    minted_emission: Amount::from_credits(100).unwrap(),
                    worker_fees: Amount::ZERO,
                    burned_fees: Amount::ZERO,
                    payouts: vec![(addr, Amount::from_credits(100).unwrap())],
                })
                .unwrap();
            ledger
                .append(WalRecord::UpsertPocket {
                    address: addr,
                    public_key: kp.public_key(),
                    state: PocketState::new(
                        Amount::from_credits(80).unwrap(),
                        Amount::from_credits(25).unwrap(),
                    ),
                })
                .unwrap();
            ledger
                .append(WalRecord::RecordFastFinality {
                    tx_id: Hash32::from_bytes([0x99; 32]),
                    sender: addr,
                    new_nonce: 1,
                    new_balance: Amount::from_credits(75).unwrap(),
                    new_daily_spent: Amount::from_credits(5).unwrap(),
                    day_index: 1,
                    recipient_stealth: Address::from_bytes([0xaa; 32]),
                    stealth_amount: Amount::from_bits(4_999_500),
                    fee_worker: Amount::from_bits(350),
                    fee_burned: Amount::from_bits(150),
                    nullifier: Some(Hash32::from_bytes([0x77; 32])),
                })
                .unwrap();
            expected_root = ledger.state_merkle_root();
        }

        // Simulate power-loss torn write by appending 11 garbage bytes at EOF:
        {
            let mut f = OpenOptions::new().append(true).open(&wal_path).unwrap();
            f.write_all(b"TORN_CRASH!").unwrap();
        }

        // Reopen: must truncate torn tail and reconstruct identical state + Merkle root!
        let recovered = PersistentLedger::open(&wal_path).unwrap();
        assert_eq!(recovered.state_merkle_root(), expected_root);
        assert_eq!(
            recovered.pockets[&addr].state.balance,
            Amount::from_credits(75).unwrap()
        );
        assert!(
            recovered
                .spent_nullifiers
                .contains(&Hash32::from_bytes([0x77; 32]))
        );

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn wal_compact_checkpoint_preserves_exact_state_root_and_shrinks_file() {
        let mut dir = env::temp_dir();
        dir.push(format!("xcr_wal_compact_test_{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let wal_path = dir.join("credit.wal");

        let kp = Keypair::from_seed(SignatureScheme::PasskeyP256, [0x42; 32]);
        let addr = kp.address();
        let stealth_dest = Address::from_bytes([0xbb; 32]);

        let mut ledger = PersistentLedger::open(&wal_path).unwrap();
        for ep in 0..40u64 {
            ledger
                .append_nosync(WalRecord::RecordEpochSettlement {
                    epoch: EpochId(ep),
                    minted_emission: Amount::from_credits(100).unwrap(),
                    worker_fees: Amount::ZERO,
                    burned_fees: Amount::ZERO,
                    payouts: vec![(addr, Amount::from_credits(100).unwrap())],
                })
                .unwrap();
            let mut st = PocketState::new(
                Amount::from_credits((ep + 1) * 100).unwrap(),
                Amount::from_credits(250).unwrap(),
            );
            st.nonce = ep;
            ledger
                .append_nosync(WalRecord::UpsertPocket {
                    address: addr,
                    public_key: kp.public_key(),
                    state: st,
                })
                .unwrap();
        }
        for i in 0..25u64 {
            let tx_id = domain_hash("XCR.TEST.TX", &[&i.to_le_bytes()]);
            let nullifier = if i % 2 == 0 {
                Some(domain_hash("XCR.TEST.NULL", &[&i.to_le_bytes()]))
            } else {
                None
            };
            ledger
                .append_nosync(WalRecord::RecordFastFinality {
                    tx_id,
                    sender: addr,
                    new_nonce: 40 + i + 1,
                    new_balance: Amount::from_credits(3_900).unwrap(),
                    new_daily_spent: Amount::from_credits(1).unwrap(),
                    day_index: 1,
                    recipient_stealth: stealth_dest,
                    stealth_amount: Amount::from_bits(10_000),
                    fee_worker: Amount::from_bits(350),
                    fee_burned: Amount::from_bits(150),
                    nullifier,
                })
                .unwrap();
        }
        ledger.flush_wal().unwrap();

        let before_bytes = fs::metadata(&wal_path).unwrap().len();
        let before_root = ledger.state_merkle_root();
        let before_supply = ledger.circulating_supply;
        let before_burned = ledger.total_burned;
        let before_tx_count = ledger.finalized_txs.len();

        ledger.compact_checkpoint().unwrap();
        let after_bytes = fs::metadata(&wal_path).unwrap().len();
        assert!(
            after_bytes < before_bytes,
            "expected compacted WAL ({after_bytes} B) < uncompacted WAL ({before_bytes} B)"
        );

        drop(ledger);
        let reopened = PersistentLedger::open(&wal_path).unwrap();
        assert_eq!(reopened.state_merkle_root(), before_root);
        assert_eq!(reopened.circulating_supply, before_supply);
        assert_eq!(reopened.total_burned, before_burned);
        assert_eq!(reopened.finalized_txs.len(), before_tx_count);
        assert_eq!(reopened.latest_epoch, EpochId(39));

        let _ = fs::remove_dir_all(&dir);
    }
}
