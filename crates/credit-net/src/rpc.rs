//! Binary Client <-> Daemon RPC Codec over `UdpQuicEndpoint` (`XQ01` + `XCR1` framing).

use std::io;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

use credit_crypto::{PublicKey, SignatureScheme};
use credit_types::{Address, Amount, EpochId, Hash32, Transaction, TransactionKind};

use crate::{ChannelTag, UdpQuicEndpoint, WireFrame};

/// Requests sent from `credit-cli` (or wallet SDKs) to a running `credit-node daemon`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum NodeRpcRequest {
    GetStatus,
    RegisterPocket {
        address: Address,
        public_key: PublicKey,
        grant_from_miner: Amount,
        daily_limit: Amount,
    },
    GetPocket {
        address: Address,
    },
    SubmitBulletproofFastPay {
        tx: Transaction,
        value_commitment: [u8; 32],
        bulletproof_672: Vec<u8>,
    },
    GetLightAccountProof {
        address: Address,
    },
    ShutdownDaemon,
    UnlockMainnetGenesis {
        btc_block_hash_hex: String,
        public_headline: String,
    },
    AnnounceStealthOutput {
        one_time_address: Address,
        ephemeral_pub: [u8; 32],
        view_tag: u8,
    },
    GetStealthOutputs,
    ClaimStealthUtxo {
        one_time_address: Address,
        claimant_pocket: Address,
        claimant_pubkey: PublicKey,
        spend_pub: [u8; 32],
        kdf: [u8; 32],
        schnorr_sig64: [u8; 64],
    },
    GetNetworkTelemetry,
    AnnounceStealthOutputV2 {
        one_time_address: Address,
        ephemeral_pub: [u8; 32],
        view_tag: u8,
        encrypted_memo: Vec<u8>,
    },
    GetStealthOutputsV2,
    InspectQuery {
        query: String,
    },
    LockHtlc {
        escrow_id: Hash32,
        sender: Address,
        sender_pubkey: PublicKey,
        recipient: Address,
        amount: Amount,
        fee: Amount,
        hashlock: Hash32,
        expiry_unix: u64,
        salt: [u8; 16],
        sig65: [u8; 65],
    },
    ClaimHtlc {
        escrow_id: Hash32,
        preimage: [u8; 32],
    },
    RefundHtlc {
        escrow_id: Hash32,
    },
    GetHtlcs,
    OpenPayChannel {
        channel_id: Hash32,
        payer: Address,
        payer_pubkey: PublicKey,
        payee: Address,
        deposit: Amount,
        fee: Amount,
        expiry_unix: u64,
        salt: [u8; 16],
        sig65: [u8; 65],
    },
    ClosePayChannel {
        channel_id: Hash32,
        cumulative_amount: Amount,
        voucher_sig65: [u8; 65],
    },
    GetPayChannels,
    CashOrCancelCheck {
        is_cancel: bool,
        check_bytes: Vec<u8>,
        check_id: Hash32,
        actor_pubkey: PublicKey,
        actual_amount: Amount,
        actor_sig65: [u8; 65],
    },
    PostSwapOffer {
        offer_bytes: Vec<u8>,
    },
    GetSwapOffers,
}

/// Wire tuple for an HTLC record: `(escrow_id, sender, recipient, amount, hashlock, expiry_unix, status, revealed_preimage)`.
pub type HtlcWireRecord = (
    Hash32,
    Address,
    Address,
    Amount,
    Hash32,
    u64,
    u8,
    Option<[u8; 32]>,
);

/// Wire tuple for a PayChan record: `(channel_id, payer, payer_pubkey, payee, deposit, expiry_unix, closed, settled_amount)`.
pub type PayChanWireRecord = (
    Hash32,
    Address,
    PublicKey,
    Address,
    Amount,
    u64,
    bool,
    Amount,
);

/// V2 stealth output record carrying `(one_time_address, amount, ephemeral_pub, view_tag, encrypted_memo)`.
pub type StealthOutputRecordV2 = (Address, Amount, [u8; 32], u8, Vec<u8>);

/// Responses returned by `credit-node daemon` in 1 UDP round-trip.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum NodeRpcResponse {
    Status {
        epoch: EpochId,
        circulating_supply: Amount,
        total_burned: Amount,
        finalized_tx_count: u64,
        state_root: Hash32,
        validator_address: Address,
    },
    PocketInfo {
        found: bool,
        balance: Amount,
        nonce: u64,
        daily_limit: Amount,
    },
    FastPayReceipt {
        accepted: bool,
        tx_id: Hash32,
        finality_latency_ms: u16,
        fee_worker: Amount,
        fee_burned: Amount,
        new_state_root: Hash32,
        message: String,
    },
    LightAccountProof {
        found: bool,
        authenticated_root: Hash32,
        balance: Amount,
        nonce: u64,
        inclusion_proof_bytes: Vec<u8>,
    },
    AckShutdown,
    Error(String),
    GenesisUnlocked {
        unlocked: bool,
        active_epoch: EpochId,
        epoch0_seed: Hash32,
        message: String,
    },
    AckStealthAnnounce,
    StealthOutputs {
        outputs: Vec<(Address, Amount, [u8; 32], u8)>,
    },
    StealthClaimReceipt {
        accepted: bool,
        claimed_amount: Amount,
        fee_burned: Amount,
        new_pocket_balance: Amount,
        new_state_root: Hash32,
        message: String,
    },
    NetworkTelemetry {
        epoch: EpochId,
        circulating_supply: Amount,
        total_burned: Amount,
        finalized_tx_count: u64,
        state_root: Hash32,
        validator_address: Address,
        connected_peers: u32,
        active_miners: u32,
    },
    StealthOutputsV2 {
        outputs: Vec<StealthOutputRecordV2>,
    },
    InspectResult {
        kind: u8,
        target_hex: String,
        address: Address,
        balance: Amount,
        nonce: u64,
        epoch: EpochId,
        authenticated_root: Hash32,
        inclusion_proof_bytes: Vec<u8>,
    },
    ContractReceipt {
        accepted: bool,
        contract_id: Hash32,
        amount: Amount,
        new_state_root: Hash32,
        message: String,
    },
    HtlcList {
        escrows: Vec<HtlcWireRecord>,
    },
    PayChannelList {
        channels: Vec<PayChanWireRecord>,
    },
    SwapOfferList {
        offers: Vec<Vec<u8>>,
    },
}

impl NodeRpcRequest {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        match self {
            Self::GetStatus => out.push(1),
            Self::RegisterPocket {
                address,
                public_key,
                grant_from_miner,
                daily_limit,
            } => {
                out.push(2);
                out.extend_from_slice(address.as_bytes());
                out.push(public_key.scheme as u8);
                out.extend_from_slice(public_key.merkle_root.as_bytes());
                out.extend_from_slice(&grant_from_miner.bits().to_le_bytes());
                out.extend_from_slice(&daily_limit.bits().to_le_bytes());
            }
            Self::GetPocket { address } => {
                out.push(3);
                out.extend_from_slice(address.as_bytes());
            }
            Self::SubmitBulletproofFastPay {
                tx,
                value_commitment,
                bulletproof_672,
            } => {
                let TransactionKind::FastTransfer {
                    from,
                    to_stealth,
                    stealth_view_tag,
                    amount,
                    fee,
                    nonce,
                    commitment,
                    innocence_nullifier,
                } = &tx.kind
                else {
                    panic!("SubmitBulletproofFastPay requires FastTransfer");
                };
                out.push(4);
                out.extend_from_slice(tx.id.as_bytes());
                out.extend_from_slice(from.as_bytes());
                out.extend_from_slice(to_stealth.as_bytes());
                out.push(*stealth_view_tag);
                out.extend_from_slice(&amount.bits().to_le_bytes());
                out.extend_from_slice(&fee.bits().to_le_bytes());
                out.extend_from_slice(&nonce.to_le_bytes());
                out.extend_from_slice(commitment.as_bytes());
                match innocence_nullifier {
                    Some(n) => {
                        out.push(1);
                        out.extend_from_slice(n.as_bytes());
                    }
                    None => out.push(0),
                }
                push_bytes(&mut out, &tx.signature_bytes);
                out.extend_from_slice(value_commitment);
                push_bytes(&mut out, bulletproof_672);
            }
            Self::ShutdownDaemon => out.push(5),
            Self::GetLightAccountProof { address } => {
                out.push(6);
                out.extend_from_slice(address.as_bytes());
            }
            Self::UnlockMainnetGenesis {
                btc_block_hash_hex,
                public_headline,
            } => {
                out.push(7);
                push_bytes(&mut out, btc_block_hash_hex.as_bytes());
                push_bytes(&mut out, public_headline.as_bytes());
            }
            Self::AnnounceStealthOutput {
                one_time_address,
                ephemeral_pub,
                view_tag,
            } => {
                out.push(8);
                out.extend_from_slice(one_time_address.as_bytes());
                out.extend_from_slice(ephemeral_pub);
                out.push(*view_tag);
            }
            Self::GetStealthOutputs => out.push(9),
            Self::ClaimStealthUtxo {
                one_time_address,
                claimant_pocket,
                claimant_pubkey,
                spend_pub,
                kdf,
                schnorr_sig64,
            } => {
                out.push(10);
                out.extend_from_slice(one_time_address.as_bytes());
                out.extend_from_slice(claimant_pocket.as_bytes());
                out.push(claimant_pubkey.scheme as u8);
                out.extend_from_slice(claimant_pubkey.merkle_root.as_bytes());
                out.extend_from_slice(spend_pub);
                out.extend_from_slice(kdf);
                out.extend_from_slice(schnorr_sig64);
            }
            Self::GetNetworkTelemetry => out.push(11),
            Self::AnnounceStealthOutputV2 {
                one_time_address,
                ephemeral_pub,
                view_tag,
                encrypted_memo,
            } => {
                out.push(12);
                out.extend_from_slice(one_time_address.as_bytes());
                out.extend_from_slice(ephemeral_pub);
                out.push(*view_tag);
                push_bytes(&mut out, encrypted_memo);
            }
            Self::GetStealthOutputsV2 => out.push(13),
            Self::InspectQuery { query } => {
                out.push(14);
                push_bytes(&mut out, query.as_bytes());
            }
            Self::LockHtlc {
                escrow_id,
                sender,
                sender_pubkey,
                recipient,
                amount,
                fee,
                hashlock,
                expiry_unix,
                salt,
                sig65,
            } => {
                out.push(15);
                out.extend_from_slice(escrow_id.as_bytes());
                out.extend_from_slice(sender.as_bytes());
                out.push(sender_pubkey.scheme as u8);
                out.extend_from_slice(sender_pubkey.merkle_root.as_bytes());
                out.extend_from_slice(recipient.as_bytes());
                out.extend_from_slice(&amount.bits().to_le_bytes());
                out.extend_from_slice(&fee.bits().to_le_bytes());
                out.extend_from_slice(hashlock.as_bytes());
                out.extend_from_slice(&expiry_unix.to_le_bytes());
                out.extend_from_slice(salt);
                out.extend_from_slice(sig65);
            }
            Self::ClaimHtlc {
                escrow_id,
                preimage,
            } => {
                out.push(16);
                out.extend_from_slice(escrow_id.as_bytes());
                out.extend_from_slice(preimage);
            }
            Self::RefundHtlc { escrow_id } => {
                out.push(17);
                out.extend_from_slice(escrow_id.as_bytes());
            }
            Self::GetHtlcs => out.push(18),
            Self::OpenPayChannel {
                channel_id,
                payer,
                payer_pubkey,
                payee,
                deposit,
                fee,
                expiry_unix,
                salt,
                sig65,
            } => {
                out.push(19);
                out.extend_from_slice(channel_id.as_bytes());
                out.extend_from_slice(payer.as_bytes());
                out.push(payer_pubkey.scheme as u8);
                out.extend_from_slice(payer_pubkey.merkle_root.as_bytes());
                out.extend_from_slice(payee.as_bytes());
                out.extend_from_slice(&deposit.bits().to_le_bytes());
                out.extend_from_slice(&fee.bits().to_le_bytes());
                out.extend_from_slice(&expiry_unix.to_le_bytes());
                out.extend_from_slice(salt);
                out.extend_from_slice(sig65);
            }
            Self::ClosePayChannel {
                channel_id,
                cumulative_amount,
                voucher_sig65,
            } => {
                out.push(20);
                out.extend_from_slice(channel_id.as_bytes());
                out.extend_from_slice(&cumulative_amount.bits().to_le_bytes());
                out.extend_from_slice(voucher_sig65);
            }
            Self::GetPayChannels => out.push(21),
            Self::CashOrCancelCheck {
                is_cancel,
                check_bytes,
                check_id,
                actor_pubkey,
                actual_amount,
                actor_sig65,
            } => {
                out.push(22);
                out.push(*is_cancel as u8);
                push_bytes(&mut out, check_bytes);
                out.extend_from_slice(check_id.as_bytes());
                out.push(actor_pubkey.scheme as u8);
                out.extend_from_slice(actor_pubkey.merkle_root.as_bytes());
                out.extend_from_slice(&actual_amount.bits().to_le_bytes());
                out.extend_from_slice(actor_sig65);
            }
            Self::PostSwapOffer { offer_bytes } => {
                out.push(23);
                push_bytes(&mut out, offer_bytes);
            }
            Self::GetSwapOffers => out.push(24),
        }
        out
    }

    pub fn decode(bytes: &[u8]) -> Option<Self> {
        let &tag = bytes.first()?;
        let mut pos = 1usize;
        match tag {
            1 if bytes.len() == 1 => Some(Self::GetStatus),
            2 => {
                let address = Address::from_bytes(take32(bytes, &mut pos)?);
                let scheme = SignatureScheme::from_u8(*bytes.get(pos)?)?;
                pos += 1;
                let merkle_root = Hash32::from_bytes(take32(bytes, &mut pos)?);
                let grant_from_miner = Amount::from_bits(take_u64(bytes, &mut pos)?);
                let daily_limit = Amount::from_bits(take_u64(bytes, &mut pos)?);
                if pos != bytes.len() {
                    return None;
                }
                Some(Self::RegisterPocket {
                    address,
                    public_key: PublicKey {
                        scheme,
                        merkle_root,
                    },
                    grant_from_miner,
                    daily_limit,
                })
            }
            3 => {
                let address = Address::from_bytes(take32(bytes, &mut pos)?);
                if pos != bytes.len() {
                    return None;
                }
                Some(Self::GetPocket { address })
            }
            4 => {
                let id = Hash32::from_bytes(take32(bytes, &mut pos)?);
                let from = Address::from_bytes(take32(bytes, &mut pos)?);
                let to_stealth = Address::from_bytes(take32(bytes, &mut pos)?);
                let stealth_view_tag = *bytes.get(pos)?;
                pos += 1;
                let amount = Amount::from_bits(take_u64(bytes, &mut pos)?);
                let fee = Amount::from_bits(take_u64(bytes, &mut pos)?);
                let nonce = take_u64(bytes, &mut pos)?;
                let commitment = Hash32::from_bytes(take32(bytes, &mut pos)?);
                let has_null = *bytes.get(pos)?;
                pos += 1;
                let innocence_nullifier = if has_null == 1 {
                    Some(Hash32::from_bytes(take32(bytes, &mut pos)?))
                } else if has_null == 0 {
                    None
                } else {
                    return None;
                };
                let signature_bytes = take_bytes(bytes, &mut pos)?;
                let value_commitment = take32(bytes, &mut pos)?;
                let bulletproof_672 = take_bytes(bytes, &mut pos)?;
                if pos != bytes.len() {
                    return None;
                }
                Some(Self::SubmitBulletproofFastPay {
                    tx: Transaction {
                        id,
                        kind: TransactionKind::FastTransfer {
                            from,
                            to_stealth,
                            stealth_view_tag,
                            amount,
                            fee,
                            nonce,
                            commitment,
                            innocence_nullifier,
                        },
                        signature_bytes,
                    },
                    value_commitment,
                    bulletproof_672,
                })
            }
            5 if bytes.len() == 1 => Some(Self::ShutdownDaemon),
            6 => {
                let address = Address::from_bytes(take32(bytes, &mut pos)?);
                if pos != bytes.len() {
                    return None;
                }
                Some(Self::GetLightAccountProof { address })
            }
            7 => {
                let b_hex = String::from_utf8(take_bytes(bytes, &mut pos)?).ok()?;
                let headline = String::from_utf8(take_bytes(bytes, &mut pos)?).ok()?;
                if pos != bytes.len() || b_hex.len() > 256 || headline.len() > 512 {
                    return None;
                }
                Some(Self::UnlockMainnetGenesis {
                    btc_block_hash_hex: b_hex,
                    public_headline: headline,
                })
            }
            8 => {
                let one_time_address = Address::from_bytes(take32(bytes, &mut pos)?);
                let ephemeral_pub = take32(bytes, &mut pos)?;
                let view_tag = *bytes.get(pos)?;
                pos += 1;
                if pos != bytes.len() {
                    return None;
                }
                Some(Self::AnnounceStealthOutput {
                    one_time_address,
                    ephemeral_pub,
                    view_tag,
                })
            }
            9 if bytes.len() == 1 => Some(Self::GetStealthOutputs),
            10 => {
                let one_time_address = Address::from_bytes(take32(bytes, &mut pos)?);
                let claimant_pocket = Address::from_bytes(take32(bytes, &mut pos)?);
                let scheme = SignatureScheme::from_u8(*bytes.get(pos)?)?;
                pos += 1;
                let merkle_root = Hash32::from_bytes(take32(bytes, &mut pos)?);
                let spend_pub = take32(bytes, &mut pos)?;
                let kdf = take32(bytes, &mut pos)?;
                let sig_lo = take32(bytes, &mut pos)?;
                let sig_hi = take32(bytes, &mut pos)?;
                if pos != bytes.len() {
                    return None;
                }
                let mut schnorr_sig64 = [0u8; 64];
                schnorr_sig64[..32].copy_from_slice(&sig_lo);
                schnorr_sig64[32..].copy_from_slice(&sig_hi);
                Some(Self::ClaimStealthUtxo {
                    one_time_address,
                    claimant_pocket,
                    claimant_pubkey: PublicKey {
                        scheme,
                        merkle_root,
                    },
                    spend_pub,
                    kdf,
                    schnorr_sig64,
                })
            }
            11 if bytes.len() == 1 => Some(Self::GetNetworkTelemetry),
            12 => {
                let one_time_address = Address::from_bytes(take32(bytes, &mut pos)?);
                let ephemeral_pub = take32(bytes, &mut pos)?;
                let view_tag = *bytes.get(pos)?;
                pos += 1;
                let encrypted_memo = take_bytes(bytes, &mut pos)?;
                if pos != bytes.len() || encrypted_memo.len() > 80 {
                    return None;
                }
                Some(Self::AnnounceStealthOutputV2 {
                    one_time_address,
                    ephemeral_pub,
                    view_tag,
                    encrypted_memo,
                })
            }
            13 if bytes.len() == 1 => Some(Self::GetStealthOutputsV2),
            14 => {
                let q = String::from_utf8(take_bytes(bytes, &mut pos)?).ok()?;
                if pos != bytes.len() || q.len() > 160 {
                    return None;
                }
                Some(Self::InspectQuery { query: q })
            }
            15 => {
                let escrow_id = Hash32::from_bytes(take32(bytes, &mut pos)?);
                let sender = Address::from_bytes(take32(bytes, &mut pos)?);
                let scheme = SignatureScheme::from_u8(*bytes.get(pos)?)?;
                pos += 1;
                let merkle_root = Hash32::from_bytes(take32(bytes, &mut pos)?);
                let recipient = Address::from_bytes(take32(bytes, &mut pos)?);
                let amount = Amount::from_bits(take_u64(bytes, &mut pos)?);
                let fee = Amount::from_bits(take_u64(bytes, &mut pos)?);
                let hashlock = Hash32::from_bytes(take32(bytes, &mut pos)?);
                let expiry_unix = take_u64(bytes, &mut pos)?;
                let salt_s = bytes.get(pos..pos + 16)?;
                pos += 16;
                let sig_s = bytes.get(pos..pos + 65)?;
                pos += 65;
                if pos != bytes.len() {
                    return None;
                }
                let mut salt = [0u8; 16];
                salt.copy_from_slice(salt_s);
                let mut sig65 = [0u8; 65];
                sig65.copy_from_slice(sig_s);
                Some(Self::LockHtlc {
                    escrow_id,
                    sender,
                    sender_pubkey: PublicKey {
                        scheme,
                        merkle_root,
                    },
                    recipient,
                    amount,
                    fee,
                    hashlock,
                    expiry_unix,
                    salt,
                    sig65,
                })
            }
            16 => {
                let escrow_id = Hash32::from_bytes(take32(bytes, &mut pos)?);
                let preimage = take32(bytes, &mut pos)?;
                if pos != bytes.len() {
                    return None;
                }
                Some(Self::ClaimHtlc {
                    escrow_id,
                    preimage,
                })
            }
            17 => {
                let escrow_id = Hash32::from_bytes(take32(bytes, &mut pos)?);
                if pos != bytes.len() {
                    return None;
                }
                Some(Self::RefundHtlc { escrow_id })
            }
            18 if bytes.len() == 1 => Some(Self::GetHtlcs),
            19 => {
                let channel_id = Hash32::from_bytes(take32(bytes, &mut pos)?);
                let payer = Address::from_bytes(take32(bytes, &mut pos)?);
                let scheme = SignatureScheme::from_u8(*bytes.get(pos)?)?;
                pos += 1;
                let merkle_root = Hash32::from_bytes(take32(bytes, &mut pos)?);
                let payee = Address::from_bytes(take32(bytes, &mut pos)?);
                let deposit = Amount::from_bits(take_u64(bytes, &mut pos)?);
                let fee = Amount::from_bits(take_u64(bytes, &mut pos)?);
                let expiry_unix = take_u64(bytes, &mut pos)?;
                let salt_s = bytes.get(pos..pos + 16)?;
                pos += 16;
                let sig_s = bytes.get(pos..pos + 65)?;
                pos += 65;
                if pos != bytes.len() {
                    return None;
                }
                let mut salt = [0u8; 16];
                salt.copy_from_slice(salt_s);
                let mut sig65 = [0u8; 65];
                sig65.copy_from_slice(sig_s);
                Some(Self::OpenPayChannel {
                    channel_id,
                    payer,
                    payer_pubkey: PublicKey {
                        scheme,
                        merkle_root,
                    },
                    payee,
                    deposit,
                    fee,
                    expiry_unix,
                    salt,
                    sig65,
                })
            }
            20 => {
                let channel_id = Hash32::from_bytes(take32(bytes, &mut pos)?);
                let cumulative_amount = Amount::from_bits(take_u64(bytes, &mut pos)?);
                let sig_s = bytes.get(pos..pos + 65)?;
                pos += 65;
                if pos != bytes.len() {
                    return None;
                }
                let mut voucher_sig65 = [0u8; 65];
                voucher_sig65.copy_from_slice(sig_s);
                Some(Self::ClosePayChannel {
                    channel_id,
                    cumulative_amount,
                    voucher_sig65,
                })
            }
            21 if bytes.len() == 1 => Some(Self::GetPayChannels),
            22 => {
                let is_cancel = *bytes.get(pos)? != 0;
                pos += 1;
                let check_bytes = take_bytes(bytes, &mut pos)?;
                if check_bytes.len() > 300 {
                    return None;
                }
                let check_id = Hash32::from_bytes(take32(bytes, &mut pos)?);
                let scheme = SignatureScheme::from_u8(*bytes.get(pos)?)?;
                pos += 1;
                let merkle_root = Hash32::from_bytes(take32(bytes, &mut pos)?);
                let actual_amount = Amount::from_bits(take_u64(bytes, &mut pos)?);
                let sig_s = bytes.get(pos..pos + 65)?;
                pos += 65;
                if pos != bytes.len() {
                    return None;
                }
                let mut actor_sig65 = [0u8; 65];
                actor_sig65.copy_from_slice(sig_s);
                Some(Self::CashOrCancelCheck {
                    is_cancel,
                    check_bytes,
                    check_id,
                    actor_pubkey: PublicKey {
                        scheme,
                        merkle_root,
                    },
                    actual_amount,
                    actor_sig65,
                })
            }
            23 => {
                let offer_bytes = take_bytes(bytes, &mut pos)?;
                if pos != bytes.len() || offer_bytes.is_empty() || offer_bytes.len() > 360 {
                    return None;
                }
                Some(Self::PostSwapOffer { offer_bytes })
            }
            24 if bytes.len() == 1 => Some(Self::GetSwapOffers),
            _ => None,
        }
    }
}

impl NodeRpcResponse {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        match self {
            Self::Status {
                epoch,
                circulating_supply,
                total_burned,
                finalized_tx_count,
                state_root,
                validator_address,
            } => {
                out.push(1);
                out.extend_from_slice(&epoch.0.to_le_bytes());
                out.extend_from_slice(&circulating_supply.bits().to_le_bytes());
                out.extend_from_slice(&total_burned.bits().to_le_bytes());
                out.extend_from_slice(&finalized_tx_count.to_le_bytes());
                out.extend_from_slice(state_root.as_bytes());
                out.extend_from_slice(validator_address.as_bytes());
            }
            Self::PocketInfo {
                found,
                balance,
                nonce,
                daily_limit,
            } => {
                out.push(2);
                out.push(*found as u8);
                out.extend_from_slice(&balance.bits().to_le_bytes());
                out.extend_from_slice(&nonce.to_le_bytes());
                out.extend_from_slice(&daily_limit.bits().to_le_bytes());
            }
            Self::FastPayReceipt {
                accepted,
                tx_id,
                finality_latency_ms,
                fee_worker,
                fee_burned,
                new_state_root,
                message,
            } => {
                out.push(3);
                out.push(*accepted as u8);
                out.extend_from_slice(tx_id.as_bytes());
                out.extend_from_slice(&finality_latency_ms.to_le_bytes());
                out.extend_from_slice(&fee_worker.bits().to_le_bytes());
                out.extend_from_slice(&fee_burned.bits().to_le_bytes());
                out.extend_from_slice(new_state_root.as_bytes());
                push_bytes(&mut out, message.as_bytes());
            }
            Self::AckShutdown => out.push(4),
            Self::Error(msg) => {
                out.push(5);
                push_bytes(&mut out, msg.as_bytes());
            }
            Self::LightAccountProof {
                found,
                authenticated_root,
                balance,
                nonce,
                inclusion_proof_bytes,
            } => {
                out.push(6);
                out.push(*found as u8);
                out.extend_from_slice(authenticated_root.as_bytes());
                out.extend_from_slice(&balance.bits().to_le_bytes());
                out.extend_from_slice(&nonce.to_le_bytes());
                push_bytes(&mut out, inclusion_proof_bytes);
            }
            Self::GenesisUnlocked {
                unlocked,
                active_epoch,
                epoch0_seed,
                message,
            } => {
                out.push(7);
                out.push(*unlocked as u8);
                out.extend_from_slice(&active_epoch.0.to_le_bytes());
                out.extend_from_slice(epoch0_seed.as_bytes());
                push_bytes(&mut out, message.as_bytes());
            }
            Self::AckStealthAnnounce => out.push(8),
            Self::StealthOutputs { outputs } => {
                out.push(9);
                out.extend_from_slice(&(outputs.len() as u32).to_le_bytes());
                for (addr, amt, eph, vt) in outputs {
                    out.extend_from_slice(addr.as_bytes());
                    out.extend_from_slice(&amt.bits().to_le_bytes());
                    out.extend_from_slice(eph);
                    out.push(*vt);
                }
            }
            Self::StealthClaimReceipt {
                accepted,
                claimed_amount,
                fee_burned,
                new_pocket_balance,
                new_state_root,
                message,
            } => {
                out.push(10);
                out.push(*accepted as u8);
                out.extend_from_slice(&claimed_amount.bits().to_le_bytes());
                out.extend_from_slice(&fee_burned.bits().to_le_bytes());
                out.extend_from_slice(&new_pocket_balance.bits().to_le_bytes());
                out.extend_from_slice(new_state_root.as_bytes());
                push_bytes(&mut out, message.as_bytes());
            }
            Self::NetworkTelemetry {
                epoch,
                circulating_supply,
                total_burned,
                finalized_tx_count,
                state_root,
                validator_address,
                connected_peers,
                active_miners,
            } => {
                out.push(11);
                out.extend_from_slice(&epoch.0.to_le_bytes());
                out.extend_from_slice(&circulating_supply.bits().to_le_bytes());
                out.extend_from_slice(&total_burned.bits().to_le_bytes());
                out.extend_from_slice(&finalized_tx_count.to_le_bytes());
                out.extend_from_slice(state_root.as_bytes());
                out.extend_from_slice(validator_address.as_bytes());
                out.extend_from_slice(&connected_peers.to_le_bytes());
                out.extend_from_slice(&active_miners.to_le_bytes());
            }
            Self::StealthOutputsV2 { outputs } => {
                out.push(12);
                out.extend_from_slice(&(outputs.len() as u32).to_le_bytes());
                for (addr, amt, eph, vt, memo) in outputs {
                    out.extend_from_slice(addr.as_bytes());
                    out.extend_from_slice(&amt.bits().to_le_bytes());
                    out.extend_from_slice(eph);
                    out.push(*vt);
                    push_bytes(&mut out, memo);
                }
            }
            Self::InspectResult {
                kind,
                target_hex,
                address,
                balance,
                nonce,
                epoch,
                authenticated_root,
                inclusion_proof_bytes,
            } => {
                out.push(13);
                out.push(*kind);
                push_bytes(&mut out, target_hex.as_bytes());
                out.extend_from_slice(address.as_bytes());
                out.extend_from_slice(&balance.bits().to_le_bytes());
                out.extend_from_slice(&nonce.to_le_bytes());
                out.extend_from_slice(&epoch.0.to_le_bytes());
                out.extend_from_slice(authenticated_root.as_bytes());
                push_bytes(&mut out, inclusion_proof_bytes);
            }
            Self::ContractReceipt {
                accepted,
                contract_id,
                amount,
                new_state_root,
                message,
            } => {
                out.push(14);
                out.push(*accepted as u8);
                out.extend_from_slice(contract_id.as_bytes());
                out.extend_from_slice(&amount.bits().to_le_bytes());
                out.extend_from_slice(new_state_root.as_bytes());
                push_bytes(&mut out, message.as_bytes());
            }
            Self::HtlcList { escrows } => {
                out.push(15);
                out.extend_from_slice(&(escrows.len() as u32).to_le_bytes());
                for (id, snd, rcv, amt, hl, exp, st, pre) in escrows {
                    out.extend_from_slice(id.as_bytes());
                    out.extend_from_slice(snd.as_bytes());
                    out.extend_from_slice(rcv.as_bytes());
                    out.extend_from_slice(&amt.bits().to_le_bytes());
                    out.extend_from_slice(hl.as_bytes());
                    out.extend_from_slice(&exp.to_le_bytes());
                    out.push(*st);
                    match pre {
                        Some(p) => {
                            out.push(1);
                            out.extend_from_slice(p);
                        }
                        None => out.push(0),
                    }
                }
            }
            Self::PayChannelList { channels } => {
                out.push(16);
                out.extend_from_slice(&(channels.len() as u32).to_le_bytes());
                for (cid, payer, pk, payee, dep, exp, closed, settled) in channels {
                    out.extend_from_slice(cid.as_bytes());
                    out.extend_from_slice(payer.as_bytes());
                    out.push(pk.scheme as u8);
                    out.extend_from_slice(pk.merkle_root.as_bytes());
                    out.extend_from_slice(payee.as_bytes());
                    out.extend_from_slice(&dep.bits().to_le_bytes());
                    out.extend_from_slice(&exp.to_le_bytes());
                    out.push(*closed as u8);
                    out.extend_from_slice(&settled.bits().to_le_bytes());
                }
            }
            Self::SwapOfferList { offers } => {
                out.push(17);
                out.extend_from_slice(&(offers.len() as u32).to_le_bytes());
                for raw in offers {
                    push_bytes(&mut out, raw);
                }
            }
        }
        out
    }

    pub fn decode(bytes: &[u8]) -> Option<Self> {
        let &tag = bytes.first()?;
        let mut pos = 1usize;
        match tag {
            1 => {
                let epoch = EpochId(take_u64(bytes, &mut pos)?);
                let circulating_supply = Amount::from_bits(take_u64(bytes, &mut pos)?);
                let total_burned = Amount::from_bits(take_u64(bytes, &mut pos)?);
                let finalized_tx_count = take_u64(bytes, &mut pos)?;
                let state_root = Hash32::from_bytes(take32(bytes, &mut pos)?);
                let validator_address = Address::from_bytes(take32(bytes, &mut pos)?);
                if pos != bytes.len() {
                    return None;
                }
                Some(Self::Status {
                    epoch,
                    circulating_supply,
                    total_burned,
                    finalized_tx_count,
                    state_root,
                    validator_address,
                })
            }
            2 => {
                let found = *bytes.get(pos)? != 0;
                pos += 1;
                let balance = Amount::from_bits(take_u64(bytes, &mut pos)?);
                let nonce = take_u64(bytes, &mut pos)?;
                let daily_limit = Amount::from_bits(take_u64(bytes, &mut pos)?);
                if pos != bytes.len() {
                    return None;
                }
                Some(Self::PocketInfo {
                    found,
                    balance,
                    nonce,
                    daily_limit,
                })
            }
            3 => {
                let accepted = *bytes.get(pos)? != 0;
                pos += 1;
                let tx_id = Hash32::from_bytes(take32(bytes, &mut pos)?);
                let finality_latency_ms =
                    u16::from_le_bytes(bytes.get(pos..pos + 2)?.try_into().ok()?);
                pos += 2;
                let fee_worker = Amount::from_bits(take_u64(bytes, &mut pos)?);
                let fee_burned = Amount::from_bits(take_u64(bytes, &mut pos)?);
                let new_state_root = Hash32::from_bytes(take32(bytes, &mut pos)?);
                let msg_bytes = take_bytes(bytes, &mut pos)?;
                if pos != bytes.len() {
                    return None;
                }
                let message = String::from_utf8(msg_bytes).ok()?;
                Some(Self::FastPayReceipt {
                    accepted,
                    tx_id,
                    finality_latency_ms,
                    fee_worker,
                    fee_burned,
                    new_state_root,
                    message,
                })
            }
            4 if bytes.len() == 1 => Some(Self::AckShutdown),
            5 => {
                let msg_bytes = take_bytes(bytes, &mut pos)?;
                if pos != bytes.len() {
                    return None;
                }
                Some(Self::Error(String::from_utf8(msg_bytes).ok()?))
            }
            6 => {
                let found = *bytes.get(pos)? != 0;
                pos += 1;
                let authenticated_root = Hash32::from_bytes(take32(bytes, &mut pos)?);
                let balance = Amount::from_bits(take_u64(bytes, &mut pos)?);
                let nonce = take_u64(bytes, &mut pos)?;
                let inclusion_proof_bytes = take_bytes(bytes, &mut pos)?;
                if pos != bytes.len() {
                    return None;
                }
                Some(Self::LightAccountProof {
                    found,
                    authenticated_root,
                    balance,
                    nonce,
                    inclusion_proof_bytes,
                })
            }
            7 => {
                let unlocked = *bytes.get(pos)? != 0;
                pos += 1;
                let active_epoch = EpochId(take_u64(bytes, &mut pos)?);
                let epoch0_seed = Hash32::from_bytes(take32(bytes, &mut pos)?);
                let message = String::from_utf8(take_bytes(bytes, &mut pos)?).ok()?;
                if pos != bytes.len() {
                    return None;
                }
                Some(Self::GenesisUnlocked {
                    unlocked,
                    active_epoch,
                    epoch0_seed,
                    message,
                })
            }
            8 if bytes.len() == 1 => Some(Self::AckStealthAnnounce),
            9 => {
                let count_slice = bytes.get(pos..pos + 4)?;
                pos += 4;
                let count = u32::from_le_bytes(count_slice.try_into().ok()?) as usize;
                if count > 64 {
                    return None;
                }
                let mut outputs = Vec::with_capacity(count);
                for _ in 0..count {
                    let addr = Address::from_bytes(take32(bytes, &mut pos)?);
                    let amt = Amount::from_bits(take_u64(bytes, &mut pos)?);
                    let eph = take32(bytes, &mut pos)?;
                    let vt = *bytes.get(pos)?;
                    pos += 1;
                    outputs.push((addr, amt, eph, vt));
                }
                if pos != bytes.len() {
                    return None;
                }
                Some(Self::StealthOutputs { outputs })
            }
            10 => {
                let accepted = *bytes.get(pos)? != 0;
                pos += 1;
                let claimed_amount = Amount::from_bits(take_u64(bytes, &mut pos)?);
                let fee_burned = Amount::from_bits(take_u64(bytes, &mut pos)?);
                let new_pocket_balance = Amount::from_bits(take_u64(bytes, &mut pos)?);
                let new_state_root = Hash32::from_bytes(take32(bytes, &mut pos)?);
                let message = String::from_utf8(take_bytes(bytes, &mut pos)?).ok()?;
                if pos != bytes.len() {
                    return None;
                }
                Some(Self::StealthClaimReceipt {
                    accepted,
                    claimed_amount,
                    fee_burned,
                    new_pocket_balance,
                    new_state_root,
                    message,
                })
            }
            11 => {
                let epoch = EpochId(take_u64(bytes, &mut pos)?);
                let circulating_supply = Amount::from_bits(take_u64(bytes, &mut pos)?);
                let total_burned = Amount::from_bits(take_u64(bytes, &mut pos)?);
                let finalized_tx_count = take_u64(bytes, &mut pos)?;
                let state_root = Hash32::from_bytes(take32(bytes, &mut pos)?);
                let validator_address = Address::from_bytes(take32(bytes, &mut pos)?);
                let cp_slice = bytes.get(pos..pos + 4)?;
                pos += 4;
                let am_slice = bytes.get(pos..pos + 4)?;
                pos += 4;
                if pos != bytes.len() {
                    return None;
                }
                let connected_peers = u32::from_le_bytes(cp_slice.try_into().ok()?);
                let active_miners = u32::from_le_bytes(am_slice.try_into().ok()?);
                Some(Self::NetworkTelemetry {
                    epoch,
                    circulating_supply,
                    total_burned,
                    finalized_tx_count,
                    state_root,
                    validator_address,
                    connected_peers,
                    active_miners,
                })
            }
            12 => {
                let count_slice = bytes.get(pos..pos + 4)?;
                pos += 4;
                let count = u32::from_le_bytes(count_slice.try_into().ok()?) as usize;
                if count > 64 {
                    return None;
                }
                let mut outputs = Vec::with_capacity(count);
                for _ in 0..count {
                    let addr = Address::from_bytes(take32(bytes, &mut pos)?);
                    let amt = Amount::from_bits(take_u64(bytes, &mut pos)?);
                    let eph = take32(bytes, &mut pos)?;
                    let vt = *bytes.get(pos)?;
                    pos += 1;
                    let memo = take_bytes(bytes, &mut pos)?;
                    if memo.len() > 80 {
                        return None;
                    }
                    outputs.push((addr, amt, eph, vt, memo));
                }
                if pos != bytes.len() {
                    return None;
                }
                Some(Self::StealthOutputsV2 { outputs })
            }
            13 => {
                let kind = *bytes.get(pos)?;
                pos += 1;
                let target_hex = String::from_utf8(take_bytes(bytes, &mut pos)?).ok()?;
                let address = Address::from_bytes(take32(bytes, &mut pos)?);
                let balance = Amount::from_bits(take_u64(bytes, &mut pos)?);
                let nonce = take_u64(bytes, &mut pos)?;
                let epoch = EpochId(take_u64(bytes, &mut pos)?);
                let authenticated_root = Hash32::from_bytes(take32(bytes, &mut pos)?);
                let inclusion_proof_bytes = take_bytes(bytes, &mut pos)?;
                if pos != bytes.len()
                    || target_hex.len() > 160
                    || inclusion_proof_bytes.len() > 1024
                {
                    return None;
                }
                Some(Self::InspectResult {
                    kind,
                    target_hex,
                    address,
                    balance,
                    nonce,
                    epoch,
                    authenticated_root,
                    inclusion_proof_bytes,
                })
            }
            14 => {
                let accepted = *bytes.get(pos)? != 0;
                pos += 1;
                let contract_id = Hash32::from_bytes(take32(bytes, &mut pos)?);
                let amount = Amount::from_bits(take_u64(bytes, &mut pos)?);
                let new_state_root = Hash32::from_bytes(take32(bytes, &mut pos)?);
                let message = String::from_utf8(take_bytes(bytes, &mut pos)?).ok()?;
                if pos != bytes.len() {
                    return None;
                }
                Some(Self::ContractReceipt {
                    accepted,
                    contract_id,
                    amount,
                    new_state_root,
                    message,
                })
            }
            15 => {
                let count_s = bytes.get(pos..pos + 4)?;
                pos += 4;
                let count = u32::from_le_bytes(count_s.try_into().ok()?) as usize;
                if count > 64 {
                    return None;
                }
                let mut escrows = Vec::with_capacity(count);
                for _ in 0..count {
                    let id = Hash32::from_bytes(take32(bytes, &mut pos)?);
                    let snd = Address::from_bytes(take32(bytes, &mut pos)?);
                    let rcv = Address::from_bytes(take32(bytes, &mut pos)?);
                    let amt = Amount::from_bits(take_u64(bytes, &mut pos)?);
                    let hl = Hash32::from_bytes(take32(bytes, &mut pos)?);
                    let exp = take_u64(bytes, &mut pos)?;
                    let st = *bytes.get(pos)?;
                    pos += 1;
                    let has_pre = *bytes.get(pos)?;
                    pos += 1;
                    let pre = if has_pre == 1 {
                        Some(take32(bytes, &mut pos)?)
                    } else if has_pre == 0 {
                        None
                    } else {
                        return None;
                    };
                    escrows.push((id, snd, rcv, amt, hl, exp, st, pre));
                }
                if pos != bytes.len() {
                    return None;
                }
                Some(Self::HtlcList { escrows })
            }
            16 => {
                let count_s = bytes.get(pos..pos + 4)?;
                pos += 4;
                let count = u32::from_le_bytes(count_s.try_into().ok()?) as usize;
                if count > 64 {
                    return None;
                }
                let mut channels = Vec::with_capacity(count);
                for _ in 0..count {
                    let cid = Hash32::from_bytes(take32(bytes, &mut pos)?);
                    let payer = Address::from_bytes(take32(bytes, &mut pos)?);
                    let scheme = SignatureScheme::from_u8(*bytes.get(pos)?)?;
                    pos += 1;
                    let merkle_root = Hash32::from_bytes(take32(bytes, &mut pos)?);
                    let payee = Address::from_bytes(take32(bytes, &mut pos)?);
                    let dep = Amount::from_bits(take_u64(bytes, &mut pos)?);
                    let exp = take_u64(bytes, &mut pos)?;
                    let closed = *bytes.get(pos)? != 0;
                    pos += 1;
                    let settled = Amount::from_bits(take_u64(bytes, &mut pos)?);
                    channels.push((
                        cid,
                        payer,
                        PublicKey {
                            scheme,
                            merkle_root,
                        },
                        payee,
                        dep,
                        exp,
                        closed,
                        settled,
                    ));
                }
                if pos != bytes.len() {
                    return None;
                }
                Some(Self::PayChannelList { channels })
            }
            17 => {
                let count_s = bytes.get(pos..pos + 4)?;
                pos += 4;
                let count = u32::from_le_bytes(count_s.try_into().ok()?) as usize;
                if count > 64 {
                    return None;
                }
                let mut offers = Vec::with_capacity(count);
                for _ in 0..count {
                    let raw = take_bytes(bytes, &mut pos)?;
                    if raw.len() > 360 {
                        return None;
                    }
                    offers.push(raw);
                }
                if pos != bytes.len() {
                    return None;
                }
                Some(Self::SwapOfferList { offers })
            }
            _ => None,
        }
    }
}

/// Persistent reusable UDP RPC channel avoiding per-request kernel socket `bind`/`close` syscalls
/// and matching transaction receipts by `tx.id` so late retry datagrams never cross streams.
pub struct PersistentRpcChannel {
    ep: UdpQuicEndpoint,
    node_addr: SocketAddr,
}

impl PersistentRpcChannel {
    pub fn connect(node_addr: SocketAddr) -> io::Result<Self> {
        let local_bind: SocketAddr = match node_addr {
            SocketAddr::V4(v4) if v4.ip().is_loopback() => "127.0.0.1:0".parse().unwrap(),
            SocketAddr::V4(_) => "0.0.0.0:0".parse().unwrap(),
            SocketAddr::V6(v6) if v6.ip().is_loopback() => "[::1]:0".parse().unwrap(),
            SocketAddr::V6(_) => "[::]:0".parse().unwrap(),
        };
        let attempt_timeout = if node_addr.ip().is_loopback() {
            Duration::from_millis(600)
        } else {
            Duration::from_millis(1_800)
        };
        let ep = UdpQuicEndpoint::bind(local_bind, 0xc11e_0002, attempt_timeout)?;
        Ok(Self { ep, node_addr })
    }

    pub fn call(
        &mut self,
        request: &NodeRpcRequest,
        timeout: Duration,
    ) -> io::Result<NodeRpcResponse> {
        let frame = WireFrame {
            channel: ChannelTag::ClientRpcRequest,
            payload: request.encode(),
        };
        let deadline = Instant::now() + timeout;
        let mut need_send = true;
        loop {
            if need_send {
                self.ep.send_1rtt_datagram(self.node_addr, &frame)?;
            }
            match self.ep.recv_packet() {
                Ok((_, pkt)) => {
                    let Some(resp_frame) = pkt.frame else {
                        need_send = false;
                        continue;
                    };
                    if resp_frame.channel != ChannelTag::ClientRpcResponse {
                        need_send = false;
                        continue;
                    }
                    let Some(decoded) = NodeRpcResponse::decode(&resp_frame.payload) else {
                        need_send = false;
                        continue;
                    };
                    // Discard any late duplicate receipt from an earlier transaction on this persistent socket:
                    if let (
                        NodeRpcRequest::SubmitBulletproofFastPay { tx, .. },
                        NodeRpcResponse::FastPayReceipt { tx_id, .. },
                    ) = (request, &decoded)
                        && tx.id != *tx_id
                    {
                        need_send = false;
                        continue;
                    }
                    return Ok(decoded);
                }
                Err(e)
                    if (e.kind() == io::ErrorKind::TimedOut
                        || e.kind() == io::ErrorKind::WouldBlock)
                        && Instant::now() < deadline =>
                {
                    need_send = true;
                    continue;
                }
                Err(e) => return Err(e),
            }
        }
    }
}

/// Sends a 1-RTT UDP RPC request to `node_addr` with automatic idempotent packet-loss retry.
pub fn rpc_call(
    node_addr: SocketAddr,
    request: &NodeRpcRequest,
    timeout: Duration,
) -> io::Result<NodeRpcResponse> {
    let local_bind: SocketAddr = match node_addr {
        SocketAddr::V4(v4) if v4.ip().is_loopback() => "127.0.0.1:0".parse().unwrap(),
        SocketAddr::V4(_) => "0.0.0.0:0".parse().unwrap(),
        SocketAddr::V6(v6) if v6.ip().is_loopback() => "[::1]:0".parse().unwrap(),
        SocketAddr::V6(_) => "[::]:0".parse().unwrap(),
    };
    let attempt_timeout = if node_addr.ip().is_loopback() {
        timeout.min(Duration::from_millis(600))
    } else {
        timeout.min(Duration::from_millis(1_800))
    };
    let mut ep = UdpQuicEndpoint::bind(local_bind, 0xc11e_0001, attempt_timeout)?;
    let frame = WireFrame {
        channel: ChannelTag::ClientRpcRequest,
        payload: request.encode(),
    };
    let deadline = Instant::now() + timeout;
    loop {
        ep.send_1rtt_datagram(node_addr, &frame)?;
        match ep.recv_packet() {
            Ok((_, pkt)) => {
                let Some(resp_frame) = pkt.frame else {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "missing RPC response frame",
                    ));
                };
                if resp_frame.channel != ChannelTag::ClientRpcResponse {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "unexpected channel tag on RPC reply",
                    ));
                }
                return NodeRpcResponse::decode(&resp_frame.payload).ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidData, "malformed RPC reply payload")
                });
            }
            Err(e)
                if (e.kind() == io::ErrorKind::TimedOut
                    || e.kind() == io::ErrorKind::WouldBlock)
                    && Instant::now() < deadline =>
            {
                continue;
            }
            Err(e) => return Err(e),
        }
    }
}

fn push_bytes(out: &mut Vec<u8>, data: &[u8]) {
    out.extend_from_slice(&(data.len() as u32).to_le_bytes());
    out.extend_from_slice(data);
}

fn take32(bytes: &[u8], pos: &mut usize) -> Option<[u8; 32]> {
    let slice = bytes.get(*pos..*pos + 32)?;
    *pos += 32;
    slice.try_into().ok()
}

fn take_u64(bytes: &[u8], pos: &mut usize) -> Option<u64> {
    let slice = bytes.get(*pos..*pos + 8)?;
    *pos += 8;
    Some(u64::from_le_bytes(slice.try_into().ok()?))
}

fn take_bytes(bytes: &[u8], pos: &mut usize) -> Option<Vec<u8>> {
    let len_slice = bytes.get(*pos..*pos + 4)?;
    *pos += 4;
    let len = u32::from_le_bytes(len_slice.try_into().ok()?) as usize;
    let data = bytes.get(*pos..*pos + len)?.to_vec();
    *pos += len;
    Some(data)
}
