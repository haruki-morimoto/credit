//! Stage-1 **Encrypted P2P Mesh Wire Protocol (`P2pHandshakePacket`, `SyncItem` & `P2pMessage`)**.
//!
//! Carries Kademlia DHT peer exchange, STUN external address reflection, UDP hole-punching
//! rendezvous signals, continuous multi-epoch PoNC Share-DAG gossip & canonical `EpochSeal`s,
//! 1-RTT distributed validator quorum votes, finality broadcasts, and **`<= 1,200-byte` MTU-safe
//! paged WAN state sync (`SyncChunkRequest` / `SyncChunkResponse`)** inside AEAD `SessionCipher`s.

use std::net::SocketAddr;

use credit_crypto::{HandshakeInit, HandshakeResp, PublicKey, SignatureScheme};
use credit_ponc::{ComputeShare, WorkProof};
use credit_types::{Address, Amount, EpochId, Hash32, PocketState, Transaction, TransactionKind};

use crate::dht::{PeerDescriptor, decode_socket_addr, encode_socket_addr};

/// Maximum plaintext byte budget packed into a single `SyncChunkResponse` (`900 B`), ensuring the
/// encrypted AEAD + `XQ01` UDP datagram remains strictly `< 1,100 bytes` (`< 1,200 B` WAN/VPN MTU).
pub const MAX_WAN_SYNC_CHUNK_BYTES: usize = 900;

/// Unencrypted outer control packets carried on `ChannelTag::P2pHandshake`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum P2pHandshakePacket {
    Init(HandshakeInit),
    Resp(HandshakeResp),
    /// Simultaneous outbound NAT pinhole opener sent prior to `Init`.
    HolePunchProbe {
        sender: Address,
    },
}

impl P2pHandshakePacket {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        match self {
            Self::Init(init) => {
                out.push(1);
                out.extend_from_slice(&init.to_bytes());
            }
            Self::Resp(resp) => {
                out.push(2);
                out.extend_from_slice(&resp.to_bytes());
            }
            Self::HolePunchProbe { sender } => {
                out.push(3);
                out.extend_from_slice(sender.as_bytes());
            }
        }
        out
    }

    pub fn decode(bytes: &[u8]) -> Option<Self> {
        let &tag = bytes.first()?;
        let body = &bytes[1..];
        match tag {
            1 => Some(Self::Init(HandshakeInit::from_bytes(body)?)),
            2 => Some(Self::Resp(HandshakeResp::from_bytes(body)?)),
            3 if body.len() == 32 => Some(Self::HolePunchProbe {
                sender: Address::from_bytes(body.try_into().ok()?),
            }),
            _ => None,
        }
    }
}

/// Individual bounded state item (`<= 240 bytes` each) streamed across `<1,200B` WAN sync pages.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SyncItem {
    Header {
        active_epoch: EpochId,
        settled_epoch: EpochId,
        active_epoch_seed: Hash32,
        circulating_supply: Amount,
        total_burned: Amount,
        endurance_balance: Amount,
        unsettled_fee_bits: i64,
    },
    CommitteeMember {
        address: Address,
        public_key: PublicKey,
        weight: u64,
    },
    ActiveShare {
        share: ComputeShare,
        author_pubkey: PublicKey,
        reward_pubkey: PublicKey,
    },
    Pocket {
        address: Address,
        public_key: PublicKey,
        state: PocketState,
    },
    StealthUtxo {
        address: Address,
        amount: Amount,
    },
    SpentNullifier(Hash32),
    FinalizedTx(Hash32),
}

impl SyncItem {
    pub fn encode_into(&self, out: &mut Vec<u8>) {
        match self {
            Self::Header {
                active_epoch,
                settled_epoch,
                active_epoch_seed,
                circulating_supply,
                total_burned,
                endurance_balance,
                unsettled_fee_bits,
            } => {
                out.push(1);
                out.extend_from_slice(&active_epoch.0.to_le_bytes());
                out.extend_from_slice(&settled_epoch.0.to_le_bytes());
                out.extend_from_slice(active_epoch_seed.as_bytes());
                out.extend_from_slice(&circulating_supply.bits().to_le_bytes());
                out.extend_from_slice(&total_burned.bits().to_le_bytes());
                out.extend_from_slice(&endurance_balance.bits().to_le_bytes());
                out.extend_from_slice(&unsettled_fee_bits.to_le_bytes());
            }
            Self::CommitteeMember {
                address,
                public_key,
                weight,
            } => {
                out.push(2);
                out.extend_from_slice(address.as_bytes());
                encode_pubkey(public_key, out);
                out.extend_from_slice(&weight.to_le_bytes());
            }
            Self::ActiveShare {
                share,
                author_pubkey,
                reward_pubkey,
            } => {
                out.push(3);
                encode_share(share, out);
                encode_pubkey(author_pubkey, out);
                encode_pubkey(reward_pubkey, out);
            }
            Self::Pocket {
                address,
                public_key,
                state,
            } => {
                out.push(4);
                out.extend_from_slice(address.as_bytes());
                encode_pubkey(public_key, out);
                out.extend_from_slice(&state.balance.bits().to_le_bytes());
                out.extend_from_slice(&state.nonce.to_le_bytes());
                out.extend_from_slice(&state.daily_spent.bits().to_le_bytes());
                out.extend_from_slice(&state.daily_limit.bits().to_le_bytes());
                out.extend_from_slice(&state.current_day.to_le_bytes());
            }
            Self::StealthUtxo { address, amount } => {
                out.push(5);
                out.extend_from_slice(address.as_bytes());
                out.extend_from_slice(&amount.bits().to_le_bytes());
            }
            Self::SpentNullifier(h) => {
                out.push(6);
                out.extend_from_slice(h.as_bytes());
            }
            Self::FinalizedTx(h) => {
                out.push(7);
                out.extend_from_slice(h.as_bytes());
            }
        }
    }

    pub fn encoded_len(&self) -> usize {
        let mut scratch = Vec::with_capacity(240);
        self.encode_into(&mut scratch);
        scratch.len()
    }

    pub fn decode_from(bytes: &[u8], pos: &mut usize) -> Option<Self> {
        let tag = *bytes.get(*pos)?;
        *pos += 1;
        match tag {
            1 => Some(Self::Header {
                active_epoch: EpochId(take_u64(bytes, pos)?),
                settled_epoch: EpochId(take_u64(bytes, pos)?),
                active_epoch_seed: Hash32::from_bytes(take32(bytes, pos)?),
                circulating_supply: Amount::from_bits(take_u64(bytes, pos)?),
                total_burned: Amount::from_bits(take_u64(bytes, pos)?),
                endurance_balance: Amount::from_bits(take_u64(bytes, pos)?),
                unsettled_fee_bits: take_u64(bytes, pos)? as i64,
            }),
            2 => Some(Self::CommitteeMember {
                address: Address::from_bytes(take32(bytes, pos)?),
                public_key: decode_pubkey(bytes, pos)?,
                weight: take_u64(bytes, pos)?,
            }),
            3 => Some(Self::ActiveShare {
                share: decode_share(bytes, pos)?,
                author_pubkey: decode_pubkey(bytes, pos)?,
                reward_pubkey: decode_pubkey(bytes, pos)?,
            }),
            4 => {
                let address = Address::from_bytes(take32(bytes, pos)?);
                let public_key = decode_pubkey(bytes, pos)?;
                let balance = Amount::from_bits(take_u64(bytes, pos)?);
                let nonce = take_u64(bytes, pos)?;
                let daily_spent = Amount::from_bits(take_u64(bytes, pos)?);
                let daily_limit = Amount::from_bits(take_u64(bytes, pos)?);
                let current_day = take_u64(bytes, pos)?;
                Some(Self::Pocket {
                    address,
                    public_key,
                    state: PocketState {
                        balance,
                        nonce,
                        daily_spent,
                        daily_limit,
                        current_day,
                    },
                })
            }
            5 => Some(Self::StealthUtxo {
                address: Address::from_bytes(take32(bytes, pos)?),
                amount: Amount::from_bits(take_u64(bytes, pos)?),
            }),
            6 => Some(Self::SpentNullifier(Hash32::from_bytes(take32(
                bytes, pos,
            )?))),
            7 => Some(Self::FinalizedTx(Hash32::from_bytes(take32(bytes, pos)?))),
            _ => None,
        }
    }
}

/// Packs as many `SyncItem`s starting from `start_index` as fit inside `MAX_WAN_SYNC_CHUNK_BYTES`
/// (`900 B`), guaranteeing every encrypted UDP packet stays `< 1,200 bytes` over WAN/VPN routers.
pub fn pack_wan_sync_chunk(all_items: &[SyncItem], start_index: u32) -> (u32, Vec<SyncItem>) {
    let start = (start_index as usize).min(all_items.len());
    let mut chunk = Vec::new();
    let mut used_bytes = 17usize; // message tag + 3x u32 + vec len header
    let mut idx = start;
    while idx < all_items.len() {
        let item_len = all_items[idx].encoded_len();
        if !chunk.is_empty() && used_bytes + item_len > MAX_WAN_SYNC_CHUNK_BYTES {
            break;
        }
        used_bytes += item_len;
        chunk.push(all_items[idx].clone());
        idx += 1;
    }
    (idx as u32, chunk)
}

/// Authenticated & encrypted peer-to-peer mesh messages carried inside `SessionCipher::seal`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum P2pMessage {
    DiscoverPing {
        target: Address,
    },
    DiscoverPong {
        observed_caller_addr: SocketAddr,
        closest_peers: Vec<PeerDescriptor>,
    },
    RequestHolePunch {
        target_peer: Address,
    },
    HolePunchRendezvous {
        peer: PeerDescriptor,
    },
    GossipShare {
        share: ComputeShare,
        author_pubkey: PublicKey,
        reward_pubkey: PublicKey,
    },
    EpochSeal {
        epoch: EpochId,
        settled_fees: Amount,
        shares: Vec<(ComputeShare, PublicKey, PublicKey)>,
    },
    GossipPocketUpsert {
        address: Address,
        public_key: PublicKey,
        balance: Amount,
        daily_limit: Amount,
    },
    QuorumVoteRequest {
        request_id: u64,
        tx: Transaction,
        value_commitment: [u8; 32],
        bulletproof_672: Vec<u8>,
    },
    QuorumVoteReply {
        request_id: u64,
        tx_id: Hash32,
        validator: Address,
        vote_signature: Vec<u8>,
    },
    FinalityCommit {
        tx: Transaction,
        fee_worker: Amount,
        fee_burned: Amount,
    },
    SyncChunkRequest {
        start_index: u32,
    },
    SyncChunkResponse {
        start_index: u32,
        next_index: u32,
        total_items: u32,
        items: Vec<SyncItem>,
    },
    CommitSummary {
        recent_tx_ids: Vec<Hash32>,
    },
    RequestCommits {
        missing_tx_ids: Vec<Hash32>,
    },
    RequestSenderCommits {
        sender: Address,
        from_nonce: u64,
    },
    AnnounceGenesisBeacon {
        btc_block_hash_hex: String,
        public_headline: String,
        timestamp_unix: u64,
    },
    GossipStealthOutput {
        one_time_address: Address,
        ephemeral_pub: [u8; 32],
        view_tag: u8,
    },
    GossipStealthClaim {
        one_time_address: Address,
        claimant_pocket: Address,
        claimant_pubkey: PublicKey,
        spend_pub: [u8; 32],
        kdf: [u8; 32],
        schnorr_sig64: [u8; 64],
    },
    GossipStealthOutputV2 {
        one_time_address: Address,
        ephemeral_pub: [u8; 32],
        view_tag: u8,
        encrypted_memo: Vec<u8>,
    },
    GossipContractRpc {
        encoded_rpc: Vec<u8>,
    },
}

impl P2pMessage {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        match self {
            Self::DiscoverPing { target } => {
                out.push(1);
                out.extend_from_slice(target.as_bytes());
            }
            Self::DiscoverPong {
                observed_caller_addr,
                closest_peers,
            } => {
                out.push(2);
                encode_socket_addr(observed_caller_addr, &mut out);
                out.extend_from_slice(&(closest_peers.len() as u32).to_le_bytes());
                for p in closest_peers {
                    p.encode_into(&mut out);
                }
            }
            Self::RequestHolePunch { target_peer } => {
                out.push(3);
                out.extend_from_slice(target_peer.as_bytes());
            }
            Self::HolePunchRendezvous { peer } => {
                out.push(4);
                peer.encode_into(&mut out);
            }
            Self::GossipShare {
                share,
                author_pubkey,
                reward_pubkey,
            } => {
                out.push(5);
                encode_share(share, &mut out);
                encode_pubkey(author_pubkey, &mut out);
                encode_pubkey(reward_pubkey, &mut out);
            }
            Self::GossipPocketUpsert {
                address,
                public_key,
                balance,
                daily_limit,
            } => {
                out.push(6);
                out.extend_from_slice(address.as_bytes());
                encode_pubkey(public_key, &mut out);
                out.extend_from_slice(&balance.bits().to_le_bytes());
                out.extend_from_slice(&daily_limit.bits().to_le_bytes());
            }
            Self::QuorumVoteRequest {
                request_id,
                tx,
                value_commitment,
                bulletproof_672,
            } => {
                out.push(7);
                out.extend_from_slice(&request_id.to_le_bytes());
                encode_fast_tx(tx, &mut out);
                out.extend_from_slice(value_commitment);
                push_bytes(&mut out, bulletproof_672);
            }
            Self::QuorumVoteReply {
                request_id,
                tx_id,
                validator,
                vote_signature,
            } => {
                out.push(8);
                out.extend_from_slice(&request_id.to_le_bytes());
                out.extend_from_slice(tx_id.as_bytes());
                out.extend_from_slice(validator.as_bytes());
                push_bytes(&mut out, vote_signature);
            }
            Self::FinalityCommit {
                tx,
                fee_worker,
                fee_burned,
            } => {
                out.push(9);
                encode_fast_tx(tx, &mut out);
                out.extend_from_slice(&fee_worker.bits().to_le_bytes());
                out.extend_from_slice(&fee_burned.bits().to_le_bytes());
            }
            Self::SyncChunkRequest { start_index } => {
                out.push(10);
                out.extend_from_slice(&start_index.to_le_bytes());
            }
            Self::SyncChunkResponse {
                start_index,
                next_index,
                total_items,
                items,
            } => {
                out.push(11);
                out.extend_from_slice(&start_index.to_le_bytes());
                out.extend_from_slice(&next_index.to_le_bytes());
                out.extend_from_slice(&total_items.to_le_bytes());
                out.extend_from_slice(&(items.len() as u32).to_le_bytes());
                for item in items {
                    item.encode_into(&mut out);
                }
            }
            Self::EpochSeal {
                epoch,
                settled_fees,
                shares,
            } => {
                out.push(12);
                out.extend_from_slice(&epoch.0.to_le_bytes());
                out.extend_from_slice(&settled_fees.bits().to_le_bytes());
                out.extend_from_slice(&(shares.len() as u32).to_le_bytes());
                for (sh, val_pk, rew_pk) in shares {
                    encode_share(sh, &mut out);
                    encode_pubkey(val_pk, &mut out);
                    encode_pubkey(rew_pk, &mut out);
                }
            }
            Self::CommitSummary { recent_tx_ids } => {
                out.push(13);
                out.extend_from_slice(&(recent_tx_ids.len() as u32).to_le_bytes());
                for id in recent_tx_ids {
                    out.extend_from_slice(id.as_bytes());
                }
            }
            Self::RequestCommits { missing_tx_ids } => {
                out.push(14);
                out.extend_from_slice(&(missing_tx_ids.len() as u32).to_le_bytes());
                for id in missing_tx_ids {
                    out.extend_from_slice(id.as_bytes());
                }
            }
            Self::RequestSenderCommits { sender, from_nonce } => {
                out.push(15);
                out.extend_from_slice(sender.as_bytes());
                out.extend_from_slice(&from_nonce.to_le_bytes());
            }
            Self::AnnounceGenesisBeacon {
                btc_block_hash_hex,
                public_headline,
                timestamp_unix,
            } => {
                out.push(16);
                push_bytes(&mut out, btc_block_hash_hex.as_bytes());
                push_bytes(&mut out, public_headline.as_bytes());
                out.extend_from_slice(&timestamp_unix.to_le_bytes());
            }
            Self::GossipStealthOutput {
                one_time_address,
                ephemeral_pub,
                view_tag,
            } => {
                out.push(17);
                out.extend_from_slice(one_time_address.as_bytes());
                out.extend_from_slice(ephemeral_pub);
                out.push(*view_tag);
            }
            Self::GossipStealthClaim {
                one_time_address,
                claimant_pocket,
                claimant_pubkey,
                spend_pub,
                kdf,
                schnorr_sig64,
            } => {
                out.push(18);
                out.extend_from_slice(one_time_address.as_bytes());
                out.extend_from_slice(claimant_pocket.as_bytes());
                encode_pubkey(claimant_pubkey, &mut out);
                out.extend_from_slice(spend_pub);
                out.extend_from_slice(kdf);
                out.extend_from_slice(schnorr_sig64);
            }
            Self::GossipStealthOutputV2 {
                one_time_address,
                ephemeral_pub,
                view_tag,
                encrypted_memo,
            } => {
                out.push(19);
                out.extend_from_slice(one_time_address.as_bytes());
                out.extend_from_slice(ephemeral_pub);
                out.push(*view_tag);
                push_bytes(&mut out, encrypted_memo);
            }
            Self::GossipContractRpc { encoded_rpc } => {
                out.push(20);
                push_bytes(&mut out, encoded_rpc);
            }
        }
        out
    }

    pub fn decode(bytes: &[u8]) -> Option<Self> {
        let &tag = bytes.first()?;
        let mut pos = 1usize;
        let msg = match tag {
            1 => Self::DiscoverPing {
                target: Address::from_bytes(take32(bytes, &mut pos)?),
            },
            2 => {
                let observed_caller_addr = decode_socket_addr(bytes, &mut pos)?;
                let count = take_u32(bytes, &mut pos)? as usize;
                let mut closest_peers = Vec::with_capacity(count.min(64));
                for _ in 0..count {
                    closest_peers.push(PeerDescriptor::decode_from(bytes, &mut pos)?);
                }
                Self::DiscoverPong {
                    observed_caller_addr,
                    closest_peers,
                }
            }
            3 => Self::RequestHolePunch {
                target_peer: Address::from_bytes(take32(bytes, &mut pos)?),
            },
            4 => Self::HolePunchRendezvous {
                peer: PeerDescriptor::decode_from(bytes, &mut pos)?,
            },
            5 => {
                let share = decode_share(bytes, &mut pos)?;
                let author_pubkey = decode_pubkey(bytes, &mut pos)?;
                let reward_pubkey = decode_pubkey(bytes, &mut pos)?;
                Self::GossipShare {
                    share,
                    author_pubkey,
                    reward_pubkey,
                }
            }
            6 => {
                let address = Address::from_bytes(take32(bytes, &mut pos)?);
                let public_key = decode_pubkey(bytes, &mut pos)?;
                let balance = Amount::from_bits(take_u64(bytes, &mut pos)?);
                let daily_limit = Amount::from_bits(take_u64(bytes, &mut pos)?);
                Self::GossipPocketUpsert {
                    address,
                    public_key,
                    balance,
                    daily_limit,
                }
            }
            7 => {
                let request_id = take_u64(bytes, &mut pos)?;
                let tx = decode_fast_tx(bytes, &mut pos)?;
                let value_commitment = take32(bytes, &mut pos)?;
                let bulletproof_672 = take_bytes(bytes, &mut pos)?;
                Self::QuorumVoteRequest {
                    request_id,
                    tx,
                    value_commitment,
                    bulletproof_672,
                }
            }
            8 => {
                let request_id = take_u64(bytes, &mut pos)?;
                let tx_id = Hash32::from_bytes(take32(bytes, &mut pos)?);
                let validator = Address::from_bytes(take32(bytes, &mut pos)?);
                let vote_signature = take_bytes(bytes, &mut pos)?;
                Self::QuorumVoteReply {
                    request_id,
                    tx_id,
                    validator,
                    vote_signature,
                }
            }
            9 => {
                let tx = decode_fast_tx(bytes, &mut pos)?;
                let fee_worker = Amount::from_bits(take_u64(bytes, &mut pos)?);
                let fee_burned = Amount::from_bits(take_u64(bytes, &mut pos)?);
                Self::FinalityCommit {
                    tx,
                    fee_worker,
                    fee_burned,
                }
            }
            10 => Self::SyncChunkRequest {
                start_index: take_u32(bytes, &mut pos)?,
            },
            11 => {
                let start_index = take_u32(bytes, &mut pos)?;
                let next_index = take_u32(bytes, &mut pos)?;
                let total_items = take_u32(bytes, &mut pos)?;
                let item_count = take_u32(bytes, &mut pos)? as usize;
                if item_count > 64 {
                    return None;
                }
                let mut items = Vec::with_capacity(item_count);
                for _ in 0..item_count {
                    items.push(SyncItem::decode_from(bytes, &mut pos)?);
                }
                Self::SyncChunkResponse {
                    start_index,
                    next_index,
                    total_items,
                    items,
                }
            }
            12 => {
                let epoch = EpochId(take_u64(bytes, &mut pos)?);
                let settled_fees = Amount::from_bits(take_u64(bytes, &mut pos)?);
                let sh_count = take_u32(bytes, &mut pos)? as usize;
                if sh_count > 64 {
                    return None;
                }
                let mut shares = Vec::with_capacity(sh_count);
                for _ in 0..sh_count {
                    let sh = decode_share(bytes, &mut pos)?;
                    let val_pk = decode_pubkey(bytes, &mut pos)?;
                    let rew_pk = decode_pubkey(bytes, &mut pos)?;
                    shares.push((sh, val_pk, rew_pk));
                }
                Self::EpochSeal {
                    epoch,
                    settled_fees,
                    shares,
                }
            }
            13 => {
                let count = take_u32(bytes, &mut pos)? as usize;
                if count > 64 {
                    return None;
                }
                let mut recent_tx_ids = Vec::with_capacity(count);
                for _ in 0..count {
                    recent_tx_ids.push(Hash32::from_bytes(take32(bytes, &mut pos)?));
                }
                Self::CommitSummary { recent_tx_ids }
            }
            14 => {
                let count = take_u32(bytes, &mut pos)? as usize;
                if count > 64 {
                    return None;
                }
                let mut missing_tx_ids = Vec::with_capacity(count);
                for _ in 0..count {
                    missing_tx_ids.push(Hash32::from_bytes(take32(bytes, &mut pos)?));
                }
                Self::RequestCommits { missing_tx_ids }
            }
            15 => {
                let sender = Address::from_bytes(take32(bytes, &mut pos)?);
                let from_nonce = take_u64(bytes, &mut pos)?;
                Self::RequestSenderCommits { sender, from_nonce }
            }
            16 => {
                let b_hex = String::from_utf8(take_bytes(bytes, &mut pos)?).ok()?;
                let headline = String::from_utf8(take_bytes(bytes, &mut pos)?).ok()?;
                let timestamp_unix = take_u64(bytes, &mut pos)?;
                if b_hex.len() > 256 || headline.len() > 512 {
                    return None;
                }
                Self::AnnounceGenesisBeacon {
                    btc_block_hash_hex: b_hex,
                    public_headline: headline,
                    timestamp_unix,
                }
            }
            17 => {
                let one_time_address = Address::from_bytes(take32(bytes, &mut pos)?);
                let ephemeral_pub = take32(bytes, &mut pos)?;
                let view_tag = *bytes.get(pos)?;
                pos += 1;
                Self::GossipStealthOutput {
                    one_time_address,
                    ephemeral_pub,
                    view_tag,
                }
            }
            18 => {
                let one_time_address = Address::from_bytes(take32(bytes, &mut pos)?);
                let claimant_pocket = Address::from_bytes(take32(bytes, &mut pos)?);
                let claimant_pubkey = decode_pubkey(bytes, &mut pos)?;
                let spend_pub = take32(bytes, &mut pos)?;
                let kdf = take32(bytes, &mut pos)?;
                let sig_lo = take32(bytes, &mut pos)?;
                let sig_hi = take32(bytes, &mut pos)?;
                let mut schnorr_sig64 = [0u8; 64];
                schnorr_sig64[..32].copy_from_slice(&sig_lo);
                schnorr_sig64[32..].copy_from_slice(&sig_hi);
                Self::GossipStealthClaim {
                    one_time_address,
                    claimant_pocket,
                    claimant_pubkey,
                    spend_pub,
                    kdf,
                    schnorr_sig64,
                }
            }
            19 => {
                let one_time_address = Address::from_bytes(take32(bytes, &mut pos)?);
                let ephemeral_pub = take32(bytes, &mut pos)?;
                let view_tag = *bytes.get(pos)?;
                pos += 1;
                let encrypted_memo = take_bytes(bytes, &mut pos)?;
                if encrypted_memo.len() > 80 {
                    return None;
                }
                Self::GossipStealthOutputV2 {
                    one_time_address,
                    ephemeral_pub,
                    view_tag,
                    encrypted_memo,
                }
            }
            20 => {
                let encoded_rpc = take_bytes(bytes, &mut pos)?;
                if encoded_rpc.is_empty() || encoded_rpc.len() > 800 {
                    return None;
                }
                Self::GossipContractRpc { encoded_rpc }
            }
            _ => return None,
        };
        if pos == bytes.len() { Some(msg) } else { None }
    }
}

fn encode_pubkey(pk: &PublicKey, out: &mut Vec<u8>) {
    out.push(pk.scheme as u8);
    out.extend_from_slice(pk.merkle_root.as_bytes());
}

fn decode_pubkey(bytes: &[u8], pos: &mut usize) -> Option<PublicKey> {
    let scheme = SignatureScheme::from_u8(*bytes.get(*pos)?)?;
    *pos += 1;
    let merkle_root = Hash32::from_bytes(take32(bytes, pos)?);
    Some(PublicKey {
        scheme,
        merkle_root,
    })
}

fn encode_share(share: &ComputeShare, out: &mut Vec<u8>) {
    out.extend_from_slice(share.id.as_bytes());
    out.extend_from_slice(&share.epoch.0.to_le_bytes());
    out.extend_from_slice(share.author.as_bytes());
    out.extend_from_slice(&(share.parents.len() as u32).to_le_bytes());
    for p in &share.parents {
        out.extend_from_slice(p.as_bytes());
    }
    out.extend_from_slice(&share.verified_weight.to_le_bytes());
    match &share.work {
        WorkProof::CpuVm { nonce, digest } => {
            out.push(1);
            out.extend_from_slice(&nonce.to_le_bytes());
            out.extend_from_slice(digest.as_bytes());
        }
        WorkProof::RecursiveZkState {
            verified_tx_count,
            zk_nonce,
            state_root,
            proof_digest,
        } => {
            out.push(4);
            out.extend_from_slice(&verified_tx_count.to_le_bytes());
            out.extend_from_slice(&zk_nonce.to_le_bytes());
            out.extend_from_slice(state_root.as_bytes());
            out.extend_from_slice(proof_digest.as_bytes());
        }
        WorkProof::EdgeRelay {
            relayed_packets,
            receipt_root,
        } => {
            out.push(3);
            out.extend_from_slice(&relayed_packets.to_le_bytes());
            out.extend_from_slice(receipt_root.as_bytes());
        }
    }
}

fn decode_share(bytes: &[u8], pos: &mut usize) -> Option<ComputeShare> {
    let id = Hash32::from_bytes(take32(bytes, pos)?);
    let epoch = EpochId(take_u64(bytes, pos)?);
    let author = Address::from_bytes(take32(bytes, pos)?);
    let p_count = take_u32(bytes, pos)? as usize;
    let mut parents = Vec::with_capacity(p_count.min(32));
    for _ in 0..p_count {
        parents.push(Hash32::from_bytes(take32(bytes, pos)?));
    }
    let verified_weight = take_u64(bytes, pos)?;
    let w_tag = *bytes.get(*pos)?;
    *pos += 1;
    let work = match w_tag {
        1 => WorkProof::CpuVm {
            nonce: take_u64(bytes, pos)?,
            digest: Hash32::from_bytes(take32(bytes, pos)?),
        },
        2 => WorkProof::RecursiveZkState {
            verified_tx_count: take_u32(bytes, pos)?,
            zk_nonce: 0,
            state_root: Hash32::from_bytes(take32(bytes, pos)?),
            proof_digest: Hash32::from_bytes(take32(bytes, pos)?),
        },
        3 => WorkProof::EdgeRelay {
            relayed_packets: take_u32(bytes, pos)?,
            receipt_root: Hash32::from_bytes(take32(bytes, pos)?),
        },
        4 => WorkProof::RecursiveZkState {
            verified_tx_count: take_u32(bytes, pos)?,
            zk_nonce: take_u64(bytes, pos)?,
            state_root: Hash32::from_bytes(take32(bytes, pos)?),
            proof_digest: Hash32::from_bytes(take32(bytes, pos)?),
        },
        _ => return None,
    };
    Some(ComputeShare {
        id,
        epoch,
        author,
        parents,
        work,
        verified_weight,
    })
}

fn encode_fast_tx(tx: &Transaction, out: &mut Vec<u8>) {
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
        panic!("P2P FastTransfer codec expects FastTransfer variant");
    };
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
    push_bytes(out, &tx.signature_bytes);
}

fn decode_fast_tx(bytes: &[u8], pos: &mut usize) -> Option<Transaction> {
    let id = Hash32::from_bytes(take32(bytes, pos)?);
    let from = Address::from_bytes(take32(bytes, pos)?);
    let to_stealth = Address::from_bytes(take32(bytes, pos)?);
    let stealth_view_tag = *bytes.get(*pos)?;
    *pos += 1;
    let amount = Amount::from_bits(take_u64(bytes, pos)?);
    let fee = Amount::from_bits(take_u64(bytes, pos)?);
    let nonce = take_u64(bytes, pos)?;
    let commitment = Hash32::from_bytes(take32(bytes, pos)?);
    let has_null = *bytes.get(*pos)?;
    *pos += 1;
    let innocence_nullifier = if has_null == 1 {
        Some(Hash32::from_bytes(take32(bytes, pos)?))
    } else if has_null == 0 {
        None
    } else {
        return None;
    };
    let signature_bytes = take_bytes(bytes, pos)?;
    Some(Transaction {
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
    })
}

fn push_bytes(out: &mut Vec<u8>, data: &[u8]) {
    out.extend_from_slice(&(data.len() as u32).to_le_bytes());
    out.extend_from_slice(data);
}

fn take32(bytes: &[u8], pos: &mut usize) -> Option<[u8; 32]> {
    let s = bytes.get(*pos..*pos + 32)?;
    *pos += 32;
    s.try_into().ok()
}

fn take_u32(bytes: &[u8], pos: &mut usize) -> Option<u32> {
    let s = bytes.get(*pos..*pos + 4)?;
    *pos += 4;
    Some(u32::from_le_bytes(s.try_into().ok()?))
}

fn take_u64(bytes: &[u8], pos: &mut usize) -> Option<u64> {
    let s = bytes.get(*pos..*pos + 8)?;
    *pos += 8;
    Some(u64::from_le_bytes(s.try_into().ok()?))
}

fn take_bytes(bytes: &[u8], pos: &mut usize) -> Option<Vec<u8>> {
    let len = take_u32(bytes, pos)? as usize;
    let s = bytes.get(*pos..*pos + len)?.to_vec();
    *pos += len;
    Some(s)
}

#[cfg(test)]
mod tests {
    use super::*;
    use credit_crypto::Keypair;

    #[test]
    fn wan_sync_packer_enforces_sub_1200_byte_mtu_across_hundreds_of_accounts() {
        let mut items = Vec::with_capacity(160);
        items.push(SyncItem::Header {
            active_epoch: EpochId(5),
            settled_epoch: EpochId(4),
            active_epoch_seed: Hash32::from_bytes([0xaa; 32]),
            circulating_supply: Amount::from_credits(500).unwrap(),
            total_burned: Amount::from_bits(1_500),
            endurance_balance: Amount::from_bits(1_500),
            unsettled_fee_bits: 0,
        });
        for i in 0u8..150 {
            let kp = Keypair::from_seed(SignatureScheme::PasskeyP256, [i; 32]);
            items.push(SyncItem::Pocket {
                address: kp.address(),
                public_key: kp.public_key(),
                state: PocketState::new(
                    Amount::from_credits(25).unwrap(),
                    Amount::from_credits(50).unwrap(),
                ),
            });
        }

        let mut cursor = 0u32;
        let mut pages = 0usize;
        let mut reassembled = Vec::new();
        while (cursor as usize) < items.len() {
            let (next, chunk) = pack_wan_sync_chunk(&items, cursor);
            let msg = P2pMessage::SyncChunkResponse {
                start_index: cursor,
                next_index: next,
                total_items: items.len() as u32,
                items: chunk,
            };
            let encoded = msg.encode();
            // Even after adding 32B Noise AEAD + 25B XQ01 UDP header, packet stays strictly < 1,200B MTU!
            assert!(
                encoded.len() + 64 < 1_200,
                "sync chunk exceeded WAN MTU: {} bytes",
                encoded.len() + 64
            );
            let decoded = P2pMessage::decode(&encoded).expect("valid chunk decode");
            let P2pMessage::SyncChunkResponse {
                next_index,
                items: page_items,
                ..
            } = decoded
            else {
                panic!("expected SyncChunkResponse");
            };
            reassembled.extend(page_items);
            cursor = next_index;
            pages += 1;
        }
        assert!(pages >= 18); // 151 items split across ~19 <1.2KB MTU-safe UDP datagrams
        assert_eq!(reassembled, items);
    }
}
