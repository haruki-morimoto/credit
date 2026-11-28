//! Low-latency wire framing (`XCR1`), QUIC-style multiplexed UDP socket transport (`XQ01`),
//! and cryptographic edge relay receipts.

pub mod dht;
pub mod p2p;
pub mod rpc;
pub mod transport;

pub use dht::{KademliaRoutingTable, NatDetector, NatTopology, PeerDescriptor, xor_distance};
pub use p2p::{
    MAX_WAN_SYNC_CHUNK_BYTES, P2pHandshakePacket, P2pMessage, SyncItem, pack_wan_sync_chunk,
};
pub use rpc::{
    ArtifactWireRecord, AssetWireRecord, AttestationWireRecord, CampaignWireRecord,
    DexOrderWireRecord, HtlcWireRecord, NodeRpcRequest, NodeRpcResponse, PayChanWireRecord,
    PersistentRpcChannel, ProposalWireRecord, StealthOutputRecordV2, rpc_call,
};
pub use transport::{QUIC_UDP_MAGIC, QuicPacket, UdpQuicEndpoint};

use credit_crypto::{domain_hash, sha256};
use credit_types::{Address, EpochId, Hash32};

/// 4-byte wire protocol magic (`"XCR1"`).
pub const WIRE_MAGIC: [u8; 4] = *b"XCR1";

/// Protocol wire version.
pub const WIRE_VERSION: u8 = 1;

/// Multiplexed QUIC stream message categories.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum ChannelTag {
    ShareDagGossip = 1,
    FastPathRequest = 2,
    FastPathVote = 3,
    FinalityCertificate = 4,
    BftDagVertex = 5,
    ClientRpcRequest = 6,
    ClientRpcResponse = 7,
    P2pHandshake = 8,
    P2pEncryptedMesh = 9,
}

impl ChannelTag {
    pub const fn from_u8(v: u8) -> Option<Self> {
        match v {
            1 => Some(Self::ShareDagGossip),
            2 => Some(Self::FastPathRequest),
            3 => Some(Self::FastPathVote),
            4 => Some(Self::FinalityCertificate),
            5 => Some(Self::BftDagVertex),
            6 => Some(Self::ClientRpcRequest),
            7 => Some(Self::ClientRpcResponse),
            8 => Some(Self::P2pHandshake),
            9 => Some(Self::P2pEncryptedMesh),
            _ => None,
        }
    }
}

/// Authenticated binary wire packet (`XCR1` + version + channel + length + payload + 8-byte checksum).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WireFrame {
    pub channel: ChannelTag,
    pub payload: Vec<u8>,
}

impl WireFrame {
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(18 + self.payload.len());
        buf.extend_from_slice(&WIRE_MAGIC);
        buf.push(WIRE_VERSION);
        buf.push(self.channel as u8);
        buf.extend_from_slice(&(self.payload.len() as u32).to_le_bytes());
        buf.extend_from_slice(&self.payload);
        let tag = sha256(&buf);
        buf.extend_from_slice(&tag[..8]);
        buf
    }

    pub fn decode(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < 18 || bytes[0..4] != WIRE_MAGIC || bytes[4] != WIRE_VERSION {
            return None;
        }
        let channel = ChannelTag::from_u8(bytes[5])?;
        let payload_len = u32::from_le_bytes(bytes[6..10].try_into().ok()?) as usize;
        if bytes.len() != 10 + payload_len + 8 {
            return None;
        }
        let body = &bytes[..10 + payload_len];
        let expected_tag = sha256(body);
        if bytes[10 + payload_len..] != expected_tag[..8] {
            return None;
        }
        Some(Self {
            channel,
            payload: bytes[10..10 + payload_len].to_vec(),
        })
    }
}

/// Cryptographic receipt crediting an edge node for low-latency packet relay during an epoch.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RelayReceipt {
    pub epoch: EpochId,
    pub relay_node: Address,
    pub relayed_packets: u32,
    pub receipt_root: Hash32,
}

impl RelayReceipt {
    pub fn new(epoch: EpochId, relay_node: Address, packet_hashes: &[Hash32]) -> Self {
        let mut raw = Vec::with_capacity(packet_hashes.len() * 32);
        for h in packet_hashes {
            raw.extend_from_slice(h.as_bytes());
        }
        let receipt_root = domain_hash(
            "XCR.NET.RELAY_RECEIPT.V1",
            &[&epoch.0.to_le_bytes(), relay_node.as_bytes(), &raw],
        );
        Self {
            epoch,
            relay_node,
            relayed_packets: packet_hashes.len() as u32,
            receipt_root,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wire_frame_roundtrip_and_corruption_detection() {
        let frame = WireFrame {
            channel: ChannelTag::FastPathRequest,
            payload: b"xcr-1rtt-payload".to_vec(),
        };
        let mut raw = frame.encode();
        assert_eq!(WireFrame::decode(&raw).unwrap(), frame);

        // Flip 1 bit in payload: checksum must reject!
        raw[12] ^= 0x01;
        assert!(WireFrame::decode(&raw).is_none());
    }
}
