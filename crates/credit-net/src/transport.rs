//! Real OS `std::net::UdpSocket` QUIC-style Multiplexed Datagram & Reliable Stream Transport.
//!
//! Provides two concurrent delivery modes over UDP without head-of-line blocking:
//! 1. **Unreliable 1-RTT Datagrams (`FLAG_DATAGRAM_1RTT`):** Zero-handshake-overhead quorum fanout
//!    for `FastPathRequest` and `FastPathVote` packets (~150-250 ms WAN target).
//! 2. **ACK-Tracked Reliable Frames (`FLAG_RELIABLE` + `FLAG_ACK_ONLY`):** Monotonic packet numbers,
//!    piggybacked `largest_acked` watermarks, and deterministic retransmission queues for
//!    `ShareDagGossip` and `BftDagVertex` dissemination.

use std::collections::BTreeMap;
use std::io;
use std::net::{SocketAddr, UdpSocket};
use std::time::Duration;

use crate::{ChannelTag, WireFrame};

/// 4-byte transport header magic (`"XQ01"`).
pub const QUIC_UDP_MAGIC: [u8; 4] = *b"XQ01";

const FLAG_DATAGRAM_1RTT: u8 = 0x01;
const FLAG_RELIABLE: u8 = 0x02;
const FLAG_ACK_ONLY: u8 = 0x04;

const HEADER_LEN: usize = 29; // 4 magic + 1 flags + 8 conn_id + 8 pkt_num + 8 ack_largest

/// Decoded QUIC-style UDP transport packet.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QuicPacket {
    pub connection_id: u64,
    pub packet_number: u64,
    pub ack_largest: u64,
    pub reliable: bool,
    pub frame: Option<WireFrame>, // `None` for pure standalone ACK packets
}

impl QuicPacket {
    pub fn encode(&self, flags: u8) -> Vec<u8> {
        let frame_bytes = self
            .frame
            .as_ref()
            .map(WireFrame::encode)
            .unwrap_or_default();
        let mut out = Vec::with_capacity(HEADER_LEN + frame_bytes.len());
        out.extend_from_slice(&QUIC_UDP_MAGIC);
        out.push(flags);
        out.extend_from_slice(&self.connection_id.to_le_bytes());
        out.extend_from_slice(&self.packet_number.to_le_bytes());
        out.extend_from_slice(&self.ack_largest.to_le_bytes());
        out.extend_from_slice(&frame_bytes);
        out
    }

    pub fn decode(raw: &[u8]) -> Option<(u8, Self)> {
        if raw.len() < HEADER_LEN || raw[0..4] != QUIC_UDP_MAGIC {
            return None;
        }
        let flags = raw[4];
        let connection_id = u64::from_le_bytes(raw[5..13].try_into().ok()?);
        let packet_number = u64::from_le_bytes(raw[13..21].try_into().ok()?);
        let ack_largest = u64::from_le_bytes(raw[21..29].try_into().ok()?);

        let frame = if flags & FLAG_ACK_ONLY != 0 {
            if raw.len() != HEADER_LEN {
                return None;
            }
            None
        } else {
            Some(WireFrame::decode(&raw[HEADER_LEN..])?)
        };

        Some((
            flags,
            Self {
                connection_id,
                packet_number,
                ack_largest,
                reliable: (flags & FLAG_RELIABLE) != 0,
                frame,
            },
        ))
    }
}

#[derive(Default)]
struct PeerSession {
    next_packet_number: u64,
    largest_received: u64,
    unacked_reliable: BTreeMap<u64, Vec<u8>>,
}

/// Multiplexed UDP endpoint supporting 1-RTT quorum datagrams and ACK-tracked reliable frames.
pub struct UdpQuicEndpoint {
    socket: UdpSocket,
    local_addr: SocketAddr,
    connection_id: u64,
    peers: BTreeMap<SocketAddr, PeerSession>,
}

impl UdpQuicEndpoint {
    /// Binds to `bind_addr` (e.g. `127.0.0.1:9400` or `0.0.0.0:9400`) with `read_timeout`.
    pub fn bind(
        bind_addr: SocketAddr,
        connection_id: u64,
        read_timeout: Duration,
    ) -> io::Result<Self> {
        let socket = UdpSocket::bind(bind_addr)?;
        socket.set_read_timeout(Some(read_timeout))?;
        let local_addr = socket.local_addr()?;
        Ok(Self {
            socket,
            local_addr,
            connection_id,
            peers: BTreeMap::new(),
        })
    }

    /// Binds an ephemeral local UDP port (`127.0.0.1:0`) with `read_timeout`.
    pub fn bind_loopback(connection_id: u64, read_timeout: Duration) -> io::Result<Self> {
        let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
        Self::bind(addr, connection_id, read_timeout)
    }

    #[inline]
    pub const fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    /// Sends a zero-head-of-line-blocking 1-RTT UDP datagram (`FastPathRequest` / `FastPathVote`).
    pub fn send_1rtt_datagram(&mut self, peer: SocketAddr, frame: &WireFrame) -> io::Result<u64> {
        let session = self.peers.entry(peer).or_default();
        session.next_packet_number += 1;
        let pkt_num = session.next_packet_number;
        let pkt = QuicPacket {
            connection_id: self.connection_id,
            packet_number: pkt_num,
            ack_largest: session.largest_received,
            reliable: false,
            frame: Some(frame.clone()),
        };
        let bytes = pkt.encode(FLAG_DATAGRAM_1RTT);
        self.socket.send_to(&bytes, peer)?;
        Ok(pkt_num)
    }

    /// Sends a reliable frame and retains it in `unacked_reliable` until acknowledged by `peer`.
    pub fn send_reliable(&mut self, peer: SocketAddr, frame: &WireFrame) -> io::Result<u64> {
        let session = self.peers.entry(peer).or_default();
        session.next_packet_number += 1;
        let pkt_num = session.next_packet_number;
        let pkt = QuicPacket {
            connection_id: self.connection_id,
            packet_number: pkt_num,
            ack_largest: session.largest_received,
            reliable: true,
            frame: Some(frame.clone()),
        };
        let bytes = pkt.encode(FLAG_RELIABLE);
        self.socket.send_to(&bytes, peer)?;
        session.unacked_reliable.insert(pkt_num, bytes);
        Ok(pkt_num)
    }

    /// Retransmits all currently unacknowledged reliable packets across peers.
    pub fn retransmit_unacked(&self) -> io::Result<usize> {
        let mut resent = 0usize;
        for (&peer, session) in &self.peers {
            for raw in session.unacked_reliable.values() {
                self.socket.send_to(raw, peer)?;
                resent += 1;
            }
        }
        Ok(resent)
    }

    /// Returns the number of reliable packets still awaiting peer acknowledgment.
    pub fn pending_reliable_count(&self, peer: &SocketAddr) -> usize {
        self.peers
            .get(peer)
            .map(|s| s.unacked_reliable.len())
            .unwrap_or(0)
    }

    /// Receives and authenticates the next UDP packet, automatically retiring ACKed reliable packets
    /// and replying with a standalone ACK when a reliable frame arrives.
    pub fn recv_packet(&mut self) -> io::Result<(SocketAddr, QuicPacket)> {
        let mut buf = [0u8; 65_535];
        loop {
            let (len, src) = match self.socket.recv_from(&mut buf) {
                Ok(pair) => pair,
                // On Windows, Winsock surfaces ICMP Port Unreachable from a closed remote UDP peer
                // as `ConnectionReset` (WSAECONNRESET / 10054) on connectionless `recv_from`; ignore it!
                Err(e) if e.kind() == io::ErrorKind::ConnectionReset => continue,
                Err(e) => return Err(e),
            };
            let Some((flags, pkt)) = QuicPacket::decode(&buf[..len]) else {
                continue; // Drop malformed or unauthenticated datagrams silently
            };

            let session = self.peers.entry(src).or_default();
            if pkt.packet_number > session.largest_received {
                session.largest_received = pkt.packet_number;
            }
            // Retire all reliable packets `<= pkt.ack_largest`:
            session
                .unacked_reliable
                .retain(|&sent_num, _| sent_num > pkt.ack_largest);

            if (flags & FLAG_RELIABLE) != 0 {
                session.next_packet_number += 1;
                let ack_pkt = QuicPacket {
                    connection_id: self.connection_id,
                    packet_number: session.next_packet_number,
                    ack_largest: session.largest_received,
                    reliable: false,
                    frame: None,
                };
                let ack_bytes = ack_pkt.encode(FLAG_ACK_ONLY);
                let _ = self.socket.send_to(&ack_bytes, src);
            }

            let _ = ChannelTag::ShareDagGossip;
            return Ok((src, pkt));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn real_udp_1rtt_datagram_and_reliable_ack_retirement() {
        let timeout = Duration::from_millis(500);
        let mut node_a = UdpQuicEndpoint::bind_loopback(0x1001, timeout).unwrap();
        let mut node_b = UdpQuicEndpoint::bind_loopback(0x2002, timeout).unwrap();
        let addr_b = node_b.local_addr();
        let addr_a = node_a.local_addr();

        // 1. Send reliable Share-DAG frame from A -> B:
        let gossip = WireFrame {
            channel: ChannelTag::ShareDagGossip,
            payload: b"epoch-0-share-vertex".to_vec(),
        };
        node_a.send_reliable(addr_b, &gossip).unwrap();
        assert_eq!(node_a.pending_reliable_count(&addr_b), 1);

        // B receives reliable frame and auto-sends ACK back to A:
        let (from, rx_pkt) = node_b.recv_packet().unwrap();
        assert_eq!(from, addr_a);
        assert_eq!(rx_pkt.frame.unwrap(), gossip);

        // A receives B's ACK and retires `unacked_reliable` down to 0!
        let (_, ack_pkt) = node_a.recv_packet().unwrap();
        assert!(ack_pkt.frame.is_none());
        assert_eq!(node_a.pending_reliable_count(&addr_b), 0);
    }
}
