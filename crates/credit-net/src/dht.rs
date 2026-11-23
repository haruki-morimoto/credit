//! **Kademlia 256-Bit XOR Routing Table**, **STUN-Style External NAT Topology Detector**,
//! and **UDP Hole-Punching Rendezvous Coordinator** (`Stage 1` Open-Internet P2P Layer).

use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use credit_types::Address;

/// Maximum peers retained per Kademlia prefix bucket (`k = 16`).
pub const K_BUCKET_SIZE: usize = 16;

/// Public routing descriptor exchanged during Kademlia DHT discovery and hole-punching.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PeerDescriptor {
    pub address: Address,
    pub static_x25519: [u8; 32],
    pub socket_addr: SocketAddr,
}

impl PeerDescriptor {
    pub fn encode_into(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(self.address.as_bytes());
        out.extend_from_slice(&self.static_x25519);
        encode_socket_addr(&self.socket_addr, out);
    }

    pub fn decode_from(bytes: &[u8], pos: &mut usize) -> Option<Self> {
        let addr_slice = bytes.get(*pos..*pos + 32)?;
        *pos += 32;
        let x_slice = bytes.get(*pos..*pos + 32)?;
        *pos += 32;
        let socket_addr = decode_socket_addr(bytes, pos)?;
        Some(Self {
            address: Address::from_bytes(addr_slice.try_into().ok()?),
            static_x25519: x_slice.try_into().ok()?,
            socket_addr,
        })
    }
}

pub fn encode_socket_addr(addr: &SocketAddr, out: &mut Vec<u8>) {
    match addr {
        SocketAddr::V4(v4) => {
            out.push(4);
            out.extend_from_slice(&v4.ip().octets());
            out.extend_from_slice(&v4.port().to_le_bytes());
        }
        SocketAddr::V6(v6) => {
            out.push(6);
            out.extend_from_slice(&v6.ip().octets());
            out.extend_from_slice(&v6.port().to_le_bytes());
        }
    }
}

pub fn decode_socket_addr(bytes: &[u8], pos: &mut usize) -> Option<SocketAddr> {
    let family = *bytes.get(*pos)?;
    *pos += 1;
    match family {
        4 => {
            let ip_b: [u8; 4] = bytes.get(*pos..*pos + 4)?.try_into().ok()?;
            *pos += 4;
            let port = u16::from_le_bytes(bytes.get(*pos..*pos + 2)?.try_into().ok()?);
            *pos += 2;
            Some(SocketAddr::new(IpAddr::V4(Ipv4Addr::from(ip_b)), port))
        }
        6 => {
            let ip_b: [u8; 16] = bytes.get(*pos..*pos + 16)?.try_into().ok()?;
            *pos += 16;
            let port = u16::from_le_bytes(bytes.get(*pos..*pos + 2)?.try_into().ok()?);
            *pos += 2;
            Some(SocketAddr::new(IpAddr::V6(Ipv6Addr::from(ip_b)), port))
        }
        _ => None,
    }
}

/// Computes the 256-bit Kademlia XOR distance `a ^ b`.
pub fn xor_distance(a: &Address, b: &Address) -> [u8; 32] {
    let mut dist = [0u8; 32];
    for i in 0..32 {
        dist[i] = a.0[i] ^ b.0[i];
    }
    dist
}

/// Returns the Kademlia bucket index (`0..256` by common prefix length), or `None` if `a == b`.
pub fn bucket_index(local: &Address, remote: &Address) -> Option<usize> {
    let dist = xor_distance(local, remote);
    let mut leading = 0usize;
    for &byte in &dist {
        if byte == 0 {
            leading += 8;
        } else {
            leading += byte.leading_zeros() as usize;
            return Some(255 - leading);
        }
    }
    None
}

/// Kademlia 256-bucket XOR routing table for decentralized peer discovery without central servers.
#[derive(Clone, Debug)]
pub struct KademliaRoutingTable {
    local_address: Address,
    buckets: Vec<Vec<PeerDescriptor>>,
}

impl KademliaRoutingTable {
    pub fn new(local_address: Address) -> Self {
        Self {
            local_address,
            buckets: vec![Vec::new(); 256],
        }
    }

    #[inline]
    pub const fn local_address(&self) -> Address {
        self.local_address
    }

    /// Inserts or refreshes `peer` in its corresponding XOR distance bucket.
    pub fn upsert_peer(&mut self, peer: PeerDescriptor) -> bool {
        let Some(idx) = bucket_index(&self.local_address, &peer.address) else {
            return false; // Ignore self
        };
        let bucket = &mut self.buckets[idx];
        if let Some(existing) = bucket.iter_mut().find(|p| p.address == peer.address) {
            *existing = peer;
            return true;
        }
        if bucket.len() < K_BUCKET_SIZE {
            bucket.push(peer);
            true
        } else {
            false
        }
    }

    /// Returns up to `limit` known peers closest in XOR metric to `target`.
    pub fn closest_peers(&self, target: &Address, limit: usize) -> Vec<PeerDescriptor> {
        let mut all = self.all_peers();
        all.sort_by_key(|p| xor_distance(&p.address, target));
        all.truncate(limit);
        all
    }

    pub fn all_peers(&self) -> Vec<PeerDescriptor> {
        let mut out = Vec::new();
        for b in &self.buckets {
            out.extend_from_slice(b);
        }
        out
    }

    pub fn peer_count(&self) -> usize {
        self.buckets.iter().map(Vec::len).sum()
    }
}

/// Detected home/cloud router NAT mapping behavior learned from remote STUN-style peer reflections.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NatTopology {
    Unknown,
    /// Local bind address matches externally observed IP:port (direct public server).
    PublicDirect(SocketAddr),
    /// Multiple peers observe the same consistent mapped IP:port -> supports direct UDP Hole-Punching!
    EndpointIndependentCone {
        local_bind: SocketAddr,
        external_mapped: SocketAddr,
    },
    /// Different peers observe different outbound ports -> requires `EdgeRelay` forwarding.
    SymmetricNatRelayRequired {
        latest_observed: SocketAddr,
    },
}

/// Tracks STUN-style `observed_addr` reflections returned in `Pong` frames from distinct peers.
#[derive(Clone, Debug)]
pub struct NatDetector {
    local_bind: SocketAddr,
    observations: BTreeMap<SocketAddr, SocketAddr>,
}

impl NatDetector {
    pub const fn new(local_bind: SocketAddr) -> Self {
        Self {
            local_bind,
            observations: BTreeMap::new(),
        }
    }

    pub fn record_observation(
        &mut self,
        reporter_peer: SocketAddr,
        observed_external: SocketAddr,
    ) -> NatTopology {
        self.observations.insert(reporter_peer, observed_external);
        self.classify()
    }

    pub fn classify(&self) -> NatTopology {
        let Some(&first) = self.observations.values().next() else {
            return NatTopology::Unknown;
        };
        if self
            .observations
            .values()
            .all(|&obs| obs == self.local_bind)
        {
            return NatTopology::PublicDirect(self.local_bind);
        }
        if self.observations.values().all(|&obs| obs == first) {
            NatTopology::EndpointIndependentCone {
                local_bind: self.local_bind,
                external_mapped: first,
            }
        } else {
            let latest = *self.observations.values().last().unwrap_or(&first);
            NatTopology::SymmetricNatRelayRequired {
                latest_observed: latest,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kademlia_xor_ordering_and_nat_cone_vs_symmetric_detection() {
        let local = Address::from_bytes([0x00; 32]);
        let mut dht = KademliaRoutingTable::new(local);

        let p_near = PeerDescriptor {
            address: Address::from_bytes([0x01; 32]),
            static_x25519: [1; 32],
            socket_addr: "127.0.0.1:9001".parse().unwrap(),
        };
        let p_far = PeerDescriptor {
            address: Address::from_bytes([0xff; 32]),
            static_x25519: [2; 32],
            socket_addr: "127.0.0.1:9002".parse().unwrap(),
        };
        assert!(dht.upsert_peer(p_far));
        assert!(dht.upsert_peer(p_near));

        let closest = dht.closest_peers(&local, 2);
        assert_eq!(closest[0].address, p_near.address);
        assert_eq!(closest[1].address, p_far.address);

        // NAT classification:
        let bind: SocketAddr = "192.168.1.25:9400".parse().unwrap();
        let mut nat = NatDetector::new(bind);
        let ext1: SocketAddr = "203.0.113.9:51200".parse().unwrap();
        let r1: SocketAddr = "198.51.100.1:9400".parse().unwrap();
        let r2: SocketAddr = "198.51.100.2:9400".parse().unwrap();

        assert_eq!(
            nat.record_observation(r1, ext1),
            NatTopology::EndpointIndependentCone {
                local_bind: bind,
                external_mapped: ext1
            }
        );
        assert_eq!(
            nat.record_observation(r2, ext1),
            NatTopology::EndpointIndependentCone {
                local_bind: bind,
                external_mapped: ext1
            }
        );

        // A third reporter sees a different NAT port -> Symmetric NAT!
        let ext_sym: SocketAddr = "203.0.113.9:51999".parse().unwrap();
        let r3: SocketAddr = "198.51.100.3:9400".parse().unwrap();
        assert_eq!(
            nat.record_observation(r3, ext_sym),
            NatTopology::SymmetricNatRelayRequired {
                latest_observed: ext_sym
            }
        );
    }
}
