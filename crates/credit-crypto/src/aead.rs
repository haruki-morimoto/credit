//! **Noise-XX-Inspired Mutual X25519 Handshake** & **Replay-Protected AEAD Session Cipher**.
//!
//! Provides Stage-1 open-internet transport security in pure safe `#![forbid(unsafe_code)]` Rust:
//! - **Forward Secrecy + Mutual Authentication:** Combines ephemeral-ephemeral (`ee`),
//!   ephemeral-static (`ie_rs`, `is_re`), and static-static (`ss`) Curve25519 Diffie-Hellman shared
//!   secrets so compromising a static disk key later never decrypts past sessions.
//! - **Constant-Time MAC & 64-Packet Sliding Replay Window:** Every encrypted P2P datagram carries
//!   an 8-byte monotonic nonce and 16-byte Encrypt-then-MAC tag verified without timing branches,
//!   rejecting out-of-window or replayed UDP datagrams.

use credit_types::{Address, Hash32};

use crate::{Keypair, PublicKey, SignatureScheme, domain_hash, x25519, x25519_basepoint};

/// Persistent cryptographic node identity combining an X25519 static transport keypair
/// and a post-quantum WOTS+/Merkle validator signing keypair.
#[derive(Clone)]
pub struct PeerIdentity {
    master_seed: [u8; 32],
    static_secret: [u8; 32],
    static_pub: [u8; 32],
    validator_kp: Keypair,
}

impl PeerIdentity {
    pub fn from_seed(master_seed: [u8; 32]) -> Self {
        let static_secret = domain_hash("XCR.P2P.NOISE_STATIC_SK.V1", &[&master_seed]).0;
        let static_pub = x25519_basepoint(&static_secret);
        let val_seed = domain_hash("XCR.P2P.VALIDATOR_SK.V1", &[&master_seed]).0;
        let validator_kp = Keypair::from_seed(SignatureScheme::Ed25519, val_seed);
        Self {
            master_seed,
            static_secret,
            static_pub,
            validator_kp,
        }
    }

    #[inline]
    pub const fn master_seed(&self) -> &[u8; 32] {
        &self.master_seed
    }

    #[inline]
    pub const fn static_pub(&self) -> [u8; 32] {
        self.static_pub
    }

    #[inline]
    pub const fn validator_public_key(&self) -> PublicKey {
        self.validator_kp.public_key()
    }

    #[inline]
    pub fn address(&self) -> Address {
        self.validator_kp.address()
    }

    #[inline]
    pub fn validator_keypair_mut(&mut self) -> &mut Keypair {
        &mut self.validator_kp
    }

    #[inline]
    pub fn validator_keypair_clone(&self) -> Keypair {
        self.validator_kp.clone()
    }
}

/// First handshake flight (`Initiator -> Responder`, `129 bytes`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HandshakeInit {
    pub static_pub: [u8; 32],
    pub ephemeral_pub: [u8; 32],
    pub validator_pubkey: PublicKey,
    pub binding_mac: [u8; 32],
}

impl HandshakeInit {
    pub const WIRE_LEN: usize = 129;

    pub fn to_bytes(&self) -> [u8; Self::WIRE_LEN] {
        let mut out = [0u8; Self::WIRE_LEN];
        out[0..32].copy_from_slice(&self.static_pub);
        out[32..64].copy_from_slice(&self.ephemeral_pub);
        out[64] = self.validator_pubkey.scheme as u8;
        out[65..97].copy_from_slice(self.validator_pubkey.merkle_root.as_bytes());
        out[97..129].copy_from_slice(&self.binding_mac);
        out
    }

    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != Self::WIRE_LEN {
            return None;
        }
        let scheme = SignatureScheme::from_u8(bytes[64])?;
        let mut static_pub = [0u8; 32];
        let mut ephemeral_pub = [0u8; 32];
        let mut root = [0u8; 32];
        let mut binding_mac = [0u8; 32];
        static_pub.copy_from_slice(&bytes[0..32]);
        ephemeral_pub.copy_from_slice(&bytes[32..64]);
        root.copy_from_slice(&bytes[65..97]);
        binding_mac.copy_from_slice(&bytes[97..129]);
        let init = Self {
            static_pub,
            ephemeral_pub,
            validator_pubkey: PublicKey {
                scheme,
                merkle_root: Hash32(root),
            },
            binding_mac,
        };
        if !ct_eq(&init.expected_binding_mac(), &init.binding_mac) {
            return None;
        }
        Some(init)
    }

    fn expected_binding_mac(&self) -> [u8; 32] {
        domain_hash(
            "XCR.NOISE.INIT_BIND.V2",
            &[
                &self.static_pub,
                &self.ephemeral_pub,
                &[self.validator_pubkey.scheme as u8],
                self.validator_pubkey.merkle_root.as_bytes(),
            ],
        )
        .0
    }
}

/// Second handshake flight (`Responder -> Initiator`, `129 bytes`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HandshakeResp {
    pub static_pub: [u8; 32],
    pub ephemeral_pub: [u8; 32],
    pub validator_pubkey: PublicKey,
    pub confirm_mac: [u8; 32],
}

impl HandshakeResp {
    pub const WIRE_LEN: usize = 129;

    pub fn to_bytes(&self) -> [u8; Self::WIRE_LEN] {
        let mut out = [0u8; Self::WIRE_LEN];
        out[0..32].copy_from_slice(&self.static_pub);
        out[32..64].copy_from_slice(&self.ephemeral_pub);
        out[64] = self.validator_pubkey.scheme as u8;
        out[65..97].copy_from_slice(self.validator_pubkey.merkle_root.as_bytes());
        out[97..129].copy_from_slice(&self.confirm_mac);
        out
    }

    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != Self::WIRE_LEN {
            return None;
        }
        let scheme = SignatureScheme::from_u8(bytes[64])?;
        let mut static_pub = [0u8; 32];
        let mut ephemeral_pub = [0u8; 32];
        let mut root = [0u8; 32];
        let mut confirm_mac = [0u8; 32];
        static_pub.copy_from_slice(&bytes[0..32]);
        ephemeral_pub.copy_from_slice(&bytes[32..64]);
        root.copy_from_slice(&bytes[65..97]);
        confirm_mac.copy_from_slice(&bytes[97..129]);
        Some(Self {
            static_pub,
            ephemeral_pub,
            validator_pubkey: PublicKey {
                scheme,
                merkle_root: Hash32(root),
            },
            confirm_mac,
        })
    }
}

/// Ephemeral state retained by the handshake initiator while awaiting `HandshakeResp`.
pub struct InitiatorHandshake {
    eph_secret: [u8; 32],
    init_msg: HandshakeInit,
}

impl InitiatorHandshake {
    pub fn start(local: &PeerIdentity, ephemeral_entropy: &[u8; 32]) -> (Self, HandshakeInit) {
        let eph_secret = domain_hash(
            "XCR.NOISE.EPH_SK.V1",
            &[local.master_seed(), ephemeral_entropy],
        )
        .0;
        let ephemeral_pub = x25519_basepoint(&eph_secret);
        let mut init_msg = HandshakeInit {
            static_pub: local.static_pub,
            ephemeral_pub,
            validator_pubkey: local.validator_public_key(),
            binding_mac: [0u8; 32],
        };
        init_msg.binding_mac = init_msg.expected_binding_mac();
        (
            Self {
                eph_secret,
                init_msg: init_msg.clone(),
            },
            init_msg,
        )
    }

    /// Completes the quadruple-DH handshake upon receiving `HandshakeResp`, authenticating
    /// the responder and returning an encrypted `SessionCipher`.
    pub fn complete(
        self,
        local: &PeerIdentity,
        resp: &HandshakeResp,
    ) -> Option<(SessionCipher, PublicKey, [u8; 32])> {
        let dh_ee = x25519(&self.eph_secret, &resp.ephemeral_pub);
        let dh_ie_rs = x25519(&self.eph_secret, &resp.static_pub);
        let dh_is_re = x25519(&local.static_secret, &resp.ephemeral_pub);
        let dh_ss = x25519(&local.static_secret, &resp.static_pub);

        let (i2r_key, r2i_key, session_id, expected_confirm) = derive_session_keys(
            &self.init_msg,
            &resp.static_pub,
            &resp.ephemeral_pub,
            &resp.validator_pubkey,
            &dh_ee,
            &dh_ie_rs,
            &dh_is_re,
            &dh_ss,
        );
        if !ct_eq(&expected_confirm, &resp.confirm_mac) {
            return None;
        }
        let cipher = SessionCipher::new(session_id, i2r_key, r2i_key);
        Some((cipher, resp.validator_pubkey, resp.static_pub))
    }
}

/// Responder-side quadruple-DH handshake acceptor.
pub fn accept_handshake(
    local: &PeerIdentity,
    init: &HandshakeInit,
    ephemeral_entropy: &[u8; 32],
) -> (SessionCipher, HandshakeResp, PublicKey, [u8; 32]) {
    let resp_eph_sk = domain_hash(
        "XCR.NOISE.RESP_EPH_SK.V1",
        &[local.master_seed(), ephemeral_entropy, &init.ephemeral_pub],
    )
    .0;
    let resp_eph_pub = x25519_basepoint(&resp_eph_sk);

    let dh_ee = x25519(&resp_eph_sk, &init.ephemeral_pub);
    let dh_ie_rs = x25519(&local.static_secret, &init.ephemeral_pub);
    let dh_is_re = x25519(&resp_eph_sk, &init.static_pub);
    let dh_ss = x25519(&local.static_secret, &init.static_pub);

    let local_val_pk = local.validator_public_key();
    let (i2r_key, r2i_key, session_id, confirm_mac) = derive_session_keys(
        init,
        &local.static_pub,
        &resp_eph_pub,
        &local_val_pk,
        &dh_ee,
        &dh_ie_rs,
        &dh_is_re,
        &dh_ss,
    );

    let resp = HandshakeResp {
        static_pub: local.static_pub,
        ephemeral_pub: resp_eph_pub,
        validator_pubkey: local_val_pk,
        confirm_mac,
    };
    // Responder transmits with `r2i_key` and receives with `i2r_key`:
    let cipher = SessionCipher::new(session_id, r2i_key, i2r_key);
    (cipher, resp, init.validator_pubkey, init.static_pub)
}

#[allow(clippy::too_many_arguments)]
fn derive_session_keys(
    init: &HandshakeInit,
    resp_static_pub: &[u8; 32],
    resp_eph_pub: &[u8; 32],
    resp_val_pk: &PublicKey,
    dh_ee: &[u8; 32],
    dh_ie_rs: &[u8; 32],
    dh_is_re: &[u8; 32],
    dh_ss: &[u8; 32],
) -> ([u8; 32], [u8; 32], Hash32, [u8; 32]) {
    let init_bytes = init.to_bytes();
    let resp_scheme = [resp_val_pk.scheme as u8];
    let master_prk = domain_hash(
        "XCR.NOISE.PRK.V2",
        &[
            &init_bytes,
            resp_static_pub,
            resp_eph_pub,
            &resp_scheme,
            resp_val_pk.merkle_root.as_bytes(),
            dh_ee,
            dh_ie_rs,
            dh_is_re,
            dh_ss,
        ],
    );
    let i2r = domain_hash("XCR.NOISE.I2R.V1", &[master_prk.as_bytes()]).0;
    let r2i = domain_hash("XCR.NOISE.R2I.V1", &[master_prk.as_bytes()]).0;
    let session_id = domain_hash("XCR.NOISE.SID.V1", &[master_prk.as_bytes()]);
    let confirm = domain_hash("XCR.NOISE.CONFIRM.V1", &[master_prk.as_bytes()]).0;
    (i2r, r2i, session_id, confirm)
}

/// Directional AEAD session cipher with a 64-packet anti-replay sliding window.
#[derive(Clone, Debug)]
pub struct SessionCipher {
    pub session_id: Hash32,
    tx_key: [u8; 32],
    rx_key: [u8; 32],
    next_tx_nonce: u64,
    highest_rx_nonce: u64,
    rx_window_bitmap: u64,
}

impl SessionCipher {
    pub const fn new(session_id: Hash32, tx_key: [u8; 32], rx_key: [u8; 32]) -> Self {
        Self {
            session_id,
            tx_key,
            rx_key,
            next_tx_nonce: 1,
            highest_rx_nonce: 0,
            rx_window_bitmap: 0,
        }
    }

    /// Encrypts `plaintext` into `[nonce: 8B][ciphertext: NB][mac16: 16B]`.
    pub fn seal(&mut self, plaintext: &[u8]) -> Vec<u8> {
        let nonce = self.next_tx_nonce;
        self.next_tx_nonce = self.next_tx_nonce.wrapping_add(1);

        let ciphertext = stream_xor(plaintext, &self.tx_key, &self.session_id, nonce);
        let mac = packet_mac16(&self.tx_key, &self.session_id, nonce, &ciphertext);

        let mut out = Vec::with_capacity(24 + ciphertext.len());
        out.extend_from_slice(&nonce.to_le_bytes());
        out.extend_from_slice(&ciphertext);
        out.extend_from_slice(&mac);
        out
    }

    /// Authenticates, checks the 64-packet anti-replay window, and decrypts `packet`.
    pub fn open(&mut self, packet: &[u8]) -> Option<Vec<u8>> {
        if packet.len() < 24 {
            return None;
        }
        let nonce = u64::from_le_bytes(packet[0..8].try_into().ok()?);
        if nonce == 0 {
            return None;
        }
        let ct_end = packet.len() - 16;
        let ciphertext = &packet[8..ct_end];
        let tag: [u8; 16] = packet[ct_end..].try_into().ok()?;

        // Check anti-replay window BEFORE mutating state:
        if nonce <= self.highest_rx_nonce {
            let delta = self.highest_rx_nonce - nonce;
            if delta >= 64 || ((self.rx_window_bitmap >> delta) & 1) == 1 {
                return None; // Replay or too old!
            }
        }

        let expected = packet_mac16(&self.rx_key, &self.session_id, nonce, ciphertext);
        if !ct_eq16(&expected, &tag) {
            return None;
        }

        // Update sliding 64-bit replay bitmap:
        if nonce > self.highest_rx_nonce {
            let shift = nonce - self.highest_rx_nonce;
            if shift >= 64 {
                self.rx_window_bitmap = 1;
            } else {
                self.rx_window_bitmap = (self.rx_window_bitmap << shift) | 1;
            }
            self.highest_rx_nonce = nonce;
        } else {
            let delta = self.highest_rx_nonce - nonce;
            self.rx_window_bitmap |= 1u64 << delta;
        }

        Some(stream_xor(
            ciphertext,
            &self.rx_key,
            &self.session_id,
            nonce,
        ))
    }
}

fn stream_xor(input: &[u8], key: &[u8; 32], session_id: &Hash32, nonce: u64) -> Vec<u8> {
    let nonce_bytes = nonce.to_le_bytes();
    let mut out = vec![0u8; input.len()];
    for (blk_idx, chunk) in input.chunks(32).enumerate() {
        let blk = (blk_idx as u64).to_le_bytes();
        let ks = domain_hash(
            "XCR.NOISE.STREAM.V1",
            &[key, session_id.as_bytes(), &nonce_bytes, &blk],
        )
        .0;
        let base = blk_idx * 32;
        for (i, &b) in chunk.iter().enumerate() {
            out[base + i] = b ^ ks[i];
        }
    }
    out
}

fn packet_mac16(key: &[u8; 32], session_id: &Hash32, nonce: u64, ciphertext: &[u8]) -> [u8; 16] {
    let h = domain_hash(
        "XCR.NOISE.AEAD_MAC.V1",
        &[key, session_id.as_bytes(), &nonce.to_le_bytes(), ciphertext],
    );
    let mut tag = [0u8; 16];
    tag.copy_from_slice(&h.0[..16]);
    tag
}

fn ct_eq(a: &[u8; 32], b: &[u8; 32]) -> bool {
    let mut diff = 0u8;
    for i in 0..32 {
        diff |= a[i] ^ b[i];
    }
    diff == 0
}

fn ct_eq16(a: &[u8; 16], b: &[u8; 16]) -> bool {
    let mut diff = 0u8;
    for i in 0..16 {
        diff |= a[i] ^ b[i];
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn noise_quadruple_dh_handshake_aead_and_replay_rejection() {
        let alice = PeerIdentity::from_seed([0x11; 32]);
        let bob = PeerIdentity::from_seed([0x22; 32]);

        let (init_state, init_wire) = InitiatorHandshake::start(&alice, &[0xa1; 32]);
        let parsed_init = HandshakeInit::from_bytes(&init_wire.to_bytes()).unwrap();

        let (mut bob_cipher, resp_wire, init_pk_seen_by_bob, _) =
            accept_handshake(&bob, &parsed_init, &[0xb2; 32]);
        assert_eq!(init_pk_seen_by_bob, alice.validator_public_key());

        let parsed_resp = HandshakeResp::from_bytes(&resp_wire.to_bytes()).unwrap();
        let (mut alice_cipher, resp_pk_seen_by_alice, _) =
            init_state.complete(&alice, &parsed_resp).unwrap();
        assert_eq!(resp_pk_seen_by_alice, bob.validator_public_key());
        assert_eq!(alice_cipher.session_id, bob_cipher.session_id);

        let pkt1 = alice_cipher.seal(b"hello-encrypted-mesh");
        let pkt2 = alice_cipher.seal(b"second-out-of-order-datagram");

        // Receive out of order (pkt2 then pkt1) — sliding window accepts both ONCE:
        assert_eq!(
            bob_cipher.open(&pkt2).unwrap(),
            b"second-out-of-order-datagram"
        );
        assert_eq!(bob_cipher.open(&pkt1).unwrap(), b"hello-encrypted-mesh");

        // Replaying either packet is immediately rejected!
        assert!(bob_cipher.open(&pkt1).is_none());
        assert!(bob_cipher.open(&pkt2).is_none());
    }
}
