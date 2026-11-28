//! **Monero + Zcash Shielded Ring-Confidential Pool (`MLSAG` RingCT), Read-Only `ViewingKey` (`xcrview1_`),
//! & Selective Disclosure `PaymentProof` (`xcrtxproof1_`)**.
//!
//! Closes Credit's sender & amount privacy gap relative to Monero (`XMR`) and Zcash (`ZEC`) with
//! **zero trusted setup** and **flat validator RAM**:
//! 1. **Shielded `Pedersen` Notes:** Notes commit `C = v*B + r*H` (`PedersenCommitment`) to hide
//!    amounts while encrypting `(v, r)` to the recipient's `ShieldedViewingKey` (`xcrview1_`).
//! 2. **`1-of-N` Curve25519 Linkable RingCT (`MLSAG`):** Proves in a single ring challenge loop
//!    that one of `N` (`1..=16`) pool notes `(P_i, C_i)` is owned by the signer, emits a
//!    prime-subgroup-verified **Key Image (`I = x * H_p(P_pi)`)** preventing double-spends without
//!    revealing *which* note was spent, and proves `C_pi - C_out - (public_out + fee)*B = z*H`!
//! 3. **Read-Only `ViewingKey` & `PaymentDisclosureProof` (`DLEQ`):** Share `xcrview1_` with
//!    auditors/accountants (`0` spend authority) or prove a specific payment via `xcrtxproof1_`.

use credit_crypto::{
    EdwardsPoint, Keypair, PublicKey, Scalar, Signature, SignatureScheme, ct_eq_slice, domain_hash,
};
use credit_types::{Address, Amount, Hash32};

/// Deterministic prime-order Curve25519 hash-to-point `H_p(data)` (`8 * P` clears cofactor).
pub fn hash_to_prime_point(tag: &str, data: &[u8]) -> EdwardsPoint {
    for ctr in 0u32..512 {
        let cand = domain_hash(tag, &[data, &ctr.to_le_bytes()]).0;
        if let Some(pt) = EdwardsPoint::from_bytes(&cand) {
            let prime = pt.double().double().double();
            if prime != EdwardsPoint::identity() {
                return prime;
            }
        }
    }
    EdwardsPoint::pedersen_generator_h()
}

/// Verifies that `pt` is non-identity and strictly inside the prime-order `l` subgroup (`l * pt == O`),
/// defeating Monero's 2017 small-subgroup torsion Key-Image double-spend attack.
pub fn is_valid_prime_order_key_image(pt: &EdwardsPoint) -> bool {
    if *pt == EdwardsPoint::identity() {
        return false;
    }
    let minus_one = Scalar::ZERO - Scalar::from_u64(1);
    let l_times_pt = (minus_one * pt) + *pt;
    l_times_pt == EdwardsPoint::identity()
}

/// Read-only incoming `ViewingKey` (`xcrview1_<128-hex>`) for tax auditors or public charity treasuries.
/// Allows scanning & decrypting incoming shielded notes with **zero** ability to compute `spend_scalar`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ShieldedViewingKey {
    pub view_scalar_bytes: [u8; 32],
    pub view_pubkey: [u8; 32],
    pub spend_pubkey: [u8; 32],
}

impl ShieldedViewingKey {
    pub const PREFIX: &'static str = "xcrview1_";

    pub fn from_master_seed(master_seed: &[u8; 32]) -> (Scalar, Scalar, Self) {
        let view_sc = Scalar::hash_from_parts("XCR.SHIELD.VIEW_SK.V1", &[master_seed]);
        let spend_sc = Scalar::hash_from_parts("XCR.SHIELD.SPEND_SK.V1", &[master_seed]);
        let b = EdwardsPoint::basepoint_b();
        let view_pub = (view_sc * &b).to_bytes();
        let spend_pub = (spend_sc * &b).to_bytes();
        (
            view_sc,
            spend_sc,
            Self {
                view_scalar_bytes: *view_sc.as_bytes(),
                view_pubkey: view_pub,
                spend_pubkey: spend_pub,
            },
        )
    }

    pub fn to_uri(&self) -> String {
        let mut raw = [0u8; 64];
        raw[0..32].copy_from_slice(&self.view_scalar_bytes);
        raw[32..64].copy_from_slice(&self.spend_pubkey);
        format!("{}{}", Self::PREFIX, hex_encode(&raw))
    }

    pub fn from_uri(uri: &str) -> Option<Self> {
        let hex_part = uri.trim().strip_prefix(Self::PREFIX)?;
        let raw = hex_decode(hex_part)?;
        if raw.len() != 64 {
            return None;
        }
        let mut vs = [0u8; 32];
        vs.copy_from_slice(&raw[0..32]);
        let view_sc = Scalar::from_canonical_bytes(&vs)?;
        let mut sp = [0u8; 32];
        sp.copy_from_slice(&raw[32..64]);
        let _ = EdwardsPoint::from_bytes(&sp)?;
        let view_pubkey = (view_sc * &EdwardsPoint::basepoint_b()).to_bytes();
        Some(Self {
            view_scalar_bytes: vs,
            view_pubkey,
            spend_pubkey: sp,
        })
    }
}

/// Public shielded note stored in the Layer-1 anonymity pool (`89` bytes).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ShieldedNoteOutput {
    pub note_id: Hash32,
    pub one_time_pub: [u8; 32],
    pub pedersen_commit: [u8; 32],
    pub ephemeral_pub: [u8; 32],
    pub view_tag: u8,
    /// `8B` XOR-encrypted `amount_bits` + `32B` XOR-encrypted `blinding` + `8B` MAC tag (`48B`).
    pub encrypted_payload: [u8; 48],
}

impl ShieldedNoteOutput {
    /// Creates a shielded Pedersen note payable to `(recipient_view_pub, recipient_spend_pub)`.
    pub fn create(
        recipient_view_pub: &[u8; 32],
        recipient_spend_pub: &[u8; 32],
        amount: Amount,
        eph_entropy: &[u8; 32],
    ) -> Option<(Self, Scalar, [u8; 32])> {
        let v_pt = EdwardsPoint::from_bytes(recipient_view_pub)?;
        let s_pt = EdwardsPoint::from_bytes(recipient_spend_pub)?;
        let b = EdwardsPoint::basepoint_b();
        let h = EdwardsPoint::pedersen_generator_h();

        let r_eph = Scalar::hash_from_parts("XCR.SHIELD.EPH_R.V1", &[eph_entropy]);
        let eph_pub = (r_eph * &b).to_bytes();
        let shared_pt = (r_eph * &v_pt).to_bytes();

        let view_tag = domain_hash("XCR.SHIELD.VTAG.V1", &[&shared_pt]).0[0];
        let kdf_sc = Scalar::hash_from_parts("XCR.SHIELD.KDF.V1", &[&shared_pt, &eph_pub]);
        let one_time_pub = (s_pt + (kdf_sc * &b)).to_bytes();

        let blind = Scalar::hash_from_parts("XCR.SHIELD.BLIND.V1", &[&shared_pt, &one_time_pub]);
        let commit_pt = (Scalar::from_u64(amount.bits()) * &b) + (blind * &h);
        let pedersen_commit = commit_pt.to_bytes();

        let mut encrypted_payload = [0u8; 48];
        let stream0 = domain_hash("XCR.SHIELD.ENC0.V1", &[&shared_pt]).0;
        let stream1 = domain_hash("XCR.SHIELD.ENC1.V1", &[&shared_pt]).0;
        let amt_le = amount.bits().to_le_bytes();
        for i in 0..8 {
            encrypted_payload[i] = amt_le[i] ^ stream0[i];
        }
        let blind_bytes = *blind.as_bytes();
        for i in 0..32 {
            encrypted_payload[8 + i] = blind_bytes[i] ^ stream1[i];
        }
        let mac = domain_hash(
            "XCR.SHIELD.MAC.V1",
            &[&shared_pt, &amt_le, &blind_bytes, &pedersen_commit],
        )
        .0;
        encrypted_payload[40..48].copy_from_slice(&mac[..8]);

        let note_id = domain_hash(
            "XCR.SHIELD.NOTE_ID.V1",
            &[&one_time_pub, &pedersen_commit, &eph_pub],
        );
        Some((
            Self {
                note_id,
                one_time_pub,
                pedersen_commit,
                ephemeral_pub: eph_pub,
                view_tag,
                encrypted_payload,
            },
            blind,
            shared_pt,
        ))
    }

    /// Scans & decrypts this shielded note using a **read-only** `ShieldedViewingKey`!
    pub fn scan_with_view_key(&self, vk: &ShieldedViewingKey) -> Option<(Amount, Scalar, Scalar)> {
        let view_sc = Scalar::from_canonical_bytes(&vk.view_scalar_bytes)?;
        let eph_pt = EdwardsPoint::from_bytes(&self.ephemeral_pub)?;
        let spend_pt = EdwardsPoint::from_bytes(&vk.spend_pubkey)?;
        let shared_pt = (view_sc * &eph_pt).to_bytes();

        if domain_hash("XCR.SHIELD.VTAG.V1", &[&shared_pt]).0[0] != self.view_tag {
            return None;
        }
        let b = EdwardsPoint::basepoint_b();
        let h = EdwardsPoint::pedersen_generator_h();
        let kdf_sc =
            Scalar::hash_from_parts("XCR.SHIELD.KDF.V1", &[&shared_pt, &self.ephemeral_pub]);
        let expected_pub = (spend_pt + (kdf_sc * &b)).to_bytes();
        if !ct_eq_slice(&expected_pub, &self.one_time_pub) {
            return None;
        }

        let stream0 = domain_hash("XCR.SHIELD.ENC0.V1", &[&shared_pt]).0;
        let stream1 = domain_hash("XCR.SHIELD.ENC1.V1", &[&shared_pt]).0;
        let mut amt_le = [0u8; 8];
        for i in 0..8 {
            amt_le[i] = self.encrypted_payload[i] ^ stream0[i];
        }
        let mut blind_bytes = [0u8; 32];
        for i in 0..32 {
            blind_bytes[i] = self.encrypted_payload[8 + i] ^ stream1[i];
        }
        let mac = domain_hash(
            "XCR.SHIELD.MAC.V1",
            &[&shared_pt, &amt_le, &blind_bytes, &self.pedersen_commit],
        )
        .0;
        if !ct_eq_slice(&mac[..8], &self.encrypted_payload[40..48]) {
            return None;
        }
        let blind = Scalar::from_canonical_bytes(&blind_bytes)?;
        let amount = Amount::from_bits(u64::from_le_bytes(amt_le));
        let check_c = ((Scalar::from_u64(amount.bits()) * &b) + (blind * &h)).to_bytes();
        if !ct_eq_slice(&check_c, &self.pedersen_commit) {
            return None;
        }
        Some((amount, blind, kdf_sc))
    }
}

/// Monero-style `MLSAG` Linkable RingCT signature over `N` (`1..=16`) pool members `(P_i, C_i)`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RingCtSignature {
    pub key_image: [u8; 32],
    pub c0: [u8; 32],
    pub responses: Vec<([u8; 32], [u8; 32])>,
}

impl RingCtSignature {
    /// Signs `msg` proving ownership of `ring[real_index]` (`P_pi = x*B`) AND exact Pedersen balance
    /// `C_pi - target_commit == z * H` without revealing `real_index`!
    pub fn sign(
        msg: &Hash32,
        ring: &[([u8; 32], [u8; 32])],
        real_index: usize,
        secret_x: Scalar,
        secret_z: Scalar,
        target_commit: &EdwardsPoint,
        nonce_entropy: &[u8; 32],
    ) -> Result<Self, &'static str> {
        let n = ring.len();
        if !(1..=16).contains(&n) || real_index >= n {
            return Err("ring size must be 1..=16 and real_index < ring.len()");
        }
        let b = EdwardsPoint::basepoint_b();
        let h = EdwardsPoint::pedersen_generator_h();

        let (real_pub_bytes, real_c_bytes) = ring[real_index];
        let real_pub = EdwardsPoint::from_bytes(&real_pub_bytes).ok_or("invalid real pubkey")?;
        let real_c = EdwardsPoint::from_bytes(&real_c_bytes).ok_or("invalid real commitment")?;
        if (secret_x * &b) != real_pub {
            return Err("secret_x does not match ring[real_index] one_time_pub");
        }
        if (real_c - *target_commit) != (secret_z * &h) {
            return Err("Pedersen commitment balance mismatch (inputs != outputs + fee)");
        }

        let hp_real = hash_to_prime_point("XCR.SHIELD.HP.V1", &real_pub_bytes);
        let key_image_pt = secret_x * &hp_real;
        let key_image = key_image_pt.to_bytes();

        let alpha_x =
            Scalar::hash_from_parts("XCR.SHIELD.ALPHA_X.V1", &[nonce_entropy, msg.as_bytes()]);
        let alpha_z =
            Scalar::hash_from_parts("XCR.SHIELD.ALPHA_Z.V1", &[nonce_entropy, &key_image]);

        let mut challenges = vec![Scalar::ZERO; n];
        let mut responses = vec![([0u8; 32], [0u8; 32]); n];

        let l_pi = (alpha_x * &b).to_bytes();
        let r_pi = (alpha_x * &hp_real).to_bytes();
        let m_pi = (alpha_z * &h).to_bytes();
        let mut cur_c = ring_challenge(msg, &key_image, &l_pi, &r_pi, &m_pi);

        for offset in 1..n {
            let idx = (real_index + offset) % n;
            challenges[idx] = cur_c;

            let sx = Scalar::hash_from_parts(
                "XCR.SHIELD.DECOY_SX.V1",
                &[nonce_entropy, &(idx as u32).to_le_bytes()],
            );
            let sz = Scalar::hash_from_parts(
                "XCR.SHIELD.DECOY_SZ.V1",
                &[nonce_entropy, &(idx as u32).to_le_bytes(), &[1]],
            );
            responses[idx] = (*sx.as_bytes(), *sz.as_bytes());

            let pi_pt = EdwardsPoint::from_bytes(&ring[idx].0).ok_or("invalid decoy pubkey")?;
            let ci_pt = EdwardsPoint::from_bytes(&ring[idx].1).ok_or("invalid decoy commitment")?;
            let hp_i = hash_to_prime_point("XCR.SHIELD.HP.V1", &ring[idx].0);
            let diff_c = ci_pt - *target_commit;

            let li = ((sx * &b) + (cur_c * &pi_pt)).to_bytes();
            let ri = ((sx * &hp_i) + (cur_c * &key_image_pt)).to_bytes();
            let mi = ((sz * &h) + (cur_c * &diff_c)).to_bytes();
            cur_c = ring_challenge(msg, &key_image, &li, &ri, &mi);
        }

        challenges[real_index] = cur_c;
        let sx_real = alpha_x - (cur_c * secret_x);
        let sz_real = alpha_z - (cur_c * secret_z);
        responses[real_index] = (*sx_real.as_bytes(), *sz_real.as_bytes());

        Ok(Self {
            key_image,
            c0: *challenges[0].as_bytes(),
            responses,
        })
    }

    /// Verifies the `1-of-N` RingCT signature, prime-order `KeyImage` subgroup membership, and
    /// homomorphic Pedersen balance conservation!
    pub fn verify(
        &self,
        msg: &Hash32,
        ring: &[([u8; 32], [u8; 32])],
        target_commit: &EdwardsPoint,
    ) -> bool {
        let n = ring.len();
        if !(1..=16).contains(&n) || self.responses.len() != n {
            return false;
        }
        let Some(key_image_pt) = EdwardsPoint::from_bytes(&self.key_image) else {
            return false;
        };
        if !is_valid_prime_order_key_image(&key_image_pt) {
            return false;
        }
        let Some(c0_sc) = Scalar::from_canonical_bytes(&self.c0) else {
            return false;
        };
        let b = EdwardsPoint::basepoint_b();
        let h = EdwardsPoint::pedersen_generator_h();

        let mut cur_c = c0_sc;
        for i in 0..n {
            let Some(sx) = Scalar::from_canonical_bytes(&self.responses[i].0) else {
                return false;
            };
            let Some(sz) = Scalar::from_canonical_bytes(&self.responses[i].1) else {
                return false;
            };
            let Some(pi_pt) = EdwardsPoint::from_bytes(&ring[i].0) else {
                return false;
            };
            let Some(ci_pt) = EdwardsPoint::from_bytes(&ring[i].1) else {
                return false;
            };
            let hp_i = hash_to_prime_point("XCR.SHIELD.HP.V1", &ring[i].0);
            let diff_c = ci_pt - *target_commit;

            let li = ((sx * &b) + (cur_c * &pi_pt)).to_bytes();
            let ri = ((sx * &hp_i) + (cur_c * &key_image_pt)).to_bytes();
            let mi = ((sz * &h) + (cur_c * &diff_c)).to_bytes();
            cur_c = ring_challenge(msg, &self.key_image, &li, &ri, &mi);
        }

        ct_eq_slice(cur_c.as_bytes(), &self.c0)
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(65 + self.responses.len() * 64);
        out.extend_from_slice(&self.key_image);
        out.extend_from_slice(&self.c0);
        out.push(self.responses.len() as u8);
        for (sx, sz) in &self.responses {
            out.extend_from_slice(sx);
            out.extend_from_slice(sz);
        }
        out
    }

    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < 65 {
            return None;
        }
        let key_image: [u8; 32] = bytes[0..32].try_into().ok()?;
        let c0: [u8; 32] = bytes[32..64].try_into().ok()?;
        let n = bytes[64] as usize;
        if !(1..=16).contains(&n) || bytes.len() != 65 + n * 64 {
            return None;
        }
        let mut responses = Vec::with_capacity(n);
        let mut pos = 65usize;
        for _ in 0..n {
            let sx: [u8; 32] = bytes[pos..pos + 32].try_into().ok()?;
            let sz: [u8; 32] = bytes[pos + 32..pos + 64].try_into().ok()?;
            responses.push((sx, sz));
            pos += 64;
        }
        Some(Self {
            key_image,
            c0,
            responses,
        })
    }
}

fn ring_challenge(
    msg: &Hash32,
    key_image: &[u8; 32],
    li: &[u8; 32],
    ri: &[u8; 32],
    mi: &[u8; 32],
) -> Scalar {
    Scalar::hash_from_parts(
        "XCR.SHIELD.RINGCT_CHAL.V1",
        &[msg.as_bytes(), key_image, li, ri, mi],
    )
}

/// Monero `TxProof` / Zcash `PaymentDisclosure` Chaum-Pedersen `DLEQ` proof (`xcrtxproof1_`):
/// Proves `R == r*B` AND `shared_pt == r*V_recipient` without exposing the sender's wallet seed!
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PaymentDisclosureProof {
    pub ephemeral_pub: [u8; 32],
    pub recipient_view_pub: [u8; 32],
    pub shared_point: [u8; 32],
    pub c: [u8; 32],
    pub s: [u8; 32],
}

impl PaymentDisclosureProof {
    pub const PREFIX: &'static str = "xcrtxproof1_";

    pub fn generate(
        eph_secret_r: Scalar,
        recipient_view_pub: &[u8; 32],
        context_note_id: &Hash32,
    ) -> Option<Self> {
        let v_pt = EdwardsPoint::from_bytes(recipient_view_pub)?;
        let b = EdwardsPoint::basepoint_b();
        let eph_pub = (eph_secret_r * &b).to_bytes();
        let shared_pt = (eph_secret_r * &v_pt).to_bytes();

        let k = Scalar::hash_from_parts(
            "XCR.TXPROOF.NONCE.V1",
            &[eph_secret_r.as_bytes(), context_note_id.as_bytes()],
        );
        let a1 = (k * &b).to_bytes();
        let a2 = (k * &v_pt).to_bytes();
        let c = Scalar::hash_from_parts(
            "XCR.TXPROOF.DLEQ.V1",
            &[
                context_note_id.as_bytes(),
                &eph_pub,
                recipient_view_pub,
                &shared_pt,
                &a1,
                &a2,
            ],
        );
        let s = k - (c * eph_secret_r);
        Some(Self {
            ephemeral_pub: eph_pub,
            recipient_view_pub: *recipient_view_pub,
            shared_point: shared_pt,
            c: *c.as_bytes(),
            s: *s.as_bytes(),
        })
    }

    pub fn verify(&self, context_note_id: &Hash32) -> bool {
        let Some(r_pt) = EdwardsPoint::from_bytes(&self.ephemeral_pub) else {
            return false;
        };
        let Some(v_pt) = EdwardsPoint::from_bytes(&self.recipient_view_pub) else {
            return false;
        };
        let Some(sh_pt) = EdwardsPoint::from_bytes(&self.shared_point) else {
            return false;
        };
        let Some(c_sc) = Scalar::from_canonical_bytes(&self.c) else {
            return false;
        };
        let Some(s_sc) = Scalar::from_canonical_bytes(&self.s) else {
            return false;
        };
        let b = EdwardsPoint::basepoint_b();
        let a1 = ((s_sc * &b) + (c_sc * &r_pt)).to_bytes();
        let a2 = ((s_sc * &v_pt) + (c_sc * &sh_pt)).to_bytes();
        let expected_c = Scalar::hash_from_parts(
            "XCR.TXPROOF.DLEQ.V1",
            &[
                context_note_id.as_bytes(),
                &self.ephemeral_pub,
                &self.recipient_view_pub,
                &self.shared_point,
                &a1,
                &a2,
            ],
        );
        ct_eq_slice(expected_c.as_bytes(), &self.c)
    }

    pub fn to_uri(&self) -> String {
        let mut raw = [0u8; 160];
        raw[0..32].copy_from_slice(&self.ephemeral_pub);
        raw[32..64].copy_from_slice(&self.recipient_view_pub);
        raw[64..96].copy_from_slice(&self.shared_point);
        raw[96..128].copy_from_slice(&self.c);
        raw[128..160].copy_from_slice(&self.s);
        format!("{}{}", Self::PREFIX, hex_encode(&raw))
    }

    pub fn from_uri(uri: &str) -> Option<Self> {
        let hex_part = uri.trim().strip_prefix(Self::PREFIX)?;
        let raw = hex_decode(hex_part)?;
        if raw.len() != 160 {
            return None;
        }
        Some(Self {
            ephemeral_pub: raw[0..32].try_into().ok()?,
            recipient_view_pub: raw[32..64].try_into().ok()?,
            shared_point: raw[64..96].try_into().ok()?,
            c: raw[96..128].try_into().ok()?,
            s: raw[128..160].try_into().ok()?,
        })
    }
}

pub fn shield_deposit_digest(
    depositor: &Address,
    note_id: &Hash32,
    amount: Amount,
    fee: Amount,
) -> Hash32 {
    domain_hash(
        "XCR.SHIELD.DEPOSIT.V1",
        &[
            depositor.as_bytes(),
            note_id.as_bytes(),
            &amount.bits().to_le_bytes(),
            &fee.bits().to_le_bytes(),
        ],
    )
}

pub fn sign_shield_deposit(
    master_seed: &[u8; 32],
    note_id: &Hash32,
    amount: Amount,
    fee: Amount,
) -> (Address, PublicKey, Hash32, [u8; 65]) {
    let sk = domain_hash("XCR.WALLET.POCKET_KEY.V1", &[master_seed]).0;
    let mut kp = Keypair::from_seed(SignatureScheme::PasskeyP256, sk);
    let addr = kp.address();
    let tx_id = shield_deposit_digest(&addr, note_id, amount, fee);
    let sig = kp.sign(tx_id.as_bytes());
    let mut sig65 = [0u8; 65];
    sig65.copy_from_slice(&sig.to_bytes());
    (addr, kp.public_key(), tx_id, sig65)
}

pub fn verify_pocket_sig(
    pubkey: &PublicKey,
    owner: &Address,
    digest: &Hash32,
    sig65: &[u8; 65],
) -> bool {
    pubkey.to_address() == *owner
        && Signature::from_bytes(sig65).is_some_and(|s| pubkey.verify(digest.as_bytes(), &s))
}

fn hex_encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

fn hex_decode(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return None;
    }
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len() / 2);
    for pair in b.as_chunks::<2>().0 {
        let hi = match pair[0] {
            c @ b'0'..=b'9' => c - b'0',
            c @ b'a'..=b'f' => c - b'a' + 10,
            c @ b'A'..=b'F' => c - b'A' + 10,
            _ => return None,
        };
        let lo = match pair[1] {
            c @ b'0'..=b'9' => c - b'0',
            c @ b'a'..=b'f' => c - b'a' + 10,
            c @ b'A'..=b'F' => c - b'A' + 10,
            _ => return None,
        };
        out.push((hi << 4) | lo);
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn monero_zcash_ringct_shielded_note_viewkey_and_dleq_txproof_roundtrip() {
        let (_alice_vs, _alice_ss, alice_vk) = ShieldedViewingKey::from_master_seed(&[0x11; 32]);
        let (_bob_vs, bob_spend_sc, bob_vk) = ShieldedViewingKey::from_master_seed(&[0x22; 32]);

        let vk_reloaded = ShieldedViewingKey::from_uri(&bob_vk.to_uri()).unwrap();
        assert_eq!(vk_reloaded, bob_vk);

        // Create 4 notes (3 decoys + 1 real note owned by Bob):
        let (decoy0, _, _) = ShieldedNoteOutput::create(
            &alice_vk.view_pubkey,
            &alice_vk.spend_pubkey,
            Amount::from_credits(7).unwrap(),
            &[1u8; 32],
        )
        .unwrap();
        let (decoy1, _, _) = ShieldedNoteOutput::create(
            &alice_vk.view_pubkey,
            &alice_vk.spend_pubkey,
            Amount::from_credits(19).unwrap(),
            &[2u8; 32],
        )
        .unwrap();
        let (bob_note, _bob_blind, _) = ShieldedNoteOutput::create(
            &bob_vk.view_pubkey,
            &bob_vk.spend_pubkey,
            Amount::from_credits(10).unwrap(),
            &[3u8; 32],
        )
        .unwrap();
        let (decoy3, _, _) = ShieldedNoteOutput::create(
            &alice_vk.view_pubkey,
            &alice_vk.spend_pubkey,
            Amount::from_credits(3).unwrap(),
            &[4u8; 32],
        )
        .unwrap();

        // Auditor with Bob's Read-Only ViewingKey (`xcrview1_`) scans & decrypts Bob's 10 XCR note!
        let (scanned_amt, scanned_blind, kdf_sc) =
            bob_note.scan_with_view_key(&vk_reloaded).unwrap();
        assert_eq!(scanned_amt, Amount::from_credits(10).unwrap());
        assert!(decoy0.scan_with_view_key(&vk_reloaded).is_none());

        // Bob spends his 10 XCR note inside a 1-of-4 RingCT (sending 6 XCR shielded + 3.9995 XCR unshielded + 0.0005 fee):
        let (out_note, out_blind, _) = ShieldedNoteOutput::create(
            &alice_vk.view_pubkey,
            &alice_vk.spend_pubkey,
            Amount::from_credits(6).unwrap(),
            &[5u8; 32],
        )
        .unwrap();
        let public_unshield_and_fee = Amount::from_credits(4).unwrap();
        let b = EdwardsPoint::basepoint_b();
        let out_c = EdwardsPoint::from_bytes(&out_note.pedersen_commit).unwrap();
        let target_c = out_c + (Scalar::from_u64(public_unshield_and_fee.bits()) * &b);

        let ring = vec![
            (decoy0.one_time_pub, decoy0.pedersen_commit),
            (decoy1.one_time_pub, decoy1.pedersen_commit),
            (bob_note.one_time_pub, bob_note.pedersen_commit),
            (decoy3.one_time_pub, decoy3.pedersen_commit),
        ];
        let real_x = bob_spend_sc + kdf_sc;
        let real_z = scanned_blind - out_blind;
        let msg = domain_hash("TEST.RINGCT.SPEND", &[out_note.note_id.as_bytes()]);

        let ring_sig =
            RingCtSignature::sign(&msg, &ring, 2, real_x, real_z, &target_c, &[9u8; 32]).unwrap();
        assert!(ring_sig.verify(&msg, &ring, &target_c));

        // Tampering with public amount breaks homomorphic RingCT verification!
        let wrong_target = out_c + (Scalar::from_u64(5_000_000) * &b);
        assert!(!ring_sig.verify(&msg, &ring, &wrong_target));

        // DLEQ Selective Payment Proof (`xcrtxproof1_`):
        let r_eph = Scalar::hash_from_parts("XCR.SHIELD.EPH_R.V1", &[&[3u8; 32]]);
        let proof = PaymentDisclosureProof::generate(r_eph, &bob_vk.view_pubkey, &bob_note.note_id)
            .unwrap();
        let parsed_proof = PaymentDisclosureProof::from_uri(&proof.to_uri()).unwrap();
        assert!(parsed_proof.verify(&bob_note.note_id));
    }
}
