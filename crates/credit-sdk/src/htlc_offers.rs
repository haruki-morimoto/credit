//! **HTLC Conditional Escrows & Peer-to-Peer Atomic Swap Order Intents** (`xcroffer1_`).
//!
//! Enables trustless cross-chain atomic swaps (`XCR <-> BTC / Lightning / USDC`) and conditional
//! commercial escrows with **zero custodial `TrustLines`, zero bridges, and zero freeze keys**:
//! 1. Maker generates `(preimage, hashlock = SHA256(preimage))` via [`generate_htlc_secret`] and
//!    publishes a signed [`AtomicSwapOffer`] (`xcroffer1_...`).
//! 2. Both legs lock funds under the identical `hashlock` (with maker's timelock longer than taker's).
//! 3. Revealing `preimage` to claim one leg automatically exposes `preimage` on-chain so the
//!    counterparty claims the second leg; if abandoned, both sides refund 100% after `expiry_unix`.

use credit_crypto::{Keypair, PublicKey, Signature, SignatureScheme, domain_hash, sha256};
use credit_types::{Address, Amount, Hash32};

use crate::qr::{QrCode, QrError};

/// Generates a fresh `(preimage, sha256_hashlock)` pair for a cross-chain HTLC atomic swap.
pub fn generate_htlc_secret(entropy: &[u8; 32]) -> ([u8; 32], Hash32) {
    let preimage = domain_hash("XCR.HTLC.PREIMAGE.V1", &[entropy]).0;
    let hashlock = Hash32(sha256(&preimage));
    (preimage, hashlock)
}

/// Verifies `SHA-256(preimage) == hashlock` (compatible with Bitcoin `OP_SHA256` & Lightning HTLCs).
#[inline]
pub fn verify_htlc_preimage(preimage: &[u8; 32], hashlock: &Hash32) -> bool {
    Hash32(sha256(preimage)) == *hashlock
}

/// Computes the canonical `escrow_id` and signing digest for locking an on-chain HTLC.
pub fn htlc_lock_signing_digest(
    sender: &Address,
    recipient: &Address,
    amount: Amount,
    fee: Amount,
    hashlock: &Hash32,
    expiry_unix: u64,
    salt: &[u8; 16],
) -> Hash32 {
    domain_hash(
        "XCR.HTLC.LOCK_MSG.V1",
        &[
            sender.as_bytes(),
            recipient.as_bytes(),
            &amount.bits().to_le_bytes(),
            &fee.bits().to_le_bytes(),
            hashlock.as_bytes(),
            &expiry_unix.to_le_bytes(),
            salt,
        ],
    )
}

/// Signs an `HtlcLock` request with the sender's `Spending Pocket` keypair (`65-byte` Schnorr).
pub fn sign_htlc_lock(
    master_seed: &[u8; 32],
    recipient: &Address,
    amount: Amount,
    fee: Amount,
    hashlock: &Hash32,
    expiry_unix: u64,
    salt: [u8; 16],
) -> (Address, PublicKey, Hash32, [u8; 65]) {
    let pocket_seed = domain_hash("XCR.WALLET.POCKET_KEY.V1", &[master_seed]).0;
    let mut kp = Keypair::from_seed(SignatureScheme::PasskeyP256, pocket_seed);
    let sender = kp.address();
    let pk = kp.public_key();
    let escrow_id = htlc_lock_signing_digest(
        &sender,
        recipient,
        amount,
        fee,
        hashlock,
        expiry_unix,
        &salt,
    );
    let sig_vec = kp.sign(escrow_id.as_bytes()).to_bytes();
    let mut sig65 = [0u8; 65];
    sig65.copy_from_slice(&sig_vec);
    (sender, pk, escrow_id, sig65)
}

/// Cryptographically signed, non-custodial P2P Atomic Swap Order Intent (`xcroffer1_`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AtomicSwapOffer {
    pub offer_id: Hash32,
    pub maker_address: Address,
    pub maker_pubkey: PublicKey,
    pub xcr_amount: Amount,
    pub counter_asset: String,
    pub counter_amount: String,
    pub hashlock: Hash32,
    pub timelock_secs: u64,
    pub expiry_unix: u64,
    pub signature_65: [u8; 65],
}

impl AtomicSwapOffer {
    pub const PREFIX: &'static str = "xcroffer1_";

    /// Creates and signs a new P2P Atomic Swap intent using `master_seed`.
    pub fn sign_new(
        master_seed: &[u8; 32],
        xcr_amount: Amount,
        counter_asset: &str,
        counter_amount: &str,
        hashlock: Hash32,
        timelock_secs: u64,
        expiry_unix: u64,
    ) -> Result<Self, &'static str> {
        let asset = counter_asset.trim();
        let c_amt = counter_amount.trim();
        if xcr_amount.is_zero()
            || asset.is_empty()
            || asset.len() > 24
            || c_amt.is_empty()
            || c_amt.len() > 32
        {
            return Err("invalid swap offer asset or amount");
        }
        let pocket_seed = domain_hash("XCR.WALLET.POCKET_KEY.V1", &[master_seed]).0;
        let mut kp = Keypair::from_seed(SignatureScheme::PasskeyP256, pocket_seed);
        let maker_address = kp.address();
        let maker_pubkey = kp.public_key();
        let offer_id = Self::compute_id(
            &maker_address,
            &maker_pubkey,
            xcr_amount,
            asset,
            c_amt,
            &hashlock,
            timelock_secs,
            expiry_unix,
        );
        let sig_vec = kp.sign(offer_id.as_bytes()).to_bytes();
        let signature_65: [u8; 65] = sig_vec.try_into().map_err(|_| "expected 65B signature")?;
        Ok(Self {
            offer_id,
            maker_address,
            maker_pubkey,
            xcr_amount,
            counter_asset: asset.to_owned(),
            counter_amount: c_amt.to_owned(),
            hashlock,
            timelock_secs,
            expiry_unix,
            signature_65,
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub fn compute_id(
        maker_address: &Address,
        maker_pubkey: &PublicKey,
        xcr_amount: Amount,
        counter_asset: &str,
        counter_amount: &str,
        hashlock: &Hash32,
        timelock_secs: u64,
        expiry_unix: u64,
    ) -> Hash32 {
        domain_hash(
            "XCR.SWAP.OFFER_ID.V1",
            &[
                maker_address.as_bytes(),
                &[maker_pubkey.scheme as u8],
                maker_pubkey.merkle_root.as_bytes(),
                &xcr_amount.bits().to_le_bytes(),
                counter_asset.as_bytes(),
                counter_amount.as_bytes(),
                hashlock.as_bytes(),
                &timelock_secs.to_le_bytes(),
                &expiry_unix.to_le_bytes(),
            ],
        )
    }

    /// Verifies maker key ownership, canonical `offer_id`, and `65-byte` Schnorr authenticity.
    pub fn verify(&self) -> bool {
        if self.xcr_amount.is_zero()
            || self.counter_asset.is_empty()
            || self.counter_asset.len() > 24
            || self.counter_amount.is_empty()
            || self.counter_amount.len() > 32
            || self.maker_pubkey.to_address() != self.maker_address
        {
            return false;
        }
        let expected_id = Self::compute_id(
            &self.maker_address,
            &self.maker_pubkey,
            self.xcr_amount,
            &self.counter_asset,
            &self.counter_amount,
            &self.hashlock,
            self.timelock_secs,
            self.expiry_unix,
        );
        if expected_id != self.offer_id {
            return false;
        }
        let Some(sig) = Signature::from_bytes(&self.signature_65) else {
            return false;
        };
        self.maker_pubkey.verify(self.offer_id.as_bytes(), &sig)
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(240);
        out.extend_from_slice(self.offer_id.as_bytes());
        out.extend_from_slice(self.maker_address.as_bytes());
        out.push(self.maker_pubkey.scheme as u8);
        out.extend_from_slice(self.maker_pubkey.merkle_root.as_bytes());
        out.extend_from_slice(&self.xcr_amount.bits().to_le_bytes());
        out.push(self.counter_asset.len() as u8);
        out.extend_from_slice(self.counter_asset.as_bytes());
        out.push(self.counter_amount.len() as u8);
        out.extend_from_slice(self.counter_amount.as_bytes());
        out.extend_from_slice(self.hashlock.as_bytes());
        out.extend_from_slice(&self.timelock_secs.to_le_bytes());
        out.extend_from_slice(&self.expiry_unix.to_le_bytes());
        out.extend_from_slice(&self.signature_65);
        out
    }

    pub fn from_bytes(raw: &[u8]) -> Option<Self> {
        if raw.len() < 32 + 32 + 1 + 32 + 8 + 2 + 32 + 16 + 65 {
            return None;
        }
        let offer_id = Hash32::from_bytes(raw[0..32].try_into().ok()?);
        let maker_address = Address::from_bytes(raw[32..64].try_into().ok()?);
        let scheme = SignatureScheme::from_u8(raw[64])?;
        let merkle_root = Hash32::from_bytes(raw[65..97].try_into().ok()?);
        let xcr_amount = Amount::from_bits(u64::from_le_bytes(raw[97..105].try_into().ok()?));
        let mut pos = 105usize;
        let asset_len = *raw.get(pos)? as usize;
        pos += 1;
        if asset_len == 0 || asset_len > 24 || pos + asset_len > raw.len() {
            return None;
        }
        let counter_asset = String::from_utf8(raw[pos..pos + asset_len].to_vec()).ok()?;
        pos += asset_len;
        let amt_len = *raw.get(pos)? as usize;
        pos += 1;
        if amt_len == 0 || amt_len > 32 || pos + amt_len + 32 + 16 + 65 != raw.len() {
            return None;
        }
        let counter_amount = String::from_utf8(raw[pos..pos + amt_len].to_vec()).ok()?;
        pos += amt_len;
        let hashlock = Hash32::from_bytes(raw[pos..pos + 32].try_into().ok()?);
        pos += 32;
        let timelock_secs = u64::from_le_bytes(raw[pos..pos + 8].try_into().ok()?);
        pos += 8;
        let expiry_unix = u64::from_le_bytes(raw[pos..pos + 8].try_into().ok()?);
        pos += 8;
        let mut signature_65 = [0u8; 65];
        signature_65.copy_from_slice(&raw[pos..pos + 65]);
        let offer = Self {
            offer_id,
            maker_address,
            maker_pubkey: PublicKey {
                scheme,
                merkle_root,
            },
            xcr_amount,
            counter_asset,
            counter_amount,
            hashlock,
            timelock_secs,
            expiry_unix,
            signature_65,
        };
        offer.verify().then_some(offer)
    }

    pub fn to_uri(&self) -> String {
        format!("{}{}", Self::PREFIX, hex_encode(&self.to_bytes()))
    }

    pub fn from_uri(uri: &str) -> Option<Self> {
        let hex_part = uri.trim().strip_prefix(Self::PREFIX)?;
        let raw = hex_decode(hex_part)?;
        Self::from_bytes(&raw)
    }

    pub fn to_qr_code(&self) -> Result<QrCode, QrError> {
        QrCode::encode_str(&self.to_uri())
    }
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
    fn htlc_preimage_and_signed_swap_offer_roundtrip() {
        let (preimage, hashlock) = generate_htlc_secret(&[0x71; 32]);
        assert!(verify_htlc_preimage(&preimage, &hashlock));
        assert!(!verify_htlc_preimage(&[0u8; 32], &hashlock));

        let offer = AtomicSwapOffer::sign_new(
            &[0x33; 32],
            Amount::from_credits(100).unwrap(),
            "BTC-LN",
            "0.00125000",
            hashlock,
            3_600,
            1_900_000_000,
        )
        .unwrap();
        assert!(offer.verify());
        let uri = offer.to_uri();
        let parsed = AtomicSwapOffer::from_uri(&uri).expect("valid swap offer URI");
        assert_eq!(parsed, offer);
    }
}
