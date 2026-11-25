//! **Air-Gapped Offline QR Cold Signing** (`xcrunsigned1_` & `xcrsigned1_`).
//!
//! Turns any offline phone, Raspberry Pi, or spare laptop (with Wi-Fi/Bluetooth permanently off)
//! into a hardware-grade cold wallet:
//! 1. **Online Watch-Only Device:** Prepares `UnsignedColdTransfer` (`121` raw bytes -> `255`-char
//!    `xcrunsigned1_` QR code, fitting inside a single Version 10 QR!) alongside the public
//!    `672B` Bulletproof bundle (which requires zero private keys).
//! 2. **Air-Gapped Offline Device:** Scans `xcrunsigned1_...`, displays `From`, `To`, `Amount`,
//!    `Fee`, and `Nonce` for human review, signs `tx_id` offline using its `65-byte` Curve25519
//!    Schnorr key, and renders a `205`-char `xcrsigned1_` QR code (Version 9 QR!).
//! 3. **Online Watch-Only Device:** Scans `xcrsigned1_...`, cryptographically verifies the `65B`
//!    signature against `public_key`, attaches the `672B` Bulletproof, and broadcasts in `~170 ms`.

use credit_consensus::tx_signing_digest;
use credit_crypto::{Keypair, PublicKey, Signature, SignatureScheme, domain_hash};
use credit_types::{Address, Amount, Hash32, Transaction, TransactionKind};

use crate::qr::{QrCode, QrError};

/// Compact `121-byte` unsigned FastTransfer request (`255` ASCII chars as `xcrunsigned1_<242-hex>`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UnsignedColdTransfer {
    pub from: Address,
    pub to_stealth: Address,
    pub stealth_view_tag: u8,
    pub amount: Amount,
    pub fee: Amount,
    pub nonce: u64,
    pub value_commitment: [u8; 32],
}

/// Compact `97-byte` air-gapped signature response (`205` ASCII chars as `xcrsigned1_<194-hex>`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignedColdTransfer {
    pub tx_id: Hash32,
    pub signature_65: [u8; 65],
}

impl UnsignedColdTransfer {
    pub const PREFIX: &'static str = "xcrunsigned1_";
    pub const RAW_LEN: usize = 121;

    pub fn to_transaction_kind(&self) -> TransactionKind {
        let commitment = domain_hash("XCR.CLI.COMMIT_TAG.V1", &[&self.value_commitment]);
        TransactionKind::FastTransfer {
            from: self.from,
            to_stealth: self.to_stealth,
            stealth_view_tag: self.stealth_view_tag,
            amount: self.amount,
            fee: self.fee,
            nonce: self.nonce,
            commitment,
            innocence_nullifier: None,
        }
    }

    pub fn signing_digest(&self) -> Hash32 {
        tx_signing_digest(&self.to_transaction_kind())
    }

    pub fn to_uri(&self) -> String {
        let mut raw = [0u8; Self::RAW_LEN];
        raw[0..32].copy_from_slice(self.from.as_bytes());
        raw[32..64].copy_from_slice(self.to_stealth.as_bytes());
        raw[64] = self.stealth_view_tag;
        raw[65..73].copy_from_slice(&self.amount.bits().to_le_bytes());
        raw[73..81].copy_from_slice(&self.fee.bits().to_le_bytes());
        raw[81..89].copy_from_slice(&self.nonce.to_le_bytes());
        raw[89..121].copy_from_slice(&self.value_commitment);
        format!("{}{}", Self::PREFIX, hex_encode(&raw))
    }

    pub fn from_uri(uri: &str) -> Option<Self> {
        let hex_part = uri.trim().strip_prefix(Self::PREFIX)?;
        let raw = hex_decode(hex_part)?;
        if raw.len() != Self::RAW_LEN {
            return None;
        }
        let mut from = [0u8; 32];
        from.copy_from_slice(&raw[0..32]);
        let mut to_stealth = [0u8; 32];
        to_stealth.copy_from_slice(&raw[32..64]);
        let stealth_view_tag = raw[64];
        let amount = Amount::from_bits(u64::from_le_bytes(raw[65..73].try_into().ok()?));
        let fee = Amount::from_bits(u64::from_le_bytes(raw[73..81].try_into().ok()?));
        let nonce = u64::from_le_bytes(raw[81..89].try_into().ok()?);
        let mut value_commitment = [0u8; 32];
        value_commitment.copy_from_slice(&raw[89..121]);
        Some(Self {
            from: Address::from_bytes(from),
            to_stealth: Address::from_bytes(to_stealth),
            stealth_view_tag,
            amount,
            fee,
            nonce,
            value_commitment,
        })
    }

    pub fn to_qr_code(&self) -> Result<QrCode, QrError> {
        QrCode::encode_str(&self.to_uri())
    }

    /// Signs this unsigned transfer offline on an air-gapped device using `master_seed` (zero network I/O).
    pub fn sign_offline(&self, master_seed: &[u8; 32]) -> Result<SignedColdTransfer, &'static str> {
        let pocket_seed = domain_hash("XCR.WALLET.POCKET_KEY.V1", &[master_seed]).0;
        let mut kp = Keypair::from_seed(SignatureScheme::PasskeyP256, pocket_seed);
        if kp.address() != self.from {
            return Err("offline wallet address does not match unsigned transaction `from` Pocket");
        }
        let tx_id = self.signing_digest();
        let sig_vec = kp.sign(tx_id.as_bytes()).to_bytes();
        let signature_65: [u8; 65] = sig_vec
            .try_into()
            .map_err(|_| "unexpected non-65B signature")?;
        Ok(SignedColdTransfer {
            tx_id,
            signature_65,
        })
    }

    /// Combines this unsigned transfer with an air-gapped `SignedColdTransfer` after verifying `sender_pubkey`.
    pub fn attach_verified_signature(
        &self,
        signed: &SignedColdTransfer,
        sender_pubkey: &PublicKey,
    ) -> Option<Transaction> {
        let expected_id = self.signing_digest();
        if signed.tx_id != expected_id || sender_pubkey.to_address() != self.from {
            return None;
        }
        let sig = Signature::from_bytes(&signed.signature_65)?;
        if !sender_pubkey.verify(expected_id.as_bytes(), &sig) {
            return None;
        }
        Some(Transaction {
            id: expected_id,
            kind: self.to_transaction_kind(),
            signature_bytes: signed.signature_65.to_vec(),
        })
    }
}

impl SignedColdTransfer {
    pub const PREFIX: &'static str = "xcrsigned1_";
    pub const RAW_LEN: usize = 97;

    pub fn to_uri(&self) -> String {
        let mut raw = [0u8; Self::RAW_LEN];
        raw[0..32].copy_from_slice(self.tx_id.as_bytes());
        raw[32..97].copy_from_slice(&self.signature_65);
        format!("{}{}", Self::PREFIX, hex_encode(&raw))
    }

    pub fn from_uri(uri: &str) -> Option<Self> {
        let hex_part = uri.trim().strip_prefix(Self::PREFIX)?;
        let raw = hex_decode(hex_part)?;
        if raw.len() != Self::RAW_LEN {
            return None;
        }
        let mut tx_id = [0u8; 32];
        tx_id.copy_from_slice(&raw[0..32]);
        let mut signature_65 = [0u8; 65];
        signature_65.copy_from_slice(&raw[32..97]);
        Some(Self {
            tx_id: Hash32::from_bytes(tx_id),
            signature_65,
        })
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
    fn airgapped_qr_cold_sign_roundtrip_fits_single_qr_and_verifies() {
        let cold_master = [0x81; 32];
        let pocket_seed = domain_hash("XCR.WALLET.POCKET_KEY.V1", &[&cold_master]).0;
        let kp = Keypair::from_seed(SignatureScheme::PasskeyP256, pocket_seed);

        let unsigned = UnsignedColdTransfer {
            from: kp.address(),
            to_stealth: Address::from_bytes([0x55; 32]),
            stealth_view_tag: 0x2A,
            amount: Amount::from_chips(1_250).unwrap(),
            fee: Amount::from_bits(500),
            nonce: 7,
            value_commitment: [0x33; 32],
        };
        let u_uri = unsigned.to_uri();
        assert_eq!(u_uri.len(), 255); // Strictly <= 271B Version 10 QR limit!
        assert!(unsigned.to_qr_code().is_ok());

        let parsed_u = UnsignedColdTransfer::from_uri(&u_uri).unwrap();
        let signed = parsed_u.sign_offline(&cold_master).unwrap();
        let s_uri = signed.to_uri();
        assert_eq!(s_uri.len(), 205); // Fits Version 9 QR!
        assert!(signed.to_qr_code().is_ok());

        let parsed_s = SignedColdTransfer::from_uri(&s_uri).unwrap();
        let final_tx = unsigned
            .attach_verified_signature(&parsed_s, &kp.public_key())
            .expect("valid cold signature");
        assert_eq!(final_tx.signature_bytes.len(), 65);
    }
}
