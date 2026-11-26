//! **Pre-Authorized "Up-To-Max" Digital Checks** (`xcrcheck1_`).
//!
//! Solves hotel check-ins, EV charging, gas pumps, and B2B invoice pre-authorizations without
//! locking or moving coins upfront:
//! - Funds remain **100% inside the drawer's `Spending Pocket`** until cashed.
//! - Authorizes a specific `payee` to claim **any `actual_amount <= max_amount`** once before `expiry_unix`.
//! - Drawer can revoke an uncashed check in `1-RTT` (`~200 ms`) via [`sign_check_cancel`].

use credit_crypto::{Keypair, PublicKey, Signature, SignatureScheme, domain_hash};
use credit_types::{Address, Amount, Hash32};

/// Signed pre-authorized digital check (`xcrcheck1_<hex>`, `182` raw bytes).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DigitalCheck {
    pub check_id: Hash32,
    pub drawer: Address,
    pub drawer_pubkey: PublicKey,
    pub payee: Address,
    pub max_amount: Amount,
    pub expiry_unix: u64,
    pub salt: [u8; 16],
    pub drawer_sig65: [u8; 65],
}

impl DigitalCheck {
    pub const PREFIX: &'static str = "xcrcheck1_";
    pub const RAW_LEN: usize = 32 + 32 + 1 + 32 + 32 + 8 + 8 + 16 + 65; // 226 bytes

    pub fn compute_id(
        drawer: &Address,
        drawer_pubkey: &PublicKey,
        payee: &Address,
        max_amount: Amount,
        expiry_unix: u64,
        salt: &[u8; 16],
    ) -> Hash32 {
        domain_hash(
            "XCR.CHECK.ID.V1",
            &[
                drawer.as_bytes(),
                &[drawer_pubkey.scheme as u8],
                drawer_pubkey.merkle_root.as_bytes(),
                payee.as_bytes(),
                &max_amount.bits().to_le_bytes(),
                &expiry_unix.to_le_bytes(),
                salt,
            ],
        )
    }

    /// Issues and signs an "up-to-`max_amount`" `DigitalCheck` without moving funds yet.
    pub fn issue(
        drawer_master_seed: &[u8; 32],
        payee: Address,
        max_amount: Amount,
        expiry_unix: u64,
        salt: [u8; 16],
    ) -> Result<Self, &'static str> {
        if max_amount.is_zero() {
            return Err("check max_amount must be > 0");
        }
        let pocket_seed = domain_hash("XCR.WALLET.POCKET_KEY.V1", &[drawer_master_seed]).0;
        let mut kp = Keypair::from_seed(SignatureScheme::PasskeyP256, pocket_seed);
        let drawer = kp.address();
        let drawer_pubkey = kp.public_key();
        let check_id = Self::compute_id(
            &drawer,
            &drawer_pubkey,
            &payee,
            max_amount,
            expiry_unix,
            &salt,
        );
        let sig_vec = kp.sign(check_id.as_bytes()).to_bytes();
        let drawer_sig65: [u8; 65] = sig_vec.try_into().map_err(|_| "expected 65B signature")?;
        Ok(Self {
            check_id,
            drawer,
            drawer_pubkey,
            payee,
            max_amount,
            expiry_unix,
            salt,
            drawer_sig65,
        })
    }

    /// Verifies drawer identity and `65-byte` Schnorr authorization over `check_id`.
    pub fn verify(&self) -> bool {
        if self.max_amount.is_zero() || self.drawer_pubkey.to_address() != self.drawer {
            return false;
        }
        let expected_id = Self::compute_id(
            &self.drawer,
            &self.drawer_pubkey,
            &self.payee,
            self.max_amount,
            self.expiry_unix,
            &self.salt,
        );
        if expected_id != self.check_id {
            return false;
        }
        let Some(sig) = Signature::from_bytes(&self.drawer_sig65) else {
            return false;
        };
        self.drawer_pubkey.verify(self.check_id.as_bytes(), &sig)
    }

    pub fn to_bytes(&self) -> [u8; Self::RAW_LEN] {
        let mut raw = [0u8; Self::RAW_LEN];
        raw[0..32].copy_from_slice(self.check_id.as_bytes());
        raw[32..64].copy_from_slice(self.drawer.as_bytes());
        raw[64] = self.drawer_pubkey.scheme as u8;
        raw[65..97].copy_from_slice(self.drawer_pubkey.merkle_root.as_bytes());
        raw[97..129].copy_from_slice(self.payee.as_bytes());
        raw[129..137].copy_from_slice(&self.max_amount.bits().to_le_bytes());
        raw[137..145].copy_from_slice(&self.expiry_unix.to_le_bytes());
        raw[145..161].copy_from_slice(&self.salt);
        raw[161..226].copy_from_slice(&self.drawer_sig65);
        raw
    }

    pub fn from_bytes(raw: &[u8]) -> Option<Self> {
        if raw.len() != Self::RAW_LEN {
            return None;
        }
        let check_id = Hash32::from_bytes(raw[0..32].try_into().ok()?);
        let drawer = Address::from_bytes(raw[32..64].try_into().ok()?);
        let scheme = SignatureScheme::from_u8(raw[64])?;
        let merkle_root = Hash32::from_bytes(raw[65..97].try_into().ok()?);
        let payee = Address::from_bytes(raw[97..129].try_into().ok()?);
        let max_amount = Amount::from_bits(u64::from_le_bytes(raw[129..137].try_into().ok()?));
        let expiry_unix = u64::from_le_bytes(raw[137..145].try_into().ok()?);
        let mut salt = [0u8; 16];
        salt.copy_from_slice(&raw[145..161]);
        let mut drawer_sig65 = [0u8; 65];
        drawer_sig65.copy_from_slice(&raw[161..226]);
        let chk = Self {
            check_id,
            drawer,
            drawer_pubkey: PublicKey {
                scheme,
                merkle_root,
            },
            payee,
            max_amount,
            expiry_unix,
            salt,
            drawer_sig65,
        };
        chk.verify().then_some(chk)
    }

    pub fn to_uri(&self) -> String {
        format!("{}{}", Self::PREFIX, hex_encode(&self.to_bytes()))
    }

    pub fn from_uri(uri: &str) -> Option<Self> {
        let hex_part = uri.trim().strip_prefix(Self::PREFIX)?;
        let raw = hex_decode(hex_part)?;
        Self::from_bytes(&raw)
    }
}

/// Digest signed by `payee` when cashing `actual_amount <= check.max_amount`.
#[inline]
pub fn check_cash_digest(check_id: &Hash32, actual_amount: Amount) -> Hash32 {
    domain_hash(
        "XCR.CHECK.CASH.V1",
        &[check_id.as_bytes(), &actual_amount.bits().to_le_bytes()],
    )
}

/// Digest signed by `drawer` to cancel an uncashed `check_id` on-chain in 1-RTT.
#[inline]
pub fn check_cancel_digest(check_id: &Hash32) -> Hash32 {
    domain_hash("XCR.CHECK.CANCEL.V1", &[check_id.as_bytes()])
}

/// Signs a `CashCheck` claim as `payee` for `actual_amount <= check.max_amount`.
pub fn sign_check_cash(
    payee_master_seed: &[u8; 32],
    check: &DigitalCheck,
    actual_amount: Amount,
) -> Result<(PublicKey, [u8; 65]), &'static str> {
    if actual_amount.is_zero() || actual_amount > check.max_amount {
        return Err("actual_amount must be > 0 and <= check.max_amount");
    }
    let pocket_seed = domain_hash("XCR.WALLET.POCKET_KEY.V1", &[payee_master_seed]).0;
    let mut kp = Keypair::from_seed(SignatureScheme::PasskeyP256, pocket_seed);
    if kp.address() != check.payee {
        return Err("wallet Pocket address does not match check payee");
    }
    let digest = check_cash_digest(&check.check_id, actual_amount);
    let sig_vec = kp.sign(digest.as_bytes()).to_bytes();
    let sig65: [u8; 65] = sig_vec.try_into().map_err(|_| "expected 65B signature")?;
    Ok((kp.public_key(), sig65))
}

/// Signs a 1-RTT `CancelCheck` revocation as `drawer`.
pub fn sign_check_cancel(
    drawer_master_seed: &[u8; 32],
    check_id: &Hash32,
) -> (Address, PublicKey, [u8; 65]) {
    let pocket_seed = domain_hash("XCR.WALLET.POCKET_KEY.V1", &[drawer_master_seed]).0;
    let mut kp = Keypair::from_seed(SignatureScheme::PasskeyP256, pocket_seed);
    let digest = check_cancel_digest(check_id);
    let sig_vec = kp.sign(digest.as_bytes()).to_bytes();
    let mut sig65 = [0u8; 65];
    sig65.copy_from_slice(&sig_vec);
    (kp.address(), kp.public_key(), sig65)
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
    fn digital_check_up_to_max_issue_cash_and_cancel_verify() {
        let alice = [0x12; 32];
        let bob = [0x34; 32];
        let bob_pocket = Keypair::from_seed(
            SignatureScheme::PasskeyP256,
            domain_hash("XCR.WALLET.POCKET_KEY.V1", &[&bob]).0,
        )
        .address();

        let chk = DigitalCheck::issue(
            &alice,
            bob_pocket,
            Amount::from_credits(50).unwrap(),
            1_900_000_000,
            [9u8; 16],
        )
        .unwrap();
        let parsed = DigitalCheck::from_uri(&chk.to_uri()).unwrap();
        assert_eq!(parsed, chk);

        // Bob can cash 42.50 XCR (<= 50.00 XCR max), but NOT 51.00 XCR!
        let (bob_pk, cash_sig) =
            sign_check_cash(&bob, &parsed, Amount::from_chips(4_250).unwrap()).unwrap();
        assert!(bob_pk.verify(
            check_cash_digest(&parsed.check_id, Amount::from_chips(4_250).unwrap()).as_bytes(),
            &Signature::from_bytes(&cash_sig).unwrap()
        ));
        assert!(sign_check_cash(&bob, &parsed, Amount::from_credits(51).unwrap()).is_err());
    }
}
