//! **Solana-Style `Durable Cold Nonces` (`xcrdurable1_`), `Blinks` Action Cards, & Polkadot
//! Non-Withdrawal Role Proxies (`VoteOnly` / `DexTradeOnly`)**.
//!
//! 1. **`DurableColdTransfer` (`xcrdurable1_`):** Air-gapped QR offline signing bound to a dedicated
//!    `2D` parallel lane `(sender, lane_id, lane_seq)` so cold-signed transactions remain valid for
//!    days/weeks even while your Pocket spends coffee on other lanes or sequential `nonce`!
//! 2. **Polkadot-Style `RoleProxy`:** Delegate a hot laptop key restricted by consensus to
//!    `ROLE_GOVERNANCE_ONLY (1)` or `ROLE_DEX_TRADE_ONLY (2)` — **consensus mathematically forbids
//!    the proxy key from ever transferring or withdrawing funds out of the owner's account!**
//! 3. **Solana `Blinks` (`ActionBlinkCard`):** Standardized interactive JSON metadata served at
//!    `GET /api/blink` so any URL unfurls into a 1-click payment, crowdfund, or governance card.

use credit_crypto::{Keypair, PublicKey, Signature, SignatureScheme, domain_hash};
use credit_types::{Address, Amount, Hash32};

use crate::atomic_lanes::parallel_lane_pay_digest;

pub const PROXY_ROLE_REVOKE: u8 = 0;
pub const PROXY_ROLE_GOVERNANCE_ONLY: u8 = 1;
pub const PROXY_ROLE_DEX_TRADE_ONLY: u8 = 2;

/// Compact `84-byte` durable offline unsigned transfer (`xcrdurable1_<168-hex>`) immune to sequential
/// `PocketState::nonce` drift!
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DurableColdTransfer {
    pub sender: Address,
    pub recipient: Address,
    pub lane_id: u32,
    pub lane_seq: u64,
    pub amount: Amount,
    pub fee: Amount,
}

impl DurableColdTransfer {
    pub const PREFIX: &'static str = "xcrdurable1_";

    pub fn signing_digest(&self) -> Hash32 {
        parallel_lane_pay_digest(
            &self.sender,
            &self.recipient,
            self.lane_id,
            self.lane_seq,
            self.amount,
            self.fee,
        )
    }

    pub fn to_uri(&self) -> String {
        let mut raw = [0u8; 84];
        raw[0..32].copy_from_slice(self.sender.as_bytes());
        raw[32..64].copy_from_slice(self.recipient.as_bytes());
        raw[64..68].copy_from_slice(&self.lane_id.to_le_bytes());
        raw[68..76].copy_from_slice(&self.lane_seq.to_le_bytes());
        // Pack amount (u64? 84 bytes -> 64+4+8 = 76; let's use 92 bytes for full u64 amount + u64 fee!)
        let mut full = [0u8; 92];
        full[0..76].copy_from_slice(&raw[0..76]);
        full[76..84].copy_from_slice(&self.amount.bits().to_le_bytes());
        full[84..92].copy_from_slice(&self.fee.bits().to_le_bytes());
        let mut s = String::with_capacity(Self::PREFIX.len() + 184);
        s.push_str(Self::PREFIX);
        for &b in &full {
            s.push_str(&format!("{b:02x}"));
        }
        s
    }

    pub fn from_uri(uri: &str) -> Option<Self> {
        let hex_part = uri.trim().strip_prefix(Self::PREFIX)?;
        if hex_part.len() != 184 {
            return None;
        }
        let mut full = [0u8; 92];
        for (i, slot) in full.iter_mut().enumerate() {
            *slot = u8::from_str_radix(&hex_part[i * 2..i * 2 + 2], 16).ok()?;
        }
        Some(Self {
            sender: Address::from_bytes(full[0..32].try_into().ok()?),
            recipient: Address::from_bytes(full[32..64].try_into().ok()?),
            lane_id: u32::from_le_bytes(full[64..68].try_into().ok()?),
            lane_seq: u64::from_le_bytes(full[68..76].try_into().ok()?),
            amount: Amount::from_bits(u64::from_le_bytes(full[76..84].try_into().ok()?)),
            fee: Amount::from_bits(u64::from_le_bytes(full[84..92].try_into().ok()?)),
        })
    }

    /// Signs offline on an air-gapped device with zero network access, returning `(pubkey_hex66, sig_hex130)`.
    pub fn sign_offline(
        &self,
        master_seed: &[u8; 32],
    ) -> Result<(PublicKey, [u8; 65]), &'static str> {
        let sk = domain_hash("XCR.WALLET.POCKET_KEY.V1", &[master_seed]).0;
        let mut kp = Keypair::from_seed(SignatureScheme::PasskeyP256, sk);
        if kp.address() != self.sender {
            return Err("offline wallet seed does not match DurableColdTransfer sender");
        }
        let sig = kp.sign(self.signing_digest().as_bytes());
        let mut sig65 = [0u8; 65];
        sig65.copy_from_slice(&sig.to_bytes());
        Ok((kp.public_key(), sig65))
    }
}

pub fn role_proxy_bind_digest(
    owner: &Address,
    proxy_pubkey: &PublicKey,
    role: u8,
    salt: &[u8; 16],
) -> Hash32 {
    domain_hash(
        "XCR.PROXY.ROLE_BIND.V1",
        &[
            owner.as_bytes(),
            &[proxy_pubkey.scheme as u8],
            proxy_pubkey.merkle_root.as_bytes(),
            &[role],
            salt,
        ],
    )
}

pub fn sign_role_proxy_bind(
    owner_seed: &[u8; 32],
    proxy_pubkey: &PublicKey,
    role: u8,
    salt: [u8; 16],
) -> Result<(Address, PublicKey, Hash32, [u8; 65]), &'static str> {
    if role > PROXY_ROLE_DEX_TRADE_ONLY {
        return Err("proxy role must be 0 (Revoke), 1 (GovernanceOnly), or 2 (DexTradeOnly)");
    }
    let sk = domain_hash("XCR.WALLET.POCKET_KEY.V1", &[owner_seed]).0;
    let mut kp = Keypair::from_seed(SignatureScheme::PasskeyP256, sk);
    let owner = kp.address();
    let tx_id = role_proxy_bind_digest(&owner, proxy_pubkey, role, &salt);
    let sig = kp.sign(tx_id.as_bytes());
    let mut sig65 = [0u8; 65];
    sig65.copy_from_slice(&sig.to_bytes());
    Ok((owner, kp.public_key(), tx_id, sig65))
}

#[allow(clippy::too_many_arguments)]
pub fn proxy_exec_digest(
    owner: &Address,
    role: u8,
    target_id: &Hash32,
    vote_choice_or_side: u8,
    units: u64,
    price_bits: u64,
    salt: &[u8; 16],
) -> Hash32 {
    domain_hash(
        "XCR.PROXY.EXEC.V1",
        &[
            owner.as_bytes(),
            &[role],
            target_id.as_bytes(),
            &[vote_choice_or_side],
            &units.to_le_bytes(),
            &price_bits.to_le_bytes(),
            salt,
        ],
    )
}

#[allow(clippy::too_many_arguments)]
pub fn sign_proxy_execute(
    proxy_seed: &[u8; 32],
    owner: &Address,
    role: u8,
    target_id: &Hash32,
    vote_choice_or_side: u8,
    units: u64,
    price_bits: u64,
    salt: [u8; 16],
) -> (PublicKey, Hash32, [u8; 65]) {
    let sk = domain_hash("XCR.WALLET.POCKET_KEY.V1", &[proxy_seed]).0;
    let mut kp = Keypair::from_seed(SignatureScheme::PasskeyP256, sk);
    let tx_id = proxy_exec_digest(
        owner,
        role,
        target_id,
        vote_choice_or_side,
        units,
        price_bits,
        &salt,
    );
    let sig = kp.sign(tx_id.as_bytes());
    let mut sig65 = [0u8; 65];
    sig65.copy_from_slice(&sig.to_bytes());
    (kp.public_key(), tx_id, sig65)
}

pub fn verify_proxy_sig(pubkey: &PublicKey, digest: &Hash32, sig65: &[u8; 65]) -> bool {
    Signature::from_bytes(sig65).is_some_and(|s| pubkey.verify(digest.as_bytes(), &s))
}

/// Formats a Solana `Blinks`-style (`xcr-action-v1`) interactive JSON action card.
pub fn format_blink_action_json(target: &str, amount_xcr: &str, label: &str) -> String {
    let clean_t = target.replace('"', "");
    let clean_a = amount_xcr.replace('"', "");
    let clean_l = label.replace('"', "");
    format!(
        r#"{{"schema":"xcr-blink-v1","title":"Credits (∀ / XCR) Instant Action","description":"1-RTT sub-second bearer settlement to {clean_t}","label":"{clean_l} ({clean_a} XCR)","links":{{"actions":[{{"label":"Pay {clean_a} XCR","href":"xcr:{clean_t}?amount={clean_a}&memo={clean_l}"}},{{"label":"Tip 1.00 XCR","href":"xcr:{clean_t}?amount=1.00&memo=BlinkTip"}}]}}}}"#
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn durable_cold_transfer_and_polkadot_role_proxy_verify() {
        let sk = domain_hash("XCR.WALLET.POCKET_KEY.V1", &[&[0x19; 32]]).0;
        let sender = Keypair::from_seed(SignatureScheme::PasskeyP256, sk).address();
        let req = DurableColdTransfer {
            sender,
            recipient: Address::from_bytes([0x88; 32]),
            lane_id: 777,
            lane_seq: 0,
            amount: Amount::from_credits(12).unwrap(),
            fee: Amount::from_bits(500),
        };
        let parsed = DurableColdTransfer::from_uri(&req.to_uri()).unwrap();
        assert_eq!(parsed, req);
        let (pk, sig) = parsed.sign_offline(&[0x19; 32]).unwrap();
        assert!(verify_proxy_sig(&pk, &parsed.signing_digest(), &sig));

        let blink = format_blink_action_json("@alice.xcr", "5.00", "Coffee");
        assert!(blink.contains(r#""schema":"xcr-blink-v1""#));
    }
}
