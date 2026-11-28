//! **Tron-Style Sybil-Safe Daily Zero-Fee `Bandwidth` Quota (`∀ 0.000000 XCR` Fee)**.
//!
//! Gives every funded `Spending Pocket` (holding `>= 1.000000 XCR` anti-Sybil balance, with **zero
//! coin lockup**) **3 completely fee-free (`∀ 0.000000 XCR`) transfers every UTC day**:
//! - Captures Tron's #1 emerging-market adoption advantage (zero-fee everyday P2P payments)
//!   without centralized Super Representatives or `USDT` freeze keys.
//! - High-frequency bots and automated traders automatically spill over to standard fees after
//!   consuming their 3 daily bandwidth slots.

use credit_crypto::{Keypair, PublicKey, Signature, SignatureScheme, domain_hash};
use credit_types::{Address, Amount, Hash32};

/// Number of regenerating zero-fee `Bandwidth` transfers per UTC day for funded Pockets.
pub const DAILY_FREE_BANDWIDTH_SLOTS: u8 = 3;

/// Minimum unlocked `Spending Pocket` balance (`1.000000 XCR`) required to prevent zero-cost Sybil spam.
pub const MIN_BANDWIDTH_ELIGIBLE_BITS: u64 = 1_000_000;

pub fn bandwidth_free_pay_digest(
    sender: &Address,
    recipient: &Address,
    utc_day: u64,
    slot_index: u8,
    amount: Amount,
) -> Hash32 {
    domain_hash(
        "XCR.BANDWIDTH.FREE_PAY.V1",
        &[
            sender.as_bytes(),
            recipient.as_bytes(),
            &utc_day.to_le_bytes(),
            &[slot_index],
            &amount.bits().to_le_bytes(),
        ],
    )
}

pub fn sign_bandwidth_free_pay(
    master_seed: &[u8; 32],
    recipient: &Address,
    utc_day: u64,
    slot_index: u8,
    amount: Amount,
) -> Result<(Address, PublicKey, Hash32, [u8; 65]), &'static str> {
    if slot_index >= DAILY_FREE_BANDWIDTH_SLOTS || amount.is_zero() {
        return Err("daily zero-fee bandwidth slot_index must be 0..3 and amount > 0");
    }
    let sk = domain_hash("XCR.WALLET.POCKET_KEY.V1", &[master_seed]).0;
    let mut kp = Keypair::from_seed(SignatureScheme::PasskeyP256, sk);
    let sender = kp.address();
    let tx_id = bandwidth_free_pay_digest(&sender, recipient, utc_day, slot_index, amount);
    let sig = kp.sign(tx_id.as_bytes());
    let mut sig65 = [0u8; 65];
    sig65.copy_from_slice(&sig.to_bytes());
    Ok((sender, kp.public_key(), tx_id, sig65))
}

pub fn verify_bandwidth_sig(
    pubkey: &PublicKey,
    sender: &Address,
    digest: &Hash32,
    sig65: &[u8; 65],
) -> bool {
    pubkey.to_address() == *sender
        && Signature::from_bytes(sig65).is_some_and(|s| pubkey.verify(digest.as_bytes(), &s))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn daily_zero_fee_bandwidth_transfer_enforces_slot_cap_and_verifies() {
        let rcpt = Address::from_bytes([0x55; 32]);
        assert!(
            sign_bandwidth_free_pay(
                &[0x12; 32],
                &rcpt,
                20_000,
                3,
                Amount::from_chips(50).unwrap()
            )
            .is_err()
        );
        let (snd, pk, tx_id, sig) = sign_bandwidth_free_pay(
            &[0x12; 32],
            &rcpt,
            20_000,
            0,
            Amount::from_chips(50).unwrap(),
        )
        .unwrap();
        assert!(verify_bandwidth_sig(&pk, &snd, &tx_id, &sig));
    }
}
