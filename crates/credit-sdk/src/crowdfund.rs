//! **Trustless All-or-Nothing Assurance Crowdfunding (`PledgeVault`)**.
//!
//! Brings Cardano Catalyst / Kickstarter-style public-goods and indie milestone funding to Layer 1
//! with **`0%` platform cut, zero custodians, and automatic 100% refunds**:
//! - Creator opens a campaign `(campaign_id, beneficiary, title, goal_amount, deadline_unix)`.
//! - Backers pledge `XCR` into the protocol-enforced `PledgeVault`.
//! - If `total_pledged >= goal_amount`, settling transfers `total_pledged` to `beneficiary`.
//! - If `now_unix >= deadline_unix && total_pledged < goal_amount`, settling automatically refunds
//!   **100% of every backer's exact pledge** back into their `Spending Pocket` in one atomic WAL frame.

use credit_crypto::{Keypair, PublicKey, SignatureScheme, domain_hash};
use credit_types::{Address, Amount, Hash32};

pub fn crowdfund_create_digest(
    creator: &Address,
    beneficiary: &Address,
    title: &str,
    goal_amount: Amount,
    deadline_unix: u64,
    salt: &[u8; 16],
) -> Hash32 {
    domain_hash(
        "XCR.CROWDFUND.CREATE.V1",
        &[
            creator.as_bytes(),
            beneficiary.as_bytes(),
            title.as_bytes(),
            &goal_amount.bits().to_le_bytes(),
            &deadline_unix.to_le_bytes(),
            salt,
        ],
    )
}

pub fn sign_crowdfund_create(
    master_seed: &[u8; 32],
    beneficiary: &Address,
    title: &str,
    goal_amount: Amount,
    deadline_unix: u64,
    salt: [u8; 16],
) -> Result<(Address, PublicKey, Hash32, [u8; 65]), &'static str> {
    let t = title.trim();
    if t.is_empty() || t.len() > 48 || goal_amount.is_zero() {
        return Err("campaign title must be 1..=48 bytes and goal_amount > 0");
    }
    let pocket_seed = domain_hash("XCR.WALLET.POCKET_KEY.V1", &[master_seed]).0;
    let mut kp = Keypair::from_seed(SignatureScheme::PasskeyP256, pocket_seed);
    let creator = kp.address();
    let pk = kp.public_key();
    let campaign_id =
        crowdfund_create_digest(&creator, beneficiary, t, goal_amount, deadline_unix, &salt);
    let sig_vec = kp.sign(campaign_id.as_bytes()).to_bytes();
    let sig65: [u8; 65] = sig_vec.try_into().map_err(|_| "expected 65B signature")?;
    Ok((creator, pk, campaign_id, sig65))
}

pub fn crowdfund_pledge_digest(
    campaign_id: &Hash32,
    backer: &Address,
    amount: Amount,
    fee: Amount,
    salt: &[u8; 16],
) -> Hash32 {
    domain_hash(
        "XCR.CROWDFUND.PLEDGE.V1",
        &[
            campaign_id.as_bytes(),
            backer.as_bytes(),
            &amount.bits().to_le_bytes(),
            &fee.bits().to_le_bytes(),
            salt,
        ],
    )
}

pub fn sign_crowdfund_pledge(
    backer_master_seed: &[u8; 32],
    campaign_id: &Hash32,
    amount: Amount,
    fee: Amount,
    salt: [u8; 16],
) -> (Address, PublicKey, Hash32, [u8; 65]) {
    let pocket_seed = domain_hash("XCR.WALLET.POCKET_KEY.V1", &[backer_master_seed]).0;
    let mut kp = Keypair::from_seed(SignatureScheme::PasskeyP256, pocket_seed);
    let backer = kp.address();
    let pk = kp.public_key();
    let pledge_id = crowdfund_pledge_digest(campaign_id, &backer, amount, fee, &salt);
    let sig_vec = kp.sign(pledge_id.as_bytes()).to_bytes();
    let mut sig65 = [0u8; 65];
    sig65.copy_from_slice(&sig_vec);
    (backer, pk, pledge_id, sig65)
}

#[cfg(test)]
mod tests {
    use super::*;
    use credit_crypto::Signature;

    #[test]
    fn crowdfund_campaign_and_pledge_signatures_verify() {
        let (_, pk, cid, sig) = sign_crowdfund_create(
            &[0x19; 32],
            &Address::from_bytes([0x44; 32]),
            "Open Hardware NFC Wallet",
            Amount::from_credits(500).unwrap(),
            1_900_000_000,
            [2u8; 16],
        )
        .unwrap();
        assert!(pk.verify(cid.as_bytes(), &Signature::from_bytes(&sig).unwrap()));

        let (_, b_pk, pid, p_sig) = sign_crowdfund_pledge(
            &[0x29; 32],
            &cid,
            Amount::from_credits(25).unwrap(),
            Amount::from_bits(500),
            [3u8; 16],
        );
        assert!(b_pk.verify(pid.as_bytes(), &Signature::from_bytes(&p_sig).unwrap()));
    }
}
