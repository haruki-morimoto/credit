//! **Cardano `Voltaire` (`CIP-1694`) Constitutional Liquid Governance & XRPL `DepositAuth` Inbox Shield**.
//!
//! 1. **Constitutional Liquid `DRep` Governance:** Zero-lockup liquid delegation (`drep-delegate`)
//!    and non-custodial proposal tallying (`proposal-create`, `vote-cast`) guarded by **Hardcoded
//!    Unbreakable Constitutional Invariants**: any proposal attempting to alter monetary emission,
//!    introduce a premine, or add issuer freeze/clawback powers is deterministically rejected!
//! 2. **Receiver-Opt-In Anti-Dust Inbox Shield (`DepositShieldPolicy`):** Allows a merchant,
//!    exchange, or public treasury to set a `min_deposit` threshold and `DepositPreauth` allowlist
//!    on *their own* `Spending Pocket` to block unsolicited `1-bit` dust-tainting spam.

use credit_crypto::{Keypair, PublicKey, Signature, SignatureScheme, domain_hash};
use credit_types::{Address, Amount, Hash32};

/// Constitutional parameter check enforcing Credit's forever-immutable monetary & sovereignty rules.
pub fn validate_constitutional_parameter(
    param_key: &str,
    param_value: u64,
) -> Result<(), &'static str> {
    match param_key {
        "min_relay_fee_bits" => {
            if (100..=50_000).contains(&param_value) {
                Ok(())
            } else {
                Err("min_relay_fee_bits must remain within constitutional bounds 100..=50_000 bits")
            }
        }
        "max_credscript_ops" => {
            if (16..=128).contains(&param_value) {
                Ok(())
            } else {
                Err("max_credscript_ops must remain within constitutional bounds 16..=128 ops")
            }
        }
        "dormant_threshold_epochs" => {
            if (1_000..=5_000_000).contains(&param_value) {
                Ok(())
            } else {
                Err("dormant_threshold_epochs must remain within 1_000..=5_000_000")
            }
        }
        "public_goods_signal" => Ok(()),
        "max_supply" | "emission_schedule" | "premine" | "freeze_accounts" | "clawback" => Err(
            "UNCONSTITUTIONAL: monetary emission, 0% premine, and bearer sovereignty are forever immutable",
        ),
        _ => Err("unknown governance parameter key"),
    }
}

pub fn proposal_create_digest(
    proposer: &Address,
    title: &str,
    param_key: &str,
    param_value: u64,
    deadline_unix: u64,
    salt: &[u8; 16],
) -> Hash32 {
    domain_hash(
        "XCR.GOV.PROPOSAL.V1",
        &[
            proposer.as_bytes(),
            title.as_bytes(),
            param_key.as_bytes(),
            &param_value.to_le_bytes(),
            &deadline_unix.to_le_bytes(),
            salt,
        ],
    )
}

pub fn sign_governance_proposal(
    master_seed: &[u8; 32],
    title: &str,
    param_key: &str,
    param_value: u64,
    deadline_unix: u64,
    salt: [u8; 16],
) -> Result<(Address, PublicKey, Hash32, [u8; 65]), &'static str> {
    let t = title.trim();
    let k = param_key.trim();
    if t.is_empty() || t.len() > 48 {
        return Err("proposal title must be 1..=48 bytes");
    }
    validate_constitutional_parameter(k, param_value)?;
    let sk = domain_hash("XCR.WALLET.POCKET_KEY.V1", &[master_seed]).0;
    let mut kp = Keypair::from_seed(SignatureScheme::PasskeyP256, sk);
    let proposer = kp.address();
    let prop_id = proposal_create_digest(&proposer, t, k, param_value, deadline_unix, &salt);
    let sig = kp.sign(prop_id.as_bytes());
    let mut sig65 = [0u8; 65];
    sig65.copy_from_slice(&sig.to_bytes());
    Ok((proposer, kp.public_key(), prop_id, sig65))
}

pub fn drep_delegate_digest(delegator: &Address, drep: &Address, seq_salt: &[u8; 16]) -> Hash32 {
    domain_hash(
        "XCR.GOV.DREP_DELEGATE.V1",
        &[delegator.as_bytes(), drep.as_bytes(), seq_salt],
    )
}

pub fn sign_drep_delegate(
    master_seed: &[u8; 32],
    drep: &Address,
    seq_salt: [u8; 16],
) -> (Address, PublicKey, Hash32, [u8; 65]) {
    let sk = domain_hash("XCR.WALLET.POCKET_KEY.V1", &[master_seed]).0;
    let mut kp = Keypair::from_seed(SignatureScheme::PasskeyP256, sk);
    let delegator = kp.address();
    let tx_id = drep_delegate_digest(&delegator, drep, &seq_salt);
    let sig = kp.sign(tx_id.as_bytes());
    let mut sig65 = [0u8; 65];
    sig65.copy_from_slice(&sig.to_bytes());
    (delegator, kp.public_key(), tx_id, sig65)
}

/// `choice`: `1 = Yes`, `0 = No`, `2 = Abstain`.
pub fn governance_vote_digest(proposal_id: &Hash32, voter: &Address, choice: u8) -> Hash32 {
    domain_hash(
        "XCR.GOV.VOTE.V1",
        &[proposal_id.as_bytes(), voter.as_bytes(), &[choice]],
    )
}

pub fn sign_governance_vote(
    master_seed: &[u8; 32],
    proposal_id: &Hash32,
    choice: u8,
) -> Result<(Address, PublicKey, Hash32, [u8; 65]), &'static str> {
    if choice > 2 {
        return Err("vote choice must be 0 (No), 1 (Yes), or 2 (Abstain)");
    }
    let sk = domain_hash("XCR.WALLET.POCKET_KEY.V1", &[master_seed]).0;
    let mut kp = Keypair::from_seed(SignatureScheme::PasskeyP256, sk);
    let voter = kp.address();
    let vote_id = governance_vote_digest(proposal_id, &voter, choice);
    let sig = kp.sign(vote_id.as_bytes());
    let mut sig65 = [0u8; 65];
    sig65.copy_from_slice(&sig.to_bytes());
    Ok((voter, kp.public_key(), vote_id, sig65))
}

pub fn deposit_shield_digest(
    owner: &Address,
    min_deposit: Amount,
    strict_allowlist_only: bool,
    allowlist: &[Address],
    salt: &[u8; 16],
) -> Hash32 {
    let mut list_bytes = Vec::with_capacity(allowlist.len() * 32);
    for a in allowlist {
        list_bytes.extend_from_slice(a.as_bytes());
    }
    domain_hash(
        "XCR.POCKET.DEPOSIT_SHIELD.V1",
        &[
            owner.as_bytes(),
            &min_deposit.bits().to_le_bytes(),
            &[strict_allowlist_only as u8],
            &list_bytes,
            salt,
        ],
    )
}

pub fn sign_deposit_shield(
    master_seed: &[u8; 32],
    min_deposit: Amount,
    strict_allowlist_only: bool,
    allowlist: &[Address],
    salt: [u8; 16],
) -> Result<(Address, PublicKey, Hash32, [u8; 65]), &'static str> {
    if allowlist.len() > 16 {
        return Err("DepositPreauth allowlist supports at most 16 addresses");
    }
    let sk = domain_hash("XCR.WALLET.POCKET_KEY.V1", &[master_seed]).0;
    let mut kp = Keypair::from_seed(SignatureScheme::PasskeyP256, sk);
    let owner = kp.address();
    let tx_id = deposit_shield_digest(&owner, min_deposit, strict_allowlist_only, allowlist, &salt);
    let sig = kp.sign(tx_id.as_bytes());
    let mut sig65 = [0u8; 65];
    sig65.copy_from_slice(&sig.to_bytes());
    Ok((owner, kp.public_key(), tx_id, sig65))
}

pub fn verify_gov_or_shield_sig(
    pubkey: &PublicKey,
    actor: &Address,
    digest: &Hash32,
    sig65: &[u8; 65],
) -> bool {
    pubkey.to_address() == *actor
        && Signature::from_bytes(sig65).is_some_and(|s| pubkey.verify(digest.as_bytes(), &s))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn constitutional_guard_blocks_monetary_tampering_and_allows_valid_proposals() {
        assert!(validate_constitutional_parameter("max_supply", 999_999_999).is_err());
        assert!(validate_constitutional_parameter("freeze_accounts", 1).is_err());
        assert!(validate_constitutional_parameter("min_relay_fee_bits", 500).is_ok());

        let (prop, pk, pid, sig) = sign_governance_proposal(
            &[0x21; 32],
            "Lower Relay Fee Floor to 400 bits",
            "min_relay_fee_bits",
            400,
            1_900_000_000,
            [1u8; 16],
        )
        .unwrap();
        assert!(verify_gov_or_shield_sig(&pk, &prop, &pid, &sig));

        let (own, opk, sid, ssig) = sign_deposit_shield(
            &[0x55; 32],
            Amount::from_chips(5).unwrap(),
            false,
            &[prop],
            [2u8; 16],
        )
        .unwrap();
        assert!(verify_gov_or_shield_sig(&opk, &own, &sid, &ssig));
    }
}
