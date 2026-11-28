//! **Stellar `ClaimableBalances`, Viral Multi-Claim `RedPackets` (`xcrdrop1_`), & Verifiable `ProofOfBurn`**.
//!
//! 1. **Stellar-Style `ClaimableBalance`:** Lock `XCR` on-chain for an **unregistered** user's
//!    `recipient_address` (with automatic sender refund after `expiry_unix` if unclaimed). When the
//!    new user sweeps, their `Spending Pocket` is automatically created & funded in `1-RTT`!
//! 2. **Multi-Claim Community `RedPacket` (`xcrdrop1_`):** Fund `N` (`1..=100`) equal-share claims
//!    unlocked by a shared link secret (`1` claim per Pocket, auto-pruned once empty).
//! 3. **Verifiable Deflationary `ProofOfBurn`:** Provably burn `XCR` or `NativeAsset` supply on-chain
//!    with an immutable `burn_memo` and cryptographic receipt ID.

use credit_crypto::{Keypair, PublicKey, Signature, SignatureScheme, domain_hash};
use credit_types::{Address, Amount, Hash32};

pub fn claimable_create_digest(
    sender: &Address,
    recipient_address: &Address,
    amount: Amount,
    expiry_unix: u64,
    fee: Amount,
    salt: &[u8; 16],
) -> Hash32 {
    domain_hash(
        "XCR.CLAIMABLE.CREATE.V1",
        &[
            sender.as_bytes(),
            recipient_address.as_bytes(),
            &amount.bits().to_le_bytes(),
            &expiry_unix.to_le_bytes(),
            &fee.bits().to_le_bytes(),
            salt,
        ],
    )
}

pub fn sign_claimable_create(
    master_seed: &[u8; 32],
    recipient_address: &Address,
    amount: Amount,
    expiry_unix: u64,
    fee: Amount,
    salt: [u8; 16],
) -> Result<(Address, PublicKey, Hash32, [u8; 65]), &'static str> {
    if amount.is_zero() {
        return Err("claimable amount must be > 0");
    }
    let sk = domain_hash("XCR.WALLET.POCKET_KEY.V1", &[master_seed]).0;
    let mut kp = Keypair::from_seed(SignatureScheme::PasskeyP256, sk);
    let sender = kp.address();
    let id = claimable_create_digest(&sender, recipient_address, amount, expiry_unix, fee, &salt);
    let sig = kp.sign(id.as_bytes());
    let mut sig65 = [0u8; 65];
    sig65.copy_from_slice(&sig.to_bytes());
    Ok((sender, kp.public_key(), id, sig65))
}

pub fn claimable_sweep_digest(claim_id: &Hash32, actor: &Address) -> Hash32 {
    domain_hash(
        "XCR.CLAIMABLE.SWEEP.V1",
        &[claim_id.as_bytes(), actor.as_bytes()],
    )
}

pub fn sign_claimable_sweep(
    master_seed: &[u8; 32],
    claim_id: &Hash32,
) -> (Address, PublicKey, Hash32, [u8; 65]) {
    let sk = domain_hash("XCR.WALLET.POCKET_KEY.V1", &[master_seed]).0;
    let mut kp = Keypair::from_seed(SignatureScheme::PasskeyP256, sk);
    let actor = kp.address();
    let digest = claimable_sweep_digest(claim_id, &actor);
    let sig = kp.sign(digest.as_bytes());
    let mut sig65 = [0u8; 65];
    sig65.copy_from_slice(&sig.to_bytes());
    (actor, kp.public_key(), digest, sig65)
}

/// Shareable viral Red-Packet link (`xcrdrop1_<128-hex>` = `drop_id || drop_secret`).
pub fn encode_redpacket_uri(drop_id: &Hash32, drop_secret: &[u8; 32]) -> String {
    let mut s = String::with_capacity(9 + 128);
    s.push_str("xcrdrop1_");
    for &b in drop_id.as_bytes().iter().chain(drop_secret.iter()) {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

pub fn decode_redpacket_uri(uri: &str) -> Option<(Hash32, [u8; 32])> {
    let hex_part = uri.trim().strip_prefix("xcrdrop1_")?;
    if hex_part.len() != 128 {
        return None;
    }
    let mut raw = [0u8; 64];
    for (i, slot) in raw.iter_mut().enumerate() {
        *slot = u8::from_str_radix(&hex_part[i * 2..i * 2 + 2], 16).ok()?;
    }
    let drop_id = Hash32::from_bytes(raw[0..32].try_into().ok()?);
    let secret: [u8; 32] = raw[32..64].try_into().ok()?;
    Some((drop_id, secret))
}

pub fn redpacket_secret_hash(drop_secret: &[u8; 32]) -> Hash32 {
    domain_hash("XCR.REDPACKET.SECRET_HASH.V1", &[drop_secret])
}

pub fn redpacket_create_digest(
    creator: &Address,
    each_amount: Amount,
    max_claims: u16,
    secret_hash: &Hash32,
    expiry_unix: u64,
    fee: Amount,
) -> Hash32 {
    domain_hash(
        "XCR.REDPACKET.CREATE.V1",
        &[
            creator.as_bytes(),
            &each_amount.bits().to_le_bytes(),
            &max_claims.to_le_bytes(),
            secret_hash.as_bytes(),
            &expiry_unix.to_le_bytes(),
            &fee.bits().to_le_bytes(),
        ],
    )
}

pub fn sign_redpacket_create(
    master_seed: &[u8; 32],
    each_amount: Amount,
    max_claims: u16,
    drop_secret: [u8; 32],
    expiry_unix: u64,
    fee: Amount,
) -> Result<SignedRedPacket, &'static str> {
    if each_amount.is_zero() || !(1..=100).contains(&max_claims) {
        return Err("each_amount must be > 0 and max_claims in 1..=100");
    }
    let sk = domain_hash("XCR.WALLET.POCKET_KEY.V1", &[master_seed]).0;
    let mut kp = Keypair::from_seed(SignatureScheme::PasskeyP256, sk);
    let creator = kp.address();
    let shash = redpacket_secret_hash(&drop_secret);
    let drop_id =
        redpacket_create_digest(&creator, each_amount, max_claims, &shash, expiry_unix, fee);
    let sig = kp.sign(drop_id.as_bytes());
    let mut sig65 = [0u8; 65];
    sig65.copy_from_slice(&sig.to_bytes());
    let uri = encode_redpacket_uri(&drop_id, &drop_secret);
    Ok((creator, kp.public_key(), drop_id, shash, uri, sig65))
}

pub fn proof_of_burn_digest(
    burner: &Address,
    asset_id: Option<&Hash32>,
    amount_bits_or_units: u64,
    memo: &str,
    salt: &[u8; 16],
) -> Hash32 {
    let mut aid_tag = [0u8; 33];
    if let Some(a) = asset_id {
        aid_tag[0] = 1;
        aid_tag[1..33].copy_from_slice(a.as_bytes());
    }
    domain_hash(
        "XCR.PROOF_OF_BURN.V1",
        &[
            burner.as_bytes(),
            &aid_tag,
            &amount_bits_or_units.to_le_bytes(),
            memo.as_bytes(),
            salt,
        ],
    )
}

pub fn sign_proof_of_burn(
    master_seed: &[u8; 32],
    asset_id: Option<&Hash32>,
    amount_bits_or_units: u64,
    memo: &str,
    salt: [u8; 16],
) -> Result<(Address, PublicKey, Hash32, [u8; 65]), &'static str> {
    if amount_bits_or_units == 0 || memo.len() > 48 {
        return Err("burn amount must be > 0 and memo <= 48 bytes");
    }
    let sk = domain_hash("XCR.WALLET.POCKET_KEY.V1", &[master_seed]).0;
    let mut kp = Keypair::from_seed(SignatureScheme::PasskeyP256, sk);
    let burner = kp.address();
    let burn_id = proof_of_burn_digest(&burner, asset_id, amount_bits_or_units, memo, &salt);
    let sig = kp.sign(burn_id.as_bytes());
    let mut sig65 = [0u8; 65];
    sig65.copy_from_slice(&sig.to_bytes());
    Ok((burner, kp.public_key(), burn_id, sig65))
}

pub type SignedRedPacket = (Address, PublicKey, Hash32, Hash32, String, [u8; 65]);

pub fn verify_claim_or_burn_sig(
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
    fn claimable_redpacket_uri_and_proof_of_burn_roundtrip() {
        let (_, pk, drop_id, _, uri, sig) = sign_redpacket_create(
            &[0x33; 32],
            Amount::from_credits(1).unwrap(),
            5,
            [0x77; 32],
            1_900_000_000,
            Amount::from_bits(500),
        )
        .unwrap();
        let (parsed_id, parsed_sec) = decode_redpacket_uri(&uri).unwrap();
        assert_eq!(parsed_id, drop_id);
        assert_eq!(parsed_sec, [0x77; 32]);
        assert!(verify_claim_or_burn_sig(
            &pk,
            &pk.to_address(),
            &drop_id,
            &sig
        ));

        let (b_addr, b_pk, burn_id, b_sig) =
            sign_proof_of_burn(&[0x44; 32], None, 2_000_000, "Community Burn #1", [1u8; 16])
                .unwrap();
        assert!(verify_claim_or_burn_sig(&b_pk, &b_addr, &burn_id, &b_sig));
    }
}
