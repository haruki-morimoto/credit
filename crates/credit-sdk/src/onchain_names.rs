//! **Censorship-Resistant On-Chain `@name.xcr` Handle Registry** (`ENS` / `ADA Handle` parity).
//!
//! Resolves human-readable `@alice.xcr` handles directly from Merkle-authenticated Layer-1 state
//! without relying on ICANN domain registrars, DNS servers, or TLS Certificate Authorities:
//! - Canonical names: `3..=24` chars (`a-z`, `0-9`, `_`, `-`), displayed as `@<name>.xcr`.
//! - Anti-squatting fee is **100% protocol-routed** (`85%` PoNC miners + `15%` permanent burn; `0%` company cut).
//! - Maps `@name.xcr` -> `(owner_pocket, owner_pubkey, stealth_meta_uri)` with `1-RTT` key rotation/transfer.

use credit_crypto::{Keypair, PublicKey, Signature, SignatureScheme, domain_hash};
use credit_types::{Address, Amount, Hash32};

/// Normalizes `@alice.xcr`, `@alice`, or `alice.xcr` into canonical lowercase `alice`.
pub fn normalize_xcr_handle(raw: &str) -> Option<String> {
    let mut s = raw.trim().to_ascii_lowercase();
    if let Some(stripped) = s.strip_prefix('@') {
        s = stripped.to_owned();
    }
    if let Some(stripped) = s.strip_suffix(".xcr") {
        s = stripped.to_owned();
    }
    if !(3..=24).contains(&s.len()) || s.starts_with("xcr1_") || s.starts_with("xcrstealth1_") {
        return None;
    }
    if !s
        .bytes()
        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_' || b == b'-')
    {
        return None;
    }
    Some(s)
}

/// Formats a normalized handle (`alice`) in canonical display form (`@alice.xcr`).
pub fn format_xcr_handle(normalized: &str) -> String {
    format!("@{normalized}.xcr")
}

/// Anti-squatting registration fee (`1.00 XCR` for scarce 3-4 char names; `0.10 XCR` for 5+ chars).
pub fn registration_fee_for_handle(normalized: &str) -> Amount {
    if normalized.len() <= 4 {
        Amount::from_credits(1).unwrap()
    } else {
        Amount::from_chips(10).unwrap()
    }
}

pub fn handle_register_digest(
    normalized_name: &str,
    owner: &Address,
    stealth_uri: &str,
    fee: Amount,
) -> Hash32 {
    domain_hash(
        "XCR.HANDLE.REGISTER.V1",
        &[
            normalized_name.as_bytes(),
            owner.as_bytes(),
            stealth_uri.as_bytes(),
            &fee.bits().to_le_bytes(),
        ],
    )
}

pub type SignedHandleRegistration = (String, Address, PublicKey, Amount, Hash32, [u8; 65]);

pub fn sign_handle_register(
    master_seed: &[u8; 32],
    raw_handle: &str,
    stealth_uri: &str,
) -> Result<SignedHandleRegistration, &'static str> {
    let Some(name) = normalize_xcr_handle(raw_handle) else {
        return Err("handle must be 3..=24 chars of [a-z0-9_-] (e.g. `@alice.xcr`)");
    };
    if stealth_uri.len() > 200 {
        return Err("stealth URI exceeds 200 bytes");
    }
    let fee = registration_fee_for_handle(&name);
    let sk = domain_hash("XCR.WALLET.POCKET_KEY.V1", &[master_seed]).0;
    let mut kp = Keypair::from_seed(SignatureScheme::PasskeyP256, sk);
    let owner = kp.address();
    let tx_id = handle_register_digest(&name, &owner, stealth_uri, fee);
    let sig = kp.sign(tx_id.as_bytes());
    let mut sig65 = [0u8; 65];
    sig65.copy_from_slice(&sig.to_bytes());
    Ok((name, owner, kp.public_key(), fee, tx_id, sig65))
}

pub fn handle_transfer_digest(
    normalized_name: &str,
    current_owner: &Address,
    new_owner: &Address,
    new_stealth_uri: &str,
    fee: Amount,
    salt: &[u8; 16],
) -> Hash32 {
    domain_hash(
        "XCR.HANDLE.TRANSFER.V1",
        &[
            normalized_name.as_bytes(),
            current_owner.as_bytes(),
            new_owner.as_bytes(),
            new_stealth_uri.as_bytes(),
            &fee.bits().to_le_bytes(),
            salt,
        ],
    )
}

pub fn sign_handle_transfer(
    current_owner_seed: &[u8; 32],
    raw_handle: &str,
    new_owner: &Address,
    new_stealth_uri: &str,
    fee: Amount,
    salt: [u8; 16],
) -> Result<(String, Address, PublicKey, Hash32, [u8; 65]), &'static str> {
    let Some(name) = normalize_xcr_handle(raw_handle) else {
        return Err("invalid handle name");
    };
    if new_stealth_uri.len() > 200 {
        return Err("stealth URI exceeds 200 bytes");
    }
    let sk = domain_hash("XCR.WALLET.POCKET_KEY.V1", &[current_owner_seed]).0;
    let mut kp = Keypair::from_seed(SignatureScheme::PasskeyP256, sk);
    let owner = kp.address();
    let tx_id = handle_transfer_digest(&name, &owner, new_owner, new_stealth_uri, fee, &salt);
    let sig = kp.sign(tx_id.as_bytes());
    let mut sig65 = [0u8; 65];
    sig65.copy_from_slice(&sig.to_bytes());
    Ok((name, owner, kp.public_key(), tx_id, sig65))
}

pub fn verify_handle_sig(
    pubkey: &PublicKey,
    owner: &Address,
    digest: &Hash32,
    sig65: &[u8; 65],
) -> bool {
    pubkey.to_address() == *owner
        && Signature::from_bytes(sig65).is_some_and(|s| pubkey.verify(digest.as_bytes(), &s))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn handle_normalization_pricing_and_signing_work() {
        assert_eq!(normalize_xcr_handle("@Alice.XCR").as_deref(), Some("alice"));
        assert_eq!(
            normalize_xcr_handle("bob_2027").as_deref(),
            Some("bob_2027")
        );
        assert!(normalize_xcr_handle("ab").is_none());
        assert!(normalize_xcr_handle("xcr1_deadbeef").is_none());

        assert_eq!(
            registration_fee_for_handle("dao"),
            Amount::from_credits(1).unwrap()
        );
        assert_eq!(
            registration_fee_for_handle("alice"),
            Amount::from_chips(10).unwrap()
        );

        let (name, owner, pk, _fee, digest, sig) =
            sign_handle_register(&[0x77; 32], "@Haruki.xcr", "xcrstealth1_demo").unwrap();
        assert_eq!(name, "haruki");
        assert!(verify_handle_sig(&pk, &owner, &digest, &sig));
    }
}
