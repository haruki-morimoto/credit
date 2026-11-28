//! **Unique `1-of-1` Bearer Artifacts (`CIP-68` / `ERC-721`) & Zero-PII Verifiable Attestations (`EAS` / `PRISM`)**.
//!
//! 1. **`BearerArtifact`:** Consensus-enforced `1-of-1` unique bearer deeds (event seat tickets,
//!    hardware warranties, software licenses, bills of lading) with an immutable `content_hash`
//!    and pure bearer ownership — **zero `ERC-721 setApprovalForAll()` wallet-drainer surface**.
//! 2. **`VerifiableAttestation`:** `EAS` / `Atala PRISM` signed on-chain claim commitments
//!    `(attester, subject, schema, claim_commitment, expiry_unix, revoked)` storing **zero PII**
//!    on-chain while allowing instant cryptographic verification and `1-RTT` revocation.

use credit_crypto::{Keypair, PublicKey, Signature, SignatureScheme, domain_hash};
use credit_types::{Address, Amount, Hash32};

#[allow(clippy::too_many_arguments)]
pub fn artifact_mint_digest(
    issuer: &Address,
    recipient: &Address,
    collection: &str,
    title: &str,
    content_hash: &Hash32,
    fee: Amount,
    salt: &[u8; 16],
) -> Hash32 {
    domain_hash(
        "XCR.ARTIFACT.MINT.V1",
        &[
            issuer.as_bytes(),
            recipient.as_bytes(),
            collection.as_bytes(),
            title.as_bytes(),
            content_hash.as_bytes(),
            &fee.bits().to_le_bytes(),
            salt,
        ],
    )
}

pub fn sign_artifact_mint(
    master_seed: &[u8; 32],
    recipient: &Address,
    collection: &str,
    title: &str,
    content_hash: Hash32,
    fee: Amount,
    salt: [u8; 16],
) -> Result<(Address, PublicKey, Hash32, [u8; 65]), &'static str> {
    if !(1..=24).contains(&collection.trim().len()) || !(1..=48).contains(&title.trim().len()) {
        return Err("collection must be 1..=24 bytes and title 1..=48 bytes");
    }
    let sk = domain_hash("XCR.WALLET.POCKET_KEY.V1", &[master_seed]).0;
    let mut kp = Keypair::from_seed(SignatureScheme::PasskeyP256, sk);
    let issuer = kp.address();
    let aid = artifact_mint_digest(
        &issuer,
        recipient,
        collection.trim(),
        title.trim(),
        &content_hash,
        fee,
        &salt,
    );
    let sig = kp.sign(aid.as_bytes());
    let mut sig65 = [0u8; 65];
    sig65.copy_from_slice(&sig.to_bytes());
    Ok((issuer, kp.public_key(), aid, sig65))
}

pub fn artifact_transfer_digest(
    artifact_id: &Hash32,
    sender: &Address,
    recipient: &Address,
    fee: Amount,
    salt: &[u8; 16],
) -> Hash32 {
    domain_hash(
        "XCR.ARTIFACT.TRANSFER.V1",
        &[
            artifact_id.as_bytes(),
            sender.as_bytes(),
            recipient.as_bytes(),
            &fee.bits().to_le_bytes(),
            salt,
        ],
    )
}

pub fn sign_artifact_transfer(
    master_seed: &[u8; 32],
    artifact_id: &Hash32,
    recipient: &Address,
    fee: Amount,
    salt: [u8; 16],
) -> (Address, PublicKey, Hash32, [u8; 65]) {
    let sk = domain_hash("XCR.WALLET.POCKET_KEY.V1", &[master_seed]).0;
    let mut kp = Keypair::from_seed(SignatureScheme::PasskeyP256, sk);
    let sender = kp.address();
    let xid = artifact_transfer_digest(artifact_id, &sender, recipient, fee, &salt);
    let sig = kp.sign(xid.as_bytes());
    let mut sig65 = [0u8; 65];
    sig65.copy_from_slice(&sig.to_bytes());
    (sender, kp.public_key(), xid, sig65)
}

/// Computes a zero-PII salted SHA-256 commitment to an off-chain credential or compliance statement.
pub fn compute_claim_commitment(raw_claim: &str, claim_salt: &[u8; 16]) -> Hash32 {
    domain_hash("XCR.ATTEST.CLAIM.V1", &[raw_claim.as_bytes(), claim_salt])
}

#[allow(clippy::too_many_arguments)]
pub fn attestation_issue_digest(
    attester: &Address,
    subject: &Address,
    schema: &str,
    claim_commitment: &Hash32,
    expiry_unix: u64,
    fee: Amount,
    salt: &[u8; 16],
) -> Hash32 {
    domain_hash(
        "XCR.ATTEST.ISSUE.V1",
        &[
            attester.as_bytes(),
            subject.as_bytes(),
            schema.as_bytes(),
            claim_commitment.as_bytes(),
            &expiry_unix.to_le_bytes(),
            &fee.bits().to_le_bytes(),
            salt,
        ],
    )
}

pub fn sign_attestation_issue(
    attester_seed: &[u8; 32],
    subject: &Address,
    schema: &str,
    claim_commitment: Hash32,
    expiry_unix: u64,
    fee: Amount,
    salt: [u8; 16],
) -> Result<(Address, PublicKey, Hash32, [u8; 65]), &'static str> {
    if !(1..=32).contains(&schema.trim().len()) {
        return Err("schema must be 1..=32 bytes");
    }
    let sk = domain_hash("XCR.WALLET.POCKET_KEY.V1", &[attester_seed]).0;
    let mut kp = Keypair::from_seed(SignatureScheme::PasskeyP256, sk);
    let attester = kp.address();
    let att_id = attestation_issue_digest(
        &attester,
        subject,
        schema.trim(),
        &claim_commitment,
        expiry_unix,
        fee,
        &salt,
    );
    let sig = kp.sign(att_id.as_bytes());
    let mut sig65 = [0u8; 65];
    sig65.copy_from_slice(&sig.to_bytes());
    Ok((attester, kp.public_key(), att_id, sig65))
}

pub fn attestation_revoke_digest(attester: &Address, attestation_id: &Hash32) -> Hash32 {
    domain_hash(
        "XCR.ATTEST.REVOKE.V1",
        &[attester.as_bytes(), attestation_id.as_bytes()],
    )
}

pub fn sign_attestation_revoke(
    attester_seed: &[u8; 32],
    attestation_id: &Hash32,
) -> (Address, PublicKey, Hash32, [u8; 65]) {
    let sk = domain_hash("XCR.WALLET.POCKET_KEY.V1", &[attester_seed]).0;
    let mut kp = Keypair::from_seed(SignatureScheme::PasskeyP256, sk);
    let attester = kp.address();
    let rev_id = attestation_revoke_digest(&attester, attestation_id);
    let sig = kp.sign(rev_id.as_bytes());
    let mut sig65 = [0u8; 65];
    sig65.copy_from_slice(&sig.to_bytes());
    (attester, kp.public_key(), rev_id, sig65)
}

pub fn verify_artifact_or_attest_sig(
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
    fn unique_artifact_and_zero_pii_attestation_verify() {
        let rcpt = Address::from_bytes([0x99; 32]);
        let content = domain_hash("TEST.DEED", &[b"Seat Row A #12"]);
        let (iss, pk, aid, sig) = sign_artifact_mint(
            &[0x12; 32],
            &rcpt,
            "DEVCON-VIP",
            "Row A Seat 12",
            content,
            Amount::from_bits(500),
            [3u8; 16],
        )
        .unwrap();
        assert!(verify_artifact_or_attest_sig(&pk, &iss, &aid, &sig));

        let comm = compute_claim_commitment("ISO-27001-AUDITED", &[7u8; 16]);
        let (att, apk, att_id, asig) = sign_attestation_issue(
            &[0x34; 32],
            &rcpt,
            "AUDIT-PASS-V1",
            comm,
            1_900_000_000,
            Amount::from_bits(500),
            [4u8; 16],
        )
        .unwrap();
        assert!(verify_artifact_or_attest_sig(&apk, &att, &att_id, &asig));
    }
}
