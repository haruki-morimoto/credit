//! Self-Custody `Pocket & Vault` Wallet SDK (`credit-sdk`).
//!
//! Unifies Passkey-backed `Spending Pocket` instant payments, X25519 Stealth Addresses,
//! Privacy Pool `ProofOfInnocence` generation for regulated merchants, opt-in encrypted
//! ISO-20022 invoices, and wrench-attack-resistant `Savings Vault` controls.

pub mod handles;
pub mod keystore;
pub mod light_client;
pub mod mnemonic;
pub mod payment_uri;
pub mod qr;

pub use handles::{LocalHandleBook, format_well_known_pay_json, resolve_remote_handle};
pub use keystore::{
    ENCRYPTED_WALLET_LEN, ENCRYPTED_WALLET_MAGIC, KeystoreError, PLAIN_WALLET_MAGIC, ZeroizingSeed,
    derive_passphrase_kek, encrypt_wallet_seed, is_encrypted_wallet_bytes, open_wallet_bytes,
};
pub use light_client::{LightClientError, MobileLightClient};
pub use mnemonic::{
    MnemonicError, decode_mnemonic_24, encode_mnemonic_24, format_backup_card_24, lookup_word,
    word_at,
};
pub use payment_uri::{
    BearerVoucher, PaymentRequestUri, parse_decimal_xcr, url_decode, url_encode,
};
pub use qr::{MAX_QR_PAYLOAD_BYTES, QrCode, QrError};

use credit_consensus::tx_signing_digest;
use credit_crypto::{
    Keypair, PublicKey, SignatureScheme, StealthKeypair, StealthMetaAddress, StealthOutput,
    derive_stealth_output, domain_hash,
};
use credit_types::{
    AccountError, Address, Amount, CredchipStatus, Hash32, PocketState, Transaction,
    TransactionKind, VaultState,
};
use credit_zk::{
    BlindedCommitment, EncryptedIso20022Receipt, Iso20022Memo, MerklePath, ProofOfInnocence,
};

/// Bundle returned when building a private or regulated-commerce 1-RTT payment.
#[derive(Clone, Debug)]
pub struct PreparedPayment {
    pub transaction: Transaction,
    pub stealth_output: StealthOutput,
    pub commitment: BlindedCommitment,
    pub innocence_proof: Option<ProofOfInnocence>,
    pub encrypted_receipt: Option<EncryptedIso20022Receipt>,
}

/// Sovereign `Pocket & Vault` client wallet.
pub struct CreditWallet {
    pocket_signer: Keypair,
    pq_guardian_signer: Keypair,
    stealth: StealthKeypair,
    pub pocket: PocketState,
    pub vault: VaultState,
    tx_counter: u64,
}

impl CreditWallet {
    /// Initializes a sovereign `Pocket & Vault` wallet from a 256-bit master seed.
    pub fn from_master_seed(
        master_seed: [u8; 32],
        initial_pocket: Amount,
        daily_tap_limit: Amount,
        initial_vault: Amount,
        vault_timelock_ms: u64,
    ) -> Self {
        let pocket_seed = domain_hash("XCR.WALLET.POCKET_KEY.V1", &[&master_seed]).0;
        let pq_seed = domain_hash("XCR.WALLET.PQ_GUARDIAN.V1", &[&master_seed]).0;
        let stealth_seed = domain_hash("XCR.WALLET.STEALTH.V1", &[&master_seed]).0;

        let pocket_signer = Keypair::from_seed(SignatureScheme::PasskeyP256, pocket_seed);
        let pq_guardian_signer = Keypair::from_seed(SignatureScheme::HybridPqMlDsa65, pq_seed);
        let stealth = StealthKeypair::from_seed(&stealth_seed);

        let pq_root = pq_guardian_signer.public_key().merkle_root;
        Self {
            pocket_signer,
            pq_guardian_signer,
            stealth,
            pocket: PocketState::new(initial_pocket, daily_tap_limit),
            vault: VaultState::new(initial_vault, vault_timelock_ms, 2, pq_root),
            tx_counter: 0,
        }
    }

    #[inline]
    pub fn pocket_public_key(&self) -> PublicKey {
        self.pocket_signer.public_key()
    }

    #[inline]
    pub fn pocket_address(&self) -> Address {
        self.pocket_signer.address()
    }

    #[inline]
    pub fn pq_guardian_public_key(&self) -> PublicKey {
        self.pq_guardian_signer.public_key()
    }

    #[inline]
    pub fn stealth_meta_address(&self) -> StealthMetaAddress {
        self.stealth.meta_address()
    }

    /// Computes the live 4-Dot Credchip status diamond for wallet UI / NFC hardware cards.
    pub fn credchip_status(&self, zk_synced: bool, node_earning: bool) -> CredchipStatus {
        CredchipStatus {
            pocket_active: !self.pocket.balance.is_zero(),
            vault_shielded: self.vault.timelock_ms > 0
                && self.vault.pq_guardian_root != Hash32::ZERO,
            zk_proof_synced: zk_synced,
            node_earning,
        }
    }

    /// Builds a signed 1-RTT `FastTransfer` to `recipient`, optionally attaching a client-side
    /// `ProofOfInnocence` and end-to-end encrypted `Iso20022Memo` for regulated commerce.
    #[allow(clippy::too_many_arguments)]
    pub fn build_fast_payment(
        &mut self,
        recipient: &StealthMetaAddress,
        amount: Amount,
        fee: Amount,
        clean_witness: Option<(BlindedCommitment, MerklePath, Hash32, &[u8])>,
        commercial_memo: Option<Iso20022Memo>,
    ) -> PreparedPayment {
        let seq = self.tx_counter;
        self.tx_counter += 1;

        let eph_seed = domain_hash(
            "XCR.WALLET.EPH.V1",
            &[self.pocket_address().as_bytes(), &seq.to_le_bytes()],
        )
        .0;
        let (stealth_output, shared_secret) = derive_stealth_output(recipient, &eph_seed);

        let blinding = domain_hash("XCR.WALLET.BLIND.V1", &[&shared_secret, &seq.to_le_bytes()]).0;
        let commitment = BlindedCommitment::commit(amount, &blinding);

        let innocence_proof = clean_witness.and_then(|(clean_note, path, root, ctx)| {
            let note_secret = domain_hash("XCR.WALLET.NOTE_SK.V1", &[&shared_secret]).0;
            ProofOfInnocence::generate(&note_secret, clean_note, path, root, ctx)
        });

        let encrypted_receipt = commercial_memo.map(|memo| {
            let view_key = domain_hash("XCR.WALLET.VIEW_KEY.V1", &[&shared_secret]).0;
            let mut nonce = [0u8; 16];
            nonce.copy_from_slice(&eph_seed[..16]);
            EncryptedIso20022Receipt::encrypt(&memo, &view_key, nonce)
        });

        let kind = TransactionKind::FastTransfer {
            from: self.pocket_address(),
            to_stealth: stealth_output.one_time_address,
            stealth_view_tag: stealth_output.view_tag,
            amount,
            fee,
            nonce: self.pocket.nonce,
            commitment: commitment.0,
            innocence_nullifier: innocence_proof.as_ref().map(|p| p.nullifier),
        };
        let id = tx_signing_digest(&kind);
        let sig = self.pocket_signer.sign(id.as_bytes()).to_bytes();

        PreparedPayment {
            transaction: Transaction {
                id,
                kind,
                signature_bytes: sig,
            },
            stealth_output,
            commitment,
            innocence_proof,
            encrypted_receipt,
        }
    }

    /// Scans an on-chain `StealthOutput` using the 1-byte `view_tag` fast filter.
    pub fn scan_stealth_output(&self, output: &StealthOutput) -> Option<[u8; 32]> {
        self.stealth.scan_output(output)
    }

    pub fn queue_vault_withdrawal(
        &mut self,
        destination: Address,
        amount: Amount,
        now_ms: u64,
    ) -> Result<u64, AccountError> {
        self.vault.queue_withdrawal(destination, amount, now_ms)
    }

    pub fn emergency_cancel_vault_withdrawal(
        &mut self,
        withdrawal_id: u64,
    ) -> Result<Amount, AccountError> {
        self.vault.emergency_cancel(withdrawal_id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wallet_credchip_4dot_and_stealth_payment_flow() {
        let mut alice = CreditWallet::from_master_seed(
            [0x10; 32],
            Amount::from_credits(250).unwrap(),
            Amount::from_credits(100).unwrap(),
            Amount::from_credits(5_000).unwrap(),
            86_400_000,
        );
        let bob = CreditWallet::from_master_seed(
            [0x20; 32],
            Amount::ZERO,
            Amount::from_credits(100).unwrap(),
            Amount::ZERO,
            86_400_000,
        );

        let status = alice.credchip_status(true, true);
        assert_eq!(status.active_dots(), 4);

        let prepared = alice.build_fast_payment(
            &bob.stealth_meta_address(),
            Amount::from_credits(15).unwrap(),
            Amount::from_bits(200),
            None,
            None,
        );
        assert!(prepared.transaction.is_single_owner_fast_path());
        assert!(bob.scan_stealth_output(&prepared.stealth_output).is_some());
        assert!(
            alice
                .scan_stealth_output(&prepared.stealth_output)
                .is_none()
        );
    }
}
