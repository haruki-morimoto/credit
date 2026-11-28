//! Self-Custody `Pocket & Vault` Wallet SDK (`credit-sdk`).
//!
//! Unifies Passkey-backed `Spending Pocket` instant payments, X25519 Stealth Addresses,
//! Privacy Pool `ProofOfInnocence` generation for regulated merchants, opt-in encrypted
//! ISO-20022 invoices, and wrench-attack-resistant `Savings Vault` controls.

pub mod amm_router;
pub mod artifacts_attest;
pub mod atomic_lanes;
pub mod bandwidth_quota;
pub mod bolt11_swap;
pub mod checks;
pub mod claimable_drops_burn;
pub mod cold_sign;
pub mod credscript;
pub mod crowdfund;
pub mod dex_babel;
pub mod frost;
pub mod governance_shield;
pub mod handles;
pub mod history;
pub mod htlc_offers;
pub mod keystore;
pub mod light_client;
pub mod mnemonic;
pub mod native_assets;
pub mod onchain_names;
pub mod oracle_feeds;
pub mod paychan;
pub mod payment_uri;
pub mod qr;
pub mod session_keys;
pub mod shamir;
pub mod shielded_pool;
pub mod subscriptions;

pub use amm_router::{
    amm_constant_product_out, amm_liquidity_digest, hybrid_swap_digest, isqrt_u128,
    sign_amm_liquidity, sign_hybrid_smart_swap, verify_amm_sig,
};
pub use artifacts_attest::{
    artifact_mint_digest, artifact_transfer_digest, attestation_issue_digest,
    attestation_revoke_digest, compute_claim_commitment, sign_artifact_mint,
    sign_artifact_transfer, sign_attestation_issue, sign_attestation_revoke,
    verify_artifact_or_attest_sig,
};
pub use atomic_lanes::{
    AtomicBatchOp, SignedAtomicBatch, atomic_batch_digest, decode_atomic_ops, encode_atomic_ops,
    parallel_lane_pay_digest, sign_atomic_batch, sign_parallel_lane_pay, verify_batch_or_lane_sig,
};
pub use bandwidth_quota::{
    DAILY_FREE_BANDWIDTH_SLOTS, MIN_BANDWIDTH_ELIGIBLE_BITS, bandwidth_free_pay_digest,
    sign_bandwidth_free_pay, verify_bandwidth_sig,
};
pub use bolt11_swap::{Bolt11Invoice, bech32_decode, bech32_encode, build_bitcoin_p2wsh_htlc};
pub use checks::{
    DigitalCheck, check_cancel_digest, check_cash_digest, sign_check_cancel, sign_check_cash,
};
pub use claimable_drops_burn::{
    SignedRedPacket, claimable_create_digest, claimable_sweep_digest, decode_redpacket_uri,
    encode_redpacket_uri, proof_of_burn_digest, redpacket_create_digest, redpacket_secret_hash,
    sign_claimable_create, sign_claimable_sweep, sign_proof_of_burn, sign_redpacket_create,
    verify_claim_or_burn_sig,
};
pub use cold_sign::{SignedColdTransfer, UnsignedColdTransfer};
pub use credscript::{
    CredEvalContext, CredOp, CredScript, CredWitnessItem, decode_witness_stack,
    encode_witness_stack, script_vault_lock_digest, script_vault_spend_digest,
    sign_script_vault_lock,
};
pub use crowdfund::{
    crowdfund_create_digest, crowdfund_pledge_digest, sign_crowdfund_create, sign_crowdfund_pledge,
};
pub use dex_babel::{
    DexLimitOrder, babel_asset_transfer_digest, bridged_payment_digest, dex_cancel_digest,
    sign_babel_asset_transfer, sign_bridged_payment, sign_dex_cancel,
};
pub use frost::{
    FrostError, FrostKeyShare, FrostNonceCommit, FrostNonceSecret, FrostPartialSig,
    frost_aggregate_cold_transfer, frost_aggregate_signature, frost_commit_nonce,
    frost_sign_partial, frost_split_pocket_key,
};
pub use governance_shield::{
    deposit_shield_digest, drep_delegate_digest, governance_vote_digest, proposal_create_digest,
    sign_deposit_shield, sign_drep_delegate, sign_governance_proposal, sign_governance_vote,
    validate_constitutional_parameter, verify_gov_or_shield_sig,
};
pub use handles::{LocalHandleBook, format_well_known_pay_json, resolve_remote_handle};
pub use history::{ActivityEntry, EncryptedActivityLog};
pub use htlc_offers::{
    AtomicSwapOffer, generate_htlc_secret, htlc_lock_signing_digest, sign_htlc_lock,
    verify_htlc_preimage,
};
pub use keystore::{
    ENCRYPTED_WALLET_LEN, ENCRYPTED_WALLET_MAGIC, KeystoreError, PLAIN_WALLET_MAGIC, ZeroizingSeed,
    derive_passphrase_kek, encrypt_wallet_seed, is_encrypted_wallet_bytes, open_wallet_bytes,
};
pub use light_client::{LightClientError, MobileLightClient};
pub use mnemonic::{
    MnemonicError, decode_mnemonic_24, encode_mnemonic_24, format_backup_card_24, lookup_word,
    word_at,
};
pub use native_assets::{NativeAssetMint, asset_transfer_digest, sign_asset_transfer};
pub use onchain_names::{
    SignedHandleRegistration, format_xcr_handle, handle_register_digest, handle_transfer_digest,
    normalize_xcr_handle, registration_fee_for_handle, sign_handle_register, sign_handle_transfer,
    verify_handle_sig,
};
pub use oracle_feeds::{
    compute_trimmed_median_micros, fiat_cents_to_xcr, is_valid_feed_id, oracle_pegged_pay_digest,
    oracle_report_digest, sign_oracle_fiat_payment, sign_oracle_report, verify_oracle_sig,
};
pub use paychan::{
    PayChanVoucher, paychan_open_signing_digest, paychan_tick_digest, sign_paychan_open,
};
pub use payment_uri::{
    BearerVoucher, PaymentRequestUri, parse_decimal_xcr, url_decode, url_encode,
};
pub use qr::{MAX_QR_PAYLOAD_BYTES, QrCode, QrError};
pub use session_keys::{
    SessionKeyGrant, fee_sponsor_digest, session_revoke_digest, session_spend_digest,
    sign_fee_sponsorship, sign_session_revoke,
};
pub use shamir::{ShamirError, ShamirShare, combine_secret_shamir, split_secret_shamir};
pub use shielded_pool::{
    PaymentDisclosureProof, RingCtSignature, ShieldedNoteOutput, ShieldedViewingKey,
    hash_to_prime_point, is_valid_prime_order_key_image, shield_deposit_digest,
    sign_shield_deposit, verify_pocket_sig,
};
pub use subscriptions::{SubscriptionBook, SubscriptionMandate};

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
