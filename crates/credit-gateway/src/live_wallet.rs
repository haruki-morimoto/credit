//! Live Network-Connected Consumer Wallet & Merchant POS Gateway (`credit-gateway --testnet --wallet <PATH>`).
//!
//! Includes CSRF session-token protection (`X-XCR-Token`), `XCRENC01` memory-hard wallet lock/unlock,
//! natural decimal `XCR` parsing, AEAD-encrypted local activity history (`<wallet>.history`),
//! zero-click stealth auto-sweeping, visual `@contacts`, QR checkout, and Bearer Cash Vouchers.

use std::fs;
use std::io::{self, Write};
use std::net::{SocketAddr, TcpListener};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use credit_consensus::tx_signing_digest;
use credit_crypto::{
    Keypair, Scalar, SignatureScheme, StealthKeypair, StealthMetaAddress, StealthOutput,
    decrypt_stealth_memo, derive_stealth_output, domain_hash, encrypt_stealth_memo,
};
use credit_net::{NodeRpcRequest, NodeRpcResponse, StealthOutputRecordV2, rpc_call};
use credit_sdk::{
    AtomicSwapOffer, BearerVoucher, DigitalCheck, EncryptedActivityLog, KeystoreError,
    LocalHandleBook, NativeAssetMint, PLAIN_WALLET_MAGIC, PayChanVoucher, PaymentRequestUri,
    QrCode, SessionKeyGrant, ShamirShare, SubscriptionBook, UnsignedColdTransfer, ZeroizingSeed,
    combine_secret_shamir, decode_mnemonic_24, encode_mnemonic_24, encrypt_wallet_seed,
    format_well_known_pay_json, frost_split_pocket_key, generate_htlc_secret,
    is_encrypted_wallet_bytes, open_wallet_bytes, parse_decimal_xcr, resolve_remote_handle,
    sign_check_cancel, sign_check_cash, sign_htlc_lock, sign_paychan_open, split_secret_shamir,
};
use credit_types::{
    Address, Amount, EpochId, FeeSplit, Hash32, MIN_BASE_FEE_BITS, Transaction, TransactionKind,
    VaultState,
};
use credit_zk::{
    AssociationTree, BlindedCommitment, BulletproofRange64, ProofOfInnocence, StateInclusionProof,
    StateLeaf,
};

use crate::jsonrpc::handle_jsonrpc_post;
use crate::ui::WALLET_AND_POS_HTML;
use crate::webhook::{EMBED_CHECKOUT_JS, dispatch_signed_webhook};
use crate::{
    check_csrf_request_allowed, generate_csrf_token, json_escape, percent_decode, query_param,
};

const LIVE_RPC_TIMEOUT: Duration = Duration::from_secs(8);

struct LiveWalletGateway {
    wallet_path: PathBuf,
    unlocked_seed: Option<ZeroizingSeed>,
    encrypted_on_disk: bool,
    pocket_addr: Address,
    stealth_meta: StealthMetaAddress,
    node_addr: SocketAddr,
    network_label: String,
    vault: VaultState,
    clean_tree: AssociationTree,
    clean_note: BlindedCommitment,
    csrf_token: String,
    webhook_url: Option<String>,
    webhook_secret: String,
}

impl LiveWalletGateway {
    fn open(
        wallet_path: &Path,
        initial_password: Option<&str>,
        node_addr: SocketAddr,
        network_label: String,
    ) -> io::Result<Self> {
        let csrf_token = generate_csrf_token();
        if wallet_path.exists() {
            let raw = fs::read(wallet_path)?;
            let encrypted_on_disk = is_encrypted_wallet_bytes(&raw);
            match open_wallet_bytes(&raw, initial_password) {
                Ok(seed) => Self::from_unlocked(
                    wallet_path.to_path_buf(),
                    seed,
                    encrypted_on_disk,
                    node_addr,
                    network_label,
                    csrf_token,
                ),
                Err(KeystoreError::PasswordRequired) => Ok(Self {
                    wallet_path: wallet_path.to_path_buf(),
                    unlocked_seed: None,
                    encrypted_on_disk: true,
                    pocket_addr: Address::default(),
                    stealth_meta: StealthKeypair::from_seed(&[1u8; 32]).meta_address(),
                    node_addr,
                    network_label,
                    vault: VaultState::new(Amount::ZERO, 86_400_000, 2, Hash32::ZERO),
                    clean_tree: AssociationTree::new(4),
                    clean_note: BlindedCommitment::commit(Amount::ZERO, &[0u8; 32]),
                    csrf_token,
                    webhook_url: None,
                    webhook_secret: String::new(),
                }),
                Err(e) => Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    e.to_string(),
                )),
            }
        } else {
            if let Some(parent) = wallet_path.parent()
                && !parent.as_os_str().is_empty()
            {
                fs::create_dir_all(parent)?;
            }
            let nanos = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos();
            let seed = domain_hash(
                "XCR.GW.LIVE_WALLET.V1",
                &[
                    &nanos.to_le_bytes(),
                    wallet_path.to_string_lossy().as_bytes(),
                ],
            )
            .0;
            let encrypted_on_disk = if let Some(pw) = initial_password.filter(|p| !p.is_empty()) {
                let mut salt = [0u8; 16];
                salt.copy_from_slice(&seed[..16]);
                let sealed = encrypt_wallet_seed(&seed, pw, salt, 1)
                    .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e.to_string()))?;
                fs::write(wallet_path, sealed)?;
                true
            } else {
                write_plain_seed_file(wallet_path, &seed)?;
                false
            };
            Self::from_unlocked(
                wallet_path.to_path_buf(),
                ZeroizingSeed::new(seed),
                encrypted_on_disk,
                node_addr,
                network_label,
                csrf_token,
            )
        }
    }

    fn from_unlocked(
        wallet_path: PathBuf,
        seed: ZeroizingSeed,
        encrypted_on_disk: bool,
        node_addr: SocketAddr,
        network_label: String,
        csrf_token: String,
    ) -> io::Result<Self> {
        let sb = seed.as_bytes();
        let pocket_seed = domain_hash("XCR.WALLET.POCKET_KEY.V1", &[sb]).0;
        let pocket_kp = Keypair::from_seed(SignatureScheme::PasskeyP256, pocket_seed);
        let pocket_addr = pocket_kp.address();

        if let Ok(NodeRpcResponse::PocketInfo { found: false, .. }) = rpc_call(
            node_addr,
            &NodeRpcRequest::GetPocket {
                address: pocket_addr,
            },
            LIVE_RPC_TIMEOUT,
        ) {
            let _ = rpc_call(
                node_addr,
                &NodeRpcRequest::RegisterPocket {
                    address: pocket_addr,
                    public_key: pocket_kp.public_key(),
                    grant_from_miner: Amount::from_credits(20).unwrap(),
                    daily_limit: Amount::from_credits(25).unwrap(),
                },
                LIVE_RPC_TIMEOUT,
            );
        }

        let stealth_seed = domain_hash("XCR.WALLET.STEALTH_KEY.V1", &[sb]).0;
        let stealth_meta = StealthKeypair::from_seed(&stealth_seed).meta_address();
        let vault = VaultState::new(
            Amount::ZERO,
            86_400_000,
            2,
            domain_hash("XCR.GW.LIVE_VAULT.V1", &[sb]),
        );
        let mut clean_tree = AssociationTree::new(4);
        let clean_note = BlindedCommitment::commit(Amount::from_credits(25).unwrap(), sb);
        clean_tree.set_clean_leaf(0, clean_note);

        Ok(Self {
            wallet_path,
            unlocked_seed: Some(seed),
            encrypted_on_disk,
            pocket_addr,
            stealth_meta,
            node_addr,
            network_label,
            vault,
            clean_tree,
            clean_note,
            csrf_token,
            webhook_url: None,
            webhook_secret: String::new(),
        })
    }

    fn handle_unlock_or_encrypt(&mut self, password: &str) -> String {
        if password.is_empty() {
            return r#"{"ok":false,"error":"enter a non-empty passphrase"}"#.to_owned();
        }
        if let Some(ref current_seed) = self.unlocked_seed {
            // Encrypt wallet on disk with `XCRENC01`!
            let nanos = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos();
            let h = domain_hash("XCR.GW.ENC_SALT.V1", &[&nanos.to_le_bytes()]).0;
            let mut salt = [0u8; 16];
            salt.copy_from_slice(&h[..16]);
            match encrypt_wallet_seed(current_seed.as_bytes(), password, salt, 1) {
                Ok(sealed) => {
                    if let Err(e) = fs::write(&self.wallet_path, sealed) {
                        return format!(
                            r#"{{"ok":false,"error":"{}"}}"#,
                            json_escape(&e.to_string())
                        );
                    }
                    self.encrypted_on_disk = true;
                    r#"{"ok":true,"message":"✓ Wallet encrypted at rest with XCRENC01 memory-hard KDF"}"#
                        .to_owned()
                }
                Err(e) => format!(
                    r#"{{"ok":false,"error":"{}"}}"#,
                    json_escape(&e.to_string())
                ),
            }
        } else {
            let Ok(raw) = fs::read(&self.wallet_path) else {
                return r#"{"ok":false,"error":"wallet file missing"}"#.to_owned();
            };
            match open_wallet_bytes(&raw, Some(password)) {
                Ok(seed) => {
                    if let Ok(mut reloaded) = Self::from_unlocked(
                        self.wallet_path.clone(),
                        seed,
                        is_encrypted_wallet_bytes(&raw),
                        self.node_addr,
                        self.network_label.clone(),
                        self.csrf_token.clone(),
                    ) {
                        reloaded.webhook_url = self.webhook_url.clone();
                        reloaded.webhook_secret = self.webhook_secret.clone();
                        *self = reloaded;
                    }
                    r#"{"ok":true,"message":"✓ Wallet unlocked"}"#.to_owned()
                }
                Err(e) => format!(
                    r#"{{"ok":false,"error":"{}"}}"#,
                    json_escape(&e.to_string())
                ),
            }
        }
    }

    fn state_json(&self) -> String {
        let locked = self.unlocked_seed.is_none();
        let (epoch, supply, burned, root) =
            match rpc_call(self.node_addr, &NodeRpcRequest::GetStatus, LIVE_RPC_TIMEOUT) {
                Ok(NodeRpcResponse::Status {
                    epoch,
                    circulating_supply,
                    total_burned,
                    state_root,
                    ..
                }) => (epoch, circulating_supply, total_burned, state_root),
                _ => (EpochId(0), Amount::ZERO, Amount::ZERO, Hash32::ZERO),
            };

        let (balance, nonce, daily_limit) = if locked {
            (Amount::ZERO, 0, Amount::ZERO)
        } else {
            match rpc_call(
                self.node_addr,
                &NodeRpcRequest::GetPocket {
                    address: self.pocket_addr,
                },
                LIVE_RPC_TIMEOUT,
            ) {
                Ok(NodeRpcResponse::PocketInfo {
                    found: true,
                    balance,
                    nonce,
                    daily_limit,
                }) => (balance, nonce, daily_limit),
                _ => (Amount::ZERO, 0, Amount::from_credits(250).unwrap()),
            }
        };

        let mut pending_items = String::new();
        for (idx, w) in self.vault.pending.iter().enumerate() {
            if idx > 0 {
                pending_items.push(',');
            }
            pending_items.push_str(&format!(
                r#"{{"id":{},"amount":"{}"}}"#,
                w.id,
                w.amount.format_symbolic()
            ));
        }

        format!(
            r#"{{"locked":{},"encrypted_on_disk":{},"epoch":{},"phase":"{}","circulating_supply":"{}","total_burned":"{}","state_root":"{}","pocket_address":"{}","stealth_uri":"{}","pocket_balance":"{}","pocket_daily_spent":"{}","pocket_daily_limit":"{}","pocket_nonce":{},"vault_balance":"{}","vault_pending":[{}]}}"#,
            locked,
            self.encrypted_on_disk,
            epoch.0,
            json_escape(&self.network_label),
            supply.format_symbolic(),
            burned.format_symbolic(),
            root,
            if locked {
                String::from("locked")
            } else {
                self.pocket_addr.to_string()
            },
            if locked {
                String::from("unlock-wallet-to-view")
            } else {
                self.stealth_meta.to_uri()
            },
            balance.format_symbolic(),
            Amount::ZERO.format_symbolic(),
            daily_limit.format_symbolic(),
            nonce,
            self.vault.balance.format_symbolic(),
            pending_items
        )
    }

    fn history_json(&self) -> String {
        let Some(ref seed) = self.unlocked_seed else {
            return r#"{"entries":[]}"#.to_owned();
        };
        let log = EncryptedActivityLog::load(
            &self.wallet_path.with_extension("history"),
            seed.as_bytes(),
        );
        let items: Vec<String> = log
            .entries()
            .iter()
            .map(|e| {
                format!(
                    r#"{{"ts":{},"kind":"{}","amount":"{}","reference":"{}","memo":"{}"}}"#,
                    e.timestamp_unix,
                    json_escape(&e.kind),
                    e.amount.format_symbolic(),
                    json_escape(&e.reference),
                    json_escape(&e.memo)
                )
            })
            .collect();
        format!(r#"{{"entries":[{}]}}"#, items.join(","))
    }

    fn contacts_json(&self) -> String {
        let book = LocalHandleBook::load(&self.wallet_path.with_extension("aliases"));
        let items: Vec<String> = book
            .entries()
            .iter()
            .map(|(a, u)| {
                format!(
                    r#"{{"alias":"{}","uri":"{}"}}"#,
                    json_escape(a),
                    json_escape(u)
                )
            })
            .collect();
        format!(r#"{{"contacts":[{}]}}"#, items.join(","))
    }

    fn handle_add_contact(&self, alias: &str, uri: &str) -> String {
        let clean_alias = alias.trim().trim_start_matches('@');
        if clean_alias.is_empty() {
            return r#"{"saved":false,"error":"enter a contact name"}"#.to_owned();
        }
        let book_path = self.wallet_path.with_extension("aliases");
        let mut book = LocalHandleBook::load(&book_path);
        let resolved_uri = if StealthMetaAddress::from_uri(uri.trim()).is_some() {
            uri.trim().to_owned()
        } else {
            let (meta, _, _) = self.resolve_target(uri, uri);
            meta.to_uri()
        };
        if !book.upsert(clean_alias, &resolved_uri) {
            return r#"{"saved":false,"error":"invalid stealth destination"}"#.to_owned();
        }
        let _ = book.save(&book_path);
        format!(r#"{{"saved":true,"alias":"{}"}}"#, json_escape(clean_alias))
    }

    fn handle_light_verify(&self) -> String {
        if self.unlocked_seed.is_none() {
            return r#"{"verified":false,"proof_bytes":0,"root":"locked"}"#.to_owned();
        }
        match rpc_call(
            self.node_addr,
            &NodeRpcRequest::GetLightAccountProof {
                address: self.pocket_addr,
            },
            LIVE_RPC_TIMEOUT,
        ) {
            Ok(NodeRpcResponse::LightAccountProof {
                found: true,
                authenticated_root,
                balance,
                nonce,
                inclusion_proof_bytes,
            }) => {
                let verified =
                    StateInclusionProof::from_bytes(&inclusion_proof_bytes).is_some_and(|branch| {
                        branch.verify(
                            &StateLeaf {
                                address: self.pocket_addr,
                                balance,
                                nonce,
                            },
                            &authenticated_root,
                        )
                    });
                format!(
                    r#"{{"verified":{},"proof_bytes":{},"root":"{}"}}"#,
                    verified,
                    inclusion_proof_bytes.len(),
                    authenticated_root
                )
            }
            _ => r#"{"verified":false,"proof_bytes":0,"root":"unavailable"}"#.to_owned(),
        }
    }

    fn resolve_target(
        &self,
        raw: &str,
        invoice_fallback: &str,
    ) -> (StealthMetaAddress, Option<Amount>, Option<String>) {
        let trimmed = if raw.trim().is_empty() {
            invoice_fallback
        } else {
            raw.trim()
        };
        if let Some(meta) = StealthMetaAddress::from_uri(trimmed) {
            return (meta, None, None);
        }
        if let Some(req) = PaymentRequestUri::parse(trimmed) {
            let (meta, _, _) = self.resolve_target(&req.recipient, invoice_fallback);
            let m = match (req.invoice, req.memo) {
                (Some(i), Some(n)) => Some(format!("{i}: {n}")),
                (Some(i), None) => Some(i),
                (None, Some(n)) => Some(n),
                (None, None) => None,
            };
            return (meta, req.amount, m);
        }
        let book = LocalHandleBook::load(&self.wallet_path.with_extension("aliases"));
        if let Some(meta) = book.resolve(trimmed) {
            return (meta, None, None);
        }
        if ((trimmed.contains('@') && !trimmed.starts_with('@')) || trimmed.starts_with('$'))
            && let Ok(meta) = resolve_remote_handle(trimmed, Duration::from_millis(2_500))
        {
            return (meta, None, None);
        }
        let s = domain_hash("XCR.CLI.RECIPIENT.V1", &[trimmed.as_bytes()]).0;
        (StealthKeypair::from_seed(&s).meta_address(), None, None)
    }

    fn handle_pay(
        &self,
        base_amount: Amount,
        invoice: &str,
        recipient: &str,
        regulated: bool,
    ) -> String {
        let Some(ref seed_guard) = self.unlocked_seed else {
            return r#"{"accepted":false,"error":"wallet is locked — enter passphrase first"}"#
                .to_owned();
        };
        let master_seed = seed_guard.as_bytes();
        if base_amount.is_zero() {
            return r#"{"accepted":false,"error":"invalid XCR amount"}"#.to_owned();
        }
        let fee = Amount::from_bits(500);

        let pocket_seed = domain_hash("XCR.WALLET.POCKET_KEY.V1", &[master_seed]).0;
        let mut kp = Keypair::from_seed(SignatureScheme::PasskeyP256, pocket_seed);

        let Ok(NodeRpcResponse::PocketInfo {
            found: true, nonce, ..
        }) = rpc_call(
            self.node_addr,
            &NodeRpcRequest::GetPocket {
                address: self.pocket_addr,
            },
            LIVE_RPC_TIMEOUT,
        )
        else {
            return r#"{"accepted":false,"error":"wallet Pocket not found on target node"}"#
                .to_owned();
        };

        let (target_meta, uri_amt, uri_memo) = self.resolve_target(recipient, invoice);
        let amount = uri_amt.filter(|a| !a.is_zero()).unwrap_or(base_amount);
        let effective_memo = if !invoice.trim().is_empty() {
            invoice.trim().to_owned()
        } else {
            uri_memo.unwrap_or_default()
        };

        let eph_seed = domain_hash(
            "XCR.CLI.EPH.V1",
            &[
                master_seed,
                &nonce.to_le_bytes(),
                recipient.as_bytes(),
                effective_memo.as_bytes(),
            ],
        )
        .0;
        let (stealth_out, shared_secret) = derive_stealth_output(&target_meta, &eph_seed);

        let gamma = Scalar::hash_from_parts(
            "XCR.CLI.BP_GAMMA.V1",
            &[&shared_secret, &nonce.to_le_bytes()],
        );
        let bp_seed = domain_hash(
            "XCR.CLI.BP_SEED.V1",
            &[&shared_secret, &nonce.to_le_bytes()],
        )
        .0;
        let Some((v_commit, bp_proof)) = BulletproofRange64::prove(amount, gamma, 64, &bp_seed)
        else {
            return r#"{"accepted":false,"error":"Bulletproof prove failed"}"#.to_owned();
        };
        let bp_bytes = bp_proof.to_bytes();

        let (innocence_nullifier, zk_verified) = if regulated {
            let root = self.clean_tree.root();
            let path = self.clean_tree.inclusion_path(0).unwrap();
            let ctx = format!("{effective_memo}:{nonce}");
            if let Some(poi) =
                ProofOfInnocence::generate(master_seed, self.clean_note, path, root, ctx.as_bytes())
            {
                let ok = poi.verify(&root, ctx.as_bytes());
                (Some(poi.nullifier), ok)
            } else {
                (None, false)
            }
        } else {
            (None, false)
        };

        let commitment_hash = domain_hash("XCR.CLI.COMMIT_TAG.V1", &[&v_commit.to_bytes()]);
        let kind = TransactionKind::FastTransfer {
            from: self.pocket_addr,
            to_stealth: stealth_out.one_time_address,
            stealth_view_tag: stealth_out.view_tag,
            amount,
            fee,
            nonce,
            commitment: commitment_hash,
            innocence_nullifier,
        };
        let tx_id = tx_signing_digest(&kind);
        let sig_bytes = kp.sign(tx_id.as_bytes()).to_bytes();

        let req = NodeRpcRequest::SubmitBulletproofFastPay {
            tx: Transaction {
                id: tx_id,
                kind,
                signature_bytes: sig_bytes,
            },
            value_commitment: v_commit.to_bytes(),
            bulletproof_672: bp_bytes.clone(),
        };

        match rpc_call(self.node_addr, &req, LIVE_RPC_TIMEOUT) {
            Ok(NodeRpcResponse::FastPayReceipt {
                accepted: true,
                tx_id,
                finality_latency_ms,
                fee_worker,
                fee_burned,
                new_state_root,
                ..
            }) => {
                let encrypted_memo = encrypt_stealth_memo(&shared_secret, &effective_memo);
                let _ = rpc_call(
                    self.node_addr,
                    &NodeRpcRequest::AnnounceStealthOutputV2 {
                        one_time_address: stealth_out.one_time_address,
                        ephemeral_pub: stealth_out.ephemeral_pub,
                        view_tag: stealth_out.view_tag,
                        encrypted_memo,
                    },
                    Duration::from_millis(2_500),
                );
                EncryptedActivityLog::append_and_persist(
                    &self.wallet_path.with_extension("history"),
                    master_seed,
                    "sent",
                    amount,
                    tx_id.to_hex(),
                    &effective_memo,
                );
                let fs = FeeSplit::compute(fee);
                format!(
                    r#"{{"accepted":true,"tx_id":"{}","latency_ms":{},"bulletproof_bytes":{},"fee_worker":"{}","fee_endurance":"{}","fee_burned":"{}","zk_verified":{},"decrypted_invoice":"{}","state_root":"{}"}}"#,
                    tx_id,
                    finality_latency_ms,
                    bp_bytes.len(),
                    fee_worker,
                    fs.endurance_deposit,
                    fee_burned,
                    zk_verified,
                    json_escape(&effective_memo),
                    new_state_root
                )
            }
            Ok(NodeRpcResponse::FastPayReceipt {
                accepted: false,
                message,
                ..
            }) => format!(
                r#"{{"accepted":false,"error":"{}"}}"#,
                json_escape(&message)
            ),
            Ok(other) => format!(
                r#"{{"accepted":false,"error":"{}"}}"#,
                json_escape(&format!("{other:?}"))
            ),
            Err(e) => format!(
                r#"{{"accepted":false,"error":"RPC error: {}"}}"#,
                json_escape(&e.to_string())
            ),
        }
    }

    fn handle_scan_stealth(&self) -> String {
        let Some(ref seed_guard) = self.unlocked_seed else {
            return r#"{"scanned":0,"claimed":0,"amount":"∀ 0.000000 XCR","memos":[]}"#.to_owned();
        };
        let master_seed = seed_guard.as_bytes();
        let pocket_seed = domain_hash("XCR.WALLET.POCKET_KEY.V1", &[master_seed]).0;
        let pocket_kp = Keypair::from_seed(SignatureScheme::PasskeyP256, pocket_seed);
        let stealth_seed = domain_hash("XCR.WALLET.STEALTH_KEY.V1", &[master_seed]).0;
        let stealth_kp = StealthKeypair::from_seed(&stealth_seed);

        let outputs: Vec<StealthOutputRecordV2> = match rpc_call(
            self.node_addr,
            &NodeRpcRequest::GetStealthOutputsV2,
            Duration::from_millis(2_500),
        ) {
            Ok(NodeRpcResponse::StealthOutputsV2 { outputs }) => outputs,
            _ => match rpc_call(
                self.node_addr,
                &NodeRpcRequest::GetStealthOutputs,
                LIVE_RPC_TIMEOUT,
            ) {
                Ok(NodeRpcResponse::StealthOutputs { outputs }) => outputs
                    .into_iter()
                    .map(|(a, amt, eph, vt)| (a, amt, eph, vt, Vec::new()))
                    .collect(),
                _ => {
                    return r#"{"scanned":0,"claimed":0,"amount":"∀ 0.000000 XCR","memos":[]}"#
                        .to_owned();
                }
            },
        };

        let scanned = outputs.len();
        let mut claimed_count = 0usize;
        let mut claimed_sum = Amount::ZERO;
        let mut memos_json = Vec::new();
        for (one_time_address, _, ephemeral_pub, view_tag, enc_memo) in outputs {
            let cand = StealthOutput {
                ephemeral_pub,
                view_tag,
                one_time_address,
            };
            if let Some(kdf) = stealth_kp.scan_and_open(&cand) {
                let dec_memo = decrypt_stealth_memo(&kdf, &enc_memo);
                let sig64 = stealth_kp.sign_claim(&one_time_address, &self.pocket_addr);
                if let Ok(NodeRpcResponse::StealthClaimReceipt {
                    accepted: true,
                    claimed_amount,
                    ..
                }) = rpc_call(
                    self.node_addr,
                    &NodeRpcRequest::ClaimStealthUtxo {
                        one_time_address,
                        claimant_pocket: self.pocket_addr,
                        claimant_pubkey: pocket_kp.public_key(),
                        spend_pub: stealth_kp.meta_address().spend_pub,
                        kdf,
                        schnorr_sig64: sig64,
                    },
                    LIVE_RPC_TIMEOUT,
                ) {
                    claimed_count += 1;
                    claimed_sum = claimed_sum.saturating_add(claimed_amount);
                    EncryptedActivityLog::append_and_persist(
                        &self.wallet_path.with_extension("history"),
                        master_seed,
                        "received",
                        claimed_amount,
                        one_time_address.short_hex(),
                        dec_memo.as_deref().unwrap_or(""),
                    );
                    if let Some(ref wh_url) = self.webhook_url {
                        let u = wh_url.clone();
                        let sec = self.webhook_secret.clone();
                        let ot_s = one_time_address.short_hex();
                        let m_s = dec_memo.clone().unwrap_or_default();
                        std::thread::spawn(move || {
                            let _ = dispatch_signed_webhook(&u, &sec, claimed_amount, &ot_s, &m_s);
                        });
                    }
                    if let Some(m) = dec_memo {
                        memos_json.push(format!("\"{}\"", json_escape(&m)));
                    }
                }
            }
        }
        format!(
            r#"{{"scanned":{},"claimed":{},"amount":"{}","memos":[{}]}}"#,
            scanned,
            claimed_count,
            claimed_sum.format_symbolic(),
            memos_json.join(",")
        )
    }

    fn handle_voucher_create(&self, amount: Amount, memo: &str) -> String {
        let Some(ref seed_guard) = self.unlocked_seed else {
            return r#"{"accepted":false,"error":"wallet is locked"}"#.to_owned();
        };
        let master_seed = seed_guard.as_bytes();
        if amount.is_zero() {
            return r#"{"accepted":false,"error":"invalid XCR amount"}"#.to_owned();
        }
        let fee = Amount::from_bits(500);
        let pocket_seed = domain_hash("XCR.WALLET.POCKET_KEY.V1", &[master_seed]).0;
        let mut kp = Keypair::from_seed(SignatureScheme::PasskeyP256, pocket_seed);

        let Ok(NodeRpcResponse::PocketInfo {
            found: true, nonce, ..
        }) = rpc_call(
            self.node_addr,
            &NodeRpcRequest::GetPocket {
                address: self.pocket_addr,
            },
            LIVE_RPC_TIMEOUT,
        )
        else {
            return r#"{"accepted":false,"error":"Pocket not registered"}"#.to_owned();
        };

        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let secret = domain_hash(
            "XCR.GW.VOUCHER_SK.V1",
            &[master_seed, &nonce.to_le_bytes(), &nanos.to_le_bytes()],
        )
        .0;
        let voucher = BearerVoucher::new(
            secret,
            Some(amount),
            if memo.trim().is_empty() {
                None
            } else {
                Some(memo.trim().to_owned())
            },
        );
        let (stealth_out, kdf, _, _) = voucher.derive_claim_material();

        let gamma =
            Scalar::hash_from_parts("XCR.CLI.VOUCHER_GAMMA.V1", &[&kdf, &nonce.to_le_bytes()]);
        let bp_seed = domain_hash("XCR.CLI.VOUCHER_BP.V1", &[&kdf, &nonce.to_le_bytes()]).0;
        let Some((v_commit, bp_proof)) = BulletproofRange64::prove(amount, gamma, 64, &bp_seed)
        else {
            return r#"{"accepted":false,"error":"Bulletproof prove failed"}"#.to_owned();
        };
        let commitment_hash = domain_hash("XCR.CLI.COMMIT_TAG.V1", &[&v_commit.to_bytes()]);
        let kind = TransactionKind::FastTransfer {
            from: self.pocket_addr,
            to_stealth: stealth_out.one_time_address,
            stealth_view_tag: stealth_out.view_tag,
            amount,
            fee,
            nonce,
            commitment: commitment_hash,
            innocence_nullifier: None,
        };
        let tx_id = tx_signing_digest(&kind);
        let sig_bytes = kp.sign(tx_id.as_bytes()).to_bytes();

        match rpc_call(
            self.node_addr,
            &NodeRpcRequest::SubmitBulletproofFastPay {
                tx: Transaction {
                    id: tx_id,
                    kind,
                    signature_bytes: sig_bytes,
                },
                value_commitment: v_commit.to_bytes(),
                bulletproof_672: bp_proof.to_bytes(),
            },
            LIVE_RPC_TIMEOUT,
        ) {
            Ok(NodeRpcResponse::FastPayReceipt {
                accepted: true,
                tx_id,
                finality_latency_ms,
                ..
            }) => {
                let uri = voucher.to_uri();
                let encrypted_memo = encrypt_stealth_memo(&kdf, memo);
                let _ = rpc_call(
                    self.node_addr,
                    &NodeRpcRequest::AnnounceStealthOutputV2 {
                        one_time_address: stealth_out.one_time_address,
                        ephemeral_pub: stealth_out.ephemeral_pub,
                        view_tag: stealth_out.view_tag,
                        encrypted_memo,
                    },
                    Duration::from_millis(2_500),
                );
                EncryptedActivityLog::append_and_persist(
                    &self.wallet_path.with_extension("history"),
                    master_seed,
                    "voucher_out",
                    amount,
                    &uri,
                    memo,
                );
                format!(
                    r#"{{"accepted":true,"uri":"{}","tx_id":"{}","latency_ms":{}}}"#,
                    json_escape(&uri),
                    tx_id,
                    finality_latency_ms
                )
            }
            Ok(NodeRpcResponse::FastPayReceipt { message, .. }) => {
                format!(
                    r#"{{"accepted":false,"error":"{}"}}"#,
                    json_escape(&message)
                )
            }
            _ => r#"{"accepted":false,"error":"voucher RPC failed"}"#.to_owned(),
        }
    }

    fn handle_voucher_claim(&self, uri: &str) -> String {
        let Some(ref seed_guard) = self.unlocked_seed else {
            return r#"{"accepted":false,"error":"wallet is locked"}"#.to_owned();
        };
        let master_seed = seed_guard.as_bytes();
        let Some(voucher) = BearerVoucher::parse(uri) else {
            return r#"{"accepted":false,"error":"invalid xcr://claim# voucher URI"}"#.to_owned();
        };
        let pocket_seed = domain_hash("XCR.WALLET.POCKET_KEY.V1", &[master_seed]).0;
        let pocket_kp = Keypair::from_seed(SignatureScheme::PasskeyP256, pocket_seed);
        let (one_time_address, spend_pub, kdf, schnorr_sig64) =
            voucher.sign_claim_for(&self.pocket_addr);

        match rpc_call(
            self.node_addr,
            &NodeRpcRequest::ClaimStealthUtxo {
                one_time_address,
                claimant_pocket: self.pocket_addr,
                claimant_pubkey: pocket_kp.public_key(),
                spend_pub,
                kdf,
                schnorr_sig64,
            },
            LIVE_RPC_TIMEOUT,
        ) {
            Ok(NodeRpcResponse::StealthClaimReceipt {
                accepted: true,
                claimed_amount,
                ..
            }) => {
                EncryptedActivityLog::append_and_persist(
                    &self.wallet_path.with_extension("history"),
                    master_seed,
                    "voucher_in",
                    claimed_amount,
                    one_time_address.short_hex(),
                    voucher.memo.as_deref().unwrap_or(""),
                );
                format!(
                    r#"{{"accepted":true,"amount":"{}"}}"#,
                    claimed_amount.format_symbolic()
                )
            }
            Ok(NodeRpcResponse::StealthClaimReceipt { message, .. }) => {
                format!(
                    r#"{{"accepted":false,"error":"{}"}}"#,
                    json_escape(&message)
                )
            }
            _ => r#"{"accepted":false,"error":"claim RPC failed"}"#.to_owned(),
        }
    }

    fn handle_recover(&mut self, phrase: &str) -> String {
        let seed = match decode_mnemonic_24(phrase) {
            Ok(s) => s,
            Err(e) => {
                return format!(
                    r#"{{"recovered":false,"error":"{}"}}"#,
                    json_escape(&e.to_string())
                );
            }
        };
        if let Err(e) = write_plain_seed_file(&self.wallet_path, &seed) {
            return format!(
                r#"{{"recovered":false,"error":"{}"}}"#,
                json_escape(&e.to_string())
            );
        }
        if let Ok(mut reloaded) = Self::from_unlocked(
            self.wallet_path.clone(),
            ZeroizingSeed::new(seed),
            false,
            self.node_addr,
            self.network_label.clone(),
            self.csrf_token.clone(),
        ) {
            reloaded.webhook_url = self.webhook_url.clone();
            reloaded.webhook_secret = self.webhook_secret.clone();
            *self = reloaded;
        }
        format!(
            r#"{{"recovered":true,"pocket_address":"{}"}}"#,
            self.pocket_addr
        )
    }

    fn handle_shamir_split(&self, k: u8, n: u8) -> String {
        let Some(ref seed) = self.unlocked_seed else {
            return r#"{"ok":false,"error":"unlock wallet first"}"#.to_owned();
        };
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let ent = domain_hash("XCR.GW.SHAMIR.V1", &[&nanos.to_le_bytes()]).0;
        match split_secret_shamir(seed.as_bytes(), k, n, &ent) {
            Ok(shares) => {
                let items: Vec<String> = shares
                    .iter()
                    .map(|s| format!("\"{}\"", json_escape(&s.to_uri())))
                    .collect();
                format!(r#"{{"ok":true,"shares":[{}]}}"#, items.join(","))
            }
            Err(e) => format!(
                r#"{{"ok":false,"error":"{}"}}"#,
                json_escape(&e.to_string())
            ),
        }
    }

    fn handle_shamir_combine(&mut self, raw_list: &str) -> String {
        let mut parsed = Vec::new();
        for tok in raw_list
            .split(|c: char| c == ',' || c.is_whitespace())
            .filter(|t| !t.is_empty())
        {
            match ShamirShare::from_uri(tok) {
                Ok(s) => parsed.push(s),
                Err(e) => {
                    return format!(
                        r#"{{"ok":false,"error":"{}"}}"#,
                        json_escape(&e.to_string())
                    );
                }
            }
        }
        match combine_secret_shamir(&parsed) {
            Ok(seed) => {
                let _ = write_plain_seed_file(&self.wallet_path, seed.as_bytes());
                if let Ok(mut reloaded) = Self::from_unlocked(
                    self.wallet_path.clone(),
                    seed,
                    false,
                    self.node_addr,
                    self.network_label.clone(),
                    self.csrf_token.clone(),
                ) {
                    reloaded.webhook_url = self.webhook_url.clone();
                    reloaded.webhook_secret = self.webhook_secret.clone();
                    *self = reloaded;
                }
                format!(r#"{{"ok":true,"pocket_address":"{}"}}"#, self.pocket_addr)
            }
            Err(e) => format!(
                r#"{{"ok":false,"error":"{}"}}"#,
                json_escape(&e.to_string())
            ),
        }
    }

    fn handle_cold_sign(&self, unsigned_uri: &str) -> String {
        let Some(ref seed) = self.unlocked_seed else {
            return r#"{"ok":false,"error":"unlock wallet first"}"#.to_owned();
        };
        let Some(u) = UnsignedColdTransfer::from_uri(unsigned_uri) else {
            return r#"{"ok":false,"error":"invalid xcrunsigned1_ URI"}"#.to_owned();
        };
        match u.sign_offline(seed.as_bytes()) {
            Ok(signed) => format!(
                r#"{{"ok":true,"amount":"{}","nonce":{},"signed_uri":"{}"}}"#,
                u.amount.format_symbolic(),
                u.nonce,
                signed.to_uri()
            ),
            Err(e) => format!(r#"{{"ok":false,"error":"{}"}}"#, json_escape(e)),
        }
    }

    fn subs_json(&self) -> String {
        let Some(ref seed) = self.unlocked_seed else {
            return r#"{"mandates":[]}"#.to_owned();
        };
        let book =
            SubscriptionBook::load(&self.wallet_path.with_extension("subs"), seed.as_bytes());
        let items: Vec<String> = book
            .mandates()
            .iter()
            .map(|m| {
                format!(
                    r#"{{"id":{},"label":"{}","recipient":"{}","amount":"{}","interval_secs":{},"cycles":{},"active":{}}}"#,
                    m.id,
                    json_escape(&m.label),
                    json_escape(&m.recipient),
                    m.amount.format_symbolic(),
                    m.interval_secs,
                    m.completed_cycles,
                    m.active
                )
            })
            .collect();
        format!(r#"{{"mandates":[{}]}}"#, items.join(","))
    }

    fn handle_sub_add(&self, label: &str, to: &str, amount: Amount, interval_secs: u64) -> String {
        let Some(ref seed) = self.unlocked_seed else {
            return r#"{"ok":false,"error":"wallet locked"}"#.to_owned();
        };
        if amount.is_zero() || label.trim().is_empty() || to.trim().is_empty() {
            return r#"{"ok":false,"error":"invalid subscription parameters"}"#.to_owned();
        }
        let now_unix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let sub_path = self.wallet_path.with_extension("subs");
        let mut book = SubscriptionBook::load(&sub_path, seed.as_bytes());
        let id = book.add_mandate(label.trim(), to.trim(), amount, interval_secs, now_unix);
        let _ = book.save(&sub_path, seed.as_bytes());
        format!(r#"{{"ok":true,"id":{id}}}"#)
    }

    fn handle_sub_cancel(&self, id: u64) -> String {
        let Some(ref seed) = self.unlocked_seed else {
            return r#"{"ok":false}"#.to_owned();
        };
        let sub_path = self.wallet_path.with_extension("subs");
        let mut book = SubscriptionBook::load(&sub_path, seed.as_bytes());
        let ok = book.cancel(id);
        if ok {
            let _ = book.save(&sub_path, seed.as_bytes());
        }
        format!(r#"{{"ok":{ok}}}"#)
    }

    fn handle_sub_run(&self) -> String {
        let Some(ref seed) = self.unlocked_seed else {
            return r#"{"paid":0}"#.to_owned();
        };
        let now_unix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let sub_path = self.wallet_path.with_extension("subs");
        let mut book = SubscriptionBook::load(&sub_path, seed.as_bytes());
        let mut paid_count = 0usize;
        for m in book.due_mandates(now_unix) {
            let memo = format!("SUB#{}: {}", m.id, m.label);
            let res = self.handle_pay(m.amount, &memo, &m.recipient, false);
            if res.contains(r#""accepted":true"#) {
                book.mark_cycle_paid(m.id, now_unix);
                paid_count += 1;
            }
        }
        if paid_count > 0 {
            let _ = book.save(&sub_path, seed.as_bytes());
        }
        format!(r#"{{"paid":{paid_count}}}"#)
    }

    fn handle_pay_multi(&self, batch_raw: &str) -> String {
        let mut count = 0usize;
        for leg in batch_raw
            .split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
        {
            let mut parts = leg.splitn(3, ':');
            let dest = parts.next().unwrap_or("").trim();
            let amt_s = parts.next().unwrap_or("").trim();
            let note = parts.next().unwrap_or("Batch");
            let Some(amt) = parse_decimal_xcr(amt_s).filter(|a| !a.is_zero()) else {
                return format!(
                    r#"{{"ok":false,"error":"invalid leg {}"}}"#,
                    json_escape(leg)
                );
            };
            let res = self.handle_pay(amt, note, dest, false);
            if !res.contains(r#""accepted":true"#) {
                return res;
            }
            count += 1;
        }
        format!(r#"{{"ok":true,"settled":{count}}}"#)
    }

    fn checkout_status_json(&self, inv: &str) -> String {
        let _ = self.handle_scan_stealth();
        let Some(ref seed) = self.unlocked_seed else {
            return r#"{"paid":false}"#.to_owned();
        };
        let log = EncryptedActivityLog::load(
            &self.wallet_path.with_extension("history"),
            seed.as_bytes(),
        );
        if !inv.is_empty()
            && let Some(hit) = log
                .entries()
                .iter()
                .rev()
                .find(|e| e.kind == "received" && e.memo.contains(inv))
        {
            return format!(
                r#"{{"paid":true,"amount":"{}","memo":"{}"}}"#,
                hit.amount.format_symbolic(),
                json_escape(&hit.memo)
            );
        }
        r#"{"paid":false}"#.to_owned()
    }

    fn resolve_pocket_target(&self, s: &str) -> Option<Address> {
        let t = s.trim();
        if t.len() == 64
            && let Some(raw) = decode_hex32_gw(t)
        {
            return Some(Address::from_bytes(raw));
        }
        if let Ok(NodeRpcResponse::InspectResult {
            kind: 1, address, ..
        }) = rpc_call(
            self.node_addr,
            &NodeRpcRequest::InspectQuery {
                query: t.to_owned(),
            },
            LIVE_RPC_TIMEOUT,
        ) {
            return Some(address);
        }
        None
    }

    fn handle_frost_split(&self, k: u8, n: u8) -> String {
        let Some(ref seed) = self.unlocked_seed else {
            return r#"{"ok":false,"error":"Unlock wallet first"}"#.to_owned();
        };
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let ent = domain_hash("XCR.GW.FROST.V1", &[&nanos.to_le_bytes()]).0;
        match frost_split_pocket_key(seed.as_bytes(), k, n, &ent) {
            Ok(shares) => {
                let items: Vec<String> = shares
                    .iter()
                    .map(|sh| format!("\"{}\"", sh.to_uri()))
                    .collect();
                format!(r#"{{"ok":true,"shares":[{}]}}"#, items.join(","))
            }
            Err(e) => format!(
                r#"{{"ok":false,"error":"{}"}}"#,
                json_escape(&e.to_string())
            ),
        }
    }

    fn handle_htlc_lock_and_offer(
        &self,
        to_str: &str,
        amount: Amount,
        asset: &str,
        counter_amt: &str,
    ) -> String {
        let Some(ref seed) = self.unlocked_seed else {
            return r#"{"ok":false,"error":"Unlock wallet first"}"#.to_owned();
        };
        let recipient = self
            .resolve_pocket_target(to_str)
            .unwrap_or(self.pocket_addr);
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let ent = domain_hash("XCR.GW.HTLC.V1", &[&nanos.to_le_bytes()]).0;
        let (preimage, hashlock) = generate_htlc_secret(&ent);
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let exp = now.saturating_add(3_600);
        let mut salt = [0u8; 16];
        salt.copy_from_slice(&ent[..16]);
        let fee = Amount::from_bits(MIN_BASE_FEE_BITS);
        let (sender, sender_pubkey, escrow_id, sig65) = sign_htlc_lock(
            seed.as_bytes(),
            &recipient,
            amount,
            fee,
            &hashlock,
            exp,
            salt,
        );
        if let Ok(offer) = AtomicSwapOffer::sign_new(
            seed.as_bytes(),
            amount,
            asset,
            counter_amt,
            hashlock,
            3_600,
            exp,
        ) {
            let _ = rpc_call(
                self.node_addr,
                &NodeRpcRequest::PostSwapOffer {
                    offer_bytes: offer.to_bytes(),
                },
                LIVE_RPC_TIMEOUT,
            );
        }
        match rpc_call(
            self.node_addr,
            &NodeRpcRequest::LockHtlc {
                escrow_id,
                sender,
                sender_pubkey,
                recipient,
                amount,
                fee,
                hashlock,
                expiry_unix: exp,
                salt,
                sig65,
            },
            LIVE_RPC_TIMEOUT,
        ) {
            Ok(NodeRpcResponse::ContractReceipt { accepted: true, .. }) => format!(
                r#"{{"ok":true,"escrow_id":"{}","preimage":"{}","hashlock":"{}"}}"#,
                escrow_id,
                Hash32(preimage),
                hashlock
            ),
            Ok(NodeRpcResponse::ContractReceipt { message, .. }) => {
                format!(r#"{{"ok":false,"error":"{}"}}"#, json_escape(&message))
            }
            _ => r#"{"ok":false,"error":"HTLC RPC failed"}"#.to_owned(),
        }
    }

    fn handle_paychan_open(&self, payee_str: &str, deposit: Amount) -> String {
        let Some(ref seed) = self.unlocked_seed else {
            return r#"{"ok":false,"error":"Unlock wallet first"}"#.to_owned();
        };
        let payee = self
            .resolve_pocket_target(payee_str)
            .unwrap_or(self.pocket_addr);
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let ent = domain_hash("XCR.GW.CHAN.V1", &[&nanos.to_le_bytes()]).0;
        let mut salt = [0u8; 16];
        salt.copy_from_slice(&ent[..16]);
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let fee = Amount::from_bits(MIN_BASE_FEE_BITS);
        let (payer, payer_pubkey, channel_id, sig65) = sign_paychan_open(
            seed.as_bytes(),
            &payee,
            deposit,
            fee,
            now.saturating_add(3_600),
            salt,
        );
        match rpc_call(
            self.node_addr,
            &NodeRpcRequest::OpenPayChannel {
                channel_id,
                payer,
                payer_pubkey,
                payee,
                deposit,
                fee,
                expiry_unix: now.saturating_add(3_600),
                salt,
                sig65,
            },
            LIVE_RPC_TIMEOUT,
        ) {
            Ok(NodeRpcResponse::ContractReceipt { accepted: true, .. }) => {
                format!(r#"{{"ok":true,"channel_id":"{}"}}"#, channel_id)
            }
            Ok(NodeRpcResponse::ContractReceipt { message, .. }) => {
                format!(r#"{{"ok":false,"error":"{}"}}"#, json_escape(&message))
            }
            _ => r#"{"ok":false,"error":"PayChan open RPC failed"}"#.to_owned(),
        }
    }

    fn handle_paychan_tick(&self, cid_hex: &str, cumulative: Amount) -> String {
        let Some(ref seed) = self.unlocked_seed else {
            return r#"{"ok":false,"error":"Unlock wallet first"}"#.to_owned();
        };
        let Some(raw) = decode_hex32_gw(cid_hex.trim()) else {
            return r#"{"ok":false,"error":"Invalid 64-hex channel_id"}"#.to_owned();
        };
        let v = PayChanVoucher::sign_tick(seed.as_bytes(), Hash32::from_bytes(raw), cumulative);
        format!(r#"{{"ok":true,"voucher":"{}"}}"#, v.to_uri())
    }

    fn handle_paychan_close(&self, voucher_uri: &str) -> String {
        let Some(v) = PayChanVoucher::from_uri(voucher_uri) else {
            return r#"{"ok":false,"error":"Invalid xcrchan1_ voucher"}"#.to_owned();
        };
        match rpc_call(
            self.node_addr,
            &NodeRpcRequest::ClosePayChannel {
                channel_id: v.channel_id,
                cumulative_amount: v.cumulative_amount,
                voucher_sig65: v.signature_65,
            },
            LIVE_RPC_TIMEOUT,
        ) {
            Ok(NodeRpcResponse::ContractReceipt {
                accepted, message, ..
            }) => format!(
                r#"{{"ok":{accepted},"message":"{}"}}"#,
                json_escape(&message)
            ),
            _ => r#"{"ok":false,"message":"PayChan close failed"}"#.to_owned(),
        }
    }

    fn handle_check_issue(&self, payee_str: &str, max_amount: Amount) -> String {
        let Some(ref seed) = self.unlocked_seed else {
            return r#"{"ok":false,"error":"Unlock wallet first"}"#.to_owned();
        };
        let payee = self
            .resolve_pocket_target(payee_str)
            .unwrap_or(self.pocket_addr);
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let ent = domain_hash("XCR.GW.CHK.V1", &[&nanos.to_le_bytes()]).0;
        let mut salt = [0u8; 16];
        salt.copy_from_slice(&ent[..16]);
        let exp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
            .saturating_add(86_400);
        match DigitalCheck::issue(seed.as_bytes(), payee, max_amount, exp, salt) {
            Ok(chk) => format!(
                r#"{{"ok":true,"check_id":"{}","uri":"{}"}}"#,
                chk.check_id,
                chk.to_uri()
            ),
            Err(e) => format!(r#"{{"ok":false,"error":"{}"}}"#, json_escape(e)),
        }
    }

    fn handle_check_cash_or_cancel(&self, uri: &str, actual: Amount, cancel: bool) -> String {
        let Some(ref seed) = self.unlocked_seed else {
            return r#"{"ok":false,"error":"Unlock wallet first"}"#.to_owned();
        };
        let Some(chk) = DigitalCheck::from_uri(uri) else {
            return r#"{"ok":false,"error":"Invalid xcrcheck1_ URI"}"#.to_owned();
        };
        let (actor_pubkey, actor_sig65, send_amt) = if cancel {
            let (_, pk, sig) = sign_check_cancel(seed.as_bytes(), &chk.check_id);
            (pk, sig, Amount::ZERO)
        } else {
            match sign_check_cash(seed.as_bytes(), &chk, actual) {
                Ok((pk, sig)) => (pk, sig, actual),
                Err(e) => return format!(r#"{{"ok":false,"error":"{}"}}"#, json_escape(e)),
            }
        };
        match rpc_call(
            self.node_addr,
            &NodeRpcRequest::CashOrCancelCheck {
                is_cancel: cancel,
                check_bytes: chk.to_bytes().to_vec(),
                check_id: chk.check_id,
                actor_pubkey,
                actual_amount: send_amt,
                actor_sig65,
            },
            LIVE_RPC_TIMEOUT,
        ) {
            Ok(NodeRpcResponse::ContractReceipt {
                accepted, message, ..
            }) => format!(
                r#"{{"ok":{accepted},"message":"{}"}}"#,
                json_escape(&message)
            ),
            _ => r#"{"ok":false,"error":"Check RPC failed"}"#.to_owned(),
        }
    }

    fn handle_session_issue(&self, max_spend: Amount) -> String {
        let Some(ref seed) = self.unlocked_seed else {
            return r#"{"ok":false,"error":"Unlock wallet first"}"#.to_owned();
        };
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let ent = domain_hash("XCR.GW.SESS.V1", &[&nanos.to_le_bytes()]).0;
        let exp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
            .saturating_add(7_200);
        match SessionKeyGrant::issue(seed.as_bytes(), max_spend, None, exp, ent) {
            Ok(g) => format!(
                r#"{{"ok":true,"session_id":"{}","uri":"{}"}}"#,
                g.session_id,
                g.to_uri()
            ),
            Err(e) => format!(r#"{{"ok":false,"error":"{}"}}"#, json_escape(e)),
        }
    }

    fn handle_asset_mint(&self, ticker: &str, supply: u64) -> String {
        let Some(ref seed) = self.unlocked_seed else {
            return r#"{"ok":false,"error":"Unlock wallet first"}"#.to_owned();
        };
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let ent = domain_hash("XCR.GW.ASSET.V1", &[&nanos.to_le_bytes()]).0;
        let mut salt = [0u8; 16];
        salt.copy_from_slice(&ent[..16]);
        let fee = Amount::from_bits(MIN_BASE_FEE_BITS);
        let Ok(mint) = NativeAssetMint::sign_new(seed.as_bytes(), ticker, supply, 0, fee, salt)
        else {
            return r#"{"ok":false,"error":"Invalid ticker or supply"}"#.to_owned();
        };
        match rpc_call(
            self.node_addr,
            &NodeRpcRequest::MintNativeAsset {
                asset_id: mint.asset_id,
                issuer: mint.issuer,
                issuer_pubkey: mint.issuer_pubkey,
                ticker: mint.ticker,
                total_supply: mint.total_supply,
                decimals: mint.decimals,
                fee: mint.fee,
                salt: mint.salt,
                sig65: mint.sig65,
            },
            LIVE_RPC_TIMEOUT,
        ) {
            Ok(NodeRpcResponse::ContractReceipt { accepted: true, .. }) => {
                format!(r#"{{"ok":true,"asset_id":"{}"}}"#, mint.asset_id)
            }
            Ok(NodeRpcResponse::ContractReceipt { message, .. }) => {
                format!(r#"{{"ok":false,"error":"{}"}}"#, json_escape(&message))
            }
            _ => r#"{"ok":false,"error":"Mint RPC failed"}"#.to_owned(),
        }
    }
}

fn decode_hex32_gw(s: &str) -> Option<[u8; 32]> {
    if s.len() != 64 {
        return None;
    }
    let b = s.as_bytes();
    let mut out = [0u8; 32];
    for (i, pair) in b.as_chunks::<2>().0.iter().enumerate() {
        let hi = (pair[0] as char).to_digit(16)? as u8;
        let lo = (pair[1] as char).to_digit(16)? as u8;
        out[i] = (hi << 4) | lo;
    }
    Some(out)
}

fn write_plain_seed_file(path: &Path, seed: &[u8; 32]) -> io::Result<()> {
    let mut out = Vec::with_capacity(40);
    out.extend_from_slice(&PLAIN_WALLET_MAGIC);
    out.extend_from_slice(seed);
    fs::write(path, out)
}

fn parse_amount_or_chips(query: &str, default_chips: u64) -> Amount {
    if let Some(amt_str) = query_param(query, "amount") {
        let dec = percent_decode(amt_str);
        if let Some(parsed) = parse_decimal_xcr(&dec) {
            return parsed;
        }
    }
    let chips = query_param(query, "chips")
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(default_chips);
    Amount::from_chips(chips).unwrap_or(Amount::ZERO)
}

/// Serves the Browser Wallet & Merchant POS Terminal connected to a live UDP `credit-node`.
pub fn serve_live_wallet_gateway(
    listener: TcpListener,
    wallet_path: &Path,
    node_addr: SocketAddr,
    network_label: String,
) -> io::Result<()> {
    serve_live_wallet_gateway_with_password(listener, wallet_path, None, node_addr, network_label)
}

/// Serves the Browser Wallet & Merchant POS Terminal with an optional initial `XCRENC01` passphrase.
pub fn serve_live_wallet_gateway_with_password(
    listener: TcpListener,
    wallet_path: &Path,
    initial_password: Option<&str>,
    node_addr: SocketAddr,
    network_label: String,
) -> io::Result<()> {
    serve_live_wallet_gateway_full(
        listener,
        wallet_path,
        initial_password,
        node_addr,
        network_label,
        None,
        String::new(),
    )
}

/// Serves the full Browser Wallet, Embeddable Checkout JS, and HMAC-Signed Webhook Merchant Gateway.
#[allow(clippy::too_many_arguments)]
pub fn serve_live_wallet_gateway_full(
    listener: TcpListener,
    wallet_path: &Path,
    initial_password: Option<&str>,
    node_addr: SocketAddr,
    network_label: String,
    webhook_url: Option<String>,
    webhook_secret: String,
) -> io::Result<()> {
    let mut gw = LiveWalletGateway::open(wallet_path, initial_password, node_addr, network_label)?;
    gw.webhook_url = webhook_url;
    gw.webhook_secret = webhook_secret;

    for incoming in listener.incoming() {
        let Ok(mut stream) = incoming else {
            continue;
        };
        let _ = stream.set_read_timeout(Some(Duration::from_secs(10)));
        let _ = stream.set_write_timeout(Some(Duration::from_secs(10)));

        let Some(req_text) = crate::read_http_request(&mut stream, 32_768) else {
            continue;
        };
        let first_line = req_text.lines().next().unwrap_or("");
        let mut parts = first_line.split_whitespace();
        let method = parts.next().unwrap_or("GET");
        let full_target = parts.next().unwrap_or("/");
        let (path, query) = full_target.split_once('?').unwrap_or((full_target, ""));

        if method == "POST"
            && path != "/rpc"
            && !check_csrf_request_allowed(&req_text, &gw.csrf_token)
        {
            let body = r#"{"accepted":false,"error":"blocked by CSRF / cross-origin protection"}"#;
            let resp = format!(
                "HTTP/1.1 403 Forbidden\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            let _ = stream.write_all(resp.as_bytes());
            continue;
        }

        let mut should_shutdown = false;
        let (status, content_type, body) = match (method, path) {
            ("OPTIONS", "/rpc") => ("200 OK", "application/json", String::new()),
            ("POST", "/rpc") => {
                let http_body = req_text
                    .split_once("\r\n\r\n")
                    .map(|(_, b)| b)
                    .unwrap_or("");
                (
                    "200 OK",
                    "application/json; charset=utf-8",
                    handle_jsonrpc_post(http_body, gw.node_addr),
                )
            }
            ("GET", "/") => (
                "200 OK",
                "text/html; charset=utf-8",
                WALLET_AND_POS_HTML.replace("__XCR_CSRF_TOKEN__", &gw.csrf_token),
            ),
            ("GET", "/embed/xcr-checkout.js") => (
                "200 OK",
                "application/javascript; charset=utf-8",
                EMBED_CHECKOUT_JS.to_owned(),
            ),
            ("GET", "/api/checkout-status") => {
                let inv = query_param(query, "inv")
                    .map(percent_decode)
                    .unwrap_or_default();
                ("200 OK", "application/json", gw.checkout_status_json(&inv))
            }
            ("GET", "/api/subs") => ("200 OK", "application/json", gw.subs_json()),
            ("POST", "/api/subs/add") => {
                let lbl = query_param(query, "label")
                    .map(percent_decode)
                    .unwrap_or_else(|| "Sub".to_owned());
                let to = query_param(query, "to")
                    .map(percent_decode)
                    .unwrap_or_default();
                let amt = parse_amount_or_chips(query, 100);
                let iv = query_param(query, "interval")
                    .and_then(|v| v.parse::<u64>().ok())
                    .unwrap_or(2_592_000);
                (
                    "200 OK",
                    "application/json",
                    gw.handle_sub_add(&lbl, &to, amt, iv),
                )
            }
            ("POST", "/api/subs/cancel") => {
                let id = query_param(query, "id")
                    .and_then(|v| v.parse::<u64>().ok())
                    .unwrap_or(1);
                ("200 OK", "application/json", gw.handle_sub_cancel(id))
            }
            ("POST", "/api/subs/run") => ("200 OK", "application/json", gw.handle_sub_run()),
            ("POST", "/api/shamir/split") => {
                let k = query_param(query, "k")
                    .and_then(|v| v.parse::<u8>().ok())
                    .unwrap_or(2);
                let n = query_param(query, "n")
                    .and_then(|v| v.parse::<u8>().ok())
                    .unwrap_or(3);
                ("200 OK", "application/json", gw.handle_shamir_split(k, n))
            }
            ("POST", "/api/shamir/combine") => {
                let s = query_param(query, "shares")
                    .map(percent_decode)
                    .unwrap_or_default();
                ("200 OK", "application/json", gw.handle_shamir_combine(&s))
            }
            ("POST", "/api/cold/sign") => {
                let u = query_param(query, "unsigned")
                    .map(percent_decode)
                    .unwrap_or_default();
                ("200 OK", "application/json", gw.handle_cold_sign(&u))
            }
            ("POST", "/api/pay-multi") => {
                let b = query_param(query, "batch")
                    .map(percent_decode)
                    .unwrap_or_default();
                ("200 OK", "application/json", gw.handle_pay_multi(&b))
            }
            ("POST", "/api/frost/split") => {
                let k = query_param(query, "k")
                    .and_then(|v| v.parse::<u8>().ok())
                    .unwrap_or(2);
                let n = query_param(query, "n")
                    .and_then(|v| v.parse::<u8>().ok())
                    .unwrap_or(3);
                ("200 OK", "application/json", gw.handle_frost_split(k, n))
            }
            ("POST", "/api/htlc/lock") => {
                let to = query_param(query, "to")
                    .map(percent_decode)
                    .unwrap_or_default();
                let amt = parse_amount_or_chips(query, 100);
                let asset = query_param(query, "asset")
                    .map(percent_decode)
                    .unwrap_or_else(|| "BTC-LN".to_owned());
                let ca = query_param(query, "counter")
                    .map(percent_decode)
                    .unwrap_or_else(|| "0.001".to_owned());
                (
                    "200 OK",
                    "application/json",
                    gw.handle_htlc_lock_and_offer(&to, amt, &asset, &ca),
                )
            }
            ("POST", "/api/paychan/open") => {
                let to = query_param(query, "to")
                    .map(percent_decode)
                    .unwrap_or_default();
                let dep = parse_amount_or_chips(query, 500);
                (
                    "200 OK",
                    "application/json",
                    gw.handle_paychan_open(&to, dep),
                )
            }
            ("POST", "/api/paychan/tick") => {
                let cid = query_param(query, "cid")
                    .map(percent_decode)
                    .unwrap_or_default();
                let cum = parse_amount_or_chips(query, 50);
                (
                    "200 OK",
                    "application/json",
                    gw.handle_paychan_tick(&cid, cum),
                )
            }
            ("POST", "/api/paychan/close") => {
                let v = query_param(query, "voucher")
                    .map(percent_decode)
                    .unwrap_or_default();
                ("200 OK", "application/json", gw.handle_paychan_close(&v))
            }
            ("POST", "/api/check/issue") => {
                let to = query_param(query, "to")
                    .map(percent_decode)
                    .unwrap_or_default();
                let amt = parse_amount_or_chips(query, 1000);
                (
                    "200 OK",
                    "application/json",
                    gw.handle_check_issue(&to, amt),
                )
            }
            ("POST", "/api/check/cash") => {
                let u = query_param(query, "uri")
                    .map(percent_decode)
                    .unwrap_or_default();
                let amt = parse_amount_or_chips(query, 500);
                (
                    "200 OK",
                    "application/json",
                    gw.handle_check_cash_or_cancel(&u, amt, false),
                )
            }
            ("POST", "/api/check/cancel") => {
                let u = query_param(query, "uri")
                    .map(percent_decode)
                    .unwrap_or_default();
                (
                    "200 OK",
                    "application/json",
                    gw.handle_check_cash_or_cancel(&u, Amount::ZERO, true),
                )
            }
            ("POST", "/api/session/issue") => {
                let amt = parse_amount_or_chips(query, 500);
                ("200 OK", "application/json", gw.handle_session_issue(amt))
            }
            ("POST", "/api/asset/mint") => {
                let t = query_param(query, "ticker")
                    .map(percent_decode)
                    .unwrap_or_else(|| "VIP".to_owned());
                let s = query_param(query, "supply")
                    .and_then(|v| v.parse::<u64>().ok())
                    .unwrap_or(1_000);
                ("200 OK", "application/json", gw.handle_asset_mint(&t, s))
            }
            ("GET", "/.well-known/xcr-pay.json") => {
                let user = query_param(query, "user")
                    .map(percent_decode)
                    .unwrap_or_else(|| "merchant".to_owned());
                (
                    "200 OK",
                    "application/json",
                    format_well_known_pay_json(&user, &gw.stealth_meta, &gw.network_label),
                )
            }
            ("GET", "/api/qr.svg") => {
                let data = query_param(query, "data")
                    .map(percent_decode)
                    .unwrap_or_else(|| gw.stealth_meta.to_uri());
                match QrCode::encode_str(&data) {
                    Ok(qr) => ("200 OK", "image/svg+xml; charset=utf-8", qr.to_svg(4)),
                    Err(e) => (
                        "400 Bad Request",
                        "application/json",
                        format!(r#"{{"error":"{}"}}"#, json_escape(&e.to_string())),
                    ),
                }
            }
            ("GET", "/api/invoice-uri") => {
                let amount = parse_amount_or_chips(query, 100);
                let inv = query_param(query, "invoice")
                    .map(percent_decode)
                    .unwrap_or_default();
                let memo = query_param(query, "memo")
                    .map(percent_decode)
                    .unwrap_or_default();
                let req = PaymentRequestUri::new(gw.stealth_meta.to_uri())
                    .with_amount(amount)
                    .with_invoice(inv.clone())
                    .with_memo(memo);
                let uri = req.to_uri();
                (
                    "200 OK",
                    "application/json",
                    format!(
                        r#"{{"uri":"{}","invoice":"{}"}}"#,
                        json_escape(&uri),
                        json_escape(&inv)
                    ),
                )
            }
            ("GET", "/api/state") => ("200 OK", "application/json", gw.state_json()),
            ("GET", "/api/history") => ("200 OK", "application/json", gw.history_json()),
            ("GET", "/api/contacts") => ("200 OK", "application/json", gw.contacts_json()),
            ("POST", "/api/contacts/add") => {
                let alias = query_param(query, "alias")
                    .map(percent_decode)
                    .unwrap_or_default();
                let uri = query_param(query, "uri")
                    .map(percent_decode)
                    .unwrap_or_default();
                (
                    "200 OK",
                    "application/json",
                    gw.handle_add_contact(&alias, &uri),
                )
            }
            ("POST", "/api/wallet/lock") => {
                gw.unlocked_seed = None; // Zeroizes master seed in RAM via Drop!
                (
                    "200 OK",
                    "application/json",
                    r#"{"locked":true}"#.to_owned(),
                )
            }
            ("POST", "/api/wallet/unlock") => {
                let pw = query_param(query, "password")
                    .map(percent_decode)
                    .unwrap_or_default();
                (
                    "200 OK",
                    "application/json",
                    gw.handle_unlock_or_encrypt(&pw),
                )
            }
            ("GET", "/api/light-verify") => {
                ("200 OK", "application/json", gw.handle_light_verify())
            }
            ("GET", "/api/backup") => match gw.unlocked_seed {
                Some(ref seed) => (
                    "200 OK",
                    "application/json",
                    format!(r#"{{"words":"{}"}}"#, encode_mnemonic_24(seed.as_bytes())),
                ),
                None => (
                    "200 OK",
                    "application/json",
                    r#"{"error":"Unlock wallet first to view recovery phrase."}"#.to_owned(),
                ),
            },
            ("POST", "/api/recover") => {
                let words = query_param(query, "words")
                    .map(percent_decode)
                    .unwrap_or_default();
                ("200 OK", "application/json", gw.handle_recover(&words))
            }
            ("POST", "/api/pay") => {
                let amount = parse_amount_or_chips(query, 100);
                let invoice = query_param(query, "invoice")
                    .map(percent_decode)
                    .unwrap_or_else(|| "POS-0001".to_owned());
                let to = query_param(query, "to")
                    .map(percent_decode)
                    .unwrap_or_default();
                let regulated = query_param(query, "regulated") != Some("0");
                (
                    "200 OK",
                    "application/json",
                    gw.handle_pay(amount, &invoice, &to, regulated),
                )
            }
            ("POST", "/api/voucher/create") => {
                let amount = parse_amount_or_chips(query, 100);
                let memo = query_param(query, "memo")
                    .map(percent_decode)
                    .unwrap_or_default();
                (
                    "200 OK",
                    "application/json",
                    gw.handle_voucher_create(amount, &memo),
                )
            }
            ("POST", "/api/voucher/claim") => {
                let uri = query_param(query, "uri")
                    .map(percent_decode)
                    .unwrap_or_default();
                ("200 OK", "application/json", gw.handle_voucher_claim(&uri))
            }
            ("POST", "/api/scan-stealth") => {
                ("200 OK", "application/json", gw.handle_scan_stealth())
            }
            ("POST", "/api/mine-epoch") | ("POST", "/api/faucet") => (
                "200 OK",
                "application/json",
                r#"{"info":"live P2P network mines continuous 60s epochs automatically"}"#
                    .to_owned(),
            ),
            ("POST", "/api/vault/queue") => {
                let credits = query_param(query, "credits")
                    .and_then(|v| v.parse::<u64>().ok())
                    .unwrap_or(50);
                if gw.vault.balance.is_zero() {
                    gw.vault.balance = Amount::from_credits(500).unwrap();
                }
                let res = match Amount::from_credits(credits).and_then(|amt| {
                    gw.vault
                        .queue_withdrawal(Address::from_bytes([0xee; 32]), amt, 1_000)
                        .ok()
                }) {
                    Some(wid) => format!(r#"{{"queued":true,"id":{wid}}}"#),
                    None => r#"{"queued":false}"#.to_owned(),
                };
                ("200 OK", "application/json", res)
            }
            ("POST", "/api/vault/cancel") => {
                let id = query_param(query, "id")
                    .and_then(|v| v.parse::<u64>().ok())
                    .unwrap_or(1);
                let res = match gw.vault.emergency_cancel(id) {
                    Ok(restored) => format!(r#"{{"cancelled":true,"restored":"{}"}}"#, restored),
                    Err(_) => r#"{"cancelled":false}"#.to_owned(),
                };
                ("200 OK", "application/json", res)
            }
            ("POST", "/api/shutdown") => {
                should_shutdown = true;
                (
                    "200 OK",
                    "application/json",
                    r#"{"shutdown":true}"#.to_owned(),
                )
            }
            _ => (
                "404 Not Found",
                "application/json",
                r#"{"error":"not found"}"#.to_owned(),
            ),
        };

        let cors = if method == "GET" {
            "Access-Control-Allow-Origin: *\r\n"
        } else {
            ""
        };
        let resp = format!(
            "HTTP/1.1 {status}\r\nContent-Type: {content_type}\r\n{cors}Cache-Control: no-store\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        );
        let _ = stream.write_all(resp.as_bytes());
        let _ = stream.flush();

        if should_shutdown {
            return Ok(());
        }
    }
    Ok(())
}
