//! Command-Line Wallet Client Library (`credit-cli`) speaking `NodeRpcRequest` over UDP.
//!
//! Manages local sovereign seed files, syncs account nonces from a running `credit-node daemon`,
//! generates compact **672-byte 64-bit Logarithmic Bulletproofs (`BulletproofRange64`)**, and
//! submits 1-RTT `FastTransfer` payments.

pub mod audit_bench;

use std::fs;
use std::io;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::Mutex;
use std::time::Duration;

use credit_consensus::tx_signing_digest;
use credit_crypto::{
    Keypair, Scalar, SignatureScheme, StealthKeypair, StealthMetaAddress, StealthOutput,
    decrypt_stealth_memo, derive_stealth_output, domain_hash, encrypt_stealth_memo,
};
use credit_net::{
    AssetWireRecord, HtlcWireRecord, NodeRpcRequest, NodeRpcResponse, PayChanWireRecord,
    PersistentRpcChannel, StealthOutputRecordV2, rpc_call,
};
use credit_sdk::{
    ActivityEntry, AtomicSwapOffer, BearerVoucher, CredScript, CredWitnessItem, DigitalCheck,
    EncryptedActivityLog, FrostKeyShare, FrostNonceCommit, FrostNonceSecret, FrostPartialSig,
    LocalHandleBook, NativeAssetMint, PayChanVoucher, PaymentRequestUri, SessionKeyGrant,
    ShamirShare, SignedColdTransfer, SubscriptionBook, SubscriptionMandate, UnsignedColdTransfer,
    ZeroizingSeed, combine_secret_shamir, decode_mnemonic_24, encode_mnemonic_24,
    encode_witness_stack, encrypt_wallet_seed, format_backup_card_24,
    frost_aggregate_cold_transfer, frost_commit_nonce, frost_sign_partial, frost_split_pocket_key,
    generate_htlc_secret, is_encrypted_wallet_bytes, open_wallet_bytes, parse_decimal_xcr,
    resolve_remote_handle, script_vault_spend_digest, sign_asset_transfer, sign_check_cancel,
    sign_check_cash, sign_crowdfund_create, sign_crowdfund_pledge, sign_fee_sponsorship,
    sign_htlc_lock, sign_paychan_open, sign_script_vault_lock, sign_session_revoke,
    split_secret_shamir,
};
use credit_types::{Address, Amount, Hash32, MIN_BASE_FEE_BITS, Transaction, TransactionKind};
use credit_zk::{BulletproofRange64, StateInclusionProof, StateLeaf};

const DEFAULT_RPC_TIMEOUT: Duration = Duration::from_secs(8);

/// Persisted 32-byte wallet master seed stored locally on disk (`XCRSEED1` + 32 bytes).
pub const WALLET_FILE_MAGIC: [u8; 8] = *b"XCRSEED1";

pub fn save_wallet_seed(path: &Path, seed: &[u8; 32]) -> io::Result<()> {
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        fs::create_dir_all(parent)?;
    }
    let mut buf = Vec::with_capacity(40);
    buf.extend_from_slice(&WALLET_FILE_MAGIC);
    buf.extend_from_slice(seed);
    fs::write(path, buf)
}

static CLI_PASSWORD_OVERRIDE: Mutex<Option<String>> = Mutex::new(None);

/// Sets the in-process wallet passphrase supplied via `--password` on `credit-cli`.
pub fn set_cli_wallet_password(password: Option<String>) {
    if let Ok(mut guard) = CLI_PASSWORD_OVERRIDE.lock() {
        *guard = password;
    }
}

pub fn load_wallet_seed(path: &Path) -> io::Result<[u8; 32]> {
    let override_pw = CLI_PASSWORD_OVERRIDE.lock().ok().and_then(|g| g.clone());
    let env_pass = override_pw.or_else(|| std::env::var("XCR_WALLET_PASSWORD").ok());
    let z = load_wallet_seed_with_password(path, env_pass.as_deref())?;
    Ok(*z.as_bytes())
}

/// Loads either a plaintext `XCRSEED1` wallet or an `XCRENC01` passphrase-encrypted wallet,
/// returning a `ZeroizingSeed` that scrubs RAM on `Drop`.
pub fn load_wallet_seed_with_password(
    path: &Path,
    password: Option<&str>,
) -> io::Result<ZeroizingSeed> {
    let raw = fs::read(path)?;
    open_wallet_bytes(&raw, password)
        .map_err(|e| io::Error::new(io::ErrorKind::PermissionDenied, e.to_string()))
}

/// Upgrades a wallet file on disk to the 80-byte memory-hard `XCRENC01` passphrase-encrypted format.
pub fn cli_encrypt_wallet_file(
    path: &Path,
    current_password: Option<&str>,
    new_password: &str,
    salt_entropy: [u8; 16],
) -> io::Result<()> {
    let z = load_wallet_seed_with_password(path, current_password)?;
    let sealed = encrypt_wallet_seed(z.as_bytes(), new_password, salt_entropy, 1)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e.to_string()))?;
    fs::write(path, sealed)
}

/// Decrypts an `XCRENC01` wallet file back to plaintext `XCRSEED1` after verifying `password`.
pub fn cli_decrypt_wallet_file(path: &Path, password: &str) -> io::Result<()> {
    let raw = fs::read(path)?;
    if !is_encrypted_wallet_bytes(&raw) {
        return Ok(());
    }
    let z = open_wallet_bytes(&raw, Some(password))
        .map_err(|e| io::Error::new(io::ErrorKind::PermissionDenied, e.to_string()))?;
    save_wallet_seed(path, z.as_bytes())
}

/// Reads and decrypts the local AEAD-encrypted `<wallet>.history` receipt log.
pub fn cli_read_activity_history(wallet_path: &Path) -> io::Result<Vec<ActivityEntry>> {
    let master = load_wallet_seed(wallet_path)?;
    let log = EncryptedActivityLog::load(&wallet_path.with_extension("history"), &master);
    Ok(log.entries().to_vec())
}

/// Queries live node status (`epoch`, `circulating_supply`, `state_root`, etc.) over UDP.
pub fn cli_get_status(node_addr: SocketAddr) -> io::Result<NodeRpcResponse> {
    rpc_call(node_addr, &NodeRpcRequest::GetStatus, DEFAULT_RPC_TIMEOUT)
}

/// Queries extended live node telemetry (`connected_peers`, `active_miners`, etc.) over UDP,
/// falling back to `GetStatus` on older nodes.
pub fn cli_get_telemetry(node_addr: SocketAddr) -> io::Result<NodeRpcResponse> {
    if let Ok(resp @ NodeRpcResponse::NetworkTelemetry { .. }) = rpc_call(
        node_addr,
        &NodeRpcRequest::GetNetworkTelemetry,
        Duration::from_millis(2_000),
    ) {
        return Ok(resp);
    }
    cli_get_status(node_addr)
}

/// Initializes a new local wallet seed file and registers its Passkey `Spending Pocket`
/// on `node_addr` with an initial devnet worker grant (`20.000000 XCR`, `25.000000 XCR` daily cap).
pub fn cli_init_wallet(
    wallet_path: &Path,
    seed_entropy: [u8; 32],
    node_addr: SocketAddr,
) -> io::Result<(Address, NodeRpcResponse)> {
    save_wallet_seed(wallet_path, &seed_entropy)?;
    let pocket_seed = domain_hash("XCR.WALLET.POCKET_KEY.V1", &[&seed_entropy]).0;
    let kp = Keypair::from_seed(SignatureScheme::PasskeyP256, pocket_seed);
    let address = kp.address();
    let req = NodeRpcRequest::RegisterPocket {
        address,
        public_key: kp.public_key(),
        grant_from_miner: Amount::from_credits(20).unwrap(),
        daily_limit: Amount::from_credits(25).unwrap(),
    };
    let resp = rpc_call(node_addr, &req, DEFAULT_RPC_TIMEOUT)?;
    Ok((address, resp))
}

/// Queries the live `Pocket` balance and `nonce` for `wallet_path` from `node_addr`.
pub fn cli_get_balance(
    wallet_path: &Path,
    node_addr: SocketAddr,
) -> io::Result<(Address, NodeRpcResponse)> {
    let master = load_wallet_seed(wallet_path)?;
    let pocket_seed = domain_hash("XCR.WALLET.POCKET_KEY.V1", &[&master]).0;
    let kp = Keypair::from_seed(SignatureScheme::PasskeyP256, pocket_seed);
    let address = kp.address();
    let resp = rpc_call(
        node_addr,
        &NodeRpcRequest::GetPocket { address },
        DEFAULT_RPC_TIMEOUT,
    )?;
    Ok((address, resp))
}

/// Builds a signed 1-RTT `FastTransfer` + **672-byte 64-bit Logarithmic Bulletproof**,
/// sends it over UDP to `node_addr`, and returns the finalized WAL receipt.
pub fn cli_send_bulletproof_payment(
    wallet_path: &Path,
    recipient_tag: &[u8],
    amount: Amount,
    fee: Amount,
    node_addr: SocketAddr,
) -> io::Result<NodeRpcResponse> {
    cli_send_bulletproof_payment_with_memo(wallet_path, recipient_tag, amount, fee, "", node_addr)
}

/// Resolves `recipient_str` across `xcr:` Payment URIs, `xcrstealth1_` URIs, local `@aliases`,
/// remote `user@domain[:port]` `.well-known/xcr-pay.json` handles, or deterministic fallback tags.
pub fn resolve_recipient_destination(
    wallet_path: Option<&Path>,
    recipient_str: &str,
) -> (StealthMetaAddress, Option<Amount>, Option<String>) {
    let trimmed = recipient_str.trim();
    if let Some(meta) = StealthMetaAddress::from_uri(trimmed) {
        return (meta, None, None);
    }
    if let Some(parsed_req) = PaymentRequestUri::parse(trimmed) {
        let (meta, _, _) = resolve_recipient_destination(wallet_path, &parsed_req.recipient);
        let combined_memo = match (parsed_req.invoice, parsed_req.memo) {
            (Some(inv), Some(m)) => Some(format!("{inv}: {m}")),
            (Some(inv), None) => Some(inv),
            (None, Some(m)) => Some(m),
            (None, None) => None,
        };
        return (meta, parsed_req.amount, combined_memo);
    }
    if let Some(wp) = wallet_path {
        let book = LocalHandleBook::load(&wp.with_extension("aliases"));
        if let Some(meta) = book.resolve(trimmed) {
            return (meta, None, None);
        }
    }
    if ((trimmed.contains('@') && !trimmed.starts_with('@')) || trimmed.starts_with('$'))
        && let Ok(meta) = resolve_remote_handle(trimmed, Duration::from_millis(2_500))
    {
        return (meta, None, None);
    }
    let recipient_seed = domain_hash("XCR.CLI.RECIPIENT.V1", &[trimmed.as_bytes()]).0;
    (
        StealthKeypair::from_seed(&recipient_seed).meta_address(),
        None,
        None,
    )
}

/// Builds a signed 1-RTT `FastTransfer` + `672B` Bulletproof with an optional end-to-end encrypted
/// stealth memo (`<= 64` UTF-8 bytes), supporting `xcr:` URIs and `@handle` resolution.
pub fn cli_send_bulletproof_payment_with_memo(
    wallet_path: &Path,
    recipient_tag: &[u8],
    amount: Amount,
    fee: Amount,
    memo: &str,
    node_addr: SocketAddr,
) -> io::Result<NodeRpcResponse> {
    let master = load_wallet_seed(wallet_path)?;
    let pocket_seed = domain_hash("XCR.WALLET.POCKET_KEY.V1", &[&master]).0;
    let mut kp = Keypair::from_seed(SignatureScheme::PasskeyP256, pocket_seed);
    let from = kp.address();

    let NodeRpcResponse::PocketInfo {
        found: true, nonce, ..
    } = rpc_call(
        node_addr,
        &NodeRpcRequest::GetPocket { address: from },
        DEFAULT_RPC_TIMEOUT,
    )?
    else {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            "wallet Pocket is not registered on target node",
        ));
    };

    let (target_meta, uri_amount, uri_memo) = if let Ok(s) = std::str::from_utf8(recipient_tag) {
        resolve_recipient_destination(Some(wallet_path), s)
    } else {
        let recipient_seed = domain_hash("XCR.CLI.RECIPIENT.V1", &[recipient_tag]).0;
        (
            StealthKeypair::from_seed(&recipient_seed).meta_address(),
            None,
            None,
        )
    };
    let final_amount = uri_amount.filter(|a| !a.is_zero()).unwrap_or(amount);
    let final_memo = if !memo.trim().is_empty() {
        memo.trim().to_owned()
    } else {
        uri_memo.unwrap_or_default()
    };

    let eph_seed = domain_hash(
        "XCR.CLI.EPH.V1",
        &[&master, &nonce.to_le_bytes(), recipient_tag],
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
    let (v_commit, bp_proof) = BulletproofRange64::prove(final_amount, gamma, 64, &bp_seed)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "Bulletproof prove failed"))?;
    let bp_bytes = bp_proof.to_bytes();
    debug_assert_eq!(bp_bytes.len(), BulletproofRange64::SERIALIZED_SIZE_64BIT);

    let commitment_hash = domain_hash("XCR.CLI.COMMIT_TAG.V1", &[&v_commit.to_bytes()]);
    let kind = TransactionKind::FastTransfer {
        from,
        to_stealth: stealth_out.one_time_address,
        stealth_view_tag: stealth_out.view_tag,
        amount: final_amount,
        fee,
        nonce,
        commitment: commitment_hash,
        innocence_nullifier: None,
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
        bulletproof_672: bp_bytes,
    };
    let resp = rpc_call(node_addr, &req, DEFAULT_RPC_TIMEOUT)?;
    if let NodeRpcResponse::FastPayReceipt {
        accepted: true,
        tx_id,
        ..
    } = &resp
    {
        let encrypted_memo = encrypt_stealth_memo(&shared_secret, &final_memo);
        let _ = rpc_call(
            node_addr,
            &NodeRpcRequest::AnnounceStealthOutputV2 {
                one_time_address: stealth_out.one_time_address,
                ephemeral_pub: stealth_out.ephemeral_pub,
                view_tag: stealth_out.view_tag,
                encrypted_memo,
            },
            Duration::from_millis(2_500),
        );
        EncryptedActivityLog::append_and_persist(
            &wallet_path.with_extension("history"),
            &master,
            "sent",
            final_amount,
            tx_id.to_hex(),
            &final_memo,
        );
    }
    Ok(resp)
}

/// Exports the wallet's `Pocket` address and shareable `xcrstealth1_...` Stealth Meta-Address URI.
pub fn cli_stealth_address(wallet_path: &Path) -> io::Result<(Address, String)> {
    let master = load_wallet_seed(wallet_path)?;
    let pocket_seed = domain_hash("XCR.WALLET.POCKET_KEY.V1", &[&master]).0;
    let pocket_addr = Keypair::from_seed(SignatureScheme::PasskeyP256, pocket_seed).address();
    let stealth_seed = domain_hash("XCR.WALLET.STEALTH_KEY.V1", &[&master]).0;
    let stealth_kp = StealthKeypair::from_seed(&stealth_seed);
    Ok((pocket_addr, stealth_kp.meta_address().to_uri()))
}

/// Tuple `(one_time_address, amount, was_claimed, updated_pocket_balance, decrypted_memo)` returned by `cli_scan_and_claim_stealth_v2`.
pub type StealthScanMatchV2 = (Address, Amount, bool, Amount, Option<String>);

///Tuple `(one_time_address, amount, was_claimed, updated_pocket_balance)` returned by `cli_scan_and_claim_stealth`.
pub type StealthScanMatch = (Address, Amount, bool, Amount);

/// Scans unspent network stealth outputs using the wallet's `1-byte` view tag (`99.6%` fast reject),
/// decrypts any attached X25519 memo, and optionally sweeps matching outputs into `Pocket`.
pub fn cli_scan_and_claim_stealth_v2(
    wallet_path: &Path,
    node_addr: SocketAddr,
    claim_matches: bool,
) -> io::Result<(usize, Vec<StealthScanMatchV2>)> {
    let master = load_wallet_seed(wallet_path)?;
    let pocket_seed = domain_hash("XCR.WALLET.POCKET_KEY.V1", &[&master]).0;
    let pocket_kp = Keypair::from_seed(SignatureScheme::PasskeyP256, pocket_seed);
    let pocket_addr = pocket_kp.address();

    let stealth_seed = domain_hash("XCR.WALLET.STEALTH_KEY.V1", &[&master]).0;
    let stealth_kp = StealthKeypair::from_seed(&stealth_seed);

    let outputs: Vec<StealthOutputRecordV2> = match rpc_call(
        node_addr,
        &NodeRpcRequest::GetStealthOutputsV2,
        Duration::from_millis(2_500),
    ) {
        Ok(NodeRpcResponse::StealthOutputsV2 { outputs }) => outputs,
        _ => {
            let NodeRpcResponse::StealthOutputs { outputs } = rpc_call(
                node_addr,
                &NodeRpcRequest::GetStealthOutputs,
                DEFAULT_RPC_TIMEOUT,
            )?
            else {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "unexpected GetStealthOutputs reply",
                ));
            };
            outputs
                .into_iter()
                .map(|(a, amt, eph, vt)| (a, amt, eph, vt, Vec::new()))
                .collect()
        }
    };

    let total_scanned = outputs.len();
    let mut matched = Vec::new();
    for (one_time_address, utxo_amt, ephemeral_pub, view_tag, enc_memo) in outputs {
        let candidate = StealthOutput {
            ephemeral_pub,
            view_tag,
            one_time_address,
        };
        let Some(kdf) = stealth_kp.scan_and_open(&candidate) else {
            continue;
        };
        let dec_memo = decrypt_stealth_memo(&kdf, &enc_memo);
        if !claim_matches {
            matched.push((one_time_address, utxo_amt, false, Amount::ZERO, dec_memo));
            continue;
        }
        let sig64 = stealth_kp.sign_claim(&one_time_address, &pocket_addr);
        let claim_resp = rpc_call(
            node_addr,
            &NodeRpcRequest::ClaimStealthUtxo {
                one_time_address,
                claimant_pocket: pocket_addr,
                claimant_pubkey: pocket_kp.public_key(),
                spend_pub: stealth_kp.meta_address().spend_pub,
                kdf,
                schnorr_sig64: sig64,
            },
            DEFAULT_RPC_TIMEOUT,
        )?;
        match claim_resp {
            NodeRpcResponse::StealthClaimReceipt {
                accepted: true,
                claimed_amount,
                new_pocket_balance,
                ..
            } => {
                EncryptedActivityLog::append_and_persist(
                    &wallet_path.with_extension("history"),
                    &master,
                    "received",
                    claimed_amount,
                    one_time_address.short_hex(),
                    dec_memo.as_deref().unwrap_or(""),
                );
                matched.push((
                    one_time_address,
                    claimed_amount,
                    true,
                    new_pocket_balance,
                    dec_memo,
                ));
            }
            _ => matched.push((one_time_address, utxo_amt, false, Amount::ZERO, dec_memo)),
        }
    }
    Ok((total_scanned, matched))
}

/// Scans unspent network stealth outputs using the wallet's `1-byte` view tag (`99.6%` fast reject)
/// and optionally sweeps/claims matching outputs into the wallet's spendable `Pocket`.
pub fn cli_scan_and_claim_stealth(
    wallet_path: &Path,
    node_addr: SocketAddr,
    claim_matches: bool,
) -> io::Result<(usize, Vec<StealthScanMatch>)> {
    let (scanned, v2) = cli_scan_and_claim_stealth_v2(wallet_path, node_addr, claim_matches)?;
    let v1 = v2
        .into_iter()
        .map(|(a, amt, ok, bal, _)| (a, amt, ok, bal))
        .collect();
    Ok((scanned, v1))
}

/// Queries and cryptographically verifies a `<256-byte` Merkle `StateInclusionProof`
/// so a lightweight wallet never blindly trusts an RPC node's reported balance.
pub fn cli_verify_light_balance(
    wallet_path: &Path,
    node_addr: SocketAddr,
) -> io::Result<(Address, Amount, u64, usize, Hash32)> {
    let master = load_wallet_seed(wallet_path)?;
    let pocket_seed = domain_hash("XCR.WALLET.POCKET_KEY.V1", &[&master]).0;
    let kp = Keypair::from_seed(SignatureScheme::PasskeyP256, pocket_seed);
    let address = kp.address();

    let resp = rpc_call(
        node_addr,
        &NodeRpcRequest::GetLightAccountProof { address },
        DEFAULT_RPC_TIMEOUT,
    )?;
    let NodeRpcResponse::LightAccountProof {
        found: true,
        authenticated_root,
        balance,
        nonce,
        inclusion_proof_bytes,
    } = resp
    else {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            "account not present in node's AuthenticatedStateTree",
        ));
    };

    let branch = StateInclusionProof::from_bytes(&inclusion_proof_bytes).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "malformed StateInclusionProof bytes",
        )
    })?;
    let leaf = StateLeaf {
        address,
        balance,
        nonce,
    };
    if !branch.verify(&leaf, &authenticated_root) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "SECURITY ALERT: untrusted RPC returned forged balance failing Merkle verification!",
        ));
    }
    Ok((
        address,
        balance,
        nonce,
        inclusion_proof_bytes.len(),
        authenticated_root,
    ))
}

/// Sends a graceful `ShutdownDaemon` RPC command to `node_addr`.
pub fn cli_shutdown_daemon(node_addr: SocketAddr) -> io::Result<NodeRpcResponse> {
    rpc_call(
        node_addr,
        &NodeRpcRequest::ShutdownDaemon,
        DEFAULT_RPC_TIMEOUT,
    )
}

/// Builds a scannable `xcr:` merchant/peer Payment Request URI and terminal QR code for `wallet_path`.
pub fn cli_create_invoice_qr(
    wallet_path: &Path,
    amount: Amount,
    invoice: &str,
    memo: &str,
) -> io::Result<(String, String)> {
    let (_, stealth_uri) = cli_stealth_address(wallet_path)?;
    let req = PaymentRequestUri::new(stealth_uri)
        .with_amount(amount)
        .with_invoice(invoice)
        .with_memo(memo);
    let uri = req.to_uri();
    let qr = req
        .to_qr_code()
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e.to_string()))?;
    Ok((uri, qr.to_terminal_unicode()))
}

/// Locks `amount` from `wallet_path` into a shareable `xcr://claim#<64-hex>` Bearer Cash Voucher
/// and returns `(voucher_uri, terminal_qr_string, FastPayReceipt)`.
pub fn cli_create_bearer_voucher(
    wallet_path: &Path,
    voucher_entropy: [u8; 32],
    amount: Amount,
    fee: Amount,
    memo: &str,
    node_addr: SocketAddr,
) -> io::Result<(String, String, NodeRpcResponse)> {
    let master = load_wallet_seed(wallet_path)?;
    let pocket_seed = domain_hash("XCR.WALLET.POCKET_KEY.V1", &[&master]).0;
    let mut kp = Keypair::from_seed(SignatureScheme::PasskeyP256, pocket_seed);
    let from = kp.address();

    let NodeRpcResponse::PocketInfo {
        found: true, nonce, ..
    } = rpc_call(
        node_addr,
        &NodeRpcRequest::GetPocket { address: from },
        DEFAULT_RPC_TIMEOUT,
    )?
    else {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            "wallet Pocket is not registered on target node",
        ));
    };

    let voucher_secret = domain_hash(
        "XCR.CLI.VOUCHER_SK.V1",
        &[&master, &nonce.to_le_bytes(), &voucher_entropy],
    )
    .0;
    let memo_opt = if memo.trim().is_empty() {
        None
    } else {
        Some(memo.trim().to_owned())
    };
    let voucher = BearerVoucher::new(voucher_secret, Some(amount), memo_opt);
    let (stealth_out, kdf, _, _) = voucher.derive_claim_material();

    let gamma = Scalar::hash_from_parts("XCR.CLI.VOUCHER_GAMMA.V1", &[&kdf, &nonce.to_le_bytes()]);
    let bp_seed = domain_hash("XCR.CLI.VOUCHER_BP.V1", &[&kdf, &nonce.to_le_bytes()]).0;
    let (v_commit, bp_proof) = BulletproofRange64::prove(amount, gamma, 64, &bp_seed)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "Bulletproof prove failed"))?;
    let bp_bytes = bp_proof.to_bytes();

    let commitment_hash = domain_hash("XCR.CLI.COMMIT_TAG.V1", &[&v_commit.to_bytes()]);
    let kind = TransactionKind::FastTransfer {
        from,
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

    let resp = rpc_call(
        node_addr,
        &NodeRpcRequest::SubmitBulletproofFastPay {
            tx: Transaction {
                id: tx_id,
                kind,
                signature_bytes: sig_bytes,
            },
            value_commitment: v_commit.to_bytes(),
            bulletproof_672: bp_bytes,
        },
        DEFAULT_RPC_TIMEOUT,
    )?;
    let uri = voucher.to_uri();
    if matches!(resp, NodeRpcResponse::FastPayReceipt { accepted: true, .. }) {
        let encrypted_memo = encrypt_stealth_memo(&kdf, memo);
        let _ = rpc_call(
            node_addr,
            &NodeRpcRequest::AnnounceStealthOutputV2 {
                one_time_address: stealth_out.one_time_address,
                ephemeral_pub: stealth_out.ephemeral_pub,
                view_tag: stealth_out.view_tag,
                encrypted_memo,
            },
            Duration::from_millis(2_500),
        );
        EncryptedActivityLog::append_and_persist(
            &wallet_path.with_extension("history"),
            &master,
            "voucher_out",
            amount,
            &uri,
            memo,
        );
    }
    let qr_str = voucher
        .to_qr_code()
        .map(|q| q.to_terminal_unicode())
        .unwrap_or_default();
    Ok((uri, qr_str, resp))
}

/// Redeems a shareable `xcr://claim#<64-hex>` Bearer Cash Voucher into `wallet_path` (auto-creating
/// `wallet_path` if the recipient doesn't even have a wallet yet!).
pub fn cli_claim_bearer_voucher(
    wallet_path: &Path,
    voucher_uri: &str,
    fallback_new_wallet_seed: [u8; 32],
    node_addr: SocketAddr,
) -> io::Result<(Address, Option<String>, NodeRpcResponse)> {
    let voucher = BearerVoucher::parse(voucher_uri).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid `xcr://claim#<64-hex>` voucher URI",
        )
    })?;
    let master = if wallet_path.exists() {
        load_wallet_seed(wallet_path)?
    } else {
        save_wallet_seed(wallet_path, &fallback_new_wallet_seed)?;
        fallback_new_wallet_seed
    };
    let pocket_seed = domain_hash("XCR.WALLET.POCKET_KEY.V1", &[&master]).0;
    let pocket_kp = Keypair::from_seed(SignatureScheme::PasskeyP256, pocket_seed);
    let pocket_addr = pocket_kp.address();

    let (one_time_address, spend_pub, kdf, schnorr_sig64) = voucher.sign_claim_for(&pocket_addr);
    let resp = rpc_call(
        node_addr,
        &NodeRpcRequest::ClaimStealthUtxo {
            one_time_address,
            claimant_pocket: pocket_addr,
            claimant_pubkey: pocket_kp.public_key(),
            spend_pub,
            kdf,
            schnorr_sig64,
        },
        DEFAULT_RPC_TIMEOUT,
    )?;
    if let NodeRpcResponse::StealthClaimReceipt {
        accepted: true,
        claimed_amount,
        ..
    } = &resp
    {
        EncryptedActivityLog::append_and_persist(
            &wallet_path.with_extension("history"),
            &master,
            "voucher_in",
            *claimed_amount,
            one_time_address.short_hex(),
            voucher.memo.as_deref().unwrap_or(""),
        );
    }
    Ok((pocket_addr, voucher.memo, resp))
}

/// Queries a validator via `InspectQuery` and cryptographically verifies any returned `<256B`
/// Merkle `StateInclusionProof`.
pub fn cli_inspect_query(
    node_addr: SocketAddr,
    query: &str,
) -> io::Result<(NodeRpcResponse, bool)> {
    let resp = rpc_call(
        node_addr,
        &NodeRpcRequest::InspectQuery {
            query: query.to_owned(),
        },
        DEFAULT_RPC_TIMEOUT,
    )?;
    let merkle_ok = match &resp {
        NodeRpcResponse::InspectResult {
            kind: 1,
            address,
            balance,
            nonce,
            authenticated_root,
            inclusion_proof_bytes,
            ..
        } => StateInclusionProof::from_bytes(inclusion_proof_bytes).is_some_and(|branch| {
            branch.verify(
                &StateLeaf {
                    address: *address,
                    balance: *balance,
                    nonce: *nonce,
                },
                authenticated_root,
            )
        }),
        NodeRpcResponse::InspectResult { kind: 2, .. } => true,
        _ => false,
    };
    Ok((resp, merkle_ok))
}

/// Splits a wallet's master seed into `total_shares` `K-of-N` Shamir Guardian Shares.
pub fn cli_split_shamir_backup(
    wallet_path: &Path,
    threshold: u8,
    total_shares: u8,
    entropy: [u8; 32],
) -> io::Result<Vec<ShamirShare>> {
    let seed = load_wallet_seed(wallet_path)?;
    split_secret_shamir(&seed, threshold, total_shares, &entropy)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e.to_string()))
}

/// Reconstructs a wallet file from at least `K` comma-separated `xcrshare1_...` Guardian Share URIs.
pub fn cli_combine_shamir_backup(
    wallet_path: &Path,
    share_uris: &[&str],
) -> io::Result<(Address, String)> {
    let mut parsed = Vec::with_capacity(share_uris.len());
    for u in share_uris {
        let s = ShamirShare::from_uri(u)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e.to_string()))?;
        parsed.push(s);
    }
    let rec = combine_secret_shamir(&parsed)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e.to_string()))?;
    save_wallet_seed(wallet_path, rec.as_bytes())?;
    cli_stealth_address(wallet_path)
}

/// Exports the watch-only 33-byte `PublicKey` (`66` hex chars) of `wallet_path` so an online
/// watch-only device can prepare `xcrunsigned1_` QR codes without holding the private seed.
pub fn cli_export_watch_pubkey_hex(wallet_path: &Path) -> io::Result<(Address, String)> {
    let master = load_wallet_seed(wallet_path)?;
    let pocket_seed = domain_hash("XCR.WALLET.POCKET_KEY.V1", &[&master]).0;
    let kp = Keypair::from_seed(SignatureScheme::PasskeyP256, pocket_seed);
    let pk = kp.public_key();
    let hex66 = format!("{:02x}{}", pk.scheme as u8, pk.merkle_root.to_hex());
    Ok((kp.address(), hex66))
}

fn parse_watch_pubkey_hex(hex66: &str) -> Option<credit_crypto::PublicKey> {
    let s = hex66.trim();
    if s.len() != 66 {
        return None;
    }
    let scheme_byte = u8::from_str_radix(&s[0..2], 16).ok()?;
    let scheme = SignatureScheme::from_u8(scheme_byte)?;
    let mut root = [0u8; 32];
    for (i, pair) in s.as_bytes()[2..].as_chunks::<2>().0.iter().enumerate() {
        let hi = (pair[0] as char).to_digit(16)? as u8;
        let lo = (pair[1] as char).to_digit(16)? as u8;
        root[i] = (hi << 4) | lo;
    }
    Some(credit_crypto::PublicKey {
        scheme,
        merkle_root: Hash32::from_bytes(root),
    })
}

/// Online Watch-Only Step 1: Prepares an `xcrunsigned1_` QR request + public `672B` Bulletproof
/// bundle file without needing any private key!
#[allow(clippy::too_many_arguments)]
pub fn cli_cold_prepare(
    sender_pubkey_hex66: &str,
    recipient_str: &str,
    amount: Amount,
    fee: Amount,
    memo: &str,
    entropy: [u8; 32],
    bundle_path: &Path,
    node_addr: SocketAddr,
) -> io::Result<(String, String)> {
    let sender_pk = parse_watch_pubkey_hex(sender_pubkey_hex66).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid 66-hex watch-only pubkey (run `credit-cli export-pubkey` on cold wallet)",
        )
    })?;
    let from = sender_pk.to_address();
    let NodeRpcResponse::PocketInfo {
        found: true, nonce, ..
    } = rpc_call(
        node_addr,
        &NodeRpcRequest::GetPocket { address: from },
        DEFAULT_RPC_TIMEOUT,
    )?
    else {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            "sender Pocket not registered on node",
        ));
    };

    let (target_meta, uri_amt, uri_memo) = resolve_recipient_destination(None, recipient_str);
    let final_amount = uri_amt.filter(|a| !a.is_zero()).unwrap_or(amount);
    let final_memo = if !memo.trim().is_empty() {
        memo.trim().to_owned()
    } else {
        uri_memo.unwrap_or_default()
    };

    let (stealth_out, shared_secret) = derive_stealth_output(&target_meta, &entropy);
    let gamma =
        Scalar::hash_from_parts("XCR.COLD.GAMMA.V1", &[&shared_secret, &nonce.to_le_bytes()]);
    let bp_seed = domain_hash("XCR.COLD.BP.V1", &[&shared_secret, &nonce.to_le_bytes()]).0;
    let (v_commit, bp_proof) = BulletproofRange64::prove(final_amount, gamma, 64, &bp_seed)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "Bulletproof prove failed"))?;
    let bp_bytes = bp_proof.to_bytes();
    let enc_memo = encrypt_stealth_memo(&shared_secret, &final_memo);

    let unsigned = UnsignedColdTransfer {
        from,
        to_stealth: stealth_out.one_time_address,
        stealth_view_tag: stealth_out.view_tag,
        amount: final_amount,
        fee,
        nonce,
        value_commitment: v_commit.to_bytes(),
    };
    let unsigned_uri = unsigned.to_uri();
    let qr_str = unsigned
        .to_qr_code()
        .map(|q| q.to_terminal_unicode())
        .unwrap_or_default();

    // Persist public-only bundle (`unsigned_uri\nsender_pubkey_hex66\neph_hex\nbp_hex\nmemo_hex`):
    let mut bundle_txt = String::new();
    bundle_txt.push_str(&unsigned_uri);
    bundle_txt.push('\n');
    bundle_txt.push_str(sender_pubkey_hex66.trim());
    bundle_txt.push('\n');
    bundle_txt.push_str(&Hash32::from_bytes(stealth_out.ephemeral_pub).to_hex());
    bundle_txt.push('\n');
    for b in &bp_bytes {
        bundle_txt.push_str(&format!("{b:02x}"));
    }
    bundle_txt.push('\n');
    for b in &enc_memo {
        bundle_txt.push_str(&format!("{b:02x}"));
    }
    bundle_txt.push('\n');
    fs::write(bundle_path, bundle_txt)?;
    Ok((unsigned_uri, qr_str))
}

/// Air-Gapped Offline Step 2: Signs `xcrunsigned1_...` completely offline (`0` sockets opened)
/// and returns `(UnsignedColdTransfer, signed_uri, terminal_qr)`.
pub fn cli_cold_sign_offline(
    wallet_path: &Path,
    unsigned_uri: &str,
) -> io::Result<(UnsignedColdTransfer, String, String)> {
    let unsigned = UnsignedColdTransfer::from_uri(unsigned_uri).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid `xcrunsigned1_` URI payload",
        )
    })?;
    let master = load_wallet_seed(wallet_path)?;
    let signed = unsigned
        .sign_offline(&master)
        .map_err(|e| io::Error::new(io::ErrorKind::PermissionDenied, e))?;
    let s_uri = signed.to_uri();
    let qr_str = signed
        .to_qr_code()
        .map(|q| q.to_terminal_unicode())
        .unwrap_or_default();
    Ok((unsigned, s_uri, qr_str))
}

/// Online Watch-Only Step 3: Verifies `xcrsigned1_...` against the public bundle and broadcasts in 1 RTT!
pub fn cli_cold_broadcast(
    bundle_path: &Path,
    signed_uri: &str,
    node_addr: SocketAddr,
) -> io::Result<NodeRpcResponse> {
    let raw = fs::read_to_string(bundle_path)?;
    let mut lines = raw.lines();
    let u_uri = lines
        .next()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "corrupt bundle"))?;
    let pk_hex = lines
        .next()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "corrupt bundle"))?;
    let eph_hex = lines
        .next()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "corrupt bundle"))?;
    let bp_hex = lines
        .next()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "corrupt bundle"))?;
    let memo_hex = lines.next().unwrap_or("");

    let unsigned = UnsignedColdTransfer::from_uri(u_uri)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "invalid unsigned in bundle"))?;
    let sender_pk = parse_watch_pubkey_hex(pk_hex)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "invalid pubkey in bundle"))?;
    let signed = SignedColdTransfer::from_uri(signed_uri)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "invalid `xcrsigned1_` URI"))?;
    let tx = unsigned
        .attach_verified_signature(&signed, &sender_pk)
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::PermissionDenied,
                "air-gapped signature verification failed!",
            )
        })?;

    let decode_hex_vec = |s: &str| -> Option<Vec<u8>> {
        if !s.len().is_multiple_of(2) {
            return None;
        }
        let mut out = Vec::with_capacity(s.len() / 2);
        for p in s.as_bytes().as_chunks::<2>().0 {
            let hi = (p[0] as char).to_digit(16)? as u8;
            let lo = (p[1] as char).to_digit(16)? as u8;
            out.push((hi << 4) | lo);
        }
        Some(out)
    };
    let eph_vec = decode_hex_vec(eph_hex)
        .filter(|v| v.len() == 32)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "invalid eph in bundle"))?;
    let mut ephemeral_pub = [0u8; 32];
    ephemeral_pub.copy_from_slice(&eph_vec);
    let bulletproof_672 = decode_hex_vec(bp_hex)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "invalid bp in bundle"))?;
    let encrypted_memo = decode_hex_vec(memo_hex).unwrap_or_default();

    let resp = rpc_call(
        node_addr,
        &NodeRpcRequest::SubmitBulletproofFastPay {
            tx,
            value_commitment: unsigned.value_commitment,
            bulletproof_672,
        },
        DEFAULT_RPC_TIMEOUT,
    )?;
    if matches!(resp, NodeRpcResponse::FastPayReceipt { accepted: true, .. }) {
        let _ = rpc_call(
            node_addr,
            &NodeRpcRequest::AnnounceStealthOutputV2 {
                one_time_address: unsigned.to_stealth,
                ephemeral_pub,
                view_tag: unsigned.stealth_view_tag,
                encrypted_memo,
            },
            Duration::from_millis(2_500),
        );
    }
    Ok(resp)
}

/// Multi-recipient batch payout (`"dest1:4.50:Coffee,dest2:0.50:Tip"`), pre-validating total balance
/// and proving all `672B` Bulletproofs in parallel across CPU cores before pipelining over 1 socket!
pub fn cli_send_multi_payout(
    wallet_path: &Path,
    batch_spec: &str,
    node_addr: SocketAddr,
) -> io::Result<Vec<(String, Amount, Hash32, u16)>> {
    let mut legs: Vec<(String, Amount, String)> = Vec::new();
    for item in batch_spec
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        let mut parts = item.splitn(3, ':');
        let dest = parts.next().unwrap_or("").trim();
        let amt_s = parts.next().unwrap_or("").trim();
        let note = parts.next().unwrap_or("").trim();
        let amt = parse_decimal_xcr(amt_s)
            .filter(|a| !a.is_zero())
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("invalid leg `{item}` (expected `dest:amount_xcr[:memo]`)"),
                )
            })?;
        if dest.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "empty recipient in batch",
            ));
        }
        legs.push((dest.to_owned(), amt, note.to_owned()));
    }
    if legs.is_empty() || legs.len() > 16 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "batch must contain 1..=16 recipients",
        ));
    }

    let master = load_wallet_seed(wallet_path)?;
    let pocket_seed = domain_hash("XCR.WALLET.POCKET_KEY.V1", &[&master]).0;
    let mut kp = Keypair::from_seed(SignatureScheme::PasskeyP256, pocket_seed);
    let from = kp.address();

    let NodeRpcResponse::PocketInfo {
        found: true,
        balance,
        nonce: base_nonce,
        ..
    } = rpc_call(
        node_addr,
        &NodeRpcRequest::GetPocket { address: from },
        DEFAULT_RPC_TIMEOUT,
    )?
    else {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            "wallet Pocket not registered on node",
        ));
    };

    let fee = Amount::from_bits(500);
    let mut total_needed = Amount::ZERO;
    for (_, amt, _) in &legs {
        total_needed = total_needed
            .checked_add(*amt)
            .and_then(|s| s.checked_add(fee))
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "batch amount overflow"))?;
    }
    if balance < total_needed {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "insufficient Pocket balance ({}) for total batch ({})",
                balance.format_symbolic(),
                total_needed.format_symbolic()
            ),
        ));
    }

    let targets: Vec<_> = legs
        .iter()
        .map(|(dest, amt, note)| {
            let (meta, _, _) = resolve_recipient_destination(Some(wallet_path), dest);
            (dest.clone(), meta, *amt, note.clone())
        })
        .collect();

    // Prove all N `672B` Bulletproofs in parallel across CPU cores!
    let proved: Vec<_> = std::thread::scope(|s| {
        let mut handles = Vec::with_capacity(targets.len());
        for (idx, (dest, meta, amt, note)) in targets.into_iter().enumerate() {
            let seq_nonce = base_nonce + idx as u64;
            let m_copy = master;
            handles.push(s.spawn(move || {
                let eph_seed = domain_hash(
                    "XCR.CLI.BATCH_EPH.V1",
                    &[&m_copy, &seq_nonce.to_le_bytes(), dest.as_bytes()],
                )
                .0;
                let (stealth_out, shared) = derive_stealth_output(&meta, &eph_seed);
                let gamma = Scalar::hash_from_parts(
                    "XCR.CLI.BP_GAMMA.V1",
                    &[&shared, &seq_nonce.to_le_bytes()],
                );
                let bp_seed =
                    domain_hash("XCR.CLI.BP_SEED.V1", &[&shared, &seq_nonce.to_le_bytes()]).0;
                let (vc, bp) = BulletproofRange64::prove(amt, gamma, 64, &bp_seed).unwrap();
                let enc_memo = encrypt_stealth_memo(&shared, &note);
                (
                    dest,
                    amt,
                    note,
                    seq_nonce,
                    stealth_out,
                    vc.to_bytes(),
                    bp.to_bytes(),
                    enc_memo,
                )
            }));
        }
        handles.into_iter().map(|h| h.join().unwrap()).collect()
    });

    let mut ch = PersistentRpcChannel::connect(node_addr)?;
    let mut receipts = Vec::with_capacity(proved.len());
    for (dest, amt, note, seq_nonce, stealth_out, vc_bytes, bp_bytes, enc_memo) in proved {
        let commitment_hash = domain_hash("XCR.CLI.COMMIT_TAG.V1", &[&vc_bytes]);
        let kind = TransactionKind::FastTransfer {
            from,
            to_stealth: stealth_out.one_time_address,
            stealth_view_tag: stealth_out.view_tag,
            amount: amt,
            fee,
            nonce: seq_nonce,
            commitment: commitment_hash,
            innocence_nullifier: None,
        };
        let tx_id = tx_signing_digest(&kind);
        let sig_bytes = kp.sign(tx_id.as_bytes()).to_bytes();
        let resp = ch.call(
            &NodeRpcRequest::SubmitBulletproofFastPay {
                tx: Transaction {
                    id: tx_id,
                    kind,
                    signature_bytes: sig_bytes,
                },
                value_commitment: vc_bytes,
                bulletproof_672: bp_bytes,
            },
            DEFAULT_RPC_TIMEOUT,
        )?;
        match resp {
            NodeRpcResponse::FastPayReceipt {
                accepted: true,
                tx_id,
                finality_latency_ms,
                ..
            } => {
                let _ = ch.call(
                    &NodeRpcRequest::AnnounceStealthOutputV2 {
                        one_time_address: stealth_out.one_time_address,
                        ephemeral_pub: stealth_out.ephemeral_pub,
                        view_tag: stealth_out.view_tag,
                        encrypted_memo: enc_memo,
                    },
                    Duration::from_millis(2_500),
                );
                EncryptedActivityLog::append_and_persist(
                    &wallet_path.with_extension("history"),
                    &master,
                    "sent",
                    amt,
                    tx_id.to_hex(),
                    format!("{dest}: {note}"),
                );
                receipts.push((dest, amt, tx_id, finality_latency_ms));
            }
            NodeRpcResponse::FastPayReceipt { message, .. } => {
                return Err(io::Error::other(format!(
                    "batch leg `{dest}` rejected: {message}"
                )));
            }
            other => {
                return Err(io::Error::other(format!("unexpected reply: {other:?}")));
            }
        }
    }
    Ok(receipts)
}

/// Generates `ways` equal-share `xcr:` invoice URIs + terminal QR codes for splitting a group tab.
pub fn cli_split_bill_invoices(
    wallet_path: &Path,
    total_amount: Amount,
    ways: u64,
    memo: &str,
) -> io::Result<Vec<(u64, Amount, String)>> {
    if ways == 0 || ways > 32 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "ways must be 1..=32",
        ));
    }
    let (_, stealth_uri) = cli_stealth_address(wallet_path)?;
    let each_bits = total_amount.bits() / ways;
    let rem_bits = total_amount.bits() % ways;
    let mut out = Vec::with_capacity(ways as usize);
    for idx in 1..=ways {
        let share_bits = if idx == 1 {
            each_bits + rem_bits
        } else {
            each_bits
        };
        let amt = Amount::from_bits(share_bits);
        let inv = format!("SPLIT-{idx}of{ways}");
        let uri = PaymentRequestUri::new(&stealth_uri)
            .with_amount(amt)
            .with_invoice(inv)
            .with_memo(memo)
            .to_uri();
        out.push((idx, amt, uri));
    }
    Ok(out)
}

/// Manages pull-free recurring subscriptions stored AEAD-encrypted in `<wallet>.subs`.
pub fn cli_list_subscriptions(wallet_path: &Path) -> io::Result<Vec<SubscriptionMandate>> {
    let seed = load_wallet_seed(wallet_path)?;
    let book = SubscriptionBook::load(&wallet_path.with_extension("subs"), &seed);
    Ok(book.mandates().to_vec())
}

pub fn cli_add_subscription(
    wallet_path: &Path,
    label: &str,
    recipient: &str,
    amount: Amount,
    interval_secs: u64,
    now_unix: u64,
) -> io::Result<u64> {
    let seed = load_wallet_seed(wallet_path)?;
    let sub_path = wallet_path.with_extension("subs");
    let mut book = SubscriptionBook::load(&sub_path, &seed);
    let id = book.add_mandate(label, recipient, amount, interval_secs, now_unix);
    book.save(&sub_path, &seed)?;
    Ok(id)
}

pub fn cli_cancel_subscription(wallet_path: &Path, id: u64) -> io::Result<bool> {
    let seed = load_wallet_seed(wallet_path)?;
    let sub_path = wallet_path.with_extension("subs");
    let mut book = SubscriptionBook::load(&sub_path, &seed);
    let ok = book.cancel(id);
    if ok {
        book.save(&sub_path, &seed)?;
    }
    Ok(ok)
}

pub fn cli_run_due_subscriptions(
    wallet_path: &Path,
    now_unix: u64,
    node_addr: SocketAddr,
) -> io::Result<Vec<(u64, String, Amount, Hash32)>> {
    let seed = load_wallet_seed(wallet_path)?;
    let sub_path = wallet_path.with_extension("subs");
    let mut book = SubscriptionBook::load(&sub_path, &seed);
    let due = book.due_mandates(now_unix);
    let mut paid = Vec::new();
    for m in due {
        let cycle_memo = format!(
            "SUB#{}: {} (Cycle #{})",
            m.id,
            m.label,
            m.completed_cycles + 1
        );
        if let Ok(NodeRpcResponse::FastPayReceipt {
            accepted: true,
            tx_id,
            ..
        }) = cli_send_bulletproof_payment_with_memo(
            wallet_path,
            m.recipient.as_bytes(),
            m.amount,
            Amount::from_bits(500),
            &cycle_memo,
            node_addr,
        ) {
            book.mark_cycle_paid(m.id, now_unix);
            paid.push((m.id, m.label, m.amount, tx_id));
        }
    }
    if !paid.is_empty() {
        book.save(&sub_path, &seed)?;
    }
    Ok(paid)
}

/// Exports the wallet's 24-word checksummed paper backup phrase and numbered recovery card.
pub fn cli_export_backup_words(wallet_path: &Path) -> io::Result<(String, String)> {
    let seed = load_wallet_seed(wallet_path)?;
    Ok((encode_mnemonic_24(&seed), format_backup_card_24(&seed)))
}

/// Recovers a wallet file from a 24-word checksummed paper backup phrase.
pub fn cli_recover_from_words(
    wallet_path: &Path,
    words_phrase: &str,
) -> io::Result<(Address, String)> {
    let seed = decode_mnemonic_24(words_phrase)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e.to_string()))?;
    save_wallet_seed(wallet_path, &seed)?;
    cli_stealth_address(wallet_path)
}

fn decode_hex32_cli(s: &str) -> Option<[u8; 32]> {
    let h = s.trim();
    if h.len() != 64 {
        return None;
    }
    let b = h.as_bytes();
    let mut out = [0u8; 32];
    for (i, pair) in b.as_chunks::<2>().0.iter().enumerate() {
        let hi = (pair[0] as char).to_digit(16)? as u8;
        let lo = (pair[1] as char).to_digit(16)? as u8;
        out[i] = (hi << 4) | lo;
    }
    Some(out)
}

/// Resolves either a full 64-hex `Address` or a short `xcr1_<prefix>` via `InspectQuery` RPC.
pub fn cli_resolve_pocket_address(addr_str: &str, node_addr: SocketAddr) -> io::Result<Address> {
    let trimmed = addr_str.trim();
    if let Some(raw) = decode_hex32_cli(trimmed) {
        return Ok(Address::from_bytes(raw));
    }
    if let Ok(NodeRpcResponse::InspectResult {
        kind: 1, address, ..
    }) = rpc_call(
        node_addr,
        &NodeRpcRequest::InspectQuery {
            query: trimmed.to_owned(),
        },
        DEFAULT_RPC_TIMEOUT,
    ) {
        return Ok(address);
    }
    Err(io::Error::new(
        io::ErrorKind::InvalidInput,
        format!("could not resolve registered Pocket address `{trimmed}`"),
    ))
}

// ============================================================================
// Wave 7: FROST Threshold Schnorr, HTLCs, PayChan, Digital Checks & Swap Offers
// ============================================================================

pub fn cli_frost_split(
    wallet_path: &Path,
    threshold: u8,
    total_shares: u8,
    entropy: [u8; 32],
) -> io::Result<Vec<FrostKeyShare>> {
    let seed = load_wallet_seed(wallet_path)?;
    frost_split_pocket_key(&seed, threshold, total_shares, &entropy)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e.to_string()))
}

pub fn cli_frost_commit_nonce(share_uri: &str, entropy: [u8; 32]) -> io::Result<(String, String)> {
    let share = FrostKeyShare::from_uri(share_uri)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e.to_string()))?;
    let sec = frost_commit_nonce(&share, &entropy);
    let pub_uri = sec.commit.to_uri();
    Ok((sec.to_uri(), pub_uri))
}

pub fn cli_frost_sign_partial(
    share_uri: &str,
    nonce_sec_uri: &str,
    commits_csv: &str,
    unsigned_uri: &str,
) -> io::Result<String> {
    let share = FrostKeyShare::from_uri(share_uri)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e.to_string()))?;
    let nsec = FrostNonceSecret::from_uri(nonce_sec_uri)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e.to_string()))?;
    let unsigned = UnsignedColdTransfer::from_uri(unsigned_uri)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "invalid xcrunsigned1_ URI"))?;
    let mut commits = Vec::new();
    for item in commits_csv
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        commits.push(
            FrostNonceCommit::from_uri(item)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e.to_string()))?,
        );
    }
    let part = frost_sign_partial(
        &share,
        &nsec,
        &commits,
        unsigned.signing_digest().as_bytes(),
    )
    .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e.to_string()))?;
    Ok(part.to_uri())
}

pub fn cli_frost_aggregate_cold(
    group_pubkey_hex66: &str,
    commits_csv: &str,
    partials_csv: &str,
    unsigned_uri: &str,
) -> io::Result<String> {
    let pk = parse_watch_pubkey_hex(group_pubkey_hex66).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid 66-hex watch-only pubkey",
        )
    })?;
    let unsigned = UnsignedColdTransfer::from_uri(unsigned_uri)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "invalid xcrunsigned1_ URI"))?;
    let mut commits = Vec::new();
    for item in commits_csv
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        commits.push(
            FrostNonceCommit::from_uri(item)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e.to_string()))?,
        );
    }
    let mut partials = Vec::new();
    for item in partials_csv
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        partials.push(
            FrostPartialSig::from_uri(item)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e.to_string()))?,
        );
    }
    let signed =
        frost_aggregate_cold_transfer(&unsigned, pk.merkle_root.as_bytes(), &commits, &partials)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e.to_string()))?;
    Ok(signed.to_uri())
}

pub fn cli_generate_htlc_secret(entropy: [u8; 32]) -> (String, String) {
    let (pre, hl) = generate_htlc_secret(&entropy);
    (Hash32(pre).to_hex(), hl.to_hex())
}

pub fn cli_htlc_lock(
    wallet_path: &Path,
    recipient_str: &str,
    amount: Amount,
    hashlock_hex: &str,
    expiry_unix: u64,
    salt: [u8; 16],
    node_addr: SocketAddr,
) -> io::Result<NodeRpcResponse> {
    let seed = load_wallet_seed(wallet_path)?;
    let recipient = cli_resolve_pocket_address(recipient_str, node_addr)?;
    let hl_bytes = decode_hex32_cli(hashlock_hex).ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidInput, "hashlock must be 64 hex chars")
    })?;
    let hashlock = Hash32::from_bytes(hl_bytes);
    let fee = Amount::from_bits(MIN_BASE_FEE_BITS);
    let (sender, sender_pubkey, escrow_id, sig65) =
        sign_htlc_lock(&seed, &recipient, amount, fee, &hashlock, expiry_unix, salt);
    rpc_call(
        node_addr,
        &NodeRpcRequest::LockHtlc {
            escrow_id,
            sender,
            sender_pubkey,
            recipient,
            amount,
            fee,
            hashlock,
            expiry_unix,
            salt,
            sig65,
        },
        DEFAULT_RPC_TIMEOUT,
    )
}

pub fn cli_htlc_claim(
    escrow_hex: &str,
    preimage_hex: &str,
    node_addr: SocketAddr,
) -> io::Result<NodeRpcResponse> {
    let escrow_id = Hash32::from_bytes(decode_hex32_cli(escrow_hex).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "escrow-id must be 64 hex chars",
        )
    })?);
    let preimage = decode_hex32_cli(preimage_hex).ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidInput, "preimage must be 64 hex chars")
    })?;
    rpc_call(
        node_addr,
        &NodeRpcRequest::ClaimHtlc {
            escrow_id,
            preimage,
        },
        DEFAULT_RPC_TIMEOUT,
    )
}

pub fn cli_htlc_refund(escrow_hex: &str, node_addr: SocketAddr) -> io::Result<NodeRpcResponse> {
    let escrow_id = Hash32::from_bytes(decode_hex32_cli(escrow_hex).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "escrow-id must be 64 hex chars",
        )
    })?);
    rpc_call(
        node_addr,
        &NodeRpcRequest::RefundHtlc { escrow_id },
        DEFAULT_RPC_TIMEOUT,
    )
}

pub fn cli_htlc_list(node_addr: SocketAddr) -> io::Result<Vec<HtlcWireRecord>> {
    match rpc_call(node_addr, &NodeRpcRequest::GetHtlcs, DEFAULT_RPC_TIMEOUT)? {
        NodeRpcResponse::HtlcList { escrows } => Ok(escrows),
        other => Err(io::Error::other(format!(
            "unexpected HTLC reply: {other:?}"
        ))),
    }
}

pub fn cli_paychan_open(
    wallet_path: &Path,
    payee_str: &str,
    deposit: Amount,
    expiry_unix: u64,
    salt: [u8; 16],
    node_addr: SocketAddr,
) -> io::Result<NodeRpcResponse> {
    let seed = load_wallet_seed(wallet_path)?;
    let payee = cli_resolve_pocket_address(payee_str, node_addr)?;
    let fee = Amount::from_bits(MIN_BASE_FEE_BITS);
    let (payer, payer_pubkey, channel_id, sig65) =
        sign_paychan_open(&seed, &payee, deposit, fee, expiry_unix, salt);
    rpc_call(
        node_addr,
        &NodeRpcRequest::OpenPayChannel {
            channel_id,
            payer,
            payer_pubkey,
            payee,
            deposit,
            fee,
            expiry_unix,
            salt,
            sig65,
        },
        DEFAULT_RPC_TIMEOUT,
    )
}

pub fn cli_paychan_tick_offline(
    wallet_path: &Path,
    channel_hex: &str,
    cumulative_amount: Amount,
) -> io::Result<String> {
    let seed = load_wallet_seed(wallet_path)?;
    let channel_id = Hash32::from_bytes(decode_hex32_cli(channel_hex).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "channel-id must be 64 hex chars",
        )
    })?);
    Ok(PayChanVoucher::sign_tick(&seed, channel_id, cumulative_amount).to_uri())
}

pub fn cli_paychan_close(voucher_uri: &str, node_addr: SocketAddr) -> io::Result<NodeRpcResponse> {
    let v = PayChanVoucher::from_uri(voucher_uri).ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidInput, "invalid xcrchan1_ voucher URI")
    })?;
    rpc_call(
        node_addr,
        &NodeRpcRequest::ClosePayChannel {
            channel_id: v.channel_id,
            cumulative_amount: v.cumulative_amount,
            voucher_sig65: v.signature_65,
        },
        DEFAULT_RPC_TIMEOUT,
    )
}

pub fn cli_paychan_list(node_addr: SocketAddr) -> io::Result<Vec<PayChanWireRecord>> {
    match rpc_call(
        node_addr,
        &NodeRpcRequest::GetPayChannels,
        DEFAULT_RPC_TIMEOUT,
    )? {
        NodeRpcResponse::PayChannelList { channels } => Ok(channels),
        other => Err(io::Error::other(format!(
            "unexpected PayChan reply: {other:?}"
        ))),
    }
}

pub fn cli_check_issue(
    wallet_path: &Path,
    payee_str: &str,
    max_amount: Amount,
    expiry_unix: u64,
    salt: [u8; 16],
    node_addr: SocketAddr,
) -> io::Result<(Hash32, String)> {
    let seed = load_wallet_seed(wallet_path)?;
    let payee = cli_resolve_pocket_address(payee_str, node_addr)?;
    let chk = DigitalCheck::issue(&seed, payee, max_amount, expiry_unix, salt)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
    Ok((chk.check_id, chk.to_uri()))
}

pub fn cli_check_cash(
    payee_wallet: &Path,
    check_uri: &str,
    actual_amount: Amount,
    node_addr: SocketAddr,
) -> io::Result<NodeRpcResponse> {
    let seed = load_wallet_seed(payee_wallet)?;
    let chk = DigitalCheck::from_uri(check_uri).ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidInput, "invalid xcrcheck1_ check URI")
    })?;
    let (actor_pubkey, actor_sig65) = sign_check_cash(&seed, &chk, actual_amount)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
    rpc_call(
        node_addr,
        &NodeRpcRequest::CashOrCancelCheck {
            is_cancel: false,
            check_bytes: chk.to_bytes().to_vec(),
            check_id: chk.check_id,
            actor_pubkey,
            actual_amount,
            actor_sig65,
        },
        DEFAULT_RPC_TIMEOUT,
    )
}

pub fn cli_check_cancel(
    drawer_wallet: &Path,
    check_uri: &str,
    node_addr: SocketAddr,
) -> io::Result<NodeRpcResponse> {
    let seed = load_wallet_seed(drawer_wallet)?;
    let chk = DigitalCheck::from_uri(check_uri).ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidInput, "invalid xcrcheck1_ check URI")
    })?;
    let (_, actor_pubkey, actor_sig65) = sign_check_cancel(&seed, &chk.check_id);
    rpc_call(
        node_addr,
        &NodeRpcRequest::CashOrCancelCheck {
            is_cancel: true,
            check_bytes: chk.to_bytes().to_vec(),
            check_id: chk.check_id,
            actor_pubkey,
            actual_amount: Amount::ZERO,
            actor_sig65,
        },
        DEFAULT_RPC_TIMEOUT,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn cli_post_swap_offer(
    wallet_path: &Path,
    xcr_amount: Amount,
    counter_asset: &str,
    counter_amount: &str,
    hashlock_hex: &str,
    timelock_secs: u64,
    expiry_unix: u64,
    node_addr: SocketAddr,
) -> io::Result<(String, NodeRpcResponse)> {
    let seed = load_wallet_seed(wallet_path)?;
    let hl = Hash32::from_bytes(decode_hex32_cli(hashlock_hex).ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidInput, "hashlock must be 64 hex chars")
    })?);
    let offer = AtomicSwapOffer::sign_new(
        &seed,
        xcr_amount,
        counter_asset,
        counter_amount,
        hl,
        timelock_secs,
        expiry_unix,
    )
    .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
    let uri = offer.to_uri();
    let resp = rpc_call(
        node_addr,
        &NodeRpcRequest::PostSwapOffer {
            offer_bytes: offer.to_bytes(),
        },
        DEFAULT_RPC_TIMEOUT,
    )?;
    Ok((uri, resp))
}

pub fn cli_list_swap_offers(node_addr: SocketAddr) -> io::Result<Vec<AtomicSwapOffer>> {
    match rpc_call(
        node_addr,
        &NodeRpcRequest::GetSwapOffers,
        DEFAULT_RPC_TIMEOUT,
    )? {
        NodeRpcResponse::SwapOfferList { offers } => Ok(offers
            .into_iter()
            .filter_map(|raw| AtomicSwapOffer::from_bytes(&raw))
            .collect()),
        other => Err(io::Error::other(format!(
            "unexpected SwapOffer reply: {other:?}"
        ))),
    }
}

// ============================================================================
// Wave 8: CredScript Smart Vaults, Session Keys, Native Assets & Crowdfunding
// ============================================================================

pub fn cli_build_inheritance_script(
    owner_wallet: &Path,
    heir_pubkey_hex66: &str,
    unlock_unix: u64,
) -> io::Result<(Hash32, String)> {
    let seed = load_wallet_seed(owner_wallet)?;
    let owner_pk = Keypair::from_seed(
        SignatureScheme::PasskeyP256,
        domain_hash("XCR.WALLET.POCKET_KEY.V1", &[&seed]).0,
    )
    .public_key();
    let heir_pk = parse_watch_pubkey_hex(heir_pubkey_hex66)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "invalid 66-hex heir pubkey"))?;
    let script = CredScript::inheritance_vault(owner_pk, heir_pk, unlock_unix);
    Ok((script.script_hash(), script.to_uri()))
}

pub fn cli_lock_script_vault(
    wallet_path: &Path,
    script_uri: &str,
    amount: Amount,
    salt: [u8; 16],
    node_addr: SocketAddr,
) -> io::Result<NodeRpcResponse> {
    let seed = load_wallet_seed(wallet_path)?;
    let script = CredScript::from_uri(script_uri)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "invalid xcrscript1_ URI"))?;
    let fee = Amount::from_bits(MIN_BASE_FEE_BITS);
    let (depositor, depositor_pubkey, vault_id, sig65) =
        sign_script_vault_lock(&seed, &script.script_hash(), amount, fee, salt);
    rpc_call(
        node_addr,
        &NodeRpcRequest::LockScriptVault {
            vault_id,
            depositor,
            depositor_pubkey,
            script_hash: script.script_hash(),
            amount,
            fee,
            salt,
            sig65,
        },
        DEFAULT_RPC_TIMEOUT,
    )
}

pub fn cli_spend_inheritance_vault(
    signer_wallet: &Path,
    vault_hex: &str,
    script_uri: &str,
    recipient_str: &str,
    amount: Amount,
    is_heir: bool,
    node_addr: SocketAddr,
) -> io::Result<NodeRpcResponse> {
    let seed = load_wallet_seed(signer_wallet)?;
    let vault_id = Hash32::from_bytes(decode_hex32_cli(vault_hex).ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidInput, "vault-id must be 64 hex chars")
    })?);
    let script = CredScript::from_uri(script_uri)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "invalid xcrscript1_ URI"))?;
    let dest = cli_resolve_pocket_address(recipient_str, node_addr)?;
    let payouts = vec![(dest, amount)];
    let digest = script_vault_spend_digest(&vault_id, &payouts);
    let mut kp = Keypair::from_seed(
        SignatureScheme::PasskeyP256,
        domain_hash("XCR.WALLET.POCKET_KEY.V1", &[&seed]).0,
    );
    let sig65: [u8; 65] = kp
        .sign(digest.as_bytes())
        .to_bytes()
        .try_into()
        .map_err(|_| io::Error::other("sig len"))?;
    let witness = if is_heir {
        vec![
            CredWitnessItem::Signature65([0u8; 65]),
            CredWitnessItem::Signature65(sig65),
        ]
    } else {
        vec![
            CredWitnessItem::Signature65(sig65),
            CredWitnessItem::Signature65([0u8; 65]),
        ]
    };
    rpc_call(
        node_addr,
        &NodeRpcRequest::SpendScriptVault {
            vault_id,
            script_bytes: script.to_bytes(),
            witness_bytes: encode_witness_stack(&witness),
            payouts,
        },
        DEFAULT_RPC_TIMEOUT,
    )
}

pub fn cli_issue_session_key(
    wallet_path: &Path,
    max_spend: Amount,
    allowed_recipient_opt: Option<&str>,
    expiry_unix: u64,
    entropy: [u8; 32],
    node_addr: SocketAddr,
) -> io::Result<(Hash32, String)> {
    let seed = load_wallet_seed(wallet_path)?;
    let allowed = match allowed_recipient_opt {
        Some(s) if !s.trim().is_empty() && s != "merchant-default" => {
            Some(cli_resolve_pocket_address(s, node_addr)?)
        }
        _ => None,
    };
    let grant = SessionKeyGrant::issue(&seed, max_spend, allowed, expiry_unix, entropy)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
    Ok((grant.session_id, grant.to_uri()))
}

pub fn cli_session_spend(
    session_uri: &str,
    recipient_str: &str,
    amount: Amount,
    sponsor_wallet: Option<&Path>,
    spend_salt: [u8; 16],
    node_addr: SocketAddr,
) -> io::Result<NodeRpcResponse> {
    let grant = SessionKeyGrant::from_uri(session_uri).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid xcrsk1_ session key URI",
        )
    })?;
    let recipient = cli_resolve_pocket_address(recipient_str, node_addr)?;
    let (spend_id, actor_sig65) = grant
        .sign_session_spend(recipient, amount, spend_salt)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
    let fee = Amount::from_bits(MIN_BASE_FEE_BITS);
    let sponsor = if let Some(sp_path) = sponsor_wallet {
        let sp_seed = load_wallet_seed(sp_path)?;
        Some(sign_fee_sponsorship(&sp_seed, &spend_id, fee))
    } else {
        None
    };
    rpc_call(
        node_addr,
        &NodeRpcRequest::ExecuteSessionKey {
            is_revoke: false,
            grant_bytes: grant.public_grant().to_bytes(),
            session_id: grant.session_id,
            spend_id,
            recipient,
            amount,
            fee,
            spend_salt,
            actor_pubkey: grant.session_pubkey,
            actor_sig65,
            sponsor,
        },
        DEFAULT_RPC_TIMEOUT,
    )
}

pub fn cli_session_revoke(
    owner_wallet: &Path,
    session_uri: &str,
    node_addr: SocketAddr,
) -> io::Result<NodeRpcResponse> {
    let seed = load_wallet_seed(owner_wallet)?;
    let grant = SessionKeyGrant::from_uri(session_uri).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid xcrsk1_ session key URI",
        )
    })?;
    let (_, actor_pubkey, actor_sig65) = sign_session_revoke(&seed, &grant.session_id);
    rpc_call(
        node_addr,
        &NodeRpcRequest::ExecuteSessionKey {
            is_revoke: true,
            grant_bytes: grant.public_grant().to_bytes(),
            session_id: grant.session_id,
            spend_id: Hash32::ZERO,
            recipient: Address::default(),
            amount: Amount::ZERO,
            fee: Amount::ZERO,
            spend_salt: [0u8; 16],
            actor_pubkey,
            actor_sig65,
            sponsor: None,
        },
        DEFAULT_RPC_TIMEOUT,
    )
}

pub fn cli_mint_native_asset(
    wallet_path: &Path,
    ticker: &str,
    total_supply: u64,
    salt: [u8; 16],
    node_addr: SocketAddr,
) -> io::Result<NodeRpcResponse> {
    let seed = load_wallet_seed(wallet_path)?;
    let fee = Amount::from_bits(MIN_BASE_FEE_BITS);
    let mint = NativeAssetMint::sign_new(&seed, ticker, total_supply, 0, fee, salt)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
    rpc_call(
        node_addr,
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
        DEFAULT_RPC_TIMEOUT,
    )
}

pub fn cli_transfer_native_asset(
    wallet_path: &Path,
    asset_hex: &str,
    recipient_str: &str,
    units: u64,
    salt: [u8; 16],
    node_addr: SocketAddr,
) -> io::Result<NodeRpcResponse> {
    let seed = load_wallet_seed(wallet_path)?;
    let asset_id = Hash32::from_bytes(decode_hex32_cli(asset_hex).ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidInput, "asset-id must be 64 hex chars")
    })?);
    let recipient = cli_resolve_pocket_address(recipient_str, node_addr)?;
    let fee = Amount::from_bits(MIN_BASE_FEE_BITS);
    let (sender, sender_pubkey, xfer_id, sig65) =
        sign_asset_transfer(&seed, &asset_id, &recipient, units, fee, salt);
    rpc_call(
        node_addr,
        &NodeRpcRequest::TransferNativeAsset {
            xfer_id,
            asset_id,
            sender,
            sender_pubkey,
            recipient,
            units,
            fee,
            salt,
            sig65,
        },
        DEFAULT_RPC_TIMEOUT,
    )
}

pub fn cli_list_native_assets(
    wallet_opt: Option<&Path>,
    node_addr: SocketAddr,
) -> io::Result<Vec<AssetWireRecord>> {
    let owner = wallet_opt.and_then(|p| {
        load_wallet_seed(p).ok().map(|s| {
            Keypair::from_seed(
                SignatureScheme::PasskeyP256,
                domain_hash("XCR.WALLET.POCKET_KEY.V1", &[&s]).0,
            )
            .address()
        })
    });
    match rpc_call(
        node_addr,
        &NodeRpcRequest::GetAssetBalances { owner },
        DEFAULT_RPC_TIMEOUT,
    )? {
        NodeRpcResponse::AssetPortfolio { assets } => Ok(assets),
        other => Err(io::Error::other(format!(
            "unexpected Asset reply: {other:?}"
        ))),
    }
}

pub fn cli_create_campaign(
    wallet_path: &Path,
    beneficiary_str: &str,
    title: &str,
    goal_amount: Amount,
    deadline_unix: u64,
    salt: [u8; 16],
    node_addr: SocketAddr,
) -> io::Result<NodeRpcResponse> {
    let seed = load_wallet_seed(wallet_path)?;
    let beneficiary = cli_resolve_pocket_address(beneficiary_str, node_addr)?;
    let (creator, creator_pubkey, campaign_id, sig65) =
        sign_crowdfund_create(&seed, &beneficiary, title, goal_amount, deadline_unix, salt)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
    rpc_call(
        node_addr,
        &NodeRpcRequest::CreateCampaign {
            campaign_id,
            creator,
            creator_pubkey,
            beneficiary,
            title: title.trim().to_owned(),
            goal_amount,
            deadline_unix,
            salt,
            sig65,
        },
        DEFAULT_RPC_TIMEOUT,
    )
}

pub fn cli_pledge_campaign(
    wallet_path: &Path,
    campaign_hex: &str,
    amount: Amount,
    salt: [u8; 16],
    node_addr: SocketAddr,
) -> io::Result<NodeRpcResponse> {
    let seed = load_wallet_seed(wallet_path)?;
    let campaign_id = Hash32::from_bytes(decode_hex32_cli(campaign_hex).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "campaign-id must be 64 hex chars",
        )
    })?);
    let fee = Amount::from_bits(MIN_BASE_FEE_BITS);
    let (backer, backer_pubkey, pledge_id, sig65) =
        sign_crowdfund_pledge(&seed, &campaign_id, amount, fee, salt);
    rpc_call(
        node_addr,
        &NodeRpcRequest::PledgeCampaign {
            pledge_id,
            campaign_id,
            backer,
            backer_pubkey,
            amount,
            fee,
            salt,
            sig65,
        },
        DEFAULT_RPC_TIMEOUT,
    )
}

pub fn cli_finalize_campaign(
    campaign_hex: &str,
    node_addr: SocketAddr,
) -> io::Result<NodeRpcResponse> {
    let campaign_id = Hash32::from_bytes(decode_hex32_cli(campaign_hex).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "campaign-id must be 64 hex chars",
        )
    })?);
    rpc_call(
        node_addr,
        &NodeRpcRequest::FinalizeCampaign { campaign_id },
        DEFAULT_RPC_TIMEOUT,
    )
}

pub fn cli_supply_audit(node_addr: SocketAddr) -> io::Result<NodeRpcResponse> {
    rpc_call(
        node_addr,
        &NodeRpcRequest::GetSupplyAndContractsSummary,
        DEFAULT_RPC_TIMEOUT,
    )
}
