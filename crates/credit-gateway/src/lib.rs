//! Stage-4 **Zero-Dependency HTTP/JSON Consumer Wallet & Merchant POS Gateway** (`credit-gateway`).
//!
//! Exposes a lightweight `std::net::TcpListener` HTTP/1.1 server backed by real Curve25519
//! 672-byte `BulletproofRange64` range proofs, Privacy Pool `ProofOfInnocence` verification,
//! encrypted `ISO-20022` commercial receipts, `Savings Vault` wrench-attack cancellation,
//! `MobileLightClient` Merkle proofs, and `PersistentLedger` (`XCRWAL01`) crash-safe storage.

pub mod explorer;
pub mod jsonrpc;
pub mod live_wallet;
pub mod ui;
pub mod webhook;

use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::Path;

use credit_consensus::{
    EpochLifecycleEngine, FastPathEngine, MAINNET_GENESIS_UNIX, VerifiableGenesisBeacon,
};
use credit_crypto::{Keypair, Scalar, SignatureScheme, domain_hash};
use credit_ponc::{ComputeShare, EpochShareDag, PoncVmConfig};
use credit_sdk::{
    CreditWallet, PaymentRequestUri, QrCode, encode_mnemonic_24, format_well_known_pay_json,
    parse_decimal_xcr,
};
use credit_storage::{PersistentLedger, WalRecord};
use credit_types::{Address, Amount, EpochId, MaturityMetrics, MonetaryPhase};
use credit_zk::{
    AssociationTree, AuthenticatedStateTree, BlindedCommitment, BulletproofRange64, Iso20022Memo,
    StateLeaf,
};

use crate::ui::WALLET_AND_POS_HTML;

struct GatewayRuntime {
    ledger: PersistentLedger,
    lifecycle: EpochLifecycleEngine,
    validators: Vec<(Address, Keypair)>,
    wallet: CreditWallet,
    merchant: CreditWallet,
    clean_tree: AssociationTree,
    clean_note: BlindedCommitment,
}

impl GatewayRuntime {
    fn open(data_dir: &Path) -> io::Result<Self> {
        let mut ledger = PersistentLedger::open(data_dir.join("gateway.wal"))?;

        let beacon = VerifiableGenesisBeacon {
            external_randomness_hex:
                "00000000000000000002a7c4c1e48d76c5a37902165a270156b7a8d72728a054".to_owned(),
            public_headline: "Credits (XCR) 1 January 2027 Fair Genesis — Money For All".to_owned(),
            launch_timestamp_unix: MAINNET_GENESIS_UNIX,
        };
        let mut lifecycle = EpochLifecycleEngine::from_fair_genesis(beacon, 1_000_000);

        let v1 = Keypair::from_seed(SignatureScheme::Ed25519, [0x11; 32]);
        let v2 = Keypair::from_seed(SignatureScheme::Ed25519, [0x22; 32]);
        let v3 = Keypair::from_seed(SignatureScheme::Ed25519, [0x33; 32]);
        let v4 = Keypair::from_seed(SignatureScheme::Ed25519, [0x44; 32]);
        let validators = vec![
            (v1.address(), v1),
            (v2.address(), v2),
            (v3.address(), v3),
            (v4.address(), v4),
        ];

        // Run Epoch 0 PoNC bootstrap so supply is 100% earned from Block 0:
        let dir: Vec<(Address, credit_crypto::PublicKey, u16)> = validators
            .iter()
            .enumerate()
            .map(|(i, (a, kp))| (*a, kp.public_key(), 150 + (i as u16) * 15))
            .collect();
        let vm_cfg = PoncVmConfig::devnet_profile();
        let mut dag0 = EpochShareDag::new(EpochId(0), lifecycle.current_epoch_seed, 3, vm_cfg);
        for (i, (addr, _)) in validators.iter().enumerate() {
            let sh = ComputeShare::mine_cpu_share(
                EpochId(0),
                &lifecycle.current_epoch_seed,
                *addr,
                dag0.tip_ids(2),
                (i as u64) * 60,
                3,
                &vm_cfg,
            );
            dag0.submit_share(sh).expect("valid gateway genesis share");
        }
        let r0 = lifecycle.advance_epoch(
            &dag0,
            Amount::ZERO,
            5_000,
            &dir,
            &MaturityMetrics {
                active_compute_nodes: 100,
                distinct_autonomous_systems: 25,
                consecutive_deep_epochs: 1,
            },
            &[],
            None,
        );

        let earned_pocket = r0.settlement.payouts[0].1; // ~25.000000 XCR earned via PoNC
        let mut wallet = CreditWallet::from_master_seed(
            [0x51; 32],
            earned_pocket,
            Amount::from_credits(50).unwrap(),
            Amount::from_credits(500).unwrap(),
            86_400_000,
        );
        let merchant = CreditWallet::from_master_seed(
            [0x62; 32],
            Amount::ZERO,
            Amount::from_credits(100).unwrap(),
            Amount::ZERO,
            86_400_000,
        );

        if ledger.circulating_supply.is_zero() && ledger.finalized_txs.is_empty() {
            let payouts = r0
                .settlement
                .payouts
                .iter()
                .map(|&(a, amt, _)| (a, amt))
                .collect();
            ledger.append(WalRecord::RecordEpochSettlement {
                epoch: EpochId(0),
                minted_emission: r0.settlement.minted_emission,
                worker_fees: Amount::ZERO,
                burned_fees: Amount::ZERO,
                payouts,
            })?;
            ledger.append(WalRecord::UpsertPocket {
                address: wallet.pocket_address(),
                public_key: wallet.pocket_public_key(),
                state: wallet.pocket.clone(),
            })?;
        } else if let Some(stored) = ledger.pockets.get(&wallet.pocket_address()) {
            wallet.pocket = stored.state.clone();
        }

        let mut clean_tree = AssociationTree::new(4);
        let clean_note = BlindedCommitment::commit(earned_pocket, &[0x73; 32]);
        clean_tree.set_clean_leaf(0, clean_note);

        Ok(Self {
            ledger,
            lifecycle,
            validators,
            wallet,
            merchant,
            clean_tree,
            clean_note,
        })
    }

    fn state_json(&self) -> String {
        let phase_label = match self.lifecycle.phase {
            MonetaryPhase::Phase1Bootstrap { .. } => "Phase 1 Sound Money",
            MonetaryPhase::Phase2GlobalBasket { .. } => "Phase 2 Global Basket",
        };
        let mut pending_items = String::new();
        for (idx, w) in self.wallet.vault.pending.iter().enumerate() {
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
            r#"{{"locked":false,"encrypted_on_disk":false,"epoch":{},"phase":"{}","circulating_supply":"{}","total_burned":"{}","state_root":"{}","pocket_address":"{}","stealth_uri":"{}","pocket_balance":"{}","pocket_daily_spent":"{}","pocket_daily_limit":"{}","pocket_nonce":{},"vault_balance":"{}","vault_pending":[{}]}}"#,
            self.lifecycle.current_epoch.0,
            phase_label,
            self.ledger.circulating_supply.format_symbolic(),
            self.ledger.total_burned.format_symbolic(),
            self.ledger.state_merkle_root(),
            self.wallet.pocket_address(),
            self.wallet.stealth_meta_address().to_uri(),
            self.wallet.pocket.balance.format_symbolic(),
            self.wallet.pocket.daily_spent.format_symbolic(),
            self.wallet.pocket.daily_limit.format_symbolic(),
            self.wallet.pocket.nonce,
            self.wallet.vault.balance.format_symbolic(),
            pending_items
        )
    }

    fn handle_pay(&mut self, chips: u64, invoice: &str, regulated: bool) -> io::Result<String> {
        let Some(amount) = Amount::from_chips(chips).filter(|a| !a.is_zero()) else {
            return Ok(r#"{"accepted":false,"error":"invalid chip amount"}"#.to_owned());
        };
        let fee = Amount::from_bits(500);

        // 1. Generate real 672-byte 64-bit Logarithmic Bulletproof (`BulletproofRange64`):
        let bp_gamma = Scalar::hash_from_parts(
            "XCR.GW.BP_GAMMA.V1",
            &[&self.wallet.pocket.nonce.to_le_bytes(), invoice.as_bytes()],
        );
        let bp_seed = domain_hash(
            "XCR.GW.BP_SEED.V1",
            &[&self.wallet.pocket.nonce.to_le_bytes(), invoice.as_bytes()],
        )
        .0;
        let Some((bp_commit, bp_proof)) = BulletproofRange64::prove(amount, bp_gamma, 64, &bp_seed)
        else {
            return Ok(r#"{"accepted":false,"error":"Bulletproof generation failed"}"#.to_owned());
        };
        let bp_wire = bp_proof.to_bytes();
        if !bp_proof.verify(&bp_commit, 64) {
            return Ok(r#"{"accepted":false,"error":"Bulletproof self-check failed"}"#.to_owned());
        }

        // 2. Attach optional Edge ZK Proof of Innocence + Encrypted ISO-20022 Commercial Memo:
        let clean_root = self.clean_tree.root();
        let path = self.clean_tree.inclusion_path(0).unwrap();
        let witness = if regulated {
            Some((self.clean_note, path, clean_root, invoice.as_bytes()))
        } else {
            None
        };
        let memo = if regulated {
            Some(Iso20022Memo {
                message_id: format!("PACS-{}", self.wallet.pocket.nonce + 1),
                purpose_code: *b"GDDS",
                jurisdiction: "GLOBAL".to_owned(),
                invoice_ref: invoice.to_owned(),
                tax_amount: Amount::from_bits(amount.bits() / 11),
            })
        } else {
            None
        };

        // Sync WOTS+ leaf index with current pocket nonce:
        let prepared = self.wallet.build_fast_payment(
            &self.merchant.stealth_meta_address(),
            amount,
            fee,
            witness,
            memo,
        );

        let committee = self
            .lifecycle
            .active_committee
            .clone()
            .expect("active committee exists");
        let mut engine = FastPathEngine::new(committee);
        engine.register_pocket(self.wallet.pocket_public_key(), self.wallet.pocket.clone());

        match engine.execute_1rtt_transfer(&prepared.transaction, &mut self.validators, 1) {
            Ok(cert) => {
                let updated = engine
                    .pocket_state(&self.wallet.pocket_address())
                    .unwrap()
                    .clone();
                self.wallet.pocket = updated.clone();

                let zk_verified = if regulated {
                    prepared
                        .innocence_proof
                        .as_ref()
                        .is_some_and(|p| p.verify(&clean_root, invoice.as_bytes()))
                } else {
                    false
                };

                self.ledger.append(WalRecord::RecordFastFinality {
                    tx_id: prepared.transaction.id,
                    sender: self.wallet.pocket_address(),
                    new_nonce: updated.nonce,
                    new_balance: updated.balance,
                    new_daily_spent: updated.daily_spent,
                    day_index: updated.current_day,
                    recipient_stealth: prepared.stealth_output.one_time_address,
                    stealth_amount: amount,
                    fee_worker: cert.fee_split.worker_reward,
                    fee_burned: cert.fee_split.burned,
                    nullifier: prepared.innocence_proof.map(|p| p.nullifier),
                })?;

                Ok(format!(
                    r#"{{"accepted":true,"tx_id":"{}","latency_ms":{},"bulletproof_bytes":{},"fee_worker":"{}","fee_endurance":"{}","fee_burned":"{}","zk_verified":{},"decrypted_invoice":"{}","state_root":"{}"}}"#,
                    prepared.transaction.id,
                    cert.finality_latency_ms,
                    bp_wire.len(),
                    cert.fee_split.worker_reward,
                    cert.fee_split.endurance_deposit,
                    cert.fee_split.burned,
                    zk_verified,
                    json_escape(invoice),
                    self.ledger.state_merkle_root()
                ))
            }
            Err(err) => Ok(format!(
                r#"{{"accepted":false,"error":"{}"}}"#,
                json_escape(&format!("{err:?}"))
            )),
        }
    }

    fn handle_mine_epoch(&mut self) -> io::Result<String> {
        let epoch = self.lifecycle.current_epoch;
        let seed = self.lifecycle.current_epoch_seed;
        let vm_cfg = PoncVmConfig::devnet_profile();
        let mut dag = EpochShareDag::new(epoch, seed, 3, vm_cfg);
        for (i, (addr, _)) in self.validators.iter().enumerate() {
            let sh = ComputeShare::mine_cpu_share(
                epoch,
                &seed,
                *addr,
                dag.tip_ids(2),
                (i as u64) * 55 + epoch.0,
                3,
                &vm_cfg,
            );
            dag.submit_share(sh).expect("valid mined share");
        }
        let dir: Vec<(Address, credit_crypto::PublicKey, u16)> = self
            .validators
            .iter()
            .enumerate()
            .map(|(i, (a, kp))| (*a, kp.public_key(), 150 + (i as u16) * 15))
            .collect();
        let rep = self.lifecycle.advance_epoch(
            &dag,
            Amount::ZERO,
            5_000,
            &dir,
            &MaturityMetrics {
                active_compute_nodes: 250,
                distinct_autonomous_systems: 40,
                consecutive_deep_epochs: epoch.0 as u32 + 1,
            },
            &[],
            None,
        );

        let user_cut = rep.settlement.payouts[0].1;
        let _ = self.wallet.pocket.credit(user_cut);
        let payouts = rep
            .settlement
            .payouts
            .iter()
            .map(|&(a, amt, _)| (a, amt))
            .collect();
        self.ledger.append(WalRecord::RecordEpochSettlement {
            epoch: rep.closed_epoch,
            minted_emission: rep.settlement.minted_emission,
            worker_fees: Amount::ZERO,
            burned_fees: Amount::ZERO,
            payouts,
        })?;
        self.ledger.append(WalRecord::UpsertPocket {
            address: self.wallet.pocket_address(),
            public_key: self.wallet.pocket_public_key(),
            state: self.wallet.pocket.clone(),
        })?;

        Ok(format!(
            r#"{{"epoch":{},"credited":"{}"}}"#,
            self.lifecycle.current_epoch.0,
            user_cut.format_symbolic()
        ))
    }

    fn handle_faucet(&mut self) -> io::Result<String> {
        let drip = Amount::from_credits(10).unwrap();
        let _ = self.wallet.pocket.credit(drip);
        self.ledger.append(WalRecord::RecordEpochSettlement {
            epoch: self.lifecycle.current_epoch,
            minted_emission: drip,
            worker_fees: Amount::ZERO,
            burned_fees: Amount::ZERO,
            payouts: vec![(self.wallet.pocket_address(), drip)],
        })?;
        self.ledger.append(WalRecord::UpsertPocket {
            address: self.wallet.pocket_address(),
            public_key: self.wallet.pocket_public_key(),
            state: self.wallet.pocket.clone(),
        })?;
        Ok(format!(
            r#"{{"faucet":true,"drip":"{}","pocket_balance":"{}"}}"#,
            drip.format_symbolic(),
            self.wallet.pocket.balance.format_symbolic()
        ))
    }

    fn handle_light_verify(&self) -> String {
        let leaves: Vec<StateLeaf> = self
            .ledger
            .pockets
            .iter()
            .map(|(&address, sp)| StateLeaf {
                address,
                balance: sp.state.balance,
                nonce: sp.state.nonce,
            })
            .collect();
        let tree = AuthenticatedStateTree::build(leaves);
        let root = tree.root();
        let (leaf, branch) = tree.prove(&self.wallet.pocket_address()).unwrap();
        let ok = branch.verify(&leaf, &root);
        let bytes = branch.to_bytes().len();
        format!(
            r#"{{"verified":{},"proof_bytes":{},"root":"{}"}}"#,
            ok, bytes, root
        )
    }
}

/// Starts the zero-dependency HTTP/1.1 Consumer Wallet & Merchant POS server on `listener`.
pub fn serve_gateway(listener: TcpListener, data_dir: &Path) -> io::Result<()> {
    let mut rt = GatewayRuntime::open(data_dir)?;
    let csrf_token = generate_csrf_token();

    for incoming in listener.incoming() {
        let mut stream = match incoming {
            Ok(s) => s,
            Err(_) => continue,
        };
        let mut buf = [0u8; 8_192];
        let n = stream.read(&mut buf).unwrap_or(0);
        if n == 0 {
            continue;
        }
        let req_text = String::from_utf8_lossy(&buf[..n]);
        let first_line = req_text.lines().next().unwrap_or("");
        let mut parts = first_line.split_whitespace();
        let method = parts.next().unwrap_or("GET");
        let full_target = parts.next().unwrap_or("/");
        let (path, query) = full_target.split_once('?').unwrap_or((full_target, ""));

        if method == "POST" && !check_csrf_request_allowed(&req_text, &csrf_token) {
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
            ("GET", "/") => (
                "200 OK",
                "text/html; charset=utf-8",
                WALLET_AND_POS_HTML.replace("__XCR_CSRF_TOKEN__", &csrf_token),
            ),
            ("GET", "/embed/xcr-checkout.js") => (
                "200 OK",
                "application/javascript; charset=utf-8",
                crate::webhook::EMBED_CHECKOUT_JS.to_owned(),
            ),
            ("GET", "/api/checkout-status") => {
                ("200 OK", "application/json", r#"{"paid":false}"#.to_owned())
            }
            ("GET", "/.well-known/xcr-pay.json") => (
                "200 OK",
                "application/json",
                format_well_known_pay_json(
                    "merchant",
                    &rt.merchant.stealth_meta_address(),
                    "xcr-local-gateway",
                ),
            ),
            ("GET", "/api/qr.svg") => {
                let data = query_param(query, "data")
                    .map(percent_decode)
                    .unwrap_or_else(|| rt.wallet.stealth_meta_address().to_uri());
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
                let chips = query_param(query, "chips")
                    .and_then(|v| v.parse::<u64>().ok())
                    .unwrap_or(100);
                let inv = query_param(query, "invoice")
                    .map(percent_decode)
                    .unwrap_or_default();
                let memo = query_param(query, "memo")
                    .map(percent_decode)
                    .unwrap_or_default();
                let req = PaymentRequestUri::new(rt.merchant.stealth_meta_address().to_uri())
                    .with_amount(Amount::from_chips(chips).unwrap_or(Amount::ZERO))
                    .with_invoice(inv.clone())
                    .with_memo(memo);
                (
                    "200 OK",
                    "application/json",
                    format!(
                        r#"{{"uri":"{}","invoice":"{}"}}"#,
                        json_escape(&req.to_uri()),
                        json_escape(&inv)
                    ),
                )
            }
            ("GET", "/api/backup") => (
                "200 OK",
                "application/json",
                format!(r#"{{"words":"{}"}}"#, encode_mnemonic_24(&[0x51; 32])),
            ),
            ("GET", "/api/state") => ("200 OK", "application/json", rt.state_json()),
            ("GET", "/api/history") => {
                ("200 OK", "application/json", r#"{"entries":[]}"#.to_owned())
            }
            ("GET", "/api/contacts") => (
                "200 OK",
                "application/json",
                r#"{"contacts":[]}"#.to_owned(),
            ),
            ("GET", "/api/light-verify") => {
                ("200 OK", "application/json", rt.handle_light_verify())
            }
            ("POST", "/api/pay") => {
                let chips = if let Some(amt_s) = query_param(query, "amount")
                    && let Some(parsed) = parse_decimal_xcr(&percent_decode(amt_s))
                {
                    (parsed.bits() / 10_000).max(1)
                } else {
                    query_param(query, "chips")
                        .and_then(|v| v.parse::<u64>().ok())
                        .unwrap_or(100)
                };
                let invoice = query_param(query, "invoice")
                    .map(percent_decode)
                    .unwrap_or_else(|| "POS-0001".to_owned());
                let regulated = query_param(query, "regulated") != Some("0");
                (
                    "200 OK",
                    "application/json",
                    rt.handle_pay(chips, &invoice, regulated)?,
                )
            }
            ("POST", "/api/mine-epoch") => ("200 OK", "application/json", rt.handle_mine_epoch()?),
            ("POST", "/api/faucet") => ("200 OK", "application/json", rt.handle_faucet()?),
            ("POST", "/api/scan-stealth") => (
                "200 OK",
                "application/json",
                r#"{"scanned":0,"claimed":0,"amount":"∀ 0.000000 XCR"}"#.to_owned(),
            ),
            ("POST", "/api/vault/queue") => {
                let credits = query_param(query, "credits")
                    .and_then(|v| v.parse::<u64>().ok())
                    .unwrap_or(50);
                let res = match Amount::from_credits(credits).and_then(|amt| {
                    rt.wallet
                        .queue_vault_withdrawal(Address::from_bytes([0xee; 32]), amt, 1_000)
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
                let res = match rt.wallet.emergency_cancel_vault_withdrawal(id) {
                    Ok(restored) => {
                        format!(r#"{{"cancelled":true,"restored":"{}"}}"#, restored)
                    }
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
            "HTTP/1.1 {status}\r\nContent-Type: {content_type}\r\n{cors}Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
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

/// Helper for tests and local scripts to issue an HTTP/1.1 request to `addr`.
pub fn http_request(addr: SocketAddr, method: &str, target: &str) -> io::Result<(u16, String)> {
    let mut stream = TcpStream::connect(addr)?;
    let req = format!("{method} {target} HTTP/1.1\r\nHost: {addr}\r\nConnection: close\r\n\r\n");
    stream.write_all(req.as_bytes())?;
    let mut raw = String::new();
    stream.read_to_string(&mut raw)?;
    let (head, body) = raw.split_once("\r\n\r\n").unwrap_or((&raw, ""));
    let code = head
        .lines()
        .next()
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|c| c.parse::<u16>().ok())
        .unwrap_or(500);
    Ok((code, body.to_owned()))
}

pub(crate) fn query_param<'a>(query: &'a str, key: &str) -> Option<&'a str> {
    for pair in query.split('&') {
        if let Some((k, v)) = pair.split_once('=')
            && k == key
        {
            return Some(v);
        }
    }
    None
}

pub(crate) fn percent_decode(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%'
            && i + 2 < bytes.len()
            && let (Some(hi), Some(lo)) = (hex_val(bytes[i + 1]), hex_val(bytes[i + 2]))
        {
            out.push((hi << 4) | lo);
            i += 3;
            continue;
        } else if bytes[i] == b'+' {
            out.push(b' ');
        } else {
            out.push(bytes[i]);
        }
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

pub(crate) fn json_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for ch in s.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            c => out.push(c),
        }
    }
    out
}

pub(crate) fn generate_csrf_token() -> String {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(1);
    let pid = std::process::id();
    let h = domain_hash(
        "XCR.GW.CSRF_TOKEN.V1",
        &[&nanos.to_le_bytes(), &pid.to_le_bytes()],
    );
    h.to_hex()[..32].to_owned()
}

/// Blocks cross-site browser CSRF requests (`Sec-Fetch-Site: cross-site` or `Origin:` without a
/// matching `X-XCR-Token` header), while allowing authenticated UI calls and local CLI scripts.
pub(crate) fn check_csrf_request_allowed(raw_http: &str, expected_token: &str) -> bool {
    let head = raw_http.split("\r\n\r\n").next().unwrap_or(raw_http);
    let mut has_browser_context = false;
    let mut is_cross_site = false;
    let mut supplied_token: Option<&str> = None;

    for line in head.lines().skip(1) {
        if let Some((name, val)) = line.split_once(':') {
            let lower = name.trim().to_ascii_lowercase();
            let v = val.trim();
            match lower.as_str() {
                "origin" => has_browser_context = true,
                "sec-fetch-site" => {
                    has_browser_context = true;
                    if v.eq_ignore_ascii_case("cross-site") {
                        is_cross_site = true;
                    }
                }
                "x-xcr-token" => supplied_token = Some(v),
                _ => {}
            }
        }
    }
    if is_cross_site {
        return false;
    }
    if let Some(tok) = supplied_token {
        return credit_crypto::ct_eq_slice(tok.as_bytes(), expected_token.as_bytes());
    }
    // Browser requests ALWAYS include `Origin` or `Sec-Fetch-*` on `POST`, so require `X-XCR-Token`:
    !has_browser_context
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;
    use std::fs;
    use std::thread;

    #[test]
    fn web_wallet_and_merchant_pos_gateway_end_to_end_over_tcp() {
        let mut dir = env::temp_dir();
        dir.push(format!("xcr_gateway_test_{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let srv_dir = dir.clone();
        let handle = thread::spawn(move || serve_gateway(listener, &srv_dir).unwrap());

        let (code_ui, html) = http_request(addr, "GET", "/").unwrap();
        assert_eq!(code_ui, 200);
        assert!(html.contains("Credits (∀ / XCR) Wallet"));

        let (code_st, st_json) = http_request(addr, "GET", "/api/state").unwrap();
        assert_eq!(code_st, 200);
        assert!(st_json.contains(r#""pocket_nonce":0"#));

        let (code_pay, pay_json) = http_request(
            addr,
            "POST",
            "/api/pay?chips=495&invoice=CAFE-ZRH-99&regulated=1",
        )
        .unwrap();
        assert_eq!(code_pay, 200);
        assert!(pay_json.contains(r#""accepted":true"#));
        assert!(pay_json.contains(r#""bulletproof_bytes":672"#));
        assert!(pay_json.contains(r#""fee_endurance":"0.000075 XCR""#));
        assert!(pay_json.contains(r#""fee_burned":"0.000075 XCR""#));
        assert!(pay_json.contains(r#""zk_verified":true"#));

        let (_, vq_json) = http_request(addr, "POST", "/api/vault/queue?credits=200").unwrap();
        assert!(vq_json.contains(r#""queued":true"#));
        let (_, vc_json) = http_request(addr, "POST", "/api/vault/cancel?id=1").unwrap();
        assert!(vc_json.contains(r#""cancelled":true"#));

        let (_, lv_json) = http_request(addr, "GET", "/api/light-verify").unwrap();
        assert!(lv_json.contains(r#""verified":true"#));

        let (code_fc, fc_json) = http_request(addr, "POST", "/api/faucet").unwrap();
        assert_eq!(code_fc, 200);
        assert!(fc_json.contains(r#""faucet":true"#));

        // Verify cross-origin browser CSRF POST without `X-XCR-Token` is rejected with 403 Forbidden:
        let mut evil = TcpStream::connect(addr).unwrap();
        evil.write_all(
            format!(
                "POST /api/pay?amount=10.00 HTTP/1.1\r\nHost: {addr}\r\nOrigin: https://evil.example\r\nConnection: close\r\n\r\n"
            )
            .as_bytes(),
        )
        .unwrap();
        let mut evil_resp = String::new();
        evil.read_to_string(&mut evil_resp).unwrap();
        assert!(evil_resp.starts_with("HTTP/1.1 403 Forbidden"));

        let _ = http_request(addr, "POST", "/api/shutdown").unwrap();
        handle.join().unwrap();
        let _ = fs::remove_dir_all(&dir);
    }
}
