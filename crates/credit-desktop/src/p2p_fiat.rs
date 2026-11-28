//! **Phase 3 — "Bisq-in-250ms" P2P Fiat Escrow + Zero-PII Reputation (`p2p_fiat.rs`)**.
//!
//! Upgrades Bisq's censorship-resistant peer-to-peer fiat architecture onto Credits' `<250 ms`
//! Layer-1 settlement engine:
//! 1. **Unstoppable Mesh Fiat Bulletin Board (`FIAT:<CCY>:<RAIL>`):** Signed P2P fiat buy/sell
//!    offers (`SEPA`, `PayID`, `FasterPay`, `Zelle`, `Revolut`, `Wise`) replicate over `PostSwapOffer`
//!    with **zero central company, zero bank honeypot, and zero KYC database**.
//! 2. **`CredScript` `2-of-3` Mutual-Bond Escrow (`Buyer`, `Seller`, `Mediator`):**
//!    - Seller locks `trade_xcr + seller_security_bond_xcr` (e.g., `15%` anti-fraud bond) in `<250 ms`.
//!    - Buyer sends fiat off-chain and clicks **"💸 I Sent Fiat — Broadcast Co-Sig"**, publishing a
//!      `65-byte` Schnorr co-signature over the exact canonical payout vector
//!      `[(buyer, trade_xcr), (seller, seller_bond_xcr)]`.
//!    - Seller verifies bank arrival and clicks **"✅ Fiat Received — Release XCR & Reclaim Bond"**,
//!      completing the `2-of-3` threshold in `1-RTT` and automatically issuing an on-chain
//!      **Zero-PII Reputation Attestation (`P2P-TRADE-OK-V1`)**!
//!    - If a dispute occurs, the bonded Mediator co-signs `(0, 2)` or `(1, 2)` to award the vault
//!      and security bond to the honest party.

use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::net::SocketAddr;
use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use credit_crypto::{Keypair, PublicKey, Signature, SignatureScheme, domain_hash};
use credit_net::{NodeRpcRequest, NodeRpcResponse, rpc_call};
use credit_sdk::{
    AtomicSwapOffer, CredScript, CredWitnessItem, compute_claim_commitment, decode_hex_32,
    encode_witness_stack, script_vault_spend_digest, sign_attestation_issue,
    sign_script_vault_lock,
};
use credit_types::{Address, Amount, Hash32, MIN_BASE_FEE_BITS};
use eframe::egui::{self, Color32, CornerRadius, RichText, Stroke};

use crate::backend::{UiSnapshot, UserCommand};
use crate::exchange::random_salt16;
use crate::theme_qr::{
    ACCENT_BLUE, ACCENT_EMERALD, ACCENT_GOLD, BG_CARD, BG_INPUT, BORDER_SUBTLE, TEXT_MUTED,
};

pub const FIAT_OFFER_PREFIX: &str = "FIAT:";
pub const P2P_REPUTATION_SCHEMA: &str = "P2P-TRADE-OK-V1";

pub const FIAT_RAILS: &[(&str, &str)] = &[
    ("AUD:PayID", "AUD — Instant Osko / PayID"),
    ("USD:Zelle", "USD — Zelle Instant"),
    ("EUR:SEPA", "EUR — SEPA Instant"),
    ("GBP:FasterPay", "GBP — UK Faster Payments"),
    ("USD:Revolut", "USD — Revolut @Revtag"),
    ("MULTI:Wise", "Global — Wise Instant"),
];

/// Default community dispute-mediator public key (`PasskeyP256`), overridable per trade.
pub fn default_community_mediator_pubkey() -> PublicKey {
    let med_seed = domain_hash(
        "XCR.P2P_FIAT.COMMUNITY_MEDIATOR.V1",
        &[b"xcr-mainnet-2027-bisq-mediator-council"],
    )
    .0;
    Keypair::from_seed(SignatureScheme::PasskeyP256, med_seed).public_key()
}

/// Locally tracked `CredScript` `2-of-3` P2P Fiat Escrow contract (`p2p_fiat_escrows.txt`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LocalFiatEscrow {
    pub vault_id: Hash32,
    pub script_uri: String,
    pub seller_address: Address,
    pub buyer_address: Address,
    pub buyer_pubkey: PublicKey,
    pub seller_pubkey: PublicKey,
    pub mediator_pubkey: PublicKey,
    pub trade_xcr: Amount,
    pub seller_bond_xcr: Amount,
    pub fiat_label: String,
    pub buyer_cosig_hex: String,
    pub settled: bool,
}

impl LocalFiatEscrow {
    pub fn total_locked(&self) -> Amount {
        self.trade_xcr.saturating_add(self.seller_bond_xcr)
    }

    pub fn canonical_happy_payouts(&self) -> Vec<(Address, Amount)> {
        if self.seller_bond_xcr.is_zero() {
            vec![(self.buyer_address, self.trade_xcr)]
        } else {
            vec![
                (self.buyer_address, self.trade_xcr),
                (self.seller_address, self.seller_bond_xcr),
            ]
        }
    }
}

#[derive(Clone, Debug, Default)]
pub struct P2pFiatSnapshot {
    pub fiat_offers: Vec<AtomicSwapOffer>,
    pub escrows: Vec<LocalFiatEscrow>,
    pub my_completed_trades: u32,
    pub network_trade_attestations: Vec<(Address, u32)>,
}

impl P2pFiatSnapshot {
    pub fn reputation_for(&self, addr: &Address) -> u32 {
        self.network_trade_attestations
            .iter()
            .find(|(a, _)| a == addr)
            .map(|(_, c)| *c)
            .unwrap_or(0)
    }

    /// Bisq-style aging/reputation trade cap (`250 XCR` starter -> `2,500 XCR` -> uncapped veteran).
    pub fn max_trade_limit_xcr(&self) -> u64 {
        match self.my_completed_trades {
            0..=1 => 250,
            2..=4 => 2_500,
            _ => 50_000,
        }
    }
}

pub struct P2pFiatUiState {
    pub rail_idx: usize,
    pub offer_xcr_str: String,
    pub offer_fiat_amount_str: String,
    pub lock_buyer_pubkey_hex66: String,
    pub lock_trade_xcr_str: String,
    pub lock_bond_pct: u64,
    pub lock_fiat_memo: String,
    pub import_escrow_ticket: String,
    pub paste_buyer_cosig: String,
}

impl Default for P2pFiatUiState {
    fn default() -> Self {
        Self {
            rail_idx: 0,
            offer_xcr_str: String::from("50.00"),
            offer_fiat_amount_str: String::from("75.00"),
            lock_buyer_pubkey_hex66: String::new(),
            lock_trade_xcr_str: String::from("50.00"),
            lock_bond_pct: 15, // 15% Bisq-style anti-fraud security deposit
            lock_fiat_memo: String::from("AUD PayID — Ref #XCR"),
            import_escrow_ticket: String::new(),
            paste_buyer_cosig: String::new(),
        }
    }
}

pub fn encode_pubkey_hex66(pk: &PublicKey) -> String {
    format!("{:02x}{}", pk.scheme as u8, pk.merkle_root.to_hex())
}

pub fn decode_pubkey_hex66(s: &str) -> Option<PublicKey> {
    let clean = s.trim();
    if clean.len() != 66 {
        return None;
    }
    let scheme_byte = u8::from_str_radix(&clean[0..2], 16).ok()?;
    let scheme = SignatureScheme::from_u8(scheme_byte)?;
    let root = decode_hex_32(&clean[2..66])?;
    Some(PublicKey {
        scheme,
        merkle_root: Hash32(root),
    })
}

fn hex_encode_65(sig: &[u8; 65]) -> String {
    let mut s = String::with_capacity(130);
    for &b in sig {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

pub fn decode_sig65_hex(s: &str) -> Option<[u8; 65]> {
    let clean = s.trim();
    if clean.len() != 130 {
        return None;
    }
    let mut out = [0u8; 65];
    for (i, slot) in out.iter_mut().enumerate() {
        *slot = u8::from_str_radix(&clean[i * 2..i * 2 + 2], 16).ok()?;
    }
    Some(out)
}

/// Shareable ticket (`xcrfiat1_...`) Seller sends to Buyer (or Buyer imports from offer match)
/// containing all public parameters needed for Buyer to inspect the `2-of-3` vault and sign release.
pub fn encode_fiat_escrow_ticket(esc: &LocalFiatEscrow) -> String {
    format!(
        "xcrfiat1_{}|{}|{}|{}|{}|{}|{}|{}",
        esc.vault_id.to_hex(),
        esc.script_uri,
        encode_pubkey_hex66(&esc.buyer_pubkey),
        encode_pubkey_hex66(&esc.seller_pubkey),
        encode_pubkey_hex66(&esc.mediator_pubkey),
        esc.trade_xcr.bits(),
        esc.seller_bond_xcr.bits(),
        esc.fiat_label.replace('|', " ")
    )
}

pub fn decode_fiat_escrow_ticket(ticket: &str) -> Option<LocalFiatEscrow> {
    let body = ticket.trim().strip_prefix("xcrfiat1_")?;
    let parts: Vec<&str> = body.splitn(8, '|').collect();
    if parts.len() != 8 {
        return None;
    }
    let vault_id = Hash32(decode_hex_32(parts[0])?);
    let script = CredScript::from_uri(parts[1])?;
    let buyer_pubkey = decode_pubkey_hex66(parts[2])?;
    let seller_pubkey = decode_pubkey_hex66(parts[3])?;
    let mediator_pubkey = decode_pubkey_hex66(parts[4])?;
    let trade_bits = parts[5].parse::<u64>().ok()?;
    let bond_bits = parts[6].parse::<u64>().ok()?;
    let expected = CredScript::two_of_three_escrow(buyer_pubkey, seller_pubkey, mediator_pubkey);
    if script.script_hash() != expected.script_hash() {
        return None;
    }
    Some(LocalFiatEscrow {
        vault_id,
        script_uri: parts[1].to_owned(),
        seller_address: seller_pubkey.to_address(),
        buyer_address: buyer_pubkey.to_address(),
        buyer_pubkey,
        seller_pubkey,
        mediator_pubkey,
        trade_xcr: Amount::from_bits(trade_bits),
        seller_bond_xcr: Amount::from_bits(bond_bits),
        fiat_label: parts[7].to_owned(),
        buyer_cosig_hex: String::new(),
        settled: false,
    })
}

pub fn save_fiat_escrows(app_dir: &Path, escrows: &[LocalFiatEscrow]) {
    let path = app_dir.join("p2p_fiat_escrows.txt");
    let mut out = String::new();
    for e in escrows {
        out.push_str(&format!(
            "{}\t{}\t{}\n",
            encode_fiat_escrow_ticket(e),
            e.buyer_cosig_hex,
            u8::from(e.settled)
        ));
    }
    if let Ok(mut f) = OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(path)
    {
        let _ = f.write_all(out.as_bytes());
        let _ = f.sync_all();
    }
}

pub fn load_fiat_escrows(app_dir: &Path) -> Vec<LocalFiatEscrow> {
    let Ok(raw) = fs::read_to_string(app_dir.join("p2p_fiat_escrows.txt")) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for ln in raw.lines() {
        let cols: Vec<&str> = ln.splitn(3, '\t').collect();
        if cols.len() == 3
            && let Some(mut esc) = decode_fiat_escrow_ticket(cols[0])
        {
            esc.buyer_cosig_hex = cols[1].to_owned();
            esc.settled = cols[2] == "1";
            out.push(esc);
        }
    }
    out
}

/// Locks `trade_xcr + seller_bond_xcr` into a Layer-1 `CredScript::two_of_three_escrow` vault (`<250ms`).
pub fn lock_bisq_fiat_escrow_vault(
    seller_seed: &[u8; 32],
    buyer_pubkey: PublicKey,
    trade_xcr: Amount,
    seller_bond_xcr: Amount,
    fiat_label: &str,
    node_addr: SocketAddr,
) -> io::Result<(LocalFiatEscrow, NodeRpcResponse)> {
    let sk = domain_hash("XCR.WALLET.POCKET_KEY.V1", &[seller_seed]).0;
    let seller_kp = Keypair::from_seed(SignatureScheme::PasskeyP256, sk);
    let seller_pubkey = seller_kp.public_key();
    let mediator_pubkey = default_community_mediator_pubkey();

    let script = CredScript::two_of_three_escrow(buyer_pubkey, seller_pubkey, mediator_pubkey);
    let total_amount = trade_xcr
        .checked_add(seller_bond_xcr)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "escrow amount overflow"))?;
    let fee = Amount::from_bits(MIN_BASE_FEE_BITS);
    let salt = random_salt16("XCR.DESKTOP.FIAT_ESCROW_LOCK.V1");

    let (depositor, depositor_pubkey, vault_id, sig65) =
        sign_script_vault_lock(seller_seed, &script.script_hash(), total_amount, fee, salt);
    let resp = rpc_call(
        node_addr,
        &NodeRpcRequest::LockScriptVault {
            vault_id,
            depositor,
            depositor_pubkey,
            script_hash: script.script_hash(),
            amount: total_amount,
            fee,
            salt,
            sig65,
        },
        Duration::from_secs(3),
    )?;

    let escrow = LocalFiatEscrow {
        vault_id,
        script_uri: script.to_uri(),
        seller_address: depositor,
        buyer_address: buyer_pubkey.to_address(),
        buyer_pubkey,
        seller_pubkey,
        mediator_pubkey,
        trade_xcr,
        seller_bond_xcr,
        fiat_label: fiat_label.to_owned(),
        buyer_cosig_hex: String::new(),
        settled: false,
    };
    Ok((escrow, resp))
}

/// Buyer signs the canonical happy-path payout (`[(buyer, trade_xcr), (seller, bond_xcr)]`) after sending fiat.
pub fn buyer_sign_fiat_sent_cosig(
    buyer_seed: &[u8; 32],
    escrow: &LocalFiatEscrow,
) -> Result<String, &'static str> {
    let sk = domain_hash("XCR.WALLET.POCKET_KEY.V1", &[buyer_seed]).0;
    let mut kp = Keypair::from_seed(SignatureScheme::PasskeyP256, sk);
    if kp.public_key() != escrow.buyer_pubkey {
        return Err("this wallet is not the designated Buyer on this escrow");
    }
    let payouts = escrow.canonical_happy_payouts();
    let digest = script_vault_spend_digest(&escrow.vault_id, &payouts);
    let sig_vec = kp.sign(digest.as_bytes()).to_bytes();
    let sig65: [u8; 65] = sig_vec.try_into().map_err(|_| "sig65 length")?;
    Ok(hex_encode_65(&sig65))
}

/// Seller verifies Buyer's co-sig, adds Seller's signature (`2-of-3` satisfied!), settles the
/// `CredScript` vault in `1-RTT`, and issues an on-chain Zero-PII Reputation Attestation to Buyer!
pub fn seller_finalize_fiat_escrow_and_attest(
    seller_seed: &[u8; 32],
    escrow: &LocalFiatEscrow,
    buyer_cosig_hex: &str,
    node_addr: SocketAddr,
) -> io::Result<NodeRpcResponse> {
    let buyer_sig65 = decode_sig65_hex(buyer_cosig_hex).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "paste valid 130-hex Buyer Fiat-Sent signature",
        )
    })?;
    let payouts = escrow.canonical_happy_payouts();
    let digest = script_vault_spend_digest(&escrow.vault_id, &payouts);
    let Some(b_sig) = Signature::from_bytes(&buyer_sig65) else {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "malformed Buyer signature",
        ));
    };
    if !escrow.buyer_pubkey.verify(digest.as_bytes(), &b_sig) {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "Buyer co-signature does not match escrow vault & payouts",
        ));
    }

    let sk = domain_hash("XCR.WALLET.POCKET_KEY.V1", &[seller_seed]).0;
    let mut seller_kp = Keypair::from_seed(SignatureScheme::PasskeyP256, sk);
    if seller_kp.public_key() != escrow.seller_pubkey {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "this wallet is not the Seller on this escrow",
        ));
    }
    let seller_sig65: [u8; 65] = seller_kp
        .sign(digest.as_bytes())
        .to_bytes()
        .try_into()
        .map_err(|_| io::Error::other("sig65"))?;

    let script = CredScript::from_uri(&escrow.script_uri)
        .ok_or_else(|| io::Error::other("invalid script_uri"))?;
    let witness = vec![CredWitnessItem::ThresholdSigs(vec![
        (0, buyer_sig65),
        (1, seller_sig65),
    ])];

    let spend_resp = rpc_call(
        node_addr,
        &NodeRpcRequest::SpendScriptVault {
            vault_id: escrow.vault_id,
            script_bytes: script.to_bytes(),
            witness_bytes: encode_witness_stack(&witness),
            payouts,
        },
        Duration::from_secs(3),
    )?;

    // Automatically mint a Zero-PII `P2P-TRADE-OK-V1` reputation attestation for Buyer:
    if let NodeRpcResponse::ContractReceipt { accepted: true, .. } = &spend_resp {
        let salt = random_salt16("XCR.DESKTOP.P2P_REP_ATTEST.V1");
        let claim = compute_claim_commitment(&escrow.vault_id.to_hex(), &salt);
        let exp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs() + 86_400 * 365 * 5)
            .unwrap_or(2_000_000_000);
        let fee = Amount::from_bits(MIN_BASE_FEE_BITS);
        if let Ok((attester, attester_pubkey, attestation_id, sig65)) = sign_attestation_issue(
            seller_seed,
            &escrow.buyer_address,
            P2P_REPUTATION_SCHEMA,
            claim,
            exp,
            fee,
            salt,
        ) {
            let _ = rpc_call(
                node_addr,
                &NodeRpcRequest::IssueOrRevokeAttestation {
                    is_revoke: false,
                    tx_id: attestation_id,
                    attestation_id,
                    attester,
                    attester_pubkey,
                    subject: escrow.buyer_address,
                    schema: String::from(P2P_REPUTATION_SCHEMA),
                    claim_commitment: claim,
                    expiry_unix: exp,
                    fee,
                    salt,
                    sig65,
                },
                Duration::from_secs(2),
            );
        }
    }

    Ok(spend_resp)
}

pub type P2pFiatNetworkPayload = (Vec<AtomicSwapOffer>, u32, Vec<(Address, u32)>);

/// Polls P2P `FIAT:*` offers and Zero-PII `P2P-TRADE-OK-V1` reputation counts across the mesh.
pub fn fetch_p2p_fiat_network_data(
    owner: Address,
    primary: SocketAddr,
    fallback: SocketAddr,
) -> Option<P2pFiatNetworkPayload> {
    let offers_resp = rpc_call(
        fallback,
        &NodeRpcRequest::GetSwapOffers,
        Duration::from_millis(900),
    )
    .or_else(|_| {
        rpc_call(
            primary,
            &NodeRpcRequest::GetSwapOffers,
            Duration::from_millis(850),
        )
    })
    .ok()?;
    let mut fiat_offers = Vec::new();
    if let NodeRpcResponse::SwapOfferList { offers } = offers_resp {
        for raw in offers {
            if let Some(off) = AtomicSwapOffer::from_bytes(&raw)
                && off.counter_asset.starts_with(FIAT_OFFER_PREFIX)
            {
                fiat_offers.push(off);
            }
        }
    }

    let mut counts: std::collections::BTreeMap<Address, u32> = std::collections::BTreeMap::new();
    if let Ok(NodeRpcResponse::LaneAndArtifactSnapshot { attestations, .. }) = rpc_call(
        fallback,
        &NodeRpcRequest::GetArtifactsAndAttestations {
            owner_or_subject: None,
            lane_id: 1,
        },
        Duration::from_millis(900),
    ) {
        for (_att_id, _attester, subject, schema, _commit, _exp, revoked) in attestations {
            if !revoked && schema == P2P_REPUTATION_SCHEMA {
                *counts.entry(subject).or_insert(0) += 1;
            }
        }
    }

    let my_rep = counts.get(&owner).copied().unwrap_or(0);
    Some((fiat_offers, my_rep, counts.into_iter().collect()))
}

pub fn render_p2p_fiat_subtab(
    ui: &mut egui::Ui,
    snap: &UiSnapshot,
    f_ui: &mut P2pFiatUiState,
    cmd_tx: &std::sync::mpsc::Sender<UserCommand>,
) {
    let pf = &snap.p2p_fiat;
    let my_pk_hex = snap
        .pocket_pubkey
        .as_ref()
        .map(encode_pubkey_hex66)
        .unwrap_or_default();

    ui.columns(2, |cols| {
        // Left Column: Post Fiat Offer + Lock 2-of-3 CredScript Mutual-Bond Vault
        egui::Frame::NONE
            .fill(BG_CARD)
            .stroke(Stroke::new(1.0_f32, BORDER_SUBTLE))
            .corner_radius(CornerRadius::same(12))
            .inner_margin(egui::Margin::same(16))
            .show(&mut cols[0], |ui| {
                ui.horizontal(|ui| {
                    ui.label(
                        RichText::new("🏦 P2P Fiat On/Off-Ramp (Bisq-in-250ms)")
                            .size(17.0)
                            .strong(),
                    );
                    ui.label(
                        RichText::new(format!(
                            "⭐ {} Verified Trades (Cap: {} XCR)",
                            pf.my_completed_trades,
                            pf.max_trade_limit_xcr()
                        ))
                        .small()
                        .color(ACCENT_GOLD),
                    );
                });
                ui.label(
                    RichText::new(
                        "Trade bank transfers (PayID, Zelle, SEPA, Faster Payments, Revolut) peer-to-peer with 2-of-3 `CredScript` security-bond vaults and Zero-PII reputation.",
                    )
                    .small()
                    .color(TEXT_MUTED),
                );
                ui.add_space(6.0);

                let rail = FIAT_RAILS[f_ui.rail_idx.min(FIAT_RAILS.len() - 1)];
                egui::ComboBox::from_id_salt("p2p_fiat_rail_combo")
                    .selected_text(rail.1)
                    .show_ui(ui, |ui| {
                        for (idx, (_, label)) in FIAT_RAILS.iter().enumerate() {
                            ui.selectable_value(&mut f_ui.rail_idx, idx, *label);
                        }
                    });

                ui.horizontal(|ui| {
                    ui.label("XCR Amount:");
                    ui.add(
                        egui::TextEdit::singleline(&mut f_ui.offer_xcr_str).desired_width(80.0),
                    );
                    ui.label("Fiat Price:");
                    ui.add(
                        egui::TextEdit::singleline(&mut f_ui.offer_fiat_amount_str)
                            .desired_width(80.0),
                    );
                    if ui
                        .add(
                            egui::Button::new(
                                RichText::new("📢 Post Fiat Offer")
                                    .strong()
                                    .color(Color32::BLACK),
                            )
                            .fill(ACCENT_GOLD),
                        )
                        .clicked()
                    {
                        let _ = cmd_tx.send(UserCommand::PostP2pFiatOffer {
                            fiat_rail_code: format!("{FIAT_OFFER_PREFIX}{}", rail.0),
                            fiat_amount_str: f_ui.offer_fiat_amount_str.trim().to_owned(),
                            xcr_amount_str: f_ui.offer_xcr_str.clone(),
                        });
                    }
                });

                ui.add_space(8.0);
                ui.separator();
                ui.horizontal(|ui| {
                    ui.label(RichText::new("🔐 Lock 2-of-3 Seller Escrow + Security Bond").strong());
                    if !my_pk_hex.is_empty() && ui.small_button("📋 Copy My Buyer PubKey").clicked() {
                        ui.ctx().copy_text(my_pk_hex.clone());
                    }
                });
                ui.label("Buyer 66-Hex PublicKey (from matched Buyer):");
                ui.add(
                    egui::TextEdit::singleline(&mut f_ui.lock_buyer_pubkey_hex66)
                        .hint_text("Paste Buyer's 66-hex PublicKey...")
                        .desired_width(f32::INFINITY),
                );
                ui.horizontal(|ui| {
                    ui.label("Trade XCR:");
                    ui.add(
                        egui::TextEdit::singleline(&mut f_ui.lock_trade_xcr_str)
                            .desired_width(80.0),
                    );
                    ui.label("Anti-Fraud Bond:");
                    ui.add(
                        egui::DragValue::new(&mut f_ui.lock_bond_pct)
                            .range(10..=50)
                            .suffix("%"),
                    );
                });
                ui.horizontal(|ui| {
                    ui.label("Payment Ref:");
                    ui.add(
                        egui::TextEdit::singleline(&mut f_ui.lock_fiat_memo)
                            .desired_width(190.0),
                    );
                    if ui
                        .add(
                            egui::Button::new(
                                RichText::new("🔒 Lock Vault (<250ms)")
                                    .strong()
                                    .color(Color32::BLACK),
                            )
                            .fill(ACCENT_EMERALD),
                        )
                        .clicked()
                    {
                        let _ = cmd_tx.send(UserCommand::LockP2pFiatEscrow {
                            buyer_pubkey_hex66: f_ui.lock_buyer_pubkey_hex66.clone(),
                            trade_xcr_str: f_ui.lock_trade_xcr_str.clone(),
                            bond_pct: f_ui.lock_bond_pct,
                            fiat_label: f_ui.lock_fiat_memo.clone(),
                        });
                    }
                });

                ui.add_space(8.0);
                ui.separator();
                ui.label(RichText::new("📥 Buyer: Import Seller's `xcrfiat1_` Escrow Ticket").small().strong());
                ui.horizontal(|ui| {
                    ui.add(
                        egui::TextEdit::singleline(&mut f_ui.import_escrow_ticket)
                            .hint_text("Paste xcrfiat1_... ticket from Seller")
                            .desired_width(240.0),
                    );
                    if ui.small_button("Import Escrow").clicked() {
                        let _ = cmd_tx.send(UserCommand::ImportP2pFiatTicket {
                            ticket: f_ui.import_escrow_ticket.clone(),
                        });
                        f_ui.import_escrow_ticket.clear();
                    }
                });
            });

        // Right Column: Live P2P Fiat Offer Book + Active 2-of-3 Escrows
        egui::Frame::NONE
            .fill(BG_CARD)
            .stroke(Stroke::new(1.0_f32, BORDER_SUBTLE))
            .corner_radius(CornerRadius::same(12))
            .inner_margin(egui::Margin::same(16))
            .show(&mut cols[1], |ui| {
                ui.label(
                    RichText::new(format!(
                        "🌍 Live P2P Fiat Offers ({}) & Escrows ({})",
                        pf.fiat_offers.len(),
                        pf.escrows.len()
                    ))
                    .size(17.0)
                    .strong(),
                );

                if pf.fiat_offers.is_empty() {
                    ui.label(
                        RichText::new("No open fiat offers yet — post a PayID / Zelle / SEPA offer on the left!")
                            .small()
                            .color(TEXT_MUTED),
                    );
                } else {
                    for off in pf.fiat_offers.iter().take(4) {
                        let rail_clean = off
                            .counter_asset
                            .strip_prefix(FIAT_OFFER_PREFIX)
                            .unwrap_or(&off.counter_asset);
                        let rep = pf.reputation_for(&off.maker_address);
                        egui::Frame::NONE
                            .fill(BG_INPUT)
                            .stroke(Stroke::new(1.0_f32, BORDER_SUBTLE))
                            .corner_radius(CornerRadius::same(8))
                            .inner_margin(egui::Margin::same(10))
                            .show(ui, |ui| {
                                ui.horizontal(|ui| {
                                    ui.label(
                                        RichText::new(format!(
                                            "{}  for  {} ({rail_clean})",
                                            snap.display_amount(off.xcr_amount),
                                            if snap.hide_figures { "••••" } else { &off.counter_amount }
                                        ))
                                        .strong()
                                        .color(ACCENT_EMERALD),
                                    );
                                    ui.with_layout(
                                        egui::Layout::right_to_left(egui::Align::Center),
                                        |ui| {
                                            if ui
                                                .small_button("Use Buyer PubKey")
                                                .on_hover_text(
                                                    "Pre-fills this peer's verified 66-hex PublicKey into the 2-of-3 Escrow Locker",
                                                )
                                                .clicked()
                                            {
                                                f_ui.lock_buyer_pubkey_hex66 =
                                                    encode_pubkey_hex66(&off.maker_pubkey);
                                                f_ui.lock_trade_xcr_str = format!(
                                                    "{}.{:06}",
                                                    off.xcr_amount.bits() / 1_000_000,
                                                    off.xcr_amount.bits() % 1_000_000
                                                );
                                            }
                                            ui.label(
                                                RichText::new(format!("⭐ {rep}"))
                                                    .small()
                                                    .color(ACCENT_GOLD),
                                            );
                                        },
                                    );
                                });
                            });
                    }
                }

                ui.add_space(8.0);
                ui.separator();
                ui.label(RichText::new("Active 2-of-3 `CredScript` Fiat Escrows:").strong());

                if pf.escrows.is_empty() {
                    ui.label(
                        RichText::new("No active fiat escrows stored on this device.")
                            .small()
                            .color(TEXT_MUTED),
                    );
                } else {
                    for esc in pf.escrows.iter().rev().take(4) {
                        egui::Frame::NONE
                            .fill(BG_INPUT)
                            .stroke(Stroke::new(1.0_f32, BORDER_SUBTLE))
                            .corner_radius(CornerRadius::same(8))
                            .inner_margin(egui::Margin::same(10))
                            .show(ui, |ui| {
                                ui.horizontal_wrapped(|ui| {
                                    ui.label(
                                        RichText::new(format!(
                                            "Vault {} (Trade {} + {} Bond) · {}",
                                            snap.display_amount(esc.total_locked()),
                                            snap.display_amount(esc.trade_xcr),
                                            snap.display_amount(esc.seller_bond_xcr),
                                            if esc.settled { "✅ Settled" } else { "🔒 Escrowed" }
                                        ))
                                        .small()
                                        .strong(),
                                    );
                                    if ui.small_button("📋 Ticket").clicked() {
                                        ui.ctx().copy_text(encode_fiat_escrow_ticket(esc));
                                    }
                                });

                                if !esc.settled {
                                    if esc.buyer_address == snap.pocket_address {
                                        ui.horizontal(|ui| {
                                            if ui
                                                .add(
                                                    egui::Button::new("💸 I Sent Fiat — Sign Release")
                                                        .small()
                                                        .fill(ACCENT_BLUE),
                                                )
                                                .clicked()
                                            {
                                                let _ = cmd_tx.send(
                                                    UserCommand::BuyerSignFiatSent {
                                                        vault_id: esc.vault_id,
                                                    },
                                                );
                                            }
                                            if !esc.buyer_cosig_hex.is_empty()
                                                && ui.small_button("📋 Copy Co-Sig").clicked()
                                            {
                                                ui.ctx().copy_text(esc.buyer_cosig_hex.clone());
                                            }
                                        });
                                    }

                                    if esc.seller_address == snap.pocket_address {
                                        ui.horizontal(|ui| {
                                            ui.add(
                                                egui::TextEdit::singleline(&mut f_ui.paste_buyer_cosig)
                                                    .hint_text("Paste Buyer 130-hex Co-Sig...")
                                                    .desired_width(165.0),
                                            );
                                            if ui
                                                .add(
                                                    egui::Button::new(
                                                        RichText::new("✅ Release XCR & Reclaim Bond")
                                                            .small()
                                                            .strong()
                                                            .color(Color32::BLACK),
                                                    )
                                                    .fill(ACCENT_EMERALD),
                                                )
                                                .clicked()
                                            {
                                                let sig_in = if !f_ui.paste_buyer_cosig.trim().is_empty() {
                                                    f_ui.paste_buyer_cosig.clone()
                                                } else {
                                                    esc.buyer_cosig_hex.clone()
                                                };
                                                let _ = cmd_tx.send(
                                                    UserCommand::SellerReleaseFiatEscrow {
                                                        vault_id: esc.vault_id,
                                                        buyer_cosig_hex: sig_in,
                                                    },
                                                );
                                            }
                                        });
                                    }
                                }
                            });
                    }
                }
            });
    });
}

#[cfg(test)]
mod tests {
    use credit_sdk::CredEvalContext;

    use super::*;

    #[test]
    fn bisq_2of3_credscript_escrow_enforces_exact_payouts_and_mediation() {
        let buyer_sk = domain_hash("XCR.WALLET.POCKET_KEY.V1", &[&[0x11; 32]]).0;
        let seller_sk = domain_hash("XCR.WALLET.POCKET_KEY.V1", &[&[0x22; 32]]).0;
        let mut buyer_kp = Keypair::from_seed(SignatureScheme::PasskeyP256, buyer_sk);
        let mut seller_kp = Keypair::from_seed(SignatureScheme::PasskeyP256, seller_sk);

        let med_seed = domain_hash(
            "XCR.P2P_FIAT.COMMUNITY_MEDIATOR.V1",
            &[b"xcr-mainnet-2027-bisq-mediator-council"],
        )
        .0;
        let mut med_kp = Keypair::from_seed(SignatureScheme::PasskeyP256, med_seed);

        let script = CredScript::two_of_three_escrow(
            buyer_kp.public_key(),
            seller_kp.public_key(),
            med_kp.public_key(),
        );
        let esc = LocalFiatEscrow {
            vault_id: Hash32([0x77; 32]),
            script_uri: script.to_uri(),
            seller_address: seller_kp.address(),
            buyer_address: buyer_kp.address(),
            buyer_pubkey: buyer_kp.public_key(),
            seller_pubkey: seller_kp.public_key(),
            mediator_pubkey: med_kp.public_key(),
            trade_xcr: Amount::from_credits(100).unwrap(),
            seller_bond_xcr: Amount::from_credits(15).unwrap(),
            fiat_label: String::from("AUD:PayID #1"),
            buyer_cosig_hex: String::new(),
            settled: false,
        };

        // Ticket roundtrip verifies script_hash integrity:
        let ticket = encode_fiat_escrow_ticket(&esc);
        let decoded = decode_fiat_escrow_ticket(&ticket).unwrap();
        assert_eq!(decoded.vault_id, esc.vault_id);
        assert_eq!(decoded.total_locked(), Amount::from_credits(115).unwrap());

        // 1) Seller alone CANNOT rug-pull back to Seller:
        let rug_payouts = vec![(esc.seller_address, esc.total_locked())];
        let rug_digest = script_vault_spend_digest(&esc.vault_id, &rug_payouts);
        let s_rug_sig: [u8; 65] = seller_kp
            .sign(rug_digest.as_bytes())
            .to_bytes()
            .try_into()
            .unwrap();
        let rug_witness = vec![CredWitnessItem::ThresholdSigs(vec![(1, s_rug_sig)])];
        let rug_ctx = CredEvalContext {
            spend_digest: rug_digest,
            now_unix: 1_800_000_000,
            primary_recipient: esc.seller_address,
        };
        assert!(!script.evaluate(&rug_witness, &rug_ctx));

        // 2) Cooperative Happy Path (`Buyer + Seller`) releases 100 XCR to Buyer + 15 XCR bond back to Seller:
        let happy_cosig_hex = buyer_sign_fiat_sent_cosig(&[0x11; 32], &esc).unwrap();
        let b_sig65 = decode_sig65_hex(&happy_cosig_hex).unwrap();
        let happy_payouts = esc.canonical_happy_payouts();
        let happy_digest = script_vault_spend_digest(&esc.vault_id, &happy_payouts);
        let s_happy_sig: [u8; 65] = seller_kp
            .sign(happy_digest.as_bytes())
            .to_bytes()
            .try_into()
            .unwrap();
        let happy_witness = vec![CredWitnessItem::ThresholdSigs(vec![
            (0, b_sig65),
            (1, s_happy_sig),
        ])];
        let happy_ctx = CredEvalContext {
            spend_digest: happy_digest,
            now_unix: 1_800_000_000,
            primary_recipient: esc.buyer_address,
        };
        assert!(script.evaluate(&happy_witness, &happy_ctx));

        // 3) Dispute Mediation (`Buyer + Mediator`) awards full 115 XCR (including forfeited Seller bond!) to Buyer:
        let dispute_payouts = vec![(esc.buyer_address, esc.total_locked())];
        let dispute_digest = script_vault_spend_digest(&esc.vault_id, &dispute_payouts);
        let b_disp: [u8; 65] = buyer_kp
            .sign(dispute_digest.as_bytes())
            .to_bytes()
            .try_into()
            .unwrap();
        let m_disp: [u8; 65] = med_kp
            .sign(dispute_digest.as_bytes())
            .to_bytes()
            .try_into()
            .unwrap();
        let disp_witness = vec![CredWitnessItem::ThresholdSigs(vec![
            (0, b_disp),
            (2, m_disp),
        ])];
        let disp_ctx = CredEvalContext {
            spend_digest: dispute_digest,
            now_unix: 1_800_000_000,
            primary_recipient: esc.buyer_address,
        };
        assert!(script.evaluate(&disp_witness, &disp_ctx));
    }
}
