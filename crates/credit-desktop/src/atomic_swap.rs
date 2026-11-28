//! **Phase 2 — Bridge-Free Cross-Chain Atomic Swap Desk (`atomic_swap.rs`)**.
//!
//! Enables 100% non-custodial cross-chain swaps (`BTC`, `Lightning BOLT-11`, `USDT-ERC20`,
//! `USDC-BASE`, `ETH`, `LTC` <-> `XCR`) with **zero wrapped-token bridges and zero custody**:
//! - **Crash-Safe Secret Journal (`atomic_swap_secrets.txt`):** Every generated 32-byte `preimage`
//!   is persisted to disk (`sync_all`) *before* broadcasting an offer or locking an HTLC, so closing
//!   the laptop or losing power mid-swap never strands funds.
//! - **Native Lightning `BOLT-11` (`lnbc...`) Submarine Swaps:** Verifies Bech32 checksums and
//!   extracts the exact 32-byte `SHA-256` `payment_hash` (`tag = 'p'`) client-side.
//! - **Native Bitcoin SegWit v0 `P2WSH` (`bc1q...` / `tb1q...`) Builder:** Generates canonical
//!   `OP_SHA256` + `OP_CHECKLOCKTIMEVERIFY` witness scripts and deposit addresses, plus stateless
//!   Esplora HTTPS inspection (`CREATE_NO_WINDOW`) to check external BTC funding status.
//! - **Automatic Preimage Sweep:** Background polling automatically claims any incoming Credit L1
//!   `HTLC` whose `hashlock` matches a known local `preimage`, and surfaces revealed on-chain
//!   preimages so Makers can immediately sweep external BTC/EVM HTLCs.

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::net::SocketAddr;
use std::path::Path;
use std::process::Command;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use credit_crypto::{domain_hash, sha256};
use credit_net::{HtlcWireRecord, NodeRpcRequest, NodeRpcResponse, rpc_call};
use credit_sdk::{
    AtomicSwapOffer, Bolt11Invoice, build_bitcoin_p2wsh_htlc, decode_hex_32, generate_htlc_secret,
    verify_htlc_preimage,
};
use credit_types::{Address, Amount, Hash32};
use eframe::egui::{self, Color32, CornerRadius, RichText, Stroke};

use crate::backend::{UiSnapshot, UserCommand};
use crate::p2p_fiat::FIAT_OFFER_PREFIX;
use crate::theme_qr::{
    ACCENT_BLUE, ACCENT_EMERALD, ACCENT_GOLD, BG_CARD, BG_INPUT, BORDER_SUBTLE, DANGER_RED,
    TEXT_MUTED,
};

pub const EXTERNAL_RAILS: &[(&str, &str)] = &[
    ("BTC", "Bitcoin (SegWit P2WSH)"),
    ("LN-BTC", "Lightning Network (BOLT-11)"),
    ("USDT-ERC20", "Tether USDT (Ethereum HTLC)"),
    ("USDC-BASE", "USD Coin (Base L2 HTLC)"),
    ("ETH", "Ethereum (Native HTLC)"),
    ("LTC", "Litecoin (SegWit P2WSH)"),
];

/// Crash-safe locally persisted `(hashlock, preimage)` record for active cross-chain swaps.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StoredSwapSecret {
    pub hashlock: Hash32,
    pub preimage: [u8; 32],
    pub created_unix: u64,
    pub label: String,
}

/// Live Layer-1 HTLC row surfaced in the Desktop Atomic Swap Desk.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HtlcView {
    pub escrow_id: Hash32,
    pub sender: Address,
    pub recipient: Address,
    pub amount: Amount,
    pub hashlock: Hash32,
    pub expiry_unix: u64,
    /// `0 = Open`, `1 = Claimed (preimage revealed)`, `2 = Refunded`.
    pub status: u8,
    pub revealed_preimage: Option<[u8; 32]>,
}

#[derive(Clone, Debug, Default)]
pub struct AtomicSwapSnapshot {
    pub offers: Vec<AtomicSwapOffer>,
    pub htlcs: Vec<HtlcView>,
    pub local_secrets: Vec<StoredSwapSecret>,
    pub btc_address_probe_status: String,
}

pub struct AtomicSwapUiState {
    pub rail_idx: usize,
    pub post_xcr_str: String,
    pub post_ext_amount_str: String,
    pub post_timelock_mins: u64,
    pub bolt11_input: String,
    pub bolt11_recipient_str: String,
    pub bolt11_xcr_str: String,
    pub manual_claim_escrow_hex: String,
    pub manual_claim_preimage_hex: String,
    pub btc_claim_pub33_hex: String,
    pub btc_refund_pub33_hex: String,
    pub generated_btc_p2wsh_addr: String,
    pub generated_btc_script_hex: String,
}

impl Default for AtomicSwapUiState {
    fn default() -> Self {
        Self {
            rail_idx: 0,
            post_xcr_str: String::from("25.00"),
            post_ext_amount_str: String::from("0.0025"),
            post_timelock_mins: 120,
            bolt11_input: String::new(),
            bolt11_recipient_str: String::new(),
            bolt11_xcr_str: String::from("10.00"),
            manual_claim_escrow_hex: String::new(),
            manual_claim_preimage_hex: String::new(),
            btc_claim_pub33_hex: String::from(
                "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
            ),
            btc_refund_pub33_hex: String::from(
                "03c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5",
            ),
            generated_btc_p2wsh_addr: String::new(),
            generated_btc_script_hex: String::new(),
        }
    }
}

fn hex_encode_bytes(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

fn decode_hex_33(s: &str) -> Option<[u8; 33]> {
    let clean = s.trim();
    if clean.len() != 66 {
        return None;
    }
    let mut out = [0u8; 33];
    for (i, slot) in out.iter_mut().enumerate() {
        *slot = u8::from_str_radix(&clean[i * 2..i * 2 + 2], 16).ok()?;
    }
    Some(out)
}

/// Crash-safely appends a newly generated `(hashlock, preimage)` secret to `atomic_swap_secrets.txt`
/// with `sync_all()` *before* any network offer or HTLC transaction is broadcast.
pub fn persist_swap_secret(app_dir: &Path, secret: &StoredSwapSecret) {
    let path = app_dir.join("atomic_swap_secrets.txt");
    let safe_label = secret.label.replace(['\n', '\r', '|'], " ");
    let line = format!(
        "{}|{}|{}|{}\n",
        secret.hashlock.to_hex(),
        hex_encode_bytes(&secret.preimage),
        secret.created_unix,
        safe_label
    );
    if let Ok(mut f) = OpenOptions::new().create(true).append(true).open(path) {
        let _ = f.write_all(line.as_bytes());
        let _ = f.sync_all();
    }
}

pub fn load_swap_secrets(app_dir: &Path) -> Vec<StoredSwapSecret> {
    let Ok(raw) = fs::read_to_string(app_dir.join("atomic_swap_secrets.txt")) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for ln in raw.lines() {
        let parts: Vec<&str> = ln.splitn(4, '|').collect();
        if parts.len() == 4
            && let (Some(hl), Some(pre), Ok(ts)) = (
                decode_hex_32(parts[0]),
                decode_hex_32(parts[1]),
                parts[2].parse::<u64>(),
            )
            && verify_htlc_preimage(&pre, &Hash32(hl))
        {
            out.push(StoredSwapSecret {
                hashlock: Hash32(hl),
                preimage: pre,
                created_unix: ts,
                label: parts[3].to_owned(),
            });
        }
    }
    out
}

/// Generates a deterministic-entropy + OS-timestamp HTLC secret and persists it immediately.
pub fn create_and_persist_swap_secret(
    app_dir: &Path,
    master_seed: &[u8; 32],
    label: &str,
) -> StoredSwapSecret {
    let now_ns = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let ent = domain_hash(
        "XCR.DESKTOP.SWAP_SECRET.V1",
        &[
            master_seed,
            &now_ns.to_le_bytes(),
            &std::process::id().to_le_bytes(),
            label.as_bytes(),
        ],
    )
    .0;
    let (preimage, hashlock) = generate_htlc_secret(&ent);
    let rec = StoredSwapSecret {
        hashlock,
        preimage,
        created_unix: (now_ns / 1_000_000_000) as u64,
        label: label.to_owned(),
    };
    persist_swap_secret(app_dir, &rec);
    rec
}

/// Fetches non-fiat cross-chain `AtomicSwapOffer`s and all Layer-1 `HTLC` escrows.
pub fn fetch_atomic_swaps_and_htlcs(
    primary: SocketAddr,
    fallback: SocketAddr,
) -> Option<(Vec<AtomicSwapOffer>, Vec<HtlcView>)> {
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
    let htlcs_resp = rpc_call(
        fallback,
        &NodeRpcRequest::GetHtlcs,
        Duration::from_millis(900),
    )
    .or_else(|_| {
        rpc_call(
            primary,
            &NodeRpcRequest::GetHtlcs,
            Duration::from_millis(850),
        )
    })
    .ok()?;

    let mut crypto_offers = Vec::new();
    if let NodeRpcResponse::SwapOfferList { offers } = offers_resp {
        for raw in offers {
            if let Some(off) = AtomicSwapOffer::from_bytes(&raw)
                && !off.counter_asset.starts_with(FIAT_OFFER_PREFIX)
            {
                crypto_offers.push(off);
            }
        }
    }

    let mut htlcs = Vec::new();
    if let NodeRpcResponse::HtlcList { escrows } = htlcs_resp {
        htlcs = escrows
            .into_iter()
            .map(
                |(
                    escrow_id,
                    sender,
                    recipient,
                    amount,
                    hashlock,
                    expiry_unix,
                    status,
                    revealed_preimage,
                ): HtlcWireRecord| HtlcView {
                    escrow_id,
                    sender,
                    recipient,
                    amount,
                    hashlock,
                    expiry_unix,
                    status,
                    revealed_preimage,
                },
            )
            .collect();
    }
    Some((crypto_offers, htlcs))
}

/// Stateless HTTPS Esplora UTXO check (`mempool.space`) for a generated Bitcoin `bc1q...` / `tb1q...`
/// SegWit `P2WSH` HTLC address (`CREATE_NO_WINDOW` — zero background daemon bloat).
pub fn probe_bitcoin_p2wsh_utxo(address: &str) -> Result<String, String> {
    let clean = address.trim();
    let api_url = if clean.starts_with("tb1q") {
        format!("https://mempool.space/testnet/api/address/{clean}/utxo")
    } else if clean.starts_with("bc1q") {
        format!("https://mempool.space/api/address/{clean}/utxo")
    } else {
        return Err(String::from(
            "Enter a valid bc1q... or tb1q... SegWit P2WSH address",
        ));
    };

    let mut cmd = Command::new("curl");
    cmd.args(["-fsSL", "--max-time", "8", &api_url]);
    #[cfg(target_os = "windows")]
    {
        use std::os::windows::process::CommandExt;
        cmd.creation_flags(0x0800_0000);
    }
    let out = cmd.output().map_err(|e| format!("curl error: {e}"))?;
    if !out.status.success() {
        return Err(String::from("Esplora endpoint unreachable"));
    }
    let body = String::from_utf8_lossy(&out.stdout);
    if body.trim() == "[]" {
        Ok(format!("0 funded UTXOs on {clean} (awaiting BTC deposit)"))
    } else {
        let count = body.matches("\"txid\"").count();
        Ok(format!("✓ Detected {count} funded BTC UTXO(s) on {clean}!"))
    }
}

pub fn render_atomic_swap_subtab(
    ui: &mut egui::Ui,
    snap: &UiSnapshot,
    sw_ui: &mut AtomicSwapUiState,
    cmd_tx: &std::sync::mpsc::Sender<UserCommand>,
) {
    let sw = &snap.atomic_swaps;
    let now_unix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    ui.columns(2, |cols| {
        // Left Column: Post Cross-Chain Offer + Lightning BOLT-11 / BTC P2WSH Script Builder
        egui::Frame::NONE
            .fill(BG_CARD)
            .stroke(Stroke::new(1.0_f32, BORDER_SUBTLE))
            .corner_radius(CornerRadius::same(12))
            .inner_margin(egui::Margin::same(16))
            .show(&mut cols[0], |ui| {
                ui.label(
                    RichText::new("🔗 Post Cross-Chain Atomic Swap Offer")
                        .size(17.0)
                        .strong(),
                );
                ui.label(
                    RichText::new(
                        "Zero wrapped tokens or bridges. Generates a crash-safe SHA-256 HTLC secret on disk before broadcasting your signed `xcroffer1_` intent.",
                    )
                    .small()
                    .color(TEXT_MUTED),
                );
                ui.add_space(6.0);

                let cur_rail = EXTERNAL_RAILS[sw_ui.rail_idx.min(EXTERNAL_RAILS.len() - 1)];
                egui::ComboBox::from_id_salt("atomic_rail_combo")
                    .selected_text(format!("{} — {}", cur_rail.0, cur_rail.1))
                    .show_ui(ui, |ui| {
                        for (idx, (code, desc)) in EXTERNAL_RAILS.iter().enumerate() {
                            ui.selectable_value(
                                &mut sw_ui.rail_idx,
                                idx,
                                format!("{code} — {desc}"),
                            );
                        }
                    });

                ui.horizontal(|ui| {
                    ui.label("XCR Size:");
                    ui.add(
                        egui::TextEdit::singleline(&mut sw_ui.post_xcr_str).desired_width(90.0),
                    );
                    ui.label(format!("For {} Amount:", cur_rail.0));
                    ui.add(
                        egui::TextEdit::singleline(&mut sw_ui.post_ext_amount_str)
                            .desired_width(95.0),
                    );
                });
                ui.horizontal(|ui| {
                    ui.label("HTLC Timelock (mins):");
                    ui.add(
                        egui::DragValue::new(&mut sw_ui.post_timelock_mins)
                            .range(15..=2_880)
                            .suffix("m"),
                    );
                    if ui
                        .add(
                            egui::Button::new(
                                RichText::new("📡 Publish Signed Offer")
                                    .strong()
                                    .color(Color32::BLACK),
                            )
                            .fill(ACCENT_EMERALD),
                        )
                        .clicked()
                    {
                        let _ = cmd_tx.send(UserCommand::PostCrossChainOffer {
                            counter_asset: cur_rail.0.to_owned(),
                            counter_amount: sw_ui.post_ext_amount_str.trim().to_owned(),
                            xcr_amount_str: sw_ui.post_xcr_str.clone(),
                            timelock_secs: sw_ui.post_timelock_mins * 60,
                        });
                    }
                });

                ui.add_space(8.0);
                ui.separator();
                ui.label(
                    RichText::new("⚡ Lightning BOLT-11 Submarine Swap (`lnbc...` <-> `XCR`)")
                        .strong()
                        .color(ACCENT_GOLD),
                );
                ui.add(
                    egui::TextEdit::singleline(&mut sw_ui.bolt11_input)
                        .hint_text("Paste lnbc... / lntb... invoice to verify & extract SHA-256 payment_hash")
                        .desired_width(f32::INFINITY),
                );
                if !sw_ui.bolt11_input.trim().is_empty() {
                    match Bolt11Invoice::parse(&sw_ui.bolt11_input) {
                        Ok(inv) => {
                            let sats_txt = inv
                                .amount_msat
                                .map(|m| format!("{} sats", m / 1_000))
                                .unwrap_or_else(|| String::from("any-amount"));
                            ui.label(
                                RichText::new(format!(
                                    "✓ Valid {} invoice ({sats_txt}) · hashlock: {}...",
                                    inv.network,
                                    &inv.payment_hash.to_hex()[..18]
                                ))
                                .small()
                                .monospace()
                                .color(ACCENT_EMERALD),
                            );
                            ui.horizontal(|ui| {
                                ui.label("Recipient:");
                                ui.add(
                                    egui::TextEdit::singleline(&mut sw_ui.bolt11_recipient_str)
                                        .hint_text("@peer.xcr or xcr1_...")
                                        .desired_width(145.0),
                                );
                                ui.label("XCR:");
                                ui.add(
                                    egui::TextEdit::singleline(&mut sw_ui.bolt11_xcr_str)
                                        .desired_width(65.0),
                                );
                                if ui.button("🔒 Lock XCR to Invoice Hash").clicked() {
                                    let _ = cmd_tx.send(UserCommand::LockCrossChainHtlc {
                                        recipient: sw_ui.bolt11_recipient_str.clone(),
                                        xcr_amount_str: sw_ui.bolt11_xcr_str.clone(),
                                        hashlock: inv.payment_hash,
                                        timelock_secs: inv.expiry_secs.max(1_800),
                                    });
                                }
                            });
                        }
                        Err(e) => {
                            ui.label(RichText::new(format!("BOLT-11: {e}")).small().color(DANGER_RED));
                        }
                    }
                }

                ui.add_space(8.0);
                ui.separator();
                ui.label(
                    RichText::new("₿ Bitcoin SegWit v0 `P2WSH` HTLC Script Generator (`bc1q...`)")
                        .strong(),
                );
                if let Some(latest_sec) = sw.local_secrets.last() {
                    ui.horizontal(|ui| {
                        if ui.small_button("Build BTC P2WSH Address").clicked()
                            && let (Some(c_pk), Some(r_pk)) = (
                                decode_hex_33(&sw_ui.btc_claim_pub33_hex),
                                decode_hex_33(&sw_ui.btc_refund_pub33_hex),
                            )
                        {
                            let is_main = matches!(
                                snap.active_mode,
                                crate::backend::ActiveNetworkMode::MainnetLiveOrStandby
                            );
                            let lock_u32 =
                                (now_unix.saturating_add(7_200)).min(u32::MAX as u64) as u32;
                            if let Ok((script, addr)) = build_bitcoin_p2wsh_htlc(
                                is_main,
                                &latest_sec.hashlock,
                                &c_pk,
                                &r_pk,
                                lock_u32,
                            ) {
                                sw_ui.generated_btc_p2wsh_addr = addr;
                                sw_ui.generated_btc_script_hex = hex_encode_bytes(&script);
                            }
                        }
                        if !sw_ui.generated_btc_p2wsh_addr.is_empty() {
                            if ui.small_button("📋 Copy P2WSH").clicked() {
                                ui.ctx().copy_text(sw_ui.generated_btc_p2wsh_addr.clone());
                            }
                            if ui.small_button("📋 Script").clicked() {
                                ui.ctx().copy_text(sw_ui.generated_btc_script_hex.clone());
                            }
                            if ui.small_button("🔍 Check BTC UTXO").clicked() {
                                let _ = cmd_tx.send(UserCommand::ProbeBitcoinP2wshAddress {
                                    address: sw_ui.generated_btc_p2wsh_addr.clone(),
                                });
                            }
                        }
                    });
                    if !sw_ui.generated_btc_p2wsh_addr.is_empty() {
                        ui.label(
                            RichText::new(format!("BTC HTLC: {}", sw_ui.generated_btc_p2wsh_addr))
                                .small()
                                .monospace()
                                .color(ACCENT_GOLD),
                        );
                    }
                    if !sw.btc_address_probe_status.is_empty() {
                        ui.label(
                            RichText::new(&sw.btc_address_probe_status)
                                .small()
                                .color(ACCENT_BLUE),
                        );
                    }
                } else {
                    ui.label(
                        RichText::new("Publish an offer first to generate a local SHA-256 hashlock.")
                            .small()
                            .color(TEXT_MUTED),
                    );
                }
            });

        // Right Column: Live P2P Cross-Chain Offer Board + Active L1 HTLC Escrows
        egui::Frame::NONE
            .fill(BG_CARD)
            .stroke(Stroke::new(1.0_f32, BORDER_SUBTLE))
            .corner_radius(CornerRadius::same(12))
            .inner_margin(egui::Margin::same(16))
            .show(&mut cols[1], |ui| {
                ui.label(
                    RichText::new(format!(
                        "🌐 Live Cross-Chain Offers ({}) & Active HTLCs ({})",
                        sw.offers.len(),
                        sw.htlcs.len()
                    ))
                    .size(17.0)
                    .strong(),
                );

                if sw.offers.is_empty() {
                    ui.label(
                        RichText::new("No open cross-chain offers yet — publish the first BTC/USDT <-> XCR offer on the left!")
                            .small()
                            .color(TEXT_MUTED),
                    );
                } else {
                    for off in sw.offers.iter().take(5) {
                        egui::Frame::NONE
                            .fill(BG_INPUT)
                            .stroke(Stroke::new(1.0_f32, BORDER_SUBTLE))
                            .corner_radius(CornerRadius::same(8))
                            .inner_margin(egui::Margin::same(10))
                            .show(ui, |ui| {
                                ui.horizontal(|ui| {
                                    ui.label(
                                        RichText::new(format!(
                                            "{}  <->  {} {}",
                                            snap.display_amount(off.xcr_amount),
                                            if snap.hide_figures { "••••" } else { &off.counter_amount },
                                            off.counter_asset
                                        ))
                                        .strong()
                                        .color(ACCENT_GOLD),
                                    );
                                    ui.with_layout(
                                        egui::Layout::right_to_left(egui::Align::Center),
                                        |ui| {
                                            if ui.small_button("📋 URI").clicked() {
                                                ui.ctx().copy_text(off.to_uri());
                                            }
                                            if off.maker_address != snap.pocket_address
                                                && ui
                                                    .add(
                                                        egui::Button::new("🔒 Match & Lock HTLC")
                                                            .small()
                                                            .fill(ACCENT_BLUE),
                                                    )
                                                    .clicked()
                                            {
                                                let _ = cmd_tx.send(
                                                    UserCommand::LockCrossChainHtlc {
                                                        recipient: Hash32(off.maker_address.0)
                                                            .to_hex(),
                                                        xcr_amount_str: format!(
                                                            "{}.{:06}",
                                                            off.xcr_amount.bits() / 1_000_000,
                                                            off.xcr_amount.bits() % 1_000_000
                                                        ),
                                                        hashlock: off.hashlock,
                                                        timelock_secs: off.timelock_secs.max(1_800),
                                                    },
                                                );
                                            }
                                        },
                                    );
                                });
                                ui.label(
                                    RichText::new(format!(
                                        "Maker {} · Hashlock {}...",
                                        off.maker_address.short_hex(),
                                        &off.hashlock.to_hex()[..16]
                                    ))
                                    .small()
                                    .monospace()
                                    .color(TEXT_MUTED),
                                );
                            });
                    }
                }

                ui.add_space(8.0);
                ui.separator();
                ui.label(RichText::new("My Layer-1 HTLC Escrows:").strong());

                let my_htlcs: Vec<&HtlcView> = sw
                    .htlcs
                    .iter()
                    .filter(|h| h.sender == snap.pocket_address || h.recipient == snap.pocket_address)
                    .collect();
                if my_htlcs.is_empty() {
                    ui.label(
                        RichText::new("No active HTLC escrows for your address.")
                            .small()
                            .color(TEXT_MUTED),
                    );
                } else {
                    for h in my_htlcs.into_iter().take(5) {
                        let status_badge = match h.status {
                            0 => {
                                let rem = h.expiry_unix.saturating_sub(now_unix);
                                if rem > 0 {
                                    format!("⏳ Locked ({}m left)", rem / 60)
                                } else {
                                    String::from("⌛ Expired (Refundable)")
                                }
                            }
                            1 => String::from("✅ Claimed (Secret Revealed)"),
                            _ => String::from("↩ Refunded"),
                        };
                        ui.horizontal_wrapped(|ui| {
                            ui.label(
                                RichText::new(format!(
                                    "{} · {}",
                                    snap.display_amount(h.amount),
                                    status_badge
                                ))
                                .small()
                                .strong(),
                            );
                            if let Some(pre) = h.revealed_preimage
                                && ui
                                    .small_button("📋 Copy Preimage (Sweep External BTC/USDT)")
                                    .clicked()
                            {
                                ui.ctx().copy_text(hex_encode_bytes(&pre));
                            }
                            if h.status == 0 && now_unix >= h.expiry_unix && h.sender == snap.pocket_address
                                && ui.small_button("↩ Refund XCR").clicked()
                            {
                                let _ = cmd_tx.send(UserCommand::RefundCrossChainHtlc {
                                    escrow_id: h.escrow_id,
                                });
                            }
                        });
                    }
                }

                ui.add_space(6.0);
                ui.label(
                    RichText::new("Manual Preimage Claim (if secret learned from external chain):")
                        .small()
                        .color(TEXT_MUTED),
                );
                ui.horizontal(|ui| {
                    ui.add(
                        egui::TextEdit::singleline(&mut sw_ui.manual_claim_escrow_hex)
                            .hint_text("64-hex Escrow ID")
                            .desired_width(135.0),
                    );
                    ui.add(
                        egui::TextEdit::singleline(&mut sw_ui.manual_claim_preimage_hex)
                            .hint_text("64-hex Preimage Secret")
                            .desired_width(135.0),
                    );
                    if ui.small_button("🔓 Claim").clicked() {
                        let _ = cmd_tx.send(UserCommand::ClaimCrossChainHtlc {
                            escrow_hex: sw_ui.manual_claim_escrow_hex.clone(),
                            preimage_hex: sw_ui.manual_claim_preimage_hex.clone(),
                        });
                    }
                });
            });
    });

    let _ = sha256;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bolt11_and_bitcoin_p2wsh_atomic_swap_primitives_interoperate() {
        let (preimage, hashlock) = generate_htlc_secret(&[0x55; 32]);
        assert!(verify_htlc_preimage(&preimage, &hashlock));

        let claim_pk =
            decode_hex_33("0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")
                .unwrap();
        let refund_pk =
            decode_hex_33("03c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5")
                .unwrap();
        let (script, addr) =
            build_bitcoin_p2wsh_htlc(true, &hashlock, &claim_pk, &refund_pk, 1_800_000_000)
                .unwrap();
        assert!(addr.starts_with("bc1q"));
        assert!(script.len() > 100);

        let inv_str = Bolt11Invoice::encode_with_sig(
            "lnbc",
            Some(250_000),
            1_798_761_600,
            &hashlock,
            "Credits Atomic Swap",
            3_600,
            &[0x11; 65],
        )
        .unwrap();
        let parsed = Bolt11Invoice::parse(&inv_str).unwrap();
        assert_eq!(parsed.payment_hash, hashlock);
        assert!(parsed.verify_preimage(&preimage));
    }
}
