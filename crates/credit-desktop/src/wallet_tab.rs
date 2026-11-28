//! **Dedicated Multi-Currency Portfolio & Asset Transfer Tab (`wallet_tab.rs`)**.
//!
//! Gives users a single, clear view of every currency and asset held by their wallet:
//! - **Credits (`XCR`) Breakdown:** Spendable Pocket, 24-Hour Safety Vault, Shielded Privacy Pool,
//!   and any funds currently reserved in open Limit Orders or Escrows.
//! - **Layer-1 Native Currencies (`USDX`, `BTCX`, `GOLD`, etc.):** Shows owned balances, live
//!   Exchange mid-prices, estimated `XCR` value, and 1-click **Send** / **Trade** actions.
//! - **Direct Multi-Currency Transfers (`TransferNativeAsset` & `BabelAssetTransfer`):** Send any
//!   owned currency to `@username.xcr` or `xcr1_...`, with optional Babel fee payment in the token
//!   itself when `XCR` balance is zero.

use credit_types::{Amount, BITS_PER_CREDIT, Hash32};
use eframe::egui::{self, Color32, CornerRadius, RichText, Stroke};

use crate::backend::{UiSnapshot, UserCommand, format_vault_remaining};
use crate::exchange::MarketAssetInfo;
use crate::theme_qr::{
    ACCENT_BLUE, ACCENT_EMERALD, ACCENT_GOLD, BG_CARD, BG_INPUT, BORDER_SUBTLE, TEXT_MUTED,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WalletNavAction {
    None,
    GoToSendXcr,
    GoToVault,
    GoToShielded,
    GoToExchangeAsset(Option<Hash32>),
}

pub struct WalletTabUiState {
    pub show_zero_balances: bool,
    pub filter_query: String,
    pub send_asset_id: Option<Hash32>,
    pub send_recipient: String,
    pub send_units_str: String,
    pub use_babel_fee: bool,
}

impl Default for WalletTabUiState {
    fn default() -> Self {
        Self {
            show_zero_balances: false,
            filter_query: String::new(),
            send_asset_id: None,
            send_recipient: String::new(),
            send_units_str: String::from("10"),
            use_babel_fee: false,
        }
    }
}

/// Computes total `XCR` value reserved across open DEX Buy orders, active outgoing HTLCs,
/// and unsettled Seller P2P Fiat Escrows belonging to `snap.pocket_address`.
pub fn reserved_in_orders_and_escrows(snap: &UiSnapshot) -> Amount {
    let owner = snap.pocket_address;
    let dex_xcr = snap
        .exchange
        .orders
        .iter()
        .filter(|o| o.maker == owner && !o.is_sell_asset && o.remaining_units > 0)
        .fold(Amount::ZERO, |acc, o| acc.saturating_add(o.escrowed_xcr));

    let htlc_xcr = snap
        .atomic_swaps
        .htlcs
        .iter()
        .filter(|h| h.sender == owner && h.status == 0)
        .fold(Amount::ZERO, |acc, h| acc.saturating_add(h.amount));

    let fiat_xcr = snap
        .p2p_fiat
        .escrows
        .iter()
        .filter(|e| e.seller_address == owner && !e.settled)
        .fold(Amount::ZERO, |acc, e| acc.saturating_add(e.total_locked()));

    dex_xcr.saturating_add(htlc_xcr).saturating_add(fiat_xcr)
}

/// Estimates total portfolio value in `XCR` across Pocket, Vault, Shielded Pool, Escrows,
/// and all owned Layer-1 Native Currencies valued at current Exchange mid-prices.
pub fn estimated_total_portfolio_xcr(snap: &UiSnapshot) -> Amount {
    let mut total_bits: u128 = (snap.balance.bits() as u128)
        .saturating_add(snap.shielded_balance.bits() as u128)
        .saturating_add(reserved_in_orders_and_escrows(snap).bits() as u128);

    for asset in &snap.exchange.assets {
        if asset.owner_balance > 0
            && let Some(mid_bits) = snap.exchange.mid_price_bits(&asset.asset_id)
        {
            total_bits =
                total_bits.saturating_add((asset.owner_balance as u128) * (mid_bits as u128));
        }
    }

    Amount::from_bits(total_bits.min(u64::MAX as u128) as u64)
}

fn format_units_masked(units: u64, ticker: &str, hide: bool) -> String {
    if hide {
        format!("•••• {ticker}")
    } else {
        format!("{units} {ticker}")
    }
}

fn format_mid_price(bits: u64, hide: bool) -> String {
    if hide {
        String::from("∀ •••••• XCR")
    } else {
        let w = bits / BITS_PER_CREDIT;
        let f = bits % BITS_PER_CREDIT;
        format!("∀ {w}.{f:06} XCR")
    }
}

pub fn render_wallet_tab(
    ui: &mut egui::Ui,
    snap: &UiSnapshot,
    w_ui: &mut WalletTabUiState,
    cmd_tx: &std::sync::mpsc::Sender<UserCommand>,
) -> WalletNavAction {
    let mut nav = WalletNavAction::None;
    let avail_xcr = snap.available_wallet_balance();
    let vault_xcr = snap.total_in_vault();
    let reserved_xcr = reserved_in_orders_and_escrows(snap);
    let est_total = estimated_total_portfolio_xcr(snap);
    let owned_token_count = snap
        .exchange
        .assets
        .iter()
        .filter(|a| a.owner_balance > 0)
        .count();

    // 1. Portfolio Summary Cards
    ui.columns(3, |cols| {
        egui::Frame::NONE
            .fill(BG_CARD)
            .stroke(Stroke::new(1.0_f32, BORDER_SUBTLE))
            .corner_radius(CornerRadius::same(12))
            .inner_margin(egui::Margin::same(16))
            .show(&mut cols[0], |ui| {
                ui.set_min_width(ui.available_width());
                ui.label(RichText::new("Estimated Total Portfolio").color(TEXT_MUTED));
                ui.label(
                    RichText::new(snap.display_amount(est_total))
                        .size(25.0)
                        .strong()
                        .color(ACCENT_GOLD),
                );
                ui.label(
                    RichText::new("Includes XCR, Vault, Shielded & owned currencies")
                        .small()
                        .color(TEXT_MUTED),
                );
            });

        egui::Frame::NONE
            .fill(BG_CARD)
            .stroke(Stroke::new(1.0_f32, BORDER_SUBTLE))
            .corner_radius(CornerRadius::same(12))
            .inner_margin(egui::Margin::same(16))
            .show(&mut cols[1], |ui| {
                ui.set_min_width(ui.available_width());
                ui.label(RichText::new("Spendable XCR Right Now").color(TEXT_MUTED));
                ui.label(
                    RichText::new(snap.display_amount(avail_xcr))
                        .size(25.0)
                        .strong()
                        .color(ACCENT_EMERALD),
                );
                ui.label(
                    RichText::new(format!(
                        "Safety Vault: {}  ·  Reserved: {}",
                        snap.display_amount(vault_xcr),
                        snap.display_amount(reserved_xcr)
                    ))
                    .small()
                    .color(TEXT_MUTED),
                );
            });

        egui::Frame::NONE
            .fill(BG_CARD)
            .stroke(Stroke::new(1.0_f32, BORDER_SUBTLE))
            .corner_radius(CornerRadius::same(12))
            .inner_margin(egui::Margin::same(16))
            .show(&mut cols[2], |ui| {
                ui.set_min_width(ui.available_width());
                ui.horizontal(|ui| {
                    ui.label(RichText::new("Owned Currencies").color(TEXT_MUTED));
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        if ui.small_button("🔄 Refresh").clicked() {
                            let _ = cmd_tx.send(UserCommand::RefreshExchangeNow);
                        }
                    });
                });
                ui.label(
                    RichText::new(format!(
                        "{} Active Currenc{}",
                        1 + owned_token_count,
                        if owned_token_count == 0 { "y" } else { "ies" }
                    ))
                    .size(24.0)
                    .strong()
                    .color(ACCENT_BLUE),
                );
                ui.checkbox(
                    &mut w_ui.show_zero_balances,
                    RichText::new("Show zero-balance listed currencies").small(),
                );
            });
    });

    // 2. Holdings List + Direct Multi-Currency Send Panel
    egui::Frame::NONE
        .fill(BG_CARD)
        .stroke(Stroke::new(1.0_f32, BORDER_SUBTLE))
        .corner_radius(CornerRadius::same(12))
        .inner_margin(egui::Margin::same(16))
        .show(ui, |ui| {
            ui.horizontal(|ui| {
                ui.label(RichText::new("Your Currency Holdings").size(17.5).strong());
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    ui.add(
                        egui::TextEdit::singleline(&mut w_ui.filter_query)
                            .hint_text("Filter by ticker (e.g. USDX, BTCX)...")
                            .desired_width(210.0),
                    );
                });
            });
            ui.add_space(6.0);

            egui::ScrollArea::vertical()
                .max_height(235.0)
                .auto_shrink([false, false])
                .show(ui, |ui| {
                    // Primary Row: Credits (XCR)
                    let q = w_ui.filter_query.trim().to_ascii_lowercase();
                    if q.is_empty() || "xcr".contains(&q) || "credits".contains(&q) {
                        egui::Frame::NONE
                            .fill(BG_INPUT)
                            .stroke(Stroke::new(1.0_f32, BORDER_SUBTLE))
                            .corner_radius(CornerRadius::same(10))
                            .inner_margin(egui::Margin::same(12))
                            .show(ui, |ui| {
                                ui.horizontal_wrapped(|ui| {
                                    ui.label(
                                        RichText::new("∀  XCR — Credits")
                                            .size(16.0)
                                            .strong()
                                            .color(ACCENT_GOLD),
                                    );
                                    ui.separator();
                                    ui.label(
                                        RichText::new(format!(
                                            "Spendable: {}",
                                            snap.display_amount(avail_xcr)
                                        ))
                                        .strong()
                                        .color(ACCENT_EMERALD),
                                    );
                                    ui.label(
                                        RichText::new(format!(
                                            "· Vault: {}",
                                            snap.display_amount(vault_xcr)
                                        ))
                                        .small()
                                        .color(ACCENT_BLUE),
                                    );
                                    if let Some(earliest) =
                                        snap.vault.pending.iter().min_by_key(|w| w.unlock_at_ms)
                                    {
                                        ui.label(
                                            RichText::new(format!(
                                                "(⏳ {})",
                                                format_vault_remaining(earliest.unlock_at_ms)
                                            ))
                                            .small()
                                            .color(ACCENT_GOLD),
                                        );
                                    }
                                    if !snap.shielded_balance.is_zero() {
                                        ui.label(
                                            RichText::new(format!(
                                                "· Shielded: {}",
                                                snap.display_amount(snap.shielded_balance)
                                            ))
                                            .small()
                                            .color(TEXT_MUTED),
                                        );
                                    }

                                    ui.with_layout(
                                        egui::Layout::right_to_left(egui::Align::Center),
                                        |ui| {
                                            if ui.small_button("⇄ Exchange").clicked() {
                                                nav = WalletNavAction::GoToExchangeAsset(None);
                                            }
                                            if ui.small_button("🛡 Vault").clicked() {
                                                nav = WalletNavAction::GoToVault;
                                            }
                                            if ui.small_button("🕵 Shielded").clicked() {
                                                nav = WalletNavAction::GoToShielded;
                                            }
                                            if ui.small_button("💸 Send XCR").clicked() {
                                                nav = WalletNavAction::GoToSendXcr;
                                            }
                                        },
                                    );
                                });
                            });
                    }

                    // Native Asset Rows
                    let filtered_assets: Vec<&MarketAssetInfo> = snap
                        .exchange
                        .assets
                        .iter()
                        .filter(|a| w_ui.show_zero_balances || a.owner_balance > 0)
                        .filter(|a| {
                            q.is_empty()
                                || a.ticker.to_ascii_lowercase().contains(&q)
                                || a.asset_id.to_hex().contains(&q)
                        })
                        .collect();

                    if filtered_assets.is_empty() && !snap.exchange.assets.is_empty() && !w_ui.show_zero_balances {
                        ui.add_space(4.0);
                        ui.label(
                            RichText::new(
                                "You do not currently hold other Layer-1 currencies. Swap into one on the Exchange tab, or check 'Show zero-balance listed currencies' above.",
                            )
                            .small()
                            .color(TEXT_MUTED),
                        );
                    }

                    for asset in filtered_assets {
                        ui.add_space(4.0);
                        let mid_opt = snap.exchange.mid_price_bits(&asset.asset_id);
                        let est_val = mid_opt.map(|m| {
                            Amount::from_bits(asset.owner_balance.saturating_mul(m))
                        });

                        egui::Frame::NONE
                            .fill(BG_INPUT)
                            .stroke(Stroke::new(1.0_f32, BORDER_SUBTLE))
                            .corner_radius(CornerRadius::same(10))
                            .inner_margin(egui::Margin::same(12))
                            .show(ui, |ui| {
                                ui.horizontal_wrapped(|ui| {
                                    ui.label(
                                        RichText::new(format!("🪙 {}", asset.ticker))
                                            .size(15.5)
                                            .strong()
                                            .color(ACCENT_EMERALD),
                                    );
                                    ui.label(
                                        RichText::new(format!(
                                            "id {}...",
                                            &asset.asset_id.to_hex()[..10]
                                        ))
                                        .small()
                                        .monospace()
                                        .color(TEXT_MUTED),
                                    );
                                    ui.separator();
                                    ui.label(
                                        RichText::new(format!(
                                            "Balance: {}",
                                            format_units_masked(
                                                asset.owner_balance,
                                                &asset.ticker,
                                                snap.hide_figures
                                            )
                                        ))
                                        .strong(),
                                    );

                                    if let (Some(mid), Some(val)) = (mid_opt, est_val) {
                                        ui.label(
                                            RichText::new(format!(
                                                "· Rate: {}  · Est: {}",
                                                format_mid_price(mid, snap.hide_figures),
                                                snap.display_amount(val)
                                            ))
                                            .small()
                                            .color(TEXT_MUTED),
                                        );
                                    }

                                    ui.with_layout(
                                        egui::Layout::right_to_left(egui::Align::Center),
                                        |ui| {
                                            if ui.small_button("⇄ Trade").clicked() {
                                                nav = WalletNavAction::GoToExchangeAsset(Some(
                                                    asset.asset_id,
                                                ));
                                            }
                                            if asset.owner_balance > 0
                                                && ui.small_button("💸 Send").clicked()
                                            {
                                                w_ui.send_asset_id = Some(asset.asset_id);
                                            }
                                        },
                                    );
                                });
                            });
                    }
                });
        });

    // 3. Inline Native Currency Send Card (appears whenever the user owns >= 1 Native Asset or selected one)
    let owned_assets: Vec<&MarketAssetInfo> = snap
        .exchange
        .assets
        .iter()
        .filter(|a| a.owner_balance > 0)
        .collect();

    if !owned_assets.is_empty() {
        let active_send = w_ui
            .send_asset_id
            .and_then(|id| owned_assets.iter().copied().find(|a| a.asset_id == id))
            .unwrap_or(owned_assets[0]);
        w_ui.send_asset_id = Some(active_send.asset_id);

        egui::Frame::NONE
            .fill(BG_CARD)
            .stroke(Stroke::new(1.0_f32, BORDER_SUBTLE))
            .corner_radius(CornerRadius::same(12))
            .inner_margin(egui::Margin::same(16))
            .show(ui, |ui| {
                ui.horizontal_wrapped(|ui| {
                    ui.label(RichText::new("💸 Send Owned Currency:").strong());
                    egui::ComboBox::from_id_salt("wallet_send_currency_combo")
                        .selected_text(format!(
                            "{} (Owned: {})",
                            active_send.ticker,
                            format_units_masked(
                                active_send.owner_balance,
                                &active_send.ticker,
                                snap.hide_figures
                            )
                        ))
                        .show_ui(ui, |ui| {
                            for a in &owned_assets {
                                if ui
                                    .selectable_label(
                                        active_send.asset_id == a.asset_id,
                                        format!("{} ({})", a.ticker, a.owner_balance),
                                    )
                                    .clicked()
                                {
                                    w_ui.send_asset_id = Some(a.asset_id);
                                }
                            }
                        });

                    ui.label("To:");
                    ui.add(
                        egui::TextEdit::singleline(&mut w_ui.send_recipient)
                            .hint_text("@alice.xcr or xcr1_...")
                            .desired_width(175.0),
                    );
                    ui.label("Units:");
                    ui.add(
                        egui::TextEdit::singleline(&mut w_ui.send_units_str).desired_width(75.0),
                    );
                    ui.checkbox(
                        &mut w_ui.use_babel_fee,
                        RichText::new("Pay fee in token (Babel Fee)").small(),
                    );

                    if ui
                        .add(
                            egui::Button::new(
                                RichText::new(format!("Send {}", active_send.ticker))
                                    .strong()
                                    .color(Color32::BLACK),
                            )
                            .fill(ACCENT_EMERALD),
                        )
                        .clicked()
                    {
                        let units = w_ui.send_units_str.trim().parse::<u64>().unwrap_or(0);
                        let _ = cmd_tx.send(UserCommand::SendNativeCurrency {
                            asset_id: active_send.asset_id,
                            ticker: active_send.ticker.clone(),
                            recipient: w_ui.send_recipient.clone(),
                            units,
                            use_babel_fee: w_ui.use_babel_fee,
                        });
                    }
                });
            });
    }

    nav
}

#[cfg(test)]
mod tests {
    use crate::exchange::{AmmPoolView, ExchangeSnapshot};

    use super::*;

    #[test]
    fn portfolio_valuation_sums_xcr_and_owned_assets_accurately() {
        let aid = Hash32([0x33; 32]);
        let mut snap = UiSnapshot {
            balance: Amount::from_credits(50).unwrap(),
            shielded_balance: Amount::from_credits(10).unwrap(),
            exchange: ExchangeSnapshot {
                assets: vec![MarketAssetInfo {
                    asset_id: aid,
                    ticker: String::from("USDX"),
                    total_supply: 1_000_000,
                    decimals: 0,
                    owner_balance: 20, // 20 USDX
                }],
                pools: vec![AmmPoolView {
                    asset_id: aid,
                    ticker: String::from("USDX"),
                    reserve_xcr: Amount::from_credits(100).unwrap(),
                    reserve_asset: 50, // Mid price = 2.00 XCR per USDX
                    total_lp_shares: 1_000,
                }],
                ..ExchangeSnapshot::default()
            },
            ..UiSnapshot::default()
        };
        snap.vault.balance = Amount::from_credits(15).unwrap();
        // 50 XCR pocket + 10 XCR shielded + (20 USDX * 2.00 XCR = 40 XCR) = 100.000000 XCR
        assert_eq!(
            estimated_total_portfolio_xcr(&snap),
            Amount::from_credits(100).unwrap()
        );
    }
}
