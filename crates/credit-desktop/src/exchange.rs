//! **Credits Native Sovereign Exchange (`exchange.rs`)** — Phase 1 Desktop DEX, AMM & Spread Bot.
//!
//! Combines four zero-custody Layer-1 trading engines under a single `⇄ Exchange` tab:
//! 1. **Instant Hybrid Smart Swap (`HybridSmartSwap`):** Quotes both the Constant-Product AMM
//!    (`x * y = k`, `0.30%` LP fee) and the Layer-1 Central Limit Orderbook (`CLOB`) in real time
//!    and atomically executes against whichever venue delivers more output (`0` MEV sandwiching).
//! 2. **Pro Central Limit Orderbook (`PlaceDexOrder` / `CancelDexOrder`):** Live visual green/red
//!    bid-ask depth ladder, click-to-fill price levels, `Immediate-Or-Cancel` (`IOC`), and 1-click
//!    order cancellations.
//! 3. **Passive AMM Liquidity Pools (`AmmLiquidity`):** Permissionless `XCR <-> Asset` LP share
//!    minting and burning with exact integer `isqrt_u128` conservation.
//! 4. **1-Click Spread Earner Bot (`PROXY_ROLE_DEX_TRADE_ONLY`):** Automates two-sided market-making
//!    using an on-chain Polkadot-style `DexTradeOnly` proxy key (`0` withdrawal power) while strictly
//!    respecting the user's 24-Hour Safety Vault boundary.

use std::io;
use std::net::SocketAddr;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use credit_crypto::{Keypair, PublicKey, SignatureScheme, domain_hash};
use credit_net::{
    AmmPoolWireRecord, AssetWireRecord, DexOrderWireRecord, NodeRpcRequest, NodeRpcResponse,
    OracleFeedWireRecord, rpc_call,
};
use credit_sdk::{
    PROXY_ROLE_DEX_TRADE_ONLY, PROXY_ROLE_REVOKE, amm_constant_product_out, parse_decimal_xcr,
    sign_proxy_execute, sign_role_proxy_bind,
};
use credit_types::{Address, Amount, BITS_PER_CREDIT, Hash32, MIN_BASE_FEE_BITS};
use eframe::egui::{self, Color32, CornerRadius, RichText, Stroke};

use crate::backend::{UiSnapshot, UserCommand};
use crate::theme_qr::{
    ACCENT_BLUE, ACCENT_EMERALD, ACCENT_GOLD, BG_CARD, BG_INPUT, BORDER_SUBTLE, DANGER_RED,
    TEXT_MUTED, TEXT_PRIMARY,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExchangeSubTab {
    SimpleSwap,
    ProOrderbook,
    LiquidityPools,
    SpreadBot,
    LaunchAsset,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MarketAssetInfo {
    pub asset_id: Hash32,
    pub ticker: String,
    pub total_supply: u64,
    pub decimals: u8,
    pub owner_balance: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AmmPoolView {
    pub asset_id: Hash32,
    pub ticker: String,
    pub reserve_xcr: Amount,
    pub reserve_asset: u64,
    pub total_lp_shares: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OrderbookRow {
    pub order_id: Hash32,
    pub maker: Address,
    pub asset_id: Hash32,
    pub is_sell_asset: bool,
    pub remaining_units: u64,
    pub price_bits_per_unit: u64,
    pub escrowed_xcr: Amount,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OracleFeedView {
    pub feed_id: String,
    pub median_micros: u64,
    pub reporter_count: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SmartSwapVenue {
    AmmPool,
    LimitOrderbook,
    NoLiquidity,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SmartSwapPreview {
    pub amm_out: u64,
    pub orderbook_out: u64,
    pub best_out: u64,
    pub min_out_after_slippage: u64,
    pub venue: SmartSwapVenue,
    pub price_impact_bps: u64,
}

#[derive(Clone, Debug)]
pub struct SpreadBotConfig {
    pub enabled: bool,
    pub asset_id: Option<Hash32>,
    pub half_spread_bps: u64,
    pub units_per_side: u64,
    pub max_xcr_budget: Amount,
    pub proxy_address_short: String,
    pub quotes_placed: u64,
    pub last_status: String,
}

impl Default for SpreadBotConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            asset_id: None,
            half_spread_bps: 75, // 0.75% each side = 1.50% round-trip spread
            units_per_side: 5,
            max_xcr_budget: Amount::from_credits(25).unwrap(),
            proxy_address_short: String::new(),
            quotes_placed: 0,
            last_status: String::from(
                "Idle — toggle ON to quote automatic Bid/Ask spreads safely.",
            ),
        }
    }
}

#[derive(Clone, Debug, Default)]
pub struct ExchangeSnapshot {
    pub assets: Vec<MarketAssetInfo>,
    pub pools: Vec<AmmPoolView>,
    pub orders: Vec<OrderbookRow>,
    pub oracles: Vec<OracleFeedView>,
    pub selected_asset: Option<Hash32>,
    pub spread_bot: SpreadBotConfig,
}

impl ExchangeSnapshot {
    pub fn active_asset(&self) -> Option<&MarketAssetInfo> {
        if let Some(sel) = self.selected_asset
            && let Some(found) = self.assets.iter().find(|a| a.asset_id == sel)
        {
            return Some(found);
        }
        self.assets.first()
    }

    pub fn pool_for(&self, asset_id: &Hash32) -> Option<&AmmPoolView> {
        self.pools.iter().find(|p| &p.asset_id == asset_id)
    }

    /// Returns open `Ask` (sell) orders for `asset_id` sorted lowest price first.
    pub fn sorted_asks(&self, asset_id: &Hash32) -> Vec<OrderbookRow> {
        let mut v: Vec<OrderbookRow> = self
            .orders
            .iter()
            .filter(|o| &o.asset_id == asset_id && o.is_sell_asset && o.remaining_units > 0)
            .cloned()
            .collect();
        v.sort_by_key(|o| o.price_bits_per_unit);
        v
    }

    /// Returns open `Bid` (buy) orders for `asset_id` sorted highest price first.
    pub fn sorted_bids(&self, asset_id: &Hash32) -> Vec<OrderbookRow> {
        let mut v: Vec<OrderbookRow> = self
            .orders
            .iter()
            .filter(|o| &o.asset_id == asset_id && !o.is_sell_asset && o.remaining_units > 0)
            .cloned()
            .collect();
        v.sort_by_key(|b| std::cmp::Reverse(b.price_bits_per_unit));
        v
    }

    /// Computes a reference mid-price (`bits per 1 asset unit`) from Orderbook Bid/Ask or AMM reserves.
    pub fn mid_price_bits(&self, asset_id: &Hash32) -> Option<u64> {
        let best_ask = self
            .sorted_asks(asset_id)
            .first()
            .map(|o| o.price_bits_per_unit);
        let best_bid = self
            .sorted_bids(asset_id)
            .first()
            .map(|o| o.price_bits_per_unit);
        if let (Some(a), Some(b)) = (best_ask, best_bid) {
            return Some(((a as u128 + b as u128) / 2) as u64);
        }
        if let Some(pool) = self.pool_for(asset_id)
            && pool.reserve_asset > 0
            && !pool.reserve_xcr.is_zero()
        {
            return Some((pool.reserve_xcr.bits() / pool.reserve_asset).max(1));
        }
        best_ask.or(best_bid)
    }

    /// Client-side mirror of `HybridSmartSwap` (`wave11_contracts.rs`) so the UI previews exact
    /// output across both AMM (`x * y = k`) and Limit Orderbook (`CLOB`) before signing.
    pub fn quote_smart_swap(
        &self,
        asset_id: &Hash32,
        is_buy_asset: bool,
        amount_in_bits_or_units: u64,
        slippage_bps: u64,
    ) -> SmartSwapPreview {
        if amount_in_bits_or_units == 0 {
            return SmartSwapPreview {
                amm_out: 0,
                orderbook_out: 0,
                best_out: 0,
                min_out_after_slippage: 0,
                venue: SmartSwapVenue::NoLiquidity,
                price_impact_bps: 0,
            };
        }

        let capped_slip = slippage_bps.min(5_000);
        if is_buy_asset {
            let dx_bits = amount_in_bits_or_units;
            let amm_out = self
                .pool_for(asset_id)
                .and_then(|p| {
                    amm_constant_product_out(p.reserve_xcr.bits(), p.reserve_asset, dx_bits)
                })
                .unwrap_or(0);

            let mut rem_bits = dx_bits;
            let mut ob_units = 0u64;
            for ask in self.sorted_asks(asset_id) {
                if ask.price_bits_per_unit == 0 || rem_bits < ask.price_bits_per_unit {
                    break;
                }
                let affordable = rem_bits / ask.price_bits_per_unit;
                let take = affordable.min(ask.remaining_units);
                if take == 0 {
                    break;
                }
                ob_units = ob_units.saturating_add(take);
                rem_bits = rem_bits.saturating_sub(take.saturating_mul(ask.price_bits_per_unit));
            }

            let (best_out, venue) = if amm_out >= ob_units && amm_out > 0 {
                (amm_out, SmartSwapVenue::AmmPool)
            } else if ob_units > 0 {
                (ob_units, SmartSwapVenue::LimitOrderbook)
            } else {
                (0, SmartSwapVenue::NoLiquidity)
            };

            let impact_bps = if venue == SmartSwapVenue::AmmPool
                && let Some(p) = self.pool_for(asset_id)
                && !p.reserve_xcr.is_zero()
            {
                ((dx_bits as u128 * 10_000) / (p.reserve_xcr.bits() as u128 + dx_bits as u128))
                    as u64
            } else {
                0
            };

            let min_out = ((best_out as u128 * (10_000 - capped_slip) as u128) / 10_000) as u64;
            SmartSwapPreview {
                amm_out,
                orderbook_out: ob_units,
                best_out,
                min_out_after_slippage: min_out.max(u64::from(best_out > 0)),
                venue,
                price_impact_bps: impact_bps,
            }
        } else {
            let dx_units = amount_in_bits_or_units;
            let amm_out_bits = self
                .pool_for(asset_id)
                .and_then(|p| {
                    amm_constant_product_out(p.reserve_asset, p.reserve_xcr.bits(), dx_units)
                })
                .unwrap_or(0);

            let mut rem_units = dx_units;
            let mut ob_out_bits = 0u64;
            for bid in self.sorted_bids(asset_id) {
                if rem_units == 0 {
                    break;
                }
                let take = rem_units.min(bid.remaining_units);
                let payout = take.saturating_mul(bid.price_bits_per_unit);
                if payout > bid.escrowed_xcr.bits() {
                    continue;
                }
                ob_out_bits = ob_out_bits.saturating_add(payout);
                rem_units -= take;
            }
            let ob_effective = if rem_units == 0 { ob_out_bits } else { 0 };

            let (best_out, venue) = if amm_out_bits >= ob_effective && amm_out_bits > 0 {
                (amm_out_bits, SmartSwapVenue::AmmPool)
            } else if ob_effective > 0 {
                (ob_effective, SmartSwapVenue::LimitOrderbook)
            } else {
                (0, SmartSwapVenue::NoLiquidity)
            };

            let impact_bps = if venue == SmartSwapVenue::AmmPool
                && let Some(p) = self.pool_for(asset_id)
                && p.reserve_asset > 0
            {
                ((dx_units as u128 * 10_000) / (p.reserve_asset as u128 + dx_units as u128)) as u64
            } else {
                0
            };

            let min_out = ((best_out as u128 * (10_000 - capped_slip) as u128) / 10_000) as u64;
            SmartSwapPreview {
                amm_out: amm_out_bits,
                orderbook_out: ob_effective,
                best_out,
                min_out_after_slippage: min_out.max(u64::from(best_out > 0)),
                venue,
                price_impact_bps: impact_bps,
            }
        }
    }
}

// ============================================================================
// Deterministic Scoped `DexTradeOnly` RoleProxy Helpers (`0` Withdrawal Power)
// ============================================================================

pub fn derive_dex_bot_proxy_seed(master_seed: &[u8; 32]) -> [u8; 32] {
    domain_hash("XCR.DESKTOP.DEX_PROXY_BOT.V1", &[master_seed]).0
}

pub fn dex_bot_proxy_pubkey(proxy_seed: &[u8; 32]) -> PublicKey {
    let sk = domain_hash("XCR.WALLET.POCKET_KEY.V1", &[proxy_seed]).0;
    Keypair::from_seed(SignatureScheme::PasskeyP256, sk).public_key()
}

pub fn random_salt16(tag: &str) -> [u8; 16] {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let h = domain_hash(
        tag,
        &[&nanos.to_le_bytes(), &std::process::id().to_le_bytes()],
    )
    .0;
    let mut s = [0u8; 16];
    s.copy_from_slice(&h[..16]);
    s
}

/// Binds (`enable = true`) or revokes (`enable = false`) the local `DexTradeOnly` RoleProxy on Layer-1.
pub fn bind_or_revoke_dex_proxy(
    master_seed: &[u8; 32],
    enable: bool,
    node_addr: SocketAddr,
) -> io::Result<(PublicKey, NodeRpcResponse)> {
    let proxy_seed = derive_dex_bot_proxy_seed(master_seed);
    let proxy_pubkey = dex_bot_proxy_pubkey(&proxy_seed);
    let role = if enable {
        PROXY_ROLE_DEX_TRADE_ONLY
    } else {
        PROXY_ROLE_REVOKE
    };
    let salt = random_salt16("XCR.DESKTOP.ROLE_BIND_SALT.V1");
    let fee = Amount::from_bits(MIN_BASE_FEE_BITS);
    let (owner, actor_pubkey, tx_id, sig65) =
        sign_role_proxy_bind(master_seed, &proxy_pubkey, role, salt)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
    let resp = rpc_call(
        node_addr,
        &NodeRpcRequest::BindOrExecuteRoleProxy {
            is_execute: false,
            tx_id,
            owner,
            actor_pubkey,
            proxy_pubkey,
            role,
            target_id: Hash32::ZERO,
            vote_choice_or_side: 0,
            units: 0,
            price_bits: 0,
            fee,
            salt,
            sig65,
        },
        Duration::from_secs(3),
    )?;
    Ok((proxy_pubkey, resp))
}

/// Places a limit order strictly via the non-withdrawal `PROXY_ROLE_DEX_TRADE_ONLY` delegate key.
#[allow(clippy::too_many_arguments)]
pub fn submit_proxy_dex_quote(
    proxy_seed: &[u8; 32],
    owner: Address,
    asset_id: Hash32,
    is_sell: bool,
    units: u64,
    price_bits: u64,
    node_addr: SocketAddr,
) -> io::Result<NodeRpcResponse> {
    let salt = random_salt16("XCR.DESKTOP.PROXY_QUOTE_SALT.V1");
    let side_u8 = u8::from(is_sell);
    let (actor_pubkey, tx_id, sig65) = sign_proxy_execute(
        proxy_seed,
        &owner,
        PROXY_ROLE_DEX_TRADE_ONLY,
        &asset_id,
        side_u8,
        units,
        price_bits,
        salt,
    );
    rpc_call(
        node_addr,
        &NodeRpcRequest::BindOrExecuteRoleProxy {
            is_execute: true,
            tx_id,
            owner,
            actor_pubkey,
            proxy_pubkey: actor_pubkey,
            role: PROXY_ROLE_DEX_TRADE_ONLY,
            target_id: asset_id,
            vote_choice_or_side: side_u8,
            units,
            price_bits,
            fee: Amount::from_bits(MIN_BASE_FEE_BITS),
            salt,
            sig65,
        },
        Duration::from_secs(3),
    )
}

pub type ExchangeNetworkPayload = (
    Vec<MarketAssetInfo>,
    Vec<AmmPoolView>,
    Vec<OrderbookRow>,
    Vec<OracleFeedView>,
);

/// Polls asset balances, AMM pools, oracle feeds, and open DEX limit orders in non-blocking RPCs.
pub fn fetch_exchange_network_data(
    owner: Address,
    primary: SocketAddr,
    fallback: SocketAddr,
) -> Option<ExchangeNetworkPayload> {
    let assets_resp = rpc_call(
        primary,
        &NodeRpcRequest::GetAssetBalances { owner: Some(owner) },
        Duration::from_millis(850),
    )
    .or_else(|_| {
        rpc_call(
            fallback,
            &NodeRpcRequest::GetAssetBalances { owner: Some(owner) },
            Duration::from_millis(950),
        )
    })
    .ok()?;

    let NodeRpcResponse::AssetPortfolio { assets: raw_assets } = assets_resp else {
        return None;
    };

    let amm_resp = rpc_call(
        fallback,
        &NodeRpcRequest::GetAmmAndOracleSnapshot,
        Duration::from_millis(950),
    )
    .or_else(|_| {
        rpc_call(
            primary,
            &NodeRpcRequest::GetAmmAndOracleSnapshot,
            Duration::from_millis(850),
        )
    })
    .ok();

    let book_resp = rpc_call(
        fallback,
        &NodeRpcRequest::GetDexOrderbook { asset_id: None },
        Duration::from_millis(950),
    )
    .or_else(|_| {
        rpc_call(
            primary,
            &NodeRpcRequest::GetDexOrderbook { asset_id: None },
            Duration::from_millis(850),
        )
    })
    .ok();

    let assets: Vec<MarketAssetInfo> = raw_assets
        .into_iter()
        .map(
            |(asset_id, ticker, total_supply, decimals, owner_balance): AssetWireRecord| {
                MarketAssetInfo {
                    asset_id,
                    ticker,
                    total_supply,
                    decimals,
                    owner_balance,
                }
            },
        )
        .collect();

    let mut pools = Vec::new();
    let mut oracles = Vec::new();
    if let Some(NodeRpcResponse::AmmAndOracleSnapshot {
        pools: raw_pools,
        feeds: raw_feeds,
    }) = amm_resp
    {
        pools = raw_pools
            .into_iter()
            .map(
                |(asset_id, ticker, reserve_xcr, reserve_asset, total_lp_shares): AmmPoolWireRecord| {
                    AmmPoolView {
                        asset_id,
                        ticker,
                        reserve_xcr,
                        reserve_asset,
                        total_lp_shares,
                    }
                },
            )
            .collect();
        oracles = raw_feeds
            .into_iter()
            .map(
                |(feed_id, median_micros, reporter_count, _ts): OracleFeedWireRecord| {
                    OracleFeedView {
                        feed_id,
                        median_micros,
                        reporter_count,
                    }
                },
            )
            .collect();
    }

    let mut orders = Vec::new();
    if let Some(NodeRpcResponse::DexOrderbookSnapshot { orders: raw_orders }) = book_resp {
        orders = raw_orders
            .into_iter()
            .map(
                |(
                    order_id,
                    maker,
                    asset_id,
                    is_sell_asset,
                    remaining_units,
                    price_bits_per_unit,
                    escrowed_xcr,
                ): DexOrderWireRecord| OrderbookRow {
                    order_id,
                    maker,
                    asset_id,
                    is_sell_asset,
                    remaining_units,
                    price_bits_per_unit,
                    escrowed_xcr,
                },
            )
            .collect();
    }

    Some((assets, pools, orders, oracles))
}

// ============================================================================
// Native `egui` Exchange Tab UI State & Renderer
// ============================================================================

pub struct ExchangeUiState {
    pub sub_tab: ExchangeSubTab,
    pub swap_buy_asset: bool,
    pub swap_input_str: String,
    pub swap_slippage_bps: u64,
    pub order_is_sell: bool,
    pub order_units_str: String,
    pub order_price_xcr_str: String,
    pub order_ioc: bool,
    pub amm_xcr_str: String,
    pub amm_units_str: String,
    pub amm_burn_lp_str: String,
    pub bot_half_spread_bps: u64,
    pub bot_units_per_side: u64,
    pub bot_max_xcr_str: String,
    pub launch_ticker: String,
    pub launch_supply_str: String,
    pub launch_pool_xcr_str: String,
    pub launch_pool_units_str: String,
}

impl Default for ExchangeUiState {
    fn default() -> Self {
        Self {
            sub_tab: ExchangeSubTab::SimpleSwap,
            swap_buy_asset: true,
            swap_input_str: String::from("2.00"),
            swap_slippage_bps: 100, // 1.00%
            order_is_sell: false,
            order_units_str: String::from("10"),
            order_price_xcr_str: String::from("0.500000"),
            order_ioc: false,
            amm_xcr_str: String::from("5.00"),
            amm_units_str: String::from("10"),
            amm_burn_lp_str: String::from("100"),
            bot_half_spread_bps: 75,
            bot_units_per_side: 5,
            bot_max_xcr_str: String::from("20.00"),
            launch_ticker: String::from("USDX"),
            launch_supply_str: String::from("1000000"),
            launch_pool_xcr_str: String::from("10.00"),
            launch_pool_units_str: String::from("20"),
        }
    }
}

fn format_price_bits(bits: u64, hide: bool) -> String {
    if hide {
        String::from("∀ ••••••")
    } else {
        let w = bits / BITS_PER_CREDIT;
        let f = bits % BITS_PER_CREDIT;
        format!("∀ {w}.{f:06}")
    }
}

fn format_units(units: u64, ticker: &str, hide: bool) -> String {
    if hide {
        format!("•••• {ticker}")
    } else {
        format!("{units} {ticker}")
    }
}

pub fn render_exchange_tab(
    ui: &mut egui::Ui,
    snap: &UiSnapshot,
    ex_ui: &mut ExchangeUiState,
    cmd_tx: &std::sync::mpsc::Sender<UserCommand>,
) {
    let ex = &snap.exchange;
    let avail_xcr = snap.available_wallet_balance();

    // 1. Market Header Strip (Pair Selector + Live Mid-Price, Pool TVL, & Balances)
    egui::Frame::NONE
        .fill(BG_CARD)
        .stroke(Stroke::new(1.0_f32, BORDER_SUBTLE))
        .corner_radius(CornerRadius::same(12))
        .inner_margin(egui::Margin::symmetric(16, 12))
        .show(ui, |ui| {
            ui.horizontal_wrapped(|ui| {
                ui.label(RichText::new("⇄ Sovereign DEX").size(18.0).strong());
                ui.separator();

                if let Some(cur) = ex.active_asset() {
                    let selected_lbl = format!("{} / XCR", cur.ticker);
                    egui::ComboBox::from_id_salt("dex_market_pair")
                        .selected_text(RichText::new(selected_lbl).strong().color(ACCENT_GOLD))
                        .show_ui(ui, |ui| {
                            for asset in &ex.assets {
                                let is_sel = cur.asset_id == asset.asset_id;
                                let row_txt = format!(
                                    "{} / XCR  (Bal: {})",
                                    asset.ticker,
                                    format_units(
                                        asset.owner_balance,
                                        &asset.ticker,
                                        snap.hide_figures
                                    )
                                );
                                if ui.selectable_label(is_sel, row_txt).clicked() {
                                    let _ = cmd_tx
                                        .send(UserCommand::SelectExchangeAsset(asset.asset_id));
                                }
                            }
                        });

                    if let Some(mid) = ex.mid_price_bits(&cur.asset_id) {
                        ui.separator();
                        ui.label(RichText::new("Mid:").small().color(TEXT_MUTED));
                        ui.label(
                            RichText::new(format!(
                                "{} XCR",
                                format_price_bits(mid, snap.hide_figures)
                            ))
                            .strong()
                            .monospace()
                            .color(ACCENT_EMERALD),
                        );
                    }

                    if let Some(pool) = ex.pool_for(&cur.asset_id) {
                        ui.separator();
                        ui.label(
                            RichText::new(format!(
                                "AMM Pool: {} + {}",
                                snap.display_amount(pool.reserve_xcr),
                                format_units(pool.reserve_asset, &cur.ticker, snap.hide_figures)
                            ))
                            .small()
                            .color(TEXT_MUTED),
                        );
                    }

                    ui.separator();
                    ui.label(
                        RichText::new(format!(
                            "My {}: {}",
                            cur.ticker,
                            format_units(cur.owner_balance, &cur.ticker, snap.hide_figures)
                        ))
                        .small()
                        .strong()
                        .color(ACCENT_BLUE),
                    );
                } else {
                    ui.label(
                        RichText::new("No Native Asset markets listed yet on this network.")
                            .color(TEXT_MUTED),
                    );
                    if ui
                        .add(
                            egui::Button::new(
                                RichText::new("⚡ 1-Click Seed Demo Market (USDX)")
                                    .strong()
                                    .color(Color32::BLACK),
                            )
                            .fill(ACCENT_GOLD),
                        )
                        .clicked()
                    {
                        let _ = cmd_tx.send(UserCommand::LaunchAssetAndOptionalPool {
                            ticker: String::from("USDX"),
                            total_supply: 1_000_000,
                            pool_xcr_str: String::from("5.00"),
                            pool_units: 100,
                        });
                    }
                }

                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if ui.small_button("🔄 Refresh").clicked() {
                        let _ = cmd_tx.send(UserCommand::RefreshExchangeNow);
                    }
                    ui.label(
                        RichText::new(format!("Spendable: {}", snap.display_amount(avail_xcr)))
                            .small()
                            .color(ACCENT_GOLD),
                    );
                });
            });
        });

    // 2. Mode Sub-Navigation Bar
    ui.horizontal(|ui| {
        ui.selectable_value(
            &mut ex_ui.sub_tab,
            ExchangeSubTab::SimpleSwap,
            "⚡ Instant Swap",
        );
        ui.selectable_value(
            &mut ex_ui.sub_tab,
            ExchangeSubTab::ProOrderbook,
            "📊 Pro Orderbook",
        );
        ui.selectable_value(
            &mut ex_ui.sub_tab,
            ExchangeSubTab::LiquidityPools,
            "💧 AMM Pools",
        );
        let bot_tab_lbl = if ex.spread_bot.enabled {
            "🤖 Spread Bot (ON)"
        } else {
            "🤖 Spread Bot"
        };
        ui.selectable_value(&mut ex_ui.sub_tab, ExchangeSubTab::SpreadBot, bot_tab_lbl);
        ui.selectable_value(
            &mut ex_ui.sub_tab,
            ExchangeSubTab::LaunchAsset,
            "🚀 Launch Token",
        );
    });

    // 3. Sub-Tab Content
    egui::ScrollArea::vertical()
        .auto_shrink([false, false])
        .show(ui, |ui| match ex_ui.sub_tab {
            ExchangeSubTab::SimpleSwap => render_simple_swap(ui, snap, ex_ui, cmd_tx),
            ExchangeSubTab::ProOrderbook => render_pro_orderbook(ui, snap, ex_ui, cmd_tx),
            ExchangeSubTab::LiquidityPools => render_amm_pools(ui, snap, ex_ui, cmd_tx),
            ExchangeSubTab::SpreadBot => render_spread_bot(ui, snap, ex_ui, cmd_tx),
            ExchangeSubTab::LaunchAsset => render_launch_asset(ui, snap, ex_ui, cmd_tx),
        });
}

fn render_simple_swap(
    ui: &mut egui::Ui,
    snap: &UiSnapshot,
    ex_ui: &mut ExchangeUiState,
    cmd_tx: &std::sync::mpsc::Sender<UserCommand>,
) {
    let ex = &snap.exchange;
    let Some(asset) = ex.active_asset() else {
        render_empty_market_prompt(ui, ex_ui, cmd_tx);
        return;
    };

    ui.columns(2, |cols| {
        // Left Card: 1-Click Hybrid Smart Swap Ticket
        egui::Frame::NONE
            .fill(BG_CARD)
            .stroke(Stroke::new(1.0_f32, BORDER_SUBTLE))
            .corner_radius(CornerRadius::same(12))
            .inner_margin(egui::Margin::same(18))
            .show(&mut cols[0], |ui| {
                ui.horizontal(|ui| {
                    ui.label(
                        RichText::new("⚡ Hybrid Smart Swap")
                            .size(18.0)
                            .strong(),
                    );
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        if ui.button("⇅ Flip Direction").clicked() {
                            ex_ui.swap_buy_asset = !ex_ui.swap_buy_asset;
                            ex_ui.swap_input_str = if ex_ui.swap_buy_asset {
                                String::from("2.00")
                            } else {
                                String::from("5")
                            };
                        }
                    });
                });
                ui.label(
                    RichText::new(
                        "Automatically compares AMM (x·y=k) vs Limit Orderbook and settles atomically in ~200 ms with zero MEV.",
                    )
                    .small()
                    .color(TEXT_MUTED),
                );
                ui.add_space(8.0);

                let amount_in_raw: u64 = if ex_ui.swap_buy_asset {
                    ui.label(format!(
                        "You Pay (XCR) — Spendable: {}",
                        snap.display_amount(snap.available_wallet_balance())
                    ));
                    ui.add(
                        egui::TextEdit::singleline(&mut ex_ui.swap_input_str)
                            .hint_text("2.00")
                            .desired_width(200.0),
                    );
                    parse_decimal_xcr(&ex_ui.swap_input_str)
                        .map(|a| a.bits())
                        .unwrap_or(0)
                } else {
                    ui.label(format!(
                        "You Sell ({}) — Owned: {}",
                        asset.ticker,
                        format_units(asset.owner_balance, &asset.ticker, snap.hide_figures)
                    ));
                    ui.add(
                        egui::TextEdit::singleline(&mut ex_ui.swap_input_str)
                            .hint_text("10")
                            .desired_width(200.0),
                    );
                    ex_ui.swap_input_str.trim().parse::<u64>().unwrap_or(0)
                };

                ui.add_space(6.0);
                ui.horizontal(|ui| {
                    ui.label(RichText::new("Max Slippage:").small().color(TEXT_MUTED));
                    for (bps, lbl) in [(50u64, "0.5%"), (100, "1.0%"), (250, "2.5%")] {
                        if ui
                            .selectable_label(ex_ui.swap_slippage_bps == bps, lbl)
                            .clicked()
                        {
                            ex_ui.swap_slippage_bps = bps;
                        }
                    }
                });

                let quote = ex.quote_smart_swap(
                    &asset.asset_id,
                    ex_ui.swap_buy_asset,
                    amount_in_raw,
                    ex_ui.swap_slippage_bps,
                );

                ui.add_space(8.0);
                egui::Frame::NONE
                    .fill(BG_INPUT)
                    .stroke(Stroke::new(1.0_f32, BORDER_SUBTLE))
                    .corner_radius(CornerRadius::same(10))
                    .inner_margin(egui::Margin::same(12))
                    .show(ui, |ui| {
                        let out_display = if ex_ui.swap_buy_asset {
                            format_units(quote.best_out, &asset.ticker, snap.hide_figures)
                        } else {
                            snap.display_amount(Amount::from_bits(quote.best_out))
                        };
                        ui.label(RichText::new("Estimated Output:").small().color(TEXT_MUTED));
                        ui.label(
                            RichText::new(out_display)
                                .size(22.0)
                                .strong()
                                .color(ACCENT_EMERALD),
                        );

                        let route_badge = match quote.venue {
                            SmartSwapVenue::AmmPool => format!(
                                "🏆 Route: AMM Pool (AMM={} vs Book={}) · Impact {:.2}%",
                                quote.amm_out,
                                quote.orderbook_out,
                                quote.price_impact_bps as f64 / 100.0
                            ),
                            SmartSwapVenue::LimitOrderbook => format!(
                                "🏆 Route: Limit Orderbook (Book={} beat AMM={}) · 0% curve slippage",
                                quote.orderbook_out, quote.amm_out
                            ),
                            SmartSwapVenue::NoLiquidity => {
                                String::from("⚠ Insufficient pool/book depth for this size")
                            }
                        };
                        ui.label(RichText::new(route_badge).small().color(ACCENT_GOLD));
                    });

                ui.add_space(10.0);
                let btn_lbl = if ex_ui.swap_buy_asset {
                    format!("⚡ Swap XCR -> {}", asset.ticker)
                } else {
                    format!("⚡ Swap {} -> XCR", asset.ticker)
                };
                let can_exec = quote.best_out > 0;
                if ui
                    .add_enabled_ui(can_exec, |ui| {
                        ui.add_sized(
                            [ui.available_width(), 42.0],
                            egui::Button::new(
                                RichText::new(btn_lbl).strong().color(Color32::BLACK),
                            )
                            .fill(ACCENT_EMERALD),
                        )
                    })
                    .inner
                    .clicked()
                {
                    let _ = cmd_tx.send(UserCommand::ExecuteSmartSwap {
                        asset_id: asset.asset_id,
                        ticker: asset.ticker.clone(),
                        is_buy_asset: ex_ui.swap_buy_asset,
                        amount_in_bits_or_units: amount_in_raw,
                        min_out_units_or_bits: quote.min_out_after_slippage,
                    });
                }
            });

        // Right Card: Live Orderbook Snapshot & Safety Guarantees
        egui::Frame::NONE
            .fill(BG_CARD)
            .stroke(Stroke::new(1.0_f32, BORDER_SUBTLE))
            .corner_radius(CornerRadius::same(12))
            .inner_margin(egui::Margin::same(18))
            .show(&mut cols[1], |ui| {
                ui.label(
                    RichText::new(format!("📖 Live {} / XCR Market Depth", asset.ticker))
                        .size(16.5)
                        .strong(),
                );
                render_compact_depth_ladder(ui, ex, &asset.asset_id, &asset.ticker, ex_ui, snap.hide_figures);
                ui.add_space(8.0);
                ui.separator();
                ui.label(
                    RichText::new("🛡 Sovereign Custody Guarantees:")
                        .small()
                        .strong()
                        .color(ACCENT_BLUE),
                );
                ui.label(
                    RichText::new(
                        "• 100% self-custody: funds stay in your Pocket until 1-RTT atomic settlement.\n• Your 24-Hour Safety Vault balance is strictly isolated from exchange spending.\n• Zero MEV sandwiching: SmartRouter enforces your exact signed min-output on L1.",
                    )
                    .small()
                    .color(TEXT_MUTED),
                );
            });
    });
}

fn render_compact_depth_ladder(
    ui: &mut egui::Ui,
    ex: &ExchangeSnapshot,
    asset_id: &Hash32,
    ticker: &str,
    ex_ui: &mut ExchangeUiState,
    hide: bool,
) {
    let asks = ex.sorted_asks(asset_id);
    let bids = ex.sorted_bids(asset_id);
    let max_units = asks
        .iter()
        .chain(bids.iter())
        .map(|o| o.remaining_units)
        .max()
        .unwrap_or(1)
        .max(1);

    ui.label(RichText::new("Asks (Sellers)").small().color(DANGER_RED));
    if asks.is_empty() {
        ui.label(
            RichText::new("  No resting limit asks")
                .small()
                .color(TEXT_MUTED),
        );
    } else {
        for ask in asks.iter().take(5).rev() {
            let ratio = (ask.remaining_units as f32 / max_units as f32).clamp(0.06, 1.0);
            let row_txt = format!(
                "Ask {:>12} XCR  |  {:>6} {ticker}",
                format_price_bits(ask.price_bits_per_unit, hide),
                if hide {
                    "•••".to_owned()
                } else {
                    ask.remaining_units.to_string()
                }
            );
            if ui
                .add(
                    egui::Button::new(RichText::new(row_txt).small().monospace().color(DANGER_RED))
                        .fill(Color32::from_rgba_unmultiplied(
                            239,
                            68,
                            68,
                            (25.0 + 60.0 * ratio) as u8,
                        )),
                )
                .on_hover_text("Click to copy this price into the Limit Order ticket")
                .clicked()
            {
                let w = ask.price_bits_per_unit / BITS_PER_CREDIT;
                let f = ask.price_bits_per_unit % BITS_PER_CREDIT;
                ex_ui.order_price_xcr_str = format!("{w}.{f:06}");
            }
        }
    }

    if let Some(mid) = ex.mid_price_bits(asset_id) {
        ui.label(
            RichText::new(format!(
                "── Mid Price: {} XCR ──",
                format_price_bits(mid, hide)
            ))
            .small()
            .strong()
            .monospace()
            .color(ACCENT_GOLD),
        );
    }

    ui.label(RichText::new("Bids (Buyers)").small().color(ACCENT_EMERALD));
    if bids.is_empty() {
        ui.label(
            RichText::new("  No resting limit bids")
                .small()
                .color(TEXT_MUTED),
        );
    } else {
        for bid in bids.iter().take(5) {
            let ratio = (bid.remaining_units as f32 / max_units as f32).clamp(0.06, 1.0);
            let row_txt = format!(
                "Bid {:>12} XCR  |  {:>6} {ticker}",
                format_price_bits(bid.price_bits_per_unit, hide),
                if hide {
                    "•••".to_owned()
                } else {
                    bid.remaining_units.to_string()
                }
            );
            if ui
                .add(
                    egui::Button::new(
                        RichText::new(row_txt)
                            .small()
                            .monospace()
                            .color(ACCENT_EMERALD),
                    )
                    .fill(Color32::from_rgba_unmultiplied(
                        16,
                        185,
                        129,
                        (25.0 + 60.0 * ratio) as u8,
                    )),
                )
                .on_hover_text("Click to copy this price into the Limit Order ticket")
                .clicked()
            {
                let w = bid.price_bits_per_unit / BITS_PER_CREDIT;
                let f = bid.price_bits_per_unit % BITS_PER_CREDIT;
                ex_ui.order_price_xcr_str = format!("{w}.{f:06}");
            }
        }
    }
}

fn render_pro_orderbook(
    ui: &mut egui::Ui,
    snap: &UiSnapshot,
    ex_ui: &mut ExchangeUiState,
    cmd_tx: &std::sync::mpsc::Sender<UserCommand>,
) {
    let ex = &snap.exchange;
    let Some(asset) = ex.active_asset() else {
        render_empty_market_prompt(ui, ex_ui, cmd_tx);
        return;
    };

    ui.columns(2, |cols| {
        // Left: Orderbook Ladder + My Open Orders
        egui::Frame::NONE
            .fill(BG_CARD)
            .stroke(Stroke::new(1.0_f32, BORDER_SUBTLE))
            .corner_radius(CornerRadius::same(12))
            .inner_margin(egui::Margin::same(16))
            .show(&mut cols[0], |ui| {
                ui.label(
                    RichText::new(format!("📊 {} / XCR Central Limit Orderbook", asset.ticker))
                        .size(17.0)
                        .strong(),
                );
                render_compact_depth_ladder(
                    ui,
                    ex,
                    &asset.asset_id,
                    &asset.ticker,
                    ex_ui,
                    snap.hide_figures,
                );

                ui.add_space(10.0);
                ui.separator();
                ui.label(RichText::new("My Open Limit Orders:").strong());
                let my_orders: Vec<&OrderbookRow> = ex
                    .orders
                    .iter()
                    .filter(|o| o.maker == snap.pocket_address && o.remaining_units > 0)
                    .collect();
                if my_orders.is_empty() {
                    ui.label(
                        RichText::new("You have no active open limit orders.")
                            .small()
                            .color(TEXT_MUTED),
                    );
                } else {
                    for ord in my_orders {
                        let side_str = if ord.is_sell_asset { "SELL" } else { "BUY" };
                        let side_col = if ord.is_sell_asset {
                            DANGER_RED
                        } else {
                            ACCENT_EMERALD
                        };
                        ui.horizontal(|ui| {
                            ui.label(RichText::new(side_str).small().strong().color(side_col));
                            ui.label(
                                RichText::new(format!(
                                    "{} @ {} XCR",
                                    format_units(
                                        ord.remaining_units,
                                        &asset.ticker,
                                        snap.hide_figures
                                    ),
                                    format_price_bits(ord.price_bits_per_unit, snap.hide_figures)
                                ))
                                .small()
                                .monospace(),
                            );
                            if ui.small_button("✕ Cancel").clicked() {
                                let _ = cmd_tx.send(UserCommand::CancelDexLimitOrder {
                                    order_id: ord.order_id,
                                });
                            }
                        });
                    }
                }
            });

        // Right: Limit / IOC Order Entry Ticket
        egui::Frame::NONE
            .fill(BG_CARD)
            .stroke(Stroke::new(1.0_f32, BORDER_SUBTLE))
            .corner_radius(CornerRadius::same(12))
            .inner_margin(egui::Margin::same(18))
            .show(&mut cols[1], |ui| {
                ui.label(
                    RichText::new("Place Escrowed Limit Order")
                        .size(17.0)
                        .strong(),
                );
                ui.horizontal(|ui| {
                    ui.selectable_value(
                        &mut ex_ui.order_is_sell,
                        false,
                        RichText::new(format!("Buy {}", asset.ticker))
                            .strong()
                            .color(ACCENT_EMERALD),
                    );
                    ui.selectable_value(
                        &mut ex_ui.order_is_sell,
                        true,
                        RichText::new(format!("Sell {}", asset.ticker))
                            .strong()
                            .color(DANGER_RED),
                    );
                });

                ui.add_space(6.0);
                ui.label(format!("Quantity ({} whole units):", asset.ticker));
                ui.add(
                    egui::TextEdit::singleline(&mut ex_ui.order_units_str)
                        .hint_text("10")
                        .desired_width(160.0),
                );

                ui.label("Limit Price per Unit (XCR):");
                ui.add(
                    egui::TextEdit::singleline(&mut ex_ui.order_price_xcr_str)
                        .hint_text("0.500000")
                        .desired_width(160.0),
                );

                ui.checkbox(
                    &mut ex_ui.order_ioc,
                    "Immediate-Or-Cancel (IOC — fill immediately or cancel remainder)",
                );

                let units = ex_ui.order_units_str.trim().parse::<u64>().unwrap_or(0);
                let price_bits = parse_decimal_xcr(&ex_ui.order_price_xcr_str)
                    .map(|a| a.bits())
                    .unwrap_or(0);
                let total_quote_bits = units.saturating_mul(price_bits);

                ui.add_space(6.0);
                ui.label(
                    RichText::new(format!(
                        "Order Value: {}",
                        snap.display_amount(Amount::from_bits(total_quote_bits))
                    ))
                    .strong()
                    .color(ACCENT_GOLD),
                );

                ui.add_space(8.0);
                let action_color = if ex_ui.order_is_sell {
                    DANGER_RED
                } else {
                    ACCENT_EMERALD
                };
                let btn_txt = if ex_ui.order_is_sell {
                    format!("Place Limit SELL ({} {})", units, asset.ticker)
                } else {
                    format!("Place Limit BUY ({} {})", units, asset.ticker)
                };
                if ui
                    .add_sized(
                        [ui.available_width(), 40.0],
                        egui::Button::new(RichText::new(btn_txt).strong().color(TEXT_PRIMARY))
                            .fill(action_color),
                    )
                    .clicked()
                {
                    let _ = cmd_tx.send(UserCommand::PlaceDexLimitOrder {
                        asset_id: asset.asset_id,
                        ticker: asset.ticker.clone(),
                        is_sell_asset: ex_ui.order_is_sell,
                        units,
                        price_bits_per_unit: price_bits,
                        immediate_or_cancel: ex_ui.order_ioc,
                    });
                }
            });
    });
}

fn render_amm_pools(
    ui: &mut egui::Ui,
    snap: &UiSnapshot,
    ex_ui: &mut ExchangeUiState,
    cmd_tx: &std::sync::mpsc::Sender<UserCommand>,
) {
    let ex = &snap.exchange;
    let Some(asset) = ex.active_asset() else {
        render_empty_market_prompt(ui, ex_ui, cmd_tx);
        return;
    };

    ui.columns(2, |cols| {
        egui::Frame::NONE
            .fill(BG_CARD)
            .stroke(Stroke::new(1.0_f32, BORDER_SUBTLE))
            .corner_radius(CornerRadius::same(12))
            .inner_margin(egui::Margin::same(18))
            .show(&mut cols[0], |ui| {
                ui.label(
                    RichText::new(format!("💧 Provide Liquidity ({} / XCR)", asset.ticker))
                        .size(17.5)
                        .strong(),
                );
                ui.label(
                    RichText::new(
                        "Earn 0.30% auto-compounding LP fees on every AMM swap (k_after >= k_before).",
                    )
                    .small()
                    .color(TEXT_MUTED),
                );
                ui.add_space(8.0);
                if let Some(pool) = ex.pool_for(&asset.asset_id) {
                    ui.label(format!(
                        "Pool Reserves: {} + {}  (Total LP Shares: {})",
                        snap.display_amount(pool.reserve_xcr),
                        format_units(pool.reserve_asset, &asset.ticker, snap.hide_figures),
                        pool.total_lp_shares
                    ));
                } else {
                    ui.label(
                        RichText::new(
                            "No AMM pool initialized for this asset yet — your first deposit sets the initial price!",
                        )
                        .small()
                        .color(ACCENT_GOLD),
                    );
                }
                ui.add_space(6.0);
                ui.label("Deposit XCR:");
                ui.add(
                    egui::TextEdit::singleline(&mut ex_ui.amm_xcr_str).desired_width(150.0),
                );
                ui.label(format!("Deposit {} Units:", asset.ticker));
                ui.add(
                    egui::TextEdit::singleline(&mut ex_ui.amm_units_str).desired_width(150.0),
                );
                ui.add_space(8.0);
                if ui
                    .add_sized(
                        [ui.available_width(), 38.0],
                        egui::Button::new(
                            RichText::new("➕ Add AMM Liquidity")
                                .strong()
                                .color(Color32::BLACK),
                        )
                        .fill(ACCENT_EMERALD),
                    )
                    .clicked()
                {
                    let _ = cmd_tx.send(UserCommand::ModifyAmmLiquidity {
                        asset_id: asset.asset_id,
                        ticker: asset.ticker.clone(),
                        is_remove: false,
                        xcr_amount_str: ex_ui.amm_xcr_str.clone(),
                        units_or_lp_str: ex_ui.amm_units_str.clone(),
                    });
                }
            });

        egui::Frame::NONE
            .fill(BG_CARD)
            .stroke(Stroke::new(1.0_f32, BORDER_SUBTLE))
            .corner_radius(CornerRadius::same(12))
            .inner_margin(egui::Margin::same(18))
            .show(&mut cols[1], |ui| {
                ui.label(
                    RichText::new("📤 Withdraw Liquidity (Burn LP Shares)")
                        .size(17.5)
                        .strong(),
                );
                ui.label(
                    RichText::new(
                        "Redeem your LP shares at any time for your proportional share of XCR + Asset reserves.",
                    )
                    .small()
                    .color(TEXT_MUTED),
                );
                ui.add_space(12.0);
                ui.label("LP Shares to Redeem:");
                ui.add(
                    egui::TextEdit::singleline(&mut ex_ui.amm_burn_lp_str).desired_width(160.0),
                );
                ui.add_space(10.0);
                if ui
                    .add_sized(
                        [ui.available_width(), 38.0],
                        egui::Button::new(RichText::new("Withdraw Liquidity").strong())
                            .fill(ACCENT_BLUE),
                    )
                    .clicked()
                {
                    let _ = cmd_tx.send(UserCommand::ModifyAmmLiquidity {
                        asset_id: asset.asset_id,
                        ticker: asset.ticker.clone(),
                        is_remove: true,
                        xcr_amount_str: String::from("0"),
                        units_or_lp_str: ex_ui.amm_burn_lp_str.clone(),
                    });
                }
            });
    });
}

fn render_spread_bot(
    ui: &mut egui::Ui,
    snap: &UiSnapshot,
    ex_ui: &mut ExchangeUiState,
    cmd_tx: &std::sync::mpsc::Sender<UserCommand>,
) {
    let ex = &snap.exchange;
    let Some(asset) = ex.active_asset() else {
        render_empty_market_prompt(ui, ex_ui, cmd_tx);
        return;
    };

    egui::Frame::NONE
        .fill(BG_CARD)
        .stroke(Stroke::new(1.0_f32, BORDER_SUBTLE))
        .corner_radius(CornerRadius::same(12))
        .inner_margin(egui::Margin::same(20))
        .show(ui, |ui| {
            ui.horizontal(|ui| {
                ui.label(
                    RichText::new("🤖 1-Click Automated Market-Maker (Zero-Withdrawal RoleProxy)")
                        .size(18.0)
                        .strong(),
                );
                let badge = if ex.spread_bot.enabled {
                    RichText::new("● ACTIVE").strong().color(ACCENT_EMERALD)
                } else {
                    RichText::new("⏸ STOPPED").color(TEXT_MUTED)
                };
                ui.label(badge);
            });
            ui.label(
                RichText::new(
                    "Hummingbot-style two-sided spread quoting built directly into Credits Desktop. Binds an on-chain `DexTradeOnly` proxy key (`0` transfer/withdrawal power) and strictly excludes your 24-Hour Safety Vault.",
                )
                .color(TEXT_MUTED),
            );
            ui.add_space(10.0);

            ui.columns(3, |cols| {
                cols[0].label("Half-Spread (bps each side):");
                cols[0].add(
                    egui::DragValue::new(&mut ex_ui.bot_half_spread_bps)
                        .range(10..=1_000)
                        .suffix(" bps"),
                );
                cols[0].label(
                    RichText::new(format!(
                        "Round-trip spread: {:.2}%",
                        (ex_ui.bot_half_spread_bps * 2) as f64 / 100.0
                    ))
                    .small()
                    .color(ACCENT_GOLD),
                );

                cols[1].label(format!("Order Size ({} per side):", asset.ticker));
                cols[1].add(egui::DragValue::new(&mut ex_ui.bot_units_per_side).range(1..=10_000));

                cols[2].label("Max Pocket XCR Budget:");
                cols[2].add(
                    egui::TextEdit::singleline(&mut ex_ui.bot_max_xcr_str).desired_width(120.0),
                );
            });

            ui.add_space(10.0);
            ui.horizontal(|ui| {
                if !ex.spread_bot.enabled {
                    if ui
                        .add_sized(
                            [260.0, 40.0],
                            egui::Button::new(
                                RichText::new(format!(
                                    "🚀 Bind Proxy & Start Quoting {}",
                                    asset.ticker
                                ))
                                .strong()
                                .color(Color32::BLACK),
                            )
                            .fill(ACCENT_EMERALD),
                        )
                        .clicked()
                    {
                        let _ = cmd_tx.send(UserCommand::ConfigureSpreadBot {
                            enable: true,
                            asset_id: asset.asset_id,
                            half_spread_bps: ex_ui.bot_half_spread_bps,
                            units_per_side: ex_ui.bot_units_per_side,
                            max_xcr_str: ex_ui.bot_max_xcr_str.clone(),
                        });
                    }
                } else if ui
                    .add_sized(
                        [260.0, 40.0],
                        egui::Button::new(
                            RichText::new("⏹ Stop Bot & Revoke Proxy Key")
                                .strong()
                                .color(Color32::WHITE),
                        )
                        .fill(DANGER_RED),
                    )
                    .clicked()
                {
                    let _ = cmd_tx.send(UserCommand::ConfigureSpreadBot {
                        enable: false,
                        asset_id: asset.asset_id,
                        half_spread_bps: ex_ui.bot_half_spread_bps,
                        units_per_side: ex_ui.bot_units_per_side,
                        max_xcr_str: ex_ui.bot_max_xcr_str.clone(),
                    });
                }

                ui.label(
                    RichText::new(format!(
                        "Quotes Placed: {}   |   Delegate: {}",
                        ex.spread_bot.quotes_placed,
                        if ex.spread_bot.proxy_address_short.is_empty() {
                            "Not bound"
                        } else {
                            &ex.spread_bot.proxy_address_short
                        }
                    ))
                    .small()
                    .monospace()
                    .color(ACCENT_BLUE),
                );
            });

            ui.add_space(6.0);
            ui.label(
                RichText::new(&ex.spread_bot.last_status)
                    .small()
                    .color(TEXT_MUTED),
            );
        });
}

fn render_launch_asset(
    ui: &mut egui::Ui,
    _snap: &UiSnapshot,
    ex_ui: &mut ExchangeUiState,
    cmd_tx: &std::sync::mpsc::Sender<UserCommand>,
) {
    egui::Frame::NONE
        .fill(BG_CARD)
        .stroke(Stroke::new(1.0_f32, BORDER_SUBTLE))
        .corner_radius(CornerRadius::same(12))
        .inner_margin(egui::Margin::same(20))
        .show(ui, |ui| {
            ui.label(
                RichText::new("🚀 Mint Native Bearer Asset & Seed Market")
                    .size(18.0)
                    .strong(),
            );
            ui.label(
                RichText::new(
                    "Issue a Cardano-style fixed-supply Layer-1 Native Asset (no smart-contract bugs or freeze admin keys) and optionally open an immediate AMM liquidity pool.",
                )
                .color(TEXT_MUTED),
            );
            ui.add_space(10.0);

            ui.columns(2, |cols| {
                cols[0].label("Ticker Symbol (e.g. USDX, BTCX, GOLD):");
                cols[0].add(
                    egui::TextEdit::singleline(&mut ex_ui.launch_ticker).desired_width(160.0),
                );
                cols[0].label("Fixed Total Supply (whole units):");
                cols[0].add(
                    egui::TextEdit::singleline(&mut ex_ui.launch_supply_str).desired_width(160.0),
                );

                cols[1].label("Optional Initial AMM Pool XCR (0 to skip):");
                cols[1].add(
                    egui::TextEdit::singleline(&mut ex_ui.launch_pool_xcr_str).desired_width(160.0),
                );
                cols[1].label("Optional Initial AMM Pool Token Units:");
                cols[1].add(
                    egui::TextEdit::singleline(&mut ex_ui.launch_pool_units_str)
                        .desired_width(160.0),
                );
            });

            ui.add_space(12.0);
            if ui
                .add_sized(
                    [280.0, 42.0],
                    egui::Button::new(
                        RichText::new("✨ Mint Asset & Open Trading")
                            .strong()
                            .color(Color32::BLACK),
                    )
                    .fill(ACCENT_GOLD),
                )
                .clicked()
            {
                let supply = ex_ui
                    .launch_supply_str
                    .trim()
                    .parse::<u64>()
                    .unwrap_or(0);
                let pool_units = ex_ui
                    .launch_pool_units_str
                    .trim()
                    .parse::<u64>()
                    .unwrap_or(0);
                let _ = cmd_tx.send(UserCommand::LaunchAssetAndOptionalPool {
                    ticker: ex_ui.launch_ticker.trim().to_ascii_uppercase(),
                    total_supply: supply,
                    pool_xcr_str: ex_ui.launch_pool_xcr_str.clone(),
                    pool_units,
                });
            }
        });
}

fn render_empty_market_prompt(
    ui: &mut egui::Ui,
    ex_ui: &mut ExchangeUiState,
    cmd_tx: &std::sync::mpsc::Sender<UserCommand>,
) {
    egui::Frame::NONE
        .fill(BG_CARD)
        .stroke(Stroke::new(1.0_f32, BORDER_SUBTLE))
        .corner_radius(CornerRadius::same(12))
        .inner_margin(egui::Margin::same(24))
        .show(ui, |ui| {
            ui.label(
                RichText::new("Ready to Open the First Market on This Network")
                    .size(18.0)
                    .strong(),
            );
            ui.label(
                RichText::new(
                    "Click below to mint a practice `USDX` Native Asset and seed an `XCR / USDX` AMM pool in 1 click, or open '🚀 Launch Token' to customize your own.",
                )
                .color(TEXT_MUTED),
            );
            ui.add_space(10.0);
            ui.horizontal(|ui| {
                if ui
                    .add(
                        egui::Button::new(
                            RichText::new("⚡ Seed Demo Market (USDX / XCR)")
                                .strong()
                                .color(Color32::BLACK),
                        )
                        .fill(ACCENT_EMERALD),
                    )
                    .clicked()
                {
                    let _ = cmd_tx.send(UserCommand::LaunchAssetAndOptionalPool {
                        ticker: String::from("USDX"),
                        total_supply: 1_000_000,
                        pool_xcr_str: String::from("5.00"),
                        pool_units: 100,
                    });
                }
                if ui.button("Customize in 🚀 Launch Token ->").clicked() {
                    ex_ui.sub_tab = ExchangeSubTab::LaunchAsset;
                }
            });
        });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn smart_router_preview_picks_best_venue_between_amm_and_orderbook() {
        let asset_id = Hash32([0x42; 32]);
        let mut snap = ExchangeSnapshot {
            assets: vec![MarketAssetInfo {
                asset_id,
                ticker: String::from("USDX"),
                total_supply: 1_000_000,
                decimals: 0,
                owner_balance: 500,
            }],
            pools: vec![AmmPoolView {
                asset_id,
                ticker: String::from("USDX"),
                reserve_xcr: Amount::from_credits(100).unwrap(), // 100 XCR
                reserve_asset: 100,                              // 100 USDX -> ~1.00 XCR spot
                total_lp_shares: 100_000,
            }],
            orders: vec![OrderbookRow {
                order_id: Hash32([0x11; 32]),
                maker: Address([0x99; 32]),
                asset_id,
                is_sell_asset: true,
                remaining_units: 20,
                price_bits_per_unit: 800_000, // 0.80 XCR cheap Ask on book!
                escrowed_xcr: Amount::ZERO,
            }],
            oracles: Vec::new(),
            selected_asset: Some(asset_id),
            spread_bot: SpreadBotConfig::default(),
        };

        // Buying with 8.00 XCR:
        // - Orderbook @ 0.80 XCR/unit gives 10 USDX!
        // - AMM (100 XCR / 100 USDX) gives (100 * 8_000_000 * 997) / (100_000_000*1000 + 8_000_000*997) = 7 USDX!
        let buy_q = snap.quote_smart_swap(&asset_id, true, 8_000_000, 100);
        assert_eq!(buy_q.orderbook_out, 10);
        assert_eq!(buy_q.amm_out, 7);
        assert_eq!(buy_q.best_out, 10);
        assert_eq!(buy_q.venue, SmartSwapVenue::LimitOrderbook);

        // Remove the cheap orderbook Ask -> AMM wins automatically!
        snap.orders.clear();
        let buy_amm = snap.quote_smart_swap(&asset_id, true, 8_000_000, 100);
        assert_eq!(buy_amm.best_out, 7);
        assert_eq!(buy_amm.venue, SmartSwapVenue::AmmPool);
    }
}
