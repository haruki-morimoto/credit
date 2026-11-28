//! Non-blocking background node controller, `XCRENC01` keystore manager, and async RPC worker.

use std::collections::VecDeque;
use std::env;
use std::fs;
use std::io;
use std::net::{SocketAddr, UdpSocket};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, mpsc};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use crate::atomic_swap::{
    AtomicSwapSnapshot, create_and_persist_swap_secret, fetch_atomic_swaps_and_htlcs,
    load_swap_secrets, probe_bitcoin_p2wsh_utxo,
};
use crate::exchange::{
    ExchangeSnapshot, bind_or_revoke_dex_proxy, derive_dex_bot_proxy_seed,
    fetch_exchange_network_data, random_salt16, submit_proxy_dex_quote,
};
use crate::gpu_wgpu::WgpuZkProver;
use crate::p2p_fiat::{
    P2pFiatSnapshot, buyer_sign_fiat_sent_cosig, decode_fiat_escrow_ticket, decode_pubkey_hex66,
    fetch_p2p_fiat_network_data, load_fiat_escrows, lock_bisq_fiat_escrow_vault, save_fiat_escrows,
    seller_finalize_fiat_escrow_and_attest,
};
use crate::updater::{
    AutoUpdateStatus, apply_staged_update_and_relaunch, cleanup_old_binary_on_startup,
    download_and_verify_staged_binary, fetch_verified_newer_manifest,
};
use credit_cli::{
    cli_amm_liquidity, cli_bandwidth_free_pay, cli_claimable_sweep, cli_dex_cancel_order,
    cli_dex_place_order, cli_htlc_claim, cli_htlc_lock, cli_htlc_refund, cli_hybrid_smart_swap,
    cli_mint_native_asset, cli_post_swap_offer, cli_redpacket_claim, cli_redpacket_create,
    cli_register_handle, cli_scan_and_claim_stealth_v2, cli_send_bulletproof_payment_with_memo,
    cli_shield_deposit, cli_shield_scan, save_wallet_seed,
};
use credit_consensus::{
    GenesisStandbyStatus, MAINNET_GENESIS_ISO8601, NetworkProfile, VerifiableGenesisBeacon,
};
use credit_crypto::{Keypair, PublicKey, SignatureScheme, StealthKeypair, domain_hash};
use credit_net::{NodeRpcRequest, NodeRpcResponse, rpc_call};
use credit_node::{
    MeshPeerConfig, gpu_zk_device_name, is_gpu_zk_boost_enabled, local_gpu_zk_evals_per_sec,
    local_ponc_epoch_weight, local_ponc_hashrate_hps, register_gpu_zk_prover,
    run_mesh_peer_with_reward_pubkey, set_gpu_zk_boost_enabled, set_ponc_miner_threads,
};
use credit_sdk::{
    PLAIN_WALLET_MAGIC, ZeroizingSeed, decode_mnemonic_24, encode_mnemonic_24, encrypt_wallet_seed,
    format_backup_card_24, is_encrypted_wallet_bytes, open_wallet_bytes, parse_decimal_xcr,
};
use credit_types::{Address, Amount, Hash32, MIN_BASE_FEE_BITS, PendingWithdrawal, VaultState};

pub const TESTNET_SEEDS: &[&str] = &[
    "162.243.166.102:9501",
    "167.71.138.246:9501",
    "139.59.229.45:9501",
];

pub const MAINNET_SEEDS: &[&str] = &[
    "162.243.166.102:9500",
    "167.71.138.246:9500",
    "139.59.229.45:9500",
];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ActiveNetworkMode {
    PracticeTestnet,
    MainnetLiveOrStandby,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CpuPowerMode {
    Eco,
    Balanced,
    Max,
}

impl CpuPowerMode {
    pub fn total_system_cores() -> usize {
        thread::available_parallelism()
            .map(|p| p.get())
            .unwrap_or(1)
            .clamp(1, 32)
    }

    pub fn thread_count(self) -> usize {
        let total = Self::total_system_cores();
        match self {
            Self::Eco => 1,
            Self::Balanced => (total / 2).max(1),
            Self::Max => total,
        }
    }

    pub const fn as_code(self) -> &'static str {
        match self {
            Self::Eco => "eco",
            Self::Balanced => "balanced",
            Self::Max => "max",
        }
    }

    pub fn from_code(s: &str) -> Self {
        match s.trim() {
            "eco" => Self::Eco,
            "max" => Self::Max,
            _ => Self::Balanced,
        }
    }
}

#[derive(Clone, Debug)]
pub struct UiSnapshot {
    pub initialized: bool,
    pub onboarding_done: bool,
    pub locked: bool,
    pub encrypted_on_disk: bool,
    pub hide_figures: bool,
    pub earning_enabled: bool,
    pub auto_mainnet_armed: bool,
    pub cpu_power_mode: CpuPowerMode,
    pub active_threads: usize,
    pub hashrate_hps: u64,
    pub local_epoch_weight: u64,
    pub gpu_boost_enabled: bool,
    pub gpu_device_name: String,
    pub gpu_evals_per_sec: u64,
    pub auto_update_enabled: bool,
    pub update_status: AutoUpdateStatus,
    pub active_mode: ActiveNetworkMode,
    pub pocket_address: Address,
    pub pocket_pubkey: Option<PublicKey>,
    pub short_address: String,
    pub full_address_hex: String,
    pub stealth_uri: String,
    pub viewing_key_uri: String,
    pub claimed_handle: String,
    pub balance: Amount,
    pub session_start_balance: Option<Amount>,
    pub session_earned: Amount,
    pub balance_history: Vec<f64>,
    pub epoch: u64,
    pub circulating_supply: Amount,
    pub total_burned: Amount,
    pub connected_peers: u32,
    pub active_miners: u32,
    pub node_online: bool,
    pub seconds_to_mainnet: u64,
    pub last_epoch_change: Instant,
    pub shielded_balance: Amount,
    pub vault: VaultState,
    pub exchange: ExchangeSnapshot,
    pub atomic_swaps: AtomicSwapSnapshot,
    pub p2p_fiat: P2pFiatSnapshot,
    pub recent_events: VecDeque<String>,
    pub latest_gift_link: String,
    pub toast: Option<(String, bool, Instant)>,
}

impl Default for UiSnapshot {
    fn default() -> Self {
        Self {
            initialized: false,
            onboarding_done: false,
            locked: false,
            encrypted_on_disk: false,
            hide_figures: false,
            earning_enabled: true,
            auto_mainnet_armed: true,
            cpu_power_mode: CpuPowerMode::Balanced,
            active_threads: CpuPowerMode::Balanced.thread_count(),
            hashrate_hps: 0,
            local_epoch_weight: 0,
            gpu_boost_enabled: true,
            gpu_device_name: String::from("Detecting GPU..."),
            gpu_evals_per_sec: 0,
            auto_update_enabled: true,
            update_status: AutoUpdateStatus::UpToDate,
            active_mode: ActiveNetworkMode::PracticeTestnet,
            pocket_address: Address::default(),
            pocket_pubkey: None,
            short_address: String::new(),
            full_address_hex: String::new(),
            stealth_uri: String::new(),
            viewing_key_uri: String::new(),
            claimed_handle: String::new(),
            balance: Amount::ZERO,
            session_start_balance: None,
            session_earned: Amount::ZERO,
            balance_history: Vec::new(),
            epoch: 0,
            circulating_supply: Amount::ZERO,
            total_burned: Amount::ZERO,
            connected_peers: 0,
            active_miners: 0,
            node_online: false,
            seconds_to_mainnet: 0,
            last_epoch_change: Instant::now(),
            shielded_balance: Amount::ZERO,
            vault: VaultState::new(Amount::ZERO, 86_400_000, 2, Hash32::ZERO),
            exchange: ExchangeSnapshot::default(),
            atomic_swaps: AtomicSwapSnapshot::default(),
            p2p_fiat: P2pFiatSnapshot::default(),
            recent_events: VecDeque::new(),
            latest_gift_link: String::new(),
            toast: None,
        }
    }
}

impl UiSnapshot {
    /// Total funds currently held inside the Safety Vault (parked + pending 24h withdrawals).
    pub fn total_in_vault(&self) -> Amount {
        let pending_sum = self
            .vault
            .pending
            .iter()
            .fold(Amount::ZERO, |s, w| s.saturating_add(w.amount));
        self.vault.balance.saturating_add(pending_sum)
    }

    /// Liquid wallet balance immediately spendable right now (`on_chain_pocket - total_in_vault`).
    pub fn available_wallet_balance(&self) -> Amount {
        self.balance
            .checked_sub(self.total_in_vault())
            .unwrap_or(Amount::ZERO)
    }

    /// Formats an `Amount` respecting the user's `hide_figures` privacy toggle.
    pub fn display_amount(&self, amt: Amount) -> String {
        if self.hide_figures {
            String::from("∀ •••••• XCR")
        } else {
            amt.format_symbolic()
        }
    }
}

pub enum UserCommand {
    CreateOrSetupWallet {
        password: Option<String>,
        recovery_words: Option<String>,
    },
    UnlockWallet {
        password: String,
    },
    LockWallet,
    CompleteOnboarding {
        enable_earning: bool,
        arm_mainnet: bool,
    },
    SetEarningEnabled(bool),
    SetHideFigures(bool),
    SetCpuPowerMode(CpuPowerMode),
    SetGpuBoostEnabled(bool),
    SetAutoUpdateEnabled(bool),
    CheckForUpdatesNow,
    ApplyUpdateAndRestart,
    SetActiveNetwork(ActiveNetworkMode),
    SendSimplePayment {
        to: String,
        amount_str: String,
        memo: String,
    },
    ClaimHandle {
        handle: String,
    },
    CreateGiftLink {
        each_amount_str: String,
        claims: u16,
    },
    RedeemGiftOrClaimable {
        code_or_id: String,
    },
    VaultDeposit {
        amount_str: String,
    },
    VaultQueueWithdraw {
        amount_str: String,
    },
    VaultEmergencyUndo {
        id: u64,
    },
    ShieldDeposit {
        amount_str: String,
    },
    RefreshShieldedScan,
    SelectExchangeAsset(Hash32),
    RefreshExchangeNow,
    ExecuteSmartSwap {
        asset_id: Hash32,
        ticker: String,
        is_buy_asset: bool,
        amount_in_bits_or_units: u64,
        min_out_units_or_bits: u64,
    },
    PlaceDexLimitOrder {
        asset_id: Hash32,
        ticker: String,
        is_sell_asset: bool,
        units: u64,
        price_bits_per_unit: u64,
        immediate_or_cancel: bool,
    },
    CancelDexLimitOrder {
        order_id: Hash32,
    },
    ModifyAmmLiquidity {
        asset_id: Hash32,
        ticker: String,
        is_remove: bool,
        xcr_amount_str: String,
        units_or_lp_str: String,
    },
    ConfigureSpreadBot {
        enable: bool,
        asset_id: Hash32,
        half_spread_bps: u64,
        units_per_side: u64,
        max_xcr_str: String,
    },
    LaunchAssetAndOptionalPool {
        ticker: String,
        total_supply: u64,
        pool_xcr_str: String,
        pool_units: u64,
    },
    PostCrossChainOffer {
        counter_asset: String,
        counter_amount: String,
        xcr_amount_str: String,
        timelock_secs: u64,
    },
    LockCrossChainHtlc {
        recipient: String,
        xcr_amount_str: String,
        hashlock: Hash32,
        timelock_secs: u64,
    },
    ClaimCrossChainHtlc {
        escrow_hex: String,
        preimage_hex: String,
    },
    RefundCrossChainHtlc {
        escrow_id: Hash32,
    },
    ProbeBitcoinP2wshAddress {
        address: String,
    },
    PostP2pFiatOffer {
        fiat_rail_code: String,
        fiat_amount_str: String,
        xcr_amount_str: String,
    },
    LockP2pFiatEscrow {
        buyer_pubkey_hex66: String,
        trade_xcr_str: String,
        bond_pct: u64,
        fiat_label: String,
    },
    ImportP2pFiatTicket {
        ticket: String,
    },
    BuyerSignFiatSent {
        vault_id: Hash32,
    },
    SellerReleaseFiatEscrow {
        vault_id: Hash32,
        buyer_cosig_hex: String,
    },
    ShutdownAll,
}

pub struct DesktopController {
    pub app_dir: PathBuf,
    pub state: Arc<Mutex<UiSnapshot>>,
    pub cmd_tx: mpsc::Sender<UserCommand>,
    unlocked_seed: Arc<Mutex<Option<ZeroizingSeed>>>,
}

pub fn default_app_data_dir() -> PathBuf {
    if let Ok(appdata) = env::var("APPDATA")
        && !appdata.is_empty()
    {
        return PathBuf::from(appdata).join("Credits");
    }
    if let Ok(home) = env::var("HOME")
        && !home.is_empty()
    {
        #[cfg(target_os = "macos")]
        {
            return PathBuf::from(home)
                .join("Library")
                .join("Application Support")
                .join("Credits");
        }
        #[cfg(not(target_os = "macos"))]
        {
            return PathBuf::from(home).join(".credits-desktop");
        }
    }
    PathBuf::from("./credits-desktop-data")
}

impl DesktopController {
    pub fn start(egui_ctx: eframe::egui::Context) -> Self {
        cleanup_old_binary_on_startup();
        let app_dir = default_app_data_dir();
        let _ = fs::create_dir_all(&app_dir);

        let state = Arc::new(Mutex::new(UiSnapshot::default()));
        let unlocked_seed: Arc<Mutex<Option<ZeroizingSeed>>> = Arc::new(Mutex::new(None));
        let (cmd_tx, cmd_rx) = mpsc::channel::<UserCommand>();

        let wallet_file = app_dir.join("wallet.dat");
        let settings_file = app_dir.join("settings.txt");
        let pubkey_cache_file = app_dir.join("public_identity.hex");

        // Load existing settings & wallet state on startup:
        let mut initial_earning = false;
        let mut initial_mainnet = true;
        {
            let mut st = state.lock().unwrap();
            if let Ok(cfg_txt) = fs::read_to_string(&settings_file) {
                for ln in cfg_txt.lines() {
                    if let Some(v) = ln.strip_prefix("onboarding_done=") {
                        st.onboarding_done = v == "1";
                    } else if let Some(v) = ln.strip_prefix("earning=") {
                        st.earning_enabled = v == "1";
                    } else if let Some(v) = ln.strip_prefix("arm_mainnet=") {
                        st.auto_mainnet_armed = v == "1";
                    } else if let Some(v) = ln.strip_prefix("handle=") {
                        st.claimed_handle = v.to_owned();
                    } else if let Some(v) = ln.strip_prefix("power_mode=") {
                        st.cpu_power_mode = CpuPowerMode::from_code(v);
                        st.active_threads = st.cpu_power_mode.thread_count();
                    } else if let Some(v) = ln.strip_prefix("gpu_boost=") {
                        st.gpu_boost_enabled = v != "0";
                    } else if let Some(v) = ln.strip_prefix("hide_figures=") {
                        st.hide_figures = v == "1";
                    } else if let Some(v) = ln.strip_prefix("auto_update=") {
                        st.auto_update_enabled = v != "0";
                    }
                }
            }
            load_vault_state(&app_dir, &mut st.vault);
            st.atomic_swaps.local_secrets = load_swap_secrets(&app_dir);
            st.p2p_fiat.escrows = load_fiat_escrows(&app_dir);
            set_ponc_miner_threads(st.cpu_power_mode.thread_count());
            set_gpu_zk_boost_enabled(st.gpu_boost_enabled);
            if wallet_file.exists()
                && let Ok(raw) = fs::read(&wallet_file)
            {
                st.initialized = true;
                st.encrypted_on_disk = is_encrypted_wallet_bytes(&raw);
                match open_wallet_bytes(&raw, None) {
                    Ok(seed) => {
                        populate_identity_from_seed(&mut st, seed.as_bytes(), &pubkey_cache_file);
                        *unlocked_seed.lock().unwrap() = Some(seed);
                    }
                    Err(_) => {
                        st.locked = true;
                        // Even while locked, restore public key from `public_identity.hex` so background earning still works!
                        if let Ok(pk_hex) = fs::read_to_string(&pubkey_cache_file)
                            && let Some(pk) = parse_pubkey_hex66(pk_hex.trim())
                        {
                            let addr = pk.to_address();
                            st.pocket_address = addr;
                            st.pocket_pubkey = Some(pk);
                            st.short_address = addr.short_hex();
                            st.full_address_hex = Hash32(addr.0).to_hex();
                        }
                    }
                }
            }
            if st.initialized && st.onboarding_done && st.earning_enabled {
                initial_earning = true;
                initial_mainnet = st.auto_mainnet_armed;
            }
        }

        let testnet_port: Arc<Mutex<Option<u16>>> = Arc::new(Mutex::new(None));
        let mainnet_port: Arc<Mutex<Option<u16>>> = Arc::new(Mutex::new(None));
        let bot_proxy_seed: Arc<Mutex<Option<[u8; 32]>>> = Arc::new(Mutex::new(None));

        // Probe cross-platform `wgpu` (`DX12` / `Metal` / `Vulkan`) hardware adapter asynchronously:
        {
            let state_g = Arc::clone(&state);
            let ctx_g = egui_ctx.clone();
            thread::spawn(move || {
                match WgpuZkProver::probe() {
                    Some(prover) => {
                        let name = prover.device_name().to_owned();
                        register_gpu_zk_prover(Arc::new(prover));
                        state_g.lock().unwrap().gpu_device_name = name;
                    }
                    None => {
                        state_g.lock().unwrap().gpu_device_name =
                            String::from("CPU-only (no wgpu adapter)");
                    }
                }
                ctx_g.request_repaint();
            });
        }

        // Spawn command processor thread:
        {
            let app_dir_c = app_dir.clone();
            let state_c = Arc::clone(&state);
            let seed_c = Arc::clone(&unlocked_seed);
            let bot_c = Arc::clone(&bot_proxy_seed);
            let t_port_c = Arc::clone(&testnet_port);
            let m_port_c = Arc::clone(&mainnet_port);
            let ctx_c = egui_ctx.clone();

            thread::spawn(move || {
                if initial_earning {
                    let pk_opt = state_c.lock().unwrap().pocket_pubkey;
                    if let Some(pk) = pk_opt {
                        ensure_node_running(&app_dir_c, false, pk, &t_port_c);
                        if initial_mainnet {
                            ensure_node_running(&app_dir_c, true, pk, &m_port_c);
                        }
                    }
                }

                while let Ok(cmd) = cmd_rx.recv() {
                    let keep_going = handle_command(
                        cmd, &app_dir_c, &state_c, &seed_c, &bot_c, &t_port_c, &m_port_c,
                    );
                    ctx_c.request_repaint();
                    if !keep_going {
                        break;
                    }
                }
            });
        }

        // Background cryptographically verified auto-update checker (5s after launch + every 30m):
        {
            let app_dir_u = app_dir.clone();
            let state_u = Arc::clone(&state);
            let ctx_u = egui_ctx.clone();
            thread::spawn(move || {
                thread::sleep(Duration::from_secs(5));
                loop {
                    run_background_update_cycle(&app_dir_u, &state_u, false);
                    ctx_u.request_repaint();
                    thread::sleep(Duration::from_secs(1_800));
                }
            });
        }

        // Spawn 1.5s non-blocking telemetry & auto-stealth-sweep poller thread:
        {
            let app_dir_p = app_dir.clone();
            let state_p = Arc::clone(&state);
            let seed_p = Arc::clone(&unlocked_seed);
            let bot_p = Arc::clone(&bot_proxy_seed);
            let t_port_p = Arc::clone(&testnet_port);
            let m_port_p = Arc::clone(&mainnet_port);
            let ctx_p = egui_ctx;

            thread::spawn(move || {
                let mut tick = 0u64;
                loop {
                    thread::sleep(Duration::from_millis(1_500));
                    tick = tick.wrapping_add(1);
                    poll_network_and_wallet(
                        tick, &app_dir_p, &state_p, &seed_p, &bot_p, &t_port_p, &m_port_p,
                    );
                    ctx_p.request_repaint();
                }
            });
        }

        Self {
            app_dir,
            state,
            cmd_tx,
            unlocked_seed,
        }
    }

    pub fn export_mnemonic_if_unlocked(&self) -> Option<(String, String)> {
        let guard = self.unlocked_seed.lock().unwrap();
        let seed = guard.as_ref()?;
        let addr = self.state.lock().unwrap().short_address.clone();
        let words = encode_mnemonic_24(seed.as_bytes());
        let card = format!(
            "=== CREDITS (XCR) 24-WORD RECOVERY BACKUP CARD ===\nWallet Address: {addr}\n\n{}\nKeep these 24 words strictly private and offline.\n",
            format_backup_card_24(seed.as_bytes())
        );
        Some((words, card))
    }
}

fn populate_identity_from_seed(st: &mut UiSnapshot, seed: &[u8; 32], pubkey_cache_file: &Path) {
    let pocket_sk = domain_hash("XCR.WALLET.POCKET_KEY.V1", &[seed]).0;
    let kp = Keypair::from_seed(SignatureScheme::PasskeyP256, pocket_sk);
    let pk = kp.public_key();
    let addr = kp.address();
    let stealth_sk = domain_hash("XCR.WALLET.STEALTH_KEY.V1", &[seed]).0;
    let stealth_uri = StealthKeypair::from_seed(&stealth_sk)
        .meta_address()
        .to_uri();
    let (_, _, vk) = credit_sdk::ShieldedViewingKey::from_master_seed(seed);

    let _ = fs::write(
        pubkey_cache_file,
        format!("{:02x}{}", pk.scheme as u8, pk.merkle_root),
    );
    st.pocket_address = addr;
    st.pocket_pubkey = Some(pk);
    st.short_address = addr.short_hex();
    st.full_address_hex = Hash32(addr.0).to_hex();
    st.stealth_uri = stealth_uri;
    st.viewing_key_uri = vk.to_uri();
    st.locked = false;
}

fn parse_pubkey_hex66(s: &str) -> Option<PublicKey> {
    if s.len() != 66 {
        return None;
    }
    let mut raw = [0u8; 33];
    for (i, slot) in raw.iter_mut().enumerate() {
        *slot = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).ok()?;
    }
    let scheme = SignatureScheme::from_u8(raw[0])?;
    Some(PublicKey {
        scheme,
        merkle_root: Hash32::from_bytes(raw[1..33].try_into().ok()?),
    })
}

fn pick_ephemeral_port() -> u16 {
    UdpSocket::bind("127.0.0.1:0")
        .and_then(|s| s.local_addr())
        .map(|a| a.port())
        .unwrap_or(19501)
}

fn ensure_node_running(
    app_dir: &Path,
    is_mainnet: bool,
    reward_pubkey: PublicKey,
    port_slot: &Arc<Mutex<Option<u16>>>,
) {
    {
        let guard = port_slot.lock().unwrap();
        if guard.is_some() {
            return;
        }
    }
    let port = pick_ephemeral_port();
    *port_slot.lock().unwrap() = Some(port);

    let sub_dir = if is_mainnet {
        app_dir.join("mainnet-node")
    } else {
        app_dir.join("testnet-node")
    };
    let seeds_raw = if is_mainnet {
        MAINNET_SEEDS
    } else {
        TESTNET_SEEDS
    };
    let seed_peers: Vec<SocketAddr> = seeds_raw.iter().filter_map(|s| s.parse().ok()).collect();
    let cfg = MeshPeerConfig {
        network: if is_mainnet {
            NetworkProfile::Mainnet
        } else {
            NetworkProfile::TestnetBeta
        },
        bind_addr: SocketAddr::from(([0, 0, 0, 0], port)),
        data_dir: sub_dir,
        seed_peers,
        min_quorum_peers: 3,
        epoch_interval: Duration::from_secs(60),
    };
    let slot_clone = Arc::clone(port_slot);
    thread::spawn(move || {
        let _ = run_mesh_peer_with_reward_pubkey(cfg, None, Some(reward_pubkey));
        *slot_clone.lock().unwrap() = None;
    });
}

fn stop_node_if_running(port_slot: &Arc<Mutex<Option<u16>>>) {
    let maybe_port = *port_slot.lock().unwrap();
    if let Some(port) = maybe_port {
        let local_ep = SocketAddr::from(([127, 0, 0, 1], port));
        let _ = rpc_call(
            local_ep,
            &NodeRpcRequest::ShutdownDaemon,
            Duration::from_millis(600),
        );
        *port_slot.lock().unwrap() = None;
    }
}

fn now_unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

fn save_vault_state(app_dir: &Path, vault: &VaultState) {
    let mut out = format!(
        "balance_bits={}\nnext_id={}\n",
        vault.balance.bits(),
        vault.next_withdrawal_id
    );
    for w in &vault.pending {
        out.push_str(&format!(
            "pending={}:{}:{}\n",
            w.id,
            w.amount.bits(),
            w.unlock_at_ms
        ));
    }
    let _ = fs::write(app_dir.join("vault_state.txt"), out);
}

fn load_vault_state(app_dir: &Path, vault: &mut VaultState) {
    let Ok(raw) = fs::read_to_string(app_dir.join("vault_state.txt")) else {
        return;
    };
    vault.pending.clear();
    for ln in raw.lines() {
        if let Some(v) = ln.strip_prefix("balance_bits=")
            && let Ok(bits) = v.trim().parse::<u64>()
        {
            vault.balance = Amount::from_bits(bits);
        } else if let Some(v) = ln.strip_prefix("next_id=")
            && let Ok(nid) = v.trim().parse::<u64>()
        {
            vault.next_withdrawal_id = nid.max(1);
        } else if let Some(v) = ln.strip_prefix("pending=") {
            let parts: Vec<&str> = v.split(':').collect();
            if parts.len() == 3
                && let (Ok(id), Ok(bits), Ok(unlock_ms)) = (
                    parts[0].parse::<u64>(),
                    parts[1].parse::<u64>(),
                    parts[2].parse::<u64>(),
                )
            {
                vault.pending.push(PendingWithdrawal {
                    id,
                    destination: Address::default(),
                    amount: Amount::from_bits(bits),
                    unlock_at_ms: unlock_ms,
                });
            }
        }
    }
}

fn save_settings(app_dir: &Path, st: &UiSnapshot) {
    let body = format!(
        "onboarding_done={}\nearning={}\narm_mainnet={}\nhandle={}\npower_mode={}\ngpu_boost={}\nhide_figures={}\nauto_update={}\n",
        st.onboarding_done as u8,
        st.earning_enabled as u8,
        st.auto_mainnet_armed as u8,
        st.claimed_handle,
        st.cpu_power_mode.as_code(),
        st.gpu_boost_enabled as u8,
        st.hide_figures as u8,
        st.auto_update_enabled as u8
    );
    let _ = fs::write(app_dir.join("settings.txt"), body);
}

fn run_background_update_cycle(app_dir: &Path, state: &Arc<Mutex<UiSnapshot>>, manual: bool) {
    let auto_dl = {
        let mut st = state.lock().unwrap();
        if matches!(st.update_status, AutoUpdateStatus::StagedReady { .. }) && !manual {
            return;
        }
        st.update_status = AutoUpdateStatus::Checking;
        st.auto_update_enabled
    };

    match fetch_verified_newer_manifest(app_dir) {
        Ok(Some(manifest)) => {
            if auto_dl || manual {
                {
                    let mut st = state.lock().unwrap();
                    st.update_status = AutoUpdateStatus::Downloading {
                        version: manifest.version.clone(),
                        build_number: manifest.build_number,
                    };
                }
                match download_and_verify_staged_binary(app_dir, &manifest) {
                    Ok(_) => {
                        let mut st = state.lock().unwrap();
                        let ver = manifest.version.clone();
                        let bnum = manifest.build_number;
                        st.update_status = AutoUpdateStatus::StagedReady { manifest };
                        set_toast(
                            &mut st,
                            format!(
                                "✨ Verified update v{ver} (#{bnum}) downloaded! Click 'Update Ready' in top bar to restart."
                            ),
                            true,
                        );
                    }
                    Err(e) => {
                        let mut st = state.lock().unwrap();
                        st.update_status = AutoUpdateStatus::Error(e.clone());
                        if manual {
                            set_toast(&mut st, format!("Update check: {e}"), false);
                        }
                    }
                }
            } else {
                state.lock().unwrap().update_status = AutoUpdateStatus::Available { manifest };
            }
        }
        Ok(None) => {
            let mut st = state.lock().unwrap();
            st.update_status = AutoUpdateStatus::UpToDate;
            if manual {
                set_toast(
                    &mut st,
                    "✓ Credits Desktop is up to date (signature verified).",
                    true,
                );
            }
        }
        Err(e) => {
            let mut st = state.lock().unwrap();
            if manual {
                st.update_status = AutoUpdateStatus::Error(e.clone());
                set_toast(&mut st, format!("Update check: {e}"), false);
            } else {
                st.update_status = AutoUpdateStatus::UpToDate;
            }
        }
    }
}

fn write_temp_seed_for_cli(app_dir: &Path, seed: &[u8; 32]) -> io::Result<PathBuf> {
    let tmp = app_dir.join(".active_tx_key.tmp");
    save_wallet_seed(&tmp, seed)?;
    Ok(tmp)
}

fn seed_rpc_endpoint(active_mode: ActiveNetworkMode) -> SocketAddr {
    match active_mode {
        ActiveNetworkMode::PracticeTestnet => TESTNET_SEEDS[0].parse().unwrap(),
        ActiveNetworkMode::MainnetLiveOrStandby => MAINNET_SEEDS[0].parse().unwrap(),
    }
}

fn best_rpc_endpoint(
    active_mode: ActiveNetworkMode,
    t_port: &Arc<Mutex<Option<u16>>>,
    m_port: &Arc<Mutex<Option<u16>>>,
) -> SocketAddr {
    match active_mode {
        ActiveNetworkMode::PracticeTestnet => {
            if let Some(p) = *t_port.lock().unwrap() {
                SocketAddr::from(([127, 0, 0, 1], p))
            } else {
                TESTNET_SEEDS[0].parse().unwrap()
            }
        }
        ActiveNetworkMode::MainnetLiveOrStandby => {
            if let Some(p) = *m_port.lock().unwrap() {
                SocketAddr::from(([127, 0, 0, 1], p))
            } else {
                MAINNET_SEEDS[0].parse().unwrap()
            }
        }
    }
}

fn set_toast(st: &mut UiSnapshot, msg: impl Into<String>, ok: bool) {
    let s = msg.into();
    if ok {
        st.recent_events.push_front(s.clone());
        while st.recent_events.len() > 25 {
            st.recent_events.pop_back();
        }
    }
    st.toast = Some((s, ok, Instant::now()));
}

fn handle_command(
    cmd: UserCommand,
    app_dir: &Path,
    state: &Arc<Mutex<UiSnapshot>>,
    unlocked_seed: &Arc<Mutex<Option<ZeroizingSeed>>>,
    bot_proxy_seed: &Arc<Mutex<Option<[u8; 32]>>>,
    t_port: &Arc<Mutex<Option<u16>>>,
    m_port: &Arc<Mutex<Option<u16>>>,
) -> bool {
    let wallet_file = app_dir.join("wallet.dat");
    let pubkey_cache_file = app_dir.join("public_identity.hex");

    match cmd {
        UserCommand::CreateOrSetupWallet {
            password,
            recovery_words,
        } => {
            let seed_bytes = if let Some(words) = recovery_words.filter(|w| !w.trim().is_empty()) {
                match decode_mnemonic_24(&words) {
                    Ok(s) => s,
                    Err(e) => {
                        set_toast(
                            &mut state.lock().unwrap(),
                            format!("Recovery error: {e}"),
                            false,
                        );
                        return true;
                    }
                }
            } else {
                let nanos = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_nanos();
                domain_hash(
                    "XCR.DESKTOP.NEW_WALLET.V1",
                    &[&nanos.to_le_bytes(), &std::process::id().to_le_bytes()],
                )
                .0
            };

            let encrypted = if let Some(pw) = password.filter(|p| !p.is_empty()) {
                let mut salt = [0u8; 16];
                salt.copy_from_slice(&seed_bytes[..16]);
                match encrypt_wallet_seed(&seed_bytes, &pw, salt, 1) {
                    Ok(bytes) => {
                        let _ = fs::write(&wallet_file, bytes);
                        true
                    }
                    Err(e) => {
                        set_toast(
                            &mut state.lock().unwrap(),
                            format!("Encryption failed: {e}"),
                            false,
                        );
                        return true;
                    }
                }
            } else {
                let mut plain = Vec::with_capacity(40);
                plain.extend_from_slice(&PLAIN_WALLET_MAGIC);
                plain.extend_from_slice(&seed_bytes);
                let _ = fs::write(&wallet_file, plain);
                false
            };

            *unlocked_seed.lock().unwrap() = Some(ZeroizingSeed::new(seed_bytes));
            let mut st = state.lock().unwrap();
            st.initialized = true;
            st.encrypted_on_disk = encrypted;
            populate_identity_from_seed(&mut st, &seed_bytes, &pubkey_cache_file);
            set_toast(
                &mut st,
                "Wallet created! Save your 24 recovery words safely.",
                true,
            );
        }

        UserCommand::UnlockWallet { password } => {
            let Ok(raw) = fs::read(&wallet_file) else {
                return true;
            };
            match open_wallet_bytes(&raw, Some(&password)) {
                Ok(seed) => {
                    let mut st = state.lock().unwrap();
                    populate_identity_from_seed(&mut st, seed.as_bytes(), &pubkey_cache_file);
                    *unlocked_seed.lock().unwrap() = Some(seed);
                    set_toast(&mut st, "Wallet unlocked.", true);
                }
                Err(e) => {
                    set_toast(
                        &mut state.lock().unwrap(),
                        format!("Incorrect password: {e}"),
                        false,
                    );
                }
            }
        }

        UserCommand::LockWallet => {
            *unlocked_seed.lock().unwrap() = None;
            let mut st = state.lock().unwrap();
            st.locked = true;
            set_toast(
                &mut st,
                "Wallet locked (background earning continues safely!).",
                true,
            );
        }

        UserCommand::CompleteOnboarding {
            enable_earning,
            arm_mainnet,
        } => {
            let pk_opt = {
                let mut st = state.lock().unwrap();
                st.onboarding_done = true;
                st.earning_enabled = enable_earning;
                st.auto_mainnet_armed = arm_mainnet;
                save_settings(app_dir, &st);
                st.pocket_pubkey
            };
            if let Some(pk) = pk_opt {
                // Register Pocket on Testnet so new users immediately get starter practice coins!
                let addr = pk.to_address();
                if let Ok(seed_ep) = TESTNET_SEEDS[0].parse::<SocketAddr>() {
                    let _ = rpc_call(
                        seed_ep,
                        &NodeRpcRequest::RegisterPocket {
                            address: addr,
                            public_key: pk,
                            grant_from_miner: Amount::from_credits(25).unwrap(),
                            daily_limit: Amount::from_credits(250).unwrap(),
                        },
                        Duration::from_secs(3),
                    );
                }
                if enable_earning {
                    ensure_node_running(app_dir, false, pk, t_port);
                    if arm_mainnet {
                        ensure_node_running(app_dir, true, pk, m_port);
                    }
                }
            }
            set_toast(
                &mut state.lock().unwrap(),
                "Welcome to Credits! Connected to global mesh & earning automatically.",
                true,
            );
        }

        UserCommand::SetEarningEnabled(enabled) => {
            let (pk_opt, arm_main) = {
                let mut st = state.lock().unwrap();
                st.earning_enabled = enabled;
                save_settings(app_dir, &st);
                (st.pocket_pubkey, st.auto_mainnet_armed)
            };
            if enabled {
                if let Some(pk) = pk_opt {
                    ensure_node_running(app_dir, false, pk, t_port);
                    if arm_main {
                        ensure_node_running(app_dir, true, pk, m_port);
                    }
                }
                set_toast(
                    &mut state.lock().unwrap(),
                    "Automatic background earning resumed.",
                    true,
                );
            } else {
                stop_node_if_running(t_port);
                stop_node_if_running(m_port);
                set_toast(
                    &mut state.lock().unwrap(),
                    "Background earning paused.",
                    true,
                );
            }
        }

        UserCommand::SetHideFigures(hide) => {
            let mut st = state.lock().unwrap();
            st.hide_figures = hide;
            save_settings(app_dir, &st);
        }

        UserCommand::SetCpuPowerMode(mode) => {
            let threads = mode.thread_count();
            set_ponc_miner_threads(threads);
            let mut st = state.lock().unwrap();
            st.cpu_power_mode = mode;
            st.active_threads = threads;
            save_settings(app_dir, &st);
            set_toast(
                &mut st,
                format!("⚡ CPU Power set to {threads} thread(s) — rewards scale with compute!"),
                true,
            );
        }

        UserCommand::SetGpuBoostEnabled(enabled) => {
            set_gpu_zk_boost_enabled(enabled);
            let mut st = state.lock().unwrap();
            st.gpu_boost_enabled = enabled;
            save_settings(app_dir, &st);
            let msg = if enabled {
                "🎮 GPU ZK Boost ON (0W idle until transactions flow)."
            } else {
                "⏸ GPU ZK Boost paused (CPU-only earning active)."
            };
            set_toast(&mut st, msg, true);
        }

        UserCommand::SetAutoUpdateEnabled(enabled) => {
            let mut st = state.lock().unwrap();
            st.auto_update_enabled = enabled;
            save_settings(app_dir, &st);
            set_toast(
                &mut st,
                if enabled {
                    "🔄 Automatic signed updates enabled."
                } else {
                    "Manual update mode set."
                },
                true,
            );
        }

        UserCommand::CheckForUpdatesNow => {
            let dir_c = app_dir.to_path_buf();
            let state_c = Arc::clone(state);
            thread::spawn(move || {
                run_background_update_cycle(&dir_c, &state_c, true);
            });
        }

        UserCommand::ApplyUpdateAndRestart => {
            let maybe_manifest = match &state.lock().unwrap().update_status {
                AutoUpdateStatus::StagedReady { manifest } => Some(manifest.clone()),
                AutoUpdateStatus::Available { manifest } => Some(manifest.clone()),
                _ => None,
            };
            if let Some(manifest) = maybe_manifest {
                let staged_file = app_dir.join("staged-credit-desktop.exe");
                if !staged_file.exists()
                    && let Err(e) = download_and_verify_staged_binary(app_dir, &manifest)
                {
                    set_toast(
                        &mut state.lock().unwrap(),
                        format!("Update error: {e}"),
                        false,
                    );
                    return true;
                }
                stop_node_if_running(t_port);
                stop_node_if_running(m_port);
                if let Err(e) = apply_staged_update_and_relaunch(app_dir, &manifest) {
                    set_toast(
                        &mut state.lock().unwrap(),
                        format!("Update error: {e}"),
                        false,
                    );
                }
            }
        }

        UserCommand::SetActiveNetwork(mode) => {
            let mut st = state.lock().unwrap();
            st.active_mode = mode;
            st.session_start_balance = None;
            st.balance_history.clear();
        }

        UserCommand::SendSimplePayment {
            to,
            amount_str,
            memo,
        } => {
            let Some(seed) = unlocked_seed
                .lock()
                .unwrap()
                .as_ref()
                .map(|z| *z.as_bytes())
            else {
                set_toast(
                    &mut state.lock().unwrap(),
                    "Unlock your wallet first to send.",
                    false,
                );
                return true;
            };
            let Some(amount) = parse_decimal_xcr(&amount_str) else {
                set_toast(
                    &mut state.lock().unwrap(),
                    "Enter a valid amount (e.g. 5.00).",
                    false,
                );
                return true;
            };
            {
                let st = state.lock().unwrap();
                if amount > st.available_wallet_balance() {
                    let mut st_mut = st;
                    set_toast(
                        &mut st_mut,
                        "Exceeds Available Wallet Balance (funds in Safety Vault require a 24h withdrawal).",
                        false,
                    );
                    return true;
                }
            }
            let ep = seed_rpc_endpoint(state.lock().unwrap().active_mode);
            let Ok(tmp_w) = write_temp_seed_for_cli(app_dir, &seed) else {
                return true;
            };
            let now_unix = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0);

            // 1) Automatically try 0-fee Daily Bandwidth Quota first for @handle / xcr1_ pockets!
            let trimmed_to = to.trim();
            let mut settled_msg: Option<String> = None;
            if !trimmed_to.starts_with("xcrstealth1_")
                && let Ok(NodeRpcResponse::ContractReceipt {
                    accepted: true,
                    message,
                    ..
                }) = cli_bandwidth_free_pay(&tmp_w, trimmed_to, amount, now_unix, ep)
            {
                settled_msg = Some(format!(
                    "✓ Sent {} FREE! ({message})",
                    amount.format_symbolic()
                ));
            }

            // 2) Fallback to private 672B Bulletproof 1-RTT Stealth FastPay:
            if settled_msg.is_none() {
                match cli_send_bulletproof_payment_with_memo(
                    &tmp_w,
                    trimmed_to.as_bytes(),
                    amount,
                    Amount::from_bits(MIN_BASE_FEE_BITS),
                    &memo,
                    ep,
                ) {
                    Ok(NodeRpcResponse::FastPayReceipt {
                        accepted: true,
                        finality_latency_ms,
                        ..
                    }) => {
                        settled_msg = Some(format!(
                            "✓ Sent {} privately in {finality_latency_ms} ms!",
                            amount.format_symbolic()
                        ));
                    }
                    Ok(other) => {
                        let _ = fs::remove_file(&tmp_w);
                        set_toast(
                            &mut state.lock().unwrap(),
                            format!("Send rejected: {other:?}"),
                            false,
                        );
                        return true;
                    }
                    Err(e) => {
                        let _ = fs::remove_file(&tmp_w);
                        set_toast(
                            &mut state.lock().unwrap(),
                            format!("Send failed: {e}"),
                            false,
                        );
                        return true;
                    }
                }
            }
            let _ = fs::remove_file(&tmp_w);
            if let Some(m) = settled_msg {
                set_toast(&mut state.lock().unwrap(), m, true);
            }
        }

        UserCommand::ClaimHandle { handle } => {
            let Some(seed) = unlocked_seed
                .lock()
                .unwrap()
                .as_ref()
                .map(|z| *z.as_bytes())
            else {
                set_toast(&mut state.lock().unwrap(), "Unlock wallet first.", false);
                return true;
            };
            let ep = seed_rpc_endpoint(state.lock().unwrap().active_mode);
            let Ok(tmp_w) = write_temp_seed_for_cli(app_dir, &seed) else {
                return true;
            };
            let res = cli_register_handle(&tmp_w, &handle, ep);
            let _ = fs::remove_file(&tmp_w);
            match res {
                Ok((disp, NodeRpcResponse::ContractReceipt { accepted: true, .. })) => {
                    let mut st = state.lock().unwrap();
                    st.claimed_handle = disp.clone();
                    save_settings(app_dir, &st);
                    set_toast(&mut st, format!("✓ Username {disp} is now yours!"), true);
                }
                Ok((_, NodeRpcResponse::ContractReceipt { message, .. })) => {
                    set_toast(&mut state.lock().unwrap(), message, false);
                }
                Err(e) => set_toast(&mut state.lock().unwrap(), format!("{e}"), false),
                _ => {}
            }
        }

        UserCommand::CreateGiftLink {
            each_amount_str,
            claims,
        } => {
            let Some(seed) = unlocked_seed
                .lock()
                .unwrap()
                .as_ref()
                .map(|z| *z.as_bytes())
            else {
                set_toast(&mut state.lock().unwrap(), "Unlock wallet first.", false);
                return true;
            };
            let Some(each) = parse_decimal_xcr(&each_amount_str) else {
                set_toast(&mut state.lock().unwrap(), "Invalid gift amount.", false);
                return true;
            };
            let ep = seed_rpc_endpoint(state.lock().unwrap().active_mode);
            let Ok(tmp_w) = write_temp_seed_for_cli(app_dir, &seed) else {
                return true;
            };
            let nanos = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos();
            let sec = domain_hash("XCR.DESKTOP.GIFT.V1", &[&nanos.to_le_bytes()]).0;
            let exp = (nanos as u64 / 1_000_000_000).saturating_add(86_400 * 7);
            let res = cli_redpacket_create(&tmp_w, each, claims.max(1), sec, exp, ep);
            let _ = fs::remove_file(&tmp_w);
            match res {
                Ok((
                    uri,
                    NodeRpcResponse::ContractReceipt {
                        accepted: true,
                        message,
                        ..
                    },
                )) => {
                    let mut st = state.lock().unwrap();
                    st.latest_gift_link = uri;
                    set_toast(
                        &mut st,
                        format!("✓ Gift Link ready to share! ({message})"),
                        true,
                    );
                }
                Ok((_, NodeRpcResponse::ContractReceipt { message, .. })) => {
                    set_toast(&mut state.lock().unwrap(), message, false);
                }
                Err(e) => set_toast(&mut state.lock().unwrap(), format!("{e}"), false),
                _ => {}
            }
        }

        UserCommand::RedeemGiftOrClaimable { code_or_id } => {
            let Some(seed) = unlocked_seed
                .lock()
                .unwrap()
                .as_ref()
                .map(|z| *z.as_bytes())
            else {
                set_toast(&mut state.lock().unwrap(), "Unlock wallet first.", false);
                return true;
            };
            let ep = seed_rpc_endpoint(state.lock().unwrap().active_mode);
            let Ok(tmp_w) = write_temp_seed_for_cli(app_dir, &seed) else {
                return true;
            };
            let clean = code_or_id.trim();
            let res = if clean.starts_with("xcrdrop1_") {
                cli_redpacket_claim(&tmp_w, clean, ep)
            } else {
                cli_claimable_sweep(&tmp_w, clean, ep)
            };
            let _ = fs::remove_file(&tmp_w);
            match res {
                Ok(NodeRpcResponse::ContractReceipt {
                    accepted: true,
                    amount,
                    message,
                    ..
                }) => {
                    set_toast(
                        &mut state.lock().unwrap(),
                        format!("✓ Claimed +{}! ({message})", amount.format_symbolic()),
                        true,
                    );
                }
                Ok(NodeRpcResponse::ContractReceipt { message, .. }) => {
                    set_toast(&mut state.lock().unwrap(), message, false);
                }
                Err(e) => set_toast(&mut state.lock().unwrap(), format!("{e}"), false),
                _ => {}
            }
        }

        UserCommand::VaultDeposit { amount_str } => {
            let Some(amt) = parse_decimal_xcr(&amount_str) else {
                set_toast(
                    &mut state.lock().unwrap(),
                    "Enter a valid amount (e.g. 10.00).",
                    false,
                );
                return true;
            };
            let mut st = state.lock().unwrap();
            if amt.is_zero() || amt > st.available_wallet_balance() {
                set_toast(
                    &mut st,
                    "Enter an amount up to your Available Wallet Balance.",
                    false,
                );
                return true;
            }
            st.vault.balance = st.vault.balance.saturating_add(amt);
            save_vault_state(app_dir, &st.vault);
            set_toast(
                &mut st,
                format!(
                    "🛡 Moved {} into your 24-Hour Safety Vault.",
                    amt.format_symbolic()
                ),
                true,
            );
        }

        UserCommand::VaultQueueWithdraw { amount_str } => {
            let Some(amt) = parse_decimal_xcr(&amount_str) else {
                return true;
            };
            let mut st = state.lock().unwrap();
            let dest = st.pocket_address;
            match st.vault.queue_withdrawal(dest, amt, now_unix_ms()) {
                Ok(id) => {
                    save_vault_state(app_dir, &st.vault);
                    set_toast(
                        &mut st,
                        format!("Queued Safety Vault withdrawal #{id} (unlocks in 24h)."),
                        true,
                    );
                }
                Err(e) => set_toast(&mut st, format!("Safety Vault: {e}"), false),
            }
        }

        UserCommand::VaultEmergencyUndo { id } => {
            let mut st = state.lock().unwrap();
            match st.vault.emergency_cancel(id) {
                Ok(restored) => {
                    save_vault_state(app_dir, &st.vault);
                    set_toast(
                        &mut st,
                        format!(
                            "🛡 EMERGENCY UNDO COMPLETE: Restored {} back to Safety Vault!",
                            restored.format_symbolic()
                        ),
                        true,
                    );
                }
                Err(e) => set_toast(&mut st, format!("Cancel error: {e}"), false),
            }
        }

        UserCommand::ShieldDeposit { amount_str } => {
            let Some(seed) = unlocked_seed
                .lock()
                .unwrap()
                .as_ref()
                .map(|z| *z.as_bytes())
            else {
                set_toast(&mut state.lock().unwrap(), "Unlock wallet first.", false);
                return true;
            };
            let Some(amt) = parse_decimal_xcr(&amount_str) else {
                return true;
            };
            let ep = seed_rpc_endpoint(state.lock().unwrap().active_mode);
            let Ok(tmp_w) = write_temp_seed_for_cli(app_dir, &seed) else {
                return true;
            };
            let nanos = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos();
            let ent = domain_hash("XCR.DESKTOP.SHIELD.V1", &[&nanos.to_le_bytes()]).0;
            let res = cli_shield_deposit(&tmp_w, "", amt, ent, ep);
            let _ = fs::remove_file(&tmp_w);
            if let Ok((
                _,
                _,
                NodeRpcResponse::ContractReceipt {
                    accepted: true,
                    message,
                    ..
                },
            )) = res
            {
                set_toast(&mut state.lock().unwrap(), format!("✓ {message}"), true);
            }
        }

        UserCommand::RefreshShieldedScan => {
            let (vk, mode) = {
                let st = state.lock().unwrap();
                (st.viewing_key_uri.clone(), st.active_mode)
            };
            if !vk.is_empty() {
                let ep = seed_rpc_endpoint(mode);
                if let Ok((_, notes)) = cli_shield_scan(&vk, None, ep) {
                    let sum = notes
                        .into_iter()
                        .fold(Amount::ZERO, |s, (_, _, a)| s.saturating_add(a));
                    let mut st = state.lock().unwrap();
                    st.shielded_balance = sum;
                    set_toast(
                        &mut st,
                        format!("Scanned Shielded Pool: {} owned.", sum.format_symbolic()),
                        true,
                    );
                }
            }
        }

        UserCommand::SelectExchangeAsset(asset_id) => {
            state.lock().unwrap().exchange.selected_asset = Some(asset_id);
        }

        UserCommand::RefreshExchangeNow => {
            let (addr, mode) = {
                let st = state.lock().unwrap();
                (st.pocket_address, st.active_mode)
            };
            let primary = best_rpc_endpoint(mode, t_port, m_port);
            let fallback = seed_rpc_endpoint(mode);
            refresh_exchange_snapshot(addr, primary, fallback, state);
        }

        UserCommand::ExecuteSmartSwap {
            asset_id,
            ticker,
            is_buy_asset,
            amount_in_bits_or_units,
            min_out_units_or_bits,
        } => {
            let Some(seed) = unlocked_seed
                .lock()
                .unwrap()
                .as_ref()
                .map(|z| *z.as_bytes())
            else {
                set_toast(&mut state.lock().unwrap(), "Unlock wallet first.", false);
                return true;
            };
            if is_buy_asset {
                let need =
                    Amount::from_bits(amount_in_bits_or_units.saturating_add(MIN_BASE_FEE_BITS));
                let mut st = state.lock().unwrap();
                if need > st.available_wallet_balance() {
                    set_toast(
                        &mut st,
                        "Exceeds Available Wallet Balance (Safety Vault funds are protected).",
                        false,
                    );
                    return true;
                }
            }
            let (addr, mode) = {
                let st = state.lock().unwrap();
                (st.pocket_address, st.active_mode)
            };
            let ep = seed_rpc_endpoint(mode);
            let Ok(tmp_w) = write_temp_seed_for_cli(app_dir, &seed) else {
                return true;
            };
            let salt = random_salt16("XCR.DESKTOP.SWAP.V1");
            let res = cli_hybrid_smart_swap(
                &tmp_w,
                &asset_id.to_hex(),
                is_buy_asset,
                amount_in_bits_or_units,
                min_out_units_or_bits,
                salt,
                ep,
            );
            let _ = fs::remove_file(&tmp_w);
            match res {
                Ok(NodeRpcResponse::ContractReceipt {
                    accepted: true,
                    message,
                    ..
                }) => {
                    set_toast(&mut state.lock().unwrap(), format!("⚡ {message}"), true);
                    let primary = best_rpc_endpoint(mode, t_port, m_port);
                    refresh_exchange_snapshot(addr, primary, ep, state);
                }
                Ok(NodeRpcResponse::ContractReceipt { message, .. }) => {
                    set_toast(
                        &mut state.lock().unwrap(),
                        format!("Swap {ticker}: {message}"),
                        false,
                    );
                }
                Err(e) => set_toast(&mut state.lock().unwrap(), format!("{e}"), false),
                _ => {}
            }
        }

        UserCommand::PlaceDexLimitOrder {
            asset_id,
            ticker,
            is_sell_asset,
            units,
            price_bits_per_unit,
            immediate_or_cancel,
        } => {
            let Some(seed) = unlocked_seed
                .lock()
                .unwrap()
                .as_ref()
                .map(|z| *z.as_bytes())
            else {
                set_toast(&mut state.lock().unwrap(), "Unlock wallet first.", false);
                return true;
            };
            if units == 0 || price_bits_per_unit == 0 {
                set_toast(
                    &mut state.lock().unwrap(),
                    "Enter positive units and limit price.",
                    false,
                );
                return true;
            }
            if !is_sell_asset {
                let need = Amount::from_bits(
                    units
                        .saturating_mul(price_bits_per_unit)
                        .saturating_add(MIN_BASE_FEE_BITS),
                );
                let mut st = state.lock().unwrap();
                if need > st.available_wallet_balance() {
                    set_toast(
                        &mut st,
                        "Limit BUY exceeds Available Wallet Balance (Safety Vault funds are protected).",
                        false,
                    );
                    return true;
                }
            }
            let (addr, mode) = {
                let st = state.lock().unwrap();
                (st.pocket_address, st.active_mode)
            };
            let ep = seed_rpc_endpoint(mode);
            let Ok(tmp_w) = write_temp_seed_for_cli(app_dir, &seed) else {
                return true;
            };
            let salt = random_salt16("XCR.DESKTOP.DEX_ORDER.V1");
            let res = cli_dex_place_order(
                &tmp_w,
                &asset_id.to_hex(),
                is_sell_asset,
                units,
                price_bits_per_unit,
                immediate_or_cancel,
                salt,
                ep,
            );
            let _ = fs::remove_file(&tmp_w);
            match res {
                Ok(NodeRpcResponse::ContractReceipt {
                    accepted: true,
                    message,
                    ..
                }) => {
                    set_toast(
                        &mut state.lock().unwrap(),
                        format!("📊 {ticker}: {message}"),
                        true,
                    );
                    let primary = best_rpc_endpoint(mode, t_port, m_port);
                    refresh_exchange_snapshot(addr, primary, ep, state);
                }
                Ok(NodeRpcResponse::ContractReceipt { message, .. }) => {
                    set_toast(&mut state.lock().unwrap(), message, false);
                }
                Err(e) => set_toast(&mut state.lock().unwrap(), format!("{e}"), false),
                _ => {}
            }
        }

        UserCommand::CancelDexLimitOrder { order_id } => {
            let Some(seed) = unlocked_seed
                .lock()
                .unwrap()
                .as_ref()
                .map(|z| *z.as_bytes())
            else {
                set_toast(&mut state.lock().unwrap(), "Unlock wallet first.", false);
                return true;
            };
            let (addr, mode) = {
                let st = state.lock().unwrap();
                (st.pocket_address, st.active_mode)
            };
            let ep = seed_rpc_endpoint(mode);
            let Ok(tmp_w) = write_temp_seed_for_cli(app_dir, &seed) else {
                return true;
            };
            let res = cli_dex_cancel_order(&tmp_w, &order_id.to_hex(), ep);
            let _ = fs::remove_file(&tmp_w);
            match res {
                Ok(NodeRpcResponse::ContractReceipt {
                    accepted: true,
                    message,
                    ..
                }) => {
                    set_toast(&mut state.lock().unwrap(), format!("✓ {message}"), true);
                    let primary = best_rpc_endpoint(mode, t_port, m_port);
                    refresh_exchange_snapshot(addr, primary, ep, state);
                }
                Ok(NodeRpcResponse::ContractReceipt { message, .. }) => {
                    set_toast(&mut state.lock().unwrap(), message, false);
                }
                Err(e) => set_toast(&mut state.lock().unwrap(), format!("{e}"), false),
                _ => {}
            }
        }

        UserCommand::ModifyAmmLiquidity {
            asset_id,
            ticker,
            is_remove,
            xcr_amount_str,
            units_or_lp_str,
        } => {
            let Some(seed) = unlocked_seed
                .lock()
                .unwrap()
                .as_ref()
                .map(|z| *z.as_bytes())
            else {
                set_toast(&mut state.lock().unwrap(), "Unlock wallet first.", false);
                return true;
            };
            let xcr_amt = if is_remove {
                Amount::ZERO
            } else {
                let Some(a) = parse_decimal_xcr(&xcr_amount_str) else {
                    set_toast(&mut state.lock().unwrap(), "Invalid XCR amount.", false);
                    return true;
                };
                let mut st = state.lock().unwrap();
                if a.saturating_add(Amount::from_bits(MIN_BASE_FEE_BITS))
                    > st.available_wallet_balance()
                {
                    set_toast(
                        &mut st,
                        "Exceeds Available Wallet Balance (Safety Vault funds are protected).",
                        false,
                    );
                    return true;
                }
                a
            };
            let Ok(units_or_lp) = units_or_lp_str.trim().parse::<u64>() else {
                set_toast(
                    &mut state.lock().unwrap(),
                    "Enter whole units/LP shares.",
                    false,
                );
                return true;
            };
            let (addr, mode) = {
                let st = state.lock().unwrap();
                (st.pocket_address, st.active_mode)
            };
            let ep = seed_rpc_endpoint(mode);
            let Ok(tmp_w) = write_temp_seed_for_cli(app_dir, &seed) else {
                return true;
            };
            let salt = random_salt16("XCR.DESKTOP.AMM_LP.V1");
            let res = cli_amm_liquidity(
                &tmp_w,
                is_remove,
                &asset_id.to_hex(),
                xcr_amt,
                units_or_lp,
                salt,
                ep,
            );
            let _ = fs::remove_file(&tmp_w);
            match res {
                Ok(NodeRpcResponse::ContractReceipt {
                    accepted: true,
                    message,
                    ..
                }) => {
                    set_toast(
                        &mut state.lock().unwrap(),
                        format!("💧 {ticker}: {message}"),
                        true,
                    );
                    let primary = best_rpc_endpoint(mode, t_port, m_port);
                    refresh_exchange_snapshot(addr, primary, ep, state);
                }
                Ok(NodeRpcResponse::ContractReceipt { message, .. }) => {
                    set_toast(&mut state.lock().unwrap(), message, false);
                }
                Err(e) => set_toast(&mut state.lock().unwrap(), format!("{e}"), false),
                _ => {}
            }
        }

        UserCommand::ConfigureSpreadBot {
            enable,
            asset_id,
            half_spread_bps,
            units_per_side,
            max_xcr_str,
        } => {
            let Some(seed) = unlocked_seed
                .lock()
                .unwrap()
                .as_ref()
                .map(|z| *z.as_bytes())
            else {
                set_toast(
                    &mut state.lock().unwrap(),
                    "Unlock wallet once to bind or revoke your on-chain DexTradeOnly proxy.",
                    false,
                );
                return true;
            };
            let max_budget = parse_decimal_xcr(&max_xcr_str)
                .unwrap_or_else(|| Amount::from_credits(20).unwrap());
            let ep = seed_rpc_endpoint(state.lock().unwrap().active_mode);

            match bind_or_revoke_dex_proxy(&seed, enable, ep) {
                Ok((
                    proxy_pk,
                    NodeRpcResponse::ContractReceipt {
                        accepted: true,
                        message,
                        ..
                    },
                )) => {
                    if enable {
                        let p_seed = derive_dex_bot_proxy_seed(&seed);
                        *bot_proxy_seed.lock().unwrap() = Some(p_seed);
                        let mut st = state.lock().unwrap();
                        st.exchange.spread_bot.enabled = true;
                        st.exchange.spread_bot.asset_id = Some(asset_id);
                        st.exchange.spread_bot.half_spread_bps = half_spread_bps.clamp(10, 2_000);
                        st.exchange.spread_bot.units_per_side = units_per_side.max(1);
                        st.exchange.spread_bot.max_xcr_budget = max_budget;
                        st.exchange.spread_bot.proxy_address_short =
                            proxy_pk.to_address().short_hex();
                        st.exchange.spread_bot.last_status = format!(
                            "Active via {message} — quoting Bid & Ask around mid-price every ~12s."
                        );
                        set_toast(
                            &mut st,
                            "🤖 Spread Bot started with non-withdrawal DexTradeOnly proxy!",
                            true,
                        );
                    } else {
                        *bot_proxy_seed.lock().unwrap() = None;
                        let mut st = state.lock().unwrap();
                        st.exchange.spread_bot.enabled = false;
                        st.exchange.spread_bot.proxy_address_short.clear();
                        st.exchange.spread_bot.last_status =
                            String::from("Stopped — on-chain DexTradeOnly proxy key revoked.");
                        set_toast(&mut st, "⏹ Spread Bot stopped & proxy key revoked.", true);
                    }
                    if enable {
                        run_spread_bot_tick(ep, state, bot_proxy_seed);
                    }
                }
                Ok((_, NodeRpcResponse::ContractReceipt { message, .. })) => {
                    set_toast(&mut state.lock().unwrap(), message, false);
                }
                Err(e) => set_toast(&mut state.lock().unwrap(), format!("{e}"), false),
                _ => {}
            }
        }

        UserCommand::LaunchAssetAndOptionalPool {
            ticker,
            total_supply,
            pool_xcr_str,
            pool_units,
        } => {
            let Some(seed) = unlocked_seed
                .lock()
                .unwrap()
                .as_ref()
                .map(|z| *z.as_bytes())
            else {
                set_toast(&mut state.lock().unwrap(), "Unlock wallet first.", false);
                return true;
            };
            let pool_xcr = parse_decimal_xcr(&pool_xcr_str).unwrap_or(Amount::ZERO);
            {
                let mut st = state.lock().unwrap();
                let need = pool_xcr.saturating_add(Amount::from_bits(MIN_BASE_FEE_BITS * 2));
                if need > st.available_wallet_balance() {
                    set_toast(
                        &mut st,
                        "Initial pool XCR exceeds Available Wallet Balance (earn a few more practice XCR or enter 0).",
                        false,
                    );
                    return true;
                }
            }
            let (addr, mode) = {
                let st = state.lock().unwrap();
                (st.pocket_address, st.active_mode)
            };
            let ep = seed_rpc_endpoint(mode);
            let Ok(tmp_w) = write_temp_seed_for_cli(app_dir, &seed) else {
                return true;
            };
            let mint_salt = random_salt16("XCR.DESKTOP.MINT_ASSET.V1");
            let mint_res = cli_mint_native_asset(&tmp_w, &ticker, total_supply, mint_salt, ep);
            match mint_res {
                Ok(NodeRpcResponse::ContractReceipt {
                    accepted: true,
                    contract_id: minted_asset_id,
                    message,
                    ..
                }) => {
                    let mut final_msg = format!("🚀 Minted `{ticker}`! ({message})");
                    if !pool_xcr.is_zero() && pool_units > 0 && pool_units <= total_supply {
                        let lp_salt = random_salt16("XCR.DESKTOP.INIT_POOL.V1");
                        if let Ok(NodeRpcResponse::ContractReceipt {
                            accepted: true,
                            message: lp_msg,
                            ..
                        }) = cli_amm_liquidity(
                            &tmp_w,
                            false,
                            &minted_asset_id.to_hex(),
                            pool_xcr,
                            pool_units,
                            lp_salt,
                            ep,
                        ) {
                            final_msg = format!("🚀 `{ticker}` live with AMM pool! ({lp_msg})");
                        }
                    }
                    let _ = fs::remove_file(&tmp_w);
                    {
                        let mut st = state.lock().unwrap();
                        st.exchange.selected_asset = Some(minted_asset_id);
                        set_toast(&mut st, final_msg, true);
                    }
                    let primary = best_rpc_endpoint(mode, t_port, m_port);
                    refresh_exchange_snapshot(addr, primary, ep, state);
                }
                Ok(NodeRpcResponse::ContractReceipt { message, .. }) => {
                    let _ = fs::remove_file(&tmp_w);
                    set_toast(&mut state.lock().unwrap(), message, false);
                }
                Err(e) => {
                    let _ = fs::remove_file(&tmp_w);
                    set_toast(&mut state.lock().unwrap(), format!("{e}"), false);
                }
                _ => {
                    let _ = fs::remove_file(&tmp_w);
                }
            }
        }

        UserCommand::PostCrossChainOffer {
            counter_asset,
            counter_amount,
            xcr_amount_str,
            timelock_secs,
        } => {
            let Some(seed) = unlocked_seed
                .lock()
                .unwrap()
                .as_ref()
                .map(|z| *z.as_bytes())
            else {
                set_toast(&mut state.lock().unwrap(), "Unlock wallet first.", false);
                return true;
            };
            let Some(xcr_amt) = parse_decimal_xcr(&xcr_amount_str) else {
                set_toast(&mut state.lock().unwrap(), "Invalid XCR amount.", false);
                return true;
            };
            let secret = create_and_persist_swap_secret(
                app_dir,
                &seed,
                &format!("{counter_asset}:{counter_amount}"),
            );
            let (addr, mode) = {
                let mut st = state.lock().unwrap();
                st.atomic_swaps.local_secrets.push(secret.clone());
                (st.pocket_address, st.active_mode)
            };
            let ep = seed_rpc_endpoint(mode);
            let Ok(tmp_w) = write_temp_seed_for_cli(app_dir, &seed) else {
                return true;
            };
            let now_s = now_unix_ms() / 1_000;
            let res = cli_post_swap_offer(
                &tmp_w,
                xcr_amt,
                &counter_asset,
                &counter_amount,
                &secret.hashlock.to_hex(),
                timelock_secs.max(900),
                now_s.saturating_add(86_400),
                ep,
            );
            let _ = fs::remove_file(&tmp_w);
            match res {
                Ok((_, NodeRpcResponse::ContractReceipt { accepted: true, .. })) => {
                    set_toast(
                        &mut state.lock().unwrap(),
                        format!(
                            "🔗 Published Cross-Chain Swap Offer: {} <-> {counter_amount} {counter_asset}",
                            xcr_amt.format_symbolic()
                        ),
                        true,
                    );
                    let primary = best_rpc_endpoint(mode, t_port, m_port);
                    refresh_swaps_and_fiat_snapshot(addr, primary, ep, state);
                }
                Ok((_, other)) => {
                    set_toast(
                        &mut state.lock().unwrap(),
                        format!("Offer reply: {other:?}"),
                        false,
                    );
                }
                Err(e) => set_toast(&mut state.lock().unwrap(), format!("{e}"), false),
            }
        }

        UserCommand::LockCrossChainHtlc {
            recipient,
            xcr_amount_str,
            hashlock,
            timelock_secs,
        } => {
            let Some(seed) = unlocked_seed
                .lock()
                .unwrap()
                .as_ref()
                .map(|z| *z.as_bytes())
            else {
                set_toast(&mut state.lock().unwrap(), "Unlock wallet first.", false);
                return true;
            };
            let Some(xcr_amt) = parse_decimal_xcr(&xcr_amount_str) else {
                set_toast(&mut state.lock().unwrap(), "Invalid XCR amount.", false);
                return true;
            };
            let (addr, mode) = {
                let mut st = state.lock().unwrap();
                if xcr_amt.saturating_add(Amount::from_bits(MIN_BASE_FEE_BITS))
                    > st.available_wallet_balance()
                {
                    set_toast(
                        &mut st,
                        "HTLC lock exceeds Available Wallet Balance (Safety Vault is protected).",
                        false,
                    );
                    return true;
                }
                (st.pocket_address, st.active_mode)
            };
            let ep = seed_rpc_endpoint(mode);
            let Ok(tmp_w) = write_temp_seed_for_cli(app_dir, &seed) else {
                return true;
            };
            let exp = (now_unix_ms() / 1_000).saturating_add(timelock_secs.max(900));
            let salt = random_salt16("XCR.DESKTOP.HTLC_LOCK.V1");
            let res = cli_htlc_lock(
                &tmp_w,
                recipient.trim(),
                xcr_amt,
                &hashlock.to_hex(),
                exp,
                salt,
                ep,
            );
            let _ = fs::remove_file(&tmp_w);
            match res {
                Ok(NodeRpcResponse::ContractReceipt {
                    accepted: true,
                    message,
                    ..
                }) => {
                    set_toast(&mut state.lock().unwrap(), format!("🔒 {message}"), true);
                    let primary = best_rpc_endpoint(mode, t_port, m_port);
                    refresh_swaps_and_fiat_snapshot(addr, primary, ep, state);
                }
                Ok(NodeRpcResponse::ContractReceipt { message, .. }) => {
                    set_toast(&mut state.lock().unwrap(), message, false);
                }
                Err(e) => set_toast(&mut state.lock().unwrap(), format!("{e}"), false),
                _ => {}
            }
        }

        UserCommand::ClaimCrossChainHtlc {
            escrow_hex,
            preimage_hex,
        } => {
            let (addr, mode) = {
                let st = state.lock().unwrap();
                (st.pocket_address, st.active_mode)
            };
            let ep = seed_rpc_endpoint(mode);
            match cli_htlc_claim(escrow_hex.trim(), preimage_hex.trim(), ep) {
                Ok(NodeRpcResponse::ContractReceipt {
                    accepted: true,
                    message,
                    ..
                }) => {
                    set_toast(&mut state.lock().unwrap(), format!("🔓 {message}"), true);
                    let primary = best_rpc_endpoint(mode, t_port, m_port);
                    refresh_swaps_and_fiat_snapshot(addr, primary, ep, state);
                }
                Ok(NodeRpcResponse::ContractReceipt { message, .. }) => {
                    set_toast(&mut state.lock().unwrap(), message, false);
                }
                Err(e) => set_toast(&mut state.lock().unwrap(), format!("{e}"), false),
                _ => {}
            }
        }

        UserCommand::RefundCrossChainHtlc { escrow_id } => {
            let (addr, mode) = {
                let st = state.lock().unwrap();
                (st.pocket_address, st.active_mode)
            };
            let ep = seed_rpc_endpoint(mode);
            match cli_htlc_refund(&escrow_id.to_hex(), ep) {
                Ok(NodeRpcResponse::ContractReceipt {
                    accepted: true,
                    message,
                    ..
                }) => {
                    set_toast(&mut state.lock().unwrap(), format!("↩ {message}"), true);
                    let primary = best_rpc_endpoint(mode, t_port, m_port);
                    refresh_swaps_and_fiat_snapshot(addr, primary, ep, state);
                }
                Ok(NodeRpcResponse::ContractReceipt { message, .. }) => {
                    set_toast(&mut state.lock().unwrap(), message, false);
                }
                Err(e) => set_toast(&mut state.lock().unwrap(), format!("{e}"), false),
                _ => {}
            }
        }

        UserCommand::ProbeBitcoinP2wshAddress { address } => {
            let state_c = Arc::clone(state);
            thread::spawn(move || {
                let msg = match probe_bitcoin_p2wsh_utxo(&address) {
                    Ok(s) => s,
                    Err(e) => e,
                };
                state_c
                    .lock()
                    .unwrap()
                    .atomic_swaps
                    .btc_address_probe_status = msg;
            });
        }

        UserCommand::PostP2pFiatOffer {
            fiat_rail_code,
            fiat_amount_str,
            xcr_amount_str,
        } => {
            let Some(seed) = unlocked_seed
                .lock()
                .unwrap()
                .as_ref()
                .map(|z| *z.as_bytes())
            else {
                set_toast(&mut state.lock().unwrap(), "Unlock wallet first.", false);
                return true;
            };
            let Some(xcr_amt) = parse_decimal_xcr(&xcr_amount_str) else {
                set_toast(&mut state.lock().unwrap(), "Invalid XCR amount.", false);
                return true;
            };
            let (addr, mode) = {
                let mut st = state.lock().unwrap();
                let cap_xcr =
                    Amount::from_credits(st.p2p_fiat.max_trade_limit_xcr()).unwrap_or(Amount::ZERO);
                if xcr_amt > cap_xcr {
                    set_toast(
                        &mut st,
                        format!(
                            "Exceeds your current Zero-PII Reputation tier cap ({}). Complete a smaller P2P trade first to age your account!",
                            cap_xcr.format_symbolic()
                        ),
                        false,
                    );
                    return true;
                }
                (st.pocket_address, st.active_mode)
            };
            let ep = seed_rpc_endpoint(mode);
            let Ok(tmp_w) = write_temp_seed_for_cli(app_dir, &seed) else {
                return true;
            };
            let now_s = now_unix_ms() / 1_000;
            let tag_hl = domain_hash(
                "XCR.DESKTOP.FIAT_OFFER_TAG.V1",
                &[&seed, &now_s.to_le_bytes(), fiat_rail_code.as_bytes()],
            );
            let res = cli_post_swap_offer(
                &tmp_w,
                xcr_amt,
                &fiat_rail_code,
                &fiat_amount_str,
                &tag_hl.to_hex(),
                86_400,
                now_s.saturating_add(86_400),
                ep,
            );
            let _ = fs::remove_file(&tmp_w);
            match res {
                Ok((_, NodeRpcResponse::ContractReceipt { accepted: true, .. })) => {
                    set_toast(
                        &mut state.lock().unwrap(),
                        format!(
                            "🏦 Published P2P Fiat Offer: {} for {fiat_amount_str} ({fiat_rail_code})",
                            xcr_amt.format_symbolic()
                        ),
                        true,
                    );
                    let primary = best_rpc_endpoint(mode, t_port, m_port);
                    refresh_swaps_and_fiat_snapshot(addr, primary, ep, state);
                }
                Ok((_, other)) => {
                    set_toast(
                        &mut state.lock().unwrap(),
                        format!("Fiat offer: {other:?}"),
                        false,
                    );
                }
                Err(e) => set_toast(&mut state.lock().unwrap(), format!("{e}"), false),
            }
        }

        UserCommand::LockP2pFiatEscrow {
            buyer_pubkey_hex66,
            trade_xcr_str,
            bond_pct,
            fiat_label,
        } => {
            let Some(seed) = unlocked_seed
                .lock()
                .unwrap()
                .as_ref()
                .map(|z| *z.as_bytes())
            else {
                set_toast(&mut state.lock().unwrap(), "Unlock wallet first.", false);
                return true;
            };
            let Some(buyer_pk) = decode_pubkey_hex66(&buyer_pubkey_hex66) else {
                set_toast(
                    &mut state.lock().unwrap(),
                    "Enter a valid 66-hex Buyer PublicKey.",
                    false,
                );
                return true;
            };
            let Some(trade_xcr) = parse_decimal_xcr(&trade_xcr_str) else {
                set_toast(
                    &mut state.lock().unwrap(),
                    "Invalid Trade XCR amount.",
                    false,
                );
                return true;
            };
            let bond_bits =
                ((trade_xcr.bits() as u128 * bond_pct.clamp(10, 50) as u128) / 100) as u64;
            let bond_xcr = Amount::from_bits(bond_bits);
            let total_need = trade_xcr
                .saturating_add(bond_xcr)
                .saturating_add(Amount::from_bits(MIN_BASE_FEE_BITS));

            let mode = {
                let mut st = state.lock().unwrap();
                if total_need > st.available_wallet_balance() {
                    set_toast(
                        &mut st,
                        "Trade + Security Bond exceeds Available Wallet Balance (Safety Vault is protected).",
                        false,
                    );
                    return true;
                }
                st.active_mode
            };
            let ep = seed_rpc_endpoint(mode);
            match lock_bisq_fiat_escrow_vault(&seed, buyer_pk, trade_xcr, bond_xcr, &fiat_label, ep)
            {
                Ok((
                    escrow,
                    NodeRpcResponse::ContractReceipt {
                        accepted: true,
                        message,
                        ..
                    },
                )) => {
                    let mut st = state.lock().unwrap();
                    st.p2p_fiat.escrows.push(escrow);
                    save_fiat_escrows(app_dir, &st.p2p_fiat.escrows);
                    set_toast(
                        &mut st,
                        format!(
                            "🔒 Locked 2-of-3 Fiat Escrow + Bond! Share `📋 Ticket` with Buyer ({message})"
                        ),
                        true,
                    );
                }
                Ok((_, NodeRpcResponse::ContractReceipt { message, .. })) => {
                    set_toast(&mut state.lock().unwrap(), message, false);
                }
                Err(e) => set_toast(&mut state.lock().unwrap(), format!("{e}"), false),
                _ => {}
            }
        }

        UserCommand::ImportP2pFiatTicket { ticket } => {
            let Some(esc) = decode_fiat_escrow_ticket(&ticket) else {
                set_toast(
                    &mut state.lock().unwrap(),
                    "Invalid `xcrfiat1_` escrow ticket or tampered 2-of-3 script hash.",
                    false,
                );
                return true;
            };
            let mut st = state.lock().unwrap();
            if !st
                .p2p_fiat
                .escrows
                .iter()
                .any(|e| e.vault_id == esc.vault_id)
            {
                st.p2p_fiat.escrows.push(esc);
                save_fiat_escrows(app_dir, &st.p2p_fiat.escrows);
                set_toast(
                    &mut st,
                    "✓ Verified & imported 2-of-3 P2P Fiat Escrow ticket!",
                    true,
                );
            }
        }

        UserCommand::BuyerSignFiatSent { vault_id } => {
            let Some(seed) = unlocked_seed
                .lock()
                .unwrap()
                .as_ref()
                .map(|z| *z.as_bytes())
            else {
                set_toast(&mut state.lock().unwrap(), "Unlock wallet first.", false);
                return true;
            };
            let mut st = state.lock().unwrap();
            let Some(idx) = st
                .p2p_fiat
                .escrows
                .iter()
                .position(|e| e.vault_id == vault_id)
            else {
                return true;
            };
            match buyer_sign_fiat_sent_cosig(&seed, &st.p2p_fiat.escrows[idx]) {
                Ok(sig_hex) => {
                    st.p2p_fiat.escrows[idx].buyer_cosig_hex = sig_hex;
                    save_fiat_escrows(app_dir, &st.p2p_fiat.escrows);
                    set_toast(
                        &mut st,
                        "💸 Signed Fiat-Sent Co-Signature! Click `📋 Copy Co-Sig` to send to Seller.",
                        true,
                    );
                }
                Err(e) => set_toast(&mut st, e, false),
            }
        }

        UserCommand::SellerReleaseFiatEscrow {
            vault_id,
            buyer_cosig_hex,
        } => {
            let Some(seed) = unlocked_seed
                .lock()
                .unwrap()
                .as_ref()
                .map(|z| *z.as_bytes())
            else {
                set_toast(&mut state.lock().unwrap(), "Unlock wallet first.", false);
                return true;
            };
            let (esc_opt, addr, mode) = {
                let st = state.lock().unwrap();
                let found = st
                    .p2p_fiat
                    .escrows
                    .iter()
                    .find(|e| e.vault_id == vault_id)
                    .cloned();
                (found, st.pocket_address, st.active_mode)
            };
            let Some(esc) = esc_opt else {
                return true;
            };
            let ep = seed_rpc_endpoint(mode);
            match seller_finalize_fiat_escrow_and_attest(&seed, &esc, &buyer_cosig_hex, ep) {
                Ok(NodeRpcResponse::ContractReceipt {
                    accepted: true,
                    message,
                    ..
                }) => {
                    {
                        let mut st = state.lock().unwrap();
                        if let Some(slot) = st
                            .p2p_fiat
                            .escrows
                            .iter_mut()
                            .find(|e| e.vault_id == vault_id)
                        {
                            slot.settled = true;
                        }
                        save_fiat_escrows(app_dir, &st.p2p_fiat.escrows);
                        set_toast(
                            &mut st,
                            format!(
                                "✅ Released XCR to Buyer, reclaimed your Bond, & minted Zero-PII Reputation! ({message})"
                            ),
                            true,
                        );
                    }
                    let primary = best_rpc_endpoint(mode, t_port, m_port);
                    refresh_swaps_and_fiat_snapshot(addr, primary, ep, state);
                }
                Ok(NodeRpcResponse::ContractReceipt { message, .. }) => {
                    set_toast(&mut state.lock().unwrap(), message, false);
                }
                Err(e) => set_toast(&mut state.lock().unwrap(), format!("{e}"), false),
                _ => {}
            }
        }

        UserCommand::ShutdownAll => {
            stop_node_if_running(t_port);
            stop_node_if_running(m_port);
            return false;
        }
    }
    true
}

fn refresh_exchange_snapshot(
    owner: Address,
    primary: SocketAddr,
    fallback: SocketAddr,
    state: &Arc<Mutex<UiSnapshot>>,
) {
    if let Some((assets, pools, orders, oracles)) =
        fetch_exchange_network_data(owner, primary, fallback)
    {
        let mut st = state.lock().unwrap();
        if st.exchange.selected_asset.is_none()
            && let Some(first) = assets.first()
        {
            st.exchange.selected_asset = Some(first.asset_id);
        }
        st.exchange.assets = assets;
        st.exchange.pools = pools;
        st.exchange.orders = orders;
        st.exchange.oracles = oracles;
    }
}

fn run_spread_bot_tick(
    node_addr: SocketAddr,
    state: &Arc<Mutex<UiSnapshot>>,
    bot_proxy_seed: &Arc<Mutex<Option<[u8; 32]>>>,
) {
    let Some(proxy_seed) = *bot_proxy_seed.lock().unwrap() else {
        return;
    };
    let (
        owner,
        avail_xcr,
        asset_id,
        half_bps,
        units,
        max_budget,
        mid_opt,
        owned_units,
        has_bid,
        has_ask,
    ) = {
        let st = state.lock().unwrap();
        if !st.exchange.spread_bot.enabled {
            return;
        }
        let Some(aid) = st.exchange.spread_bot.asset_id else {
            return;
        };
        let mid = st.exchange.mid_price_bits(&aid);
        let owned = st
            .exchange
            .assets
            .iter()
            .find(|a| a.asset_id == aid)
            .map(|a| a.owner_balance)
            .unwrap_or(0);
        let my_bid = st.exchange.orders.iter().any(|o| {
            o.maker == st.pocket_address
                && o.asset_id == aid
                && !o.is_sell_asset
                && o.remaining_units > 0
        });
        let my_ask = st.exchange.orders.iter().any(|o| {
            o.maker == st.pocket_address
                && o.asset_id == aid
                && o.is_sell_asset
                && o.remaining_units > 0
        });
        (
            st.pocket_address,
            st.available_wallet_balance(),
            aid,
            st.exchange.spread_bot.half_spread_bps,
            st.exchange.spread_bot.units_per_side,
            st.exchange.spread_bot.max_xcr_budget,
            mid,
            owned,
            my_bid,
            my_ask,
        )
    };

    let Some(mid_bits) = mid_opt.filter(|&m| m > 100) else {
        return;
    };
    let bid_price =
        ((mid_bits as u128 * (10_000u128.saturating_sub(half_bps as u128))) / 10_000).max(1) as u64;
    let ask_price =
        (((mid_bits as u128 * (10_000u128 + half_bps as u128)) / 10_000) as u64).max(bid_price + 1);

    let mut placed_now = 0u64;
    if !has_bid {
        let cost = Amount::from_bits(
            units
                .saturating_mul(bid_price)
                .saturating_add(MIN_BASE_FEE_BITS),
        );
        if cost <= avail_xcr
            && cost <= max_budget
            && let Ok(NodeRpcResponse::ContractReceipt { accepted: true, .. }) =
                submit_proxy_dex_quote(
                    &proxy_seed,
                    owner,
                    asset_id,
                    false,
                    units,
                    bid_price,
                    node_addr,
                )
        {
            placed_now += 1;
        }
    }

    if !has_ask
        && owned_units >= units
        && avail_xcr >= Amount::from_bits(MIN_BASE_FEE_BITS)
        && let Ok(NodeRpcResponse::ContractReceipt { accepted: true, .. }) = submit_proxy_dex_quote(
            &proxy_seed,
            owner,
            asset_id,
            true,
            units,
            ask_price,
            node_addr,
        )
    {
        placed_now += 1;
    }

    if placed_now > 0 {
        let mut st = state.lock().unwrap();
        st.exchange.spread_bot.quotes_placed = st
            .exchange
            .spread_bot
            .quotes_placed
            .saturating_add(placed_now);
        st.exchange.spread_bot.last_status = format!(
            "Quoted live spread around ∀ {:.4} XCR (Bid ∀ {:.4} / Ask ∀ {:.4})",
            mid_bits as f64 / 1_000_000.0,
            bid_price as f64 / 1_000_000.0,
            ask_price as f64 / 1_000_000.0
        );
    }
}

fn poll_network_and_wallet(
    tick: u64,
    app_dir: &Path,
    state: &Arc<Mutex<UiSnapshot>>,
    unlocked_seed: &Arc<Mutex<Option<ZeroizingSeed>>>,
    bot_proxy_seed: &Arc<Mutex<Option<[u8; 32]>>>,
    t_port: &Arc<Mutex<Option<u16>>>,
    m_port: &Arc<Mutex<Option<u16>>>,
) {
    let now_unix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let secs_to_mainnet =
        match VerifiableGenesisBeacon::evaluate_genesis_standby(now_unix, None, None) {
            GenesisStandbyStatus::StandbyCountdown {
                seconds_remaining, ..
            } => seconds_remaining,
            _ => 0,
        };

    let (initialized, active_mode, addr) = {
        let mut st = state.lock().unwrap();
        st.seconds_to_mainnet = secs_to_mainnet;
        st.hashrate_hps = local_ponc_hashrate_hps();
        st.local_epoch_weight = local_ponc_epoch_weight();
        st.gpu_boost_enabled = is_gpu_zk_boost_enabled();
        st.gpu_evals_per_sec = local_gpu_zk_evals_per_sec();
        if let Some(dev_name) = gpu_zk_device_name() {
            st.gpu_device_name = dev_name;
        }
        // Automatically release any Safety Vault withdrawals whose 24-hour timer has completed:
        let matured = st.vault.release_matured(now_unix_ms());
        if !matured.is_empty() {
            save_vault_state(app_dir, &st.vault);
            let released = matured
                .iter()
                .fold(Amount::ZERO, |s, w| s.saturating_add(w.amount));
            set_toast(
                &mut st,
                format!(
                    "✓ 24h Safety Vault withdrawal matured: {} moved to Available Wallet Balance.",
                    released.format_symbolic()
                ),
                true,
            );
        }
        // Automatically switch view to Mainnet the instant `2027-01-01T00:00:00Z` arrives if armed!
        if secs_to_mainnet == 0
            && st.auto_mainnet_armed
            && st.active_mode == ActiveNetworkMode::PracticeTestnet
            && tick == 2
        {
            st.active_mode = ActiveNetworkMode::MainnetLiveOrStandby;
        }
        (st.initialized, st.active_mode, st.pocket_address)
    };
    if !initialized {
        return;
    }

    let primary = best_rpc_endpoint(active_mode, t_port, m_port);
    let fallback: SocketAddr = match active_mode {
        ActiveNetworkMode::PracticeTestnet => TESTNET_SEEDS[0].parse().unwrap(),
        ActiveNetworkMode::MainnetLiveOrStandby => MAINNET_SEEDS[0].parse().unwrap(),
    };

    let telem = rpc_call(
        primary,
        &NodeRpcRequest::GetNetworkTelemetry,
        Duration::from_millis(800),
    )
    .or_else(|_| {
        rpc_call(
            fallback,
            &NodeRpcRequest::GetNetworkTelemetry,
            Duration::from_millis(900),
        )
    });

    if let Ok(NodeRpcResponse::NetworkTelemetry {
        epoch,
        circulating_supply,
        total_burned,
        connected_peers,
        active_miners,
        ..
    }) = telem
    {
        let mut st = state.lock().unwrap();
        if epoch.0 != st.epoch {
            st.epoch = epoch.0;
            st.last_epoch_change = Instant::now();
        }
        st.circulating_supply = circulating_supply;
        st.total_burned = total_burned;
        st.connected_peers = connected_peers;
        st.active_miners = active_miners;
        st.node_online = true;
    }

    let pocket_res = rpc_call(
        primary,
        &NodeRpcRequest::GetPocket { address: addr },
        Duration::from_millis(800),
    )
    .or_else(|_| {
        rpc_call(
            fallback,
            &NodeRpcRequest::GetPocket { address: addr },
            Duration::from_millis(900),
        )
    });

    if let Ok(NodeRpcResponse::PocketInfo { found, balance, .. }) = pocket_res {
        let mut st = state.lock().unwrap();
        let new_bal = if found { balance } else { Amount::ZERO };
        let start = *st.session_start_balance.get_or_insert(new_bal);
        if new_bal > st.balance && st.session_start_balance.is_some() && !st.balance.is_zero() {
            let delta = new_bal.checked_sub(st.balance).unwrap_or(Amount::ZERO);
            let ep_num = st.epoch;
            st.recent_events.push_front(format!(
                "⚡ Earned / Received +{} (Epoch #{ep_num})",
                delta.format_symbolic(),
            ));
            while st.recent_events.len() > 25 {
                st.recent_events.pop_back();
            }
        }
        st.balance = new_bal;
        st.session_earned = new_bal.checked_sub(start).unwrap_or(Amount::ZERO);
        let xcr_f64 = new_bal.bits() as f64 / 1_000_000.0;
        if st
            .balance_history
            .last()
            .is_none_or(|&last| (last - xcr_f64).abs() > 1e-7)
            || tick.is_multiple_of(4)
        {
            st.balance_history.push(xcr_f64);
            if st.balance_history.len() > 60 {
                st.balance_history.remove(0);
            }
        }
    }

    // Background zero-click Stealth incoming sweep every ~9 seconds when unlocked:
    if tick.is_multiple_of(6)
        && let Some(seed) = unlocked_seed
            .lock()
            .unwrap()
            .as_ref()
            .map(|z| *z.as_bytes())
        && let Ok(tmp_w) = write_temp_seed_for_cli(app_dir, &seed)
    {
        if let Ok((_, matches)) = cli_scan_and_claim_stealth_v2(&tmp_w, fallback, true) {
            let total_in = matches
                .iter()
                .filter(|(_, _, was_claimed, _, _)| *was_claimed)
                .fold(Amount::ZERO, |s, (_, a, _, _, _)| s.saturating_add(*a));
            if !total_in.is_zero() {
                set_toast(
                    &mut state.lock().unwrap(),
                    format!(
                        "✓ Auto-received private payment +{}",
                        total_in.format_symbolic()
                    ),
                    true,
                );
            }
        }
        let _ = fs::remove_file(&tmp_w);
    }

    // Refresh native DEX assets, AMM pools, and open orderbooks every ~3 seconds:
    if tick == 1 || tick.is_multiple_of(2) {
        refresh_exchange_snapshot(addr, primary, fallback, state);
    }

    // Refresh Cross-Chain Atomic Swaps, auto-claim matching HTLCs, & refresh P2P Fiat Reputation every ~6s:
    if tick == 1 || tick.is_multiple_of(4) {
        refresh_swaps_and_fiat_snapshot(addr, primary, fallback, state);
    }

    // Run non-withdrawal `DexTradeOnly` Spread Bot cycle every ~12 seconds if armed:
    if tick.is_multiple_of(8) {
        run_spread_bot_tick(fallback, state, bot_proxy_seed);
    }
}

fn refresh_swaps_and_fiat_snapshot(
    owner: Address,
    primary: SocketAddr,
    fallback: SocketAddr,
    state: &Arc<Mutex<UiSnapshot>>,
) {
    if let Some((offers, htlcs)) = fetch_atomic_swaps_and_htlcs(primary, fallback) {
        // Check if any open incoming HTLC can be automatically claimed using a local secret:
        let claimable: Vec<(Hash32, [u8; 32], Amount)> = {
            let st = state.lock().unwrap();
            htlcs
                .iter()
                .filter(|h| h.status == 0 && h.recipient == owner)
                .filter_map(|h| {
                    st.atomic_swaps
                        .local_secrets
                        .iter()
                        .find(|s| s.hashlock == h.hashlock)
                        .map(|s| (h.escrow_id, s.preimage, h.amount))
                })
                .collect()
        };

        for (escrow_id, preimage, amt) in claimable {
            if let Ok(NodeRpcResponse::ContractReceipt { accepted: true, .. }) = rpc_call(
                fallback,
                &NodeRpcRequest::ClaimHtlc {
                    escrow_id,
                    preimage,
                },
                Duration::from_secs(2),
            ) {
                set_toast(
                    &mut state.lock().unwrap(),
                    format!(
                        "🔓 Auto-claimed incoming Atomic Swap HTLC +{}!",
                        amt.format_symbolic()
                    ),
                    true,
                );
            }
        }

        let mut st = state.lock().unwrap();
        st.atomic_swaps.offers = offers;
        st.atomic_swaps.htlcs = htlcs;
    }

    if let Some((fiat_offers, my_rep, rep_list)) =
        fetch_p2p_fiat_network_data(owner, primary, fallback)
    {
        let mut st = state.lock().unwrap();
        st.p2p_fiat.fiat_offers = fiat_offers;
        st.p2p_fiat.my_completed_trades = my_rep;
        st.p2p_fiat.network_trade_attestations = rep_list;
    }
}

pub fn format_countdown(secs: u64) -> String {
    if secs == 0 {
        return format!("LIVE ({MAINNET_GENESIS_ISO8601})");
    }
    let d = secs / 86_400;
    let h = (secs % 86_400) / 3_600;
    let m = (secs % 3_600) / 60;
    let s = secs % 60;
    format!("{d}d {h:02}h {m:02}m {s:02}s")
}

/// Formats remaining time until `unlock_at_ms` for pending 24-hour Safety Vault withdrawals.
pub fn format_vault_remaining(unlock_at_ms: u64) -> String {
    let rem_secs = unlock_at_ms.saturating_sub(now_unix_ms()) / 1_000;
    if rem_secs == 0 {
        return String::from("Releasing now...");
    }
    let h = rem_secs / 3_600;
    let m = (rem_secs % 3_600) / 60;
    let s = rem_secs % 60;
    format!("{h}h {m:02}m {s:02}s left")
}

/// Computes the 0.0..=1.0 completion fraction of a 24-hour (`86_400_000 ms`) Safety Vault timer.
pub fn vault_unlock_progress(unlock_at_ms: u64) -> f32 {
    const WINDOW_MS: f64 = 86_400_000.0;
    let rem_ms = unlock_at_ms.saturating_sub(now_unix_ms()) as f64;
    ((WINDOW_MS - rem_ms) / WINDOW_MS).clamp(0.01, 1.0) as f32
}

/// Masks `∀ <digits> XCR` substrings inside activity log lines when `hide_figures` is enabled.
pub fn mask_figures_in_line(line: &str, hide_figures: bool) -> String {
    if !hide_figures {
        return line.to_owned();
    }
    let mut out = String::with_capacity(line.len());
    let mut rest = line;
    while let Some(sym_idx) = rest.find("∀ ") {
        out.push_str(&rest[..sym_idx]);
        let after = &rest[sym_idx + "∀ ".len()..];
        if let Some(xcr_idx) = after.find(" XCR") {
            out.push_str("∀ •••••• XCR");
            rest = &after[xcr_idx + " XCR".len()..];
        } else {
            out.push_str("∀ ");
            rest = after;
        }
    }
    out.push_str(rest);
    out
}
