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

use credit_cli::{
    cli_bandwidth_free_pay, cli_claimable_sweep, cli_redpacket_claim, cli_redpacket_create,
    cli_register_handle, cli_scan_and_claim_stealth_v2, cli_send_bulletproof_payment_with_memo,
    cli_shield_deposit, cli_shield_scan, save_wallet_seed,
};
use credit_consensus::{
    GenesisStandbyStatus, MAINNET_GENESIS_ISO8601, NetworkProfile, VerifiableGenesisBeacon,
};
use credit_crypto::{Keypair, PublicKey, SignatureScheme, StealthKeypair, domain_hash};
use credit_net::{NodeRpcRequest, NodeRpcResponse, rpc_call};
use credit_node::{MeshPeerConfig, run_mesh_peer_with_reward_pubkey};
use credit_sdk::{
    PLAIN_WALLET_MAGIC, ZeroizingSeed, decode_mnemonic_24, encode_mnemonic_24, encrypt_wallet_seed,
    format_backup_card_24, is_encrypted_wallet_bytes, open_wallet_bytes, parse_decimal_xcr,
};
use credit_types::{Address, Amount, Hash32, MIN_BASE_FEE_BITS, VaultState};

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

#[derive(Clone, Debug)]
pub struct UiSnapshot {
    pub initialized: bool,
    pub onboarding_done: bool,
    pub locked: bool,
    pub encrypted_on_disk: bool,
    pub earning_enabled: bool,
    pub auto_mainnet_armed: bool,
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
            earning_enabled: true,
            auto_mainnet_armed: true,
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
            recent_events: VecDeque::new(),
            latest_gift_link: String::new(),
            toast: None,
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
                    }
                }
            }
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

        // Spawn command processor thread:
        {
            let app_dir_c = app_dir.clone();
            let state_c = Arc::clone(&state);
            let seed_c = Arc::clone(&unlocked_seed);
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
                    let keep_going =
                        handle_command(cmd, &app_dir_c, &state_c, &seed_c, &t_port_c, &m_port_c);
                    ctx_c.request_repaint();
                    if !keep_going {
                        break;
                    }
                }
            });
        }

        // Spawn 1.5s non-blocking telemetry & auto-stealth-sweep poller thread:
        {
            let app_dir_p = app_dir.clone();
            let state_p = Arc::clone(&state);
            let seed_p = Arc::clone(&unlocked_seed);
            let t_port_p = Arc::clone(&testnet_port);
            let m_port_p = Arc::clone(&mainnet_port);
            let ctx_p = egui_ctx;

            thread::spawn(move || {
                let mut tick = 0u64;
                loop {
                    thread::sleep(Duration::from_millis(1_500));
                    tick = tick.wrapping_add(1);
                    poll_network_and_wallet(
                        tick, &app_dir_p, &state_p, &seed_p, &t_port_p, &m_port_p,
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

fn save_settings(app_dir: &Path, st: &UiSnapshot) {
    let body = format!(
        "onboarding_done={}\nearning={}\narm_mainnet={}\nhandle={}\n",
        st.onboarding_done as u8,
        st.earning_enabled as u8,
        st.auto_mainnet_armed as u8,
        st.claimed_handle
    );
    let _ = fs::write(app_dir.join("settings.txt"), body);
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
                return true;
            };
            let mut st = state.lock().unwrap();
            st.vault.balance = st.vault.balance.saturating_add(amt);
            set_toast(
                &mut st,
                format!(
                    "✓ Parked {} in 24-Hour Savings Vault.",
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
            match st.vault.queue_withdrawal(dest, amt, 1_000) {
                Ok(id) => set_toast(
                    &mut st,
                    format!("Queued Vault withdrawal #{id} (24h safety window active)."),
                    true,
                ),
                Err(e) => set_toast(&mut st, format!("Vault: {e}"), false),
            }
        }

        UserCommand::VaultEmergencyUndo { id } => {
            let mut st = state.lock().unwrap();
            match st.vault.emergency_cancel(id) {
                Ok(restored) => set_toast(
                    &mut st,
                    format!(
                        "🛡 EMERGENCY UNDO COMPLETE: Restored {} back to Vault!",
                        restored.format_symbolic()
                    ),
                    true,
                ),
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

        UserCommand::ShutdownAll => {
            stop_node_if_running(t_port);
            stop_node_if_running(m_port);
            return false;
        }
    }
    true
}

fn poll_network_and_wallet(
    tick: u64,
    app_dir: &Path,
    state: &Arc<Mutex<UiSnapshot>>,
    unlocked_seed: &Arc<Mutex<Option<ZeroizingSeed>>>,
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
