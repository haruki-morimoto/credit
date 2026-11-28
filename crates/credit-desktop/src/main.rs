#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

//! **Credits Desktop (`credit-desktop`)** — Native `egui` Consumer Wallet & 1-Click Automatic Miner.
//!
//! Designed for everyday people with zero terminal commands or crypto jargon:
//! - **30-Second First-Launch Wizard:** Creates an `XCRENC01`-protected wallet, displays a printable
//!   24-word recovery card, and starts automatic background earning in 1 click.
//! - **Home & Live Earnings Dashboard:** Real-time `∀ XCR` balance, session earnings counter, 60s
//!   epoch reward progress bar, balance sparkline, and automatic Mainnet Epoch-0 readiness (`2027-01-01`).
//! - **Simple Send, QR Receive & Gift Links:** Automatically uses the 3 free `0`-fee daily transfers
//!   first, renders native `egui` QR codes, and creates/redeems shareable `xcrdrop1_` Gift Links.
//! - **24-Hour Savings Vault + Optional Pro Tab:** Emergency Undo scam protection up front, with
//!   Shielded RingCT privacy tucked cleanly under `Advanced`.

mod backend;
mod gpu_wgpu;
mod theme_qr;
mod updater;

use std::fs;
use std::time::Duration;

use backend::{
    ActiveNetworkMode, CpuPowerMode, DesktopController, UiSnapshot, UserCommand, format_countdown,
    format_vault_remaining, mask_figures_in_line, vault_unlock_progress,
};
use eframe::egui::{self, Color32, CornerRadius, RichText, Stroke, Vec2};
use theme_qr::{
    ACCENT_BLUE, ACCENT_EMERALD, ACCENT_GOLD, BG_CARD, BG_INPUT, BORDER_SUBTLE, DANGER_RED,
    TEXT_MUTED, TEXT_PRIMARY, apply_credits_theme, build_app_icon, draw_earnings_sparkline,
    draw_qr_canvas,
};
use updater::{APP_BUILD_NUMBER, APP_VERSION, AutoUpdateStatus, OFFICIAL_RELEASE_PUBKEY_HEX};

#[derive(Clone, Copy, PartialEq, Eq)]
enum MainTab {
    HomeAndEarnings,
    SendAndReceive,
    SavingsVault,
    AdvancedPrivacy,
}

struct CreditsDesktopApp {
    ctrl: DesktopController,
    tab: MainTab,
    wizard_step: u8,
    setup_use_recovery: bool,
    setup_password: String,
    setup_words: String,
    wizard_enable_earning: bool,
    wizard_arm_mainnet: bool,
    wizard_gift_code: String,
    unlock_password: String,
    send_to: String,
    send_amount: String,
    send_memo: String,
    handle_input: String,
    gift_amount: String,
    gift_claims: u16,
    redeem_input: String,
    vault_amount: String,
    shield_amount: String,
    show_recovery_modal: bool,
}

impl CreditsDesktopApp {
    fn new(cc: &eframe::CreationContext<'_>) -> Self {
        apply_credits_theme(&cc.egui_ctx);
        let ctrl = DesktopController::start(cc.egui_ctx.clone());
        Self {
            ctrl,
            tab: MainTab::HomeAndEarnings,
            wizard_step: 1,
            setup_use_recovery: false,
            setup_password: String::new(),
            setup_words: String::new(),
            wizard_enable_earning: true,
            wizard_arm_mainnet: true,
            wizard_gift_code: String::new(),
            unlock_password: String::new(),
            send_to: String::new(),
            send_amount: String::from("5.00"),
            send_memo: String::new(),
            handle_input: String::from("@"),
            gift_amount: String::from("1.00"),
            gift_claims: 1,
            redeem_input: String::new(),
            vault_amount: String::from("10.00"),
            shield_amount: String::from("2.00"),
            show_recovery_modal: false,
        }
    }

    fn render_wizard(&mut self, ui: &mut egui::Ui, snap: &UiSnapshot) {
        ui.vertical_centered(|ui| {
            ui.add_space(18.0);
            ui.label(
                RichText::new("∀  Welcome to Credits")
                    .size(30.0)
                    .strong()
                    .color(TEXT_PRIMARY),
            );
            ui.label(
                RichText::new(
                    "Instant, private digital cash — earned automatically by your computer.",
                )
                .size(15.5)
                .color(TEXT_MUTED),
            );
            ui.add_space(18.0);
        });

        let step = if !snap.initialized {
            1
        } else {
            self.wizard_step.max(2)
        };

        egui::Frame::NONE
            .fill(BG_CARD)
            .stroke(Stroke::new(1.0_f32, BORDER_SUBTLE))
            .corner_radius(CornerRadius::same(14))
            .inner_margin(egui::Margin::same(24))
            .show(ui, |ui| {
                ui.set_min_width(ui.available_width());
                match step {
                    1 => {
                        ui.label(
                            RichText::new("Step 1 of 3 — Create Your Personal Wallet")
                                .size(19.0)
                                .strong()
                                .color(ACCENT_EMERALD),
                        );
                        ui.label(
                            RichText::new(
                                "Your wallet lives strictly on your computer. No email, phone number, or ID required.",
                            )
                            .color(TEXT_MUTED),
                        );
                        ui.add_space(10.0);

                        ui.horizontal(|ui| {
                            ui.selectable_value(
                                &mut self.setup_use_recovery,
                                false,
                                "Create Brand-New Wallet",
                            );
                            ui.selectable_value(
                                &mut self.setup_use_recovery,
                                true,
                                "Restore from 24 Words",
                            );
                        });

                        if self.setup_use_recovery {
                            ui.label("Paste your 24 recovery words:");
                            ui.add(
                                egui::TextEdit::multiline(&mut self.setup_words)
                                    .desired_rows(3)
                                    .desired_width(f32::INFINITY),
                            );
                        }

                        ui.add_space(6.0);
                        ui.label("Optional PIN / Password to lock wallet on this PC (leave blank for instant open):");
                        ui.add(
                            egui::TextEdit::singleline(&mut self.setup_password)
                                .password(true)
                                .hint_text("Optional password...")
                                .desired_width(340.0),
                        );
                        ui.add_space(14.0);

                        if ui
                            .add_sized(
                                [260.0, 42.0],
                                egui::Button::new(
                                    RichText::new("Create My Wallet  ->")
                                        .strong()
                                        .color(Color32::BLACK),
                                )
                                .fill(ACCENT_EMERALD),
                            )
                            .clicked()
                        {
                            let _ = self.ctrl.cmd_tx.send(UserCommand::CreateOrSetupWallet {
                                password: (!self.setup_password.is_empty())
                                    .then(|| self.setup_password.clone()),
                                recovery_words: self
                                    .setup_use_recovery
                                    .then(|| self.setup_words.clone()),
                            });
                            self.wizard_step = 2;
                        }
                    }

                    2 => {
                        ui.label(
                            RichText::new("Step 2 of 3 — Save Your 24-Word Recovery Key")
                                .size(19.0)
                                .strong()
                                .color(ACCENT_GOLD),
                        );
                        ui.label(
                            RichText::new(
                                "Write these 24 words down or save a backup file. Anyone with these words can recover your money if you ever buy a new computer.",
                            )
                            .color(TEXT_MUTED),
                        );
                        ui.add_space(8.0);

                        if let Some((words, card)) = self.ctrl.export_mnemonic_if_unlocked() {
                            egui::Frame::NONE
                                .fill(BG_INPUT)
                                .stroke(Stroke::new(1.0_f32, BORDER_SUBTLE))
                                .corner_radius(CornerRadius::same(10))
                                .inner_margin(egui::Margin::same(14))
                                .show(ui, |ui| {
                                    ui.label(RichText::new(&words).monospace().color(ACCENT_GOLD));
                                });
                            ui.horizontal(|ui| {
                                if ui.button("📋 Copy 24 Words").clicked() {
                                    ui.ctx().copy_text(words);
                                }
                                if ui.button("💾 Save Backup Card to Folder").clicked() {
                                    let out = self.ctrl.app_dir.join("Credits-Recovery-Card.txt");
                                    let _ = fs::write(&out, card);
                                }
                                ui.label(
                                    RichText::new(format!("Address: {}", snap.short_address))
                                        .monospace()
                                        .color(TEXT_MUTED),
                                );
                            });
                        }

                        ui.add_space(12.0);
                        ui.horizontal(|ui| {
                            if ui
                                .add_sized(
                                    [240.0, 42.0],
                                    egui::Button::new(
                                        RichText::new("I Saved My Words  ->")
                                            .strong()
                                            .color(Color32::BLACK),
                                    )
                                    .fill(ACCENT_EMERALD),
                                )
                                .clicked()
                            {
                                self.wizard_step = 3;
                            }
                        });
                    }

                    _ => {
                        ui.label(
                            RichText::new("Step 3 of 3 — Start Earning Credits Automatically")
                                .size(19.0)
                                .strong()
                                .color(ACCENT_EMERALD),
                        );
                        ui.label(
                            RichText::new(
                                "Credits has zero premine and zero insider coins — 100% of new coins are earned every 60 seconds by everyday computers like yours.",
                            )
                            .color(TEXT_MUTED),
                        );
                        ui.add_space(10.0);

                        ui.checkbox(
                            &mut self.wizard_enable_earning,
                            RichText::new("⚡ Join the network & earn Credits automatically in the background")
                                .strong(),
                        );
                        ui.checkbox(
                            &mut self.wizard_arm_mainnet,
                            RichText::new("🚀 Auto-start earning real Mainnet XCR on Jan 1, 2027 (00:00 UTC)")
                                .color(ACCENT_GOLD),
                        );

                        ui.add_space(8.0);
                        ui.label(
                            RichText::new("Have a Gift Link (xcrdrop1_...) from a friend? Paste it here (optional):")
                                .color(TEXT_MUTED),
                        );
                        ui.add(
                            egui::TextEdit::singleline(&mut self.wizard_gift_code)
                                .hint_text("Optional xcrdrop1_... gift link")
                                .desired_width(420.0),
                        );

                        ui.add_space(14.0);
                        if ui
                            .add_sized(
                                [280.0, 44.0],
                                egui::Button::new(
                                    RichText::new("Start Earning & Open Wallet")
                                        .size(16.0)
                                        .strong()
                                        .color(Color32::BLACK),
                                )
                                .fill(ACCENT_EMERALD),
                            )
                            .clicked()
                        {
                            let _ = self.ctrl.cmd_tx.send(UserCommand::CompleteOnboarding {
                                enable_earning: self.wizard_enable_earning,
                                arm_mainnet: self.wizard_arm_mainnet,
                            });
                            if !self.wizard_gift_code.trim().is_empty() {
                                let _ = self.ctrl.cmd_tx.send(UserCommand::RedeemGiftOrClaimable {
                                    code_or_id: self.wizard_gift_code.clone(),
                                });
                            }
                        }
                    }
                }
            });
    }

    fn render_top_bar(&mut self, ui: &mut egui::Ui, snap: &UiSnapshot) {
        ui.horizontal(|ui| {
            ui.label(
                RichText::new("∀ Credits")
                    .size(21.0)
                    .strong()
                    .color(TEXT_PRIMARY),
            );
            if !snap.claimed_handle.is_empty() {
                ui.label(
                    RichText::new(&snap.claimed_handle)
                        .strong()
                        .color(ACCENT_GOLD),
                );
            }

            ui.separator();

            let net_label = match snap.active_mode {
                ActiveNetworkMode::PracticeTestnet => "Practice Network (Live)",
                ActiveNetworkMode::MainnetLiveOrStandby => "Mainnet (Jan 1, 2027)",
            };
            egui::ComboBox::from_id_salt("net_mode_box")
                .selected_text(net_label)
                .show_ui(ui, |ui| {
                    if ui
                        .selectable_label(
                            snap.active_mode == ActiveNetworkMode::PracticeTestnet,
                            "Practice Network (Live Today — Earn & Test)",
                        )
                        .clicked()
                    {
                        let _ = self.ctrl.cmd_tx.send(UserCommand::SetActiveNetwork(
                            ActiveNetworkMode::PracticeTestnet,
                        ));
                    }
                    if ui
                        .selectable_label(
                            snap.active_mode == ActiveNetworkMode::MainnetLiveOrStandby,
                            format!(
                                "Mainnet (Auto-Launches in {})",
                                format_countdown(snap.seconds_to_mainnet)
                            ),
                        )
                        .clicked()
                    {
                        let _ = self.ctrl.cmd_tx.send(UserCommand::SetActiveNetwork(
                            ActiveNetworkMode::MainnetLiveOrStandby,
                        ));
                    }
                });

            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                match &snap.update_status {
                    AutoUpdateStatus::StagedReady { manifest } => {
                        if ui
                            .add(
                                egui::Button::new(
                                    RichText::new(format!(
                                        "✨ Update Ready (v{} #{}) — Restart",
                                        manifest.version, manifest.build_number
                                    ))
                                    .strong()
                                    .color(Color32::WHITE),
                                )
                                .fill(ACCENT_BLUE),
                            )
                            .on_hover_text(&manifest.notes)
                            .clicked()
                        {
                            let _ = self.ctrl.cmd_tx.send(UserCommand::ApplyUpdateAndRestart);
                        }
                    }
                    AutoUpdateStatus::Available { manifest } => {
                        if ui
                            .add(
                                egui::Button::new(
                                    RichText::new(format!(
                                        "⬇ Update v{} (#{})",
                                        manifest.version, manifest.build_number
                                    ))
                                    .strong()
                                    .color(Color32::WHITE),
                                )
                                .fill(ACCENT_BLUE),
                            )
                            .clicked()
                        {
                            let _ = self.ctrl.cmd_tx.send(UserCommand::CheckForUpdatesNow);
                        }
                    }
                    AutoUpdateStatus::Downloading {
                        version,
                        build_number,
                    } => {
                        ui.label(
                            RichText::new(format!("⬇ Downloading v{version} (#{build_number})..."))
                                .small()
                                .color(ACCENT_GOLD),
                        );
                    }
                    _ => {}
                }

                if snap.locked {
                    ui.label(RichText::new("🔒 Locked").color(ACCENT_GOLD));
                } else if snap.encrypted_on_disk && ui.button("🔒 Lock").clicked() {
                    let _ = self.ctrl.cmd_tx.send(UserCommand::LockWallet);
                }

                let privacy_lbl = if snap.hide_figures {
                    "🙈 Show Figures"
                } else {
                    "👁 Hide Figures"
                };
                if ui.button(privacy_lbl).clicked() {
                    let _ = self
                        .ctrl
                        .cmd_tx
                        .send(UserCommand::SetHideFigures(!snap.hide_figures));
                }

                let earn_btn_text = if snap.earning_enabled {
                    RichText::new("⚡ Earning: ON")
                        .strong()
                        .color(Color32::BLACK)
                } else {
                    RichText::new("⏸ Earning: Paused").color(TEXT_PRIMARY)
                };
                let earn_fill = if snap.earning_enabled {
                    ACCENT_EMERALD
                } else {
                    BG_CARD
                };
                if ui
                    .add(egui::Button::new(earn_btn_text).fill(earn_fill))
                    .clicked()
                {
                    let _ = self
                        .ctrl
                        .cmd_tx
                        .send(UserCommand::SetEarningEnabled(!snap.earning_enabled));
                }

                let status_dot = if snap.node_online {
                    RichText::new(format!(
                        "● Online · {} nodes · Epoch #{}",
                        snap.active_miners.max(1),
                        snap.epoch
                    ))
                    .color(ACCENT_EMERALD)
                } else {
                    RichText::new("◌ Connecting to mesh...").color(ACCENT_GOLD)
                };
                ui.label(status_dot);
            });
        });
    }

    fn render_home_tab(&mut self, ui: &mut egui::Ui, snap: &UiSnapshot) {
        let avail_bal = snap.available_wallet_balance();
        let vault_total = snap.total_in_vault();

        // Top Row: 3 side-by-side summary cards — Available Wallet Balance | Safety Vault | Session Earnings
        ui.columns(3, |cols| {
            // 1. Available Wallet Balance (spendable right now)
            egui::Frame::NONE
                .fill(BG_CARD)
                .stroke(Stroke::new(1.0_f32, BORDER_SUBTLE))
                .corner_radius(CornerRadius::same(12))
                .inner_margin(egui::Margin::same(16))
                .show(&mut cols[0], |ui| {
                    ui.set_min_width(ui.available_width());
                    ui.horizontal(|ui| {
                        ui.label(RichText::new("Available Wallet Balance").color(TEXT_MUTED));
                        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                            let eye = if snap.hide_figures { "🙈" } else { "👁" };
                            if ui
                                .small_button(eye)
                                .on_hover_text("Hide or show all money figures")
                                .clicked()
                            {
                                let _ = self
                                    .ctrl
                                    .cmd_tx
                                    .send(UserCommand::SetHideFigures(!snap.hide_figures));
                            }
                        });
                    });
                    ui.label(
                        RichText::new(snap.display_amount(avail_bal))
                            .size(26.0)
                            .strong()
                            .color(ACCENT_GOLD),
                    );
                    ui.add_space(6.0);
                    ui.horizontal(|ui| {
                        ui.label(
                            RichText::new(snap.short_address.clone())
                                .small()
                                .monospace()
                                .color(TEXT_MUTED),
                        );
                        if ui.small_button("Copy").clicked() {
                            ui.ctx().copy_text(snap.short_address.clone());
                        }
                        if ui.small_button("🔑 Words").clicked() {
                            self.show_recovery_modal = !self.show_recovery_modal;
                        }
                    });
                });

            // 2. Safety Vault Balance (protected by 24-hour anti-scam timer)
            egui::Frame::NONE
                .fill(BG_CARD)
                .stroke(Stroke::new(1.0_f32, BORDER_SUBTLE))
                .corner_radius(CornerRadius::same(12))
                .inner_margin(egui::Margin::same(16))
                .show(&mut cols[1], |ui| {
                    ui.set_min_width(ui.available_width());
                    ui.label(RichText::new("🛡 Safety Vault").color(TEXT_MUTED));
                    ui.label(
                        RichText::new(snap.display_amount(vault_total))
                            .size(26.0)
                            .strong()
                            .color(ACCENT_BLUE),
                    );
                    ui.add_space(6.0);
                    ui.horizontal(|ui| {
                        if let Some(earliest) =
                            snap.vault.pending.iter().min_by_key(|w| w.unlock_at_ms)
                        {
                            ui.label(
                                RichText::new(format!(
                                    "⏳ {}",
                                    format_vault_remaining(earliest.unlock_at_ms)
                                ))
                                .small()
                                .color(ACCENT_GOLD),
                            );
                        } else {
                            ui.label(
                                RichText::new("24h anti-scam lock")
                                    .small()
                                    .color(TEXT_MUTED),
                            );
                        }
                        if ui.small_button("Manage ->").clicked() {
                            self.tab = MainTab::SavingsVault;
                        }
                    });
                });

            // 3. Earned / Net Gain This Session
            egui::Frame::NONE
                .fill(BG_CARD)
                .stroke(Stroke::new(1.0_f32, BORDER_SUBTLE))
                .corner_radius(CornerRadius::same(12))
                .inner_margin(egui::Margin::same(16))
                .show(&mut cols[2], |ui| {
                    ui.set_min_width(ui.available_width());
                    ui.label(RichText::new("Earned This Session").color(TEXT_MUTED));
                    let earned_str = if snap.hide_figures {
                        String::from("+∀ •••••• XCR")
                    } else {
                        format!("+{}", snap.session_earned.format_symbolic())
                    };
                    ui.label(
                        RichText::new(earned_str)
                            .size(24.0)
                            .strong()
                            .color(ACCENT_EMERALD),
                    );
                    let elapsed = snap.last_epoch_change.elapsed().as_secs_f32();
                    let progress = (elapsed / 60.0).clamp(0.0, 0.99);
                    let secs_left = 60u64.saturating_sub(elapsed as u64);
                    ui.add_space(6.0);
                    ui.add(
                        egui::ProgressBar::new(if snap.earning_enabled { progress } else { 0.0 })
                            .fill(ACCENT_EMERALD)
                            .text(if snap.earning_enabled {
                                format!("Next payout ~{secs_left}s (#{})", snap.epoch + 1)
                            } else {
                                "Earning paused".to_owned()
                            }),
                    );
                });
        });

        // Compact Hardware Compute Strip (CPU Power Mode + GPU ZK Boost)
        egui::Frame::NONE
            .fill(BG_CARD)
            .stroke(Stroke::new(1.0_f32, BORDER_SUBTLE))
            .corner_radius(CornerRadius::same(10))
            .inner_margin(egui::Margin::symmetric(14, 8))
            .show(ui, |ui| {
                ui.horizontal_wrapped(|ui| {
                    ui.label(RichText::new("CPU Power:").small().color(TEXT_MUTED));
                    for (mode, label) in [
                        (CpuPowerMode::Eco, "🌱 Eco"),
                        (CpuPowerMode::Balanced, "⚖ Balanced"),
                        (CpuPowerMode::Max, "🚀 Max"),
                    ] {
                        if ui
                            .selectable_label(snap.cpu_power_mode == mode, label)
                            .clicked()
                        {
                            let _ = self.ctrl.cmd_tx.send(UserCommand::SetCpuPowerMode(mode));
                        }
                    }
                    ui.label(
                        RichText::new(format!(
                            "{}T · {} H/s · Wt {}",
                            snap.active_threads, snap.hashrate_hps, snap.local_epoch_weight
                        ))
                        .small()
                        .monospace()
                        .color(TEXT_MUTED),
                    );
                    ui.separator();
                    let gpu_btn = if snap.gpu_boost_enabled {
                        "🎮 GPU ZK Boost: ON"
                    } else {
                        "⏸ GPU ZK Boost: OFF"
                    };
                    if ui
                        .selectable_label(snap.gpu_boost_enabled, gpu_btn)
                        .clicked()
                    {
                        let _ = self
                            .ctrl
                            .cmd_tx
                            .send(UserCommand::SetGpuBoostEnabled(!snap.gpu_boost_enabled));
                    }
                    let gpu_stat = if snap.gpu_evals_per_sec > 0 {
                        format!(
                            "{} · ⚡ {} ZK/s",
                            snap.gpu_device_name, snap.gpu_evals_per_sec
                        )
                    } else {
                        format!("{} · 0W idle", snap.gpu_device_name)
                    };
                    ui.label(RichText::new(gpu_stat).small().color(TEXT_MUTED));
                });
            });

        if self.show_recovery_modal
            && let Some((words, _)) = self.ctrl.export_mnemonic_if_unlocked()
        {
            egui::Frame::NONE
                .fill(BG_INPUT)
                .stroke(Stroke::new(1.0_f32, ACCENT_GOLD))
                .corner_radius(CornerRadius::same(10))
                .inner_margin(egui::Margin::same(12))
                .show(ui, |ui| {
                    ui.horizontal(|ui| {
                        ui.label(
                            RichText::new("24 Recovery Words (Keep Private!):")
                                .strong()
                                .color(ACCENT_GOLD),
                        );
                        if ui.small_button("Copy").clicked() {
                            ui.ctx().copy_text(words.clone());
                        }
                        if ui.small_button("Hide").clicked() {
                            self.show_recovery_modal = false;
                        }
                    });
                    ui.label(RichText::new(words).monospace());
                });
        }

        // Balance Growth Chart + Mainnet Launch Banner
        egui::Frame::NONE
            .fill(BG_CARD)
            .stroke(Stroke::new(1.0_f32, BORDER_SUBTLE))
            .corner_radius(CornerRadius::same(12))
            .inner_margin(egui::Margin::same(16))
            .show(ui, |ui| {
                ui.horizontal(|ui| {
                    ui.label(RichText::new("Live Balance & Earnings Activity").strong());
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        ui.label(
                            RichText::new(format!(
                                "🚀 Mainnet Epoch 0 Countdown: {}",
                                format_countdown(snap.seconds_to_mainnet)
                            ))
                            .color(ACCENT_GOLD),
                        );
                    });
                });
                draw_earnings_sparkline(ui, &snap.balance_history, 95.0, snap.hide_figures);
            });

        // Claim Username + Recent Activity Feed
        ui.columns(2, |cols| {
            egui::Frame::NONE
                .fill(BG_CARD)
                .stroke(Stroke::new(1.0_f32, BORDER_SUBTLE))
                .corner_radius(CornerRadius::same(12))
                .inner_margin(egui::Margin::same(14))
                .show(&mut cols[0], |ui| {
                    ui.label(RichText::new("Claim Your Friendly @name.xcr").strong());
                    ui.label(
                        RichText::new(
                            "Let friends pay '@yourname.xcr' instead of copying hex addresses.",
                        )
                        .small()
                        .color(TEXT_MUTED),
                    );
                    ui.horizontal(|ui| {
                        ui.add(
                            egui::TextEdit::singleline(&mut self.handle_input)
                                .hint_text("@alice.xcr")
                                .desired_width(170.0),
                        );
                        if ui.button("Register Username").clicked() {
                            let _ = self.ctrl.cmd_tx.send(UserCommand::ClaimHandle {
                                handle: self.handle_input.clone(),
                            });
                        }
                    });
                });

            egui::Frame::NONE
                .fill(BG_CARD)
                .stroke(Stroke::new(1.0_f32, BORDER_SUBTLE))
                .corner_radius(CornerRadius::same(12))
                .inner_margin(egui::Margin::same(14))
                .show(&mut cols[1], |ui| {
                    ui.label(RichText::new("Recent Activity").strong());
                    if snap.recent_events.is_empty() {
                        ui.label(
                            RichText::new("Waiting for your next 60s reward or transfer...")
                                .small()
                                .color(TEXT_MUTED),
                        );
                    } else {
                        egui::ScrollArea::vertical()
                            .max_height(85.0)
                            .show(ui, |ui| {
                                for ev in snap.recent_events.iter().take(6) {
                                    ui.label(
                                        RichText::new(mask_figures_in_line(ev, snap.hide_figures))
                                            .small(),
                                    );
                                }
                            });
                    }
                });
        });
    }

    fn render_send_receive_tab(&mut self, ui: &mut egui::Ui, snap: &UiSnapshot) {
        ui.columns(2, |cols| {
            // Send Money Card
            egui::Frame::NONE
                .fill(BG_CARD)
                .stroke(Stroke::new(1.0_f32, BORDER_SUBTLE))
                .corner_radius(CornerRadius::same(12))
                .inner_margin(egui::Margin::same(18))
                .show(&mut cols[0], |ui| {
                    ui.label(
                        RichText::new("💸 Send Credits Instantly")
                            .size(18.0)
                            .strong(),
                    );
                    ui.label(
                        RichText::new(
                            "Your first 3 sends every day are 100% FREE (∀ 0.000000 XCR fee).",
                        )
                        .small()
                        .color(ACCENT_EMERALD),
                    );
                    ui.add_space(6.0);
                    ui.label("To (@username.xcr, xcr1_..., or stealth URI):");
                    ui.add(
                        egui::TextEdit::singleline(&mut self.send_to)
                            .hint_text("@alice.xcr or xcr1_...")
                            .desired_width(f32::INFINITY),
                    );
                    ui.label("Amount (XCR):");
                    ui.add(
                        egui::TextEdit::singleline(&mut self.send_amount)
                            .hint_text("5.00")
                            .desired_width(160.0),
                    );
                    ui.label("Note (optional, end-to-end encrypted):");
                    ui.add(
                        egui::TextEdit::singleline(&mut self.send_memo)
                            .hint_text("Dinner / Coffee")
                            .desired_width(f32::INFINITY),
                    );
                    ui.add_space(8.0);
                    if ui
                        .add_sized(
                            [ui.available_width(), 40.0],
                            egui::Button::new(
                                RichText::new("Send Instant Payment")
                                    .strong()
                                    .color(Color32::BLACK),
                            )
                            .fill(ACCENT_EMERALD),
                        )
                        .clicked()
                    {
                        let _ = self.ctrl.cmd_tx.send(UserCommand::SendSimplePayment {
                            to: self.send_to.clone(),
                            amount_str: self.send_amount.clone(),
                            memo: self.send_memo.clone(),
                        });
                    }
                });

            // Receive & QR Card
            egui::Frame::NONE
                .fill(BG_CARD)
                .stroke(Stroke::new(1.0_f32, BORDER_SUBTLE))
                .corner_radius(CornerRadius::same(12))
                .inner_margin(egui::Margin::same(18))
                .show(&mut cols[1], |ui| {
                    ui.label(RichText::new("📲 Receive Credits").size(18.0).strong());
                    let qr_target = if !snap.claimed_handle.is_empty() {
                        format!("xcr:{}", snap.claimed_handle)
                    } else {
                        format!("xcr:{}", snap.short_address)
                    };
                    ui.vertical_centered(|ui| {
                        draw_qr_canvas(ui, &qr_target, 148.0);
                    });
                    ui.add_space(6.0);
                    ui.horizontal(|ui| {
                        if ui.button("📋 Copy My Address").clicked() {
                            ui.ctx().copy_text(snap.short_address.clone());
                        }
                        if ui.button("🕵 Copy Private Stealth Link").clicked() {
                            ui.ctx().copy_text(snap.stealth_uri.clone());
                        }
                    });
                });
        });

        // Gift Links (`RedPacket`) for onboarding friends with zero wallet yet!
        egui::Frame::NONE
            .fill(BG_CARD)
            .stroke(Stroke::new(1.0_f32, BORDER_SUBTLE))
            .corner_radius(CornerRadius::same(12))
            .inner_margin(egui::Margin::same(16))
            .show(ui, |ui| {
                ui.columns(2, |cols| {
                    cols[0].label(RichText::new("🎁 Text a Gift Link to a Friend").strong());
                    cols[0].label(
                        RichText::new("Works even if your friend hasn't installed Credits yet!")
                            .small()
                            .color(TEXT_MUTED),
                    );
                    cols[0].horizontal(|ui| {
                        ui.label("Each:");
                        ui.add(
                            egui::TextEdit::singleline(&mut self.gift_amount).desired_width(70.0),
                        );
                        ui.label("People:");
                        ui.add(egui::DragValue::new(&mut self.gift_claims).range(1..=50));
                        if ui.button("Create Gift Link").clicked() {
                            let _ = self.ctrl.cmd_tx.send(UserCommand::CreateGiftLink {
                                each_amount_str: self.gift_amount.clone(),
                                claims: self.gift_claims,
                            });
                        }
                    });
                    if !snap.latest_gift_link.is_empty() {
                        cols[0].horizontal(|ui| {
                            ui.label(
                                RichText::new(format!(
                                    "{}...",
                                    &snap.latest_gift_link[..26.min(snap.latest_gift_link.len())]
                                ))
                                .monospace()
                                .color(ACCENT_GOLD),
                            );
                            if ui.small_button("📋 Copy Gift Link").clicked() {
                                ui.ctx().copy_text(snap.latest_gift_link.clone());
                            }
                        });
                    }

                    cols[1].label(RichText::new("✨ Redeem a Gift Link or Claim ID").strong());
                    cols[1].label(
                        RichText::new("Paste an xcrdrop1_... link or 64-hex Claim ID:")
                            .small()
                            .color(TEXT_MUTED),
                    );
                    cols[1].horizontal(|ui| {
                        ui.add(
                            egui::TextEdit::singleline(&mut self.redeem_input)
                                .hint_text("xcrdrop1_...")
                                .desired_width(210.0),
                        );
                        if ui
                            .add(egui::Button::new("Claim Now").fill(ACCENT_BLUE))
                            .clicked()
                        {
                            let _ = self.ctrl.cmd_tx.send(UserCommand::RedeemGiftOrClaimable {
                                code_or_id: self.redeem_input.clone(),
                            });
                        }
                    });
                });
            });
    }

    fn render_vault_tab(&mut self, ui: &mut egui::Ui, snap: &UiSnapshot) {
        egui::Frame::NONE
            .fill(BG_CARD)
            .stroke(Stroke::new(1.0_f32, BORDER_SUBTLE))
            .corner_radius(CornerRadius::same(12))
            .inner_margin(egui::Margin::same(20))
            .show(ui, |ui| {
                ui.label(
                    RichText::new("🛡 24-Hour Anti-Scam Safety Vault")
                        .size(20.0)
                        .strong(),
                );
                ui.label(
                    RichText::new(
                        "Money in your Safety Vault has a 24-hour safety timer on withdrawals. If anyone ever steals your laptop or tricks you, click 'Emergency Undo' to cancel the withdrawal and keep 100% of your savings.",
                    )
                    .color(TEXT_MUTED),
                );
                ui.add_space(10.0);
                ui.columns(2, |cols| {
                    cols[0].label(RichText::new("Available Wallet Balance:").color(TEXT_MUTED));
                    cols[0].label(
                        RichText::new(snap.display_amount(snap.available_wallet_balance()))
                            .size(22.0)
                            .strong()
                            .color(ACCENT_GOLD),
                    );
                    cols[1].label(RichText::new("Protected in Safety Vault:").color(TEXT_MUTED));
                    cols[1].label(
                        RichText::new(snap.display_amount(snap.vault.balance))
                            .size(22.0)
                            .strong()
                            .color(ACCENT_BLUE),
                    );
                });
                ui.add_space(10.0);
                ui.horizontal(|ui| {
                    ui.label("Amount (XCR):");
                    ui.add(egui::TextEdit::singleline(&mut self.vault_amount).desired_width(110.0));
                    if ui.button("Move into Safety Vault").clicked() {
                        let _ = self.ctrl.cmd_tx.send(UserCommand::VaultDeposit {
                            amount_str: self.vault_amount.clone(),
                        });
                    }
                    if ui.button("Queue 24h Withdrawal").clicked() {
                        let _ = self.ctrl.cmd_tx.send(UserCommand::VaultQueueWithdraw {
                            amount_str: self.vault_amount.clone(),
                        });
                    }
                });

                if !snap.vault.pending.is_empty() {
                    ui.add_space(12.0);
                    ui.label(RichText::new("Pending 24-Hour Withdrawals:").strong());
                    for w in &snap.vault.pending {
                        let rem_label = format_vault_remaining(w.unlock_at_ms);
                        let prog = vault_unlock_progress(w.unlock_at_ms);
                        egui::Frame::NONE
                            .fill(BG_INPUT)
                            .stroke(Stroke::new(1.0_f32, BORDER_SUBTLE))
                            .corner_radius(CornerRadius::same(10))
                            .inner_margin(egui::Margin::same(12))
                            .show(ui, |ui| {
                                ui.horizontal(|ui| {
                                    ui.label(
                                        RichText::new(format!(
                                            "Withdrawal #{}: {}",
                                            w.id,
                                            snap.display_amount(w.amount)
                                        ))
                                        .strong(),
                                    );
                                    ui.label(
                                        RichText::new(format!("⏳ {rem_label}"))
                                            .strong()
                                            .color(ACCENT_GOLD),
                                    );
                                    ui.with_layout(
                                        egui::Layout::right_to_left(egui::Align::Center),
                                        |ui| {
                                            if ui
                                                .add(
                                                    egui::Button::new(
                                                        RichText::new(
                                                            "🚨 Emergency Undo / Cancel",
                                                        )
                                                        .strong()
                                                        .color(Color32::WHITE),
                                                    )
                                                    .fill(DANGER_RED),
                                                )
                                                .clicked()
                                            {
                                                let _ = self.ctrl.cmd_tx.send(
                                                    UserCommand::VaultEmergencyUndo { id: w.id },
                                                );
                                            }
                                        },
                                    );
                                });
                                ui.add_space(4.0);
                                ui.add(
                                    egui::ProgressBar::new(prog)
                                        .fill(ACCENT_BLUE)
                                        .text(format!(
                                            "⏳ {rem_label} before release to Available Wallet Balance"
                                        )),
                                );
                            });
                    }
                }
            });
    }

    fn render_advanced_tab(&mut self, ui: &mut egui::Ui, snap: &UiSnapshot) {
        egui::Frame::NONE
            .fill(BG_CARD)
            .stroke(Stroke::new(1.0_f32, BORDER_SUBTLE))
            .corner_radius(CornerRadius::same(12))
            .inner_margin(egui::Margin::same(18))
            .show(ui, |ui| {
                ui.label(
                    RichText::new("🕵 Shielded RingCT Privacy Pool (Monero + Zcash Grade)")
                        .size(18.0)
                        .strong(),
                );
                ui.label(
                    RichText::new(
                        "Hides sender, receiver, and amount simultaneously using 1-of-N Curve25519 MLSAG RingCT + Pedersen Commitments with zero trusted setup.",
                    )
                    .color(TEXT_MUTED),
                );
                ui.add_space(8.0);
                ui.horizontal(|ui| {
                    ui.label(
                        RichText::new(format!(
                            "Owned Shielded Balance: {}",
                            snap.display_amount(snap.shielded_balance)
                        ))
                        .strong()
                        .color(ACCENT_EMERALD),
                    );
                    if ui.button("Scan Shielded Pool").clicked() {
                        let _ = self.ctrl.cmd_tx.send(UserCommand::RefreshShieldedScan);
                    }
                    if ui.button("📋 Copy Auditor View-Key (xcrview1_)").clicked() {
                        ui.ctx().copy_text(snap.viewing_key_uri.clone());
                    }
                });
                ui.horizontal(|ui| {
                    ui.label("Shield Amount (XCR):");
                    ui.add(egui::TextEdit::singleline(&mut self.shield_amount).desired_width(100.0));
                    if ui.button("Deposit into Shielded Pool").clicked() {
                        let _ = self.ctrl.cmd_tx.send(UserCommand::ShieldDeposit {
                            amount_str: self.shield_amount.clone(),
                        });
                    }
                });
                ui.add_space(10.0);
                ui.separator();
                ui.horizontal_wrapped(|ui| {
                    ui.label(
                        RichText::new(format!(
                            "🔄 App Updates: v{APP_VERSION} (Build #{APP_BUILD_NUMBER})"
                        ))
                        .strong(),
                    );
                    let mut auto_up = snap.auto_update_enabled;
                    if ui
                        .checkbox(&mut auto_up, "Auto-download signed updates")
                        .changed()
                    {
                        let _ = self
                            .ctrl
                            .cmd_tx
                            .send(UserCommand::SetAutoUpdateEnabled(auto_up));
                    }
                    if ui.button("Check for Updates Now").clicked() {
                        let _ = self.ctrl.cmd_tx.send(UserCommand::CheckForUpdatesNow);
                    }
                    ui.label(
                        RichText::new(format!(
                            "Pinned Release Key: {}...",
                            &OFFICIAL_RELEASE_PUBKEY_HEX[..16]
                        ))
                        .small()
                        .monospace()
                        .color(TEXT_MUTED),
                    );
                });
                ui.add_space(6.0);
                ui.label(
                    RichText::new(format!(
                        "Data Folder: {}   |   Full 64-Hex Pocket ID: {}",
                        self.ctrl.app_dir.display(),
                        snap.full_address_hex
                    ))
                    .small()
                    .monospace()
                    .color(TEXT_MUTED),
                );
            });
    }
}

impl eframe::App for CreditsDesktopApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        ctx.request_repaint_after(Duration::from_secs(1));
        let snap = self.ctrl.state.lock().unwrap().clone();

        egui::CentralPanel::default().show(ctx, |ui| {
            if !snap.initialized || !snap.onboarding_done {
                self.render_wizard(ui, &snap);
            } else if snap.locked {
                self.render_top_bar(ui, &snap);
                ui.add_space(40.0);
                ui.vertical_centered(|ui| {
                    ui.label(RichText::new("🔒 Wallet Locked").size(26.0).strong());
                    ui.label(
                        RichText::new(
                            "Your background node continues earning safely while your spending key is locked.",
                        )
                        .color(TEXT_MUTED),
                    );
                    ui.add_space(12.0);
                    ui.add(
                        egui::TextEdit::singleline(&mut self.unlock_password)
                            .password(true)
                            .hint_text("Enter wallet password...")
                            .desired_width(260.0),
                    );
                    ui.add_space(8.0);
                    if ui
                        .add_sized(
                            [200.0, 38.0],
                            egui::Button::new(
                                RichText::new("Unlock Wallet")
                                    .strong()
                                    .color(Color32::BLACK),
                            )
                            .fill(ACCENT_EMERALD),
                        )
                        .clicked()
                    {
                        let _ = self.ctrl.cmd_tx.send(UserCommand::UnlockWallet {
                            password: self.unlock_password.clone(),
                        });
                        self.unlock_password.clear();
                    }
                });
            } else {
                self.render_top_bar(ui, &snap);
                ui.add_space(6.0);

                ui.horizontal(|ui| {
                    ui.selectable_value(&mut self.tab, MainTab::HomeAndEarnings, "🏠 Home & Earnings");
                    ui.selectable_value(&mut self.tab, MainTab::SendAndReceive, "💸 Send & Receive");
                    ui.selectable_value(&mut self.tab, MainTab::SavingsVault, "🛡 Safety Vault");
                    ui.selectable_value(&mut self.tab, MainTab::AdvancedPrivacy, "⚙ Advanced");
                });
                ui.separator();

                match self.tab {
                    MainTab::HomeAndEarnings => self.render_home_tab(ui, &snap),
                    MainTab::SendAndReceive => self.render_send_receive_tab(ui, &snap),
                    MainTab::SavingsVault => self.render_vault_tab(ui, &snap),
                    MainTab::AdvancedPrivacy => self.render_advanced_tab(ui, &snap),
                }
            }

            if let Some((ref msg, ok, ts)) = snap.toast
                && ts.elapsed() < Duration::from_secs(6)
            {
                ui.with_layout(egui::Layout::bottom_up(egui::Align::Center), |ui| {
                    egui::Frame::NONE
                        .fill(if ok {
                            Color32::from_rgb(13, 68, 52)
                        } else {
                            Color32::from_rgb(90, 24, 30)
                        })
                        .stroke(Stroke::new(
                            1.0_f32,
                            if ok { ACCENT_EMERALD } else { DANGER_RED },
                        ))
                        .corner_radius(CornerRadius::same(8))
                        .inner_margin(egui::Margin::symmetric(16, 8))
                        .show(ui, |ui| {
                            ui.label(
                                RichText::new(mask_figures_in_line(msg, snap.hide_figures))
                                    .strong()
                                    .color(Color32::WHITE),
                            );
                        });
                });
            }
        });
    }

    fn on_exit(&mut self, _gl: Option<&eframe::glow::Context>) {
        let _ = self.ctrl.cmd_tx.send(UserCommand::ShutdownAll);
    }
}

fn main() -> eframe::Result<()> {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_title("Credits (∀ / XCR) — Wallet & Automatic Node")
            .with_inner_size(Vec2::new(920.0, 620.0))
            .with_min_inner_size(Vec2::new(760.0, 520.0))
            .with_icon(build_app_icon()),
        ..Default::default()
    };
    eframe::run_native(
        "Credits (XCR)",
        options,
        Box::new(|cc| Ok(Box::new(CreditsDesktopApp::new(cc)))),
    )
}
