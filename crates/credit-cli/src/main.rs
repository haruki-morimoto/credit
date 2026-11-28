use std::env;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::process;
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use credit_cli::audit_bench::{run_adversarial_attack_suite, run_tps_benchmark};
use credit_cli::{
    cli_add_subscription, cli_babel_asset_transfer, cli_bridged_payment,
    cli_build_btc_p2wsh_swap_address, cli_build_inheritance_script, cli_cancel_subscription,
    cli_check_cancel, cli_check_cash, cli_check_issue, cli_claim_bearer_voucher,
    cli_cold_broadcast, cli_cold_prepare, cli_cold_sign_offline, cli_combine_shamir_backup,
    cli_create_bearer_voucher, cli_create_campaign, cli_create_invoice_qr, cli_decode_bolt11,
    cli_decrypt_wallet_file, cli_delegate_drep, cli_dex_cancel_order, cli_dex_orderbook,
    cli_dex_place_order, cli_encrypt_wallet_file, cli_execute_atomic_batch,
    cli_export_backup_words, cli_export_signed_raw_lane_hex, cli_export_watch_pubkey_hex,
    cli_finalize_campaign, cli_frost_aggregate_cold, cli_frost_commit_nonce,
    cli_frost_sign_partial, cli_frost_split, cli_generate_bolt11_swap_invoice,
    cli_generate_htlc_secret, cli_get_balance, cli_get_telemetry, cli_htlc_claim, cli_htlc_list,
    cli_htlc_lock, cli_htlc_refund, cli_init_wallet, cli_inspect_query, cli_issue_attestation,
    cli_issue_session_key, cli_list_artifacts_and_attestations, cli_list_governance,
    cli_list_native_assets, cli_list_subscriptions, cli_list_swap_offers, cli_lock_script_vault,
    cli_lock_xcr_to_bolt11, cli_mint_artifact, cli_mint_native_asset, cli_parallel_lane_pay,
    cli_paychan_close, cli_paychan_list, cli_paychan_open, cli_paychan_tick_offline,
    cli_pledge_campaign, cli_post_swap_offer, cli_propose_governance, cli_read_activity_history,
    cli_recover_from_words, cli_register_handle, cli_resolve_onchain_handle,
    cli_revoke_attestation, cli_run_due_subscriptions, cli_scan_and_claim_stealth_v2,
    cli_send_bulletproof_payment_with_memo, cli_send_multi_payout, cli_session_revoke,
    cli_session_spend, cli_set_deposit_shield, cli_shutdown_daemon, cli_spend_inheritance_vault,
    cli_split_bill_invoices, cli_split_shamir_backup, cli_stealth_address, cli_supply_audit,
    cli_transfer_artifact, cli_transfer_handle, cli_transfer_native_asset,
    cli_verify_light_balance, cli_vote_governance, set_cli_wallet_password,
};
use credit_crypto::domain_hash;
use credit_net::NodeRpcResponse;
use credit_sdk::{LocalHandleBook, parse_decimal_xcr, resolve_remote_handle};
use credit_types::Amount;

const DEFAULT_TESTNET_NODES: &[&str] = &[
    "162.243.166.102:9501",
    "167.71.138.246:9501",
    "139.59.229.45:9501",
];

fn main() {
    let args: Vec<String> = env::args().skip(1).collect();
    let Some(cmd) = args.first().map(String::as_str) else {
        print_usage();
        process::exit(2);
    };

    let mut node_addr: SocketAddr = "127.0.0.1:9400".parse().unwrap();
    let mut node_list: Vec<SocketAddr> = Vec::new();
    let mut use_testnet = false;
    let mut wallet_path = PathBuf::from("./credit.wallet");
    let mut bundle_path = PathBuf::from("./cold_tx.bundle");
    let mut amount_override: Option<Amount> = None;
    let mut chips: u64 = 100;
    let mut recipient = String::from("merchant-default");
    let mut memo = String::new();
    let mut invoice_id = String::new();
    let mut voucher_uri = String::new();
    let mut words_phrase = String::new();
    let mut handle_arg = String::new();
    let mut password_arg: Option<String> = None;
    let mut query_arg = String::new();
    let mut threshold: u8 = 2;
    let mut total_shares: u8 = 3;
    let mut shares_list = String::new();
    let mut pubkey_hex = String::new();
    let mut unsigned_uri = String::new();
    let mut signed_uri = String::new();
    let mut batch_spec = String::new();
    let mut split_ways: u64 = 2;
    let mut sub_label = String::from("Subscription");
    let mut sub_interval: u64 = 2_592_000;
    let mut sub_id: u64 = 1;
    let mut bench_txs: usize = 300;
    let mut bench_streams: usize = 24;
    let mut frost_share_uri = String::new();
    let mut frost_nonce_sec_uri = String::new();
    let mut frost_commits_csv = String::new();
    let mut frost_partials_csv = String::new();
    let mut hashlock_hex = String::new();
    let mut preimage_hex = String::new();
    let mut contract_id_hex = String::new();
    let mut timelock_secs: u64 = 3_600;
    let mut check_uri = String::new();
    let mut counter_asset = String::from("BTC-LN");
    let mut counter_amount = String::from("0.00100000");
    let mut script_uri = String::new();
    let mut session_key_uri = String::new();
    let mut sponsor_wallet: Option<PathBuf> = None;
    let mut asset_ticker = String::from("VIP2027");
    let mut asset_supply: u64 = 1_000;
    let mut is_heir_role = false;
    let mut dex_sell = true;
    let mut dex_ioc = false;
    let mut price_bits: u64 = 10_000;
    let mut babel_fee_units: u64 = 1;
    let mut out_asset_hex = String::new();
    let mut min_out_units: u64 = 1;
    let mut lane_id: u32 = 1;
    let mut collection_name = String::from("CREDITS-GENESIS");
    let mut schema_name = String::from("ISO-AUDIT-V1");
    let mut param_key = String::from("min_relay_fee_bits");
    let mut param_value: u64 = 500;
    let mut vote_choice = String::from("yes");
    let mut strict_shield = false;
    let mut allowlist_csv = String::new();

    let mut i = 1usize;
    while i < args.len() {
        match args[i].as_str() {
            "--testnet" => {
                use_testnet = true;
                node_addr = DEFAULT_TESTNET_NODES[0].parse().unwrap();
                i += 1;
            }
            "--node" if i + 1 < args.len() => {
                node_addr = args[i + 1].parse().unwrap_or_else(|e| {
                    eprintln!("invalid --node socket address: {e}");
                    process::exit(2);
                });
                i += 2;
            }
            "--nodes" if i + 1 < args.len() => {
                for item in args[i + 1]
                    .split(',')
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
                {
                    let parsed: SocketAddr = item.parse().unwrap_or_else(|e| {
                        eprintln!("invalid address '{item}' in --nodes: {e}");
                        process::exit(2);
                    });
                    node_list.push(parsed);
                }
                i += 2;
            }
            "--wallet" if i + 1 < args.len() => {
                wallet_path = PathBuf::from(&args[i + 1]);
                i += 2;
            }
            "--bundle" if i + 1 < args.len() => {
                bundle_path = PathBuf::from(&args[i + 1]);
                i += 2;
            }
            "--amount" if i + 1 < args.len() => {
                amount_override = Some(parse_decimal_xcr(&args[i + 1]).unwrap_or_else(|| {
                    eprintln!("invalid decimal XCR --amount '{}'", args[i + 1]);
                    process::exit(2);
                }));
                i += 2;
            }
            "--chips" if i + 1 < args.len() => {
                chips = args[i + 1].parse().unwrap_or_else(|e| {
                    eprintln!("invalid --chips integer: {e}");
                    process::exit(2);
                });
                i += 2;
            }
            "--to" if i + 1 < args.len() => {
                recipient = args[i + 1].clone();
                i += 2;
            }
            "--memo" if i + 1 < args.len() => {
                memo = args[i + 1].clone();
                i += 2;
            }
            "--invoice" if i + 1 < args.len() => {
                invoice_id = args[i + 1].clone();
                i += 2;
            }
            "--voucher" if i + 1 < args.len() => {
                voucher_uri = args[i + 1].clone();
                i += 2;
            }
            "--words" if i + 1 < args.len() => {
                words_phrase = args[i + 1].clone();
                i += 2;
            }
            "--handle" if i + 1 < args.len() => {
                handle_arg = args[i + 1].clone();
                i += 2;
            }
            "--password" if i + 1 < args.len() => {
                password_arg = Some(args[i + 1].clone());
                set_cli_wallet_password(Some(args[i + 1].clone()));
                i += 2;
            }
            "--query" if i + 1 < args.len() => {
                query_arg = args[i + 1].clone();
                i += 2;
            }
            "--threshold" if i + 1 < args.len() => {
                threshold = args[i + 1].parse().unwrap_or(2);
                i += 2;
            }
            "--shares" if i + 1 < args.len() => {
                total_shares = args[i + 1].parse().unwrap_or(3);
                i += 2;
            }
            "--shares-list" if i + 1 < args.len() => {
                shares_list = args[i + 1].clone();
                i += 2;
            }
            "--pubkey" if i + 1 < args.len() => {
                pubkey_hex = args[i + 1].clone();
                i += 2;
            }
            "--unsigned" if i + 1 < args.len() => {
                unsigned_uri = args[i + 1].clone();
                i += 2;
            }
            "--signed" if i + 1 < args.len() => {
                signed_uri = args[i + 1].clone();
                i += 2;
            }
            "--batch" if i + 1 < args.len() => {
                batch_spec = args[i + 1].clone();
                i += 2;
            }
            "--ways" if i + 1 < args.len() => {
                split_ways = args[i + 1].parse().unwrap_or(2);
                i += 2;
            }
            "--label" if i + 1 < args.len() => {
                sub_label = args[i + 1].clone();
                i += 2;
            }
            "--interval-secs" if i + 1 < args.len() => {
                sub_interval = args[i + 1].parse().unwrap_or(2_592_000);
                i += 2;
            }
            "--id" if i + 1 < args.len() => {
                sub_id = args[i + 1].parse().unwrap_or(1);
                i += 2;
            }
            "--txs" if i + 1 < args.len() => {
                bench_txs = args[i + 1].parse().unwrap_or(300);
                i += 2;
            }
            "--streams" if i + 1 < args.len() => {
                bench_streams = args[i + 1].parse().unwrap_or(24);
                i += 2;
            }
            "--frost-share" if i + 1 < args.len() => {
                frost_share_uri = args[i + 1].clone();
                i += 2;
            }
            "--nonce-secret" if i + 1 < args.len() => {
                frost_nonce_sec_uri = args[i + 1].clone();
                i += 2;
            }
            "--commits" if i + 1 < args.len() => {
                frost_commits_csv = args[i + 1].clone();
                i += 2;
            }
            "--partials" if i + 1 < args.len() => {
                frost_partials_csv = args[i + 1].clone();
                i += 2;
            }
            "--hashlock" if i + 1 < args.len() => {
                hashlock_hex = args[i + 1].clone();
                i += 2;
            }
            "--preimage" if i + 1 < args.len() => {
                preimage_hex = args[i + 1].clone();
                i += 2;
            }
            "--escrow-id" | "--channel-id" if i + 1 < args.len() => {
                contract_id_hex = args[i + 1].clone();
                i += 2;
            }
            "--vault-id" | "--asset-id" | "--campaign-id" | "--order-id" | "--artifact-id"
            | "--attestation-id" | "--proposal-id"
                if i + 1 < args.len() =>
            {
                contract_id_hex = args[i + 1].clone();
                i += 2;
            }
            "--script" if i + 1 < args.len() => {
                script_uri = args[i + 1].clone();
                i += 2;
            }
            "--session-key" if i + 1 < args.len() => {
                session_key_uri = args[i + 1].clone();
                i += 2;
            }
            "--sponsor-wallet" if i + 1 < args.len() => {
                sponsor_wallet = Some(PathBuf::from(&args[i + 1]));
                i += 2;
            }
            "--ticker" if i + 1 < args.len() => {
                asset_ticker = args[i + 1].clone();
                i += 2;
            }
            "--supply" | "--units" if i + 1 < args.len() => {
                asset_supply = args[i + 1].parse().unwrap_or(1_000);
                i += 2;
            }
            "--heir" => {
                is_heir_role = true;
                i += 1;
            }
            "--timelock-secs" if i + 1 < args.len() => {
                timelock_secs = args[i + 1].parse().unwrap_or(3_600);
                i += 2;
            }
            "--check" if i + 1 < args.len() => {
                check_uri = args[i + 1].clone();
                i += 2;
            }
            "--asset" if i + 1 < args.len() => {
                counter_asset = args[i + 1].clone();
                i += 2;
            }
            "--counter-amount" if i + 1 < args.len() => {
                counter_amount = args[i + 1].clone();
                i += 2;
            }
            "--sell" => {
                dex_sell = true;
                i += 1;
            }
            "--buy" => {
                dex_sell = false;
                i += 1;
            }
            "--ioc" => {
                dex_ioc = true;
                i += 1;
            }
            "--price-bits" if i + 1 < args.len() => {
                price_bits = args[i + 1].parse().unwrap_or(10_000);
                i += 2;
            }
            "--babel-fee-units" if i + 1 < args.len() => {
                babel_fee_units = args[i + 1].parse().unwrap_or(1);
                i += 2;
            }
            "--out-asset" if i + 1 < args.len() => {
                out_asset_hex = args[i + 1].clone();
                i += 2;
            }
            "--min-units" if i + 1 < args.len() => {
                min_out_units = args[i + 1].parse().unwrap_or(1);
                i += 2;
            }
            "--lane" if i + 1 < args.len() => {
                lane_id = args[i + 1].parse().unwrap_or(1);
                i += 2;
            }
            "--collection" if i + 1 < args.len() => {
                collection_name = args[i + 1].clone();
                i += 2;
            }
            "--schema" if i + 1 < args.len() => {
                schema_name = args[i + 1].clone();
                i += 2;
            }
            "--param" if i + 1 < args.len() => {
                param_key = args[i + 1].clone();
                i += 2;
            }
            "--value" if i + 1 < args.len() => {
                param_value = args[i + 1].parse().unwrap_or(500);
                i += 2;
            }
            "--choice" if i + 1 < args.len() => {
                vote_choice = args[i + 1].clone();
                i += 2;
            }
            "--strict" => {
                strict_shield = true;
                i += 1;
            }
            "--allowlist" if i + 1 < args.len() => {
                allowlist_csv = args[i + 1].clone();
                i += 2;
            }
            other => {
                eprintln!("unknown option: {other}");
                print_usage();
                process::exit(2);
            }
        }
    }

    if node_list.is_empty() {
        if use_testnet {
            node_list = DEFAULT_TESTNET_NODES
                .iter()
                .map(|s| s.parse().unwrap())
                .collect();
        } else {
            node_list.push(node_addr);
        }
    }

    let resolved_amount = || -> Amount {
        amount_override
            .unwrap_or_else(|| Amount::from_chips(chips).unwrap_or_else(|| fail("amount overflow")))
    };
    let now_unix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    match cmd {
        "status" => match cli_get_telemetry(node_addr) {
            Ok(NodeRpcResponse::NetworkTelemetry {
                epoch,
                circulating_supply,
                total_burned,
                finalized_tx_count,
                state_root,
                validator_address,
                connected_peers,
                active_miners,
            }) => {
                println!("Node              : {node_addr} ({validator_address})");
                println!("Epoch             : {}", epoch.0);
                println!(
                    "Circulating Supply: {}",
                    circulating_supply.format_symbolic()
                );
                println!("Total Burned (15%): {}", total_burned.format_symbolic());
                println!("Finalized Txs     : {finalized_tx_count}");
                println!(
                    "Active Mesh Nodes : {active_miners} PoNC miners ({connected_peers} direct P2P peers)"
                );
                println!("WAL State Root    : {state_root}");
            }
            Ok(NodeRpcResponse::Status {
                epoch,
                circulating_supply,
                total_burned,
                finalized_tx_count,
                state_root,
                validator_address,
            }) => {
                println!("Node              : {node_addr} ({validator_address})");
                println!("Epoch             : {}", epoch.0);
                println!(
                    "Circulating Supply: {}",
                    circulating_supply.format_symbolic()
                );
                println!("Total Burned (15%): {}", total_burned.format_symbolic());
                println!("Finalized Txs     : {finalized_tx_count}");
                println!("WAL State Root    : {state_root}");
            }
            Ok(other) => println!("Unexpected reply: {other:?}"),
            Err(e) => fail(&format!("status RPC failed: {e}")),
        },
        "init-wallet" => {
            let nanos = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos();
            let seed = domain_hash(
                "XCR.CLI.INIT_SEED.V1",
                &[
                    &nanos.to_le_bytes(),
                    wallet_path.to_string_lossy().as_bytes(),
                ],
            )
            .0;
            match cli_init_wallet(&wallet_path, seed, node_addr) {
                Ok((addr, NodeRpcResponse::PocketInfo { balance, nonce, .. })) => {
                    println!("Initialized wallet : {}", wallet_path.display());
                    println!("Pocket Address     : {addr}");
                    println!("Balance            : {}", balance.format_symbolic());
                    println!("Nonce              : {nonce}");
                    if let Ok((_, card)) = cli_export_backup_words(&wallet_path) {
                        println!("\n24-Word Paper Recovery Sheet (store offline):");
                        print!("{card}");
                    }
                    if let Some(ref pw) = password_arg {
                        let mut salt = [0u8; 16];
                        salt.copy_from_slice(&seed[..16]);
                        if let Err(e) = cli_encrypt_wallet_file(&wallet_path, None, pw, salt) {
                            fail(&format!("failed encrypting wallet with --password: {e}"));
                        }
                        println!("\nEncrypted wallet on disk with XCRENC01 memory-hard KDF.");
                    }
                }
                Ok((_, other)) => println!("Unexpected reply: {other:?}"),
                Err(e) => fail(&format!("init-wallet failed: {e}")),
            }
        }
        "split-backup" => {
            let nanos = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos();
            let ent = domain_hash("XCR.CLI.SHAMIR_ENT.V1", &[&nanos.to_le_bytes()]).0;
            match cli_split_shamir_backup(&wallet_path, threshold, total_shares, ent) {
                Ok(shares) => {
                    for sh in shares {
                        println!("{}\n", sh.format_guardian_card());
                    }
                }
                Err(e) => fail(&format!("split-backup failed: {e}")),
            }
        }
        "combine-backup" => {
            let uris: Vec<&str> = shares_list
                .split(',')
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .collect();
            if uris.is_empty() {
                fail("pass `--shares-list \"xcrshare1_...,xcrshare1_...\"`");
            }
            match cli_combine_shamir_backup(&wallet_path, &uris) {
                Ok((pocket_addr, stealth_uri)) => {
                    println!(
                        "Reconstructed wallet from {} Guardian Shares -> {}",
                        uris.len(),
                        wallet_path.display()
                    );
                    println!("Pocket Address : {pocket_addr}");
                    println!("Stealth URI    : {stealth_uri}");
                }
                Err(e) => fail(&format!("combine-backup failed: {e}")),
            }
        }
        "export-pubkey" => match cli_export_watch_pubkey_hex(&wallet_path) {
            Ok((addr, hex66)) => {
                println!("Pocket Address      : {addr}");
                println!("Watch-Only Pubkey   : {hex66}");
            }
            Err(e) => fail(&format!("export-pubkey failed: {e}")),
        },
        "cold-prepare" => {
            if pubkey_hex.trim().is_empty() {
                fail("pass `--pubkey <66-HEX>` from `export-pubkey`");
            }
            let nanos = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos();
            let ent = domain_hash("XCR.CLI.COLD_ENT.V1", &[&nanos.to_le_bytes()]).0;
            match cli_cold_prepare(
                &pubkey_hex,
                &recipient,
                resolved_amount(),
                Amount::from_bits(500),
                &memo,
                ent,
                &bundle_path,
                node_addr,
            ) {
                Ok((u_uri, qr)) => {
                    println!(
                        "Saved public Bulletproof bundle : {}",
                        bundle_path.display()
                    );
                    println!("Unsigned Air-Gap Payload        : {u_uri}\n");
                    println!("{qr}");
                }
                Err(e) => fail(&format!("cold-prepare failed: {e}")),
            }
        }
        "cold-sign" => {
            if unsigned_uri.trim().is_empty() {
                fail("pass `--unsigned \"xcrunsigned1_...\"`");
            }
            match cli_cold_sign_offline(&wallet_path, &unsigned_uri) {
                Ok((u, s_uri, qr)) => {
                    println!("=== AIR-GAPPED OFFLINE SIGNER VERIFICATION (0 NETWORK SOCKETS) ===");
                    println!("From Pocket  : {}", u.from);
                    println!("To Stealth   : {}", u.to_stealth);
                    println!("Amount       : {}", u.amount.format_symbolic());
                    println!("Fee          : {}", u.fee.format_symbolic());
                    println!("Nonce        : {}", u.nonce);
                    println!("Signed Reply : {s_uri}\n");
                    println!("{qr}");
                }
                Err(e) => fail(&format!("cold-sign failed: {e}")),
            }
        }
        "cold-broadcast" => {
            if signed_uri.trim().is_empty() {
                fail("pass `--signed \"xcrsigned1_...\"`");
            }
            match cli_cold_broadcast(&bundle_path, &signed_uri, node_addr) {
                Ok(NodeRpcResponse::FastPayReceipt {
                    accepted,
                    tx_id,
                    finality_latency_ms,
                    new_state_root,
                    message,
                    ..
                }) => {
                    println!("Air-Gapped Tx Accepted : {accepted} ({message})");
                    println!("Tx ID                  : {tx_id}");
                    println!("1-RTT WAN Latency      : {finality_latency_ms} ms");
                    println!("New WAL State Root     : {new_state_root}");
                }
                Ok(other) => println!("Unexpected reply: {other:?}"),
                Err(e) => fail(&format!("cold-broadcast failed: {e}")),
            }
        }
        "pay-multi" => {
            if batch_spec.trim().is_empty() {
                fail("pass `--batch \"dest1:4.50:Coffee,dest2:0.50:Tip\"`");
            }
            match cli_send_multi_payout(&wallet_path, &batch_spec, node_addr) {
                Ok(legs) => {
                    println!("Batch Settled ({} recipients):", legs.len());
                    for (idx, (dest, amt, tid, rtt)) in legs.iter().enumerate() {
                        println!(
                            "  {:>2}. {:<22} | {:<16} | {rtt:>3} ms | tx={tid}",
                            idx + 1,
                            dest,
                            amt.format_symbolic()
                        );
                    }
                }
                Err(e) => fail(&format!("pay-multi failed: {e}")),
            }
        }
        "split-bill" => {
            match cli_split_bill_invoices(&wallet_path, resolved_amount(), split_ways, &memo) {
                Ok(items) => {
                    println!(
                        "Split {} across {split_ways} shares:",
                        resolved_amount().format_symbolic()
                    );
                    for (idx, amt, uri) in items {
                        println!("  Share #{idx}: {} -> {uri}", amt.format_symbolic());
                    }
                }
                Err(e) => fail(&format!("split-bill failed: {e}")),
            }
        }
        "sub-add" => match cli_add_subscription(
            &wallet_path,
            &sub_label,
            &recipient,
            resolved_amount(),
            sub_interval,
            now_unix,
        ) {
            Ok(id) => println!(
                "Created pull-free subscription #{id}: `{sub_label}` ({} every {sub_interval}s -> `{recipient}`). Cancel anytime with `sub-cancel --id {id}`.",
                resolved_amount().format_symbolic()
            ),
            Err(e) => fail(&format!("sub-add failed: {e}")),
        },
        "sub-list" => match cli_list_subscriptions(&wallet_path) {
            Ok(list) => {
                println!("Pull-Free Subscriptions ({} mandates):", list.len());
                for m in list {
                    let st = if m.active { "ACTIVE" } else { "CANCELLED" };
                    println!(
                        "  #{:<2} [{:<9}] {:<18} | {} / {}s | paid={} cycles | to={}",
                        m.id,
                        st,
                        m.label,
                        m.amount.format_symbolic(),
                        m.interval_secs,
                        m.completed_cycles,
                        m.recipient
                    );
                }
            }
            Err(e) => fail(&format!("sub-list failed: {e}")),
        },
        "sub-cancel" => match cli_cancel_subscription(&wallet_path, sub_id) {
            Ok(true) => println!(
                "Cancelled subscription #{sub_id} locally — merchant has zero pull authority."
            ),
            Ok(false) => fail(&format!("subscription #{sub_id} not found")),
            Err(e) => fail(&format!("sub-cancel failed: {e}")),
        },
        "sub-run" => match cli_run_due_subscriptions(&wallet_path, now_unix, node_addr) {
            Ok(paid) => {
                println!("Executed {} due subscription payment(s):", paid.len());
                for (id, lbl, amt, tid) in paid {
                    println!(
                        "  [PAID SUB #{id}] {lbl} -> {} (tx={tid})",
                        amt.format_symbolic()
                    );
                }
            }
            Err(e) => fail(&format!("sub-run failed: {e}")),
        },
        "encrypt-wallet" => {
            let Some(ref pw) = password_arg else {
                fail("pass `--password <PASSPHRASE>`");
            };
            let nanos = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos();
            let h = domain_hash("XCR.CLI.ENC_SALT.V1", &[&nanos.to_le_bytes()]).0;
            let mut salt = [0u8; 16];
            salt.copy_from_slice(&h[..16]);
            match cli_encrypt_wallet_file(&wallet_path, None, pw, salt)
                .or_else(|_| cli_encrypt_wallet_file(&wallet_path, Some(pw.as_str()), pw, salt))
            {
                Ok(()) => println!(
                    "Encrypted wallet {} -> 80-byte XCRENC01 memory-hard AEAD format.",
                    wallet_path.display()
                ),
                Err(e) => fail(&format!("encrypt-wallet failed: {e}")),
            }
        }
        "decrypt-wallet" => {
            let Some(ref pw) = password_arg else {
                fail("pass `--password <PASSPHRASE>`");
            };
            match cli_decrypt_wallet_file(&wallet_path, pw) {
                Ok(()) => println!(
                    "Decrypted wallet {} -> XCRSEED1 format.",
                    wallet_path.display()
                ),
                Err(e) => fail(&format!("decrypt-wallet failed: {e}")),
            }
        }
        "history" => match cli_read_activity_history(&wallet_path) {
            Ok(entries) => {
                println!(
                    "Encrypted Activity History for {} ({} entries):",
                    wallet_path.display(),
                    entries.len()
                );
                for (idx, e) in entries.iter().enumerate() {
                    let note = if e.memo.is_empty() {
                        String::new()
                    } else {
                        format!(" | \"{}\"", e.memo)
                    };
                    println!(
                        "  {:>2}. [{:<11}] {:<18} | ref={}{}",
                        idx + 1,
                        e.kind,
                        e.amount.format_symbolic(),
                        e.reference,
                        note
                    );
                }
            }
            Err(e) => fail(&format!("history read failed: {e}")),
        },
        "inspect" => {
            if query_arg.trim().is_empty() {
                fail("pass `--query <xcr1_... | tx_id_hex>`");
            }
            match cli_inspect_query(node_addr, &query_arg) {
                Ok((
                    NodeRpcResponse::InspectResult {
                        kind: 1,
                        target_hex,
                        balance,
                        nonce,
                        epoch,
                        authenticated_root,
                        inclusion_proof_bytes,
                        ..
                    },
                    merkle_ok,
                )) => {
                    println!("Inspect Type       : Pocket Account ({target_hex})");
                    println!("Balance            : {}", balance.format_symbolic());
                    println!("Nonce              : {nonce} (Epoch {})", epoch.0);
                    println!(
                        "Merkle Inclusion   : verified={merkle_ok} ({} bytes, root {authenticated_root})",
                        inclusion_proof_bytes.len()
                    );
                }
                Ok((
                    NodeRpcResponse::InspectResult {
                        kind: 2,
                        target_hex,
                        epoch,
                        authenticated_root,
                        ..
                    },
                    _,
                )) => {
                    println!("Inspect Type       : 1-RTT Finalized Transaction");
                    println!("Tx ID              : {target_hex}");
                    println!("Node Epoch         : {}", epoch.0);
                    println!("WAL State Root     : {authenticated_root}");
                }
                Ok(_) => fail(&format!("`{query_arg}` not found on {node_addr}")),
                Err(e) => fail(&format!("inspect RPC failed: {e}")),
            }
        }
        "watch" => {
            println!(
                "Watching 1-byte stealth view tags on {node_addr} for {} (Ctrl+C to stop)...",
                wallet_path.display()
            );
            loop {
                if let Ok((_, matches)) =
                    cli_scan_and_claim_stealth_v2(&wallet_path, node_addr, true)
                {
                    for (ot_addr, amt, claimed, new_bal, dec_memo) in matches {
                        if claimed {
                            let m = dec_memo
                                .map(|s| format!(" | Memo: \"{s}\""))
                                .unwrap_or_default();
                            println!(
                                "  [AUTO-SWEPT] {ot_addr} -> +{} (Pocket: {}){m}",
                                amt.format_symbolic(),
                                new_bal.format_symbolic()
                            );
                        }
                    }
                }
                thread::sleep(Duration::from_millis(2_500));
            }
        }
        "balance" => match cli_get_balance(&wallet_path, node_addr) {
            Ok((
                addr,
                NodeRpcResponse::PocketInfo {
                    found,
                    balance,
                    nonce,
                    daily_limit,
                },
            )) => {
                println!("Pocket Address : {addr} (registered={found})");
                println!("Balance        : {}", balance.format_symbolic());
                println!("Daily Tap Cap  : {}", daily_limit.format_symbolic());
                println!("Current Nonce  : {nonce}");
            }
            Ok((_, other)) => println!("Unexpected reply: {other:?}"),
            Err(e) => fail(&format!("balance query failed: {e}")),
        },
        "pay" => {
            let amount = resolved_amount();
            let fee = Amount::from_bits(500);
            match cli_send_bulletproof_payment_with_memo(
                &wallet_path,
                recipient.as_bytes(),
                amount,
                fee,
                &memo,
                node_addr,
            ) {
                Ok(NodeRpcResponse::FastPayReceipt {
                    accepted,
                    tx_id,
                    finality_latency_ms,
                    fee_worker,
                    fee_burned,
                    new_state_root,
                    message,
                }) => {
                    println!("Accepted          : {accepted} ({message})");
                    println!("Tx ID             : {tx_id}");
                    println!("1-RTT WAN Latency : {finality_latency_ms} ms (672B Bulletproof)");
                    println!("Fee Split         : worker={fee_worker} | burned={fee_burned}");
                    println!("New WAL State Root: {new_state_root}");
                    if !accepted {
                        process::exit(1);
                    }
                }
                Ok(other) => println!("Unexpected reply: {other:?}"),
                Err(e) => fail(&format!("pay failed: {e}")),
            }
        }
        "invoice" => {
            let amount = resolved_amount();
            match cli_create_invoice_qr(&wallet_path, amount, &invoice_id, &memo) {
                Ok((uri, qr)) => {
                    println!("Payment Request URI: {uri}");
                    println!("Amount             : {}", amount.format_symbolic());
                    if !invoice_id.is_empty() {
                        println!("Invoice ID         : {invoice_id}");
                    }
                    if !memo.is_empty() {
                        println!("Memo               : {memo}");
                    }
                    println!("\n{qr}");
                }
                Err(e) => fail(&format!("invoice QR generation failed: {e}")),
            }
        }
        "voucher-create" => {
            let amount = resolved_amount();
            let fee = Amount::from_bits(500);
            let nanos = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos();
            let ent = domain_hash("XCR.CLI.VOUCHER_ENT.V1", &[&nanos.to_le_bytes()]).0;
            match cli_create_bearer_voucher(&wallet_path, ent, amount, fee, &memo, node_addr) {
                Ok((
                    uri,
                    qr,
                    NodeRpcResponse::FastPayReceipt {
                        accepted: true,
                        tx_id,
                        finality_latency_ms,
                        ..
                    },
                )) => {
                    println!("Bearer Cash Voucher Locked ({finality_latency_ms} ms):");
                    println!("Tx ID       : {tx_id}");
                    println!("Amount      : {}", amount.format_symbolic());
                    println!("Claim Link  : {uri}\n");
                    println!("{qr}");
                }
                Ok((_, _, other)) => fail(&format!("voucher lock rejected: {other:?}")),
                Err(e) => fail(&format!("voucher-create failed: {e}")),
            }
        }
        "voucher-claim" => {
            if voucher_uri.trim().is_empty() {
                fail("pass `--voucher \"xcr://claim#<64-hex>...\"`");
            }
            let nanos = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos();
            let fallback_seed = domain_hash(
                "XCR.CLI.VOUCHER_NEW_WALLET.V1",
                &[
                    &nanos.to_le_bytes(),
                    wallet_path.to_string_lossy().as_bytes(),
                ],
            )
            .0;
            match cli_claim_bearer_voucher(&wallet_path, &voucher_uri, fallback_seed, node_addr) {
                Ok((
                    pocket_addr,
                    v_memo,
                    NodeRpcResponse::StealthClaimReceipt {
                        accepted: true,
                        claimed_amount,
                        new_pocket_balance,
                        ..
                    },
                )) => {
                    println!("Redeemed Bearer Cash Voucher!");
                    println!("Credited Pocket : {pocket_addr}");
                    println!("Swept Amount    : +{}", claimed_amount.format_symbolic());
                    println!("New Balance     : {}", new_pocket_balance.format_symbolic());
                    if let Some(m) = v_memo {
                        println!("Voucher Note    : {m}");
                    }
                }
                Ok((_, _, NodeRpcResponse::StealthClaimReceipt { message, .. })) => {
                    fail(&format!("voucher claim rejected: {message}"))
                }
                Ok((_, _, other)) => fail(&format!("unexpected reply: {other:?}")),
                Err(e) => fail(&format!("voucher-claim failed: {e}")),
            }
        }
        "backup" => match cli_export_backup_words(&wallet_path) {
            Ok((phrase, card)) => {
                println!("Wallet File: {}", wallet_path.display());
                println!("24-Word Checksummed Paper Recovery Card:\n");
                print!("{card}");
                println!("\nSingle-line phrase:\n{phrase}");
            }
            Err(e) => fail(&format!("backup failed: {e}")),
        },
        "recover" => {
            if words_phrase.trim().is_empty() {
                fail("pass `--words \"word1 word2 ... word24\"`");
            }
            match cli_recover_from_words(&wallet_path, &words_phrase) {
                Ok((pocket_addr, stealth_uri)) => {
                    println!("Recovered wallet : {}", wallet_path.display());
                    println!("Pocket Address   : {pocket_addr}");
                    println!("Stealth URI      : {stealth_uri}");
                }
                Err(e) => fail(&format!("recover failed: {e}")),
            }
        }
        "alias-set" => {
            if handle_arg.trim().is_empty() || recipient == "merchant-default" {
                fail("pass `--handle @name --to xcrstealth1_...`");
            }
            let book_path = wallet_path.with_extension("aliases");
            let mut book = LocalHandleBook::load(&book_path);
            if !book.upsert(&handle_arg, &recipient) {
                fail("`--to` must be a valid `xcrstealth1_<128-hex>` Stealth URI");
            }
            if let Err(e) = book.save(&book_path) {
                fail(&format!("failed saving alias book: {e}"));
            }
            println!(
                "Saved local handle {} -> {}",
                handle_arg,
                book_path.display()
            );
        }
        "resolve" => {
            if handle_arg.trim().is_empty() {
                fail("pass `--handle user@domain[:port]` or `--handle @local_alias`");
            }
            let book = LocalHandleBook::load(&wallet_path.with_extension("aliases"));
            if let Some(meta) = book.resolve(&handle_arg) {
                println!("Resolved Local Alias `{handle_arg}` -> {}", meta.to_uri());
            } else {
                match resolve_remote_handle(&handle_arg, Duration::from_secs(3)) {
                    Ok(meta) => {
                        println!("Resolved Remote Handle `{handle_arg}` -> {}", meta.to_uri())
                    }
                    Err(e) => fail(&format!("resolve failed for `{handle_arg}`: {e}")),
                }
            }
        }
        "light-verify" => match cli_verify_light_balance(&wallet_path, node_addr) {
            Ok((addr, balance, nonce, proof_bytes, auth_root)) => {
                println!("Light-Verified Addr: {addr}");
                println!("Verified Balance   : {}", balance.format_symbolic());
                println!("Verified Nonce     : {nonce}");
                println!("Merkle Proof Size  : {proof_bytes} bytes (<1 KB mobile-ready)");
                println!("Authenticated Root : {auth_root}");
            }
            Err(e) => fail(&format!("light-verify failed: {e}")),
        },
        "shutdown" => match cli_shutdown_daemon(node_addr) {
            Ok(NodeRpcResponse::AckShutdown) => {
                println!("Daemon at {node_addr} acknowledged shutdown.")
            }
            Ok(other) => println!("Unexpected reply: {other:?}"),
            Err(e) => fail(&format!("shutdown failed: {e}")),
        },
        "bench" => {
            if let Err(e) = run_tps_benchmark(&node_list, bench_txs, bench_streams) {
                fail(&format!("bench failed: {e}"));
            }
        }
        "attack-audit" => match run_adversarial_attack_suite(&node_list) {
            Ok(true) => {}
            Ok(false) => process::exit(1),
            Err(e) => fail(&format!("attack-audit failed: {e}")),
        },
        "stealth-address" => match cli_stealth_address(&wallet_path) {
            Ok((pocket_addr, stealth_uri)) => {
                println!("Wallet File    : {}", wallet_path.display());
                println!("Pocket Address : {pocket_addr}");
                println!("Stealth URI    : {stealth_uri}");
            }
            Err(e) => fail(&format!("stealth-address failed: {e}")),
        },
        "scan" | "claim-stealth" => {
            let do_claim = cmd == "claim-stealth";
            match cli_scan_and_claim_stealth_v2(&wallet_path, node_addr, do_claim) {
                Ok((scanned, matches)) => {
                    println!(
                        "Scanned {scanned} unspent stealth outputs via 1-byte view tag ({} owned by wallet):",
                        matches.len()
                    );
                    for (ot_addr, amt, claimed, new_bal, dec_memo) in matches {
                        let memo_tag = dec_memo
                            .map(|m| format!(" | Memo: \"{m}\""))
                            .unwrap_or_default();
                        if claimed {
                            println!(
                                "  [CLAIMED] {ot_addr} -> +{} (New Pocket Balance: {}){memo_tag}",
                                amt.format_symbolic(),
                                new_bal.format_symbolic()
                            );
                        } else {
                            println!(
                                "  [UNCLAIMED] {ot_addr} : {}{memo_tag} (run `claim-stealth` to sweep into Pocket)",
                                amt.format_symbolic()
                            );
                        }
                    }
                }
                Err(e) => fail(&format!("{cmd} failed: {e}")),
            }
        }
        "frost-split" => {
            let nanos = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos();
            let ent = domain_hash("XCR.CLI.FROST_SPLIT.V1", &[&nanos.to_le_bytes()]).0;
            match cli_frost_split(&wallet_path, threshold, total_shares, ent) {
                Ok(shares) => {
                    println!(
                        "Generated {total_shares} FROST Threshold Schnorr Shares ({threshold}-of-{total_shares}, 0B on-chain overhead):"
                    );
                    for s in shares {
                        println!("  Signer #{}: {}", s.index, s.to_uri());
                    }
                }
                Err(e) => fail(&format!("frost-split failed: {e}")),
            }
        }
        "frost-nonce" => {
            let nanos = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos();
            let ent = domain_hash("XCR.CLI.FROST_NONCE.V1", &[&nanos.to_le_bytes()]).0;
            match cli_frost_commit_nonce(&frost_share_uri, ent) {
                Ok((sec_uri, pub_uri)) => {
                    println!("Nonce Secret (KEEP LOCAL): {sec_uri}");
                    println!("Nonce Commit (SHARE)     : {pub_uri}");
                }
                Err(e) => fail(&format!("frost-nonce failed: {e}")),
            }
        }
        "frost-partial" => {
            match cli_frost_sign_partial(
                &frost_share_uri,
                &frost_nonce_sec_uri,
                &frost_commits_csv,
                &unsigned_uri,
            ) {
                Ok(part_uri) => println!("FROST Partial Signature: {part_uri}"),
                Err(e) => fail(&format!("frost-partial failed: {e}")),
            }
        }
        "frost-aggregate" => {
            match cli_frost_aggregate_cold(
                &pubkey_hex,
                &frost_commits_csv,
                &frost_partials_csv,
                &unsigned_uri,
            ) {
                Ok(signed_uri) => println!("Aggregated 65B Schnorr Cold Reply: {signed_uri}"),
                Err(e) => fail(&format!("frost-aggregate failed: {e}")),
            }
        }
        "htlc-secret" => {
            let nanos = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos();
            let ent = domain_hash("XCR.CLI.HTLC_ENT.V1", &[&nanos.to_le_bytes()]).0;
            let (pre, hl) = cli_generate_htlc_secret(ent);
            println!("HTLC Secret Preimage (32B): {pre}");
            println!("SHA-256 Hashlock     (32B): {hl}");
        }
        "htlc-lock" => {
            let nanos = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos();
            let h = domain_hash("XCR.CLI.HTLC_SALT.V1", &[&nanos.to_le_bytes()]).0;
            let mut salt = [0u8; 16];
            salt.copy_from_slice(&h[..16]);
            let exp = now_unix.saturating_add(timelock_secs);
            match cli_htlc_lock(
                &wallet_path,
                &recipient,
                resolved_amount(),
                &hashlock_hex,
                exp,
                salt,
                node_addr,
            ) {
                Ok(NodeRpcResponse::ContractReceipt {
                    accepted,
                    contract_id,
                    amount,
                    new_state_root,
                    message,
                }) => {
                    println!("HTLC Accepted  : {accepted} ({message})");
                    println!("Escrow ID      : {contract_id}");
                    println!("Locked Amount  : {}", amount.format_symbolic());
                    println!("WAL State Root : {new_state_root}");
                }
                Ok(other) => println!("Unexpected reply: {other:?}"),
                Err(e) => fail(&format!("htlc-lock failed: {e}")),
            }
        }
        "htlc-claim" => match cli_htlc_claim(&contract_id_hex, &preimage_hex, node_addr) {
            Ok(NodeRpcResponse::ContractReceipt {
                accepted,
                contract_id,
                amount,
                new_state_root,
                message,
            }) => {
                println!("HTLC Claimed   : {accepted} ({message})");
                println!("Escrow ID      : {contract_id}");
                println!("Credited       : {}", amount.format_symbolic());
                println!("WAL State Root : {new_state_root}");
            }
            Ok(other) => println!("Unexpected reply: {other:?}"),
            Err(e) => fail(&format!("htlc-claim failed: {e}")),
        },
        "htlc-refund" => match cli_htlc_refund(&contract_id_hex, node_addr) {
            Ok(NodeRpcResponse::ContractReceipt {
                accepted,
                contract_id,
                amount,
                new_state_root,
                message,
            }) => {
                println!("HTLC Refunded  : {accepted} ({message})");
                println!("Escrow ID      : {contract_id}");
                println!("Refunded       : {}", amount.format_symbolic());
                println!("WAL State Root : {new_state_root}");
            }
            Ok(other) => println!("Unexpected reply: {other:?}"),
            Err(e) => fail(&format!("htlc-refund failed: {e}")),
        },
        "htlc-list" => match cli_htlc_list(node_addr) {
            Ok(list) => {
                println!("On-Chain HTLC Escrows ({} entries):", list.len());
                for (id, snd, rcv, amt, hl, exp, st, pre) in list {
                    let st_lbl = match st {
                        0 => "OPEN",
                        1 => "CLAIMED",
                        _ => "REFUNDED",
                    };
                    let pre_str = pre
                        .map(|p| format!(" | preimage={}", credit_types::Hash32(p)))
                        .unwrap_or_default();
                    println!(
                        "  [{st_lbl:<8}] id={id} | {} | {snd} -> {rcv} | hashlock={hl} | exp={exp}{pre_str}",
                        amt.format_symbolic()
                    );
                }
            }
            Err(e) => fail(&format!("htlc-list failed: {e}")),
        },
        "channel-open" => {
            let nanos = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos();
            let h = domain_hash("XCR.CLI.CHAN_SALT.V1", &[&nanos.to_le_bytes()]).0;
            let mut salt = [0u8; 16];
            salt.copy_from_slice(&h[..16]);
            let exp = now_unix.saturating_add(timelock_secs);
            match cli_paychan_open(
                &wallet_path,
                &recipient,
                resolved_amount(),
                exp,
                salt,
                node_addr,
            ) {
                Ok(NodeRpcResponse::ContractReceipt {
                    accepted,
                    contract_id,
                    amount,
                    new_state_root,
                    message,
                }) => {
                    println!("PayChan Opened : {accepted} ({message})");
                    println!("Channel ID     : {contract_id}");
                    println!("Deposit Cap    : {}", amount.format_symbolic());
                    println!("WAL State Root : {new_state_root}");
                }
                Ok(other) => println!("Unexpected reply: {other:?}"),
                Err(e) => fail(&format!("channel-open failed: {e}")),
            }
        }
        "channel-tick" => {
            match cli_paychan_tick_offline(&wallet_path, &contract_id_hex, resolved_amount()) {
                Ok(uri) => println!("Off-Chain Streaming Voucher: {uri}"),
                Err(e) => fail(&format!("channel-tick failed: {e}")),
            }
        }
        "channel-close" => match cli_paychan_close(&voucher_uri, node_addr) {
            Ok(NodeRpcResponse::ContractReceipt {
                accepted,
                contract_id,
                amount,
                new_state_root,
                message,
            }) => {
                println!("PayChan Closed : {accepted} ({message})");
                println!("Channel ID     : {contract_id}");
                println!("Settled Total  : {}", amount.format_symbolic());
                println!("WAL State Root : {new_state_root}");
            }
            Ok(other) => println!("Unexpected reply: {other:?}"),
            Err(e) => fail(&format!("channel-close failed: {e}")),
        },
        "channel-list" => match cli_paychan_list(node_addr) {
            Ok(list) => {
                println!("Streaming Payment Channels ({} entries):", list.len());
                for (cid, payer, _, payee, dep, exp, closed, settled) in list {
                    let st = if closed { "CLOSED" } else { "OPEN" };
                    println!(
                        "  [{st:<6}] id={cid} | deposit={} | settled={} | {payer} -> {payee} | exp={exp}",
                        dep.format_symbolic(),
                        settled.format_symbolic()
                    );
                }
            }
            Err(e) => fail(&format!("channel-list failed: {e}")),
        },
        "check-issue" => {
            let nanos = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos();
            let h = domain_hash("XCR.CLI.CHK_SALT.V1", &[&nanos.to_le_bytes()]).0;
            let mut salt = [0u8; 16];
            salt.copy_from_slice(&h[..16]);
            let exp = now_unix.saturating_add(timelock_secs);
            match cli_check_issue(
                &wallet_path,
                &recipient,
                resolved_amount(),
                exp,
                salt,
                node_addr,
            ) {
                Ok((id, uri)) => {
                    println!("Check ID       : {id}");
                    println!("Authorized Max : {}", resolved_amount().format_symbolic());
                    println!("Signed Check   : {uri}");
                }
                Err(e) => fail(&format!("check-issue failed: {e}")),
            }
        }
        "check-cash" => {
            match cli_check_cash(&wallet_path, &check_uri, resolved_amount(), node_addr) {
                Ok(NodeRpcResponse::ContractReceipt {
                    accepted,
                    contract_id,
                    amount,
                    new_state_root,
                    message,
                }) => {
                    println!("Check Cashed   : {accepted} ({message})");
                    println!("Check ID       : {contract_id}");
                    println!("Cashed Amount  : {}", amount.format_symbolic());
                    println!("WAL State Root : {new_state_root}");
                }
                Ok(other) => println!("Unexpected reply: {other:?}"),
                Err(e) => fail(&format!("check-cash failed: {e}")),
            }
        }
        "check-cancel" => match cli_check_cancel(&wallet_path, &check_uri, node_addr) {
            Ok(NodeRpcResponse::ContractReceipt {
                accepted,
                contract_id,
                new_state_root,
                message,
                ..
            }) => {
                println!("Check Revoked  : {accepted} ({message})");
                println!("Check ID       : {contract_id}");
                println!("WAL State Root : {new_state_root}");
            }
            Ok(other) => println!("Unexpected reply: {other:?}"),
            Err(e) => fail(&format!("check-cancel failed: {e}")),
        },
        "offer-post" => {
            let exp = now_unix.saturating_add(timelock_secs);
            match cli_post_swap_offer(
                &wallet_path,
                resolved_amount(),
                &counter_asset,
                &counter_amount,
                &hashlock_hex,
                timelock_secs,
                exp,
                node_addr,
            ) {
                Ok((
                    uri,
                    NodeRpcResponse::ContractReceipt {
                        accepted, message, ..
                    },
                )) => {
                    println!("Swap Offer Posted: {accepted} ({message})");
                    println!("Offer URI        : {uri}");
                }
                Ok((_, other)) => println!("Unexpected reply: {other:?}"),
                Err(e) => fail(&format!("offer-post failed: {e}")),
            }
        }
        "offer-list" => match cli_list_swap_offers(node_addr) {
            Ok(offers) => {
                println!(
                    "Active P2P Atomic Swap Offers ({} signed intents):",
                    offers.len()
                );
                for o in offers {
                    println!(
                        "  offer={} | {} <-> {} {} | maker={} | hashlock={}",
                        o.offer_id,
                        o.xcr_amount.format_symbolic(),
                        o.counter_amount,
                        o.counter_asset,
                        o.maker_address,
                        o.hashlock
                    );
                }
            }
            Err(e) => fail(&format!("offer-list failed: {e}")),
        },
        "script-inheritance" => {
            let unlock_at = now_unix.saturating_add(timelock_secs);
            match cli_build_inheritance_script(&wallet_path, &pubkey_hex, unlock_at) {
                Ok((sh, uri)) => {
                    println!("CredScript Hash (P2SH): {sh}");
                    println!("Unlock Timestamp      : {unlock_at}");
                    println!("CredScript Bytecode   : {uri}");
                }
                Err(e) => fail(&format!("script-inheritance failed: {e}")),
            }
        }
        "script-lock" => {
            let nanos = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos();
            let h = domain_hash("XCR.CLI.SCRIPT_SALT.V1", &[&nanos.to_le_bytes()]).0;
            let mut salt = [0u8; 16];
            salt.copy_from_slice(&h[..16]);
            match cli_lock_script_vault(
                &wallet_path,
                &script_uri,
                resolved_amount(),
                salt,
                node_addr,
            ) {
                Ok(NodeRpcResponse::ContractReceipt {
                    accepted,
                    contract_id,
                    amount,
                    new_state_root,
                    message,
                }) => {
                    println!("Vault Locked   : {accepted} ({message})");
                    println!("Vault ID       : {contract_id}");
                    println!("Locked Balance : {}", amount.format_symbolic());
                    println!("WAL State Root : {new_state_root}");
                }
                Ok(other) => println!("Unexpected reply: {other:?}"),
                Err(e) => fail(&format!("script-lock failed: {e}")),
            }
        }
        "script-spend" => {
            match cli_spend_inheritance_vault(
                &wallet_path,
                &contract_id_hex,
                &script_uri,
                &recipient,
                resolved_amount(),
                is_heir_role,
                node_addr,
            ) {
                Ok(NodeRpcResponse::ContractReceipt {
                    accepted,
                    contract_id,
                    amount,
                    new_state_root,
                    message,
                }) => {
                    println!("Vault Spent    : {accepted} ({message})");
                    println!("Vault ID       : {contract_id}");
                    println!("Released       : {}", amount.format_symbolic());
                    println!("WAL State Root : {new_state_root}");
                }
                Ok(other) => println!("Unexpected reply: {other:?}"),
                Err(e) => fail(&format!("script-spend failed: {e}")),
            }
        }
        "session-issue" => {
            let nanos = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos();
            let ent = domain_hash("XCR.CLI.SESS_ENT.V1", &[&nanos.to_le_bytes()]).0;
            let exp = now_unix.saturating_add(timelock_secs);
            match cli_issue_session_key(
                &wallet_path,
                resolved_amount(),
                Some(recipient.as_str()),
                exp,
                ent,
                node_addr,
            ) {
                Ok((sid, uri)) => {
                    println!("Session ID     : {sid}");
                    println!("Max Allowance  : {}", resolved_amount().format_symbolic());
                    println!("Session Key URI: {uri}");
                }
                Err(e) => fail(&format!("session-issue failed: {e}")),
            }
        }
        "session-pay" => {
            let nanos = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos();
            let h = domain_hash("XCR.CLI.SESS_SPEND.V1", &[&nanos.to_le_bytes()]).0;
            let mut salt = [0u8; 16];
            salt.copy_from_slice(&h[..16]);
            match cli_session_spend(
                &session_key_uri,
                &recipient,
                resolved_amount(),
                sponsor_wallet.as_deref(),
                salt,
                node_addr,
            ) {
                Ok(NodeRpcResponse::ContractReceipt {
                    accepted,
                    contract_id,
                    amount,
                    new_state_root,
                    message,
                }) => {
                    println!("Session Spend  : {accepted} ({message})");
                    println!("Spend ID       : {contract_id}");
                    println!("Paid Amount    : {}", amount.format_symbolic());
                    println!("WAL State Root : {new_state_root}");
                }
                Ok(other) => println!("Unexpected reply: {other:?}"),
                Err(e) => fail(&format!("session-pay failed: {e}")),
            }
        }
        "session-revoke" => match cli_session_revoke(&wallet_path, &session_key_uri, node_addr) {
            Ok(NodeRpcResponse::ContractReceipt {
                accepted,
                contract_id,
                new_state_root,
                message,
                ..
            }) => {
                println!("Session Revoked: {accepted} ({message})");
                println!("Session ID     : {contract_id}");
                println!("WAL State Root : {new_state_root}");
            }
            Ok(other) => println!("Unexpected reply: {other:?}"),
            Err(e) => fail(&format!("session-revoke failed: {e}")),
        },
        "asset-mint" => {
            let nanos = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos();
            let h = domain_hash("XCR.CLI.ASSET_MINT.V1", &[&nanos.to_le_bytes()]).0;
            let mut salt = [0u8; 16];
            salt.copy_from_slice(&h[..16]);
            match cli_mint_native_asset(&wallet_path, &asset_ticker, asset_supply, salt, node_addr)
            {
                Ok(NodeRpcResponse::ContractReceipt {
                    accepted,
                    contract_id,
                    new_state_root,
                    message,
                    ..
                }) => {
                    println!("Asset Minted   : {accepted} ({message})");
                    println!("Asset ID       : {contract_id}");
                    println!("WAL State Root : {new_state_root}");
                }
                Ok(other) => println!("Unexpected reply: {other:?}"),
                Err(e) => fail(&format!("asset-mint failed: {e}")),
            }
        }
        "asset-send" => {
            let nanos = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos();
            let h = domain_hash("XCR.CLI.ASSET_XFER.V1", &[&nanos.to_le_bytes()]).0;
            let mut salt = [0u8; 16];
            salt.copy_from_slice(&h[..16]);
            match cli_transfer_native_asset(
                &wallet_path,
                &contract_id_hex,
                &recipient,
                asset_supply,
                salt,
                node_addr,
            ) {
                Ok(NodeRpcResponse::ContractReceipt {
                    accepted,
                    contract_id,
                    new_state_root,
                    message,
                    ..
                }) => {
                    println!("Asset Sent     : {accepted} ({message})");
                    println!("Transfer ID    : {contract_id}");
                    println!("WAL State Root : {new_state_root}");
                }
                Ok(other) => println!("Unexpected reply: {other:?}"),
                Err(e) => fail(&format!("asset-send failed: {e}")),
            }
        }
        "asset-list" => {
            let w_opt = wallet_path.exists().then_some(wallet_path.as_path());
            match cli_list_native_assets(w_opt, node_addr) {
                Ok(list) => {
                    println!("Native Bearer Multi-Assets ({} assets):", list.len());
                    for (aid, ticker, sup, dec, bal) in list {
                        println!(
                            "  {ticker:<12} | balance={bal:<8} / supply={sup:<8} (dec={dec}) | id={aid}"
                        );
                    }
                }
                Err(e) => fail(&format!("asset-list failed: {e}")),
            }
        }
        "campaign-create" => {
            let nanos = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos();
            let h = domain_hash("XCR.CLI.CAMP_NEW.V1", &[&nanos.to_le_bytes()]).0;
            let mut salt = [0u8; 16];
            salt.copy_from_slice(&h[..16]);
            let dl = now_unix.saturating_add(timelock_secs);
            match cli_create_campaign(
                &wallet_path,
                &recipient,
                &sub_label,
                resolved_amount(),
                dl,
                salt,
                node_addr,
            ) {
                Ok(NodeRpcResponse::ContractReceipt {
                    accepted,
                    contract_id,
                    new_state_root,
                    message,
                    ..
                }) => {
                    println!("Campaign Open  : {accepted} ({message})");
                    println!("Campaign ID    : {contract_id}");
                    println!("WAL State Root : {new_state_root}");
                }
                Ok(other) => println!("Unexpected reply: {other:?}"),
                Err(e) => fail(&format!("campaign-create failed: {e}")),
            }
        }
        "campaign-pledge" => {
            let nanos = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos();
            let h = domain_hash("XCR.CLI.CAMP_PLEDGE.V1", &[&nanos.to_le_bytes()]).0;
            let mut salt = [0u8; 16];
            salt.copy_from_slice(&h[..16]);
            match cli_pledge_campaign(
                &wallet_path,
                &contract_id_hex,
                resolved_amount(),
                salt,
                node_addr,
            ) {
                Ok(NodeRpcResponse::ContractReceipt {
                    accepted,
                    contract_id,
                    amount,
                    new_state_root,
                    message,
                }) => {
                    println!("Pledge Accepted: {accepted} ({message})");
                    println!("Campaign ID    : {contract_id}");
                    println!("Total Pledged  : {}", amount.format_symbolic());
                    println!("WAL State Root : {new_state_root}");
                }
                Ok(other) => println!("Unexpected reply: {other:?}"),
                Err(e) => fail(&format!("campaign-pledge failed: {e}")),
            }
        }
        "campaign-finalize" => match cli_finalize_campaign(&contract_id_hex, node_addr) {
            Ok(NodeRpcResponse::ContractReceipt {
                accepted,
                contract_id,
                amount,
                new_state_root,
                message,
            }) => {
                println!("Campaign Closed: {accepted} ({message})");
                println!("Campaign ID    : {contract_id}");
                println!("Settled Amount : {}", amount.format_symbolic());
                println!("WAL State Root : {new_state_root}");
            }
            Ok(other) => println!("Unexpected reply: {other:?}"),
            Err(e) => fail(&format!("campaign-finalize failed: {e}")),
        },
        "supply-audit" => match cli_supply_audit(node_addr) {
            Ok(NodeRpcResponse::SupplyAndContractsSummary {
                pockets_total,
                stealth_utxos_total,
                locked_contracts_total,
                circulating_supply,
                total_burned,
                delta_conserved,
                open_script_vaults,
                campaigns,
            }) => {
                println!("=== FORMAL CARDANO-STYLE SUPPLY & CONTRACT AUDIT ===");
                println!(
                    "Pockets Balance Sum   : {}",
                    pockets_total.format_symbolic()
                );
                println!(
                    "Stealth UTXOs Sum     : {}",
                    stealth_utxos_total.format_symbolic()
                );
                println!(
                    "Locked Contracts Sum  : {}",
                    locked_contracts_total.format_symbolic()
                );
                println!(
                    "Circulating Supply    : {}",
                    circulating_supply.format_symbolic()
                );
                println!("Total Burned (15%)    : {}", total_burned.format_symbolic());
                println!("Open Script Vaults    : {open_script_vaults}");
                println!("Active Campaigns      : {}", campaigns.len());
                println!("Delta Conservation OK : {delta_conserved}");
            }
            Ok(other) => println!("Unexpected reply: {other:?}"),
            Err(e) => fail(&format!("supply-audit failed: {e}")),
        },
        "dex-order" => {
            let nanos = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos();
            let h = domain_hash("XCR.CLI.DEX_ORD.V1", &[&nanos.to_le_bytes()]).0;
            let mut salt = [0u8; 16];
            salt.copy_from_slice(&h[..16]);
            match cli_dex_place_order(
                &wallet_path,
                &contract_id_hex,
                dex_sell,
                asset_supply,
                price_bits,
                dex_ioc,
                salt,
                node_addr,
            ) {
                Ok(NodeRpcResponse::ContractReceipt {
                    accepted,
                    contract_id,
                    new_state_root,
                    message,
                    ..
                }) => {
                    println!("DEX Order      : {accepted} ({message})");
                    println!("Order ID       : {contract_id}");
                    println!("WAL State Root : {new_state_root}");
                }
                Ok(other) => println!("Unexpected reply: {other:?}"),
                Err(e) => fail(&format!("dex-order failed: {e}")),
            }
        }
        "dex-cancel" => match cli_dex_cancel_order(&wallet_path, &contract_id_hex, node_addr) {
            Ok(NodeRpcResponse::ContractReceipt {
                accepted,
                contract_id,
                new_state_root,
                message,
                ..
            }) => {
                println!("DEX Cancelled  : {accepted} ({message})");
                println!("Order ID       : {contract_id}");
                println!("WAL State Root : {new_state_root}");
            }
            Ok(other) => println!("Unexpected reply: {other:?}"),
            Err(e) => fail(&format!("dex-cancel failed: {e}")),
        },
        "dex-book" => match cli_dex_orderbook(
            (!contract_id_hex.is_empty()).then_some(contract_id_hex.as_str()),
            node_addr,
        ) {
            Ok(orders) => {
                println!("Native Limit Orderbook ({} open orders):", orders.len());
                for (oid, maker, aid, is_sell, rem, pbits, esc) in orders {
                    let side = if is_sell { "ASK" } else { "BID" };
                    println!(
                        "  [{side}] rem={rem:<6} @ {pbits} bits/unit | esc={} | maker={} | asset={} | order={oid}",
                        esc.format_symbolic(),
                        maker.short_hex(),
                        &aid.to_hex()[..12]
                    );
                }
            }
            Err(e) => fail(&format!("dex-book failed: {e}")),
        },
        "pay-bridged" => {
            let nanos = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos();
            let h = domain_hash("XCR.CLI.BRIDGE_PAY.V1", &[&nanos.to_le_bytes()]).0;
            let mut salt = [0u8; 16];
            salt.copy_from_slice(&h[..16]);
            let min_target = if out_asset_hex.is_empty() {
                resolved_amount().bits()
            } else {
                min_out_units
            };
            match cli_bridged_payment(
                &wallet_path,
                &recipient,
                &contract_id_hex,
                asset_supply,
                (!out_asset_hex.is_empty()).then_some(out_asset_hex.as_str()),
                min_target,
                salt,
                node_addr,
            ) {
                Ok(NodeRpcResponse::ContractReceipt {
                    accepted,
                    contract_id,
                    new_state_root,
                    message,
                    ..
                }) => {
                    println!("Bridged Pay    : {accepted} ({message})");
                    println!("Tx ID          : {contract_id}");
                    println!("WAL State Root : {new_state_root}");
                }
                Ok(other) => println!("Unexpected reply: {other:?}"),
                Err(e) => fail(&format!("pay-bridged failed: {e}")),
            }
        }
        "asset-send-babel" => {
            let nanos = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos();
            let h = domain_hash("XCR.CLI.BABEL_XFER.V1", &[&nanos.to_le_bytes()]).0;
            let mut salt = [0u8; 16];
            salt.copy_from_slice(&h[..16]);
            match cli_babel_asset_transfer(
                &wallet_path,
                &contract_id_hex,
                &recipient,
                asset_supply,
                babel_fee_units,
                salt,
                node_addr,
            ) {
                Ok(NodeRpcResponse::ContractReceipt {
                    accepted,
                    contract_id,
                    new_state_root,
                    message,
                    ..
                }) => {
                    println!("Babel Transfer : {accepted} ({message})");
                    println!("Transfer ID    : {contract_id}");
                    println!("WAL State Root : {new_state_root}");
                }
                Ok(other) => println!("Unexpected reply: {other:?}"),
                Err(e) => fail(&format!("asset-send-babel failed: {e}")),
            }
        }
        "handle-register" => match cli_register_handle(&wallet_path, &handle_arg, node_addr) {
            Ok((
                disp,
                NodeRpcResponse::ContractReceipt {
                    accepted,
                    contract_id,
                    new_state_root,
                    message,
                    ..
                },
            )) => {
                println!("Handle Bound   : {accepted} ({message})");
                println!("On-Chain Name  : {disp}");
                println!("Tx ID          : {contract_id}");
                println!("WAL State Root : {new_state_root}");
            }
            Ok((_, other)) => println!("Unexpected reply: {other:?}"),
            Err(e) => fail(&format!("handle-register failed: {e}")),
        },
        "handle-transfer" => {
            let nanos = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos();
            let h = domain_hash("XCR.CLI.HND_XFER.V1", &[&nanos.to_le_bytes()]).0;
            let mut salt = [0u8; 16];
            salt.copy_from_slice(&h[..16]);
            match cli_transfer_handle(
                &wallet_path,
                &handle_arg,
                &recipient,
                &memo,
                salt,
                node_addr,
            ) {
                Ok(NodeRpcResponse::ContractReceipt {
                    accepted,
                    contract_id,
                    new_state_root,
                    message,
                    ..
                }) => {
                    println!("Handle Moved   : {accepted} ({message})");
                    println!("Tx ID          : {contract_id}");
                    println!("WAL State Root : {new_state_root}");
                }
                Ok(other) => println!("Unexpected reply: {other:?}"),
                Err(e) => fail(&format!("handle-transfer failed: {e}")),
            }
        }
        "handle-resolve" => match cli_resolve_onchain_handle(&handle_arg, node_addr) {
            Ok(NodeRpcResponse::HandleResolution {
                found,
                normalized_name,
                owner,
                stealth_uri,
                registered_epoch,
            }) => {
                println!("Found          : {found}");
                println!("Handle         : @{normalized_name}.xcr");
                println!("Owner Pocket   : {}", owner.short_hex());
                println!("Stealth URI    : {stealth_uri}");
                println!("Epoch Bound    : {registered_epoch}");
            }
            Ok(other) => println!("Unexpected reply: {other:?}"),
            Err(e) => fail(&format!("handle-resolve failed: {e}")),
        },
        "lane-pay" => {
            match cli_parallel_lane_pay(
                &wallet_path,
                &recipient,
                lane_id,
                resolved_amount(),
                node_addr,
            ) {
                Ok(NodeRpcResponse::ContractReceipt {
                    accepted,
                    contract_id,
                    amount,
                    new_state_root,
                    message,
                }) => {
                    println!("Lane Settled   : {accepted} ({message})");
                    println!("Tx ID          : {contract_id}");
                    println!("Paid Amount    : {}", amount.format_symbolic());
                    println!("WAL State Root : {new_state_root}");
                }
                Ok(other) => println!("Unexpected reply: {other:?}"),
                Err(e) => fail(&format!("lane-pay failed: {e}")),
            }
        }
        "atomic-batch" => {
            let nanos = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos();
            let h = domain_hash("XCR.CLI.BATCH_ATOMIC.V1", &[&nanos.to_le_bytes()]).0;
            let mut salt = [0u8; 16];
            salt.copy_from_slice(&h[..16]);
            match cli_execute_atomic_batch(
                &wallet_path,
                &batch_spec,
                resolved_amount(),
                salt,
                node_addr,
            ) {
                Ok(NodeRpcResponse::ContractReceipt {
                    accepted,
                    contract_id,
                    amount,
                    new_state_root,
                    message,
                }) => {
                    println!("Atomic Batch   : {accepted} ({message})");
                    println!("Batch ID       : {contract_id}");
                    println!("Net XCR Debit  : {}", amount.format_symbolic());
                    println!("WAL State Root : {new_state_root}");
                }
                Ok(other) => println!("Unexpected reply: {other:?}"),
                Err(e) => fail(&format!("atomic-batch failed: {e}")),
            }
        }
        "artifact-mint" => {
            let nanos = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos();
            let h = domain_hash("XCR.CLI.ART_MINT.V1", &[&nanos.to_le_bytes()]).0;
            let mut salt = [0u8; 16];
            salt.copy_from_slice(&h[..16]);
            match cli_mint_artifact(
                &wallet_path,
                &recipient,
                &collection_name,
                &sub_label,
                &memo,
                salt,
                node_addr,
            ) {
                Ok(NodeRpcResponse::ContractReceipt {
                    accepted,
                    contract_id,
                    new_state_root,
                    message,
                    ..
                }) => {
                    println!("Artifact Minted: {accepted} ({message})");
                    println!("Artifact ID    : {contract_id}");
                    println!("WAL State Root : {new_state_root}");
                }
                Ok(other) => println!("Unexpected reply: {other:?}"),
                Err(e) => fail(&format!("artifact-mint failed: {e}")),
            }
        }
        "artifact-send" => {
            let nanos = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos();
            let h = domain_hash("XCR.CLI.ART_SEND.V1", &[&nanos.to_le_bytes()]).0;
            let mut salt = [0u8; 16];
            salt.copy_from_slice(&h[..16]);
            match cli_transfer_artifact(&wallet_path, &contract_id_hex, &recipient, salt, node_addr)
            {
                Ok(NodeRpcResponse::ContractReceipt {
                    accepted,
                    contract_id,
                    new_state_root,
                    message,
                    ..
                }) => {
                    println!("Artifact Sent  : {accepted} ({message})");
                    println!("Artifact ID    : {contract_id}");
                    println!("WAL State Root : {new_state_root}");
                }
                Ok(other) => println!("Unexpected reply: {other:?}"),
                Err(e) => fail(&format!("artifact-send failed: {e}")),
            }
        }
        "attest-issue" => {
            let nanos = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos();
            let h = domain_hash("XCR.CLI.ATT_ISSUE.V1", &[&nanos.to_le_bytes()]).0;
            let mut salt = [0u8; 16];
            salt.copy_from_slice(&h[..16]);
            let exp = now_unix.saturating_add(timelock_secs);
            match cli_issue_attestation(
                &wallet_path,
                &recipient,
                &schema_name,
                &memo,
                exp,
                salt,
                node_addr,
            ) {
                Ok((
                    comm,
                    NodeRpcResponse::ContractReceipt {
                        accepted,
                        contract_id,
                        new_state_root,
                        message,
                        ..
                    },
                )) => {
                    println!("Attestation OK : {accepted} ({message})");
                    println!("Attestation ID : {contract_id}");
                    println!("Zero-PII Commit: {comm}");
                    println!("WAL State Root : {new_state_root}");
                }
                Ok((_, other)) => println!("Unexpected reply: {other:?}"),
                Err(e) => fail(&format!("attest-issue failed: {e}")),
            }
        }
        "attest-revoke" => {
            match cli_revoke_attestation(&wallet_path, &contract_id_hex, node_addr) {
                Ok(NodeRpcResponse::ContractReceipt {
                    accepted,
                    contract_id,
                    new_state_root,
                    message,
                    ..
                }) => {
                    println!("Attest Revoked : {accepted} ({message})");
                    println!("Attestation ID : {contract_id}");
                    println!("WAL State Root : {new_state_root}");
                }
                Ok(other) => println!("Unexpected reply: {other:?}"),
                Err(e) => fail(&format!("attest-revoke failed: {e}")),
            }
        }
        "artifact-list" => {
            let w_opt = wallet_path.exists().then_some(wallet_path.as_path());
            match cli_list_artifacts_and_attestations(w_opt, node_addr) {
                Ok((arts, atts)) => {
                    println!("1-of-1 Bearer Artifacts ({}):", arts.len());
                    for (aid, _iss, own, col, title, chash) in arts {
                        println!(
                            "  [{col}] `{title}` | owner={} | content={} | id={aid}",
                            own.short_hex(),
                            &chash.to_hex()[..16]
                        );
                    }
                    println!("Zero-PII Verifiable Attestations ({}):", atts.len());
                    for (id, att, sub, sch, comm, _exp, rev) in atts {
                        println!(
                            "  [{sch}] subject={} | attester={} | revoked={rev} | commit={} | id={id}",
                            sub.short_hex(),
                            att.short_hex(),
                            &comm.to_hex()[..16]
                        );
                    }
                }
                Err(e) => fail(&format!("artifact-list failed: {e}")),
            }
        }
        "gov-propose" => {
            let nanos = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos();
            let h = domain_hash("XCR.CLI.GOV_PROP.V1", &[&nanos.to_le_bytes()]).0;
            let mut salt = [0u8; 16];
            salt.copy_from_slice(&h[..16]);
            let dl = now_unix.saturating_add(timelock_secs);
            match cli_propose_governance(
                &wallet_path,
                &sub_label,
                &param_key,
                param_value,
                dl,
                salt,
                node_addr,
            ) {
                Ok(NodeRpcResponse::ContractReceipt {
                    accepted,
                    contract_id,
                    new_state_root,
                    message,
                    ..
                }) => {
                    println!("Proposal Open  : {accepted} ({message})");
                    println!("Proposal ID    : {contract_id}");
                    println!("WAL State Root : {new_state_root}");
                }
                Ok(other) => println!("Unexpected reply: {other:?}"),
                Err(e) => fail(&format!("gov-propose failed: {e}")),
            }
        }
        "drep-delegate" => {
            let nanos = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos();
            let h = domain_hash("XCR.CLI.DREP_DEL.V1", &[&nanos.to_le_bytes()]).0;
            let mut salt = [0u8; 16];
            salt.copy_from_slice(&h[..16]);
            match cli_delegate_drep(&wallet_path, &recipient, salt, node_addr) {
                Ok(NodeRpcResponse::ContractReceipt {
                    accepted,
                    contract_id,
                    new_state_root,
                    message,
                    ..
                }) => {
                    println!("DRep Delegated : {accepted} ({message})");
                    println!("Tx ID          : {contract_id}");
                    println!("WAL State Root : {new_state_root}");
                }
                Ok(other) => println!("Unexpected reply: {other:?}"),
                Err(e) => fail(&format!("drep-delegate failed: {e}")),
            }
        }
        "gov-vote" => {
            match cli_vote_governance(&wallet_path, &contract_id_hex, &vote_choice, node_addr) {
                Ok(NodeRpcResponse::ContractReceipt {
                    accepted,
                    contract_id,
                    new_state_root,
                    message,
                    ..
                }) => {
                    println!("Vote Recorded  : {accepted} ({message})");
                    println!("Proposal ID    : {contract_id}");
                    println!("WAL State Root : {new_state_root}");
                }
                Ok(other) => println!("Unexpected reply: {other:?}"),
                Err(e) => fail(&format!("gov-vote failed: {e}")),
            }
        }
        "gov-list" => match cli_list_governance(node_addr) {
            Ok((dreps, props)) => {
                println!(
                    "Voltaire Constitutional Governance ({dreps} active DRep(s), {} proposal(s)):",
                    props.len()
                );
                for (pid, title, pkey, pval, yes_b, no_b, abs_b, _dl) in props {
                    println!(
                        "  `{title}` [{pkey}={pval}] | YES={} | NO={} | ABSTAIN={} | id={pid}",
                        Amount::from_bits(yes_b).format_symbolic(),
                        Amount::from_bits(no_b).format_symbolic(),
                        Amount::from_bits(abs_b).format_symbolic()
                    );
                }
            }
            Err(e) => fail(&format!("gov-list failed: {e}")),
        },
        "deposit-shield" => {
            let nanos = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos();
            let h = domain_hash("XCR.CLI.SHIELD.V1", &[&nanos.to_le_bytes()]).0;
            let mut salt = [0u8; 16];
            salt.copy_from_slice(&h[..16]);
            match cli_set_deposit_shield(
                &wallet_path,
                resolved_amount(),
                strict_shield,
                &allowlist_csv,
                salt,
                node_addr,
            ) {
                Ok(NodeRpcResponse::ContractReceipt {
                    accepted,
                    contract_id,
                    new_state_root,
                    message,
                    ..
                }) => {
                    println!("Inbox Shield   : {accepted} ({message})");
                    println!("Shield Tx ID   : {contract_id}");
                    println!("WAL State Root : {new_state_root}");
                }
                Ok(other) => println!("Unexpected reply: {other:?}"),
                Err(e) => fail(&format!("deposit-shield failed: {e}")),
            }
        }
        "ln-gen-invoice" => {
            let nanos = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos();
            let ent = domain_hash("XCR.CLI.LN_GEN.V1", &[&nanos.to_le_bytes()]).0;
            let desc = if memo.is_empty() {
                "Lightning <-> XCR Atomic Swap"
            } else {
                memo.as_str()
            };
            match cli_generate_bolt11_swap_invoice(
                "lnbc",
                asset_supply,
                desc,
                timelock_secs,
                now_unix,
                ent,
            ) {
                Ok((pre_hex, hl_hex, bolt11)) => {
                    println!("Preimage (KEEP): {pre_hex}");
                    println!("Payment Hash   : {hl_hex}");
                    println!("BOLT-11 Invoice: {bolt11}");
                }
                Err(e) => fail(&format!("ln-gen-invoice failed: {e}")),
            }
        }
        "ln-decode" => match cli_decode_bolt11(&invoice_id) {
            Ok(inv) => {
                println!("Network HRP    : {}", inv.network);
                println!("Amount (msat)  : {:?}", inv.amount_msat);
                println!("Payment Hash   : {}", inv.payment_hash);
                println!("Description    : {}", inv.description);
                println!("Expiry (secs)  : {}", inv.expiry_secs);
            }
            Err(e) => fail(&format!("ln-decode failed: {e}")),
        },
        "ln-swap-lock" => {
            let nanos = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos();
            let h = domain_hash("XCR.CLI.LN_LOCK.V1", &[&nanos.to_le_bytes()]).0;
            let mut salt = [0u8; 16];
            salt.copy_from_slice(&h[..16]);
            match cli_lock_xcr_to_bolt11(
                &wallet_path,
                &recipient,
                resolved_amount(),
                &invoice_id,
                timelock_secs,
                now_unix,
                salt,
                node_addr,
            ) {
                Ok((
                    inv,
                    NodeRpcResponse::ContractReceipt {
                        accepted,
                        contract_id,
                        amount,
                        new_state_root,
                        message,
                    },
                )) => {
                    println!("LN Swap Locked : {accepted} ({message})");
                    println!("Escrow ID      : {contract_id}");
                    println!("Payment Hash   : {}", inv.payment_hash);
                    println!("Locked XCR     : {}", amount.format_symbolic());
                    println!("WAL State Root : {new_state_root}");
                }
                Ok((_, other)) => println!("Unexpected reply: {other:?}"),
                Err(e) => fail(&format!("ln-swap-lock failed: {e}")),
            }
        }
        "btc-htlc-script" => {
            let locktime = now_unix.saturating_add(timelock_secs) as u32;
            match cli_build_btc_p2wsh_swap_address(
                !use_testnet,
                &hashlock_hex,
                &pubkey_hex,
                &memo,
                locktime,
            ) {
                Ok((script_hex, btc_addr)) => {
                    println!("BTC P2WSH Addr : {btc_addr}");
                    println!("Witness Script : {script_hex}");
                    println!("CLTV Locktime  : {locktime}");
                }
                Err(e) => fail(&format!("btc-htlc-script failed: {e}")),
            }
        }
        "raw-lane-hex" => {
            match cli_export_signed_raw_lane_hex(
                &wallet_path,
                &recipient,
                lane_id,
                resolved_amount(),
                node_addr,
            ) {
                Ok((tx_id, raw_hex)) => {
                    println!("Signed Tx ID   : {tx_id}");
                    println!("Raw Tx Hex     : {raw_hex}");
                }
                Err(e) => fail(&format!("raw-lane-hex failed: {e}")),
            }
        }
        _ => {
            print_usage();
            process::exit(2);
        }
    }
}

fn print_usage() {
    eprintln!(
        "Usage: credit-cli <status|init-wallet|encrypt-wallet|decrypt-wallet|split-backup|combine-backup|export-pubkey|cold-prepare|cold-sign|cold-broadcast|pay|pay-multi|split-bill|sub-add|sub-list|sub-cancel|sub-run|balance|history|watch|inspect|stealth-address|invoice|scan|claim-stealth|voucher-create|voucher-claim|backup|recover|alias-set|resolve|light-verify|bench|attack-audit|shutdown> [options]"
    );
}

fn fail(msg: &str) -> ! {
    eprintln!("error: {msg}");
    process::exit(1);
}
