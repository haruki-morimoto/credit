use std::env;
use std::fs;
use std::net::{SocketAddr, ToSocketAddrs};
use std::path::PathBuf;
use std::process;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use credit_consensus::{
    GenesisStandbyStatus, MAINNET_GENESIS_ISO8601, MAINNET_GENESIS_UNIX, NetworkProfile,
    VerifiableGenesisBeacon,
};
use credit_node::{
    MeshPeerConfig, current_ponc_miner_threads, run_genesis_simulation, run_mesh_peer_with_beacon,
    run_node_daemon, set_ponc_miner_threads,
};
use credit_storage::PersistentLedger;

/// Public Testnet bootstrap seed nodes (`--testnet`) across North America, Europe, and Asia.
const DEFAULT_TESTNET_SEEDS: &[&str] = &[
    "162.243.166.102:9501",
    "167.71.138.246:9501",
    "139.59.229.45:9501",
];

/// Public Mainnet Standby bootstrap seed nodes (`--mainnet`, separate port `9500` from Testnet `9501`).
const DEFAULT_MAINNET_SEEDS: &[&str] = &[
    "162.243.166.102:9500",
    "167.71.138.246:9500",
    "139.59.229.45:9500",
];

fn resolve_peer_endpoint(spec: &str) -> Result<Vec<SocketAddr>, String> {
    spec.to_socket_addrs()
        .map(|iter| iter.collect())
        .map_err(|e| format!("unable to resolve peer '{spec}': {e}"))
}

fn main() {
    let args: Vec<String> = env::args().skip(1).collect();
    if args.first().map(String::as_str) == Some("genesis-status") {
        let now_unix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let status = VerifiableGenesisBeacon::evaluate_genesis_standby(now_unix, None, None);
        println!("==========================================================================");
        println!("  Credits (∀ / XCR) — 1 January 2027 Fair-Launch Genesis Gate");
        println!("==========================================================================");
        println!(
            "  Mainnet Chain ID   : {}",
            NetworkProfile::Mainnet.chain_id()
        );
        println!("  Target Genesis UTC : {MAINNET_GENESIS_ISO8601} (Unix {MAINNET_GENESIS_UNIX})");
        println!("  Genesis Supply     : ∀ 0.000000 XCR (Zero Premine / Zero Insider Allocation)");
        match status {
            GenesisStandbyStatus::StandbyCountdown {
                seconds_remaining, ..
            } => {
                let days = seconds_remaining / 86_400;
                let hours = (seconds_remaining % 86_400) / 3_600;
                let mins = (seconds_remaining % 3_600) / 60;
                println!("  Gate Status        : STANDBY ARMED (Early Pre-Mine Blocked)");
                println!("  Countdown to Epoch0: {days}d {hours}h {mins}m ({seconds_remaining}s)");
            }
            GenesisStandbyStatus::AwaitingPublicBeacon { .. } => {
                println!(
                    "  Gate Status        : GENESIS WINDOW OPEN — Awaiting Bitcoin Block Beacon"
                );
            }
            GenesisStandbyStatus::ReadyToLaunch(_) => {
                println!("  Gate Status        : LIVE");
            }
        }
        println!("==========================================================================");
        return;
    }
    if args.first().map(String::as_str) == Some("peer") {
        let mut network = NetworkProfile::LocalDevnet;
        let mut bind_addr: SocketAddr = "127.0.0.1:9500".parse().unwrap();
        let mut data_dir = PathBuf::from("./peer-data");
        let mut seed_peers: Vec<SocketAddr> = Vec::new();
        let mut min_quorum_peers: usize = 3;
        let mut epoch_ms: u64 = 60_000;
        let mut genesis_btc_hex: Option<String> = None;
        let mut genesis_headline =
            String::from("2027-01-01 00:00 UTC — Credits (XCR) Fair Open Monetary Genesis");

        let mut i = 1usize;
        while i < args.len() {
            match args[i].as_str() {
                "--testnet" => {
                    network = NetworkProfile::TestnetBeta;
                    i += 1;
                }
                "--mainnet" => {
                    network = NetworkProfile::Mainnet;
                    i += 1;
                }
                "--genesis-beacon" if i + 1 < args.len() => {
                    genesis_btc_hex = Some(args[i + 1].clone());
                    i += 2;
                }
                "--genesis-headline" if i + 1 < args.len() => {
                    genesis_headline = args[i + 1].clone();
                    i += 2;
                }
                "--network" if i + 1 < args.len() => {
                    network = match args[i + 1].as_str() {
                        "testnet" => NetworkProfile::TestnetBeta,
                        "mainnet" => NetworkProfile::Mainnet,
                        "devnet" => NetworkProfile::LocalDevnet,
                        other => {
                            eprintln!(
                                "invalid --network '{other}' (expected testnet|mainnet|devnet)"
                            );
                            process::exit(2);
                        }
                    };
                    i += 2;
                }
                "--bind" if i + 1 < args.len() => {
                    bind_addr = args[i + 1].parse().unwrap_or_else(|e| {
                        eprintln!("invalid --bind address '{}': {e}", args[i + 1]);
                        process::exit(2);
                    });
                    i += 2;
                }
                "--data-dir" if i + 1 < args.len() => {
                    data_dir = PathBuf::from(&args[i + 1]);
                    i += 2;
                }
                "--seed" if i + 1 < args.len() => {
                    let resolved = resolve_peer_endpoint(&args[i + 1]).unwrap_or_else(|e| {
                        eprintln!("invalid --seed '{}': {e}", args[i + 1]);
                        process::exit(2);
                    });
                    seed_peers.extend(resolved);
                    i += 2;
                }
                "--min-quorum-peers" if i + 1 < args.len() => {
                    min_quorum_peers = args[i + 1].parse().unwrap_or_else(|e| {
                        eprintln!("invalid --min-quorum-peers integer '{}': {e}", args[i + 1]);
                        process::exit(2);
                    });
                    i += 2;
                }
                "--epoch-ms" if i + 1 < args.len() => {
                    epoch_ms = args[i + 1].parse().unwrap_or_else(|e| {
                        eprintln!("invalid --epoch-ms integer '{}': {e}", args[i + 1]);
                        process::exit(2);
                    });
                    i += 2;
                }
                "--threads" if i + 1 < args.len() => {
                    let t: usize = args[i + 1].parse().unwrap_or_else(|e| {
                        eprintln!("invalid --threads integer '{}': {e}", args[i + 1]);
                        process::exit(2);
                    });
                    set_ponc_miner_threads(t.max(1));
                    i += 2;
                }
                other => {
                    eprintln!("unknown peer flag: {other}");
                    process::exit(2);
                }
            }
        }

        // Support comma-separated `XCR_SEED_PEERS=host1:9501,host2:9501` for cloud & container setups:
        if let Ok(env_seeds) = env::var("XCR_SEED_PEERS") {
            for entry in env_seeds
                .split(',')
                .map(str::trim)
                .filter(|s| !s.is_empty())
            {
                if let Ok(addrs) = resolve_peer_endpoint(entry) {
                    seed_peers.extend(addrs);
                }
            }
        }
        if network == NetworkProfile::TestnetBeta && seed_peers.is_empty() {
            for &seed in DEFAULT_TESTNET_SEEDS {
                if let Ok(addrs) = resolve_peer_endpoint(seed) {
                    seed_peers.extend(addrs);
                }
            }
        } else if network == NetworkProfile::Mainnet && seed_peers.is_empty() {
            for &seed in DEFAULT_MAINNET_SEEDS {
                if let Ok(addrs) = resolve_peer_endpoint(seed) {
                    seed_peers.extend(addrs);
                }
            }
        }

        if let Ok(env_threads) = env::var("XCR_MINER_THREADS")
            && let Ok(parsed_t) = env_threads.trim().parse::<usize>()
        {
            set_ponc_miner_threads(parsed_t.max(1));
        }
        eprintln!(
            "[PoNC] Active CPU compute threads: {} (proportional difficulty-weighted Share-DAG)",
            current_ponc_miner_threads()
        );
        // holding encrypted peer sessions open and unlocking Epoch 0 automatically at midnight UTC:
        if network == NetworkProfile::Mainnet {
            let now_unix = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0);
            if let GenesisStandbyStatus::StandbyCountdown {
                seconds_remaining, ..
            } = VerifiableGenesisBeacon::evaluate_genesis_standby(now_unix, None, None)
            {
                let days = seconds_remaining / 86_400;
                let hours = (seconds_remaining % 86_400) / 3_600;
                let mins = (seconds_remaining % 3_600) / 60;
                println!(
                    "[STANDBY] Mainnet ({}) armed in Live Standby Mesh — {days}d {hours}h {mins}m until {} (auto-unlocks at 00:00:00 UTC).",
                    network.chain_id(),
                    MAINNET_GENESIS_ISO8601
                );
            }
        }

        let initial_beacon = genesis_btc_hex.map(|hex| (hex, genesis_headline));
        if let Err(err) = run_mesh_peer_with_beacon(
            MeshPeerConfig {
                network,
                bind_addr,
                data_dir,
                seed_peers,
                min_quorum_peers,
                epoch_interval: Duration::from_millis(epoch_ms.max(100)),
            },
            initial_beacon,
        ) {
            eprintln!("credit-node peer exited with error: {err}");
            process::exit(1);
        }
        return;
    }

    if args.first().map(String::as_str) == Some("compact-wal") {
        let mut data_dir = PathBuf::from("./peer-data");
        let mut i = 1usize;
        while i < args.len() {
            match args[i].as_str() {
                "--data-dir" if i + 1 < args.len() => {
                    data_dir = PathBuf::from(&args[i + 1]);
                    i += 2;
                }
                other => {
                    eprintln!("unknown compact-wal flag: {other}");
                    process::exit(2);
                }
            }
        }
        let wal_path = data_dir.join("credit.wal");
        let before_bytes = fs::metadata(&wal_path).map(|m| m.len()).unwrap_or(0);
        let mut ledger = PersistentLedger::open(&wal_path).unwrap_or_else(|e| {
            eprintln!("failed to open {}: {e}", wal_path.display());
            process::exit(1);
        });
        let before_root = ledger.state_merkle_root();
        let epochs = ledger.latest_epoch.0;
        let pockets = ledger.pockets.len();
        let txs = ledger.finalized_txs.len();
        if let Err(e) = ledger.compact_checkpoint() {
            eprintln!("compact_checkpoint failed: {e}");
            process::exit(1);
        }
        drop(ledger);
        let after_bytes = fs::metadata(&wal_path).map(|m| m.len()).unwrap_or(0);
        let verified = PersistentLedger::open(&wal_path).unwrap_or_else(|e| {
            eprintln!("failed to reopen compacted {}: {e}", wal_path.display());
            process::exit(1);
        });
        let after_root = verified.state_merkle_root();
        if before_root != after_root {
            eprintln!("CRITICAL: state_merkle_root mismatch ({before_root} != {after_root})");
            process::exit(1);
        }
        println!("WAL Path          : {}", wal_path.display());
        println!("Settled Epoch     : {epochs}");
        println!("Pockets / Txs     : {pockets} pockets | {txs} finalized txs");
        println!("Compacted Bytes   : {before_bytes} B -> {after_bytes} B");
        println!("Verified Root     : {after_root} (100% lossless match)");
        return;
    }

    if args.first().map(String::as_str) == Some("daemon") {
        let mut bind_addr: SocketAddr = "127.0.0.1:9400".parse().unwrap();
        let mut data_dir = PathBuf::from("./credit-data");

        let mut i = 1usize;
        while i < args.len() {
            match args[i].as_str() {
                "--bind" if i + 1 < args.len() => {
                    bind_addr = args[i + 1].parse().unwrap_or_else(|e| {
                        eprintln!("invalid --bind address '{}': {e}", args[i + 1]);
                        process::exit(2);
                    });
                    i += 2;
                }
                "--data-dir" if i + 1 < args.len() => {
                    data_dir = PathBuf::from(&args[i + 1]);
                    i += 2;
                }
                other => {
                    eprintln!("unknown daemon flag: {other}");
                    process::exit(2);
                }
            }
        }

        if let Err(err) = run_node_daemon(bind_addr, &data_dir) {
            eprintln!("credit-node daemon exited with error: {err}");
            process::exit(1);
        }
        return;
    }

    let report = run_genesis_simulation();

    println!("==========================================================================");
    println!("  Credits (∀ / XCR) — v0.3 Live UDP, 672B Bulletproof & Phase-2 Node");
    println!(
        "  Mainnet Epoch 0 Target: {} ({})",
        MAINNET_GENESIS_ISO8601,
        NetworkProfile::Mainnet.chain_id()
    );
    println!("==========================================================================");
    println!(
        "  [1] Fair Launch Premine          : {} (100% earned from Block 0)",
        report.genesis_premine.format_symbolic()
    );
    println!(
        "  [2] Epoch 0 Share-DAG Minted     : {} across {} pool-free nodes",
        report.epoch0_settlement.minted_emission.format_symbolic(),
        report.epoch0_settlement.payouts.len()
    );
    for (idx, (worker, reward, weight)) in report.epoch0_settlement.payouts.iter().enumerate() {
        println!(
            "      - Worker #{} ({})    : {} (weight={})",
            idx + 1,
            worker,
            reward.format_symbolic(),
            weight
        );
    }
    println!(
        "  [3] Live 4-Socket UDP 1-RTT      : {} us loopback ({} UDP votes, WAN p67={} ms)",
        report.live_udp_quorum_rtt_us,
        report.live_udp_votes_collected,
        report.fast_path_cert.finality_latency_ms
    );
    println!(
        "      - Closed-Loop 70/15/15 Fee     : worker={} (70%) | endurance={} (15%) | burned={} (15%)",
        report.fast_path_cert.fee_split.worker_reward,
        report.fast_path_cert.fee_split.endurance_deposit,
        report.fast_path_cert.fee_split.burned
    );
    println!(
        "  [4] 64-Bit Logarithmic Bulletprf : verified={} ({} B wire, 12.2x smaller)",
        report.bulletproof_verified && report.confidential_range_proof_verified,
        report.bulletproof_64bit_bytes
    );
    println!(
        "  [5] Edge ZK Proof of Innocence   : verified={} (L1 remains 100% unfreezable)",
        report.merchant_zk_verified
    );
    println!(
        "  [6] 3-Round Shared BFT DAG       : committed={}",
        report.bft_3round_committed
    );
    println!(
        "  [7] Phase-2 Basket PID Vault     : target={} -> converged={} (>=200% CR)",
        report.phase2_basket_target_micros, report.phase2_converged_market_micros
    );
    println!(
        "  [8] Vault Emergency Cancel       : restored {} (24h wrench-attack shield)",
        report.vault_restored_balance.format_symbolic()
    );
    println!(
        "  [9] 4-Shard Parallel + Light SDK : {} txs settled | {}B hdr + {}B Merkle verified={}",
        report.sharded_parallel_txs_settled,
        report.mobile_header_bytes,
        report.mobile_account_proof_bytes,
        report.mobile_light_verified
    );
    println!(
        "  [10] Self-Sustaining Longevity   : dormant_revived={} ({}B proof) | >=85% compute_gov={}",
        report.dormant_account_revived,
        report.archive_revival_proof_bytes,
        report.compute_upgrade_ratified
    );
    println!(
        "  [11] Credchip 4-Dot Status       : {}/4 active dots [Pocket · Vault · ZK · Node]",
        report.credchip_status.active_dots()
    );
    println!("==========================================================================");
}
