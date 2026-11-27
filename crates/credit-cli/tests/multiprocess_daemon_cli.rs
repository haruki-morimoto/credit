//! Multi-Process End-to-End Integration Test:
//! Spawns a real OS child daemon process (`credit-node daemon`), executes `credit-cli` UDP
//! operations (including a 672-byte 64-bit Logarithmic Bulletproof `FastTransfer`), shuts down
//! the daemon process, spawns a SECOND OS daemon process over the same disk WAL directory, and
//! verifies bit-identical crash-safe state persistence across OS process restarts.

use std::env;
use std::fs;
use std::io::{BufRead, BufReader};
use std::net::SocketAddr;
use std::path::Path;
use std::process::{Child, Command, Stdio};

use credit_cli::{
    cli_get_balance, cli_get_status, cli_init_wallet, cli_scan_and_claim_stealth,
    cli_send_bulletproof_payment, cli_shutdown_daemon, cli_stealth_address, save_wallet_seed,
};
use credit_net::NodeRpcResponse;
use credit_node::run_node_daemon;
use credit_types::Amount;

const CHILD_DAEMON_ENV: &str = "XCR_TEST_CHILD_DAEMON_DATADIR";

struct DaemonGuard {
    child: Option<Child>,
    _stdout_guard: Option<BufReader<std::process::ChildStdout>>,
    addr: SocketAddr,
}

impl DaemonGuard {
    fn wait_clean_exit(mut self) {
        if let Some(mut c) = self.child.take() {
            assert!(c.wait().unwrap().success());
        }
    }
}

impl Drop for DaemonGuard {
    fn drop(&mut self) {
        if let Some(mut c) = self.child.take() {
            let _ = c.kill();
            let _ = c.wait();
        }
    }
}

fn spawn_daemon_child(data_dir: &Path) -> DaemonGuard {
    let exe = env::current_exe().expect("locate current test executable");
    let mut child = Command::new(exe)
        .arg("--exact")
        .arg("multiprocess_daemon_cli_bulletproof_pay_and_wal_restart")
        .arg("--nocapture")
        .env(CHILD_DAEMON_ENV, data_dir.as_os_str())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .expect("spawn child daemon OS process");

    let stdout = child.stdout.take().expect("capture child stdout");
    let mut guard = DaemonGuard {
        child: Some(child),
        _stdout_guard: None,
        addr: "127.0.0.1:0".parse().unwrap(),
    };
    let mut reader = BufReader::new(stdout);
    let mut line = String::new();
    loop {
        line.clear();
        let n = reader
            .read_line(&mut line)
            .expect("read READY line from child daemon");
        assert!(n > 0, "daemon child exited before printing READY");
        if let Some(rest) = line.trim().strip_prefix("READY bind=") {
            let bind_str = rest
                .split_whitespace()
                .next()
                .expect("parse bind socket address");
            guard.addr = bind_str.parse().expect("valid SocketAddr");
            guard._stdout_guard = Some(reader);
            return guard;
        }
    }
}

#[test]
fn multiprocess_daemon_cli_bulletproof_pay_and_wal_restart() {
    // Entry hook when spawned as the isolated child daemon OS process:
    if let Ok(data_dir_str) = env::var(CHILD_DAEMON_ENV) {
        let bind_ephemeral: SocketAddr = "127.0.0.1:0".parse().unwrap();
        run_node_daemon(bind_ephemeral, Path::new(&data_dir_str))
            .expect("child daemon run cleanly");
        return;
    }

    let mut temp_dir = env::temp_dir();
    temp_dir.push(format!("xcr_multiproc_wal_{}", std::process::id()));
    let _ = fs::remove_dir_all(&temp_dir);
    fs::create_dir_all(&temp_dir).unwrap();
    let wallet_file = temp_dir.join("alice.wallet");

    let post_payment_root;

    // --- OS Process #1: Fresh Genesis Boot, Wallet Registration, & 672B Bulletproof Payment ---
    {
        let daemon_1 = spawn_daemon_child(&temp_dir);
        let node_addr = daemon_1.addr;

        let NodeRpcResponse::Status {
            circulating_supply,
            finalized_tx_count,
            ..
        } = cli_get_status(node_addr).unwrap()
        else {
            panic!("expected Status response");
        };
        assert_eq!(circulating_supply, Amount::from_credits(100).unwrap());
        assert_eq!(finalized_tx_count, 0);

        let (alice_addr, init_resp) = cli_init_wallet(&wallet_file, [0x55; 32], node_addr).unwrap();
        assert!(matches!(
            init_resp,
            NodeRpcResponse::PocketInfo {
                found: true,
                nonce: 0,
                ..
            }
        ));

        // Send `4.950000 XCR` + `0.000500 XCR` micro-fee backed by a 672-byte 64-bit Bulletproof:
        let pay_resp = cli_send_bulletproof_payment(
            &wallet_file,
            b"coffee-merchant-01",
            Amount::from_chips(495).unwrap(),
            Amount::from_bits(500),
            node_addr,
        )
        .unwrap();

        let NodeRpcResponse::FastPayReceipt {
            accepted,
            fee_worker,
            fee_burned,
            new_state_root,
            ..
        } = pay_resp
        else {
            panic!("expected FastPayReceipt");
        };
        assert!(accepted);
        assert_eq!(fee_worker, Amount::from_bits(350));
        assert_eq!(fee_burned, Amount::from_bits(75)); // 70% worker (350) / 15% endurance (75) / 15% burned (75)
        post_payment_root = new_state_root;

        let (queried_addr, bal_resp) = cli_get_balance(&wallet_file, node_addr).unwrap();
        assert_eq!(queried_addr, alice_addr);
        assert_eq!(
            bal_resp,
            NodeRpcResponse::PocketInfo {
                found: true,
                balance: Amount::from_bits(15_049_500), // 20.000000 - 4.950000 - 0.000500 XCR
                nonce: 1,
                daily_limit: Amount::from_credits(25).unwrap(),
            }
        );

        assert_eq!(
            cli_shutdown_daemon(node_addr).unwrap(),
            NodeRpcResponse::AckShutdown
        );
        daemon_1.wait_clean_exit();
    }

    // --- OS Process #2: Cold Restart Over Existing `credit.wal` ---
    {
        let daemon_2 = spawn_daemon_child(&temp_dir);
        let node_addr_2 = daemon_2.addr;

        let NodeRpcResponse::Status {
            circulating_supply,
            total_burned,
            finalized_tx_count,
            state_root,
            ..
        } = cli_get_status(node_addr_2).unwrap()
        else {
            panic!("expected Status response after WAL restart");
        };
        assert_eq!(finalized_tx_count, 1);
        assert_eq!(total_burned, Amount::from_bits(75));
        assert_eq!(circulating_supply, Amount::from_bits(99_999_925));
        assert_eq!(state_root, post_payment_root);

        let (_, bal_resp_2) = cli_get_balance(&wallet_file, node_addr_2).unwrap();
        assert_eq!(
            bal_resp_2,
            NodeRpcResponse::PocketInfo {
                found: true,
                balance: Amount::from_bits(15_049_500),
                nonce: 1,
                daily_limit: Amount::from_credits(25).unwrap(),
            }
        );

        // End-to-end Stealth URI receive, 1-byte view-tag scan, unlinkability, & Schnorr claim:
        let bob_wallet = temp_dir.join("bob.wallet");
        let carol_wallet = temp_dir.join("carol.wallet");
        save_wallet_seed(&bob_wallet, &[0x77; 32]).unwrap();
        save_wallet_seed(&carol_wallet, &[0x88; 32]).unwrap();
        let (_, bob_stealth_uri) = cli_stealth_address(&bob_wallet).unwrap();
        assert!(bob_stealth_uri.starts_with("xcrstealth1_"));

        let stealth_pay = cli_send_bulletproof_payment(
            &wallet_file,
            bob_stealth_uri.as_bytes(),
            Amount::from_chips(300).unwrap(), // 3.000000 XCR
            Amount::from_bits(500),
            node_addr_2,
        )
        .unwrap();
        assert!(matches!(
            stealth_pay,
            NodeRpcResponse::FastPayReceipt { accepted: true, .. }
        ));

        // Unrelated Carol sees 0 owned outputs via 1-byte view-tag filter:
        let (_, carol_matches) =
            cli_scan_and_claim_stealth(&carol_wallet, node_addr_2, false).unwrap();
        assert!(carol_matches.is_empty());

        // Bob scans & claims via Curve25519 Schnorr spend-key proof into Bob's Pocket:
        let (_, bob_claimed) = cli_scan_and_claim_stealth(&bob_wallet, node_addr_2, true).unwrap();
        assert_eq!(bob_claimed.len(), 1);
        assert!(bob_claimed[0].2);
        assert_eq!(bob_claimed[0].1, Amount::from_bits(2_999_990)); // 3.000000 - MIN_BASE_FEE_BITS (10)

        let (_, bob_bal) = cli_get_balance(&bob_wallet, node_addr_2).unwrap();
        assert!(matches!(
            bob_bal,
            NodeRpcResponse::PocketInfo {
                found: true,
                balance,
                ..
            } if balance == Amount::from_bits(2_999_990)
        ));

        assert_eq!(
            cli_shutdown_daemon(node_addr_2).unwrap(),
            NodeRpcResponse::AckShutdown
        );
        daemon_2.wait_clean_exit();
    }

    let _ = fs::remove_dir_all(&temp_dir);
}
