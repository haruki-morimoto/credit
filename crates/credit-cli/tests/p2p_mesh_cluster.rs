//! Stage-1 **True 4-Process Distributed P2P Mesh & Late-Joiner Catch-Up Integration Test**.
//!
//! Spawns **4 completely independent OS processes** (`Peer 1`, `Peer 2`, `Peer 3`, and late-joining
//! `Peer 4`), each with its own isolated `node_identity.bin`, its own `credit.wal`, and its own UDP
//! socket:
//! 1. `Peer 2` and `Peer 3` dial ONLY `--seed Peer1`, discover each other via Kademlia XOR DHT +
//!    Noise quadruple-DH encrypted handshakes, gossip Epoch-0 PoNC shares, and converge on the
//!    exact same Epoch-1 committee and `state_merkle_root`.
//! 2. `credit-cli` registers Alice's `Pocket` on `Peer 2` (replicated across the encrypted mesh)
//!    and submits a **672-byte 64-bit Logarithmic Bulletproof `FastTransfer`** to `Peer 1`—which
//!    collects real cryptographic quorum votes from `Peer 2` and `Peer 3` over P2P UDP in 1 RTT!
//! 3. `Peer 4` boots up cold **after** Epoch 0 and **after** Alice's payment, dials `--seed Peer2`,
//!    catches up via `SyncRequest`/`SyncResponse`, verifies all PoNC shares + finalized commits into
//!    its own `credit.wal`, and reaches the **bit-identical 32-byte `state_merkle_root`** as Peers 1–3!

use std::env;
use std::fs;
use std::io::{BufRead, BufReader};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdout, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use credit_cli::{
    cli_get_balance, cli_get_status, cli_init_wallet, cli_send_bulletproof_payment,
    cli_shutdown_daemon, cli_verify_light_balance,
};
use credit_net::NodeRpcResponse;
use credit_node::{MeshPeerConfig, run_mesh_peer};
use credit_types::{Amount, EpochId, Hash32};

const ENV_PEER_DATADIR: &str = "XCR_TEST_MESH_DATADIR";
const ENV_PEER_SEED: &str = "XCR_TEST_MESH_SEED";
const ENV_PEER_MIN_QUORUM: &str = "XCR_TEST_MESH_MIN_QUORUM";
const ENV_PEER_EPOCH_MS: &str = "XCR_TEST_MESH_EPOCH_MS";

struct RunningPeer {
    child: Option<Child>,
    _stdout_guard: Option<BufReader<ChildStdout>>,
    pub addr: SocketAddr,
}

impl RunningPeer {
    fn shutdown_and_wait(mut self) {
        let _ = cli_shutdown_daemon(self.addr);
        if let Some(mut c) = self.child.take() {
            let status = c.wait().expect("wait for peer process exit");
            assert!(status.success(), "peer process exited cleanly");
        }
    }
}

impl Drop for RunningPeer {
    fn drop(&mut self) {
        if let Some(mut c) = self.child.take() {
            let _ = c.kill();
            let _ = c.wait();
        }
    }
}

fn spawn_mesh_peer_process(
    data_dir: &Path,
    seed: Option<SocketAddr>,
    min_quorum_peers: usize,
) -> RunningPeer {
    spawn_mesh_peer_with_epoch_ms(data_dir, seed, min_quorum_peers, 60_000)
}

fn spawn_mesh_peer_with_epoch_ms(
    data_dir: &Path,
    seed: Option<SocketAddr>,
    min_quorum_peers: usize,
    epoch_ms: u64,
) -> RunningPeer {
    let exe = env::current_exe().expect("locate test binary");
    let mut cmd = Command::new(exe);
    cmd.arg("--exact")
        .arg("four_process_encrypted_p2p_mesh_quorum_and_late_joiner_sync")
        .arg("--nocapture")
        .env(ENV_PEER_DATADIR, data_dir.as_os_str())
        .env(ENV_PEER_MIN_QUORUM, min_quorum_peers.to_string())
        .env(ENV_PEER_EPOCH_MS, epoch_ms.to_string())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit());

    if let Some(seed_addr) = seed {
        cmd.env(ENV_PEER_SEED, seed_addr.to_string());
    }

    let mut child = cmd.spawn().expect("spawn mesh peer OS process");
    let stdout = child.stdout.take().expect("capture peer stdout");
    let mut peer = RunningPeer {
        child: Some(child),
        _stdout_guard: None,
        addr: "127.0.0.1:0".parse().unwrap(),
    };
    let mut reader = BufReader::new(stdout);
    let mut line = String::new();
    loop {
        line.clear();
        let n = reader.read_line(&mut line).expect("read peer READY line");
        assert!(n > 0, "mesh peer exited before READY");
        if let Some(rest) = line.trim().strip_prefix("READY bind=") {
            let addr_str = rest.split_whitespace().next().expect("extract bind addr");
            peer.addr = addr_str.parse().expect("parse bind SocketAddr");
            peer._stdout_guard = Some(reader);
            return peer;
        }
    }
}

fn wait_for_epoch_and_root(
    node_addr: SocketAddr,
    expected_epoch: EpochId,
    expected_txs: u64,
) -> Hash32 {
    let deadline = Instant::now() + Duration::from_secs(8);
    while Instant::now() < deadline {
        if let Ok(NodeRpcResponse::Status {
            epoch,
            finalized_tx_count,
            state_root,
            ..
        }) = cli_get_status(node_addr)
            && epoch == expected_epoch
            && finalized_tx_count == expected_txs
        {
            return state_root;
        }
        thread::sleep(Duration::from_millis(40));
    }
    panic!(
        "node {node_addr} did not converge to epoch {:?} / txs {} within timeout",
        expected_epoch, expected_txs
    );
}

#[test]
fn four_process_encrypted_p2p_mesh_quorum_and_late_joiner_sync() {
    // Child OS process entry point when spawned as an isolated P2P mesh peer:
    if let Ok(dir_str) = env::var(ENV_PEER_DATADIR) {
        let seed_peers = env::var(ENV_PEER_SEED)
            .ok()
            .map(|s| vec![s.parse::<SocketAddr>().expect("valid seed addr")])
            .unwrap_or_default();
        let min_quorum_peers: usize = env::var(ENV_PEER_MIN_QUORUM)
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(3);
        let epoch_ms: u64 = env::var(ENV_PEER_EPOCH_MS)
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(60_000);
        let bind_addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
        run_mesh_peer(MeshPeerConfig {
            network: credit_node::NetworkProfile::TestnetBeta,
            bind_addr,
            data_dir: PathBuf::from(dir_str),
            seed_peers,
            min_quorum_peers,
            epoch_interval: Duration::from_millis(epoch_ms),
        })
        .expect("run mesh peer process");
        return;
    }

    let mut base_dir = env::temp_dir();
    base_dir.push(format!("xcr_stage1_mesh_{}", std::process::id()));
    let _ = fs::remove_dir_all(&base_dir);
    fs::create_dir_all(&base_dir).unwrap();

    // 1. Boot 3 completely separate P2P validator processes (Peer 2 & Peer 3 only know Peer 1!):
    let peer1 = spawn_mesh_peer_process(&base_dir.join("peer1"), None, 3);
    let peer2 = spawn_mesh_peer_process(&base_dir.join("peer2"), Some(peer1.addr), 3);
    let peer3 = spawn_mesh_peer_process(&base_dir.join("peer3"), Some(peer1.addr), 3);

    // Wait for all 3 independent processes to complete Noise X25519 handshakes, DHT discovery,
    // Epoch-0 PoNC Share-DAG gossip, and Epoch-1 committee election:
    let root1_e0 = wait_for_epoch_and_root(peer1.addr, EpochId(1), 0);
    let root2_e0 = wait_for_epoch_and_root(peer2.addr, EpochId(1), 0);
    let root3_e0 = wait_for_epoch_and_root(peer3.addr, EpochId(1), 0);
    assert_eq!(root1_e0, root2_e0);
    assert_eq!(root2_e0, root3_e0);

    // 2. Register Alice's `Spending Pocket` on Peer 2 — verify it replicates across the encrypted mesh!
    let wallet_path = base_dir.join("alice_mesh.wallet");
    let (alice_addr, _) = cli_init_wallet(&wallet_path, [0x7a; 32], peer2.addr).unwrap();

    // Wait until both Peer 1 and Peer 3 receive the gossiped Pocket registration:
    for (label, target_peer) in [("Peer 1", peer1.addr), ("Peer 3", peer3.addr)] {
        let pocket_deadline = Instant::now() + Duration::from_secs(8);
        loop {
            if let Ok((_, NodeRpcResponse::PocketInfo { found: true, .. })) =
                cli_get_balance(&wallet_path, target_peer)
            {
                break;
            }
            assert!(
                Instant::now() < pocket_deadline,
                "Pocket gossip did not reach {label}"
            );
            thread::sleep(Duration::from_millis(30));
        }
    }

    // 3. Submit a 672-byte 64-bit Bulletproof `FastTransfer` to Peer 1 -> co-signed across Peer 1, 2, 3!
    let pay_receipt = cli_send_bulletproof_payment(
        &wallet_path,
        b"global-merchant-tokyo",
        Amount::from_chips(750).unwrap(), // 7.500000 XCR
        Amount::from_bits(1_000),         // 0.001000 XCR micro-fee (700 worker / 300 burned)
        peer1.addr,
    )
    .unwrap();

    let NodeRpcResponse::FastPayReceipt {
        accepted,
        fee_worker,
        fee_burned,
        new_state_root: finalized_root_p1,
        message,
        ..
    } = pay_receipt
    else {
        panic!("expected FastPayReceipt from Peer 1");
    };
    assert!(
        accepted,
        "distributed P2P quorum rejected 672B Bulletproof payment: {message}"
    );
    assert_eq!(fee_worker, Amount::from_bits(700));
    assert_eq!(fee_burned, Amount::from_bits(150)); // 700 worker / 150 endurance / 150 burned

    // Verify Peer 2 and Peer 3 independently committed `FinalityCommit` to their own WALs:
    let finalized_root_p2 = wait_for_epoch_and_root(peer2.addr, EpochId(1), 1);
    let finalized_root_p3 = wait_for_epoch_and_root(peer3.addr, EpochId(1), 1);
    assert_eq!(finalized_root_p1, finalized_root_p2);
    assert_eq!(finalized_root_p2, finalized_root_p3);

    // 4. Boot Late-Joining Laptop `Peer 4` pointed ONLY at `Peer 2` — verify full catch-up sync!
    let peer4 = spawn_mesh_peer_process(&base_dir.join("peer4"), Some(peer2.addr), 3);
    let synced_root_p4 = wait_for_epoch_and_root(peer4.addr, EpochId(1), 1);
    assert_eq!(synced_root_p4, finalized_root_p1);

    let (queried_addr, bal_on_peer4) = cli_get_balance(&wallet_path, peer4.addr).unwrap();
    assert_eq!(queried_addr, alice_addr);
    assert_eq!(
        bal_on_peer4,
        NodeRpcResponse::PocketInfo {
            found: true,
            balance: Amount::from_bits(12_499_000), // 20.000000 - 7.500000 - 0.001000 XCR
            nonce: 1,
            daily_limit: Amount::from_credits(25).unwrap(),
        }
    );

    // Trustlessly verify Alice's balance on late-joining Peer 4 via compact Merkle inclusion proof:
    let (verified_addr, verified_bal, verified_nonce, proof_len, _) =
        cli_verify_light_balance(&wallet_path, peer4.addr).unwrap();
    assert_eq!(verified_addr, alice_addr);
    assert_eq!(verified_bal, Amount::from_bits(12_499_000));
    assert_eq!(verified_nonce, 1);
    assert!(proof_len < 256);

    // Cleanly shut down all 4 independent OS node processes:
    peer4.shutdown_and_wait();
    peer3.shutdown_and_wait();
    peer2.shutdown_and_wait();
    peer1.shutdown_and_wait();

    let _ = fs::remove_dir_all(&base_dir);
}

#[test]
fn continuous_multi_epoch_mining_miner_wallet_spend_and_1200b_mtu_wan_sync() {
    if env::var(ENV_PEER_DATADIR).is_ok() {
        return;
    }

    let mut base_dir = env::temp_dir();
    base_dir.push(format!("xcr_multiepoch_mtu_{}", std::process::id()));
    let _ = fs::remove_dir_all(&base_dir);
    fs::create_dir_all(&base_dir).unwrap();

    // 1. Boot 3 peers with fast 700ms continuous epochs (`Epoch 0 -> 1 -> 2 -> 3...`):
    let p1_dir = base_dir.join("peer1");
    let p2_dir = base_dir.join("peer2");
    let p3_dir = base_dir.join("peer3");
    let peer1 = spawn_mesh_peer_with_epoch_ms(&p1_dir, None, 3, 700);
    let peer2 = spawn_mesh_peer_with_epoch_ms(&p2_dir, Some(peer1.addr), 3, 700);
    let peer3 = spawn_mesh_peer_with_epoch_ms(&p3_dir, Some(peer1.addr), 3, 700);

    // Wait until the cluster autonomously advances past Epoch 3 (>= 300 XCR earned across 3 epochs!):
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        if let (
            Ok(NodeRpcResponse::Status {
                epoch: e1,
                circulating_supply: sup1,
                ..
            }),
            Ok(NodeRpcResponse::Status { epoch: e2, .. }),
            Ok(NodeRpcResponse::Status { epoch: e3, .. }),
        ) = (
            cli_get_status(peer1.addr),
            cli_get_status(peer2.addr),
            cli_get_status(peer3.addr),
        ) && e1.0 >= 3
            && e2.0 >= 3
            && e3.0 >= 3
            && sup1 >= Amount::from_credits(300).unwrap()
        {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "cluster did not advance past Epoch 3 within timeout"
        );
        thread::sleep(Duration::from_millis(50));
    }

    // 2. Verify Peer 1's auto-generated `miner.wallet` earned real PoNC rewards and can spend them
    //    directly via 1-RTT 672-byte Bulletproof FastTransfer (zero faucet / zero init-wallet!):
    let miner1_wallet = p1_dir.join("miner.wallet");
    assert!(miner1_wallet.exists());
    let (_, miner_info) = cli_get_balance(&miner1_wallet, peer1.addr).unwrap();
    let NodeRpcResponse::PocketInfo {
        found: true,
        balance: mined_balance,
        ..
    } = miner_info
    else {
        panic!("expected funded miner.wallet Pocket");
    };
    assert!(mined_balance >= Amount::from_credits(95).unwrap());

    let pay_resp = cli_send_bulletproof_payment(
        &miner1_wallet,
        b"coffee-earned-by-cpu",
        Amount::from_credits(15).unwrap(),
        Amount::from_bits(1_000),
        peer1.addr,
    )
    .unwrap();
    assert!(matches!(
        pay_resp,
        NodeRpcResponse::FastPayReceipt { accepted: true, .. }
    ));

    // 3. Register 80 additional accounts (> 9,000 bytes of state — ~8x larger than 1,200B WAN MTU)
    //    so late-joining Peer 4 must stream state across ~10+ MTU-bounded encrypted sync chunks:
    for idx in 0u8..80 {
        let w_path = base_dir.join(format!("acct_{idx}.wallet"));
        let mut seed = [0u8; 32];
        seed[0] = idx;
        seed[1] = 0x5a;
        let _ = cli_init_wallet(&w_path, seed, peer1.addr).unwrap();
    }

    // Pause further epoch rotation on late-joiner by giving Peer 4 a 60s interval and syncing from Peer 1:
    let peer4 = spawn_mesh_peer_with_epoch_ms(&base_dir.join("peer4"), Some(peer1.addr), 3, 60_000);
    let sync_deadline = Instant::now() + Duration::from_secs(12);
    loop {
        if let (
            Ok(NodeRpcResponse::Status {
                epoch: e1,
                state_root: r1,
                ..
            }),
            Ok(NodeRpcResponse::Status {
                epoch: e4,
                state_root: r4,
                ..
            }),
        ) = (cli_get_status(peer1.addr), cli_get_status(peer4.addr))
            && e4 >= EpochId(3)
            && e1 == e4
            && r1 == r4
        {
            break;
        }
        assert!(
            Instant::now() < sync_deadline,
            "Peer 4 did not complete multi-page <1,200B WAN sync with Peer 1"
        );
        thread::sleep(Duration::from_millis(50));
    }

    // Verify the 80th account synced cleanly onto Peer 4 across the paged <1,200B chunks:
    let last_wallet = base_dir.join("acct_79.wallet");
    let (_, bal_79) = cli_get_balance(&last_wallet, peer4.addr).unwrap();
    assert!(matches!(
        bal_79,
        NodeRpcResponse::PocketInfo { found: true, .. }
    ));

    peer4.shutdown_and_wait();
    peer3.shutdown_and_wait();
    peer2.shutdown_and_wait();
    peer1.shutdown_and_wait();
    let _ = fs::remove_dir_all(&base_dir);
}
