//! Standalone WAL-Backed Multi-Process UDP Node Daemon (`credit-node daemon`).
//!
//! - Recovers or initializes `PersistentLedger` (`credit.wal`) on startup.
//! - If starting from a fresh Genesis WAL, mines Epoch 0 PoNC Share-DAG shares (`0 XCR` premine ->
//!   `100.000000 XCR` fair-launch worker rewards) and persists them to disk.
//! - Verifies incoming 672-byte 64-bit `BulletproofRange64` range proofs, executes 1-RTT quorum
//!   settlement, journals `WalRecord::RecordFastFinality` (`fsync`), and replies over UDP.

use std::collections::BTreeMap;
use std::io::{self, Write};
use std::net::SocketAddr;
use std::path::Path;
use std::time::Duration;

use credit_consensus::{FastPathEngine, QuorumCommittee};
use credit_crypto::{Keypair, SignatureScheme, domain_hash, verify_stealth_claim};
use credit_net::{ChannelTag, NodeRpcRequest, NodeRpcResponse, UdpQuicEndpoint, WireFrame};
use credit_ponc::{ComputeShare, EpochShareDag, PoncVmConfig};
use credit_storage::{PersistentLedger, WalRecord};
use credit_types::{
    Address, Amount, EpochId, FeeSplit, MIN_BASE_FEE_BITS, PocketState, TransactionKind,
};
use credit_zk::{BulletproofRange64, PedersenCommitment};

use crate::build_light_account_proof;

/// Runs the persistent UDP node daemon until a `ShutdownDaemon` RPC or fatal socket error occurs.
pub fn run_node_daemon(bind_addr: SocketAddr, data_dir: &Path) -> io::Result<()> {
    let wal_path = data_dir.join("credit.wal");
    let mut ledger = PersistentLedger::open(&wal_path)?;

    // Deterministic validator quorum keys for local devnet / daemon operation:
    let v1 = Keypair::from_seed(SignatureScheme::Ed25519, [0x11; 32]);
    let v2 = Keypair::from_seed(SignatureScheme::Ed25519, [0x22; 32]);
    let v3 = Keypair::from_seed(SignatureScheme::Ed25519, [0x33; 32]);
    let v4 = Keypair::from_seed(SignatureScheme::Ed25519, [0x44; 32]);
    let primary_validator = v1.address();

    let vm_cfg = PoncVmConfig::devnet_profile();
    let epoch0_seed = domain_hash("XCR.DAEMON.GENESIS.V1", &[b"Credits-Daemon-Epoch-0"]);
    let mut dag = EpochShareDag::new(EpochId(0), epoch0_seed, 3, vm_cfg);
    for (idx, addr) in [v1.address(), v2.address(), v3.address(), v4.address()]
        .into_iter()
        .enumerate()
    {
        let parents = dag.tip_ids(2);
        let share = ComputeShare::mine_cpu_share(
            EpochId(0),
            &epoch0_seed,
            addr,
            parents,
            (idx as u64) * 100,
            3,
            &vm_cfg,
        );
        dag.submit_share(share).expect("valid daemon genesis share");
    }
    let epoch0_settlement = dag.settle_epoch(Amount::ZERO);

    // Persist Epoch 0 PoNC settlement on first boot ONLY (replayed from WAL on subsequent restarts!):
    if ledger.circulating_supply.is_zero() && ledger.finalized_txs.is_empty() {
        let payouts = epoch0_settlement
            .payouts
            .iter()
            .map(|&(a, amt, _)| (a, amt))
            .collect();
        ledger.append(WalRecord::RecordEpochSettlement {
            epoch: EpochId(0),
            minted_emission: epoch0_settlement.minted_emission,
            worker_fees: Amount::ZERO,
            burned_fees: Amount::ZERO,
            payouts,
        })?;
    }

    let directory = vec![
        (v1.address(), v1.public_key(), 145u16),
        (v2.address(), v2.public_key(), 165u16),
        (v3.address(), v3.public_key(), 180u16),
        (v4.address(), v4.public_key(), 220u16),
    ];
    let committee =
        QuorumCommittee::elect_from_settlement(EpochId(1), &epoch0_settlement, &directory);
    let mut fast_engine = FastPathEngine::new(committee);
    // Rehydrate all persisted `Spending Pocket` accounts from the WAL!
    for stored in ledger.pockets.values() {
        fast_engine.register_pocket(stored.public_key, stored.state.clone());
    }

    let mut quorum_signers = vec![
        (v1.address(), v1),
        (v2.address(), v2),
        (v3.address(), v3),
        (v4.address(), v4),
    ];

    let mut endpoint = UdpQuicEndpoint::bind(bind_addr, 0xdaee_0001, Duration::from_millis(250))?;
    let actual_addr = endpoint.local_addr();
    let mut stealth_announcements: BTreeMap<Address, ([u8; 32], u8)> = BTreeMap::new();
    let mut stealth_memos: BTreeMap<Address, Vec<u8>> = BTreeMap::new();
    let mut swap_offers: BTreeMap<credit_types::Hash32, Vec<u8>> = BTreeMap::new();
    let mut unsettled_fee_bits: i64 = 0;

    println!(
        "READY bind={} state_root={} supply={}",
        actual_addr,
        ledger.state_merkle_root(),
        ledger.circulating_supply
    );
    io::stdout().flush()?;

    loop {
        let (peer, pkt) = match endpoint.recv_packet() {
            Ok(pair) => pair,
            Err(e)
                if e.kind() == io::ErrorKind::WouldBlock || e.kind() == io::ErrorKind::TimedOut =>
            {
                continue;
            }
            Err(e) => return Err(e),
        };

        let Some(frame) = pkt.frame else {
            continue;
        };
        if frame.channel != ChannelTag::ClientRpcRequest {
            continue;
        }
        let Some(req) = NodeRpcRequest::decode(&frame.payload) else {
            let reply = NodeRpcResponse::Error("invalid RPC payload".to_owned());
            let _ = send_rpc_reply(&mut endpoint, peer, &reply);
            continue;
        };

        let mut should_exit = false;
        let response = match req {
            NodeRpcRequest::GetStatus => NodeRpcResponse::Status {
                epoch: ledger.latest_epoch,
                circulating_supply: ledger.circulating_supply,
                total_burned: ledger.total_burned,
                finalized_tx_count: ledger.finalized_txs.len() as u64,
                state_root: ledger.state_merkle_root(),
                validator_address: primary_validator,
            },
            NodeRpcRequest::GetNetworkTelemetry => NodeRpcResponse::NetworkTelemetry {
                epoch: ledger.latest_epoch,
                circulating_supply: ledger.circulating_supply,
                total_burned: ledger.total_burned,
                finalized_tx_count: ledger.finalized_txs.len() as u64,
                state_root: ledger.state_merkle_root(),
                validator_address: primary_validator,
                connected_peers: 3,
                active_miners: 4,
            },
            NodeRpcRequest::RegisterPocket {
                address,
                public_key,
                grant_from_miner,
                daily_limit,
            } => {
                if public_key.to_address() != address {
                    NodeRpcResponse::Error("address does not match public_key".to_owned())
                } else if let Some(existing) = ledger.pockets.get(&address) {
                    NodeRpcResponse::PocketInfo {
                        found: true,
                        balance: existing.state.balance,
                        nonce: existing.state.nonce,
                        daily_limit: existing.state.daily_limit,
                    }
                } else {
                    let state = PocketState::new(grant_from_miner, daily_limit);
                    ledger.append(WalRecord::UpsertPocket {
                        address,
                        public_key,
                        state: state.clone(),
                    })?;
                    fast_engine.register_pocket(public_key, state.clone());
                    NodeRpcResponse::PocketInfo {
                        found: true,
                        balance: state.balance,
                        nonce: state.nonce,
                        daily_limit: state.daily_limit,
                    }
                }
            }
            NodeRpcRequest::GetPocket { address } => match ledger.pockets.get(&address) {
                Some(sp) => NodeRpcResponse::PocketInfo {
                    found: true,
                    balance: sp.state.balance,
                    nonce: sp.state.nonce,
                    daily_limit: sp.state.daily_limit,
                },
                None => NodeRpcResponse::PocketInfo {
                    found: false,
                    balance: Amount::ZERO,
                    nonce: 0,
                    daily_limit: Amount::ZERO,
                },
            },
            NodeRpcRequest::SubmitBulletproofFastPay {
                tx,
                value_commitment,
                bulletproof_672,
            } => {
                let commitment_matches = match &tx.kind {
                    TransactionKind::FastTransfer { commitment, .. } => {
                        *commitment == domain_hash("XCR.CLI.COMMIT_TAG.V1", &[&value_commitment])
                    }
                    _ => false,
                };
                // 1. Verify commitment binding + compact 672-byte 64-bit Logarithmic Bulletproof!
                let v_commit = PedersenCommitment::from_bytes(&value_commitment);
                let bp = BulletproofRange64::from_bytes(&bulletproof_672, 64);
                let bp_ok = commitment_matches
                    && match (v_commit, bp) {
                        (Some(vc), Some(proof)) => proof.verify(&vc, 64),
                        _ => false,
                    };
                if !bp_ok {
                    NodeRpcResponse::FastPayReceipt {
                        accepted: false,
                        tx_id: tx.id,
                        finality_latency_ms: 0,
                        fee_worker: Amount::ZERO,
                        fee_burned: Amount::ZERO,
                        new_state_root: ledger.state_merkle_root(),
                        message: "rejected: invalid 64-bit BulletproofRange64".to_owned(),
                    }
                } else if ledger.finalized_txs.contains(&tx.id) {
                    NodeRpcResponse::FastPayReceipt {
                        accepted: false,
                        tx_id: tx.id,
                        finality_latency_ms: 0,
                        fee_worker: Amount::ZERO,
                        fee_burned: Amount::ZERO,
                        new_state_root: ledger.state_merkle_root(),
                        message: "rejected: duplicate transaction replay".to_owned(),
                    }
                } else {
                    match fast_engine.execute_1rtt_transfer(&tx, &mut quorum_signers, 1) {
                        Ok(cert) => {
                            let TransactionKind::FastTransfer {
                                from,
                                to_stealth,
                                amount,
                                innocence_nullifier,
                                ..
                            } = &tx.kind
                            else {
                                unreachable!()
                            };
                            let updated_pocket = fast_engine
                                .pocket_state(from)
                                .expect("registered pocket exists")
                                .clone();
                            ledger.append(WalRecord::RecordFastFinality {
                                tx_id: tx.id,
                                sender: *from,
                                new_nonce: updated_pocket.nonce,
                                new_balance: updated_pocket.balance,
                                new_daily_spent: updated_pocket.daily_spent,
                                day_index: updated_pocket.current_day,
                                recipient_stealth: *to_stealth,
                                stealth_amount: *amount,
                                fee_worker: cert.fee_split.worker_reward,
                                fee_burned: cert.fee_split.burned,
                                nullifier: *innocence_nullifier,
                            })?;
                            NodeRpcResponse::FastPayReceipt {
                                accepted: true,
                                tx_id: tx.id,
                                finality_latency_ms: cert.finality_latency_ms,
                                fee_worker: cert.fee_split.worker_reward,
                                fee_burned: cert.fee_split.burned,
                                new_state_root: ledger.state_merkle_root(),
                                message: "1-RTT finalized + persisted to WAL".to_owned(),
                            }
                        }
                        Err(err) => NodeRpcResponse::FastPayReceipt {
                            accepted: false,
                            tx_id: tx.id,
                            finality_latency_ms: 0,
                            fee_worker: Amount::ZERO,
                            fee_burned: Amount::ZERO,
                            new_state_root: ledger.state_merkle_root(),
                            message: format!("consensus rejected: {err:?}"),
                        },
                    }
                }
            }
            NodeRpcRequest::GetLightAccountProof { address } => {
                build_light_account_proof(&ledger, &address)
            }
            NodeRpcRequest::ShutdownDaemon => {
                should_exit = true;
                NodeRpcResponse::AckShutdown
            }
            NodeRpcRequest::UnlockMainnetGenesis { .. } => {
                NodeRpcResponse::Error("daemon runs in local devnet mode".to_owned())
            }
            NodeRpcRequest::AnnounceStealthOutput {
                one_time_address,
                ephemeral_pub,
                view_tag,
            } => {
                if ledger
                    .stealth_utxos
                    .get(&one_time_address)
                    .is_some_and(|a| !a.is_zero())
                {
                    stealth_announcements.insert(one_time_address, (ephemeral_pub, view_tag));
                }
                NodeRpcResponse::AckStealthAnnounce
            }
            NodeRpcRequest::GetStealthOutputs => {
                let mut outputs = Vec::new();
                for (&addr, &amt) in &ledger.stealth_utxos {
                    if !amt.is_zero()
                        && let Some(&(eph, vt)) = stealth_announcements.get(&addr)
                    {
                        outputs.push((addr, amt, eph, vt));
                        if outputs.len() >= 32 {
                            break;
                        }
                    }
                }
                NodeRpcResponse::StealthOutputs { outputs }
            }
            NodeRpcRequest::AnnounceStealthOutputV2 {
                one_time_address,
                ephemeral_pub,
                view_tag,
                encrypted_memo,
            } => {
                if ledger
                    .stealth_utxos
                    .get(&one_time_address)
                    .is_some_and(|a| !a.is_zero())
                {
                    stealth_announcements.insert(one_time_address, (ephemeral_pub, view_tag));
                    if !encrypted_memo.is_empty() && encrypted_memo.len() <= 80 {
                        stealth_memos.insert(one_time_address, encrypted_memo);
                    }
                }
                NodeRpcResponse::AckStealthAnnounce
            }
            NodeRpcRequest::InspectQuery { query } => {
                crate::handle_inspect_query(&ledger, ledger.latest_epoch, &query)
            }
            NodeRpcRequest::GetStealthOutputsV2 => {
                let mut outputs = Vec::new();
                for (&addr, &amt) in &ledger.stealth_utxos {
                    if !amt.is_zero()
                        && let Some(&(eph, vt)) = stealth_announcements.get(&addr)
                    {
                        let memo = stealth_memos.get(&addr).cloned().unwrap_or_default();
                        outputs.push((addr, amt, eph, vt, memo));
                        if outputs.len() >= 32 {
                            break;
                        }
                    }
                }
                NodeRpcResponse::StealthOutputsV2 { outputs }
            }
            NodeRpcRequest::ClaimStealthUtxo {
                one_time_address,
                claimant_pocket,
                claimant_pubkey,
                spend_pub,
                kdf,
                schnorr_sig64,
            } => {
                let claim_nullifier =
                    domain_hash("XCR.STEALTH.CLAIM_NULL.V1", &[one_time_address.as_bytes()]);
                let fee = Amount::from_bits(MIN_BASE_FEE_BITS);
                if claimant_pubkey.to_address() != claimant_pocket {
                    NodeRpcResponse::StealthClaimReceipt {
                        accepted: false,
                        claimed_amount: Amount::ZERO,
                        fee_burned: Amount::ZERO,
                        new_pocket_balance: Amount::ZERO,
                        new_state_root: ledger.state_merkle_root(),
                        message: "rejected: claimant pubkey/address mismatch".to_owned(),
                    }
                } else if ledger.spent_nullifiers.contains(&claim_nullifier) {
                    NodeRpcResponse::StealthClaimReceipt {
                        accepted: false,
                        claimed_amount: Amount::ZERO,
                        fee_burned: Amount::ZERO,
                        new_pocket_balance: Amount::ZERO,
                        new_state_root: ledger.state_merkle_root(),
                        message: "rejected: stealth output already claimed".to_owned(),
                    }
                } else if !verify_stealth_claim(
                    &one_time_address,
                    &claimant_pocket,
                    &spend_pub,
                    &kdf,
                    &schnorr_sig64,
                ) {
                    NodeRpcResponse::StealthClaimReceipt {
                        accepted: false,
                        claimed_amount: Amount::ZERO,
                        fee_burned: Amount::ZERO,
                        new_pocket_balance: Amount::ZERO,
                        new_state_root: ledger.state_merkle_root(),
                        message: "rejected: invalid Schnorr stealth ownership proof".to_owned(),
                    }
                } else if let Some(&utxo_amt) = ledger.stealth_utxos.get(&one_time_address)
                    && let Some(net_credit) = utxo_amt.checked_sub(fee)
                    && !net_credit.is_zero()
                {
                    if !ledger.pockets.contains_key(&claimant_pocket) {
                        let st = PocketState::new(Amount::ZERO, Amount::from_credits(25).unwrap());
                        ledger.append(WalRecord::UpsertPocket {
                            address: claimant_pocket,
                            public_key: claimant_pubkey,
                            state: st.clone(),
                        })?;
                        fast_engine.register_pocket(claimant_pubkey, st);
                    }
                    let mut next_state = ledger.pockets[&claimant_pocket].state.clone();
                    let _ = next_state.credit(net_credit);
                    fast_engine.register_pocket(claimant_pubkey, next_state.clone());
                    let fs = FeeSplit::compute(fee);
                    let tx_id = domain_hash(
                        "XCR.STEALTH.CLAIM_TX.V1",
                        &[one_time_address.as_bytes(), claimant_pocket.as_bytes()],
                    );
                    ledger.append(WalRecord::ClaimStealthUtxo {
                        tx_id,
                        one_time_address,
                        claimant_pocket,
                        new_pocket_balance: next_state.balance,
                        fee_burned: fs.burned,
                        claim_nullifier,
                    })?;
                    stealth_announcements.remove(&one_time_address);
                    NodeRpcResponse::StealthClaimReceipt {
                        accepted: true,
                        claimed_amount: net_credit,
                        fee_burned: fs.burned,
                        new_pocket_balance: next_state.balance,
                        new_state_root: ledger.state_merkle_root(),
                        message: "stealth UTXO claimed into Pocket".to_owned(),
                    }
                } else {
                    NodeRpcResponse::StealthClaimReceipt {
                        accepted: false,
                        claimed_amount: Amount::ZERO,
                        fee_burned: Amount::ZERO,
                        new_pocket_balance: Amount::ZERO,
                        new_state_root: ledger.state_merkle_root(),
                        message: "rejected: unspent stealth output not found".to_owned(),
                    }
                }
            }
            contract_req @ (NodeRpcRequest::LockHtlc { .. }
            | NodeRpcRequest::ClaimHtlc { .. }
            | NodeRpcRequest::RefundHtlc { .. }
            | NodeRpcRequest::GetHtlcs
            | NodeRpcRequest::OpenPayChannel { .. }
            | NodeRpcRequest::ClosePayChannel { .. }
            | NodeRpcRequest::GetPayChannels
            | NodeRpcRequest::CashOrCancelCheck { .. }
            | NodeRpcRequest::PostSwapOffer { .. }
            | NodeRpcRequest::GetSwapOffers
            | NodeRpcRequest::LockScriptVault { .. }
            | NodeRpcRequest::SpendScriptVault { .. }
            | NodeRpcRequest::ExecuteSessionKey { .. }
            | NodeRpcRequest::MintNativeAsset { .. }
            | NodeRpcRequest::TransferNativeAsset { .. }
            | NodeRpcRequest::GetAssetBalances { .. }
            | NodeRpcRequest::CreateCampaign { .. }
            | NodeRpcRequest::PledgeCampaign { .. }
            | NodeRpcRequest::FinalizeCampaign { .. }
            | NodeRpcRequest::GetSupplyAndContractsSummary
            | NodeRpcRequest::PlaceDexOrder { .. }
            | NodeRpcRequest::CancelDexOrder { .. }
            | NodeRpcRequest::BridgedAssetPayment { .. }
            | NodeRpcRequest::BabelAssetTransfer { .. }
            | NodeRpcRequest::GetDexOrderbook { .. }
            | NodeRpcRequest::RegisterOrTransferHandle { .. }
            | NodeRpcRequest::ResolveHandle { .. }
            | NodeRpcRequest::ParallelLanePay { .. }
            | NodeRpcRequest::GetArtifactsAndAttestations { .. }
            | NodeRpcRequest::ExecuteAtomicBatch { .. }
            | NodeRpcRequest::MintOrTransferArtifact { .. }
            | NodeRpcRequest::IssueOrRevokeAttestation { .. }
            | NodeRpcRequest::GovernanceAction { .. }
            | NodeRpcRequest::SetDepositShield { .. }
            | NodeRpcRequest::GetGovernanceSummary
            | NodeRpcRequest::ShieldDeposit { .. }
            | NodeRpcRequest::ShieldRingTransfer { .. }
            | NodeRpcRequest::GetShieldedNotes { .. }
            | NodeRpcRequest::AmmLiquidity { .. }
            | NodeRpcRequest::HybridSmartSwap { .. }
            | NodeRpcRequest::GetAmmAndOracleSnapshot
            | NodeRpcRequest::SubmitOracleReport { .. }
            | NodeRpcRequest::OracleFiatPayment { .. }
            | NodeRpcRequest::BandwidthFreePay { .. }
            | NodeRpcRequest::CreateClaimable { .. }
            | NodeRpcRequest::SweepOrReclaimClaimable { .. }
            | NodeRpcRequest::CreateRedPacket { .. }
            | NodeRpcRequest::ClaimOrReclaimRedPacket { .. }
            | NodeRpcRequest::ExecuteProofOfBurn { .. }
            | NodeRpcRequest::BindOrExecuteRoleProxy { .. }) => {
                let (resp, mutated) = crate::contracts::execute_contract_rpc(
                    &contract_req,
                    &mut ledger,
                    &mut swap_offers,
                    &mut unsettled_fee_bits,
                    false,
                )?;
                if mutated {
                    for sp in ledger.pockets.values() {
                        fast_engine.register_pocket(sp.public_key, sp.state.clone());
                    }
                }
                resp
            }
        };

        let _ = send_rpc_reply(&mut endpoint, peer, &response);
        if should_exit {
            return Ok(());
        }
    }
}

fn send_rpc_reply(
    endpoint: &mut UdpQuicEndpoint,
    peer: SocketAddr,
    response: &NodeRpcResponse,
) -> io::Result<u64> {
    let frame = WireFrame {
        channel: ChannelTag::ClientRpcResponse,
        payload: response.encode(),
    };
    endpoint.send_1rtt_datagram(peer, &frame)
}
