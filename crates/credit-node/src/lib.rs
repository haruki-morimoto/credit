//! Unified Laptop-to-Server Participant Node, WAL Daemon, & End-to-End Harness.

pub mod contracts;
pub mod daemon;
pub mod mesh_node;
pub mod wave11_contracts;
pub mod wave9_contracts;

pub use credit_consensus::NetworkProfile;
pub use daemon::run_node_daemon;
pub use mesh_node::{
    MeshPeerConfig, run_mesh_peer, run_mesh_peer_with_beacon, run_mesh_peer_with_reward_pubkey,
};

use std::net::SocketAddr;
use std::thread;
use std::time::{Duration, Instant};

use credit_consensus::{
    BasketObservation, BftDagEngine, DagVertex, FastPathEngine, FinalityCertificate, ProposalState,
    QuorumCommittee, ReserveVaultEngine, ShardConfig, ShardedFastPathCluster,
    UpgradeGovernanceEngine, assign_validators_to_shards, tx_signing_digest,
};
use credit_crypto::{Keypair, Scalar, Signature, SignatureScheme, domain_hash};
use credit_net::{ChannelTag, NodeRpcResponse, UdpQuicEndpoint, WireFrame};
use credit_ponc::{ComputeShare, EpochSettlement, EpochShareDag, PoncVmConfig};
use credit_sdk::{CreditWallet, MobileLightClient};
use credit_storage::{DormantArchiveRegistry, PersistentLedger, WalRecord};
use credit_types::{
    Address, Amount, CredchipStatus, EpochId, Hash32, MaturityMetrics, MonetaryPhase, PocketState,
    Transaction, TransactionKind,
};
use credit_zk::{
    AssociationTree, AuthenticatedStateTree, BlindedCommitment, BulletproofRange64,
    ConfidentialTransferProof, EpochStateHeader, Iso20022Memo, StateLeaf, SuccinctEpochProof,
};

/// Builds a compact `O(log2 N)` Merkle `LightAccountProof` RPC reply from `ledger.pockets`.
pub fn build_light_account_proof(ledger: &PersistentLedger, address: &Address) -> NodeRpcResponse {
    let leaves: Vec<StateLeaf> = ledger
        .pockets
        .iter()
        .map(|(&addr, sp)| StateLeaf {
            address: addr,
            balance: sp.state.balance,
            nonce: sp.state.nonce,
        })
        .collect();
    let tree = AuthenticatedStateTree::build(leaves);
    let authenticated_root = tree.root();
    match tree.prove(address) {
        Some((leaf, branch)) => NodeRpcResponse::LightAccountProof {
            found: true,
            authenticated_root,
            balance: leaf.balance,
            nonce: leaf.nonce,
            inclusion_proof_bytes: branch.to_bytes(),
        },
        None => NodeRpcResponse::LightAccountProof {
            found: false,
            authenticated_root,
            balance: Amount::ZERO,
            nonce: 0,
            inclusion_proof_bytes: Vec::new(),
        },
    }
}

/// Resolves an Explorer/CLI `InspectQuery` (`xcr1_<prefix>` Pocket or `64-hex` `Tx ID`) into a
/// cryptographically verifiable `<256B` Merkle account proof or finalized transaction confirmation.
pub fn handle_inspect_query(
    ledger: &PersistentLedger,
    active_epoch: EpochId,
    raw_query: &str,
) -> NodeRpcResponse {
    if let Some(norm) = credit_sdk::normalize_xcr_handle(raw_query)
        && let Some(h) = ledger.handles.get(&norm)
        && let NodeRpcResponse::LightAccountProof {
            found: true,
            authenticated_root,
            balance,
            nonce,
            inclusion_proof_bytes,
        } = build_light_account_proof(ledger, &h.owner)
    {
        return NodeRpcResponse::InspectResult {
            kind: 1,
            target_hex: format!("@{}.xcr ({})", h.name, h.owner.short_hex()),
            address: h.owner,
            balance,
            nonce,
            epoch: active_epoch,
            authenticated_root,
            inclusion_proof_bytes,
        };
    }

    let q = raw_query.trim().to_ascii_lowercase();
    let hex_part = q.strip_prefix("xcr1_").unwrap_or(&q);
    if hex_part.len() >= 6 && hex_part.bytes().all(|b| b.is_ascii_hexdigit()) {
        if let Some((&found_addr, _)) = ledger
            .pockets
            .iter()
            .find(|(addr, _)| Hash32(addr.0).to_hex().starts_with(hex_part))
            && let NodeRpcResponse::LightAccountProof {
                found: true,
                authenticated_root,
                balance,
                nonce,
                inclusion_proof_bytes,
            } = build_light_account_proof(ledger, &found_addr)
        {
            return NodeRpcResponse::InspectResult {
                kind: 1,
                target_hex: found_addr.short_hex(),
                address: found_addr,
                balance,
                nonce,
                epoch: active_epoch,
                authenticated_root,
                inclusion_proof_bytes,
            };
        }

        if !q.starts_with("xcr1_")
            && hex_part.len() >= 12
            && let Some(&tx_id) = ledger
                .finalized_txs
                .iter()
                .find(|id| id.to_hex().starts_with(hex_part))
        {
            return NodeRpcResponse::InspectResult {
                kind: 2,
                target_hex: tx_id.to_hex(),
                address: Address::default(),
                balance: Amount::ZERO,
                nonce: 0,
                epoch: active_epoch,
                authenticated_root: ledger.state_merkle_root(),
                inclusion_proof_bytes: Vec::new(),
            };
        }
    }

    NodeRpcResponse::InspectResult {
        kind: 0,
        target_hex: String::new(),
        address: Address::default(),
        balance: Amount::ZERO,
        nonce: 0,
        epoch: active_epoch,
        authenticated_root: ledger.state_merkle_root(),
        inclusion_proof_bytes: Vec::new(),
    }
}

/// Summary produced by an end-to-end Genesis + Live UDP + Confidential ZK + Phase-2 simulation.
#[derive(Clone, Debug)]
pub struct GenesisSimulationSummary {
    pub genesis_premine: Amount,
    pub epoch0_settlement: EpochSettlement,
    pub quorum_threshold: u64,
    pub fast_path_cert: FinalityCertificate,
    pub live_udp_votes_collected: usize,
    pub live_udp_quorum_rtt_us: u128,
    pub confidential_range_proof_verified: bool,
    pub bulletproof_64bit_bytes: usize,
    pub bulletproof_verified: bool,
    pub merchant_zk_verified: bool,
    pub bft_3round_committed: bool,
    pub phase2_basket_target_micros: u64,
    pub phase2_converged_market_micros: u64,
    pub sharded_parallel_txs_settled: u32,
    pub mobile_header_bytes: usize,
    pub mobile_account_proof_bytes: usize,
    pub mobile_light_verified: bool,
    pub archive_revival_proof_bytes: usize,
    pub dormant_account_revived: bool,
    pub compute_upgrade_ratified: bool,
    pub vault_restored_balance: Amount,
    pub credchip_status: CredchipStatus,
}

/// Executes a real multi-thread OS `UdpSocket` 1-RTT quorum round-trip across 4 independent
/// validator sockets bound to `127.0.0.1:<ephemeral>`.
pub fn run_live_udp_quorum_1rtt(
    committee: &QuorumCommittee,
    tx_id: Hash32,
    mut validators: Vec<(Address, Keypair)>,
) -> (usize, u64, u128) {
    let timeout = Duration::from_millis(1_000);
    let mut val_endpoints = Vec::with_capacity(validators.len());
    let mut val_addrs: Vec<SocketAddr> = Vec::with_capacity(validators.len());
    for idx in 0..validators.len() {
        let ep = UdpQuicEndpoint::bind_loopback(0x9000 + idx as u64, timeout)
            .expect("bind validator loopback UDP socket");
        val_addrs.push(ep.local_addr());
        val_endpoints.push(ep);
    }

    let mut client_ep =
        UdpQuicEndpoint::bind_loopback(0x0001, timeout).expect("bind wallet loopback UDP socket");
    let epoch = committee.epoch;

    thread::scope(|s| {
        for (mut ep, (val_addr, mut val_kp)) in val_endpoints.into_iter().zip(validators.drain(..))
        {
            s.spawn(move || {
                if let Ok((client_src, pkt)) = ep.recv_packet()
                    && let Some(frame) = pkt.frame
                    && frame.channel == ChannelTag::FastPathRequest
                    && frame.payload.len() == 32
                {
                    let mut req_id = [0u8; 32];
                    req_id.copy_from_slice(&frame.payload);
                    let vote_msg = domain_hash(
                        "XCR.CONSENSUS.FAST_VOTE.V1",
                        &[&epoch.0.to_le_bytes(), &req_id],
                    );
                    let sig = val_kp.sign(vote_msg.as_bytes()).to_bytes();
                    let mut reply_payload = Vec::with_capacity(32 + sig.len());
                    reply_payload.extend_from_slice(val_addr.as_bytes());
                    reply_payload.extend_from_slice(&sig);

                    let vote_frame = WireFrame {
                        channel: ChannelTag::FastPathVote,
                        payload: reply_payload,
                    };
                    let _ = ep.send_1rtt_datagram(client_src, &vote_frame);
                }
            });
        }

        let start = Instant::now();
        let req_frame = WireFrame {
            channel: ChannelTag::FastPathRequest,
            payload: tx_id.as_bytes().to_vec(),
        };
        for &peer in &val_addrs {
            client_ep
                .send_1rtt_datagram(peer, &req_frame)
                .expect("broadcast 1-RTT FastPathRequest over UDP");
        }

        let threshold = committee.quorum_threshold();
        let vote_msg = domain_hash(
            "XCR.CONSENSUS.FAST_VOTE.V1",
            &[&epoch.0.to_le_bytes(), tx_id.as_bytes()],
        );
        let mut signed_weight = 0u64;
        let mut votes_collected = 0usize;
        let mut quorum_rtt_us = 0u128;

        for _ in 0..val_addrs.len() {
            let (_, pkt) = client_ep.recv_packet().expect("receive UDP FastPathVote");
            if let Some(frame) = pkt.frame
                && frame.channel == ChannelTag::FastPathVote
                && frame.payload.len() > 32
            {
                let mut addr_bytes = [0u8; 32];
                addr_bytes.copy_from_slice(&frame.payload[..32]);
                let voter = Address::from_bytes(addr_bytes);
                if let Some(sig) = Signature::from_bytes(&frame.payload[32..])
                    && let Some(member) = committee.members().iter().find(|m| m.address == voter)
                    && member.public_key.verify(vote_msg.as_bytes(), &sig)
                {
                    votes_collected += 1;
                    signed_weight = signed_weight.saturating_add(member.weight);
                    if quorum_rtt_us == 0 && signed_weight >= threshold {
                        quorum_rtt_us = start.elapsed().as_micros().max(1);
                    }
                }
            }
        }

        (votes_collected, signed_weight, quorum_rtt_us)
    })
}

/// Runs a complete, deterministic multi-node lifecycle exercising every subsystem:
/// PoNC Share-DAG, Curve25519 Pedersen Range Proofs, Live 4-Socket UDP 1-RTT Finality,
/// Privacy Pool Proofs of Innocence, 3-Round BFT DAG, Vault Recovery, and Phase-2 PID Vaults.
pub fn run_genesis_simulation() -> GenesisSimulationSummary {
    // 1. Constitutional Fair-Launch Invariant: Genesis Premine == 0.000000 XCR.
    let MonetaryPhase::Phase1Bootstrap {
        circulating_supply: genesis_premine,
        ..
    } = (MonetaryPhase::Phase1Bootstrap {
        epoch: EpochId(0),
        circulating_supply: Amount::ZERO,
        total_burned: Amount::ZERO,
    })
    else {
        unreachable!()
    };
    assert_eq!(genesis_premine, Amount::ZERO);

    // 2. Epoch 0 Fair-Launch PoNC + Protocol-Native Share-DAG (3 consumer laptops + 1 ZK server).
    let vm_cfg = PoncVmConfig::devnet_profile();
    let epoch0_seed = domain_hash("XCR.GENESIS.SEED.V1", &[b"Credits-For-All-Block-0"]);
    let mut dag = EpochShareDag::new(EpochId(0), epoch0_seed, 3, vm_cfg);

    let v_laptop_1 = Keypair::from_seed(SignatureScheme::Ed25519, [0x01; 32]);
    let v_laptop_2 = Keypair::from_seed(SignatureScheme::Ed25519, [0x02; 32]);
    let v_laptop_3 = Keypair::from_seed(SignatureScheme::Ed25519, [0x03; 32]);
    let v_zk_server = Keypair::from_seed(SignatureScheme::Ed25519, [0x04; 32]);

    let s1 = ComputeShare::mine_cpu_share(
        EpochId(0),
        &epoch0_seed,
        v_laptop_1.address(),
        vec![],
        0,
        3,
        &vm_cfg,
    );
    dag.submit_share(s1.clone()).expect("valid laptop #1 share");

    let s2 = ComputeShare::mine_cpu_share(
        EpochId(0),
        &epoch0_seed,
        v_laptop_2.address(),
        vec![s1.id],
        50,
        3,
        &vm_cfg,
    );
    dag.submit_share(s2.clone()).expect("valid laptop #2 share");

    let s3 = ComputeShare::mine_cpu_share(
        EpochId(0),
        &epoch0_seed,
        v_laptop_3.address(),
        vec![s1.id, s2.id],
        120,
        3,
        &vm_cfg,
    );
    dag.submit_share(s3.clone()).expect("valid laptop #3 share");

    let state_root = domain_hash("XCR.EPOCH0.ROOT", &[s1.id.as_bytes(), s2.id.as_bytes()]);
    let s4 = ComputeShare::new_zk_prover_share(
        EpochId(0),
        &epoch0_seed,
        v_zk_server.address(),
        vec![s2.id, s3.id],
        150,
        state_root,
    );
    dag.submit_share(s4).expect("valid server ZK share");

    let epoch0_settlement = dag.settle_epoch(Amount::ZERO);

    // 3. Elect Epoch 1 Rolling 4-Node Quorum (`3f + 1 = 4, f = 1`) from Epoch 0 Share-DAG merit.
    let directory = vec![
        (v_laptop_1.address(), v_laptop_1.public_key(), 145u16),
        (v_laptop_2.address(), v_laptop_2.public_key(), 165u16),
        (v_laptop_3.address(), v_laptop_3.public_key(), 185u16),
        (v_zk_server.address(), v_zk_server.public_key(), 230u16),
    ];
    let committee =
        QuorumCommittee::elect_from_settlement(EpochId(1), &epoch0_settlement, &directory);
    let quorum_threshold = committee.quorum_threshold();

    // 4. Initialize Alice's Earned Wallet (`Pocket & Vault`) + Merchant's Wallet.
    let alice_earned = epoch0_settlement.payouts[0].1;
    let mut alice = CreditWallet::from_master_seed(
        [0xa1; 32],
        alice_earned,
        Amount::from_credits(25).expect("valid limit"),
        Amount::from_credits(500).expect("valid vault"),
        86_400_000,
    );
    let merchant = CreditWallet::from_master_seed(
        [0xb2; 32],
        Amount::ZERO,
        Amount::from_credits(100).expect("valid limit"),
        Amount::ZERO,
        86_400_000,
    );

    // 5. Curve25519 Pedersen Confidential Transfer Proof + AOS Zero-Knowledge Range Proofs!
    let spend_amount = Amount::from_chips(495).expect("4.95 XCR");
    let fee_amount = Amount::from_bits(500); // 0.000500 XCR
    let change_amount = alice_earned
        .checked_sub(spend_amount)
        .unwrap()
        .checked_sub(fee_amount)
        .unwrap();
    let input_blind = Scalar::hash_from_parts("XCR.DEMO.IN_BLIND", &[b"epoch0-payout"]);
    let ct_proof = ConfidentialTransferProof::create(
        &[(alice_earned, input_blind)],
        &[(spend_amount, 32), (change_amount, 32)],
        fee_amount,
        &[0x77; 32],
    )
    .expect("construct Pedersen confidential transfer proof");
    let confidential_range_proof_verified = ct_proof.verify();

    // 5b. Logarithmic 64-bit Inner-Product Bulletproof (`672 bytes` vs `8,192 bytes` uncompressed):
    let bp_gamma = Scalar::hash_from_parts("XCR.DEMO.BP_GAMMA", &[b"spend-note-64"]);
    let (bp_commit, bp_proof) = BulletproofRange64::prove(spend_amount, bp_gamma, 64, &[0x88; 32])
        .expect("64-bit BulletproofRange64");
    let bulletproof_64bit_bytes = bp_proof.to_bytes().len();
    let bulletproof_verified = bp_proof.verify(&bp_commit, 64);

    // 6. Edge Privacy Pool Proof of Innocence + Encrypted ISO-20022 Commercial Receipt.
    let mut clean_tree = AssociationTree::new(4);
    let clean_deposit = BlindedCommitment::commit(alice_earned, &[0x33; 32]);
    clean_tree.set_clean_leaf(0, clean_deposit);
    let accepted_clean_root = clean_tree.root();
    let inclusion_path = clean_tree.inclusion_path(0).expect("leaf 0 path");

    let order_ctx = b"POS-GLOBAL-COFFEE-0042";
    let invoice_memo = Iso20022Memo {
        message_id: "REMT-2027-0042".to_owned(),
        purpose_code: *b"GDDS",
        jurisdiction: "CH".to_owned(),
        invoice_ref: "COFFEE-42".to_owned(),
        tax_amount: Amount::from_chips(45).expect("0.45 XCR VAT"),
    };

    let payment = alice.build_fast_payment(
        &merchant.stealth_meta_address(),
        spend_amount,
        fee_amount,
        Some((
            clean_deposit,
            inclusion_path,
            accepted_clean_root,
            order_ctx,
        )),
        Some(invoice_memo),
    );

    // 7. Live Multi-Thread OS UDP Socket 1-RTT Quorum Fanout + State Finality!
    let udp_validators = vec![
        (v_laptop_1.address(), v_laptop_1.clone()),
        (v_laptop_2.address(), v_laptop_2.clone()),
        (v_laptop_3.address(), v_laptop_3.clone()),
        (v_zk_server.address(), v_zk_server.clone()),
    ];
    let (live_udp_votes_collected, udp_weight, live_udp_quorum_rtt_us) =
        run_live_udp_quorum_1rtt(&committee, payment.transaction.id, udp_validators);
    assert!(udp_weight >= quorum_threshold);

    let mut fast_engine = FastPathEngine::new(committee.clone());
    fast_engine.register_pocket(alice.pocket_public_key(), alice.pocket.clone());
    let mut quorum_signers = vec![
        (v_laptop_1.address(), v_laptop_1),
        (v_laptop_2.address(), v_laptop_2),
        (v_laptop_3.address(), v_laptop_3),
        (v_zk_server.address(), v_zk_server),
    ];
    let fast_path_cert = fast_engine
        .execute_1rtt_transfer(&payment.transaction, &mut quorum_signers, 1)
        .expect("1-RTT Fast-Path finality");

    assert!(
        merchant
            .scan_stealth_output(&payment.stealth_output)
            .is_some()
    );
    let merchant_zk_verified = payment
        .innocence_proof
        .as_ref()
        .is_some_and(|poi| poi.verify(&accepted_clean_root, order_ctx));

    // 8. 3-Round Uncertified BFT DAG + Savings Vault Wrench-Attack Defense.
    let mut bft_dag = BftDagEngine::new(committee);
    let r0_anchor = DagVertex::new(0, quorum_signers[0].0, vec![], vec![payment.transaction.id]);
    bft_dag.insert_vertex(r0_anchor.clone());
    let r1_a = DagVertex::new(1, quorum_signers[0].0, vec![r0_anchor.id], vec![]);
    let r1_b = DagVertex::new(1, quorum_signers[1].0, vec![r0_anchor.id], vec![]);
    let r1_c = DagVertex::new(1, quorum_signers[2].0, vec![r0_anchor.id], vec![]);
    bft_dag.insert_vertex(r1_a.clone());
    bft_dag.insert_vertex(r1_b.clone());
    bft_dag.insert_vertex(r1_c.clone());
    let r2_a = DagVertex::new(
        2,
        quorum_signers[0].0,
        vec![r1_a.id, r1_b.id, r1_c.id],
        vec![],
    );
    let r2_b = DagVertex::new(
        2,
        quorum_signers[1].0,
        vec![r1_a.id, r1_b.id, r1_c.id],
        vec![],
    );
    let r2_c = DagVertex::new(
        2,
        quorum_signers[2].0,
        vec![r1_a.id, r1_b.id, r1_c.id],
        vec![],
    );
    bft_dag.insert_vertex(r2_a);
    bft_dag.insert_vertex(r2_b);
    bft_dag.insert_vertex(r2_c);
    let bft_3round_committed = bft_dag.is_committed_3round(&r0_anchor.id);

    let duress_wid = alice
        .queue_vault_withdrawal(
            Address::from_bytes([0xee; 32]),
            Amount::from_credits(400).expect("duress amount"),
            1_000_000,
        )
        .expect("queued into 24h timelock");
    alice
        .emergency_cancel_vault_withdrawal(duress_wid)
        .expect("emergency cancel restores vault");

    // 9. Phase-2 Over-Collateralized Reserve Vault + Integer PID Global CPI Basket Stabilization.
    let mut reserve_engine = ReserveVaultEngine::new(1_000_000);
    assert!(reserve_engine.try_unlock_phase2(&MaturityMetrics {
        active_compute_nodes: 15_000,
        distinct_autonomous_systems: 650,
        consecutive_deep_epochs: 50_000,
    }));
    let basket_obs = vec![
        BasketObservation {
            validator: quorum_signers[0].0,
            weight: 800,
            shelter_materials_micros: 1_003_000,
            food_staples_micros: 1_001_000,
            energy_kwh_micros: 1_002_000,
            healthcare_micros: 1_001_500,
            education_micros: 1_001_200,
            compute_bandwidth_micros: 999_000,
            scientific_research_micros: 1_002_500,
            emergency_resilience_micros: 1_001_800,
            entertainment_micros: 1_000_500,
        },
        BasketObservation {
            validator: quorum_signers[1].0,
            weight: 800,
            shelter_materials_micros: 1_002_800,
            food_staples_micros: 1_001_200,
            energy_kwh_micros: 1_002_200,
            healthcare_micros: 1_001_600,
            education_micros: 1_001_100,
            compute_bandwidth_micros: 999_200,
            scientific_research_micros: 1_002_400,
            emergency_resilience_micros: 1_001_700,
            entertainment_micros: 1_000_600,
        },
        BasketObservation {
            validator: quorum_signers[2].0,
            weight: 800,
            shelter_materials_micros: 1_003_000,
            food_staples_micros: 1_001_000,
            energy_kwh_micros: 1_001_800,
            healthcare_micros: 1_001_400,
            education_micros: 1_001_200,
            compute_bandwidth_micros: 999_000,
            scientific_research_micros: 1_002_600,
            emergency_resilience_micros: 1_001_800,
            entertainment_micros: 1_000_500,
        },
    ];
    let phase2_basket_target_micros = reserve_engine
        .oracle
        .update_from_quorum(EpochId(50_001), &basket_obs, quorum_threshold)
        .expect("trimmed-median basket quorum update");

    reserve_engine
        .open_vault(
            alice.pocket_address(),
            Amount::from_credits(250).unwrap(),
            Amount::from_credits(100).unwrap(),
            phase2_basket_target_micros,
        )
        .expect("open 250% over-collateralized Reserve Vault");

    let mut market_micros = 940_000i128; // -6% demand shock
    for _ in 0..60 {
        let (rate_bps, _) = reserve_engine
            .pid
            .step(phase2_basket_target_micros, market_micros as u64);
        market_micros += (rate_bps as i128 - 200) * 8;
    }

    let credchip_status = alice.credchip_status(merchant_zk_verified, true);

    // 10. Stage-2 Horizontal 4-Shard Multi-Core Parallel Wave + Mobile Light-Client Verification!
    let shard_cfg = ShardConfig::new(2).expect("4 shards");
    let shard_committees = assign_validators_to_shards(
        EpochId(1),
        &epoch0_seed,
        fast_engine.committee.members(),
        shard_cfg,
        4,
    );
    let mut shard_signers: Vec<Vec<(Address, Keypair)>> = shard_committees
        .iter()
        .map(|comm| {
            comm.members()
                .iter()
                .map(|m| {
                    let kp = quorum_signers
                        .iter()
                        .find(|(a, _)| *a == m.address)
                        .unwrap()
                        .1
                        .clone();
                    (m.address, kp)
                })
                .collect()
        })
        .collect();
    let mut sharded_cluster = ShardedFastPathCluster::new(shard_cfg, shard_committees);
    let mut wave_txs = Vec::with_capacity(8);
    let mut state_leaves = Vec::with_capacity(8);
    for idx in 0u8..8 {
        let mut w_kp = Keypair::from_seed(SignatureScheme::PasskeyP256, [0xc0 + idx; 32]);
        let (_, w_addr) = sharded_cluster.register_pocket(
            w_kp.public_key(),
            PocketState::new(
                Amount::from_credits(20).unwrap(),
                Amount::from_credits(25).unwrap(),
            ),
        );
        let kind = TransactionKind::FastTransfer {
            from: w_addr,
            to_stealth: Address::from_bytes([0xd0 + idx; 32]),
            stealth_view_tag: idx,
            amount: Amount::from_credits(2).unwrap(),
            fee: Amount::from_bits(500),
            nonce: 0,
            commitment: Hash32::from_bytes([0xee; 32]),
            innocence_nullifier: None,
        };
        let tid = tx_signing_digest(&kind);
        let sig = w_kp.sign(tid.as_bytes()).to_bytes();
        wave_txs.push(Transaction {
            id: tid,
            kind,
            signature_bytes: sig,
        });
        state_leaves.push(StateLeaf {
            address: w_addr,
            balance: Amount::from_bits(17_999_500),
            nonce: 1,
        });
    }
    let wave = sharded_cluster.execute_parallel_wave(&wave_txs, &mut shard_signers, 1);
    let sharded_parallel_txs_settled: u32 =
        wave.shard_roots.iter().map(|r| r.settled_tx_count).sum();

    let state_tree = AuthenticatedStateTree::build(state_leaves.clone());
    let mut mobile_client = MobileLightClient::from_genesis();
    let epoch1_hdr = EpochStateHeader {
        epoch: EpochId(1),
        prev_header_hash: Hash32::ZERO,
        prev_state_root: Hash32::ZERO,
        new_state_root: state_tree.root(),
        shard_roots_merkle: wave.global_shard_merkle_root,
        circulating_supply: Amount::from_bits(99_999_850),
        total_burned: Amount::from_bits(150),
        verified_tx_count: sharded_parallel_txs_settled + 1,
        next_committee_root: Hash32::ZERO,
    };
    let epoch1_proof = SuccinctEpochProof::prove_epoch_transition(
        &mobile_client.inductive_chain_seal,
        Amount::ZERO,
        Scalar::ZERO,
        Amount::from_credits(100).unwrap(),
        Amount::from_bits(150),
        Scalar::from_u64(777),
        &epoch1_hdr,
        &mut quorum_signers,
    )
    .expect("generate succinct epoch transition proof");
    mobile_client
        .verify_and_advance(&epoch1_hdr, &epoch1_proof, &fast_engine.committee)
        .expect("mobile light client advances in 188B header");
    let (sample_leaf, sample_branch) = state_tree.prove(&state_leaves[0].address).unwrap();
    let mobile_account_proof_bytes = sample_branch.to_bytes().len();
    let mobile_light_verified = mobile_client.verify_my_account(&sample_leaf, &sample_branch);

    // 11. Self-Sustaining Protocol: Dormant Cold-Archival Revival + >=85% Compute Ratification!
    let mut tmp_wal_dir = std::env::temp_dir();
    tmp_wal_dir.push(format!("xcr_sim_archive_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&tmp_wal_dir);
    let mut archive_ledger =
        PersistentLedger::open(tmp_wal_dir.join("sim_archive.wal")).expect("open sim WAL");
    let dormant_kp = Keypair::from_seed(SignatureScheme::PasskeyP256, [0x99; 32]);
    let dormant_addr = dormant_kp.address();
    archive_ledger
        .append(WalRecord::UpsertPocket {
            address: dormant_addr,
            public_key: dormant_kp.public_key(),
            state: PocketState::new(
                Amount::from_credits(75).unwrap(),
                Amount::from_credits(25).unwrap(),
            ),
        })
        .expect("insert dormant pocket");
    let mut archive_registry = DormantArchiveRegistry::new();
    let archive_tree = archive_registry
        .archive_accounts(&mut archive_ledger, &[dormant_addr], EpochId(1_500_000))
        .expect("compact dormant pocket into 32B root");
    let (archived_leaf, archive_proof) = archive_tree.prove(&dormant_addr).unwrap();
    let archive_revival_proof_bytes = archive_proof.byte_len();
    let dormant_account_revived = archive_registry
        .revive_account(
            &mut archive_ledger,
            archive_tree.root(),
            &archived_leaf,
            &archive_proof,
        )
        .is_ok()
        && archive_ledger.pockets[&dormant_addr].state.balance == Amount::from_credits(75).unwrap();
    let _ = std::fs::remove_dir_all(&tmp_wal_dir);

    let mut gov = UpgradeGovernanceEngine::new();
    let xip_id = domain_hash("XCR.GOVERNANCE.XIP.V1", &[b"XIP-01-PQ-FALCON"]);
    gov.register_proposal(
        xip_id,
        "XIP-01: Next-Gen PQ Guardian Agility".to_owned(),
        domain_hash("XCR.SPEC", &[b"spec-v1"]),
        EpochId(10),
        4,
        4,
    );
    for ep in 10..14 {
        gov.on_epoch_finalized(EpochId(ep), 1_000, &[(xip_id, 900)]);
    }
    gov.on_epoch_finalized(EpochId(18), 1_000, &[]);
    let compute_upgrade_ratified = matches!(
        gov.proposal(&xip_id).map(|p| p.state),
        Some(ProposalState::Activated {
            activated_at_epoch: EpochId(18)
        })
    );

    GenesisSimulationSummary {
        genesis_premine,
        epoch0_settlement,
        quorum_threshold,
        fast_path_cert,
        live_udp_votes_collected,
        live_udp_quorum_rtt_us,
        confidential_range_proof_verified,
        bulletproof_64bit_bytes,
        bulletproof_verified,
        merchant_zk_verified,
        bft_3round_committed,
        phase2_basket_target_micros,
        phase2_converged_market_micros: market_micros as u64,
        sharded_parallel_txs_settled,
        mobile_header_bytes: mobile_client.verified_headers_bytes,
        mobile_account_proof_bytes,
        mobile_light_verified,
        archive_revival_proof_bytes,
        dormant_account_revived,
        compute_upgrade_ratified,
        vault_restored_balance: alice.vault.balance,
        credchip_status,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn end_to_end_live_udp_pedersen_and_phase2_simulation_succeeds() {
        let summary = run_genesis_simulation();
        assert_eq!(summary.genesis_premine, Amount::ZERO);
        assert_eq!(summary.epoch0_settlement.payouts.len(), 4);
        assert_eq!(summary.live_udp_votes_collected, 4);
        assert!(summary.live_udp_quorum_rtt_us > 0);
        assert!(summary.fast_path_cert.finality_latency_ms <= 250);
        assert!(summary.confidential_range_proof_verified);
        assert!(summary.merchant_zk_verified);
        assert!(summary.bft_3round_committed);
        assert!(
            (summary.phase2_converged_market_micros as i128
                - summary.phase2_basket_target_micros as i128)
                .abs()
                < 5_000
        );
        assert_eq!(
            summary.vault_restored_balance,
            Amount::from_credits(500).unwrap()
        );
        assert!(summary.dormant_account_revived);
        assert!(summary.archive_revival_proof_bytes < 256);
        assert!(summary.compute_upgrade_ratified);
        assert_eq!(summary.credchip_status.active_dots(), 4);
    }
}
