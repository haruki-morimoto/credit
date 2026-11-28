//! **True Distributed Multi-Peer P2P Node Engine (`credit-node peer`)**.
//!
//! Each `MeshPeerConfig` instance holds **only its own persistent node identity** (`node_identity.bin`)
//! and auto-generated spendable **`miner.wallet`** (`XCRSEED1`), discovers peers via Kademlia XOR DHT
//! and STUN reflection + UDP hole-punching, encrypts all mesh traffic with quadruple-DH Noise
//! `SessionCipher`s, continuously mines & seals PoNC epochs (`Epoch 0 -> 1 -> 2 -> ...`) with
//! automatic solo-miner `Pocket` payouts and `70/15/15` `SecurityEndurancePool` smoothing, settles
//! 1-RTT `FastTransfer` Bulletproof payments, and syncs arbitrarily large ledgers in **`<1,200-byte`
//! MTU-safe WAN chunks**.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::fs;
use std::io::{self, Write};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock, mpsc};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use credit_consensus::{
    GenesisStandbyStatus, MAINNET_GENESIS_UNIX, NetworkProfile, QuorumCommittee, QuorumMember,
    VerifiableGenesisBeacon, tx_signing_digest,
};
use credit_crypto::{
    InitiatorHandshake, Keypair, PeerIdentity, PublicKey, SessionCipher, Signature,
    SignatureScheme, accept_handshake, domain_hash, verify_stealth_claim,
};
use credit_gpu_sys::HeadlessLinuxGpu;
use credit_net::{
    ChannelTag, KademliaRoutingTable, NatDetector, NodeRpcRequest, NodeRpcResponse,
    P2pHandshakePacket, P2pMessage, PeerDescriptor, SyncItem, UdpQuicEndpoint, WireFrame,
    pack_wan_sync_chunk,
};
use credit_ponc::{
    ComputeShare, EpochShareDag, MIN_ZK_ZERO_BITS, PoncVmConfig, WorkProof, zk_fold_context_hash,
};
use credit_storage::{PersistentLedger, StoredPocket, WalRecord};
use credit_types::{
    AccountError, Address, Amount, EpochId, FeeSplit, Hash32, MIN_BASE_FEE_BITS, PocketState,
    SecurityEndurancePool, Transaction, TransactionKind,
};
use credit_zk::{BulletproofRange64, PedersenCommitment};

use crate::build_light_account_proof;

const NODE_KEY_MAGIC: [u8; 8] = *b"XCRNKEY1";
const WALLET_FILE_MAGIC: [u8; 8] = *b"XCRSEED1";

static PONC_MINER_THREADS_OVERRIDE: AtomicUsize = AtomicUsize::new(0);
static PONC_HASHRATE_HPS: AtomicU64 = AtomicU64::new(0);
static PONC_LOCAL_EPOCH_WEIGHT: AtomicU64 = AtomicU64::new(0);

/// Dynamically sets the number of background CPU compute threads (`1..=32`) used for PoNC mining.
pub fn set_ponc_miner_threads(threads: usize) {
    PONC_MINER_THREADS_OVERRIDE.store(threads.clamp(1, 32), Ordering::Relaxed);
}

/// Returns the active number of CPU compute threads used by the background PoNC miner.
pub fn current_ponc_miner_threads() -> usize {
    let ov = PONC_MINER_THREADS_OVERRIDE.load(Ordering::Relaxed);
    if ov > 0 {
        return ov;
    }
    if cfg!(debug_assertions) {
        1
    } else {
        thread::available_parallelism()
            .map(|p| p.get())
            .unwrap_or(1)
            .clamp(1, 32)
    }
}

/// Returns the live measured PoNC CPU VM execution rate (`hashes / second`) across active cores.
pub fn local_ponc_hashrate_hps() -> u64 {
    PONC_HASHRATE_HPS.load(Ordering::Relaxed)
}

/// Returns the local node's verified Share-DAG compute weight in the current epoch.
pub fn local_ponc_epoch_weight() -> u64 {
    PONC_LOCAL_EPOCH_WEIGHT.load(Ordering::Relaxed)
}

/// Safe hardware-abstraction trait implemented by both `credit_gpu_sys::HeadlessLinuxGpu`
/// (on headless Linux servers) and `wgpu` compute shaders (in `credit-desktop`).
pub trait GpuZkBatchProver: Send + Sync {
    fn device_name(&self) -> &str;
    fn search_zk_fold_batch(
        &self,
        context_hash: &[u8; 32],
        base_nonce: u64,
        batch_threads: u32,
        min_zero_bits: u32,
    ) -> Option<(u64, u32)>;
}

impl GpuZkBatchProver for HeadlessLinuxGpu {
    fn device_name(&self) -> &str {
        Self::device_name(self)
    }

    fn search_zk_fold_batch(
        &self,
        context_hash: &[u8; 32],
        base_nonce: u64,
        batch_threads: u32,
        min_zero_bits: u32,
    ) -> Option<(u64, u32)> {
        Self::search_zk_fold_batch(self, context_hash, base_nonce, batch_threads, min_zero_bits)
    }
}

static GPU_ZK_BOOST_ENABLED: AtomicBool = AtomicBool::new(true);
static GPU_ZK_EVALS_PER_SEC: AtomicU64 = AtomicU64::new(0);
static GPU_PROVER_SLOT: OnceLock<Mutex<Option<Arc<dyn GpuZkBatchProver>>>> = OnceLock::new();

fn prover_slot() -> &'static Mutex<Option<Arc<dyn GpuZkBatchProver>>> {
    GPU_PROVER_SLOT.get_or_init(|| {
        let auto = HeadlessLinuxGpu::probe().map(|g| Arc::new(g) as Arc<dyn GpuZkBatchProver>);
        Mutex::new(auto)
    })
}

/// Registers an external safe GPU batch prover (such as `credit-desktop`'s `wgpu` backend).
pub fn register_gpu_zk_prover(prover: Arc<dyn GpuZkBatchProver>) {
    *prover_slot().lock().unwrap() = Some(prover);
}

/// Enables or pauses Tier-2 GPU `RecursiveZkState` proving at runtime.
pub fn set_gpu_zk_boost_enabled(enabled: bool) {
    GPU_ZK_BOOST_ENABLED.store(enabled, Ordering::Relaxed);
    if !enabled {
        GPU_ZK_EVALS_PER_SEC.store(0, Ordering::Relaxed);
    }
}

/// Returns whether Tier-2 GPU `RecursiveZkState` acceleration is enabled.
pub fn is_gpu_zk_boost_enabled() -> bool {
    GPU_ZK_BOOST_ENABLED.load(Ordering::Relaxed)
}

/// Returns the detected GPU device name (`OpenCL` on Linux servers or `wgpu` on Desktop), if any.
pub fn gpu_zk_device_name() -> Option<String> {
    prover_slot()
        .lock()
        .unwrap()
        .as_ref()
        .map(|p| p.device_name().to_owned())
}

/// Returns the live GPU `RecursiveZkState` evaluation rate (`evals / sec`), or `0` when idle (`0W`).
pub fn local_gpu_zk_evals_per_sec() -> u64 {
    GPU_ZK_EVALS_PER_SEC.load(Ordering::Relaxed)
}

struct GpuZkJobState {
    epoch: EpochId,
    epoch_seed: Hash32,
    state_root: Hash32,
    verified_tx_count: u32,
    enabled: bool,
    stop_all: bool,
    best_zk_weight: u64,
}

struct BackgroundGpuZkPool {
    state: Arc<Mutex<GpuZkJobState>>,
    rx: mpsc::Receiver<ComputeShare>,
}

impl BackgroundGpuZkPool {
    fn spawn(author: Address, enable_pool: bool) -> Self {
        let (tx, rx) = mpsc::channel::<ComputeShare>();
        let state = Arc::new(Mutex::new(GpuZkJobState {
            epoch: EpochId(0),
            epoch_seed: Hash32::ZERO,
            state_root: Hash32::ZERO,
            verified_tx_count: 0,
            enabled: false,
            stop_all: !enable_pool,
            best_zk_weight: 0,
        }));

        if enable_pool {
            let st_ref = Arc::clone(&state);
            thread::spawn(move || {
                let mut base_nonce = 0u64;
                let mut observed_key = (EpochId(u64::MAX), 0u32);
                let batch_threads: u32 = 16_384;
                loop {
                    let (epoch, seed, root, tx_count, enabled, stop_all, prev_best) = {
                        let g = st_ref.lock().unwrap();
                        (
                            g.epoch,
                            g.epoch_seed,
                            g.state_root,
                            g.verified_tx_count,
                            g.enabled,
                            g.stop_all,
                            g.best_zk_weight,
                        )
                    };
                    if stop_all {
                        break;
                    }
                    // Strictly 0% GPU / 0W whenever no transactions occurred this epoch or paused:
                    let prover_opt = if enabled && is_gpu_zk_boost_enabled() && tx_count > 0 {
                        prover_slot().lock().unwrap().clone()
                    } else {
                        None
                    };
                    let Some(prover) = prover_opt else {
                        GPU_ZK_EVALS_PER_SEC.store(0, Ordering::Relaxed);
                        thread::sleep(Duration::from_millis(120));
                        continue;
                    };

                    if (epoch, tx_count) != observed_key {
                        observed_key = (epoch, tx_count);
                        base_nonce = 0;
                    }

                    let ctx_hash = zk_fold_context_hash(epoch, &seed, &author, &root, tx_count);
                    let t0 = Instant::now();
                    let found = prover.search_zk_fold_batch(
                        ctx_hash.as_bytes(),
                        base_nonce,
                        batch_threads,
                        MIN_ZK_ZERO_BITS,
                    );
                    let dt = t0.elapsed().as_secs_f64().max(1e-4);
                    GPU_ZK_EVALS_PER_SEC
                        .store((batch_threads as f64 / dt) as u64, Ordering::Relaxed);
                    base_nonce = base_nonce.wrapping_add(batch_threads as u64);

                    if let Some((winning_nonce, _zeros)) = found
                        && let Some(zk_share) = ComputeShare::try_zk_prover_share_at_nonce(
                            epoch,
                            &seed,
                            author,
                            Vec::new(),
                            tx_count,
                            root,
                            winning_nonce,
                        )
                        && zk_share.verified_weight > prev_best.saturating_add(prev_best / 8)
                    {
                        {
                            let mut g = st_ref.lock().unwrap();
                            if g.epoch == epoch {
                                g.best_zk_weight = zk_share.verified_weight;
                            }
                        }
                        if tx.send(zk_share).is_err() {
                            break;
                        }
                    }
                    // Polite 25ms pacing between GPU dispatches so desktop UI stays silky smooth:
                    thread::sleep(Duration::from_millis(25));
                }
            });
        }

        Self { state, rx }
    }

    fn sync_state(
        &self,
        epoch: EpochId,
        seed: Hash32,
        state_root: Hash32,
        epoch_tx_count: u32,
        enabled: bool,
    ) {
        let mut g = self.state.lock().unwrap();
        if g.epoch != epoch || g.epoch_seed != seed {
            g.epoch = epoch;
            g.epoch_seed = seed;
            g.best_zk_weight = 0;
        }
        g.state_root = state_root;
        g.verified_tx_count = epoch_tx_count;
        g.enabled = enabled;
    }
}

impl Drop for BackgroundGpuZkPool {
    fn drop(&mut self) {
        if let Ok(mut g) = self.state.lock() {
            g.stop_all = true;
            g.enabled = false;
        }
        GPU_ZK_EVALS_PER_SEC.store(0, Ordering::Relaxed);
    }
}

struct MinerTargetState {
    epoch: EpochId,
    epoch_seed: Hash32,
    enabled: bool,
    stop_all: bool,
    top2_weights: [u64; 2],
}

struct BackgroundPoncPool {
    target: Arc<Mutex<MinerTargetState>>,
    rx: mpsc::Receiver<ComputeShare>,
}

impl BackgroundPoncPool {
    fn spawn(author: Address, vm_cfg: PoncVmConfig, enable_pool: bool) -> Self {
        let (tx, rx) = mpsc::channel::<ComputeShare>();
        let target = Arc::new(Mutex::new(MinerTargetState {
            epoch: EpochId(0),
            epoch_seed: Hash32::ZERO,
            enabled: false,
            stop_all: !enable_pool,
            top2_weights: [0, 0],
        }));

        if enable_pool {
            let max_workers = thread::available_parallelism()
                .map(|p| p.get())
                .unwrap_or(1)
                .clamp(1, 32);
            let hash_counter = Arc::new(AtomicU64::new(0));
            let sample_clock = Arc::new(Mutex::new(Instant::now()));

            for worker_idx in 0..max_workers {
                let target_ref = Arc::clone(&target);
                let tx_out = tx.clone();
                let counter_ref = Arc::clone(&hash_counter);
                let clock_ref = Arc::clone(&sample_clock);

                thread::spawn(move || {
                    let mut step: u64 = 0;
                    let mut observed_epoch = EpochId(u64::MAX);
                    loop {
                        let (epoch, seed, enabled, stop_all, floor_w) = {
                            let guard = target_ref.lock().unwrap();
                            (
                                guard.epoch,
                                guard.epoch_seed,
                                guard.enabled,
                                guard.stop_all,
                                guard.top2_weights[0].min(guard.top2_weights[1]),
                            )
                        };
                        if stop_all {
                            break;
                        }
                        let active_limit = current_ponc_miner_threads();
                        if !enabled || worker_idx >= active_limit {
                            thread::sleep(Duration::from_millis(50));
                            continue;
                        }
                        if epoch != observed_epoch {
                            observed_epoch = epoch;
                            step = 0;
                        }

                        // Execute a non-blocking batch of 32 memory-hard CPU VM evaluations:
                        let mut best_in_batch: Option<ComputeShare> = None;
                        for _ in 0..32u64 {
                            let nonce = 1_000_000u64
                                .wrapping_add(epoch.0.wrapping_mul(1_000_003))
                                .wrapping_add(worker_idx as u64)
                                .wrapping_add(step.wrapping_mul(max_workers as u64));
                            step = step.wrapping_add(1);
                            if let Some(sh) = ComputeShare::try_cpu_share_at_nonce(
                                epoch,
                                &seed,
                                author,
                                Vec::new(),
                                nonce,
                                3,
                                &vm_cfg,
                            ) && sh.verified_weight > floor_w.saturating_add(floor_w / 10)
                                && best_in_batch
                                    .as_ref()
                                    .is_none_or(|prev| sh.verified_weight > prev.verified_weight)
                            {
                                best_in_batch = Some(sh);
                            }
                        }

                        let prev_hashes = counter_ref.fetch_add(32, Ordering::Relaxed) + 32;
                        if worker_idx == 0
                            && let Ok(mut clk) = clock_ref.try_lock()
                        {
                            let elapsed = clk.elapsed().as_secs_f64();
                            if elapsed >= 1.0 {
                                let total = counter_ref.swap(0, Ordering::Relaxed);
                                PONC_HASHRATE_HPS
                                    .store((total as f64 / elapsed) as u64, Ordering::Relaxed);
                                *clk = Instant::now();
                            }
                        } else if prev_hashes > 1_000_000
                            && let Ok(mut clk) = clock_ref.try_lock()
                        {
                            let elapsed = clk.elapsed().as_secs_f64().max(0.05);
                            let total = counter_ref.swap(0, Ordering::Relaxed);
                            PONC_HASHRATE_HPS
                                .store((total as f64 / elapsed) as u64, Ordering::Relaxed);
                            *clk = Instant::now();
                        }

                        if let Some(candidate) = best_in_batch {
                            let should_send = {
                                let mut guard = target_ref.lock().unwrap();
                                if guard.epoch == candidate.epoch && guard.enabled {
                                    let min_slot = if guard.top2_weights[0] <= guard.top2_weights[1]
                                    {
                                        0
                                    } else {
                                        1
                                    };
                                    let cur_min = guard.top2_weights[min_slot];
                                    if candidate.verified_weight
                                        > cur_min.saturating_add(cur_min / 10)
                                    {
                                        guard.top2_weights[min_slot] = candidate.verified_weight;
                                        true
                                    } else {
                                        false
                                    }
                                } else {
                                    false
                                }
                            };
                            if should_send && tx_out.send(candidate).is_err() {
                                break;
                            }
                        }
                    }
                });
            }
        }

        Self { target, rx }
    }

    fn sync_epoch(&self, epoch: EpochId, seed: Hash32, enabled: bool) {
        let mut guard = self.target.lock().unwrap();
        if guard.epoch != epoch || guard.epoch_seed != seed {
            guard.epoch = epoch;
            guard.epoch_seed = seed;
            guard.top2_weights = [0, 0];
        }
        guard.enabled = enabled;
        if !enabled {
            PONC_HASHRATE_HPS.store(0, Ordering::Relaxed);
        }
    }
}

impl Drop for BackgroundPoncPool {
    fn drop(&mut self) {
        if let Ok(mut guard) = self.target.lock() {
            guard.stop_all = true;
            guard.enabled = false;
        }
        PONC_HASHRATE_HPS.store(0, Ordering::Relaxed);
        PONC_LOCAL_EPOCH_WEIGHT.store(0, Ordering::Relaxed);
    }
}

/// Configuration for a standalone P2P mesh validator / laptop participant node.
#[derive(Clone, Debug)]
pub struct MeshPeerConfig {
    pub network: NetworkProfile,
    pub bind_addr: SocketAddr,
    pub data_dir: PathBuf,
    pub seed_peers: Vec<SocketAddr>,
    pub min_quorum_peers: usize,
    pub epoch_interval: Duration,
}

struct EstablishedPeer {
    address: Address,
    static_x25519: [u8; 32],
    cipher: SessionCipher,
}

struct PendingQuorumRequest {
    client_addr: SocketAddr,
    tx: Transaction,
    value_commitment: [u8; 32],
    bulletproof_672: Vec<u8>,
    fee_split: FeeSplit,
    voters: BTreeSet<Address>,
    signed_weight: u64,
    started_at: Instant,
    last_retry: Instant,
}

enum VerifyTask {
    ClientFastPay {
        client_addr: SocketAddr,
        tx: Transaction,
        value_commitment: [u8; 32],
        bulletproof_672: Vec<u8>,
    },
    PeerVote {
        peer_addr: SocketAddr,
        request_id: u64,
        tx: Transaction,
        value_commitment: [u8; 32],
        bulletproof_672: Vec<u8>,
    },
}

struct BulletproofVerifierPool {
    job_tx: mpsc::Sender<VerifyTask>,
    done_rx: mpsc::Receiver<(VerifyTask, bool)>,
}

impl BulletproofVerifierPool {
    fn new() -> Self {
        let workers = if cfg!(debug_assertions) {
            1
        } else {
            thread::available_parallelism()
                .map(|p| p.get())
                .unwrap_or(1)
                .clamp(1, 8)
        };
        let (job_tx, job_rx) = mpsc::channel::<VerifyTask>();
        let (done_tx, done_rx) = mpsc::channel::<(VerifyTask, bool)>();
        let shared_rx = Arc::new(Mutex::new(job_rx));
        for worker_idx in 0..workers {
            let rx = Arc::clone(&shared_rx);
            let tx_out = done_tx.clone();
            thread::spawn(move || {
                let mut batch_seq = 0u64;
                loop {
                    let mut batch = Vec::with_capacity(16);
                    {
                        let guard = rx.lock().unwrap();
                        let Ok(first) = guard.recv() else {
                            break;
                        };
                        batch.push(first);
                        while batch.len() < 16 {
                            match guard.try_recv() {
                                Ok(next) => batch.push(next),
                                Err(_) => break,
                            }
                        }
                    }

                    if batch.len() == 1 {
                        let task = batch.pop().unwrap();
                        let (vc_bytes, bp_bytes) = task_commitment_and_proof(&task);
                        let ok = PedersenCommitment::from_bytes(vc_bytes)
                            .zip(BulletproofRange64::from_bytes(bp_bytes, 64))
                            .is_some_and(|(vc, bp)| bp.verify(&vc, 64));
                        if tx_out.send((task, ok)).is_err() {
                            break;
                        }
                        continue;
                    }

                    batch_seq = batch_seq.wrapping_add(1);
                    let nanos = SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_nanos();
                    let entropy = domain_hash(
                        "XCR.MESH.BP_BATCH_ENTROPY.V1",
                        &[
                            &(worker_idx as u64).to_le_bytes(),
                            &batch_seq.to_le_bytes(),
                            &nanos.to_le_bytes(),
                        ],
                    )
                    .0;

                    let decoded: Vec<Option<(PedersenCommitment, BulletproofRange64)>> = batch
                        .iter()
                        .map(|t| {
                            let (vc_b, bp_b) = task_commitment_and_proof(t);
                            PedersenCommitment::from_bytes(vc_b)
                                .zip(BulletproofRange64::from_bytes(bp_b, 64))
                        })
                        .collect();

                    let valid_refs: Vec<(&PedersenCommitment, &BulletproofRange64)> = decoded
                        .iter()
                        .filter_map(|opt| opt.as_ref().map(|(vc, bp)| (vc, bp)))
                        .collect();

                    let all_decoded_valid = !valid_refs.is_empty()
                        && BulletproofRange64::verify_batch(&valid_refs, 64, &entropy);

                    for (task, dec_opt) in batch.into_iter().zip(decoded) {
                        let ok = match dec_opt {
                            None => false,
                            Some(_) if all_decoded_valid => true,
                            Some((vc, bp)) => bp.verify(&vc, 64),
                        };
                        if tx_out.send((task, ok)).is_err() {
                            return;
                        }
                    }
                }
            });
        }
        Self { job_tx, done_rx }
    }
}

fn task_commitment_and_proof(task: &VerifyTask) -> (&[u8; 32], &[u8]) {
    match task {
        VerifyTask::ClientFastPay {
            value_commitment,
            bulletproof_672,
            ..
        }
        | VerifyTask::PeerVote {
            value_commitment,
            bulletproof_672,
            ..
        } => (value_commitment, bulletproof_672.as_slice()),
    }
}

#[derive(Default)]
struct CommitTracker {
    initial_grants: BTreeMap<Address, (PublicKey, Amount, Amount)>,
    by_id: BTreeMap<Hash32, (Transaction, Amount, Amount)>,
    by_sender_nonce: BTreeMap<(Address, u64), Hash32>,
    recent_order: VecDeque<Hash32>,
    deferred: BTreeMap<(Address, u64), (Transaction, Amount, Amount)>,
}

impl CommitTracker {
    fn record_committed(&mut self, tx: &Transaction, fee_worker: Amount, fee_burned: Amount) {
        if self.by_id.contains_key(&tx.id) {
            return;
        }
        if let TransactionKind::FastTransfer { from, nonce, .. } = &tx.kind {
            self.by_sender_nonce.insert((*from, *nonce), tx.id);
        }
        self.by_id
            .insert(tx.id, (tx.clone(), fee_worker, fee_burned));
        self.recent_order.push_back(tx.id);
        while self.recent_order.len() > 512 {
            if let Some(evicted) = self.recent_order.pop_front()
                && let Some((old_tx, _, _)) = self.by_id.remove(&evicted)
                && let TransactionKind::FastTransfer { from, nonce, .. } = &old_tx.kind
            {
                self.by_sender_nonce.remove(&(*from, *nonce));
            }
        }
    }

    fn apply_or_defer(
        &mut self,
        tx: &Transaction,
        fee_worker: Amount,
        fee_burned: Amount,
        ledger: &mut PersistentLedger,
        locks: &mut BTreeMap<(Address, u64), Hash32>,
        unsettled_fee_bits: &mut i64,
    ) -> io::Result<bool> {
        if ledger.finalized_txs.contains(&tx.id) {
            return Ok(false);
        }
        let TransactionKind::FastTransfer { from, nonce, .. } = &tx.kind else {
            return Ok(false);
        };
        let sender = *from;
        let tx_nonce = *nonce;

        let local_nonce = ledger.pockets.get(&sender).map(|sp| sp.state.nonce);
        match local_nonce {
            None => {
                self.deferred
                    .insert((sender, tx_nonce), (tx.clone(), fee_worker, fee_burned));
                Ok(false)
            }
            Some(cur) if cur < tx_nonce => {
                self.deferred
                    .insert((sender, tx_nonce), (tx.clone(), fee_worker, fee_burned));
                Ok(false)
            }
            Some(cur) if cur > tx_nonce => Ok(false),
            Some(_) => {
                if apply_finalized_tx_to_wal(tx, fee_worker, fee_burned, ledger, locks)? {
                    *unsettled_fee_bits = unsettled_fee_bits.saturating_add(tx.fee().bits() as i64);
                    self.record_committed(tx, fee_worker, fee_burned);
                    self.drain_deferred_for_sender(sender, ledger, locks, unsettled_fee_bits)?;
                    Ok(true)
                } else {
                    Ok(false)
                }
            }
        }
    }

    fn drain_deferred_for_sender(
        &mut self,
        sender: Address,
        ledger: &mut PersistentLedger,
        locks: &mut BTreeMap<(Address, u64), Hash32>,
        unsettled_fee_bits: &mut i64,
    ) -> io::Result<()> {
        while let Some(expected_nonce) = ledger.pockets.get(&sender).map(|sp| sp.state.nonce) {
            let Some((queued_tx, qw, qb)) = self.deferred.remove(&(sender, expected_nonce)) else {
                break;
            };
            if ledger.finalized_txs.contains(&queued_tx.id) {
                continue;
            }
            if apply_finalized_tx_to_wal(&queued_tx, qw, qb, ledger, locks)? {
                *unsettled_fee_bits =
                    unsettled_fee_bits.saturating_add(queued_tx.fee().bits() as i64);
                self.record_committed(&queued_tx, qw, qb);
            } else {
                break;
            }
        }
        Ok(())
    }

    fn recent_summary(&self, max_ids: usize) -> Vec<Hash32> {
        self.recent_order
            .iter()
            .rev()
            .take(max_ids)
            .copied()
            .collect()
    }
}

#[derive(Default)]
struct InFlightWanSync {
    peer: Option<SocketAddr>,
    expected_index: u32,
    last_progress_at: Option<Instant>,
    last_req_at: Option<Instant>,
    active_epoch: EpochId,
    settled_epoch: EpochId,
    active_epoch_seed: Hash32,
    circulating_supply: Amount,
    total_burned: Amount,
    endurance_balance: Amount,
    unsettled_fee_bits: i64,
    committee_members: Vec<QuorumMember>,
    active_shares: Vec<(ComputeShare, PublicKey, PublicKey)>,
    pockets: BTreeMap<Address, StoredPocket>,
    stealth_utxos: BTreeMap<Address, Amount>,
    spent_nullifiers: BTreeSet<Hash32>,
    finalized_txs: BTreeSet<Hash32>,
}

impl InFlightWanSync {
    fn begin(&mut self, peer: SocketAddr) {
        let now = Instant::now();
        *self = Self {
            peer: Some(peer),
            expected_index: 0,
            last_progress_at: Some(now),
            last_req_at: Some(now),
            ..Self::default()
        };
    }
}

/// Runs a live distributed P2P Credits node (`credit-node peer`).
pub fn run_mesh_peer(cfg: MeshPeerConfig) -> io::Result<()> {
    run_mesh_peer_with_beacon(cfg, None)
}

/// Runs a live distributed P2P Credits node with an optional Mainnet Genesis Beacon commitment.
pub fn run_mesh_peer_with_beacon(
    cfg: MeshPeerConfig,
    initial_beacon: Option<(String, String)>,
) -> io::Result<()> {
    run_mesh_peer_with_reward_pubkey(cfg, initial_beacon, None)
}

/// Runs a live distributed P2P Credits node crediting epoch rewards to `reward_pubkey_override`
/// (allowing `credit-desktop` to mine directly into an `XCRENC01`-encrypted user wallet).
pub fn run_mesh_peer_with_reward_pubkey(
    cfg: MeshPeerConfig,
    initial_beacon: Option<(String, String)>,
    reward_pubkey_override: Option<PublicKey>,
) -> io::Result<()> {
    fs::create_dir_all(&cfg.data_dir)?;
    let mut identity = load_or_create_node_identity(&cfg.data_dir)?;
    let local_address = identity.address();
    let local_val_pk = identity.validator_public_key();
    let local_reward_pk = match reward_pubkey_override {
        Some(pk) => pk,
        None => load_or_create_miner_wallet_pubkey(&cfg.data_dir)?,
    };

    let wal_path = cfg.data_dir.join("credit.wal");
    let mut ledger = PersistentLedger::open(&wal_path)?;
    let mut stealth_announcements = load_stealth_announcements(&cfg.data_dir);
    let mut stealth_memos = load_stealth_memos(&cfg.data_dir);

    let mut endpoint = UdpQuicEndpoint::bind(cfg.bind_addr, 0x7270_0001, Duration::from_millis(4))?;
    let actual_bind = endpoint.local_addr();
    let _ = fs::write(
        cfg.data_dir.join("bound_port.txt"),
        actual_bind.port().to_string(),
    );

    let mut dht = KademliaRoutingTable::new(local_address);
    let mut nat_detector = NatDetector::new(actual_bind);
    let mut pending_handshakes: BTreeMap<SocketAddr, (InitiatorHandshake, Instant)> =
        BTreeMap::new();
    let mut sessions: BTreeMap<SocketAddr, EstablishedPeer> = BTreeMap::new();
    let mut known_targets: BTreeSet<SocketAddr> = cfg.seed_peers.iter().copied().collect();
    known_targets.remove(&actual_bind);

    let vm_cfg = PoncVmConfig::devnet_profile();
    let mut active_epoch = if ledger.circulating_supply.is_zero() {
        EpochId(0)
    } else {
        EpochId(ledger.latest_epoch.0 + 1)
    };
    let mut active_epoch_seed = derive_epoch_seed(cfg.network, active_epoch, &Hash32::ZERO);
    let mut standby_locked = cfg.network == NetworkProfile::Mainnet
        && ledger.circulating_supply.is_zero()
        && ledger.latest_epoch == EpochId(0);
    let mut unlocked_beacon: Option<VerifiableGenesisBeacon> = None;
    let beacon_file = cfg.data_dir.join("genesis_beacon.txt");
    let persisted_or_cli_beacon = initial_beacon.or_else(|| {
        let raw = fs::read_to_string(&beacon_file).ok()?;
        let mut lines = raw.lines();
        Some((
            lines.next()?.trim().to_owned(),
            lines.next()?.trim().to_owned(),
        ))
    });
    if standby_locked
        && let Some((ref btc_hex, ref headline)) = persisted_or_cli_beacon
        && is_valid_64_hex(btc_hex)
    {
        let now_unix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        if let GenesisStandbyStatus::ReadyToLaunch(b) =
            VerifiableGenesisBeacon::evaluate_genesis_standby(
                now_unix,
                Some(btc_hex),
                Some(headline),
            )
        {
            active_epoch_seed = b.derive_epoch0_seed();
            standby_locked = false;
            let _ = fs::write(&beacon_file, format!("{btc_hex}\n{headline}\n"));
            unlocked_beacon = Some(b);
        }
    }

    let mut share_dag = EpochShareDag::new(active_epoch, active_epoch_seed, 3, vm_cfg);
    // Maps validator `author` -> `(validator_pubkey, miner_reward_pocket_pubkey)`.
    let mut share_meta: BTreeMap<Address, (PublicKey, PublicKey)> = BTreeMap::new();
    let mut non_equivocation_locks: BTreeMap<(Address, u64), Hash32> = BTreeMap::new();
    let mut committee: Option<QuorumCommittee> = None;
    let mut endurance_pool = SecurityEndurancePool::new();
    let mut unsettled_fee_bits: i64 = 0;
    let boot_instant = Instant::now();
    let mut epoch_started_at = boot_instant;
    let mut has_mined_current_epoch = false;
    let mut awaiting_initial_sync = !known_targets.is_empty();
    let mut wan_sync = InFlightWanSync::default();
    let mut failed_sync_peers: BTreeMap<SocketAddr, Instant> = BTreeMap::new();

    // Bootstrap seed node (no `--seed` flags) mines its Genesis Epoch-0 PoNC share immediately:
    if !standby_locked && !awaiting_initial_sync && active_epoch == EpochId(0) {
        let own_share = ComputeShare::mine_cpu_share(
            EpochId(0),
            &active_epoch_seed,
            local_address,
            vec![],
            0,
            3,
            &vm_cfg,
        );
        share_dag
            .submit_share(own_share)
            .expect("valid local genesis share");
        share_meta.insert(local_address, (local_val_pk, local_reward_pk));
        has_mined_current_epoch = true;

        if share_meta.len() >= cfg.min_quorum_peers {
            let sealed_shares = collect_ordered_shares(&share_dag, &share_meta);
            let settled_fees = Amount::from_bits(unsettled_fee_bits.max(0) as u64);
            apply_epoch_seal(
                cfg.network,
                &vm_cfg,
                EpochId(0),
                settled_fees,
                &sealed_shares,
                &mut active_epoch,
                &mut active_epoch_seed,
                &mut share_dag,
                &mut share_meta,
                &mut unsettled_fee_bits,
                &mut endurance_pool,
                &mut ledger,
                &mut committee,
                &mut epoch_started_at,
                &mut has_mined_current_epoch,
            )?;
        }
    }

    let bg_ponc_pool = BackgroundPoncPool::spawn(
        local_address,
        vm_cfg,
        cfg.epoch_interval >= Duration::from_secs(5),
    );
    bg_ponc_pool.sync_epoch(
        active_epoch,
        active_epoch_seed,
        !standby_locked && !awaiting_initial_sync,
    );
    let bg_gpu_zk_pool =
        BackgroundGpuZkPool::spawn(local_address, cfg.epoch_interval >= Duration::from_secs(5));
    let mut epoch_start_tx_count = ledger.finalized_txs.len();

    let mut next_vote_req_id = 1u64;
    let mut pending_votes: BTreeMap<u64, PendingQuorumRequest> = BTreeMap::new();
    let mut swap_offers: BTreeMap<Hash32, Vec<u8>> = BTreeMap::new();
    let bp_pool = BulletproofVerifierPool::new();
    let mut verified_bp_cache: BTreeMap<Hash32, [u8; 32]> = BTreeMap::new();
    let mut in_flight_peer_votes: BTreeMap<Hash32, Vec<(SocketAddr, u64)>> = BTreeMap::new();
    let mut in_flight_client_txs: BTreeSet<Hash32> = BTreeSet::new();
    let mut commit_tracker = CommitTracker::default();
    for (&addr, sp) in &ledger.pockets {
        if sp.state.nonce == 0 {
            commit_tracker.initial_grants.insert(
                addr,
                (sp.public_key, sp.state.balance, sp.state.daily_limit),
            );
        }
    }
    let mut handshake_counter = 1u64;
    let mut last_maintenance = Instant::now() - Duration::from_secs(1);
    let mut last_wal_flush = Instant::now();
    let mut last_anti_entropy = Instant::now();

    println!(
        "READY bind={} peer_id={} state_root={}",
        actual_bind,
        local_address,
        ledger.state_merkle_root()
    );
    io::stdout().flush()?;

    for &seed_addr in &known_targets {
        initiate_handshake(
            &mut endpoint,
            &identity,
            seed_addr,
            &mut pending_handshakes,
            &mut handshake_counter,
        )?;
    }

    loop {
        // Drain completed parallel 64-bit Curve25519 Bulletproof verifications from worker pool:
        while let Ok((completed_task, bp_ok)) = bp_pool.done_rx.try_recv() {
            match completed_task {
                VerifyTask::ClientFastPay {
                    client_addr,
                    tx,
                    value_commitment,
                    bulletproof_672,
                } => {
                    in_flight_client_txs.remove(&tx.id);
                    if !bp_ok {
                        let _ = send_rpc_reply(
                            &mut endpoint,
                            client_addr,
                            &NodeRpcResponse::FastPayReceipt {
                                accepted: false,
                                tx_id: tx.id,
                                finality_latency_ms: 0,
                                fee_worker: Amount::ZERO,
                                fee_burned: Amount::ZERO,
                                new_state_root: ledger.state_merkle_root(),
                                message: "rejected: 64-bit Bulletproof verification failed"
                                    .to_owned(),
                            },
                        );
                        continue;
                    }
                    if verified_bp_cache.len() >= 2048 {
                        verified_bp_cache.clear();
                    }
                    verified_bp_cache.insert(tx.id, value_commitment);

                    if ledger.finalized_txs.contains(&tx.id) {
                        let fs = FeeSplit::compute(tx.fee());
                        let _ = send_rpc_reply(
                            &mut endpoint,
                            client_addr,
                            &NodeRpcResponse::FastPayReceipt {
                                accepted: true,
                                tx_id: tx.id,
                                finality_latency_ms: 1,
                                fee_worker: fs.worker_reward,
                                fee_burned: fs.burned,
                                new_state_root: ledger.state_merkle_root(),
                                message: "already finalized (idempotent receipt)".to_owned(),
                            },
                        );
                        continue;
                    }
                    let Some(comm) = &committee else {
                        let _ = send_rpc_reply(
                            &mut endpoint,
                            client_addr,
                            &NodeRpcResponse::FastPayReceipt {
                                accepted: false,
                                tx_id: tx.id,
                                finality_latency_ms: 0,
                                fee_worker: Amount::ZERO,
                                fee_burned: Amount::ZERO,
                                new_state_root: ledger.state_merkle_root(),
                                message: "mesh quorum still bootstrapping".to_owned(),
                            },
                        );
                        continue;
                    };
                    if let Err(reason) = validate_fast_transfer_state_and_sig(
                        &tx,
                        &value_commitment,
                        &ledger,
                        &mut non_equivocation_locks,
                        true,
                    ) {
                        let _ = send_rpc_reply(
                            &mut endpoint,
                            client_addr,
                            &NodeRpcResponse::FastPayReceipt {
                                accepted: false,
                                tx_id: tx.id,
                                finality_latency_ms: 0,
                                fee_worker: Amount::ZERO,
                                fee_burned: Amount::ZERO,
                                new_state_root: ledger.state_merkle_root(),
                                message: reason,
                            },
                        );
                        continue;
                    }
                    let req_id = next_vote_req_id;
                    next_vote_req_id += 1;
                    let fee_split = FeeSplit::compute(tx.fee());
                    let mut voters = BTreeSet::new();
                    let mut signed_weight = 0u64;
                    if let Some(self_member) =
                        comm.members().iter().find(|m| m.address == local_address)
                    {
                        let vote_msg = domain_hash(
                            "XCR.CONSENSUS.FAST_VOTE.V1",
                            &[cfg.network.chain_id().as_bytes(), tx.id.as_bytes()],
                        );
                        let _ = identity.validator_keypair_mut().sign(vote_msg.as_bytes());
                        voters.insert(local_address);
                        signed_weight = self_member.weight;
                    }
                    if signed_weight >= comm.quorum_threshold() {
                        let _ = commit_tracker.apply_or_defer(
                            &tx,
                            fee_split.worker_reward,
                            fee_split.burned,
                            &mut ledger,
                            &mut non_equivocation_locks,
                            &mut unsettled_fee_bits,
                        )?;
                        let _ = send_rpc_reply(
                            &mut endpoint,
                            client_addr,
                            &NodeRpcResponse::FastPayReceipt {
                                accepted: true,
                                tx_id: tx.id,
                                finality_latency_ms: 1,
                                fee_worker: fee_split.worker_reward,
                                fee_burned: fee_split.burned,
                                new_state_root: ledger.state_merkle_root(),
                                message: "1-RTT finalized".to_owned(),
                            },
                        );
                    } else {
                        broadcast_encrypted(
                            &mut endpoint,
                            &mut sessions,
                            None,
                            &P2pMessage::QuorumVoteRequest {
                                request_id: req_id,
                                tx: tx.clone(),
                                value_commitment,
                                bulletproof_672: bulletproof_672.clone(),
                            },
                        );
                        let now_inst = Instant::now();
                        pending_votes.insert(
                            req_id,
                            PendingQuorumRequest {
                                client_addr,
                                tx,
                                value_commitment,
                                bulletproof_672,
                                fee_split,
                                voters,
                                signed_weight,
                                started_at: now_inst,
                                last_retry: now_inst,
                            },
                        );
                    }
                }
                VerifyTask::PeerVote {
                    peer_addr,
                    request_id,
                    tx,
                    value_commitment,
                    ..
                } => {
                    let mut waiters = in_flight_peer_votes.remove(&tx.id).unwrap_or_default();
                    if !waiters.contains(&(peer_addr, request_id)) {
                        waiters.push((peer_addr, request_id));
                    }
                    if !bp_ok {
                        continue;
                    }
                    if verified_bp_cache.len() >= 2048 {
                        verified_bp_cache.clear();
                    }
                    verified_bp_cache.insert(tx.id, value_commitment);
                    if committee.is_some()
                        && (ledger.finalized_txs.contains(&tx.id)
                            || validate_fast_transfer_state_and_sig(
                                &tx,
                                &value_commitment,
                                &ledger,
                                &mut non_equivocation_locks,
                                true,
                            )
                            .is_ok())
                    {
                        let vote_msg = domain_hash(
                            "XCR.CONSENSUS.FAST_VOTE.V1",
                            &[cfg.network.chain_id().as_bytes(), tx.id.as_bytes()],
                        );
                        let sig_bytes = identity
                            .validator_keypair_mut()
                            .sign(vote_msg.as_bytes())
                            .to_bytes();
                        for (wait_peer, wait_req_id) in waiters {
                            let reply = P2pMessage::QuorumVoteReply {
                                request_id: wait_req_id,
                                tx_id: tx.id,
                                validator: local_address,
                                vote_signature: sig_bytes.clone(),
                            };
                            let _ = send_encrypted(&mut endpoint, &mut sessions, wait_peer, &reply);
                        }
                    }
                }
            }
        }

        // Group-commit WAL durability flush every 25ms (eliminates per-tx fsync bottlenecks):
        if last_wal_flush.elapsed() >= Duration::from_millis(25) {
            last_wal_flush = Instant::now();
            ledger.flush_wal()?;
        }

        if last_maintenance.elapsed() >= Duration::from_millis(75) {
            last_maintenance = Instant::now();

            // 1. Dial discovered DHT peers not yet connected (expiring unanswered handshakes after 1.5s):
            pending_handshakes.retain(|_, (_, t)| t.elapsed() < Duration::from_millis(1_500));
            let targets: Vec<SocketAddr> = known_targets.iter().copied().collect();
            for target_addr in targets {
                if target_addr != actual_bind
                    && !sessions.contains_key(&target_addr)
                    && !pending_handshakes.contains_key(&target_addr)
                {
                    let _ = initiate_handshake(
                        &mut endpoint,
                        &identity,
                        target_addr,
                        &mut pending_handshakes,
                        &mut handshake_counter,
                    );
                }
            }

            // 2. Retry in-flight `<1,200B` WAN sync cursor, and quarantine stalled/outdated sync peers:
            if let (Some(stalled_peer), Some(last_prog)) =
                (wan_sync.peer, wan_sync.last_progress_at)
                && last_prog.elapsed() >= Duration::from_millis(2_000)
            {
                failed_sync_peers.insert(stalled_peer, Instant::now());
                wan_sync = InFlightWanSync::default();
                awaiting_initial_sync = false;
            }
            if awaiting_initial_sync {
                if wan_sync.peer.is_none()
                    && let Some(&first_peer) = sessions.keys().find(|addr| {
                        !failed_sync_peers
                            .get(*addr)
                            .is_some_and(|t| t.elapsed() < Duration::from_secs(120))
                    })
                {
                    wan_sync.begin(first_peer);
                    let _ = send_encrypted(
                        &mut endpoint,
                        &mut sessions,
                        first_peer,
                        &P2pMessage::SyncChunkRequest { start_index: 0 },
                    );
                } else if boot_instant.elapsed() >= Duration::from_millis(1_500)
                    && wan_sync.peer.is_none()
                {
                    awaiting_initial_sync = false;
                }
            }
            if let (Some(sync_peer), Some(t_req)) = (wan_sync.peer, wan_sync.last_req_at)
                && t_req.elapsed() >= Duration::from_millis(220)
            {
                wan_sync.last_req_at = Some(Instant::now());
                let _ = send_encrypted(
                    &mut endpoint,
                    &mut sessions,
                    sync_peer,
                    &P2pMessage::SyncChunkRequest {
                        start_index: wan_sync.expected_index,
                    },
                );
            }

            // 3. Continuous multi-epoch PoNC mining & canonical `EpochSeal` coordination:
            // Auto-check CLI/persisted beacon if Mainnet Genesis timestamp (`2027-01-01T00:00:00Z`) just arrived!
            if standby_locked
                && let Some((ref btc_hex, ref headline)) = persisted_or_cli_beacon
                && is_valid_64_hex(btc_hex)
            {
                let now_unix = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .map(|d| d.as_secs())
                    .unwrap_or(0);
                if let GenesisStandbyStatus::ReadyToLaunch(b) =
                    VerifiableGenesisBeacon::evaluate_genesis_standby(
                        now_unix,
                        Some(btc_hex),
                        Some(headline),
                    )
                {
                    active_epoch = EpochId(0);
                    active_epoch_seed = b.derive_epoch0_seed();
                    share_dag = EpochShareDag::new(active_epoch, active_epoch_seed, 3, vm_cfg);
                    share_meta.clear();
                    has_mined_current_epoch = false;
                    epoch_started_at = Instant::now();
                    standby_locked = false;
                    let _ = fs::write(&beacon_file, format!("{btc_hex}\n{headline}\n"));
                    broadcast_encrypted(
                        &mut endpoint,
                        &mut sessions,
                        None,
                        &P2pMessage::AnnounceGenesisBeacon {
                            btc_block_hash_hex: b.external_randomness_hex.clone(),
                            public_headline: b.public_headline.clone(),
                            timestamp_unix: b.launch_timestamp_unix,
                        },
                    );
                    unlocked_beacon = Some(b);
                }
            }

            let prev_tracked_epoch = bg_gpu_zk_pool.state.lock().unwrap().epoch;
            if prev_tracked_epoch != active_epoch {
                epoch_start_tx_count = ledger.finalized_txs.len();
            }
            let epoch_tx_delta = ledger
                .finalized_txs
                .len()
                .saturating_sub(epoch_start_tx_count) as u32;
            let mining_active =
                !standby_locked && !awaiting_initial_sync && wan_sync.peer.is_none();
            bg_ponc_pool.sync_epoch(active_epoch, active_epoch_seed, mining_active);
            bg_gpu_zk_pool.sync_state(
                active_epoch,
                active_epoch_seed,
                ledger.state_merkle_root(),
                epoch_tx_delta,
                mining_active,
            );

            if mining_active {
                if !has_mined_current_epoch && !share_meta.contains_key(&local_address) {
                    let salt = active_epoch.0.wrapping_mul(131).wrapping_add(1);
                    let own_share = ComputeShare::mine_cpu_share(
                        active_epoch,
                        &active_epoch_seed,
                        local_address,
                        Vec::new(),
                        salt,
                        3,
                        &vm_cfg,
                    );
                    if share_dag.upsert_best_cpu_share(own_share.clone()) == Ok(true) {
                        share_meta.insert(local_address, (local_val_pk, local_reward_pk));
                        has_mined_current_epoch = true;
                        PONC_LOCAL_EPOCH_WEIGHT
                            .store(share_dag.worker_weight(&local_address), Ordering::Relaxed);
                        broadcast_encrypted(
                            &mut endpoint,
                            &mut sessions,
                            None,
                            &P2pMessage::GossipShare {
                                share: own_share,
                                author_pubkey: local_val_pk,
                                reward_pubkey: local_reward_pk,
                            },
                        );
                    }
                }

                // Drain stronger PoNC shares discovered by background multi-core CPU worker threads:
                while let Ok(upgraded_share) = bg_ponc_pool.rx.try_recv() {
                    if upgraded_share.epoch == active_epoch
                        && share_dag.upsert_best_cpu_share(upgraded_share.clone()) == Ok(true)
                    {
                        share_meta.insert(local_address, (local_val_pk, local_reward_pk));
                        has_mined_current_epoch = true;
                        PONC_LOCAL_EPOCH_WEIGHT
                            .store(share_dag.worker_weight(&local_address), Ordering::Relaxed);
                        broadcast_encrypted(
                            &mut endpoint,
                            &mut sessions,
                            None,
                            &P2pMessage::GossipShare {
                                share: upgraded_share,
                                author_pubkey: local_val_pk,
                                reward_pubkey: local_reward_pk,
                            },
                        );
                    }
                }

                // Drain Tier-2 GPU `RecursiveZkState` shares produced when real epoch transactions flow:
                while let Ok(zk_share) = bg_gpu_zk_pool.rx.try_recv() {
                    if zk_share.epoch == active_epoch
                        && share_dag.upsert_best_zk_share(zk_share.clone()) == Ok(true)
                    {
                        share_meta.insert(local_address, (local_val_pk, local_reward_pk));
                        has_mined_current_epoch = true;
                        PONC_LOCAL_EPOCH_WEIGHT
                            .store(share_dag.worker_weight(&local_address), Ordering::Relaxed);
                        broadcast_encrypted(
                            &mut endpoint,
                            &mut sessions,
                            None,
                            &P2pMessage::GossipShare {
                                share: zk_share,
                                author_pubkey: local_val_pk,
                                reward_pubkey: local_reward_pk,
                            },
                        );
                    }
                }

                let ready_to_seal = active_epoch == EpochId(0)
                    || committee.is_none()
                    || epoch_started_at.elapsed() >= cfg.epoch_interval;

                if ready_to_seal
                    && share_meta.len() >= cfg.min_quorum_peers
                    && is_epoch_seal_coordinator(
                        local_address,
                        active_epoch,
                        &committee,
                        &share_meta,
                        epoch_started_at,
                        cfg.epoch_interval,
                    )
                {
                    let sealed_shares = collect_ordered_shares(&share_dag, &share_meta);
                    let sealing_epoch = active_epoch;
                    let settled_fees = Amount::from_bits(unsettled_fee_bits.max(0) as u64);
                    apply_epoch_seal(
                        cfg.network,
                        &vm_cfg,
                        sealing_epoch,
                        settled_fees,
                        &sealed_shares,
                        &mut active_epoch,
                        &mut active_epoch_seed,
                        &mut share_dag,
                        &mut share_meta,
                        &mut unsettled_fee_bits,
                        &mut endurance_pool,
                        &mut ledger,
                        &mut committee,
                        &mut epoch_started_at,
                        &mut has_mined_current_epoch,
                    )?;
                    broadcast_encrypted(
                        &mut endpoint,
                        &mut sessions,
                        None,
                        &P2pMessage::EpochSeal {
                            epoch: sealing_epoch,
                            settled_fees,
                            shares: sealed_shares,
                        },
                    );
                }
            }

            // 4. Periodically exchange DHT peers + re-gossip current epoch shares:
            let peer_addrs: Vec<SocketAddr> = sessions.keys().copied().collect();
            for peer_addr in peer_addrs {
                let _ = send_encrypted(
                    &mut endpoint,
                    &mut sessions,
                    peer_addr,
                    &P2pMessage::DiscoverPing {
                        target: local_address,
                    },
                );
                if let Some(ref b) = unlocked_beacon {
                    let _ = send_encrypted(
                        &mut endpoint,
                        &mut sessions,
                        peer_addr,
                        &P2pMessage::AnnounceGenesisBeacon {
                            btc_block_hash_hex: b.external_randomness_hex.clone(),
                            public_headline: b.public_headline.clone(),
                            timestamp_unix: b.launch_timestamp_unix,
                        },
                    );
                }
                for sh in share_dag.shares() {
                    if let Some(&(val_pk, rew_pk)) = share_meta.get(&sh.author) {
                        let _ = send_encrypted(
                            &mut endpoint,
                            &mut sessions,
                            peer_addr,
                            &P2pMessage::GossipShare {
                                share: sh.clone(),
                                author_pubkey: val_pk,
                                reward_pubkey: rew_pk,
                            },
                        );
                    }
                }
            }

            // 5. Anti-entropy commit reconciliation every 350ms + WAN-safe 450ms vote retries:
            if last_anti_entropy.elapsed() >= Duration::from_millis(350) {
                last_anti_entropy = Instant::now();
                let summary = commit_tracker.recent_summary(24);
                if !summary.is_empty() {
                    broadcast_encrypted(
                        &mut endpoint,
                        &mut sessions,
                        None,
                        &P2pMessage::CommitSummary {
                            recent_tx_ids: summary,
                        },
                    );
                }
                let deferred_senders: BTreeSet<Address> =
                    commit_tracker.deferred.keys().map(|&(s, _)| s).collect();
                for sender in deferred_senders {
                    let from_nonce = ledger.pockets.get(&sender).map_or(0, |sp| sp.state.nonce);
                    broadcast_encrypted(
                        &mut endpoint,
                        &mut sessions,
                        None,
                        &P2pMessage::RequestSenderCommits { sender, from_nonce },
                    );
                }
            }

            for (&req_id, pending) in &mut pending_votes {
                if pending.last_retry.elapsed() >= Duration::from_millis(450) {
                    pending.last_retry = Instant::now();
                    let missing_peers: Vec<SocketAddr> = sessions
                        .iter()
                        .filter(|(_, p)| !pending.voters.contains(&p.address))
                        .map(|(&addr, _)| addr)
                        .collect();
                    if let TransactionKind::FastTransfer { from, nonce, .. } = &pending.tx.kind {
                        if *nonce == 0 {
                            if let Some(&(pk, init_bal, dlim)) =
                                commit_tracker.initial_grants.get(from)
                            {
                                for &peer_addr in &missing_peers {
                                    let _ = send_encrypted(
                                        &mut endpoint,
                                        &mut sessions,
                                        peer_addr,
                                        &P2pMessage::GossipPocketUpsert {
                                            address: *from,
                                            public_key: pk,
                                            balance: init_bal,
                                            daily_limit: dlim,
                                        },
                                    );
                                }
                            }
                        } else if let Some(&prev_id) =
                            commit_tracker.by_sender_nonce.get(&(*from, *nonce - 1))
                            && let Some((prev_tx, pw, pb)) = commit_tracker.by_id.get(&prev_id)
                        {
                            for &peer_addr in &missing_peers {
                                let _ = send_encrypted(
                                    &mut endpoint,
                                    &mut sessions,
                                    peer_addr,
                                    &P2pMessage::FinalityCommit {
                                        tx: prev_tx.clone(),
                                        fee_worker: *pw,
                                        fee_burned: *pb,
                                    },
                                );
                            }
                        }
                    }
                    for peer_addr in missing_peers {
                        let _ = send_encrypted(
                            &mut endpoint,
                            &mut sessions,
                            peer_addr,
                            &P2pMessage::QuorumVoteRequest {
                                request_id: req_id,
                                tx: pending.tx.clone(),
                                value_commitment: pending.value_commitment,
                                bulletproof_672: pending.bulletproof_672.clone(),
                            },
                        );
                    }
                }
            }

            let expired: Vec<u64> = pending_votes
                .iter()
                .filter(|(_, p)| p.started_at.elapsed() > Duration::from_millis(6_000))
                .map(|(&id, _)| id)
                .collect();
            for id in expired {
                if let Some(p) = pending_votes.remove(&id) {
                    if !ledger.finalized_txs.contains(&p.tx.id)
                        && let TransactionKind::FastTransfer { from, nonce, .. } = &p.tx.kind
                        && non_equivocation_locks.get(&(*from, *nonce)) == Some(&p.tx.id)
                    {
                        non_equivocation_locks.remove(&(*from, *nonce));
                    }
                    let resp = NodeRpcResponse::FastPayReceipt {
                        accepted: false,
                        tx_id: p.tx.id,
                        finality_latency_ms: 0,
                        fee_worker: Amount::ZERO,
                        fee_burned: Amount::ZERO,
                        new_state_root: ledger.state_merkle_root(),
                        message: "timed out awaiting distributed P2P quorum".to_owned(),
                    };
                    let _ = send_rpc_reply(&mut endpoint, p.client_addr, &resp);
                }
            }
        }

        let (src, pkt) = match endpoint.recv_packet() {
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

        match frame.channel {
            ChannelTag::P2pHandshake => {
                let Some(hs) = P2pHandshakePacket::decode(&frame.payload) else {
                    continue;
                };
                match hs {
                    P2pHandshakePacket::HolePunchProbe { .. } => {
                        known_targets.insert(src);
                    }
                    P2pHandshakePacket::Init(init_msg) => {
                        handshake_counter = handshake_counter.wrapping_add(1);
                        let ent =
                            domain_hash("XCR.MESH.HS_RESP.V1", &[&handshake_counter.to_le_bytes()])
                                .0;
                        let (cipher, resp_msg, remote_val_pk, remote_x25519) =
                            accept_handshake(&identity, &init_msg, &ent);
                        let remote_addr = remote_val_pk.to_address();
                        if remote_addr != local_address {
                            if pending_handshakes.contains_key(&src) {
                                if local_address < remote_addr {
                                    continue;
                                }
                                pending_handshakes.remove(&src);
                            }
                            dht.upsert_peer(PeerDescriptor {
                                address: remote_addr,
                                static_x25519: remote_x25519,
                                socket_addr: src,
                            });
                            known_targets.insert(src);
                            sessions.insert(
                                src,
                                EstablishedPeer {
                                    address: remote_addr,
                                    static_x25519: remote_x25519,
                                    cipher,
                                },
                            );
                            let reply_frame = WireFrame {
                                channel: ChannelTag::P2pHandshake,
                                payload: P2pHandshakePacket::Resp(resp_msg).encode(),
                            };
                            let _ = endpoint.send_1rtt_datagram(src, &reply_frame);
                        }
                    }
                    P2pHandshakePacket::Resp(resp_msg) => {
                        if let Some((init_state, _)) = pending_handshakes.remove(&src)
                            && let Some((cipher, remote_val_pk, remote_x25519)) =
                                init_state.complete(&identity, &resp_msg)
                        {
                            let remote_addr = remote_val_pk.to_address();
                            dht.upsert_peer(PeerDescriptor {
                                address: remote_addr,
                                static_x25519: remote_x25519,
                                socket_addr: src,
                            });
                            sessions.insert(
                                src,
                                EstablishedPeer {
                                    address: remote_addr,
                                    static_x25519: remote_x25519,
                                    cipher,
                                },
                            );
                            let _ = send_encrypted(
                                &mut endpoint,
                                &mut sessions,
                                src,
                                &P2pMessage::DiscoverPing {
                                    target: local_address,
                                },
                            );
                            if awaiting_initial_sync && wan_sync.peer.is_none() {
                                wan_sync.begin(src);
                                let _ = send_encrypted(
                                    &mut endpoint,
                                    &mut sessions,
                                    src,
                                    &P2pMessage::SyncChunkRequest { start_index: 0 },
                                );
                            }
                        }
                    }
                }
            }

            ChannelTag::P2pEncryptedMesh => {
                let Some(plaintext) = sessions
                    .get_mut(&src)
                    .and_then(|peer| peer.cipher.open(&frame.payload))
                else {
                    if frame.payload.len() >= 24
                        && !pending_handshakes.contains_key(&src)
                        && pending_handshakes.len() < 64
                    {
                        sessions.remove(&src);
                        let _ = initiate_handshake(
                            &mut endpoint,
                            &identity,
                            src,
                            &mut pending_handshakes,
                            &mut handshake_counter,
                        );
                    }
                    continue;
                };
                let Some(msg) = P2pMessage::decode(&plaintext) else {
                    continue;
                };

                match msg {
                    P2pMessage::DiscoverPing { target } => {
                        let closest = dht.closest_peers(&target, 16);
                        let pong = P2pMessage::DiscoverPong {
                            observed_caller_addr: src,
                            closest_peers: closest,
                        };
                        let _ = send_encrypted(&mut endpoint, &mut sessions, src, &pong);
                    }
                    P2pMessage::DiscoverPong {
                        observed_caller_addr,
                        closest_peers,
                    } => {
                        let _ = nat_detector.record_observation(src, observed_caller_addr);
                        for peer_desc in closest_peers {
                            if peer_desc.address != local_address
                                && peer_desc.socket_addr != actual_bind
                            {
                                dht.upsert_peer(peer_desc);
                                known_targets.insert(peer_desc.socket_addr);
                            }
                        }
                    }
                    P2pMessage::RequestHolePunch { target_peer } => {
                        if let Some(target_desc) = dht
                            .all_peers()
                            .into_iter()
                            .find(|p| p.address == target_peer)
                            && let Some(caller_session) = sessions.get(&src)
                        {
                            let caller_desc = PeerDescriptor {
                                address: caller_session.address,
                                static_x25519: caller_session.static_x25519,
                                socket_addr: src,
                            };
                            let target_sock = target_desc.socket_addr;
                            let _ = send_encrypted(
                                &mut endpoint,
                                &mut sessions,
                                src,
                                &P2pMessage::HolePunchRendezvous { peer: target_desc },
                            );
                            let _ = send_encrypted(
                                &mut endpoint,
                                &mut sessions,
                                target_sock,
                                &P2pMessage::HolePunchRendezvous { peer: caller_desc },
                            );
                        }
                    }
                    P2pMessage::HolePunchRendezvous { peer } => {
                        if peer.address != local_address && peer.socket_addr != actual_bind {
                            dht.upsert_peer(peer);
                            known_targets.insert(peer.socket_addr);
                            let probe = WireFrame {
                                channel: ChannelTag::P2pHandshake,
                                payload: P2pHandshakePacket::HolePunchProbe {
                                    sender: local_address,
                                }
                                .encode(),
                            };
                            let _ = endpoint.send_1rtt_datagram(peer.socket_addr, &probe);
                        }
                    }
                    P2pMessage::GossipShare {
                        share,
                        author_pubkey,
                        reward_pubkey,
                    } => {
                        if standby_locked {
                            continue;
                        }
                        if share.epoch > active_epoch
                            && wan_sync.peer.is_none()
                            && !failed_sync_peers
                                .get(&src)
                                .is_some_and(|t| t.elapsed() < Duration::from_secs(120))
                        {
                            wan_sync.begin(src);
                            let _ = send_encrypted(
                                &mut endpoint,
                                &mut sessions,
                                src,
                                &P2pMessage::SyncChunkRequest { start_index: 0 },
                            );
                            continue;
                        }
                        let tx_claim_plausible = match &share.work {
                            WorkProof::RecursiveZkState {
                                verified_tx_count, ..
                            } => (*verified_tx_count as usize) <= ledger.finalized_txs.len().max(1),
                            _ => true,
                        };
                        if share.epoch == active_epoch
                            && tx_claim_plausible
                            && author_pubkey.to_address() == share.author
                            && share_dag.upsert_best_cpu_share(share.clone()) == Ok(true)
                        {
                            share_meta.insert(share.author, (author_pubkey, reward_pubkey));
                            broadcast_encrypted(
                                &mut endpoint,
                                &mut sessions,
                                Some(src),
                                &P2pMessage::GossipShare {
                                    share,
                                    author_pubkey,
                                    reward_pubkey,
                                },
                            );

                            // For Epoch 0 bootstrap or cold WAL recovery, seal immediately once `min_quorum_peers` arrive:
                            if (active_epoch == EpochId(0) || committee.is_none())
                                && share_meta.len() >= cfg.min_quorum_peers
                                && is_epoch_seal_coordinator(
                                    local_address,
                                    active_epoch,
                                    &committee,
                                    &share_meta,
                                    epoch_started_at,
                                    cfg.epoch_interval,
                                )
                            {
                                let sealing_epoch = active_epoch;
                                let sealed_shares = collect_ordered_shares(&share_dag, &share_meta);
                                let settled_fees =
                                    Amount::from_bits(unsettled_fee_bits.max(0) as u64);
                                apply_epoch_seal(
                                    cfg.network,
                                    &vm_cfg,
                                    sealing_epoch,
                                    settled_fees,
                                    &sealed_shares,
                                    &mut active_epoch,
                                    &mut active_epoch_seed,
                                    &mut share_dag,
                                    &mut share_meta,
                                    &mut unsettled_fee_bits,
                                    &mut endurance_pool,
                                    &mut ledger,
                                    &mut committee,
                                    &mut epoch_started_at,
                                    &mut has_mined_current_epoch,
                                )?;
                                broadcast_encrypted(
                                    &mut endpoint,
                                    &mut sessions,
                                    None,
                                    &P2pMessage::EpochSeal {
                                        epoch: sealing_epoch,
                                        settled_fees,
                                        shares: sealed_shares,
                                    },
                                );
                            }
                        }
                    }
                    P2pMessage::EpochSeal {
                        epoch,
                        settled_fees,
                        shares,
                    } => {
                        if standby_locked {
                            continue;
                        }
                        if epoch > active_epoch && wan_sync.peer.is_none() {
                            wan_sync.begin(src);
                            let _ = send_encrypted(
                                &mut endpoint,
                                &mut sessions,
                                src,
                                &P2pMessage::SyncChunkRequest { start_index: 0 },
                            );
                        } else if epoch == active_epoch
                            && shares
                                .iter()
                                .map(|(s, _, _)| s.author)
                                .collect::<BTreeSet<_>>()
                                .len()
                                >= cfg.min_quorum_peers
                            && apply_epoch_seal(
                                cfg.network,
                                &vm_cfg,
                                epoch,
                                settled_fees,
                                &shares,
                                &mut active_epoch,
                                &mut active_epoch_seed,
                                &mut share_dag,
                                &mut share_meta,
                                &mut unsettled_fee_bits,
                                &mut endurance_pool,
                                &mut ledger,
                                &mut committee,
                                &mut epoch_started_at,
                                &mut has_mined_current_epoch,
                            )
                            .is_ok()
                        {
                            awaiting_initial_sync = false;
                            broadcast_encrypted(
                                &mut endpoint,
                                &mut sessions,
                                Some(src),
                                &P2pMessage::EpochSeal {
                                    epoch,
                                    settled_fees,
                                    shares,
                                },
                            );
                        }
                    }
                    P2pMessage::GossipPocketUpsert {
                        address,
                        public_key,
                        balance,
                        daily_limit,
                    } => {
                        if public_key.to_address() == address
                            && !ledger.pockets.contains_key(&address)
                        {
                            let capped_balance = if cfg.network == NetworkProfile::Mainnet {
                                Amount::ZERO
                            } else {
                                balance.min(Amount::from_credits(25).unwrap())
                            };
                            commit_tracker.initial_grants.entry(address).or_insert((
                                public_key,
                                capped_balance,
                                daily_limit,
                            ));
                            let state = PocketState::new(capped_balance, daily_limit);
                            ledger.append_nosync(WalRecord::UpsertPocket {
                                address,
                                public_key,
                                state,
                            })?;
                            commit_tracker.drain_deferred_for_sender(
                                address,
                                &mut ledger,
                                &mut non_equivocation_locks,
                                &mut unsettled_fee_bits,
                            )?;
                            broadcast_encrypted(
                                &mut endpoint,
                                &mut sessions,
                                Some(src),
                                &P2pMessage::GossipPocketUpsert {
                                    address,
                                    public_key,
                                    balance: capped_balance,
                                    daily_limit,
                                },
                            );
                        }
                    }
                    P2pMessage::QuorumVoteRequest {
                        request_id,
                        tx,
                        value_commitment,
                        bulletproof_672,
                    } => {
                        if committee.is_some() {
                            if ledger.finalized_txs.contains(&tx.id) {
                                let vote_msg = domain_hash(
                                    "XCR.CONSENSUS.FAST_VOTE.V1",
                                    &[cfg.network.chain_id().as_bytes(), tx.id.as_bytes()],
                                );
                                let sig_bytes = identity
                                    .validator_keypair_mut()
                                    .sign(vote_msg.as_bytes())
                                    .to_bytes();
                                let reply = P2pMessage::QuorumVoteReply {
                                    request_id,
                                    tx_id: tx.id,
                                    validator: local_address,
                                    vote_signature: sig_bytes,
                                };
                                let _ = send_encrypted(&mut endpoint, &mut sessions, src, &reply);
                            } else if let TransactionKind::FastTransfer { from, nonce, .. } =
                                &tx.kind
                            {
                                let local_nonce = ledger.pockets.get(from).map(|sp| sp.state.nonce);
                                if local_nonce.is_none_or(|cur| cur < *nonce) {
                                    let _ = send_encrypted(
                                        &mut endpoint,
                                        &mut sessions,
                                        src,
                                        &P2pMessage::RequestSenderCommits {
                                            sender: *from,
                                            from_nonce: local_nonce.unwrap_or(0),
                                        },
                                    );
                                } else if validate_fast_transfer_state_and_sig(
                                    &tx,
                                    &value_commitment,
                                    &ledger,
                                    &mut non_equivocation_locks,
                                    false,
                                )
                                .is_ok()
                                {
                                    if verified_bp_cache.get(&tx.id) == Some(&value_commitment) {
                                        non_equivocation_locks.insert((*from, *nonce), tx.id);
                                        let vote_msg = domain_hash(
                                            "XCR.CONSENSUS.FAST_VOTE.V1",
                                            &[cfg.network.chain_id().as_bytes(), tx.id.as_bytes()],
                                        );
                                        let sig_bytes = identity
                                            .validator_keypair_mut()
                                            .sign(vote_msg.as_bytes())
                                            .to_bytes();
                                        let reply = P2pMessage::QuorumVoteReply {
                                            request_id,
                                            tx_id: tx.id,
                                            validator: local_address,
                                            vote_signature: sig_bytes,
                                        };
                                        let _ = send_encrypted(
                                            &mut endpoint,
                                            &mut sessions,
                                            src,
                                            &reply,
                                        );
                                    } else if let Some(waiters) =
                                        in_flight_peer_votes.get_mut(&tx.id)
                                    {
                                        if !waiters.contains(&(src, request_id)) {
                                            waiters.push((src, request_id));
                                        }
                                    } else {
                                        in_flight_peer_votes.insert(tx.id, vec![(src, request_id)]);
                                        let _ = bp_pool.job_tx.send(VerifyTask::PeerVote {
                                            peer_addr: src,
                                            request_id,
                                            tx,
                                            value_commitment,
                                            bulletproof_672,
                                        });
                                    }
                                }
                            }
                        }
                    }
                    P2pMessage::QuorumVoteReply {
                        request_id,
                        tx_id,
                        validator,
                        vote_signature,
                    } => {
                        if let (Some(comm), Some(pending)) =
                            (&committee, pending_votes.get_mut(&request_id))
                            && pending.tx.id == tx_id
                            && !pending.voters.contains(&validator)
                            && let Some(sig) = Signature::from_bytes(&vote_signature)
                            && let Some(member) =
                                comm.members().iter().find(|m| m.address == validator)
                        {
                            let vote_msg = domain_hash(
                                "XCR.CONSENSUS.FAST_VOTE.V1",
                                &[cfg.network.chain_id().as_bytes(), tx_id.as_bytes()],
                            );
                            if member.public_key.verify(vote_msg.as_bytes(), &sig) {
                                pending.voters.insert(validator);
                                pending.signed_weight =
                                    pending.signed_weight.saturating_add(member.weight);

                                if pending.signed_weight >= comm.quorum_threshold() {
                                    let completed = pending_votes.remove(&request_id).unwrap();
                                    let rtt_ms =
                                        (completed.started_at.elapsed().as_millis() as u16).max(1);
                                    let _ = commit_tracker.apply_or_defer(
                                        &completed.tx,
                                        completed.fee_split.worker_reward,
                                        completed.fee_split.burned,
                                        &mut ledger,
                                        &mut non_equivocation_locks,
                                        &mut unsettled_fee_bits,
                                    )?;

                                    broadcast_encrypted(
                                        &mut endpoint,
                                        &mut sessions,
                                        None,
                                        &P2pMessage::FinalityCommit {
                                            tx: completed.tx.clone(),
                                            fee_worker: completed.fee_split.worker_reward,
                                            fee_burned: completed.fee_split.burned,
                                        },
                                    );

                                    let client_reply = NodeRpcResponse::FastPayReceipt {
                                        accepted: true,
                                        tx_id: completed.tx.id,
                                        finality_latency_ms: rtt_ms,
                                        fee_worker: completed.fee_split.worker_reward,
                                        fee_burned: completed.fee_split.burned,
                                        new_state_root: ledger.state_merkle_root(),
                                        message: format!(
                                            "1-RTT P2P quorum finalized ({} independent validators)",
                                            completed.voters.len()
                                        ),
                                    };
                                    let _ = send_rpc_reply(
                                        &mut endpoint,
                                        completed.client_addr,
                                        &client_reply,
                                    );
                                }
                            }
                        }
                    }
                    P2pMessage::FinalityCommit {
                        tx,
                        fee_worker,
                        fee_burned,
                    } => {
                        if commit_tracker.apply_or_defer(
                            &tx,
                            fee_worker,
                            fee_burned,
                            &mut ledger,
                            &mut non_equivocation_locks,
                            &mut unsettled_fee_bits,
                        )? {
                            broadcast_encrypted(
                                &mut endpoint,
                                &mut sessions,
                                Some(src),
                                &P2pMessage::FinalityCommit {
                                    tx,
                                    fee_worker,
                                    fee_burned,
                                },
                            );
                        }
                    }
                    P2pMessage::SyncChunkRequest { start_index } => {
                        let all_items = build_sync_items(
                            active_epoch,
                            active_epoch_seed,
                            &endurance_pool,
                            unsettled_fee_bits,
                            &committee,
                            &share_dag,
                            &share_meta,
                            &ledger,
                        );
                        let total_items = all_items.len() as u32;
                        let (next_index, items) = pack_wan_sync_chunk(&all_items, start_index);
                        let resp = P2pMessage::SyncChunkResponse {
                            start_index,
                            next_index,
                            total_items,
                            items,
                        };
                        let _ = send_encrypted(&mut endpoint, &mut sessions, src, &resp);
                    }
                    P2pMessage::SyncChunkResponse {
                        start_index,
                        next_index,
                        total_items,
                        items,
                    } => {
                        if wan_sync.peer != Some(src) || start_index != wan_sync.expected_index {
                            continue;
                        }
                        for item in items {
                            match item {
                                SyncItem::Header {
                                    active_epoch: ae,
                                    settled_epoch: se,
                                    active_epoch_seed: seed,
                                    circulating_supply,
                                    total_burned,
                                    endurance_balance,
                                    unsettled_fee_bits: synced_fee_bits,
                                } => {
                                    wan_sync.active_epoch = ae;
                                    wan_sync.settled_epoch = se;
                                    wan_sync.active_epoch_seed = seed;
                                    wan_sync.circulating_supply = circulating_supply;
                                    wan_sync.total_burned = total_burned;
                                    wan_sync.endurance_balance = endurance_balance;
                                    wan_sync.unsettled_fee_bits = synced_fee_bits;
                                }
                                SyncItem::CommitteeMember {
                                    address,
                                    public_key,
                                    weight,
                                } => {
                                    wan_sync.committee_members.push(QuorumMember {
                                        address,
                                        public_key,
                                        weight,
                                        wan_rtt_ms: 165,
                                    });
                                }
                                SyncItem::ActiveShare {
                                    share,
                                    author_pubkey,
                                    reward_pubkey,
                                } => {
                                    wan_sync.active_shares.push((
                                        share,
                                        author_pubkey,
                                        reward_pubkey,
                                    ));
                                }
                                SyncItem::Pocket {
                                    address,
                                    public_key,
                                    state,
                                } => {
                                    wan_sync
                                        .pockets
                                        .insert(address, StoredPocket { public_key, state });
                                }
                                SyncItem::StealthUtxo { address, amount } => {
                                    wan_sync.stealth_utxos.insert(address, amount);
                                }
                                SyncItem::SpentNullifier(h) => {
                                    wan_sync.spent_nullifiers.insert(h);
                                }
                                SyncItem::FinalizedTx(h) => {
                                    wan_sync.finalized_txs.insert(h);
                                }
                            }
                        }

                        if next_index < total_items {
                            let now_prog = Instant::now();
                            wan_sync.expected_index = next_index;
                            wan_sync.last_progress_at = Some(now_prog);
                            wan_sync.last_req_at = Some(now_prog);
                            let _ = send_encrypted(
                                &mut endpoint,
                                &mut sessions,
                                src,
                                &P2pMessage::SyncChunkRequest {
                                    start_index: next_index,
                                },
                            );
                        } else {
                            // Completed streaming all `<1,200B` WAN sync pages!
                            let finished = std::mem::take(&mut wan_sync);
                            let peer_is_ahead = finished.active_epoch > active_epoch
                                || (finished.active_epoch == active_epoch
                                    && (finished.finalized_txs.len() > ledger.finalized_txs.len()
                                        || (committee.is_none()
                                            && !finished.committee_members.is_empty())
                                        || ledger.circulating_supply.is_zero()));
                            if peer_is_ahead
                                && (finished.active_epoch > EpochId(0)
                                    || !finished.circulating_supply.is_zero())
                            {
                                ledger.import_synced_state(
                                    finished.settled_epoch,
                                    finished.circulating_supply,
                                    finished.total_burned,
                                    finished.pockets,
                                    finished.stealth_utxos,
                                    finished.spent_nullifiers,
                                    finished.finalized_txs,
                                )?;
                                active_epoch = finished.active_epoch;
                                active_epoch_seed = finished.active_epoch_seed;
                                endurance_pool.balance = finished.endurance_balance;
                                unsettled_fee_bits = finished.unsettled_fee_bits;
                                if !finished.committee_members.is_empty() {
                                    committee = Some(QuorumCommittee::new(
                                        active_epoch,
                                        finished.committee_members,
                                    ));
                                }
                                share_dag =
                                    EpochShareDag::new(active_epoch, active_epoch_seed, 3, vm_cfg);
                                share_meta.clear();
                                has_mined_current_epoch = false;
                                epoch_started_at = Instant::now();
                            }
                            for (sh, val_pk, rew_pk) in finished.active_shares {
                                if sh.epoch == active_epoch
                                    && val_pk.to_address() == sh.author
                                    && share_dag.upsert_best_cpu_share(sh.clone()) == Ok(true)
                                {
                                    if sh.author == local_address {
                                        has_mined_current_epoch = true;
                                    }
                                    share_meta.insert(sh.author, (val_pk, rew_pk));
                                }
                            }
                            awaiting_initial_sync = false;
                        }
                    }
                    P2pMessage::CommitSummary { recent_tx_ids } => {
                        let missing: Vec<Hash32> = recent_tx_ids
                            .into_iter()
                            .filter(|id| !ledger.finalized_txs.contains(id))
                            .take(24)
                            .collect();
                        if !missing.is_empty() {
                            let _ = send_encrypted(
                                &mut endpoint,
                                &mut sessions,
                                src,
                                &P2pMessage::RequestCommits {
                                    missing_tx_ids: missing,
                                },
                            );
                        }
                    }
                    P2pMessage::RequestCommits { missing_tx_ids } => {
                        for id in missing_tx_ids.into_iter().take(24) {
                            if let Some((tx, fw, fb)) = commit_tracker.by_id.get(&id).cloned() {
                                if let TransactionKind::FastTransfer { from, nonce: 0, .. } =
                                    &tx.kind
                                    && let Some(&(pk, init_bal, dlim)) =
                                        commit_tracker.initial_grants.get(from)
                                {
                                    let _ = send_encrypted(
                                        &mut endpoint,
                                        &mut sessions,
                                        src,
                                        &P2pMessage::GossipPocketUpsert {
                                            address: *from,
                                            public_key: pk,
                                            balance: init_bal,
                                            daily_limit: dlim,
                                        },
                                    );
                                }
                                let _ = send_encrypted(
                                    &mut endpoint,
                                    &mut sessions,
                                    src,
                                    &P2pMessage::FinalityCommit {
                                        tx,
                                        fee_worker: fw,
                                        fee_burned: fb,
                                    },
                                );
                            }
                        }
                    }
                    P2pMessage::RequestSenderCommits { sender, from_nonce } => {
                        if from_nonce == 0
                            && let Some(&(pk, init_bal, dlim)) =
                                commit_tracker.initial_grants.get(&sender)
                        {
                            let _ = send_encrypted(
                                &mut endpoint,
                                &mut sessions,
                                src,
                                &P2pMessage::GossipPocketUpsert {
                                    address: sender,
                                    public_key: pk,
                                    balance: init_bal,
                                    daily_limit: dlim,
                                },
                            );
                        }
                        for n in from_nonce..from_nonce.saturating_add(16) {
                            if let Some(&id) = commit_tracker.by_sender_nonce.get(&(sender, n))
                                && let Some((tx, fw, fb)) = commit_tracker.by_id.get(&id).cloned()
                            {
                                let _ = send_encrypted(
                                    &mut endpoint,
                                    &mut sessions,
                                    src,
                                    &P2pMessage::FinalityCommit {
                                        tx,
                                        fee_worker: fw,
                                        fee_burned: fb,
                                    },
                                );
                            } else {
                                break;
                            }
                        }
                    }
                    P2pMessage::AnnounceGenesisBeacon {
                        btc_block_hash_hex,
                        public_headline,
                        timestamp_unix,
                    } => {
                        let now_unix = SystemTime::now()
                            .duration_since(UNIX_EPOCH)
                            .map(|d| d.as_secs())
                            .unwrap_or(0);
                        if standby_locked
                            && cfg.network == NetworkProfile::Mainnet
                            && is_valid_64_hex(&btc_block_hash_hex)
                            && timestamp_unix >= MAINNET_GENESIS_UNIX
                            && let GenesisStandbyStatus::ReadyToLaunch(b) =
                                VerifiableGenesisBeacon::evaluate_genesis_standby(
                                    now_unix,
                                    Some(&btc_block_hash_hex),
                                    Some(&public_headline),
                                )
                        {
                            active_epoch = EpochId(0);
                            active_epoch_seed = b.derive_epoch0_seed();
                            share_dag =
                                EpochShareDag::new(active_epoch, active_epoch_seed, 3, vm_cfg);
                            share_meta.clear();
                            has_mined_current_epoch = false;
                            epoch_started_at = Instant::now();
                            standby_locked = false;
                            let _ = fs::write(
                                &beacon_file,
                                format!("{btc_block_hash_hex}\n{public_headline}\n"),
                            );
                            broadcast_encrypted(
                                &mut endpoint,
                                &mut sessions,
                                Some(src),
                                &P2pMessage::AnnounceGenesisBeacon {
                                    btc_block_hash_hex,
                                    public_headline,
                                    timestamp_unix: b.launch_timestamp_unix,
                                },
                            );
                            unlocked_beacon = Some(b);
                        }
                    }
                    P2pMessage::GossipStealthOutput {
                        one_time_address,
                        ephemeral_pub,
                        view_tag,
                    } => {
                        if stealth_announcements.len() < 32_768
                            && !stealth_announcements.contains_key(&one_time_address)
                        {
                            stealth_announcements
                                .insert(one_time_address, (ephemeral_pub, view_tag));
                            append_stealth_announcement(
                                &cfg.data_dir,
                                &one_time_address,
                                &ephemeral_pub,
                                view_tag,
                            );
                            broadcast_encrypted(
                                &mut endpoint,
                                &mut sessions,
                                Some(src),
                                &P2pMessage::GossipStealthOutput {
                                    one_time_address,
                                    ephemeral_pub,
                                    view_tag,
                                },
                            );
                        }
                    }
                    P2pMessage::GossipStealthOutputV2 {
                        one_time_address,
                        ephemeral_pub,
                        view_tag,
                        encrypted_memo,
                    } => {
                        if stealth_announcements.len() < 32_768
                            && !stealth_announcements.contains_key(&one_time_address)
                        {
                            stealth_announcements
                                .insert(one_time_address, (ephemeral_pub, view_tag));
                            append_stealth_announcement(
                                &cfg.data_dir,
                                &one_time_address,
                                &ephemeral_pub,
                                view_tag,
                            );
                            if !encrypted_memo.is_empty() && encrypted_memo.len() <= 80 {
                                append_stealth_memo(
                                    &cfg.data_dir,
                                    &one_time_address,
                                    &encrypted_memo,
                                );
                                stealth_memos.insert(one_time_address, encrypted_memo.clone());
                            }
                            broadcast_encrypted(
                                &mut endpoint,
                                &mut sessions,
                                Some(src),
                                &P2pMessage::GossipStealthOutputV2 {
                                    one_time_address,
                                    ephemeral_pub,
                                    view_tag,
                                    encrypted_memo,
                                },
                            );
                        }
                    }
                    P2pMessage::GossipStealthClaim {
                        one_time_address,
                        claimant_pocket,
                        claimant_pubkey,
                        spend_pub,
                        kdf,
                        schnorr_sig64,
                    } => {
                        if let Ok((_, _, _)) = apply_verified_stealth_claim(
                            one_time_address,
                            claimant_pocket,
                            claimant_pubkey,
                            &spend_pub,
                            &kdf,
                            &schnorr_sig64,
                            &mut ledger,
                            &mut stealth_announcements,
                            &mut unsettled_fee_bits,
                        )? {
                            stealth_memos.remove(&one_time_address);
                            broadcast_encrypted(
                                &mut endpoint,
                                &mut sessions,
                                Some(src),
                                &P2pMessage::GossipStealthClaim {
                                    one_time_address,
                                    claimant_pocket,
                                    claimant_pubkey,
                                    spend_pub,
                                    kdf,
                                    schnorr_sig64,
                                },
                            );
                        }
                    }
                    P2pMessage::GossipContractRpc { encoded_rpc } => {
                        if let Some(decoded_req) = NodeRpcRequest::decode(&encoded_rpc)
                            && let Ok((_, true)) = crate::contracts::execute_contract_rpc(
                                &decoded_req,
                                &mut ledger,
                                &mut swap_offers,
                                &mut unsettled_fee_bits,
                                true,
                            )
                        {
                            broadcast_encrypted(
                                &mut endpoint,
                                &mut sessions,
                                Some(src),
                                &P2pMessage::GossipContractRpc { encoded_rpc },
                            );
                        }
                    }
                }
            }

            ChannelTag::ClientRpcRequest => {
                let Some(req) = NodeRpcRequest::decode(&frame.payload) else {
                    let _ = send_rpc_reply(
                        &mut endpoint,
                        src,
                        &NodeRpcResponse::Error("malformed RPC request".to_owned()),
                    );
                    continue;
                };
                match req {
                    NodeRpcRequest::GetStatus => {
                        let resp = NodeRpcResponse::Status {
                            epoch: active_epoch,
                            circulating_supply: ledger.circulating_supply,
                            total_burned: ledger.total_burned,
                            finalized_tx_count: ledger.finalized_txs.len() as u64,
                            state_root: ledger.state_merkle_root(),
                            validator_address: local_address,
                        };
                        let _ = send_rpc_reply(&mut endpoint, src, &resp);
                    }
                    NodeRpcRequest::GetNetworkTelemetry => {
                        let active_miners = committee
                            .as_ref()
                            .map(|c| c.members().len())
                            .unwrap_or(0)
                            .max(share_dag.shares().len())
                            .max(1) as u32;
                        let resp = NodeRpcResponse::NetworkTelemetry {
                            epoch: active_epoch,
                            circulating_supply: ledger.circulating_supply,
                            total_burned: ledger.total_burned,
                            finalized_tx_count: ledger.finalized_txs.len() as u64,
                            state_root: ledger.state_merkle_root(),
                            validator_address: local_address,
                            connected_peers: sessions.len() as u32,
                            active_miners,
                        };
                        let _ = send_rpc_reply(&mut endpoint, src, &resp);
                    }
                    NodeRpcRequest::RegisterPocket {
                        address,
                        public_key,
                        grant_from_miner,
                        daily_limit,
                    } => {
                        if public_key.to_address() != address {
                            let _ = send_rpc_reply(
                                &mut endpoint,
                                src,
                                &NodeRpcResponse::Error("address/pubkey mismatch".to_owned()),
                            );
                        } else {
                            if !ledger.pockets.contains_key(&address) {
                                let capped_grant = if cfg.network == NetworkProfile::Mainnet {
                                    Amount::ZERO
                                } else {
                                    grant_from_miner.min(Amount::from_credits(25).unwrap())
                                };
                                commit_tracker.initial_grants.entry(address).or_insert((
                                    public_key,
                                    capped_grant,
                                    daily_limit,
                                ));
                                let state = PocketState::new(capped_grant, daily_limit);
                                ledger.append_nosync(WalRecord::UpsertPocket {
                                    address,
                                    public_key,
                                    state,
                                })?;
                                commit_tracker.drain_deferred_for_sender(
                                    address,
                                    &mut ledger,
                                    &mut non_equivocation_locks,
                                    &mut unsettled_fee_bits,
                                )?;
                                broadcast_encrypted(
                                    &mut endpoint,
                                    &mut sessions,
                                    None,
                                    &P2pMessage::GossipPocketUpsert {
                                        address,
                                        public_key,
                                        balance: capped_grant,
                                        daily_limit,
                                    },
                                );
                            }
                            let sp = &ledger.pockets[&address].state;
                            let _ = send_rpc_reply(
                                &mut endpoint,
                                src,
                                &NodeRpcResponse::PocketInfo {
                                    found: true,
                                    balance: sp.balance,
                                    nonce: sp.nonce,
                                    daily_limit: sp.daily_limit,
                                },
                            );
                        }
                    }
                    NodeRpcRequest::GetPocket { address } => {
                        let resp = match ledger.pockets.get(&address) {
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
                        };
                        let _ = send_rpc_reply(&mut endpoint, src, &resp);
                    }
                    NodeRpcRequest::SubmitBulletproofFastPay {
                        tx,
                        value_commitment,
                        bulletproof_672,
                    } => {
                        if standby_locked {
                            let _ = send_rpc_reply(
                                &mut endpoint,
                                src,
                                &NodeRpcResponse::FastPayReceipt {
                                    accepted: false,
                                    tx_id: tx.id,
                                    finality_latency_ms: 0,
                                    fee_worker: Amount::ZERO,
                                    fee_burned: Amount::ZERO,
                                    new_state_root: ledger.state_merkle_root(),
                                    message: "Mainnet locked in Genesis Standby until 2027-01-01T00:00:00Z"
                                        .to_owned(),
                                },
                            );
                            continue;
                        }
                        if ledger.finalized_txs.contains(&tx.id) {
                            let fs = FeeSplit::compute(tx.fee());
                            let _ = send_rpc_reply(
                                &mut endpoint,
                                src,
                                &NodeRpcResponse::FastPayReceipt {
                                    accepted: true,
                                    tx_id: tx.id,
                                    finality_latency_ms: 1,
                                    fee_worker: fs.worker_reward,
                                    fee_burned: fs.burned,
                                    new_state_root: ledger.state_merkle_root(),
                                    message: "already finalized (idempotent receipt)".to_owned(),
                                },
                            );
                            continue;
                        }
                        if committee.is_none() {
                            let _ = send_rpc_reply(
                                &mut endpoint,
                                src,
                                &NodeRpcResponse::FastPayReceipt {
                                    accepted: false,
                                    tx_id: tx.id,
                                    finality_latency_ms: 0,
                                    fee_worker: Amount::ZERO,
                                    fee_burned: Amount::ZERO,
                                    new_state_root: ledger.state_merkle_root(),
                                    message: "mesh quorum still bootstrapping Epoch 0".to_owned(),
                                },
                            );
                            continue;
                        }
                        if let Err(reason) = validate_fast_transfer_state_and_sig(
                            &tx,
                            &value_commitment,
                            &ledger,
                            &mut non_equivocation_locks,
                            false,
                        ) {
                            let _ = send_rpc_reply(
                                &mut endpoint,
                                src,
                                &NodeRpcResponse::FastPayReceipt {
                                    accepted: false,
                                    tx_id: tx.id,
                                    finality_latency_ms: 0,
                                    fee_worker: Amount::ZERO,
                                    fee_burned: Amount::ZERO,
                                    new_state_root: ledger.state_merkle_root(),
                                    message: reason,
                                },
                            );
                            continue;
                        }
                        if in_flight_client_txs.insert(tx.id) {
                            let _ = bp_pool.job_tx.send(VerifyTask::ClientFastPay {
                                client_addr: src,
                                tx,
                                value_commitment,
                                bulletproof_672,
                            });
                        }
                    }
                    NodeRpcRequest::GetLightAccountProof { address } => {
                        let resp = build_light_account_proof(&ledger, &address);
                        let _ = send_rpc_reply(&mut endpoint, src, &resp);
                    }
                    NodeRpcRequest::ShutdownDaemon => {
                        if !src.ip().is_loopback() {
                            let _ = send_rpc_reply(
                                &mut endpoint,
                                src,
                                &NodeRpcResponse::Error(
                                    "shutdown RPC is restricted to loopback".to_owned(),
                                ),
                            );
                            continue;
                        }
                        ledger.flush_wal()?;
                        let _ = send_rpc_reply(&mut endpoint, src, &NodeRpcResponse::AckShutdown);
                        return Ok(());
                    }
                    NodeRpcRequest::UnlockMainnetGenesis {
                        btc_block_hash_hex,
                        public_headline,
                    } => {
                        if !src.ip().is_loopback() {
                            let _ = send_rpc_reply(
                                &mut endpoint,
                                src,
                                &NodeRpcResponse::Error(
                                    "UnlockMainnetGenesis RPC is restricted to loopback".to_owned(),
                                ),
                            );
                            continue;
                        }
                        let now_unix = SystemTime::now()
                            .duration_since(UNIX_EPOCH)
                            .map(|d| d.as_secs())
                            .unwrap_or(0);
                        if !is_valid_64_hex(&btc_block_hash_hex) {
                            let _ = send_rpc_reply(
                                &mut endpoint,
                                src,
                                &NodeRpcResponse::GenesisUnlocked {
                                    unlocked: false,
                                    active_epoch,
                                    epoch0_seed: active_epoch_seed,
                                    message: "btc_block_hash_hex must be 64 hex characters"
                                        .to_owned(),
                                },
                            );
                            continue;
                        }
                        match VerifiableGenesisBeacon::evaluate_genesis_standby(
                            now_unix,
                            Some(&btc_block_hash_hex),
                            Some(&public_headline),
                        ) {
                            GenesisStandbyStatus::ReadyToLaunch(b) => {
                                if standby_locked {
                                    active_epoch = EpochId(0);
                                    active_epoch_seed = b.derive_epoch0_seed();
                                    share_dag = EpochShareDag::new(
                                        active_epoch,
                                        active_epoch_seed,
                                        3,
                                        vm_cfg,
                                    );
                                    share_meta.clear();
                                    has_mined_current_epoch = false;
                                    epoch_started_at = Instant::now();
                                    standby_locked = false;
                                    let _ = fs::write(
                                        &beacon_file,
                                        format!("{btc_block_hash_hex}\n{public_headline}\n"),
                                    );
                                    broadcast_encrypted(
                                        &mut endpoint,
                                        &mut sessions,
                                        None,
                                        &P2pMessage::AnnounceGenesisBeacon {
                                            btc_block_hash_hex,
                                            public_headline,
                                            timestamp_unix: b.launch_timestamp_unix,
                                        },
                                    );
                                    unlocked_beacon = Some(b);
                                }
                                let _ = send_rpc_reply(
                                    &mut endpoint,
                                    src,
                                    &NodeRpcResponse::GenesisUnlocked {
                                        unlocked: true,
                                        active_epoch,
                                        epoch0_seed: active_epoch_seed,
                                        message: "Mainnet Epoch 0 unlocked and gossiped".to_owned(),
                                    },
                                );
                            }
                            GenesisStandbyStatus::StandbyCountdown {
                                seconds_remaining, ..
                            } => {
                                let _ = send_rpc_reply(
                                    &mut endpoint,
                                    src,
                                    &NodeRpcResponse::GenesisUnlocked {
                                        unlocked: false,
                                        active_epoch,
                                        epoch0_seed: active_epoch_seed,
                                        message: format!(
                                            "still in Genesis Standby ({seconds_remaining}s remaining until 2027-01-01T00:00:00Z)"
                                        ),
                                    },
                                );
                            }
                            GenesisStandbyStatus::AwaitingPublicBeacon { .. } => {
                                let _ = send_rpc_reply(
                                    &mut endpoint,
                                    src,
                                    &NodeRpcResponse::GenesisUnlocked {
                                        unlocked: false,
                                        active_epoch,
                                        epoch0_seed: active_epoch_seed,
                                        message: "awaiting non-empty Bitcoin block hash & headline"
                                            .to_owned(),
                                    },
                                );
                            }
                        }
                    }
                    NodeRpcRequest::AnnounceStealthOutput {
                        one_time_address,
                        ephemeral_pub,
                        view_tag,
                    } => {
                        let has_funded_utxo = ledger
                            .stealth_utxos
                            .get(&one_time_address)
                            .is_some_and(|a| !a.is_zero());
                        if has_funded_utxo
                            && stealth_announcements.len() < 32_768
                            && !stealth_announcements.contains_key(&one_time_address)
                        {
                            stealth_announcements
                                .insert(one_time_address, (ephemeral_pub, view_tag));
                            append_stealth_announcement(
                                &cfg.data_dir,
                                &one_time_address,
                                &ephemeral_pub,
                                view_tag,
                            );
                            broadcast_encrypted(
                                &mut endpoint,
                                &mut sessions,
                                None,
                                &P2pMessage::GossipStealthOutput {
                                    one_time_address,
                                    ephemeral_pub,
                                    view_tag,
                                },
                            );
                        }
                        let _ = send_rpc_reply(
                            &mut endpoint,
                            src,
                            &NodeRpcResponse::AckStealthAnnounce,
                        );
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
                        let _ = send_rpc_reply(
                            &mut endpoint,
                            src,
                            &NodeRpcResponse::StealthOutputs { outputs },
                        );
                    }
                    NodeRpcRequest::AnnounceStealthOutputV2 {
                        one_time_address,
                        ephemeral_pub,
                        view_tag,
                        encrypted_memo,
                    } => {
                        let has_funded_utxo = ledger
                            .stealth_utxos
                            .get(&one_time_address)
                            .is_some_and(|a| !a.is_zero());
                        if has_funded_utxo
                            && stealth_announcements.len() < 32_768
                            && !stealth_announcements.contains_key(&one_time_address)
                        {
                            stealth_announcements
                                .insert(one_time_address, (ephemeral_pub, view_tag));
                            append_stealth_announcement(
                                &cfg.data_dir,
                                &one_time_address,
                                &ephemeral_pub,
                                view_tag,
                            );
                            if !encrypted_memo.is_empty() && encrypted_memo.len() <= 80 {
                                append_stealth_memo(
                                    &cfg.data_dir,
                                    &one_time_address,
                                    &encrypted_memo,
                                );
                                stealth_memos.insert(one_time_address, encrypted_memo.clone());
                            }
                            broadcast_encrypted(
                                &mut endpoint,
                                &mut sessions,
                                None,
                                &P2pMessage::GossipStealthOutputV2 {
                                    one_time_address,
                                    ephemeral_pub,
                                    view_tag,
                                    encrypted_memo: encrypted_memo.clone(),
                                },
                            );
                            if encrypted_memo.is_empty() {
                                broadcast_encrypted(
                                    &mut endpoint,
                                    &mut sessions,
                                    None,
                                    &P2pMessage::GossipStealthOutput {
                                        one_time_address,
                                        ephemeral_pub,
                                        view_tag,
                                    },
                                );
                            }
                        }
                        let _ = send_rpc_reply(
                            &mut endpoint,
                            src,
                            &NodeRpcResponse::AckStealthAnnounce,
                        );
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
                        let _ = send_rpc_reply(
                            &mut endpoint,
                            src,
                            &NodeRpcResponse::StealthOutputsV2 { outputs },
                        );
                    }
                    NodeRpcRequest::InspectQuery { query } => {
                        let resp = crate::handle_inspect_query(&ledger, active_epoch, &query);
                        let _ = send_rpc_reply(&mut endpoint, src, &resp);
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
                        let encoded_rpc = contract_req.encode();
                        let (resp, newly_mutated) = crate::contracts::execute_contract_rpc(
                            &contract_req,
                            &mut ledger,
                            &mut swap_offers,
                            &mut unsettled_fee_bits,
                            false,
                        )?;
                        if newly_mutated {
                            broadcast_encrypted(
                                &mut endpoint,
                                &mut sessions,
                                None,
                                &P2pMessage::GossipContractRpc { encoded_rpc },
                            );
                        }
                        let _ = send_rpc_reply(&mut endpoint, src, &resp);
                    }
                    NodeRpcRequest::ClaimStealthUtxo {
                        one_time_address,
                        claimant_pocket,
                        claimant_pubkey,
                        spend_pub,
                        kdf,
                        schnorr_sig64,
                    } => {
                        match apply_verified_stealth_claim(
                            one_time_address,
                            claimant_pocket,
                            claimant_pubkey,
                            &spend_pub,
                            &kdf,
                            &schnorr_sig64,
                            &mut ledger,
                            &mut stealth_announcements,
                            &mut unsettled_fee_bits,
                        )? {
                            Ok((claimed_amount, fee_burned, new_pocket_balance)) => {
                                stealth_memos.remove(&one_time_address);
                                ledger.flush_wal()?;
                                broadcast_encrypted(
                                    &mut endpoint,
                                    &mut sessions,
                                    None,
                                    &P2pMessage::GossipStealthClaim {
                                        one_time_address,
                                        claimant_pocket,
                                        claimant_pubkey,
                                        spend_pub,
                                        kdf,
                                        schnorr_sig64,
                                    },
                                );
                                let _ = send_rpc_reply(
                                    &mut endpoint,
                                    src,
                                    &NodeRpcResponse::StealthClaimReceipt {
                                        accepted: true,
                                        claimed_amount,
                                        fee_burned,
                                        new_pocket_balance,
                                        new_state_root: ledger.state_merkle_root(),
                                        message: "stealth UTXO claimed & gossiped".to_owned(),
                                    },
                                );
                            }
                            Err(reason) => {
                                let _ = send_rpc_reply(
                                    &mut endpoint,
                                    src,
                                    &NodeRpcResponse::StealthClaimReceipt {
                                        accepted: false,
                                        claimed_amount: Amount::ZERO,
                                        fee_burned: Amount::ZERO,
                                        new_pocket_balance: Amount::ZERO,
                                        new_state_root: ledger.state_merkle_root(),
                                        message: reason,
                                    },
                                );
                            }
                        }
                    }
                }
            }

            _ => {}
        }
    }
}

fn derive_epoch_seed(network: NetworkProfile, epoch: EpochId, prev_state_root: &Hash32) -> Hash32 {
    if epoch == EpochId(0) {
        domain_hash(
            "XCR.MESH.EPOCH0_SEED.V1",
            &[
                network.chain_id().as_bytes(),
                b"Credits-Fair-Genesis-Epoch-0",
            ],
        )
    } else {
        domain_hash(
            "XCR.MESH.NEXT_EPOCH_SEED.V1",
            &[
                network.chain_id().as_bytes(),
                &epoch.0.to_le_bytes(),
                prev_state_root.as_bytes(),
            ],
        )
    }
}

fn is_epoch_seal_coordinator(
    local_address: Address,
    active_epoch: EpochId,
    committee: &Option<QuorumCommittee>,
    share_meta: &BTreeMap<Address, (PublicKey, PublicKey)>,
    epoch_started_at: Instant,
    epoch_interval: Duration,
) -> bool {
    if active_epoch == EpochId(0) || committee.is_none() {
        let Some(rank) = share_meta.keys().position(|&addr| addr == local_address) else {
            return false;
        };
        return epoch_started_at.elapsed() >= Duration::from_secs((rank as u64).saturating_mul(12));
    }
    if let Some(comm) = committee {
        let Some(rank) = comm
            .members()
            .iter()
            .position(|m| m.address == local_address)
        else {
            return false;
        };
        // Primary (`rank == 0`) seals at `epoch_interval`; backups stagger by +8s per rank:
        return epoch_started_at.elapsed()
            >= epoch_interval.saturating_add(Duration::from_secs((rank as u64).saturating_mul(8)));
    }
    false
}

fn collect_ordered_shares(
    share_dag: &EpochShareDag,
    share_meta: &BTreeMap<Address, (PublicKey, PublicKey)>,
) -> Vec<(ComputeShare, PublicKey, PublicKey)> {
    // Keep `EpochSeal` compact (`<= 5` shares, `< 1,100B` WAN MTU) when many nodes participate:
    if share_dag.shares().len() <= 5 {
        let mut out = Vec::with_capacity(share_dag.shares().len());
        for sh in share_dag.shares() {
            if let Some(&(val_pk, rew_pk)) = share_meta.get(&sh.author) {
                out.push((sh.clone(), val_pk, rew_pk));
            }
        }
        return out;
    }

    let mut best_by_author: BTreeMap<Address, ComputeShare> = BTreeMap::new();
    for sh in share_dag.shares() {
        best_by_author
            .entry(sh.author)
            .and_modify(|cur| {
                if sh.verified_weight > cur.verified_weight {
                    *cur = sh.clone();
                }
            })
            .or_insert_with(|| sh.clone());
    }
    let mut out = Vec::with_capacity(best_by_author.len());
    for (author, mut sh) in best_by_author {
        if let Some(&(val_pk, rew_pk)) = share_meta.get(&author) {
            sh.parents.clear();
            out.push((sh, val_pk, rew_pk));
        }
    }
    out
}

#[allow(clippy::too_many_arguments)]
fn apply_epoch_seal(
    network: NetworkProfile,
    vm_cfg: &PoncVmConfig,
    sealing_epoch: EpochId,
    settled_fees: Amount,
    sealed_shares: &[(ComputeShare, PublicKey, PublicKey)],
    active_epoch: &mut EpochId,
    active_epoch_seed: &mut Hash32,
    share_dag: &mut EpochShareDag,
    share_meta: &mut BTreeMap<Address, (PublicKey, PublicKey)>,
    unsettled_fee_bits: &mut i64,
    endurance_pool: &mut SecurityEndurancePool,
    ledger: &mut PersistentLedger,
    committee: &mut Option<QuorumCommittee>,
    epoch_started_at: &mut Instant,
    has_mined_current_epoch: &mut bool,
) -> io::Result<()> {
    let mut verified_dag = EpochShareDag::new(sealing_epoch, *active_epoch_seed, 3, *vm_cfg);
    let mut directory = Vec::with_capacity(sealed_shares.len());
    let mut reward_pks: BTreeMap<Address, PublicKey> = BTreeMap::new();

    let mut remaining: Vec<(ComputeShare, PublicKey, PublicKey)> = sealed_shares.to_vec();
    while !remaining.is_empty() {
        let before = remaining.len();
        let mut next_pass = Vec::new();
        for (sh, val_pk, rew_pk) in remaining {
            if sh.epoch != sealing_epoch || val_pk.to_address() != sh.author {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "invalid share author or epoch in EpochSeal",
                ));
            }
            let parents_ready = sh.parents.iter().all(|p| {
                verified_dag
                    .shares()
                    .iter()
                    .any(|existing| &existing.id == p)
            });
            if parents_ready {
                verified_dag.submit_share(sh.clone()).map_err(|_| {
                    io::Error::new(io::ErrorKind::InvalidData, "EpochSeal PoNC proof invalid")
                })?;
                if !reward_pks.contains_key(&sh.author) {
                    directory.push((sh.author, val_pk, 165u16));
                }
                reward_pks.insert(sh.author, rew_pk);
            } else {
                next_pass.push((sh, val_pk, rew_pk));
            }
        }
        if next_pass.len() == before {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "EpochSeal contains unresolvable Share-DAG parent",
            ));
        }
        remaining = next_pass;
    }
    directory.sort_by_key(|(addr, _, _)| *addr);

    let drip = endurance_pool.drip_for_epoch();
    let settlement = verified_dag.settle_epoch_with_endurance(settled_fees, drip);
    endurance_pool.deposit(settlement.endurance_deposited);
    *unsettled_fee_bits = unsettled_fee_bits.saturating_sub(settled_fees.bits() as i64);

    let mut batch_records = Vec::with_capacity(1 + settlement.payouts.len());
    let payouts_vec: Vec<(Address, Amount)> = settlement
        .payouts
        .iter()
        .map(|&(a, amt, _)| (a, amt))
        .collect();
    // Per-tx 1-RTT finality already subtracted `fee_burned` immediately, so `burned_fees` here is 0:
    batch_records.push(WalRecord::RecordEpochSettlement {
        epoch: sealing_epoch,
        minted_emission: settlement.minted_emission,
        worker_fees: settlement.worker_fee_pool,
        burned_fees: Amount::ZERO,
        payouts: payouts_vec,
    });

    // Auto-credit each miner's `miner.wallet` `Spending Pocket` directly at Layer 1!
    for &(validator_addr, reward_amt, _) in &settlement.payouts {
        if reward_amt.is_zero() {
            continue;
        }
        if let Some(&rew_pk) = reward_pks.get(&validator_addr) {
            let rew_addr = rew_pk.to_address();
            let mut next_pocket = ledger.pockets.get(&rew_addr).map_or_else(
                || PocketState::new(Amount::ZERO, Amount::from_credits(250).unwrap()),
                |sp| sp.state.clone(),
            );
            let _ = next_pocket.credit(reward_amt);
            batch_records.push(WalRecord::UpsertPocket {
                address: rew_addr,
                public_key: rew_pk,
                state: next_pocket,
            });
        }
    }
    ledger.append_batch(batch_records)?;
    let now_prune = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let _ = ledger.prune_closed_contracts(now_prune, 3_600);
    if sealing_epoch.0 > 0 && sealing_epoch.0.is_multiple_of(50) {
        let _ = ledger.compact_checkpoint();
    }

    let next_epoch = EpochId(sealing_epoch.0 + 1);
    *committee = Some(QuorumCommittee::elect_from_settlement(
        next_epoch,
        &settlement,
        &directory,
    ));
    let mut seal_commitment_bytes = Vec::with_capacity(40 + sealed_shares.len() * 32);
    seal_commitment_bytes.extend_from_slice(active_epoch_seed.as_bytes());
    seal_commitment_bytes.extend_from_slice(&settled_fees.bits().to_le_bytes());
    let mut sorted_ids: Vec<Hash32> = sealed_shares.iter().map(|(sh, _, _)| sh.id).collect();
    sorted_ids.sort_by(|a, b| a.as_bytes().cmp(b.as_bytes()));
    for id in &sorted_ids {
        seal_commitment_bytes.extend_from_slice(id.as_bytes());
    }
    let seal_digest = domain_hash("XCR.MESH.SEAL_COMMIT.V1", &[&seal_commitment_bytes]);

    *active_epoch = next_epoch;
    *active_epoch_seed = derive_epoch_seed(network, next_epoch, &seal_digest);
    *share_dag = EpochShareDag::new(*active_epoch, *active_epoch_seed, 3, *vm_cfg);
    share_meta.clear();
    PONC_LOCAL_EPOCH_WEIGHT.store(0, Ordering::Relaxed);
    *epoch_started_at = Instant::now();
    *has_mined_current_epoch = false;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn build_sync_items(
    active_epoch: EpochId,
    active_epoch_seed: Hash32,
    endurance_pool: &SecurityEndurancePool,
    unsettled_fee_bits: i64,
    committee: &Option<QuorumCommittee>,
    share_dag: &EpochShareDag,
    share_meta: &BTreeMap<Address, (PublicKey, PublicKey)>,
    ledger: &PersistentLedger,
) -> Vec<SyncItem> {
    let mut items = Vec::with_capacity(1 + ledger.pockets.len() + ledger.stealth_utxos.len() + 8);
    items.push(SyncItem::Header {
        active_epoch,
        settled_epoch: ledger.latest_epoch,
        active_epoch_seed,
        circulating_supply: ledger.circulating_supply,
        total_burned: ledger.total_burned,
        endurance_balance: endurance_pool.balance,
        unsettled_fee_bits,
    });
    if let Some(comm) = committee {
        for m in comm.members() {
            items.push(SyncItem::CommitteeMember {
                address: m.address,
                public_key: m.public_key,
                weight: m.weight,
            });
        }
    }
    for sh in share_dag.shares() {
        if let Some(&(val_pk, rew_pk)) = share_meta.get(&sh.author) {
            items.push(SyncItem::ActiveShare {
                share: sh.clone(),
                author_pubkey: val_pk,
                reward_pubkey: rew_pk,
            });
        }
    }
    for (&address, sp) in &ledger.pockets {
        items.push(SyncItem::Pocket {
            address,
            public_key: sp.public_key,
            state: sp.state.clone(),
        });
    }
    for (&address, &amount) in &ledger.stealth_utxos {
        items.push(SyncItem::StealthUtxo { address, amount });
    }
    for &nullifier in &ledger.spent_nullifiers {
        items.push(SyncItem::SpentNullifier(nullifier));
    }
    for &tx_id in &ledger.finalized_txs {
        items.push(SyncItem::FinalizedTx(tx_id));
    }
    items
}

fn load_or_create_node_identity(data_dir: &Path) -> io::Result<PeerIdentity> {
    let key_path = data_dir.join("node_identity.bin");
    if key_path.exists() {
        let raw = fs::read(&key_path)?;
        if raw.len() == 40 && raw[..8] == NODE_KEY_MAGIC {
            let mut seed = [0u8; 32];
            seed.copy_from_slice(&raw[8..40]);
            return Ok(PeerIdentity::from_seed(seed));
        }
    }
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let pid = std::process::id();
    let seed = domain_hash(
        "XCR.MESH.NEW_NODE_SEED.V1",
        &[
            &nanos.to_le_bytes(),
            &pid.to_le_bytes(),
            data_dir.to_string_lossy().as_bytes(),
        ],
    )
    .0;
    let mut out = Vec::with_capacity(40);
    out.extend_from_slice(&NODE_KEY_MAGIC);
    out.extend_from_slice(&seed);
    fs::write(&key_path, out)?;
    Ok(PeerIdentity::from_seed(seed))
}

/// Loads or creates `<data_dir>/miner.wallet` in standard `XCRSEED1` format so solo laptop miners
/// can spend their continuous 60-second epoch rewards directly with `credit-cli`.
fn load_or_create_miner_wallet_pubkey(data_dir: &Path) -> io::Result<PublicKey> {
    let wallet_path = data_dir.join("miner.wallet");
    let master = if wallet_path.exists() {
        let raw = fs::read(&wallet_path)?;
        if raw.len() == 40 && raw[..8] == WALLET_FILE_MAGIC {
            let mut seed = [0u8; 32];
            seed.copy_from_slice(&raw[8..40]);
            seed
        } else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "corrupted miner.wallet header",
            ));
        }
    } else {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let pid = std::process::id();
        let seed = domain_hash(
            "XCR.MESH.MINER_WALLET_SEED.V1",
            &[
                &nanos.to_le_bytes(),
                &pid.to_le_bytes(),
                data_dir.to_string_lossy().as_bytes(),
            ],
        )
        .0;
        let mut buf = Vec::with_capacity(40);
        buf.extend_from_slice(&WALLET_FILE_MAGIC);
        buf.extend_from_slice(&seed);
        fs::write(&wallet_path, buf)?;
        seed
    };
    let pocket_seed = domain_hash("XCR.WALLET.POCKET_KEY.V1", &[&master]).0;
    Ok(Keypair::from_seed(SignatureScheme::PasskeyP256, pocket_seed).public_key())
}

fn initiate_handshake(
    endpoint: &mut UdpQuicEndpoint,
    identity: &PeerIdentity,
    target_addr: SocketAddr,
    pending: &mut BTreeMap<SocketAddr, (InitiatorHandshake, Instant)>,
    counter: &mut u64,
) -> io::Result<()> {
    *counter = counter.wrapping_add(1);
    let ent = domain_hash(
        "XCR.MESH.HS_INIT.V1",
        &[&counter.to_le_bytes(), &target_addr.port().to_le_bytes()],
    )
    .0;
    let (state, init_msg) = InitiatorHandshake::start(identity, &ent);
    pending.insert(target_addr, (state, Instant::now()));
    let frame = WireFrame {
        channel: ChannelTag::P2pHandshake,
        payload: P2pHandshakePacket::Init(init_msg).encode(),
    };
    endpoint.send_1rtt_datagram(target_addr, &frame)?;
    Ok(())
}

fn send_encrypted(
    endpoint: &mut UdpQuicEndpoint,
    sessions: &mut BTreeMap<SocketAddr, EstablishedPeer>,
    peer_addr: SocketAddr,
    msg: &P2pMessage,
) -> io::Result<()> {
    if let Some(peer) = sessions.get_mut(&peer_addr) {
        let sealed = peer.cipher.seal(&msg.encode());
        let frame = WireFrame {
            channel: ChannelTag::P2pEncryptedMesh,
            payload: sealed,
        };
        endpoint.send_1rtt_datagram(peer_addr, &frame)?;
    }
    Ok(())
}

fn broadcast_encrypted(
    endpoint: &mut UdpQuicEndpoint,
    sessions: &mut BTreeMap<SocketAddr, EstablishedPeer>,
    exclude: Option<SocketAddr>,
    msg: &P2pMessage,
) {
    let encoded = msg.encode();
    let addrs: Vec<SocketAddr> = sessions.keys().copied().collect();
    for addr in addrs {
        if Some(addr) == exclude {
            continue;
        }
        if let Some(peer) = sessions.get_mut(&addr) {
            let sealed = peer.cipher.seal(&encoded);
            let frame = WireFrame {
                channel: ChannelTag::P2pEncryptedMesh,
                payload: sealed,
            };
            let _ = endpoint.send_1rtt_datagram(addr, &frame);
        }
    }
}

fn validate_fast_transfer_state_and_sig(
    tx: &Transaction,
    value_commitment: &[u8; 32],
    ledger: &PersistentLedger,
    locks: &mut BTreeMap<(Address, u64), Hash32>,
    record_lock: bool,
) -> Result<(), String> {
    if ledger.finalized_txs.contains(&tx.id) {
        return Err("rejected: duplicate transaction".to_owned());
    }
    let TransactionKind::FastTransfer {
        from,
        amount,
        fee,
        nonce,
        commitment,
        ..
    } = &tx.kind
    else {
        return Err("rejected: expected FastTransfer".to_owned());
    };
    let expected_commitment = domain_hash("XCR.CLI.COMMIT_TAG.V1", &[value_commitment]);
    if *commitment != expected_commitment {
        return Err(
            "rejected: Pedersen value_commitment does not match signed tx commitment".to_owned(),
        );
    }
    if fee.bits() < MIN_BASE_FEE_BITS {
        return Err("rejected: fee below base minimum".to_owned());
    }

    if let Some(&locked) = locks.get(&(*from, *nonce))
        && locked != tx.id
    {
        return Err("rejected: double-spend equivocation lock conflict".to_owned());
    }

    let stored = ledger
        .pockets
        .get(from)
        .ok_or_else(|| "rejected: unknown sender Pocket".to_owned())?;
    let sig = Signature::from_bytes(&tx.signature_bytes)
        .ok_or_else(|| "rejected: malformed WOTS+ signature".to_owned())?;
    let digest = tx_signing_digest(&tx.kind);
    if tx.id != digest || !stored.public_key.verify(digest.as_bytes(), &sig) {
        return Err("rejected: invalid sender signature".to_owned());
    }

    let mut dry_run = stored.state.clone();
    let debit = amount
        .checked_add(*fee)
        .ok_or_else(|| AccountError::AmountOverflow.to_string())?;
    dry_run
        .spend_fast(debit, *nonce, 1)
        .map_err(|e| format!("rejected: {e}"))?;

    if record_lock {
        locks.insert((*from, *nonce), tx.id);
    }
    Ok(())
}

fn apply_finalized_tx_to_wal(
    tx: &Transaction,
    fee_worker: Amount,
    fee_burned: Amount,
    ledger: &mut PersistentLedger,
    locks: &mut BTreeMap<(Address, u64), Hash32>,
) -> io::Result<bool> {
    let TransactionKind::FastTransfer {
        from,
        to_stealth,
        amount,
        fee,
        nonce,
        innocence_nullifier,
        ..
    } = &tx.kind
    else {
        return Ok(false);
    };

    if let Some(stored) = ledger.pockets.get(from) {
        let mut next_state = stored.state.clone();
        let Some(debit) = amount.checked_add(*fee) else {
            return Ok(false);
        };
        if next_state.spend_fast(debit, *nonce, 1).is_err() {
            return Ok(false);
        }
        locks.insert((*from, *nonce), tx.id);
        ledger.append_nosync(WalRecord::RecordFastFinality {
            tx_id: tx.id,
            sender: *from,
            new_nonce: next_state.nonce,
            new_balance: next_state.balance,
            new_daily_spent: next_state.daily_spent,
            day_index: next_state.current_day,
            recipient_stealth: *to_stealth,
            stealth_amount: *amount,
            fee_worker,
            fee_burned,
            nullifier: *innocence_nullifier,
        })?;
        return Ok(true);
    }
    Ok(false)
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

fn is_valid_64_hex(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit())
}

fn load_stealth_announcements(data_dir: &Path) -> BTreeMap<Address, ([u8; 32], u8)> {
    let mut map = BTreeMap::new();
    let path = data_dir.join("stealth_outputs.bin");
    let Ok(raw) = fs::read(&path) else {
        return map;
    };
    for rec in raw.as_chunks::<65>().0 {
        let mut addr = [0u8; 32];
        addr.copy_from_slice(&rec[..32]);
        let mut eph = [0u8; 32];
        eph.copy_from_slice(&rec[32..64]);
        let vt = rec[64];
        map.insert(Address::from_bytes(addr), (eph, vt));
    }
    map
}

fn append_stealth_announcement(
    data_dir: &Path,
    one_time_address: &Address,
    ephemeral_pub: &[u8; 32],
    view_tag: u8,
) {
    let path = data_dir.join("stealth_outputs.bin");
    if let Ok(mut f) = fs::OpenOptions::new().create(true).append(true).open(path) {
        let mut buf = [0u8; 65];
        buf[..32].copy_from_slice(one_time_address.as_bytes());
        buf[32..64].copy_from_slice(ephemeral_pub);
        buf[64] = view_tag;
        let _ = f.write_all(&buf);
    }
}

fn load_stealth_memos(data_dir: &Path) -> BTreeMap<Address, Vec<u8>> {
    let mut map = BTreeMap::new();
    let path = data_dir.join("stealth_memos.bin");
    let Ok(raw) = fs::read(&path) else {
        return map;
    };
    let mut pos = 0usize;
    while pos + 33 <= raw.len() {
        let mut addr = [0u8; 32];
        addr.copy_from_slice(&raw[pos..pos + 32]);
        let len = raw[pos + 32] as usize;
        pos += 33;
        if len > 80 || pos + len > raw.len() {
            break;
        }
        map.insert(Address::from_bytes(addr), raw[pos..pos + len].to_vec());
        pos += len;
    }
    map
}

fn append_stealth_memo(data_dir: &Path, one_time_address: &Address, encrypted_memo: &[u8]) {
    if encrypted_memo.is_empty() || encrypted_memo.len() > 80 {
        return;
    }
    let path = data_dir.join("stealth_memos.bin");
    if let Ok(mut f) = fs::OpenOptions::new().create(true).append(true).open(path) {
        let _ = f.write_all(one_time_address.as_bytes());
        let _ = f.write_all(&[encrypted_memo.len() as u8]);
        let _ = f.write_all(encrypted_memo);
    }
}

#[allow(clippy::too_many_arguments)]
fn apply_verified_stealth_claim(
    one_time_address: Address,
    claimant_pocket: Address,
    claimant_pubkey: PublicKey,
    spend_pub: &[u8; 32],
    kdf: &[u8; 32],
    schnorr_sig64: &[u8; 64],
    ledger: &mut PersistentLedger,
    stealth_announcements: &mut BTreeMap<Address, ([u8; 32], u8)>,
    unsettled_fee_bits: &mut i64,
) -> io::Result<Result<(Amount, Amount, Amount), String>> {
    if claimant_pubkey.to_address() != claimant_pocket {
        return Ok(Err(
            "rejected: claimant pubkey does not match pocket address".to_owned(),
        ));
    }
    let claim_nullifier = domain_hash("XCR.STEALTH.CLAIM_NULL.V1", &[one_time_address.as_bytes()]);
    if ledger.spent_nullifiers.contains(&claim_nullifier) {
        return Ok(Err("rejected: stealth output already claimed".to_owned()));
    }
    if !verify_stealth_claim(
        &one_time_address,
        &claimant_pocket,
        spend_pub,
        kdf,
        schnorr_sig64,
    ) {
        return Ok(Err(
            "rejected: invalid Schnorr stealth ownership proof".to_owned()
        ));
    }
    let fee = Amount::from_bits(MIN_BASE_FEE_BITS);
    let Some(&utxo_amt) = ledger.stealth_utxos.get(&one_time_address) else {
        return Ok(Err("rejected: unspent stealth output not found".to_owned()));
    };
    let Some(net_credit) = utxo_amt.checked_sub(fee).filter(|a| !a.is_zero()) else {
        return Ok(Err(
            "rejected: stealth output smaller than base fee".to_owned()
        ));
    };
    if !ledger.pockets.contains_key(&claimant_pocket) {
        let st = PocketState::new(Amount::ZERO, Amount::from_credits(25).unwrap());
        ledger.append_nosync(WalRecord::UpsertPocket {
            address: claimant_pocket,
            public_key: claimant_pubkey,
            state: st,
        })?;
    }
    let mut next_state = ledger.pockets[&claimant_pocket].state.clone();
    let _ = next_state.credit(net_credit);
    let fs = FeeSplit::compute(fee);
    let tx_id = domain_hash(
        "XCR.STEALTH.CLAIM_TX.V1",
        &[one_time_address.as_bytes(), claimant_pocket.as_bytes()],
    );
    ledger.append_nosync(WalRecord::ClaimStealthUtxo {
        tx_id,
        one_time_address,
        claimant_pocket,
        new_pocket_balance: next_state.balance,
        fee_burned: fs.burned,
        claim_nullifier,
    })?;
    *unsettled_fee_bits = unsettled_fee_bits.saturating_add(fee.bits() as i64);
    stealth_announcements.remove(&one_time_address);
    Ok(Ok((net_credit, fs.burned, next_state.balance)))
}
