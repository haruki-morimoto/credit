//! **Wave-11 Layer-1 Settlement Engine**:
//! 1. **Monero + Zcash Shielded Pool (`MLSAG` RingCT + `Pedersen` Notes + Turnstile Conservation)**
//! 2. **Uniswap `x * y = k` Constant-Product AMM Liquidity Pools + Hybrid Orderbook/AMM Smart Router**
//! 3. **Chainlink-Style Trimmed-Median Quorum Oracle Feeds & Fiat-Pegged Invoice Settlement**
//! 4. **Tron-Style Sybil-Safe Daily Zero-Fee `Bandwidth` Quota (`3` Free Transfers / UTC Day)**
//! 5. **Stellar `ClaimableBalances` (Unregistered User Onboarding), `RedPackets` (`xcrdrop1_`), & `ProofOfBurn`**
//! 6. **Polkadot Non-Withdrawal `RoleProxies` (`GovernanceOnly` / `DexTradeOnly`)**

use std::collections::{BTreeMap, BTreeSet};
use std::io;
use std::time::{SystemTime, UNIX_EPOCH};

use credit_crypto::{EdwardsPoint, Scalar, domain_hash};
use credit_net::{NodeRpcRequest, NodeRpcResponse, ShieldedNoteWire};
use credit_sdk::{
    DAILY_FREE_BANDWIDTH_SLOTS, DexLimitOrder, MIN_BANDWIDTH_ELIGIBLE_BITS,
    PROXY_ROLE_DEX_TRADE_ONLY, PROXY_ROLE_GOVERNANCE_ONLY, RingCtSignature,
    amm_constant_product_out, amm_liquidity_digest, bandwidth_free_pay_digest,
    claimable_create_digest, claimable_sweep_digest, compute_trimmed_median_micros,
    fiat_cents_to_xcr, hybrid_swap_digest, is_valid_feed_id, isqrt_u128, oracle_pegged_pay_digest,
    oracle_report_digest, proof_of_burn_digest, proxy_exec_digest, redpacket_create_digest,
    redpacket_secret_hash, role_proxy_bind_digest, shield_deposit_digest, verify_amm_sig,
    verify_bandwidth_sig, verify_claim_or_burn_sig, verify_oracle_sig, verify_pocket_sig,
    verify_proxy_sig,
};
use credit_storage::{
    PersistentLedger, StoredAmmPool, StoredClaimable, StoredDexOrder, StoredRedPacket,
    StoredShieldedNote, WalRecord,
};
use credit_types::{Address, Amount, FeeSplit, Hash32, MIN_BASE_FEE_BITS, PocketState};

/// Canonical signing message digest for a `1-of-N` `MLSAG` RingCT shielded transfer / unshielding.
pub fn shield_ring_transfer_digest(
    ring_indices: &[u32],
    out_note_id: Option<&Hash32>,
    unshield_recipient: Option<&Address>,
    unshield_amount: Amount,
    fee: Amount,
) -> Hash32 {
    let mut idx_bytes = Vec::with_capacity(ring_indices.len() * 4);
    for &idx in ring_indices {
        idx_bytes.extend_from_slice(&idx.to_le_bytes());
    }
    let mut out_tag = [0u8; 33];
    if let Some(nid) = out_note_id {
        out_tag[0] = 1;
        out_tag[1..33].copy_from_slice(nid.as_bytes());
    }
    let mut unsh_tag = [0u8; 33];
    if let Some(r) = unshield_recipient {
        unsh_tag[0] = 1;
        unsh_tag[1..33].copy_from_slice(r.as_bytes());
    }
    domain_hash(
        "XCR.SHIELD.RING_TX.V1",
        &[
            &idx_bytes,
            &out_tag,
            &unsh_tag,
            &unshield_amount.bits().to_le_bytes(),
            &fee.bits().to_le_bytes(),
        ],
    )
}

fn validate_wire_note(n: &ShieldedNoteWire) -> Option<StoredShieldedNote> {
    let _ = EdwardsPoint::from_bytes(&n.1)?;
    let _ = EdwardsPoint::from_bytes(&n.2)?;
    let _ = EdwardsPoint::from_bytes(&n.3)?;
    let expected_id = domain_hash("XCR.SHIELD.NOTE_ID.V1", &[&n.1, &n.2, &n.3]);
    if expected_id != n.0 {
        return None;
    }
    Some(StoredShieldedNote {
        note_id: n.0,
        one_time_pub: n.1,
        pedersen_commit: n.2,
        ephemeral_pub: n.3,
        view_tag: n.4,
        encrypted_payload: n.5,
    })
}

pub fn execute_wave11_rpc(
    req: &NodeRpcRequest,
    ledger: &mut PersistentLedger,
    unsettled_fee_bits: &mut i64,
    from_p2p_gossip: bool,
) -> io::Result<(NodeRpcResponse, bool)> {
    let min_fee = Amount::from_bits(MIN_BASE_FEE_BITS);
    let now_unix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    match req {
        // ====================================================================
        // 1. Monero + Zcash Shielded Pool (`MLSAG` RingCT + Turnstile)
        // ====================================================================
        NodeRpcRequest::ShieldDeposit {
            tx_id,
            depositor,
            depositor_pubkey,
            amount,
            fee,
            note,
            sig65,
        } => {
            if ledger.spent_nullifiers.contains(tx_id) {
                return Ok((
                    already_ok(ledger, *tx_id, *amount, "shield deposit recorded"),
                    false,
                ));
            }
            let expected = shield_deposit_digest(depositor, &note.0, *amount, *fee);
            let Some(stored_note) = validate_wire_note(note) else {
                return Ok((
                    reject(ledger, *tx_id, "malformed shielded Pedersen note"),
                    false,
                ));
            };
            if expected != *tx_id
                || !verify_pocket_sig(depositor_pubkey, depositor, tx_id, sig65)
                || amount.is_zero()
                || *fee < min_fee
            {
                return Ok((
                    reject(ledger, *tx_id, "invalid ShieldDeposit signature or fee"),
                    false,
                ));
            }
            let Some(tot) = amount.checked_add(*fee) else {
                return Ok((reject(ledger, *tx_id, "amount + fee overflow"), false));
            };
            let Some(cur_bal) = ledger.pockets.get(depositor).map(|p| p.state.balance) else {
                return Ok((reject(ledger, *tx_id, "depositor Pocket not found"), false));
            };
            let Some(new_bal) = cur_bal.checked_sub(tot) else {
                return Ok((
                    reject(ledger, *tx_id, "insufficient depositor balance"),
                    false,
                ));
            };
            let Some(new_pool_bal) = ledger.shielded_pool_balance.checked_add(*amount) else {
                return Ok((reject(ledger, *tx_id, "shielded pool overflow"), false));
            };
            let fs = FeeSplit::compute(*fee);
            *unsettled_fee_bits = unsettled_fee_bits.saturating_add(fs.worker_reward.bits() as i64);
            let note_index = ledger.shielded_notes.len();
            ledger.append_nosync(WalRecord::UpsertShieldedPool {
                tx_id: *tx_id,
                key_image_nullifier: None,
                new_notes: vec![stored_note],
                new_pool_balance: new_pool_bal,
                pocket_updates: vec![(*depositor, new_bal)],
                fee_burned: fs.burned,
            })?;
            ledger.flush_wal()?;
            Ok((
                NodeRpcResponse::ContractReceipt {
                    accepted: true,
                    contract_id: *tx_id,
                    amount: *amount,
                    new_state_root: ledger.state_merkle_root(),
                    message: format!(
                        "shielded {} into Pedersen Note #{note_index} (pool={})",
                        amount.format_symbolic(),
                        new_pool_bal.format_symbolic()
                    ),
                },
                true,
            ))
        }

        NodeRpcRequest::ShieldRingTransfer {
            tx_id,
            ring_indices,
            out_note,
            unshield_recipient,
            unshield_amount,
            fee,
            ring_sig_bytes,
        } => {
            if ledger.spent_nullifiers.contains(tx_id) {
                return Ok((
                    already_ok(ledger, *tx_id, *unshield_amount, "RingCT transfer recorded"),
                    false,
                ));
            }
            if !(1..=16).contains(&ring_indices.len()) || *fee < min_fee {
                return Ok((reject(ledger, *tx_id, "invalid ring size or fee"), false));
            }
            let expected = shield_ring_transfer_digest(
                ring_indices,
                out_note.as_ref().map(|n| &n.0),
                unshield_recipient.as_ref(),
                *unshield_amount,
                *fee,
            );
            if expected != *tx_id {
                return Ok((
                    reject(ledger, *tx_id, "RingCT tx_id digest mismatch"),
                    false,
                ));
            }
            let Some(ring_sig) = RingCtSignature::from_bytes(ring_sig_bytes) else {
                return Ok((reject(ledger, *tx_id, "malformed RingCtSignature"), false));
            };
            let ki_nullifier = Hash32::from_bytes(ring_sig.key_image);
            if ledger.spent_nullifiers.contains(&ki_nullifier) {
                return Ok((
                    reject(
                        ledger,
                        *tx_id,
                        "double-spend blocked: KeyImage already spent",
                    ),
                    false,
                ));
            }

            // Enforce unique ring member indices & gather `(one_time_pub, pedersen_commit)`:
            let mut seen_idx = BTreeSet::new();
            let mut ring_members = Vec::with_capacity(ring_indices.len());
            for &idx in ring_indices {
                let idx_usize = idx as usize;
                if !seen_idx.insert(idx) || idx_usize >= ledger.shielded_notes.len() {
                    return Ok((
                        reject(
                            ledger,
                            *tx_id,
                            "duplicate or out-of-bounds ring decoy index",
                        ),
                        false,
                    ));
                }
                let sn = &ledger.shielded_notes[idx_usize];
                ring_members.push((sn.one_time_pub, sn.pedersen_commit));
            }

            let mut new_notes = Vec::new();
            let b = EdwardsPoint::basepoint_b();
            let Some(public_exit) = unshield_amount.checked_add(*fee) else {
                return Ok((reject(ledger, *tx_id, "unshield + fee overflow"), false));
            };
            // Turnstile invariant: aggregate shielded pool can NEVER go negative!
            let Some(new_pool_bal) = ledger.shielded_pool_balance.checked_sub(public_exit) else {
                return Ok((
                    reject(
                        ledger,
                        *tx_id,
                        "Turnstile violation: exceeds shielded pool balance",
                    ),
                    false,
                ));
            };

            let target_commit = if let Some(wn) = out_note {
                let Some(sn) = validate_wire_note(wn) else {
                    return Ok((
                        reject(ledger, *tx_id, "invalid output shielded note"),
                        false,
                    ));
                };
                let out_c = EdwardsPoint::from_bytes(&sn.pedersen_commit).unwrap();
                new_notes.push(sn);
                out_c + (Scalar::from_u64(public_exit.bits()) * &b)
            } else {
                if unshield_amount.is_zero() {
                    return Ok((
                        reject(
                            ledger,
                            *tx_id,
                            "RingCT transfer has neither output note nor unshield",
                        ),
                        false,
                    ));
                }
                Scalar::from_u64(public_exit.bits()) * &b
            };

            if !ring_sig.verify(tx_id, &ring_members, &target_commit) {
                return Ok((
                    reject(
                        ledger,
                        *tx_id,
                        "MLSAG RingCT or Pedersen balance verification failed",
                    ),
                    false,
                ));
            }

            let mut pocket_updates = Vec::new();
            if !unshield_amount.is_zero() {
                let Some(rcpt) = unshield_recipient else {
                    return Ok((reject(ledger, *tx_id, "missing unshield_recipient"), false));
                };
                if let Err(reason) =
                    ledger.check_deposit_shield_allowed(&Address::default(), rcpt, *unshield_amount)
                {
                    return Ok((reject(ledger, *tx_id, reason), false));
                }
                let Some(cur_r) = ledger.pockets.get(rcpt).map(|p| p.state.balance) else {
                    return Ok((
                        reject(ledger, *tx_id, "unshield recipient Pocket not found"),
                        false,
                    ));
                };
                let Some(new_r) = cur_r.checked_add(*unshield_amount) else {
                    return Ok((reject(ledger, *tx_id, "recipient balance overflow"), false));
                };
                pocket_updates.push((*rcpt, new_r));
            }

            let fs = FeeSplit::compute(*fee);
            *unsettled_fee_bits = unsettled_fee_bits.saturating_add(fs.worker_reward.bits() as i64);
            let ring_n = ring_indices.len();
            ledger.append_nosync(WalRecord::UpsertShieldedPool {
                tx_id: *tx_id,
                key_image_nullifier: Some(ki_nullifier),
                new_notes,
                new_pool_balance: new_pool_bal,
                pocket_updates,
                fee_burned: fs.burned,
            })?;
            ledger.flush_wal()?;
            Ok((
                NodeRpcResponse::ContractReceipt {
                    accepted: true,
                    contract_id: *tx_id,
                    amount: *unshield_amount,
                    new_state_root: ledger.state_merkle_root(),
                    message: format!(
                        "verified 1-of-{ring_n} MLSAG RingCT transfer (KeyImage={}..)",
                        &ki_nullifier.to_hex()[..12]
                    ),
                },
                true,
            ))
        }

        NodeRpcRequest::GetShieldedNotes { start_index } => {
            let total_notes = ledger.shielded_notes.len() as u32;
            let start = (*start_index as usize).min(ledger.shielded_notes.len());
            // Max 6 notes per UDP packet (`6 * 177 = 1,062 B` < 1,200B WAN QUIC MTU):
            let notes = ledger.shielded_notes[start..]
                .iter()
                .take(6)
                .map(|n| {
                    (
                        n.note_id,
                        n.one_time_pub,
                        n.pedersen_commit,
                        n.ephemeral_pub,
                        n.view_tag,
                        n.encrypted_payload,
                    )
                })
                .collect();
            Ok((
                NodeRpcResponse::ShieldedPoolSnapshot {
                    total_notes,
                    pool_balance: ledger.shielded_pool_balance,
                    notes,
                },
                false,
            ))
        }

        // ====================================================================
        // 2. Uniswap `x * y = k` AMM Liquidity Pools + Hybrid Smart Router
        // ====================================================================
        NodeRpcRequest::AmmLiquidity {
            is_remove,
            tx_id,
            provider,
            provider_pubkey,
            asset_id,
            xcr_amount,
            asset_units_or_lp_shares,
            fee,
            salt,
            sig65,
        } => {
            if ledger.spent_nullifiers.contains(tx_id) {
                return Ok((
                    already_ok(ledger, *tx_id, *xcr_amount, "AMM liquidity recorded"),
                    false,
                ));
            }
            let expected = amm_liquidity_digest(
                *is_remove,
                provider,
                asset_id,
                *xcr_amount,
                *asset_units_or_lp_shares,
                *fee,
                salt,
            );
            if expected != *tx_id
                || !verify_amm_sig(provider_pubkey, provider, tx_id, sig65)
                || *fee < min_fee
                || *asset_units_or_lp_shares == 0
                || !ledger.native_assets.contains_key(asset_id)
            {
                return Ok((
                    reject(ledger, *tx_id, "invalid AMM liquidity signature or asset"),
                    false,
                ));
            }
            let ticker = ledger.native_assets[asset_id].ticker.clone();
            let Some(cur_xcr) = ledger.pockets.get(provider).map(|p| p.state.balance) else {
                return Ok((reject(ledger, *tx_id, "provider Pocket not found"), false));
            };
            let cur_units = ledger
                .asset_balances
                .get(&(*provider, *asset_id))
                .copied()
                .unwrap_or(0);
            let cur_lp = ledger
                .amm_lp_shares
                .get(&(*provider, *asset_id))
                .copied()
                .unwrap_or(0);
            let mut pool = ledger
                .amm_pools
                .get(asset_id)
                .cloned()
                .unwrap_or(StoredAmmPool {
                    asset_id: *asset_id,
                    reserve_xcr: Amount::ZERO,
                    reserve_asset: 0,
                    total_lp_shares: 0,
                });

            if !*is_remove {
                let add_units = *asset_units_or_lp_shares;
                if xcr_amount.is_zero() || cur_units < add_units {
                    return Ok((
                        reject(
                            ledger,
                            *tx_id,
                            "insufficient native asset balance for AMM deposit",
                        ),
                        false,
                    ));
                }
                let Some(tot_debit) = xcr_amount.checked_add(*fee) else {
                    return Ok((reject(ledger, *tx_id, "XCR overflow"), false));
                };
                let Some(new_xcr) = cur_xcr.checked_sub(tot_debit) else {
                    return Ok((reject(ledger, *tx_id, "insufficient XCR balance"), false));
                };
                let minted_lp = if pool.total_lp_shares == 0 {
                    isqrt_u128((xcr_amount.bits() as u128) * (add_units as u128))
                } else {
                    let by_xcr = ((xcr_amount.bits() as u128) * (pool.total_lp_shares as u128))
                        / (pool.reserve_xcr.bits() as u128);
                    let by_ast = ((add_units as u128) * (pool.total_lp_shares as u128))
                        / (pool.reserve_asset as u128);
                    u64::try_from(by_xcr.min(by_ast)).unwrap_or(0)
                };
                if minted_lp == 0 {
                    return Ok((
                        reject(ledger, *tx_id, "liquidity deposit too small for LP share"),
                        false,
                    ));
                }
                let Some(new_rxcr) = pool.reserve_xcr.checked_add(*xcr_amount) else {
                    return Ok((reject(ledger, *tx_id, "pool XCR reserve overflow"), false));
                };
                let Some(new_rast) = pool.reserve_asset.checked_add(add_units) else {
                    return Ok((reject(ledger, *tx_id, "pool asset reserve overflow"), false));
                };
                let Some(new_tot_lp) = pool.total_lp_shares.checked_add(minted_lp) else {
                    return Ok((reject(ledger, *tx_id, "LP supply overflow"), false));
                };
                pool.reserve_xcr = new_rxcr;
                pool.reserve_asset = new_rast;
                pool.total_lp_shares = new_tot_lp;

                let fs = FeeSplit::compute(*fee);
                *unsettled_fee_bits =
                    unsettled_fee_bits.saturating_add(fs.worker_reward.bits() as i64);
                ledger.append_nosync(WalRecord::UpsertAmmPool {
                    tx_id: *tx_id,
                    pool: Some(pool),
                    lp_updates: vec![(*provider, *asset_id, cur_lp + minted_lp)],
                    order_updates: Vec::new(),
                    asset_updates: vec![(*provider, *asset_id, cur_units - add_units)],
                    pocket_updates: vec![(*provider, new_xcr)],
                    fee_burned: fs.burned,
                })?;
                ledger.flush_wal()?;
                Ok((
                    NodeRpcResponse::ContractReceipt {
                        accepted: true,
                        contract_id: *tx_id,
                        amount: *xcr_amount,
                        new_state_root: ledger.state_merkle_root(),
                        message: format!(
                            "added {} + {add_units} `{ticker}` -> minted {minted_lp} LP shares",
                            xcr_amount.format_symbolic()
                        ),
                    },
                    true,
                ))
            } else {
                let burn_lp = *asset_units_or_lp_shares;
                if cur_lp < burn_lp || pool.total_lp_shares < burn_lp || pool.total_lp_shares == 0 {
                    return Ok((reject(ledger, *tx_id, "insufficient LP shares"), false));
                }
                let out_xcr_bits = (((pool.reserve_xcr.bits() as u128) * (burn_lp as u128))
                    / (pool.total_lp_shares as u128)) as u64;
                let out_units = (((pool.reserve_asset as u128) * (burn_lp as u128))
                    / (pool.total_lp_shares as u128)) as u64;
                let out_xcr = Amount::from_bits(out_xcr_bits);
                if out_xcr < *xcr_amount || out_units == 0 {
                    return Ok((
                        reject(ledger, *tx_id, "AMM withdrawal below min_xcr"),
                        false,
                    ));
                }
                let Some(after_credit) = cur_xcr.checked_add(out_xcr) else {
                    return Ok((reject(ledger, *tx_id, "provider XCR overflow"), false));
                };
                let Some(new_xcr) = after_credit.checked_sub(*fee) else {
                    return Ok((reject(ledger, *tx_id, "insufficient XCR for fee"), false));
                };
                pool.reserve_xcr = pool.reserve_xcr.checked_sub(out_xcr).unwrap();
                pool.reserve_asset -= out_units;
                pool.total_lp_shares -= burn_lp;

                let fs = FeeSplit::compute(*fee);
                *unsettled_fee_bits =
                    unsettled_fee_bits.saturating_add(fs.worker_reward.bits() as i64);
                ledger.append_nosync(WalRecord::UpsertAmmPool {
                    tx_id: *tx_id,
                    pool: Some(pool),
                    lp_updates: vec![(*provider, *asset_id, cur_lp - burn_lp)],
                    order_updates: Vec::new(),
                    asset_updates: vec![(
                        *provider,
                        *asset_id,
                        cur_units.saturating_add(out_units),
                    )],
                    pocket_updates: vec![(*provider, new_xcr)],
                    fee_burned: fs.burned,
                })?;
                ledger.flush_wal()?;
                Ok((
                    NodeRpcResponse::ContractReceipt {
                        accepted: true,
                        contract_id: *tx_id,
                        amount: out_xcr,
                        new_state_root: ledger.state_merkle_root(),
                        message: format!(
                            "burned {burn_lp} LP -> withdrew {} + {out_units} `{ticker}`",
                            out_xcr.format_symbolic()
                        ),
                    },
                    true,
                ))
            }
        }

        NodeRpcRequest::HybridSmartSwap {
            tx_id,
            trader,
            trader_pubkey,
            asset_id,
            is_buy_asset,
            amount_in_bits_or_units,
            min_out_units_or_bits,
            fee,
            salt,
            sig65,
        } => {
            if ledger.spent_nullifiers.contains(tx_id) {
                return Ok((
                    already_ok(ledger, *tx_id, Amount::ZERO, "smart swap recorded"),
                    false,
                ));
            }
            let expected = hybrid_swap_digest(
                trader,
                asset_id,
                *is_buy_asset,
                *amount_in_bits_or_units,
                *min_out_units_or_bits,
                *fee,
                salt,
            );
            if expected != *tx_id
                || !verify_amm_sig(trader_pubkey, trader, tx_id, sig65)
                || *fee < min_fee
                || *amount_in_bits_or_units == 0
                || !ledger.native_assets.contains_key(asset_id)
            {
                return Ok((
                    reject(ledger, *tx_id, "invalid HybridSmartSwap signature"),
                    false,
                ));
            }
            let ticker = ledger.native_assets[asset_id].ticker.clone();
            let Some(trader_xcr) = ledger.pockets.get(trader).map(|p| p.state.balance) else {
                return Ok((reject(ledger, *tx_id, "trader Pocket not found"), false));
            };
            let trader_units = ledger
                .asset_balances
                .get(&(*trader, *asset_id))
                .copied()
                .unwrap_or(0);

            if *is_buy_asset {
                let dx_bits = *amount_in_bits_or_units;
                let Some(tot_xcr_needed) = Amount::from_bits(dx_bits).checked_add(*fee) else {
                    return Ok((reject(ledger, *tx_id, "XCR input + fee overflow"), false));
                };
                if trader_xcr < tot_xcr_needed {
                    return Ok((reject(ledger, *tx_id, "insufficient trader XCR"), false));
                }

                // 1) Quote AMM `x * y = k`:
                let amm_out = ledger
                    .amm_pools
                    .get(asset_id)
                    .and_then(|p| {
                        amm_constant_product_out(p.reserve_xcr.bits(), p.reserve_asset, dx_bits)
                    })
                    .unwrap_or(0);

                // 2) Quote Limit Orderbook (`Ask`s sorted lowest price first):
                let (ob_units, ob_spent_bits, ob_orders, ob_maker_credits) =
                    quote_orderbook_buy(ledger, asset_id, dx_bits);

                if amm_out >= ob_units && amm_out > 0 && amm_out >= *min_out_units_or_bits {
                    let mut pool = ledger.amm_pools[asset_id].clone();
                    let k_before = (pool.reserve_xcr.bits() as u128) * (pool.reserve_asset as u128);
                    pool.reserve_xcr = pool
                        .reserve_xcr
                        .checked_add(Amount::from_bits(dx_bits))
                        .ok_or_else(|| io::Error::other("AMM XCR overflow"))?;
                    pool.reserve_asset -= amm_out;
                    let k_after = (pool.reserve_xcr.bits() as u128) * (pool.reserve_asset as u128);
                    if k_after < k_before {
                        return Ok((reject(ledger, *tx_id, "AMM k-invariant violated"), false));
                    }
                    let new_xcr = trader_xcr.checked_sub(tot_xcr_needed).unwrap();
                    let fs = FeeSplit::compute(*fee);
                    *unsettled_fee_bits =
                        unsettled_fee_bits.saturating_add(fs.worker_reward.bits() as i64);
                    ledger.append_nosync(WalRecord::UpsertAmmPool {
                        tx_id: *tx_id,
                        pool: Some(pool),
                        lp_updates: Vec::new(),
                        order_updates: Vec::new(),
                        asset_updates: vec![(
                            *trader,
                            *asset_id,
                            trader_units.saturating_add(amm_out),
                        )],
                        pocket_updates: vec![(*trader, new_xcr)],
                        fee_burned: fs.burned,
                    })?;
                    ledger.flush_wal()?;
                    Ok((
                        NodeRpcResponse::ContractReceipt {
                            accepted: true,
                            contract_id: *tx_id,
                            amount: Amount::from_bits(dx_bits),
                            new_state_root: ledger.state_merkle_root(),
                            message: format!(
                                "SmartRouter[AMM] swapped {} -> {amm_out} `{ticker}` (beat Orderbook={ob_units})",
                                Amount::from_bits(dx_bits).format_symbolic()
                            ),
                        },
                        true,
                    ))
                } else if ob_units > 0 && ob_units >= *min_out_units_or_bits {
                    let mut p_map: BTreeMap<Address, Amount> = BTreeMap::new();
                    let trader_after = trader_xcr
                        .checked_sub(Amount::from_bits(ob_spent_bits).checked_add(*fee).unwrap())
                        .unwrap();
                    p_map.insert(*trader, trader_after);
                    for (maker, credit_bits) in ob_maker_credits {
                        let base = p_map
                            .get(&maker)
                            .copied()
                            .or_else(|| ledger.pockets.get(&maker).map(|p| p.state.balance))
                            .unwrap_or(Amount::ZERO);
                        p_map.insert(maker, base.saturating_add(Amount::from_bits(credit_bits)));
                    }
                    let fs = FeeSplit::compute(*fee);
                    *unsettled_fee_bits =
                        unsettled_fee_bits.saturating_add(fs.worker_reward.bits() as i64);
                    ledger.append_nosync(WalRecord::UpsertAmmPool {
                        tx_id: *tx_id,
                        pool: None,
                        lp_updates: Vec::new(),
                        order_updates: ob_orders,
                        asset_updates: vec![(
                            *trader,
                            *asset_id,
                            trader_units.saturating_add(ob_units),
                        )],
                        pocket_updates: p_map.into_iter().collect(),
                        fee_burned: fs.burned,
                    })?;
                    ledger.flush_wal()?;
                    Ok((
                        NodeRpcResponse::ContractReceipt {
                            accepted: true,
                            contract_id: *tx_id,
                            amount: Amount::from_bits(ob_spent_bits),
                            new_state_root: ledger.state_merkle_root(),
                            message: format!(
                                "SmartRouter[Orderbook] swapped {} -> {ob_units} `{ticker}` (beat AMM={amm_out})",
                                Amount::from_bits(ob_spent_bits).format_symbolic()
                            ),
                        },
                        true,
                    ))
                } else {
                    Ok((
                        reject(
                            ledger,
                            *tx_id,
                            "SmartRouter: output below min_out across both AMM and Orderbook",
                        ),
                        false,
                    ))
                }
            } else {
                let dx_units = *amount_in_bits_or_units;
                if trader_units < dx_units || trader_xcr < *fee {
                    return Ok((
                        reject(ledger, *tx_id, "insufficient asset units or XCR fee"),
                        false,
                    ));
                }
                let amm_out_bits = ledger
                    .amm_pools
                    .get(asset_id)
                    .and_then(|p| {
                        amm_constant_product_out(p.reserve_asset, p.reserve_xcr.bits(), dx_units)
                    })
                    .unwrap_or(0);
                let (ob_sold, ob_out_bits, ob_orders, ob_maker_assets) =
                    quote_orderbook_sell(ledger, asset_id, dx_units);
                let ob_effective = if ob_sold == dx_units { ob_out_bits } else { 0 };

                if amm_out_bits >= ob_effective
                    && amm_out_bits > 0
                    && amm_out_bits >= *min_out_units_or_bits
                {
                    let mut pool = ledger.amm_pools[asset_id].clone();
                    let k_before = (pool.reserve_xcr.bits() as u128) * (pool.reserve_asset as u128);
                    pool.reserve_asset = pool.reserve_asset.saturating_add(dx_units);
                    pool.reserve_xcr = pool
                        .reserve_xcr
                        .checked_sub(Amount::from_bits(amm_out_bits))
                        .unwrap();
                    let k_after = (pool.reserve_xcr.bits() as u128) * (pool.reserve_asset as u128);
                    if k_after < k_before {
                        return Ok((reject(ledger, *tx_id, "AMM k-invariant violated"), false));
                    }
                    let new_xcr = trader_xcr
                        .checked_add(Amount::from_bits(amm_out_bits))
                        .and_then(|v| v.checked_sub(*fee))
                        .ok_or_else(|| io::Error::other("XCR overflow"))?;
                    let fs = FeeSplit::compute(*fee);
                    *unsettled_fee_bits =
                        unsettled_fee_bits.saturating_add(fs.worker_reward.bits() as i64);
                    ledger.append_nosync(WalRecord::UpsertAmmPool {
                        tx_id: *tx_id,
                        pool: Some(pool),
                        lp_updates: Vec::new(),
                        order_updates: Vec::new(),
                        asset_updates: vec![(*trader, *asset_id, trader_units - dx_units)],
                        pocket_updates: vec![(*trader, new_xcr)],
                        fee_burned: fs.burned,
                    })?;
                    ledger.flush_wal()?;
                    Ok((
                        NodeRpcResponse::ContractReceipt {
                            accepted: true,
                            contract_id: *tx_id,
                            amount: Amount::from_bits(amm_out_bits),
                            new_state_root: ledger.state_merkle_root(),
                            message: format!(
                                "SmartRouter[AMM] sold {dx_units} `{ticker}` -> {}",
                                Amount::from_bits(amm_out_bits).format_symbolic()
                            ),
                        },
                        true,
                    ))
                } else if ob_effective > 0 && ob_effective >= *min_out_units_or_bits {
                    let mut a_map: BTreeMap<(Address, Hash32), u64> = BTreeMap::new();
                    a_map.insert((*trader, *asset_id), trader_units - dx_units);
                    for (maker, gain_u) in ob_maker_assets {
                        let base = a_map
                            .get(&(maker, *asset_id))
                            .copied()
                            .or_else(|| ledger.asset_balances.get(&(maker, *asset_id)).copied())
                            .unwrap_or(0);
                        a_map.insert((maker, *asset_id), base.saturating_add(gain_u));
                    }
                    let new_xcr = trader_xcr
                        .checked_add(Amount::from_bits(ob_effective))
                        .and_then(|v| v.checked_sub(*fee))
                        .unwrap();
                    let fs = FeeSplit::compute(*fee);
                    *unsettled_fee_bits =
                        unsettled_fee_bits.saturating_add(fs.worker_reward.bits() as i64);
                    ledger.append_nosync(WalRecord::UpsertAmmPool {
                        tx_id: *tx_id,
                        pool: None,
                        lp_updates: Vec::new(),
                        order_updates: ob_orders,
                        asset_updates: a_map.into_iter().map(|((o, a), u)| (o, a, u)).collect(),
                        pocket_updates: vec![(*trader, new_xcr)],
                        fee_burned: fs.burned,
                    })?;
                    ledger.flush_wal()?;
                    Ok((
                        NodeRpcResponse::ContractReceipt {
                            accepted: true,
                            contract_id: *tx_id,
                            amount: Amount::from_bits(ob_effective),
                            new_state_root: ledger.state_merkle_root(),
                            message: format!(
                                "SmartRouter[Orderbook] sold {dx_units} `{ticker}` -> {}",
                                Amount::from_bits(ob_effective).format_symbolic()
                            ),
                        },
                        true,
                    ))
                } else {
                    Ok((
                        reject(ledger, *tx_id, "SmartRouter: sell output below min_out"),
                        false,
                    ))
                }
            }
        }

        // ====================================================================
        // 3. Chainlink-Style Trimmed-Median Oracles & Fiat-Pegged Settlement
        // ====================================================================
        NodeRpcRequest::GetAmmAndOracleSnapshot => {
            let pools = ledger
                .amm_pools
                .values()
                .filter(|p| p.total_lp_shares > 0)
                .take(24)
                .map(|p| {
                    let ticker = ledger
                        .native_assets
                        .get(&p.asset_id)
                        .map(|a| a.ticker.clone())
                        .unwrap_or_else(|| "ASSET".to_owned());
                    (
                        p.asset_id,
                        ticker,
                        p.reserve_xcr,
                        p.reserve_asset,
                        p.total_lp_shares,
                    )
                })
                .collect();
            let feeds = ledger
                .oracle_feeds
                .iter()
                .take(24)
                .filter_map(|(fid, reps)| {
                    let prices: Vec<u64> = reps.values().map(|&(p, _)| p).collect();
                    let med = compute_trimmed_median_micros(&prices)?;
                    let max_ts = reps.values().map(|&(_, ts)| ts).max().unwrap_or(0);
                    Some((fid.clone(), med, reps.len() as u32, max_ts))
                })
                .collect();
            Ok((
                NodeRpcResponse::AmmAndOracleSnapshot { pools, feeds },
                false,
            ))
        }

        NodeRpcRequest::SubmitOracleReport {
            tx_id,
            reporter,
            reporter_pubkey,
            feed_id,
            price_micros,
            timestamp_unix,
            sig65,
        } => {
            if ledger.spent_nullifiers.contains(tx_id) {
                return Ok((
                    already_ok(ledger, *tx_id, Amount::ZERO, "oracle report recorded"),
                    false,
                ));
            }
            let expected = oracle_report_digest(reporter, feed_id, *price_micros, *timestamp_unix);
            if !is_valid_feed_id(feed_id)
                || *price_micros == 0
                || expected != *tx_id
                || !verify_oracle_sig(reporter_pubkey, reporter, tx_id, sig65)
            {
                return Ok((
                    reject(ledger, *tx_id, "invalid oracle report signature"),
                    false,
                ));
            }
            let rep_bal = ledger
                .pockets
                .get(reporter)
                .map(|p| p.state.balance.bits())
                .unwrap_or(0);
            if rep_bal < MIN_BANDWIDTH_ELIGIBLE_BITS {
                return Ok((
                    reject(
                        ledger,
                        *tx_id,
                        "Sybil guard: oracle reporter Pocket must hold >= 1.000000 XCR",
                    ),
                    false,
                ));
            }
            if let Some(prev_ts) = ledger
                .oracle_feeds
                .get(feed_id)
                .and_then(|m| m.get(reporter))
                .map(|&(_, ts)| ts)
                && *timestamp_unix <= prev_ts
            {
                return Ok((reject(ledger, *tx_id, "stale oracle timestamp"), false));
            }
            ledger.append_nosync(WalRecord::UpsertOracleOrBandwidth {
                tx_id: *tx_id,
                oracle_report: Some((feed_id.clone(), *reporter, *price_micros, *timestamp_unix)),
                bandwidth_slot: None,
                pocket_updates: Vec::new(),
                fee_burned: Amount::ZERO,
            })?;
            ledger.flush_wal()?;
            let prices: Vec<u64> = ledger.oracle_feeds[feed_id]
                .values()
                .map(|&(p, _)| p)
                .collect();
            let med = compute_trimmed_median_micros(&prices).unwrap_or(*price_micros);
            Ok((
                NodeRpcResponse::ContractReceipt {
                    accepted: true,
                    contract_id: *tx_id,
                    amount: Amount::ZERO,
                    new_state_root: ledger.state_merkle_root(),
                    message: format!(
                        "oracle `{feed_id}` updated -> trimmed median = {}.{:06} ({} reporters)",
                        med / 1_000_000,
                        med % 1_000_000,
                        prices.len()
                    ),
                },
                true,
            ))
        }

        NodeRpcRequest::OracleFiatPayment {
            tx_id,
            payer,
            payer_pubkey,
            recipient,
            feed_id,
            fiat_cents,
            max_xcr_spend,
            fee,
            salt,
            sig65,
        } => {
            if ledger.spent_nullifiers.contains(tx_id) {
                return Ok((
                    already_ok(ledger, *tx_id, *max_xcr_spend, "fiat payment settled"),
                    false,
                ));
            }
            let expected = oracle_pegged_pay_digest(
                payer,
                recipient,
                feed_id,
                *fiat_cents,
                *max_xcr_spend,
                *fee,
                salt,
            );
            if expected != *tx_id
                || !verify_oracle_sig(payer_pubkey, payer, tx_id, sig65)
                || *fee < min_fee
            {
                return Ok((
                    reject(ledger, *tx_id, "invalid OracleFiatPayment signature"),
                    false,
                ));
            }
            let Some(reps) = ledger.oracle_feeds.get(feed_id) else {
                return Ok((reject(ledger, *tx_id, "oracle feed not found"), false));
            };
            let prices: Vec<u64> = reps.values().map(|&(p, _)| p).collect();
            let Some(med_micros) = compute_trimmed_median_micros(&prices) else {
                return Ok((
                    reject(ledger, *tx_id, "no active oracle observations"),
                    false,
                ));
            };
            let Some(xcr_due) = fiat_cents_to_xcr(*fiat_cents, med_micros) else {
                return Ok((
                    reject(ledger, *tx_id, "fiat-to-XCR conversion failed"),
                    false,
                ));
            };
            if xcr_due > *max_xcr_spend {
                return Ok((
                    reject(
                        ledger,
                        *tx_id,
                        "live oracle XCR quote exceeds max_xcr_spend cap",
                    ),
                    false,
                ));
            }
            if let Err(reason) = ledger.check_deposit_shield_allowed(payer, recipient, xcr_due) {
                return Ok((reject(ledger, *tx_id, reason), false));
            }
            let Some(tot) = xcr_due.checked_add(*fee) else {
                return Ok((reject(ledger, *tx_id, "overflow"), false));
            };
            let Some(p_cur) = ledger.pockets.get(payer).map(|p| p.state.balance) else {
                return Ok((reject(ledger, *tx_id, "payer Pocket not found"), false));
            };
            let Some(p_new) = p_cur.checked_sub(tot) else {
                return Ok((reject(ledger, *tx_id, "insufficient payer balance"), false));
            };
            let pocket_updates = if payer == recipient {
                vec![(*payer, p_cur.checked_sub(*fee).unwrap())]
            } else {
                let Some(r_cur) = ledger.pockets.get(recipient).map(|p| p.state.balance) else {
                    return Ok((reject(ledger, *tx_id, "recipient Pocket not found"), false));
                };
                let Some(r_new) = r_cur.checked_add(xcr_due) else {
                    return Ok((reject(ledger, *tx_id, "recipient overflow"), false));
                };
                vec![(*payer, p_new), (*recipient, r_new)]
            };
            let fs = FeeSplit::compute(*fee);
            *unsettled_fee_bits = unsettled_fee_bits.saturating_add(fs.worker_reward.bits() as i64);
            ledger.append_nosync(WalRecord::UpsertOracleOrBandwidth {
                tx_id: *tx_id,
                oracle_report: None,
                bandwidth_slot: None,
                pocket_updates,
                fee_burned: fs.burned,
            })?;
            ledger.flush_wal()?;
            Ok((
                NodeRpcResponse::ContractReceipt {
                    accepted: true,
                    contract_id: *tx_id,
                    amount: xcr_due,
                    new_state_root: ledger.state_merkle_root(),
                    message: format!(
                        "settled {}.{:02} via `{feed_id}` ({}.{:06}) -> {}",
                        fiat_cents / 100,
                        fiat_cents % 100,
                        med_micros / 1_000_000,
                        med_micros % 1_000_000,
                        xcr_due.format_symbolic()
                    ),
                },
                true,
            ))
        }

        // ====================================================================
        // 4. Tron-Style Sybil-Safe Daily Zero-Fee `Bandwidth` Quota
        // ====================================================================
        NodeRpcRequest::BandwidthFreePay {
            tx_id,
            sender,
            sender_pubkey,
            recipient,
            utc_day,
            slot_index,
            amount,
            sig65,
        } => {
            if ledger.spent_nullifiers.contains(tx_id) {
                return Ok((
                    already_ok(ledger, *tx_id, *amount, "bandwidth pay settled"),
                    false,
                ));
            }
            let expected =
                bandwidth_free_pay_digest(sender, recipient, *utc_day, *slot_index, *amount);
            if expected != *tx_id
                || !verify_bandwidth_sig(sender_pubkey, sender, tx_id, sig65)
                || *slot_index >= DAILY_FREE_BANDWIDTH_SLOTS
                || amount.is_zero()
            {
                return Ok((
                    reject(ledger, *tx_id, "invalid BandwidthFreePay signature"),
                    false,
                ));
            }
            let cur_day = now_unix / 86_400;
            if !from_p2p_gossip && utc_day.abs_diff(cur_day) > 1 {
                return Ok((
                    reject(ledger, *tx_id, "utc_day outside active window"),
                    false,
                ));
            }
            let used = ledger
                .daily_bandwidth_used
                .get(&(*sender, *utc_day))
                .copied()
                .unwrap_or(0);
            if *slot_index != used || used >= DAILY_FREE_BANDWIDTH_SLOTS {
                return Ok((
                    reject(
                        ledger,
                        *tx_id,
                        "daily free Bandwidth quota (3/3) exhausted — use standard fee",
                    ),
                    false,
                ));
            }
            if let Err(reason) = ledger.check_deposit_shield_allowed(sender, recipient, *amount) {
                return Ok((reject(ledger, *tx_id, reason), false));
            }
            let Some(s_cur) = ledger.pockets.get(sender).map(|p| p.state.balance) else {
                return Ok((reject(ledger, *tx_id, "sender Pocket not found"), false));
            };
            if s_cur.bits() < MIN_BANDWIDTH_ELIGIBLE_BITS {
                return Ok((
                    reject(
                        ledger,
                        *tx_id,
                        "Bandwidth eligibility requires >= 1.000000 XCR Pocket balance",
                    ),
                    false,
                ));
            }
            let Some(s_new) = s_cur.checked_sub(*amount) else {
                return Ok((reject(ledger, *tx_id, "insufficient sender balance"), false));
            };
            let pocket_updates = if sender == recipient {
                vec![(*sender, s_cur)]
            } else {
                let Some(r_cur) = ledger.pockets.get(recipient).map(|p| p.state.balance) else {
                    return Ok((reject(ledger, *tx_id, "recipient Pocket not found"), false));
                };
                let Some(r_new) = r_cur.checked_add(*amount) else {
                    return Ok((reject(ledger, *tx_id, "recipient overflow"), false));
                };
                vec![(*sender, s_new), (*recipient, r_new)]
            };
            ledger.append_nosync(WalRecord::UpsertOracleOrBandwidth {
                tx_id: *tx_id,
                oracle_report: None,
                bandwidth_slot: Some((*sender, *utc_day, used + 1)),
                pocket_updates,
                fee_burned: Amount::ZERO,
            })?;
            ledger.flush_wal()?;
            Ok((
                NodeRpcResponse::ContractReceipt {
                    accepted: true,
                    contract_id: *tx_id,
                    amount: *amount,
                    new_state_root: ledger.state_merkle_root(),
                    message: format!(
                        "settled {} with ∀ 0.000000 XCR fee (Bandwidth slot {}/{DAILY_FREE_BANDWIDTH_SLOTS})",
                        amount.format_symbolic(),
                        used + 1
                    ),
                },
                true,
            ))
        }

        // ====================================================================
        // 5. Stellar ClaimableBalances, Viral RedPackets, & Proof-of-Burn
        // ====================================================================
        NodeRpcRequest::CreateClaimable {
            claim_id,
            sender,
            sender_pubkey,
            recipient,
            amount,
            expiry_unix,
            fee,
            salt,
            sig65,
        } => {
            if ledger.spent_nullifiers.contains(claim_id) {
                return Ok((
                    already_ok(ledger, *claim_id, *amount, "claimable recorded"),
                    false,
                ));
            }
            let expected =
                claimable_create_digest(sender, recipient, *amount, *expiry_unix, *fee, salt);
            if expected != *claim_id
                || !verify_claim_or_burn_sig(sender_pubkey, sender, claim_id, sig65)
                || amount.is_zero()
                || *fee < min_fee
            {
                return Ok((
                    reject(ledger, *claim_id, "invalid CreateClaimable signature"),
                    false,
                ));
            }
            let Some(tot) = amount.checked_add(*fee) else {
                return Ok((reject(ledger, *claim_id, "overflow"), false));
            };
            let Some(s_cur) = ledger.pockets.get(sender).map(|p| p.state.balance) else {
                return Ok((reject(ledger, *claim_id, "sender Pocket not found"), false));
            };
            let Some(s_new) = s_cur.checked_sub(tot) else {
                return Ok((
                    reject(ledger, *claim_id, "insufficient sender balance"),
                    false,
                ));
            };
            let fs = FeeSplit::compute(*fee);
            *unsettled_fee_bits = unsettled_fee_bits.saturating_add(fs.worker_reward.bits() as i64);
            ledger.append_nosync(WalRecord::UpsertClaimableDropBurn {
                tx_id: *claim_id,
                claimable: Some(StoredClaimable {
                    claim_id: *claim_id,
                    sender: *sender,
                    recipient: *recipient,
                    amount: *amount,
                    expiry_unix: *expiry_unix,
                    closed: false,
                }),
                red_packet: None,
                auto_onboard_pocket: None,
                asset_supply_update: None,
                asset_updates: Vec::new(),
                pocket_updates: vec![(*sender, s_new)],
                total_burned_delta: fs.burned,
            })?;
            ledger.flush_wal()?;
            Ok((
                NodeRpcResponse::ContractReceipt {
                    accepted: true,
                    contract_id: *claim_id,
                    amount: *amount,
                    new_state_root: ledger.state_merkle_root(),
                    message: format!(
                        "locked {} ClaimableBalance for {} (unregistered onboarding ready)",
                        amount.format_symbolic(),
                        recipient.short_hex()
                    ),
                },
                true,
            ))
        }

        NodeRpcRequest::SweepOrReclaimClaimable {
            claim_id,
            actor,
            actor_pubkey,
            sig65,
        } => {
            let sweep_tx = claimable_sweep_digest(claim_id, actor);
            if ledger.spent_nullifiers.contains(&sweep_tx) {
                return Ok((
                    already_ok(ledger, sweep_tx, Amount::ZERO, "claimable swept"),
                    false,
                ));
            }
            if !verify_claim_or_burn_sig(actor_pubkey, actor, &sweep_tx, sig65) {
                return Ok((reject(ledger, sweep_tx, "invalid sweep signature"), false));
            }
            let Some(mut cl) = ledger.claimables.get(claim_id).cloned() else {
                return Ok((
                    reject(ledger, *claim_id, "ClaimableBalance not found"),
                    false,
                ));
            };
            if cl.closed {
                return Ok((
                    reject(ledger, *claim_id, "ClaimableBalance already closed"),
                    false,
                ));
            }
            let amt = cl.amount;
            let (onboard, pocket_updates, label) = if *actor == cl.recipient {
                if let Some(sp) = ledger.pockets.get(actor) {
                    let Some(nb) = sp.state.balance.checked_add(amt) else {
                        return Ok((reject(ledger, *claim_id, "overflow"), false));
                    };
                    (None, vec![(*actor, nb)], "swept into existing Pocket")
                } else {
                    let st = PocketState::new(amt, Amount::from_credits(25).unwrap());
                    (
                        Some((*actor, *actor_pubkey, st)),
                        Vec::new(),
                        "auto-created & funded brand-new Pocket in 1-RTT",
                    )
                }
            } else if *actor == cl.sender && (from_p2p_gossip || now_unix >= cl.expiry_unix) {
                let s_cur = ledger
                    .pockets
                    .get(actor)
                    .map(|p| p.state.balance)
                    .unwrap_or(Amount::ZERO);
                (
                    None,
                    vec![(*actor, s_cur.saturating_add(amt))],
                    "expired unclaimed balance refunded to sender",
                )
            } else {
                return Ok((
                    reject(
                        ledger,
                        *claim_id,
                        "unauthorized sweep or expiry not yet reached",
                    ),
                    false,
                ));
            };
            cl.closed = true;
            ledger.append_nosync(WalRecord::UpsertClaimableDropBurn {
                tx_id: sweep_tx,
                claimable: Some(cl),
                red_packet: None,
                auto_onboard_pocket: onboard,
                asset_supply_update: None,
                asset_updates: Vec::new(),
                pocket_updates,
                total_burned_delta: Amount::ZERO,
            })?;
            ledger.flush_wal()?;
            Ok((
                NodeRpcResponse::ContractReceipt {
                    accepted: true,
                    contract_id: *claim_id,
                    amount: amt,
                    new_state_root: ledger.state_merkle_root(),
                    message: format!("{} ({label})", amt.format_symbolic()),
                },
                true,
            ))
        }

        NodeRpcRequest::CreateRedPacket {
            drop_id,
            creator,
            creator_pubkey,
            each_amount,
            max_claims,
            secret_hash,
            expiry_unix,
            fee,
            sig65,
        } => {
            if ledger.spent_nullifiers.contains(drop_id) {
                return Ok((
                    already_ok(ledger, *drop_id, *each_amount, "RedPacket recorded"),
                    false,
                ));
            }
            let expected = redpacket_create_digest(
                creator,
                *each_amount,
                *max_claims,
                secret_hash,
                *expiry_unix,
                *fee,
            );
            if expected != *drop_id
                || !verify_claim_or_burn_sig(creator_pubkey, creator, drop_id, sig65)
                || each_amount.is_zero()
                || !(1..=100).contains(max_claims)
                || *fee < min_fee
            {
                return Ok((reject(ledger, *drop_id, "invalid CreateRedPacket"), false));
            }
            let Some(total_pool_bits) = each_amount.bits().checked_mul(*max_claims as u64) else {
                return Ok((reject(ledger, *drop_id, "RedPacket pool overflow"), false));
            };
            let pool_amt = Amount::from_bits(total_pool_bits);
            let Some(tot) = pool_amt.checked_add(*fee) else {
                return Ok((reject(ledger, *drop_id, "overflow"), false));
            };
            let Some(c_cur) = ledger.pockets.get(creator).map(|p| p.state.balance) else {
                return Ok((reject(ledger, *drop_id, "creator Pocket not found"), false));
            };
            let Some(c_new) = c_cur.checked_sub(tot) else {
                return Ok((
                    reject(ledger, *drop_id, "insufficient creator balance"),
                    false,
                ));
            };
            let fs = FeeSplit::compute(*fee);
            *unsettled_fee_bits = unsettled_fee_bits.saturating_add(fs.worker_reward.bits() as i64);
            ledger.append_nosync(WalRecord::UpsertClaimableDropBurn {
                tx_id: *drop_id,
                claimable: None,
                red_packet: Some(StoredRedPacket {
                    drop_id: *drop_id,
                    creator: *creator,
                    each_amount: *each_amount,
                    remaining_claims: *max_claims,
                    secret_hash: *secret_hash,
                    expiry_unix: *expiry_unix,
                    claimants: Vec::new(),
                }),
                auto_onboard_pocket: None,
                asset_supply_update: None,
                asset_updates: Vec::new(),
                pocket_updates: vec![(*creator, c_new)],
                total_burned_delta: fs.burned,
            })?;
            ledger.flush_wal()?;
            Ok((
                NodeRpcResponse::ContractReceipt {
                    accepted: true,
                    contract_id: *drop_id,
                    amount: pool_amt,
                    new_state_root: ledger.state_merkle_root(),
                    message: format!(
                        "funded RedPacket ({max_claims} claims x {} = {})",
                        each_amount.format_symbolic(),
                        pool_amt.format_symbolic()
                    ),
                },
                true,
            ))
        }

        NodeRpcRequest::ClaimOrReclaimRedPacket {
            drop_id,
            actor,
            actor_pubkey,
            drop_secret,
        } => {
            let claim_tx = domain_hash(
                "XCR.REDPACKET.CLAIM_TX.V1",
                &[drop_id.as_bytes(), actor.as_bytes()],
            );
            if ledger.spent_nullifiers.contains(&claim_tx) {
                return Ok((
                    already_ok(ledger, claim_tx, Amount::ZERO, "RedPacket claimed"),
                    false,
                ));
            }
            if actor_pubkey.to_address() != *actor {
                return Ok((reject(ledger, claim_tx, "actor pubkey mismatch"), false));
            }
            let Some(mut rp) = ledger.red_packets.get(drop_id).cloned() else {
                return Ok((
                    reject(ledger, *drop_id, "RedPacket not found or empty"),
                    false,
                ));
            };
            if rp.remaining_claims == 0 {
                return Ok((reject(ledger, *drop_id, "RedPacket fully claimed"), false));
            }
            let (payout, onboard, pocket_updates, msg) =
                if redpacket_secret_hash(drop_secret) == rp.secret_hash {
                    if rp.claimants.contains(actor) {
                        return Ok((
                            reject(ledger, *drop_id, "Pocket already claimed this RedPacket"),
                            false,
                        ));
                    }
                    let each = rp.each_amount;
                    rp.remaining_claims -= 1;
                    rp.claimants.push(*actor);
                    let rem = rp.remaining_claims;
                    if let Some(sp) = ledger.pockets.get(actor) {
                        (
                            each,
                            None,
                            vec![(*actor, sp.state.balance.saturating_add(each))],
                            format!(
                                "claimed {} from RedPacket ({rem} claims remaining)",
                                each.format_symbolic()
                            ),
                        )
                    } else {
                        let st = PocketState::new(each, Amount::from_credits(25).unwrap());
                        (
                            each,
                            Some((*actor, *actor_pubkey, st)),
                            Vec::new(),
                            format!(
                                "auto-onboarded Pocket & claimed {} ({rem} claims remaining)",
                                each.format_symbolic()
                            ),
                        )
                    }
                } else if *actor == rp.creator && (from_p2p_gossip || now_unix >= rp.expiry_unix) {
                    let refund = Amount::from_bits(
                        rp.each_amount
                            .bits()
                            .saturating_mul(rp.remaining_claims as u64),
                    );
                    rp.remaining_claims = 0;
                    let cur = ledger
                        .pockets
                        .get(actor)
                        .map(|p| p.state.balance)
                        .unwrap_or(Amount::ZERO);
                    (
                        refund,
                        None,
                        vec![(*actor, cur.saturating_add(refund))],
                        format!(
                            "reclaimed {} expired RedPacket balance",
                            refund.format_symbolic()
                        ),
                    )
                } else {
                    return Ok((reject(ledger, *drop_id, "invalid RedPacket secret"), false));
                };

            ledger.append_nosync(WalRecord::UpsertClaimableDropBurn {
                tx_id: claim_tx,
                claimable: None,
                red_packet: Some(rp),
                auto_onboard_pocket: onboard,
                asset_supply_update: None,
                asset_updates: Vec::new(),
                pocket_updates,
                total_burned_delta: Amount::ZERO,
            })?;
            ledger.flush_wal()?;
            Ok((
                NodeRpcResponse::ContractReceipt {
                    accepted: true,
                    contract_id: *drop_id,
                    amount: payout,
                    new_state_root: ledger.state_merkle_root(),
                    message: msg,
                },
                true,
            ))
        }

        NodeRpcRequest::ExecuteProofOfBurn {
            burn_id,
            burner,
            burner_pubkey,
            asset_id,
            amount_bits_or_units,
            memo,
            fee,
            salt,
            sig65,
        } => {
            if ledger.spent_nullifiers.contains(burn_id) {
                return Ok((
                    already_ok(ledger, *burn_id, Amount::ZERO, "burn recorded"),
                    false,
                ));
            }
            let expected =
                proof_of_burn_digest(burner, asset_id.as_ref(), *amount_bits_or_units, memo, salt);
            if expected != *burn_id
                || !verify_claim_or_burn_sig(burner_pubkey, burner, burn_id, sig65)
                || *amount_bits_or_units == 0
                || memo.len() > 48
                || *fee < min_fee
            {
                return Ok((
                    reject(ledger, *burn_id, "invalid ProofOfBurn signature"),
                    false,
                ));
            }
            let Some(b_cur) = ledger.pockets.get(burner).map(|p| p.state.balance) else {
                return Ok((reject(ledger, *burn_id, "burner Pocket not found"), false));
            };
            let fs = FeeSplit::compute(*fee);

            if let Some(aid) = asset_id {
                let Some(na) = ledger.native_assets.get(aid) else {
                    return Ok((reject(ledger, *burn_id, "native asset not found"), false));
                };
                let cur_u = ledger
                    .asset_balances
                    .get(&(*burner, *aid))
                    .copied()
                    .unwrap_or(0);
                if cur_u < *amount_bits_or_units || na.total_supply < *amount_bits_or_units {
                    return Ok((reject(ledger, *burn_id, "insufficient asset units"), false));
                }
                let Some(b_new) = b_cur.checked_sub(*fee) else {
                    return Ok((reject(ledger, *burn_id, "insufficient XCR for fee"), false));
                };
                let ticker = na.ticker.clone();
                let new_sup = na.total_supply - *amount_bits_or_units;
                *unsettled_fee_bits =
                    unsettled_fee_bits.saturating_add(fs.worker_reward.bits() as i64);
                ledger.append_nosync(WalRecord::UpsertClaimableDropBurn {
                    tx_id: *burn_id,
                    claimable: None,
                    red_packet: None,
                    auto_onboard_pocket: None,
                    asset_supply_update: Some((*aid, new_sup)),
                    asset_updates: vec![(*burner, *aid, cur_u - *amount_bits_or_units)],
                    pocket_updates: vec![(*burner, b_new)],
                    total_burned_delta: fs.burned,
                })?;
                ledger.flush_wal()?;
                Ok((
                    NodeRpcResponse::ContractReceipt {
                        accepted: true,
                        contract_id: *burn_id,
                        amount: Amount::ZERO,
                        new_state_root: ledger.state_merkle_root(),
                        message: format!(
                            "Proof-of-Burn: destroyed {} `{ticker}` (new supply={new_sup}, memo=\"{memo}\")",
                            amount_bits_or_units
                        ),
                    },
                    true,
                ))
            } else {
                let burn_amt = Amount::from_bits(*amount_bits_or_units);
                let Some(tot) = burn_amt.checked_add(*fee) else {
                    return Ok((reject(ledger, *burn_id, "overflow"), false));
                };
                let Some(b_new) = b_cur.checked_sub(tot) else {
                    return Ok((reject(ledger, *burn_id, "insufficient XCR to burn"), false));
                };
                let Some(burned_delta) = burn_amt.checked_add(fs.burned) else {
                    return Ok((reject(ledger, *burn_id, "burn delta overflow"), false));
                };
                *unsettled_fee_bits =
                    unsettled_fee_bits.saturating_add(fs.worker_reward.bits() as i64);
                ledger.append_nosync(WalRecord::UpsertClaimableDropBurn {
                    tx_id: *burn_id,
                    claimable: None,
                    red_packet: None,
                    auto_onboard_pocket: None,
                    asset_supply_update: None,
                    asset_updates: Vec::new(),
                    pocket_updates: vec![(*burner, b_new)],
                    total_burned_delta: burned_delta,
                })?;
                ledger.flush_wal()?;
                Ok((
                    NodeRpcResponse::ContractReceipt {
                        accepted: true,
                        contract_id: *burn_id,
                        amount: burn_amt,
                        new_state_root: ledger.state_merkle_root(),
                        message: format!(
                            "Proof-of-Burn: permanently burned {} (memo=\"{memo}\")",
                            burn_amt.format_symbolic()
                        ),
                    },
                    true,
                ))
            }
        }

        // ====================================================================
        // 6. Polkadot Non-Withdrawal RoleProxies (`GovernanceOnly` / `DexTradeOnly`)
        // ====================================================================
        NodeRpcRequest::BindOrExecuteRoleProxy {
            is_execute,
            tx_id,
            owner,
            actor_pubkey,
            proxy_pubkey,
            role,
            target_id,
            vote_choice_or_side,
            units,
            price_bits,
            fee,
            salt,
            sig65,
        } => {
            if ledger.spent_nullifiers.contains(tx_id) {
                return Ok((
                    already_ok(ledger, *tx_id, Amount::ZERO, "proxy op recorded"),
                    false,
                ));
            }
            if !*is_execute {
                let expected = role_proxy_bind_digest(owner, proxy_pubkey, *role, salt);
                if actor_pubkey.to_address() != *owner
                    || *role > PROXY_ROLE_DEX_TRADE_ONLY
                    || expected != *tx_id
                    || !verify_proxy_sig(actor_pubkey, tx_id, sig65)
                    || *fee < min_fee
                {
                    return Ok((
                        reject(ledger, *tx_id, "invalid RoleProxy bind signature"),
                        false,
                    ));
                }
                let Some(o_cur) = ledger.pockets.get(owner).map(|p| p.state.balance) else {
                    return Ok((reject(ledger, *tx_id, "owner Pocket not found"), false));
                };
                let Some(o_new) = o_cur.checked_sub(*fee) else {
                    return Ok((
                        reject(ledger, *tx_id, "insufficient owner XCR for fee"),
                        false,
                    ));
                };
                let fs = FeeSplit::compute(*fee);
                *unsettled_fee_bits =
                    unsettled_fee_bits.saturating_add(fs.worker_reward.bits() as i64);
                let role_name = match *role {
                    0 => "Revoked",
                    PROXY_ROLE_GOVERNANCE_ONLY => "GovernanceOnly (0 withdrawal power)",
                    _ => "DexTradeOnly (0 withdrawal power)",
                };
                ledger.append_nosync(WalRecord::UpsertRoleProxy {
                    tx_id: *tx_id,
                    proxy_bind: Some((*owner, *proxy_pubkey, *role)),
                    proposal: None,
                    order_updates: Vec::new(),
                    asset_updates: Vec::new(),
                    pocket_updates: vec![(*owner, o_new)],
                    fee_burned: fs.burned,
                })?;
                ledger.flush_wal()?;
                Ok((
                    NodeRpcResponse::ContractReceipt {
                        accepted: true,
                        contract_id: *tx_id,
                        amount: Amount::ZERO,
                        new_state_root: ledger.state_merkle_root(),
                        message: format!(
                            "bound RoleProxy {} -> {role_name}",
                            proxy_pubkey.to_address().short_hex()
                        ),
                    },
                    true,
                ))
            } else {
                let delegate = actor_pubkey.to_address();
                let Some(&(bound_pk, bound_role)) = ledger.role_proxies.get(&(*owner, delegate))
                else {
                    return Ok((
                        reject(ledger, *tx_id, "no active RoleProxy bound for delegate"),
                        false,
                    ));
                };
                let expected = proxy_exec_digest(
                    owner,
                    *role,
                    target_id,
                    *vote_choice_or_side,
                    *units,
                    *price_bits,
                    salt,
                );
                if bound_pk != *actor_pubkey
                    || bound_role != *role
                    || expected != *tx_id
                    || !verify_proxy_sig(actor_pubkey, tx_id, sig65)
                {
                    return Ok((
                        reject(
                            ledger,
                            *tx_id,
                            "RoleProxy role mismatch or invalid signature",
                        ),
                        false,
                    ));
                }

                if *role == PROXY_ROLE_GOVERNANCE_ONLY {
                    if *vote_choice_or_side > 2 {
                        return Ok((reject(ledger, *tx_id, "invalid vote choice"), false));
                    }
                    let Some(mut prop) = ledger.gov_proposals.get(target_id).cloned() else {
                        return Ok((
                            reject(ledger, *tx_id, "governance proposal not found"),
                            false,
                        ));
                    };
                    prop.votes.retain(|(v, _)| v != owner);
                    prop.votes.push((*owner, *vote_choice_or_side));
                    ledger.append_nosync(WalRecord::UpsertRoleProxy {
                        tx_id: *tx_id,
                        proxy_bind: None,
                        proposal: Some(prop.clone()),
                        order_updates: Vec::new(),
                        asset_updates: Vec::new(),
                        pocket_updates: Vec::new(),
                        fee_burned: Amount::ZERO,
                    })?;
                    ledger.flush_wal()?;
                    Ok((
                        NodeRpcResponse::ContractReceipt {
                            accepted: true,
                            contract_id: *tx_id,
                            amount: Amount::ZERO,
                            new_state_root: ledger.state_merkle_root(),
                            message: format!(
                                "RoleProxy[GovernanceOnly] cast vote for {} on `{}` (0 withdrawal)",
                                owner.short_hex(),
                                prop.title
                            ),
                        },
                        true,
                    ))
                } else if *role == PROXY_ROLE_DEX_TRADE_ONLY {
                    if *units == 0
                        || *price_bits == 0
                        || *fee < min_fee
                        || !ledger.native_assets.contains_key(target_id)
                    {
                        return Ok((reject(ledger, *tx_id, "invalid proxy DEX order"), false));
                    }
                    let is_sell = *vote_choice_or_side != 0;
                    let Some(o_cur) = ledger.pockets.get(owner).map(|p| p.state.balance) else {
                        return Ok((reject(ledger, *tx_id, "owner Pocket not found"), false));
                    };
                    let max_seq = ledger
                        .dex_orders
                        .values()
                        .map(|o| o.seq_priority)
                        .max()
                        .unwrap_or(0);
                    let (escrow_xcr, pocket_new, asset_updates) = if is_sell {
                        let cur_u = ledger
                            .asset_balances
                            .get(&(*owner, *target_id))
                            .copied()
                            .unwrap_or(0);
                        if cur_u < *units {
                            return Ok((reject(ledger, *tx_id, "insufficient owner asset"), false));
                        }
                        let Some(nb) = o_cur.checked_sub(*fee) else {
                            return Ok((
                                reject(ledger, *tx_id, "insufficient owner XCR fee"),
                                false,
                            ));
                        };
                        (Amount::ZERO, nb, vec![(*owner, *target_id, cur_u - *units)])
                    } else {
                        let Some(q) = DexLimitOrder::checked_quote_bits(*units, *price_bits) else {
                            return Ok((reject(ledger, *tx_id, "DEX quote overflow"), false));
                        };
                        let esc = Amount::from_bits(q);
                        let Some(tot) = esc.checked_add(*fee) else {
                            return Ok((reject(ledger, *tx_id, "overflow"), false));
                        };
                        let Some(nb) = o_cur.checked_sub(tot) else {
                            return Ok((reject(ledger, *tx_id, "insufficient owner XCR"), false));
                        };
                        (esc, nb, Vec::new())
                    };
                    let ord = StoredDexOrder {
                        order_id: *tx_id,
                        seq_priority: max_seq + 1,
                        maker: *owner,
                        asset_id: *target_id,
                        is_sell_asset: is_sell,
                        remaining_units: *units,
                        price_bits_per_unit: *price_bits,
                        escrowed_xcr: escrow_xcr,
                        closed: false,
                    };
                    let fs = FeeSplit::compute(*fee);
                    *unsettled_fee_bits =
                        unsettled_fee_bits.saturating_add(fs.worker_reward.bits() as i64);
                    ledger.append_nosync(WalRecord::UpsertRoleProxy {
                        tx_id: *tx_id,
                        proxy_bind: None,
                        proposal: None,
                        order_updates: vec![ord],
                        asset_updates,
                        pocket_updates: vec![(*owner, pocket_new)],
                        fee_burned: fs.burned,
                    })?;
                    ledger.flush_wal()?;
                    Ok((
                        NodeRpcResponse::ContractReceipt {
                            accepted: true,
                            contract_id: *tx_id,
                            amount: escrow_xcr,
                            new_state_root: ledger.state_merkle_root(),
                            message: format!(
                                "RoleProxy[DexTradeOnly] posted order strictly for owner {} (0 external withdrawal)",
                                owner.short_hex()
                            ),
                        },
                        true,
                    ))
                } else {
                    Ok((reject(ledger, *tx_id, "unsupported proxy role"), false))
                }
            }
        }

        _ => Ok((
            NodeRpcResponse::Error("unsupported contract RPC".to_owned()),
            false,
        )),
    }
}

type OrderbookBuyQuote = (u64, u64, Vec<StoredDexOrder>, Vec<(Address, u64)>);
type OrderbookSellQuote = (u64, u64, Vec<StoredDexOrder>, Vec<(Address, u64)>);

fn quote_orderbook_buy(
    ledger: &PersistentLedger,
    asset_id: &Hash32,
    mut rem_budget_bits: u64,
) -> OrderbookBuyQuote {
    let mut asks: Vec<StoredDexOrder> = ledger
        .dex_orders
        .values()
        .filter(|o| {
            !o.closed && o.is_sell_asset && o.asset_id == *asset_id && o.remaining_units > 0
        })
        .cloned()
        .collect();
    asks.sort_by(|a, b| {
        a.price_bits_per_unit
            .cmp(&b.price_bits_per_unit)
            .then_with(|| a.seq_priority.cmp(&b.seq_priority))
    });
    let mut bought = 0u64;
    let mut spent = 0u64;
    let mut touched = Vec::new();
    let mut maker_credits = Vec::new();
    for mut ask in asks {
        if ask.price_bits_per_unit == 0 {
            continue;
        }
        let affordable = rem_budget_bits / ask.price_bits_per_unit;
        if affordable == 0 {
            break;
        }
        let fill = ask.remaining_units.min(affordable);
        let Some(cost) = DexLimitOrder::checked_quote_bits(fill, ask.price_bits_per_unit) else {
            break;
        };
        ask.remaining_units -= fill;
        if ask.remaining_units == 0 {
            ask.closed = true;
        }
        maker_credits.push((ask.maker, cost));
        touched.push(ask);
        bought += fill;
        spent += cost;
        rem_budget_bits -= cost;
    }
    (bought, spent, touched, maker_credits)
}

fn quote_orderbook_sell(
    ledger: &PersistentLedger,
    asset_id: &Hash32,
    mut rem_units: u64,
) -> OrderbookSellQuote {
    let mut bids: Vec<StoredDexOrder> = ledger
        .dex_orders
        .values()
        .filter(|o| {
            !o.closed && !o.is_sell_asset && o.asset_id == *asset_id && o.remaining_units > 0
        })
        .cloned()
        .collect();
    bids.sort_by(|a, b| {
        b.price_bits_per_unit
            .cmp(&a.price_bits_per_unit)
            .then_with(|| a.seq_priority.cmp(&b.seq_priority))
    });
    let mut sold = 0u64;
    let mut out_bits = 0u64;
    let mut touched = Vec::new();
    let mut maker_assets = Vec::new();
    for mut bid in bids {
        if rem_units == 0 {
            break;
        }
        let fill = rem_units.min(bid.remaining_units);
        let Some(proceeds) = DexLimitOrder::checked_quote_bits(fill, bid.price_bits_per_unit)
        else {
            break;
        };
        let Some(new_esc) = bid.escrowed_xcr.checked_sub(Amount::from_bits(proceeds)) else {
            break;
        };
        bid.remaining_units -= fill;
        bid.escrowed_xcr = new_esc;
        if bid.remaining_units == 0 {
            bid.closed = true;
        }
        maker_assets.push((bid.maker, fill));
        touched.push(bid);
        rem_units -= fill;
        sold += fill;
        out_bits += proceeds;
    }
    (sold, out_bits, touched, maker_assets)
}

fn already_ok(ledger: &PersistentLedger, id: Hash32, amt: Amount, msg: &str) -> NodeRpcResponse {
    NodeRpcResponse::ContractReceipt {
        accepted: true,
        contract_id: id,
        amount: amt,
        new_state_root: ledger.state_merkle_root(),
        message: msg.to_owned(),
    }
}

fn reject(ledger: &PersistentLedger, id: Hash32, msg: &str) -> NodeRpcResponse {
    NodeRpcResponse::ContractReceipt {
        accepted: false,
        contract_id: id,
        amount: Amount::ZERO,
        new_state_root: ledger.state_merkle_root(),
        message: format!("rejected: {msg}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use credit_crypto::{Keypair, SignatureScheme};
    use credit_sdk::{
        NativeAssetMint, ShieldedNoteOutput, ShieldedViewingKey, decode_redpacket_uri,
        sign_amm_liquidity, sign_bandwidth_free_pay, sign_claimable_create, sign_claimable_sweep,
        sign_governance_proposal, sign_hybrid_smart_swap, sign_oracle_fiat_payment,
        sign_oracle_report, sign_proof_of_burn, sign_proxy_execute, sign_redpacket_create,
        sign_role_proxy_bind, sign_shield_deposit,
    };
    use std::env;
    use std::fs;

    #[test]
    fn wave11_all_six_features_preserve_exact_supply_prune_cleanly_and_survive_wal_checkpoint() {
        let dir = env::temp_dir().join(format!("xcr_wave11_test_{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let wal_path = dir.join("wave11.wal");

        let alice_seed = [0x11; 32];
        let bob_seed = [0x22; 32];
        let carol_unregistered_seed = [0x33; 32];
        let proxy_hot_seed = [0x44; 32];
        let rep3_seed = [0x55; 32];

        let akp = Keypair::from_seed(
            SignatureScheme::PasskeyP256,
            domain_hash("XCR.WALLET.POCKET_KEY.V1", &[&alice_seed]).0,
        );
        let bkp = Keypair::from_seed(
            SignatureScheme::PasskeyP256,
            domain_hash("XCR.WALLET.POCKET_KEY.V1", &[&bob_seed]).0,
        );
        let ckp = Keypair::from_seed(
            SignatureScheme::PasskeyP256,
            domain_hash("XCR.WALLET.POCKET_KEY.V1", &[&carol_unregistered_seed]).0,
        );
        let pkp = Keypair::from_seed(
            SignatureScheme::PasskeyP256,
            domain_hash("XCR.WALLET.POCKET_KEY.V1", &[&proxy_hot_seed]).0,
        );
        let r3kp = Keypair::from_seed(
            SignatureScheme::PasskeyP256,
            domain_hash("XCR.WALLET.POCKET_KEY.V1", &[&rep3_seed]).0,
        );

        let mut ledger = PersistentLedger::open(&wal_path).unwrap();
        let total_minted = Amount::from_credits(300).unwrap();
        ledger
            .append(WalRecord::RecordEpochSettlement {
                epoch: credit_types::EpochId(1),
                minted_emission: total_minted,
                worker_fees: Amount::ZERO,
                burned_fees: Amount::ZERO,
                payouts: Vec::new(),
            })
            .unwrap();
        for (kp, credits) in [(&akp, 150u64), (&bkp, 100u64), (&r3kp, 50u64)] {
            ledger
                .append(WalRecord::UpsertPocket {
                    address: kp.address(),
                    public_key: kp.public_key(),
                    state: PocketState::new(
                        Amount::from_credits(credits).unwrap(),
                        Amount::from_credits(200).unwrap(),
                    ),
                })
                .unwrap();
        }
        let initial_accounted = ledger.total_live_accounted_bits();
        assert_eq!(initial_accounted, total_minted.bits() as u128);

        let fee = Amount::from_bits(MIN_BASE_FEE_BITS);
        let mut unsettled_fees = 0i64;
        let mut endurance_bits = 0u128;
        let mut swap_offers = BTreeMap::new();
        let fs_one = FeeSplit::compute(fee);

        // --------------------------------------------------------------------
        // Feature 1: Monero/Zcash Shielded Deposit + 1-of-2 MLSAG RingCT Transfer
        // --------------------------------------------------------------------
        let (_avs, _ass, alice_vk) = ShieldedViewingKey::from_master_seed(&alice_seed);
        let (_bvs, bob_spend_sc, bob_vk) = ShieldedViewingKey::from_master_seed(&bob_seed);

        let (decoy_note, _, _) = ShieldedNoteOutput::create(
            &alice_vk.view_pubkey,
            &alice_vk.spend_pubkey,
            Amount::from_credits(8).unwrap(),
            &[1u8; 32],
        )
        .unwrap();
        let (d_addr, d_pk, d_tx, d_sig) = sign_shield_deposit(
            &alice_seed,
            &decoy_note.note_id,
            Amount::from_credits(8).unwrap(),
            fee,
        );
        let (_, m) = execute_wave11_rpc(
            &NodeRpcRequest::ShieldDeposit {
                tx_id: d_tx,
                depositor: d_addr,
                depositor_pubkey: d_pk,
                amount: Amount::from_credits(8).unwrap(),
                fee,
                note: (
                    decoy_note.note_id,
                    decoy_note.one_time_pub,
                    decoy_note.pedersen_commit,
                    decoy_note.ephemeral_pub,
                    decoy_note.view_tag,
                    decoy_note.encrypted_payload,
                ),
                sig65: d_sig,
            },
            &mut ledger,
            &mut unsettled_fees,
            false,
        )
        .unwrap();
        assert!(m);
        endurance_bits += fs_one.endurance_deposit.bits() as u128;

        let (bob_note, _, _) = ShieldedNoteOutput::create(
            &bob_vk.view_pubkey,
            &bob_vk.spend_pubkey,
            Amount::from_credits(10).unwrap(),
            &[2u8; 32],
        )
        .unwrap();
        let (d2_addr, d2_pk, d2_tx, d2_sig) = sign_shield_deposit(
            &alice_seed,
            &bob_note.note_id,
            Amount::from_credits(10).unwrap(),
            fee,
        );
        execute_wave11_rpc(
            &NodeRpcRequest::ShieldDeposit {
                tx_id: d2_tx,
                depositor: d2_addr,
                depositor_pubkey: d2_pk,
                amount: Amount::from_credits(10).unwrap(),
                fee,
                note: (
                    bob_note.note_id,
                    bob_note.one_time_pub,
                    bob_note.pedersen_commit,
                    bob_note.ephemeral_pub,
                    bob_note.view_tag,
                    bob_note.encrypted_payload,
                ),
                sig65: d2_sig,
            },
            &mut ledger,
            &mut unsettled_fees,
            false,
        )
        .unwrap();
        endurance_bits += fs_one.endurance_deposit.bits() as u128;

        // Bob scans with `xcrview1_` and spends inside a 1-of-2 RingCT (6 XCR change note + unshield 3.9995 XCR to Bob):
        let (scanned_amt, scanned_blind, kdf_sc) = bob_note.scan_with_view_key(&bob_vk).unwrap();
        assert_eq!(scanned_amt, Amount::from_credits(10).unwrap());
        let unshield_amt = Amount::from_credits(4).unwrap().checked_sub(fee).unwrap();
        let (change_note, change_blind, _) = ShieldedNoteOutput::create(
            &bob_vk.view_pubkey,
            &bob_vk.spend_pubkey,
            Amount::from_credits(6).unwrap(),
            &[3u8; 32],
        )
        .unwrap();
        let ring_indices = vec![0u32, 1u32];
        let ring_tx_id = shield_ring_transfer_digest(
            &ring_indices,
            Some(&change_note.note_id),
            Some(&bkp.address()),
            unshield_amt,
            fee,
        );
        let b = EdwardsPoint::basepoint_b();
        let target_c = EdwardsPoint::from_bytes(&change_note.pedersen_commit).unwrap()
            + (Scalar::from_u64(unshield_amt.bits() + fee.bits()) * &b);
        let ring_sig = RingCtSignature::sign(
            &ring_tx_id,
            &[
                (decoy_note.one_time_pub, decoy_note.pedersen_commit),
                (bob_note.one_time_pub, bob_note.pedersen_commit),
            ],
            1,
            bob_spend_sc + kdf_sc,
            scanned_blind - change_blind,
            &target_c,
            &[7u8; 32],
        )
        .unwrap();
        let (r_resp, rm) = execute_wave11_rpc(
            &NodeRpcRequest::ShieldRingTransfer {
                tx_id: ring_tx_id,
                ring_indices: ring_indices.clone(),
                out_note: Some((
                    change_note.note_id,
                    change_note.one_time_pub,
                    change_note.pedersen_commit,
                    change_note.ephemeral_pub,
                    change_note.view_tag,
                    change_note.encrypted_payload,
                )),
                unshield_recipient: Some(bkp.address()),
                unshield_amount: unshield_amt,
                fee,
                ring_sig_bytes: ring_sig.to_bytes(),
            },
            &mut ledger,
            &mut unsettled_fees,
            false,
        )
        .unwrap();
        assert!(rm, "RingCT failed: {r_resp:?}");
        endurance_bits += fs_one.endurance_deposit.bits() as u128;

        // --------------------------------------------------------------------
        // Feature 2: Uniswap `x * y = k` AMM Pool + Hybrid Smart Router
        // --------------------------------------------------------------------
        let asset =
            NativeAssetMint::sign_new(&alice_seed, "UNI27", 2_000, 0, fee, [10u8; 16]).unwrap();
        crate::contracts::execute_contract_rpc(
            &NodeRpcRequest::MintNativeAsset {
                asset_id: asset.asset_id,
                issuer: asset.issuer,
                issuer_pubkey: asset.issuer_pubkey,
                ticker: asset.ticker,
                total_supply: asset.total_supply,
                decimals: asset.decimals,
                fee: asset.fee,
                salt: asset.salt,
                sig65: asset.sig65,
            },
            &mut ledger,
            &mut swap_offers,
            &mut unsettled_fees,
            false,
        )
        .unwrap();
        endurance_bits += fs_one.endurance_deposit.bits() as u128;

        let (lp_p, lp_pk, lp_tx, lp_sig) = sign_amm_liquidity(
            &alice_seed,
            false,
            &asset.asset_id,
            Amount::from_credits(20).unwrap(),
            1_000,
            fee,
            [11u8; 16],
        )
        .unwrap();
        let (_, am) = execute_wave11_rpc(
            &NodeRpcRequest::AmmLiquidity {
                is_remove: false,
                tx_id: lp_tx,
                provider: lp_p,
                provider_pubkey: lp_pk,
                asset_id: asset.asset_id,
                xcr_amount: Amount::from_credits(20).unwrap(),
                asset_units_or_lp_shares: 1_000,
                fee,
                salt: [11u8; 16],
                sig65: lp_sig,
            },
            &mut ledger,
            &mut unsettled_fees,
            false,
        )
        .unwrap();
        assert!(am);
        endurance_bits += fs_one.endurance_deposit.bits() as u128;

        let (sw_t, sw_pk, sw_tx, sw_sig) = sign_hybrid_smart_swap(
            &bob_seed,
            &asset.asset_id,
            true,
            2_000_000,
            80,
            fee,
            [12u8; 16],
        )
        .unwrap();
        let (sw_resp, swm) = execute_wave11_rpc(
            &NodeRpcRequest::HybridSmartSwap {
                tx_id: sw_tx,
                trader: sw_t,
                trader_pubkey: sw_pk,
                asset_id: asset.asset_id,
                is_buy_asset: true,
                amount_in_bits_or_units: 2_000_000,
                min_out_units_or_bits: 80,
                fee,
                salt: [12u8; 16],
                sig65: sw_sig,
            },
            &mut ledger,
            &mut unsettled_fees,
            false,
        )
        .unwrap();
        assert!(swm, "{sw_resp:?}");
        endurance_bits += fs_one.endurance_deposit.bits() as u128;

        // --------------------------------------------------------------------
        // Feature 3: Trimmed-Median Quorum Oracles (3 Reporters w/ Outlier) + USD Pay
        // --------------------------------------------------------------------
        for (seed, price) in [
            (&alice_seed, 2_500_000u64),
            (&bob_seed, 2_500_000u64),
            (&rep3_seed, 999_000_000u64), // Byzantine outlier trimmed!
        ] {
            let (rep, rpk, rtx, rsig) =
                sign_oracle_report(seed, "USD/XCR", price, 1_800_000_000).unwrap();
            let (_, om) = execute_wave11_rpc(
                &NodeRpcRequest::SubmitOracleReport {
                    tx_id: rtx,
                    reporter: rep,
                    reporter_pubkey: rpk,
                    feed_id: "USD/XCR".to_owned(),
                    price_micros: price,
                    timestamp_unix: 1_800_000_000,
                    sig65: rsig,
                },
                &mut ledger,
                &mut unsettled_fees,
                false,
            )
            .unwrap();
            assert!(om);
        }
        // Pay $5.00 USD (500 cents) @ $2.50/XCR = 2.000000 XCR:
        let (fp, fpk, ftx, fsig) = sign_oracle_fiat_payment(
            &bob_seed,
            &akp.address(),
            "USD/XCR",
            500,
            Amount::from_credits(3).unwrap(),
            fee,
            [13u8; 16],
        )
        .unwrap();
        let (_, fm) = execute_wave11_rpc(
            &NodeRpcRequest::OracleFiatPayment {
                tx_id: ftx,
                payer: fp,
                payer_pubkey: fpk,
                recipient: akp.address(),
                feed_id: "USD/XCR".to_owned(),
                fiat_cents: 500,
                max_xcr_spend: Amount::from_credits(3).unwrap(),
                fee,
                salt: [13u8; 16],
                sig65: fsig,
            },
            &mut ledger,
            &mut unsettled_fees,
            false,
        )
        .unwrap();
        assert!(fm);
        endurance_bits += fs_one.endurance_deposit.bits() as u128;

        // --------------------------------------------------------------------
        // Feature 4: Tron-Style Zero-Fee Daily Bandwidth Quota (`0` Fee!)
        // --------------------------------------------------------------------
        let cur_day = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            / 86_400;
        let (bw_s, bw_pk, bw_tx, bw_sig) = sign_bandwidth_free_pay(
            &alice_seed,
            &bkp.address(),
            cur_day,
            0,
            Amount::from_credits(1).unwrap(),
        )
        .unwrap();
        let (_, bwm) = execute_wave11_rpc(
            &NodeRpcRequest::BandwidthFreePay {
                tx_id: bw_tx,
                sender: bw_s,
                sender_pubkey: bw_pk,
                recipient: bkp.address(),
                utc_day: cur_day,
                slot_index: 0,
                amount: Amount::from_credits(1).unwrap(),
                sig65: bw_sig,
            },
            &mut ledger,
            &mut unsettled_fees,
            false,
        )
        .unwrap();
        assert!(bwm); // 0 fee!

        // --------------------------------------------------------------------
        // Feature 5: Stellar Claimable (Unregistered Carol Auto-Onboard!) + RedPacket + Burn
        // --------------------------------------------------------------------
        assert!(!ledger.pockets.contains_key(&ckp.address()));
        let (cl_s, cl_pk, cl_id, cl_sig) = sign_claimable_create(
            &alice_seed,
            &ckp.address(),
            Amount::from_credits(5).unwrap(),
            1_999_999_999,
            fee,
            [14u8; 16],
        )
        .unwrap();
        execute_wave11_rpc(
            &NodeRpcRequest::CreateClaimable {
                claim_id: cl_id,
                sender: cl_s,
                sender_pubkey: cl_pk,
                recipient: ckp.address(),
                amount: Amount::from_credits(5).unwrap(),
                expiry_unix: 1_999_999_999,
                fee,
                salt: [14u8; 16],
                sig65: cl_sig,
            },
            &mut ledger,
            &mut unsettled_fees,
            false,
        )
        .unwrap();
        endurance_bits += fs_one.endurance_deposit.bits() as u128;

        let (sw_c, sw_cpk, _, sw_csig) = sign_claimable_sweep(&carol_unregistered_seed, &cl_id);
        let (_, csm) = execute_wave11_rpc(
            &NodeRpcRequest::SweepOrReclaimClaimable {
                claim_id: cl_id,
                actor: sw_c,
                actor_pubkey: sw_cpk,
                sig65: sw_csig,
            },
            &mut ledger,
            &mut unsettled_fees,
            false,
        )
        .unwrap();
        assert!(csm);
        assert_eq!(
            ledger.pockets[&ckp.address()].state.balance,
            Amount::from_credits(5).unwrap()
        );

        let (rp_c, rp_pk, rp_id, rp_sh, rp_uri, rp_sig) = sign_redpacket_create(
            &alice_seed,
            Amount::from_credits(2).unwrap(),
            1,
            [0x7a; 32],
            1_999_999_999,
            fee,
        )
        .unwrap();
        execute_wave11_rpc(
            &NodeRpcRequest::CreateRedPacket {
                drop_id: rp_id,
                creator: rp_c,
                creator_pubkey: rp_pk,
                each_amount: Amount::from_credits(2).unwrap(),
                max_claims: 1,
                secret_hash: rp_sh,
                expiry_unix: 1_999_999_999,
                fee,
                sig65: rp_sig,
            },
            &mut ledger,
            &mut unsettled_fees,
            false,
        )
        .unwrap();
        endurance_bits += fs_one.endurance_deposit.bits() as u128;

        let (_, decoded_sec) = decode_redpacket_uri(&rp_uri).unwrap();
        execute_wave11_rpc(
            &NodeRpcRequest::ClaimOrReclaimRedPacket {
                drop_id: rp_id,
                actor: bkp.address(),
                actor_pubkey: bkp.public_key(),
                drop_secret: decoded_sec,
            },
            &mut ledger,
            &mut unsettled_fees,
            false,
        )
        .unwrap();

        let (bn_a, bn_pk, bn_id, bn_sig) =
            sign_proof_of_burn(&alice_seed, None, 3_000_000, "Deflation Burn", [15u8; 16]).unwrap();
        execute_wave11_rpc(
            &NodeRpcRequest::ExecuteProofOfBurn {
                burn_id: bn_id,
                burner: bn_a,
                burner_pubkey: bn_pk,
                asset_id: None,
                amount_bits_or_units: 3_000_000,
                memo: "Deflation Burn".to_owned(),
                fee,
                salt: [15u8; 16],
                sig65: bn_sig,
            },
            &mut ledger,
            &mut unsettled_fees,
            false,
        )
        .unwrap();
        endurance_bits += fs_one.endurance_deposit.bits() as u128;

        // --------------------------------------------------------------------
        // Feature 6: Polkadot Non-Withdrawal `RoleProxy` (`GovernanceOnly`)
        // --------------------------------------------------------------------
        let (pr_a, pr_pk, prop_id, pr_sig) = sign_governance_proposal(
            &alice_seed,
            "Relay Fee 600 Bits",
            "min_relay_fee_bits",
            600,
            1_999_999_999,
            [16u8; 16],
        )
        .unwrap();
        crate::wave9_contracts::execute_wave9_rpc(
            &NodeRpcRequest::GovernanceAction {
                kind: 0,
                tx_id: prop_id,
                actor: pr_a,
                actor_pubkey: pr_pk,
                target_id: Hash32::ZERO,
                title: "Relay Fee 600 Bits".to_owned(),
                param_key: "min_relay_fee_bits".to_owned(),
                param_value: 600,
                deadline_unix: 1_999_999_999,
                choice: 0,
                salt: [16u8; 16],
                sig65: pr_sig,
            },
            &mut ledger,
            &mut unsettled_fees,
            false,
        )
        .unwrap();
        endurance_bits += fs_one.endurance_deposit.bits() as u128;

        let (ow, ow_pk, bind_tx, bind_sig) = sign_role_proxy_bind(
            &alice_seed,
            &pkp.public_key(),
            PROXY_ROLE_GOVERNANCE_ONLY,
            [17u8; 16],
        )
        .unwrap();
        execute_wave11_rpc(
            &NodeRpcRequest::BindOrExecuteRoleProxy {
                is_execute: false,
                tx_id: bind_tx,
                owner: ow,
                actor_pubkey: ow_pk,
                proxy_pubkey: pkp.public_key(),
                role: PROXY_ROLE_GOVERNANCE_ONLY,
                target_id: Hash32::ZERO,
                vote_choice_or_side: 0,
                units: 0,
                price_bits: 0,
                fee,
                salt: [17u8; 16],
                sig65: bind_sig,
            },
            &mut ledger,
            &mut unsettled_fees,
            false,
        )
        .unwrap();
        endurance_bits += fs_one.endurance_deposit.bits() as u128;

        let (ex_pk, ex_tx, ex_sig) = sign_proxy_execute(
            &proxy_hot_seed,
            &akp.address(),
            PROXY_ROLE_GOVERNANCE_ONLY,
            &prop_id,
            1,
            0,
            0,
            [18u8; 16],
        );
        let (_, exm) = execute_wave11_rpc(
            &NodeRpcRequest::BindOrExecuteRoleProxy {
                is_execute: true,
                tx_id: ex_tx,
                owner: akp.address(),
                actor_pubkey: ex_pk,
                proxy_pubkey: ex_pk,
                role: PROXY_ROLE_GOVERNANCE_ONLY,
                target_id: prop_id,
                vote_choice_or_side: 1,
                units: 0,
                price_bits: 0,
                fee: Amount::ZERO,
                salt: [18u8; 16],
                sig65: ex_sig,
            },
            &mut ledger,
            &mut unsettled_fees,
            false,
        )
        .unwrap();
        assert!(exm);

        // Verify 100% mathematical bit conservation across all 6 features!
        let final_accounted = ledger.total_live_accounted_bits();
        assert_eq!(
            final_accounted
                + (ledger.total_burned.bits() as u128)
                + (unsettled_fees as u128)
                + endurance_bits,
            initial_accounted
        );

        // Verify flat-RAM pruning + WAL checkpoint replay preserve exact 256-bit state root!
        let root_before = ledger.state_merkle_root();
        let evicted = ledger.prune_closed_contracts(cur_day * 86_400 + 5_000, 3_600);
        assert!(evicted >= 2); // swept Claimable + emptied RedPacket evicted!
        assert!(ledger.claimables.is_empty());
        assert!(ledger.red_packets.is_empty());
        assert_eq!(ledger.state_merkle_root(), root_before);

        ledger.compact_checkpoint().unwrap();
        drop(ledger);
        let reopened = PersistentLedger::open(&wal_path).unwrap();
        assert_eq!(reopened.state_merkle_root(), root_before);
        assert_eq!(reopened.shielded_notes.len(), 3);

        let _ = fs::remove_dir_all(&dir);
    }
}
