//! **Wave-9 Layer-1 Settlement Engine** (`DEX + Babel Fees`, `@name.xcr` Handles,
//! `2D` Nonce Lanes + `AtomicBatch`, `1-of-1` Artifacts + `EAS` Attestations, and
//! `Voltaire` Constitutional `DRep` Governance + `DepositAuth` Inbox Shields).

use std::collections::{BTreeMap, BTreeSet};
use std::io;

use credit_net::{NodeRpcRequest, NodeRpcResponse};
use credit_sdk::{
    AtomicBatchOp, DexLimitOrder, artifact_mint_digest, artifact_transfer_digest,
    atomic_batch_digest, attestation_issue_digest, attestation_revoke_digest,
    babel_asset_transfer_digest, bridged_payment_digest, decode_atomic_ops, deposit_shield_digest,
    dex_cancel_digest, drep_delegate_digest, format_xcr_handle, governance_vote_digest,
    handle_register_digest, handle_transfer_digest, normalize_xcr_handle, parallel_lane_pay_digest,
    proposal_create_digest, registration_fee_for_handle, validate_constitutional_parameter,
    verify_artifact_or_attest_sig, verify_batch_or_lane_sig, verify_gov_or_shield_sig,
    verify_handle_sig,
};
use credit_storage::{
    PersistentLedger, StoredAttestation, StoredBearerArtifact, StoredDepositShield, StoredDexOrder,
    StoredGovProposal, StoredOnchainHandle, WalRecord,
};
use credit_types::{Address, Amount, FeeSplit, Hash32, MIN_BASE_FEE_BITS};

/// Transactional staging buffer ensuring `AtomicBatch`, `DEX`, and `Babel Fee` operations
/// either succeed 100% with exact delta conservation or revert with zero partial state.
struct StagedLedger<'a> {
    base: &'a PersistentLedger,
    pockets: BTreeMap<Address, Amount>,
    assets: BTreeMap<(Address, Hash32), u64>,
    orders: BTreeMap<Hash32, StoredDexOrder>,
    touched_orders: BTreeSet<Hash32>,
    next_seq: u64,
}

type StagedDeltas = (
    Vec<StoredDexOrder>,
    Vec<(Address, Hash32, u64)>,
    Vec<(Address, Amount)>,
);

impl<'a> StagedLedger<'a> {
    fn new(base: &'a PersistentLedger) -> Self {
        let max_seq = base
            .dex_orders
            .values()
            .map(|o| o.seq_priority)
            .max()
            .unwrap_or(0);
        Self {
            base,
            pockets: BTreeMap::new(),
            assets: BTreeMap::new(),
            orders: base.dex_orders.clone(),
            touched_orders: BTreeSet::new(),
            next_seq: max_seq + 1,
        }
    }

    fn pocket_exists(&self, addr: &Address) -> bool {
        self.base.pockets.contains_key(addr)
    }

    fn pocket_bal(&self, addr: &Address) -> Option<Amount> {
        if let Some(&b) = self.pockets.get(addr) {
            Some(b)
        } else {
            self.base.pockets.get(addr).map(|p| p.state.balance)
        }
    }

    fn debit_xcr(&mut self, addr: &Address, amt: Amount) -> Result<(), &'static str> {
        let cur = self.pocket_bal(addr).ok_or("Pocket not found")?;
        let new_bal = cur.checked_sub(amt).ok_or("insufficient XCR balance")?;
        self.pockets.insert(*addr, new_bal);
        Ok(())
    }

    fn credit_xcr(&mut self, addr: &Address, amt: Amount) -> Result<(), &'static str> {
        if amt.is_zero() {
            return Ok(());
        }
        let cur = self.pocket_bal(addr).ok_or("recipient Pocket not found")?;
        let new_bal = cur.checked_add(amt).ok_or("XCR balance overflow")?;
        self.pockets.insert(*addr, new_bal);
        Ok(())
    }

    fn asset_bal(&self, owner: &Address, aid: &Hash32) -> u64 {
        if let Some(&u) = self.assets.get(&(*owner, *aid)) {
            u
        } else {
            self.base
                .asset_balances
                .get(&(*owner, *aid))
                .copied()
                .unwrap_or(0)
        }
    }

    fn debit_asset(
        &mut self,
        owner: &Address,
        aid: &Hash32,
        units: u64,
    ) -> Result<(), &'static str> {
        let cur = self.asset_bal(owner, aid);
        if cur < units {
            return Err("insufficient native asset units");
        }
        self.assets.insert((*owner, *aid), cur - units);
        Ok(())
    }

    fn credit_asset(&mut self, owner: &Address, aid: &Hash32, units: u64) {
        if units == 0 {
            return;
        }
        let cur = self.asset_bal(owner, aid);
        self.assets
            .insert((*owner, *aid), cur.saturating_add(units));
    }

    /// Sells up to `units_to_sell` of `asset_id` into resting `Bid`s (`price >= min_price_bits`).
    /// Returns `(units_sold, xcr_proceeds_bits)`.
    fn sell_into_bids(
        &mut self,
        asset_id: &Hash32,
        mut rem_units: u64,
        min_price_bits: u64,
    ) -> Result<(u64, u64), &'static str> {
        let mut candidate_ids: Vec<(u64, u64, Hash32)> = self
            .orders
            .values()
            .filter(|o| {
                !o.closed
                    && !o.is_sell_asset
                    && o.asset_id == *asset_id
                    && o.remaining_units > 0
                    && o.price_bits_per_unit >= min_price_bits
            })
            .map(|o| (o.price_bits_per_unit, o.seq_priority, o.order_id))
            .collect();
        // Highest bid price first, then earliest seq_priority:
        candidate_ids.sort_by(|a, b| b.0.cmp(&a.0).then_with(|| a.1.cmp(&b.1)));

        let mut total_sold = 0u64;
        let mut total_xcr_bits = 0u64;
        for (_, _, oid) in candidate_ids {
            if rem_units == 0 {
                break;
            }
            let ord = self.orders.get_mut(&oid).unwrap();
            let fill = rem_units.min(ord.remaining_units);
            let trade_bits = DexLimitOrder::checked_quote_bits(fill, ord.price_bits_per_unit)
                .ok_or("DEX quote overflow")?;
            let new_esc = ord
                .escrowed_xcr
                .checked_sub(Amount::from_bits(trade_bits))
                .ok_or("corrupt bid escrow")?;
            let bid_maker = ord.maker;
            ord.remaining_units -= fill;
            ord.escrowed_xcr = new_esc;
            if ord.remaining_units == 0 {
                ord.closed = true;
            }
            self.touched_orders.insert(oid);
            self.credit_asset(&bid_maker, asset_id, fill);
            rem_units -= fill;
            total_sold += fill;
            total_xcr_bits = total_xcr_bits
                .checked_add(trade_bits)
                .ok_or("XCR proceeds overflow")?;
        }
        Ok((total_sold, total_xcr_bits))
    }

    /// Buys up to `units_to_buy` of `asset_id` from resting `Ask`s (`price <= max_price_bits`),
    /// spending at most `budget_xcr_bits`. Returns `(units_bought, xcr_spent_bits)`.
    fn buy_from_asks(
        &mut self,
        asset_id: &Hash32,
        mut rem_units: u64,
        max_price_bits: u64,
        mut rem_budget_bits: u64,
    ) -> Result<(u64, u64), &'static str> {
        let mut candidate_ids: Vec<(u64, u64, Hash32)> = self
            .orders
            .values()
            .filter(|o| {
                !o.closed
                    && o.is_sell_asset
                    && o.asset_id == *asset_id
                    && o.remaining_units > 0
                    && o.price_bits_per_unit <= max_price_bits
            })
            .map(|o| (o.price_bits_per_unit, o.seq_priority, o.order_id))
            .collect();
        // Lowest ask price first, then earliest seq_priority:
        candidate_ids.sort_by(|a, b| a.0.cmp(&b.0).then_with(|| a.1.cmp(&b.1)));

        let mut total_bought = 0u64;
        let mut total_spent_bits = 0u64;
        for (_, _, oid) in candidate_ids {
            if rem_units == 0 {
                break;
            }
            let price = self.orders[&oid].price_bits_per_unit;
            let affordable = rem_budget_bits / price;
            if affordable == 0 {
                break;
            }
            let ord = self.orders.get_mut(&oid).unwrap();
            let fill = rem_units.min(ord.remaining_units).min(affordable);
            let cost_bits =
                DexLimitOrder::checked_quote_bits(fill, price).ok_or("DEX quote overflow")?;
            let ask_maker = ord.maker;
            ord.remaining_units -= fill;
            if ord.remaining_units == 0 {
                ord.closed = true;
            }
            self.touched_orders.insert(oid);
            self.credit_xcr(&ask_maker, Amount::from_bits(cost_bits))?;
            rem_units -= fill;
            rem_budget_bits -= cost_bits;
            total_bought += fill;
            total_spent_bits += cost_bits;
        }
        Ok((total_bought, total_spent_bits))
    }

    fn into_deltas(self) -> StagedDeltas {
        let order_updates = self
            .touched_orders
            .into_iter()
            .filter_map(|id| self.orders.get(&id).cloned())
            .collect();
        let asset_updates = self
            .assets
            .into_iter()
            .map(|((o, a), u)| (o, a, u))
            .collect();
        let pocket_updates = self.pockets.into_iter().collect();
        (order_updates, asset_updates, pocket_updates)
    }
}

pub fn execute_wave9_rpc(
    req: &NodeRpcRequest,
    ledger: &mut PersistentLedger,
    unsettled_fee_bits: &mut i64,
    from_p2p_gossip: bool,
) -> io::Result<(NodeRpcResponse, bool)> {
    let min_fee = Amount::from_bits(MIN_BASE_FEE_BITS);

    match req {
        NodeRpcRequest::PlaceDexOrder {
            order_id,
            maker,
            maker_pubkey,
            asset_id,
            is_sell_asset,
            asset_units,
            price_bits_per_unit,
            immediate_or_cancel,
            fee,
            salt,
            sig65,
        } => {
            if ledger.spent_nullifiers.contains(order_id)
                || ledger.dex_orders.contains_key(order_id)
            {
                return Ok((
                    NodeRpcResponse::ContractReceipt {
                        accepted: true,
                        contract_id: *order_id,
                        amount: Amount::ZERO,
                        new_state_root: ledger.state_merkle_root(),
                        message: "DEX order already recorded".to_owned(),
                    },
                    false,
                ));
            }
            let ord = DexLimitOrder {
                order_id: *order_id,
                maker: *maker,
                maker_pubkey: *maker_pubkey,
                asset_id: *asset_id,
                is_sell_asset: *is_sell_asset,
                asset_units: *asset_units,
                price_bits_per_unit: *price_bits_per_unit,
                immediate_or_cancel: *immediate_or_cancel,
                fee: *fee,
                salt: *salt,
                sig65: *sig65,
            };
            if !ord.verify() || *fee < min_fee || !ledger.native_assets.contains_key(asset_id) {
                return Ok((
                    reject(ledger, *order_id, "invalid DexLimitOrder or unknown asset"),
                    false,
                ));
            }
            let mut stage = StagedLedger::new(ledger);
            if let Err(e) = stage.debit_xcr(maker, *fee) {
                return Ok((reject(ledger, *order_id, e), false));
            }

            let summary_msg = if *is_sell_asset {
                if let Err(e) = stage.debit_asset(maker, asset_id, *asset_units) {
                    return Ok((reject(ledger, *order_id, e), false));
                }
                let (sold, xcr_bits) =
                    match stage.sell_into_bids(asset_id, *asset_units, *price_bits_per_unit) {
                        Ok(v) => v,
                        Err(e) => return Ok((reject(ledger, *order_id, e), false)),
                    };
                if let Err(e) = stage.credit_xcr(maker, Amount::from_bits(xcr_bits)) {
                    return Ok((reject(ledger, *order_id, e), false));
                }
                let rem = asset_units - sold;
                if rem > 0 {
                    if *immediate_or_cancel {
                        stage.credit_asset(maker, asset_id, rem);
                    } else {
                        let seq = stage.next_seq;
                        stage.orders.insert(
                            *order_id,
                            StoredDexOrder {
                                order_id: *order_id,
                                seq_priority: seq,
                                maker: *maker,
                                asset_id: *asset_id,
                                is_sell_asset: true,
                                remaining_units: rem,
                                price_bits_per_unit: *price_bits_per_unit,
                                escrowed_xcr: Amount::ZERO,
                                closed: false,
                            },
                        );
                        stage.touched_orders.insert(*order_id);
                    }
                }
                format!(
                    "DEX Ask accepted (matched {sold}/{asset_units} units -> {})",
                    Amount::from_bits(xcr_bits).format_symbolic()
                )
            } else {
                let max_quote_bits =
                    DexLimitOrder::checked_quote_bits(*asset_units, *price_bits_per_unit).unwrap();
                if let Err(e) = stage.debit_xcr(maker, Amount::from_bits(max_quote_bits)) {
                    return Ok((reject(ledger, *order_id, e), false));
                }
                let (bought, spent_bits) = match stage.buy_from_asks(
                    asset_id,
                    *asset_units,
                    *price_bits_per_unit,
                    max_quote_bits,
                ) {
                    Ok(v) => v,
                    Err(e) => return Ok((reject(ledger, *order_id, e), false)),
                };
                stage.credit_asset(maker, asset_id, bought);
                let rem_units = asset_units - bought;
                let rem_escrow_bits = if *immediate_or_cancel {
                    0
                } else {
                    rem_units * (*price_bits_per_unit)
                };
                let refund_bits = max_quote_bits - spent_bits - rem_escrow_bits;
                let _ = stage.credit_xcr(maker, Amount::from_bits(refund_bits));
                if rem_units > 0 && !*immediate_or_cancel {
                    let seq = stage.next_seq;
                    stage.orders.insert(
                        *order_id,
                        StoredDexOrder {
                            order_id: *order_id,
                            seq_priority: seq,
                            maker: *maker,
                            asset_id: *asset_id,
                            is_sell_asset: false,
                            remaining_units: rem_units,
                            price_bits_per_unit: *price_bits_per_unit,
                            escrowed_xcr: Amount::from_bits(rem_escrow_bits),
                            closed: false,
                        },
                    );
                    stage.touched_orders.insert(*order_id);
                }
                format!(
                    "DEX Bid accepted (matched {bought}/{asset_units} units, escrowed {})",
                    Amount::from_bits(rem_escrow_bits).format_symbolic()
                )
            };

            let fs = FeeSplit::compute(*fee);
            *unsettled_fee_bits = unsettled_fee_bits.saturating_add(fs.worker_reward.bits() as i64);
            let (order_updates, asset_updates, pocket_updates) = stage.into_deltas();
            ledger.append_nosync(WalRecord::UpsertDexState {
                tx_id: *order_id,
                order_updates,
                asset_updates,
                pocket_updates,
                fee_burned: fs.burned,
            })?;
            ledger.flush_wal()?;
            Ok((
                NodeRpcResponse::ContractReceipt {
                    accepted: true,
                    contract_id: *order_id,
                    amount: Amount::ZERO,
                    new_state_root: ledger.state_merkle_root(),
                    message: summary_msg,
                },
                true,
            ))
        }

        NodeRpcRequest::CancelDexOrder {
            order_id,
            maker,
            maker_pubkey,
            sig65,
        } => {
            let Some(existing) = ledger.dex_orders.get(order_id).cloned() else {
                return Ok((reject(ledger, *order_id, "order not found"), false));
            };
            if existing.closed {
                return Ok((
                    NodeRpcResponse::ContractReceipt {
                        accepted: true,
                        contract_id: *order_id,
                        amount: Amount::ZERO,
                        new_state_root: ledger.state_merkle_root(),
                        message: "order already closed".to_owned(),
                    },
                    false,
                ));
            }
            let digest = dex_cancel_digest(maker, order_id);
            if existing.maker != *maker
                || !verify_batch_or_lane_sig(maker_pubkey, maker, &digest, sig65)
            {
                return Ok((reject(ledger, *order_id, "invalid cancel signature"), false));
            }
            let mut stage = StagedLedger::new(ledger);
            if existing.is_sell_asset {
                stage.credit_asset(maker, &existing.asset_id, existing.remaining_units);
            } else {
                let _ = stage.credit_xcr(maker, existing.escrowed_xcr);
            }
            let mut closed_ord = existing;
            closed_ord.closed = true;
            closed_ord.remaining_units = 0;
            closed_ord.escrowed_xcr = Amount::ZERO;
            stage.orders.insert(*order_id, closed_ord);
            stage.touched_orders.insert(*order_id);
            let cancel_tx =
                credit_crypto::domain_hash("XCR.DEX.CANCEL_TX.V1", &[order_id.as_bytes()]);
            let (order_updates, asset_updates, pocket_updates) = stage.into_deltas();
            ledger.append_nosync(WalRecord::UpsertDexState {
                tx_id: cancel_tx,
                order_updates,
                asset_updates,
                pocket_updates,
                fee_burned: Amount::ZERO,
            })?;
            ledger.flush_wal()?;
            Ok((
                NodeRpcResponse::ContractReceipt {
                    accepted: true,
                    contract_id: *order_id,
                    amount: Amount::ZERO,
                    new_state_root: ledger.state_merkle_root(),
                    message: "DEX resting order cancelled and escrow refunded in 1-RTT".to_owned(),
                },
                true,
            ))
        }

        NodeRpcRequest::BridgedAssetPayment {
            tx_id,
            payer,
            payer_pubkey,
            recipient,
            in_asset_id,
            max_in_units,
            out_asset_id,
            min_out_amount_or_units,
            fee,
            salt,
            sig65,
        } => {
            if ledger.spent_nullifiers.contains(tx_id) {
                return Ok((
                    NodeRpcResponse::ContractReceipt {
                        accepted: from_p2p_gossip,
                        contract_id: *tx_id,
                        amount: Amount::ZERO,
                        new_state_root: ledger.state_merkle_root(),
                        message: "bridged payment already settled".to_owned(),
                    },
                    false,
                ));
            }
            let expected = bridged_payment_digest(
                payer,
                recipient,
                in_asset_id,
                *max_in_units,
                out_asset_id.as_ref(),
                *min_out_amount_or_units,
                *fee,
                salt,
            );
            if expected != *tx_id
                || !verify_batch_or_lane_sig(payer_pubkey, payer, tx_id, sig65)
                || *fee < min_fee
                || !ledger.pockets.contains_key(recipient)
            {
                return Ok((reject(ledger, *tx_id, "invalid bridged payment"), false));
            }

            let mut stage = StagedLedger::new(ledger);
            if let Err(e) = stage.debit_xcr(payer, *fee) {
                return Ok((reject(ledger, *tx_id, e), false));
            }
            if let Err(e) = stage.debit_asset(payer, in_asset_id, *max_in_units) {
                return Ok((reject(ledger, *tx_id, e), false));
            }
            let (sold, bridge_xcr_bits) = match stage.sell_into_bids(in_asset_id, *max_in_units, 1)
            {
                Ok(v) => v,
                Err(e) => return Ok((reject(ledger, *tx_id, e), false)),
            };
            if sold < *max_in_units {
                stage.credit_asset(payer, in_asset_id, *max_in_units - sold);
            }

            let settled_amt: Amount;
            let msg: String;
            if let Some(target_aid) = out_asset_id {
                let (bought, spent_bits) = match stage.buy_from_asks(
                    target_aid,
                    u64::MAX / 2,
                    u64::MAX,
                    bridge_xcr_bits,
                ) {
                    Ok(v) => v,
                    Err(e) => return Ok((reject(ledger, *tx_id, e), false)),
                };
                if bought < *min_out_amount_or_units {
                    return Ok((
                        reject(
                            ledger,
                            *tx_id,
                            "insufficient orderbook liquidity for bridged min_out units",
                        ),
                        false,
                    ));
                }
                stage.credit_asset(recipient, target_aid, bought);
                let _ = stage.credit_xcr(payer, Amount::from_bits(bridge_xcr_bits - spent_bits));
                settled_amt = Amount::ZERO;
                msg = format!(
                    "XRPL-style auto-bridged payment settled ({sold} in -> XCR -> {bought} out)"
                );
            } else {
                if bridge_xcr_bits < *min_out_amount_or_units {
                    return Ok((
                        reject(
                            ledger,
                            *tx_id,
                            "insufficient Bid liquidity for min XCR delivery",
                        ),
                        false,
                    ));
                }
                let deliver = Amount::from_bits(*min_out_amount_or_units);
                if let Err(e) = ledger.check_deposit_shield_allowed(payer, recipient, deliver) {
                    return Ok((reject(ledger, *tx_id, e), false));
                }
                let _ = stage.credit_xcr(recipient, deliver);
                let _ = stage.credit_xcr(
                    payer,
                    Amount::from_bits(bridge_xcr_bits - *min_out_amount_or_units),
                );
                settled_amt = deliver;
                msg = format!(
                    "auto-bridged token->XCR payment delivered {} to recipient",
                    deliver.format_symbolic()
                );
            }

            let fs = FeeSplit::compute(*fee);
            *unsettled_fee_bits = unsettled_fee_bits.saturating_add(fs.worker_reward.bits() as i64);
            let (order_updates, asset_updates, pocket_updates) = stage.into_deltas();
            ledger.append_nosync(WalRecord::UpsertDexState {
                tx_id: *tx_id,
                order_updates,
                asset_updates,
                pocket_updates,
                fee_burned: fs.burned,
            })?;
            ledger.flush_wal()?;
            Ok((
                NodeRpcResponse::ContractReceipt {
                    accepted: true,
                    contract_id: *tx_id,
                    amount: settled_amt,
                    new_state_root: ledger.state_merkle_root(),
                    message: msg,
                },
                true,
            ))
        }

        NodeRpcRequest::BabelAssetTransfer {
            xfer_id,
            asset_id,
            sender,
            sender_pubkey,
            recipient,
            units,
            babel_fee_units,
            salt,
            sig65,
        } => {
            if ledger.spent_nullifiers.contains(xfer_id) {
                return Ok((
                    NodeRpcResponse::ContractReceipt {
                        accepted: from_p2p_gossip,
                        contract_id: *xfer_id,
                        amount: Amount::ZERO,
                        new_state_root: ledger.state_merkle_root(),
                        message: "Babel-fee transfer already settled".to_owned(),
                    },
                    false,
                ));
            }
            let expected = babel_asset_transfer_digest(
                asset_id,
                sender,
                recipient,
                *units,
                *babel_fee_units,
                salt,
            );
            let Some(total_asset_debit) = units.checked_add(*babel_fee_units) else {
                return Ok((reject(ledger, *xfer_id, "asset units overflow"), false));
            };
            if expected != *xfer_id
                || !verify_batch_or_lane_sig(sender_pubkey, sender, xfer_id, sig65)
                || *units == 0
                || *babel_fee_units == 0
                || !ledger.pockets.contains_key(sender)
                || !ledger.pockets.contains_key(recipient)
            {
                return Ok((
                    reject(ledger, *xfer_id, "invalid Babel-fee transfer"),
                    false,
                ));
            }

            let mut stage = StagedLedger::new(ledger);
            if let Err(e) = stage.debit_asset(sender, asset_id, total_asset_debit) {
                return Ok((reject(ledger, *xfer_id, e), false));
            }
            let (sold_fee_units, babel_xcr_bits) =
                match stage.sell_into_bids(asset_id, *babel_fee_units, 1) {
                    Ok(v) => v,
                    Err(e) => return Ok((reject(ledger, *xfer_id, e), false)),
                };
            if babel_xcr_bits < MIN_BASE_FEE_BITS {
                return Ok((
                    reject(
                        ledger,
                        *xfer_id,
                        "Babel fee offer insufficient to cover 0.0005 XCR via DEX Bids",
                    ),
                    false,
                ));
            }
            if sold_fee_units < *babel_fee_units {
                stage.credit_asset(sender, asset_id, *babel_fee_units - sold_fee_units);
            }
            stage.credit_asset(recipient, asset_id, *units);
            let surplus_xcr = Amount::from_bits(babel_xcr_bits - MIN_BASE_FEE_BITS);
            let _ = stage.credit_xcr(sender, surplus_xcr);

            let fs = FeeSplit::compute(min_fee);
            *unsettled_fee_bits = unsettled_fee_bits.saturating_add(fs.worker_reward.bits() as i64);
            let (order_updates, asset_updates, pocket_updates) = stage.into_deltas();
            ledger.append_nosync(WalRecord::UpsertDexState {
                tx_id: *xfer_id,
                order_updates,
                asset_updates,
                pocket_updates,
                fee_burned: fs.burned,
            })?;
            ledger.flush_wal()?;
            Ok((
                NodeRpcResponse::ContractReceipt {
                    accepted: true,
                    contract_id: *xfer_id,
                    amount: surplus_xcr,
                    new_state_root: ledger.state_merkle_root(),
                    message: format!(
                        "Cardano Babel-Fee transfer settled ({units} sent; {sold_fee_units} units auto-paid 0.0005 XCR fee)"
                    ),
                },
                true,
            ))
        }

        NodeRpcRequest::GetDexOrderbook { asset_id } => {
            let orders = ledger
                .dex_orders
                .values()
                .filter(|o| {
                    !o.closed && o.remaining_units > 0 && asset_id.is_none_or(|a| o.asset_id == a)
                })
                .take(32)
                .map(|o| {
                    (
                        o.order_id,
                        o.maker,
                        o.asset_id,
                        o.is_sell_asset,
                        o.remaining_units,
                        o.price_bits_per_unit,
                        o.escrowed_xcr,
                    )
                })
                .collect();
            Ok((NodeRpcResponse::DexOrderbookSnapshot { orders }, false))
        }

        NodeRpcRequest::RegisterOrTransferHandle {
            is_transfer,
            tx_id,
            normalized_name,
            actor,
            actor_pubkey,
            target_owner,
            stealth_uri,
            fee,
            salt,
            sig65,
        } => {
            if ledger.spent_nullifiers.contains(tx_id) {
                return Ok((
                    NodeRpcResponse::ContractReceipt {
                        accepted: true,
                        contract_id: *tx_id,
                        amount: Amount::ZERO,
                        new_state_root: ledger.state_merkle_root(),
                        message: "handle update already finalized".to_owned(),
                    },
                    false,
                ));
            }
            let Some(clean) = normalize_xcr_handle(normalized_name) else {
                return Ok((reject(ledger, *tx_id, "invalid @name.xcr format"), false));
            };
            if clean != *normalized_name || stealth_uri.len() > 200 {
                return Ok((
                    reject(ledger, *tx_id, "non-canonical handle payload"),
                    false,
                ));
            }

            let (new_owner, new_pubkey) = if !*is_transfer {
                if ledger.handles.contains_key(&clean) {
                    return Ok((
                        reject(ledger, *tx_id, "handle @name.xcr is already registered"),
                        false,
                    ));
                }
                let req_fee = registration_fee_for_handle(&clean);
                let expected = handle_register_digest(&clean, actor, stealth_uri, *fee);
                if *fee < req_fee
                    || expected != *tx_id
                    || !verify_handle_sig(actor_pubkey, actor, tx_id, sig65)
                {
                    return Ok((
                        reject(
                            ledger,
                            *tx_id,
                            "invalid handle registration signature or fee",
                        ),
                        false,
                    ));
                }
                (*actor, *actor_pubkey)
            } else {
                let Some(cur_h) = ledger.handles.get(&clean) else {
                    return Ok((reject(ledger, *tx_id, "handle not registered"), false));
                };
                let expected =
                    handle_transfer_digest(&clean, actor, target_owner, stealth_uri, *fee, salt);
                if cur_h.owner != *actor
                    || *fee < min_fee
                    || expected != *tx_id
                    || !verify_handle_sig(actor_pubkey, actor, tx_id, sig65)
                    || !ledger.pockets.contains_key(target_owner)
                {
                    return Ok((reject(ledger, *tx_id, "invalid handle transfer"), false));
                }
                (*target_owner, ledger.pockets[target_owner].public_key)
            };

            let Some(cur_bal) = ledger.pockets.get(actor).map(|p| p.state.balance) else {
                return Ok((reject(ledger, *tx_id, "actor Pocket not found"), false));
            };
            let Some(new_bal) = cur_bal.checked_sub(*fee) else {
                return Ok((
                    reject(ledger, *tx_id, "insufficient XCR for handle fee"),
                    false,
                ));
            };

            let fs = FeeSplit::compute(*fee);
            *unsettled_fee_bits = unsettled_fee_bits.saturating_add(fs.worker_reward.bits() as i64);
            let reg_epoch = ledger.latest_epoch.0;
            ledger.append_nosync(WalRecord::UpsertHandle {
                tx_id: *tx_id,
                handle: StoredOnchainHandle {
                    name: clean.clone(),
                    owner: new_owner,
                    owner_pubkey: new_pubkey,
                    stealth_uri: stealth_uri.clone(),
                    registered_epoch: reg_epoch,
                },
                pocket_updates: vec![(*actor, new_bal)],
                fee_burned: fs.burned,
            })?;
            ledger.flush_wal()?;
            Ok((
                NodeRpcResponse::ContractReceipt {
                    accepted: true,
                    contract_id: *tx_id,
                    amount: *fee,
                    new_state_root: ledger.state_merkle_root(),
                    message: format!(
                        "on-chain handle `{}` bound to {}",
                        format_xcr_handle(&clean),
                        new_owner.short_hex()
                    ),
                },
                true,
            ))
        }

        NodeRpcRequest::ResolveHandle { name } => {
            let Some(clean) = normalize_xcr_handle(name) else {
                return Ok((
                    NodeRpcResponse::HandleResolution {
                        found: false,
                        normalized_name: String::new(),
                        owner: Address::default(),
                        stealth_uri: String::new(),
                        registered_epoch: 0,
                    },
                    false,
                ));
            };
            if let Some(h) = ledger.handles.get(&clean) {
                Ok((
                    NodeRpcResponse::HandleResolution {
                        found: true,
                        normalized_name: h.name.clone(),
                        owner: h.owner,
                        stealth_uri: h.stealth_uri.clone(),
                        registered_epoch: h.registered_epoch,
                    },
                    false,
                ))
            } else {
                Ok((
                    NodeRpcResponse::HandleResolution {
                        found: false,
                        normalized_name: clean,
                        owner: Address::default(),
                        stealth_uri: String::new(),
                        registered_epoch: 0,
                    },
                    false,
                ))
            }
        }

        NodeRpcRequest::ParallelLanePay {
            tx_id,
            sender,
            sender_pubkey,
            recipient,
            lane_id,
            lane_seq,
            amount,
            fee,
            sig65,
        } => {
            if ledger.spent_nullifiers.contains(tx_id) {
                return Ok((
                    NodeRpcResponse::ContractReceipt {
                        accepted: from_p2p_gossip,
                        contract_id: *tx_id,
                        amount: *amount,
                        new_state_root: ledger.state_merkle_root(),
                        message: "parallel lane payment already settled".to_owned(),
                    },
                    false,
                ));
            }
            let expected_seq = ledger
                .lane_nonces
                .get(&(*sender, *lane_id))
                .copied()
                .unwrap_or(0);
            let expected_id =
                parallel_lane_pay_digest(sender, recipient, *lane_id, *lane_seq, *amount, *fee);
            if *lane_id == 0
                || *lane_id > 10_000
                || *lane_seq != expected_seq
                || expected_id != *tx_id
                || amount.is_zero()
                || *fee < min_fee
                || !verify_batch_or_lane_sig(sender_pubkey, sender, tx_id, sig65)
            {
                return Ok((
                    reject(
                        ledger,
                        *tx_id,
                        "invalid parallel 2D lane sequence or signature",
                    ),
                    false,
                ));
            }
            if let Err(e) = ledger.check_deposit_shield_allowed(sender, recipient, *amount) {
                return Ok((reject(ledger, *tx_id, e), false));
            }
            let mut stage = StagedLedger::new(ledger);
            let Some(tot) = amount.checked_add(*fee) else {
                return Ok((reject(ledger, *tx_id, "overflow"), false));
            };
            if let Err(e) = stage.debit_xcr(sender, tot) {
                return Ok((reject(ledger, *tx_id, e), false));
            }
            if let Err(e) = stage.credit_xcr(recipient, *amount) {
                return Ok((reject(ledger, *tx_id, e), false));
            }
            let fs = FeeSplit::compute(*fee);
            *unsettled_fee_bits = unsettled_fee_bits.saturating_add(fs.worker_reward.bits() as i64);
            let (order_updates, asset_updates, pocket_updates) = stage.into_deltas();
            ledger.append_nosync(WalRecord::UpsertLaneOrBatch {
                tx_id: *tx_id,
                lane_update: Some((*sender, *lane_id, expected_seq + 1)),
                order_updates,
                asset_updates,
                pocket_updates,
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
                        "parallel ticket lane #{lane_id} (seq {lane_seq}) settled {}",
                        amount.format_symbolic()
                    ),
                },
                true,
            ))
        }

        NodeRpcRequest::GetArtifactsAndAttestations {
            owner_or_subject,
            lane_id,
        } => {
            let next_lane_seq = owner_or_subject
                .and_then(|o| ledger.lane_nonces.get(&(o, *lane_id)).copied())
                .unwrap_or(0);
            let artifacts = ledger
                .artifacts
                .values()
                .filter(|a| owner_or_subject.is_none_or(|o| a.owner == o))
                .take(32)
                .map(|a| {
                    (
                        a.artifact_id,
                        a.issuer,
                        a.owner,
                        a.collection.clone(),
                        a.title.clone(),
                        a.content_hash,
                    )
                })
                .collect();
            let attestations = ledger
                .attestations
                .values()
                .filter(|att| {
                    owner_or_subject.is_none_or(|s| att.subject == s || att.attester == s)
                })
                .take(32)
                .map(|att| {
                    (
                        att.attestation_id,
                        att.attester,
                        att.subject,
                        att.schema.clone(),
                        att.claim_commitment,
                        att.expiry_unix,
                        att.revoked,
                    )
                })
                .collect();
            Ok((
                NodeRpcResponse::LaneAndArtifactSnapshot {
                    next_lane_seq,
                    artifacts,
                    attestations,
                },
                false,
            ))
        }

        NodeRpcRequest::ExecuteAtomicBatch {
            batch_id,
            sender,
            sender_pubkey,
            ops_bytes,
            max_xcr_debit,
            fee,
            salt,
            sig65,
        } => {
            if ledger.spent_nullifiers.contains(batch_id) {
                return Ok((
                    NodeRpcResponse::ContractReceipt {
                        accepted: from_p2p_gossip,
                        contract_id: *batch_id,
                        amount: Amount::ZERO,
                        new_state_root: ledger.state_merkle_root(),
                        message: "AtomicBatch already finalized".to_owned(),
                    },
                    false,
                ));
            }
            let Some(ops) = decode_atomic_ops(ops_bytes) else {
                return Ok((
                    reject(ledger, *batch_id, "malformed AtomicBatch ops"),
                    false,
                ));
            };
            let expected = atomic_batch_digest(sender, ops_bytes, *max_xcr_debit, *fee, salt);
            if expected != *batch_id
                || *fee < min_fee
                || !verify_batch_or_lane_sig(sender_pubkey, sender, batch_id, sig65)
            {
                return Ok((
                    reject(ledger, *batch_id, "invalid AtomicBatch signature"),
                    false,
                ));
            }

            let mut stage = StagedLedger::new(ledger);
            let Some(initial_bal) = stage.pocket_bal(sender) else {
                return Ok((reject(ledger, *batch_id, "sender Pocket not found"), false));
            };
            if let Err(e) = stage.debit_xcr(sender, *fee) {
                return Ok((reject(ledger, *batch_id, e), false));
            }

            for op in &ops {
                match op {
                    AtomicBatchOp::TransferXcr { to, amount } => {
                        if amount.is_zero() || !stage.pocket_exists(to) {
                            return Ok((
                                reject(ledger, *batch_id, "reverted: invalid TransferXcr op"),
                                false,
                            ));
                        }
                        if let Err(e) = ledger.check_deposit_shield_allowed(sender, to, *amount) {
                            return Ok((reject(ledger, *batch_id, e), false));
                        }
                        if let Err(e) = stage.debit_xcr(sender, *amount) {
                            return Ok((reject(ledger, *batch_id, e), false));
                        }
                        if let Err(e) = stage.credit_xcr(to, *amount) {
                            return Ok((reject(ledger, *batch_id, e), false));
                        }
                    }
                    AtomicBatchOp::TransferAsset {
                        asset_id,
                        to,
                        units,
                    } => {
                        if *units == 0 || !stage.pocket_exists(to) {
                            return Ok((
                                reject(ledger, *batch_id, "reverted: invalid TransferAsset op"),
                                false,
                            ));
                        }
                        if let Err(e) = stage.debit_asset(sender, asset_id, *units) {
                            return Ok((reject(ledger, *batch_id, e), false));
                        }
                        stage.credit_asset(to, asset_id, *units);
                    }
                    AtomicBatchOp::DexBuyAsset {
                        asset_id,
                        units,
                        max_price_bits,
                    } => {
                        let Some(budget) =
                            DexLimitOrder::checked_quote_bits(*units, *max_price_bits)
                        else {
                            return Ok((
                                reject(ledger, *batch_id, "reverted: quote overflow"),
                                false,
                            ));
                        };
                        if let Err(e) = stage.debit_xcr(sender, Amount::from_bits(budget)) {
                            return Ok((reject(ledger, *batch_id, e), false));
                        }
                        let (bought, spent) =
                            match stage.buy_from_asks(asset_id, *units, *max_price_bits, budget) {
                                Ok(v) => v,
                                Err(e) => return Ok((reject(ledger, *batch_id, e), false)),
                            };
                        if bought < *units {
                            return Ok((
                                reject(
                                    ledger,
                                    *batch_id,
                                    "reverted: insufficient DEX Ask liquidity for exact batch buy",
                                ),
                                false,
                            ));
                        }
                        stage.credit_asset(sender, asset_id, bought);
                        let _ = stage.credit_xcr(sender, Amount::from_bits(budget - spent));
                    }
                    AtomicBatchOp::DexSellAsset {
                        asset_id,
                        units,
                        min_price_bits,
                    } => {
                        if let Err(e) = stage.debit_asset(sender, asset_id, *units) {
                            return Ok((reject(ledger, *batch_id, e), false));
                        }
                        let (sold, proceeds) =
                            match stage.sell_into_bids(asset_id, *units, *min_price_bits) {
                                Ok(v) => v,
                                Err(e) => return Ok((reject(ledger, *batch_id, e), false)),
                            };
                        if sold < *units {
                            return Ok((
                                reject(
                                    ledger,
                                    *batch_id,
                                    "reverted: insufficient DEX Bid liquidity for exact batch sell",
                                ),
                                false,
                            ));
                        }
                        let _ = stage.credit_xcr(sender, Amount::from_bits(proceeds));
                    }
                }
            }

            let final_bal = stage.pocket_bal(sender).unwrap_or(Amount::ZERO);
            let net_debit = initial_bal.checked_sub(final_bal).unwrap_or(Amount::ZERO);
            if net_debit > *max_xcr_debit {
                return Ok((
                    reject(
                        ledger,
                        *batch_id,
                        "reverted by Post-Condition Guard: net XCR debit exceeded max_xcr_debit",
                    ),
                    false,
                ));
            }

            let fs = FeeSplit::compute(*fee);
            *unsettled_fee_bits = unsettled_fee_bits.saturating_add(fs.worker_reward.bits() as i64);
            let op_len = ops.len();
            let (order_updates, asset_updates, pocket_updates) = stage.into_deltas();
            ledger.append_nosync(WalRecord::UpsertLaneOrBatch {
                tx_id: *batch_id,
                lane_update: None,
                order_updates,
                asset_updates,
                pocket_updates,
                fee_burned: fs.burned,
            })?;
            ledger.flush_wal()?;
            Ok((
                NodeRpcResponse::ContractReceipt {
                    accepted: true,
                    contract_id: *batch_id,
                    amount: net_debit,
                    new_state_root: ledger.state_merkle_root(),
                    message: format!(
                        "composable AtomicBatch settled all {op_len} ops atomically (net debit {})",
                        net_debit.format_symbolic()
                    ),
                },
                true,
            ))
        }

        NodeRpcRequest::MintOrTransferArtifact {
            is_transfer,
            tx_id,
            artifact_id,
            actor,
            actor_pubkey,
            recipient,
            collection,
            title,
            content_hash,
            fee,
            salt,
            sig65,
        } => {
            if ledger.spent_nullifiers.contains(tx_id) {
                return Ok((
                    NodeRpcResponse::ContractReceipt {
                        accepted: true,
                        contract_id: *artifact_id,
                        amount: Amount::ZERO,
                        new_state_root: ledger.state_merkle_root(),
                        message: "artifact op already finalized".to_owned(),
                    },
                    false,
                ));
            }
            if *fee < min_fee || !ledger.pockets.contains_key(recipient) {
                return Ok((reject(ledger, *tx_id, "invalid fee or recipient"), false));
            }
            let Some(cur_bal) = ledger.pockets.get(actor).map(|p| p.state.balance) else {
                return Ok((reject(ledger, *tx_id, "actor Pocket not found"), false));
            };
            let Some(new_bal) = cur_bal.checked_sub(*fee) else {
                return Ok((reject(ledger, *tx_id, "insufficient fee balance"), false));
            };

            let stored_art = if !*is_transfer {
                if ledger.artifacts.contains_key(artifact_id) {
                    return Ok((
                        reject(ledger, *artifact_id, "artifact already minted"),
                        false,
                    ));
                }
                let expected = artifact_mint_digest(
                    actor,
                    recipient,
                    collection,
                    title,
                    content_hash,
                    *fee,
                    salt,
                );
                if expected != *artifact_id
                    || *tx_id != *artifact_id
                    || collection.is_empty()
                    || title.is_empty()
                    || !verify_artifact_or_attest_sig(actor_pubkey, actor, artifact_id, sig65)
                {
                    return Ok((reject(ledger, *artifact_id, "invalid artifact mint"), false));
                }
                StoredBearerArtifact {
                    artifact_id: *artifact_id,
                    issuer: *actor,
                    owner: *recipient,
                    collection: collection.clone(),
                    title: title.clone(),
                    content_hash: *content_hash,
                }
            } else {
                let Some(mut cur_art) = ledger.artifacts.get(artifact_id).cloned() else {
                    return Ok((reject(ledger, *artifact_id, "artifact not found"), false));
                };
                let expected = artifact_transfer_digest(artifact_id, actor, recipient, *fee, salt);
                if cur_art.owner != *actor
                    || expected != *tx_id
                    || !verify_artifact_or_attest_sig(actor_pubkey, actor, tx_id, sig65)
                {
                    return Ok((reject(ledger, *tx_id, "invalid artifact transfer"), false));
                }
                cur_art.owner = *recipient;
                cur_art
            };

            let fs = FeeSplit::compute(*fee);
            *unsettled_fee_bits = unsettled_fee_bits.saturating_add(fs.worker_reward.bits() as i64);
            let art_title = stored_art.title.clone();
            ledger.append_nosync(WalRecord::UpsertArtifactOrAttest {
                tx_id: *tx_id,
                artifact: Some(stored_art),
                attestation: None,
                pocket_updates: vec![(*actor, new_bal)],
                fee_burned: fs.burned,
            })?;
            ledger.flush_wal()?;
            Ok((
                NodeRpcResponse::ContractReceipt {
                    accepted: true,
                    contract_id: *artifact_id,
                    amount: Amount::ZERO,
                    new_state_root: ledger.state_merkle_root(),
                    message: format!(
                        "1-of-1 bearer artifact `{art_title}` owned by {}",
                        recipient.short_hex()
                    ),
                },
                true,
            ))
        }

        NodeRpcRequest::IssueOrRevokeAttestation {
            is_revoke,
            tx_id,
            attestation_id,
            attester,
            attester_pubkey,
            subject,
            schema,
            claim_commitment,
            expiry_unix,
            fee,
            salt,
            sig65,
        } => {
            if ledger.spent_nullifiers.contains(tx_id) {
                return Ok((
                    NodeRpcResponse::ContractReceipt {
                        accepted: true,
                        contract_id: *attestation_id,
                        amount: Amount::ZERO,
                        new_state_root: ledger.state_merkle_root(),
                        message: "attestation op already finalized".to_owned(),
                    },
                    false,
                ));
            }
            if *is_revoke {
                let Some(mut cur_att) = ledger.attestations.get(attestation_id).cloned() else {
                    return Ok((
                        reject(ledger, *attestation_id, "attestation not found"),
                        false,
                    ));
                };
                if cur_att.revoked {
                    return Ok((
                        NodeRpcResponse::ContractReceipt {
                            accepted: true,
                            contract_id: *attestation_id,
                            amount: Amount::ZERO,
                            new_state_root: ledger.state_merkle_root(),
                            message: "attestation already revoked".to_owned(),
                        },
                        false,
                    ));
                }
                let expected = attestation_revoke_digest(attester, attestation_id);
                if cur_att.attester != *attester
                    || expected != *tx_id
                    || !verify_artifact_or_attest_sig(attester_pubkey, attester, tx_id, sig65)
                {
                    return Ok((
                        reject(ledger, *attestation_id, "invalid attestation revoke sig"),
                        false,
                    ));
                }
                cur_att.revoked = true;
                ledger.append_nosync(WalRecord::UpsertArtifactOrAttest {
                    tx_id: *tx_id,
                    artifact: None,
                    attestation: Some(cur_att),
                    pocket_updates: Vec::new(),
                    fee_burned: Amount::ZERO,
                })?;
                ledger.flush_wal()?;
                return Ok((
                    NodeRpcResponse::ContractReceipt {
                        accepted: true,
                        contract_id: *attestation_id,
                        amount: Amount::ZERO,
                        new_state_root: ledger.state_merkle_root(),
                        message: "zero-PII attestation revoked in 1-RTT".to_owned(),
                    },
                    true,
                ));
            }

            let expected = attestation_issue_digest(
                attester,
                subject,
                schema,
                claim_commitment,
                *expiry_unix,
                *fee,
                salt,
            );
            if ledger.attestations.contains_key(attestation_id)
                || expected != *attestation_id
                || *tx_id != *attestation_id
                || schema.is_empty()
                || *fee < min_fee
                || !verify_artifact_or_attest_sig(attester_pubkey, attester, attestation_id, sig65)
            {
                return Ok((
                    reject(ledger, *attestation_id, "invalid attestation issue"),
                    false,
                ));
            }
            let Some(cur_bal) = ledger.pockets.get(attester).map(|p| p.state.balance) else {
                return Ok((
                    reject(ledger, *attestation_id, "attester Pocket not found"),
                    false,
                ));
            };
            let Some(new_bal) = cur_bal.checked_sub(*fee) else {
                return Ok((reject(ledger, *attestation_id, "insufficient fee"), false));
            };
            let fs = FeeSplit::compute(*fee);
            *unsettled_fee_bits = unsettled_fee_bits.saturating_add(fs.worker_reward.bits() as i64);
            ledger.append_nosync(WalRecord::UpsertArtifactOrAttest {
                tx_id: *tx_id,
                artifact: None,
                attestation: Some(StoredAttestation {
                    attestation_id: *attestation_id,
                    attester: *attester,
                    subject: *subject,
                    schema: schema.clone(),
                    claim_commitment: *claim_commitment,
                    expiry_unix: *expiry_unix,
                    revoked: false,
                }),
                pocket_updates: vec![(*attester, new_bal)],
                fee_burned: fs.burned,
            })?;
            ledger.flush_wal()?;
            Ok((
                NodeRpcResponse::ContractReceipt {
                    accepted: true,
                    contract_id: *attestation_id,
                    amount: Amount::ZERO,
                    new_state_root: ledger.state_merkle_root(),
                    message: format!(
                        "issued zero-PII EAS attestation `{schema}` for {}",
                        subject.short_hex()
                    ),
                },
                true,
            ))
        }

        NodeRpcRequest::GovernanceAction {
            kind,
            tx_id,
            actor,
            actor_pubkey,
            target_id,
            title,
            param_key,
            param_value,
            deadline_unix,
            choice,
            salt,
            sig65,
        } => {
            if ledger.spent_nullifiers.contains(tx_id) {
                return Ok((
                    NodeRpcResponse::ContractReceipt {
                        accepted: true,
                        contract_id: *tx_id,
                        amount: Amount::ZERO,
                        new_state_root: ledger.state_merkle_root(),
                        message: "governance action already recorded".to_owned(),
                    },
                    false,
                ));
            }
            if !ledger.pockets.contains_key(actor) {
                return Ok((reject(ledger, *tx_id, "actor Pocket not found"), false));
            }
            match *kind {
                0 => {
                    if let Err(unconst) = validate_constitutional_parameter(param_key, *param_value)
                    {
                        return Ok((reject(ledger, *tx_id, unconst), false));
                    }
                    let expected = proposal_create_digest(
                        actor,
                        title,
                        param_key,
                        *param_value,
                        *deadline_unix,
                        salt,
                    );
                    if expected != *tx_id
                        || title.is_empty()
                        || !verify_gov_or_shield_sig(actor_pubkey, actor, tx_id, sig65)
                    {
                        return Ok((reject(ledger, *tx_id, "invalid proposal signature"), false));
                    }
                    let cur_bal = ledger.pockets[actor].state.balance;
                    let Some(new_bal) = cur_bal.checked_sub(min_fee) else {
                        return Ok((reject(ledger, *tx_id, "insufficient fee balance"), false));
                    };
                    let fs = FeeSplit::compute(min_fee);
                    *unsettled_fee_bits =
                        unsettled_fee_bits.saturating_add(fs.worker_reward.bits() as i64);
                    ledger.append_nosync(WalRecord::UpsertGovOrShield {
                        tx_id: *tx_id,
                        proposal: Some(StoredGovProposal {
                            proposal_id: *tx_id,
                            proposer: *actor,
                            title: title.clone(),
                            param_key: param_key.clone(),
                            param_value: *param_value,
                            deadline_unix: *deadline_unix,
                            votes: Vec::new(),
                        }),
                        drep_update: None,
                        shield: None,
                        pocket_updates: vec![(*actor, new_bal)],
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
                                "constitutional proposal `{title}` ({param_key}={param_value}) opened"
                            ),
                        },
                        true,
                    ))
                }
                1 => {
                    let drep = Address::from_bytes(target_id.0);
                    let expected = drep_delegate_digest(actor, &drep, salt);
                    if expected != *tx_id
                        || !verify_gov_or_shield_sig(actor_pubkey, actor, tx_id, sig65)
                    {
                        return Ok((reject(ledger, *tx_id, "invalid DRep delegate sig"), false));
                    }
                    ledger.append_nosync(WalRecord::UpsertGovOrShield {
                        tx_id: *tx_id,
                        proposal: None,
                        drep_update: Some((*actor, drep)),
                        shield: None,
                        pocket_updates: Vec::new(),
                        fee_burned: Amount::ZERO,
                    })?;
                    ledger.flush_wal()?;
                    Ok((
                        NodeRpcResponse::ContractReceipt {
                            accepted: true,
                            contract_id: *tx_id,
                            amount: ledger.pockets[actor].state.balance,
                            new_state_root: ledger.state_merkle_root(),
                            message: format!(
                                "liquid DRep voting power delegated to {} (0 XCR locked)",
                                drep.short_hex()
                            ),
                        },
                        true,
                    ))
                }
                2 => {
                    let Some(mut prop) = ledger.gov_proposals.get(target_id).cloned() else {
                        return Ok((reject(ledger, *target_id, "proposal not found"), false));
                    };
                    let expected = governance_vote_digest(target_id, actor, *choice);
                    if *choice > 2
                        || expected != *tx_id
                        || !verify_gov_or_shield_sig(actor_pubkey, actor, tx_id, sig65)
                    {
                        return Ok((reject(ledger, *tx_id, "invalid governance vote sig"), false));
                    }
                    if let Some(slot) = prop.votes.iter_mut().find(|(v, _)| v == actor) {
                        slot.1 = *choice;
                    } else {
                        prop.votes.push((*actor, *choice));
                    }
                    ledger.append_nosync(WalRecord::UpsertGovOrShield {
                        tx_id: *tx_id,
                        proposal: Some(prop),
                        drep_update: None,
                        shield: None,
                        pocket_updates: Vec::new(),
                        fee_burned: Amount::ZERO,
                    })?;
                    ledger.flush_wal()?;
                    let label = match *choice {
                        1 => "YES",
                        0 => "NO",
                        _ => "ABSTAIN",
                    };
                    Ok((
                        NodeRpcResponse::ContractReceipt {
                            accepted: true,
                            contract_id: *target_id,
                            amount: ledger.pockets[actor].state.balance,
                            new_state_root: ledger.state_merkle_root(),
                            message: format!("recorded `{label}` vote on proposal"),
                        },
                        true,
                    ))
                }
                _ => Ok((reject(ledger, *tx_id, "unknown governance kind"), false)),
            }
        }

        NodeRpcRequest::SetDepositShield {
            tx_id,
            owner,
            owner_pubkey,
            min_deposit,
            strict_allowlist_only,
            allowlist,
            salt,
            sig65,
        } => {
            if ledger.spent_nullifiers.contains(tx_id) {
                return Ok((
                    NodeRpcResponse::ContractReceipt {
                        accepted: true,
                        contract_id: *tx_id,
                        amount: *min_deposit,
                        new_state_root: ledger.state_merkle_root(),
                        message: "DepositShield already configured".to_owned(),
                    },
                    false,
                ));
            }
            let expected =
                deposit_shield_digest(owner, *min_deposit, *strict_allowlist_only, allowlist, salt);
            if expected != *tx_id
                || allowlist.len() > 16
                || !ledger.pockets.contains_key(owner)
                || !verify_gov_or_shield_sig(owner_pubkey, owner, tx_id, sig65)
            {
                return Ok((
                    reject(ledger, *tx_id, "invalid DepositShield signature"),
                    false,
                ));
            }
            ledger.append_nosync(WalRecord::UpsertGovOrShield {
                tx_id: *tx_id,
                proposal: None,
                drep_update: None,
                shield: Some(StoredDepositShield {
                    owner: *owner,
                    min_deposit: *min_deposit,
                    strict_allowlist_only: *strict_allowlist_only,
                    allowlist: allowlist.clone(),
                }),
                pocket_updates: Vec::new(),
                fee_burned: Amount::ZERO,
            })?;
            ledger.flush_wal()?;
            Ok((
                NodeRpcResponse::ContractReceipt {
                    accepted: true,
                    contract_id: *tx_id,
                    amount: *min_deposit,
                    new_state_root: ledger.state_merkle_root(),
                    message: format!(
                        "opt-in DepositShield active (min_deposit={}, preauth={} addrs)",
                        min_deposit.format_symbolic(),
                        allowlist.len()
                    ),
                },
                true,
            ))
        }

        NodeRpcRequest::GetGovernanceSummary => {
            let distinct_dreps: BTreeSet<Address> =
                ledger.drep_delegations.values().copied().collect();
            let proposals = ledger
                .gov_proposals
                .values()
                .rev()
                .take(16)
                .map(|p| {
                    let direct_map: BTreeMap<Address, u8> = p.votes.iter().copied().collect();
                    let mut yes_bits = 0u64;
                    let mut no_bits = 0u64;
                    let mut abs_bits = 0u64;
                    for (holder, sp) in &ledger.pockets {
                        let effective_choice = direct_map.get(holder).copied().or_else(|| {
                            ledger
                                .drep_delegations
                                .get(holder)
                                .and_then(|drep| direct_map.get(drep).copied())
                        });
                        if let Some(ch) = effective_choice {
                            let w = sp.state.balance.bits();
                            match ch {
                                1 => yes_bits = yes_bits.saturating_add(w),
                                0 => no_bits = no_bits.saturating_add(w),
                                _ => abs_bits = abs_bits.saturating_add(w),
                            }
                        }
                    }
                    (
                        p.proposal_id,
                        p.title.clone(),
                        p.param_key.clone(),
                        p.param_value,
                        yes_bits,
                        no_bits,
                        abs_bits,
                        p.deadline_unix,
                    )
                })
                .collect();
            Ok((
                NodeRpcResponse::GovernanceSnapshot {
                    proposals,
                    total_dreps: distinct_dreps.len() as u32,
                },
                false,
            ))
        }

        _ => Ok((
            NodeRpcResponse::Error("unsupported contract RPC".to_owned()),
            false,
        )),
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
    use credit_crypto::{Keypair, SignatureScheme, domain_hash};
    use credit_sdk::{
        NativeAssetMint, compute_claim_commitment, sign_artifact_mint, sign_atomic_batch,
        sign_attestation_issue, sign_attestation_revoke, sign_babel_asset_transfer,
        sign_bridged_payment, sign_deposit_shield, sign_drep_delegate, sign_governance_proposal,
        sign_governance_vote, sign_handle_register, sign_parallel_lane_pay,
    };
    use credit_types::PocketState;
    use std::env;
    use std::fs;

    #[test]
    fn wave9_dex_babel_handles_lanes_atomic_artifacts_and_voltaire_end_to_end() {
        let dir = env::temp_dir().join(format!("xcr_wave9_test_{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let wal_path = dir.join("wave9.wal");

        let alice_seed = [0xA1; 32];
        let bob_seed = [0xB2; 32];
        let zero_xcr_user = [0xC3; 32];

        let akp = Keypair::from_seed(
            SignatureScheme::PasskeyP256,
            domain_hash("XCR.WALLET.POCKET_KEY.V1", &[&alice_seed]).0,
        );
        let bkp = Keypair::from_seed(
            SignatureScheme::PasskeyP256,
            domain_hash("XCR.WALLET.POCKET_KEY.V1", &[&bob_seed]).0,
        );
        let zkp = Keypair::from_seed(
            SignatureScheme::PasskeyP256,
            domain_hash("XCR.WALLET.POCKET_KEY.V1", &[&zero_xcr_user]).0,
        );

        let mut ledger = PersistentLedger::open(&wal_path).unwrap();
        ledger
            .append(WalRecord::RecordEpochSettlement {
                epoch: credit_types::EpochId(1),
                minted_emission: Amount::from_credits(100).unwrap(),
                worker_fees: Amount::ZERO,
                burned_fees: Amount::ZERO,
                payouts: Vec::new(),
            })
            .unwrap();
        for (kp, credits) in [(&akp, 50u64), (&bkp, 50u64), (&zkp, 0u64)] {
            ledger
                .append(WalRecord::UpsertPocket {
                    address: kp.address(),
                    public_key: kp.public_key(),
                    state: PocketState::new(
                        Amount::from_credits(credits).unwrap(),
                        Amount::from_credits(100).unwrap(),
                    ),
                })
                .unwrap();
        }

        let mut swap_offers = BTreeMap::new();
        let mut unsettled_fees = 0i64;
        let fee = Amount::from_bits(MIN_BASE_FEE_BITS);
        let initial_accounted = ledger.total_live_accounted_bits();

        // 1. Mint Native Asset `GOLD` (Alice) and `SILVER` (Bob), post DEX Bids/Asks, & run Babel Fee + Bridged Pay:
        let gold =
            NativeAssetMint::sign_new(&alice_seed, "GOLD", 1_000, 0, fee, [1u8; 16]).unwrap();
        let (_, m) = crate::contracts::execute_contract_rpc(
            &NodeRpcRequest::MintNativeAsset {
                asset_id: gold.asset_id,
                issuer: gold.issuer,
                issuer_pubkey: gold.issuer_pubkey,
                ticker: gold.ticker,
                total_supply: gold.total_supply,
                decimals: gold.decimals,
                fee: gold.fee,
                salt: gold.salt,
                sig65: gold.sig65,
            },
            &mut ledger,
            &mut swap_offers,
            &mut unsettled_fees,
            false,
        )
        .unwrap();
        assert!(m);

        // Give zero-XCR user 50 GOLD so they can transact with 0.000000 XCR via Cardano Babel Fees!
        let (snd, spk, xid, xsig) = credit_sdk::sign_asset_transfer(
            &alice_seed,
            &gold.asset_id,
            &zkp.address(),
            50,
            fee,
            [2u8; 16],
        );
        let (_, m2) = crate::contracts::execute_contract_rpc(
            &NodeRpcRequest::TransferNativeAsset {
                xfer_id: xid,
                asset_id: gold.asset_id,
                sender: snd,
                sender_pubkey: spk,
                recipient: zkp.address(),
                units: 50,
                fee,
                salt: [2u8; 16],
                sig65: xsig,
            },
            &mut ledger,
            &mut swap_offers,
            &mut unsettled_fees,
            false,
        )
        .unwrap();
        assert!(m2);
        assert!(ledger.pockets[&zkp.address()].state.balance.is_zero());

        // Bob posts a resting Bid on GOLD: 100 units @ 10,000 bits (0.01 XCR) each -> escrows 1.00 XCR
        let bid = DexLimitOrder::sign_new(
            &bob_seed,
            gold.asset_id,
            false,
            100,
            10_000,
            false,
            fee,
            [3u8; 16],
        )
        .unwrap();
        let (_, m3) = execute_wave9_rpc(
            &NodeRpcRequest::PlaceDexOrder {
                order_id: bid.order_id,
                maker: bid.maker,
                maker_pubkey: bid.maker_pubkey,
                asset_id: bid.asset_id,
                is_sell_asset: false,
                asset_units: bid.asset_units,
                price_bits_per_unit: bid.price_bits_per_unit,
                immediate_or_cancel: false,
                fee: bid.fee,
                salt: bid.salt,
                sig65: bid.sig65,
            },
            &mut ledger,
            &mut unsettled_fees,
            false,
        )
        .unwrap();
        assert!(m3);

        // Zero-XCR user transfers 20 GOLD -> Alice paying 1 GOLD as Cardano Babel Fee (0 XCR in Pocket!):
        let (bsnd, bpk, bxid, bsig) = sign_babel_asset_transfer(
            &zero_xcr_user,
            &gold.asset_id,
            &akp.address(),
            20,
            1,
            [4u8; 16],
        )
        .unwrap();
        let (b_resp, m4) = execute_wave9_rpc(
            &NodeRpcRequest::BabelAssetTransfer {
                xfer_id: bxid,
                asset_id: gold.asset_id,
                sender: bsnd,
                sender_pubkey: bpk,
                recipient: akp.address(),
                units: 20,
                babel_fee_units: 1,
                salt: [4u8; 16],
                sig65: bsig,
            },
            &mut ledger,
            &mut unsettled_fees,
            false,
        )
        .unwrap();
        assert!(
            m4 && matches!(
                b_resp,
                NodeRpcResponse::ContractReceipt { accepted: true, .. }
            )
        );

        // Cross-Asset Auto-Bridged Payment: Alice spends 10 GOLD -> delivers 0.10 XCR to Zero-XCR user!
        let (payer, ppk, br_id, br_sig) = sign_bridged_payment(
            &alice_seed,
            &zkp.address(),
            &gold.asset_id,
            10,
            None,
            100_000,
            fee,
            [5u8; 16],
        )
        .unwrap();
        let (_, m5) = execute_wave9_rpc(
            &NodeRpcRequest::BridgedAssetPayment {
                tx_id: br_id,
                payer,
                payer_pubkey: ppk,
                recipient: zkp.address(),
                in_asset_id: gold.asset_id,
                max_in_units: 10,
                out_asset_id: None,
                min_out_amount_or_units: 100_000,
                fee,
                salt: [5u8; 16],
                sig65: br_sig,
            },
            &mut ledger,
            &mut unsettled_fees,
            false,
        )
        .unwrap();
        assert!(m5);

        // 2. Register @alice.xcr on-chain handle:
        let (hname, howner, hpk, hfee, htx, hsig) =
            sign_handle_register(&alice_seed, "@Alice.xcr", "xcrstealth1_test").unwrap();
        let (_, m6) = execute_wave9_rpc(
            &NodeRpcRequest::RegisterOrTransferHandle {
                is_transfer: false,
                tx_id: htx,
                normalized_name: hname,
                actor: howner,
                actor_pubkey: hpk,
                target_owner: howner,
                stealth_uri: "xcrstealth1_test".to_owned(),
                fee: hfee,
                salt: [0u8; 16],
                sig65: hsig,
            },
            &mut ledger,
            &mut unsettled_fees,
            false,
        )
        .unwrap();
        assert!(m6 && ledger.handles.contains_key("alice"));

        // 3. Parallel 2D Nonce Lanes (#7 & #3 concurrently) + AtomicBatch + Post-Condition revert test:
        for lane in [7u32, 3u32] {
            let (ls, lpk, ltx, lsig) = sign_parallel_lane_pay(
                &alice_seed,
                &bkp.address(),
                lane,
                0,
                Amount::from_chips(50).unwrap(),
                fee,
            )
            .unwrap();
            let (_, ml) = execute_wave9_rpc(
                &NodeRpcRequest::ParallelLanePay {
                    tx_id: ltx,
                    sender: ls,
                    sender_pubkey: lpk,
                    recipient: bkp.address(),
                    lane_id: lane,
                    lane_seq: 0,
                    amount: Amount::from_chips(50).unwrap(),
                    fee,
                    sig65: lsig,
                },
                &mut ledger,
                &mut unsettled_fees,
                false,
            )
            .unwrap();
            assert!(ml);
        }

        // Post-Condition Guard MUST revert if max_xcr_debit < actual debit!
        let ops = vec![
            AtomicBatchOp::TransferXcr {
                to: bkp.address(),
                amount: Amount::from_credits(2).unwrap(),
            },
            AtomicBatchOp::TransferAsset {
                asset_id: gold.asset_id,
                to: bkp.address(),
                units: 5,
            },
        ];
        let (bs, b_pk, ops_raw, bad_bid, bad_sig) = sign_atomic_batch(
            &alice_seed,
            &ops,
            Amount::from_credits(1).unwrap(),
            fee,
            [6u8; 16],
        )
        .unwrap();
        let (rev_resp, rev_mut) = execute_wave9_rpc(
            &NodeRpcRequest::ExecuteAtomicBatch {
                batch_id: bad_bid,
                sender: bs,
                sender_pubkey: b_pk,
                ops_bytes: ops_raw,
                max_xcr_debit: Amount::from_credits(1).unwrap(),
                fee,
                salt: [6u8; 16],
                sig65: bad_sig,
            },
            &mut ledger,
            &mut unsettled_fees,
            false,
        )
        .unwrap();
        assert!(!rev_mut);
        assert!(matches!(
            rev_resp,
            NodeRpcResponse::ContractReceipt {
                accepted: false,
                ..
            }
        ));

        // Valid Post-Condition Guard commits all ops atomically:
        let (bs2, b_pk2, ops_raw2, ok_bid, ok_sig) = sign_atomic_batch(
            &alice_seed,
            &ops,
            Amount::from_credits(3).unwrap(),
            fee,
            [7u8; 16],
        )
        .unwrap();
        let (_, ok_mut) = execute_wave9_rpc(
            &NodeRpcRequest::ExecuteAtomicBatch {
                batch_id: ok_bid,
                sender: bs2,
                sender_pubkey: b_pk2,
                ops_bytes: ops_raw2,
                max_xcr_debit: Amount::from_credits(3).unwrap(),
                fee,
                salt: [7u8; 16],
                sig65: ok_sig,
            },
            &mut ledger,
            &mut unsettled_fees,
            false,
        )
        .unwrap();
        assert!(ok_mut);

        // 4. 1-of-1 BearerArtifact + Zero-PII Attestation + 1-RTT Revoke:
        let chash = domain_hash("DEED", &[b"Hardware Credchip #0001"]);
        let (ais, apk, art_id, asig) = sign_artifact_mint(
            &alice_seed,
            &bkp.address(),
            "CREDCHIP-GEN1",
            "Unit #0001",
            chash,
            fee,
            [8u8; 16],
        )
        .unwrap();
        let (_, ma) = execute_wave9_rpc(
            &NodeRpcRequest::MintOrTransferArtifact {
                is_transfer: false,
                tx_id: art_id,
                artifact_id: art_id,
                actor: ais,
                actor_pubkey: apk,
                recipient: bkp.address(),
                collection: "CREDCHIP-GEN1".to_owned(),
                title: "Unit #0001".to_owned(),
                content_hash: chash,
                fee,
                salt: [8u8; 16],
                sig65: asig,
            },
            &mut ledger,
            &mut unsettled_fees,
            false,
        )
        .unwrap();
        assert!(ma);

        let comm = compute_claim_commitment("AML-CLEAN-2027", &[9u8; 16]);
        let (att, att_pk, att_id, att_sig) = sign_attestation_issue(
            &alice_seed,
            &bkp.address(),
            "ISO-CLEAN-V1",
            comm,
            1_900_000_000,
            fee,
            [9u8; 16],
        )
        .unwrap();
        let (_, matt) = execute_wave9_rpc(
            &NodeRpcRequest::IssueOrRevokeAttestation {
                is_revoke: false,
                tx_id: att_id,
                attestation_id: att_id,
                attester: att,
                attester_pubkey: att_pk,
                subject: bkp.address(),
                schema: "ISO-CLEAN-V1".to_owned(),
                claim_commitment: comm,
                expiry_unix: 1_900_000_000,
                fee,
                salt: [9u8; 16],
                sig65: att_sig,
            },
            &mut ledger,
            &mut unsettled_fees,
            false,
        )
        .unwrap();
        assert!(matt);
        let (ratt, rpk, rtx, rsig) = sign_attestation_revoke(&alice_seed, &att_id);
        let (_, mrev) = execute_wave9_rpc(
            &NodeRpcRequest::IssueOrRevokeAttestation {
                is_revoke: true,
                tx_id: rtx,
                attestation_id: att_id,
                attester: ratt,
                attester_pubkey: rpk,
                subject: Address::default(),
                schema: String::new(),
                claim_commitment: Hash32::ZERO,
                expiry_unix: 0,
                fee: Amount::ZERO,
                salt: [0u8; 16],
                sig65: rsig,
            },
            &mut ledger,
            &mut unsettled_fees,
            false,
        )
        .unwrap();
        assert!(mrev && ledger.attestations[&att_id].revoked);

        // 5. Voltaire Constitutional DRep Delegation + Proposal + Vote + DepositShield Anti-Dust:
        let (del, del_pk, dtx, dsig) = sign_drep_delegate(&bob_seed, &akp.address(), [10u8; 16]);
        let (_, mdel) = execute_wave9_rpc(
            &NodeRpcRequest::GovernanceAction {
                kind: 1,
                tx_id: dtx,
                actor: del,
                actor_pubkey: del_pk,
                target_id: Hash32(akp.address().0),
                title: String::new(),
                param_key: String::new(),
                param_value: 0,
                deadline_unix: 0,
                choice: 0,
                salt: [10u8; 16],
                sig65: dsig,
            },
            &mut ledger,
            &mut unsettled_fees,
            false,
        )
        .unwrap();
        assert!(mdel);

        let (pr, pr_pk, pid, psig) = sign_governance_proposal(
            &alice_seed,
            "Tune Relay Floor",
            "min_relay_fee_bits",
            450,
            1_900_000_000,
            [11u8; 16],
        )
        .unwrap();
        let (_, mp) = execute_wave9_rpc(
            &NodeRpcRequest::GovernanceAction {
                kind: 0,
                tx_id: pid,
                actor: pr,
                actor_pubkey: pr_pk,
                target_id: Hash32::ZERO,
                title: "Tune Relay Floor".to_owned(),
                param_key: "min_relay_fee_bits".to_owned(),
                param_value: 450,
                deadline_unix: 1_900_000_000,
                choice: 0,
                salt: [11u8; 16],
                sig65: psig,
            },
            &mut ledger,
            &mut unsettled_fees,
            false,
        )
        .unwrap();
        assert!(mp);

        let (vt, vpk, vid, vsig) = sign_governance_vote(&alice_seed, &pid, 1).unwrap();
        let (_, mv) = execute_wave9_rpc(
            &NodeRpcRequest::GovernanceAction {
                kind: 2,
                tx_id: vid,
                actor: vt,
                actor_pubkey: vpk,
                target_id: pid,
                title: String::new(),
                param_key: String::new(),
                param_value: 0,
                deadline_unix: 0,
                choice: 1,
                salt: [0u8; 16],
                sig65: vsig,
            },
            &mut ledger,
            &mut unsettled_fees,
            false,
        )
        .unwrap();
        assert!(mv);

        // Set DepositShield on Bob (min_deposit = 1.00 XCR) and confirm 0.01 XCR dust is blocked!
        let (so, spk2, stx, ssig) = sign_deposit_shield(
            &bob_seed,
            Amount::from_credits(1).unwrap(),
            false,
            &[],
            [12u8; 16],
        )
        .unwrap();
        let (_, msh) = execute_wave9_rpc(
            &NodeRpcRequest::SetDepositShield {
                tx_id: stx,
                owner: so,
                owner_pubkey: spk2,
                min_deposit: Amount::from_credits(1).unwrap(),
                strict_allowlist_only: false,
                allowlist: Vec::new(),
                salt: [12u8; 16],
                sig65: ssig,
            },
            &mut ledger,
            &mut unsettled_fees,
            false,
        )
        .unwrap();
        assert!(msh);
        assert!(
            ledger
                .check_deposit_shield_allowed(
                    &akp.address(),
                    &bkp.address(),
                    Amount::from_chips(1).unwrap()
                )
                .is_err()
        );

        // Verify exact mathematical XCR supply conservation across ALL Wave-9 contracts
        // (70% worker + 15% SecurityEndurancePool + 15% burned across 11 base-fee txs + 1 handle reg):
        let endurance_bits = 11 * (FeeSplit::compute(fee).endurance_deposit.bits() as u128)
            + (FeeSplit::compute(hfee).endurance_deposit.bits() as u128);
        let final_accounted = ledger.total_live_accounted_bits();
        assert_eq!(
            initial_accounted,
            final_accounted
                + (ledger.total_burned.bits() as u128)
                + (unsettled_fees as u128)
                + endurance_bits
        );

        // Verify crash-safe WAL replay reproduces identical state_merkle_root()!
        let root_before = ledger.state_merkle_root();
        drop(ledger);
        let reopened = PersistentLedger::open(&wal_path).unwrap();
        assert_eq!(reopened.state_merkle_root(), root_before);
        let _ = fs::remove_dir_all(&dir);
    }
}
