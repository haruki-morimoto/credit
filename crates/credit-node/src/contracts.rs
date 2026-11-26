//! Layer-1 **Zero-Custody Programmable Settlement Contracts** (`HTLC`, `PayChan`, `Check`, `SwapOffer`).
//!
//! Executes identical deterministic verification across both distributed P2P validator meshes
//! (`mesh_node` + `P2pMessage::GossipContractRpc`) and local WAL daemons (`daemon`), without
//! mutating `PocketState::nonce` (so 1-RTT `FastTransfer` nonces never stall on pending contracts).

use std::collections::BTreeMap;
use std::io;
use std::time::{SystemTime, UNIX_EPOCH};

use credit_crypto::Signature;
use credit_net::{NodeRpcRequest, NodeRpcResponse};
use credit_sdk::{
    AtomicSwapOffer, DigitalCheck, PayChanVoucher, check_cancel_digest, check_cash_digest,
    htlc_lock_signing_digest, paychan_open_signing_digest, verify_htlc_preimage,
};
use credit_storage::{PersistentLedger, StoredHtlc, StoredPayChannel, WalRecord};
use credit_types::{Amount, FeeSplit, Hash32, MIN_BASE_FEE_BITS, PocketState};

/// Returns `(response, newly_mutated_for_gossip)`.
pub fn execute_contract_rpc(
    req: &NodeRpcRequest,
    ledger: &mut PersistentLedger,
    swap_offers: &mut BTreeMap<Hash32, Vec<u8>>,
    unsettled_fee_bits: &mut i64,
    from_p2p_gossip: bool,
) -> io::Result<(NodeRpcResponse, bool)> {
    let now_unix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let min_fee = Amount::from_bits(MIN_BASE_FEE_BITS);

    match req {
        NodeRpcRequest::LockHtlc {
            escrow_id,
            sender,
            sender_pubkey,
            recipient,
            amount,
            fee,
            hashlock,
            expiry_unix,
            salt,
            sig65,
        } => {
            if ledger.htlcs.contains_key(escrow_id) {
                return Ok((
                    NodeRpcResponse::ContractReceipt {
                        accepted: true,
                        contract_id: *escrow_id,
                        amount: *amount,
                        new_state_root: ledger.state_merkle_root(),
                        message: "HTLC already locked (idempotent)".to_owned(),
                    },
                    false,
                ));
            }
            let expected_id = htlc_lock_signing_digest(
                sender,
                recipient,
                *amount,
                *fee,
                hashlock,
                *expiry_unix,
                salt,
            );
            let sig_ok = Signature::from_bytes(sig65)
                .is_some_and(|s| sender_pubkey.verify(expected_id.as_bytes(), &s));
            if sender_pubkey.to_address() != *sender || expected_id != *escrow_id || !sig_ok {
                return Ok((
                    reject(ledger, *escrow_id, "invalid HTLC lock signature or digest"),
                    false,
                ));
            }
            if amount.is_zero() || *fee < min_fee || !from_p2p_gossip && *expiry_unix <= now_unix {
                return Ok((
                    reject(
                        ledger,
                        *escrow_id,
                        "invalid HTLC amount, fee, or past expiry",
                    ),
                    false,
                ));
            }
            if !ledger.pockets.contains_key(recipient) {
                return Ok((
                    reject(
                        ledger,
                        *escrow_id,
                        "recipient Pocket must be registered first",
                    ),
                    false,
                ));
            }
            let Some(total_debit) = amount.checked_add(*fee) else {
                return Ok((reject(ledger, *escrow_id, "HTLC amount overflow"), false));
            };
            let Some(sender_sp) = ledger.pockets.get(sender) else {
                return Ok((reject(ledger, *escrow_id, "sender Pocket not found"), false));
            };
            let Some(new_sender_bal) = sender_sp.state.balance.checked_sub(total_debit) else {
                return Ok((
                    reject(ledger, *escrow_id, "insufficient Pocket balance for HTLC"),
                    false,
                ));
            };
            let fs = FeeSplit::compute(*fee);
            *unsettled_fee_bits = unsettled_fee_bits.saturating_add(fs.worker_reward.bits() as i64);
            let htlc = StoredHtlc {
                escrow_id: *escrow_id,
                sender: *sender,
                recipient: *recipient,
                amount: *amount,
                hashlock: *hashlock,
                expiry_unix: *expiry_unix,
                status: 0,
                revealed_preimage: None,
            };
            ledger.append_nosync(WalRecord::UpsertHtlc {
                htlc,
                pocket_updates: vec![(*sender, new_sender_bal)],
                fee_burned: fs.burned,
            })?;
            ledger.flush_wal()?;
            Ok((
                NodeRpcResponse::ContractReceipt {
                    accepted: true,
                    contract_id: *escrow_id,
                    amount: *amount,
                    new_state_root: ledger.state_merkle_root(),
                    message: "HTLC conditional escrow locked on-chain".to_owned(),
                },
                true,
            ))
        }

        NodeRpcRequest::ClaimHtlc {
            escrow_id,
            preimage,
        } => {
            let Some(existing) = ledger.htlcs.get(escrow_id).cloned() else {
                return Ok((
                    reject(ledger, *escrow_id, "HTLC escrow_id not found"),
                    false,
                ));
            };
            if existing.status == 1 {
                return Ok((
                    NodeRpcResponse::ContractReceipt {
                        accepted: true,
                        contract_id: *escrow_id,
                        amount: existing.amount,
                        new_state_root: ledger.state_merkle_root(),
                        message: "HTLC already claimed".to_owned(),
                    },
                    false,
                ));
            }
            if existing.status != 0 || !verify_htlc_preimage(preimage, &existing.hashlock) {
                return Ok((
                    reject(
                        ledger,
                        *escrow_id,
                        "HTLC not open or SHA-256 preimage mismatch",
                    ),
                    false,
                ));
            }
            let Some(rcv_sp) = ledger.pockets.get(&existing.recipient) else {
                return Ok((
                    reject(ledger, *escrow_id, "recipient Pocket missing"),
                    false,
                ));
            };
            let new_rcv_bal = rcv_sp.state.balance.saturating_add(existing.amount);
            let mut updated = existing.clone();
            updated.status = 1;
            updated.revealed_preimage = Some(*preimage);
            ledger.append_nosync(WalRecord::UpsertHtlc {
                htlc: updated,
                pocket_updates: vec![(existing.recipient, new_rcv_bal)],
                fee_burned: Amount::ZERO,
            })?;
            ledger.flush_wal()?;
            Ok((
                NodeRpcResponse::ContractReceipt {
                    accepted: true,
                    contract_id: *escrow_id,
                    amount: existing.amount,
                    new_state_root: ledger.state_merkle_root(),
                    message: "HTLC claimed via SHA-256 preimage (atomic swap preimage revealed)"
                        .to_owned(),
                },
                true,
            ))
        }

        NodeRpcRequest::RefundHtlc { escrow_id } => {
            let Some(existing) = ledger.htlcs.get(escrow_id).cloned() else {
                return Ok((
                    reject(ledger, *escrow_id, "HTLC escrow_id not found"),
                    false,
                ));
            };
            if existing.status == 2 {
                return Ok((
                    NodeRpcResponse::ContractReceipt {
                        accepted: true,
                        contract_id: *escrow_id,
                        amount: existing.amount,
                        new_state_root: ledger.state_merkle_root(),
                        message: "HTLC already refunded".to_owned(),
                    },
                    false,
                ));
            }
            if existing.status != 0 || (!from_p2p_gossip && now_unix < existing.expiry_unix) {
                return Ok((
                    reject(
                        ledger,
                        *escrow_id,
                        "HTLC not open or timelock has not expired yet",
                    ),
                    false,
                ));
            }
            let Some(snd_sp) = ledger.pockets.get(&existing.sender) else {
                return Ok((reject(ledger, *escrow_id, "sender Pocket missing"), false));
            };
            let new_snd_bal = snd_sp.state.balance.saturating_add(existing.amount);
            let mut updated = existing.clone();
            updated.status = 2;
            ledger.append_nosync(WalRecord::UpsertHtlc {
                htlc: updated,
                pocket_updates: vec![(existing.sender, new_snd_bal)],
                fee_burned: Amount::ZERO,
            })?;
            ledger.flush_wal()?;
            Ok((
                NodeRpcResponse::ContractReceipt {
                    accepted: true,
                    contract_id: *escrow_id,
                    amount: existing.amount,
                    new_state_root: ledger.state_merkle_root(),
                    message: "expired HTLC refunded 100% to sender Pocket".to_owned(),
                },
                true,
            ))
        }

        NodeRpcRequest::GetHtlcs => {
            let escrows = ledger
                .htlcs
                .values()
                .rev()
                .take(32)
                .map(|h| {
                    (
                        h.escrow_id,
                        h.sender,
                        h.recipient,
                        h.amount,
                        h.hashlock,
                        h.expiry_unix,
                        h.status,
                        h.revealed_preimage,
                    )
                })
                .collect();
            Ok((NodeRpcResponse::HtlcList { escrows }, false))
        }

        NodeRpcRequest::OpenPayChannel {
            channel_id,
            payer,
            payer_pubkey,
            payee,
            deposit,
            fee,
            expiry_unix,
            salt,
            sig65,
        } => {
            if ledger.pay_channels.contains_key(channel_id) {
                return Ok((
                    NodeRpcResponse::ContractReceipt {
                        accepted: true,
                        contract_id: *channel_id,
                        amount: *deposit,
                        new_state_root: ledger.state_merkle_root(),
                        message: "PayChan already open".to_owned(),
                    },
                    false,
                ));
            }
            let expected_id =
                paychan_open_signing_digest(payer, payee, *deposit, *fee, *expiry_unix, salt);
            let sig_ok = Signature::from_bytes(sig65)
                .is_some_and(|s| payer_pubkey.verify(expected_id.as_bytes(), &s));
            if payer_pubkey.to_address() != *payer
                || expected_id != *channel_id
                || !sig_ok
                || deposit.is_zero()
                || *fee < min_fee
            {
                return Ok((
                    reject(
                        ledger,
                        *channel_id,
                        "invalid PayChan open signature or params",
                    ),
                    false,
                ));
            }
            if !ledger.pockets.contains_key(payee) {
                return Ok((
                    reject(ledger, *channel_id, "payee Pocket must be registered first"),
                    false,
                ));
            }
            let Some(total_debit) = deposit.checked_add(*fee) else {
                return Ok((
                    reject(ledger, *channel_id, "PayChan deposit overflow"),
                    false,
                ));
            };
            let Some(payer_sp) = ledger.pockets.get(payer) else {
                return Ok((reject(ledger, *channel_id, "payer Pocket not found"), false));
            };
            let Some(new_payer_bal) = payer_sp.state.balance.checked_sub(total_debit) else {
                return Ok((
                    reject(
                        ledger,
                        *channel_id,
                        "insufficient Pocket balance for PayChan",
                    ),
                    false,
                ));
            };
            let fs = FeeSplit::compute(*fee);
            *unsettled_fee_bits = unsettled_fee_bits.saturating_add(fs.worker_reward.bits() as i64);
            let channel = StoredPayChannel {
                channel_id: *channel_id,
                payer: *payer,
                payer_pubkey: *payer_pubkey,
                payee: *payee,
                deposit: *deposit,
                expiry_unix: *expiry_unix,
                closed: false,
                settled_amount: Amount::ZERO,
            };
            ledger.append_nosync(WalRecord::UpsertPayChan {
                channel,
                pocket_updates: vec![(*payer, new_payer_bal)],
                fee_burned: fs.burned,
            })?;
            ledger.flush_wal()?;
            Ok((
                NodeRpcResponse::ContractReceipt {
                    accepted: true,
                    contract_id: *channel_id,
                    amount: *deposit,
                    new_state_root: ledger.state_merkle_root(),
                    message: "streaming PayChan opened on-chain".to_owned(),
                },
                true,
            ))
        }

        NodeRpcRequest::ClosePayChannel {
            channel_id,
            cumulative_amount,
            voucher_sig65,
        } => {
            let Some(ch) = ledger.pay_channels.get(channel_id).cloned() else {
                return Ok((reject(ledger, *channel_id, "PayChan not found"), false));
            };
            if ch.closed {
                return Ok((
                    NodeRpcResponse::ContractReceipt {
                        accepted: true,
                        contract_id: *channel_id,
                        amount: ch.settled_amount,
                        new_state_root: ledger.state_merkle_root(),
                        message: "PayChan already closed".to_owned(),
                    },
                    false,
                ));
            }
            if *cumulative_amount > ch.deposit {
                return Ok((
                    reject(
                        ledger,
                        *channel_id,
                        "cumulative voucher exceeds channel deposit",
                    ),
                    false,
                ));
            }
            if cumulative_amount.is_zero() {
                if !from_p2p_gossip && now_unix < ch.expiry_unix {
                    return Ok((
                        reject(
                            ledger,
                            *channel_id,
                            "0-value channel close requires expiry_unix reached",
                        ),
                        false,
                    ));
                }
            } else {
                let v = PayChanVoucher {
                    channel_id: *channel_id,
                    cumulative_amount: *cumulative_amount,
                    signature_65: *voucher_sig65,
                };
                if !v.verify_signature(&ch.payer_pubkey) {
                    return Ok((
                        reject(ledger, *channel_id, "invalid PayChan voucher signature"),
                        false,
                    ));
                }
            }
            let refund = ch
                .deposit
                .checked_sub(*cumulative_amount)
                .unwrap_or(Amount::ZERO);
            let mut updates = Vec::new();
            if ch.payer == ch.payee {
                if let Some(sp) = ledger.pockets.get(&ch.payer) {
                    updates.push((ch.payer, sp.state.balance.saturating_add(ch.deposit)));
                }
            } else {
                if !cumulative_amount.is_zero()
                    && let Some(sp) = ledger.pockets.get(&ch.payee)
                {
                    updates.push((
                        ch.payee,
                        sp.state.balance.saturating_add(*cumulative_amount),
                    ));
                }
                if !refund.is_zero()
                    && let Some(sp) = ledger.pockets.get(&ch.payer)
                {
                    updates.push((ch.payer, sp.state.balance.saturating_add(refund)));
                }
            }
            let mut closed_ch = ch;
            closed_ch.closed = true;
            closed_ch.settled_amount = *cumulative_amount;
            ledger.append_nosync(WalRecord::UpsertPayChan {
                channel: closed_ch,
                pocket_updates: updates,
                fee_burned: Amount::ZERO,
            })?;
            ledger.flush_wal()?;
            Ok((
                NodeRpcResponse::ContractReceipt {
                    accepted: true,
                    contract_id: *channel_id,
                    amount: *cumulative_amount,
                    new_state_root: ledger.state_merkle_root(),
                    message: format!(
                        "PayChan settled (paid {}, auto-refunded {})",
                        cumulative_amount.format_symbolic(),
                        refund.format_symbolic()
                    ),
                },
                true,
            ))
        }

        NodeRpcRequest::GetPayChannels => {
            let channels = ledger
                .pay_channels
                .values()
                .rev()
                .take(32)
                .map(|c| {
                    (
                        c.channel_id,
                        c.payer,
                        c.payer_pubkey,
                        c.payee,
                        c.deposit,
                        c.expiry_unix,
                        c.closed,
                        c.settled_amount,
                    )
                })
                .collect();
            Ok((NodeRpcResponse::PayChannelList { channels }, false))
        }

        NodeRpcRequest::CashOrCancelCheck {
            is_cancel,
            check_bytes,
            check_id,
            actor_pubkey,
            actual_amount,
            actor_sig65,
        } => {
            if ledger.spent_nullifiers.contains(check_id) {
                return Ok((
                    NodeRpcResponse::ContractReceipt {
                        accepted: from_p2p_gossip,
                        contract_id: *check_id,
                        amount: Amount::ZERO,
                        new_state_root: ledger.state_merkle_root(),
                        message: "digital check already cashed or cancelled".to_owned(),
                    },
                    false,
                ));
            }
            let Some(chk) = DigitalCheck::from_bytes(check_bytes) else {
                return Ok((
                    reject(
                        ledger,
                        *check_id,
                        "invalid or tampered DigitalCheck signature",
                    ),
                    false,
                ));
            };
            if chk.check_id != *check_id {
                return Ok((reject(ledger, *check_id, "check_id mismatch"), false));
            }
            let Some(actor_sig) = Signature::from_bytes(actor_sig65) else {
                return Ok((
                    reject(ledger, *check_id, "malformed actor signature"),
                    false,
                ));
            };

            if *is_cancel {
                if actor_pubkey.to_address() != chk.drawer
                    || !actor_pubkey.verify(check_cancel_digest(check_id).as_bytes(), &actor_sig)
                {
                    return Ok((
                        reject(ledger, *check_id, "only check drawer can cancel check"),
                        false,
                    ));
                }
                ledger.append_nosync(WalRecord::SettleCheck {
                    check_id: *check_id,
                    pocket_updates: Vec::new(),
                    fee_burned: Amount::ZERO,
                })?;
                ledger.flush_wal()?;
                return Ok((
                    NodeRpcResponse::ContractReceipt {
                        accepted: true,
                        contract_id: *check_id,
                        amount: Amount::ZERO,
                        new_state_root: ledger.state_merkle_root(),
                        message: "digital check cancelled on-chain (0 XCR debited)".to_owned(),
                    },
                    true,
                ));
            }

            if !from_p2p_gossip && now_unix > chk.expiry_unix {
                return Ok((
                    reject(ledger, *check_id, "digital check has expired"),
                    false,
                ));
            }
            if actual_amount.is_zero()
                || *actual_amount > chk.max_amount
                || actor_pubkey.to_address() != chk.payee
                || !actor_pubkey.verify(
                    check_cash_digest(check_id, *actual_amount).as_bytes(),
                    &actor_sig,
                )
            {
                return Ok((
                    reject(
                        ledger,
                        *check_id,
                        "invalid payee signature or actual_amount exceeds check max_amount",
                    ),
                    false,
                ));
            }
            let Some(total_debit) = actual_amount.checked_add(min_fee) else {
                return Ok((reject(ledger, *check_id, "check amount overflow"), false));
            };
            let Some(drawer_cur_bal) = ledger.pockets.get(&chk.drawer).map(|sp| sp.state.balance)
            else {
                return Ok((reject(ledger, *check_id, "drawer Pocket not found"), false));
            };
            let Some(new_drawer_bal) = drawer_cur_bal.checked_sub(total_debit) else {
                return Ok((
                    reject(ledger, *check_id, "insufficient drawer Pocket balance"),
                    false,
                ));
            };
            if !ledger.pockets.contains_key(&chk.payee) {
                ledger.append_nosync(WalRecord::UpsertPocket {
                    address: chk.payee,
                    public_key: *actor_pubkey,
                    state: PocketState::new(Amount::ZERO, Amount::from_credits(25).unwrap()),
                })?;
            }
            let mut updates = Vec::new();
            if chk.drawer == chk.payee {
                let net = drawer_cur_bal.checked_sub(min_fee).unwrap_or(Amount::ZERO);
                updates.push((chk.drawer, net));
            } else {
                let payee_bal = ledger.pockets[&chk.payee]
                    .state
                    .balance
                    .saturating_add(*actual_amount);
                updates.push((chk.drawer, new_drawer_bal));
                updates.push((chk.payee, payee_bal));
            }
            let fs = FeeSplit::compute(min_fee);
            *unsettled_fee_bits = unsettled_fee_bits.saturating_add(fs.worker_reward.bits() as i64);
            ledger.append_nosync(WalRecord::SettleCheck {
                check_id: *check_id,
                pocket_updates: updates,
                fee_burned: fs.burned,
            })?;
            ledger.flush_wal()?;
            Ok((
                NodeRpcResponse::ContractReceipt {
                    accepted: true,
                    contract_id: *check_id,
                    amount: *actual_amount,
                    new_state_root: ledger.state_merkle_root(),
                    message: format!(
                        "digital check cashed for {} (authorized max {})",
                        actual_amount.format_symbolic(),
                        chk.max_amount.format_symbolic()
                    ),
                },
                true,
            ))
        }

        NodeRpcRequest::PostSwapOffer { offer_bytes } => {
            let Some(offer) = AtomicSwapOffer::from_bytes(offer_bytes) else {
                return Ok((
                    reject(ledger, Hash32::ZERO, "invalid signed AtomicSwapOffer"),
                    false,
                ));
            };
            if !from_p2p_gossip && offer.expiry_unix <= now_unix {
                return Ok((
                    reject(ledger, offer.offer_id, "swap offer expiry is in the past"),
                    false,
                ));
            }
            if swap_offers.contains_key(&offer.offer_id) {
                return Ok((
                    NodeRpcResponse::ContractReceipt {
                        accepted: true,
                        contract_id: offer.offer_id,
                        amount: offer.xcr_amount,
                        new_state_root: ledger.state_merkle_root(),
                        message: "swap offer already published".to_owned(),
                    },
                    false,
                ));
            }
            if swap_offers.len() >= 256
                && let Some(&first_key) = swap_offers.keys().next()
            {
                swap_offers.remove(&first_key);
            }
            swap_offers.insert(offer.offer_id, offer_bytes.clone());
            Ok((
                NodeRpcResponse::ContractReceipt {
                    accepted: true,
                    contract_id: offer.offer_id,
                    amount: offer.xcr_amount,
                    new_state_root: ledger.state_merkle_root(),
                    message: format!(
                        "published signed P2P atomic swap offer ({} <-> {} {})",
                        offer.xcr_amount.format_symbolic(),
                        offer.counter_amount,
                        offer.counter_asset
                    ),
                },
                true,
            ))
        }

        NodeRpcRequest::GetSwapOffers => {
            let offers: Vec<Vec<u8>> = swap_offers
                .values()
                .filter(|raw| {
                    AtomicSwapOffer::from_bytes(raw).is_some_and(|o| o.expiry_unix > now_unix)
                })
                .take(32)
                .cloned()
                .collect();
            Ok((NodeRpcResponse::SwapOfferList { offers }, false))
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
    use credit_sdk::{generate_htlc_secret, sign_check_cash, sign_htlc_lock, sign_paychan_open};
    use std::env;
    use std::fs;

    #[test]
    fn htlc_paychan_check_and_swap_offer_end_to_end_wal_persistence() {
        let dir = env::temp_dir().join("xcr_wave7_contracts_test");
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let wal_path = dir.join("test.wal");

        let alice_master = [0xA1; 32];
        let bob_master = [0xB2; 32];
        let alice_kp = Keypair::from_seed(
            SignatureScheme::PasskeyP256,
            domain_hash("XCR.WALLET.POCKET_KEY.V1", &[&alice_master]).0,
        );
        let bob_kp = Keypair::from_seed(
            SignatureScheme::PasskeyP256,
            domain_hash("XCR.WALLET.POCKET_KEY.V1", &[&bob_master]).0,
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
        ledger
            .append(WalRecord::UpsertPocket {
                address: alice_kp.address(),
                public_key: alice_kp.public_key(),
                state: PocketState::new(
                    Amount::from_credits(50).unwrap(),
                    Amount::from_credits(50).unwrap(),
                ),
            })
            .unwrap();
        ledger
            .append(WalRecord::UpsertPocket {
                address: bob_kp.address(),
                public_key: bob_kp.public_key(),
                state: PocketState::new(
                    Amount::from_credits(10).unwrap(),
                    Amount::from_credits(50).unwrap(),
                ),
            })
            .unwrap();

        let mut offers = BTreeMap::new();
        let mut fees = 0i64;
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // 1. HTLC Lock + Preimage Claim:
        let (preimage, hashlock) = generate_htlc_secret(&[0x55; 32]);
        let fee = Amount::from_bits(MIN_BASE_FEE_BITS);
        let (snd, snd_pk, eid, sig65) = sign_htlc_lock(
            &alice_master,
            &bob_kp.address(),
            Amount::from_credits(5).unwrap(),
            fee,
            &hashlock,
            now + 3600,
            [1u8; 16],
        );
        let (r1, m1) = execute_contract_rpc(
            &NodeRpcRequest::LockHtlc {
                escrow_id: eid,
                sender: snd,
                sender_pubkey: snd_pk,
                recipient: bob_kp.address(),
                amount: Amount::from_credits(5).unwrap(),
                fee,
                hashlock,
                expiry_unix: now + 3600,
                salt: [1u8; 16],
                sig65,
            },
            &mut ledger,
            &mut offers,
            &mut fees,
            false,
        )
        .unwrap();
        assert!(m1 && matches!(r1, NodeRpcResponse::ContractReceipt { accepted: true, .. }));

        let (r2, m2) = execute_contract_rpc(
            &NodeRpcRequest::ClaimHtlc {
                escrow_id: eid,
                preimage,
            },
            &mut ledger,
            &mut offers,
            &mut fees,
            false,
        )
        .unwrap();
        assert!(m2 && matches!(r2, NodeRpcResponse::ContractReceipt { accepted: true, .. }));
        assert_eq!(ledger.htlcs[&eid].revealed_preimage, Some(preimage));

        // 2. PayChan Open -> Off-Chain Tick -> Close (settles 1.25 XCR, refunds 3.75 XCR):
        let (payer, payer_pk, cid, ch_sig) = sign_paychan_open(
            &alice_master,
            &bob_kp.address(),
            Amount::from_credits(5).unwrap(),
            fee,
            now + 3600,
            [2u8; 16],
        );
        let (_, m3) = execute_contract_rpc(
            &NodeRpcRequest::OpenPayChannel {
                channel_id: cid,
                payer,
                payer_pubkey: payer_pk,
                payee: bob_kp.address(),
                deposit: Amount::from_credits(5).unwrap(),
                fee,
                expiry_unix: now + 3600,
                salt: [2u8; 16],
                sig65: ch_sig,
            },
            &mut ledger,
            &mut offers,
            &mut fees,
            false,
        )
        .unwrap();
        assert!(m3);
        let tick = PayChanVoucher::sign_tick(&alice_master, cid, Amount::from_chips(125).unwrap());
        let (_, m4) = execute_contract_rpc(
            &NodeRpcRequest::ClosePayChannel {
                channel_id: cid,
                cumulative_amount: tick.cumulative_amount,
                voucher_sig65: tick.signature_65,
            },
            &mut ledger,
            &mut offers,
            &mut fees,
            false,
        )
        .unwrap();
        assert!(m4);

        // 3. Up-To-Max Digital Check (max 10 XCR, cashed for 3.50 XCR):
        let chk = DigitalCheck::issue(
            &alice_master,
            bob_kp.address(),
            Amount::from_credits(10).unwrap(),
            now + 3600,
            [3u8; 16],
        )
        .unwrap();
        let (b_pk, b_sig) =
            sign_check_cash(&bob_master, &chk, Amount::from_chips(350).unwrap()).unwrap();
        let (_, m5) = execute_contract_rpc(
            &NodeRpcRequest::CashOrCancelCheck {
                is_cancel: false,
                check_bytes: chk.to_bytes().to_vec(),
                check_id: chk.check_id,
                actor_pubkey: b_pk,
                actual_amount: Amount::from_chips(350).unwrap(),
                actor_sig65: b_sig,
            },
            &mut ledger,
            &mut offers,
            &mut fees,
            false,
        )
        .unwrap();
        assert!(m5);

        // Verify crash-safe WAL replay reproduces identical state_merkle_root()!
        let root_before = ledger.state_merkle_root();
        drop(ledger);
        let reopened = PersistentLedger::open(&wal_path).unwrap();
        assert_eq!(reopened.state_merkle_root(), root_before);
        let _ = fs::remove_dir_all(&dir);
    }
}
