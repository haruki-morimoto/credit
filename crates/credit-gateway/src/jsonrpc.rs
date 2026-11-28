//! **Ethereum-Compatible `JSON-RPC 2.0` Developer Endpoint** (`POST /rpc` + `OPTIONS /rpc`).
//!
//! Enables Python, TypeScript, Go, and Rust integrations in 10 lines of standard HTTP JSON-RPC 2.0
//! with `Access-Control-Allow-Origin: *` CORS headers:
//! - `xcr_chainInfo` -> live epoch, supply, burned fees, active miners, and WAL state root
//! - `xcr_getBalance` -> Pocket balance, nonce, and `<256B` Merkle account proof verification
//! - `xcr_getMerkleProof` -> raw hex Merkle branch + authenticated root
//! - `xcr_supplyAudit` -> Cardano-style formal supply & contract conservation audit
//! - `xcr_getAssets` -> native bearer multi-asset registry & balances
//! - `xcr_simulateScript` -> deterministic `CredScript` pre-flight simulator (`0` fees)

use std::net::SocketAddr;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use credit_net::{NodeRpcRequest, NodeRpcResponse, rpc_call};
use credit_sdk::{CredEvalContext, CredScript, decode_witness_stack};
use credit_types::{Address, Hash32};
use credit_zk::{StateInclusionProof, StateLeaf};

use crate::json_escape;

/// Handles a raw `POST /rpc` body and returns a valid `JSON-RPC 2.0` response string.
pub fn handle_jsonrpc_post(body: &str, primary_node: SocketAddr) -> String {
    let id_val = extract_json_id(body);
    let Some(method) = extract_json_str(body, "method") else {
        return rpc_err(&id_val, -32600, "Invalid Request: missing `method`");
    };

    let timeout = Duration::from_millis(1_800);
    match method.as_str() {
        "xcr_chainInfo" => {
            match rpc_call(primary_node, &NodeRpcRequest::GetNetworkTelemetry, timeout) {
                Ok(NodeRpcResponse::NetworkTelemetry {
                    epoch,
                    circulating_supply,
                    total_burned,
                    finalized_tx_count,
                    state_root,
                    validator_address,
                    connected_peers,
                    active_miners,
                }) => rpc_ok(
                    &id_val,
                    &format!(
                        r#"{{"epoch":{},"circulating_supply":"{}","total_burned":"{}","finalized_txs":{},"active_miners":{},"connected_peers":{},"validator":"{}","state_root":"{}"}}"#,
                        epoch.0,
                        circulating_supply.format_symbolic(),
                        total_burned.format_symbolic(),
                        finalized_tx_count,
                        active_miners,
                        connected_peers,
                        validator_address,
                        state_root
                    ),
                ),
                _ => rpc_err(&id_val, -32001, "validator telemetry unavailable"),
            }
        }

        "xcr_getBalance" | "xcr_getMerkleProof" => {
            let addr_q = extract_json_str(body, "address").unwrap_or_default();
            if addr_q.len() < 6 {
                return rpc_err(&id_val, -32602, "pass `\"address\":\"xcr1_...\"`");
            }
            match rpc_call(
                primary_node,
                &NodeRpcRequest::InspectQuery { query: addr_q },
                timeout,
            ) {
                Ok(NodeRpcResponse::InspectResult {
                    kind: 1,
                    target_hex,
                    address,
                    balance,
                    nonce,
                    epoch,
                    authenticated_root,
                    inclusion_proof_bytes,
                }) => {
                    let verified = StateInclusionProof::from_bytes(&inclusion_proof_bytes)
                        .is_some_and(|br| {
                            br.verify(
                                &StateLeaf {
                                    address,
                                    balance,
                                    nonce,
                                },
                                &authenticated_root,
                            )
                        });
                    let proof_hex = hex_encode(&inclusion_proof_bytes);
                    rpc_ok(
                        &id_val,
                        &format!(
                            r#"{{"found":true,"pocket":"{}","address_hex":"{}","balance":"{}","balance_bits":{},"nonce":{},"epoch":{},"merkle_verified":{},"proof_bytes":{},"proof_hex":"{}","authenticated_root":"{}"}}"#,
                            json_escape(&target_hex),
                            Hash32(address.0),
                            balance.format_symbolic(),
                            balance.bits(),
                            nonce,
                            epoch.0,
                            verified,
                            inclusion_proof_bytes.len(),
                            proof_hex,
                            authenticated_root
                        ),
                    )
                }
                _ => rpc_ok(&id_val, r#"{"found":false}"#),
            }
        }

        "xcr_supplyAudit" => match rpc_call(
            primary_node,
            &NodeRpcRequest::GetSupplyAndContractsSummary,
            timeout,
        ) {
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
                let camp_json: Vec<String> = campaigns
                    .iter()
                    .map(|(cid, title, pl, goal, dl, st)| {
                        format!(
                            r#"{{"campaign_id":"{}","title":"{}","pledged":"{}","goal":"{}","deadline_unix":{},"status":{}}}"#,
                            cid,
                            json_escape(title),
                            pl.format_symbolic(),
                            goal.format_symbolic(),
                            dl,
                            st
                        )
                    })
                    .collect();
                rpc_ok(
                    &id_val,
                    &format!(
                        r#"{{"pockets_total":"{}","stealth_utxos_total":"{}","locked_contracts_total":"{}","circulating_supply":"{}","total_burned":"{}","delta_conservation_verified":{},"open_script_vaults":{},"campaigns":[{}]}}"#,
                        pockets_total.format_symbolic(),
                        stealth_utxos_total.format_symbolic(),
                        locked_contracts_total.format_symbolic(),
                        circulating_supply.format_symbolic(),
                        total_burned.format_symbolic(),
                        delta_conserved,
                        open_script_vaults,
                        camp_json.join(",")
                    ),
                )
            }
            _ => rpc_err(&id_val, -32002, "supply audit RPC failed"),
        },

        "xcr_getAssets" => match rpc_call(
            primary_node,
            &NodeRpcRequest::GetAssetBalances { owner: None },
            timeout,
        ) {
            Ok(NodeRpcResponse::AssetPortfolio { assets }) => {
                let items: Vec<String> = assets
                    .iter()
                    .map(|(aid, ticker, sup, dec, bal)| {
                        format!(
                            r#"{{"asset_id":"{}","ticker":"{}","total_supply":{},"decimals":{},"balance":{}}}"#,
                            aid,
                            json_escape(ticker),
                            sup,
                            dec,
                            bal
                        )
                    })
                    .collect();
                rpc_ok(&id_val, &format!(r#"{{"assets":[{}]}}"#, items.join(",")))
            }
            _ => rpc_err(&id_val, -32003, "asset portfolio RPC failed"),
        },

        "xcr_simulateScript" => {
            let script_uri = extract_json_str(body, "script").unwrap_or_default();
            let Some(script) = CredScript::from_uri(&script_uri) else {
                return rpc_err(&id_val, -32602, "invalid `xcrscript1_...` URI");
            };
            let wit_hex = extract_json_str(body, "witness_hex").unwrap_or_default();
            let witness = if wit_hex.is_empty() {
                Vec::new()
            } else {
                match hex_decode(&wit_hex).and_then(|b| decode_witness_stack(&b)) {
                    Some(w) => w,
                    None => return rpc_err(&id_val, -32602, "invalid witness_hex"),
                }
            };
            let now_unix = extract_json_u64(body, "now_unix").unwrap_or_else(|| {
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .map(|d| d.as_secs())
                    .unwrap_or(0)
            });
            let result = script.evaluate(
                &witness,
                &CredEvalContext {
                    spend_digest: Hash32::ZERO,
                    now_unix,
                    primary_recipient: Address::default(),
                },
            );
            rpc_ok(
                &id_val,
                &format!(
                    r#"{{"script_hash":"{}","op_count":{},"evaluated":{},"gas_burned":0}}"#,
                    script.script_hash(),
                    script.ops.len(),
                    result
                ),
            )
        }

        "xcr_resolveName" => {
            let name = extract_json_str(body, "name").unwrap_or_default();
            match rpc_call(
                primary_node,
                &NodeRpcRequest::ResolveHandle { name },
                timeout,
            ) {
                Ok(NodeRpcResponse::HandleResolution {
                    found,
                    normalized_name,
                    owner,
                    stealth_uri,
                    registered_epoch,
                }) => rpc_ok(
                    &id_val,
                    &format!(
                        r#"{{"found":{},"handle":"@{}","owner_pocket":"{}","owner_hex":"{}","stealth_uri":"{}","registered_epoch":{}}}"#,
                        found,
                        json_escape(&normalized_name),
                        owner.short_hex(),
                        Hash32(owner.0),
                        json_escape(&stealth_uri),
                        registered_epoch
                    ),
                ),
                _ => rpc_err(&id_val, -32004, "handle resolution RPC failed"),
            }
        }

        "xcr_getOrderbook" => match rpc_call(
            primary_node,
            &NodeRpcRequest::GetDexOrderbook { asset_id: None },
            timeout,
        ) {
            Ok(NodeRpcResponse::DexOrderbookSnapshot { orders }) => {
                let items: Vec<String> = orders
                    .iter()
                    .map(|(oid, maker, aid, is_sell, rem, price, esc)| {
                        format!(
                            r#"{{"order_id":"{}","maker":"{}","asset_id":"{}","side":"{}","remaining_units":{},"price_bits_per_unit":{},"escrowed_xcr":"{}"}}"#,
                            oid,
                            maker.short_hex(),
                            aid,
                            if *is_sell { "ASK" } else { "BID" },
                            rem,
                            price,
                            esc.format_symbolic()
                        )
                    })
                    .collect();
                rpc_ok(&id_val, &format!(r#"{{"orders":[{}]}}"#, items.join(",")))
            }
            _ => rpc_err(&id_val, -32005, "DEX orderbook RPC failed"),
        },

        "xcr_getArtifacts" => match rpc_call(
            primary_node,
            &NodeRpcRequest::GetArtifactsAndAttestations {
                owner_or_subject: None,
                lane_id: 1,
            },
            timeout,
        ) {
            Ok(NodeRpcResponse::LaneAndArtifactSnapshot {
                artifacts,
                attestations,
                ..
            }) => {
                let art_json: Vec<String> = artifacts
                    .iter()
                    .map(|(aid, iss, own, col, title, chash)| {
                        format!(
                            r#"{{"artifact_id":"{}","issuer":"{}","owner":"{}","collection":"{}","title":"{}","content_hash":"{}"}}"#,
                            aid,
                            iss.short_hex(),
                            own.short_hex(),
                            json_escape(col),
                            json_escape(title),
                            chash
                        )
                    })
                    .collect();
                let att_json: Vec<String> = attestations
                    .iter()
                    .map(|(id, att, sub, sch, comm, exp, rev)| {
                        format!(
                            r#"{{"attestation_id":"{}","attester":"{}","subject":"{}","schema":"{}","claim_commitment":"{}","expiry_unix":{},"revoked":{}}}"#,
                            id,
                            att.short_hex(),
                            sub.short_hex(),
                            json_escape(sch),
                            comm,
                            exp,
                            rev
                        )
                    })
                    .collect();
                rpc_ok(
                    &id_val,
                    &format!(
                        r#"{{"artifacts":[{}],"attestations":[{}]}}"#,
                        art_json.join(","),
                        att_json.join(",")
                    ),
                )
            }
            _ => rpc_err(&id_val, -32006, "artifact/attestation RPC failed"),
        },

        "xcr_getGovernance" => {
            match rpc_call(primary_node, &NodeRpcRequest::GetGovernanceSummary, timeout) {
                Ok(NodeRpcResponse::GovernanceSnapshot {
                    proposals,
                    total_dreps,
                }) => {
                    let p_json: Vec<String> = proposals
                    .iter()
                    .map(|(pid, title, pkey, pval, yes_b, no_b, abs_b, dl)| {
                        format!(
                            r#"{{"proposal_id":"{}","title":"{}","param_key":"{}","param_value":{},"yes_bits":{},"no_bits":{},"abstain_bits":{},"deadline_unix":{}}}"#,
                            pid,
                            json_escape(title),
                            json_escape(pkey),
                            pval,
                            yes_b,
                            no_b,
                            abs_b,
                            dl
                        )
                    })
                    .collect();
                    rpc_ok(
                        &id_val,
                        &format!(
                            r#"{{"total_dreps":{},"proposals":[{}]}}"#,
                            total_dreps,
                            p_json.join(",")
                        ),
                    )
                }
                _ => rpc_err(&id_val, -32007, "governance RPC failed"),
            }
        }

        "xcr_getShieldedPool" => {
            let start_index = extract_json_u64(body, "start_index").unwrap_or(0) as u32;
            match rpc_call(
                primary_node,
                &NodeRpcRequest::GetShieldedNotes { start_index },
                timeout,
            ) {
                Ok(NodeRpcResponse::ShieldedPoolSnapshot {
                    total_notes,
                    pool_balance,
                    notes,
                }) => {
                    let n_json: Vec<String> = notes
                        .iter()
                        .map(|(nid, otp, com, eph, vt, _enc)| {
                            format!(
                                r#"{{"note_id":"{}","one_time_pub":"{}","pedersen_commit":"{}","ephemeral_pub":"{}","view_tag":{}}}"#,
                                nid,
                                hex_encode(otp),
                                hex_encode(com),
                                hex_encode(eph),
                                vt
                            )
                        })
                        .collect();
                    rpc_ok(
                        &id_val,
                        &format!(
                            r#"{{"total_notes":{},"pool_balance":"{}","notes":[{}]}}"#,
                            total_notes,
                            pool_balance.format_symbolic(),
                            n_json.join(",")
                        ),
                    )
                }
                _ => rpc_err(&id_val, -32009, "shielded pool RPC failed"),
            }
        }

        "xcr_getAmmPools" | "xcr_getOracleFeeds" => {
            match rpc_call(
                primary_node,
                &NodeRpcRequest::GetAmmAndOracleSnapshot,
                timeout,
            ) {
                Ok(NodeRpcResponse::AmmAndOracleSnapshot { pools, feeds }) => {
                    let p_json: Vec<String> = pools
                        .iter()
                        .map(|(aid, ticker, rxcr, rast, lp)| {
                            format!(
                                r#"{{"asset_id":"{}","ticker":"{}","reserve_xcr":"{}","reserve_asset":{},"total_lp_shares":{}}}"#,
                                aid,
                                json_escape(ticker),
                                rxcr.format_symbolic(),
                                rast,
                                lp
                            )
                        })
                        .collect();
                    let f_json: Vec<String> = feeds
                        .iter()
                        .map(|(fid, med, cnt, ts)| {
                            format!(
                                r#"{{"feed_id":"{}","median_micros":{},"median_decimal":"{}.{:06}","reporters":{},"updated_unix":{}}}"#,
                                json_escape(fid),
                                med,
                                med / 1_000_000,
                                med % 1_000_000,
                                cnt,
                                ts
                            )
                        })
                        .collect();
                    rpc_ok(
                        &id_val,
                        &format!(
                            r#"{{"amm_pools":[{}],"oracle_feeds":[{}]}}"#,
                            p_json.join(","),
                            f_json.join(",")
                        ),
                    )
                }
                _ => rpc_err(&id_val, -32010, "AMM & Oracle snapshot RPC failed"),
            }
        }

        "xcr_sendRawTransaction" => {
            let raw_hex = extract_json_str(body, "raw_tx_hex")
                .or_else(|| extract_json_str(body, "raw_tx"))
                .unwrap_or_default();
            let Some(raw_bytes) = hex_decode(raw_hex.trim()) else {
                return rpc_err(
                    &id_val,
                    -32602,
                    "pass hex-encoded signed RPC packet in `raw_tx_hex`",
                );
            };
            let Some(decoded_req) = NodeRpcRequest::decode(&raw_bytes) else {
                return rpc_err(&id_val, -32602, "malformed signed transaction packet");
            };
            let is_stateless_user_tx = matches!(
                decoded_req,
                NodeRpcRequest::SubmitBulletproofFastPay { .. }
                    | NodeRpcRequest::ClaimStealthUtxo { .. }
                    | NodeRpcRequest::LockHtlc { .. }
                    | NodeRpcRequest::ClaimHtlc { .. }
                    | NodeRpcRequest::RefundHtlc { .. }
                    | NodeRpcRequest::OpenPayChannel { .. }
                    | NodeRpcRequest::ClosePayChannel { .. }
                    | NodeRpcRequest::CashOrCancelCheck { .. }
                    | NodeRpcRequest::LockScriptVault { .. }
                    | NodeRpcRequest::SpendScriptVault { .. }
                    | NodeRpcRequest::ExecuteSessionKey { .. }
                    | NodeRpcRequest::MintNativeAsset { .. }
                    | NodeRpcRequest::TransferNativeAsset { .. }
                    | NodeRpcRequest::CreateCampaign { .. }
                    | NodeRpcRequest::PledgeCampaign { .. }
                    | NodeRpcRequest::FinalizeCampaign { .. }
                    | NodeRpcRequest::PlaceDexOrder { .. }
                    | NodeRpcRequest::CancelDexOrder { .. }
                    | NodeRpcRequest::BridgedAssetPayment { .. }
                    | NodeRpcRequest::BabelAssetTransfer { .. }
                    | NodeRpcRequest::RegisterOrTransferHandle { .. }
                    | NodeRpcRequest::ParallelLanePay { .. }
                    | NodeRpcRequest::ExecuteAtomicBatch { .. }
                    | NodeRpcRequest::MintOrTransferArtifact { .. }
                    | NodeRpcRequest::IssueOrRevokeAttestation { .. }
                    | NodeRpcRequest::GovernanceAction { .. }
                    | NodeRpcRequest::SetDepositShield { .. }
                    | NodeRpcRequest::ShieldDeposit { .. }
                    | NodeRpcRequest::ShieldRingTransfer { .. }
                    | NodeRpcRequest::AmmLiquidity { .. }
                    | NodeRpcRequest::HybridSmartSwap { .. }
                    | NodeRpcRequest::SubmitOracleReport { .. }
                    | NodeRpcRequest::OracleFiatPayment { .. }
                    | NodeRpcRequest::BandwidthFreePay { .. }
                    | NodeRpcRequest::CreateClaimable { .. }
                    | NodeRpcRequest::SweepOrReclaimClaimable { .. }
                    | NodeRpcRequest::CreateRedPacket { .. }
                    | NodeRpcRequest::ClaimOrReclaimRedPacket { .. }
                    | NodeRpcRequest::ExecuteProofOfBurn { .. }
                    | NodeRpcRequest::BindOrExecuteRoleProxy { .. }
            );
            if !is_stateless_user_tx {
                return rpc_err(
                    &id_val,
                    -32600,
                    "blocked: only signed user/contract transactions allowed on xcr_sendRawTransaction",
                );
            }
            match rpc_call(primary_node, &decoded_req, timeout) {
                Ok(NodeRpcResponse::FastPayReceipt {
                    accepted,
                    tx_id,
                    finality_latency_ms,
                    new_state_root,
                    message,
                    ..
                }) => rpc_ok(
                    &id_val,
                    &format!(
                        r#"{{"accepted":{},"tx_id":"{}","finality_latency_ms":{},"state_root":"{}","message":"{}"}}"#,
                        accepted,
                        tx_id,
                        finality_latency_ms,
                        new_state_root,
                        json_escape(&message)
                    ),
                ),
                Ok(NodeRpcResponse::ContractReceipt {
                    accepted,
                    contract_id,
                    amount,
                    new_state_root,
                    message,
                }) => rpc_ok(
                    &id_val,
                    &format!(
                        r#"{{"accepted":{},"tx_id":"{}","amount":"{}","state_root":"{}","message":"{}"}}"#,
                        accepted,
                        contract_id,
                        amount.format_symbolic(),
                        new_state_root,
                        json_escape(&message)
                    ),
                ),
                Ok(NodeRpcResponse::StealthClaimReceipt {
                    accepted,
                    claimed_amount,
                    new_state_root,
                    message,
                    ..
                }) => rpc_ok(
                    &id_val,
                    &format!(
                        r#"{{"accepted":{},"amount":"{}","state_root":"{}","message":"{}"}}"#,
                        accepted,
                        claimed_amount.format_symbolic(),
                        new_state_root,
                        json_escape(&message)
                    ),
                ),
                _ => rpc_err(&id_val, -32008, "validator broadcast timed out"),
            }
        }

        _ => rpc_err(&id_val, -32601, "Method not found"),
    }
}

fn rpc_ok(id_raw: &str, result_json: &str) -> String {
    format!(r#"{{"jsonrpc":"2.0","id":{id_raw},"result":{result_json}}}"#)
}

fn rpc_err(id_raw: &str, code: i32, msg: &str) -> String {
    format!(
        r#"{{"jsonrpc":"2.0","id":{id_raw},"error":{{"code":{code},"message":"{}"}}}}"#,
        json_escape(msg)
    )
}

fn extract_json_id(s: &str) -> String {
    let Some(idx) = s.find("\"id\"") else {
        return "1".to_owned();
    };
    let rest = s[idx + 4..].trim_start();
    let Some(after_colon) = rest.strip_prefix(':') else {
        return "1".to_owned();
    };
    let val = after_colon.trim_start();
    if let Some(stripped) = val.strip_prefix('"')
        && let Some(end) = stripped.find('"')
    {
        return format!("\"{}\"", json_escape(&stripped[..end]));
    }
    let digits: String = val
        .chars()
        .take_while(|c| c.is_ascii_digit() || *c == '-')
        .collect();
    if digits.is_empty() {
        "1".to_owned()
    } else {
        digits
    }
}

fn extract_json_str(s: &str, key: &str) -> Option<String> {
    let needle = format!("\"{key}\"");
    let idx = s.find(&needle)?;
    let rest = s[idx + needle.len()..]
        .trim_start()
        .strip_prefix(':')?
        .trim_start();
    let inner = rest.strip_prefix('"')?;
    let end = inner.find('"')?;
    Some(inner[..end].to_owned())
}

fn extract_json_u64(s: &str, key: &str) -> Option<u64> {
    let needle = format!("\"{key}\"");
    let idx = s.find(&needle)?;
    let rest = s[idx + needle.len()..]
        .trim_start()
        .strip_prefix(':')?
        .trim_start();
    let digits: String = rest.chars().take_while(|c| c.is_ascii_digit()).collect();
    digits.parse().ok()
}

fn hex_encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

fn hex_decode(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return None;
    }
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len() / 2);
    for pair in b.as_chunks::<2>().0 {
        let hi = match pair[0] {
            c @ b'0'..=b'9' => c - b'0',
            c @ b'a'..=b'f' => c - b'a' + 10,
            c @ b'A'..=b'F' => c - b'A' + 10,
            _ => return None,
        };
        let lo = match pair[1] {
            c @ b'0'..=b'9' => c - b'0',
            c @ b'a'..=b'f' => c - b'a' + 10,
            c @ b'A'..=b'F' => c - b'A' + 10,
            _ => return None,
        };
        out.push((hi << 4) | lo);
    }
    Some(out)
}
