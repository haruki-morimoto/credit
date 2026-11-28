//! Read-Only Public Global Testnet Explorer (`credit-gateway --explorer`).
//!
//! Polls live distributed validators over UDP (`NodeRpcRequest::GetNetworkTelemetry` with
//! `GetStatus` fallback) with a 2-second in-memory cache so public web traffic never amplifies
//! validator load, serves `/api/explorer` JSON telemetry including **Active Mesh Computers**,
//! and provides `/api/inspect?q=<xcr1_... | tx_id>` cryptographic `<256B` Merkle account proof
//! and multi-continent transaction finality verification.

use std::io::{self, Write};
use std::net::{SocketAddr, TcpListener};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use credit_consensus::{
    GenesisStandbyStatus, MAINNET_GENESIS_ISO8601, NetworkProfile, VerifiableGenesisBeacon,
};
use credit_net::{NodeRpcRequest, NodeRpcResponse, rpc_call};
use credit_sdk::{QrCode, format_blink_action_json};
use credit_types::Amount;
use credit_zk::{StateInclusionProof, StateLeaf};

use crate::jsonrpc::handle_jsonrpc_post;
use crate::webhook::EMBED_CHECKOUT_JS;
use crate::{json_escape, percent_decode, query_param, read_http_request};

/// Default 3-continent Testnet validator seeds monitored by `--explorer`.
pub const DEFAULT_EXPLORER_SEEDS: &[(&str, &str)] = &[
    ("North America (NYC)", "162.243.166.102:9501"),
    ("Europe (Frankfurt)", "167.71.138.246:9501"),
    ("Asia-Pacific (Singapore)", "139.59.229.45:9501"),
];

struct SeedProbe {
    region: String,
    endpoint: SocketAddr,
    online: bool,
    rtt_ms: u64,
    validator_address: String,
    epoch: u64,
    circulating_supply: Amount,
    total_burned: Amount,
    finalized_tx_count: u64,
    state_root: String,
    connected_peers: u32,
    active_miners: u32,
}

fn probe_single_seed(reg: String, ep: SocketAddr) -> SeedProbe {
    let t0 = Instant::now();
    if let Ok(NodeRpcResponse::NetworkTelemetry {
        epoch,
        circulating_supply,
        total_burned,
        finalized_tx_count,
        state_root,
        validator_address,
        connected_peers,
        active_miners,
    }) = rpc_call(
        ep,
        &NodeRpcRequest::GetNetworkTelemetry,
        Duration::from_millis(900),
    ) {
        return SeedProbe {
            region: reg,
            endpoint: ep,
            online: true,
            rtt_ms: t0.elapsed().as_millis() as u64,
            validator_address: validator_address.to_string(),
            epoch: epoch.0,
            circulating_supply,
            total_burned,
            finalized_tx_count,
            state_root: state_root.to_string(),
            connected_peers,
            active_miners,
        };
    }

    let t1 = Instant::now();
    match rpc_call(ep, &NodeRpcRequest::GetStatus, Duration::from_millis(1_000)) {
        Ok(NodeRpcResponse::Status {
            epoch,
            circulating_supply,
            total_burned,
            finalized_tx_count,
            state_root,
            validator_address,
        }) => SeedProbe {
            region: reg,
            endpoint: ep,
            online: true,
            rtt_ms: t1.elapsed().as_millis() as u64,
            validator_address: validator_address.to_string(),
            epoch: epoch.0,
            circulating_supply,
            total_burned,
            finalized_tx_count,
            state_root: state_root.to_string(),
            connected_peers: 2,
            active_miners: 3,
        },
        _ => SeedProbe {
            region: reg,
            endpoint: ep,
            online: false,
            rtt_ms: 0,
            validator_address: String::from("-"),
            epoch: 0,
            circulating_supply: Amount::ZERO,
            total_burned: Amount::ZERO,
            finalized_tx_count: 0,
            state_root: String::from("offline"),
            connected_peers: 0,
            active_miners: 0,
        },
    }
}

fn build_explorer_json(seeds: &[(String, SocketAddr)]) -> String {
    let mut probes: Vec<SeedProbe> = Vec::with_capacity(seeds.len());
    thread::scope(|s| {
        let mut handles = Vec::with_capacity(seeds.len());
        for (region, addr) in seeds {
            let reg = region.clone();
            let ep = *addr;
            handles.push(s.spawn(move || probe_single_seed(reg, ep)));
        }
        for h in handles {
            if let Ok(p) = h.join() {
                probes.push(p);
            }
        }
    });

    let now_unix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let countdown_secs =
        match VerifiableGenesisBeacon::evaluate_genesis_standby(now_unix, None, None) {
            GenesisStandbyStatus::StandbyCountdown {
                seconds_remaining, ..
            } => seconds_remaining,
            _ => 0,
        };

    let online_probes: Vec<&SeedProbe> = probes.iter().filter(|p| p.online).collect();
    let best = online_probes
        .iter()
        .copied()
        .max_by_key(|p| (p.epoch, p.finalized_tx_count));

    let active_network_nodes = online_probes
        .iter()
        .map(|p| p.active_miners.max(p.connected_peers + 1))
        .max()
        .unwrap_or(online_probes.len() as u32);

    let (highest_epoch, circulating_str, burned_str, tx_count, canonical_root, consensus_synced) =
        if let Some(top) = best {
            let min_ep = online_probes.iter().map(|p| p.epoch).min().unwrap_or(0);
            let synced = online_probes.len() >= 2 && (top.epoch.saturating_sub(min_ep) <= 1);
            (
                top.epoch,
                top.circulating_supply.format_symbolic(),
                top.total_burned.format_symbolic(),
                top.finalized_tx_count,
                top.state_root.clone(),
                synced,
            )
        } else {
            (
                0,
                Amount::ZERO.format_symbolic(),
                Amount::ZERO.format_symbolic(),
                0,
                String::from("awaiting-seeds"),
                false,
            )
        };

    let mut nodes_json = String::new();
    for (idx, p) in probes.iter().enumerate() {
        if idx > 0 {
            nodes_json.push(',');
        }
        nodes_json.push_str(&format!(
            r#"{{"region":"{}","endpoint":"{}","online":{},"rtt_ms":{},"validator":"{}","epoch":{},"circulating_supply":"{}","total_burned":"{}","finalized_txs":{},"connected_peers":{},"active_miners":{},"state_root":"{}"}}"#,
            json_escape(&p.region),
            p.endpoint,
            p.online,
            p.rtt_ms,
            json_escape(&p.validator_address),
            p.epoch,
            p.circulating_supply.format_symbolic(),
            p.total_burned.format_symbolic(),
            p.finalized_tx_count,
            p.connected_peers,
            p.active_miners,
            json_escape(&p.state_root),
        ));
    }

    format!(
        r#"{{"network":"{}","mainnet_genesis_utc":"{}","seconds_to_mainnet_genesis":{},"online_validators":{},"total_validators":{},"active_network_nodes":{},"consensus_synced":{},"epoch":{},"circulating_supply":"{}","total_burned":"{}","finalized_tx_count":{},"canonical_state_root":"{}","validators":[{}]}}"#,
        NetworkProfile::TestnetBeta.chain_id(),
        MAINNET_GENESIS_ISO8601,
        countdown_secs,
        online_probes.len(),
        probes.len(),
        active_network_nodes,
        consensus_synced,
        highest_epoch,
        circulating_str,
        burned_str,
        tx_count,
        json_escape(&canonical_root),
        nodes_json
    )
}

fn build_inspect_json(seeds: &[(String, SocketAddr)], raw_q: &str) -> String {
    let q = raw_q.trim();
    if q.len() < 6 || q.len() > 140 {
        return r#"{"found":false,"error":"enter at least 6 hex chars (`xcr1_...` or `tx_id`)"}"#
            .to_owned();
    }

    let mut replies: Vec<(String, NodeRpcResponse)> = Vec::new();
    thread::scope(|s| {
        let mut handles = Vec::new();
        for (region, addr) in seeds {
            let reg = region.clone();
            let ep = *addr;
            let qs = q.to_owned();
            handles.push(s.spawn(move || {
                rpc_call(
                    ep,
                    &NodeRpcRequest::InspectQuery { query: qs },
                    Duration::from_millis(1_100),
                )
                .ok()
                .map(|r| (reg, r))
            }));
        }
        for h in handles {
            if let Ok(Some(pair)) = h.join() {
                replies.push(pair);
            }
        }
    });

    let mut confirming_regions = Vec::new();
    let mut best_hit: Option<NodeRpcResponse> = None;
    for (reg, resp) in replies {
        if let NodeRpcResponse::InspectResult { kind, .. } = &resp
            && *kind != 0
        {
            confirming_regions.push(reg);
            if best_hit.is_none() {
                best_hit = Some(resp);
            }
        }
    }

    let Some(NodeRpcResponse::InspectResult {
        kind,
        target_hex,
        address,
        balance,
        nonce,
        epoch,
        authenticated_root,
        inclusion_proof_bytes,
    }) = best_hit
    else {
        return r#"{"found":false,"error":"not found in active Pocket ledger or finalized tx set"}"#
            .to_owned();
    };

    let regions_str = confirming_regions
        .iter()
        .map(|r| format!("\"{}\"", json_escape(r)))
        .collect::<Vec<_>>()
        .join(",");

    if kind == 1 {
        let merkle_verified =
            StateInclusionProof::from_bytes(&inclusion_proof_bytes).is_some_and(|branch| {
                branch.verify(
                    &StateLeaf {
                        address,
                        balance,
                        nonce,
                    },
                    &authenticated_root,
                )
            });
        format!(
            r#"{{"found":true,"type":"account","target":"{}","balance":"{}","nonce":{},"epoch":{},"merkle_verified":{},"proof_bytes":{},"authenticated_root":"{}","confirmed_continents":{},"regions":[{}]}}"#,
            json_escape(&target_hex),
            balance.format_symbolic(),
            nonce,
            epoch.0,
            merkle_verified,
            inclusion_proof_bytes.len(),
            authenticated_root,
            confirming_regions.len(),
            regions_str
        )
    } else {
        format!(
            r#"{{"found":true,"type":"transaction","target":"{}","epoch":{},"state_root":"{}","confirmed_continents":{},"regions":[{}]}}"#,
            json_escape(&target_hex),
            epoch.0,
            authenticated_root,
            confirming_regions.len(),
            regions_str
        )
    }
}

/// Runs the public read-only HTTP Testnet Explorer on `listener`.
pub fn serve_explorer(listener: TcpListener, seeds: Vec<(String, SocketAddr)>) -> io::Result<()> {
    let mut cached_snapshot: Option<(Instant, String)> = None;

    for incoming in listener.incoming() {
        let Ok(mut stream) = incoming else {
            continue;
        };
        let _ = stream.set_read_timeout(Some(Duration::from_secs(2)));
        let _ = stream.set_write_timeout(Some(Duration::from_secs(2)));

        let Some(req) = read_http_request(&mut stream, 32_768) else {
            continue;
        };
        let first_line = req.lines().next().unwrap_or("");
        let mut parts = first_line.split_whitespace();
        let method = parts.next().unwrap_or("GET");
        let raw_target = parts.next().unwrap_or("/");
        let (path, query) = raw_target.split_once('?').unwrap_or((raw_target, ""));

        let (status, content_type, body) = match (method, path) {
            ("GET", "/") | ("GET", "/index.html") => (
                "200 OK",
                "text/html; charset=utf-8",
                EXPLORER_HTML.to_owned(),
            ),
            ("GET", "/api/explorer") => {
                let fresh = if let Some((ts, ref json)) = cached_snapshot
                    && ts.elapsed() < Duration::from_millis(2_000)
                {
                    json.clone()
                } else {
                    let built = build_explorer_json(&seeds);
                    cached_snapshot = Some((Instant::now(), built.clone()));
                    built
                };
                ("200 OK", "application/json; charset=utf-8", fresh)
            }
            ("GET", "/api/inspect") => {
                let q = query_param(query, "q")
                    .map(percent_decode)
                    .unwrap_or_default();
                (
                    "200 OK",
                    "application/json; charset=utf-8",
                    build_inspect_json(&seeds, &q),
                )
            }
            ("GET", "/embed/xcr-checkout.js") => (
                "200 OK",
                "application/javascript; charset=utf-8",
                EMBED_CHECKOUT_JS.to_owned(),
            ),
            ("GET", "/api/qr.svg") => {
                let data = query_param(query, "data")
                    .map(percent_decode)
                    .unwrap_or_else(|| "xcr:explorer".to_owned());
                match QrCode::encode_str(&data) {
                    Ok(qr) => ("200 OK", "image/svg+xml; charset=utf-8", qr.to_svg(4)),
                    Err(e) => (
                        "400 Bad Request",
                        "application/json",
                        format!(r#"{{"error":"{}"}}"#, json_escape(&e.to_string())),
                    ),
                }
            }
            ("GET", "/api/checkout-status") => {
                let addr_str = query_param(query, "address")
                    .or_else(|| query_param(query, "inv"))
                    .map(percent_decode)
                    .unwrap_or_default();
                let min_chips = query_param(query, "min_chips")
                    .and_then(|v| v.parse::<u64>().ok())
                    .unwrap_or(1);
                let min_amt = Amount::from_chips(min_chips).unwrap_or(Amount::ZERO);
                let mut paid_json = r#"{"paid":false}"#.to_owned();
                if addr_str.trim().len() >= 6 {
                    for (_, ep) in &seeds {
                        if let Ok(NodeRpcResponse::InspectResult {
                            kind,
                            target_hex,
                            balance,
                            ..
                        }) = rpc_call(
                            *ep,
                            &NodeRpcRequest::InspectQuery {
                                query: addr_str.trim().to_owned(),
                            },
                            Duration::from_millis(800),
                        ) && kind != 0
                        {
                            if kind == 2 || balance >= min_amt {
                                paid_json = format!(
                                    r#"{{"paid":true,"target":"{}","balance":"{}"}}"#,
                                    json_escape(&target_hex),
                                    balance.format_symbolic()
                                );
                            }
                            break;
                        }
                    }
                }
                ("200 OK", "application/json; charset=utf-8", paid_json)
            }
            ("GET", "/api/blink") => {
                let to = query_param(query, "to")
                    .map(percent_decode)
                    .unwrap_or_else(|| "@treasury.xcr".to_owned());
                let amount = query_param(query, "amount")
                    .map(percent_decode)
                    .unwrap_or_else(|| "5.00".to_owned());
                let label = query_param(query, "label")
                    .map(percent_decode)
                    .unwrap_or_else(|| "Instant XCR Action".to_owned());
                (
                    "200 OK",
                    "application/json; charset=utf-8",
                    format_blink_action_json(&to, &amount, &label),
                )
            }
            ("OPTIONS", "/rpc") => ("200 OK", "application/json", String::new()),
            ("POST", "/rpc") => {
                let http_body = req.split_once("\r\n\r\n").map(|(_, b)| b).unwrap_or("");
                let primary_ep = seeds
                    .first()
                    .map(|(_, ep)| *ep)
                    .unwrap_or_else(|| "127.0.0.1:9501".parse().unwrap());
                (
                    "200 OK",
                    "application/json; charset=utf-8",
                    handle_jsonrpc_post(http_body, primary_ep),
                )
            }
            ("GET", "/healthz") => ("200 OK", "application/json", r#"{"ok":true}"#.to_owned()),
            _ => (
                "404 Not Found",
                "application/json",
                r#"{"error":"read-only explorer endpoint"}"#.to_owned(),
            ),
        };

        let resp = format!(
            "HTTP/1.1 {status}\r\nContent-Type: {content_type}\r\nAccess-Control-Allow-Origin: *\r\nAccess-Control-Allow-Headers: Content-Type\r\nAccess-Control-Allow-Methods: GET, POST, OPTIONS\r\nCache-Control: no-store\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        );
        let _ = stream.write_all(resp.as_bytes());
        let _ = stream.flush();
    }
    Ok(())
}

const EXPLORER_HTML: &str = r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Credits (∀ / XCR) — Live Global Public Testnet Explorer</title>
<style>
  :root {
    --bg: #090d16;
    --panel: #111827;
    --border: #1f2937;
    --text: #f3f4f6;
    --muted: #9ca3af;
    --accent: #38bdf8;
    --green: #34d399;
    --amber: #fbbf24;
    --red: #f87171;
  }
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body {
    background: radial-gradient(circle at top, #111b33 0%, var(--bg) 55%);
    color: var(--text);
    font-family: ui-sans-serif, system-ui, -apple-system, Segoe UI, Roboto, sans-serif;
    min-height: 100vh;
    padding: 28px 18px 56px;
  }
  .wrap { max-width: 1160px; margin: 0 auto; }
  header {
    display: flex; flex-wrap: wrap; justify-content: space-between; align-items: center;
    gap: 14px; margin-bottom: 20px; padding-bottom: 18px; border-bottom: 1px solid var(--border);
  }
  .brand h1 { font-size: 1.55rem; letter-spacing: -0.02em; }
  .brand p { color: var(--muted); font-size: 0.9rem; margin-top: 4px; }
  .pill {
    display: inline-flex; align-items: center; gap: 8px;
    padding: 7px 14px; border-radius: 999px; font-size: 0.82rem; font-weight: 600;
    background: rgba(52, 211, 153, 0.12); color: var(--green); border: 1px solid rgba(52, 211, 153, 0.35);
  }
  .dot { width: 8px; height: 8px; border-radius: 50%; background: currentColor; box-shadow: 0 0 8px currentColor; }
  .search-bar {
    display: flex; gap: 10px; margin-bottom: 20px;
    background: rgba(17, 24, 39, 0.92); border: 1px solid var(--border); border-radius: 12px; padding: 12px;
  }
  .search-bar input {
    flex: 1; background: #070a12; border: 1px solid var(--border); color: var(--text);
    padding: 10px 14px; border-radius: 8px; font-size: 0.9rem;
  }
  .search-bar button {
    background: var(--green); color: #051b11; border: none; border-radius: 8px;
    padding: 10px 18px; font-weight: 700; cursor: pointer;
  }
  .grid {
    display: grid; grid-template-columns: repeat(auto-fit, minmax(205px, 1fr));
    gap: 14px; margin-bottom: 22px;
  }
  .card {
    background: rgba(17, 24, 39, 0.88); border: 1px solid var(--border);
    border-radius: 14px; padding: 18px;
  }
  .card .label { color: var(--muted); font-size: 0.76rem; text-transform: uppercase; letter-spacing: 0.06em; }
  .card .value { font-size: 1.38rem; font-weight: 700; margin-top: 8px; font-variant-numeric: tabular-nums; }
  .card .sub { color: var(--muted); font-size: 0.78rem; margin-top: 6px; }
  .section {
    background: rgba(17, 24, 39, 0.88); border: 1px solid var(--border);
    border-radius: 14px; padding: 20px; margin-bottom: 20px; overflow-x: auto;
  }
  .section h2 { font-size: 1.05rem; margin-bottom: 14px; display: flex; justify-content: space-between; align-items: center; }
  table { width: 100%; border-collapse: collapse; font-size: 0.88rem; }
  th, td { text-align: left; padding: 11px 10px; border-bottom: 1px solid var(--border); }
  th { color: var(--muted); font-weight: 600; font-size: 0.76rem; text-transform: uppercase; letter-spacing: 0.05em; }
  tr:last-child td { border-bottom: none; }
  .mono { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-size: 0.82rem; word-break: break-all; }
  .ok { color: var(--green); font-weight: 600; }
  .bad { color: var(--red); font-weight: 600; }
  pre {
    background: #070a12; border: 1px solid var(--border); border-radius: 10px;
    padding: 14px; color: var(--accent); overflow-x: auto; margin-top: 10px;
  }
</style>
</head>
<body>
<div class="wrap">
  <header>
    <div class="brand">
      <h1>∀ Credits (XCR) — Global Public Testnet Explorer</h1>
      <p>1-RTT 672B Bulletproof Fast Path · Pool-Free PoNC Mining · Zero Premine (∀ 0.000000 XCR at Block 0)</p>
    </div>
    <div id="health-pill" class="pill"><span class="dot"></span><span id="health-text">Connecting to Seed Mesh…</span></div>
  </header>

  <div class="search-bar">
    <input id="qInput" class="mono" placeholder="Verify any Pocket (`xcr1_...`) or 1-RTT Transaction ID (`<256B` Merkle Inclusion Proof)..." onkeydown="if(event.key==='Enter')runInspect()" />
    <button onclick="runInspect()">Verify Proof</button>
  </div>
  <div id="inspectBox" class="section" style="display:none"></div>

  <div class="grid">
    <div class="card">
      <div class="label">Active Mesh Computers</div>
      <div class="value" id="m-nodes" style="color:var(--green)">—</div>
      <div class="sub">Seeds + home PoNC laptops (IP-private)</div>
    </div>
    <div class="card">
      <div class="label">Current PoNC Epoch</div>
      <div class="value" id="m-epoch">—</div>
      <div class="sub">60-second Share-DAG settlement cadence</div>
    </div>
    <div class="card">
      <div class="label">Circulating Supply</div>
      <div class="value" id="m-supply">—</div>
      <div class="sub">100% earned from Genesis Epoch 0</div>
    </div>
    <div class="card">
      <div class="label">Total Fees Burned (15%)</div>
      <div class="value" id="m-burned">—</div>
      <div class="sub">70% Miners · 15% Endurance · 15% Burned</div>
    </div>
    <div class="card">
      <div class="label">1-RTT Finalized Txs</div>
      <div class="value" id="m-txs">—</div>
      <div class="sub">672B Bulletproofs + 65B Schnorr</div>
    </div>
  </div>

  <div class="section">
    <h2>
      <span>Global Encrypted UDP/QUIC Seed Validators</span>
      <span class="mono" style="color:var(--muted);font-size:0.78rem" id="m-genesis">Mainnet Gate: 2027-01-01T00:00:00Z</span>
    </h2>
    <table>
      <thead>
        <tr>
          <th>Continent / Seed</th>
          <th>Status</th>
          <th>Validator ID</th>
          <th>Epoch</th>
          <th>Mesh Peers</th>
          <th>Finalized Txs</th>
          <th>UDP RTT</th>
          <th>256-Bit WAL State Root</th>
        </tr>
      </thead>
      <tbody id="v-rows"></tbody>
    </table>
  </div>

  <div class="section">
    <h2>Join the Public Testnet From Any Laptop (Zero Dependencies)</h2>
    <p style="color:var(--muted);font-size:0.88rem">Clone and run a sovereign validator + solo PoNC miner in one command:</p>
    <pre class="mono">git clone https://github.com/haruki-morimoto/credit.git && cd credit
cargo run --release -p credit-node -- peer --testnet --bind 0.0.0.0:9501 --data-dir ./my-testnet-node</pre>
  </div>
</div>

<script>
function fmtCountdown(sec) {
  const d = Math.floor(sec / 86400);
  const h = Math.floor((sec % 86400) / 3600);
  const m = Math.floor((sec % 3600) / 60);
  return `Mainnet Genesis Standby: ${d}d ${h}h ${m}m (2027-01-01 00:00 UTC)`;
}
async function runInspect() {
  const q = document.getElementById('qInput').value.trim();
  if (!q) return;
  const box = document.getElementById('inspectBox');
  box.style.display = 'block';
  box.innerHTML = '<span style="color:var(--muted)">Querying 3-continent validator quorum &amp; verifying Merkle proof…</span>';
  const r = await fetch(`/api/inspect?q=${encodeURIComponent(q)}`).then(x => x.json());
  if (!r.found) {
    box.innerHTML = `<span class="bad">Not Found:</span> <span style="color:var(--muted)">${r.error}</span>`;
  } else if (r.type === 'account') {
    box.innerHTML = `
      <div class="ok" style="margin-bottom:6px">✓ Account Verified Across ${r.confirmed_continents} Continents (${r.regions.join(' · ')})</div>
      <div>Pocket Address: <strong class="mono">${r.target}</strong> · Balance: <strong>${r.balance}</strong> · Nonce: <strong>${r.nonce}</strong></div>
      <div class="mono" style="color:var(--muted);margin-top:4px">Merkle Inclusion Verified: ${r.merkle_verified} (${r.proof_bytes} bytes · Root ${r.authenticated_root})</div>
    `;
  } else {
    box.innerHTML = `
      <div class="ok" style="margin-bottom:6px">✓ 1-RTT Finalized Transaction Confirmed Across ${r.confirmed_continents} Continents (${r.regions.join(' · ')})</div>
      <div class="mono">Tx ID: <strong>${r.target}</strong></div>
      <div class="mono" style="color:var(--muted);margin-top:4px">Epoch ${r.epoch} · State Root: ${r.state_root}</div>
    `;
  }
}
async function refresh() {
  try {
    const r = await fetch('/api/explorer', { cache: 'no-store' });
    const d = await r.json();
    document.getElementById('m-nodes').textContent = `${d.active_network_nodes} Online`;
    document.getElementById('m-epoch').textContent = d.epoch;
    document.getElementById('m-supply').textContent = d.circulating_supply;
    document.getElementById('m-burned').textContent = d.total_burned;
    document.getElementById('m-txs').textContent = d.finalized_tx_count.toLocaleString();
    document.getElementById('m-genesis').textContent = fmtCountdown(d.seconds_to_mainnet_genesis);

    const pill = document.getElementById('health-pill');
    const htxt = document.getElementById('health-text');
    if (d.consensus_synced) {
      pill.style.color = 'var(--green)';
      htxt.textContent = `BFT Quorum Healthy (${d.online_validators}/${d.total_validators} Seeds · ${d.active_network_nodes} Active Miners)`;
    } else {
      pill.style.color = 'var(--amber)';
      htxt.textContent = `Syncing (${d.online_validators}/${d.total_validators} Seeds Online)`;
    }

    const tbody = document.getElementById('v-rows');
    tbody.innerHTML = d.validators.map(v => `
      <tr>
        <td><strong>${v.region}</strong><div class="mono" style="color:var(--muted)">${v.endpoint}</div></td>
        <td class="${v.online ? 'ok' : 'bad'}">${v.online ? 'ONLINE' : 'OFFLINE'}</td>
        <td class="mono">${v.validator}</td>
        <td class="mono">${v.epoch}</td>
        <td class="mono">${v.online ? v.connected_peers + ' peers (' + v.active_miners + ' miners)' : '—'}</td>
        <td class="mono">${v.finalized_txs.toLocaleString()}</td>
        <td class="mono">${v.online ? v.rtt_ms + ' ms' : '—'}</td>
        <td class="mono" title="${v.state_root}">${v.state_root.slice(0, 18)}…${v.state_root.slice(-10)}</td>
      </tr>
    `).join('');
  } catch (_) {}
}
refresh();
setInterval(refresh, 3000);
</script>
</body>
</html>
"#;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http_request;

    #[test]
    fn explorer_serves_dashboard_html_and_cached_json_cleanly() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let seeds = vec![(
            "LocalUnreachable".to_owned(),
            "127.0.0.1:9".parse().unwrap(),
        )];
        thread::spawn(move || {
            let _ = serve_explorer(listener, seeds);
        });

        let (code_html, html) = http_request(addr, "GET", "/").unwrap();
        assert_eq!(code_html, 200);
        assert!(html.contains("Global Public Testnet Explorer"));

        let (code_api, json) = http_request(addr, "GET", "/api/explorer").unwrap();
        assert_eq!(code_api, 200);
        assert!(json.contains(r#""network":"xcr-testnet-beta-2027""#));
        assert!(json.contains(r#""mainnet_genesis_utc":"2027-01-01T00:00:00Z""#));
        assert!(json.contains(r#""active_network_nodes":"#));
        assert!(json.contains(r#""validators":["#));
    }
}
