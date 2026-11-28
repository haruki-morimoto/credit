//! Self-contained, zero-CDN HTML/CSS/JS Consumer Wallet (`Pocket & Vault` + 4-Dot Credchip),
//! CSRF-Protected Keystore Lock/Unlock, Natural Decimal `XCR` Inputs, Automatic Stealth Sweep,
//! Visual Contacts Book, Encrypted Activity Feed, Live QR Merchant POS, and Bearer Cash Vouchers.

pub const WALLET_AND_POS_HTML: &str = r##"<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Credits (∀ / XCR) Wallet &amp; Live QR Merchant POS</title>
  <style>
    :root {
      --bg: #0f1215;
      --panel: #181d22;
      --border: #2a323b;
      --text: #eef2f6;
      --muted: #94a3b8;
      --green: #76b82a;
      --gold: #c8a96e;
      --danger: #ef4444;
    }
    * { box-sizing: border-box; font-family: system-ui, -apple-system, Segoe UI, sans-serif; }
    body { margin: 0; background: var(--bg); color: var(--text); padding: 20px; }
    .wrap { max-width: 1220px; margin: 0 auto; display: grid; gap: 18px; }
    header { display: flex; flex-wrap: wrap; align-items: center; justify-content: space-between; gap: 12px; padding-bottom: 14px; border-bottom: 1px solid var(--border); }
    .brand { display: flex; align-items: center; gap: 12px; font-size: 19px; font-weight: 700; }
    .pill { font-family: ui-monospace, monospace; font-size: 12px; padding: 5px 10px; border-radius: 999px; background: var(--panel); border: 1px solid var(--border); color: var(--muted); }
    .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(345px, 1fr)); gap: 16px; }
    .card { background: var(--panel); border: 1px solid var(--border); border-radius: 14px; padding: 16px; display: flex; flex-direction: column; gap: 11px; }
    h2 { margin: 0; font-size: 13.5px; letter-spacing: 0.03em; color: var(--muted); text-transform: uppercase; }
    .big { font-family: ui-monospace, monospace; font-size: 24px; font-weight: 700; color: var(--text); }
    .credchip { border: 2px solid var(--gold); background: #2c2a2a; border-radius: 12px; padding: 12px; display: flex; align-items: center; justify-content: space-between; }
    .dots { display: grid; grid-template-columns: repeat(2, 10px); gap: 5px; transform: rotate(45deg); margin-left: 6px; }
    .dot { width: 10px; height: 10px; border-radius: 50%; background: #4b5563; }
    .dot.on { background: var(--green); box-shadow: 0 0 8px var(--green); }
    label { font-size: 12px; color: var(--muted); display: flex; flex-direction: column; gap: 4px; }
    input[type="text"], input[type="password"], input[type="number"], textarea { background: var(--bg); border: 1px solid var(--border); color: var(--text); padding: 8px 10px; border-radius: 8px; font-size: 13px; width: 100%; }
    button { background: var(--green); color: #0b1105; border: none; border-radius: 8px; padding: 9px 12px; font-weight: 700; font-size: 13px; cursor: pointer; }
    button.sec { background: transparent; color: var(--text); border: 1px solid var(--border); }
    button.warn { background: var(--danger); color: #fff; }
    .row { display: flex; align-items: center; justify-content: space-between; gap: 8px; font-size: 12px; }
    .mono { font-family: ui-monospace, monospace; font-size: 11.5px; word-break: break-all; }
    .receipt { background: var(--bg); border: 1px solid var(--border); border-radius: 8px; padding: 10px; font-size: 12px; display: grid; gap: 4px; }
    .qr-box { background: #fff; border-radius: 10px; padding: 8px; width: 168px; height: 168px; margin: 0 auto; display: flex; align-items: center; justify-content: center; }
    .qr-box img { width: 100%; height: 100%; display: block; }
    .paid-banner { background: rgba(118, 184, 42, 0.16); border: 2px solid var(--green); border-radius: 10px; padding: 12px; text-align: center; color: var(--green); font-weight: 700; }
    .chip-btn { background: #222931; color: var(--gold); border: 1px solid var(--border); border-radius: 999px; padding: 4px 10px; font-size: 11.5px; cursor: pointer; }
    #toast { position: fixed; top: 18px; right: 18px; background: #162610; border: 2px solid var(--green); color: var(--text); padding: 12px 16px; border-radius: 10px; font-size: 13px; display: none; z-index: 99; box-shadow: 0 8px 24px rgba(0,0,0,0.45); }
  </style>
</head>
<body>
  <div id="toast"></div>
  <div class="wrap">
    <header>
      <div class="brand">
        <svg viewBox="0 0 64 64" width="30" height="30" fill="none">
          <g stroke="#76b82a" stroke-width="7" stroke-linecap="square" stroke-linejoin="miter">
            <path d="M14 11 L32 53 L50 11" />
            <line x1="10" y1="26" x2="54" y2="26" />
            <line x1="10" y1="38" x2="54" y2="38" />
          </g>
        </svg>
        <span>Credits (∀ / XCR) Wallet &amp; Live QR Merchant POS</span>
      </div>
      <div style="display:flex;gap:8px;flex-wrap:wrap;align-items:center;">
        <span class="pill" id="lockPill" style="color:var(--green)">Unlocked</span>
        <span class="pill" id="epochPill">Epoch --</span>
        <span class="pill" id="supplyPill">Supply: --</span>
        <span class="pill" id="burnPill">Burned: --</span>
      </div>
    </header>

    <div class="grid">
      <!-- 1. Spending Pocket + Keystore Lock/Encrypt -->
      <div class="card">
        <h2>1. Passkey Spending Pocket &amp; Keystore</h2>
        <div class="credchip">
          <div class="dots" title="4-Dot Credchip: Pocket · Vault · ZK · Node">
            <div class="dot on"></div><div class="dot on"></div>
            <div class="dot on"></div><div class="dot on"></div>
          </div>
          <div style="text-align:right;">
            <div style="font-size:11px;color:#d1d5db;">POCKET BALANCE (AUTO-SWEEP ON)</div>
            <div class="big" id="pocketBal">--</div>
          </div>
        </div>
        <div class="row"><span style="color:var(--muted)">Pocket Address</span><span class="mono" id="pocketAddr">--</span></div>
        <div class="row"><span style="color:var(--muted)">Daily Tap Cap</span><span class="mono" id="dailyCap">--</span></div>
        <div class="row"><span style="color:var(--muted)">Account Nonce</span><span class="mono" id="pocketNonce">0</span></div>
        <label>Shareable Private Stealth URI
          <input type="text" id="stealthUri" readonly value="--" onclick="this.select()" class="mono" />
        </label>
        <div style="display:flex;gap:6px;">
          <input type="password" id="walletPass" placeholder="Passphrase (XCRENC01 at-rest encryption)" />
          <button class="sec" onclick="encryptOrUnlock()">Encrypt / Unlock</button>
          <button class="sec" onclick="lockWallet()">Lock</button>
        </div>
        <div style="display:flex;gap:6px;flex-wrap:wrap;">
          <button class="sec" style="flex:1" onclick="verifyLight()">Light-Verify (&lt;256B)</button>
          <button class="sec" style="flex:1" onclick="scanStealth()">Sweep Now</button>
          <button class="sec" style="flex:1" onclick="claimFaucet()">Faucet</button>
        </div>
        <div class="mono" id="lightOut" style="color:var(--green);"></div>
      </div>

      <!-- 2. Natural Decimal XCR Send + Contacts + QR Scanner -->
      <div class="card">
        <h2>2. Send Decimal `XCR` · Contacts · Scan QR</h2>
        <div style="display:flex;gap:6px;">
          <input type="text" id="scanInput" placeholder="Paste xcr:... URI or scan via camera" class="mono" />
          <button class="sec" onclick="applyScannedUri()">Parse</button>
          <button class="sec" onclick="startCameraScan()">Camera</button>
        </div>
        <video id="qrVideo" style="display:none;width:100%;border-radius:8px;" playsinline muted></video>
        <div id="contactPills" style="display:flex;gap:6px;flex-wrap:wrap;"></div>
        <label>Amount (`XCR` — e.g. `4.95` or `0.25`)
          <input type="text" id="payAmount" value="4.95" />
        </label>
        <label>Recipient (`xcrstealth1_...`, `user@host:port`, or `@contact`)
          <input type="text" id="payTo" value="merchant-pos-terminal" class="mono" />
        </label>
        <div style="display:flex;gap:6px;">
          <input type="text" id="newAlias" placeholder="Save recipient as @name" style="max-width:165px;" />
          <button class="sec" onclick="saveContact()">Save Contact</button>
        </div>
        <label>Encrypted Stealth Memo (`<= 64B` X25519)
          <input type="text" id="payInvoice" value="POS-ZRH-COFFEE-0108" />
        </label>
        <label style="flex-direction:row;align-items:center;gap:8px;color:var(--text);">
          <input type="checkbox" id="payRegulated" checked />
          Attach ZK Proof of Innocence
        </label>
        <button onclick="tapPay()">Tap to Pay (672B Bulletproof + 65B Schnorr)</button>
        <div id="posResult" class="receipt">
          <span style="color:var(--muted)">Ready for 1-RTT payment (0.0005 XCR micro-fee).</span>
        </div>
      </div>

      <!-- 3. Live Auto-Confirming Merchant Register -->
      <div class="card">
        <h2>3. Live Merchant POS Register (QR Checkout)</h2>
        <div style="display:flex;gap:8px;">
          <label style="flex:1">Price (`XCR`)
            <input type="text" id="regAmount" value="4.50" />
          </label>
          <label style="flex:1">Order / Table Memo
            <input type="text" id="regMemo" value="Flat White #104" />
          </label>
        </div>
        <button onclick="createPosQr()">Generate Customer Checkout QR &amp; Watch Live</button>
        <div id="regQrWrap" style="display:none;text-align:center;gap:8px;">
          <div class="qr-box"><img id="regQrImg" alt="XCR Payment QR" /></div>
          <div class="mono" id="regUriText" style="margin-top:6px;color:var(--muted);"></div>
        </div>
        <div id="regStatus" class="receipt">
          <span style="color:var(--muted)">Displays customer `xcr:` QR and auto-confirms stealth arrival in ~250 ms.</span>
        </div>
      </div>

      <!-- 4. Encrypted Activity & Receipts Timeline -->
      <div class="card">
        <h2>4. Encrypted Activity &amp; Receipts (`XCRHIST1`)</h2>
        <div id="historyFeed" style="display:grid;gap:6px;max-height:265px;overflow-y:auto;">
          <span style="color:var(--muted);font-size:12px;">No activity recorded yet.</span>
        </div>
      </div>

      <!-- 5. Bearer Cash Links & Printable QR Gift Vouchers -->
      <div class="card">
        <h2>5. Bearer Cash Links &amp; QR Gift Vouchers</h2>
        <div style="display:flex;gap:8px;">
          <label style="flex:1">Gift Amount (`XCR`)
            <input type="text" id="vouchAmount" value="5.00" />
          </label>
          <label style="flex:1">Gift Note
            <input type="text" id="vouchMemo" value="Coffee on me!" />
          </label>
        </div>
        <button class="sec" onclick="mintVoucher()">Mint Shareable `xcr://claim#` QR Voucher</button>
        <div id="vouchOut" style="display:none;text-align:center;">
          <div class="qr-box"><img id="vouchQrImg" alt="Bearer Voucher QR" /></div>
          <input type="text" id="vouchUriBox" readonly onclick="this.select()" class="mono" style="margin-top:6px;" />
        </div>
        <div style="display:flex;gap:6px;">
          <input type="text" id="claimVouchInput" placeholder="Paste xcr://claim#<64-hex> to redeem" class="mono" />
          <button onclick="redeemVoucher()">Redeem</button>
        </div>
        <div class="mono" id="vouchStatus" style="color:var(--green);"></div>
      </div>

      <!-- 6. 24-Word Paper Backup & Savings Vault -->
      <div class="card">
        <h2>6. 24-Word Backup &amp; Post-Quantum Vault</h2>
        <div style="display:flex;gap:6px;">
          <button class="sec" style="flex:1" onclick="revealBackup()">Reveal 24 Words</button>
          <button class="sec" style="flex:1" onclick="restoreBackup()">Restore 24 Words</button>
        </div>
        <textarea id="backupBox" rows="2" class="mono" placeholder="24 lowercase recovery words..."></textarea>
        <div class="mono" id="backupStatus" style="color:var(--gold);"></div>
        <div class="row" style="border-top:1px solid var(--border);padding-top:8px;">
          <span>PQ Vault (24h Lock)</span><strong class="mono" id="vaultBal">--</strong>
        </div>
        <div style="display:flex;gap:6px;">
          <input type="number" id="vaultAmt" value="100" min="1" />
          <button class="sec" onclick="queueVault()">Queue Withdrawal</button>
        </div>
        <div id="vaultPending" style="display:grid;gap:6px;"></div>
      </div>

      <!-- 7. Pull-Free Subscriptions (1-Click Sovereign Cancel) -->
      <div class="card">
        <h2>7. Pull-Free Subscriptions (1-Click Cancel)</h2>
        <div style="display:flex;gap:6px;">
          <input type="text" id="subLabel" value="Cloud Pro" placeholder="Label" />
          <input type="text" id="subAmt" value="2.50" placeholder="XCR" style="max-width:90px;" />
        </div>
        <input type="text" id="subTo" value="saas-provider" placeholder="Recipient (`xcrstealth1_...` or `@handle`)" class="mono" />
        <div style="display:flex;gap:6px;">
          <button class="sec" style="flex:1" onclick="addSub()">Authorize Mandate</button>
          <button style="flex:1" onclick="runSubs()">Run Due Cycles</button>
        </div>
        <div id="subsList" style="display:grid;gap:6px;"></div>
      </div>

      <!-- 8. Multi-Recipient Batch & Split-Bill -->
      <div class="card">
        <h2>8. Multi-Recipient Batch &amp; Split-Bill</h2>
        <label>Batch Legs (`recipient:amount_xcr:memo`, comma-separated)
          <textarea id="batchBox" rows="2" class="mono">cafe-barista:3.50:Latte,cafe-tipjar:0.50:Tip</textarea>
        </label>
        <button onclick="sendBatch()">Execute Multi-Recipient Batch</button>
        <div class="mono" id="batchOut" style="color:var(--green);"></div>
      </div>

      <!-- 9. 2-of-3 Shamir Guardians · Air-Gap Signer · Web Embed -->
      <div class="card">
        <h2>9. 2-of-3 Shamir · Cold Signer · Web Widget</h2>
        <div style="display:flex;gap:6px;">
          <button class="sec" style="flex:1" onclick="splitShamir()">Split 2-of-3 Shares</button>
          <button class="sec" style="flex:1" onclick="combineShamir()">Combine 2 Shares</button>
        </div>
        <textarea id="shamirBox" rows="2" class="mono" placeholder="xcrshare1_... Guardian Shares"></textarea>
        <div style="display:flex;gap:6px;">
          <input type="text" id="coldIn" placeholder="Paste xcrunsigned1_... to offline-sign" class="mono" />
          <button class="sec" onclick="coldSignUi()">Cold-Sign</button>
        </div>
        <label>3-Line Merchant Website Embed (`0%` Card Fees)
          <input type="text" readonly onclick="this.select()" class="mono" value='&lt;script src="/embed/xcr-checkout.js"&gt;&lt;/script&gt;&lt;div class="xcr-pay-button" data-amount="4.95" data-memo="Order"&gt;&lt;/div&gt;' />
        </label>
      </div>

      <!-- 10. K-of-N FROST Threshold Schnorr Multi-Sig -->
      <div class="card">
        <h2>10. 2-of-3 FROST Threshold Multi-Sig (0B Overhead)</h2>
        <button class="sec" onclick="splitFrost()">Generate 2-of-3 FROST Co-Signing Shares</button>
        <textarea id="frostBox" rows="2" class="mono" placeholder="xcrfrost1_... Curve25519 scalar shares (never reconstructs key)"></textarea>
      </div>

      <!-- 11. HTLC Atomic Swaps & Streaming PayChan -->
      <div class="card">
        <h2>11. HTLC Atomic Swaps &amp; PayChan Streaming</h2>
        <div style="display:flex;gap:6px;">
          <input type="text" id="htlcAmt" value="5.00" placeholder="XCR" style="max-width:85px;" />
          <input type="text" id="htlcAsset" value="BTC-LN" style="max-width:85px;" />
          <button onclick="lockHtlcSwap()" style="flex:1">Lock HTLC + Swap Offer</button>
        </div>
        <div style="display:flex;gap:6px;">
          <button class="sec" style="flex:1" onclick="openChan()">Open 5 XCR PayChan</button>
          <button class="sec" style="flex:1" onclick="tickChan()">Stream Tick</button>
          <button style="flex:1" onclick="closeChan()">Settle</button>
        </div>
        <textarea id="chanBox" rows="2" class="mono" placeholder="Channel ID / xcrchan1_... off-chain streaming voucher"></textarea>
      </div>

      <!-- 12. Pre-Authorized Up-To-Max Digital Checks -->
      <div class="card">
        <h2>12. Pre-Authorized Up-To-Max Digital Checks</h2>
        <div style="display:flex;gap:6px;">
          <input type="text" id="chkMax" value="25.00" placeholder="Max XCR" style="max-width:90px;" />
          <button class="sec" style="flex:1" onclick="issueCheck()">Issue Check</button>
          <button style="flex:1" onclick="cashCheck()">Cash</button>
          <button class="warn" onclick="cancelCheck()">Void</button>
        </div>
        <textarea id="chkBox" rows="2" class="mono" placeholder="xcrcheck1_... (funds stay in Pocket until cashed)"></textarea>
      </div>

      <!-- 13. CredScript Smart Vaults · Session Keys · Native Assets -->
      <div class="card">
        <h2>13. CredScript · Session Keys · Native Assets</h2>
        <div style="display:flex;gap:6px;">
          <button class="sec" style="flex:1" onclick="issueSessionKey()">Issue 5 XCR Session Key</button>
          <button style="flex:1" onclick="mintNativeAsset()">Mint Native Asset</button>
        </div>
        <textarea id="wave8Box" rows="2" class="mono" placeholder="xcrsk1_... Session Key or Native Bearer Asset ID"></textarea>
      </div>

      <!-- 14. Assurance Crowdfunding & JSON-RPC 2.0 / Supply Audit -->
      <div class="card">
        <h2>14. Crowdfunding · Supply Audit · JSON-RPC 2.0</h2>
        <div style="display:flex;gap:6px;">
          <button class="sec" style="flex:1" onclick="runSupplyAudit()">Run Formal Supply Audit</button>
          <button style="flex:1" onclick="testJsonRpc()">Test POST /rpc</button>
        </div>
        <textarea id="rpcAuditBox" rows="2" class="mono" placeholder="POST /rpc JSON-RPC 2.0 &amp; Cardano-style conservation audit"></textarea>
      </div>

      <!-- 15. Native DEX Orderbook · @name.xcr · Babel Fees -->
      <div class="card">
        <h2>15. Native DEX · @name.xcr Handles · Babel Fees</h2>
        <div style="display:flex;gap:6px;">
          <input type="text" id="xcrHandleLookup" value="@alice.xcr" style="max-width:120px;" />
          <button class="sec" style="flex:1" onclick="lookupOnchainHandle()">Resolve @name.xcr</button>
          <button style="flex:1" onclick="loadDexBook()">Orderbook</button>
        </div>
        <textarea id="dexHandleBox" rows="2" class="mono" placeholder="On-chain @name.xcr resolution &amp; XRPL-style limit orderbook"></textarea>
      </div>

      <!-- 16. Voltaire DRep Governance · 1-of-1 Artifacts · EAS -->
      <div class="card">
        <h2>16. Voltaire Governance · Artifacts · Zero-PII EAS</h2>
        <div style="display:flex;gap:6px;">
          <button class="sec" style="flex:1" onclick="loadGovernance()">Governance Tally</button>
          <button style="flex:1" onclick="loadArtifacts()">Artifacts &amp; EAS</button>
        </div>
        <textarea id="govArtBox" rows="2" class="mono" placeholder="CIP-1694 Constitutional DRep tallies, 1-of-1 deeds &amp; EAS claims"></textarea>
      </div>

      <!-- 17. Shielded RingCT · AMM Smart Router · Oracles · Blinks -->
      <div class="card">
        <h2>17. RingCT Shielded Pool · AMM · Oracles · Blinks</h2>
        <div style="display:flex;gap:6px;">
          <button class="sec" style="flex:1" onclick="loadShieldedPool()">RingCT Pool</button>
          <button class="sec" style="flex:1" onclick="loadAmmOracles()">AMM &amp; Oracles</button>
          <button style="flex:1" onclick="previewBlinkCard()">Blink Card</button>
        </div>
        <textarea id="wave11Box" rows="2" class="mono" placeholder="MLSAG RingCT pool, Uniswap x*y=k AMM, median oracles &amp; /api/blink"></textarea>
      </div>
    </div>
  </div>

  <script>
    const CSRF = "__XCR_CSRF_TOKEN__";
    let posWatchTimer = null;

    function apiPost(url) {
      return fetch(url, { method: 'POST', headers: { 'X-XCR-Token': CSRF } }).then(x => x.json());
    }

    function showToast(msg) {
      const t = document.getElementById('toast');
      t.textContent = msg;
      t.style.display = 'block';
      setTimeout(() => { t.style.display = 'none'; }, 5500);
    }

    async function refresh() {
      const r = await fetch('/api/state').then(x => x.json());
      document.getElementById('epochPill').textContent = `Epoch ${r.epoch} (${r.phase})`;
      document.getElementById('supplyPill').textContent = `Supply: ${r.circulating_supply}`;
      document.getElementById('burnPill').textContent = `Burned: ${r.total_burned}`;
      const lp = document.getElementById('lockPill');
      if (r.locked) {
        lp.textContent = '🔒 Locked (XCRENC01)';
        lp.style.color = 'var(--gold)';
      } else {
        lp.textContent = r.encrypted_on_disk ? '🔓 Encrypted & Unlocked' : '🔓 Unlocked';
        lp.style.color = 'var(--green)';
      }
      document.getElementById('pocketBal').textContent = r.pocket_balance;
      if (r.pocket_address) document.getElementById('pocketAddr').textContent = r.pocket_address;
      if (r.stealth_uri) document.getElementById('stealthUri').value = r.stealth_uri;
      document.getElementById('dailyCap').textContent = `${r.pocket_daily_spent} / ${r.pocket_daily_limit}`;
      document.getElementById('pocketNonce').textContent = r.pocket_nonce;
      document.getElementById('vaultBal').textContent = r.vault_balance;

      const box = document.getElementById('vaultPending');
      box.innerHTML = '';
      (r.vault_pending || []).forEach(w => {
        const div = document.createElement('div');
        div.className = 'receipt';
        div.innerHTML = `<div class="row"><span>#${w.id}: <b>${w.amount}</b></span>
          <button class="warn" style="padding:4px 8px;font-size:11px;" onclick="cancelVault(${w.id})">Cancel</button></div>`;
        box.appendChild(div);
      });

      const hist = await fetch('/api/history').then(x => x.json()).catch(() => ({ entries: [] }));
      const hbox = document.getElementById('historyFeed');
      if (hist.entries && hist.entries.length > 0) {
        hbox.innerHTML = hist.entries.slice().reverse().map(e => `
          <div class="receipt">
            <div class="row"><strong style="color:${e.kind.includes('in') || e.kind === 'received' ? 'var(--green)' : 'var(--gold)'}">${e.kind.toUpperCase()}</strong><span class="mono">${e.amount}</span></div>
            ${e.memo ? `<div>Memo: <b>${e.memo}</b></div>` : ''}
            <div class="mono" style="color:var(--muted)">${e.reference}</div>
          </div>
        `).join('');
      }

      const cRes = await fetch('/api/contacts').then(x => x.json()).catch(() => ({ contacts: [] }));
      const cBox = document.getElementById('contactPills');
      cBox.innerHTML = (cRes.contacts || []).map(c =>
        `<span class="chip-btn" onclick="document.getElementById('payTo').value='@${c.alias}'">@${c.alias}</span>`
      ).join('');

      const sRes = await fetch('/api/subs').then(x => x.json()).catch(() => ({ mandates: [] }));
      const sBox = document.getElementById('subsList');
      sBox.innerHTML = (sRes.mandates || []).map(m => `
        <div class="receipt">
          <div class="row"><span><b>#${m.id} ${m.label}</b> (${m.amount})</span>
            ${m.active ? `<button class="warn" style="padding:3px 8px;font-size:11px;" onclick="cancelSub(${m.id})">Cancel</button>` : '<span style="color:var(--muted)">Cancelled</span>'}
          </div>
          <div class="mono" style="color:var(--muted)">Cycles paid: ${m.cycles} · To: ${m.recipient}</div>
        </div>
      `).join('');
    }

    function parseXcrUriIntoFields(raw) {
      const s = raw.trim();
      if (s.startsWith('xcr://claim#')) {
        document.getElementById('claimVouchInput').value = s;
        return;
      }
      const body = s.startsWith('xcr:') ? s.slice(4) : s;
      const [dest, q] = body.split('?');
      if (dest) document.getElementById('payTo').value = decodeURIComponent(dest);
      if (q) {
        const params = new URLSearchParams(q);
        if (params.get('chips')) document.getElementById('payAmount').value = (Number(params.get('chips')) / 100).toFixed(2);
        if (params.get('bits')) document.getElementById('payAmount').value = (Number(params.get('bits')) / 1000000).toFixed(6);
        const inv = params.get('inv') || '';
        const memo = params.get('memo') || '';
        const combined = inv && memo ? `${inv}: ${memo}` : (inv || memo);
        if (combined) document.getElementById('payInvoice').value = combined;
      }
    }

    function applyScannedUri() { parseXcrUriIntoFields(document.getElementById('scanInput').value); }

    async function startCameraScan() {
      const video = document.getElementById('qrVideo');
      if (!('BarcodeDetector' in window) || !navigator.mediaDevices) {
        alert('Paste any `xcr:` URI into the input box on browsers without BarcodeDetector.');
        return;
      }
      const stream = await navigator.mediaDevices.getUserMedia({ video: { facingMode: 'environment' } });
      video.srcObject = stream;
      video.style.display = 'block';
      await video.play();
      const detector = new BarcodeDetector({ formats: ['qr_code'] });
      const timer = setInterval(async () => {
        const codes = await detector.detect(video).catch(() => []);
        if (codes.length > 0) {
          clearInterval(timer);
          stream.getTracks().forEach(t => t.stop());
          video.style.display = 'none';
          document.getElementById('scanInput').value = codes[0].rawValue;
          parseXcrUriIntoFields(codes[0].rawValue);
        }
      }, 250);
    }

    async function encryptOrUnlock() {
      const pw = encodeURIComponent(document.getElementById('walletPass').value);
      const r = await apiPost(`/api/wallet/unlock?password=${pw}`);
      document.getElementById('lightOut').textContent = r.message || (r.ok ? '✓ Keystore ready' : r.error);
      await refresh();
    }

    async function lockWallet() {
      await apiPost('/api/wallet/lock');
      document.getElementById('lightOut').textContent = '🔒 Master seed scrubbed from RAM';
      await refresh();
    }

    async function saveContact() {
      const alias = encodeURIComponent(document.getElementById('newAlias').value);
      const uri = encodeURIComponent(document.getElementById('payTo').value);
      const r = await apiPost(`/api/contacts/add?alias=${alias}&uri=${uri}`);
      document.getElementById('lightOut').textContent = r.saved ? `✓ Saved contact @${r.alias}` : `Error: ${r.error}`;
      document.getElementById('newAlias').value = '';
      await refresh();
    }

    async function tapPay() {
      const amt = encodeURIComponent(document.getElementById('payAmount').value);
      const inv = encodeURIComponent(document.getElementById('payInvoice').value);
      const to = encodeURIComponent(document.getElementById('payTo').value);
      const reg = document.getElementById('payRegulated').checked ? '1' : '0';
      const res = await apiPost(`/api/pay?amount=${amt}&invoice=${inv}&to=${to}&regulated=${reg}`);
      const box = document.getElementById('posResult');
      if (res.accepted) {
        box.innerHTML = `
          <div style="color:var(--green);font-weight:700;">✓ 1-RTT FINALIZED (${res.latency_ms} ms | ${res.bulletproof_bytes}B Bulletproof)</div>
          <div class="mono">Tx: ${res.tx_id.slice(0, 24)}...</div>
          <div>Fee: <b>${res.fee_worker}</b> worker + <b>${res.fee_endurance}</b> endurance + <b>${res.fee_burned}</b> burned</div>
          <div>Encrypted Memo: <b>${res.decrypted_invoice}</b></div>
        `;
      } else {
        box.innerHTML = `<div style="color:var(--danger);font-weight:700;">Rejected: ${res.error}</div>`;
      }
      await refresh();
    }

    async function createPosQr() {
      const amt = encodeURIComponent(document.getElementById('regAmount').value);
      const memo = encodeURIComponent(document.getElementById('regMemo').value);
      const inv = 'POS-' + Math.floor(1000 + Math.random() * 9000);
      const r = await fetch(`/api/invoice-uri?amount=${amt}&invoice=${inv}&memo=${memo}`).then(x => x.json());
      document.getElementById('regQrImg').src = `/api/qr.svg?data=${encodeURIComponent(r.uri)}`;
      document.getElementById('regUriText').textContent = r.uri.slice(0, 52) + '…';
      document.getElementById('regQrWrap').style.display = 'block';
      document.getElementById('regStatus').innerHTML = `<span style="color:var(--gold)">Watching 1-byte view tags for <b>${inv}</b> (${decodeURIComponent(amt)} XCR)...</span>`;
      if (posWatchTimer) clearInterval(posWatchTimer);
      posWatchTimer = setInterval(async () => {
        const sc = await apiPost('/api/scan-stealth');
        if (sc.claimed > 0) {
          clearInterval(posWatchTimer);
          posWatchTimer = null;
          const note = (sc.memos && sc.memos.length) ? sc.memos.join(' · ') : inv;
          document.getElementById('regStatus').innerHTML = `<div class="paid-banner">✓ PAID &amp; SETTLED: +${sc.amount}<br/><span class="mono">${note}</span></div>`;
          await refresh();
        }
      }, 1500);
    }

    async function mintVoucher() {
      const amt = encodeURIComponent(document.getElementById('vouchAmount').value);
      const memo = encodeURIComponent(document.getElementById('vouchMemo').value);
      const res = await apiPost(`/api/voucher/create?amount=${amt}&memo=${memo}`);
      if (res.accepted) {
        document.getElementById('vouchQrImg').src = `/api/qr.svg?data=${encodeURIComponent(res.uri)}`;
        document.getElementById('vouchUriBox').value = res.uri;
        document.getElementById('vouchOut').style.display = 'block';
        document.getElementById('vouchStatus').textContent = `✓ Locked voucher (${res.latency_ms} ms — saved in History)`;
        await refresh();
      } else {
        document.getElementById('vouchStatus').textContent = `Error: ${res.error}`;
      }
    }

    async function redeemVoucher() {
      const uri = encodeURIComponent(document.getElementById('claimVouchInput').value);
      const res = await apiPost(`/api/voucher/claim?uri=${uri}`);
      if (res.accepted) {
        document.getElementById('vouchStatus').textContent = `✓ Redeemed +${res.amount} into Pocket!`;
        await refresh();
      } else {
        document.getElementById('vouchStatus').textContent = `Claim failed: ${res.error}`;
      }
    }

    async function revealBackup() {
      const res = await fetch('/api/backup').then(x => x.json());
      if (res.words) {
        document.getElementById('backupBox').value = res.words;
        document.getElementById('backupStatus').textContent = 'Write these 24 words on paper (never share online).';
      } else {
        document.getElementById('backupStatus').textContent = res.error || 'Unlock wallet first.';
      }
    }

    async function restoreBackup() {
      const w = encodeURIComponent(document.getElementById('backupBox').value);
      const res = await apiPost(`/api/recover?words=${w}`);
      document.getElementById('backupStatus').textContent = res.recovered
        ? `✓ Restored Pocket ${res.pocket_address}`
        : `Error: ${res.error}`;
      await refresh();
    }

    async function verifyLight() {
      const res = await fetch('/api/light-verify').then(x => x.json());
      document.getElementById('lightOut').textContent =
        `✓ Merkle verified (${res.proof_bytes}B, root ${res.root.slice(0, 14)}...)`;
    }

    async function scanStealth() {
      const res = await apiPost('/api/scan-stealth');
      const m = (res.memos && res.memos.length) ? ` [${res.memos.join(', ')}]` : '';
      document.getElementById('lightOut').textContent =
        `✓ Scanned ${res.scanned} -> Claimed ${res.claimed} (${res.amount})${m}`;
      await refresh();
    }

    async function claimFaucet() { await apiPost('/api/faucet'); await refresh(); }
    async function queueVault() { await apiPost(`/api/vault/queue?credits=${document.getElementById('vaultAmt').value}`); await refresh(); }
    async function cancelVault(id) { await apiPost(`/api/vault/cancel?id=${id}`); await refresh(); }

    async function addSub() {
      const l = encodeURIComponent(document.getElementById('subLabel').value);
      const t = encodeURIComponent(document.getElementById('subTo').value);
      const a = encodeURIComponent(document.getElementById('subAmt').value);
      await apiPost(`/api/subs/add?label=${l}&to=${t}&amount=${a}&interval=2592000`);
      await refresh();
    }
    async function cancelSub(id) { await apiPost(`/api/subs/cancel?id=${id}`); await refresh(); }
    async function runSubs() {
      const r = await apiPost('/api/subs/run');
      showToast(`✓ Executed ${r.paid || 0} due subscription(s)`);
      await refresh();
    }
    async function sendBatch() {
      const b = encodeURIComponent(document.getElementById('batchBox').value);
      const r = await apiPost(`/api/pay-multi?batch=${b}`);
      document.getElementById('batchOut').textContent = r.ok ? `✓ Settled ${r.settled} batch payments!` : `Error: ${r.error}`;
      await refresh();
    }
    async function splitShamir() {
      const r = await apiPost('/api/shamir/split?k=2&n=3');
      if (r.ok) document.getElementById('shamirBox').value = r.shares.join('\n');
    }
    async function combineShamir() {
      const s = encodeURIComponent(document.getElementById('shamirBox').value);
      const r = await apiPost(`/api/shamir/combine?shares=${s}`);
      showToast(r.ok ? `✓ Reconstructed Pocket ${r.pocket_address}` : `Error: ${r.error}`);
      await refresh();
    }
    async function coldSignUi() {
      const u = encodeURIComponent(document.getElementById('coldIn').value);
      const r = await apiPost(`/api/cold/sign?unsigned=${u}`);
      document.getElementById('coldIn').value = r.ok ? r.signed_uri : (r.error || 'Failed');
    }
    async function splitFrost() {
      const r = await apiPost('/api/frost/split?k=2&n=3');
      document.getElementById('frostBox').value = r.ok ? r.shares.join('\n') : (r.error || 'Failed');
    }
    let activeChanId = '';
    async function lockHtlcSwap() {
      const a = encodeURIComponent(document.getElementById('htlcAmt').value);
      const s = encodeURIComponent(document.getElementById('htlcAsset').value);
      const r = await apiPost(`/api/htlc/lock?amount=${a}&asset=${s}&counter=0.001`);
      document.getElementById('chanBox').value = r.ok ? `HTLC=${r.escrow_id}\nPREIMAGE=${r.preimage}` : r.error;
      await refresh();
    }
    async function openChan() {
      const r = await apiPost('/api/paychan/open?amount=5.00');
      if (r.ok) { activeChanId = r.channel_id; document.getElementById('chanBox').value = r.channel_id; }
      await refresh();
    }
    async function tickChan() {
      const cid = activeChanId || document.getElementById('chanBox').value.trim();
      const r = await apiPost(`/api/paychan/tick?cid=${encodeURIComponent(cid)}&amount=1.25`);
      if (r.ok) document.getElementById('chanBox').value = r.voucher;
    }
    async function closeChan() {
      const v = encodeURIComponent(document.getElementById('chanBox').value.trim());
      const r = await apiPost(`/api/paychan/close?voucher=${v}`);
      showToast(r.message || 'Closed');
      await refresh();
    }
    async function issueCheck() {
      const m = encodeURIComponent(document.getElementById('chkMax').value);
      const r = await apiPost(`/api/check/issue?amount=${m}`);
      if (r.ok) document.getElementById('chkBox').value = r.uri;
    }
    async function cashCheck() {
      const u = encodeURIComponent(document.getElementById('chkBox').value.trim());
      const m = encodeURIComponent(document.getElementById('chkMax').value);
      const r = await apiPost(`/api/check/cash?uri=${u}&amount=${m}`);
      showToast(r.message || r.error);
      await refresh();
    }
    async function cancelCheck() {
      const u = encodeURIComponent(document.getElementById('chkBox').value.trim());
      const r = await apiPost(`/api/check/cancel?uri=${u}`);
      showToast(r.message || r.error);
      await refresh();
    }
    async function issueSessionKey() {
      const r = await apiPost('/api/session/issue?amount=5.00');
      document.getElementById('wave8Box').value = r.ok ? r.uri : (r.error || 'Failed');
    }
    async function mintNativeAsset() {
      const t = 'VIP' + Math.floor(100 + Math.random() * 900);
      const r = await apiPost(`/api/asset/mint?ticker=${t}&supply=1000`);
      document.getElementById('wave8Box').value = r.ok ? `${t} AssetID=${r.asset_id}` : (r.error || 'Failed');
      await refresh();
    }
    async function runSupplyAudit() {
      const res = await fetch('/rpc', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'xcr_supplyAudit' })
      }).then(x => x.json());
      document.getElementById('rpcAuditBox').value = JSON.stringify(res.result || res.error);
    }
    async function testJsonRpc() {
      const res = await fetch('/rpc', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ jsonrpc: '2.0', id: 2, method: 'xcr_chainInfo' })
      }).then(x => x.json());
      document.getElementById('rpcAuditBox').value = JSON.stringify(res.result || res.error);
    }
    async function lookupOnchainHandle() {
      const n = document.getElementById('xcrHandleLookup').value.trim();
      const res = await fetch('/rpc', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ jsonrpc: '2.0', id: 3, method: 'xcr_resolveName', params: { name: n } })
      }).then(x => x.json());
      document.getElementById('dexHandleBox').value = JSON.stringify(res.result || res.error);
    }
    async function loadDexBook() {
      const res = await fetch('/rpc', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ jsonrpc: '2.0', id: 4, method: 'xcr_getOrderbook' })
      }).then(x => x.json());
      document.getElementById('dexHandleBox').value = JSON.stringify(res.result || res.error);
    }
    async function loadGovernance() {
      const res = await fetch('/rpc', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ jsonrpc: '2.0', id: 5, method: 'xcr_getGovernance' })
      }).then(x => x.json());
      document.getElementById('govArtBox').value = JSON.stringify(res.result || res.error);
    }
    async function loadArtifacts() {
      const res = await fetch('/rpc', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ jsonrpc: '2.0', id: 6, method: 'xcr_getArtifacts' })
      }).then(x => x.json());
      document.getElementById('govArtBox').value = JSON.stringify(res.result || res.error);
    }
    async function loadShieldedPool() {
      const res = await fetch('/rpc', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ jsonrpc: '2.0', id: 7, method: 'xcr_getShieldedPool' })
      }).then(x => x.json());
      document.getElementById('wave11Box').value = JSON.stringify(res.result || res.error);
    }
    async function loadAmmOracles() {
      const res = await fetch('/rpc', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ jsonrpc: '2.0', id: 8, method: 'xcr_getAmmPools' })
      }).then(x => x.json());
      document.getElementById('wave11Box').value = JSON.stringify(res.result || res.error);
    }
    async function previewBlinkCard() {
      const r = await fetch('/api/blink?amount=5.00&label=OneClickAction').then(x => x.json());
      document.getElementById('wave11Box').value = JSON.stringify(r);
    }

    // Background Zero-Click Stealth Auto-Sweep every 4 seconds:
    setInterval(async () => {
      if (posWatchTimer) return;
      const sc = await apiPost('/api/scan-stealth').catch(() => ({ claimed: 0 }));
      if (sc.claimed > 0) {
        const note = (sc.memos && sc.memos.length) ? ` — "${sc.memos.join(', ')}"` : '';
        showToast(`✓ Auto-Received +${sc.amount}${note}`);
        await refresh();
      }
    }, 4000);

    refresh();
  </script>
</body>
</html>
"##;
