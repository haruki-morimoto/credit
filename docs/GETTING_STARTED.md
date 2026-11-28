# Getting Started with Credits (`∀` / `XCR`)

Welcome to **Credits**. This guide walks you through installing **Credits Desktop**, setting up your personal wallet, managing multiple currencies, protecting long-term savings, and participating in the network.

---

## 1. Installing Credits Desktop

On Windows, please run the included installer script in PowerShell:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\install-desktop.ps1
```

This places `credit-desktop.exe` in `%LOCALAPPDATA%\Programs\Credits` and adds a **`Credits Wallet & Miner`** shortcut to your Desktop and Start Menu.

> **macOS & Linux:** You can launch the same native `egui` desktop application directly from source with `cargo run --release -p credit-desktop`.

---

## 2. First-Launch Setup

When you open **Credits Wallet & Miner** for the first time, a short three-step guide helps you configure your wallet:

1. **Create Your Wallet:** You may optionally set a password (`XCRENC01` memory-hard encryption) to lock spending on shared computers. Even while locked, background network earning can continue safely.
2. **Save Your 24 Recovery Words:** Please write down your 24 recovery words or save the backup card in a safe offline place. Because Credits is non-custodial and has no central account server, these 24 words are the only way to restore your wallet on a new device.
3. **Enable Network Participation:** Leave **"Join the network & earn Credits automatically"** and **"Auto-start earning real Mainnet XCR on Jan 1, 2027"** selected if you would like your computer to earn rewards automatically.

---

## 3. Managing Your Currencies (`Wallet` Tab)

The **Wallet** tab provides a single, organized view of every currency and asset you hold:

- **Credits (`XCR`) Balances:** Clearly separates your immediately spendable **Pocket** balance, your 24-hour protected **Safety Vault** balance, and any **Shielded Pool** holdings.
- **Native Currencies & Assets:** Lists every Layer-1 token you own (such as `USDX`, `BTCX`, `GOLD`, or community-issued assets), alongside live reference prices, estimated `XCR` value, and direct **Send** and **Trade** buttons.
- **Privacy Toggle (`Hide Figures`):** Whenever you are in a public space or sharing your screen, click **Hide Figures** in the top bar to mask all balances and activity amounts across the application.

---

## 4. Sending, Receiving & Gift Links

- **Free Daily Transfers:** Your first **3 standard transfers each UTC day carry zero network fee (`∀ 0.000000 XCR`)**. Additional transfers typically cost a fraction of a cent and finalize in roughly `200 ms`.
- **Readable `@username.xcr` Handles:** You can register a friendly name such as `@alice.xcr` on the Home tab so contacts do not need to copy hexadecimal addresses.
- **Shareable Gift Links (`xcrdrop1_...`):** On the **Send & Receive** tab, you can create a Gift Link for friends or family who have not installed Credits yet; once they install the app and paste the link, the funds are claimed directly into their wallet.

---

## 5. Built-In Sovereign Exchange (`Exchange` Tab)

Credits Desktop includes a non-custodial **Exchange** tab so you can trade without depositing funds with a third party:

- **Instant Swap & Pro Orderbook:** Automatically routes swaps across both the on-chain Limit Orderbook and Constant-Product AMM liquidity pools for optimal pricing, or lets you place custom limit and `Immediate-Or-Cancel` orders.
- **Automated Spread Bot:** An optional built-in market-maker that quotes two-sided spreads using a scoped `DexTradeOnly` proxy key with zero withdrawal permissions.
- **Cross-Chain Atomic Swaps & P2P Fiat Escrow:** Supports bridge-free `SHA-256` HTLC swaps (`BTC`, Lightning `BOLT-11` invoices, `ETH`, `USDT`/`USDC`) as well as peer-to-peer bank transfer escrows secured by `2-of-3` `CredScript` security deposits and zero-PII trade reputation.

---

## 6. 24-Hour Safety Vault

We recommend keeping everyday spending money in your **Available Wallet Balance** and moving larger savings into the **Safety Vault** tab:

- Vault withdrawals observe a **24-hour cooling period** with a live countdown progress bar on both the Home and Safety Vault screens.
- Vault funds are automatically excluded from Exchange orders and automated trading budgets.
- If an unauthorized withdrawal is ever queued, clicking **Emergency Undo / Cancel** within the 24-hour window immediately cancels the withdrawal and restores your full Vault balance.

---

## 7. Background Earning & Automatic Updates

- **Adjustable Compute Modes:** On the **Home & Earnings** tab, you can switch anytime between **Eco** (`1` CPU core), **Balanced** (`50%` of cores), and **Max** (`100%` of cores). Graphics cards remain at `0W` idle when network traffic is quiet and assist with zero-knowledge proving only when transactions are active.
- **Practice Network & Mainnet Launch:** Today, your app connects to the public **Practice Network** (`xcr-testnet-beta-2027`). On **Friday, 1 January 2027 at `00:00:00 UTC`**, Credits **Mainnet** (`xcr-mainnet-2027`) unlocks automatically on the first Bitcoin block mined in 2027.
- **Signed In-App Updates:** Updates are verified against a pinned Curve25519 release public key (`7c597663533b...`) and full SHA-256 binary checksum before showing an **`Update Ready — Restart`** button in the top bar for one-click upgrades.

Thank you for trying Credits. If you have questions or suggestions, feedback is always welcome on GitHub.
