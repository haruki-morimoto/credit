# Getting Started with Credits (`∀` / `XCR`)

Welcome to **Credits** — instant, private digital cash that your own computer can earn automatically in the background, with zero bank accounts, zero sign-up forms, and zero insider premine.

---

## 1. Install Credits Desktop in 1 Click (Windows)

Run the included installer script in PowerShell:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\install-desktop.ps1
```

This installs `credit-desktop.exe` into `%LOCALAPPDATA%\Programs\Credits` and places a **`Credits Wallet & Miner`** icon directly on your **Desktop** and **Start Menu**.

> **macOS & Linux Users:** Run `cargo run --release -p credit-desktop` from the repository folder to launch the same native `egui` desktop app.

---

## 2. First-Launch Setup (30 Seconds)

When you open **Credits Wallet & Miner** for the first time, a 3-step guided setup walks you through everything:

1. **Create Your Personal Wallet:** Optionally add a password (`XCRENC01` memory-hard encryption) to lock spending on shared computers. Even while locked, your computer can continue earning Credits safely in the background.
2. **Save Your 24 Recovery Words:** Write down or save your 24-word recovery card offline. Because Credits has no central company or password-reset server, these 24 words are the master key to restore your money if you ever replace your computer.
3. **Start Earning Automatically:** Leave **"Join the network & earn Credits automatically"** and **"Auto-start earning real Mainnet XCR on Jan 1, 2027"** checked, then click **Start Earning & Open Wallet**.

---

## 3. How Automatic Earning Scales With Your Computer

Credits has **`∀ 0.000000 XCR` premine** — 100% of coins are earned every 60 seconds by computers running the network:

- **No Mining Pools Needed:** Even a lightweight laptop earns solo payouts directly into your wallet every 60 seconds.
- **Rewards Scale With CPU Contribution:** Contributing more CPU compute discovers deeper memory-hard `PoNC` shares with higher cryptographic weight (`Wt`), earning a proportionally larger share of each 60-second epoch reward.
- **Live Power Mode Selector:** On the **Home & Earnings** tab, switch anytime with one click:
  - **🌱 Eco (`1` Core):** Whisper-quiet background mode while working or on battery.
  - **⚖ Balanced (`50%` of Cores):** Default everyday balance of responsive desktop use and strong rewards.
  - **🚀 Max (`100%` of Cores):** Full multi-core hashpower when your PC is idle or overnight.
- **🎮 Automatic GPU ZK Boost (`0W` When Idle):** Credits Desktop automatically detects your graphics card via `wgpu` (DirectX 12 on Windows, Metal on macOS, Vulkan on Linux). Base coin mining stays CPU-only so laptop users aren't crowded out by GPU warehouses, while your GPU sleeps at **0W** when traffic is quiet and automatically accelerates Tier-2 `RecursiveZkState` transaction proving whenever real payments flow on the network.

---

## 4. Sending, Receiving & Gift Links

- **3 Free Transfers Every Day:** Your first **3 sends every UTC day cost `∀ 0.000000 XCR` in fees** automatically via your daily Bandwidth quota. Additional sends cost a tiny fraction of a cent (`~0.0005 XCR`) and settle in **~200 milliseconds**.
- **Friendly `@username.xcr` Handles:** Claim a memorable name like `@alice.xcr` on the Home tab so friends can pay `@alice.xcr` instead of copying hex addresses.
- **Gift Links (`xcrdrop1_...`):** Want to send Credits to a friend who hasn't installed the app yet? On the **Send & Receive** tab, create a **Gift Link** and text or email it to them. The moment they install Credits and paste the link, the money sweeps straight into their wallet.

---

## 5. Protecting Savings Against Scams (`24-Hour Savings Vault`)

Keep everyday spending money in your main **Wallet Pocket**, and move larger long-term holdings into the **🛡 Savings Vault** tab:

- Withdrawals from your Savings Vault enforce a **24-hour safety timer**.
- If anyone ever steals your laptop or tricks you into authorizing a withdrawal, click **🚨 Emergency Undo / Cancel** inside the 24-hour window to cancel the transfer and restore 100% of your funds immediately.

---

## 6. Practice Network Today → Real Mainnet on 1 January 2027

- **Right Now:** Your app connects to the live global **Practice Network** (`xcr-testnet-beta-2027`) so you can test earning, sending, Gift Links, and Safety Vault protection freely.
- **Friday, 1 January 2027 at `00:00:00 UTC`:** Credits **Mainnet (`xcr-mainnet-2027`)** unlocks automatically on the first Bitcoin block mined in 2027 (`∀ 0.000000 XCR` starting supply), and armed Desktop apps & servers transition into real Mainnet earning automatically.

---

## 7. Automatic Signed App Updates (Zero Manual Re-Downloads)

You never need to hunt for new installers when **Credits Desktop** is improved:
- In the background, the app checks for new releases, verifies both the **256-bit SHA-256 binary hash** and **offline Curve25519 release signature** against the pinned release public key (`7c597663533b...`), and stages the update automatically.
- Whenever an update is ready, a **`✨ Update Ready — Restart`** button appears in the top bar — one click swaps the binary in place and reopens the new version in ~1 second without losing your wallet or settings.
