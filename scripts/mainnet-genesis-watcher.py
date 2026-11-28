#!/usr/bin/env python3
"""
Autonomous Fair-Launch Mainnet Genesis Beacon Watcher (`2027-01-01T00:00:00Z`).

- Sleeps with 0% CPU until Friday, 1 January 2027 at 00:00:00 UTC (`Unix 1798761600`).
- Once the Genesis window opens, queries 4 independent public Bitcoin block APIs
  (`mempool.space`, `blockstream.info`, `mempool.emzy.de`, `blockchain.info`) to locate
  the globally unique FIRST Bitcoin block mined with `timestamp >= 1798761600`
  (verifying `parent_block.timestamp < 1798761600`).
- Requires >= 2 independent sources to agree on `(height, block_hash_64_hex)`, then
  invokes `credit-cli unlock-genesis` on `127.0.0.1:9500`, unlocking Mainnet `Epoch 0`
  and gossiping the beacon across the global mesh automatically.
"""

import json
import os
import subprocess
import sys
import time
import urllib.request

MAINNET_GENESIS_UNIX = 1_798_761_600  # 2027-01-01T00:00:00Z
NODE_ADDR = os.environ.get("XCR_MAINNET_RPC", "127.0.0.1:9500")
CLI_BIN = os.environ.get("XCR_CLI_BIN", "/usr/local/bin/credit-cli")
BEACON_DONE_FILE = os.environ.get(
    "XCR_BEACON_FILE", "/var/lib/credit-mainnet/genesis_beacon.txt"
)

ESPLORA_ENDPOINTS = [
    ("mempool.space", "https://mempool.space/api/blocks"),
    ("blockstream.info", "https://blockstream.info/api/blocks"),
    ("mempool.emzy.de", "https://mempool.emzy.de/api/blocks"),
]


def fetch_json(url: str):
    req = urllib.request.Request(
        url, headers={"User-Agent": "Credits-Genesis-Watcher/0.3"}
    )
    with urllib.request.urlopen(req, timeout=10) as resp:
        return json.loads(resp.read().decode("utf-8"))


def query_esplora_first_2027_block(url: str):
    blocks = fetch_json(url)
    if not isinstance(blocks, list) or len(blocks) < 2:
        return None
    by_height = {int(b["height"]): b for b in blocks if "height" in b and "id" in b}
    candidates = [
        b for b in by_height.values() if int(b.get("timestamp", 0)) >= MAINNET_GENESIS_UNIX
    ]
    if not candidates:
        return None
    earliest = min(candidates, key=lambda b: int(b["height"]))
    h = int(earliest["height"])
    parent = by_height.get(h - 1)
    if parent is None:
        # Fetch earlier page starting at `h` to verify `h - 1` was strictly < MAINNET_GENESIS_UNIX:
        older = fetch_json(f"{url}/{h}")
        for b in older:
            if int(b.get("height", -1)) == h - 1:
                parent = b
                break
    if parent is None or int(parent.get("timestamp", 0)) >= MAINNET_GENESIS_UNIX:
        return None
    bh = str(earliest["id"]).strip().lower()
    if len(bh) == 64 and all(c in "0123456789abcdef" for c in bh):
        return (h, bh)
    return None


def query_blockchain_info_first_2027_block():
    now_ms = int(time.time() * 1000)
    data = fetch_json(f"https://blockchain.info/blocks/{now_ms}?format=json")
    blocks = data.get("blocks", []) if isinstance(data, dict) else data
    if not isinstance(blocks, list) or len(blocks) < 2:
        return None
    by_height = {int(b["height"]): b for b in blocks if "height" in b and "hash" in b}
    candidates = [
        b for b in by_height.values() if int(b.get("time", 0)) >= MAINNET_GENESIS_UNIX
    ]
    if not candidates:
        return None
    earliest = min(candidates, key=lambda b: int(b["height"]))
    h = int(earliest["height"])
    parent = by_height.get(h - 1)
    if parent is None or int(parent.get("time", 0)) >= MAINNET_GENESIS_UNIX:
        return None
    bh = str(earliest["hash"]).strip().lower()
    if len(bh) == 64 and all(c in "0123456789abcdef" for c in bh):
        return (h, bh)
    return None


def find_quorum_genesis_block():
    votes = {}
    for name, url in ESPLORA_ENDPOINTS:
        try:
            res = query_esplora_first_2027_block(url)
            if res:
                votes.setdefault(res, []).append(name)
        except Exception as exc:
            print(f"[WATCHER] {name} check: {exc}", flush=True)

    try:
        res = query_blockchain_info_first_2027_block()
        if res:
            votes.setdefault(res, []).append("blockchain.info")
    except Exception as exc:
        print(f"[WATCHER] blockchain.info check: {exc}", flush=True)

    for (height, block_hash), sources in votes.items():
        if len(sources) >= 2:
            return height, block_hash, sources
    return None


def main():
    print(
        f"[WATCHER] Credits Mainnet Genesis Watcher armed for 2027-01-01T00:00:00Z ({MAINNET_GENESIS_UNIX}) -> {NODE_ADDR}",
        flush=True,
    )
    last_log = 0.0
    while True:
        if os.path.exists(BEACON_DONE_FILE) and os.path.getsize(BEACON_DONE_FILE) >= 64:
            print(
                f"[WATCHER] {BEACON_DONE_FILE} already populated — Mainnet Epoch 0 is unlocked! Exiting cleanly.",
                flush=True,
            )
            return 0

        now = int(time.time())
        if now < MAINNET_GENESIS_UNIX:
            rem = MAINNET_GENESIS_UNIX - now
            if time.time() - last_log >= 3600 or last_log == 0.0:
                days = rem // 86400
                hours = (rem % 86400) // 3600
                print(
                    f"[WATCHER] Standby countdown: {days}d {hours}h ({rem}s) until 2027-01-01T00:00:00Z",
                    flush=True,
                )
                last_log = time.time()
            sleep_secs = 60 if rem > 120 else (2 if rem > 5 else 1)
            time.sleep(sleep_secs)
            continue

        hit = find_quorum_genesis_block()
        if hit is None:
            print(
                "[WATCHER] 2027-01-01T00:00:00Z reached — awaiting first 2027 Bitcoin block across >=2 APIs...",
                flush=True,
            )
            time.sleep(10)
            continue

        height, block_hash, sources = hit
        canonical_headline = (
            f"2027-01-01T00:00:00Z BTC #{height} {block_hash} — Credits (XCR) Fair Open Genesis"
        )
        print(
            f"[WATCHER] QUORUM CONFIRMED ({', '.join(sources)}): BTC #{height} = {block_hash}",
            flush=True,
        )
        proc = subprocess.run(
            [
                CLI_BIN,
                "unlock-genesis",
                "--node",
                NODE_ADDR,
                "--beacon",
                block_hash,
                "--memo",
                canonical_headline,
            ],
            capture_output=True,
            text=True,
        )
        print(proc.stdout, flush=True)
        if proc.returncode == 0:
            print("[WATCHER] Mainnet Epoch 0 UNLOCKED & GOSSIPED! Mining active.", flush=True)
            return 0
        print(f"[WATCHER] unlock-genesis retry in 5s: {proc.stderr}", flush=True)
        time.sleep(5)


if __name__ == "__main__":
    sys.exit(main())
