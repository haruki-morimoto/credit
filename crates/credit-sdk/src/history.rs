//! AEAD-Encrypted **Local Wallet Activity, Receipt, & Unclaimed Voucher Log** (`XCRHIST1`).
//!
//! Persists a user's sent payments, received/auto-swept stealth payments (with decrypted memos),
//! and minted `xcr://claim#` Bearer Cash Vouchers in an authenticated encrypted local log file
//! (`<wallet>.history`) keyed from `master_seed`, so on-disk history is completely unreadable
//! without unlocking the wallet.

use std::fs;
use std::io;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use credit_crypto::{ct_eq_slice, domain_hash};
use credit_types::Amount;

const HISTORY_MAGIC: [u8; 8] = *b"XCRHIST1";

/// Single wallet activity event displayed in `credit-cli history` and the Browser Wallet feed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ActivityEntry {
    pub timestamp_unix: u64,
    /// `"sent"`, `"received"`, `"voucher_out"`, or `"voucher_in"`.
    pub kind: String,
    pub amount: Amount,
    /// Tx ID, one-time stealth address, or `xcr://claim#...` link for recoverable vouchers.
    pub reference: String,
    pub memo: String,
}

/// Encrypted local history log bound to a wallet's 32-byte master seed.
#[derive(Clone, Debug, Default)]
pub struct EncryptedActivityLog {
    entries: Vec<ActivityEntry>,
}

impl EncryptedActivityLog {
    pub fn load(history_path: &Path, master_seed: &[u8; 32]) -> Self {
        let Ok(raw) = fs::read(history_path) else {
            return Self::default();
        };
        Self::decrypt_bytes(&raw, master_seed).unwrap_or_default()
    }

    pub fn save(&self, history_path: &Path, master_seed: &[u8; 32], nonce: u64) -> io::Result<()> {
        if let Some(parent) = history_path.parent()
            && !parent.as_os_str().is_empty()
        {
            fs::create_dir_all(parent)?;
        }
        let sealed = self.encrypt_bytes(master_seed, nonce);
        fs::write(history_path, sealed)
    }

    pub fn record_now(
        &mut self,
        kind: impl Into<String>,
        amount: Amount,
        reference: impl Into<String>,
        memo: impl Into<String>,
    ) {
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        self.entries.push(ActivityEntry {
            timestamp_unix: ts,
            kind: kind.into(),
            amount,
            reference: reference.into(),
            memo: memo.into(),
        });
        if self.entries.len() > 256 {
            let drain = self.entries.len() - 256;
            self.entries.drain(0..drain);
        }
    }

    /// Appends one entry and atomically re-encrypts `<wallet>.history` on disk.
    pub fn append_and_persist(
        history_path: &Path,
        master_seed: &[u8; 32],
        kind: impl Into<String>,
        amount: Amount,
        reference: impl Into<String>,
        memo: impl Into<String>,
    ) {
        let mut log = Self::load(history_path, master_seed);
        let nonce = (log.entries.len() as u64).wrapping_add(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_nanos() as u64)
                .unwrap_or(1),
        );
        log.record_now(kind, amount, reference, memo);
        let _ = log.save(history_path, master_seed, nonce);
    }

    pub fn entries(&self) -> &[ActivityEntry] {
        &self.entries
    }

    fn encrypt_bytes(&self, master_seed: &[u8; 32], nonce: u64) -> Vec<u8> {
        let mut pt = Vec::new();
        pt.extend_from_slice(&(self.entries.len() as u32).to_le_bytes());
        for e in &self.entries {
            pt.extend_from_slice(&e.timestamp_unix.to_le_bytes());
            pt.extend_from_slice(&e.amount.bits().to_le_bytes());
            push_str(&mut pt, &e.kind);
            push_str(&mut pt, &e.reference);
            push_str(&mut pt, &e.memo);
        }

        let key = domain_hash("XCR.WALLET.HISTORY_KEY.V1", &[master_seed]).0;
        let nb = nonce.to_le_bytes();
        let mut ct = vec![0u8; pt.len()];
        for (blk_idx, chunk) in pt.chunks(32).enumerate() {
            let blk = (blk_idx as u64).to_le_bytes();
            let ks = domain_hash("XCR.WALLET.HISTORY_KS.V1", &[&key, &nb, &blk]).0;
            let base = blk_idx * 32;
            for (i, &b) in chunk.iter().enumerate() {
                ct[base + i] = b ^ ks[i];
            }
        }
        let mac = domain_hash(
            "XCR.WALLET.HISTORY_MAC.V1",
            &[&key, &HISTORY_MAGIC, &nb, &ct],
        )
        .0;

        let mut out = Vec::with_capacity(8 + 8 + ct.len() + 16);
        out.extend_from_slice(&HISTORY_MAGIC);
        out.extend_from_slice(&nb);
        out.extend_from_slice(&ct);
        out.extend_from_slice(&mac[..16]);
        out
    }

    fn decrypt_bytes(raw: &[u8], master_seed: &[u8; 32]) -> Option<Self> {
        if raw.len() < 36 || raw[..8] != HISTORY_MAGIC {
            return None;
        }
        let nb = &raw[8..16];
        let ct_end = raw.len() - 16;
        let ct = &raw[16..ct_end];
        let tag = &raw[ct_end..];

        let key = domain_hash("XCR.WALLET.HISTORY_KEY.V1", &[master_seed]).0;
        let expected_mac =
            domain_hash("XCR.WALLET.HISTORY_MAC.V1", &[&key, &HISTORY_MAGIC, nb, ct]).0;
        if !ct_eq_slice(tag, &expected_mac[..16]) {
            return None;
        }

        let mut pt = vec![0u8; ct.len()];
        for (blk_idx, chunk) in ct.chunks(32).enumerate() {
            let blk = (blk_idx as u64).to_le_bytes();
            let ks = domain_hash("XCR.WALLET.HISTORY_KS.V1", &[&key, nb, &blk]).0;
            let base = blk_idx * 32;
            for (i, &b) in chunk.iter().enumerate() {
                pt[base + i] = b ^ ks[i];
            }
        }

        let mut pos = 0usize;
        let count = take_u32(&pt, &mut pos)?.min(512) as usize;
        let mut entries = Vec::with_capacity(count);
        for _ in 0..count {
            let timestamp_unix = take_u64(&pt, &mut pos)?;
            let amount = Amount::from_bits(take_u64(&pt, &mut pos)?);
            let kind = take_str(&pt, &mut pos)?;
            let reference = take_str(&pt, &mut pos)?;
            let memo = take_str(&pt, &mut pos)?;
            entries.push(ActivityEntry {
                timestamp_unix,
                kind,
                amount,
                reference,
                memo,
            });
        }
        Some(Self { entries })
    }
}

fn push_str(out: &mut Vec<u8>, s: &str) {
    let b = s.as_bytes();
    out.extend_from_slice(&(b.len() as u32).to_le_bytes());
    out.extend_from_slice(b);
}

fn take_u32(bytes: &[u8], pos: &mut usize) -> Option<u32> {
    let s = bytes.get(*pos..*pos + 4)?;
    *pos += 4;
    Some(u32::from_le_bytes(s.try_into().ok()?))
}

fn take_u64(bytes: &[u8], pos: &mut usize) -> Option<u64> {
    let s = bytes.get(*pos..*pos + 8)?;
    *pos += 8;
    Some(u64::from_le_bytes(s.try_into().ok()?))
}

fn take_str(bytes: &[u8], pos: &mut usize) -> Option<String> {
    let len = take_u32(bytes, pos)? as usize;
    if len > 4096 {
        return None;
    }
    let s = bytes.get(*pos..*pos + len)?;
    *pos += len;
    String::from_utf8(s.to_vec()).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aead_encrypted_activity_history_roundtrip_and_wrong_seed_isolation() {
        let seed = [0x22; 32];
        let mut log = EncryptedActivityLog::default();
        log.record_now(
            "sent",
            Amount::from_chips(495).unwrap(),
            "tx_abc123",
            "POS-108: Flat White",
        );
        log.record_now(
            "voucher_out",
            Amount::from_credits(5).unwrap(),
            "xcr://claim#deadbeef",
            "Birthday Gift",
        );

        let ct = log.encrypt_bytes(&seed, 99);
        // Plaintext memo must NOT appear in on-disk encrypted bytes:
        assert!(!String::from_utf8_lossy(&ct).contains("Flat White"));
        // Wrong seed fails MAC and returns None:
        assert!(EncryptedActivityLog::decrypt_bytes(&ct, &[0x33; 32]).is_none());
        // Matching seed recovers exact history:
        let dec = EncryptedActivityLog::decrypt_bytes(&ct, &seed).unwrap();
        assert_eq!(dec.entries(), log.entries());
    }
}
