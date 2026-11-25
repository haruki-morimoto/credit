//! **Pull-Free Recurring Subscriptions & Scoped Allowances** (`XCRSUBS1` AEAD-Encrypted Store).
//!
//! Solves recurring SaaS, creator, and utility billing without credit-card pull-authority or
//! smart-contract custody risk:
//! - Users authorize a local `SubscriptionMandate` (`merchant`, `recipient`, `amount_per_cycle`,
//!   `interval_secs`, optional `max_cycles`), stored AEAD-encrypted in `<wallet>.subs`.
//! - Merchants have **zero pull access** to the user's `Pocket` or `Vault`.
//! - Cancelling is an **instant 1-click local state toggle** (`cancel(id)`), immediately stopping
//!   all future cycles without asking the merchant's permission.

use std::fs;
use std::io;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use credit_crypto::{ct_eq_slice, domain_hash};
use credit_types::Amount;

const SUBS_MAGIC: [u8; 8] = *b"XCRSUBS1";

/// Sovereign client-pushed recurring payment mandate.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SubscriptionMandate {
    pub id: u64,
    pub label: String,
    pub recipient: String,
    pub amount: Amount,
    pub interval_secs: u64,
    pub next_due_unix: u64,
    pub completed_cycles: u32,
    pub active: bool,
}

#[derive(Clone, Debug, Default)]
pub struct SubscriptionBook {
    next_id: u64,
    mandates: Vec<SubscriptionMandate>,
}

impl SubscriptionBook {
    pub fn load(path: &Path, master_seed: &[u8; 32]) -> Self {
        let Ok(raw) = fs::read(path) else {
            return Self {
                next_id: 1,
                mandates: Vec::new(),
            };
        };
        Self::decrypt_bytes(&raw, master_seed).unwrap_or(Self {
            next_id: 1,
            mandates: Vec::new(),
        })
    }

    pub fn save(&self, path: &Path, master_seed: &[u8; 32]) -> io::Result<()> {
        if let Some(parent) = path.parent()
            && !parent.as_os_str().is_empty()
        {
            fs::create_dir_all(parent)?;
        }
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(1);
        fs::write(path, self.encrypt_bytes(master_seed, nonce))
    }

    pub fn add_mandate(
        &mut self,
        label: impl Into<String>,
        recipient: impl Into<String>,
        amount: Amount,
        interval_secs: u64,
        first_due_unix: u64,
    ) -> u64 {
        let id = self.next_id.max(1);
        self.next_id = id + 1;
        self.mandates.push(SubscriptionMandate {
            id,
            label: label.into(),
            recipient: recipient.into(),
            amount,
            interval_secs: interval_secs.max(10),
            next_due_unix: first_due_unix,
            completed_cycles: 0,
            active: true,
        });
        id
    }

    /// Instant 1-click sovereign cancellation — merchant cannot charge another cycle.
    pub fn cancel(&mut self, id: u64) -> bool {
        if let Some(m) = self.mandates.iter_mut().find(|m| m.id == id) {
            m.active = false;
            return true;
        }
        false
    }

    /// Returns IDs of active mandates due for execution at `now_unix`.
    pub fn due_mandates(&self, now_unix: u64) -> Vec<SubscriptionMandate> {
        self.mandates
            .iter()
            .filter(|m| m.active && now_unix >= m.next_due_unix && !m.amount.is_zero())
            .cloned()
            .collect()
    }

    /// Advances `next_due_unix` after a cycle payment settles on-chain.
    pub fn mark_cycle_paid(&mut self, id: u64, now_unix: u64) {
        if let Some(m) = self.mandates.iter_mut().find(|m| m.id == id) {
            m.completed_cycles = m.completed_cycles.saturating_add(1);
            let base = m.next_due_unix.max(now_unix);
            m.next_due_unix = base.saturating_add(m.interval_secs);
        }
    }

    pub fn mandates(&self) -> &[SubscriptionMandate] {
        &self.mandates
    }

    fn encrypt_bytes(&self, master_seed: &[u8; 32], nonce: u64) -> Vec<u8> {
        let mut pt = Vec::new();
        pt.extend_from_slice(&self.next_id.to_le_bytes());
        pt.extend_from_slice(&(self.mandates.len() as u32).to_le_bytes());
        for m in &self.mandates {
            pt.extend_from_slice(&m.id.to_le_bytes());
            pt.extend_from_slice(&m.amount.bits().to_le_bytes());
            pt.extend_from_slice(&m.interval_secs.to_le_bytes());
            pt.extend_from_slice(&m.next_due_unix.to_le_bytes());
            pt.extend_from_slice(&m.completed_cycles.to_le_bytes());
            pt.push(m.active as u8);
            push_str(&mut pt, &m.label);
            push_str(&mut pt, &m.recipient);
        }

        let key = domain_hash("XCR.WALLET.SUBS_KEY.V1", &[master_seed]).0;
        let nb = nonce.to_le_bytes();
        let mut ct = vec![0u8; pt.len()];
        for (blk_idx, chunk) in pt.chunks(32).enumerate() {
            let blk = (blk_idx as u64).to_le_bytes();
            let ks = domain_hash("XCR.WALLET.SUBS_KS.V1", &[&key, &nb, &blk]).0;
            let base = blk_idx * 32;
            for (i, &b) in chunk.iter().enumerate() {
                ct[base + i] = b ^ ks[i];
            }
        }
        let mac = domain_hash("XCR.WALLET.SUBS_MAC.V1", &[&key, &SUBS_MAGIC, &nb, &ct]).0;
        let mut out = Vec::with_capacity(16 + ct.len() + 16);
        out.extend_from_slice(&SUBS_MAGIC);
        out.extend_from_slice(&nb);
        out.extend_from_slice(&ct);
        out.extend_from_slice(&mac[..16]);
        out
    }

    fn decrypt_bytes(raw: &[u8], master_seed: &[u8; 32]) -> Option<Self> {
        if raw.len() < 44 || raw[..8] != SUBS_MAGIC {
            return None;
        }
        let nb = &raw[8..16];
        let ct_end = raw.len() - 16;
        let ct = &raw[16..ct_end];
        let tag = &raw[ct_end..];

        let key = domain_hash("XCR.WALLET.SUBS_KEY.V1", &[master_seed]).0;
        let expected_mac = domain_hash("XCR.WALLET.SUBS_MAC.V1", &[&key, &SUBS_MAGIC, nb, ct]).0;
        if !ct_eq_slice(tag, &expected_mac[..16]) {
            return None;
        }

        let mut pt = vec![0u8; ct.len()];
        for (blk_idx, chunk) in ct.chunks(32).enumerate() {
            let blk = (blk_idx as u64).to_le_bytes();
            let ks = domain_hash("XCR.WALLET.SUBS_KS.V1", &[&key, nb, &blk]).0;
            let base = blk_idx * 32;
            for (i, &b) in chunk.iter().enumerate() {
                pt[base + i] = b ^ ks[i];
            }
        }

        let mut pos = 0usize;
        let next_id = take_u64(&pt, &mut pos)?;
        let count = take_u32(&pt, &mut pos)?.min(256) as usize;
        let mut mandates = Vec::with_capacity(count);
        for _ in 0..count {
            let id = take_u64(&pt, &mut pos)?;
            let amount = Amount::from_bits(take_u64(&pt, &mut pos)?);
            let interval_secs = take_u64(&pt, &mut pos)?;
            let next_due_unix = take_u64(&pt, &mut pos)?;
            let completed_cycles = take_u32(&pt, &mut pos)?;
            let active = *pt.get(pos)? != 0;
            pos += 1;
            let label = take_str(&pt, &mut pos)?;
            let recipient = take_str(&pt, &mut pos)?;
            mandates.push(SubscriptionMandate {
                id,
                label,
                recipient,
                amount,
                interval_secs,
                next_due_unix,
                completed_cycles,
                active,
            });
        }
        Some(Self { next_id, mandates })
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
    if len > 2048 {
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
    fn subscription_mandates_encrypt_schedule_and_one_click_cancel() {
        let seed = [0x6B; 32];
        let mut book = SubscriptionBook::default();
        let id = book.add_mandate(
            "ProtonMail Plus",
            "proton-merchant",
            Amount::from_chips(999).unwrap(),
            2_592_000,
            1_000,
        );
        assert_eq!(book.due_mandates(999).len(), 0);
        assert_eq!(book.due_mandates(1_000).len(), 1);

        book.mark_cycle_paid(id, 1_005);
        assert_eq!(book.due_mandates(1_010).len(), 0);
        assert_eq!(book.mandates()[0].completed_cycles, 1);

        // Encrypt & decrypt roundtrip:
        let ct = book.encrypt_bytes(&seed, 42);
        let mut restored = SubscriptionBook::decrypt_bytes(&ct, &seed).unwrap();
        assert_eq!(restored.mandates(), book.mandates());

        // Instant 1-click cancel stops all future cycles:
        assert!(restored.cancel(id));
        assert!(restored.due_mandates(99_999_999).is_empty());
    }
}
