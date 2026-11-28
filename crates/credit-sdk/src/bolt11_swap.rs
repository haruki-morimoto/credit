//! **Client-Side Lightning `BOLT-11` (`lnbc...`) & Bitcoin `P2WSH` ↔ `XCR` Atomic Swap Toolkit**.
//!
//! Operates **100% at the wallet/client edge** (`0` validator RAM growth, `0` external block
//! headers on Credit Layer 1, `0` external crate dependencies):
//! 1. **RFC-173 Bech32 + `BOLT-11` Lightning Invoice Parser & Builder:** Verifies the 6-char
//!    Bech32 polymod checksum, extracts invoice `millisatoshis`, `timestamp_unix`, `expiry_secs`,
//!    UTF-8 `description`, and the exact **32-byte `SHA-256` `payment_hash`** (`tag = 'p' / 1`).
//!    Paying the Lightning invoice atomically reveals the 32-byte `preimage` that claims the
//!    matching Credit `HTLC` in `1-RTT`!
//! 2. **Bitcoin SegWit v0 `P2WSH` (`bc1q...`) `OP_SHA256` Script Builder:** Generates the exact
//!    canonical witness script + `bc1q...` / `tb1q...` deposit address for on-chain `BTC <-> XCR`
//!    atomic swaps.

use credit_crypto::{ct_eq_slice, sha256};
use credit_types::Hash32;

const BECH32_CHARSET: &[u8; 32] = b"qpzry9x8gf2tvdw0s3jn54khce6mua7l";

/// Parsed Lightning Network `BOLT-11` payment request (`lnbc...`, `lntb...`, `lnbcrt...`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Bolt11Invoice {
    pub network: String,
    pub amount_msat: Option<u64>,
    pub timestamp_unix: u64,
    pub payment_hash: Hash32,
    pub description: String,
    pub expiry_secs: u64,
}

impl Bolt11Invoice {
    /// Decodes and Bech32-verifies a `BOLT-11` invoice (`lnbc...`, `lntb...`, `lnbcrt...`).
    pub fn parse(raw_invoice: &str) -> Result<Self, &'static str> {
        let trimmed = raw_invoice.trim();
        let stripped = trimmed
            .strip_prefix("lightning:")
            .or_else(|| trimmed.strip_prefix("LIGHTNING:"))
            .unwrap_or(trimmed);
        let (hrp, data_5bit) = bech32_decode(stripped)?;

        let prefix = if hrp.starts_with("lnbcrt") {
            "lnbcrt"
        } else if hrp.starts_with("lntbs") {
            "lntbs"
        } else if hrp.starts_with("lntb") {
            "lntb"
        } else if hrp.starts_with("lnbc") {
            "lnbc"
        } else {
            return Err("BOLT-11 HRP must start with lnbc, lntb, lntbs, or lnbcrt");
        };

        let amount_part = &hrp[prefix.len()..];
        let amount_msat = if amount_part.is_empty() {
            None
        } else {
            Some(parse_bolt11_hrp_msat(amount_part)?)
        };

        // Minimum BOLT-11 5-bit payload: 7 (35-bit timestamp) + 104 (65-byte sig = 520 bits) = 111 words
        if data_5bit.len() < 111 {
            return Err("BOLT-11 data payload shorter than timestamp + 65B signature");
        }

        let mut ts = 0u64;
        for &w in &data_5bit[..7] {
            ts = (ts << 5) | (w as u64);
        }

        let tagged_end = data_5bit.len() - 104;
        let mut pos = 7usize;
        let mut payment_hash_opt: Option<Hash32> = None;
        let mut description = String::new();
        let mut expiry_secs = 3_600u64;

        while pos + 3 <= tagged_end {
            let tag = data_5bit[pos];
            let data_len = ((data_5bit[pos + 1] as usize) << 5) | (data_5bit[pos + 2] as usize);
            pos += 3;
            if pos + data_len > tagged_end {
                return Err("truncated BOLT-11 tagged field");
            }
            let slice = &data_5bit[pos..pos + data_len];
            pos += data_len;

            match tag {
                // `p` (1) -> 256-bit SHA-256 payment_hash (52 x 5-bit words)
                1 if data_len == 52 && payment_hash_opt.is_none() => {
                    let bytes = convert_bits(slice, 5, 8, false)?;
                    if bytes.len() == 32 {
                        let mut arr = [0u8; 32];
                        arr.copy_from_slice(&bytes);
                        payment_hash_opt = Some(Hash32(arr));
                    }
                }
                // `d` (13) -> UTF-8 short description
                13 => {
                    if let Ok(bytes) = convert_bits(slice, 5, 8, false)
                        && let Ok(s) = String::from_utf8(bytes)
                    {
                        description = s;
                    }
                }
                // `x` (6) -> expiry delta in seconds
                6 if data_len <= 12 => {
                    let mut exp = 0u64;
                    for &w in slice {
                        exp = (exp << 5) | (w as u64);
                    }
                    expiry_secs = exp;
                }
                _ => {}
            }
        }

        let Some(payment_hash) = payment_hash_opt else {
            return Err("BOLT-11 invoice missing 32-byte `p` SHA-256 payment_hash tag");
        };

        Ok(Self {
            network: prefix.to_owned(),
            amount_msat,
            timestamp_unix: ts,
            payment_hash,
            description,
            expiry_secs,
        })
    }

    /// Encodes a Bech32-valid `BOLT-11` Lightning invoice (`lnbc...` / `lntb...`) binding `payment_hash`.
    pub fn encode_with_sig(
        network_prefix: &str,
        amount_sats: Option<u64>,
        timestamp_unix: u64,
        payment_hash: &Hash32,
        description: &str,
        expiry_secs: u64,
        sig65: &[u8; 65],
    ) -> Result<String, &'static str> {
        if !matches!(network_prefix, "lnbc" | "lntb" | "lntbs" | "lnbcrt") {
            return Err("network_prefix must be lnbc, lntb, lntbs, or lnbcrt");
        }
        let hrp = match amount_sats {
            Some(sats) if sats > 0 => {
                if sats.is_multiple_of(100_000) {
                    format!("{network_prefix}{}m", sats / 100_000)
                } else if sats.is_multiple_of(100) {
                    format!("{network_prefix}{}u", sats / 100)
                } else {
                    format!("{network_prefix}{}n", sats * 10)
                }
            }
            _ => network_prefix.to_owned(),
        };

        let mut words = Vec::with_capacity(220);
        // 35-bit timestamp (7 x 5-bit words):
        for shift in (0..7).rev() {
            words.push(((timestamp_unix >> (shift * 5)) & 0x1f) as u8);
        }

        // Tag `p` (1): 52 words of 32-byte `payment_hash`
        let p_words = convert_bits(payment_hash.as_bytes(), 8, 5, true)?;
        push_tagged_field(&mut words, 1, &p_words)?;

        // Tag `d` (13): UTF-8 description
        if !description.is_empty() {
            let d_words = convert_bits(description.as_bytes(), 8, 5, true)?;
            push_tagged_field(&mut words, 13, &d_words)?;
        }

        // Tag `x` (6): expiry seconds
        let mut exp_words = Vec::new();
        let mut tmp = expiry_secs;
        while tmp > 0 {
            exp_words.push((tmp & 0x1f) as u8);
            tmp >>= 5;
        }
        if exp_words.is_empty() {
            exp_words.push(0);
        }
        exp_words.reverse();
        push_tagged_field(&mut words, 6, &exp_words)?;

        // 65-byte (520-bit = 104 x 5-bit words) signature tail:
        let sig_words = convert_bits(sig65, 8, 5, false)?;
        if sig_words.len() != 104 {
            return Err("internal sig 5-bit conversion length mismatch");
        }
        words.extend_from_slice(&sig_words);

        bech32_encode(&hrp, &words)
    }

    /// Constant-time check that `SHA-256(preimage) == self.payment_hash`.
    pub fn verify_preimage(&self, preimage: &[u8; 32]) -> bool {
        let h = sha256(preimage);
        ct_eq_slice(&h, self.payment_hash.as_bytes())
    }
}

/// Builds a canonical Bitcoin `OP_SHA256` `P2WSH` HTLC witness script and SegWit v0 `bc1q...` / `tb1q...`
/// deposit address (`OP_IF OP_SHA256 <32B H> OP_EQUALVERIFY <33B ClaimPub> OP_CHECKSIG OP_ELSE
/// <4B Locktime> OP_CHECKLOCKTIMEVERIFY OP_DROP <33B RefundPub> OP_CHECKSIG OP_ENDIF`).
pub fn build_bitcoin_p2wsh_htlc(
    mainnet: bool,
    hashlock: &Hash32,
    claim_compressed_pubkey33: &[u8; 33],
    refund_compressed_pubkey33: &[u8; 33],
    refund_unix_locktime: u32,
) -> Result<(Vec<u8>, String), &'static str> {
    if claim_compressed_pubkey33[0] != 0x02 && claim_compressed_pubkey33[0] != 0x03 {
        return Err("claim pubkey must be a 33-byte SEC1 compressed key (0x02 / 0x03)");
    }
    if refund_compressed_pubkey33[0] != 0x02 && refund_compressed_pubkey33[0] != 0x03 {
        return Err("refund pubkey must be a 33-byte SEC1 compressed key (0x02 / 0x03)");
    }

    let mut script = Vec::with_capacity(116);
    script.push(0x63); // OP_IF
    script.push(0xa8); // OP_SHA256
    script.push(0x20); // PUSH 32 bytes
    script.extend_from_slice(hashlock.as_bytes());
    script.push(0x88); // OP_EQUALVERIFY
    script.push(0x21); // PUSH 33 bytes
    script.extend_from_slice(claim_compressed_pubkey33);
    script.push(0xac); // OP_CHECKSIG
    script.push(0x67); // OP_ELSE
    // Minimal CScriptNum 5-byte unsigned little-endian push for locktime >= 0x80000000 safe encoding:
    let le = refund_unix_locktime.to_le_bytes();
    if le[3] & 0x80 != 0 {
        script.push(0x05);
        script.extend_from_slice(&le);
        script.push(0x00);
    } else {
        script.push(0x04);
        script.extend_from_slice(&le);
    }
    script.push(0xb1); // OP_CHECKLOCKTIMEVERIFY
    script.push(0x75); // OP_DROP
    script.push(0x21); // PUSH 33 bytes
    script.extend_from_slice(refund_compressed_pubkey33);
    script.push(0xac); // OP_CHECKSIG
    script.push(0x68); // OP_ENDIF

    // SegWit v0 P2WSH witness program: witness_version=0 || SHA256(witness_script)
    let wsh = sha256(&script);
    let mut prog_5bit = Vec::with_capacity(53);
    prog_5bit.push(0u8); // witness version 0
    prog_5bit.extend_from_slice(&convert_bits(&wsh, 8, 5, true)?);
    let hrp = if mainnet { "bc" } else { "tb" };
    let address = bech32_encode(hrp, &prog_5bit)?;
    Ok((script, address))
}

fn push_tagged_field(out: &mut Vec<u8>, tag: u8, payload_5bit: &[u8]) -> Result<(), &'static str> {
    if payload_5bit.len() >= 1024 {
        return Err("BOLT-11 tagged field exceeds 10-bit length limit");
    }
    out.push(tag & 0x1f);
    out.push(((payload_5bit.len() >> 5) & 0x1f) as u8);
    out.push((payload_5bit.len() & 0x1f) as u8);
    out.extend_from_slice(payload_5bit);
    Ok(())
}

fn parse_bolt11_hrp_msat(amount_part: &str) -> Result<u64, &'static str> {
    let bytes = amount_part.as_bytes();
    let last = *bytes.last().ok_or("empty amount")?;
    let (digits, mult_opt) = if last.is_ascii_alphabetic() {
        (&amount_part[..amount_part.len() - 1], Some(last))
    } else {
        (amount_part, None)
    };
    let val: u64 = digits.parse().map_err(|_| "invalid BOLT-11 HRP digits")?;
    match mult_opt {
        None => val
            .checked_mul(100_000_000_000)
            .ok_or("BOLT-11 BTC amount overflow"),
        Some(b'm') => val
            .checked_mul(100_000_000)
            .ok_or("BOLT-11 mBTC amount overflow"),
        Some(b'u') => val
            .checked_mul(100_000)
            .ok_or("BOLT-11 uBTC amount overflow"),
        Some(b'n') => val.checked_mul(100).ok_or("BOLT-11 nBTC amount overflow"),
        Some(b'p') => {
            if !val.is_multiple_of(10) {
                return Err("sub-millisatoshi pBTC amount must be divisible by 10");
            }
            Ok(val / 10)
        }
        _ => Err("unsupported BOLT-11 amount multiplier"),
    }
}

fn bech32_polymod(values: &[u8]) -> u32 {
    const GEN: [u32; 5] = [
        0x3b6a_57b2,
        0x2650_8e6d,
        0x1ea1_19fa,
        0x3d42_33dd,
        0x2a14_62b3,
    ];
    let mut chk = 1u32;
    for &v in values {
        let top = chk >> 25;
        chk = ((chk & 0x01ff_ffff) << 5) ^ (v as u32);
        for (i, &g) in GEN.iter().enumerate() {
            if ((top >> i) & 1) != 0 {
                chk ^= g;
            }
        }
    }
    chk
}

fn bech32_hrp_expand(hrp: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(hrp.len() * 2 + 1);
    for b in hrp.bytes() {
        out.push(b >> 5);
    }
    out.push(0);
    for b in hrp.bytes() {
        out.push(b & 0x1f);
    }
    out
}

pub fn bech32_encode(hrp: &str, data_5bit: &[u8]) -> Result<String, &'static str> {
    let lower_hrp = hrp.to_ascii_lowercase();
    let mut chk_in = bech32_hrp_expand(&lower_hrp);
    chk_in.extend_from_slice(data_5bit);
    chk_in.extend_from_slice(&[0u8; 6]);
    let polymod = bech32_polymod(&chk_in) ^ 1;

    let mut out = String::with_capacity(lower_hrp.len() + 1 + data_5bit.len() + 6);
    out.push_str(&lower_hrp);
    out.push('1');
    for &d in data_5bit {
        if d >= 32 {
            return Err("invalid 5-bit Bech32 value");
        }
        out.push(BECH32_CHARSET[d as usize] as char);
    }
    for i in 0..6 {
        let v = ((polymod >> (5 * (5 - i))) & 0x1f) as usize;
        out.push(BECH32_CHARSET[v] as char);
    }
    Ok(out)
}

pub fn bech32_decode(s: &str) -> Result<(String, Vec<u8>), &'static str> {
    let has_lower = s.bytes().any(|b| b.is_ascii_lowercase());
    let has_upper = s.bytes().any(|b| b.is_ascii_uppercase());
    if has_lower && has_upper {
        return Err("mixed-case Bech32 string is invalid");
    }
    let lower = s.to_ascii_lowercase();
    let sep = lower.rfind('1').ok_or("Bech32 missing `1` separator")?;
    if sep == 0 || sep + 7 > lower.len() {
        return Err("Bech32 HRP or checksum too short");
    }
    let hrp = &lower[..sep];
    let data_chars = &lower.as_bytes()[sep + 1..];
    let mut data = Vec::with_capacity(data_chars.len());
    for &ch in data_chars {
        let idx = BECH32_CHARSET
            .iter()
            .position(|&c| c == ch)
            .ok_or("invalid Bech32 character")?;
        data.push(idx as u8);
    }
    let mut chk_in = bech32_hrp_expand(hrp);
    chk_in.extend_from_slice(&data);
    if bech32_polymod(&chk_in) != 1 {
        return Err("Bech32 checksum verification failed");
    }
    data.truncate(data.len() - 6);
    Ok((hrp.to_owned(), data))
}

pub fn convert_bits(
    data: &[u8],
    from_bits: u32,
    to_bits: u32,
    pad: bool,
) -> Result<Vec<u8>, &'static str> {
    let mut acc = 0u32;
    let mut bits = 0u32;
    let maxv = (1u32 << to_bits) - 1;
    let mut out =
        Vec::with_capacity((data.len() * (from_bits as usize)).div_ceil(to_bits as usize));
    for &value in data {
        if ((value as u32) >> from_bits) != 0 {
            return Err("convert_bits input value out of range");
        }
        acc = (acc << from_bits) | (value as u32);
        bits += from_bits;
        while bits >= to_bits {
            bits -= to_bits;
            out.push(((acc >> bits) & maxv) as u8);
        }
    }
    if pad {
        if bits > 0 {
            out.push(((acc << (to_bits - bits)) & maxv) as u8);
        }
    } else if bits >= from_bits || ((acc << (to_bits - bits)) & maxv) != 0 {
        return Err("non-zero padding bits in Bech32 payload");
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::htlc_offers::generate_htlc_secret;

    #[test]
    fn bolt11_invoice_roundtrip_preimage_unlock_and_btc_p2wsh_address() {
        let (preimage, hashlock) = generate_htlc_secret(&[0x77; 32]);
        let inv_str = Bolt11Invoice::encode_with_sig(
            "lnbc",
            Some(25_000),
            1_795_840_000,
            &hashlock,
            "Swap 25k sats -> 50 XCR",
            1_800,
            &[0x42; 65],
        )
        .unwrap();
        assert!(inv_str.starts_with("lnbc250u1"));

        let decoded = Bolt11Invoice::parse(&inv_str).unwrap();
        assert_eq!(decoded.network, "lnbc");
        assert_eq!(decoded.amount_msat, Some(25_000_000));
        assert_eq!(decoded.payment_hash, hashlock);
        assert_eq!(decoded.description, "Swap 25k sats -> 50 XCR");
        assert_eq!(decoded.expiry_secs, 1_800);
        assert!(decoded.verify_preimage(&preimage));
        assert!(!decoded.verify_preimage(&[0x99; 32]));

        let mut pk1 = [0x11u8; 33];
        pk1[0] = 0x02;
        let mut pk2 = [0x22u8; 33];
        pk2[0] = 0x03;
        let (script, btc_addr) =
            build_bitcoin_p2wsh_htlc(true, &hashlock, &pk1, &pk2, 1_795_900_000).unwrap();
        assert!(btc_addr.starts_with("bc1q"));
        assert!(script.len() >= 110);
    }
}
