//! Standardized **`xcr:` Payment Request URIs** & **`xcr://claim#` Bearer Cash Voucher URIs**.
//!
//! Enables instant interoperable QR code scanning and deep-linking across mobile/browser wallets,
//! merchant Point-of-Sale (`POS`) registers, and `credit-cli`:
//! - **Payment Request URI:** `xcr:<recipient>?chips=495&inv=POS-108&memo=Flat%20White`
//! - **Bearer Cash Voucher URI:** `xcr://claim#<64-hex-secret>?chips=500&memo=Gift`

use credit_crypto::{
    StealthKeypair, StealthMetaAddress, StealthOutput, derive_stealth_output, domain_hash,
};
use credit_types::{Address, Amount};

use crate::qr::{QrCode, QrError};

/// Parsed `xcr:` merchant or peer-to-peer payment request URI.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PaymentRequestUri {
    /// Recipient `xcrstealth1_<128-hex>` URI, `@handle`, or merchant tag.
    pub recipient: String,
    /// Optional requested amount in `Amount` (`bits` / `chips` / `XCR`).
    pub amount: Option<Amount>,
    /// Optional merchant invoice reference (`POS-104`).
    pub invoice: Option<String>,
    /// Optional human-readable memo encrypted end-to-end via `XCR.STEALTH.MEMO_ENC.V1`.
    pub memo: Option<String>,
}

impl PaymentRequestUri {
    pub const SCHEME: &'static str = "xcr:";

    pub fn new(recipient: impl Into<String>) -> Self {
        Self {
            recipient: recipient.into(),
            amount: None,
            invoice: None,
            memo: None,
        }
    }

    pub fn with_amount(mut self, amount: Amount) -> Self {
        self.amount = Some(amount);
        self
    }

    pub fn with_invoice(mut self, invoice: impl Into<String>) -> Self {
        let s = invoice.into();
        if !s.trim().is_empty() {
            self.invoice = Some(s);
        }
        self
    }

    pub fn with_memo(mut self, memo: impl Into<String>) -> Self {
        let s = memo.into();
        if !s.trim().is_empty() {
            self.memo = Some(s);
        }
        self
    }

    /// Formats a canonical `xcr:<recipient>?chips=...&inv=...&memo=...` string.
    pub fn to_uri(&self) -> String {
        let mut out = format!("{}{}", Self::SCHEME, self.recipient);
        let mut params = Vec::new();
        if let Some(amt) = self.amount
            && !amt.is_zero()
        {
            if amt.bits().is_multiple_of(10_000) {
                params.push(format!("chips={}", amt.bits() / 10_000));
            } else {
                params.push(format!("bits={}", amt.bits()));
            }
        }
        if let Some(ref inv) = self.invoice {
            params.push(format!("inv={}", url_encode(inv)));
        }
        if let Some(ref memo) = self.memo {
            params.push(format!("memo={}", url_encode(memo)));
        }
        if !params.is_empty() {
            out.push('?');
            out.push_str(&params.join("&"));
        }
        out
    }

    /// Parses either a full `xcr:<recipient>?...` URI or a bare `xcrstealth1_...` URI.
    pub fn parse(input: &str) -> Option<Self> {
        let trimmed = input.trim();
        if trimmed.starts_with("xcr://claim#") {
            return None;
        }
        let rest = if let Some(stripped) = trimmed.strip_prefix(Self::SCHEME) {
            stripped
        } else if trimmed.starts_with(StealthMetaAddress::URI_PREFIX) && trimmed.contains('?') {
            trimmed
        } else {
            return None;
        };

        let (target, query) = rest.split_once('?').unwrap_or((rest, ""));
        if target.is_empty() {
            return None;
        }
        let mut amount = None;
        let mut invoice = None;
        let mut memo = None;

        for pair in query.split('&').filter(|p| !p.is_empty()) {
            let Some((k, v)) = pair.split_once('=') else {
                continue;
            };
            match k {
                "chips" => {
                    if let Ok(c) = v.parse::<u64>() {
                        amount = Amount::from_chips(c);
                    }
                }
                "bits" => {
                    if let Ok(b) = v.parse::<u64>() {
                        amount = Some(Amount::from_bits(b));
                    }
                }
                "amount" => {
                    amount = parse_decimal_xcr(v);
                }
                "inv" | "invoice" => {
                    let dec = url_decode(v);
                    if !dec.is_empty() {
                        invoice = Some(dec);
                    }
                }
                "memo" | "note" => {
                    let dec = url_decode(v);
                    if !dec.is_empty() {
                        memo = Some(dec);
                    }
                }
                _ => {}
            }
        }

        Some(Self {
            recipient: url_decode(target),
            amount,
            invoice,
            memo,
        })
    }

    /// Encodes this payment request directly into an ISO/IEC 18004 QR code.
    pub fn to_qr_code(&self) -> Result<QrCode, QrError> {
        QrCode::encode_str(&self.to_uri())
    }
}

/// Bearer "Cash Link" / Printable QR Gift Voucher (`xcr://claim#<64-hex-secret>?chips=...&memo=...`).
///
/// Locks funds into a deterministic one-time Curve25519 Schnorr stealth UTXO derived from
/// `secret`. Anyone who scans the QR code or opens the link can sweep the funds into their
/// own sovereign `Pocket` in `~250 ms` without prior wallet registration (and the creator can
/// reclaim unclaimed funds using the same link).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BearerVoucher {
    pub secret: [u8; 32],
    pub amount: Option<Amount>,
    pub memo: Option<String>,
}

impl BearerVoucher {
    pub const PREFIX: &'static str = "xcr://claim#";

    pub fn new(secret: [u8; 32], amount: Option<Amount>, memo: Option<String>) -> Self {
        Self {
            secret,
            amount,
            memo,
        }
    }

    /// Derives the deterministic `(StealthOutput, kdf, spend_pub)` locked by this voucher's secret
    /// so the redeemer can claim in `O(1)` without scanning all network stealth outputs.
    pub fn derive_claim_material(&self) -> (StealthOutput, [u8; 32], [u8; 32], StealthKeypair) {
        let kp = StealthKeypair::from_seed(&self.secret);
        let eph_seed = domain_hash("XCR.VOUCHER.EPH.V1", &[&self.secret]).0;
        let (out, kdf) = derive_stealth_output(&kp.meta_address(), &eph_seed);
        let spend_pub = kp.meta_address().spend_pub;
        (out, kdf, spend_pub, kp)
    }

    /// Signs the 64-byte Curve25519 Schnorr claim sweeping this voucher into `claimant_pocket`.
    pub fn sign_claim_for(
        &self,
        claimant_pocket: &Address,
    ) -> (Address, [u8; 32], [u8; 32], [u8; 64]) {
        let (out, kdf, spend_pub, kp) = self.derive_claim_material();
        let sig64 = kp.sign_claim(&out.one_time_address, claimant_pocket);
        (out.one_time_address, spend_pub, kdf, sig64)
    }

    pub fn to_uri(&self) -> String {
        let mut hex = String::with_capacity(64);
        for b in &self.secret {
            hex.push_str(&format!("{b:02x}"));
        }
        let mut out = format!("{}{hex}", Self::PREFIX);
        let mut params = Vec::new();
        if let Some(amt) = self.amount
            && !amt.is_zero()
        {
            if amt.bits().is_multiple_of(10_000) {
                params.push(format!("chips={}", amt.bits() / 10_000));
            } else {
                params.push(format!("bits={}", amt.bits()));
            }
        }
        if let Some(ref m) = self.memo
            && !m.trim().is_empty()
        {
            params.push(format!("memo={}", url_encode(m)));
        }
        if !params.is_empty() {
            out.push('?');
            out.push_str(&params.join("&"));
        }
        out
    }

    pub fn parse(uri: &str) -> Option<Self> {
        let rest = uri.trim().strip_prefix(Self::PREFIX)?;
        let (hex_part, query) = rest.split_once('?').unwrap_or((rest, ""));
        if hex_part.len() != 64 {
            return None;
        }
        let mut secret = [0u8; 32];
        let hb = hex_part.as_bytes();
        for i in 0..32 {
            let hi = hex_nibble(hb[2 * i])?;
            let lo = hex_nibble(hb[2 * i + 1])?;
            secret[i] = (hi << 4) | lo;
        }
        let mut amount = None;
        let mut memo = None;
        for pair in query.split('&').filter(|p| !p.is_empty()) {
            let Some((k, v)) = pair.split_once('=') else {
                continue;
            };
            match k {
                "chips" => amount = v.parse::<u64>().ok().and_then(Amount::from_chips),
                "bits" => amount = v.parse::<u64>().ok().map(Amount::from_bits),
                "memo" => {
                    let dec = url_decode(v);
                    if !dec.is_empty() {
                        memo = Some(dec);
                    }
                }
                _ => {}
            }
        }
        Some(Self {
            secret,
            amount,
            memo,
        })
    }

    pub fn to_qr_code(&self) -> Result<QrCode, QrError> {
        QrCode::encode_str(&self.to_uri())
    }
}

fn hex_nibble(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

/// Parses a human-friendly decimal `XCR` string (e.g. `"4.95"`, `"0.000500"`, `"25"`) into `Amount`.
pub fn parse_decimal_xcr(s: &str) -> Option<Amount> {
    let clean = s.trim().trim_start_matches('∀').trim();
    let clean = clean.strip_suffix("XCR").unwrap_or(clean).trim();
    if clean.is_empty() {
        return None;
    }
    let (whole_s, frac_s) = clean.split_once('.').unwrap_or((clean, ""));
    let whole: u64 = if whole_s.is_empty() {
        0
    } else {
        whole_s.parse().ok()?
    };
    if frac_s.len() > 6 || !frac_s.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let mut padded = frac_s.to_owned();
    while padded.len() < 6 {
        padded.push('0');
    }
    let frac: u64 = padded.parse().ok()?;
    whole
        .checked_mul(1_000_000)?
        .checked_add(frac)
        .map(Amount::from_bits)
}

pub fn url_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for &b in s.as_bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'@' => {
                out.push(b as char);
            }
            b' ' => out.push('+'),
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

pub fn url_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'+' {
            out.push(b' ');
            i += 1;
        } else if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let (Some(h), Some(l)) = (hex_nibble(bytes[i + 1]), hex_nibble(bytes[i + 2])) {
                out.push((h << 4) | l);
                i += 3;
            } else {
                out.push(bytes[i]);
                i += 1;
            }
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;
    use credit_crypto::verify_stealth_claim;

    #[test]
    fn payment_uri_and_bearer_voucher_roundtrip_and_qr() {
        let kp = StealthKeypair::from_seed(&[0x55; 32]);
        let req = PaymentRequestUri::new(kp.meta_address().to_uri())
            .with_amount(Amount::from_chips(495).unwrap())
            .with_invoice("POS-900")
            .with_memo("2x Espresso & Croissant");
        let uri_str = req.to_uri();
        let parsed = PaymentRequestUri::parse(&uri_str).unwrap();
        assert_eq!(parsed, req);
        assert!(parsed.to_qr_code().is_ok());

        let voucher = BearerVoucher::new(
            [0xAB; 32],
            Amount::from_credits(10),
            Some("Welcome to Credits!".to_owned()),
        );
        let v_uri = voucher.to_uri();
        let v_parsed = BearerVoucher::parse(&v_uri).unwrap();
        assert_eq!(v_parsed, voucher);
        assert!(v_parsed.to_qr_code().is_ok());

        let claimant = Address::from_bytes([0x77; 32]);
        let (ot_addr, spend_pub, kdf, sig64) = v_parsed.sign_claim_for(&claimant);
        assert!(verify_stealth_claim(
            &ot_addr, &claimant, &spend_pub, &kdf, &sig64
        ));
    }
}
