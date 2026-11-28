//! **Chainlink-Style Threshold Quorum Oracle Feeds & Fiat-Denominated Invoice Settlement**.
//!
//! Enables real-world price discovery (`USD/XCR`, `BTC/USD`, `EUR/XCR`, `CPI-BASKET`) with
//! outlier-resistant trimmed-median aggregation and **zero rent-extracting oracle token**, storing
//! only a compact 32-byte median slot per feed (`0` historical ledger bloat).

use credit_crypto::{Keypair, PublicKey, Signature, SignatureScheme, domain_hash};
use credit_types::{Address, Amount, Hash32};

/// Validates canonical feed tickers (`"USD/XCR"`, `"EUR/XCR"`, `"BTC/USD"`, `"CPI-BASKET"`).
pub fn is_valid_feed_id(feed_id: &str) -> bool {
    let b = feed_id.as_bytes();
    (3..=20).contains(&b.len())
        && b.iter()
            .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || *c == b'/' || *c == b'-')
}

/// Computes an outlier-resistant trimmed median over reporter observations (`price_micros`).
/// When `n >= 3`, drops both the minimum and maximum observation so a compromised reporter
/// submitting `0` or `u64::MAX` cannot skew the feed!
pub fn compute_trimmed_median_micros(observations: &[u64]) -> Option<u64> {
    if observations.is_empty() {
        return None;
    }
    let mut sorted = observations.to_vec();
    sorted.sort_unstable();
    let window = if sorted.len() >= 3 {
        &sorted[1..sorted.len() - 1]
    } else {
        &sorted[..]
    };
    let mid = window.len() / 2;
    if window.len() % 2 == 1 {
        Some(window[mid])
    } else {
        Some(((window[mid - 1] as u128 + window[mid] as u128) / 2) as u64)
    }
}

/// Converts `fiat_cents` (e.g. `1500` = `\$15.00`) into exact `XCR` given `fiat_micros_per_xcr`
/// (e.g. `2_500_000` = `\$2.50` per `1.000000 XCR` -> returns `6.000000 XCR`).
pub fn fiat_cents_to_xcr(fiat_cents: u64, fiat_micros_per_xcr: u64) -> Option<Amount> {
    if fiat_cents == 0 || fiat_micros_per_xcr == 0 {
        return None;
    }
    // fiat_micros = fiat_cents * 10_000; xcr_bits = (fiat_micros * 1_000_000) / fiat_micros_per_xcr
    let total_micros = (fiat_cents as u128).checked_mul(10_000)?;
    let xcr_bits = total_micros.checked_mul(1_000_000)? / (fiat_micros_per_xcr as u128);
    let bits_u64 = u64::try_from(xcr_bits).ok()?;
    (bits_u64 > 0).then_some(Amount::from_bits(bits_u64))
}

pub fn oracle_report_digest(
    reporter: &Address,
    feed_id: &str,
    price_micros: u64,
    timestamp_unix: u64,
) -> Hash32 {
    domain_hash(
        "XCR.ORACLE.REPORT.V1",
        &[
            reporter.as_bytes(),
            feed_id.as_bytes(),
            &price_micros.to_le_bytes(),
            &timestamp_unix.to_le_bytes(),
        ],
    )
}

pub fn sign_oracle_report(
    master_seed: &[u8; 32],
    feed_id: &str,
    price_micros: u64,
    timestamp_unix: u64,
) -> Result<(Address, PublicKey, Hash32, [u8; 65]), &'static str> {
    if !is_valid_feed_id(feed_id) || price_micros == 0 {
        return Err("invalid feed_id or zero price_micros");
    }
    let sk = domain_hash("XCR.WALLET.POCKET_KEY.V1", &[master_seed]).0;
    let mut kp = Keypair::from_seed(SignatureScheme::PasskeyP256, sk);
    let reporter = kp.address();
    let tx_id = oracle_report_digest(&reporter, feed_id, price_micros, timestamp_unix);
    let sig = kp.sign(tx_id.as_bytes());
    let mut sig65 = [0u8; 65];
    sig65.copy_from_slice(&sig.to_bytes());
    Ok((reporter, kp.public_key(), tx_id, sig65))
}

#[allow(clippy::too_many_arguments)]
pub fn oracle_pegged_pay_digest(
    payer: &Address,
    recipient: &Address,
    feed_id: &str,
    fiat_cents: u64,
    max_xcr_spend: Amount,
    fee: Amount,
    salt: &[u8; 16],
) -> Hash32 {
    domain_hash(
        "XCR.ORACLE.FIAT_PAY.V1",
        &[
            payer.as_bytes(),
            recipient.as_bytes(),
            feed_id.as_bytes(),
            &fiat_cents.to_le_bytes(),
            &max_xcr_spend.bits().to_le_bytes(),
            &fee.bits().to_le_bytes(),
            salt,
        ],
    )
}

pub fn sign_oracle_fiat_payment(
    master_seed: &[u8; 32],
    recipient: &Address,
    feed_id: &str,
    fiat_cents: u64,
    max_xcr_spend: Amount,
    fee: Amount,
    salt: [u8; 16],
) -> Result<(Address, PublicKey, Hash32, [u8; 65]), &'static str> {
    if !is_valid_feed_id(feed_id) || fiat_cents == 0 || max_xcr_spend.is_zero() {
        return Err("invalid oracle fiat payment parameters");
    }
    let sk = domain_hash("XCR.WALLET.POCKET_KEY.V1", &[master_seed]).0;
    let mut kp = Keypair::from_seed(SignatureScheme::PasskeyP256, sk);
    let payer = kp.address();
    let tx_id = oracle_pegged_pay_digest(
        &payer,
        recipient,
        feed_id,
        fiat_cents,
        max_xcr_spend,
        fee,
        &salt,
    );
    let sig = kp.sign(tx_id.as_bytes());
    let mut sig65 = [0u8; 65];
    sig65.copy_from_slice(&sig.to_bytes());
    Ok((payer, kp.public_key(), tx_id, sig65))
}

pub fn verify_oracle_sig(
    pubkey: &PublicKey,
    actor: &Address,
    digest: &Hash32,
    sig65: &[u8; 65],
) -> bool {
    pubkey.to_address() == *actor
        && Signature::from_bytes(sig65).is_some_and(|s| pubkey.verify(digest.as_bytes(), &s))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn trimmed_median_ignores_byzantine_outliers_and_prices_usd_invoices() {
        // 5 reporters: [1, 2_490_000, 2_500_000, 2_510_000, 999_999_999_999] -> median = 2_500_000 ($2.50)
        let med =
            compute_trimmed_median_micros(&[999_999_999_999, 2_510_000, 1, 2_500_000, 2_490_000])
                .unwrap();
        assert_eq!(med, 2_500_000);
        // $15.00 USD (1500 cents) at $2.50/XCR = 6.000000 XCR:
        assert_eq!(
            fiat_cents_to_xcr(1_500, med),
            Some(Amount::from_credits(6).unwrap())
        );
    }
}
