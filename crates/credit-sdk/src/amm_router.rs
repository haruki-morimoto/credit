//! **Uniswap `x * y = k` Constant-Product AMM Liquidity Pools & Hybrid Orderbook/AMM Smart Router**.
//!
//! Provides passive 24/7 `XCR <-> NativeAsset` liquidity with `0.30%` LP fee auto-compounding
//! (`k_after >= k_before`) and zero market-maker bots, seamlessly paired with Wave-9's Limit
//! Orderbook via a **Smart Router** that executes against whichever venue yields better output!

use credit_crypto::{Keypair, PublicKey, Signature, SignatureScheme, domain_hash};
use credit_types::{Address, Amount, Hash32};

/// Exact integer floor `sqrt(n)` over `u128` (`#![forbid(unsafe_code)]`, zero floating point).
pub fn isqrt_u128(n: u128) -> u64 {
    if n == 0 {
        return 0;
    }
    let mut x = 1u128 << ((128 - n.leading_zeros()).div_ceil(2));
    loop {
        let y = (x + n / x) >> 1;
        if y >= x {
            return x.min(u64::MAX as u128) as u64;
        }
        x = y;
    }
}

/// Uniswap v2 `0.30%` constant-product swap quote: `dy = (y * dx * 997) / (x * 1000 + dx * 997)`.
pub fn amm_constant_product_out(reserve_in: u64, reserve_out: u64, amount_in: u64) -> Option<u64> {
    if reserve_in == 0 || reserve_out == 0 || amount_in == 0 {
        return None;
    }
    let dx_with_fee = (amount_in as u128).checked_mul(997)?;
    let num = dx_with_fee.checked_mul(reserve_out as u128)?;
    let den = (reserve_in as u128)
        .checked_mul(1_000)?
        .checked_add(dx_with_fee)?;
    let dy = (num / den) as u64;
    (dy > 0 && dy < reserve_out).then_some(dy)
}

#[allow(clippy::too_many_arguments)]
pub fn amm_liquidity_digest(
    is_remove: bool,
    provider: &Address,
    asset_id: &Hash32,
    xcr_amount: Amount,
    asset_units_or_lp_shares: u64,
    fee: Amount,
    salt: &[u8; 16],
) -> Hash32 {
    domain_hash(
        "XCR.AMM.LIQUIDITY.V1",
        &[
            &[is_remove as u8],
            provider.as_bytes(),
            asset_id.as_bytes(),
            &xcr_amount.bits().to_le_bytes(),
            &asset_units_or_lp_shares.to_le_bytes(),
            &fee.bits().to_le_bytes(),
            salt,
        ],
    )
}

pub fn sign_amm_liquidity(
    master_seed: &[u8; 32],
    is_remove: bool,
    asset_id: &Hash32,
    xcr_amount: Amount,
    asset_units_or_lp_shares: u64,
    fee: Amount,
    salt: [u8; 16],
) -> Result<(Address, PublicKey, Hash32, [u8; 65]), &'static str> {
    if asset_units_or_lp_shares == 0 || (!is_remove && xcr_amount.is_zero()) {
        return Err("AMM liquidity amounts must be > 0");
    }
    let sk = domain_hash("XCR.WALLET.POCKET_KEY.V1", &[master_seed]).0;
    let mut kp = Keypair::from_seed(SignatureScheme::PasskeyP256, sk);
    let provider = kp.address();
    let tx_id = amm_liquidity_digest(
        is_remove,
        &provider,
        asset_id,
        xcr_amount,
        asset_units_or_lp_shares,
        fee,
        &salt,
    );
    let sig = kp.sign(tx_id.as_bytes());
    let mut sig65 = [0u8; 65];
    sig65.copy_from_slice(&sig.to_bytes());
    Ok((provider, kp.public_key(), tx_id, sig65))
}

#[allow(clippy::too_many_arguments)]
pub fn hybrid_swap_digest(
    trader: &Address,
    asset_id: &Hash32,
    is_buy_asset: bool,
    amount_in_bits_or_units: u64,
    min_out_units_or_bits: u64,
    fee: Amount,
    salt: &[u8; 16],
) -> Hash32 {
    domain_hash(
        "XCR.AMM.HYBRID_SWAP.V1",
        &[
            trader.as_bytes(),
            asset_id.as_bytes(),
            &[is_buy_asset as u8],
            &amount_in_bits_or_units.to_le_bytes(),
            &min_out_units_or_bits.to_le_bytes(),
            &fee.bits().to_le_bytes(),
            salt,
        ],
    )
}

pub fn sign_hybrid_smart_swap(
    master_seed: &[u8; 32],
    asset_id: &Hash32,
    is_buy_asset: bool,
    amount_in_bits_or_units: u64,
    min_out_units_or_bits: u64,
    fee: Amount,
    salt: [u8; 16],
) -> Result<(Address, PublicKey, Hash32, [u8; 65]), &'static str> {
    if amount_in_bits_or_units == 0 {
        return Err("swap input must be > 0");
    }
    let sk = domain_hash("XCR.WALLET.POCKET_KEY.V1", &[master_seed]).0;
    let mut kp = Keypair::from_seed(SignatureScheme::PasskeyP256, sk);
    let trader = kp.address();
    let tx_id = hybrid_swap_digest(
        &trader,
        asset_id,
        is_buy_asset,
        amount_in_bits_or_units,
        min_out_units_or_bits,
        fee,
        &salt,
    );
    let sig = kp.sign(tx_id.as_bytes());
    let mut sig65 = [0u8; 65];
    sig65.copy_from_slice(&sig.to_bytes());
    Ok((trader, kp.public_key(), tx_id, sig65))
}

pub fn verify_amm_sig(
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
    fn uniswap_constant_product_math_preserves_k_and_computes_isqrt() {
        assert_eq!(isqrt_u128(10_000_000 * 1_000), 100_000);
        // Pool: 10.00 XCR (10_000_000 bits) & 1,000 tokens -> buy with 1.00 XCR (1_000_000 bits):
        let dy = amm_constant_product_out(10_000_000, 1_000, 1_000_000).unwrap();
        assert_eq!(dy, 90); // (1000 * 997_000) / 10_997_000 = 90 units
        let k_before = 10_000_000u128 * 1_000u128;
        let k_after = 11_000_000u128 * (1_000 - dy as u128);
        assert!(k_after > k_before);
    }
}
