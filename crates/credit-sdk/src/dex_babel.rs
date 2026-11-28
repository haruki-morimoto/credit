//! **XRPL-Style Native Limit Orderbook DEX, Cross-Asset Auto-Bridging & Cardano `Babel Fees`**.
//!
//! Brings three major Ripple + Cardano capabilities directly into Layer-1 integer state:
//! 1. **Resting Limit Orderbook (`DexOrder`):** Makers post `Ask` (sell `asset_id` for `XCR`) or
//!    `Bid` (buy `asset_id` with escrowed `XCR`) orders matched via deterministic price-time
//!    priority at the maker's resting price (**zero EVM sandwich `MEV`**, zero `approve()` drainers).
//! 2. **Cross-Asset Payment Auto-Bridging:** Spend `Asset A` while delivering exact `XCR` (or
//!    auto-bridging `Asset A -> XCR -> Asset B` across two orderbooks) in one atomic step.
//! 3. **Cardano `Babel Fees`:** Users with **`0.000000 XCR`** can transfer native assets by
//!    attaching a `babel_fee_units` token offer — automatically converted into `XCR` against
//!    resting `Bid` liquidity to pay the `85%` miner + `15%` burn network fee with zero `Paymaster`.

use credit_crypto::{Keypair, PublicKey, Signature, SignatureScheme, domain_hash};
use credit_types::{Address, Amount, Hash32};

/// Signed Layer-1 limit order on the `(asset_id / XCR)` native orderbook.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DexLimitOrder {
    pub order_id: Hash32,
    pub maker: Address,
    pub maker_pubkey: PublicKey,
    pub asset_id: Hash32,
    /// `true` = Ask (selling `asset_units` for `XCR`), `false` = Bid (buying `asset_units` with `XCR`).
    pub is_sell_asset: bool,
    pub asset_units: u64,
    /// Price per `1` asset unit expressed in `XCR` bits (`1 XCR = 1_000_000 bits`).
    pub price_bits_per_unit: u64,
    pub immediate_or_cancel: bool,
    pub fee: Amount,
    pub salt: [u8; 16],
    pub sig65: [u8; 65],
}

impl DexLimitOrder {
    #[allow(clippy::too_many_arguments)]
    pub fn compute_id(
        maker: &Address,
        asset_id: &Hash32,
        is_sell_asset: bool,
        asset_units: u64,
        price_bits_per_unit: u64,
        immediate_or_cancel: bool,
        fee: Amount,
        salt: &[u8; 16],
    ) -> Hash32 {
        domain_hash(
            "XCR.DEX.ORDER_ID.V1",
            &[
                maker.as_bytes(),
                asset_id.as_bytes(),
                &[is_sell_asset as u8],
                &asset_units.to_le_bytes(),
                &price_bits_per_unit.to_le_bytes(),
                &[immediate_or_cancel as u8],
                &fee.bits().to_le_bytes(),
                salt,
            ],
        )
    }

    /// Computes exact total `XCR` bits required for `units * price_bits_per_unit` using `u128` overflow checks.
    pub fn checked_quote_bits(units: u64, price_bits_per_unit: u64) -> Option<u64> {
        let prod = (units as u128).checked_mul(price_bits_per_unit as u128)?;
        u64::try_from(prod).ok()
    }

    #[allow(clippy::too_many_arguments)]
    pub fn sign_new(
        master_seed: &[u8; 32],
        asset_id: Hash32,
        is_sell_asset: bool,
        asset_units: u64,
        price_bits_per_unit: u64,
        immediate_or_cancel: bool,
        fee: Amount,
        salt: [u8; 16],
    ) -> Result<Self, &'static str> {
        if asset_units == 0 || price_bits_per_unit == 0 {
            return Err("asset_units and price_bits_per_unit must be > 0");
        }
        if Self::checked_quote_bits(asset_units, price_bits_per_unit).is_none() {
            return Err("order quote overflows u64 XCR bits");
        }
        let sk = domain_hash("XCR.WALLET.POCKET_KEY.V1", &[master_seed]).0;
        let mut kp = Keypair::from_seed(SignatureScheme::PasskeyP256, sk);
        let maker = kp.address();
        let maker_pubkey = kp.public_key();
        let order_id = Self::compute_id(
            &maker,
            &asset_id,
            is_sell_asset,
            asset_units,
            price_bits_per_unit,
            immediate_or_cancel,
            fee,
            &salt,
        );
        let sig = kp.sign(order_id.as_bytes());
        let mut sig65 = [0u8; 65];
        sig65.copy_from_slice(&sig.to_bytes());
        Ok(Self {
            order_id,
            maker,
            maker_pubkey,
            asset_id,
            is_sell_asset,
            asset_units,
            price_bits_per_unit,
            immediate_or_cancel,
            fee,
            salt,
            sig65,
        })
    }

    pub fn verify(&self) -> bool {
        if self.asset_units == 0
            || self.price_bits_per_unit == 0
            || Self::checked_quote_bits(self.asset_units, self.price_bits_per_unit).is_none()
            || self.maker_pubkey.to_address() != self.maker
        {
            return false;
        }
        let expected = Self::compute_id(
            &self.maker,
            &self.asset_id,
            self.is_sell_asset,
            self.asset_units,
            self.price_bits_per_unit,
            self.immediate_or_cancel,
            self.fee,
            &self.salt,
        );
        if expected != self.order_id {
            return false;
        }
        let Some(sig) = Signature::from_bytes(&self.sig65) else {
            return false;
        };
        self.maker_pubkey.verify(self.order_id.as_bytes(), &sig)
    }
}

pub fn dex_cancel_digest(maker: &Address, order_id: &Hash32) -> Hash32 {
    domain_hash(
        "XCR.DEX.CANCEL.V1",
        &[maker.as_bytes(), order_id.as_bytes()],
    )
}

pub fn sign_dex_cancel(
    master_seed: &[u8; 32],
    order_id: &Hash32,
) -> (Address, PublicKey, [u8; 65]) {
    let sk = domain_hash("XCR.WALLET.POCKET_KEY.V1", &[master_seed]).0;
    let mut kp = Keypair::from_seed(SignatureScheme::PasskeyP256, sk);
    let maker = kp.address();
    let digest = dex_cancel_digest(&maker, order_id);
    let sig = kp.sign(digest.as_bytes());
    let mut sig65 = [0u8; 65];
    sig65.copy_from_slice(&sig.to_bytes());
    (maker, kp.public_key(), sig65)
}

#[allow(clippy::too_many_arguments)]
pub fn bridged_payment_digest(
    payer: &Address,
    recipient: &Address,
    in_asset_id: &Hash32,
    max_in_units: u64,
    out_asset_id: Option<&Hash32>,
    min_out_amount_or_units: u64,
    fee: Amount,
    salt: &[u8; 16],
) -> Hash32 {
    let mut out_tag = [0u8; 33];
    if let Some(aid) = out_asset_id {
        out_tag[0] = 1;
        out_tag[1..33].copy_from_slice(aid.as_bytes());
    }
    domain_hash(
        "XCR.DEX.BRIDGED_PAY.V1",
        &[
            payer.as_bytes(),
            recipient.as_bytes(),
            in_asset_id.as_bytes(),
            &max_in_units.to_le_bytes(),
            &out_tag,
            &min_out_amount_or_units.to_le_bytes(),
            &fee.bits().to_le_bytes(),
            salt,
        ],
    )
}

#[allow(clippy::too_many_arguments)]
pub fn sign_bridged_payment(
    master_seed: &[u8; 32],
    recipient: &Address,
    in_asset_id: &Hash32,
    max_in_units: u64,
    out_asset_id: Option<&Hash32>,
    min_out_amount_or_units: u64,
    fee: Amount,
    salt: [u8; 16],
) -> Result<(Address, PublicKey, Hash32, [u8; 65]), &'static str> {
    if max_in_units == 0 || min_out_amount_or_units == 0 {
        return Err("max_in_units and min_out_amount_or_units must be > 0");
    }
    let sk = domain_hash("XCR.WALLET.POCKET_KEY.V1", &[master_seed]).0;
    let mut kp = Keypair::from_seed(SignatureScheme::PasskeyP256, sk);
    let payer = kp.address();
    let tx_id = bridged_payment_digest(
        &payer,
        recipient,
        in_asset_id,
        max_in_units,
        out_asset_id,
        min_out_amount_or_units,
        fee,
        &salt,
    );
    let sig = kp.sign(tx_id.as_bytes());
    let mut sig65 = [0u8; 65];
    sig65.copy_from_slice(&sig.to_bytes());
    Ok((payer, kp.public_key(), tx_id, sig65))
}

/// Cardano `Babel Fee` native-asset transfer digest (`0 XCR` required in sender's Pocket!).
pub fn babel_asset_transfer_digest(
    asset_id: &Hash32,
    sender: &Address,
    recipient: &Address,
    units: u64,
    babel_fee_units: u64,
    salt: &[u8; 16],
) -> Hash32 {
    domain_hash(
        "XCR.ASSET.BABEL_XFER.V1",
        &[
            asset_id.as_bytes(),
            sender.as_bytes(),
            recipient.as_bytes(),
            &units.to_le_bytes(),
            &babel_fee_units.to_le_bytes(),
            salt,
        ],
    )
}

/// Signs a permissionless Cardano `Babel Fee` asset transfer paying network fees in `asset_id` units.
pub fn sign_babel_asset_transfer(
    master_seed: &[u8; 32],
    asset_id: &Hash32,
    recipient: &Address,
    units: u64,
    babel_fee_units: u64,
    salt: [u8; 16],
) -> Result<(Address, PublicKey, Hash32, [u8; 65]), &'static str> {
    if units == 0 || babel_fee_units == 0 || units.checked_add(babel_fee_units).is_none() {
        return Err("units and babel_fee_units must be > 0 without overflow");
    }
    let sk = domain_hash("XCR.WALLET.POCKET_KEY.V1", &[master_seed]).0;
    let mut kp = Keypair::from_seed(SignatureScheme::PasskeyP256, sk);
    let sender = kp.address();
    let xfer_id =
        babel_asset_transfer_digest(asset_id, &sender, recipient, units, babel_fee_units, &salt);
    let sig = kp.sign(xfer_id.as_bytes());
    let mut sig65 = [0u8; 65];
    sig65.copy_from_slice(&sig.to_bytes());
    Ok((sender, kp.public_key(), xfer_id, sig65))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dex_order_bridged_pay_and_babel_fee_signatures_verify() {
        let asset = Hash32::from_bytes([0x44; 32]);
        let ord = DexLimitOrder::sign_new(
            &[0x11; 32],
            asset,
            false,
            100,
            25_000,
            false,
            Amount::from_bits(500),
            [1u8; 16],
        )
        .unwrap();
        assert!(ord.verify());
        assert_eq!(
            DexLimitOrder::checked_quote_bits(100, 25_000),
            Some(2_500_000)
        );

        let rcpt = Address::from_bytes([0x22; 32]);
        let (snd, pk, xid, sig) =
            sign_babel_asset_transfer(&[0x33; 32], &asset, &rcpt, 50, 2, [9u8; 16]).unwrap();
        assert_eq!(pk.to_address(), snd);
        let s = Signature::from_bytes(&sig).unwrap();
        assert!(pk.verify(xid.as_bytes(), &s));
    }
}
