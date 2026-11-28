//! **Cardano-Style First-Class Native Bearer Multi-Assets** (`xcrasset1_`).
//!
//! Enables event tickets, loyalty points, compute vouchers, and community co-op shares directly
//! in Layer-1 integer state — **eliminating Solidity smart-contract vulnerabilities and the
//! `ERC-20 approve()` / `transferFrom()` wallet-drainer bug class**:
//! - Fixed, immutable `total_supply: u64` bound cryptographically into `asset_id`.
//! - Pure bearer ownership (`(Address, AssetId) -> u64`) with **zero** issuer freeze or clawback keys.

use credit_crypto::{Keypair, PublicKey, Signature, SignatureScheme, domain_hash};
use credit_types::{Address, Amount, Hash32};

/// Signed genesis mint definition for a fixed-supply native bearer asset.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NativeAssetMint {
    pub asset_id: Hash32,
    pub issuer: Address,
    pub issuer_pubkey: PublicKey,
    pub ticker: String,
    pub total_supply: u64,
    pub decimals: u8,
    pub fee: Amount,
    pub salt: [u8; 16],
    pub sig65: [u8; 65],
}

impl NativeAssetMint {
    pub fn compute_asset_id(
        issuer: &Address,
        ticker: &str,
        total_supply: u64,
        decimals: u8,
        fee: Amount,
        salt: &[u8; 16],
    ) -> Hash32 {
        domain_hash(
            "XCR.ASSET.MINT_ID.V1",
            &[
                issuer.as_bytes(),
                ticker.as_bytes(),
                &total_supply.to_le_bytes(),
                &[decimals],
                &fee.bits().to_le_bytes(),
                salt,
            ],
        )
    }

    pub fn is_valid_ticker(ticker: &str) -> bool {
        let b = ticker.as_bytes();
        (1..=12).contains(&b.len())
            && b.iter()
                .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || *c == b'-')
    }

    pub fn sign_new(
        master_seed: &[u8; 32],
        ticker: &str,
        total_supply: u64,
        decimals: u8,
        fee: Amount,
        salt: [u8; 16],
    ) -> Result<Self, &'static str> {
        let t = ticker.trim().to_ascii_uppercase();
        if !Self::is_valid_ticker(&t) || total_supply == 0 || decimals > 9 {
            return Err("invalid asset ticker (1..=12 A-Z/0-9), zero supply, or decimals > 9");
        }
        let pocket_seed = domain_hash("XCR.WALLET.POCKET_KEY.V1", &[master_seed]).0;
        let mut kp = Keypair::from_seed(SignatureScheme::PasskeyP256, pocket_seed);
        let issuer = kp.address();
        let issuer_pubkey = kp.public_key();
        let asset_id = Self::compute_asset_id(&issuer, &t, total_supply, decimals, fee, &salt);
        let sig_vec = kp.sign(asset_id.as_bytes()).to_bytes();
        let sig65: [u8; 65] = sig_vec.try_into().map_err(|_| "expected 65B signature")?;
        Ok(Self {
            asset_id,
            issuer,
            issuer_pubkey,
            ticker: t,
            total_supply,
            decimals,
            fee,
            salt,
            sig65,
        })
    }

    pub fn verify(&self) -> bool {
        if !Self::is_valid_ticker(&self.ticker)
            || self.total_supply == 0
            || self.decimals > 9
            || self.issuer_pubkey.to_address() != self.issuer
        {
            return false;
        }
        let expected = Self::compute_asset_id(
            &self.issuer,
            &self.ticker,
            self.total_supply,
            self.decimals,
            self.fee,
            &self.salt,
        );
        if expected != self.asset_id {
            return false;
        }
        Signature::from_bytes(&self.sig65)
            .is_some_and(|sig| self.issuer_pubkey.verify(self.asset_id.as_bytes(), &sig))
    }
}

/// Canonical digest signed when transferring `units` of `asset_id` to `recipient`.
pub fn asset_transfer_digest(
    asset_id: &Hash32,
    sender: &Address,
    recipient: &Address,
    units: u64,
    fee: Amount,
    salt: &[u8; 16],
) -> Hash32 {
    domain_hash(
        "XCR.ASSET.XFER.V1",
        &[
            asset_id.as_bytes(),
            sender.as_bytes(),
            recipient.as_bytes(),
            &units.to_le_bytes(),
            &fee.bits().to_le_bytes(),
            salt,
        ],
    )
}

/// Signs a direct peer-to-peer native bearer asset transfer (`0` smart contracts, `0` approvals).
pub fn sign_asset_transfer(
    master_seed: &[u8; 32],
    asset_id: &Hash32,
    recipient: &Address,
    units: u64,
    fee: Amount,
    salt: [u8; 16],
) -> (Address, PublicKey, Hash32, [u8; 65]) {
    let pocket_seed = domain_hash("XCR.WALLET.POCKET_KEY.V1", &[master_seed]).0;
    let mut kp = Keypair::from_seed(SignatureScheme::PasskeyP256, pocket_seed);
    let sender = kp.address();
    let pk = kp.public_key();
    let xfer_id = asset_transfer_digest(asset_id, &sender, recipient, units, fee, &salt);
    let sig_vec = kp.sign(xfer_id.as_bytes()).to_bytes();
    let mut sig65 = [0u8; 65];
    sig65.copy_from_slice(&sig_vec);
    (sender, pk, xfer_id, sig65)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn native_bearer_asset_mint_and_transfer_signatures_verify() {
        let mint = NativeAssetMint::sign_new(
            &[0x33; 32],
            "conf-vip27",
            1_000,
            0,
            Amount::from_bits(500),
            [5u8; 16],
        )
        .unwrap();
        assert_eq!(mint.ticker, "CONF-VIP27");
        assert!(mint.verify());

        let (_, pk, xfer_id, sig65) = sign_asset_transfer(
            &[0x33; 32],
            &mint.asset_id,
            &Address::from_bytes([0x77; 32]),
            2,
            Amount::from_bits(500),
            [6u8; 16],
        );
        assert!(pk.verify(xfer_id.as_bytes(), &Signature::from_bytes(&sig65).unwrap()));
    }
}
