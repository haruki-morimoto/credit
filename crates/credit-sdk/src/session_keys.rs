//! **ERC-4337-Style Scoped Session Keys (`xcrsk1_`) & Paymaster Fee Sponsorship**.
//!
//! Solves two critical Web3/Ethereum UX gaps directly on Layer 1 without smart-contract risk:
//! 1. **Scoped Session Keys:** Delegate an ephemeral signing sub-key (`session_pubkey`) to a web
//!    app, CLI automation, or AI agent with consensus-enforced `(max_spend, allowed_recipient, expiry_unix)`.
//!    Your master `Spending Pocket` key never touches the third-party app and can revoke in `1-RTT`.
//! 2. **Merchant / App Fee Sponsorship (`Paymaster`):** Allows a merchant or onboarding sponsor to
//!    co-sign and pay the `0.0005 XCR` network fee so a new user can transact with zero gas friction.

use credit_crypto::{Keypair, PublicKey, Signature, SignatureScheme, domain_hash};
use credit_types::{Address, Amount, Hash32};

/// Owner-signed delegation grant bundled with the ephemeral `session_secret` (`xcrsk1_<hex>`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SessionKeyGrant {
    pub session_id: Hash32,
    pub owner: Address,
    pub owner_pubkey: PublicKey,
    pub session_pubkey: PublicKey,
    pub max_spend: Amount,
    pub allowed_recipient: Option<Address>,
    pub expiry_unix: u64,
    pub salt: [u8; 16],
    pub owner_sig65: [u8; 65],
    /// Optional 32-byte session secret included when exporting `xcrsk1_` to the authorized app.
    pub session_secret: Option<[u8; 32]>,
}

impl SessionKeyGrant {
    pub const PREFIX: &'static str = "xcrsk1_";

    #[allow(clippy::too_many_arguments)]
    pub fn compute_id(
        owner: &Address,
        owner_pubkey: &PublicKey,
        session_pubkey: &PublicKey,
        max_spend: Amount,
        allowed_recipient: Option<&Address>,
        expiry_unix: u64,
        salt: &[u8; 16],
    ) -> Hash32 {
        let mut rcpt_buf = [0u8; 33];
        if let Some(r) = allowed_recipient {
            rcpt_buf[0] = 1;
            rcpt_buf[1..33].copy_from_slice(r.as_bytes());
        }
        domain_hash(
            "XCR.SESSION.GRANT_ID.V1",
            &[
                owner.as_bytes(),
                &[owner_pubkey.scheme as u8],
                owner_pubkey.merkle_root.as_bytes(),
                &[session_pubkey.scheme as u8],
                session_pubkey.merkle_root.as_bytes(),
                &max_spend.bits().to_le_bytes(),
                &rcpt_buf,
                &expiry_unix.to_le_bytes(),
                salt,
            ],
        )
    }

    /// Mints and owner-signs a fresh `SessionKeyGrant` bounded by `max_spend` and `expiry_unix`.
    pub fn issue(
        owner_master_seed: &[u8; 32],
        max_spend: Amount,
        allowed_recipient: Option<Address>,
        expiry_unix: u64,
        entropy: [u8; 32],
    ) -> Result<Self, &'static str> {
        if max_spend.is_zero() {
            return Err("session key max_spend must be > 0");
        }
        let pocket_seed = domain_hash("XCR.WALLET.POCKET_KEY.V1", &[owner_master_seed]).0;
        let mut owner_kp = Keypair::from_seed(SignatureScheme::PasskeyP256, pocket_seed);
        let owner = owner_kp.address();
        let owner_pubkey = owner_kp.public_key();

        let session_secret = domain_hash("XCR.SESSION.EPH_SK.V1", &[&entropy, owner.as_bytes()]).0;
        let session_kp = Keypair::from_seed(SignatureScheme::PasskeyP256, session_secret);
        let session_pubkey = session_kp.public_key();

        let mut salt = [0u8; 16];
        salt.copy_from_slice(&entropy[..16]);

        let session_id = Self::compute_id(
            &owner,
            &owner_pubkey,
            &session_pubkey,
            max_spend,
            allowed_recipient.as_ref(),
            expiry_unix,
            &salt,
        );
        let sig_vec = owner_kp.sign(session_id.as_bytes()).to_bytes();
        let owner_sig65: [u8; 65] = sig_vec.try_into().map_err(|_| "expected 65B signature")?;
        Ok(Self {
            session_id,
            owner,
            owner_pubkey,
            session_pubkey,
            max_spend,
            allowed_recipient,
            expiry_unix,
            salt,
            owner_sig65,
            session_secret: Some(session_secret),
        })
    }

    /// Public-only certificate stripped of `session_secret` for network transmission.
    pub fn public_grant(&self) -> Self {
        let mut c = self.clone();
        c.session_secret = None;
        c
    }

    /// Verifies owner authorization over `session_id`.
    pub fn verify_grant(&self) -> bool {
        if self.max_spend.is_zero() || self.owner_pubkey.to_address() != self.owner {
            return false;
        }
        let expected = Self::compute_id(
            &self.owner,
            &self.owner_pubkey,
            &self.session_pubkey,
            self.max_spend,
            self.allowed_recipient.as_ref(),
            self.expiry_unix,
            &self.salt,
        );
        if expected != self.session_id {
            return false;
        }
        let Some(sig) = Signature::from_bytes(&self.owner_sig65) else {
            return false;
        };
        self.owner_pubkey.verify(self.session_id.as_bytes(), &sig)
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(264);
        out.extend_from_slice(self.session_id.as_bytes());
        out.extend_from_slice(self.owner.as_bytes());
        out.push(self.owner_pubkey.scheme as u8);
        out.extend_from_slice(self.owner_pubkey.merkle_root.as_bytes());
        out.push(self.session_pubkey.scheme as u8);
        out.extend_from_slice(self.session_pubkey.merkle_root.as_bytes());
        out.extend_from_slice(&self.max_spend.bits().to_le_bytes());
        match self.allowed_recipient {
            Some(r) => {
                out.push(1);
                out.extend_from_slice(r.as_bytes());
            }
            None => out.push(0),
        }
        out.extend_from_slice(&self.expiry_unix.to_le_bytes());
        out.extend_from_slice(&self.salt);
        out.extend_from_slice(&self.owner_sig65);
        match self.session_secret {
            Some(sk) => {
                out.push(1);
                out.extend_from_slice(&sk);
            }
            None => out.push(0),
        }
        out
    }

    pub fn from_bytes(raw: &[u8]) -> Option<Self> {
        if raw.len() < 32 + 32 + 33 + 33 + 8 + 1 + 8 + 16 + 65 + 1 {
            return None;
        }
        let session_id = Hash32::from_bytes(raw[0..32].try_into().ok()?);
        let owner = Address::from_bytes(raw[32..64].try_into().ok()?);
        let o_scheme = SignatureScheme::from_u8(raw[64])?;
        let o_root = Hash32::from_bytes(raw[65..97].try_into().ok()?);
        let s_scheme = SignatureScheme::from_u8(raw[97])?;
        let s_root = Hash32::from_bytes(raw[98..130].try_into().ok()?);
        let max_spend = Amount::from_bits(u64::from_le_bytes(raw[130..138].try_into().ok()?));
        let mut pos = 138usize;
        let has_rcpt = *raw.get(pos)?;
        pos += 1;
        let allowed_recipient = if has_rcpt == 1 {
            let a = Address::from_bytes(raw.get(pos..pos + 32)?.try_into().ok()?);
            pos += 32;
            Some(a)
        } else if has_rcpt == 0 {
            None
        } else {
            return None;
        };
        let expiry_unix = u64::from_le_bytes(raw.get(pos..pos + 8)?.try_into().ok()?);
        pos += 8;
        let salt: [u8; 16] = raw.get(pos..pos + 16)?.try_into().ok()?;
        pos += 16;
        let owner_sig65: [u8; 65] = raw.get(pos..pos + 65)?.try_into().ok()?;
        pos += 65;
        let has_sk = *raw.get(pos)?;
        pos += 1;
        let session_secret = if has_sk == 1 {
            let sk: [u8; 32] = raw.get(pos..pos + 32)?.try_into().ok()?;
            pos += 32;
            Some(sk)
        } else if has_sk == 0 {
            None
        } else {
            return None;
        };
        if pos != raw.len() {
            return None;
        }
        let g = Self {
            session_id,
            owner,
            owner_pubkey: PublicKey {
                scheme: o_scheme,
                merkle_root: o_root,
            },
            session_pubkey: PublicKey {
                scheme: s_scheme,
                merkle_root: s_root,
            },
            max_spend,
            allowed_recipient,
            expiry_unix,
            salt,
            owner_sig65,
            session_secret,
        };
        g.verify_grant().then_some(g)
    }

    pub fn to_uri(&self) -> String {
        format!("{}{}", Self::PREFIX, hex_encode(&self.to_bytes()))
    }

    pub fn from_uri(uri: &str) -> Option<Self> {
        let hex_part = uri.trim().strip_prefix(Self::PREFIX)?;
        Self::from_bytes(&hex_decode(hex_part)?)
    }

    /// Signs a spend order using ONLY the delegated `session_secret` (master seed not required!).
    pub fn sign_session_spend(
        &self,
        recipient: Address,
        amount: Amount,
        spend_salt: [u8; 16],
    ) -> Result<(Hash32, [u8; 65]), &'static str> {
        let Some(sk) = self.session_secret else {
            return Err("SessionKeyGrant does not contain private session_secret");
        };
        if let Some(allowed) = self.allowed_recipient
            && allowed != recipient
        {
            return Err("recipient violates session key allowed_recipient policy");
        }
        let mut kp = Keypair::from_seed(SignatureScheme::PasskeyP256, sk);
        if kp.public_key() != self.session_pubkey {
            return Err("session_secret does not match session_pubkey");
        }
        let spend_id = session_spend_digest(&self.session_id, &recipient, amount, &spend_salt);
        let sig_vec = kp.sign(spend_id.as_bytes()).to_bytes();
        let sig65: [u8; 65] = sig_vec.try_into().map_err(|_| "expected 65B signature")?;
        Ok((spend_id, sig65))
    }
}

pub fn session_spend_digest(
    session_id: &Hash32,
    recipient: &Address,
    amount: Amount,
    spend_salt: &[u8; 16],
) -> Hash32 {
    domain_hash(
        "XCR.SESSION.SPEND.V1",
        &[
            session_id.as_bytes(),
            recipient.as_bytes(),
            &amount.bits().to_le_bytes(),
            spend_salt,
        ],
    )
}

pub fn session_revoke_digest(session_id: &Hash32) -> Hash32 {
    domain_hash("XCR.SESSION.REVOKE.V1", &[session_id.as_bytes()])
}

/// Digest signed by an ERC-4337-style `Paymaster` sponsor covering `fee` for `spend_id`.
pub fn fee_sponsor_digest(spend_id: &Hash32, fee: Amount) -> Hash32 {
    domain_hash(
        "XCR.PAYMASTER.SPONSOR.V1",
        &[spend_id.as_bytes(), &fee.bits().to_le_bytes()],
    )
}

pub fn sign_fee_sponsorship(
    sponsor_master_seed: &[u8; 32],
    spend_id: &Hash32,
    fee: Amount,
) -> (Address, PublicKey, [u8; 65]) {
    let pocket_seed = domain_hash("XCR.WALLET.POCKET_KEY.V1", &[sponsor_master_seed]).0;
    let mut kp = Keypair::from_seed(SignatureScheme::PasskeyP256, pocket_seed);
    let msg = fee_sponsor_digest(spend_id, fee);
    let sig_vec = kp.sign(msg.as_bytes()).to_bytes();
    let mut sig65 = [0u8; 65];
    sig65.copy_from_slice(&sig_vec);
    (kp.address(), kp.public_key(), sig65)
}

pub fn sign_session_revoke(
    owner_master_seed: &[u8; 32],
    session_id: &Hash32,
) -> (Address, PublicKey, [u8; 65]) {
    let pocket_seed = domain_hash("XCR.WALLET.POCKET_KEY.V1", &[owner_master_seed]).0;
    let mut kp = Keypair::from_seed(SignatureScheme::PasskeyP256, pocket_seed);
    let msg = session_revoke_digest(session_id);
    let sig_vec = kp.sign(msg.as_bytes()).to_bytes();
    let mut sig65 = [0u8; 65];
    sig65.copy_from_slice(&sig_vec);
    (kp.address(), kp.public_key(), sig65)
}

fn hex_encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

fn hex_decode(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return None;
    }
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len() / 2);
    for pair in b.as_chunks::<2>().0 {
        let hi = match pair[0] {
            c @ b'0'..=b'9' => c - b'0',
            c @ b'a'..=b'f' => c - b'a' + 10,
            c @ b'A'..=b'F' => c - b'A' + 10,
            _ => return None,
        };
        let lo = match pair[1] {
            c @ b'0'..=b'9' => c - b'0',
            c @ b'a'..=b'f' => c - b'a' + 10,
            c @ b'A'..=b'F' => c - b'A' + 10,
            _ => return None,
        };
        out.push((hi << 4) | lo);
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scoped_session_key_enforces_recipient_and_supports_paymaster_sponsorship() {
        let alice = [0x41; 32];
        let merchant = [0x52; 32];
        let game_server = Address::from_bytes([0x88; 32]);
        let wrong_dest = Address::from_bytes([0x99; 32]);

        let grant = SessionKeyGrant::issue(
            &alice,
            Amount::from_credits(5).unwrap(),
            Some(game_server),
            1_900_000_000,
            [7u8; 32],
        )
        .unwrap();
        let parsed = SessionKeyGrant::from_uri(&grant.to_uri()).unwrap();
        assert_eq!(parsed, grant);

        // App can sign for allowed `game_server`, but NOT `wrong_dest`!
        assert!(
            parsed
                .sign_session_spend(wrong_dest, Amount::from_chips(50).unwrap(), [1u8; 16])
                .is_err()
        );
        let (spend_id, sp_sig) = parsed
            .sign_session_spend(game_server, Amount::from_chips(50).unwrap(), [1u8; 16])
            .unwrap();
        assert!(parsed.session_pubkey.verify(
            spend_id.as_bytes(),
            &Signature::from_bytes(&sp_sig).unwrap()
        ));

        // Paymaster sponsorship signature verifies cleanly:
        let fee = Amount::from_bits(500);
        let (_, sponsor_pk, sponsor_sig) = sign_fee_sponsorship(&merchant, &spend_id, fee);
        assert!(sponsor_pk.verify(
            fee_sponsor_digest(&spend_id, fee).as_bytes(),
            &Signature::from_bytes(&sponsor_sig).unwrap()
        ));
    }
}
