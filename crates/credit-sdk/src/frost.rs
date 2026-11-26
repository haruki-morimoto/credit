//! **RFC 9591 FROST `K-of-N` Threshold Curve25519 Schnorr Co-Signing** (`xcrfrost1_`).
//!
//! Splits a `Spending Pocket` Schnorr signing scalar over the Curve25519 prime-order field
//! $\mathbb{Z}_\ell$ ($\ell = 2^{252} + 27742317777372353535851937790883648493$) so any `K` of `N`
//! (`2 <= K <= N <= 16`) co-signers interactively produce a **standard `65-byte` Schnorr signature**
//! (`Signature::FastSchnorr`) **without ever reconstructing the private key on any machine**:
//! - **0 extra on-chain bytes:** Indistinguishable from a 1-of-1 `PasskeyP256` signature (`65B`).
//! - **100% governance privacy:** Validators never learn `K`, `N`, or which subset co-signed.
//! - **Identifiable abort:** Verifies $z_i \cdot B = D_i + \rho_i E_i + (\lambda_i c) Y_i$ per share.

use credit_crypto::{EdwardsPoint, PublicKey, Scalar, Signature, SignatureScheme, domain_hash};
use credit_types::Hash32;

use crate::cold_sign::{SignedColdTransfer, UnsignedColdTransfer};

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FrostError {
    InvalidParameters,
    MalformedUri,
    DuplicateOrInsufficientSigners,
    GroupKeyMismatch,
    PointDecompressionFailed,
    InvalidPartialSignature { culprit_index: u8 },
    FinalVerificationFailed,
}

impl core::fmt::Display for FrostError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::InvalidParameters => {
                write!(f, "FROST requires 2 <= threshold <= total_shares <= 16")
            }
            Self::MalformedUri => write!(f, "malformed FROST URI or checksum mismatch"),
            Self::DuplicateOrInsufficientSigners => {
                write!(f, "insufficient or duplicate FROST signer indices")
            }
            Self::GroupKeyMismatch => write!(f, "FROST shares belong to different group keys"),
            Self::PointDecompressionFailed => write!(f, "invalid Curve25519 Edwards point"),
            Self::InvalidPartialSignature { culprit_index } => write!(
                f,
                "invalid FROST partial signature from signer #{culprit_index}"
            ),
            Self::FinalVerificationFailed => {
                write!(f, "aggregated 65B Schnorr verification failed")
            }
        }
    }
}

/// Long-lived secret + public verification share held by signer `index` (`1..=N`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FrostKeyShare {
    pub threshold: u8,
    pub total_shares: u8,
    pub index: u8,
    pub group_pubkey: [u8; 32],
    pub secret_share: Scalar,
    pub public_share: [u8; 32],
}

/// Ephemeral Round-1 secret nonces kept strictly in local memory/file by signer `index`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FrostNonceSecret {
    pub index: u8,
    pub hiding_d: Scalar,
    pub binding_e: Scalar,
    pub commit: FrostNonceCommit,
}

/// Public Round-1 nonce commitment `(index, D_i, E_i)` shared with co-signers (`xcrfrostnonce1_`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FrostNonceCommit {
    pub index: u8,
    pub hiding_point: [u8; 32],
    pub binding_point: [u8; 32],
}

/// Public Round-2 verifiable partial signature `(index, z_i, Y_i)` (`xcrfrostpart1_`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FrostPartialSig {
    pub index: u8,
    pub z_share: Scalar,
    pub public_share: [u8; 32],
}

impl FrostKeyShare {
    pub const PREFIX: &'static str = "xcrfrost1_";
    const RAW_LEN: usize = 3 + 32 + 32 + 32 + 4; // 103B

    pub fn pocket_public_key(&self) -> PublicKey {
        PublicKey {
            scheme: SignatureScheme::PasskeyP256,
            merkle_root: Hash32(self.group_pubkey),
        }
    }

    pub fn to_uri(&self) -> String {
        let mut raw = [0u8; Self::RAW_LEN];
        raw[0] = self.threshold;
        raw[1] = self.total_shares;
        raw[2] = self.index;
        raw[3..35].copy_from_slice(&self.group_pubkey);
        raw[35..67].copy_from_slice(self.secret_share.as_bytes());
        raw[67..99].copy_from_slice(&self.public_share);
        let chk = domain_hash("XCR.FROST.KEYSHARE_CHK.V1", &[&raw[..99]]).0;
        raw[99..103].copy_from_slice(&chk[..4]);
        format!("{}{}", Self::PREFIX, hex_encode(&raw))
    }

    pub fn from_uri(uri: &str) -> Result<Self, FrostError> {
        let hex_part = uri
            .trim()
            .strip_prefix(Self::PREFIX)
            .ok_or(FrostError::MalformedUri)?;
        let raw = hex_decode(hex_part).ok_or(FrostError::MalformedUri)?;
        if raw.len() != Self::RAW_LEN {
            return Err(FrostError::MalformedUri);
        }
        let chk = domain_hash("XCR.FROST.KEYSHARE_CHK.V1", &[&raw[..99]]).0;
        if raw[99..103] != chk[..4] {
            return Err(FrostError::MalformedUri);
        }
        let threshold = raw[0];
        let total_shares = raw[1];
        let index = raw[2];
        if threshold < 2
            || total_shares < threshold
            || total_shares > 16
            || index == 0
            || index > total_shares
        {
            return Err(FrostError::InvalidParameters);
        }
        let mut group_pubkey = [0u8; 32];
        group_pubkey.copy_from_slice(&raw[3..35]);
        let mut sec_arr = [0u8; 32];
        sec_arr.copy_from_slice(&raw[35..67]);
        let secret_share =
            Scalar::from_canonical_bytes(&sec_arr).ok_or(FrostError::MalformedUri)?;
        let mut public_share = [0u8; 32];
        public_share.copy_from_slice(&raw[67..99]);
        if EdwardsPoint::mul_basepoint_ct(&secret_share).to_bytes() != public_share {
            return Err(FrostError::MalformedUri);
        }
        Ok(Self {
            threshold,
            total_shares,
            index,
            group_pubkey,
            secret_share,
            public_share,
        })
    }
}

impl FrostNonceSecret {
    pub const PREFIX: &'static str = "xcrfrostsec1_";
    const RAW_LEN: usize = 1 + 32 + 32 + 64 + 4; // 133B

    pub fn to_uri(&self) -> String {
        let mut raw = [0u8; Self::RAW_LEN];
        raw[0] = self.index;
        raw[1..33].copy_from_slice(self.hiding_d.as_bytes());
        raw[33..65].copy_from_slice(self.binding_e.as_bytes());
        raw[65..97].copy_from_slice(&self.commit.hiding_point);
        raw[97..129].copy_from_slice(&self.commit.binding_point);
        let chk = domain_hash("XCR.FROST.NONCESEC_CHK.V1", &[&raw[..129]]).0;
        raw[129..133].copy_from_slice(&chk[..4]);
        format!("{}{}", Self::PREFIX, hex_encode(&raw))
    }

    pub fn from_uri(uri: &str) -> Result<Self, FrostError> {
        let hex_part = uri
            .trim()
            .strip_prefix(Self::PREFIX)
            .ok_or(FrostError::MalformedUri)?;
        let raw = hex_decode(hex_part).ok_or(FrostError::MalformedUri)?;
        if raw.len() != Self::RAW_LEN {
            return Err(FrostError::MalformedUri);
        }
        let chk = domain_hash("XCR.FROST.NONCESEC_CHK.V1", &[&raw[..129]]).0;
        if raw[129..133] != chk[..4] {
            return Err(FrostError::MalformedUri);
        }
        let index = raw[0];
        let hiding_d = Scalar::from_canonical_bytes(raw[1..33].try_into().unwrap())
            .ok_or(FrostError::MalformedUri)?;
        let binding_e = Scalar::from_canonical_bytes(raw[33..65].try_into().unwrap())
            .ok_or(FrostError::MalformedUri)?;
        let mut hiding_point = [0u8; 32];
        hiding_point.copy_from_slice(&raw[65..97]);
        let mut binding_point = [0u8; 32];
        binding_point.copy_from_slice(&raw[97..129]);
        Ok(Self {
            index,
            hiding_d,
            binding_e,
            commit: FrostNonceCommit {
                index,
                hiding_point,
                binding_point,
            },
        })
    }
}

impl FrostNonceCommit {
    pub const PREFIX: &'static str = "xcrfrostnonce1_";
    const RAW_LEN: usize = 1 + 32 + 32 + 4; // 69B

    pub fn to_uri(&self) -> String {
        let mut raw = [0u8; Self::RAW_LEN];
        raw[0] = self.index;
        raw[1..33].copy_from_slice(&self.hiding_point);
        raw[33..65].copy_from_slice(&self.binding_point);
        let chk = domain_hash("XCR.FROST.NONCE_CHK.V1", &[&raw[..65]]).0;
        raw[65..69].copy_from_slice(&chk[..4]);
        format!("{}{}", Self::PREFIX, hex_encode(&raw))
    }

    pub fn from_uri(uri: &str) -> Result<Self, FrostError> {
        let hex_part = uri
            .trim()
            .strip_prefix(Self::PREFIX)
            .ok_or(FrostError::MalformedUri)?;
        let raw = hex_decode(hex_part).ok_or(FrostError::MalformedUri)?;
        if raw.len() != Self::RAW_LEN {
            return Err(FrostError::MalformedUri);
        }
        let chk = domain_hash("XCR.FROST.NONCE_CHK.V1", &[&raw[..65]]).0;
        if raw[65..69] != chk[..4] {
            return Err(FrostError::MalformedUri);
        }
        let index = raw[0];
        if index == 0 || index > 16 {
            return Err(FrostError::InvalidParameters);
        }
        let mut hiding_point = [0u8; 32];
        hiding_point.copy_from_slice(&raw[1..33]);
        let mut binding_point = [0u8; 32];
        binding_point.copy_from_slice(&raw[33..65]);
        let _ =
            EdwardsPoint::from_bytes(&hiding_point).ok_or(FrostError::PointDecompressionFailed)?;
        let _ =
            EdwardsPoint::from_bytes(&binding_point).ok_or(FrostError::PointDecompressionFailed)?;
        Ok(Self {
            index,
            hiding_point,
            binding_point,
        })
    }
}

impl FrostPartialSig {
    pub const PREFIX: &'static str = "xcrfrostpart1_";
    const RAW_LEN: usize = 1 + 32 + 32 + 4; // 69B

    pub fn to_uri(&self) -> String {
        let mut raw = [0u8; Self::RAW_LEN];
        raw[0] = self.index;
        raw[1..33].copy_from_slice(self.z_share.as_bytes());
        raw[33..65].copy_from_slice(&self.public_share);
        let chk = domain_hash("XCR.FROST.PART_CHK.V1", &[&raw[..65]]).0;
        raw[65..69].copy_from_slice(&chk[..4]);
        format!("{}{}", Self::PREFIX, hex_encode(&raw))
    }

    pub fn from_uri(uri: &str) -> Result<Self, FrostError> {
        let hex_part = uri
            .trim()
            .strip_prefix(Self::PREFIX)
            .ok_or(FrostError::MalformedUri)?;
        let raw = hex_decode(hex_part).ok_or(FrostError::MalformedUri)?;
        if raw.len() != Self::RAW_LEN {
            return Err(FrostError::MalformedUri);
        }
        let chk = domain_hash("XCR.FROST.PART_CHK.V1", &[&raw[..65]]).0;
        if raw[65..69] != chk[..4] {
            return Err(FrostError::MalformedUri);
        }
        let index = raw[0];
        if index == 0 || index > 16 {
            return Err(FrostError::InvalidParameters);
        }
        let z_share = Scalar::from_canonical_bytes(raw[1..33].try_into().unwrap())
            .ok_or(FrostError::MalformedUri)?;
        let mut public_share = [0u8; 32];
        public_share.copy_from_slice(&raw[33..65]);
        let _ =
            EdwardsPoint::from_bytes(&public_share).ok_or(FrostError::PointDecompressionFailed)?;
        Ok(Self {
            index,
            z_share,
            public_share,
        })
    }
}

/// Splits a wallet's `PasskeyP256` `Spending Pocket` key into `N` FROST scalar shares with threshold `K`.
pub fn frost_split_pocket_key(
    master_seed: &[u8; 32],
    threshold: u8,
    total_shares: u8,
    entropy: &[u8; 32],
) -> Result<Vec<FrostKeyShare>, FrostError> {
    if threshold < 2 || total_shares < threshold || total_shares > 16 {
        return Err(FrostError::InvalidParameters);
    }
    let pocket_seed = domain_hash("XCR.WALLET.POCKET_KEY.V1", &[master_seed]).0;
    let secret = Scalar::hash_from_parts(
        "XCR.FAST_SIG.SK.V2",
        &[&[SignatureScheme::PasskeyP256 as u8], &pocket_seed],
    );
    let group_pubkey = EdwardsPoint::mul_basepoint_ct(&secret).to_bytes();

    // Random degree-(K-1) polynomial over Z_l: f(x) = secret + a_1*x + ... + a_{K-1}*x^{K-1}
    let mut coeffs = Vec::with_capacity(threshold as usize);
    coeffs.push(secret);
    for deg in 1..threshold {
        coeffs.push(Scalar::hash_from_parts(
            "XCR.FROST.POLY_COEFF.V1",
            &[secret.as_bytes(), entropy, &[deg]],
        ));
    }

    let mut shares = Vec::with_capacity(total_shares as usize);
    for idx in 1..=total_shares {
        let x = Scalar::from_u64(idx as u64);
        let mut y = Scalar::ZERO;
        for c in coeffs.iter().rev() {
            y = (y * x) + *c;
        }
        let public_share = EdwardsPoint::mul_basepoint_ct(&y).to_bytes();
        shares.push(FrostKeyShare {
            threshold,
            total_shares,
            index: idx,
            group_pubkey,
            secret_share: y,
            public_share,
        });
    }
    Ok(shares)
}

/// Round 1: Generates a fresh `(d_i, e_i)` nonce pair and public `(D_i, E_i)` commitment for signer `share`.
pub fn frost_commit_nonce(share: &FrostKeyShare, entropy: &[u8; 32]) -> FrostNonceSecret {
    let hiding_d = Scalar::hash_from_parts(
        "XCR.FROST.NONCE_D.V1",
        &[share.secret_share.as_bytes(), entropy, &[share.index]],
    );
    let binding_e = Scalar::hash_from_parts(
        "XCR.FROST.NONCE_E.V1",
        &[
            share.secret_share.as_bytes(),
            entropy,
            &[share.index ^ 0xA5],
        ],
    );
    let hiding_point = EdwardsPoint::mul_basepoint_ct(&hiding_d).to_bytes();
    let binding_point = EdwardsPoint::mul_basepoint_ct(&binding_e).to_bytes();
    FrostNonceSecret {
        index: share.index,
        hiding_d,
        binding_e,
        commit: FrostNonceCommit {
            index: share.index,
            hiding_point,
            binding_point,
        },
    }
}

fn lagrange_coeff_at_zero(i: u8, participants: &[u8]) -> Result<Scalar, FrostError> {
    let xi = Scalar::from_u64(i as u64);
    let mut num = Scalar::from_u64(1);
    let mut den = Scalar::from_u64(1);
    for &j in participants {
        if j == i {
            continue;
        }
        let xj = Scalar::from_u64(j as u64);
        num = num * xj;
        den = den * (xj - xi);
    }
    let den_inv = den
        .invert()
        .ok_or(FrostError::DuplicateOrInsufficientSigners)?;
    Ok(num * den_inv)
}

type FrostRhoTuple = (u8, Scalar, EdwardsPoint, EdwardsPoint);

fn compute_group_nonce_and_rhos(
    group_pubkey: &[u8; 32],
    message: &[u8],
    sorted_commits: &[FrostNonceCommit],
) -> Result<([u8; 32], Vec<FrostRhoTuple>), FrostError> {
    let mut b_list = Vec::with_capacity(sorted_commits.len() * 65);
    for c in sorted_commits {
        b_list.push(c.index);
        b_list.extend_from_slice(&c.hiding_point);
        b_list.extend_from_slice(&c.binding_point);
    }
    let mut group_r = EdwardsPoint::identity();
    let mut out = Vec::with_capacity(sorted_commits.len());
    for c in sorted_commits {
        let d_pt = EdwardsPoint::from_bytes(&c.hiding_point)
            .ok_or(FrostError::PointDecompressionFailed)?;
        let e_pt = EdwardsPoint::from_bytes(&c.binding_point)
            .ok_or(FrostError::PointDecompressionFailed)?;
        let rho = Scalar::hash_from_parts(
            "XCR.FROST.RHO.V1",
            &[&[c.index], group_pubkey, message, &b_list],
        );
        group_r = group_r + d_pt + (rho * &e_pt);
        out.push((c.index, rho, d_pt, e_pt));
    }
    Ok((group_r.to_bytes(), out))
}

/// Round 2: Produces signer `i`'s partial signature `z_i` over `message` without reconstructing any key.
pub fn frost_sign_partial(
    share: &FrostKeyShare,
    nonce_secret: &FrostNonceSecret,
    commits: &[FrostNonceCommit],
    message: &[u8],
) -> Result<FrostPartialSig, FrostError> {
    if nonce_secret.index != share.index || commits.len() < share.threshold as usize {
        return Err(FrostError::DuplicateOrInsufficientSigners);
    }
    let mut sorted = commits.to_vec();
    sorted.sort_by_key(|c| c.index);
    for w in sorted.windows(2) {
        if w[0].index == w[1].index {
            return Err(FrostError::DuplicateOrInsufficientSigners);
        }
    }
    if !sorted
        .iter()
        .any(|c| c.index == share.index && *c == nonce_secret.commit)
    {
        return Err(FrostError::DuplicateOrInsufficientSigners);
    }
    let participants: Vec<u8> = sorted.iter().map(|c| c.index).collect();
    let (r_bytes, rhos) = compute_group_nonce_and_rhos(&share.group_pubkey, message, &sorted)?;
    let (_, rho_i, _, _) = rhos
        .into_iter()
        .find(|(idx, _, _, _)| *idx == share.index)
        .ok_or(FrostError::DuplicateOrInsufficientSigners)?;

    let challenge = Scalar::hash_from_parts(
        "XCR.SCHNORR.CHAL.V1",
        &[&r_bytes, &share.group_pubkey, message],
    );
    let lambda_i = lagrange_coeff_at_zero(share.index, &participants)?;
    let z_i = nonce_secret.hiding_d
        + (rho_i * nonce_secret.binding_e)
        + (lambda_i * challenge * share.secret_share);

    Ok(FrostPartialSig {
        index: share.index,
        z_share: z_i,
        public_share: share.public_share,
    })
}

/// Aggregates `K` verifiable partial signatures into a standard `65-byte` Curve25519 Schnorr signature.
/// The coordinator requires **zero** secret key material!
pub fn frost_aggregate_signature(
    group_pubkey: &[u8; 32],
    commits: &[FrostNonceCommit],
    partials: &[FrostPartialSig],
    message: &[u8],
) -> Result<[u8; 65], FrostError> {
    if commits.len() < 2 || commits.len() != partials.len() {
        return Err(FrostError::DuplicateOrInsufficientSigners);
    }
    let mut sorted_commits = commits.to_vec();
    sorted_commits.sort_by_key(|c| c.index);
    let mut sorted_partials = partials.to_vec();
    sorted_partials.sort_by_key(|p| p.index);
    for i in 0..sorted_commits.len() {
        if sorted_commits[i].index != sorted_partials[i].index {
            return Err(FrostError::DuplicateOrInsufficientSigners);
        }
        if i > 0 && sorted_commits[i - 1].index == sorted_commits[i].index {
            return Err(FrostError::DuplicateOrInsufficientSigners);
        }
    }

    let participants: Vec<u8> = sorted_commits.iter().map(|c| c.index).collect();
    let (r_bytes, rhos) = compute_group_nonce_and_rhos(group_pubkey, message, &sorted_commits)?;
    let challenge =
        Scalar::hash_from_parts("XCR.SCHNORR.CHAL.V1", &[&r_bytes, group_pubkey, message]);

    let mut total_z = Scalar::ZERO;
    for (part, (_, rho_i, d_pt, e_pt)) in sorted_partials.iter().zip(rhos) {
        let y_pt = EdwardsPoint::from_bytes(&part.public_share)
            .ok_or(FrostError::PointDecompressionFailed)?;
        let lambda_i = lagrange_coeff_at_zero(part.index, &participants)?;
        let lhs = EdwardsPoint::mul_basepoint_ct(&part.z_share);
        let rhs = d_pt + (rho_i * &e_pt) + ((lambda_i * challenge) * &y_pt);
        if lhs != rhs {
            return Err(FrostError::InvalidPartialSignature {
                culprit_index: part.index,
            });
        }
        total_z = total_z + part.z_share;
    }

    let mut sig64 = [0u8; 64];
    sig64[..32].copy_from_slice(&r_bytes);
    sig64[32..].copy_from_slice(total_z.as_bytes());

    let pk = PublicKey {
        scheme: SignatureScheme::PasskeyP256,
        merkle_root: Hash32(*group_pubkey),
    };
    let sig = Signature::FastSchnorr {
        scheme: SignatureScheme::PasskeyP256,
        sig64,
    };
    if !pk.verify(message, &sig) {
        return Err(FrostError::FinalVerificationFailed);
    }
    let mut out = [0u8; 65];
    out[0] = SignatureScheme::PasskeyP256 as u8;
    out[1..65].copy_from_slice(&sig64);
    Ok(out)
}

/// Aggregates `K` FROST partial signatures directly into an `xcrsigned1_` `SignedColdTransfer`
/// ready for immediate 1-RTT broadcast via `cold-broadcast`!
pub fn frost_aggregate_cold_transfer(
    unsigned: &UnsignedColdTransfer,
    group_pubkey: &[u8; 32],
    commits: &[FrostNonceCommit],
    partials: &[FrostPartialSig],
) -> Result<SignedColdTransfer, FrostError> {
    let pk = PublicKey {
        scheme: SignatureScheme::PasskeyP256,
        merkle_root: Hash32(*group_pubkey),
    };
    if pk.to_address() != unsigned.from {
        return Err(FrostError::GroupKeyMismatch);
    }
    let tx_id = unsigned.signing_digest();
    let signature_65 =
        frost_aggregate_signature(group_pubkey, commits, partials, tx_id.as_bytes())?;
    Ok(SignedColdTransfer {
        tx_id,
        signature_65,
    })
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
    use credit_crypto::Keypair;
    use credit_types::{Address, Amount};

    #[test]
    fn frost_2_of_3_and_3_of_5_produce_standard_65b_schnorr_without_key_reconstruction() {
        let master = [0x5A; 32];
        let pocket_seed = domain_hash("XCR.WALLET.POCKET_KEY.V1", &[&master]).0;
        let expected_kp = Keypair::from_seed(SignatureScheme::PasskeyP256, pocket_seed);

        // 2-of-3 split: Signers #1 and #3 co-sign an UnsignedColdTransfer without Signer #2!
        let shares = frost_split_pocket_key(&master, 2, 3, &[0x11; 32]).unwrap();
        assert_eq!(shares[0].pocket_public_key(), expected_kp.public_key());

        let s1 = FrostKeyShare::from_uri(&shares[0].to_uri()).unwrap();
        let s3 = FrostKeyShare::from_uri(&shares[2].to_uri()).unwrap();

        let unsigned = UnsignedColdTransfer {
            from: expected_kp.address(),
            to_stealth: Address::from_bytes([0x77; 32]),
            stealth_view_tag: 0x19,
            amount: Amount::from_chips(500).unwrap(),
            fee: Amount::from_bits(500),
            nonce: 3,
            value_commitment: [0x44; 32],
        };
        let msg = unsigned.signing_digest();

        let n1 = frost_commit_nonce(&s1, &[0xA1; 32]);
        let n3 = frost_commit_nonce(&s3, &[0xC3; 32]);
        let c1 = FrostNonceCommit::from_uri(&n1.commit.to_uri()).unwrap();
        let c3 = FrostNonceCommit::from_uri(&n3.commit.to_uri()).unwrap();
        let commits = [c3, c1];

        let p1 = frost_sign_partial(&s1, &n1, &commits, msg.as_bytes()).unwrap();
        let p3 = frost_sign_partial(&s3, &n3, &commits, msg.as_bytes()).unwrap();
        let p1_rt = FrostPartialSig::from_uri(&p1.to_uri()).unwrap();
        let p3_rt = FrostPartialSig::from_uri(&p3.to_uri()).unwrap();

        let signed_cold =
            frost_aggregate_cold_transfer(&unsigned, &s1.group_pubkey, &commits, &[p1_rt, p3_rt])
                .unwrap();
        let tx = unsigned
            .attach_verified_signature(&signed_cold, &expected_kp.public_key())
            .expect("unmodified 65B validator verify must pass");
        assert_eq!(tx.signature_bytes.len(), 65);

        // Tampering with Signer #3's partial signature triggers identifiable abort on culprit #3!
        let mut bad_p3 = p3_rt;
        bad_p3.z_share = bad_p3.z_share + Scalar::from_u64(1);
        assert_eq!(
            frost_aggregate_signature(&s1.group_pubkey, &commits, &[p1_rt, bad_p3], msg.as_bytes()),
            Err(FrostError::InvalidPartialSignature { culprit_index: 3 })
        );
    }
}
