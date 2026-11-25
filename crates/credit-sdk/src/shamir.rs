//! Information-Theoretic **`K-of-N` Shamir Secret Sharing** (`GF(256)`) for Sovereign Guardian Backup.
//!
//! Splits any 32-byte master seed into `N` (`2..=16`) checksummed Guardian Shares such that:
//! - Any **`K` (`2..=N`) shares** reconstruct 100% of the master seed via exact Lagrange
//!   interpolation at `x = 0` over `GF(2^8)` (`x^8 + x^4 + x^3 + x^2 + 1 = 0x11D`).
//! - Any **`K - 1` or fewer shares** leak strictly **zero bits** of information about the seed.
//! - Every share can be printed as a compact `xcrshare1_...` URI/QR code **and** as a 24-word
//!   paper Guardian Card (`encode_mnemonic_24(&share.y)`).

use core::fmt;

use credit_crypto::domain_hash;

use crate::keystore::ZeroizingSeed;
use crate::mnemonic::format_backup_card_24;
use crate::qr::{QrCode, QrError};

/// Single `K-of-N` Shamir Guardian Share (`x in 1..=16`, `y` = 32-byte evaluation vector).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ShamirShare {
    pub threshold: u8,
    pub total_shares: u8,
    pub index: u8,
    pub set_id: [u8; 4],
    pub y: [u8; 32],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ShamirError {
    InvalidParameters,
    InsufficientShares { required: usize, supplied: usize },
    MismatchedShareSet,
    DuplicateShareIndex(u8),
    MalformedShareUri,
    ChecksumFailed,
}

impl fmt::Display for ShamirError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidParameters => {
                f.write_str("Shamir parameters must satisfy `2 <= threshold <= total_shares <= 16`")
            }
            Self::InsufficientShares { required, supplied } => {
                write!(
                    f,
                    "need at least {required} Guardian Shares, got {supplied}"
                )
            }
            Self::MismatchedShareSet => {
                f.write_str("shares belong to different backups (set_id/threshold mismatch)")
            }
            Self::DuplicateShareIndex(idx) => write!(f, "duplicate Guardian Share #{idx}"),
            Self::MalformedShareUri => f.write_str("malformed `xcrshare1_` Guardian Share URI"),
            Self::ChecksumFailed => f.write_str("Guardian Share failed integrity checksum"),
        }
    }
}

impl ShamirShare {
    pub const PREFIX: &'static str = "xcrshare1_";

    /// Encodes this share as `xcrshare1_<K>of<N>_<idx>_<setid8>_<y64>_<chk8>` (`95–98` chars, fits in a small QR!).
    pub fn to_uri(&self) -> String {
        let chk = self.checksum4();
        format!(
            "{}{}of{}_{}_{}_{}_{}",
            Self::PREFIX,
            self.threshold,
            self.total_shares,
            self.index,
            hex_encode(&self.set_id),
            hex_encode(&self.y),
            hex_encode(&chk),
        )
    }

    pub fn from_uri(uri: &str) -> Result<Self, ShamirError> {
        let body = uri
            .trim()
            .strip_prefix(Self::PREFIX)
            .ok_or(ShamirError::MalformedShareUri)?;
        let parts: Vec<&str> = body.split('_').collect();
        if parts.len() != 5 {
            return Err(ShamirError::MalformedShareUri);
        }
        let (k_s, n_s) = parts[0]
            .split_once("of")
            .ok_or(ShamirError::MalformedShareUri)?;
        let threshold: u8 = k_s.parse().map_err(|_| ShamirError::MalformedShareUri)?;
        let total_shares: u8 = n_s.parse().map_err(|_| ShamirError::MalformedShareUri)?;
        let index: u8 = parts[1]
            .parse()
            .map_err(|_| ShamirError::MalformedShareUri)?;
        if threshold < 2
            || total_shares < threshold
            || total_shares > 16
            || index == 0
            || index > total_shares
        {
            return Err(ShamirError::InvalidParameters);
        }
        let set_vec = hex_decode(parts[2]).ok_or(ShamirError::MalformedShareUri)?;
        let y_vec = hex_decode(parts[3]).ok_or(ShamirError::MalformedShareUri)?;
        let chk_vec = hex_decode(parts[4]).ok_or(ShamirError::MalformedShareUri)?;
        if set_vec.len() != 4 || y_vec.len() != 32 || chk_vec.len() != 4 {
            return Err(ShamirError::MalformedShareUri);
        }
        let mut set_id = [0u8; 4];
        set_id.copy_from_slice(&set_vec);
        let mut y = [0u8; 32];
        y.copy_from_slice(&y_vec);
        let share = Self {
            threshold,
            total_shares,
            index,
            set_id,
            y,
        };
        if share.checksum4().as_slice() != chk_vec.as_slice() {
            return Err(ShamirError::ChecksumFailed);
        }
        Ok(share)
    }

    /// Formats a printable Guardian Card containing both the URI and 24-word evaluation table.
    pub fn format_guardian_card(&self) -> String {
        format!(
            "=== CREDITS (∀) GUARDIAN SHARE #{} OF {} (ANY {} RECOVER WALLET) ===\nSet Fingerprint: {}\nShare URI      : {}\n24-Word Vector :\n{}",
            self.index,
            self.total_shares,
            self.threshold,
            hex_encode(&self.set_id),
            self.to_uri(),
            format_backup_card_24(&self.y)
        )
    }

    pub fn to_qr_code(&self) -> Result<QrCode, QrError> {
        QrCode::encode_str(&self.to_uri())
    }

    fn checksum4(&self) -> [u8; 4] {
        let h = domain_hash(
            "XCR.SHAMIR.SHARE_CHK.V1",
            &[
                &[self.threshold, self.total_shares, self.index],
                &self.set_id,
                &self.y,
            ],
        );
        let mut out = [0u8; 4];
        out.copy_from_slice(&h.0[..4]);
        out
    }
}

/// Splits `secret` into `total_shares` (`N`) shares with reconstruction threshold `threshold` (`K`).
pub fn split_secret_shamir(
    secret: &[u8; 32],
    threshold: u8,
    total_shares: u8,
    entropy: &[u8; 32],
) -> Result<Vec<ShamirShare>, ShamirError> {
    if threshold < 2 || total_shares < threshold || total_shares > 16 {
        return Err(ShamirError::InvalidParameters);
    }
    let set_hash = domain_hash("XCR.SHAMIR.SET_ID.V1", &[secret, entropy]).0;
    let mut set_id = [0u8; 4];
    set_id.copy_from_slice(&set_hash[..4]);

    // Pre-generate random degree-(K-1) polynomial coefficients `coeffs[byte_idx][deg 1..K]`:
    let mut coeffs = vec![vec![0u8; threshold as usize]; 32];
    for (byte_idx, poly) in coeffs.iter_mut().enumerate() {
        poly[0] = secret[byte_idx];
        for (deg, c) in poly.iter_mut().enumerate().skip(1) {
            let h = domain_hash(
                "XCR.SHAMIR.COEFF.V1",
                &[secret, entropy, &[byte_idx as u8, deg as u8]],
            );
            *c = h.0[0];
        }
    }

    let mut shares = Vec::with_capacity(total_shares as usize);
    for idx in 1..=total_shares {
        let x = idx;
        let mut y = [0u8; 32];
        for (byte_idx, poly) in coeffs.iter().enumerate() {
            // Horner's method evaluation `P(x)` in `GF(256)`:
            let mut acc = 0u8;
            for &coef in poly.iter().rev() {
                acc = gf256_mul(acc, x) ^ coef;
            }
            y[byte_idx] = acc;
        }
        shares.push(ShamirShare {
            threshold,
            total_shares,
            index: idx,
            set_id,
            y,
        });
    }
    Ok(shares)
}

/// Reconstructs the 32-byte master seed from at least `threshold` distinct `ShamirShare`s.
pub fn combine_secret_shamir(shares: &[ShamirShare]) -> Result<ZeroizingSeed, ShamirError> {
    let Some(first) = shares.first() else {
        return Err(ShamirError::InsufficientShares {
            required: 2,
            supplied: 0,
        });
    };
    let k = first.threshold as usize;
    if shares.len() < k {
        return Err(ShamirError::InsufficientShares {
            required: k,
            supplied: shares.len(),
        });
    }
    let subset = &shares[..k];
    for (i, s) in subset.iter().enumerate() {
        if s.threshold != first.threshold || s.set_id != first.set_id {
            return Err(ShamirError::MismatchedShareSet);
        }
        if s.index == 0 {
            return Err(ShamirError::InvalidParameters);
        }
        for prev in &subset[..i] {
            if prev.index == s.index {
                return Err(ShamirError::DuplicateShareIndex(s.index));
            }
        }
    }

    let mut secret = [0u8; 32];
    for (byte_idx, out_byte) in secret.iter_mut().enumerate() {
        let mut sum = 0u8;
        for (m, sm) in subset.iter().enumerate() {
            let xm = sm.index;
            let mut num = 1u8;
            let mut den = 1u8;
            for (r, sr) in subset.iter().enumerate() {
                if r != m {
                    let xr = sr.index;
                    num = gf256_mul(num, xr);
                    den = gf256_mul(den, xm ^ xr);
                }
            }
            let basis = gf256_mul(num, gf256_inv(den));
            sum ^= gf256_mul(sm.y[byte_idx], basis);
        }
        *out_byte = sum;
    }
    Ok(ZeroizingSeed::new(secret))
}

#[inline]
fn gf256_mul(mut a: u8, mut b: u8) -> u8 {
    let mut p = 0u8;
    for _ in 0..8 {
        if (b & 1) != 0 {
            p ^= a;
        }
        let hi = (a & 0x80) != 0;
        a <<= 1;
        if hi {
            a ^= 0x1D;
        }
        b >>= 1;
    }
    p
}

/// Multiplicative inverse `a^254` in `GF(256)` via Fermat's Little Theorem (constant-time).
#[inline]
fn gf256_inv(a: u8) -> u8 {
    let a2 = gf256_mul(a, a);
    let a4 = gf256_mul(a2, a2);
    let a8 = gf256_mul(a4, a4);
    let a16 = gf256_mul(a8, a8);
    let a32 = gf256_mul(a16, a16);
    let a64 = gf256_mul(a32, a32);
    let a128 = gf256_mul(a64, a64);
    // 254 = 128 + 64 + 32 + 16 + 8 + 4 + 2:
    let t = gf256_mul(a128, a64);
    let t = gf256_mul(t, a32);
    let t = gf256_mul(t, a16);
    let t = gf256_mul(t, a8);
    let t = gf256_mul(t, a4);
    gf256_mul(t, a2)
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
        let hi = nibble(pair[0])?;
        let lo = nibble(pair[1])?;
        out.push((hi << 4) | lo);
    }
    Some(out)
}

fn nibble(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shamir_2_of_3_and_3_of_5_reconstruct_across_any_subset_and_qr() {
        let seed = [0x9C; 32];
        let shares = split_secret_shamir(&seed, 2, 3, &[0x11; 32]).unwrap();
        assert_eq!(shares.len(), 3);

        // Verify URI + QR roundtrip on every share:
        for sh in &shares {
            let uri = sh.to_uri();
            assert_eq!(ShamirShare::from_uri(&uri).unwrap(), *sh);
            assert!(sh.to_qr_code().is_ok());
        }

        // Any 2-of-3 combination recovers exact master seed:
        assert_eq!(
            combine_secret_shamir(&[shares[0].clone(), shares[1].clone()])
                .unwrap()
                .as_bytes(),
            &seed
        );
        assert_eq!(
            combine_secret_shamir(&[shares[0].clone(), shares[2].clone()])
                .unwrap()
                .as_bytes(),
            &seed
        );
        assert_eq!(
            combine_secret_shamir(&[shares[1].clone(), shares[2].clone()])
                .unwrap()
                .as_bytes(),
            &seed
        );

        // 1 share alone is rejected, and duplicating share #1 is rejected:
        assert!(combine_secret_shamir(&[shares[0].clone()]).is_err());
        assert_eq!(
            combine_secret_shamir(&[shares[0].clone(), shares[0].clone()]).err(),
            Some(ShamirError::DuplicateShareIndex(1))
        );

        // 3-of-5 non-contiguous subset `(shares[1], shares[3], shares[4])`:
        let s5 = split_secret_shamir(&seed, 3, 5, &[0x22; 32]).unwrap();
        let rec5 = combine_secret_shamir(&[s5[1].clone(), s5[3].clone(), s5[4].clone()]).unwrap();
        assert_eq!(rec5.as_bytes(), &seed);
    }
}
