//! Cryptographically Signed **Desktop Auto-Update Manifest (`XCR_UPDATE_V1`)**.
//!
//! Protects self-custody desktop users against server, CDN, or repository compromise:
//! 1. **Offline Curve25519 Schnorr Signature (`XCR.DESKTOP.UPDATE_MANIFEST.V1`):** Every update
//!    manifest is signed by an offline release keypair and verified against a hardcoded 32-byte
//!    `EdwardsPoint` public key compiled directly inside `credit-desktop`.
//! 2. **End-to-End SHA-256 Binary Verification:** Downloaded `.exe` / binary bytes must match the
//!    signed `sha256_hex` (constant-time `ct_eq_slice`) before replacing the installed executable.

use credit_crypto::{
    EdwardsPoint, Scalar, ct_eq_slice, domain_hash, schnorr_sign, schnorr_verify, sha256,
};
use credit_types::Hash32;

pub const UPDATE_MANIFEST_FORMAT: &str = "XCR_UPDATE_V1";

/// Derives the deterministic Curve25519 release-signing `(Scalar, pubkey_bytes32)` from a 32-byte seed.
pub fn derive_release_signing_keypair(master_seed: &[u8; 32]) -> (Scalar, [u8; 32]) {
    let secret = Scalar::hash_from_parts("XCR.RELEASE.SIGNING_KEY.V1", &[master_seed]);
    let pub_bytes = EdwardsPoint::mul_basepoint_ct(&secret).to_bytes();
    (secret, pub_bytes)
}

/// Signed release metadata fetched by `credit-desktop` during background update checks.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DesktopUpdateManifest {
    pub version: String,
    pub build_number: u64,
    pub windows_x86_64_url: String,
    pub windows_x86_64_sha256: [u8; 32],
    pub notes: String,
    pub schnorr_sig: [u8; 64],
}

impl DesktopUpdateManifest {
    /// Computes the domain-separated 32-byte message bound into `schnorr_sig`.
    pub fn signing_digest(
        version: &str,
        build_number: u64,
        windows_x86_64_url: &str,
        windows_x86_64_sha256: &[u8; 32],
        notes: &str,
    ) -> Hash32 {
        domain_hash(
            "XCR.DESKTOP.UPDATE_MANIFEST.V1",
            &[
                version.as_bytes(),
                &build_number.to_le_bytes(),
                windows_x86_64_url.as_bytes(),
                windows_x86_64_sha256,
                notes.as_bytes(),
            ],
        )
    }

    /// Signs a new `DesktopUpdateManifest` for `binary_bytes` using `master_seed`.
    pub fn sign_for_binary(
        master_seed: &[u8; 32],
        version: impl Into<String>,
        build_number: u64,
        windows_x86_64_url: impl Into<String>,
        notes: impl Into<String>,
        binary_bytes: &[u8],
    ) -> (Self, [u8; 32]) {
        let version = version.into();
        let windows_x86_64_url = windows_x86_64_url.into();
        let notes = notes.into();
        let windows_x86_64_sha256 = sha256(binary_bytes);
        let (secret, pub_bytes) = derive_release_signing_keypair(master_seed);
        let digest = Self::signing_digest(
            &version,
            build_number,
            &windows_x86_64_url,
            &windows_x86_64_sha256,
            &notes,
        );
        let schnorr_sig = schnorr_sign(&secret, &pub_bytes, digest.as_bytes());
        (
            Self {
                version,
                build_number,
                windows_x86_64_url,
                windows_x86_64_sha256,
                notes,
                schnorr_sig,
            },
            pub_bytes,
        )
    }

    /// Verifies the manifest's Curve25519 Schnorr signature against `pinned_release_pubkey`.
    pub fn verify_signature(&self, pinned_release_pubkey: &[u8; 32]) -> bool {
        if self.version.is_empty() || !self.windows_x86_64_url.starts_with("https://") {
            return false;
        }
        let digest = Self::signing_digest(
            &self.version,
            self.build_number,
            &self.windows_x86_64_url,
            &self.windows_x86_64_sha256,
            &self.notes,
        );
        schnorr_verify(pinned_release_pubkey, digest.as_bytes(), &self.schnorr_sig)
    }

    /// Verifies BOTH the manifest's Schnorr signature AND the SHA-256 digest of `downloaded_bytes`.
    pub fn verify_downloaded_binary(
        &self,
        pinned_release_pubkey: &[u8; 32],
        downloaded_bytes: &[u8],
    ) -> bool {
        if !self.verify_signature(pinned_release_pubkey) {
            return false;
        }
        let actual_hash = sha256(downloaded_bytes);
        ct_eq_slice(&actual_hash, &self.windows_x86_64_sha256)
    }

    /// Encodes the signed manifest as deterministic line-oriented UTF-8 text.
    pub fn to_manifest_text(&self) -> String {
        let sha_hex = Hash32(self.windows_x86_64_sha256).to_hex();
        let sig_lo = Hash32::from_bytes(self.schnorr_sig[..32].try_into().unwrap()).to_hex();
        let sig_hi = Hash32::from_bytes(self.schnorr_sig[32..].try_into().unwrap()).to_hex();
        let clean_notes = self.notes.replace(['\r', '\n'], " ");
        format!(
            "format={UPDATE_MANIFEST_FORMAT}\nversion={}\nbuild_number={}\nwindows_x86_64_url={}\nwindows_x86_64_sha256={sha_hex}\nwindows_x86_64_sig={sig_lo}{sig_hi}\nnotes={clean_notes}\n",
            self.version, self.build_number, self.windows_x86_64_url
        )
    }

    /// Parses a `DesktopUpdateManifest` from UTF-8 manifest text (does not verify signature yet).
    pub fn from_manifest_text(text: &str) -> Option<Self> {
        let mut fmt_ok = false;
        let mut version = String::new();
        let mut build_number = None;
        let mut url = String::new();
        let mut sha_bytes = None;
        let mut sig_bytes = None;
        let mut notes = String::new();

        for raw_line in text.lines() {
            let line = raw_line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            if let Some(v) = line.strip_prefix("format=") {
                fmt_ok = v.trim() == UPDATE_MANIFEST_FORMAT;
            } else if let Some(v) = line.strip_prefix("version=") {
                version = v.trim().to_owned();
            } else if let Some(v) = line.strip_prefix("build_number=") {
                build_number = v.trim().parse::<u64>().ok();
            } else if let Some(v) = line.strip_prefix("windows_x86_64_url=") {
                url = v.trim().to_owned();
            } else if let Some(v) = line.strip_prefix("windows_x86_64_sha256=") {
                sha_bytes = decode_hex_32(v.trim());
            } else if let Some(v) = line.strip_prefix("windows_x86_64_sig=") {
                sig_bytes = decode_hex_64(v.trim());
            } else if let Some(v) = line.strip_prefix("notes=") {
                notes = v.trim().to_owned();
            }
        }

        if !fmt_ok || version.is_empty() || url.is_empty() {
            return None;
        }
        Some(Self {
            version,
            build_number: build_number?,
            windows_x86_64_url: url,
            windows_x86_64_sha256: sha_bytes?,
            notes,
            schnorr_sig: sig_bytes?,
        })
    }
}

pub fn decode_hex_32(hex: &str) -> Option<[u8; 32]> {
    if hex.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, slot) in out.iter_mut().enumerate() {
        *slot = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).ok()?;
    }
    Some(out)
}

pub fn decode_hex_64(hex: &str) -> Option<[u8; 64]> {
    if hex.len() != 128 {
        return None;
    }
    let mut out = [0u8; 64];
    for (i, slot) in out.iter_mut().enumerate() {
        *slot = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).ok()?;
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signed_desktop_update_manifest_roundtrips_and_rejects_any_tampering() {
        let seed = [0x3c; 32];
        let fake_exe = b"MZ\x90\x00-credits-desktop-release-binary-payload";
        let (manifest, pubkey) = DesktopUpdateManifest::sign_for_binary(
            &seed,
            "0.3.1",
            105,
            "https://github.com/haruki-morimoto/credit/releases/download/v0.3.0-testnet/credit-desktop-windows-x86_64.exe",
            "Safety Vault & Auto-Updater",
            fake_exe,
        );

        let text = manifest.to_manifest_text();
        let parsed = DesktopUpdateManifest::from_manifest_text(&text).expect("parse manifest");
        assert_eq!(parsed, manifest);
        assert!(parsed.verify_signature(&pubkey));
        assert!(parsed.verify_downloaded_binary(&pubkey, fake_exe));

        // 1. Tampered binary byte must be rejected:
        let mut corrupted_exe = fake_exe.to_vec();
        corrupted_exe[10] ^= 0x01;
        assert!(!parsed.verify_downloaded_binary(&pubkey, &corrupted_exe));

        // 2. Wrong/attacker signing key must be rejected:
        let (_, attacker_pk) = derive_release_signing_keypair(&[0x99; 32]);
        assert!(!parsed.verify_signature(&attacker_pk));

        // 3. Tampered URL in manifest must fail Schnorr verification:
        let mut hijacked = parsed.clone();
        hijacked.windows_x86_64_url = String::from("https://evil.example/malware.exe");
        assert!(!hijacked.verify_signature(&pubkey));
    }
}
