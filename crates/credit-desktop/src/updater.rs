//! Cryptographically Verified **In-Place Self-Updater (`updater.rs`)** for Credits Desktop.
//!
//! - **Pinned Curve25519 Release Key (`OFFICIAL_RELEASE_PUBKEY_HEX`):** Refuses any update manifest
//!   or binary that is not signed by the offline release keypair and verified end-to-end via SHA-256.
//! - **Zero-UAC Silent Staging:** Downloads updates silently in the background (`CREATE_NO_WINDOW`)
//!   and swaps `<current_exe>` -> `<current_exe>.old` in place on NTFS before relaunching.

use std::env;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::process::Command;

use credit_sdk::{DesktopUpdateManifest, decode_hex_32};

pub const APP_VERSION: &str = env!("CARGO_PKG_VERSION");
pub const APP_BUILD_NUMBER: u64 = 102;

/// Hardcoded official Curve25519 release-signing public key (`7c597663533b...`).
/// Corresponding private seed lives strictly offline in `.local-secrets/release-signing.wallet`.
pub const OFFICIAL_RELEASE_PUBKEY_HEX: &str =
    "7c597663533bfe970b5621892a1220a56c1954c36a787a504d7ce7d373c9191d";

pub const UPDATE_MANIFEST_URLS: &[&str] = &[
    "https://github.com/haruki-morimoto/credit/releases/download/v0.3.0-testnet/desktop-update.manifest",
    "https://github.com/haruki-morimoto/credit/releases/latest/download/desktop-update.manifest",
];

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AutoUpdateStatus {
    UpToDate,
    Checking,
    Available { manifest: DesktopUpdateManifest },
    Downloading { version: String, build_number: u64 },
    StagedReady { manifest: DesktopUpdateManifest },
    Error(String),
}

pub fn pinned_release_pubkey() -> [u8; 32] {
    decode_hex_32(OFFICIAL_RELEASE_PUBKEY_HEX).expect("valid 64-hex pinned release public key")
}

/// Removes any leftover `<current_exe>.old` from a previous in-place self-update on startup.
pub fn cleanup_old_binary_on_startup() {
    if let Ok(cur) = env::current_exe() {
        let mut old_os = cur.clone().into_os_string();
        old_os.push(".old");
        let _ = fs::remove_file(PathBuf::from(old_os));
    }
}

fn silent_curl_download(url: &str, dest: &Path, max_secs: u32) -> io::Result<()> {
    let mut cmd = Command::new("curl");
    cmd.args([
        "-fsSL",
        "--max-time",
        &max_secs.to_string(),
        "-H",
        "Cache-Control: no-cache",
        url,
        "-o",
    ])
    .arg(dest);

    #[cfg(target_os = "windows")]
    {
        use std::os::windows::process::CommandExt;
        const CREATE_NO_WINDOW: u32 = 0x0800_0000;
        cmd.creation_flags(CREATE_NO_WINDOW);
    }

    let status = cmd.status()?;
    if status.success() {
        Ok(())
    } else {
        Err(io::Error::other(format!("curl exited with {status}")))
    }
}

/// Fetches and cryptographically verifies the latest `DesktopUpdateManifest`.
/// Returns `Ok(Some(manifest))` strictly when `manifest.build_number > APP_BUILD_NUMBER` and
/// `manifest.verify_signature(&pinned_release_pubkey())` succeeds.
pub fn fetch_verified_newer_manifest(
    app_dir: &Path,
) -> Result<Option<DesktopUpdateManifest>, String> {
    let pk = pinned_release_pubkey();
    let tmp_manifest = app_dir.join(".update_check.manifest.tmp");
    let mut last_err = String::from("manifest unreachable");

    for &url in UPDATE_MANIFEST_URLS {
        if let Err(e) = silent_curl_download(url, &tmp_manifest, 12) {
            last_err = format!("{e}");
            continue;
        }
        let Ok(txt) = fs::read_to_string(&tmp_manifest) else {
            continue;
        };
        let _ = fs::remove_file(&tmp_manifest);

        let Some(manifest) = DesktopUpdateManifest::from_manifest_text(&txt) else {
            last_err = String::from("malformed update manifest");
            continue;
        };
        if !manifest.verify_signature(&pk) {
            return Err(String::from(
                "SECURITY ALERT: rejected update manifest with invalid release signature",
            ));
        }
        if manifest.build_number > APP_BUILD_NUMBER {
            return Ok(Some(manifest));
        }
        return Ok(None);
    }
    let _ = fs::remove_file(&tmp_manifest);
    Err(last_err)
}

/// Downloads the signed executable into `app_dir/staged-credit-desktop.exe` and verifies
/// both its Curve25519 Schnorr manifest signature and full SHA-256 binary hash.
pub fn download_and_verify_staged_binary(
    app_dir: &Path,
    manifest: &DesktopUpdateManifest,
) -> Result<PathBuf, String> {
    let pk = pinned_release_pubkey();
    if !manifest.verify_signature(&pk) {
        return Err(String::from("invalid manifest signature"));
    }
    let dl_tmp = app_dir.join("staged-credit-desktop.exe.part");
    let staged_final = app_dir.join("staged-credit-desktop.exe");
    let _ = fs::remove_file(&dl_tmp);

    silent_curl_download(&manifest.windows_x86_64_url, &dl_tmp, 120)
        .map_err(|e| format!("download failed: {e}"))?;

    let bytes = fs::read(&dl_tmp).map_err(|e| format!("read staged file failed: {e}"))?;
    if bytes.len() < 500_000 || !bytes.starts_with(b"MZ") {
        let _ = fs::remove_file(&dl_tmp);
        return Err(String::from(
            "downloaded file is not a valid Windows executable",
        ));
    }
    if !manifest.verify_downloaded_binary(&pk, &bytes) {
        let _ = fs::remove_file(&dl_tmp);
        return Err(String::from(
            "SECURITY ALERT: SHA-256 mismatch against signed manifest — update aborted",
        ));
    }

    let _ = fs::remove_file(&staged_final);
    fs::rename(&dl_tmp, &staged_final).map_err(|e| format!("stage rename failed: {e}"))?;
    Ok(staged_final)
}

/// Re-verifies the staged update right before installation (preventing TOCTOU tampering),
/// swaps `<current_exe>` -> `<current_exe>.old`, writes the new binary, and relaunches it.
pub fn apply_staged_update_and_relaunch(
    app_dir: &Path,
    manifest: &DesktopUpdateManifest,
) -> Result<(), String> {
    let pk = pinned_release_pubkey();
    let staged_path = app_dir.join("staged-credit-desktop.exe");
    let bytes = fs::read(&staged_path).map_err(|e| format!("missing staged update: {e}"))?;
    if bytes.len() < 500_000
        || !bytes.starts_with(b"MZ")
        || !manifest.verify_downloaded_binary(&pk, &bytes)
    {
        let _ = fs::remove_file(&staged_path);
        return Err(String::from(
            "staged binary failed pre-launch signature check",
        ));
    }

    let current_exe = env::current_exe().map_err(|e| format!("locate current_exe failed: {e}"))?;
    let mut old_os = current_exe.clone().into_os_string();
    old_os.push(".old");
    let old_exe = PathBuf::from(old_os);
    let _ = fs::remove_file(&old_exe);

    fs::rename(&current_exe, &old_exe)
        .map_err(|e| format!("live executable rename failed: {e}"))?;
    if let Err(e) = fs::write(&current_exe, &bytes) {
        // Roll back immediately if writing the new binary failed:
        let _ = fs::rename(&old_exe, &current_exe);
        return Err(format!("writing updated executable failed: {e}"));
    }
    let _ = fs::remove_file(&staged_path);

    let _ = Command::new(&current_exe).spawn();
    std::process::exit(0);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pinned_release_pubkey_is_valid_64_hex() {
        let pk = pinned_release_pubkey();
        assert_ne!(pk, [0u8; 32]);
    }
}
