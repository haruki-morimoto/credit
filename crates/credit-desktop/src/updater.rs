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
pub const APP_BUILD_NUMBER: u64 = 106;

/// Hardcoded official Curve25519 release-signing public key (`7c597663533b...`).
/// Corresponding private seed lives strictly offline in `.local-secrets/release-signing.wallet`.
pub const OFFICIAL_RELEASE_PUBKEY_HEX: &str =
    "7c597663533bfe970b5621892a1220a56c1954c36a787a504d7ce7d373c9191d";

pub const UPDATE_MANIFEST_URLS: &[&str] = &[
    "https://raw.githubusercontent.com/haruki-morimoto/credit/desktop-binaries/desktop-update.manifest",
    "https://raw.githubusercontent.com/haruki-morimoto/credit/main/releases/desktop-update.manifest",
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

/// Removes any leftover `credit-desktop*.old` binaries from previous self-updates on startup.
pub fn cleanup_old_binary_on_startup() {
    if let Ok(cur) = env::current_exe()
        && let Some(dir) = cur.parent()
        && let Ok(entries) = fs::read_dir(dir)
    {
        for entry in entries.flatten() {
            let p = entry.path();
            if let Some(name) = p.file_name().and_then(|n| n.to_str())
                && name.starts_with("credit-desktop")
                && name.ends_with(".old")
                && p != cur
            {
                let _ = fs::remove_file(p);
            }
        }
    }
}

/// Normalizes `current_exe` back to `credit-desktop.exe` even if the running binary was renamed
/// to `credit-desktop.exe*.old` while open.
fn canonical_target_exe(current_exe: &Path) -> PathBuf {
    if let (Some(dir), Some(name)) = (
        current_exe.parent(),
        current_exe.file_name().and_then(|n| n.to_str()),
    ) && name.starts_with("credit-desktop.exe.")
        && name.ends_with(".old")
    {
        return dir.join("credit-desktop.exe");
    }
    if let (Some(dir), Some("credit-desktop.exe.old")) = (
        current_exe.parent(),
        current_exe.file_name().and_then(|n| n.to_str()),
    ) {
        return dir.join("credit-desktop.exe");
    }
    current_exe.to_path_buf()
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
/// swaps `<target_exe>` -> `<target_exe>.<pid>.old` (or spawns a post-exit swapper if locked),
/// writes the new binary, and relaunches it.
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
    let target_exe = canonical_target_exe(&current_exe);
    let pid = std::process::id();
    let mut old_os = target_exe.clone().into_os_string();
    old_os.push(format!(".{pid}.old"));
    let old_exe = PathBuf::from(old_os);
    let _ = fs::remove_file(&old_exe);

    // Fast Path: direct NTFS rename `<target_exe>` -> `<target_exe>.<pid>.old` + write:
    let direct_ok = if target_exe.exists() {
        if fs::rename(&target_exe, &old_exe).is_ok() {
            if fs::write(&target_exe, &bytes).is_ok() {
                true
            } else {
                let _ = fs::rename(&old_exe, &target_exe);
                false
            }
        } else {
            false
        }
    } else {
        fs::write(&target_exe, &bytes).is_ok()
    };

    if direct_ok {
        let _ = fs::remove_file(&staged_path);
        let _ = Command::new(&target_exe).spawn();
        std::process::exit(0);
    }

    // Fallback Path (Windows): if antivirus or a previously renamed `.old` handle blocked in-place
    // rename (`os error 5`), spawn a silent post-exit PowerShell swapper that waits for `pid` to
    // exit, copies the verified `staged-credit-desktop.exe` into place, and relaunches cleanly!
    #[cfg(target_os = "windows")]
    {
        use std::os::windows::process::CommandExt;
        const CREATE_NO_WINDOW: u32 = 0x0800_0000;

        let helper_ps1 = app_dir.join("apply_staged_update.ps1");
        let staged_esc = staged_path.to_string_lossy().replace('\'', "''");
        let target_esc = target_exe.to_string_lossy().replace('\'', "''");
        let old_esc = old_exe.to_string_lossy().replace('\'', "''");
        let script = format!(
            "Wait-Process -Id {pid} -Timeout 12 -ErrorAction SilentlyContinue\r\n\
             Start-Sleep -Milliseconds 350\r\n\
             if (Test-Path -LiteralPath '{target_esc}') {{\r\n\
                 Move-Item -Force -LiteralPath '{target_esc}' -Destination '{old_esc}' -ErrorAction SilentlyContinue\r\n\
             }}\r\n\
             Copy-Item -Force -LiteralPath '{staged_esc}' -Destination '{target_esc}'\r\n\
             Remove-Item -Force -LiteralPath '{staged_esc}' -ErrorAction SilentlyContinue\r\n\
             Start-Process -FilePath '{target_esc}'\r\n"
        );
        fs::write(&helper_ps1, script).map_err(|e| format!("helper script write failed: {e}"))?;

        let mut cmd = Command::new("powershell.exe");
        cmd.args([
            "-NoProfile",
            "-ExecutionPolicy",
            "Bypass",
            "-WindowStyle",
            "Hidden",
            "-File",
        ])
        .arg(&helper_ps1)
        .creation_flags(CREATE_NO_WINDOW);

        cmd.spawn()
            .map_err(|e| format!("failed to launch post-exit updater: {e}"))?;
        std::process::exit(0);
    }

    #[cfg(not(target_os = "windows"))]
    {
        Err(String::from("live executable replacement failed"))
    }
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
