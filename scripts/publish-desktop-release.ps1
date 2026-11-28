# 1-Command Signed Release Publisher for Credits Desktop
# Builds `credit-desktop.exe`, signs `desktop-update.manifest` (`XCR_UPDATE_V1`) using your
# private offline `.local-secrets\release-signing.wallet`, updates your local install, and
# uploads both assets to GitHub Releases so every user's Desktop app auto-updates safely.

param(
    [switch]$BumpBuild,
    [string]$Notes = "Latest Credits Desktop improvements & security updates",
    [string]$ReleaseTag = "v0.3.0-testnet"
)

$ErrorActionPreference = "Stop"
$RepoRoot = Split-Path -Parent $PSScriptRoot
Set-Location $RepoRoot

$UpdaterRs = Join-Path $RepoRoot "crates\credit-desktop\src\updater.rs"
$RawUpdater = [System.IO.File]::ReadAllText($UpdaterRs)
$Match = [regex]::Match($RawUpdater, 'pub const APP_BUILD_NUMBER: u64 = (\d+);')
if (-not $Match.Success) {
    throw "Could not locate APP_BUILD_NUMBER in updater.rs"
}
$BuildNum = [uint64]$Match.Groups[1].Value
if ($BumpBuild) {
    $BuildNum = $BuildNum + 1
    $UpdatedSrc = $RawUpdater -replace 'pub const APP_BUILD_NUMBER: u64 = \d+;', "pub const APP_BUILD_NUMBER: u64 = $BuildNum;"
    [System.IO.File]::WriteAllText($UpdaterRs, $UpdatedSrc)
    Write-Host "Bumped APP_BUILD_NUMBER -> $BuildNum" -ForegroundColor Cyan
}

Write-Host "Building release binaries (credit-desktop & credit-cli)..." -ForegroundColor Cyan
& cargo build --release -p credit-desktop -p credit-cli
if ($LASTEXITCODE -ne 0) { throw "cargo build failed" }

$SigningWallet = Join-Path $RepoRoot ".local-secrets\release-signing.wallet"
if (-not (Test-Path $SigningWallet)) {
    throw "Missing offline release signing key at $SigningWallet"
}

$CliExe = Join-Path $RepoRoot "target\release\credit-cli.exe"
$BuiltDesktop = Join-Path $RepoRoot "target\release\credit-desktop.exe"
$StageDir = Join-Path $RepoRoot "target\release\desktop-publish"
New-Item -ItemType Directory -Force -Path $StageDir | Out-Null

$PublishedExeName = "credit-desktop-windows-x86_64.exe"
$PublishedExePath = Join-Path $StageDir $PublishedExeName
Copy-Item -Force $BuiltDesktop $PublishedExePath

$DownloadUrl = "https://github.com/haruki-morimoto/credit/releases/download/$ReleaseTag/$PublishedExeName"
$ManifestPath = Join-Path $StageDir "desktop-update.manifest"

$ManifestText = (& $CliExe release-sign --wallet $SigningWallet --bundle $PublishedExePath --value $BuildNum --query $DownloadUrl --memo $Notes) -join "`n"
if ($LASTEXITCODE -ne 0) { throw "release-sign failed" }
[System.IO.File]::WriteAllText($ManifestPath, ($ManifestText.Trim() + "`n"))

& powershell.exe -NoProfile -ExecutionPolicy Bypass -File (Join-Path $PSScriptRoot "install-desktop.ps1")

if (Get-Command gh.exe -ErrorAction SilentlyContinue) {
    Write-Host "Uploading signed Desktop binary & manifest to GitHub Release $ReleaseTag..." -ForegroundColor Cyan
    & gh.exe release view $ReleaseTag *>$null
    if ($LASTEXITCODE -ne 0) {
        & gh.exe release create $ReleaseTag --title "Credits (XCR) $ReleaseTag" --notes $Notes $PublishedExePath $ManifestPath
    } else {
        & gh.exe release upload $ReleaseTag $PublishedExePath $ManifestPath --clobber
    }
    if ($LASTEXITCODE -ne 0) { throw "gh release upload failed" }
}

Write-Host ""
Write-Host "================================================================" -ForegroundColor Green
Write-Host "  Published Signed Credits Desktop Release (Build #$BuildNum)!" -ForegroundColor Green
Write-Host "  Manifest : $ManifestPath"
Write-Host "  Asset    : $DownloadUrl"
Write-Host "================================================================" -ForegroundColor Green
