# Credits (∀ / XCR) — Zero-Dependency SHA-256 Verified Binary Installer (Windows x86_64)
# Usage: irm https://raw.githubusercontent.com/haruki-morimoto/credit/main/scripts/install.ps1 | iex
$ErrorActionPreference = "Stop"

$Repo       = "haruki-morimoto/credit"
$Tag        = if ($env:XCR_VERSION) { $env:XCR_VERSION } else { "v0.3.0-testnet" }
$InstallDir = if ($env:XCR_INSTALL_DIR) { $env:XCR_INSTALL_DIR } else { Join-Path $HOME ".credits\bin" }

$Stage   = "credits-$Tag-windows-x86_64"
$Archive = "$Stage.tar.gz"
$BaseUrl = "https://github.com/$Repo/releases/download/$Tag"

$TmpDir = Join-Path ([System.IO.Path]::GetTempPath()) ("xcr_install_" + [Guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Force -Path $TmpDir | Out-Null

try {
    $ArchivePath = Join-Path $TmpDir $Archive
    $ShaPath     = Join-Path $TmpDir "$Archive.sha256"

    Write-Host "==> Downloading $Archive and SHA-256 checksum from GitHub Releases..."
    Invoke-WebRequest -UseBasicParsing -Uri "$BaseUrl/$Archive" -OutFile $ArchivePath
    Invoke-WebRequest -UseBasicParsing -Uri "$BaseUrl/$Archive.sha256" -OutFile $ShaPath

    $ExpectedSha = ((Get-Content -Raw $ShaPath).Trim() -split '\s+')[0].ToLowerInvariant()
    $ActualSha   = (Get-FileHash -Algorithm SHA256 -Path $ArchivePath).Hash.ToLowerInvariant()
    if ($ExpectedSha -ne $ActualSha) {
        throw "SHA-256 verification failed! Expected $ExpectedSha, got $ActualSha"
    }
    Write-Host "==> Verified SHA-256: $ActualSha"

    New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
    & tar.exe -xzf $ArchivePath -C $TmpDir
    foreach ($bin in @("credit-node.exe", "credit-cli.exe", "credit-gateway.exe")) {
        Copy-Item -Force (Join-Path (Join-Path $TmpDir $Stage) $bin) (Join-Path $InstallDir $bin)
    }

    $UserPath = [Environment]::GetEnvironmentVariable("Path", "User")
    if (-not (($UserPath -split ';') -contains $InstallDir)) {
        [Environment]::SetEnvironmentVariable("Path", "$UserPath;$InstallDir", "User")
        $env:Path = "$env:Path;$InstallDir"
    }

    Write-Host ""
    Write-Host "=========================================================================="
    Write-Host "  Credits (∀ / XCR) $Tag installed to $InstallDir"
    Write-Host "=========================================================================="
    Write-Host "  1. Join the Live Global Public Testnet (solo PoNC rewards every 60s):"
    Write-Host "     credit-node peer --testnet --bind 0.0.0.0:9501 --data-dir .\my-testnet-node"
    Write-Host ""
    Write-Host "  2. Launch your Live Browser Wallet & Merchant POS Terminal:"
    Write-Host "     credit-gateway --testnet --wallet .\my-testnet-node\miner.wallet --http 127.0.0.1:8090"
    Write-Host ""
    Write-Host "  3. Pre-join the 2027-01-01T00:00:00Z Mainnet Live Standby Mesh:"
    Write-Host "     credit-node peer --mainnet --bind 0.0.0.0:9500 --data-dir .\my-mainnet-node"
    Write-Host "=========================================================================="
} finally {
    Remove-Item -Recurse -Force $TmpDir -ErrorAction SilentlyContinue
}
