# 1-Command Signed Release Publisher for Credits Desktop
# Builds `credit-desktop.exe`, signs `desktop-update.manifest` (`XCR_UPDATE_V1`) using your
# private offline `.local-secrets\release-signing.wallet`, updates your local install, and
# uploads both assets to GitHub Releases so every user's Desktop app auto-updates safely.

param(
    [switch]$BumpBuild,
    [switch]$SignGitHubRelease,
    [string]$Notes = "Latest Credits Desktop improvements & security updates",
    [string]$ReleaseTag = "v0.3.0-testnet",
    [string]$BinaryDistBranch = "desktop-binaries"
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
if ($BumpBuild -and -not $SignGitHubRelease) {
    $BuildNum = $BuildNum + 1
    $UpdatedSrc = $RawUpdater -replace 'pub const APP_BUILD_NUMBER: u64 = \d+;', "pub const APP_BUILD_NUMBER: u64 = $BuildNum;"
    [System.IO.File]::WriteAllText($UpdaterRs, $UpdatedSrc)
    Write-Host "Bumped APP_BUILD_NUMBER -> $BuildNum" -ForegroundColor Cyan
}

$SigningWallet = Join-Path $RepoRoot ".local-secrets\release-signing.wallet"
if (-not (Test-Path $SigningWallet)) {
    throw "Missing offline release signing key at $SigningWallet"
}

$StageDir = Join-Path $RepoRoot "target\release\desktop-publish"
$RepoReleasesDir = Join-Path $RepoRoot "releases"
New-Item -ItemType Directory -Force -Path $StageDir | Out-Null
New-Item -ItemType Directory -Force -Path $RepoReleasesDir | Out-Null

$PublishedExeName = "credit-desktop-windows-x86_64.exe"
$PublishedExePath = Join-Path $StageDir $PublishedExeName
$DownloadUrl = if ($SignGitHubRelease) {
    "https://github.com/haruki-morimoto/credit/releases/download/$ReleaseTag/$PublishedExeName"
} else {
    "https://raw.githubusercontent.com/haruki-morimoto/credit/$BinaryDistBranch/$PublishedExeName"
}

if ($SignGitHubRelease) {
    Write-Host "Building credit-cli release signer..." -ForegroundColor Cyan
    & cargo build --release -p credit-cli
    if ($LASTEXITCODE -ne 0) { throw "cargo build credit-cli failed" }
    Write-Host "Downloading CI-built release binary from $DownloadUrl ..." -ForegroundColor Cyan
    & curl.exe -fsSL --max-time 120 $DownloadUrl -o $PublishedExePath
    if ($LASTEXITCODE -ne 0) { throw "Failed to download $DownloadUrl (wait for GitHub Actions release workflow to finish)" }
} else {
    Write-Host "Building release binaries (credit-desktop & credit-cli)..." -ForegroundColor Cyan
    & cargo build --release -p credit-desktop -p credit-cli
    if ($LASTEXITCODE -ne 0) { throw "cargo build failed" }
    $BuiltDesktop = Join-Path $RepoRoot "target\release\credit-desktop.exe"
    Copy-Item -Force $BuiltDesktop $PublishedExePath
}

$CliExe = Join-Path $RepoRoot "target\release\credit-cli.exe"
$ManifestPath = Join-Path $StageDir "desktop-update.manifest"
$RepoManifestPath = Join-Path $RepoReleasesDir "desktop-update.manifest"

$ManifestText = (& $CliExe release-sign --wallet $SigningWallet --bundle $PublishedExePath --value $BuildNum --query $DownloadUrl --memo $Notes) -join "`n"
if ($LASTEXITCODE -ne 0) { throw "release-sign failed" }
$FormattedManifest = ($ManifestText.Trim() + "`n")
[System.IO.File]::WriteAllText($ManifestPath, $FormattedManifest)
[System.IO.File]::WriteAllText($RepoManifestPath, $FormattedManifest)

if (-not $SignGitHubRelease) {
    & powershell.exe -NoProfile -ExecutionPolicy Bypass -File (Join-Path $PSScriptRoot "install-desktop.ps1")
    if ($BinaryDistBranch -ne "") {
        Write-Host "Publishing signed binary & manifest to HTTPS distribution branch ($BinaryDistBranch)..." -ForegroundColor Cyan
        $RemoteUrl = (& git remote get-url origin).Trim()
        Push-Location $StageDir
        try {
            if (Test-Path ".git") { Remove-Item -Recurse -Force ".git" }
            $env:GIT_AUTHOR_NAME = "Haruki Morimoto"
            $env:GIT_AUTHOR_EMAIL = "haruki-morimoto@users.noreply.github.com"
            $env:GIT_COMMITTER_NAME = "Haruki Morimoto"
            $env:GIT_COMMITTER_EMAIL = "haruki-morimoto@users.noreply.github.com"
            $env:TZ = "UTC0"
            $ts = [DateTimeOffset]::UtcNow.ToString("yyyy-MM-ddTHH:mm:ss+00:00")
            $env:GIT_AUTHOR_DATE = $ts
            $env:GIT_COMMITTER_DATE = $ts
            & git init -b $BinaryDistBranch | Out-Null
            & git add $PublishedExeName "desktop-update.manifest"
            & git commit -m "release(desktop): signed Credits Desktop Build #$BuildNum" | Out-Null
            & git push -f $RemoteUrl "HEAD:refs/heads/$BinaryDistBranch"
            Remove-Item -Recurse -Force ".git"
        } finally {
            Pop-Location
        }
    }
}

if ((-not $SignGitHubRelease) -and (Get-Command gh.exe -ErrorAction SilentlyContinue)) {
    Write-Host "Uploading signed Desktop binary & manifest to GitHub Release $ReleaseTag..." -ForegroundColor Cyan
    $prevEap = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    & gh.exe release view $ReleaseTag *>$null
    $relExists = ($LASTEXITCODE -eq 0)
    if (-not $relExists) {
        & gh.exe release create $ReleaseTag --title "Credits (XCR) $ReleaseTag" --notes $Notes $PublishedExePath $ManifestPath
    } else {
        & gh.exe release upload $ReleaseTag $PublishedExePath $ManifestPath --clobber
    }
    $ghCode = $LASTEXITCODE
    $ErrorActionPreference = $prevEap
    if ($ghCode -ne 0) {
        Write-Warning "gh release upload skipped ($ghCode) - commit & push releases/desktop-update.manifest or run with -SignGitHubRelease after tag push"
    }
}

Write-Host ""
Write-Host "================================================================" -ForegroundColor Green
Write-Host "  Signed Credits Desktop Release Ready (Build #$BuildNum)!" -ForegroundColor Green
Write-Host "  Repo Manifest : $RepoManifestPath"
Write-Host "  Staged Binary : $PublishedExePath"
Write-Host "  Download URL  : $DownloadUrl"
Write-Host "================================================================" -ForegroundColor Green
