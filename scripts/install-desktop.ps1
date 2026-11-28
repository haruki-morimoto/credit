# 1-Click Installer for Credits Desktop (Wallet & Automatic Background Miner)
# Builds or copies `credit-desktop.exe` into `%LOCALAPPDATA%\Programs\Credits`
# and creates Desktop & Start Menu shortcuts (with optional Start-on-Login).

param(
    [switch]$AutoStartOnLogin
)

$ErrorActionPreference = "Stop"
$RepoRoot = Split-Path -Parent $PSScriptRoot
$InstallDir = Join-Path $env:LOCALAPPDATA "Programs\Credits"
New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null

$BuiltExe = Join-Path $RepoRoot "target\release\credit-desktop.exe"
if (-not (Test-Path $BuiltExe)) {
    Write-Host "Building Credits Desktop native application..." -ForegroundColor Cyan
    Push-Location $RepoRoot
    try {
        & cargo build --release -p credit-desktop
        if ($LASTEXITCODE -ne 0) { throw "cargo build -p credit-desktop failed" }
    } finally {
        Pop-Location
    }
}

$TargetExe = Join-Path $InstallDir "credit-desktop.exe"
Get-ChildItem -Path $InstallDir -Filter "credit-desktop*.old" -ErrorAction SilentlyContinue | ForEach-Object {
    Remove-Item -Force $_.FullName -ErrorAction SilentlyContinue
}
if (Test-Path $TargetExe) {
    try {
        Copy-Item -Force $BuiltExe $TargetExe -ErrorAction Stop
    } catch {
        # Windows allows renaming an in-use executable on NTFS using a unique timestamped `.old`:
        $UniqueOld = Join-Path $InstallDir "credit-desktop.exe.$((Get-Date).Ticks).old"
        Move-Item -Force $TargetExe $UniqueOld
        Copy-Item -Force $BuiltExe $TargetExe
    }
} else {
    Copy-Item -Force $BuiltExe $TargetExe
}

$WshShell = New-Object -ComObject WScript.Shell

# 1. Desktop Shortcut
$DesktopPath = [Environment]::GetFolderPath("Desktop")
$DesktopLnk = $WshShell.CreateShortcut((Join-Path $DesktopPath "Credits Wallet & Miner.lnk"))
$DesktopLnk.TargetPath = $TargetExe
$DesktopLnk.WorkingDirectory = $InstallDir
$DesktopLnk.Description = "Credits (XCR) - Wallet & Automatic Background Earner"
$DesktopLnk.Save()

# 2. Start Menu Shortcut
$StartMenuDir = Join-Path ([Environment]::GetFolderPath("StartMenu")) "Programs\Credits"
New-Item -ItemType Directory -Force -Path $StartMenuDir | Out-Null
$StartLnk = $WshShell.CreateShortcut((Join-Path $StartMenuDir "Credits Wallet & Miner.lnk"))
$StartLnk.TargetPath = $TargetExe
$StartLnk.WorkingDirectory = $InstallDir
$StartLnk.Description = "Credits (XCR) - Wallet & Automatic Background Earner"
$StartLnk.Save()

if ($AutoStartOnLogin) {
    $StartupDir = [Environment]::GetFolderPath("Startup")
    $StartupLnk = $WshShell.CreateShortcut((Join-Path $StartupDir "Credits Wallet & Miner.lnk"))
    $StartupLnk.TargetPath = $TargetExe
    $StartupLnk.WorkingDirectory = $InstallDir
    $StartupLnk.Save()
}

Write-Host ""
Write-Host "================================================================" -ForegroundColor Green
Write-Host "  Credits Desktop Installed Successfully!" -ForegroundColor Green
Write-Host "  App Binary : $TargetExe"
Write-Host "  Shortcut   : Desktop -> 'Credits Wallet & Miner'"
Write-Host "================================================================" -ForegroundColor Green
