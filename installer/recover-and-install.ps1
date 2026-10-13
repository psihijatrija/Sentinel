<#
    recover-and-install.ps1

    One-shot recovery + install for Sentinel 3.0.0.

    WHY THIS EXISTS:
    A previous SentinelSetup run was cancelled at the file-copy step. That left the
    install folder half-updated: the old binaries were renamed to *.old (the installer's
    normal anti-lock step) but the new 3.0.0 files were never written, so version.txt
    still reads an older version. This is NOT a tampered install script - setup.iss is
    byte-identical to the 2.9.7 release (verified by hash). The only cause was the Setup
    process not having write permission to Program Files at the copy step.

    This script runs every step in the correct order with the privileges it needs.

    HOW TO RUN (must be elevated):
      Right-click Start -> "Terminal (Admin)" or "PowerShell (Admin)", then:
        powershell -ExecutionPolicy Bypass -File "e:\Gorstak\Sentinel\installer\recover-and-install.ps1"
#>

$ErrorActionPreference = "Continue"

function Assert-Admin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $p  = New-Object Security.Principal.WindowsPrincipal($id)
    if (-not $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        Write-Host "ERROR: This script must be run as Administrator." -ForegroundColor Red
        Write-Host "Open an elevated PowerShell (Run as administrator) and run it again." -ForegroundColor Yellow
        exit 1
    }
}

Assert-Admin

$InstallDir = "C:\Program Files (x86)\Sentinel"
if (-not (Test-Path $InstallDir)) { $InstallDir = "C:\Program Files\Sentinel" }
$Installer  = "e:\Gorstak\Sentinel\installer\SentinelSetup-3.0.0.exe"

Write-Host "=== Sentinel 3.0.0 recovery install ===" -ForegroundColor Cyan
Write-Host "Install dir: $InstallDir"
Write-Host ""

# 1. Stop the watchdog FIRST (it respawns the service), then the service.
Write-Host "[1/5] Stopping SentinelGuard (watchdog) then Sentinel..." -ForegroundColor Yellow
Stop-Service SentinelGuard -Force -ErrorAction SilentlyContinue
Stop-Service Sentinel      -Force -ErrorAction SilentlyContinue
Start-Sleep -Seconds 2

# 2. Kill any surviving processes that hold the DLLs mapped.
Write-Host "[2/5] Killing any leftover Sentinel processes..." -ForegroundColor Yellow
Get-Process Sentinel.Agent, Sentinel.Service -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
Start-Sleep -Seconds 1
$still = Get-Process Sentinel.Agent, Sentinel.Service -ErrorAction SilentlyContinue
if ($still) {
    Write-Host "  WARNING: processes still running:" -ForegroundColor Red
    $still | Select-Object ProcessName, Id | Format-Table -AutoSize
} else {
    Write-Host "  No Sentinel processes running." -ForegroundColor Green
}

# 3. Clean up the half-finished *.old files from the cancelled run.
Write-Host "[3/5] Cleaning leftover *.old files from the aborted install..." -ForegroundColor Yellow
if (Test-Path $InstallDir) {
    $old = Get-ChildItem $InstallDir -Filter "*.old" -ErrorAction SilentlyContinue
    if ($old) {
        $old | Remove-Item -Force -ErrorAction SilentlyContinue
        Write-Host "  Removed $($old.Count) *.old file(s)." -ForegroundColor Green
    } else {
        Write-Host "  No *.old files to clean." -ForegroundColor Green
    }
}

# 4. Confirm the installer exists.
Write-Host "[4/5] Verifying installer is present..." -ForegroundColor Yellow
if (-not (Test-Path $Installer)) {
    Write-Host "  ERROR: Installer not found at $Installer" -ForegroundColor Red
    Write-Host "  Build it first: e:\Gorstak\Sentinel\installer\build.ps1" -ForegroundColor Yellow
    exit 1
}
Write-Host "  Found: $Installer" -ForegroundColor Green

# 5. Run the installer. Because this script is already elevated, the child inherits
#    admin, so the file-copy step has the rights it was missing before.
Write-Host "[5/5] Launching installer (elevated)..." -ForegroundColor Yellow
$proc = Start-Process -FilePath $Installer -PassThru -Wait
Write-Host "  Installer exited with code $($proc.ExitCode)." -ForegroundColor Cyan

Write-Host ""
Write-Host "=== Post-install verification ===" -ForegroundColor Cyan
$vf = Join-Path $InstallDir "version.txt"
if (Test-Path $vf) {
    $ver = (Get-Content $vf -Raw).Trim()
    if ($ver -eq "3.0.0") {
        Write-Host "Installed version: $ver  (SUCCESS)" -ForegroundColor Green
    } else {
        Write-Host "Installed version: $ver  (expected 3.0.0 - install may not have completed)" -ForegroundColor Red
    }
} else {
    Write-Host "version.txt not found - install did not complete." -ForegroundColor Red
}
Get-Service Sentinel, SentinelGuard -ErrorAction SilentlyContinue |
    Select-Object Name, Status | Format-Table -AutoSize
Write-Host "Done." -ForegroundColor Cyan
