# Sentinel manual install - bypasses Inno Setup (no TEMP extract).
# Use when Defender ASR "advanced ransomware protection" blocks SentinelSetup-*.exe
# with: Unable to execute file in temporary directory / Error 5.
#
# Run elevated:
#   powershell -ExecutionPolicy Bypass -File .\install-no-inno.ps1
#
# Requires: publish\service + publish\agent already built (run build.ps1 first, or use an existing tree).

$ErrorActionPreference = "Stop"

function Assert-Admin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $p = New-Object Security.Principal.WindowsPrincipal($id)
    if (-not $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw "Run this script as Administrator."
    }
}

Assert-Admin

$Root = Split-Path -Parent $PSScriptRoot
if (-not (Test-Path (Join-Path $Root "publish\service\Sentinel.Service.exe"))) {
    $Root = Split-Path -Parent $Root
}
$ServiceSrc = Join-Path $Root "publish\service"
$AgentSrc = Join-Path $Root "publish\agent"
if (-not (Test-Path (Join-Path $ServiceSrc "Sentinel.Service.exe"))) {
    throw "Missing $ServiceSrc\Sentinel.Service.exe - run installer\build.ps1 first (publish step is enough even if ISCC fails)."
}
if (-not (Test-Path (Join-Path $AgentSrc "Sentinel.Agent.exe"))) {
    throw "Missing $AgentSrc\Sentinel.Agent.exe"
}

$AppDir = Join-Path ${env:ProgramFiles(x86)} "Sentinel"
if (-not (Test-Path ${env:ProgramFiles(x86)})) {
    $AppDir = Join-Path $env:ProgramFiles "Sentinel"
}

Write-Host "Installing Sentinel from publish tree -> $AppDir" -ForegroundColor Cyan

# Stop existing
$svc = Get-Service -Name "Sentinel" -ErrorAction SilentlyContinue
if ($svc) {
    Write-Host "Stopping service..."
    Stop-Service Sentinel -Force -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 2
    sc.exe stop Sentinel | Out-Null
}
Get-Process -Name "Sentinel.Agent","Sentinel.Service" -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
Start-Sleep -Seconds 1

New-Item -ItemType Directory -Path $AppDir -Force | Out-Null

Write-Host "Copying service..."
Copy-Item -Path (Join-Path $ServiceSrc "*") -Destination $AppDir -Recurse -Force
Write-Host "Copying agent..."
Copy-Item -Path (Join-Path $AgentSrc "*") -Destination $AppDir -Recurse -Force

$svcExe = Join-Path $AppDir "Sentinel.Service.exe"
$agentExe = Join-Path $AppDir "Sentinel.Agent.exe"
if (-not (Test-Path $svcExe)) { throw "Service exe missing after copy" }

# Service create/update
$existing = Get-Service -Name "Sentinel" -ErrorAction SilentlyContinue
if (-not $existing) {
    Write-Host "Creating Windows service Sentinel..."
    New-Service -Name "Sentinel" -BinaryPathName "`"$svcExe`"" -DisplayName "Sentinel" `
        -Description "Sentinel endpoint detection and response" -StartupType Automatic | Out-Null
} else {
    Write-Host "Updating service binPath..."
    sc.exe config Sentinel binPath= "`"$svcExe`"" start= auto | Out-Null
}

# Safe Mode registration (best effort)
try {
    New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SafeBoot\Minimal\Sentinel" -Force | Out-Null
    Set-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\SafeBoot\Minimal\Sentinel" -Name "(default)" -Value "Service"
    New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SafeBoot\Network\Sentinel" -Force | Out-Null
    Set-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\SafeBoot\Network\Sentinel" -Name "(default)" -Value "Service"
} catch { Write-Host "SafeBoot keys skipped: $_" }

# Run key for agent
$runKey = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
Set-ItemProperty -Path $runKey -Name "SentinelAgent" -Value "`"$agentExe`"" -Type String

Write-Host "Starting service..."
Start-Service Sentinel -ErrorAction SilentlyContinue
Start-Sleep -Seconds 2
$st = (Get-Service Sentinel -EA SilentlyContinue).Status
Write-Host "Service status: $st"

Write-Host "Starting agent..."
Start-Process -FilePath $agentExe -WorkingDirectory $AppDir

$ver = ""
$vf = Join-Path $AppDir "version.txt"
if (Test-Path $vf) { $ver = (Get-Content $vf -Raw).Trim() }
Write-Host "========================================" -ForegroundColor Green
Write-Host "Sentinel installed (no Inno). Version: $ver" -ForegroundColor Green
Write-Host "Path: $AppDir" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Green
