# Allow SentinelSetup / Inno temp extract past Defender ASR ransomware rule.
# The Event Viewer block ID is: C1DB55AB-C21A-4637-BB3F-A12568109D35
# ("Use advanced protection against ransomware") - action Block.
#
# Run in elevated PowerShell, then re-run SentinelSetup-*.exe:
#   powershell -ExecutionPolicy Bypass -File .\fix-asr-for-setup.ps1

$ErrorActionPreference = "Stop"
$id = [Security.Principal.WindowsIdentity]::GetCurrent()
$p = New-Object Security.Principal.WindowsPrincipal($id)
if (-not $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "Run as Administrator."
}

$RuleId = "c1db55ab-c21a-4637-bb3f-a12568109d35"  # advanced ransomware protection (do not re-enable in Block)
$Root = Split-Path -Parent $PSScriptRoot

# Stop service so AsrPolicyGuard (pre-1.9.6) cannot re-write the rule within 60s
try {
    Stop-Service Sentinel -Force -ErrorAction SilentlyContinue
    Write-Host "Stopped Sentinel service (if present)." -ForegroundColor Yellow
} catch {}

# Delete the policy value entirely (Sentinel 1.9.6+ will not re-add it)
$ruleKey = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules"
try {
    Remove-ItemProperty -Path $ruleKey -Name $RuleId -Force -ErrorAction Stop
    Write-Host "Removed ASR policy rule $RuleId (will not Block TEMP installers)." -ForegroundColor Green
} catch {
    Write-Host "Could not remove rule from registry: $($_.Exception.Message)" -ForegroundColor Yellow
}

$paths = @(
    (Join-Path $PSScriptRoot "SentinelSetup-1.9.6.exe"),
    (Join-Path $PSScriptRoot "SentinelSetup-1.9.5.exe"),
    (Join-Path $Root "releases\1.9.6\SentinelSetup-1.9.6.exe"),
    (Join-Path $Root "releases\1.9.5\SentinelSetup-1.9.5.exe"),
    $PSScriptRoot,
    (Join-Path $Root "releases\1.9.6"),
    $env:TEMP
) | Where-Object { $_ -and (Test-Path $_) }

foreach ($path in $paths) {
    try {
        Add-MpPreference -AttackSurfaceReductionOnlyExclusions $path -ErrorAction Stop
        Write-Host "ASR path exclusion: $path" -ForegroundColor Green
    } catch {
        Write-Host "Skip exclusion $path : $($_.Exception.Message)" -ForegroundColor Yellow
    }
}

Write-Host ""
Write-Host "Done. Re-run SentinelSetup-1.9.6.exe as Administrator, or install-no-inno.ps1." -ForegroundColor Cyan
Write-Host "Do NOT re-enable rule $RuleId in Block mode - it breaks Inno Setup." -ForegroundColor Yellow