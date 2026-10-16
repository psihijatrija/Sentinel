<#
.SYNOPSIS
Recover an interrupted Sentinel installation without discarding old binaries.
.DESCRIPTION
Requires an explicitly selected installer, its expected version and SHA-256 from
an independently trusted release record. A matching digest checks byte identity;
it does not establish publisher identity or replace Authenticode verification.
Existing install files are archived before services are stopped. Never deletes
.old files or automatically runs a backup: rollback needs explicit operator review.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$Installer,
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[0-9]+\.[0-9]+\.[0-9]+$')]
    [string]$ExpectedVersion,
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[a-fA-F0-9]{64}$')]
    [string]$ExpectedSha256,
    [string]$InstallDir = "$env:ProgramFiles\Sentinel",
    [string]$BackupRoot = "$env:ProgramData\Sentinel\Recovery"
)
$ErrorActionPreference = 'Stop'
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Run this recovery script from an elevated PowerShell terminal.'
}
# Validate all prerequisites before disrupting the running installation.
$Installer = (Resolve-Path -LiteralPath $Installer).ProviderPath
if ([IO.Path]::GetExtension($Installer) -ne '.exe') { throw 'Installer must be an executable.' }
$actualHash = (Get-FileHash -LiteralPath $Installer -Algorithm SHA256).Hash
if ($actualHash -ne $ExpectedSha256) { throw 'Installer SHA-256 does not match the trusted release record.' }
$signature = Get-AuthenticodeSignature -LiteralPath $Installer
if ($signature.Status -ne 'Valid') {
    throw "Installer publisher signature is not valid ($($signature.Status)). Use a verified signed installer."
}
if (-not (Test-Path -LiteralPath $InstallDir -PathType Container)) {
    throw 'Specify the existing Sentinel install directory with -InstallDir.'
}
$InstallDir = (Resolve-Path -LiteralPath $InstallDir).ProviderPath
$links = @(Get-Item -LiteralPath $InstallDir; Get-ChildItem -LiteralPath $InstallDir -Recurse -Force) |
    Where-Object { $_.Attributes -band [IO.FileAttributes]::ReparsePoint }
if ($links) { throw 'Installation contains reparse points; inspect them before recovery.' }
$BackupRoot = [IO.Path]::GetFullPath($BackupRoot)
$installPrefix = $InstallDir.TrimEnd('\') + '\'
if ($BackupRoot.Equals($InstallDir, [StringComparison]::OrdinalIgnoreCase) -or
    $BackupRoot.StartsWith($installPrefix, [StringComparison]::OrdinalIgnoreCase)) {
    throw 'Recovery archive must be outside the installation directory.'
}
$backup = Join-Path $BackupRoot ([Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $backup -Force | Out-Null
# Copy, never move/delete: preserve both the interrupted install and *.old recovery material.
Copy-Item -LiteralPath $InstallDir -Destination (Join-Path $backup 'installation') -Recurse -Force
foreach ($file in @(Get-ChildItem -LiteralPath $InstallDir -File -Recurse -Force)) {
    $relative = $file.FullName.Substring($InstallDir.TrimEnd('\').Length + 1)
    $copy = Join-Path (Join-Path $backup 'installation') $relative
    if (-not (Test-Path -LiteralPath $copy -PathType Leaf) -or
        (Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256).Hash -ne
        (Get-FileHash -LiteralPath $copy -Algorithm SHA256).Hash) {
        throw "Recovery archive did not verify for $relative. Services have not been stopped."
    }
}
$before = @('SentinelGuard', 'Sentinel') | ForEach-Object {
    $service = Get-Service -Name $_ -ErrorAction SilentlyContinue
    if ($service) { [PSCustomObject]@{ Name = $service.Name; Status = [string]$service.Status } }
}
$statePath = Join-Path $backup 'recovery.json'
$state = [ordered]@{
    SchemaVersion = 1; State = 'Prepared'; InstallDir = $InstallDir
    ExpectedVersion = $ExpectedVersion; InstallerSha256 = $actualHash
    PreviousServices = @($before); Error = $null
}
$state | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $statePath -Encoding UTF8
try {
    foreach ($name in @('SentinelGuard', 'Sentinel')) {
        $service = Get-Service -Name $name -ErrorAction SilentlyContinue
        if ($service) {
            Stop-Service -Name $name -Force
            $service.WaitForStatus('Stopped', [TimeSpan]::FromSeconds(30))
        }
    }
    # Refuse an ambiguous process rather than killing arbitrary same-named processes.
    $remaining = @(Get-Process -Name Sentinel.Agent, Sentinel.Service -ErrorAction SilentlyContinue)
    if ($remaining) { throw 'Sentinel processes remain active. Close them explicitly before retrying recovery.' }
    # Recheck bytes immediately before launch; do not trust an earlier check after a long backup.
    if ((Get-FileHash -LiteralPath $Installer -Algorithm SHA256).Hash -ne $ExpectedSha256) {
        throw 'Installer changed during recovery preparation.'
    }
    $state.State = 'Installing'
    $state | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $statePath -Encoding UTF8
    $process = Start-Process -FilePath $Installer -PassThru -Wait
    if ($process.ExitCode -ne 0) { throw "Installer failed or was cancelled (exit $($process.ExitCode))." }
    $versionFile = Join-Path $InstallDir 'version.txt'
    if (-not (Test-Path -LiteralPath $versionFile) -or
        (Get-Content -LiteralPath $versionFile -Raw).Trim() -ne $ExpectedVersion) {
        throw 'Installed version does not match the selected release.'
    }
    foreach ($name in @('Sentinel', 'SentinelGuard')) {
        $service = Get-Service -Name $name
        if ($service.Status -ne 'Running') { Start-Service -Name $name }
        $service.WaitForStatus('Running', [TimeSpan]::FromSeconds(30))
    }
    $state.State = 'Verified'
    Write-Host "Installation version and service state verified. Recovery archive: $backup"
} catch {
    $state.State = 'Failed'
    $state.Error = $_.Exception.Message
    Write-Warning "Recovery failed. Original files retained at $backup. No automatic rollback was attempted."
    throw
} finally {
    $state | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $statePath -Encoding UTF8
}
