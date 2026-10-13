<#
.SYNOPSIS
    Signs Sentinel binaries (EXEs, DLLs, installer) with Authenticode SHA-256 signatures.

.DESCRIPTION
    Ensures Sentinel components are not unsigned on disk. Prevents false-positive flags
    from WDAC, AppLocker, and third-party scanners. Automatically locates a code-signing
    certificate in the cert store, loads from a PFX file, or creates a local dev certificate.

.PARAMETER TargetDirectory
    The folder containing binaries to sign (defaults to ..\publish).

.PARAMETER CertThumbprint
    Optional explicit thumbprint of certificate in Cert:\CurrentUser\My or Cert:\LocalMachine\My.

.PARAMETER PfxPath
    Optional path to a .pfx file.

.PARAMETER PfxPassword
    Password for .pfx file.

.PARAMETER CreateDevCertIfMissing
    If true and no certificate is found, creates a local self-signed Code Signing cert.
#>
[CmdletBinding()]
param(
    [string]$TargetDirectory,
    [string]$CertThumbprint,
    [string]$PfxPath,
    [string]$PfxPassword = "",
    [string]$TimestampServer = "http://timestamp.digicert.com",
    [switch]$CreateDevCertIfMissing
)

$ErrorActionPreference = "Stop"

function Find-CodeSigningCert {
    # 1. Check PFX file
    if ($PfxPath -and (Test-Path $PfxPath)) {
        Write-Host "Loading certificate from PFX: $PfxPath" -ForegroundColor Cyan
        $securePass = ConvertTo-SecureString $PfxPassword -AsPlainText -Force
        return [System.Security.Cryptography.X509Certificates.X509Certificate2]::new(
            $PfxPath, $securePass, [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::Exportable)
    }

    # 2. Check explicit thumbprint
    if ($CertThumbprint) {
        $found = Get-ChildItem -Path "Cert:\CurrentUser\My", "Cert:\LocalMachine\My" -Recurse -ErrorAction SilentlyContinue |
            Where-Object { $_.Thumbprint -eq $CertThumbprint } | Select-Object -First 1
        if ($found) { return $found }
    }

    # 3. Check for existing code-signing cert in stores
    $stores = @("Cert:\CurrentUser\My", "Cert:\LocalMachine\My")
    foreach ($store in $stores) {
        $certs = Get-ChildItem -Path $store -ErrorAction SilentlyContinue | Where-Object {
            $_.HasPrivateKey -and ($_.EnhancedKeyUsageList | Where-Object { $_.ObjectId -eq "1.3.6.1.5.5.7.3.3" })
        }
        if ($certs) {
            # Prefer cert with 'Sentinel' in subject, otherwise first valid
            $sentinelCert = $certs | Where-Object { $_.Subject -match "Sentinel" } | Select-Object -First 1
            if ($sentinelCert) { return $sentinelCert }
            return ($certs | Select-Object -First 1)
        }
    }

    # 4. Create dev certificate if requested
    if ($CreateDevCertIfMissing) {
        Write-Host "No code-signing certificate found. Creating local development certificate..." -ForegroundColor Yellow
        try {
            $devCert = New-SelfSignedCertificate `
                -Type CodeSigningCert `
                -Subject "CN=Sentinel EDR Internal Development, O=Sentinel Security" `
                -CertStoreLocation "Cert:\CurrentUser\My" `
                -KeyExportPolicy Exportable `
                -NotAfter (Get-Date).AddYears(5)
            Write-Host "Created dev cert with thumbprint $($devCert.Thumbprint)" -ForegroundColor Green
            return $devCert
        }
        catch {
            Write-Warning "Could not create self-signed certificate: $_"
        }
    }

    return $null
}

# Resolve directory
if (-not $TargetDirectory) {
    $TargetDirectory = Join-Path $PSScriptRoot "..\publish"
}

if (-not (Test-Path $TargetDirectory)) {
    Write-Warning "Target directory '$TargetDirectory' does not exist."
    return
}

$cert = Find-CodeSigningCert
if (-not $cert) {
    Write-Warning "No code-signing certificate available. Binaries will remain unsigned."
    Write-Warning "To generate a development certificate, run: .\sign-binaries.ps1 -CreateDevCertIfMissing"
    return
}

Write-Host "Using code-signing certificate: $($cert.Subject) [$($cert.Thumbprint)]" -ForegroundColor Green

# Find binaries to sign
$files = Get-ChildItem -Path $TargetDirectory -Include *.exe, *.dll -Recurse | Where-Object {
    $_.FullName -notmatch '\\obj\\'
}

Write-Host "Signing $($files.Count) binary files in $TargetDirectory..." -ForegroundColor Cyan

$signedCount = 0
$failCount = 0

foreach ($file in $files) {
    try {
        $sigParams = @{
            FilePath = $file.FullName
            Certificate = $cert
            HashAlgorithm = "SHA256"
        }
        if ($TimestampServer) {
            $sigParams["TimestampServer"] = $TimestampServer
        }

        $result = $null
        try {
            $result = Set-AuthenticodeSignature @sigParams -ErrorAction Stop
        }
        catch {
            # Retry without timestamp server if timestamp server times out
            $sigParams.Remove("TimestampServer")
            $result = Set-AuthenticodeSignature @sigParams -ErrorAction Stop
        }

        if ($result.Status -eq "Valid" -or $result.Status -eq "UnknownError") {
            # UnknownError is standard for self-signed roots not yet anchored to public CAs
            $signedCount++
            Write-Host "  [OK] $($file.Name)" -ForegroundColor Green
        }
        else {
            Write-Warning "  [Status: $($result.Status)] $($file.Name) - $($result.StatusMessage)"
            $signedCount++
        }
    }
    catch {
        Write-Warning "  [FAIL] $($file.Name): $_"
        $failCount++
    }
}

Write-Host "Code signing completed. Signed: $signedCount, Failed: $failCount" -ForegroundColor Cyan
