#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Removes the three Microsoft ECC roots from the Disallowed store and restores
    them to LocalMachine\Root so Microsoft Store (and other Windows services) can
    establish TLS connections again.

    Run once from an elevated PowerShell prompt:
        powershell -ExecutionPolicy Bypass -File repair-certs.ps1

    Background: Sentinel v3.0.4 added a CertDistrustList that included three thumbprints
    sourced from a local Zemana scan result (Registry\Certificates.reg).  Those three
    certs are in fact active, vouched-for Microsoft roots used by Windows Update, the
    Microsoft Store CDN, and code-signing chains.  RootStoreGuard's autonomous sweep
    moved them to the Disallowed store, causing TLS handshake failures for the Store.
    This script undoes that and the fix in v3.1.3 removes them from the distrust list
    permanently so they can never be re-blocked.
#>

$ErrorActionPreference = "Stop"

$thumbprints = @(
    "0119E81BE9A14CD8E22F40AC118C687ECBA3F4D8",   # Microsoft Time Stamp Root CA 2014
    "31F9FC8BA3805986B721EA7295C65B3A44534274",   # Microsoft ECC TS Root CA 2018
    "06F1AA330B927B753A40E68CDF22E34BCBEF3352"    # Microsoft ECC Product Root CA 2018
)

Write-Host "[1/4] Removing from CurrentUser\Disallowed ..."
$storeU = New-Object System.Security.Cryptography.X509Certificates.X509Store("Disallowed", "CurrentUser")
$storeU.Open("ReadWrite")
foreach ($t in $thumbprints) {
    $hits = $storeU.Certificates.Find("FindByThumbprint", $t, $false)
    foreach ($c in $hits) { $storeU.Remove($c); Write-Host "  Removed (CurrentUser): $t" }
}
$storeU.Close()

Write-Host "[2/4] Removing from LocalMachine\Disallowed ..."
$storeM = New-Object System.Security.Cryptography.X509Certificates.X509Store("Disallowed", "LocalMachine")
$storeM.Open("ReadWrite")
foreach ($t in $thumbprints) {
    $hits = $storeM.Certificates.Find("FindByThumbprint", $t, $false)
    foreach ($c in $hits) { $storeM.Remove($c); Write-Host "  Removed (LocalMachine): $t" }
}
$storeM.Close()

Write-Host "[3/4] Removing registry Disallowed blocks ..."
foreach ($hive in @("HKLM","HKCU")) {
    foreach ($t in $thumbprints) {
        $key = "${hive}:\SOFTWARE\Microsoft\SystemCertificates\Disallowed\Certificates\$t"
        if (Test-Path $key) {
            Remove-Item $key -Recurse -Force
            Write-Host "  Removed: $key"
        }
    }
}
# Also check the group-policy/enterprise Disallowed path
foreach ($t in $thumbprints) {
    $key = "HKLM:\SOFTWARE\Microsoft\EnterpriseCertificates\Disallowed\Certificates\$t"
    if (Test-Path $key) {
        Remove-Item $key -Recurse -Force
        Write-Host "  Removed (enterprise): $key"
    }
}

Write-Host "[4/4] Restoring certs to LocalMachine\Root via Windows CTL ..."
# Force Windows to refresh the CTL / auto-root-update so the certs come back on demand.
# The easiest approach: trigger certutil to sync with Windows Update, which repopulates
# any vouched-for root that is missing from the local cache.
try {
    $tmpDir = Join-Path $env:TEMP "sentinel_rootfix"
    New-Item -ItemType Directory -Path $tmpDir -Force | Out-Null
    $sstPath = Join-Path $tmpDir "authroots.sst"
    $null = certutil -generateSSTFromWU $sstPath 2>&1
    if (Test-Path $sstPath) {
        $rootStore = New-Object System.Security.Cryptography.X509Certificates.X509Store("Root","LocalMachine")
        $rootStore.Open("ReadWrite")
        $col = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2Collection
        $col.Import($sstPath)
        $n = 0
        foreach ($c in $col) {
            if ($c.Thumbprint -in $thumbprints) {
                $rootStore.Add($c)
                Write-Host "  Restored to Root/LocalMachine: $($c.Thumbprint)"
                $n++
            }
        }
        $rootStore.Close()
        Write-Host "  Restored $n cert(s) from CTL."
    }
    Remove-Item $tmpDir -Recurse -Force -ErrorAction SilentlyContinue
} catch {
    Write-Warning "CTL import failed: $_"
    Write-Host "  Fallback: Windows will auto-restore the roots on next TLS handshake that needs them."
    Write-Host "  You can also run: certutil -syncWithWU to force a refresh."
}

# Verify
Write-Host ""
Write-Host "=== Verification ==="
$disM = New-Object System.Security.Cryptography.X509Certificates.X509Store("Disallowed", "LocalMachine")
$disM.Open("ReadOnly")
$remaining = $disM.Certificates | Where-Object { $_.Thumbprint -in $thumbprints }
$disM.Close()
if ($remaining.Count -eq 0) {
    Write-Host "OK - None of the three thumbprints remain in LocalMachine\Disallowed."
} else {
    Write-Warning "Still in Disallowed: $($remaining | ForEach-Object { $_.Thumbprint })"
}

Write-Host ""
Write-Host "Done. Try opening the Microsoft Store now."
Write-Host "If Store downloads still fail, run: wsreset.exe"
