try {
# Real DNS mutation on an ephemeral hosted runner. The product makes no network probes.
$ErrorActionPreference = 'Stop'
if ($env:GITHUB_ACTIONS -ne 'true' -or $env:RUNNER_OS -ne 'Windows' -or $env:RUNNER_ENVIRONMENT -ne 'github-hosted') {
    throw 'DNS mutation validation requires a disposable GitHub-hosted Windows runner.'
}
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
if (-not ([Security.Principal.WindowsPrincipal]::new($identity)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'DNS mutation validation requires the disposable runner administrator token.'
}
$repo = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../..'))
$adapter = Get-NetAdapter | Where-Object {
    $_.Status -eq 'Up' -and $_.HardwareInterface -and
    @(Get-DnsClientServerAddress -InterfaceIndex $_.ifIndex -ErrorAction SilentlyContinue).Count -gt 0
} | Select-Object -First 1
if (-not $adapter) {
    $inventory = Get-NetAdapter | Select-Object Name,InterfaceIndex,InterfaceDescription,HardwareInterface,Status | ConvertTo-Json -Compress
    throw ('No connected DNS-capable hardware adapter is available; validation did not execute. Inventory: ' + $inventory)
}
$id = ([guid]$adapter.InterfaceGuid).ToString('B')
$v4Key = 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\' + $id
$v6Key = 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters\Interfaces\' + $id
function Read-Static($path) {
    if (-not (Test-Path $path)) { return '' }
    $value = Get-ItemPropertyValue -Path $path -Name NameServer -ErrorAction SilentlyContinue
    if ($null -eq $value) { return '' }; return [string]$value
}
function Normalize-Servers($value) {
    return (($value -split '[,;\s]+' | Where-Object { $_ } | ForEach-Object { ([Net.IPAddress]::Parse($_)).ToString() }) -join ',')
}
$beforeV4 = Read-Static $v4Key
$beforeV6 = Read-Static $v6Key
$backup = Join-Path $env:RUNNER_TEMP ('SentinelDnsEmergency-' + [guid]::NewGuid().ToString('N') + '.json')
@{ AdapterId=$id; InterfaceIndex=$adapter.ifIndex; Ipv4=$beforeV4; Ipv6=$beforeV6 } | ConvertTo-Json | Set-Content $backup
$previousAdapter = $env:SENTINEL_DNS_SMOKE_ADAPTER_ID
$env:SENTINEL_DNS_SMOKE_ADAPTER_ID = $id
$process = $null
$success = $false
try {
    $start = [Diagnostics.ProcessStartInfo]::new('dotnet', 'test tests/Sentinel.Tests/Sentinel.Tests.csproj -c Release --no-build --filter FullyQualifiedName~DnsRepairWindowsSmokeTests --logger "trx;LogFileName=dns-smoke.trx" --results-directory TestResults')
    $start.WorkingDirectory = $repo
    $start.UseShellExecute = $false
    $start.RedirectStandardOutput = $true; $start.RedirectStandardError = $true
    $process = [Diagnostics.Process]::Start($start)
    $output = $process.StandardOutput.ReadToEndAsync(); $errors = $process.StandardError.ReadToEndAsync()
    if (-not $process.WaitForExit(150000)) {
        & (Join-Path $env:SystemRoot 'System32/taskkill.exe') /PID $process.Id /T /F | Out-Null
        $process.WaitForExit()
        throw 'DNS fixture exceeded its 150-second budget; emergency restoration is required.'
    }
    Write-Host $output.GetAwaiter().GetResult(); Write-Host $errors.GetAwaiter().GetResult()
    $resultPath = Join-Path $repo 'TestResults/dns-smoke.trx'
    if (Test-Path $resultPath) {
        [xml]$trx = Get-Content $resultPath -Raw
        foreach ($failure in $trx.SelectNodes("//*[local-name()='UnitTestResult'][@outcome='Failed']")) {
            $message = $failure.SelectSingleNode(".//*[local-name()='Message']").InnerText
            $encodedMessage = ($failure.testName + ': ' + $message).Replace('%', '%25').Replace("`r", '%0D').Replace("`n", '%0A')
            Write-Host ('::error::' + $encodedMessage)
        }
    }
    if ($process.ExitCode -ne 0) { throw 'Native DNS repair/restoration fixture failed.' }
    [xml]$trx = Get-Content $resultPath -Raw
    if ([int]$trx.TestRun.ResultSummary.Counters.passed -ne 1) { throw 'Live DNS test did not execute and pass.' }
    $success = $true
} finally {
    $env:SENTINEL_DNS_SMOKE_ADAPTER_ID = $previousAdapter
    if ($process) { $process.Dispose() }
    # Independent recovery mechanism: never rely on the implementation under test to
    # restore runner connectivity after a native failure or a killed test host.
    if ((Normalize-Servers (Read-Static $v4Key)) -ne (Normalize-Servers $beforeV4) -or (Normalize-Servers (Read-Static $v6Key)) -ne (Normalize-Servers $beforeV6)) {
        Write-Warning ('Restoring DNS using independent Windows cmdlets; saved state: ' + $backup)
        Set-DnsClientServerAddress -InterfaceIndex $adapter.ifIndex -ResetServerAddresses
        foreach ($family in @('IPv4', 'IPv6')) {
            $saved = if ($family -eq 'IPv4') { $beforeV4 } else { $beforeV6 }
            if ($saved) {
                $inputState = Get-DnsClientServerAddress -InterfaceIndex $adapter.ifIndex -AddressFamily $family
                $inputState | Set-DnsClientServerAddress -ServerAddresses ($saved -split '[,;\s]+' | Where-Object { $_ })
            }
        }
        Clear-DnsClientCache
        if ((Normalize-Servers (Read-Static $v4Key)) -ne (Normalize-Servers $beforeV4) -or
            (Normalize-Servers (Read-Static $v6Key)) -ne (Normalize-Servers $beforeV6)) {
            throw ('Emergency DNS restoration could not be verified. Saved state: ' + $backup)
        }
    }
}
if (-not $success) { throw 'DNS validation failed; emergency restoration is not a passing native result.' }
Write-Host 'PASS: Native DNS repair, original/automatic restoration, cancellation rollback and restart recovery.'

} catch {
    $detail = ($_.Exception.Message + " " + $_.InvocationInfo.PositionMessage).Replace('%', '%25').Replace("`r", '%0D').Replace("`n", '%0A')
    Write-Host ('::error::DNS validation: ' + $detail)
    throw
}
