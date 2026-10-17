# Mutates only a disposable GitHub-hosted Windows runner; never run against an installed PC.
$ErrorActionPreference = 'Stop'
if ($env:GITHUB_ACTIONS -ne 'true' -or $env:RUNNER_OS -ne 'Windows' -or $env:RUNNER_ENVIRONMENT -ne 'github-hosted') {
    throw 'This destructive integration fixture requires a disposable GitHub-hosted Windows runner.'
}
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
if (-not ([Security.Principal.WindowsPrincipal]::new($identity)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'The isolated Windows firewall fixture requires the hosted runner administrator token.'
}
$repo = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../..'))
$core = Join-Path $repo 'src/Sentinel.Core/bin/Release/net48-windows'
$fixture = Join-Path ([IO.Path]::GetTempPath()) ('Sentinel-Firewall-Smoke-' + [Guid]::NewGuid().ToString('N'))
$prefix = 'Sentinel-Smoke-' + [Guid]::NewGuid().ToString('N')
New-Item -ItemType Directory -Path $fixture | Out-Null
$smokeExe = Join-Path $repo 'tools/Sentinel.FirewallSmoke/bin/Release/net48-windows/Sentinel.FirewallSmoke.exe'
$clientSource = @'
using System;
using System.Net.Sockets;
public static class SmokeClient {
    public static int Main(string[] args) {
        try {
            using (var client = new TcpClient()) {
                var operation = client.BeginConnect(args[0], int.Parse(args[1]), null, null);
                using (var waiting = operation.AsyncWaitHandle) {
                    if (!waiting.WaitOne(6000)) return 2;
                    client.EndConnect(operation);
                    return client.Connected ? 0 : 2;
                }
            }
        } catch { return 2; }
    }
}
'@
Add-Type -TypeDefinition $clientSource -OutputAssembly (Join-Path $fixture 'Sentinel.Agent.exe') -OutputType ConsoleApplication
Copy-Item (Join-Path $fixture 'Sentinel.Agent.exe') (Join-Path $fixture 'control.exe')
Copy-Item (Join-Path $repo 'src/Sentinel.Service/bin/Release/net48-windows/Sentinel.Service.exe') $fixture
Copy-Item (Join-Path $repo 'tools/Sentinel.AutoRotate/bin/Release/net48-windows/SentinelAutoRotate.exe') $fixture
$listener = $null
$mutated = $false
function Invoke-Policy($operation, $store = $null, $name = $null) {
    $arguments = @($operation, $fixture)
    if ($store) { $arguments += $store }
    if ($name) { $arguments += $name }
    $result = & $smokeExe @arguments
    if ($LASTEXITCODE -ne 0) { throw ('Native firewall fixture failed: ' + $operation) }
    Write-Host $result
    return ($result | ConvertFrom-Json)
}
function Assert-Smoke($condition, $message) { if (-not $condition) { throw $message }; Write-Host ('PASS: ' + $message) }
try {
    # An external host is used only by this disposable test client, never by Sentinel product code.
    $remote = [Net.Dns]::GetHostAddresses('example.com') | Where-Object AddressFamily -eq InterNetwork | Select-Object -First 1
    if (-not $remote) { throw 'No IPv4 test endpoint resolved' }
    & (Join-Path $fixture 'control.exe') $remote.IPAddressToString 443
    Assert-Smoke ($LASTEXITCODE -eq 0) 'Control executable can reach the external test endpoint before mutation'
    & (Join-Path $fixture 'Sentinel.Agent.exe') $remote.IPAddressToString 443
    Assert-Smoke ($LASTEXITCODE -eq 0) 'Identical Agent-path test executable connects before its own block'
    New-NetFirewallRule -Name ($prefix + '-IN') -DisplayName ($prefix + '-IN') -Direction Inbound -Action Allow -Protocol TCP -LocalPort 65271 -Enabled True | Out-Null
    New-NetFirewallRule -Name ($prefix + '-OUT') -DisplayName ($prefix + '-OUT') -Direction Outbound -Action Allow -Protocol TCP -RemotePort 65271 -Enabled True | Out-Null
    $mutated = $true
    New-NetFirewallRule -PolicyStore localhost -Name ($prefix + '-GPO-IN') -DisplayName ($prefix + '-GPO-IN') -Direction Inbound -Action Allow -Protocol TCP -LocalPort 65272 -Enabled True | Out-Null
    $null = Invoke-Policy Apply
    $null = Invoke-Policy NativeApply
    $result = Invoke-Policy Apply
    if (-not $result.SelfBlocksEffective) {
        Get-NetFirewallRule -PolicyStore ActiveStore -TracePolicyStore | Where-Object { $_.Name -like 'Sentinel-Offline-*' -or $_.DisplayName -like 'Sentinel-Offline-*' } | ForEach-Object {
            [pscustomobject]@{
                Rule=($_ | Select-Object Name,DisplayName,Enabled,Direction,Action,Profile,EnforcementStatus,PolicyStoreSource)
                Port=($_ | Get-NetFirewallPortFilter | Select-Object Protocol,LocalPort,RemotePort)
                App=($_ | Get-NetFirewallApplicationFilter | Select-Object Program,Package)
                Address=($_ | Get-NetFirewallAddressFilter | Select-Object LocalAddress,RemoteAddress)
                Security=($_ | Get-NetFirewallSecurityFilter | Select-Object Authentication,Encryption,LocalUser,RemoteUser,RemoteMachine,OverrideBlockRules)
            } | ConvertTo-Json -Depth 6 | Write-Host
        }
    }
    Assert-Smoke $result.LocalGpoAvailable 'Local computer GPO is available on the Windows runner'
    Assert-Smoke ((Get-NetFirewallRule -PolicyStore localhost -Name ($prefix + '-GPO-IN')).Enabled -eq 'False') 'Unapproved local-GPO inbound rule is retained and disabled'
    Assert-Smoke $result.SelfBlocksEffective 'Real ActiveStore reports the six self-blocks fully effective'
    Assert-Smoke ((Get-NetFirewallRule -PolicyStore PersistentStore -Name ($prefix + '-IN')).Enabled -eq 'False') 'Unapproved local inbound rule is retained and disabled'
    Assert-Smoke ((Get-NetFirewallRule -PolicyStore PersistentStore -Name ($prefix + '-OUT')).Enabled -eq 'True') 'Outbound allow rule remains enabled'
    Set-NetFirewallRule -PolicyStore PersistentStore -Name ($prefix + '-IN') -Enabled True
    $null = Invoke-Policy Apply
    Assert-Smoke ((Get-NetFirewallRule -PolicyStore PersistentStore -Name ($prefix + '-IN')).Enabled -eq 'False') 'Windows-style re-enable is reconciled'
    $null = Invoke-Policy Approve PersistentStore ($prefix + '-IN')
    $null = Invoke-Policy Apply
    Assert-Smoke ((Get-NetFirewallRule -PolicyStore PersistentStore -Name ($prefix + '-IN')).Enabled -eq 'True') 'Explicit approval survives a fresh policy-engine invocation'
    & (Join-Path $fixture 'Sentinel.Agent.exe') $remote.IPAddressToString 443
    Assert-Smoke ($LASTEXITCODE -eq 2) 'Agent-path executable cannot connect after external self-block enforcement'
    & (Join-Path $fixture 'control.exe') $remote.IPAddressToString 443
    Assert-Smoke ($LASTEXITCODE -eq 0) 'Identical control executable still connects, excluding a general endpoint outage'
    $listener = [Net.Sockets.TcpListener]::new([Net.IPAddress]::Loopback, 0)
    $listener.Start()
    & (Join-Path $fixture 'Sentinel.Agent.exe') '127.0.0.1' $listener.LocalEndpoint.Port
    Assert-Smoke ($LASTEXITCODE -eq 0) 'Agent-path executable retains localhost connectivity'
    $null = Invoke-Policy Restore
    $null = Invoke-Policy NativeRemove
    Assert-Smoke ((Get-NetFirewallRule -PolicyStore PersistentStore -Name ($prefix + '-IN')).Enabled -eq 'True') 'Rollback restores the original inbound enabled state'
    Assert-Smoke ((Get-NetFirewallRule -PolicyStore localhost -Name ($prefix + '-GPO-IN')).Enabled -eq 'True') 'Rollback restores the original local-GPO inbound enabled state'
    foreach ($executable in @('Sentinel.Service.exe', 'Sentinel.Agent.exe', 'SentinelAutoRotate.exe')) {
        foreach ($direction in @('IN', 'OUT')) {
            $ruleName = 'Sentinel-Offline-' + $executable + '-' + $direction
            Assert-Smoke (@(Get-NetFirewallRule -PolicyStore ActiveStore | Where-Object { $_.Name -eq $ruleName -or $_.DisplayName -eq $ruleName }).Count -eq 0) ('Rollback removed effective owned rule ' + $ruleName)
        }
    }
    $mutated = $false
} finally {
    if ($listener) { $listener.Stop() }
    if ($mutated) {
        try { $null = Invoke-Policy Restore; $null = Invoke-Policy NativeRemove }
        catch { Write-Warning ('Rollback failed in disposable runner: ' + $_.Exception.Message) }
    }
    foreach ($store in @('PersistentStore', 'localhost')) {
        Get-NetFirewallRule -PolicyStore $store | Where-Object { $_.Name -like ($prefix + '-*') } | Remove-NetFirewallRule
    }
    Remove-Item -LiteralPath $fixture -Recurse -Force
}
