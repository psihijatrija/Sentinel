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
Add-Type -Path (Join-Path $core 'Sentinel.Core.dll')
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
$bridge = [Sentinel.Core.WindowsFirewallPolicyBridge]::new($fixture)
$native = [Sentinel.Core.WindowsSelfNetworkFirewall]::new()
$isolation = [Sentinel.Core.SelfNetworkIsolation]::new($native, $fixture)
$token = [Threading.CancellationToken]::None
$listener = $null
$mutated = $false
function Invoke-Policy($operation, $store = $null, $name = $null) {
    $result = $bridge.RunAsync($operation, $token, $store, $name).GetAwaiter().GetResult()
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
    $null = Invoke-Policy Apply
    $isolation.Apply()
    $result = Invoke-Policy Apply
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
    $isolation.Remove()
    Assert-Smoke ((Get-NetFirewallRule -PolicyStore PersistentStore -Name ($prefix + '-IN')).Enabled -eq 'True') 'Rollback restores the original inbound enabled state'
    foreach ($rule in $isolation.Rules) {
        Assert-Smoke (@(Get-NetFirewallRule -PolicyStore ActiveStore | Where-Object Name -eq $rule.Name).Count -eq 0) ('Rollback removed effective owned rule ' + $rule.Name)
    }
    $mutated = $false
} finally {
    if ($listener) { $listener.Stop() }
    if ($mutated) {
        try { $null = Invoke-Policy Restore; $isolation.Remove() }
        catch { Write-Warning ('Rollback failed in disposable runner: ' + $_.Exception.Message) }
    }
    Get-NetFirewallRule -PolicyStore PersistentStore | Where-Object { $_.Name -like ($prefix + '-*') } | Remove-NetFirewallRule
    Remove-Item -LiteralPath $fixture -Recurse -Force
}
