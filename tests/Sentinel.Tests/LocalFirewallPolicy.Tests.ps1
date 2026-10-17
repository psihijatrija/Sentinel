# Portable regression tests for the real embedded policy engine, with in-memory NetSecurity stores.
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot '../../src/Sentinel.Core/PolicyResources/LocalFirewallPolicy.ps1')
$script:passed = 0
function Assert($condition, $message) { if (-not $condition) { throw $message }; $script:passed++ }
function New-Rule($name, $store, $direction = 'Inbound', $action = 'Allow', $enabled = 'True', $service = 'Any', $local = 'Any', $remote = 'Any') {
    [pscustomobject]@{ Name=$name; Store=$store; Direction=$direction; Action=$action; Enabled=$enabled; Service=$service
        Protocol='UDP'; LocalPort=$local; RemotePort=$remote; IcmpType='Any'; Program='Any'; Package='Any'; Profile='Any'
        LocalAddress='Any'; RemoteAddress='Any'; InterfaceAlias='Any'; InterfaceType='Any'; Authentication='NotRequired'
        Encryption='NotRequired'; LocalUser='Any'; RemoteUser='Any'; RemoteMachine='Any'; OverrideBlockRules='False'
        EdgeTraversalPolicy='Block'; PolicyStoreSource=$store; PolicyStoreSourceType=$(if ($store -eq 'PersistentStore') {'Local'} else {'GroupPolicy'}); EnforcementStatus='Full' }
}
function New-Fixture {
    $script:rules = @{
        PersistentStore=@((New-Rule 'local-in' 'PersistentStore'), (New-Rule 'local-out' 'PersistentStore' 'Outbound'),
            (New-Rule 'local-block' 'PersistentStore' 'Inbound' 'Block'),
            (New-Rule 'dhcp4' 'PersistentStore' 'Inbound' 'Allow' 'True' 'Dhcp' '68' '67'),
            (New-Rule 'dhcp6' 'PersistentStore' 'Inbound' 'Allow' 'True' 'Dhcp' '546' '547'),
            (New-Rule 'DHCP-name-only' 'PersistentStore'), (New-Rule 'initially-off' 'PersistentStore' 'Inbound' 'Allow' 'False'))
        localhost=@((New-Rule 'gpo-in' 'localhost'))
        domain=@((New-Rule 'managed-in' 'domain'))
    }
    $script:profiles = @{}
    foreach ($store in @('PersistentStore','localhost')) {
        $script:profiles[$store] = @('Domain','Private','Public' | ForEach-Object {
            [pscustomobject]@{ Store=$store; Name=$_; Enabled='True'; DefaultInboundAction='Allow'; DefaultOutboundAction='Allow' }
        })
    }
    $script:gpoAvailable = $true; $script:duplicateActive = $false; $script:failName = ''; $script:writes = @()
    $dir = Join-Path ([IO.Path]::GetTempPath()) ('SentinelPolicyTest-' + [Guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $dir | Out-Null
    $script:temporaryDirectories += $dir
    $self = @()
    foreach ($exe in @('Sentinel.Service.exe','Sentinel.Agent.exe','SentinelAutoRotate.exe')) {
        foreach ($direction in @(1,2)) { $self += [pscustomobject]@{ Name=('Sentinel-Offline-' + $exe + $(if ($direction -eq 1) {'-IN'} else {'-OUT'})); ApplicationPath=('C:\Sentinel\' + $exe); Direction=$direction } }
    }
    [pscustomobject]@{ Operation='Apply'; StatePath=(Join-Path $dir 'rollback.json'); SelfRules=$self
        RemoteAddresses='0.0.0.0-126.255.255.255,128.0.0.0-255.255.255.255,::2-ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff'; Store='PersistentStore'; RuleName='initially-off' }
}
function Get-NetFirewallProfile { param($PolicyStore)
    if ($PolicyStore -eq 'localhost' -and -not $script:gpoAvailable) { throw 'Trimmed image: no local GPO' }
    if ($PolicyStore -eq 'ActiveStore') { return $script:profiles[$(if ($script:gpoAvailable) {'localhost'} else {'PersistentStore'})] }
    return $script:profiles[$PolicyStore]
}
function Get-NetFirewallRule { param($PolicyStore, [switch]$TracePolicyStore)
    if ($PolicyStore -eq 'localhost' -and -not $script:gpoAvailable) { throw 'No GPO' }
    if ($PolicyStore -eq 'ActiveStore') {
        if ($script:duplicateActive) { return @($script:rules.PersistentStore) + @($script:rules.localhost) + @($script:rules.domain) }
        $merged = @{}; foreach ($store in @('PersistentStore','localhost','domain')) {
            if ($store -eq 'localhost' -and -not $script:gpoAvailable) { continue }
            foreach ($rule in $script:rules[$store]) { $merged[$rule.Name] = $rule }
        }; return @($merged.Values)
    }; return $script:rules[$PolicyStore]
}
foreach ($filter in @('Port','Service','Application','Address','Interface','InterfaceType','Security')) {
    Set-Item -Path ('Function:Get-NetFirewall' + $filter + 'Filter') -Value {
        param([Parameter(ValueFromPipeline)]$InputObject)
        process { $InputObject }
    }
}
function Set-NetFirewallRule {
    param([Parameter(ValueFromPipeline)]$InputObject, $Enabled, $Direction, $Action, $Profile, $Protocol, $LocalAddress, $RemoteAddress, $Program, $InterfaceType, $Service, $EdgeTraversalPolicy)
    process {
        if ($InputObject.Store -eq 'domain') { throw 'A domain write was attempted' }
        if ($InputObject.Name -eq $script:failName) { throw 'Simulated mutation failure' }
        foreach ($key in @($PSBoundParameters.Keys)) { if ($key -ne 'InputObject') { $InputObject.$key = $PSBoundParameters[$key] } }
        $script:writes += $InputObject.Store
    }
}
function New-NetFirewallRule {
    param($PolicyStore, $Name, $DisplayName, $Group, $Enabled, $Direction, $Action, $Profile, $Protocol, $LocalAddress, $RemoteAddress, $Program, $InterfaceType, $Service, $EdgeTraversalPolicy)
    $rule = New-Rule $Name $PolicyStore
    foreach ($key in @('Enabled','Direction','Action','Profile','Protocol','LocalAddress','RemoteAddress','Program','InterfaceType','Service','EdgeTraversalPolicy')) { $rule.$key = $PSBoundParameters[$key] }
    $script:rules[$PolicyStore] += $rule; $script:writes += $PolicyStore
}
function Remove-NetFirewallRule { param([Parameter(ValueFromPipeline)]$InputObject)
    process { $script:rules[$InputObject.Store] = @($script:rules[$InputObject.Store] | Where-Object { $_.Name -cne $InputObject.Name }) }
}
function Set-NetFirewallProfile { param([Parameter(ValueFromPipeline)]$InputObject, $DefaultInboundAction, $Enabled)
    process { if ($PSBoundParameters.ContainsKey('DefaultInboundAction')) { $InputObject.DefaultInboundAction=$DefaultInboundAction }; if ($PSBoundParameters.ContainsKey('Enabled')) { $InputObject.Enabled=$Enabled }; $script:writes += $InputObject.Store }
}
function Get-Service { param($Name) foreach ($item in $Name) { [pscustomobject]@{ Name=$item; Status='Running' } } }
$script:temporaryDirectories = @()
try {
    $request = New-Fixture
    $result = Invoke-SentinelFirewallPolicy $request
    Assert (($script:rules.PersistentStore | Where-Object Name -eq 'local-in').Enabled -eq 'False') 'Local inbound exception stayed enabled'
    Assert (($script:rules.localhost | Where-Object Name -eq 'gpo-in').Enabled -eq 'False') 'Local GPO exception stayed enabled'
    Assert (($script:rules.PersistentStore | Where-Object Name -eq 'local-out').Enabled -eq 'True') 'Outbound exception was disabled'
    Assert (($script:rules.PersistentStore | Where-Object Name -eq 'local-block').Enabled -eq 'True') 'Existing block was disabled'
    Assert (($script:rules.PersistentStore | Where-Object Name -eq 'dhcp4').Enabled -eq 'True') 'DHCPv4 was disabled'
    Assert (($script:rules.PersistentStore | Where-Object Name -eq 'dhcp6').Enabled -eq 'True') 'DHCPv6 was disabled'
    Assert (($script:rules.PersistentStore | Where-Object Name -eq 'DHCP-name-only').Enabled -eq 'False') 'Display name granted a DHCP exemption'
    Assert (@($script:rules.localhost | Where-Object Action -eq 'Block').Count -eq 6) 'Self-blocks were not mirrored into local GPO'
    Assert $result.SelfBlocksEffective 'Effective self-blocks were not verified'
    Assert (-not $result.PolicyCompliant) 'Domain inbound exception was concealed'
    Assert (@($result.Conflicts | Where-Object { $_ -match 'managed-in' }).Count -eq 1) 'Domain conflict was not reported'
    Assert (($script:writes -notcontains 'domain') -and ($script:rules.domain[0].Enabled -eq 'True')) 'Domain policy was modified'
    Assert (@($script:profiles.PersistentStore | Where-Object DefaultOutboundAction -ne 'Allow').Count -eq 0) 'Outbound default was modified'
    ($script:rules.PersistentStore | Where-Object Name -eq 'local-in').Enabled = 'True'
    $script:rules.PersistentStore += New-Rule 'windows-added' 'PersistentStore'
    $script:profiles.localhost[0].DefaultInboundAction = 'Allow'
    $null = Invoke-SentinelFirewallPolicy $request
    Assert (($script:rules.PersistentStore | Where-Object Name -eq 'local-in').Enabled -eq 'False') 'Windows re-enable survived reconciliation'
    Assert (($script:rules.PersistentStore | Where-Object Name -eq 'windows-added').Enabled -eq 'False') 'New Windows inbound rule survived'
    Assert ($script:profiles.localhost[0].DefaultInboundAction -eq 'Block') 'Windows profile reset survived'
    $request.Operation='Approve'; $null=Invoke-SentinelFirewallPolicy $request
    $request.Operation='Apply'; $null=Invoke-SentinelFirewallPolicy $request
    Assert (($script:rules.PersistentStore | Where-Object Name -eq 'initially-off').Enabled -eq 'True') 'Explicit approval did not persist'
    $request.Operation='Revoke'; $null=Invoke-SentinelFirewallPolicy $request
    $request.Operation='Apply'; $null=Invoke-SentinelFirewallPolicy $request
    Assert (($script:rules.PersistentStore | Where-Object Name -eq 'initially-off').Enabled -eq 'False') 'Revoked approval stayed enabled'
    $request.Operation='Approve'; $null=Invoke-SentinelFirewallPolicy $request; $request.Operation='Apply'
    ($script:rules.PersistentStore | Where-Object Name -eq 'initially-off').Program = 'C:\changed.exe'
    $null=Invoke-SentinelFirewallPolicy $request
    Assert (($script:rules.PersistentStore | Where-Object Name -eq 'initially-off').Enabled -eq 'False') 'Approval survived a changed rule definition'
    $request.Operation='Restore'; $result=Invoke-SentinelFirewallPolicy $request
    Assert (($script:rules.PersistentStore | Where-Object Name -eq 'local-in').Enabled -eq 'True') 'Original enabled state was not restored'
    Assert (($script:rules.localhost | Where-Object Name -eq 'gpo-in').Enabled -eq 'True') 'Original GPO enabled state was not restored'
    Assert (@($script:rules.localhost | Where-Object Name -like 'Sentinel-Offline-*').Count -eq 0) 'Owned GPO self-blocks survived rollback'
    Assert (@($script:profiles.localhost | Where-Object DefaultInboundAction -ne 'Allow').Count -eq 0) 'Original inbound defaults were not restored'
    $request=New-Fixture; $script:profiles.localhost[0].Enabled='False'
    $nd=New-Rule 'ipv6-neighbour' 'PersistentStore'; $nd.Program='System'; $nd.Protocol='ICMPv6'; $nd.IcmpType='135'
    $fake=New-Rule 'fake-neighbour' 'PersistentStore'; $fake.Program='game.exe'; $fake.Protocol='ICMPv6'; $fake.IcmpType='135'
    $echo=New-Rule 'icmp6-echo' 'PersistentStore'; $echo.Program='System'; $echo.Protocol='ICMPv6'; $echo.IcmpType='128'
    $script:rules.PersistentStore += @($nd,$fake,$echo)
    $null=Invoke-SentinelFirewallPolicy $request
    Assert ($nd.Enabled -eq 'True') 'Essential IPv6 control traffic was disabled'
    Assert ($fake.Enabled -eq 'False' -and $echo.Enabled -eq 'False') 'IPv6 exemption allowed an app or echo server'
    Assert ($script:profiles.localhost[0].Enabled -eq 'True') 'Local GPO disabled profile was not repaired'
    $request.Operation='Restore'; $null=Invoke-SentinelFirewallPolicy $request
    Assert ($script:profiles.localhost[0].Enabled -eq 'False') 'Original profile enabled state was not restored'
    $request=New-Fixture; $script:gpoAvailable=$false
    $result=Invoke-SentinelFirewallPolicy $request
    Assert (-not $result.LocalGpoAvailable -and $result.Notes.Count -gt 0) 'Unavailable GPO was not reported'
    Assert (($script:rules.PersistentStore | Where-Object Name -eq 'local-in').Enabled -eq 'False') 'Fallback failed on a trimmed image'
    $request=New-Fixture; $script:failName='local-in'; $failed=$false
    try { $null=Invoke-SentinelFirewallPolicy $request } catch { $failed=$true }
    Assert $failed 'Mutation failure was concealed'
    Assert (Test-Path -LiteralPath $request.StatePath) 'Mutation occurred without a durable rollback record'
    $script:failName=''; $null=Invoke-SentinelFirewallPolicy $request
    Assert (($script:rules.PersistentStore | Where-Object Name -eq 'local-in').Enabled -eq 'False') 'Interrupted mutation was not retried'
    $request.Operation='Restore'; $null=Invoke-SentinelFirewallPolicy $request
    Assert (($script:rules.PersistentStore | Where-Object Name -eq 'local-in').Enabled -eq 'True') 'Crash recovery lost the original rule state'
    $request=New-Fixture
    $override=New-Rule $request.SelfRules[0].Name 'domain'
    $script:rules.domain += $override
    $result=Invoke-SentinelFirewallPolicy $request
    Assert (-not $result.SelfBlocksEffective) 'Domain override of a self-block was falsely reported as effective'
    Assert ($override.Action -eq 'Allow' -and $script:writes -notcontains 'domain') 'Domain override was modified'
    $request.Operation='Approve'; $request.Store='domain'; $request.RuleName='managed-in'; $failed=$false
    try { $null=Invoke-SentinelFirewallPolicy $request } catch { $failed=$true }
    Assert $failed 'Approval allowed a domain store write'
    $request=New-Fixture
    $null=Invoke-SentinelFirewallPolicy $request
    # Native COM and local GPO may expose the same fixed name as separate effective rules.
    $script:rules.PersistentStore += @($script:rules.localhost | Where-Object Action -eq 'Block' | ForEach-Object { $copy=$_.PSObject.Copy(); $copy.Store='PersistentStore'; $copy.PolicyStoreSource='PersistentStore'; $copy.PolicyStoreSourceType='Local'; $copy })
    $script:duplicateActive=$true
    foreach ($rule in @($script:rules.PersistentStore | Where-Object Action -eq 'Block')) { $rule | Add-Member -NotePropertyName DisplayName -NotePropertyValue $rule.Name; $rule.Name=[Guid]::NewGuid().ToString() }
    $result=Invoke-SentinelFirewallPolicy $request
    Assert $result.SelfBlocksEffective 'Duplicate effective local/GPO blocks were falsely rejected'
    foreach ($rule in @($script:rules.PersistentStore + $script:rules.localhost | Where-Object Action -eq 'Block')) { $rule.EnforcementStatus='LocalFirewallRulesDisallowed' }
    $result=Invoke-SentinelFirewallPolicy $request
    Assert (-not $result.SelfBlocksEffective) 'Unenforced duplicate blocks were falsely accepted'
    $request=New-Fixture; Set-Content -LiteralPath $request.StatePath -Value '{broken'; $failed=$false
    try { $null=Invoke-SentinelFirewallPolicy $request } catch { $failed=$true }
    Assert ($failed -and $script:writes.Count -eq 0) 'Malformed journal allowed unjournaled mutation'
    $request=New-Fixture
    @{Version=1;Rules=@(@{Store='PersistentStore';Name='local-in';Identity=('a'*44);OriginalEnabled=$true;Changed=$true;Pending=$false;Approved='false'});Profiles=@()} | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $request.StatePath
    $failed=$false; try { $null=Invoke-SentinelFirewallPolicy $request } catch { $failed=$true }
    Assert ($failed -and $script:writes.Count -eq 0) 'Non-boolean approval data was trusted'
    $request=New-Fixture; $null=Invoke-SentinelFirewallPolicy $request
    $script:gpoAvailable=$false; $request.Operation='Restore'; $failed=$false
    try { $null=Invoke-SentinelFirewallPolicy $request } catch { $failed=$true }
    Assert $failed 'Unavailable GPO rollback was falsely reported complete'
    $request=New-Fixture; $script:failName='local-in'
    try { $null=Invoke-SentinelFirewallPolicy $request } catch { }
    $script:failName=''; $request.Operation='Approve'; $request.RuleName='local-in'; $null=Invoke-SentinelFirewallPolicy $request
    $request.Operation='Apply'; $null=Invoke-SentinelFirewallPolicy $request
    Assert (($script:rules.PersistentStore | Where-Object Name -eq 'local-in').Enabled -eq 'True') 'Interrupted disable overrode a subsequent explicit approval'
    $request=New-Fixture
    $dynamic=New-Rule 'generated-exception' 'domain'; $dynamic.PolicyStoreSourceType='Dynamic'; $dynamic.PolicyStoreSource='Generated'
    $script:rules.domain += $dynamic
    $result=Invoke-SentinelFirewallPolicy $request
    Assert (@($result.Conflicts | Where-Object { $_ -match 'Unmanaged effective.*generated-exception' }).Count -eq 1) 'Generated effective inbound exception was hidden'
    Assert ($dynamic.Enabled -eq 'True' -and $script:writes -notcontains 'domain') 'Read-only effective policy was rewritten'
    "Passed $script:passed firewall policy checks"
} finally {
    foreach ($dir in $script:temporaryDirectories) { Remove-Item -LiteralPath $dir -Recurse -Force }
}
