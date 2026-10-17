# Embedded, fixed management code. Request data is JSON on stdin, never executable text.
function Invoke-SentinelFirewallPolicy {
    param($Request)
    $ErrorActionPreference = 'Stop'
    $statePath = [string]$Request.StatePath
    $notes = [System.Collections.Generic.List[string]]::new()
    $state = @{ Version = 1; Rules = @(); Profiles = @() }
    if (Test-Path -LiteralPath $statePath) {
        if ((Get-Item -LiteralPath $statePath).Length -gt 4194304) { throw 'Firewall rollback journal exceeds its size limit' }
        $loaded = Get-Content -LiteralPath $statePath -Raw | ConvertFrom-Json
        if ($loaded.Version -ne 1) { throw 'Unsupported firewall rollback journal version' }
        if ($loaded.Rules -isnot [array] -or $loaded.Profiles -isnot [array] -or $loaded.Rules.Count -gt 10000 -or $loaded.Profiles.Count -gt 6) {
            throw 'Invalid firewall rollback journal structure'
        }
        foreach ($entry in $loaded.Rules) {
            if ($entry.Store -notin @('PersistentStore','localhost') -or [string]::IsNullOrEmpty($entry.Name) -or
                $entry.Identity -isnot [string] -or $entry.Identity.Length -ne 44 -or $entry.OriginalEnabled -isnot [bool] -or
                $entry.Changed -isnot [bool] -or $entry.Pending -isnot [bool] -or $entry.Approved -isnot [bool]) {
                throw 'Invalid firewall rollback rule entry'
            }
        }
        foreach ($entry in $loaded.Profiles) {
            if ($entry.Store -notin @('PersistentStore','localhost') -or $entry.Name -notin @('Domain','Private','Public') -or
                $entry.OriginalInboundAction -notin @('Allow','Block','NotConfigured') -or
                $entry.OriginalEnabled -notin @('True','False','NotConfigured') -or $entry.Changed -isnot [bool] -or
                $entry.ChangedInbound -isnot [bool] -or $entry.ChangedEnabled -isnot [bool]) {
                throw 'Invalid firewall rollback profile entry'
            }
        }
        $state.Rules = @($loaded.Rules); $state.Profiles = @($loaded.Profiles)
    }
    $ruleIndex = @{}
    foreach ($entry in $state.Rules) {
        $key = [string]$entry.Store + '|' + [string]$entry.Name
        $ruleIndex[$key] = @($ruleIndex[$key]) + $entry
    }
    function Save-State {
        $temp = $statePath + '.' + [Guid]::NewGuid().ToString('N') + '.tmp'
        try {
            $json = $state | ConvertTo-Json -Depth 10
            if ($json.Length -gt 2097152) { throw 'Firewall journal capacity exceeded; refusing unjournaled policy changes' }
            $json | Set-Content -LiteralPath $temp -Encoding UTF8
            if (Test-Path -LiteralPath $statePath) { [IO.File]::Replace($temp, $statePath, ($statePath + '.bak')) }
            else { [IO.File]::Move($temp, $statePath) }
        } finally { if (Test-Path -LiteralPath $temp) { Remove-Item -LiteralPath $temp -Force } }
    }
    function Get-RuleIdentity($rule) {
        $port = $rule | Get-NetFirewallPortFilter
        $service = $rule | Get-NetFirewallServiceFilter
        $app = $rule | Get-NetFirewallApplicationFilter
        $address = $rule | Get-NetFirewallAddressFilter
        $interface = $rule | Get-NetFirewallInterfaceFilter
        $interfaceType = $rule | Get-NetFirewallInterfaceTypeFilter
        $security = $rule | Get-NetFirewallSecurityFilter
        # Enabled is excluded so Windows re-enables cannot change a rule identity or grant approval.
        $identity = [ordered]@{
            Name=[string]$rule.Name; Direction=[string]$rule.Direction; Action=[string]$rule.Action
            Profile=[string]$rule.Profile; Protocol=[string]$port.Protocol
            LocalPort=@($port.LocalPort); RemotePort=@($port.RemotePort); IcmpType=@($port.IcmpType)
            Service=[string]$service.Service; Program=[string]$app.Program; Package=[string]$app.Package
            LocalAddress=@($address.LocalAddress); RemoteAddress=@($address.RemoteAddress)
            Interface=@($interface.InterfaceAlias); InterfaceType=[string]$interfaceType.InterfaceType
            Authentication=[string]$security.Authentication; Encryption=[string]$security.Encryption
            LocalUser=[string]$security.LocalUser; RemoteUser=[string]$security.RemoteUser; RemoteMachine=[string]$security.RemoteMachine
            OverrideBlockRules=[string]$security.OverrideBlockRules; EdgeTraversal=[string]$rule.EdgeTraversalPolicy
        } | ConvertTo-Json -Compress -Depth 6
        $sha = [Security.Cryptography.SHA256]::Create()
        try { return [Convert]::ToBase64String($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($identity))) }
        finally { $sha.Dispose() }
    }
    function Test-Dhcp($rule) {
        $port = $rule | Get-NetFirewallPortFilter
        $service = $rule | Get-NetFirewallServiceFilter
        if ([string]$service.Service -ine 'Dhcp' -or [string]$port.Protocol -notin @('UDP', '17')) { return $false }
        return ((@($port.LocalPort) -join ',') -eq '68' -and (@($port.RemotePort) -join ',') -eq '67') -or
               ((@($port.LocalPort) -join ',') -eq '546' -and (@($port.RemotePort) -join ',') -eq '547')
    }
    function Test-EssentialInbound($rule) {
        if (Test-Dhcp $rule) { return $true }
        $port = $rule | Get-NetFirewallPortFilter
        $app = $rule | Get-NetFirewallApplicationFilter
        if ([string]$port.Protocol -notin @('ICMPv6', '58') -or [string]$app.Program -ine 'System') { return $false }
        $types = @($port.IcmpType)
        if ($types.Count -eq 0) { return $false }
        foreach ($type in $types) {
            $parts = ([string]$type).Split(':')
            if ($parts[0] -notin @('1','2','3','4','133','134','135','136')) { return $false }
        }
        return $true
    }
    function Test-SelfRule($rule, $spec) {
        $port = $rule | Get-NetFirewallPortFilter
        $service = $rule | Get-NetFirewallServiceFilter
        $app = $rule | Get-NetFirewallApplicationFilter
        $address = $rule | Get-NetFirewallAddressFilter
        $interface = $rule | Get-NetFirewallInterfaceFilter
        $type = $rule | Get-NetFirewallInterfaceTypeFilter
        $security = $rule | Get-NetFirewallSecurityFilter
        $profile = [string]$rule.Profile
        $allProfiles = $profile -eq 'Any' -or ($profile -match 'Domain' -and $profile -match 'Private' -and $profile -match 'Public')
        $wantedDirection = $(if ($spec.Direction -eq 1) { 'Inbound' } else { 'Outbound' })
        $scope = (@($address.RemoteAddress) | Sort-Object) -join ','
        $expected = (([string]$Request.RemoteAddresses).Split(',') | Sort-Object) -join ','
        return [string]$rule.Enabled -eq 'True' -and [string]$rule.Action -eq 'Block' -and [string]$rule.Direction -eq $wantedDirection -and
            $allProfiles -and [string]$app.Program -ieq [string]$spec.ApplicationPath -and [string]$app.Package -in @('', 'Any') -and
            [string]$port.Protocol -in @('Any', '256') -and (@($port.LocalPort) -join ',') -in @('', 'Any') -and
            (@($port.RemotePort) -join ',') -in @('', 'Any') -and [string]$service.Service -in @('', 'Any') -and
            (@($address.LocalAddress) -join ',') -in @('Any', '*') -and $scope -ieq $expected -and
            (@($interface.InterfaceAlias) -join ',') -in @('', 'Any') -and [string]$type.InterfaceType -in @('', 'Any') -and
            [string]$security.Authentication -eq 'NotRequired' -and [string]$security.Encryption -eq 'NotRequired' -and
            [string]$security.LocalUser -in @('', 'Any') -and [string]$security.RemoteUser -in @('', 'Any') -and
            [string]$security.RemoteMachine -in @('', 'Any') -and [string]$security.OverrideBlockRules -in @('', 'False')
    }
    $stores = @('PersistentStore')
    $localGpo = $false
    try { $null = @(Get-NetFirewallProfile -PolicyStore localhost); $localGpo = $true; $stores += 'localhost' }
    catch { $notes.Add('Local Group Policy firewall store is unavailable: ' + $_.Exception.Message) }
    $restoring = [string]$Request.Operation -eq 'Restore'
    if ($restoring -and -not $localGpo -and (@($state.Rules | Where-Object Store -eq 'localhost').Count -gt 0 -or
        @($state.Profiles | Where-Object Store -eq 'localhost').Count -gt 0)) {
        throw 'Local Group Policy is unavailable but the rollback journal contains local-GPO state; retain recovery files'
    }
    if ([string]$Request.Operation -notin @('Apply', 'Restore', 'Approve', 'Revoke')) { throw 'Unsupported firewall policy operation' }
    $changed = 0
    if ([string]$Request.Operation -in @('Approve', 'Revoke')) {
        if ([string]$Request.Store -notin $stores) { throw 'Only an available local policy store can be changed' }
        $matching = @(Get-NetFirewallRule -PolicyStore $Request.Store | Where-Object { $_.Name -ceq $Request.RuleName })
        if ($matching.Count -ne 1 -or [string]$matching[0].Direction -ne 'Inbound' -or [string]$matching[0].Action -ne 'Allow') {
            throw 'The exact rule must be a single existing local inbound allow rule'
        }
        $rule = $matching[0]; $identity = Get-RuleIdentity $rule
        $entry = @($state.Rules | Where-Object { $_.Store -eq $Request.Store -and $_.Name -ceq $rule.Name -and $_.Identity -eq $identity })
        if ($entry.Count -eq 0) {
            $entry = [pscustomobject]@{ Store=[string]$Request.Store; Name=[string]$rule.Name; Identity=$identity; OriginalEnabled=([string]$rule.Enabled -eq 'True'); Changed=$false; Pending=$false; Approved=$false }
            $state.Rules += $entry
        } else { $entry = $entry[0] }
        if (-not $entry.PSObject.Properties['Approved']) { $entry | Add-Member -NotePropertyName Approved -NotePropertyValue $false }
        $entry.Approved = [string]$Request.Operation -eq 'Approve'
        $entry.Changed = $true; $entry.Pending = -not $entry.Approved; Save-State
        $rule | Set-NetFirewallRule -Enabled $(if ($entry.Approved) { 'True' } else { 'False' })
        $entry.Pending = $false; Save-State
        return [pscustomobject]@{ Approved=$entry.Approved; Store=$entry.Store; RuleName=$entry.Name }
    }
    foreach ($store in $stores) {
        # A failed inventory must never be mistaken for an empty policy store.
        $inventory = @(Get-NetFirewallRule -PolicyStore $store)
        $profiles = @(Get-NetFirewallProfile -PolicyStore $store)
        if ($restoring) {
            foreach ($entry in @($state.Rules | Where-Object { $_.Store -eq $store -and $_.Changed })) {
                $rule = @($inventory | Where-Object { $_.Name -ceq $entry.Name })
                if ($rule.Count -eq 1 -and (Get-RuleIdentity $rule[0]) -eq $entry.Identity) {
                    if ([string]$rule[0].Enabled -ne [string]$entry.OriginalEnabled) {
                        $rule[0] | Set-NetFirewallRule -Enabled $(if ($entry.OriginalEnabled) { 'True' } else { 'False' }); $changed++
                    }
                    $entry.Changed = $false; Save-State
                } else { $notes.Add('Rollback skipped a removed or changed rule: ' + $store + '/' + $entry.Name) }
            }
            foreach ($entry in @($state.Profiles | Where-Object { $_.Store -eq $store -and $_.Changed })) {
                $profile = @($profiles | Where-Object { [string]$_.Name -eq $entry.Name })
                if ($profile.Count -eq 1) {
                    if ($entry.ChangedInbound -and [string]$profile[0].DefaultInboundAction -eq 'Block') {
                        $profile[0] | Set-NetFirewallProfile -DefaultInboundAction $entry.OriginalInboundAction
                    }
                    if ($entry.ChangedEnabled -and [string]$profile[0].Enabled -eq 'True') {
                        $profile[0] | Set-NetFirewallProfile -Enabled $entry.OriginalEnabled
                    }
                    $entry.Changed = $false; Save-State
                }
            }
            foreach ($spec in @($Request.SelfRules)) {
                @($inventory | Where-Object { $_.Name -ceq $spec.Name -or $_.Name -ceq ($spec.Name + '-Repair') }) | Remove-NetFirewallRule
            }
            continue
        }
        foreach ($profile in $profiles) {
            $prior = @($state.Profiles | Where-Object { $_.Store -eq $store -and $_.Name -eq [string]$profile.Name })
            if ($prior.Count -eq 0) {
                $entry = [pscustomobject]@{ Store=$store; Name=[string]$profile.Name; OriginalInboundAction=[string]$profile.DefaultInboundAction; OriginalEnabled=[string]$profile.Enabled; ChangedInbound=([string]$profile.DefaultInboundAction -ne 'Block'); ChangedEnabled=([string]$profile.Enabled -ne 'True'); Changed=([string]$profile.DefaultInboundAction -ne 'Block' -or [string]$profile.Enabled -ne 'True') }
                $state.Profiles += $entry; Save-State # Journal before mutation, including crash recovery.
                if ($entry.Changed) { $profile | Set-NetFirewallProfile -DefaultInboundAction Block -Enabled True }
            } elseif ([string]$profile.DefaultInboundAction -ne 'Block' -or [string]$profile.Enabled -ne 'True') {
                $prior[0].Changed = $true
                if ([string]$profile.DefaultInboundAction -ne 'Block') { $prior[0].ChangedInbound = $true }
                if ([string]$profile.Enabled -ne 'True') { $prior[0].ChangedEnabled = $true }
                Save-State
                $profile | Set-NetFirewallProfile -DefaultInboundAction Block -Enabled True
            }
        }
        foreach ($rule in $inventory) {
            if ([string]$rule.Direction -ne 'Inbound' -or [string]$rule.Action -ne 'Allow') { continue }
            $enabled = [string]$rule.Enabled -eq 'True'
            $knownName = @($ruleIndex[([string]$store + '|' + [string]$rule.Name)] | Where-Object { $null -ne $_ })
            if (-not $enabled -and $knownName.Count -gt 0) { continue }
            if (Test-EssentialInbound $rule) { continue }
            $identity = Get-RuleIdentity $rule
            $prior = @($knownName | Where-Object { $null -ne $_ -and $_.Identity -eq $identity })
            if ($prior.Count -gt 0) {
                $entry = $prior[0]
                if ($entry.PSObject.Properties['Approved'] -and $entry.Approved) { continue }
                if ($enabled) {
                    $entry.Changed = $true; $entry.Pending = $true; Save-State
                    $rule | Set-NetFirewallRule -Enabled False
                    $entry.Pending = $false; Save-State; $changed++
                }
                continue
            }
            $entry = [pscustomobject]@{ Store=$store; Name=[string]$rule.Name; Identity=$identity; OriginalEnabled=$enabled; Changed=$enabled; Pending=$enabled; Approved=$false }
            $state.Rules += $entry; $ruleIndex[([string]$store + '|' + [string]$rule.Name)] = @($knownName | Where-Object { $null -ne $_ }) + $entry; Save-State
            if ($enabled) {
                $rule | Set-NetFirewallRule -Enabled False
                $entry.Pending = $false; Save-State; $changed++
            }
        }
        # A previous mutation may have failed after the journal write. Retry those entries only.
        foreach ($entry in @($state.Rules | Where-Object { $_.Store -eq $store -and $_.Pending })) {
            $rule = @($inventory | Where-Object { $_.Name -ceq $entry.Name })
            if ($rule.Count -eq 1 -and (Get-RuleIdentity $rule[0]) -eq $entry.Identity) {
                $rule[0] | Set-NetFirewallRule -Enabled False
                $entry.Pending = $false; Save-State; $changed++
            }
        }
        if ($store -eq 'localhost') {
            foreach ($spec in @($Request.SelfRules)) {
                $parameters = @{
                    Enabled='True'; Direction= $(if ($spec.Direction -eq 1) { 'Inbound' } else { 'Outbound' })
                    Action='Block'; Profile='Any'; Protocol='Any'; LocalAddress='Any'
                    RemoteAddress=([string]$Request.RemoteAddresses).Split(','); Program=[string]$spec.ApplicationPath
                    InterfaceType='Any'; Service='Any'; EdgeTraversalPolicy='Block'
                }
                $existing = @($inventory | Where-Object { $_.Name -ceq $spec.Name })
                if ($existing.Count -eq 1 -and (Test-SelfRule $existing[0] $spec)) { continue }
                # Install a fresh guard before replacing a drifted primary rule. This avoids
                # inheriting restrictive package/interface/security filters or opening a repair gap.
                $repairName = [string]$spec.Name + '-Repair'
                @($inventory | Where-Object { $_.Name -ceq $repairName }) | Remove-NetFirewallRule
                New-NetFirewallRule -PolicyStore localhost -Name $repairName -DisplayName $repairName -Group 'Sentinel Offline Isolation' @parameters | Out-Null
                $existing | Remove-NetFirewallRule
                New-NetFirewallRule -PolicyStore localhost -Name $spec.Name -DisplayName $spec.Name -Group 'Sentinel Offline Isolation' @parameters | Out-Null
                @(Get-NetFirewallRule -PolicyStore localhost | Where-Object { $_.Name -ceq $repairName }) | Remove-NetFirewallRule
            }
        }
    }
    if ($restoring) {
        return [pscustomobject]@{ Restored=$true; Changed=$changed; LocalGpoAvailable=$localGpo; Notes=@($notes) }
    }
    $effective = @(Get-NetFirewallRule -PolicyStore ActiveStore -TracePolicyStore)
    $effectiveProfiles = @(Get-NetFirewallProfile -PolicyStore ActiveStore)
    $conflicts = [System.Collections.Generic.List[string]]::new()
    foreach ($spec in @($Request.SelfRules)) {
        $rule = @($effective | Where-Object { $_.Name -ceq $spec.Name })
        if ($rule.Count -ne 1) { $conflicts.Add('Missing/ambiguous effective self-block: ' + $spec.Name); continue }
        $enforcement = @($rule[0].EnforcementStatus | ForEach-Object { [string]$_ })
        $enforced = ($enforcement -contains 'Full') -and @($enforcement | Where-Object { $_ -notin @('Full', 'InactiveProfile') }).Count -eq 0
        if (-not (Test-SelfRule $rule[0] $spec) -or -not $enforced) {
            $conflicts.Add('Self-block not fully effective (policy/filter conflict): ' + $spec.Name + ' / ' + [string]$rule[0].EnforcementStatus)
        }
    }
    $selfBlocksEffective = $conflicts.Count -eq 0
    foreach ($service in @(Get-Service -Name BFE,MpsSvc)) {
        if ([string]$service.Status -ne 'Running') { $conflicts.Add('Required firewall service is not running: ' + [string]$service.Name) }
    }
    foreach ($profile in $effectiveProfiles) {
        if ([string]$profile.Enabled -ne 'True' -or [string]$profile.DefaultInboundAction -ne 'Block') {
            $conflicts.Add('Effective profile is disabled or allows inbound by default: ' + [string]$profile.Name)
        }
    }
    # Read-only/generated policy cannot be safely rewritten as a local rule. Surface every
    # enabled effective exception outside the approved local baseline instead of claiming compliance.
    $localNames = @('localhost', [Environment]::MachineName, 'Local Group Policy')
    foreach ($rule in $effective) {
        if ([string]$rule.Direction -ne 'Inbound' -or [string]$rule.Action -ne 'Allow' -or
            [string]$rule.Enabled -ne 'True' -or (Test-EssentialInbound $rule)) { continue }
        $type = [string]$rule.PolicyStoreSourceType
        $source = [string]$rule.PolicyStoreSource
        if ($type -eq 'GroupPolicy' -and $source -notin $localNames) {
            $conflicts.Add('Managed inbound exception remains enabled: ' + [string]$rule.Name + ' / ' + $source)
            continue
        }
        $store = $null
        if ($type -eq 'Local' -and $source -eq 'PersistentStore') { $store = 'PersistentStore' }
        elseif ($type -eq 'GroupPolicy' -and $source -in $localNames) { $store = 'localhost' }
        if (-not $store) {
            $conflicts.Add('Unmanaged effective inbound exception remains enabled: ' + [string]$rule.Name + ' / ' + $type + ' / ' + $source)
            continue
        }
        $identity = Get-RuleIdentity $rule
        $approved = @($state.Rules | Where-Object { $_.Store -eq $store -and $_.Name -ceq $rule.Name -and $_.Identity -eq $identity -and $_.Approved })
        if ($approved.Count -eq 0) { $conflicts.Add('Unapproved effective inbound exception remains enabled: ' + [string]$rule.Name + ' / ' + $source) }
    }
    return [pscustomobject]@{ Changed=$changed; LocalGpoAvailable=$localGpo; SelfBlocksEffective=$selfBlocksEffective; PolicyCompliant=($conflicts.Count -eq 0); Conflicts=@($conflicts | Select-Object -First 128); Notes=@($notes | Select-Object -First 32); Coverage="PersistentStore and supported local computer GPO; non-writable effective exceptions are reported; AppIso rules outside NetSecurity enumeration require separate review" }
}
