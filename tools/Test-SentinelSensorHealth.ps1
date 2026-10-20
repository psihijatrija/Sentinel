# Read-only collection diagnostics. -Probe issues one benign DNS query; it changes no OS settings.
[CmdletBinding()]
param(
    [string]$MetricsPath = (Join-Path $env:ProgramData 'Sentinel\ops_metrics.json'),
    [switch]$Probe,
    [ValidateRange(15,120)][int]$WaitSeconds = 35
)
$ErrorActionPreference = 'Stop'

function Read-Metrics {
    if (!(Test-Path -LiteralPath $MetricsPath)) { throw "Metrics missing: $MetricsPath" }
    Get-Content -LiteralPath $MetricsPath -Raw | ConvertFrom-Json
}
function Read-DnsChannel {
    try {
        $log = Get-WinEvent -ListLog 'Microsoft-Windows-DNS-Client/Operational' -ErrorAction Stop
        [pscustomobject]@{ Available = $true; Enabled = $log.IsEnabled; RecordCount = $log.RecordCount; Error = $null }
    } catch {
        [pscustomobject]@{ Available = $false; Enabled = $null; RecordCount = $null; Error = $_.Exception.Message }
    }
}

$before = Read-Metrics
$channel = Read-DnsChannel
$probeName = $null
$probeError = $null
$probeObservedInWindows = $false
if ($Probe) {
    $probeName = 'sentinel-health-' + [guid]::NewGuid().ToString('N') + '.example.com'
    $started = Get-Date
    try { [void][System.Net.Dns]::GetHostAddresses($probeName) }
    catch { $probeError = $_.Exception.Message } # NXDOMAIN is expected; the query is what we need.
    Start-Sleep -Seconds $WaitSeconds
    try {
        $records = Get-WinEvent -FilterHashtable @{
            LogName = 'Microsoft-Windows-DNS-Client/Operational'; Id = 3006; StartTime = $started
        } -MaxEvents 4096 -ErrorAction Stop
        foreach ($record in $records) {
            [xml]$xml = $record.ToXml()
            foreach ($item in $xml.Event.EventData.Data) {
                if ($item.Name -eq 'QueryName' -and $item.InnerText.TrimEnd('.') -eq $probeName) {
                    $probeObservedInWindows = $true
                }
            }
        }
    } catch { $probeError = 'Reading probe event: ' + $_.Exception.Message }
}
$after = Read-Metrics
$details = @()
foreach ($property in $after.MonitorStates.PSObject.Properties) {
    $name = $property.Name
    $state = $property.Value
    $progress = $after.SensorProgress.$name
    if ($state.State -ne 'Running' -or $progress.State -in @('Failed','Stale','Unknown') -or
        $name -in @('DnsQueryMonitor','EtwProcessMonitor','EtwThreatIntelMonitor','FileVerdictScanner','EtwSessionGuard')) {
        $details += [pscustomobject]@{
            Name = $name; TaskState = $state.State; Reason = $state.LastError
            Collection = $progress.State; Scope = $progress.Scope; Error = $progress.Error
            LastSuccess = $progress.LastSuccess; Cycles = $progress.SuccessfulCycles; Observations = $progress.Observations
        }
    }
}
$denied = @($after.Etw.ProviderStatus.PSObject.Properties | Where-Object { $_.Value -ne 0 } |
    ForEach-Object { [pscustomobject]@{ Provider = $_.Name; Win32Error = $_.Value } })
$dnsBefore = $before.SensorProgress.DnsQueryMonitor.Observations
$dnsAfter = $after.SensorProgress.DnsQueryMonitor.Observations
[pscustomobject]@{
    CapturedUtc = [datetime]::UtcNow.ToString('o')
    ProductVersion = $after.ProductVersion; MetricsTimestampUtc = $after.TimestampUtc
    MetricsAgeSeconds = ([datetime]::UtcNow - ([datetime]$after.TimestampUtc).ToUniversalTime()).TotalSeconds
    RegisteredTasks = $after.RegisteredMonitors; RunningTasks = $after.RunningMonitors
    DnsChannel = $channel
    Probe = [pscustomobject]@{
        Requested = [bool]$Probe; QueryName = $probeName; ResolverMessage = $probeError
        ExactQueryFoundInWindows = $probeObservedInWindows
        ParsedQueriesBefore = $dnsBefore; ParsedQueriesAfter = $dnsAfter
        Note = 'A counter increase alone does not identify this exact query. Inspect it alongside the collection mode, errors and optional Windows event match. Real-time ETW does not require the Operational channel. Old binaries lack observation counters.'
    }
    EtwConsumerAlive = $after.Etw.ConsumerAlive
    EtwProviderFailures = $denied
    NativeEventsLost = $after.Etw.NativeEventsLost
    NativeLossDelta = ([long]$after.Etw.NativeEventsLost - [long]$before.Etw.NativeEventsLost)
    DispatchDrops = $after.Etw.DispatchDrops
    Monitors = $details
} | ConvertTo-Json -Depth 12
