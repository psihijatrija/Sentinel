# AntivirusLite.ps1
# Author: Gorstak
#
# EMBED MODE (-Embedded): when hosted in-process by Sentinel.Agent via the
# System.Management.Automation runspace, pass -Embedded. This disables the two
# Start-Job-based scanners (memory scanner + deep scanner), which are the only
# paths that spawn a child powershell.exe. In embedded mode every monitor runs
# on the hosting runspace thread inside Sentinel.Agent.exe, so NO separate
# PowerShell process is ever visible in Task Manager. AutoStart (scheduled task)
# is also suppressed in embedded mode - the Agent owns the lifecycle.
param(
    [switch]$Embedded,

    # When hosted by Sentinel.Agent, the agent passes its own install directory
    # here. The engine then treats that directory (and the Sentinel process
    # names) as OFF-LIMITS for every destructive action - no quarantine, no
    # delete, no process kill - so the embedded AV can never attack the product
    # it runs inside. Without this guard the file scanner flagged
    # Sentinel.Agent.exe / Sentinel.Service.exe as "known bad" and the C2 engine
    # killed them, taking the whole agent down.
    [string]$SentinelDir = ""
)

$Config = @{
    BaseDirectory           = "C:\ProgramData\Antivirus"
    QuarantineDirectory     = "C:\ProgramData\Antivirus\Quarantine"
    BackupDirectory         = "C:\ProgramData\Antivirus\Backup"
    LogFile                 = "C:\ProgramData\Antivirus\av.log"
    BlockedLogFile          = "C:\ProgramData\Antivirus\blocked.log"
    DatabaseFile            = "C:\ProgramData\Antivirus\known_files.db"
    OwnPidFile              = "C:\ProgramData\Antivirus\av_pids.txt"
    
    MaxDatabaseEntries      = 50000
    MaxLogSizeMB            = 10
    MemoryScanIntervalSec   = 300   # was 8s. Memory scans walk .Modules across
                                    # every process, which bloats working set.
                                    # Run periodically (every 5 min) instead.
    MemoryScanMaxSizeMB     = 150
    ProcessTimeoutSeconds   = 30
    DatabaseCleanupDays     = 30
    
    EnableMemoryScanning    = $true  # Set $false to disable in-memory scanning.
                                     # String/module heuristic scan only.
                                     # Runs every MemoryScanIntervalSec
                                     # (periodic), not in a tight loop.
    EnableRealtimeMonitor   = $true
    EnableAutoStart         = $true  # On launch (as admin) register a scheduled
                                     # task so this script runs at every startup.
    AutoStartTaskName       = "AntivirusLite"
    EnableThreatIntel       = $true
    EnableAlerts            = $true
    AutoQuarantine          = $true
    
    MalwareBazaarApiKey     = ""
    CirclHashLookupUrl      = "https://hashlookup.circl.lu/lookup/sha256"
    CymruApiUrl             = "https://api.malwarehash.cymru.com/v1/hash"
    MalwareBazaarApiUrl     = "https://mb-api.abuse.ch/api/v1/"
    
    CymruDetectionThreshold = 60
    SuspiciousFileSizeKB    = 3072
}

$BehaviorConfig = @{
    EnableBehaviorKill      = $true
    EnableAutoBlockC2       = $true
    DeepScanIntervalHours   = 6
    ThreatIntelUpdateDays   = 7
}

# Embedded-mode overrides. When Sentinel.Agent hosts this script in-process,
# suppress everything that would create a visible child process or steal the
# lifecycle from the Agent:
#   - Start-MemoryScanner uses Start-Job  -> spawns child powershell.exe
#   - the deep-scan loop   uses Start-Job  -> spawns child powershell.exe
#   - Register-AutoStart registers a scheduled task that runs the .ps1 directly,
#     which would double-run outside the Agent.
# The in-process monitors (file watcher, WMI exec monitor, C2 engine,
# reverse-shell killer) are unaffected and keep running on the host thread.
if ($Embedded) {
    $Config.EnableMemoryScanning = $false
    $Config.EnableThreatIntel    = $false   # gates the deep-scan Start-Job block
    $Config.EnableAutoStart      = $false
}

# ============================================================================
# C2 / Reverse-Shell killer configuration
# Adapted from Antivirus.ps1 (Gorstak) - scored C2 detection, beacon tracking,
# reverse-shell command-line heuristics, and firewall auto-block.
# ============================================================================
$C2Config = @{
    EnableC2Detection       = $true   # Scored outbound-connection analysis + kill
    EnableReverseShellKill  = $true   # Reverse-shell command-line + handle heuristics
    EnableBeaconDetection   = $true   # Regular-interval callback (beacon) detection
    EnableFirewallAutoBlock = $true   # Drop a blocking firewall rule on the remote IP
    KillScoreThreshold      = 50      # Score at/above which the owning process is killed
    FirewallBlockThreshold  = 40      # Score at/above which the remote IP is firewall-blocked
    BeaconMinSamples        = 4       # Minimum callbacks before a beacon verdict
    BeaconMaxJitterRatio    = 0.25    # stdDev/avg below this = regular = beacon
    BeaconMinIntervalSec    = 10      # Ignore very chatty intervals (normal traffic)
    BeaconMaxIntervalSec    = 86400   # Ignore intervals longer than a day
    IpRotationThreshold     = 12      # One process talking to this many unique IPs = C2 rotation
}

# Ports strongly associated with Metasploit/backdoors/reverse shells.
# Value = base score contribution when a remote connection uses this port.
$C2SuspiciousPorts = @{
    4444 = 30; 4445 = 30; 5555 = 30; 6666 = 20; 7777 = 20; 8888 = 15
    9001 = 20; 9002 = 20; 9999 = 15; 1337 = 25; 31337 = 25
    12345 = 20; 54321 = 20; 50050 = 35   # 50050 = Cobalt Strike team-server default
}

# Known-bad / bulletproof-hoster IP prefixes (coarse heuristic, scored not blind-blocked)
$C2MaliciousRangePrefixes = @('5.8.', '45.', '91.', '185.', '194.', '195.')

# TLDs commonly abused for free/anonymous C2 domains
$C2SuspiciousTLDs = @('.onion', '.bit', '.i2p', '.tk', '.ml', '.ga', '.cf', '.gq', '.top', '.xyz', '.duckdns.org', '.ddns.net', '.no-ip.org', '.hopto.org')

# Interpreters/LOLBins that should rarely hold a raw outbound socket to the internet
$C2SuspiciousProcesses = @('cmd', 'powershell', 'pwsh', 'wscript', 'cscript', 'mshta', 'rundll32', 'regsvr32', 'certutil', 'bitsadmin', 'installutil', 'msbuild')

# Processes that legitimately open localhost listeners + outbound 443 (skip for proxy pattern)
$C2ProxyExcludeProcesses = @('svchost', 'msedge', 'chrome', 'firefox', 'opera', 'brave', 'iexplore', 'ApplicationFrameHost', 'System', 'Idle')

# Reverse-shell command-line signatures (regex, case-insensitive)
$ReverseShellPatterns = @(
    # PowerShell reverse shells
    'powershell.*-nop.*-w.*hidden.*-(e|enc|encodedcommand)',
    'powershell.*-(e|enc|encodedcommand)\s+[A-Za-z0-9+/=]{40,}',
    'new-object\s+system\.net\.sockets\.tcpclient',
    'new-object\s+net\.sockets\.tcpclient',
    '\$client\s*=\s*new-object.*tcpclient',
    'getstream\(\).*\.read\(|\.write\(.*getstream',
    'iex\s*\(.*\.getstream',
    # nix-style / bash reverse shells (via WSL, git-bash, etc.)
    '/dev/tcp/\d{1,3}(\.\d{1,3}){3}/\d+',
    'bash\s+-i\s+>&\s*/dev/tcp',
    'sh\s+-i\s+2>&1',
    # netcat / socat family
    '\bnc(\.exe)?\b.*(-e|-c)\s+(cmd|/bin/sh|bash|powershell)',
    '\bncat(\.exe)?\b.*(-e|--exec)',
    '\bsocat\b.*exec',
    # cmd piping its I/O to a socket helper
    'cmd(\.exe)?\s+/c\s+.*(nc|ncat|socat|telnet)\b',
    # python/perl/php one-liner reverse shells
    'python.*socket.*connect.*subprocess.*(call|popen)',
    'perl.*socket.*(exec|system)\(',
    'php\s+-r.*fsockopen'
)

$RulesDirectory = Join-Path $Config.BaseDirectory "rules"
$KnownFilesCache = @{}

# Beacon tracking: per "PID:RemoteIP" key, keep the timestamps we've seen an
# established connection. A callback that recurs at a near-constant interval is
# a beacon. We sample on each scan cycle rather than hooking the network stack.
$script:BeaconHistory = @{}
# Remote IPs we have already firewall-blocked, so we don't re-add rules each cycle.
$script:BlockedC2Ips = [System.Collections.Generic.HashSet[string]]::new()

$IsAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")

$AllowedSIDs = @('S-1-2-0', 'S-1-5-20')

$RiskyPaths = @('\temp\', '\downloads\', '\appdata\local\temp\', '\public\', '\windows\temp\', '\appdata\roaming\', '\desktop\')

$MonitoredExtensions = @(
    # Standard executable and script extensions
    '.exe','.dll','.sys','.ocx','.scr','.com','.cpl','.msi','.drv','.winmd',
    '.ps1','.bat','.cmd','.vbs','.js','.hta','.jse','.wsf','.wsh','.psc1','.exif',
   
    # Extended list (unchanged from original)
    '.zoo','.zlo','.zfsendtotarget','.z','.xz','.xsl','.xps','.xpi','.xnk','.xml',
    '.xlw','.xltx','.xltm','.xlt','.xlsx','.xlsm','.xlsb','.xls','.xlm','.xll',
    '.xld','.xlc','.xlb','.xlam','.xla','.xip','.xbap','.xar','.wwl','.wsc',
    '.ws','.wll','.wiz','.website','.webpnp','.webloc','.wbk','.was','.vxd',
    '.vsw','.vst','.vss','.vsmacros','.vhdx','.vhd','.vbp','.vb','.url','.tz',
    '.txz','.tsp','.tpz','.tool','.tmp','.tlb','.theme','.tgz','.terminal',
    '.term','.tbz','.taz','.tar','.swf','.stm','.spl','.slk','.sldx',
    '.sldm','.sit','.shs','.shb','.settingcontent-ms','.search-ms','.searchconnector-ms',
    '.sea','.sct','.scf','.rtf','.rqy','.rpy','.rev','.reg','.rb',
    '.rar','.r09','.r08','.r07','.r06','.r05','.r04','.r03','.r02','.r01',
    '.r00','.pyzw','.pyz','.pyx','.pywz','.pyw','.pyt','.pyp','.pyo','.pyi',
    '.pyde','.pyd','.pyc','.py3','.py','.pxd','.pstreg','.pst','.psdm1','.psd1',
    '.prn','.printerexport','.prg','.prf','.pptx','.pptm','.ppt','.ppsx','.ppsm',
    '.pps','.ppam','.ppa','.potx','.potm','.pot','.plg','.pl','.pkg','.pif',
    '.pi','.perl','.pcd','.pa','.osd','.oqy','.ops','.one','.ods',
    '.ntfs','.nsh','.nls','.mydocs','.mui','.msu','.mst','.msp','.mshxml',
    '.msh2xml','.msh2','.msh1xml','.msh1','.msh','.mof','.mmc','.mhtml','.mht',
    '.mdz','.mdw','.mdt','.mdn','.mdf','.mde','.mdb','.mda','.mcl','.mcf',
    '.may','.maw','.mav','.mau','.mat','.mas','.mar','.maq','.mapimail',
    '.manifest','.mam','.mag','.maf','.mad','.lzh','.local','.library-ms',
    '.lha','.ldb','.laccdb','.ksh','.job','.jnlp','.jar','.its','.isp','.iso',
    '.iqy','.ins','.ini','.inf','.img','.ime','.ie','.hwp','.htt','.htm',
    '.htc','.hpj','.hlp','.hex','.gz','.grp','.glk','.gadget',
    '.fxp','.fon','.fat','.elf','.ecf','.dqy','.dotx','.dotm',
    '.dot','.docm','.docb','.doc','.dmg','.dir','.dif','.diagcab',
    '.desktop','.desklink','.der','.dcr','.db','.csv','.csh','.crx','.crt',
    '.crazy','.cpx','.command','.cnt','.cnv','.clb',
    '.class','.cla','.chm','.chi','.cfg','.cer','.cdb','.cab','.bzip2','.bzip',
    '.bz2','.bz','.bas','.ax','.asx','.aspx','.asp','.asa','.arj',
    '.arc','.appref-ms','.application','.app','.air','.adp','.adn','.ade',
    '.ad','.acm','.accdu','.accdt','.accdr','.accde','.accda','.c','.h'
)

$ProtectedProcesses = @(
    'System', 'Idle', 'Registry', 'smss', 'csrss', 'wininit', 'services', 'lsass',
    'svchost', 'winlogon', 'explorer', 'dwm', 'SearchUI', 'SearchIndexer', 'fontdrvhost',
    'RuntimeBroker', 'sihost', 'taskhostw',
    # Sentinel's own processes - the embedded engine must never kill its host.
    'Sentinel.Agent', 'Sentinel.Service', 'SentinelAutoRotate', 'SentinelGuard'
)

# Normalized Sentinel install directory for self-protection. Any file under this
# directory is exempt from quarantine/delete, and any process whose image lives
# here is exempt from being killed. Set from the -SentinelDir parameter the
# agent passes in embedded mode; empty (and thus inert) for standalone runs.
$script:SelfProtectDir = ""
if ($SentinelDir) {
    try { $script:SelfProtectDir = ([IO.Path]::GetFullPath($SentinelDir)).TrimEnd('\').ToLower() } catch {}
}

function Test-IsSentinelOwnedPath {
    # $true when the path is inside Sentinel's install dir (self-protection).
    param([string]$Path)
    if (-not $script:SelfProtectDir) { return $false }
    if ([string]::IsNullOrWhiteSpace($Path)) { return $false }
    try {
        $full = ([IO.Path]::GetFullPath($Path)).ToLower()
        return $full.StartsWith($script:SelfProtectDir + '\') -or $full -eq $script:SelfProtectDir
    } catch { return $false }
}

$EvilStrings = @(
    'mimikatz', 'sekurlsa::', 'kerberos::', 'lsadump::', 'wdigest', 'tspkg',
    'http-beacon', 'https-beacon', 'cobaltstrike', 'sleepmask', 'reflective',
    'amsi.dll', 'AmsiScanBuffer', 'EtwEventWrite', 'MiniDumpWriteDump',
    'VirtualAllocEx', 'WriteProcessMemory', 'CreateRemoteThread',
    'ReflectiveLoader', 'sharpchrome', 'rubeus', 'safetykatz', 'sharphound',
    'invoke-mimikatz', 'invoke-bloodhound', 'powersploit', 'empire'
)

New-Item -ItemType Directory -Path $Config.BaseDirectory, $Config.QuarantineDirectory, $Config.BackupDirectory, $RulesDirectory -Force -ErrorAction SilentlyContinue | Out-Null

function Write-Log {
    param([string]$Message)
    
    $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $logLine = "$timestamp | $Message"
    
    try {
        $logLine | Out-File -FilePath $Config.LogFile -Append -Encoding UTF8
    } catch {
        Write-Host "[LOG ERROR] $_"
    }
    
    Write-Host $logLine
    
    if (Test-Path $Config.LogFile) {
        $logSize = (Get-Item $Config.LogFile -ErrorAction SilentlyContinue).Length
        if ($logSize -ge ($Config.MaxLogSizeMB * 1MB)) {
            $archiveName = "$($Config.BaseDirectory)\av_log_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt"
            try {
                Rename-Item -Path $Config.LogFile -NewName $archiveName -ErrorAction SilentlyContinue
            } catch {}
        }
    }
}

# --- Working-set trimming -----------------------------------------------
# GC.Collect() frees managed memory inside the process but does NOT hand it
# back to the OS, so Task Manager's working set stays high. EmptyWorkingSet
# (psapi.dll) asks Windows to release this process's physical pages back to
# the system. For a background scanner that idles between cycles, the trimmed
# pages are genuinely unneeded, so this is a safe way to keep the footprint low.
# Ref: https://learn.microsoft.com/windows/desktop/api/psapi/nf-psapi-emptyworkingset
if (-not ([System.Management.Automation.PSTypeName]'AV.MemTrim').Type) {
    Add-Type -Namespace AV -Name MemTrim -MemberDefinition @'
[System.Runtime.InteropServices.DllImport("psapi.dll")]
public static extern bool EmptyWorkingSet(System.IntPtr hProcess);
'@ -ErrorAction SilentlyContinue
}

# --- Self-PID registry --------------------------------------------------
# Every AV-owned PowerShell process (the main script and each background job)
# records its own PID in a shared file. The memory scanner reads this file so
# it never scans or kills the antivirus's own processes - while still scanning
# every PowerShell process the AV did NOT spawn.
function Register-OwnPid {
    param([int]$ProcessId = $PID)
    try {
        $mutex = New-Object System.Threading.Mutex($false, 'Global\AV_PidFile')
        [void]$mutex.WaitOne(2000)
        try {
            Add-Content -Path $Config.OwnPidFile -Value $ProcessId -ErrorAction SilentlyContinue
        } finally {
            $mutex.ReleaseMutex(); $mutex.Dispose()
        }
    } catch {}
}

function Remove-DeadOwnPids {
    # Rewrite the shared PID file keeping only PIDs whose process is still
    # alive, so the registry does not accumulate stale entries over long uptime.
    try {
        $mutex = New-Object System.Threading.Mutex($false, 'Global\AV_PidFile')
        [void]$mutex.WaitOne(2000)
        try {
            if (-not (Test-Path $Config.OwnPidFile)) { return }

            $alive = [System.Collections.Generic.HashSet[int]]::new()
            foreach ($line in (Get-Content -Path $Config.OwnPidFile -ErrorAction SilentlyContinue)) {
                $n = 0
                if ([int]::TryParse(($line.Trim()), [ref]$n)) {
                    if (Get-Process -Id $n -ErrorAction SilentlyContinue) { [void]$alive.Add($n) }
                }
            }
            # Our own PID is always alive here; make sure it stays listed.
            [void]$alive.Add($PID)
            Set-Content -Path $Config.OwnPidFile -Value ($alive | Sort-Object) -ErrorAction SilentlyContinue
        } finally {
            $mutex.ReleaseMutex(); $mutex.Dispose()
        }
    } catch {}
}

# Fresh start: clear any stale PIDs from a previous run, then register self.
try { Remove-Item -Path $Config.OwnPidFile -Force -ErrorAction SilentlyContinue } catch {}
Register-OwnPid -ProcessId $PID

function Clear-ProcessMemory {
    # Compact the Large Object Heap, do a blocking collect, then trim the
    # working set back to the OS. Call this after a scan pass completes.
    try {
        [System.Runtime.GCSettings]::LargeObjectHeapCompactionMode = `
            [System.Runtime.GCLargeObjectHeapCompactionMode]::CompactOnce
    } catch {}

    [System.GC]::Collect()
    [System.GC]::WaitForPendingFinalizers()
    [System.GC]::Collect()

    try {
        [void][AV.MemTrim]::EmptyWorkingSet([System.Diagnostics.Process]::GetCurrentProcess().Handle)
    } catch {}
}

Write-Log "=== Clean Antivirus Starting ==="
Write-Log "C2 killer: $($C2Config.EnableC2Detection) | ReverseShell killer: $($C2Config.EnableReverseShellKill) | Beacon detect: $($C2Config.EnableBeaconDetection) | FW auto-block: $($C2Config.EnableFirewallAutoBlock)"
Write-Log "Admin: $IsAdmin | User: $env:USERNAME | SID: $([Security.Principal.WindowsIdentity]::GetCurrent().User.Value)"

function Load-Database {
    if (Test-Path $Config.DatabaseFile) {
        try {
            $lines = Get-Content $Config.DatabaseFile -ErrorAction Stop
            $count = 0
            
            foreach ($line in $lines) {
                if ($line -match '^([0-9a-f]{64}),(true|false),(.+)$') {
                    $hash = $matches[1]
                    $safe = [bool]::Parse($matches[2])
                    $timestamp = $matches[3]
                    
                    try {
                        $entryDate = [datetime]::Parse($timestamp)
                        if ($entryDate -lt (Get-Date).AddDays(-$Config.DatabaseCleanupDays)) {
                            continue
                        }
                    } catch {}
                    
                    $KnownFilesCache[$hash] = $safe
                    $count++
                    
                    if ($count -ge $Config.MaxDatabaseEntries) {
                        break
                    }
                }
            }
            
            Write-Log "Loaded $count entries from database"
        } catch {
            Write-Log "Failed to load database: $_"
            $KnownFilesCache.Clear()
        }
    } else {
        New-Item -Path $Config.DatabaseFile -ItemType File -Force -ErrorAction SilentlyContinue | Out-Null
        Write-Log "Created new database file"
    }
}

function Save-ToDatabase {
    param(
        [string]$Hash,
        [bool]$IsSafe
    )
    
    if (-not $Hash) { return }
    
    $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $entry = "$Hash,$IsSafe,$timestamp"
    
    try {
        $entry | Out-File -FilePath $Config.DatabaseFile -Append -Encoding UTF8
        $KnownFilesCache[$Hash] = $IsSafe
    } catch {
        Write-Log "Failed to save to database: $_"
    }

    # Hard cap the in-memory cache. A dictionary that only ever grows is a leak;
    # GC cannot reclaim live entries. Evict oldest ~10% when over the cap.
    if ($KnownFilesCache.Count -gt $Config.MaxDatabaseEntries) {
        $evictCount = [int]($Config.MaxDatabaseEntries * 0.1)
        $toEvict = @($KnownFilesCache.Keys | Select-Object -First $evictCount)
        foreach ($k in $toEvict) { [void]$KnownFilesCache.Remove($k) }
        Write-Log "KnownFilesCache trimmed by $($toEvict.Count) entries (cap: $($Config.MaxDatabaseEntries))"
    }
}

Load-Database

function Register-AutoStart {
    # Registers a scheduled task that runs THIS script at system startup as
    # SYSTEM with highest privileges (silent elevation, no UAC prompt).
    # Idempotent: if the task already points at this script path, it is left
    # as-is. Requires admin; silently skips otherwise.
    if (-not $Config.EnableAutoStart) { return }

    if (-not $IsAdmin) {
        Write-Log "AutoStart skipped - not running as administrator (task registration needs admin)"
        return
    }

    $taskName   = $Config.AutoStartTaskName
    $scriptPath = $PSCommandPath
    if (-not $scriptPath) { $scriptPath = $MyInvocation.MyCommand.Definition }

    if (-not $scriptPath -or -not (Test-Path $scriptPath)) {
        Write-Log "AutoStart skipped - could not resolve this script's own path"
        return
    }

    try {
        $existing = Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
        if ($existing) {
            # Already registered - verify it still targets this script.
            $argMatch = $existing.Actions | Where-Object { $_.Arguments -like "*$scriptPath*" }
            if ($argMatch) {
                Write-Log "AutoStart task '$taskName' already present and current"
                return
            }
            Write-Log "AutoStart task '$taskName' exists but targets a different path - re-registering"
            Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue
        }

        $psExe = (Get-Process -Id $PID).Path
        if (-not $psExe) { $psExe = "powershell.exe" }

        $action = New-ScheduledTaskAction -Execute $psExe `
            -Argument ('-ExecutionPolicy Bypass -WindowStyle Hidden -File "{0}"' -f $scriptPath) `
            -WorkingDirectory (Split-Path -Parent $scriptPath)
        $trigger   = New-ScheduledTaskTrigger -AtStartup
        $principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
        $settings  = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries `
            -StartWhenAvailable -ExecutionTimeLimit ([TimeSpan]::Zero)

        Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger `
            -Principal $principal -Settings $settings `
            -Description 'Launches AntivirusLite at system startup' -ErrorAction Stop | Out-Null

        Write-Log "AutoStart task '$taskName' registered (runs at startup as SYSTEM)"
    } catch {
        Write-Log "AutoStart registration failed: $_"
    }
}

Register-AutoStart

function Test-ShouldExclude {
    param([string]$FilePath)
    
    # Never scan (and therefore never quarantine/delete) anything inside
    # Sentinel's own install directory. This is the primary self-protection
    # gate - it runs first in Invoke-ThreatAnalysis.
    if (Test-IsSentinelOwnedPath -Path $FilePath) { return $true }

    $lower = $FilePath.ToLower()
    
    if ($lower -like '*\assembly\*') { return $true }
    if ($lower -like '*\winsxs\*') { return $true }
    if ($lower -like '*\microsoft.net\*') { return $true }
    if ($lower -like '*\windows\system32\config\*') { return $true }
    if ($lower -like '*ctfmon*' -or $lower -like '*msctf.dll' -or $lower -like '*msutb.dll') {
        return $true
    }
    
    return $false
}

function Get-FileHashSafe {
    param([string]$FilePath)
    
    if (-not (Test-Path $FilePath)) { return $null }
    
    try {
        return (Get-FileHash -Path $FilePath -Algorithm SHA256 -ErrorAction Stop).Hash.ToLower()
    } catch {
        return $null
    }
}

function Get-FileSignatureInfo {
    param([string]$FilePath)
    
    if (-not (Test-Path $FilePath)) { return $null }
    
    try {
        $signature = Get-AuthenticodeSignature -FilePath $FilePath -ErrorAction Stop
        $hash = Get-FileHashSafe -FilePath $FilePath
        
        return [PSCustomObject]@{
            Hash          = $hash
            Status        = $signature.Status
            StatusMessage = $signature.StatusMessage
            SignerName    = $signature.SignerCertificate.Subject
        }
    } catch {
        return $null
    }
}

function Test-CirclHashLookup {
    param([string]$SHA256)
    
    if (-not $SHA256) { return $false }
    
    try {
        $url = "$($Config.CirclHashLookupUrl)/$SHA256"
        $response = Invoke-RestMethod -Uri $url -TimeoutSec 8 -ErrorAction Stop
        
        if ($response) {
            Write-Log "CIRCL known-good match: $SHA256"
            return $true
        }
    } catch {}
    
    return $false
}

function Test-CymruMalwareHash {
    param([string]$SHA256)
    
    if (-not $SHA256) { return $false }
    
    try {
        $url = "$($Config.CymruApiUrl)/$SHA256"
        $response = Invoke-RestMethod -Uri $url -TimeoutSec 8 -ErrorAction Stop
        
        if ($response.detections -ge $Config.CymruDetectionThreshold) {
            Write-Log "CYMRU malware match: $SHA256 (detections: $($response.detections))"
            return $true
        }
    } catch {}
    
    return $false
}

function Test-MalwareBazaarHash {
    param([string]$SHA256)
    
    if (-not $SHA256) { return $false }
    
    try {
        $body = @{
            query = 'get_info'
            hash = $SHA256
        }
        
        if ($Config.MalwareBazaarApiKey) {
            $body.api_key = $Config.MalwareBazaarApiKey
        }
        
        $response = Invoke-RestMethod -Uri $Config.MalwareBazaarApiUrl -Method Post -Body $body -TimeoutSec 10 -ErrorAction Stop
        
        if ($response.query_status -eq 'ok' -or ($response.data -and $response.data.Count -gt 0)) {
            Write-Log "MalwareBazaar match: $SHA256"
            return $true
        }
    } catch {}
    
    return $false
}

function Test-SuspiciousUnsignedDll {
    param([string]$FilePath)
    
    $extension = [IO.Path]::GetExtension($FilePath).ToLower()
    if ($extension -notin @('.dll', '.winmd')) { return $false }
    
    try {
        $signature = Get-AuthenticodeSignature -FilePath $FilePath -ErrorAction Stop
        if ($signature.Status -eq 'Valid') { return $false }
    } catch {}
    
    $fileInfo = Get-Item $FilePath -ErrorAction SilentlyContinue
    if (-not $fileInfo) { return $false }
    
    $fileSizeKB = $fileInfo.Length / 1KB
    $pathLower = $FilePath.ToLower()
    
    foreach ($riskyPath in $RiskyPaths) {
        if ($pathLower -like "*$riskyPath*" -and $fileSizeKB -lt $Config.SuspiciousFileSizeKB) {
            return $true
        }
    }
    
    if ($pathLower -like '*\appdata\roaming\*' -and $fileSizeKB -lt 800 -and $fileInfo.Name -match '^[a-z0-9]{4,12}\.(dll|winmd)$') {
        return $true
    }
    
    return $false
}

function Test-FileLocked {
    param([string]$FilePath)
    
    try {
        $stream = [IO.File]::Open($FilePath, 'Open', 'ReadWrite', 'None')
        $stream.Close()
        return $false
    } catch {
        return $true
    }
}

function Stop-ProcessesUsingFile {
    param([string]$FilePath)
    
    $fileName = [IO.Path]::GetFileName($FilePath)
    
    try {
        Get-Process | Where-Object {
            try {
                $_.Modules.FileName -contains $FilePath
            } catch {
                $false
            }
        } | ForEach-Object {
            $procImg = $null
            try { $procImg = $_.Path } catch {}
            if ($ProtectedProcesses -notcontains $_.Name -and -not (Test-IsSentinelOwnedPath -Path $procImg)) {
                Write-Log "Stopping process $($_.Name) (PID: $($_.Id)) using file: $FilePath"
                try {
                    $_.CloseMainWindow() | Out-Null
                    Start-Sleep -Milliseconds 500
                    if (-not $_.HasExited) {
                        Stop-Process -Id $_.Id -Force -ErrorAction SilentlyContinue
                    }
                } catch {}
            }
        }
    } catch {
        try {
            taskkill /F /FI "MODULES eq $fileName" 2>&1 | Out-Null
        } catch {}
    }
}

function Set-FileOwnership {
    param([string]$FilePath)
    
    try {
        takeown /F $FilePath /A 2>&1 | Out-Null
        icacls $FilePath /reset 2>&1 | Out-Null
        icacls $FilePath /grant "Administrators:F" /inheritance:d 2>&1 | Out-Null
        Write-Log "Set ownership and permissions for: $FilePath"
        return $true
    } catch {
        Write-Log "Failed to set ownership: $_"
        return $false
    }
}

function Move-ToQuarantine {
    param(
        [string]$FilePath,
        [string]$Reason
    )
    
    if (-not (Test-Path $FilePath)) {
        Write-Log "Cannot quarantine - file not found: $FilePath"
        return
    }
    
    if (Test-FileLocked -FilePath $FilePath) {
        Stop-ProcessesUsingFile -FilePath $FilePath
        Start-Sleep -Milliseconds 500
    }
    
    $fileName = [IO.Path]::GetFileName($FilePath)
    $timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'
    $backupPath = Join-Path $Config.BackupDirectory "${fileName}_${timestamp}.bak"
    $quarantinePath = Join-Path $Config.QuarantineDirectory "${fileName}_${timestamp}"
    
    try {
        Copy-Item -Path $FilePath -Destination $backupPath -Force -ErrorAction Stop
        Move-Item -Path $FilePath -Destination $quarantinePath -Force -ErrorAction Stop
        Write-Log "QUARANTINED [$Reason]: $FilePath -> $quarantinePath"
        Send-ThreatAlert -Severity "HIGH" -Message "File quarantined: $Reason" -Details $FilePath
    } catch {
        Write-Log "Quarantine failed for $FilePath : $_"
        
        if (Set-FileOwnership -FilePath $FilePath) {
            try {
                Copy-Item -Path $FilePath -Destination $backupPath -Force -ErrorAction Stop
                Move-Item -Path $FilePath -Destination $quarantinePath -Force -ErrorAction Stop
                Write-Log "QUARANTINED (after ownership fix) [$Reason]: $FilePath"
            } catch {
                Write-Log "Quarantine still failed after ownership fix: $_"
            }
        }
    }
}

function Block-FileExecution {
    param(
        [string]$FilePath,
        [int]$ProcessId,
        [string]$Type
    )

    # Self-protection: never block/kill/quarantine Sentinel's own binaries.
    # This path fires from the WMI process-start monitor on every launch, so
    # without this guard an agent restart would be executed-blocked here.
    if (Test-IsSentinelOwnedPath -Path $FilePath) { return }
    
    $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $blockEntry = "$timestamp | BLOCKED $Type | $FilePath | PID $ProcessId"
    
    try {
        $blockEntry | Out-File -FilePath $Config.BlockedLogFile -Append -Encoding UTF8
    } catch {}
    
    Write-Log "BLOCKED $Type | $FilePath | PID $ProcessId"
    
    try {
        $process = Get-Process -Id $ProcessId -ErrorAction SilentlyContinue
        if ($process -and ($ProtectedProcesses -notcontains $process.ProcessName)) {
            Stop-Process -Id $ProcessId -Force -ErrorAction SilentlyContinue
            Write-Log "Killed process PID $ProcessId"
        }
    } catch {}
    
    if (Test-Path $FilePath) {
        Move-ToQuarantine -FilePath $FilePath -Reason "Real-time $Type block"
    }
}

$global:EmailConfig = $null
$global:WebhookUrl = $null

function Send-ThreatAlert {
    param(
        [string]$Severity,
        [string]$Message,
        [string]$Details
    )
    
    if (-not $Config.EnableAlerts) { return }
    
    $severityUpper = $Severity.ToUpper()
    
    $entryType = switch ($severityUpper) {
        "CRITICAL" { [System.Diagnostics.EventLogEntryType]::Error }
        "HIGH"     { [System.Diagnostics.EventLogEntryType]::Warning }
        "MEDIUM"   { [System.Diagnostics.EventLogEntryType]::Warning }
        default    { [System.Diagnostics.EventLogEntryType]::Information }
    }
    
    try {
        if (-not [System.Diagnostics.EventLog]::SourceExists("Antivirus")) {
            New-EventLog -LogName Application -Source "Antivirus" -ErrorAction SilentlyContinue
        }
        
        Write-EventLog -LogName Application -Source "Antivirus" `
            -EventId 1001 -Message "$Message - $Details" `
            -EntryType $entryType -ErrorAction SilentlyContinue
    } catch {}
    
    if ($global:EmailConfig) {
        try {
            Send-MailMessage @global:EmailConfig `
                -Subject "[$severityUpper] Antivirus Alert" `
                -Body "$Message`n`nDetails: $Details" `
                -ErrorAction SilentlyContinue
        } catch {
            Write-Log "Email alert failed: $_"
        }
    }
    
    if ($global:WebhookUrl) {
        try {
            $payload = @{
                severity  = $severityUpper
                message   = $Message
                details   = $Details
                timestamp = Get-Date -Format 'o'
                hostname  = $env:COMPUTERNAME
            } | ConvertTo-Json
            
            Invoke-WebRequest -Uri $global:WebhookUrl -Method Post -Body $payload -ContentType 'application/json' -ErrorAction SilentlyContinue | Out-Null
        } catch {
            Write-Log "Webhook alert failed: $_"
        }
    }
}

function Update-ThreatIntelligence {
    if (-not $Config.EnableThreatIntel) { return }
    
    Write-Log "Updating threat intelligence feeds..."
    
    $hashLists = @(
        "https://raw.githubusercontent.com/davidonzo/Threat-Intel/master/lists/latest-hashes.txt"
    )
    
    foreach ($url in $hashLists) {
        $fileName = Split-Path $url -Leaf
        $outputPath = Join-Path $Config.BaseDirectory $fileName
        
        try {
            Invoke-WebRequest -Uri $url -OutFile $outputPath -UseBasicParsing -TimeoutSec 15 -ErrorAction Stop
            Write-Log "Downloaded hash list: $fileName"
        } catch {
            Write-Log "Failed to download hash list $fileName : $_"
        }
    }
}

function Invoke-ThreatAnalysis {
    param([string]$FilePath)
    
    if (-not (Test-Path $FilePath -PathType Leaf)) { return }
    if (Test-ShouldExclude -FilePath $FilePath) { return }
    
    $extension = [IO.Path]::GetExtension($FilePath).ToLower()
    if ($extension -notin $MonitoredExtensions) { return }
    
    $fileHash = Get-FileHashSafe -FilePath $FilePath
    if (-not $fileHash) { return }
    
    if ($KnownFilesCache.ContainsKey($fileHash)) {
        if (-not $KnownFilesCache[$fileHash]) {
            if (Test-Path $FilePath) {
                Write-Log "Known bad file re-detected - HARD DELETING: $FilePath (hash: $fileHash)"
                try {
                    Remove-Item -Path $FilePath -Force -ErrorAction Stop
                    Write-Log "Successfully deleted known-bad file: $FilePath"
                    Send-ThreatAlert -Severity "HIGH" -Message "Known-bad file auto-deleted" -Details $FilePath
                } catch {
                    Write-Log "Delete failed - falling back to quarantine: $_"
                    Move-ToQuarantine -FilePath $FilePath -Reason "Known threat (delete failed)"
                }
            }
        }
        return
    }
    
    if (Test-CirclHashLookup -SHA256 $fileHash) {
        Save-ToDatabase -Hash $fileHash -IsSafe $true
        Write-Log "ALLOWED (CIRCL known-good): $FilePath"
        return
    }
    
    if (Test-CymruMalwareHash -SHA256 $fileHash) {
        Save-ToDatabase -Hash $fileHash -IsSafe $false
        Move-ToQuarantine -FilePath $FilePath -Reason "Cymru MHR malware match (>= $($Config.CymruDetectionThreshold)% detection)"
        return
    }
    
    if (Test-MalwareBazaarHash -SHA256 $fileHash) {
        Save-ToDatabase -Hash $fileHash -IsSafe $false
        Move-ToQuarantine -FilePath $FilePath -Reason "MalwareBazaar malware match"
        return
    }
    
    if (Test-SuspiciousUnsignedDll -FilePath $FilePath) {
        Save-ToDatabase -Hash $fileHash -IsSafe $false
        Move-ToQuarantine -FilePath $FilePath -Reason "Suspicious unsigned DLL/WINMD in risky location"
        return
    }
    
    $signatureInfo = Get-FileSignatureInfo -FilePath $FilePath
    if ($signatureInfo) {
        $isSafe = ($signatureInfo.Status -eq 'Valid')
        Save-ToDatabase -Hash $fileHash -IsSafe $isSafe
        
        if ($isSafe) {
            Write-Log "ALLOWED (digitally signed): $FilePath"
        } else {
            Write-Log "ALLOWED (unsigned but no threat indicators): $FilePath"
        }
    }
}

function Start-MemoryScanner {
    if (-not $Config.EnableMemoryScanning) {
        Write-Log "Memory scanning is disabled in configuration"
        return
    }
    
    Write-Log "Starting optimized memory scanner (interval: $($Config.MemoryScanIntervalSec)s, max size: $($Config.MemoryScanMaxSizeMB)MB)"
    
    $mainPid = $PID
    Start-Job -ScriptBlock {
        $config = $using:Config
        $protected = $using:ProtectedProcesses
        $evilStrings = $using:EvilStrings
        $mainPid = $using:mainPid          # PID of the main AntivirusLite script
        $selfPid = $PID                     # PID of this background job host

        # Register this job's PID in the shared AV PID file so the scan loop
        # below never flags the antivirus's own job host.
        try {
            $m = New-Object System.Threading.Mutex($false, 'Global\AV_PidFile')
            [void]$m.WaitOne(2000)
            try { Add-Content -Path $config.OwnPidFile -Value $selfPid -ErrorAction SilentlyContinue }
            finally { $m.ReleaseMutex(); $m.Dispose() }
        } catch {}

        $logFile = Join-Path $config.BaseDirectory "memory_hits.log"
        
        while ($true) {
            Start-Sleep -Seconds $config.MemoryScanIntervalSec
            
            $maxBytes = $config.MemoryScanMaxSizeMB * 1MB

            # Load the set of AV-owned PIDs (main script + all AV jobs). These
            # are never scanned/killed. Unrelated PowerShell is still scanned.
            $ownPids = @{}
            try {
                foreach ($line in (Get-Content -Path $config.OwnPidFile -ErrorAction SilentlyContinue)) {
                    $n = 0
                    if ([int]::TryParse(($line.Trim()), [ref]$n)) { $ownPids[$n] = $true }
                }
            } catch {}
            # Always include our own two known PIDs as a fallback.
            $ownPids[$mainPid] = $true
            $ownPids[$selfPid] = $true

            Get-Process | Where-Object {
                $_.WorkingSet64 -lt $maxBytes -and
                $protected -notcontains $_.Name -and
                -not $ownPids.ContainsKey($_.Id)           # not an AV-owned process
            } | ForEach-Object {
                $process = $_
                $suspicious = $false
                $reasons = @()
                
                try {
                    if (-not $process.Path -or $process.Path -eq '') {
                        $suspicious = $true
                        $reasons += "NoPath"
                    }
                } catch {}
                
                try {
                    $emptyModules = $process.Modules | Where-Object {
                        $_.FileName -eq '' -or $_.ModuleName -eq ''
                    }
                    
                    if ($emptyModules) {
                        $suspicious = $true
                        $reasons += "EmptyModule"
                    }
                } catch {}
                
                try {
                    foreach ($module in $process.Modules) {
                        foreach ($evilString in $evilStrings) {
                            if ($module.ModuleName -match $evilString -or ($module.FileName -and $module.FileName -match $evilString)) {
                                $suspicious = $true
                                $reasons += "EvilString($evilString)"
                                break
                            }
                        }
                        if ($suspicious) { break }
                    }
                } catch {}
                
                if ($suspicious) {
                    $reasonString = $reasons -join '; '
                    $logEntry = "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') | MEMORY HIT [$reasonString] -> $($process.Name) (PID: $($process.Id)) Path: '$($process.Path)' WS: $([math]::Round($process.WorkingSet64/1MB, 2))MB"
                    
                    try {
                        $logEntry | Out-File -FilePath $logFile -Append -Encoding UTF8
                    } catch {}
                    
                    try {
                        Stop-Process -Id $process.Id -Force -ErrorAction SilentlyContinue
                    } catch {}
                }
            }

            # Deterministic cleanup after each full pass. Enumerating .Modules
            # across all processes retains native handles/metadata; collect,
            # then trim this job's working set back to the OS.
            try {
                [System.Runtime.GCSettings]::LargeObjectHeapCompactionMode = `
                    [System.Runtime.GCLargeObjectHeapCompactionMode]::CompactOnce
            } catch {}
            [System.GC]::Collect()
            [System.GC]::WaitForPendingFinalizers()
            try {
                if (-not ([System.Management.Automation.PSTypeName]'AVJob.Mem').Type) {
                    Add-Type -Namespace AVJob -Name Mem -MemberDefinition @'
[System.Runtime.InteropServices.DllImport("psapi.dll")]
public static extern bool EmptyWorkingSet(System.IntPtr hProcess);
'@ -ErrorAction SilentlyContinue
                }
                [void][AVJob.Mem]::EmptyWorkingSet([System.Diagnostics.Process]::GetCurrentProcess().Handle)
            } catch {}
        }
    } | Out-Null
}

function Find-FilelessIndicators {
    $detections = @()
    
    try {
        $suspiciousPowerShell = Get-Process -Name powershell, pwsh -ErrorAction SilentlyContinue | Where-Object {
            $_.MainWindowTitle -match 'encodedcommand|enc|iex|invoke-expression'
        }
        
        if ($suspiciousPowerShell) {
            $detections += [PSCustomObject]@{
                Type    = "FilelessPowerShell"
                Details = $suspiciousPowerShell | Select-Object Name, Id, MainWindowTitle
            }
            Write-Log "Fileless indicator detected: PowerShell without file"
        }
    } catch {}
    
    try {
        $wmiEvents = Get-WmiObject -Namespace root\Subscription -Class __EventFilter -ErrorAction SilentlyContinue |
            Where-Object { $_.Query -match 'powershell|vbscript|javascript' }
        
        if ($wmiEvents) {
            $detections += [PSCustomObject]@{
                Type    = "WMIEventSubscription"
                Details = $wmiEvents | Select-Object Name, Query
            }
            Write-Log "Fileless indicator detected: WMI event subscriptions"
        }
    } catch {}
    
    try {
        $registryKeys = @(
            'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
            'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run'
        )
        
        foreach ($key in $registryKeys) {
            if (Test-Path $key) {
                $props = Get-ItemProperty -Path $key -ErrorAction SilentlyContinue
                
                if ($props) {
                    $props.PSObject.Properties | Where-Object {
                        $_.MemberType -eq 'NoteProperty' -and $_.Value -match 'powershell.*-enc|mshta|regsvr32.*scrobj'
                    } | ForEach-Object {
                        $detections += [PSCustomObject]@{
                            Type    = "RegistryScript"
                            Details = "$key -> $($_.Name): $($_.Value)"
                        }
                        Write-Log "Fileless indicator detected: Registry script in $key"
                    }
                }
            }
        }
    } catch {}
    
    return $detections
}

function Find-PersistenceMechanisms {
    $suspiciousItems = @()
    
    $locations = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
        'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run',
        'C:\Windows\System32\Tasks',
        'C:\Windows\Tasks',
        "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup",
        'C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup'
    )
    
    foreach ($location in $locations) {
        try {
            if ($location -match '^HK') {
                if (Test-Path $location) {
                    $props = Get-ItemProperty -Path $location -ErrorAction SilentlyContinue
                    
                    if ($props) {
                        $props.PSObject.Properties | Where-Object {
                            $_.MemberType -eq 'NoteProperty' -and $_.Value -match '\.(exe|dll|ps1|vbs|js|bat|cmd)$'
                        } | ForEach-Object {
                            $suspiciousItems += [PSCustomObject]@{
                                Location = $location
                                Name     = $_.Name
                                Value    = $_.Value
                                Type     = 'Registry'
                            }
                        }
                    }
                }
            } else {
                if (Test-Path $location) {
                    Get-ChildItem -Path $location -Recurse -File -ErrorAction SilentlyContinue |
                        Where-Object { $_.Extension -match '\.(exe|dll|lnk|ps1|vbs|js|bat|cmd)$' } |
                        ForEach-Object {
                            $suspiciousItems += [PSCustomObject]@{
                                Location = $location
                                Name     = $_.Name
                                Value    = $_.FullName
                                Type     = 'FileSystem'
                            }
                        }
                }
            }
        } catch {
            Write-Log "Error checking persistence location $location : $_"
        }
    }
    
    return $suspiciousItems
}

function Test-ProcessHollowing {
    param($Process)
    
    try {
        $processPath = $Process.Path
        if (-not $processPath) { return $false }
        
        $modules = $Process.Modules
        if ($modules -and $modules.Count -gt 0) {
            return ($modules[0].FileName -ne $processPath)
        }
    } catch {}
    
    return $false
}

function Test-CredentialAccessBehavior {
    param($Process)
    
    try {
        $commandLine = (Get-CimInstance Win32_Process -Filter "ProcessId=$($Process.Id)" -ErrorAction SilentlyContinue).CommandLine
        
        if ($commandLine -match 'mimikatz|procdump|sekurlsa|lsadump|credential|password') {
            return $true
        }
    } catch {}
    
    if ($Process.ProcessName -match 'vaultcmd|cred') {
        return $true
    }
    
    return $false
}

function Test-LateralMovementBehavior {
    param($Process)
    
    try {
        $connections = Get-NetTCPConnection -OwningProcess $Process.Id -ErrorAction SilentlyContinue
        
        $externalConnections = $connections | Where-Object {
            $_.RemoteAddress -notmatch '^(127\.|192\.168\.|10\.|172\.(1[6-9]|2[0-9]|3[0-1])\.)|^(::1|fe80:)' -and
            $_.RemoteAddress -ne '0.0.0.0' -and $_.RemoteAddress -ne '::'
        }
        
        return (($externalConnections | Measure-Object).Count -gt 10)
    } catch {}
    
    return $false
}

function Test-C2Communication {
    param($Connection)
    
    $suspiciousPorts = @(4444, 5555, 6666, 7777, 8080, 8443, 9001, 1337, 31337)
    
    if ($Connection.RemotePort -in $suspiciousPorts) {
        try {
            $hostname = [System.Net.Dns]::GetHostEntry($Connection.RemoteAddress).HostName
            
            $c2Domains = @('pastebin', 'ddns.net', 'no-ip.org', 'duckdns.org', 'bit.ly', 'tinyurl')
            
            foreach ($domain in $c2Domains) {
                if ($hostname -like "*$domain*") {
                    return $true
                }
            }
        } catch {}
    }
    
    return $false
}

# ============================================================================
# C2 / Reverse-Shell killer
# ============================================================================

function Get-OwnPidSet {
    # Return a hashtable of AV-owned PIDs (main script + all jobs) so the C2
    # engine never blocks/kills the antivirus itself.
    $own = @{ $PID = $true }
    try {
        foreach ($line in (Get-Content -Path $Config.OwnPidFile -ErrorAction SilentlyContinue)) {
            $n = 0
            if ([int]::TryParse(($line.Trim()), [ref]$n)) { $own[$n] = $true }
        }
    } catch {}
    return $own
}

function Test-PrivateOrLocalAddress {
    param([string]$Address)
    if ([string]::IsNullOrWhiteSpace($Address)) { return $true }
    if ($Address -eq '0.0.0.0' -or $Address -eq '::' -or $Address -eq '::1') { return $true }
    $privatePrefixes = @('127.', '10.', '192.168.', '169.254.',
        '172.16.', '172.17.', '172.18.', '172.19.', '172.20.', '172.21.',
        '172.22.', '172.23.', '172.24.', '172.25.', '172.26.', '172.27.',
        '172.28.', '172.29.', '172.30.', '172.31.', 'fe80:', 'fc', 'fd')
    foreach ($p in $privatePrefixes) {
        if ($Address.ToLower().StartsWith($p)) { return $true }
    }
    return $false
}

function Get-ProcessCommandLine {
    param([int]$ProcessId)
    try {
        return (Get-CimInstance Win32_Process -Filter "ProcessId=$ProcessId" -ErrorAction SilentlyContinue).CommandLine
    } catch {
        return $null
    }
}

function Test-ReverseShellCommandLine {
    # Returns $true when a command line matches a known reverse-shell signature.
    param([string]$CommandLine)
    if ([string]::IsNullOrWhiteSpace($CommandLine)) { return $false }
    foreach ($pattern in $ReverseShellPatterns) {
        if ($CommandLine -imatch $pattern) { return $true }
    }
    return $false
}

function Block-RemoteC2Ip {
    # Drop an outbound-blocking firewall rule for a confirmed C2 IP (idempotent).
    param([string]$RemoteAddress, [string]$Reason = "C2")
    if (-not $C2Config.EnableFirewallAutoBlock) { return }
    if (Test-PrivateOrLocalAddress -Address $RemoteAddress) { return }
    if ($script:BlockedC2Ips.Contains($RemoteAddress)) { return }
    if (-not $IsAdmin) {
        Write-Log "C2 block skipped (needs admin): $RemoteAddress"
        return
    }
    try {
        $ruleName = "AVLite_Block_C2_$($RemoteAddress -replace '[:.]','_')"
        $existing = Get-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue
        if (-not $existing) {
            New-NetFirewallRule -DisplayName $ruleName -Direction Outbound -Action Block `
                -RemoteAddress $RemoteAddress -Protocol Any -Profile Any -ErrorAction SilentlyContinue | Out-Null
            Write-Log "FIREWALL: Blocked C2 IP $RemoteAddress [$Reason]"
        }
        [void]$script:BlockedC2Ips.Add($RemoteAddress)
    } catch {
        Write-Log "Firewall block failed for $RemoteAddress : $_"
    }
}

function Stop-C2Process {
    # Kill a process backing a C2/reverse-shell connection, honoring the
    # protected-process list and the AV's own PID set.
    param([int]$ProcessId, [string]$ProcessName, [string]$Reason, [hashtable]$OwnPids)
    if ($OwnPids -and $OwnPids.ContainsKey($ProcessId)) {
        Write-Log "C2 kill skipped - own AV process (PID: $ProcessId)"
        return
    }
    if ($ProtectedProcesses -contains $ProcessName) {
        Write-Log "C2 kill skipped - protected process $ProcessName (PID: $ProcessId) [$Reason]"
        return
    }
    # Path-based self-protection: never kill a process whose image lives inside
    # Sentinel's install dir, even if its name was renamed off the protected list.
    try {
        $imgPath = (Get-Process -Id $ProcessId -ErrorAction SilentlyContinue).Path
        if (Test-IsSentinelOwnedPath -Path $imgPath) {
            Write-Log "C2 kill skipped - Sentinel-owned image (PID: $ProcessId, $imgPath) [$Reason]"
            return
        }
    } catch {}
    try {
        Stop-Process -Id $ProcessId -Force -ErrorAction SilentlyContinue
        Write-Log "KILLED C2/reverse-shell process $ProcessName (PID: $ProcessId) [$Reason]"
        Send-ThreatAlert -Severity "CRITICAL" -Message "C2/reverse-shell process terminated" -Details "$ProcessName PID:$ProcessId - $Reason"
    } catch {
        Write-Log "Failed to kill C2 process $ProcessName (PID: $ProcessId): $_"
    }
}

function Update-BeaconHistory {
    # Record a timestamp for a (PID,RemoteIP) pair and return a verdict object
    # when the callback cadence looks like a beacon.
    param([int]$ProcessId, [string]$RemoteAddress)
    $key = "$ProcessId|$RemoteAddress"
    if (-not $script:BeaconHistory.ContainsKey($key)) {
        $script:BeaconHistory[$key] = New-Object System.Collections.Generic.List[datetime]
    }
    $list = $script:BeaconHistory[$key]
    $list.Add((Get-Date))

    # Cap samples per key to bound memory.
    while ($list.Count -gt 50) { $list.RemoveAt(0) }

    if ($list.Count -lt $C2Config.BeaconMinSamples) { return $null }

    $intervals = @()
    for ($i = 1; $i -lt $list.Count; $i++) {
        $intervals += ($list[$i] - $list[$i - 1]).TotalSeconds
    }
    if ($intervals.Count -lt 2) { return $null }

    $avg = ($intervals | Measure-Object -Average).Average
    if ($avg -lt $C2Config.BeaconMinIntervalSec -or $avg -gt $C2Config.BeaconMaxIntervalSec) { return $null }

    $variance = ($intervals | ForEach-Object { [Math]::Pow($_ - $avg, 2) } | Measure-Object -Average).Average
    $stdDev = [Math]::Sqrt($variance)

    if ($stdDev -lt ($avg * $C2Config.BeaconMaxJitterRatio)) {
        return [PSCustomObject]@{
            AverageInterval = [Math]::Round($avg, 1)
            Jitter          = [Math]::Round($stdDev, 1)
            Samples         = $list.Count
        }
    }
    return $null
}

function Get-C2ConnectionScore {
    # Score a single established outbound connection. Higher = more likely C2.
    param($Connection, $Process)

    $score = 0
    $reasons = @()
    $remotePort = $Connection.RemotePort
    $remoteAddr = $Connection.RemoteAddress.ToString()

    # Suspicious / backdoor ports
    if ($C2SuspiciousPorts.ContainsKey([int]$remotePort)) {
        $score += $C2SuspiciousPorts[[int]$remotePort]
        $reasons += "Backdoor/C2 port $remotePort"
    }

    # Known-bad IP prefixes
    foreach ($prefix in $C2MaliciousRangePrefixes) {
        if ($remoteAddr.StartsWith($prefix)) {
            $score += 25
            $reasons += "Known-bad IP range $prefix"
            break
        }
    }

    if ($Process) {
        $pname = $Process.ProcessName.ToLower()

        # Interpreter / LOLBin holding an outbound socket
        if ($C2SuspiciousProcesses -contains $pname) {
            $score += 25
            $reasons += "Interpreter/LOLBin with outbound socket ($pname)"
        }

        # Process running from a non-standard location
        if ($Process.Path -and $Process.Path -notmatch '(?i)^C:\\(Windows|Program Files|Program Files \(x86\))') {
            $score += 15
            $reasons += "Non-standard process path"
        }

        # Core system process making an outbound connection => likely injection
        if ($pname -match '^(svchost|lsass|winlogon|services|csrss|smss|wininit)$') {
            # svchost legitimately connects, but to standard ports only
            if ($remotePort -notin @(80, 443, 123, 53, 88, 135, 389, 445, 636)) {
                $score += 30
                $reasons += "System process ($pname) outbound to unusual port $remotePort"
            }
        }

        # Reverse-shell command line on the owning process
        $cmd = Get-ProcessCommandLine -ProcessId $Process.Id
        if (Test-ReverseShellCommandLine -CommandLine $cmd) {
            $score += 45
            $reasons += "Reverse-shell command line"
        }
    }

    # Suspicious resolved hostname TLD
    if ($remoteAddr -match '^\d{1,3}(\.\d{1,3}){3}$') {
        try {
            $hostName = [System.Net.Dns]::GetHostEntry($remoteAddr).HostName
            if ($hostName) {
                foreach ($tld in $C2SuspiciousTLDs) {
                    if ($hostName.ToLower().EndsWith($tld) -or $hostName.ToLower().Contains($tld)) {
                        $score += 20
                        $reasons += "Suspicious hostname TLD ($hostName)"
                        break
                    }
                }
            }
        } catch {}
    }

    return [PSCustomObject]@{
        Score   = $score
        Reasons = $reasons
    }
}

function Invoke-C2Detection {
    # Main scored C2 engine: walk established outbound connections, score each,
    # fold in beacon cadence + IP-rotation, then firewall-block and/or kill.
    if (-not $C2Config.EnableC2Detection) { return }

    $ownPids = Get-OwnPidSet
    $seenKeys = @{}

    try {
        $connections = Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue |
            Where-Object { -not (Test-PrivateOrLocalAddress -Address $_.RemoteAddress) }
    } catch {
        return
    }

    # Per-process unique remote-IP count for rotation detection.
    $procIpMap = @{}

    foreach ($conn in $connections) {
        $procId = [int]$conn.OwningProcess
        if ($procId -le 0 -or $ownPids.ContainsKey($procId)) { continue }

        $proc = Get-Process -Id $procId -ErrorAction SilentlyContinue
        $pname = if ($proc) { $proc.ProcessName } else { "Unknown" }

        if (-not $procIpMap.ContainsKey($procId)) {
            $procIpMap[$procId] = New-Object System.Collections.Generic.HashSet[string]
        }
        [void]$procIpMap[$procId].Add($conn.RemoteAddress.ToString())

        $result = Get-C2ConnectionScore -Connection $conn -Process $proc
        $score = $result.Score
        $reasons = $result.Reasons

        # Beacon cadence (only meaningful once per key per cycle)
        $bkey = "$procId|$($conn.RemoteAddress)"
        if ($C2Config.EnableBeaconDetection -and -not $seenKeys.ContainsKey($bkey)) {
            $seenKeys[$bkey] = $true
            $beacon = Update-BeaconHistory -ProcessId $procId -RemoteAddress $conn.RemoteAddress.ToString()
            if ($beacon) {
                $score += 30
                $reasons += "Beacon cadence ~$($beacon.AverageInterval)s (jitter $($beacon.Jitter)s, n=$($beacon.Samples))"
            }
        }

        if ($score -le 0) { continue }

        $target = "$($conn.RemoteAddress):$($conn.RemotePort)"
        $reasonStr = $reasons -join '; '

        if ($score -ge $C2Config.FirewallBlockThreshold) {
            Write-Log "C2 SUSPECT (score $score): $pname (PID $procId) -> $target | $reasonStr"
            Send-ThreatAlert -Severity "HIGH" -Message "Suspicious C2 connection (score $score)" -Details "$pname -> $target | $reasonStr"
            Block-RemoteC2Ip -RemoteAddress $conn.RemoteAddress.ToString() -Reason "score $score"
        }

        if ($score -ge $C2Config.KillScoreThreshold) {
            Stop-C2Process -ProcessId $procId -ProcessName $pname -Reason "C2 score $score -> $target" -OwnPids $ownPids
        }
    }

    # IP-rotation: one process fanning out to many unique remote IPs = C2 rotation.
    foreach ($entry in $procIpMap.GetEnumerator()) {
        if ($entry.Value.Count -ge $C2Config.IpRotationThreshold) {
            $procId = $entry.Key
            if ($ownPids.ContainsKey($procId)) { continue }
            $proc = Get-Process -Id $procId -ErrorAction SilentlyContinue
            $pname = if ($proc) { $proc.ProcessName } else { "Unknown" }
            Write-Log "C2 IP-ROTATION: $pname (PID $procId) -> $($entry.Value.Count) unique remote IPs"
            Send-ThreatAlert -Severity "HIGH" -Message "C2 IP rotation detected" -Details "$pname PID:$procId -> $($entry.Value.Count) IPs"
            Stop-C2Process -ProcessId $procId -ProcessName $pname -Reason "IP rotation ($($entry.Value.Count) IPs)" -OwnPids $ownPids
        }
    }

    # Prune beacon-history keys whose process no longer exists.
    $deadKeys = @()
    foreach ($k in $script:BeaconHistory.Keys) {
        $kpid = 0
        if ([int]::TryParse(($k -split '\|')[0], [ref]$kpid)) {
            if (-not (Get-Process -Id $kpid -ErrorAction SilentlyContinue)) { $deadKeys += $k }
        }
    }
    foreach ($k in $deadKeys) { [void]$script:BeaconHistory.Remove($k) }
}

function Invoke-ReverseShellKiller {
    # Hunt reverse shells independent of an already-open socket: any interpreter
    # process whose command line matches a reverse-shell signature is killed,
    # and if it currently holds an outbound socket that remote IP is blocked.
    if (-not $C2Config.EnableReverseShellKill) { return }

    $ownPids = Get-OwnPidSet

    try {
        $procInfos = Get-CimInstance Win32_Process -ErrorAction SilentlyContinue |
            Where-Object { $_.CommandLine }
    } catch {
        return
    }

    foreach ($pi in $procInfos) {
        $procId = [int]$pi.ProcessId
        if ($procId -le 0 -or $ownPids.ContainsKey($procId)) { continue }

        if (-not (Test-ReverseShellCommandLine -CommandLine $pi.CommandLine)) { continue }

        $pname = ($pi.Name -replace '\.exe$', '')
        if ($ProtectedProcesses -contains $pname) {
            Write-Log "Reverse-shell signature on protected process $pname (PID $procId) - logging only"
            Write-Log "  CMD: $($pi.CommandLine)"
            continue
        }

        Write-Log "REVERSE SHELL DETECTED: $pname (PID $procId)"
        Write-Log "  CMD: $($pi.CommandLine)"
        Send-ThreatAlert -Severity "CRITICAL" -Message "Reverse shell command line detected" -Details "$pname PID:$procId"

        # Block any remote endpoints this process is currently talking to.
        try {
            Get-NetTCPConnection -OwningProcess $procId -State Established -ErrorAction SilentlyContinue |
                Where-Object { -not (Test-PrivateOrLocalAddress -Address $_.RemoteAddress) } |
                ForEach-Object { Block-RemoteC2Ip -RemoteAddress $_.RemoteAddress.ToString() -Reason "reverse shell" }
        } catch {}

        Stop-C2Process -ProcessId $procId -ProcessName $pname -Reason "reverse-shell command line" -OwnPids $ownPids

        # Quarantine the on-disk payload if the image path is resolvable.
        if ($pi.ExecutablePath -and (Test-Path $pi.ExecutablePath)) {
            $imgLower = $pi.ExecutablePath.ToLower()
            # Don't quarantine the trusted system interpreters themselves.
            if ($imgLower -notmatch '\\windows\\system32\\' -and $imgLower -notmatch '\\windows\\syswow64\\') {
                Move-ToQuarantine -FilePath $pi.ExecutablePath -Reason "Reverse-shell host image"
            }
        }
    }
}

function Invoke-ProcessAndNetworkScan {
    Get-Process | ForEach-Object {
        $process = $_
        
        try {
            $exePath = $process.MainModule.FileName
            if ($exePath -and (Test-Path $exePath)) {
                Invoke-ThreatAnalysis -FilePath $exePath
            }
        } catch {}
        
        $procImgPath = $null
        try { $procImgPath = $process.Path } catch {}
        if ($BehaviorConfig.EnableBehaviorKill -and
            ($ProtectedProcesses -notcontains $process.Name) -and
            -not (Test-IsSentinelOwnedPath -Path $procImgPath)) {
            try {
                if (Test-ProcessHollowing -Process $process) {
                    Write-Log "BEHAVIOR: Process hollowing detected - $($process.Name) (PID: $($process.Id))"
                    Send-ThreatAlert -Severity "HIGH" -Message "Process hollowing detected" -Details "$($process.Name) PID: $($process.Id)"
                    Stop-Process -Id $process.Id -Force -ErrorAction SilentlyContinue
                }
                elseif (Test-CredentialAccessBehavior -Process $process) {
                    Write-Log "BEHAVIOR: Credential access detected - $($process.Name) (PID: $($process.Id))"
                    Send-ThreatAlert -Severity "HIGH" -Message "Credential access behavior" -Details "$($process.Name) PID: $($process.Id)"
                    Stop-Process -Id $process.Id -Force -ErrorAction SilentlyContinue
                }
                elseif (Test-LateralMovementBehavior -Process $process) {
                    Write-Log "BEHAVIOR: Lateral movement detected - $($process.Name) (PID: $($process.Id))"
                    Send-ThreatAlert -Severity "MEDIUM" -Message "Lateral movement behavior" -Details "$($process.Name) PID: $($process.Id)"
                }
            } catch {}
        }
    }
    
    # Upgraded C2 / reverse-shell killer engines (scored, beacon-aware).
    try { Invoke-ReverseShellKiller } catch { Write-Log "ReverseShellKiller error: $_" }
    try { Invoke-C2Detection }        catch { Write-Log "C2Detection error: $_" }

    if ($BehaviorConfig.EnableAutoBlockC2) {
        Get-NetTCPConnection -ErrorAction SilentlyContinue | Where-Object {
            $_.State -in @('Established', 'Listen')
        } | ForEach-Object {
            $connection = $_
            
            try {
                $process = Get-Process -Id $connection.OwningProcess -ErrorAction SilentlyContinue
                
                if ($process -and (Test-C2Communication -Connection $connection)) {
                    Write-Log "NETWORK: Suspicious C2 connection - $($process.Name) (PID: $($process.Id)) -> $($connection.RemoteAddress):$($connection.RemotePort)"
                    Send-ThreatAlert -Severity "HIGH" -Message "C2 communication detected" -Details "$($process.Name) -> $($connection.RemoteAddress):$($connection.RemotePort)"
                    
                    if ($ProtectedProcesses -notcontains $process.Name) {
                        Stop-Process -Id $process.Id -Force -ErrorAction SilentlyContinue
                    }
                    
                    try {
                        $ruleName = "Block_C2_$($connection.RemoteAddress)"
                        New-NetFirewallRule -DisplayName $ruleName `
                            -Direction Outbound `
                            -Protocol TCP `
                            -RemoteAddress $connection.RemoteAddress `
                            -Action Block `
                            -Enabled True `
                            -ErrorAction SilentlyContinue | Out-Null
                        
                        Write-Log "Created firewall rule to block: $($connection.RemoteAddress)"
                    } catch {}
                }
            } catch {}
        }
    }
}

Write-Log "Performing initial scan of high-risk folders"

$highRiskFolders = @(
    "$env:USERPROFILE\Downloads",
    "$env:USERPROFILE\Desktop",
    "$env:TEMP",
    "$env:APPDATA",
    "$env:LOCALAPPDATA\Temp"
)

foreach ($folder in $highRiskFolders) {
    if (Test-Path $folder) {
        Write-Log "Scanning: $folder"
        Get-ChildItem -Path $folder -Recurse -File -ErrorAction SilentlyContinue | ForEach-Object {
            Invoke-ThreatAnalysis -FilePath $_.FullName
        }
    }
}

if ($Config.EnableRealtimeMonitor) {
    Write-Log "Setting up real-time file monitoring"
    
    foreach ($folder in $highRiskFolders) {
        if (-not (Test-Path $folder)) { continue }
        
        try {
            $watcher = New-Object IO.FileSystemWatcher $folder, '*.*' -Property @{
                IncludeSubdirectories = $true
                NotifyFilter          = [IO.NotifyFilters]'FileName, LastWrite'
            }
            
            Register-ObjectEvent $watcher Created -Action {
                $filePath = $Event.SourceEventArgs.FullPath
                $extension = [IO.Path]::GetExtension($filePath).ToLower()
                
                if ($MonitoredExtensions -contains $extension) {
                    Start-Sleep -Milliseconds 800
                    Invoke-ThreatAnalysis -FilePath $filePath
                }
            } | Out-Null
            
            $watcher.EnableRaisingEvents = $true
            Write-Log "File watcher active for: $folder"
        } catch {
            Write-Log "Failed to create file watcher for $folder : $_"
        }
    }
}

Write-Log "Registering WMI real-time execution monitors"

try {
    Register-WmiEvent -Query "SELECT * FROM Win32_ProcessStartTrace" -SourceIdentifier "AV_ProcStart" -Action {
        try {
            $newEvent  = $Event.SourceEventArgs.NewEvent
            $filePath  = $newEvent.ProcessName
            $processId = $newEvent.ProcessId

            $cim = Get-CimInstance Win32_Process -Filter "ProcessId=$processId" -ErrorAction SilentlyContinue
            $ownerSid = "Unknown"
            if ($cim) {
                try { $ownerSid = ($cim | Invoke-CimMethod -MethodName GetOwnerSid).Sid } catch {}
                $cim.Dispose()
            }

            if ($AllowedSIDs -contains $ownerSid) {
                try {
                    $signature = Get-AuthenticodeSignature -FilePath $filePath -ErrorAction Stop
                    if ($signature.Status -eq 'Valid') { return }
                } catch {}
            }

            Block-FileExecution -FilePath $filePath -ProcessId $processId -Type "EXE"
        }
        finally {
            # Drain this event from the engine's event log so PSEventArgs
            # objects do not accumulate in memory.
            Remove-Event -EventIdentifier $Event.EventIdentifier -ErrorAction SilentlyContinue
        }
    } | Out-Null
    
    Write-Log "WMI process start monitor registered"
} catch {
    Write-Log "Failed to register WMI process start monitor: $_"
}

# NOTE: Win32_ModuleLoadTrace monitoring was removed intentionally.
# It fires on EVERY DLL load system-wide (thousands/sec). The PowerShell
# -Action event queue cannot drain that fast, so PSEventArgs objects pile up
# unbounded and consume gigabytes of RAM within minutes.
# DLL threats on disk are already covered by the FileSystemWatcher and by
# Invoke-ThreatAnalysis (which hashes and signature-checks .dll/.winmd files).
Write-Log "Module-load monitoring disabled by design (high-frequency event leak prevention)"

if ($Config.EnableMemoryScanning) {
    Start-MemoryScanner
}

if ($IsAdmin -and $Config.EnableThreatIntel) {
    $lastUpdateFile = Join-Path $Config.BaseDirectory "last_update.txt"
    $currentTime = Get-Date
    $shouldUpdate = $false
    
    if (-not (Test-Path $lastUpdateFile)) {
        $shouldUpdate = $true
    } else {
        try {
            $lastUpdate = (Get-Item $lastUpdateFile).LastWriteTime
            if ($lastUpdate -lt $currentTime.AddDays(-$BehaviorConfig.ThreatIntelUpdateDays)) {
                $shouldUpdate = $true
            }
        } catch {
            $shouldUpdate = $true
        }
    }
    
    if ($shouldUpdate) {
        Update-ThreatIntelligence
        $currentTime | Out-File -FilePath $lastUpdateFile
    }
    
    Start-Job -ScriptBlock {
        $config = $using:Config
        $behaviorConfig = $using:BehaviorConfig

        # Register this deep-scan job's PID so the memory scanner never flags it.
        try {
            $m = New-Object System.Threading.Mutex($false, 'Global\AV_PidFile')
            [void]$m.WaitOne(2000)
            try { Add-Content -Path $config.OwnPidFile -Value $PID -ErrorAction SilentlyContinue }
            finally { $m.ReleaseMutex(); $m.Dispose() }
        } catch {}
        
        while ($true) {
            Start-Sleep -Seconds (60 * 60 * $behaviorConfig.DeepScanIntervalHours)
            
            try {
                $persistence = Find-PersistenceMechanisms
                if ($persistence -and $persistence.Count -gt 0) {
                    $outputFile = Join-Path $config.BaseDirectory "persistence_scan.csv"
                    $persistence | Export-Csv -Path $outputFile -NoTypeInformation
                    Write-Log "Persistence scan found $($persistence.Count) items -> $outputFile"
                    Send-ThreatAlert -Severity "MEDIUM" -Message "Persistence mechanisms detected" -Details "Found $($persistence.Count) items"
                }
            } catch {
                Write-Log "Persistence scan error: $_"
            }
            
            try {
                $fileless = Find-FilelessIndicators
                if ($fileless -and $fileless.Count -gt 0) {
                    $outputFile = Join-Path $config.BaseDirectory "fileless_detections.xml"
                    $fileless | Export-Clixml -Path $outputFile
                    Write-Log "Fileless indicators found: $($fileless.Count) -> $outputFile"
                    Send-ThreatAlert -Severity "HIGH" -Message "Fileless malware indicators" -Details "Found $($fileless.Count) indicators"
                }
            } catch {
                Write-Log "Fileless scan error: $_"
            }
        }
    } | Out-Null
    
    Write-Log "Deep scanner job started"
}

Write-Log "All monitoring systems active"
Write-Host "`nClean Antivirus is now running" -ForegroundColor Green
Write-Host "Press [Ctrl+C] to stop" -ForegroundColor Yellow

try {
    while ($true) {
        try {
            Invoke-ProcessAndNetworkScan
            Write-Log "Periodic scan cycle completed"
        } catch {
            Write-Log "Scan cycle error: $_"
        }

        # Deterministic cleanup each cycle. The scan creates large transient
        # object graphs (process lists, modules, CIM/TCP objects); collect,
        # compact the LOH, and trim the working set back to the OS.
        Clear-ProcessMemory
        Remove-DeadOwnPids

        Start-Sleep -Seconds 30
    }
} catch {
    Write-Log "Main loop terminated: $($_.Exception.Message)"
    Write-Host "`nAntivirus stopped. Check log file: $($Config.LogFile)" -ForegroundColor Red
}