// Phase A coverage expansion (v2.1.0) - LPE scaffolding, initial-access paths,
// persistence surfaces (COM/IFEO/accessibility/Winlogon).
// v2.5.3: named LPE tools (potato / PrintSpoofer / winPEAS) are kill-grade.
// Elevated-from-staging and persistence surfaces stay observe-until-chain.

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Security.Principal;
using System.ServiceProcess;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Win32;

namespace Sentinel.Core
{
    /// <summary>
    /// Detects post-foothold LPE scaffolding: potato-class tools, exploit hosts from
    /// staging paths, unexpected elevation of user shells to high integrity.
    /// Named LPE tools are kill-grade (v2.5.3). Staging elevation stays observe fuel.
    /// </summary>
    public sealed class LpeScaffoldMonitor : BackgroundService
    {
        private readonly DetectionEngine _detectionEngine;
        private readonly ILogger<LpeScaffoldMonitor> _logger;
        private readonly HashSet<string> _alerted = new(StringComparer.OrdinalIgnoreCase);
        private static readonly TimeSpan ScanInterval = TimeSpan.FromSeconds(20);
        private static readonly TimeSpan AlertCooldown = TimeSpan.FromMinutes(15);

        private static readonly string[] LpeToolNameFragments =
        {
            "JuicyPotato", "JuicyPotatoNG", "GodPotato", "SweetPotato", "RoguePotato",
            "PrintSpoofer", "SharpEfsPotato", "EfsPotato", "CoercedPotato", "DeadPotato",
            "LocalPotato", "GenericPotato", "RemotePotato", "MultiPotato",
            "PetitPotam", "DFSCoerce", "SpoolSample", "SharpUp", "Seatbelt",
            "winPEAS", "PowerUp", "BeRoot", "PrivescCheck", "Watson",
            "ExploitCapcom", "PrintNightmare",
        };

        private static readonly string[] StagingPathMarkers =
        {
            @"\Temp\", @"\AppData\Local\Temp\", @"\Downloads\", @"\Public\",
            @"\Users\Public\", @"\PerfLogs\", @"\Tasks\", @"\$Recycle.Bin\",
        };

        public LpeScaffoldMonitor(DetectionEngine detectionEngine, ILogger<LpeScaffoldMonitor> logger)
        {
            _detectionEngine = detectionEngine;
            _logger = logger;
        }

        protected override async Task ExecuteAsync(CancellationToken ct)
        {
            _logger.LogInformation("[LpeScaffoldMonitor] Started - LPE tool / elevation scaffolding");
            while (!ct.IsCancellationRequested)
            {
                try
                {
                    await ScanAsync(ct).ConfigureAwait(false);
                    await Task.Delay(ScanInterval, ct).ConfigureAwait(false);
                }
                catch (OperationCanceledException) when (ct.IsCancellationRequested) { break; }
                catch (Exception ex) { _logger.LogDebug(ex, "[LpeScaffoldMonitor] scan error"); }
            }
        }

        private async Task ScanAsync(CancellationToken ct)
        {
            Process[] procs;
            try { procs = Process.GetProcesses(); }
            catch { return; }

            try
            {
                foreach (var proc in procs)
                {
                    if (ct.IsCancellationRequested) break;
                    try
                    {
                        var name = proc.ProcessName ?? "";
                        var pid = proc.Id;
                        if (pid <= 4) continue;

                        string? path = null;
                        try { path = SecurityValidation.GetProcessImagePath(pid); } catch { }

                        bool toolHit = false;
                        string? matched = null;
                        foreach (var frag in LpeToolNameFragments)
                        {
                            if (frag.Length < 4) continue;
                            if (name.IndexOf(frag, StringComparison.OrdinalIgnoreCase) >= 0 ||
                                (path != null && path.IndexOf(frag, StringComparison.OrdinalIgnoreCase) >= 0))
                            {
                                toolHit = true;
                                matched = frag;
                                break;
                            }
                        }

                        bool staging = path != null && StagingPathMarkers.Any(m =>
                            path.IndexOf(m, StringComparison.OrdinalIgnoreCase) >= 0);

                        if (!toolHit && !staging) continue;
                        if (toolHit)
                        {
                            var key = $"tool:{pid}:{matched}";
                            if (!ShouldAlert(key)) continue;

                            bool signed = !string.IsNullOrEmpty(path) &&
                                          SecurityValidation.VerifyAuthenticodeSignature(path!);
                            // Signed Microsoft path in System32 is not a potato tool false positive
                            if (signed && path != null &&
                                path.IndexOf(@"\Windows\System32\", StringComparison.OrdinalIgnoreCase) >= 0)
                                continue;

                            await _detectionEngine.EmitAsync(new DetectionEvent
                            {
                                RuleName = "LPE Scaffold: Privilege Escalation Tool",
                                Evidence = $"Process '{name}' (PID {pid}) matches LPE toolkit pattern '{matched}' path='{path ?? "?"}'",
                                Reasoning =
                                    "Binary name/path matches known local privilege-escalation tooling " +
                                    "(potato-class, PrintSpoofer, winPEAS, etc.). That process is the attack - " +
                                    "kill-grade. Does not patch kernel races (e.g. afd.sys) - stops userland scaffolding.",
                                Confidence = staging ? 0.90 : 0.86,
                                Tier = DetectionTier.Tier1Behavioral,
                                AuthorizedResponse = ResponseAction.KillProcessTree,
                                ProcessName = name,
                                ProcessId = pid,
                                SignalType = SignalType.SecurityEvasion,
                                // Terminal TokenTheft: rule name matches the "LPE Scaffold: Privilege
                                // Escalation Tool" fragment (kill-grade). Preserves current classification.
                                Family = TerminalFamily.TokenTheft,
                                Metadata = new Dictionary<string, string>
                                {
                                    ["LpeTool"] = matched ?? "",
                                    ["StagingPath"] = staging ? "true" : "false",
                                    ["ImagePath"] = path ?? ""
                                }
                            }).ConfigureAwait(false);
                        }
                        else if (staging)
                        {
                            // Unsigned PE from staging with high entropy / no signature - weak observe
                            if (string.IsNullOrEmpty(path) || !File.Exists(path)) continue;
                            if (SecurityValidation.VerifyAuthenticodeSignature(path!)) continue;
                            if (InstallerHeuristics.LooksLikeInstallerName(name) ||
                                InstallerHeuristics.IsDirectXOrRuntimeRedist(name, path))
                                continue;
                            if (SecurityValidation.IsGameOrAntiCheatPath(path)) continue;

                            var key = $"stage:{pid}";
                            if (!ShouldAlert(key)) continue;

                            // Only flag if process is elevated (high integrity) from staging
                            if (!IsElevatedProcess(proc)) continue;

                            await _detectionEngine.EmitAsync(new DetectionEvent
                            {
                                RuleName = "LPE Scaffold: Elevated Process from Staging Path",
                                Evidence = $"Elevated unsigned process '{name}' (PID {pid}) from staging path '{path}'",
                                Reasoning =
                                    "An elevated (high-integrity) unsigned binary is running from Temp/Downloads/Public. " +
                                    "Common after local privilege escalation or UAC bypass. Observe fuel for chain correlation.",
                                Confidence = 0.78,
                                Tier = DetectionTier.Tier2Indicator,
                                AuthorizedResponse = ResponseAction.LogOnly,
                                ProcessName = name,
                                ProcessId = pid,
                                SignalType = SignalType.SecurityEvasion,
                            }).ConfigureAwait(false);
                        }
                    }
                    catch { /* process exited */ }
                    finally
                    {
                        try { proc.Dispose(); } catch { }
                    }
                }
            }
            finally
            {
                foreach (var p in procs)
                {
                    try { p.Dispose(); } catch { }
                }
            }
        }

        private bool ShouldAlert(string key)
        {
            // Simple cooldown via set + time-bucket key
            var bucket = DateTime.UtcNow.Ticks / AlertCooldown.Ticks;
            var full = key + ":" + bucket;
            lock (_alerted)
            {
                if (_alerted.Contains(full)) return false;
                _alerted.Add(full);
                if (_alerted.Count > 500)
                    _alerted.Clear();
                return true;
            }
        }

        private static bool IsElevatedProcess(Process proc)
        {
            try
            {
                // Best-effort: Owner SID check is heavy; use limited query via OpenProcessToken
                return UacBypassSurfaceMonitorHelpers.IsProcessElevated(proc.Id);
            }
            catch { return false; }
        }
    }

    internal static class UacBypassSurfaceMonitorHelpers
    {
        [System.Runtime.InteropServices.DllImport("advapi32.dll", SetLastError = true)]
        private static extern bool OpenProcessToken(IntPtr ProcessHandle, uint DesiredAccess, out IntPtr TokenHandle);

        [System.Runtime.InteropServices.DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool CloseHandle(IntPtr hObject);

        [System.Runtime.InteropServices.DllImport("advapi32.dll", SetLastError = true)]
        private static extern bool GetTokenInformation(IntPtr TokenHandle, int TokenInformationClass,
            IntPtr TokenInformation, int TokenInformationLength, out int ReturnLength);

        private const uint TOKEN_QUERY = 0x0008;
        private const int TokenElevation = 20;

        public static bool IsProcessElevated(int pid)
        {
            IntPtr token = IntPtr.Zero;
            try
            {
                using var proc = Process.GetProcessById(pid);
                if (!OpenProcessToken(proc.Handle, TOKEN_QUERY, out token))
                    return false;
                int size = sizeof(int);
                IntPtr buf = System.Runtime.InteropServices.Marshal.AllocHGlobal(size);
                try
                {
                    if (!GetTokenInformation(token, TokenElevation, buf, size, out _))
                        return false;
                    return System.Runtime.InteropServices.Marshal.ReadInt32(buf) != 0;
                }
                finally { System.Runtime.InteropServices.Marshal.FreeHGlobal(buf); }
            }
            catch { return false; }
            finally
            {
                if (token != IntPtr.Zero) CloseHandle(token);
            }
        }
    }

    /// <summary>
    /// Registry persistence surfaces: IFEO, COM hijack (InprocServer32), accessibility
    /// (sethc/utilman), Winlogon Userinit/Shell/Notify.
    /// </summary>
    public sealed class PersistenceSurfaceMonitor : BackgroundService
    {
        private readonly DetectionEngine _detectionEngine;
        private readonly ILogger<PersistenceSurfaceMonitor> _logger;
        private readonly Dictionary<string, string> _baseline = new(StringComparer.OrdinalIgnoreCase);
        private bool _baselined;
        private static readonly TimeSpan ScanInterval = TimeSpan.FromSeconds(45);

        private static readonly (string Key, string ValueName, string Label)[] WatchedValues =
        {
            (@"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options", "", "IFEO"),
            (@"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon", "Userinit", "Winlogon Userinit"),
            (@"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon", "Shell", "Winlogon Shell"),
            (@"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon", "Taskman", "Winlogon Taskman"),
            (@"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\sethc.exe", "Debugger", "Accessibility sethc"),
            (@"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\utilman.exe", "Debugger", "Accessibility utilman"),
            (@"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\osk.exe", "Debugger", "Accessibility osk"),
            (@"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\Magnify.exe", "Debugger", "Accessibility Magnify"),
            (@"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\Narrator.exe", "Debugger", "Accessibility Narrator"),
            (@"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\DisplaySwitch.exe", "Debugger", "Accessibility DisplaySwitch"),
            (@"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\AtBroker.exe", "Debugger", "Accessibility AtBroker"),
        };

        // COM InprocServer32 hijack candidates (common UAC bypass / persistence)
        private static readonly string[] ComHijackClsidHints =
        {
            // fodhelper / eventvwr / sdclt related often use ms-settings
            @"{0A29FF9E-7F9C-4437-8B11-F424491E3931}", // example placeholder - we scan broadly under CLSID below
        };

        public PersistenceSurfaceMonitor(DetectionEngine detectionEngine, ILogger<PersistenceSurfaceMonitor> logger)
        {
            _detectionEngine = detectionEngine;
            _logger = logger;
        }

        protected override async Task ExecuteAsync(CancellationToken ct)
        {
            _logger.LogInformation("[PersistenceSurfaceMonitor] Started - IFEO / accessibility / Winlogon / COM");
            await Task.Delay(TimeSpan.FromSeconds(15), ct).ConfigureAwait(false); // stagger
            SnapshotBaseline();
            _baselined = true;

            while (!ct.IsCancellationRequested)
            {
                try
                {
                    await ScanAsync().ConfigureAwait(false);
                    await Task.Delay(ScanInterval, ct).ConfigureAwait(false);
                }
                catch (OperationCanceledException) when (ct.IsCancellationRequested) { break; }
                catch (Exception ex) { _logger.LogDebug(ex, "[PersistenceSurfaceMonitor] error"); }
            }
        }

        private void SnapshotBaseline()
        {
            foreach (var (key, valueName, label) in WatchedValues)
            {
                try
                {
                    if (string.IsNullOrEmpty(valueName))
                    {
                        // IFEO root: count subkeys
                        using var k = Registry.LocalMachine.OpenSubKey(key);
                        var count = k?.GetSubKeyNames()?.Length ?? 0;
                        _baseline["IFEO:count"] = count.ToString();
                    }
                    else
                    {
                        using var k = Registry.LocalMachine.OpenSubKey(key);
                        var v = k?.GetValue(valueName)?.ToString() ?? "";
                        _baseline[label] = v;
                    }
                }
                catch { }
            }

            // Baseline a set of high-risk COM InprocServer32 paths for ms-settings / eventvwr
            BaselineComKeys();
        }

        private void BaselineComKeys()
        {
            string[] comPaths =
            {
                @"SOFTWARE\Classes\ms-settings\Shell\Open\command",
                @"SOFTWARE\Classes\mscfile\Shell\Open\command",
                @"SOFTWARE\Classes\Folder\shell\open\command",
                @"SOFTWARE\Classes\exefile\shell\open\command",
            };
            foreach (var hive in new[] { Registry.CurrentUser, Registry.LocalMachine })
            {
                foreach (var path in comPaths)
                {
                    try
                    {
                        using var k = hive.OpenSubKey(path);
                        var def = k?.GetValue(null)?.ToString() ?? "";
                        var delegateEx = k?.GetValue("DelegateExecute")?.ToString() ?? "";
                        var id = hive.Name + "\\" + path;
                        _baseline[id + ":default"] = def;
                        _baseline[id + ":delegate"] = delegateEx;
                    }
                    catch { }
                }
            }
        }

        private async Task ScanAsync()
        {
            if (!_baselined) return;

            // IFEO debugger values on accessibility binaries
            foreach (var (key, valueName, label) in WatchedValues)
            {
                if (string.IsNullOrEmpty(valueName)) continue;
                try
                {
                    using var k = Registry.LocalMachine.OpenSubKey(key);
                    var v = k?.GetValue(valueName)?.ToString() ?? "";
                    _baseline.TryGetValue(label, out var old);
                    old ??= "";
                    if (!string.Equals(v, old, StringComparison.OrdinalIgnoreCase))
                    {
                        _baseline[label] = v;
                        if (string.IsNullOrEmpty(v) && string.IsNullOrEmpty(old)) continue;
                        // Ignore empty->empty; fire on new debugger or Winlogon change away from defaults
                        if (IsBenignWinlogon(label, v)) continue;

                        await _detectionEngine.EmitAsync(new DetectionEvent
                        {
                            RuleName = "Persistence: " + label + " Modified",
                            Evidence = $"{label} changed from '{Truncate(old, 120)}' to '{Truncate(v, 120)}'",
                            Reasoning =
                                "Registry persistence surface modified (IFEO debugger, accessibility hijack, or Winlogon). " +
                                "Classic post-compromise persistence / sticky-keys backdoor / logon hijack.",
                            Confidence = label.Contains("Accessibility") || label.Contains("IFEO") || label.Contains("Debugger")
                                ? 0.90 : 0.80,
                            Tier = DetectionTier.Tier2Indicator,
                            AuthorizedResponse = ResponseAction.LogOnly,
                            ProcessName = "SYSTEM",
                            ProcessId = 0,
                            SignalType = SignalType.SecurityEvasion,
                        }).ConfigureAwait(false);
                    }
                }
                catch { }
            }

            // IFEO subkey growth (new image names)
            try
            {
                using var ifeo = Registry.LocalMachine.OpenSubKey(
                    @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options");
                var count = ifeo?.GetSubKeyNames()?.Length ?? 0;
                if (_baseline.TryGetValue("IFEO:count", out var oldCountStr) &&
                    int.TryParse(oldCountStr, out var oldCount) &&
                    count > oldCount + 2)
                {
                    _baseline["IFEO:count"] = count.ToString();
                    await _detectionEngine.EmitAsync(new DetectionEvent
                    {
                        RuleName = "Persistence: IFEO Subkey Growth",
                        Evidence = $"IFEO subkeys grew from {oldCount} to {count}",
                        Reasoning = "Multiple new Image File Execution Options entries can indicate debugger-based persistence or process hijacking.",
                        Confidence = 0.72,
                        Tier = DetectionTier.Tier2Indicator,
                        AuthorizedResponse = ResponseAction.LogOnly,
                        ProcessName = "SYSTEM",
                        ProcessId = 0,
                        SignalType = SignalType.SecurityEvasion,
                    }).ConfigureAwait(false);
                }
                else
                {
                    _baseline["IFEO:count"] = count.ToString();
                }
            }
            catch { }

            // COM / protocol handler hijacks (HKCU preferred by attackers - no admin)
            string[] comPaths =
            {
                @"SOFTWARE\Classes\ms-settings\Shell\Open\command",
                @"SOFTWARE\Classes\mscfile\Shell\Open\command",
            };
            foreach (var hive in new[] { Registry.CurrentUser, Registry.LocalMachine })
            {
                foreach (var path in comPaths)
                {
                    try
                    {
                        using var k = hive.OpenSubKey(path);
                        var def = k?.GetValue(null)?.ToString() ?? "";
                        var id = hive.Name + "\\" + path;
                        _baseline.TryGetValue(id + ":default", out var oldDef);
                        oldDef ??= "";
                        if (!string.Equals(def, oldDef, StringComparison.OrdinalIgnoreCase) &&
                            !string.IsNullOrEmpty(def))
                        {
                            _baseline[id + ":default"] = def;
                            // Empty->empty skip; system defaults often empty or DelegateExecute
                            if (IsLikelyComHijack(def))
                            {
                                await _detectionEngine.EmitAsync(new DetectionEvent
                                {
                                    RuleName = "Persistence: COM/Protocol Handler Hijack",
                                    Evidence = $"{id} default -> '{Truncate(def, 160)}'",
                                    Reasoning =
                                        "ms-settings/mscfile open command modified - classic fodhelper/eventvwr UAC bypass " +
                                        "and persistence technique. Correlate with auto-elevate binary launch.",
                                    Confidence = 0.88,
                                    Tier = DetectionTier.Tier2Indicator,
                                    AuthorizedResponse = ResponseAction.LogOnly,
                                    ProcessName = "SYSTEM",
                                    ProcessId = 0,
                                    SignalType = SignalType.SecurityEvasion,
                                }).ConfigureAwait(false);
                            }
                        }
                    }
                    catch { }
                }
            }
        }

        private static bool IsBenignWinlogon(string label, string value)
        {
            if (!label.StartsWith("Winlogon", StringComparison.OrdinalIgnoreCase))
                return false;
            var v = value.ToLowerInvariant();
            if (label.Contains("Userinit") &&
                (v.Contains(@"\windows\system32\userinit.exe") || string.IsNullOrWhiteSpace(v)))
                return true;
            if (label.Contains("Shell") &&
                (v == "explorer.exe" || v.EndsWith(@"\explorer.exe")))
                return true;
            return false;
        }

        private static bool IsLikelyComHijack(string command)
        {
            if (string.IsNullOrWhiteSpace(command)) return false;
            var c = command.ToLowerInvariant();
            // Empty DelegateExecute-only is normal for some keys
            if (c.Contains("delegateexecute") && c.Length < 40) return false;
            // Hijack often points to Temp/AppData/Downloads or powershell/cmd
            return c.Contains(@"\temp\") || c.Contains(@"\downloads\") || c.Contains(@"\appdata\") ||
                   c.Contains("powershell") || c.Contains("cmd.exe") || c.Contains("mshta") ||
                   c.Contains("wscript") || c.Contains("cscript") || c.Contains("rundll32") ||
                   c.Contains("regsvr32") || c.Contains("http://") || c.Contains("https://") ||
                   c.Contains(@"\users\public\");
        }

        private static string Truncate(string s, int n) =>
            string.IsNullOrEmpty(s) ? "" : (s.Length <= n ? s : s.Substring(0, n) + "...");
    }

    /// <summary>
    /// Initial-access style process patterns: browser/Office parent -> LOLBin or staging child;
    /// ISO/IMG-related mount tooling; MotW-adjacent execution heuristics via path+parent.
    /// Implemented as a BackgroundService scanning recent process ancestry (lightweight).
    /// </summary>
    public sealed class InitialAccessMonitor : BackgroundService
    {
        private readonly DetectionEngine _detectionEngine;
        private readonly ProcessAncestryCache? _ancestry;
        private readonly ILogger<InitialAccessMonitor> _logger;
        private readonly HashSet<int> _alertedPids = new();
        private static readonly TimeSpan ScanInterval = TimeSpan.FromSeconds(12);

        private static readonly HashSet<string> BrowserParents = new(StringComparer.OrdinalIgnoreCase)
        {
            "chrome", "msedge", "firefox", "brave", "opera", "vivaldi", "iexplore", "browser",
            "MicrosoftEdge", "msedgewebview2"
        };

        private static readonly HashSet<string> OfficeParents = new(StringComparer.OrdinalIgnoreCase)
        {
            "winword", "excel", "powerpnt", "outlook", "msaccess", "mspub", "onenote",
            "eqnedt32", "visio", "lync", "teams"
        };

        private static readonly HashSet<string> LolBins = new(StringComparer.OrdinalIgnoreCase)
        {
            "cmd", "powershell", "pwsh", "wscript", "cscript", "mshta", "rundll32",
            "regsvr32", "cmstp", "msiexec", "certutil", "bitsadmin", "curl", "wget",
            "powershell_ise", "forfiles", "hh", "infdefaultinstall", "installutil",
            "msbuild", "msiexec", "odbcconf", "pcalua", "presentationhost", "regasm",
            "regsvcs", "syncappvpublishingserver", "verclsid", "wmic", "wt"
        };

        public InitialAccessMonitor(
            DetectionEngine detectionEngine,
            ILogger<InitialAccessMonitor> logger,
            ProcessAncestryCache? ancestry = null)
        {
            _detectionEngine = detectionEngine;
            _logger = logger;
            _ancestry = ancestry;
        }

        protected override async Task ExecuteAsync(CancellationToken ct)
        {
            _logger.LogInformation("[InitialAccessMonitor] Started - browser/Office -> LOLBin / staging");
            while (!ct.IsCancellationRequested)
            {
                try
                {
                    await ScanAsync(ct).ConfigureAwait(false);
                    await Task.Delay(ScanInterval, ct).ConfigureAwait(false);
                }
                catch (OperationCanceledException) when (ct.IsCancellationRequested) { break; }
                catch (Exception ex) { _logger.LogDebug(ex, "[InitialAccessMonitor] error"); }
            }
        }

        private async Task ScanAsync(CancellationToken ct)
        {
            Process[] procs;
            try { procs = Process.GetProcesses(); }
            catch { return; }

            try
            {
                foreach (var proc in procs)
                {
                    if (ct.IsCancellationRequested) break;
                    try
                    {
                        var pid = proc.Id;
                        if (pid <= 4 || _alertedPids.Contains(pid)) continue;
                        var name = (proc.ProcessName ?? "").ToLowerInvariant();
                        if (!LolBins.Contains(name) && !IsStagingExe(proc, out _))
                            continue;

                        int parentPid = 0;
                        string parentName = "";
                        if (_ancestry != null)
                        {
                            var (ppid, pname) = _ancestry.GetParent(pid);
                            parentPid = ppid;
                            parentName = pname ?? string.Empty;
                        }

                        var parentStem = Sentinel.Core.StringNet48.ReplaceIgnoreCase(parentName, ".exe", "");
                        bool fromBrowser = BrowserParents.Contains(parentStem);
                        bool fromOffice = OfficeParents.Contains(parentStem);

                        string? path = null;
                        try { path = SecurityValidation.GetProcessImagePath(pid); } catch { }

                        bool stagingChild = path != null && (
                            path.IndexOf(@"\Downloads\", StringComparison.OrdinalIgnoreCase) >= 0 ||
                            path.IndexOf(@"\Temp\", StringComparison.OrdinalIgnoreCase) >= 0 ||
                            path.IndexOf(@"\AppData\Local\Temp\", StringComparison.OrdinalIgnoreCase) >= 0 ||
                            path.IndexOf(@"\Users\Public\", StringComparison.OrdinalIgnoreCase) >= 0);

                        // ISO/VHD mount helpers launching content
                        bool isoContext = parentStem.Equals("explorer", StringComparison.OrdinalIgnoreCase) &&
                                          path != null &&
                                          (path.IndexOf(@"\AppData\Local\Temp\", StringComparison.OrdinalIgnoreCase) >= 0) &&
                                          LolBins.Contains(name);

                        if (!(fromBrowser || fromOffice || (stagingChild && LolBins.Contains(name)) || isoContext))
                            continue;

                        // Skip signed system LOLBins spawned by Office for legitimate print/export? 
                        // Office -> powershell is rarely legit without macros; keep as Tier2 observe.
                        if (fromOffice && name == "outlook") continue;

                        _alertedPids.Add(pid);
                        if (_alertedPids.Count > 2000)
                            _alertedPids.Clear();

                        string rule;
                        string evidence;
                        double conf;
                        if (fromBrowser && LolBins.Contains(name))
                        {
                            rule = "Initial Access: Browser Spawned LOLBin";
                            evidence = $"Browser parent '{parentName}' (PID {parentPid}) spawned '{proc.ProcessName}' (PID {pid})";
                            conf = 0.84;
                        }
                        else if (fromOffice && LolBins.Contains(name))
                        {
                            rule = "Initial Access: Office Spawned LOLBin";
                            evidence = $"Office parent '{parentName}' (PID {parentPid}) spawned '{proc.ProcessName}' (PID {pid}) path='{path ?? "?"}'";
                            conf = 0.90;
                        }
                        else if (stagingChild && LolBins.Contains(name))
                        {
                            rule = "Initial Access: LOLBin from Staging Path";
                            evidence = $"LOLBin '{proc.ProcessName}' (PID {pid}) running from staging path '{path}'";
                            conf = 0.80;
                        }
                        else
                        {
                            rule = "Initial Access: Suspicious Temp Execution";
                            evidence = $"Process '{proc.ProcessName}' (PID {pid}) path='{path}' parent='{parentName}'";
                            conf = 0.75;
                        }

                        await _detectionEngine.EmitAsync(new DetectionEvent
                        {
                            RuleName = rule,
                            Evidence = evidence,
                            Reasoning =
                                "Initial-access pattern: browser or Office document chain spawning a LOLBin, " +
                                "or LOLBin executing from Downloads/Temp (ISO/smuggling/MotW bypass path). " +
                                "Observe fuel - chain with C2/script/network for destructive response.",
                            Confidence = conf,
                            Tier = DetectionTier.Tier2Indicator,
                            AuthorizedResponse = ResponseAction.LogOnly,
                            ProcessName = proc.ProcessName ?? "",
                            ProcessId = pid,
                            SignalType = SignalType.SuspiciousProcess,
                            Metadata = new Dictionary<string, string>
                            {
                                ["ParentProcess"] = parentName,
                                ["ParentPid"] = parentPid.ToString(),
                                ["ImagePath"] = path ?? ""
                            }
                        }).ConfigureAwait(false);
                    }
                    catch { }
                    finally
                    {
                        try { proc.Dispose(); } catch { }
                    }
                }
            }
            finally
            {
                foreach (var p in procs)
                {
                    try { p.Dispose(); } catch { }
                }
            }
        }

        private static bool IsStagingExe(Process proc, out string? path)
        {
            path = null;
            try
            {
                path = SecurityValidation.GetProcessImagePath(proc.Id);
                if (string.IsNullOrEmpty(path)) return false;
                var ext = Path.GetExtension(path).ToLowerInvariant();
                if (ext is not (".exe" or ".dll" or ".scr" or ".com")) return false;
                return path!.IndexOf(@"\Downloads\", StringComparison.OrdinalIgnoreCase) >= 0 ||
                       path.IndexOf(@"\Temp\", StringComparison.OrdinalIgnoreCase) >= 0;
            }
            catch { return false; }
        }
    }
}
