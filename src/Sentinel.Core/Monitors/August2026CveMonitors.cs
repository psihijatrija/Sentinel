using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Win32;

namespace Sentinel.Core
{
    /// <summary>
    /// Operation Dream Job / Lazarus userland sensors (CVE-2026-68820 campaign).
    /// Distinctive loaders, MuPDF sideload, Temp\new.exe from a PDF viewer, C2 IOCs,
    /// FudModule module names. Does not detect the afd.sys race itself.
    /// </summary>
    public sealed class DreamJobCampaignMonitor : BackgroundService
    {
        private readonly DetectionEngine _detectionEngine;
        private readonly ILogger<DreamJobCampaignMonitor> _logger;
        private readonly ProcessAncestryCache? _ancestry;
        private readonly IoCScanner? _iocScanner;
        private readonly HashSet<string> _alerted = new(StringComparer.OrdinalIgnoreCase);
        private static readonly TimeSpan ScanInterval = TimeSpan.FromSeconds(15);
        private static readonly TimeSpan AlertCooldown = TimeSpan.FromMinutes(15);
        private bool _hashesSeeded;

        public DreamJobCampaignMonitor(
            DetectionEngine detectionEngine,
            ILogger<DreamJobCampaignMonitor> logger,
            ProcessAncestryCache? ancestry = null,
            IoCScanner? iocScanner = null)
        {
            _detectionEngine = detectionEngine;
            _logger = logger;
            _ancestry = ancestry;
            _iocScanner = iocScanner;
        }

        protected override async Task ExecuteAsync(CancellationToken ct)
        {
            _logger.LogInformation("[DreamJobCampaignMonitor] Started - Lazarus / Operation Dream Job userland IOCs");
            SeedHashes();

            while (!ct.IsCancellationRequested)
            {
                try
                {
                    await ScanAsync(ct).ConfigureAwait(false);
                    await CheckSmartAppControlAsync(ct).ConfigureAwait(false);
                    await Task.Delay(ScanInterval, ct).ConfigureAwait(false);
                }
                catch (OperationCanceledException) when (ct.IsCancellationRequested) { break; }
                catch (Exception ex) { _logger.LogDebug(ex, "[DreamJobCampaignMonitor] scan error"); }
            }
        }

        private void SeedHashes()
        {
            if (_hashesSeeded || _iocScanner == null) return;
            try
            {
                _iocScanner.AddHashes(August2026CveHeuristics.DreamJobSha256);
                _hashesSeeded = true;
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "[DreamJobCampaignMonitor] IoC hash seed failed");
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

                        string? cmd = null;
                        try { cmd = proc.StartInfo?.Arguments; } catch { }

                        if (August2026CveHeuristics.IsFudModuleName(name) ||
                            August2026CveHeuristics.IsFudModuleName(path))
                        {
                            await EmitAsync(
                                "Dream Job: FudModule LPE module",
                                $"Process '{name}' (PID {pid}) matches FudModule / Afd4Eop12 path='{path ?? "?"}'",
                                "Lazarus FudModule 3.1 (Afd4Eop12_x64.dll) is the userland loader for CVE-2026-68820. " +
                                "Does not patch afd.sys - stops the exploit host. Apply KB5121003.",
                                0.93, DetectionTier.Tier1Behavioral, ResponseAction.KillProcessTree,
                                name, pid, path, SignalType.SecurityEvasion, weak: false).ConfigureAwait(false);
                            continue;
                        }

                        if (August2026CveHeuristics.MatchesDreamJobFileName(name) ||
                            August2026CveHeuristics.MatchesDreamJobFileName(path))
                        {
                            await EmitAsync(
                                "Dream Job: SecurityPDF loader",
                                $"Process '{name}' (PID {pid}) matches Operation Dream Job loader path='{path ?? "?"}'",
                                "Filename matches Lazarus Operation Dream Job (SecurityPDF / plugin modules). " +
                                "Observe-until-chain; distinctive names are campaign IOCs (T1204.002 / T1574.002).",
                                0.90, DetectionTier.Tier1Behavioral, ResponseAction.KillProcessTree,
                                name, pid, path, SignalType.SuspiciousProcess, weak: false).ConfigureAwait(false);
                        }

                        if (August2026CveHeuristics.ContainsDreamJobDomain(cmd) ||
                            August2026CveHeuristics.ContainsDreamJobDomain(path))
                        {
                            await EmitAsync(
                                "Dream Job: C2 domain",
                                $"Process '{name}' (PID {pid}) references Dream Job C2 (envell/enveil/uxtramine or published IPs).",
                                "Command line or path contains Lazarus Operation Dream Job C2 indicators published by Check Point.",
                                0.92, DetectionTier.Tier1Behavioral, ResponseAction.KillProcessTree,
                                name, pid, path, SignalType.NetworkC2, weak: false).ConfigureAwait(false);
                        }

                        if (!string.IsNullOrEmpty(path) && August2026CveHeuristics.IsStagingPath(path))
                        {
                            try
                            {
                                var dir = Path.GetDirectoryName(path);
                                if (!string.IsNullOrEmpty(dir))
                                {
                                    var mupdf = Path.Combine(dir, "libmupdf.dll");
                                    if (File.Exists(mupdf) &&
                                        August2026CveHeuristics.IsLibmupdfSideload(mupdf, path))
                                    {
                                        await EmitAsync(
                                            "Dream Job: MuPDF sideload",
                                            $"'{name}' (PID {pid}) from staging path with libmupdf.dll at '{mupdf}'",
                                            "DLL sideload of libmupdf.dll next to a PDF viewer in Temp/Downloads is Infection Chain 1 of Operation Dream Job.",
                                            0.88, DetectionTier.Tier1Behavioral, ResponseAction.KillProcessTree,
                                            name, pid, path, SignalType.SuspiciousProcess, weak: false).ConfigureAwait(false);
                                    }
                                }
                            }
                            catch { }
                        }

                        if (August2026CveHeuristics.IsTempNewExe(path, name))
                        {
                            var parentName = "";
                            try
                            {
                                if (_ancestry != null)
                                    parentName = _ancestry.GetParent(pid).name ?? "";
                            }
                            catch { }

                            if (August2026CveHeuristics.IsPdfViewerProcess(parentName) ||
                                August2026CveHeuristics.IsPdfViewerProcess(name) ||
                                August2026CveHeuristics.MatchesDreamJobFileName(parentName))
                            {
                                await EmitAsync(
                                    "Dream Job: PDF viewer dropped Temp payload",
                                    $"'{name}' (PID {pid}) is %TEMP%\\new.exe parent='{parentName}' path='{path}'",
                                    "SecurityPDF XOR-decrypts an embedded payload to %TEMP%\\new.exe and launches it (Troy backdoor). " +
                                    "Only fires when parent is a PDF viewer or Dream Job loader.",
                                    0.91, DetectionTier.Tier1Behavioral, ResponseAction.KillProcessTree,
                                    name, pid, path, SignalType.SuspiciousProcess, weak: false).ConfigureAwait(false);
                            }
                        }
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

        private async Task CheckSmartAppControlAsync(CancellationToken ct)
        {
            try
            {
                using var key = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Control\CI\Policy");
                var val = key?.GetValue("VerifiedAndReputablePolicyState");
                if (val is int i && i == 0)
                {
                    await EmitAsync(
                        "Dream Job: Smart App Control tamper",
                        "VerifiedAndReputablePolicyState is 0 (Smart App Control / code integrity policy unloaded).",
                        "FudModule 3.1 zeroes this value from a SYSTEM msiexec stub after CVE-2026-68820. " +
                        "Users can also disable SAC - WeakObserveSeed, never a solo nuke.",
                        0.62, DetectionTier.Tier2Indicator, ResponseAction.LogOnly,
                        "SYSTEM", 0, null, SignalType.AntiTamper, weak: true).ConfigureAwait(false);
                }
            }
            catch { }
        }

        private async Task EmitAsync(
            string rule, string evidence, string reasoning, double conf,
            DetectionTier tier, ResponseAction action,
            string processName, int pid, string? path, SignalType signal, bool weak)
        {
            var bucket = DateTime.UtcNow.Ticks / AlertCooldown.Ticks;
            var key = rule + ":" + pid + ":" + bucket;
            lock (_alerted)
            {
                if (_alerted.Contains(key)) return;
                _alerted.Add(key);
                if (_alerted.Count > 400) _alerted.Clear();
            }

            var meta = new Dictionary<string, string>
            {
                ["Campaign"] = "Lazarus-DreamJob",
                ["CVE"] = August2026CveHeuristics.CveAfdSys,
            };
            if (!string.IsNullOrEmpty(path)) meta["ImagePath"] = path!;
            if (weak) meta["WeakObserveSeed"] = "true";

            await _detectionEngine.EmitAsync(new DetectionEvent
            {
                RuleName = rule,
                Evidence = evidence,
                Reasoning = reasoning,
                Confidence = conf,
                Tier = tier,
                AuthorizedResponse = action,
                ProcessName = processName,
                ProcessId = pid,
                SignalType = signal,
                Metadata = meta
            }).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// CVE-2026-62832 LegacyHive: User Profile Service loading another user's hive,
    /// custom-named HKU loads, junctions onto NTUSER.DAT.
    /// </summary>
    public sealed class LegacyHiveMonitor : BackgroundService
    {
        private readonly DetectionEngine _detectionEngine;
        private readonly ILogger<LegacyHiveMonitor> _logger;
        private readonly HashSet<string> _pending = new(StringComparer.OrdinalIgnoreCase);
        private readonly HashSet<string> _alerted = new(StringComparer.OrdinalIgnoreCase);
        private static readonly TimeSpan ScanInterval = TimeSpan.FromSeconds(20);
        private static readonly TimeSpan AlertCooldown = TimeSpan.FromMinutes(20);

        public LegacyHiveMonitor(DetectionEngine detectionEngine, ILogger<LegacyHiveMonitor> logger)
        {
            _detectionEngine = detectionEngine;
            _logger = logger;
        }

        protected override async Task ExecuteAsync(CancellationToken ct)
        {
            _logger.LogInformation("[LegacyHiveMonitor] Started - CVE-2026-62832 user hive load");
            while (!ct.IsCancellationRequested)
            {
                try
                {
                    await ScanAsync(ct).ConfigureAwait(false);
                    await Task.Delay(ScanInterval, ct).ConfigureAwait(false);
                }
                catch (OperationCanceledException) when (ct.IsCancellationRequested) { break; }
                catch (Exception ex) { _logger.LogDebug(ex, "[LegacyHiveMonitor] scan error"); }
            }
        }

        private async Task ScanAsync(CancellationToken ct)
        {
            List<string> loaded;
            try { loaded = ListLoadedHiveKeys(); }
            catch { return; }

            var loggedOn = GetLoggedOnSids();
            var stillPending = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

            foreach (var key in loaded)
            {
                if (ct.IsCancellationRequested) break;
                var profilePath = LookupProfilePath(key);
                if (!August2026CveHeuristics.IsUnexpectedUserHive(key, loggedOn, profilePath))
                    continue;

                stillPending.Add(key);
                if (!_pending.Contains(key))
                    continue; // require two consecutive scans (~40s) to survive logon races

                var bucket = DateTime.UtcNow.Ticks / AlertCooldown.Ticks;
                var alertKey = key + ":" + bucket;
                lock (_alerted)
                {
                    if (_alerted.Contains(alertKey)) continue;
                    _alerted.Add(alertKey);
                    if (_alerted.Count > 200) _alerted.Clear();
                }

                var custom = August2026CveHeuristics.IsCustomNamedHive(key);
                await _detectionEngine.EmitAsync(new DetectionEvent
                {
                    RuleName = custom
                        ? "LegacyHive: Custom-named registry hive loaded"
                        : "LegacyHive: Another user's hive loaded",
                    Evidence = $"HKU\\{key} is loaded. Profile='{profilePath ?? "?"}'. Logged-on SIDs={loggedOn.Count}.",
                    Reasoning =
                        "CVE-2026-62832 (LegacyHive) loads another user's NTUSER.DAT / UsrClass.dat via the User Profile Service " +
                        "to steal Classes data and escalate to Administrator. A hive that stays loaded while that user is not " +
                        "logged on (or a custom HKU name) is the userland footprint. LogOnly unless chained with token/UAC.",
                    Confidence = custom ? 0.88 : 0.80,
                    Tier = custom ? DetectionTier.Tier1Behavioral : DetectionTier.Tier2Indicator,
                    AuthorizedResponse = ResponseAction.LogOnly,
                    ProcessName = "ProfSvc",
                    ProcessId = 0,
                    SignalType = SignalType.SecurityEvasion,
                    Metadata = new Dictionary<string, string>
                    {
                        ["CVE"] = August2026CveHeuristics.CveLegacyHive,
                        ["HiveKey"] = key,
                        ["WeakObserveSeed"] = custom ? "false" : "true",
                    }
                }).ConfigureAwait(false);
            }

            _pending.Clear();
            foreach (var s in stillPending) _pending.Add(s);
        }

        internal static List<string> ListLoadedHiveKeys()
        {
            var list = new List<string>();
            using var users = Registry.Users;
            foreach (var name in users.GetSubKeyNames())
                list.Add(name);
            return list;
        }

        internal static string? LookupProfilePath(string sid)
        {
            try
            {
                using var key = Registry.LocalMachine.OpenSubKey(
                    @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\" + sid);
                return key?.GetValue("ProfileImagePath") as string;
            }
            catch { return null; }
        }

        private static HashSet<string> GetLoggedOnSids()
        {
            var sids = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            try
            {
                if (!WtsEnumerateSessions(out var sessions) || sessions == null)
                    return sids;
                foreach (var s in sessions)
                {
                    if (s.State != WtsConnectState.Active && s.State != WtsConnectState.Disconnected)
                        continue;
                    var user = WtsQuerySessionUser(s.SessionId);
                    if (string.IsNullOrEmpty(user)) continue;
                    var sid = SidFromUsername(user!);
                    if (!string.IsNullOrEmpty(sid)) sids.Add(sid!);
                }
            }
            catch { }
            return sids;
        }

        private static string? SidFromUsername(string username)
        {
            try
            {
                using var list = Registry.LocalMachine.OpenSubKey(
                    @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList");
                if (list == null) return null;
                foreach (var sid in list.GetSubKeyNames())
                {
                    try
                    {
                        using var sub = list.OpenSubKey(sid);
                        var path = sub?.GetValue("ProfileImagePath") as string;
                        if (string.IsNullOrEmpty(path)) continue;
                        var leaf = Path.GetFileName(path!.TrimEnd('\\'));
                        if (leaf.Equals(username, StringComparison.OrdinalIgnoreCase))
                            return sid;
                    }
                    catch { }
                }
            }
            catch { }
            return null;
        }

        private enum WtsConnectState
        {
            Active = 0,
            Connected = 1,
            ConnectQuery = 2,
            Shadow = 3,
            Disconnected = 4,
            Idle = 5,
            Listen = 6,
            Reset = 7,
            Down = 8,
            Init = 9
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct WtsSessionInfo
        {
            public int SessionId;
            public IntPtr pWinStationName;
            public WtsConnectState State;
        }

        [DllImport("wtsapi32.dll", SetLastError = true)]
        private static extern bool WTSEnumerateSessions(
            IntPtr hServer, int reserved, int version,
            out IntPtr ppSessionInfo, out int pCount);

        [DllImport("wtsapi32.dll")]
        private static extern void WTSFreeMemory(IntPtr pMemory);

        [DllImport("wtsapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern bool WTSQuerySessionInformation(
            IntPtr hServer, int sessionId, int wtsInfoClass,
            out IntPtr ppBuffer, out int pBytesReturned);

        private const int WtsUserName = 5;

        private static bool WtsEnumerateSessions(out List<WtsSessionInfo>? sessions)
        {
            sessions = null;
            if (!WTSEnumerateSessions(IntPtr.Zero, 0, 1, out var ptr, out var count) || ptr == IntPtr.Zero)
                return false;
            try
            {
                sessions = new List<WtsSessionInfo>(count);
                var size = Marshal.SizeOf<WtsSessionInfo>();
                for (int i = 0; i < count; i++)
                {
                    var item = Marshal.PtrToStructure<WtsSessionInfo>(IntPtr.Add(ptr, i * size));
                    sessions.Add(item);
                }
                return true;
            }
            finally { WTSFreeMemory(ptr); }
        }

        private static string? WtsQuerySessionUser(int sessionId)
        {
            if (!WTSQuerySessionInformation(IntPtr.Zero, sessionId, WtsUserName, out var buf, out _))
                return null;
            try { return Marshal.PtrToStringUni(buf); }
            finally { WTSFreeMemory(buf); }
        }
    }

    /// <summary>
    /// Cloud Files Mini Filter / ShieldBreak: unauthorized CfApi sync roots and
    /// cloud placeholders in staging paths that are not OneDrive/Dropbox/etc.
    /// CVE-2026-62713 + Defender CfApi hydration TOCTOU (ShieldBreak).
    /// </summary>
    public sealed class CloudFilesHydrationMonitor : BackgroundService
    {
        private readonly DetectionEngine _detectionEngine;
        private readonly ILogger<CloudFilesHydrationMonitor> _logger;
        private readonly HashSet<string> _baselineRoots = new(StringComparer.OrdinalIgnoreCase);
        private readonly HashSet<string> _alerted = new(StringComparer.OrdinalIgnoreCase);
        private bool _baselined;
        private static readonly TimeSpan ScanInterval = TimeSpan.FromSeconds(30);
        private static readonly TimeSpan AlertCooldown = TimeSpan.FromMinutes(20);

        public CloudFilesHydrationMonitor(
            DetectionEngine detectionEngine,
            ILogger<CloudFilesHydrationMonitor> logger)
        {
            _detectionEngine = detectionEngine;
            _logger = logger;
        }

        protected override async Task ExecuteAsync(CancellationToken ct)
        {
            _logger.LogInformation("[CloudFilesHydrationMonitor] Started - CfApi sync roots / ShieldBreak placeholders");
            try { SnapshotSyncRoots(_baselineRoots); _baselined = true; }
            catch { }

            while (!ct.IsCancellationRequested)
            {
                try
                {
                    await ScanSyncRootsAsync(ct).ConfigureAwait(false);
                    await ScanStagingPlaceholdersAsync(ct).ConfigureAwait(false);
                    await Task.Delay(ScanInterval, ct).ConfigureAwait(false);
                }
                catch (OperationCanceledException) when (ct.IsCancellationRequested) { break; }
                catch (Exception ex) { _logger.LogDebug(ex, "[CloudFilesHydrationMonitor] scan error"); }
            }
        }

        internal static void SnapshotSyncRoots(HashSet<string> target)
        {
            target.Clear();
            using var key = Registry.LocalMachine.OpenSubKey(
                @"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\SyncRootManager");
            if (key == null) return;
            foreach (var name in key.GetSubKeyNames())
                target.Add(name);
        }

        private async Task ScanSyncRootsAsync(CancellationToken ct)
        {
            var current = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            try { SnapshotSyncRoots(current); }
            catch { return; }

            if (!_baselined)
            {
                foreach (var r in current) _baselineRoots.Add(r);
                _baselined = true;
                return;
            }

            foreach (var root in current)
            {
                if (ct.IsCancellationRequested) break;
                if (_baselineRoots.Contains(root)) continue;
                _baselineRoots.Add(root);

                if (August2026CveHeuristics.IsKnownSyncRootId(root))
                    continue;

                if (!ShouldAlert("root:" + root)) continue;

                await _detectionEngine.EmitAsync(new DetectionEvent
                {
                    RuleName = "Cloud Files: Unauthorized sync root",
                    Evidence = $"New CfApi / Cloud Files sync root registered: '{root}'",
                    Reasoning =
                        "ShieldBreak and CVE-2026-62713 abuse the Cloud Files Mini Filter (cldflt) / CfApi. " +
                        "A sync root that is not OneDrive/Dropbox/iCloud/SharePoint/WorkFolders is how an attacker " +
                        "registers a hydration callback to swap file contents during a Defender cloud scan. " +
                        "Does not disable OneDrive. LogOnly unless chained with system-path writes.",
                    Confidence = 0.84,
                    Tier = DetectionTier.Tier1Behavioral,
                    AuthorizedResponse = ResponseAction.LogOnly,
                    ProcessName = "SYSTEM",
                    ProcessId = 0,
                    SignalType = SignalType.AntiTamper,
                    Metadata = new Dictionary<string, string>
                    {
                        ["CVE"] = August2026CveHeuristics.CveCloudFiles,
                        ["SyncRoot"] = root,
                    }
                }).ConfigureAwait(false);
            }
        }

        private async Task ScanStagingPlaceholdersAsync(CancellationToken ct)
        {
            var roots = new List<string>();
            try
            {
                var users = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "..", "Users");
                users = Path.GetFullPath(users);
                if (Directory.Exists(users))
                {
                    foreach (var profile in Directory.GetDirectories(users))
                    {
                        var leaf = Path.GetFileName(profile);
                        if (leaf.Equals("Public", StringComparison.OrdinalIgnoreCase) ||
                            leaf.Equals("Default", StringComparison.OrdinalIgnoreCase) ||
                            leaf.Equals("Default User", StringComparison.OrdinalIgnoreCase) ||
                            leaf.StartsWith("All Users", StringComparison.OrdinalIgnoreCase))
                            continue;
                        roots.Add(Path.Combine(profile, "Downloads"));
                        roots.Add(Path.Combine(profile, "Desktop"));
                        roots.Add(Path.Combine(profile, "AppData", "Local", "Temp"));
                    }
                }
            }
            catch { }

            foreach (var dir in roots)
            {
                if (ct.IsCancellationRequested) break;
                if (!Directory.Exists(dir)) continue;
                if (August2026CveHeuristics.IsKnownCloudSyncFolder(dir)) continue;

                string[] files;
                try { files = Directory.GetFiles(dir); }
                catch { continue; }

                foreach (var file in files)
                {
                    try
                    {
                        var attrs = (int)File.GetAttributes(file);
                        if (!August2026CveHeuristics.IsCloudPlaceholderAttributes(attrs))
                            continue;
                        if (August2026CveHeuristics.IsKnownCloudSyncFolder(file))
                            continue;
                        if (!ShouldAlert("ph:" + file.ToLowerInvariant())) continue;

                        await _detectionEngine.EmitAsync(new DetectionEvent
                        {
                            RuleName = "Cloud Files: Placeholder in staging path",
                            Evidence = $"Cloud Files placeholder (recall-on-open/data-access) at '{file}'",
                            Reasoning =
                                "A CfApi / Cloud Files placeholder in Downloads/Desktop/Temp outside OneDrive is the " +
                                "ShieldBreak bait file: Defender hydrates it, the callback swaps contents. Weak observe " +
                                "unless a system path is overwritten in the same window.",
                            Confidence = 0.72,
                            Tier = DetectionTier.Tier2Indicator,
                            AuthorizedResponse = ResponseAction.LogOnly,
                            ProcessName = "SYSTEM",
                            ProcessId = 0,
                            SignalType = SignalType.AntiTamper,
                            Metadata = new Dictionary<string, string>
                            {
                                ["CVE"] = August2026CveHeuristics.CveCloudFiles,
                                ["Path"] = file,
                                ["WeakObserveSeed"] = "true",
                            }
                        }).ConfigureAwait(false);
                    }
                    catch { }
                }
            }
        }

        private bool ShouldAlert(string key)
        {
            var bucket = DateTime.UtcNow.Ticks / AlertCooldown.Ticks;
            var full = key + ":" + bucket;
            lock (_alerted)
            {
                if (_alerted.Contains(full)) return false;
                _alerted.Add(full);
                if (_alerted.Count > 400) _alerted.Clear();
                return true;
            }
        }
    }

    /// <summary>
    /// CLFS (Common Log File System, clfs.sys) exploitation footprint sensor.
    ///
    /// CLFS LPE exploits (CVE-2025-29824 - an in-the-wild ransomware 0-day - and the recurring
    /// -32706 / -60709 / -62470 / CVE-2026-40407 class) work by handing the kernel a crafted
    /// Base Log File (.blf) whose internal structures corrupt kernel memory to reach SYSTEM.
    /// Sentinel is userland-only and cannot see the malformed IOCTL, but the observable footprint
    /// is a .blf Base Log File created OUTSIDE the legitimate CLFS locations - i.e. dropped into a
    /// user-writable staging path by a non-system actor.
    ///
    /// This is deliberately an OBSERVE-ONLY leg (Tier2, LogOnly, WeakObserveSeed). A .blf in a
    /// staging path is suspicious but not proof - some software legitimately uses CLFS. It becomes
    /// kill-grade ONLY when the correlation engine fuses it with a same-process/ancestry integrity
    /// jump ("...Token Integrity Jump to SYSTEM") via the "CLFS Privilege Escalation Chain"
    /// composite. That is the honest "a known CVE was invoked locally AND it succeeded -> kill"
    /// path: the drop is the attempt, the integrity jump is the success.
    ///
    /// Adversarial note: the attacker controls the filename and the drop folder, so neither alone
    /// authorizes anything. The anchor is the LOCATION - the legitimate CLFS trees are not
    /// user-writable; a .blf in Temp/Downloads/AppData/Public is a drop, not a trusted log.
    /// </summary>
    public sealed class ClfsExploitationMonitor : BackgroundService
    {
        private readonly DetectionEngine _detectionEngine;
        private readonly ILogger<ClfsExploitationMonitor> _logger;
        private readonly HashSet<string> _alerted = new(StringComparer.OrdinalIgnoreCase);
        private static readonly TimeSpan ScanInterval = TimeSpan.FromSeconds(30);
        private static readonly TimeSpan AlertCooldown = TimeSpan.FromMinutes(20);

        public ClfsExploitationMonitor(
            DetectionEngine detectionEngine,
            ILogger<ClfsExploitationMonitor> logger)
        {
            _detectionEngine = detectionEngine;
            _logger = logger;
        }

        protected override async Task ExecuteAsync(CancellationToken ct)
        {
            _logger.LogInformation("[ClfsExploitationMonitor] Started - .blf Base Log File drops in staging paths");

            while (!ct.IsCancellationRequested)
            {
                try
                {
                    await ScanStagingForBlfAsync(ct).ConfigureAwait(false);
                    await Task.Delay(ScanInterval, ct).ConfigureAwait(false);
                }
                catch (OperationCanceledException) when (ct.IsCancellationRequested) { break; }
                catch (Exception ex) { _logger.LogDebug(ex, "[ClfsExploitationMonitor] scan error"); }
            }
        }

        /// <summary>
        /// True when a path is a user-writable staging location - the only place a .blf drop is
        /// suspicious. The legitimate CLFS trees (System32\config, System32\SMI, TxR journals)
        /// are not user-writable, so this is the non-attacker-controllable anchor.
        /// </summary>
        internal static bool IsStagingBlfPath(string path)
        {
            if (string.IsNullOrEmpty(path)) return false;
            if (!path.EndsWith(".blf", StringComparison.OrdinalIgnoreCase)) return false;

            // Exclude the legitimate CLFS/TxR locations even if they appear under a scanned root.
            if (path.IndexOf(@"\System32\config", StringComparison.OrdinalIgnoreCase) >= 0 ||
                path.IndexOf(@"\System32\SMI", StringComparison.OrdinalIgnoreCase) >= 0 ||
                path.IndexOf(@"\$Txf", StringComparison.OrdinalIgnoreCase) >= 0 ||
                path.IndexOf(@"\TxR", StringComparison.OrdinalIgnoreCase) >= 0 ||
                path.IndexOf(@"\Microsoft\Search", StringComparison.OrdinalIgnoreCase) >= 0)
                return false;

            return path.IndexOf(@"\Temp\", StringComparison.OrdinalIgnoreCase) >= 0 ||
                   path.IndexOf(@"\Downloads\", StringComparison.OrdinalIgnoreCase) >= 0 ||
                   path.IndexOf(@"\AppData\Local\Temp", StringComparison.OrdinalIgnoreCase) >= 0 ||
                   path.IndexOf(@"\Users\Public\", StringComparison.OrdinalIgnoreCase) >= 0 ||
                   path.IndexOf(@"\PerfLogs\", StringComparison.OrdinalIgnoreCase) >= 0;
        }

        private async Task ScanStagingForBlfAsync(CancellationToken ct)
        {
            var roots = new List<string>();
            try
            {
                roots.Add(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "..", "Users", "Public"));
                roots.Add(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "..", "PerfLogs"));

                var users = Path.GetFullPath(Path.Combine(
                    Environment.GetFolderPath(Environment.SpecialFolder.Windows), "..", "Users"));
                if (Directory.Exists(users))
                {
                    foreach (var profile in Directory.GetDirectories(users))
                    {
                        var leaf = Path.GetFileName(profile);
                        if (leaf.Equals("Default", StringComparison.OrdinalIgnoreCase) ||
                            leaf.Equals("Default User", StringComparison.OrdinalIgnoreCase) ||
                            leaf.StartsWith("All Users", StringComparison.OrdinalIgnoreCase))
                            continue;
                        roots.Add(Path.Combine(profile, "Downloads"));
                        roots.Add(Path.Combine(profile, "AppData", "Local", "Temp"));
                    }
                }
            }
            catch { }

            foreach (var dir in roots)
            {
                if (ct.IsCancellationRequested) break;
                string fullDir;
                try { fullDir = Path.GetFullPath(dir); } catch { continue; }
                if (!Directory.Exists(fullDir)) continue;

                string[] files;
                try { files = Directory.GetFiles(fullDir, "*.blf", SearchOption.TopDirectoryOnly); }
                catch { continue; }

                foreach (var file in files)
                {
                    if (ct.IsCancellationRequested) break;
                    if (!IsStagingBlfPath(file)) continue;
                    if (!ShouldAlert("blf:" + file.ToLowerInvariant())) continue;

                    await _detectionEngine.EmitAsync(new DetectionEvent
                    {
                        RuleName = "CVE Class: CLFS Base Log File in Staging Path",
                        Evidence = $"CLFS Base Log File (.blf) at user-writable path '{file}'",
                        Reasoning =
                            "A CLFS Base Log File (.blf) was created in a user-writable staging directory, outside the " +
                            "legitimate CLFS/TxR locations. This is the userland footprint of a Common Log File System " +
                            "kernel LPE exploit (CVE-2025-29824-class: a crafted .blf corrupts kernel memory to reach " +
                            "SYSTEM). Observe-only on its own - many programs never touch CLFS here, but some do. It is " +
                            "kill-grade only when the same process/ancestry then jumps to SYSTEM integrity (the " +
                            "'CLFS Privilege Escalation Chain' composite). Userland cannot patch clfs.sys - apply OS updates.",
                        Confidence = 0.72,
                        Tier = DetectionTier.Tier2Indicator,
                        AuthorizedResponse = ResponseAction.LogOnly,
                        ProcessName = "SYSTEM",
                        ProcessId = 0,
                        SignalType = SignalType.SecurityEvasion,
                        Metadata = new Dictionary<string, string>
                        {
                            ["CVE"] = August2026CveHeuristics.CveClfs,
                            ["Path"] = file,
                            ["Technique"] = "T1068 (Exploitation for Privilege Escalation)",
                            ["WeakObserveSeed"] = "true",
                        }
                    }).ConfigureAwait(false);
                }
            }
        }

        private bool ShouldAlert(string key)
        {
            var bucket = DateTime.UtcNow.Ticks / AlertCooldown.Ticks;
            var full = key + ":" + bucket;
            lock (_alerted)
            {
                if (_alerted.Contains(full)) return false;
                _alerted.Add(full);
                if (_alerted.Count > 400) _alerted.Clear();
                return true;
            }
        }
    }
}
