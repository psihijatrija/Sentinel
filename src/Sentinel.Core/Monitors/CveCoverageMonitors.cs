// Generic CVE-class coverage (v2.2.4). Catches the userland shape of new
// kernel EoP / MSI EoP / winget / MOTW / VS Code / unionfs bugs without
// waiting for a named campaign pack.
// v2.5.3: kernel EoP loader and ClickFix encoded-run are kill-grade.
// MOTW / disk-image / VSIX / winget / VS Code encoded stay observe.

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Win32;

namespace Sentinel.Core
{
    /// <summary>
    /// One process-enumeration pass covering kernel-EoP loaders, MSI repair from
    /// staging, winget/AppInstaller abuse, VS Code workspace shells, ClickFix
    /// encoded commands, MIDI service children, and RDP-client spawn.
    /// </summary>
    public sealed class CveClassCoverageMonitor : BackgroundService
    {
        private readonly DetectionEngine _detectionEngine;
        private readonly ILogger<CveClassCoverageMonitor> _logger;
        private readonly ProcessAncestryCache? _ancestry;
        private readonly HashSet<string> _alerted = new(StringComparer.OrdinalIgnoreCase);
        private static readonly TimeSpan ScanInterval = TimeSpan.FromSeconds(18);
        private static readonly TimeSpan AlertCooldown = TimeSpan.FromMinutes(15);

        public CveClassCoverageMonitor(
            DetectionEngine detectionEngine,
            ILogger<CveClassCoverageMonitor> logger,
            ProcessAncestryCache? ancestry = null)
        {
            _detectionEngine = detectionEngine;
            _logger = logger;
            _ancestry = ancestry;
        }

        protected override async Task ExecuteAsync(CancellationToken ct)
        {
            _logger.LogInformation("[CveClassCoverageMonitor] Started - generic CVE-class userland sensors");
            while (!ct.IsCancellationRequested)
            {
                try
                {
                    await ScanAsync(ct).ConfigureAwait(false);
                    await Task.Delay(ScanInterval, ct).ConfigureAwait(false);
                }
                catch (OperationCanceledException) when (ct.IsCancellationRequested) { break; }
                catch (Exception ex) { _logger.LogDebug(ex, "[CveClassCoverageMonitor] scan error"); }
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
                        if (pid <= 4) continue;
                        var name = proc.ProcessName ?? "";
                        if (string.IsNullOrEmpty(name)) continue;

                        string? path = null;
                        try { path = SecurityValidation.GetProcessImagePath(pid); } catch { }

                        int parentPid = 0;
                        string parentName = "";
                        if (_ancestry != null)
                        {
                            var (ppid, pname) = _ancestry.GetParent(pid);
                            parentPid = ppid;
                            parentName = pname ?? "";
                        }

                        var parentStem = Path.GetFileNameWithoutExtension(parentName) ?? parentName;
                        bool staging = CveCoverageHeuristics.IsStagingPath(path);
                        bool interestingName =
                            CveCoverageHeuristics.IsKernelExploitLoaderName(name) ||
                            CveCoverageHeuristics.IsKernelExploitLoaderName(path) ||
                            name.Equals("msiexec", StringComparison.OrdinalIgnoreCase) ||
                            name.Equals("winget", StringComparison.OrdinalIgnoreCase) ||
                            name.Equals("AppInstaller", StringComparison.OrdinalIgnoreCase) ||
                            name.Equals("WindowsPackageManagerServer", StringComparison.OrdinalIgnoreCase) ||
                            CveCoverageHeuristics.IsVsCodeHost(name) ||
                            CveCoverageHeuristics.IsMidiServiceProcess(name) ||
                            name.Equals("mstsc", StringComparison.OrdinalIgnoreCase) ||
                            CveCoverageHeuristics.IsLolBinName(name);

                        if (!interestingName && !staging) continue;

                        string? cmd = null;
                        if (interestingName || staging)
                            cmd = TryGetCommandLine(pid);

                        if (CveCoverageHeuristics.IsKernelExploitLoaderName(name) ||
                            CveCoverageHeuristics.IsKernelExploitLoaderName(path) ||
                            CveCoverageHeuristics.ContainsDeviceIoctlPrimitive(cmd) ||
                            CveCoverageHeuristics.LooksLikeCveId(cmd) ||
                            CveCoverageHeuristics.LooksLikeCveId(path))
                        {
                            bool signed = !string.IsNullOrEmpty(path) &&
                                          SecurityValidation.VerifyAuthenticodeSignature(path!);
                            if (signed && path != null &&
                                path.IndexOf(@"\Windows\System32\", StringComparison.OrdinalIgnoreCase) >= 0)
                            {
                                // skip
                            }
                            else if (!signed || staging)
                            {
                                await EmitAsync(
                                    "CVE Class: Kernel Exploit Loader",
                                    $"Process '{name}' (PID {pid}) matches kernel-EoP loader shape path='{path ?? "?"}' cmd='{Truncate(cmd, 160)}'",
                                    "Userland loader for kernel elevation-of-privilege (AFD/WinSock, isolation FS, HTTP.sys-class). " +
                                    "Does not patch the kernel race - stops the exploit host. Kill-grade. " +
                                    $"Covers {CveCoverageHeuristics.CveAfdAlt1}/{CveCoverageHeuristics.CveAfdAlt2} class, not just named campaigns.",
                                    staging ? 0.90 : 0.86, name, pid, path, parentName, parentPid,
                                    SignalType.SecurityEvasion, killGrade: true,
                                    family: TerminalFamily.TokenTheft).ConfigureAwait(false);
                            }
                        }

                        if (name.Equals("msiexec", StringComparison.OrdinalIgnoreCase) &&
                            CveCoverageHeuristics.IsMsiFromStaging(cmd))
                        {
                            await EmitAsync(
                                "CVE Class: Installer EoP from Staging",
                                $"msiexec (PID {pid}) installing/repairing MSI from staging cmd='{Truncate(cmd, 180)}'",
                                "Windows Installer EoP class (CVE-2026-61925 and siblings): repair/install of an MSI from Temp/Downloads. " +
                                "Custom actions run as SYSTEM. Observe-until-chain.",
                                0.84, name, pid, path, parentName, parentPid,
                                SignalType.SecurityEvasion).ConfigureAwait(false);
                        }

                        if ((name.Equals("winget", StringComparison.OrdinalIgnoreCase) ||
                             name.Equals("AppInstaller", StringComparison.OrdinalIgnoreCase) ||
                             name.Equals("WindowsPackageManagerServer", StringComparison.OrdinalIgnoreCase)) &&
                            (CveCoverageHeuristics.IsAppInstallerProtocol(cmd) ||
                             CveCoverageHeuristics.IsUntrustedWingetSource(cmd) ||
                             staging))
                        {
                            await EmitAsync(
                                "CVE Class: Package Manager EoP",
                                $"'{name}' (PID {pid}) AppInstaller/winget from untrusted source or staging cmd='{Truncate(cmd, 180)}'",
                                "Windows Package Manager EoP (CVE-2026-68821): ms-appinstaller protocol, HTTP source add, or staging binary. " +
                                "Work-first - Store/winget of signed apps is not this pattern.",
                                0.82, name, pid, path, parentName, parentPid,
                                SignalType.SuspiciousProcess).ConfigureAwait(false);
                        }

                        if (CveCoverageHeuristics.IsLolBinName(name) &&
                            CveCoverageHeuristics.IsVsCodeHost(parentStem) &&
                            CveCoverageHeuristics.IsClickFixEncodedCommand(cmd))
                        {
                            await EmitAsync(
                                "CVE Class: VS Code Encoded Shell",
                                $"VS Code host '{parentName}' spawned '{name}' (PID {pid}) with encoded/IEX command",
                                "VS Code / Copilot security-feature-bypass class (CVE-2026-58650 / CVE-2026-70335): " +
                                "editor host launching an encoded shell. Tasks.json and Copilot chat abuse look like this. " +
                                "Unsigned workspace tooling is observe fuel.",
                                0.88, name, pid, path, parentName, parentPid,
                                SignalType.SuspiciousProcess).ConfigureAwait(false);
                        }

                        if (CveCoverageHeuristics.IsLolBinName(name) &&
                            parentStem.Equals("explorer", StringComparison.OrdinalIgnoreCase) &&
                            CveCoverageHeuristics.IsClickFixEncodedCommand(cmd))
                        {
                            await EmitAsync(
                                "CVE Class: ClickFix Encoded Run",
                                $"explorer spawned '{name}' (PID {pid}) with encoded PowerShell/IEX cmd='{Truncate(cmd, 160)}'",
                                "ClickFix / fake-CAPTCHA social engineering: user is talked into Win+R / Run dialog paste of encoded PowerShell. " +
                                "Parent explorer + encoded command is the host trace. Kill-grade - that process is the attack.",
                                0.90, name, pid, path, parentName, parentPid,
                                SignalType.SuspiciousProcess, killGrade: true).ConfigureAwait(false);
                        }

                        if (CveCoverageHeuristics.IsMidiServiceProcess(name) &&
                            CveCoverageHeuristics.IsLolBinName(parentStem) == false)
                        {
                            if (!string.IsNullOrEmpty(path) &&
                                path!.IndexOf(@"\Windows\System32\", StringComparison.OrdinalIgnoreCase) < 0 &&
                                path.IndexOf(@"\Windows\SysWOW64\", StringComparison.OrdinalIgnoreCase) < 0)
                            {
                                await EmitAsync(
                                    "CVE Class: MIDI Service Module Hijack",
                                    $"midisrv (PID {pid}) running from '{path}' (not System32)",
                                    "Windows MIDI Service Module EoP (CVE-2026-62688): service image replaced or sideloaded outside System32.",
                                    0.90, name, pid, path, parentName, parentPid,
                                    SignalType.SecurityEvasion).ConfigureAwait(false);
                            }
                        }

                        if (CveCoverageHeuristics.IsLolBinName(name) &&
                            parentStem.Equals("mstsc", StringComparison.OrdinalIgnoreCase))
                        {
                            await EmitAsync(
                                "CVE Class: RDP Client Spawned LOLBin",
                                $"mstsc spawned '{name}' (PID {pid}) path='{path ?? "?"}'",
                                "Remote Desktop Client RCE class (CVE-2026-62824): RDP client should not spawn shells. " +
                                "Malicious .rdp / drive-redirection payload path.",
                                0.88, name, pid, path, parentName, parentPid,
                                SignalType.SuspiciousProcess).ConfigureAwait(false);
                        }

                        if (CveCoverageHeuristics.IsLolBinName(name) &&
                            (parentStem.Equals("CrossDeviceService", StringComparison.OrdinalIgnoreCase) ||
                             parentStem.Equals("PhoneExperienceHost", StringComparison.OrdinalIgnoreCase) ||
                             parentStem.IndexOf("CrossDevice", StringComparison.OrdinalIgnoreCase) >= 0))
                        {
                            await EmitAsync(
                                "CVE Class: Cross Device Service Spawn",
                                $"'{parentName}' spawned '{name}' (PID {pid})",
                                "Windows Cross Device Service EoP (CVE-2026-66804): nearby-share / Phone Link host spawning a LOLBin.",
                                0.85, name, pid, path, parentName, parentPid,
                                SignalType.SecurityEvasion).ConfigureAwait(false);
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

        private async Task EmitAsync(
            string rule, string evidence, string reasoning, double conf,
            string name, int pid, string? path, string parentName, int parentPid,
            SignalType signal, bool killGrade = false, TerminalFamily? family = null)
        {
            var key = rule + ":" + pid;
            if (!ShouldAlert(key)) return;

            var meta = new Dictionary<string, string>
            {
                ["ImagePath"] = path ?? "",
                ["ParentProcess"] = parentName,
                ["ParentPid"] = parentPid.ToString(),
                ["CveClass"] = "true",
            };
            if (!killGrade)
                meta["WeakObserveSeed"] = "true";

            await _detectionEngine.EmitAsync(new DetectionEvent
            {
                RuleName = rule,
                Evidence = evidence,
                Reasoning = reasoning,
                Confidence = conf,
                Tier = killGrade ? DetectionTier.Tier1Behavioral : DetectionTier.Tier2Indicator,
                AuthorizedResponse = killGrade ? ResponseAction.KillProcessTree : ResponseAction.LogOnly,
                ProcessName = name,
                ProcessId = pid,
                SignalType = signal,
                // Explicit terminal family when the caller declares one (only the kill-grade
                // Kernel Exploit Loader does today). Non-killGrade emits stay WeakObserveSeed=true
                // and classify null regardless, so leaving family null there preserves behavior.
                Family = family,
                Metadata = meta
            }).ConfigureAwait(false);
        }

        private bool ShouldAlert(string key)
        {
            var bucket = DateTime.UtcNow.Ticks / AlertCooldown.Ticks;
            var full = key + ":" + bucket;
            lock (_alerted)
            {
                if (_alerted.Contains(full)) return false;
                _alerted.Add(full);
                if (_alerted.Count > 800)
                    _alerted.Clear();
                return true;
            }
        }

        private static string? TryGetCommandLine(int pid)
        {
            try
            {
                using var searcher = new System.Management.ManagementObjectSearcher(
                    $"SELECT CommandLine FROM Win32_Process WHERE ProcessId = {pid}");
                foreach (System.Management.ManagementObject obj in searcher.Get())
                    return obj["CommandLine"]?.ToString();
            }
            catch { }
            return null;
        }

        private static string Truncate(string? s, int max)
        {
            if (string.IsNullOrEmpty(s)) return "";
            return s!.Length <= max ? s : s.Substring(0, max) + "...";
        }
    }

    /// <summary>
    /// MOTW / disk-image / AppInstaller delivery. Gamers drop ISOs in Downloads -
    /// LogOnly weak observe, never a kill seed.
    /// </summary>
    public sealed class MotwBypassMonitor : BackgroundService
    {
        private readonly DetectionEngine _detectionEngine;
        private readonly ILogger<MotwBypassMonitor> _logger;
        private readonly HashSet<string> _alerted = new(StringComparer.OrdinalIgnoreCase);
        private static readonly TimeSpan ScanInterval = TimeSpan.FromSeconds(40);
        private static readonly TimeSpan RecentWrite = TimeSpan.FromHours(6);

        public MotwBypassMonitor(DetectionEngine detectionEngine, ILogger<MotwBypassMonitor> logger)
        {
            _detectionEngine = detectionEngine;
            _logger = logger;
        }

        protected override async Task ExecuteAsync(CancellationToken ct)
        {
            _logger.LogInformation("[MotwBypassMonitor] Started - MOTW / ISO / AppInstaller delivery");
            try { await Task.Delay(TimeSpan.FromSeconds(20), ct).ConfigureAwait(false); }
            catch (OperationCanceledException) { return; }

            while (!ct.IsCancellationRequested)
            {
                try
                {
                    await ScanAsync(ct).ConfigureAwait(false);
                    await Task.Delay(ScanInterval, ct).ConfigureAwait(false);
                }
                catch (OperationCanceledException) when (ct.IsCancellationRequested) { break; }
                catch (Exception ex) { _logger.LogDebug(ex, "[MotwBypassMonitor] scan error"); }
            }
        }

        private async Task ScanAsync(CancellationToken ct)
        {
            var roots = GetUserDeliveryRoots();
            foreach (var root in roots)
            {
                if (ct.IsCancellationRequested) break;
                if (!Directory.Exists(root)) continue;

                IEnumerable<string> files;
                try
                {
                    files = Directory.EnumerateFiles(root, "*", SearchOption.TopDirectoryOnly);
                }
                catch { continue; }

                int n = 0;
                foreach (var file in files)
                {
                    if (ct.IsCancellationRequested) break;
                    if (++n > 80) break;
                    try
                    {
                        var info = new FileInfo(file);
                        if (!info.Exists) continue;
                        if (DateTime.UtcNow - info.LastWriteTimeUtc > RecentWrite) continue;

                        if (CveCoverageHeuristics.IsDiskImagePath(file))
                        {
                            if (HasZoneIdentifier(file))
                                continue;

                            await EmitFileAsync(
                                "CVE Class: Disk Image Missing Mark-of-the-Web",
                                $"Recently written disk image '{file}' ({info.Length} bytes) has no Zone.Identifier ADS",
                                "ISO/VHD in Downloads/Desktop without MOTW is a MOTW-bypass initial-access path " +
                                "(USB copy / inner-archive smuggle / CVE-2026-59125 VHD miniport class). " +
                                "Browser-stamped game ISOs are skipped. LogOnly, never a kill seed.",
                                0.68, file).ConfigureAwait(false);
                            continue;
                        }

                        var ext = Path.GetExtension(file);
                        if (ext.Equals(".vsix", StringComparison.OrdinalIgnoreCase))
                        {
                            await EmitFileAsync(
                                "CVE Class: VSIX in Delivery Folder",
                                $"VS Code extension package '{file}'",
                                "Unsigned/sideloaded VSIX from Downloads is a VS Code SFB delivery path (CVE-2026-58650 class).",
                                0.70, file).ConfigureAwait(false);
                            continue;
                        }

                        if (ext.Equals(".rdp", StringComparison.OrdinalIgnoreCase) ||
                            ext.Equals(".rdg", StringComparison.OrdinalIgnoreCase))
                        {
                            await EmitFileAsync(
                                "CVE Class: RDP File in Delivery Folder",
                                $"RDP connection file '{file}'",
                                "Malicious .rdp from email/Downloads is the Remote Desktop Client RCE delivery path (CVE-2026-62824).",
                                0.68, file).ConfigureAwait(false);
                            continue;
                        }

                        if (ext.Equals(".appinstaller", StringComparison.OrdinalIgnoreCase) ||
                            ext.Equals(".msix", StringComparison.OrdinalIgnoreCase) ||
                            ext.Equals(".msixbundle", StringComparison.OrdinalIgnoreCase) ||
                            ext.Equals(".appx", StringComparison.OrdinalIgnoreCase) ||
                            ext.Equals(".appxbundle", StringComparison.OrdinalIgnoreCase))
                        {
                            await EmitFileAsync(
                                "CVE Class: AppInstaller Package in Delivery Folder",
                                $"App Installer package '{file}'",
                                "ms-appinstaller / MSIX from Downloads is Windows Package Manager EoP delivery (CVE-2026-68821).",
                                0.74, file).ConfigureAwait(false);
                            continue;
                        }

                        if (CveCoverageHeuristics.IsPeExtension(file))
                        {
                            if (HasZoneIdentifier(file)) continue;

                            await EmitFileAsync(
                                "CVE Class: PE Missing Mark-of-the-Web",
                                $"Recently written PE '{file}' has no Zone.Identifier ADS",
                                "Browser downloads normally carry MOTW. A PE in Downloads/Desktop without Zone.Identifier " +
                                "is a MOTW-strip / ISO-smuggle / inner-archive drop. Local compiles rarely land here. LogOnly.",
                                0.72, file).ConfigureAwait(false);
                            continue;
                        }

                        if (CveCoverageHeuristics.IsScriptDropperExtension(file))
                        {
                            if (HasZoneIdentifier(file)) continue;

                            await EmitFileAsync(
                                "CVE Class: Script Dropper Missing Mark-of-the-Web",
                                $"Recently written script '{file}' has no Zone.Identifier ADS",
                                "Script-class droppers (.hta/.js/.vbs/.wsf/.ps1/.lnk/.chm) detonate via WSH/mshta " +
                                "without being a PE. A browser or archive extraction normally stamps MOTW; its absence " +
                                "in Downloads/Desktop is a drive-by / XSS-forced-download / archive-smuggle shape. LogOnly.",
                                0.70, file).ConfigureAwait(false);
                        }
                    }
                    catch (Exception ex)
                    {
                        _logger.LogDebug(ex, "[MotwBypassMonitor] file error {File}", file);
                    }
                }
            }
        }

        private async Task EmitFileAsync(string rule, string evidence, string reasoning, double conf, string file)
        {
            if (!ShouldAlert(rule + ":" + file)) return;
            var procName = Path.GetFileName(file) ?? "file";
            await _detectionEngine.EmitAsync(new DetectionEvent
            {
                RuleName = rule,
                Evidence = evidence,
                Reasoning = reasoning,
                Confidence = conf,
                Tier = DetectionTier.Tier2Indicator,
                AuthorizedResponse = ResponseAction.LogOnly,
                ProcessName = procName,
                ProcessId = 0,
                SignalType = SignalType.SuspiciousProcess,
                Metadata = new Dictionary<string, string>
                {
                    ["WeakObserveSeed"] = "true",
                    ["FilePath"] = file,
                    ["CveClass"] = "true",
                }
            }).ConfigureAwait(false);
        }

        private bool ShouldAlert(string key)
        {
            lock (_alerted)
            {
                if (_alerted.Contains(key)) return false;
                _alerted.Add(key);
                if (_alerted.Count > 400)
                    _alerted.Clear();
                return true;
            }
        }

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern uint GetFileAttributesW(string lpFileName);

        private const uint InvalidFileAttributes = 0xFFFFFFFF;

        internal static bool HasZoneIdentifier(string path)
        {
            if (string.IsNullOrWhiteSpace(path)) return false;
            try
            {
                var attrs = GetFileAttributesW(path + ":Zone.Identifier");
                return attrs != InvalidFileAttributes;
            }
            catch
            {
                return false;
            }
        }

        private static List<string> GetUserDeliveryRoots()
        {
            var roots = new List<string>();
            try
            {
                var users = Path.Combine(Environment.GetEnvironmentVariable("SystemDrive") ?? "C:", "Users");
                if (!Directory.Exists(users)) return roots;
                foreach (var dir in Directory.EnumerateDirectories(users))
                {
                    var leaf = Path.GetFileName(dir);
                    if (string.IsNullOrEmpty(leaf)) continue;
                    if (leaf.Equals("Public", StringComparison.OrdinalIgnoreCase) ||
                        leaf.Equals("Default", StringComparison.OrdinalIgnoreCase) ||
                        leaf.Equals("Default User", StringComparison.OrdinalIgnoreCase) ||
                        leaf.Equals("All Users", StringComparison.OrdinalIgnoreCase))
                        continue;
                    roots.Add(Path.Combine(dir, "Downloads"));
                    roots.Add(Path.Combine(dir, "Desktop"));
                    roots.Add(Path.Combine(dir, "AppData", "Local", "Temp"));
                }
            }
            catch { }
            return roots;
        }
    }

    public sealed class ContainerIsolationTamperMonitor : BackgroundService
    {
        private readonly DetectionEngine _detectionEngine;
        private readonly ILogger<ContainerIsolationTamperMonitor> _logger;
        private readonly HashSet<string> _alerted = new(StringComparer.OrdinalIgnoreCase);
        private static readonly TimeSpan ScanInterval = TimeSpan.FromSeconds(30);

        public ContainerIsolationTamperMonitor(
            DetectionEngine detectionEngine,
            ILogger<ContainerIsolationTamperMonitor> logger)
        {
            _detectionEngine = detectionEngine;
            _logger = logger;
        }

        protected override async Task ExecuteAsync(CancellationToken ct)
        {
            _logger.LogInformation("[ContainerIsolationTamperMonitor] Started - unionfs/wcifs + AlwaysInstallElevated");
            try { await Task.Delay(TimeSpan.FromSeconds(25), ct).ConfigureAwait(false); }
            catch (OperationCanceledException) { return; }

            while (!ct.IsCancellationRequested)
            {
                try
                {
                    await ScanDriversAsync().ConfigureAwait(false);
                    await ScanAlwaysInstallElevatedAsync().ConfigureAwait(false);
                    await Task.Delay(ScanInterval, ct).ConfigureAwait(false);
                }
                catch (OperationCanceledException) when (ct.IsCancellationRequested) { break; }
                catch (Exception ex) { _logger.LogDebug(ex, "[ContainerIsolationTamperMonitor] scan error"); }
            }
        }

        private async Task ScanDriversAsync()
        {
            var roots = new List<string>();
            try
            {
                roots.Add(Path.GetTempPath());
                var users = Path.Combine(Environment.GetEnvironmentVariable("SystemDrive") ?? "C:", "Users");
                if (Directory.Exists(users))
                {
                    foreach (var dir in Directory.EnumerateDirectories(users))
                    {
                        roots.Add(Path.Combine(dir, "Downloads"));
                        roots.Add(Path.Combine(dir, "Desktop"));
                        roots.Add(Path.Combine(dir, "AppData", "Local", "Temp"));
                    }
                }
            }
            catch { }

            foreach (var root in roots)
            {
                if (!Directory.Exists(root)) continue;
                IEnumerable<string> files;
                try { files = Directory.EnumerateFiles(root, "*.sys", SearchOption.TopDirectoryOnly); }
                catch { continue; }

                foreach (var file in files)
                {
                    if (!CveCoverageHeuristics.IsIsolationDriverName(file)) continue;
                    if (!ShouldAlert("drv:" + file)) continue;

                    await _detectionEngine.EmitAsync(new DetectionEvent
                    {
                        RuleName = "CVE Class: Isolation Filter Driver Staged",
                        Evidence = $"Container isolation / unionfs-class driver dropped at '{file}'",
                        Reasoning =
                            "Windows Container Isolation FS Filter Driver tampering (CVE-2026-72971, publicly disclosed). " +
                            "unionfs.sys / wcifs / bindflt in a user-writable path is staging for container-escape / host overwrite. " +
                            "Does not unload a Microsoft-signed inbox driver under System32\\drivers.",
                        Confidence = 0.91,
                        Tier = DetectionTier.Tier2Indicator,
                        AuthorizedResponse = ResponseAction.LogOnly,
                        ProcessName = Path.GetFileName(file) ?? "driver",
                        ProcessId = 0,
                        SignalType = SignalType.SecurityEvasion,
                        Metadata = new Dictionary<string, string>
                        {
                            ["WeakObserveSeed"] = "true",
                            ["FilePath"] = file,
                            ["CVE"] = CveCoverageHeuristics.CveUnionFs,
                            ["CveClass"] = "true",
                        }
                    }).ConfigureAwait(false);
                }
            }
        }

        private async Task ScanAlwaysInstallElevatedAsync()
        {
            try
            {
                bool machine = ReadAlwaysInstallElevated(Registry.LocalMachine);
                bool user = ReadAlwaysInstallElevated(Registry.CurrentUser);
                if (!machine && !user) return;
                if (!ShouldAlert("aie")) return;

                await _detectionEngine.EmitAsync(new DetectionEvent
                {
                    RuleName = "CVE Class: AlwaysInstallElevated Enabled",
                    Evidence = $"AlwaysInstallElevated HKLM={machine} HKCU={user}",
                    Reasoning =
                        "AlwaysInstallElevated lets any MSI run as SYSTEM - prerequisite for Windows Installer EoP " +
                        "(CVE-2026-61925 class, MITRE T1548.002). Sentinel hardening clears this; re-enablement is tamper. LogOnly.",
                    Confidence = 0.88,
                    Tier = DetectionTier.Tier2Indicator,
                    AuthorizedResponse = ResponseAction.LogOnly,
                    ProcessName = "SYSTEM",
                    ProcessId = 0,
                    SignalType = SignalType.SecurityEvasion,
                    Metadata = new Dictionary<string, string>
                    {
                        ["WeakObserveSeed"] = "true",
                        ["HKLM"] = machine ? "1" : "0",
                        ["HKCU"] = user ? "1" : "0",
                        ["CVE"] = CveCoverageHeuristics.CveInstallerEop,
                        ["CveClass"] = "true",
                    }
                }).ConfigureAwait(false);
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "[ContainerIsolationTamperMonitor] AlwaysInstallElevated");
            }
        }

        private static bool ReadAlwaysInstallElevated(RegistryKey hive)
        {
            try
            {
                using var k = hive.OpenSubKey(@"SOFTWARE\Policies\Microsoft\Windows\Installer");
                var v = k?.GetValue("AlwaysInstallElevated");
                return v is int i && i == 1;
            }
            catch { return false; }
        }

        private bool ShouldAlert(string key)
        {
            lock (_alerted)
            {
                if (_alerted.Contains(key)) return false;
                _alerted.Add(key);
                if (_alerted.Count > 200)
                    _alerted.Clear();
                return true;
            }
        }
    }

    public sealed class WpadProxyMonitor : BackgroundService
    {
        private readonly DetectionEngine _detectionEngine;
        private readonly ILogger<WpadProxyMonitor> _logger;
        private readonly HashSet<string> _alerted = new(StringComparer.OrdinalIgnoreCase);
        private static readonly TimeSpan ScanInterval = TimeSpan.FromSeconds(45);

        private string? _baselineAutoConfigUrl;
        private bool _baselineCaptured;

        private const string InternetSettingsPath =
            @"Software\Microsoft\Windows\CurrentVersion\Internet Settings";

        public WpadProxyMonitor(DetectionEngine detectionEngine, ILogger<WpadProxyMonitor> logger)
        {
            _detectionEngine = detectionEngine;
            _logger = logger;
        }

        protected override async Task ExecuteAsync(CancellationToken ct)
        {
            _logger.LogInformation("[WpadProxyMonitor] Started - WPAD / PAC auto-proxy (DHCP Option 252 vector)");
            try { await Task.Delay(TimeSpan.FromSeconds(15), ct).ConfigureAwait(false); }
            catch (OperationCanceledException) { return; }

            while (!ct.IsCancellationRequested)
            {
                try
                {
                    await ScanAsync().ConfigureAwait(false);
                    await Task.Delay(ScanInterval, ct).ConfigureAwait(false);
                }
                catch (OperationCanceledException) when (ct.IsCancellationRequested) { break; }
                catch (Exception ex) { _logger.LogDebug(ex, "[WpadProxyMonitor] scan error"); }
            }
        }

        private async Task ScanAsync()
        {
            string? autoConfigUrl = ReadAutoConfigUrl();

            if (!_baselineCaptured)
            {
                _baselineAutoConfigUrl = autoConfigUrl;
                _baselineCaptured = true;

                if (IsSuspiciousPacUrl(autoConfigUrl))
                {
                    await EmitAsync(
                        "WPAD Auto-Proxy PAC Configured",
                        $"AutoConfigURL present at startup: {Redact(autoConfigUrl)}",
                        "A Proxy Auto-Config (PAC) URL is set. PAC files are JavaScript the WinHTTP auto-proxy " +
                        "resolver executes to route traffic - the host-side landing point for the DHCP Option 252 / " +
                        "WPAD vector (CVE-2026-62755 DHCP client class). A remote or IP-literal PAC can MITM all " +
                        "browser traffic and leak visited hosts. Corporate PAC is legitimate; LogOnly.",
                        0.55, autoConfigUrl!);
                }
                return;
            }

            if (!string.Equals(autoConfigUrl, _baselineAutoConfigUrl, StringComparison.OrdinalIgnoreCase))
            {
                var conf = IsSuspiciousPacUrl(autoConfigUrl) ? 0.82 : 0.68;
                await EmitAsync(
                    "WPAD Auto-Proxy PAC Changed",
                    $"AutoConfigURL changed from '{Redact(_baselineAutoConfigUrl)}' to '{Redact(autoConfigUrl)}'",
                    "The Proxy Auto-Config URL was rewritten after Sentinel started. A rogue DHCP server (Option 252) " +
                    "or malware can point the WinHTTP/WinINET auto-proxy resolver at an attacker-controlled PAC - " +
                    "JavaScript that reroutes every browser through a MITM proxy. Unexpected PAC changes are a strong " +
                    "network-hijack indicator. Does not revert the setting; LogOnly + chain fuel.",
                    conf, autoConfigUrl ?? "(cleared)");
                _baselineAutoConfigUrl = autoConfigUrl;
            }

            if (IsAutoDetectEnabled() && IsSuspiciousPacUrl(autoConfigUrl))
            {
                await EmitAsync(
                    "WPAD Auto-Detect With Remote PAC",
                    "WPAD auto-detect is enabled and a remote/IP-literal PAC URL is configured",
                    "Automatic proxy discovery (WPAD) plus a remote PAC URL is the complete DHCP/DNS WPAD hijack shape. " +
                    "An attacker on the LAN can answer WPAD and serve routing JavaScript. Recommend disabling " +
                    "'Automatically detect settings' unless a trusted corporate PAC requires it. LogOnly.",
                    0.78, autoConfigUrl ?? "wpad");
            }
        }

        private async Task EmitAsync(string rule, string evidence, string reasoning, double conf, string key)
        {
            if (!ShouldAlert(rule + ":" + key)) return;
            await _detectionEngine.EmitAsync(new DetectionEvent
            {
                RuleName = rule,
                Evidence = evidence,
                Reasoning = reasoning,
                Confidence = conf,
                Tier = DetectionTier.Tier2Indicator,
                AuthorizedResponse = ResponseAction.LogOnly,
                ProcessName = "SYSTEM",
                ProcessId = 0,
                SignalType = SignalType.SecurityEvasion,
                Metadata = new Dictionary<string, string>
                {
                    ["WeakObserveSeed"] = "true",
                    ["Vector"] = "WPAD/PAC",
                    ["CVE"] = CveCoverageHeuristics.CveDhcpClient,
                    ["CveClass"] = "true",
                    // Root observation = the PAC URL. All WPAD signals about the same PAC config
                    // share this key, so they cannot stack into multiple independent vectors.
                    [BehavioralCorrelationEngine.ObservationKeyMeta] = $"wpad:{key}",
                }
            }).ConfigureAwait(false);
        }

        private static string? ReadAutoConfigUrl()
        {
            try
            {
                using var k = Registry.CurrentUser.OpenSubKey(InternetSettingsPath);
                var v = k?.GetValue("AutoConfigURL") as string;
                return string.IsNullOrWhiteSpace(v) ? null : v!.Trim();
            }
            catch { return null; }
        }

        private static bool IsSuspiciousPacUrl(string? url)
        {
            if (string.IsNullOrWhiteSpace(url)) return false;
            var u = url!.Trim();
            if (u.StartsWith("file:", StringComparison.OrdinalIgnoreCase)) return false;

            bool remote = u.StartsWith("http://", StringComparison.OrdinalIgnoreCase)
                          || u.StartsWith("https://", StringComparison.OrdinalIgnoreCase);
            if (!remote) return false;

            bool plainHttp = u.StartsWith("http://", StringComparison.OrdinalIgnoreCase);
            bool ipLiteral = System.Text.RegularExpressions.Regex.IsMatch(
                u, @"^https?://\d{1,3}(\.\d{1,3}){3}",
                System.Text.RegularExpressions.RegexOptions.IgnoreCase);

            return plainHttp || ipLiteral || remote;
        }

        private static bool IsAutoDetectEnabled()
        {
            try
            {
                using var k = Registry.CurrentUser.OpenSubKey(
                    InternetSettingsPath + @"\Connections");
                if (k?.GetValue("DefaultConnectionSettings") is byte[] blob && blob.Length > 8)
                {
                    return (blob[8] & 0x08) != 0;
                }
            }
            catch { }
            return false;
        }

        private static string Redact(string? url)
        {
            if (string.IsNullOrWhiteSpace(url)) return "(none)";
            var u = url!.Trim();
            return u.Length <= 120 ? u : u.Substring(0, 120) + "...";
        }

        private bool ShouldAlert(string key)
        {
            lock (_alerted)
            {
                if (_alerted.Contains(key)) return false;
                _alerted.Add(key);
                if (_alerted.Count > 200)
                    _alerted.Clear();
                return true;
            }
        }
    }
}
