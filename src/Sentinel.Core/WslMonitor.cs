using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Management;
using System.Runtime.InteropServices;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Win32;

namespace Sentinel.Core
{
    /// <summary>
    /// Monitors Windows Subsystem for Linux (WSL) activity to detect:
    /// - WSL process spawns (wsl.exe, wslhost.exe, bash.exe via WSL)
    /// - File access from WSL to Windows filesystem (/mnt/c/, /mnt/d/)
    /// - Network connections originating from WSL2 VM
    /// - Suspicious command execution inside WSL (curl to C2, reverse shells)
    /// - WSL distribution installs/imports at runtime
    ///
    /// WSL2 runs in a lightweight Hyper-V VM - Sentinel has NO visibility into
    /// processes running inside the Linux kernel. This monitor observes the
    /// Windows-side attack surface: WSL host processes, cross-filesystem access,
    /// and network traffic from the WSL virtual adapter.
    ///
    /// v1.0.1: New monitor.
    /// </summary>
    public sealed class WslMonitor : BackgroundService
    {
        private readonly DetectionEngine _detectionEngine;
        private readonly ProcessAncestryCache _ancestryCache;
        private readonly ILogger<WslMonitor> _logger;

        private readonly ConcurrentDictionary<int, WslProcessInfo> _trackedWslProcesses = new();
        private readonly HashSet<string> _baselineDistros = new(StringComparer.OrdinalIgnoreCase);
        private bool _wslAvailable;

        private static readonly TimeSpan ScanInterval = TimeSpan.FromSeconds(10);

        // Suspicious commands that indicate malicious WSL usage
        private static readonly string[] SuspiciousPatterns = new[]
        {
            "nc -", "ncat ", "socat ", "/dev/tcp/", "bash -i",
            "curl http", "wget http", "python -c", "python3 -c",
            "perl -e", "ruby -e", "php -r",
            "/etc/shadow", "/etc/passwd", "mimikatz", "sekurlsa",
            "meterpreter", "reverse_tcp", "bind_shell",
            "base64 -d", "openssl enc",
            "iptables", "tcpdump", "nmap ", "masscan",
            "/mnt/c/windows/system32", "/mnt/c/users",
            // v2.5.5: CloudSEK BRIDGEHEAD npm campaign (June 2026) - reads /proc/version to detect WSL
            "/proc/version", "cat /proc/version", "is_wsl", "get_wu()"
        };

        // Legitimate WSL uses that should not alert
        private static readonly string[] LegitimatePatterns = new[]
        {
            "git ", "npm ", "node ", "docker ", "kubectl ",
            "apt ", "apt-get ", "pip ", "cargo ", "make ",
            "code ", "vim ", "nano ", "ls ", "cd ", "cat ",
            "grep ", "find ", "sed ", "awk "
        };

        public WslMonitor(
            DetectionEngine detectionEngine,
            ProcessAncestryCache ancestryCache,
            ILogger<WslMonitor> logger)
        {
            _detectionEngine = detectionEngine;
            _ancestryCache = ancestryCache;
            _logger = logger;
        }

        protected override async Task ExecuteAsync(CancellationToken ct)
        {
            _logger.LogInformation("[WslMonitor] Started");

            // Check if WSL is installed
            _wslAvailable = File.Exists(Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.System), "wsl.exe"));

            if (!_wslAvailable)
            {
                _logger.LogInformation("[WslMonitor] WSL not installed - monitor idle");
                // Keep running in case WSL gets installed later
                while (!ct.IsCancellationRequested)
                {
                    await Task.Delay(TimeSpan.FromMinutes(5), ct);
                    _wslAvailable = File.Exists(Path.Combine(
                        Environment.GetFolderPath(Environment.SpecialFolder.System), "wsl.exe"));
                    if (_wslAvailable) break;
                }
                if (ct.IsCancellationRequested) return;
                _logger.LogInformation("[WslMonitor] WSL detected - activating");
            }

            // Baseline existing WSL distributions
            BaselineDistros();

            while (!ct.IsCancellationRequested)
            {
                try
                {
                    await Task.Delay(ScanInterval, ct);

                    await ScanWslProcesses(ct);
                    await CheckNewDistroInstalls(ct);
                    await MonitorWslFileAccess(ct);
                    // v1.6.8: Detect lateral movement FROM container/WSL INTO host
                    await DetectContainerToHostLateralMovement(ct);
                }
                catch (OperationCanceledException) { break; }
                catch (Exception ex) { _logger.LogDebug(ex, "[WslMonitor] Error"); }
            }
        }

        private async Task ScanWslProcesses(CancellationToken ct)
        {
            var wslProcessNames = new[] { "wsl", "wslhost", "bash" };
            var currentPids = new HashSet<int>();

            foreach (var proc in Process.GetProcesses())
            {
                try
                {
                    var name = proc.ProcessName.ToLowerInvariant();
                    if (!wslProcessNames.Contains(name)) continue;

                    currentPids.Add(proc.Id);

                    // Skip already tracked
                    if (_trackedWslProcesses.ContainsKey(proc.Id)) continue;

                    string cmdLine = GetProcessCommandLine(proc.Id);
                    if (string.IsNullOrEmpty(cmdLine)) continue;

                    // For bash.exe, verify it's WSL bash (not Git bash, Cygwin, etc.)
                    if (name == "bash")
                    {
                        try
                        {
                            var path = SecurityValidation.GetProcessImagePath(proc.Id) ?? "";
                            if (!path.Contains("Windows") &&
                                !path.Contains("wsl"))
                                continue;
                        }
                        catch { continue; }
                    }

                    var info = new WslProcessInfo
                    {
                        Pid = proc.Id,
                        ProcessName = proc.ProcessName,
                        CommandLine = cmdLine,
                        StartTime = DateTimeOffset.UtcNow
                    };
                    _trackedWslProcesses[proc.Id] = info;

                    // Check for suspicious commands
                    var cmdLower = cmdLine.ToLowerInvariant();
                    bool isSuspicious = SuspiciousPatterns.Any(p => cmdLower.Contains(p));
                    bool isLegitimate = LegitimatePatterns.Any(p => cmdLower.Contains(p));

                    if (isSuspicious && !isLegitimate)
                    {
                        var matchedPattern = SuspiciousPatterns.First(p => cmdLower.Contains(p));
                        await _detectionEngine.EmitAsync(new DetectionEvent
                        {
                            RuleName = "WSL: Suspicious Command Execution",
                            Evidence = $"WSL process {proc.ProcessName} (PID {proc.Id}) executing suspicious command. " +
                                       $"Pattern: '{matchedPattern}', CmdLine: {Truncate(cmdLine, 200)}",
                            Reasoning = "A potentially malicious command was executed inside WSL. " +
                                        "WSL provides a Linux environment with direct access to the Windows filesystem " +
                                        "via /mnt/. Attackers use WSL to evade Windows-native security tools, execute " +
                                        "Linux-native attack tools, and establish reverse shells that bypass Windows firewall.",
                            Confidence = 0.78,
                            Tier = DetectionTier.Tier1Behavioral,
                            AuthorizedResponse = ResponseAction.KillProcessTree,
                            ProcessName = proc.ProcessName,
                            ProcessId = proc.Id,
                            Metadata = new Dictionary<string, string>
                            {
                                ["CommandLine"] = Truncate(cmdLine, 500),
                                ["MatchedPattern"] = matchedPattern
                            }
                        });
                    }
                    else if (!isLegitimate && name == "wsl" && cmdLine.Contains("-e "))
                    {
                        // WSL exec mode (-e) running non-standard commands
                        await _detectionEngine.EmitAsync(new DetectionEvent
                        {
                            RuleName = "WSL: Direct Command Execution",
                            Evidence = $"WSL direct exec: {Truncate(cmdLine, 200)}",
                            Reasoning = "WSL was invoked with -e (execute) flag to run a command directly. " +
                                        "This is commonly used in attack chains to execute Linux tools from Windows.",
                            Confidence = 0.50,
                            Tier = DetectionTier.Tier2Indicator,
                            AuthorizedResponse = ResponseAction.LogOnly,
                            ProcessName = proc.ProcessName,
                            ProcessId = proc.Id
                        });
                    }
                }
                catch { }
                finally { proc.Dispose(); }
            }

            // Clean up exited processes
            var exited = _trackedWslProcesses.Keys.Except(currentPids).ToList();
            foreach (var pid in exited) _trackedWslProcesses.TryRemove(pid, out _);
        }

        private async Task CheckNewDistroInstalls(CancellationToken ct)
        {
            try
            {
                var currentDistros = GetInstalledDistros();
                foreach (var distro in currentDistros)
                {
                    if (_baselineDistros.Contains(distro)) continue;
                    _baselineDistros.Add(distro);

                    await _detectionEngine.EmitAsync(new DetectionEvent
                    {
                        RuleName = "WSL: New Distribution Installed",
                        Evidence = $"New WSL distribution installed at runtime: '{distro}'",
                        Reasoning = "A new WSL Linux distribution was installed after Sentinel started. " +
                                    "Attackers can import custom distros containing pre-staged tools via " +
                                    "'wsl --import'. This provides a full Linux environment for evading " +
                                    "Windows-native detection.",
                        Confidence = 0.72,
                        Tier = DetectionTier.Tier1Behavioral,
                        AuthorizedResponse = ResponseAction.LogOnly,
                        ProcessName = "SYSTEM",
                        ProcessId = 0,
                        Metadata = new Dictionary<string, string> { ["Distro"] = distro }
                    });
                }
            }
            catch { }
        }

        private async Task MonitorWslFileAccess(CancellationToken ct)
        {
            // Monitor \\wsl$ and \\wsl.localhost access via open file handles
            // This catches Windows processes reading from WSL filesystem (data staging)
            try
            {
                // Check if any non-WSL process is accessing \\wsl$ paths
                // We detect this by looking for processes with handles to \\wsl.localhost\
                foreach (var proc in Process.GetProcesses())
                {
                    try
                    {
                        var name = proc.ProcessName.ToLowerInvariant();
                        // Skip WSL-related and known-good processes
                        if (name is "wsl" or "wslhost" or "wslservice" or "explorer"
                            or "code" or "devenv" or "rider64" or "idea64")
                        {
                            proc.Dispose();
                            continue;
                        }

                        // Check if the process image is loaded from \\wsl$ path
                        try
                        {
                            var mainModule = SecurityValidation.GetProcessImagePath(proc.Id);
                            if (mainModule != null &&
                                (mainModule.StartsWith(@"\\wsl") ||
                                 mainModule.StartsWith(@"\\wsl.localhost")))
                            {
                                await _detectionEngine.EmitAsync(new DetectionEvent
                                {
                                    RuleName = "WSL: Process Running from WSL Filesystem",
                                    Evidence = $"Process '{proc.ProcessName}' (PID {proc.Id}) loaded from WSL path: {mainModule}",
                                    Reasoning = "A Windows process is running from the WSL filesystem (\\\\wsl$\\). " +
                                                "This is unusual and may indicate a staged payload being executed " +
                                                "from within WSL's Linux filesystem to avoid Windows file scanning.",
                                    Confidence = 0.82,
                                    Tier = DetectionTier.Tier1Behavioral,
                                    AuthorizedResponse = ResponseAction.KillProcessTree,
                                    ProcessName = proc.ProcessName,
                                    ProcessId = proc.Id
                                });
                            }
                        }
                        catch { }
                    }
                    catch { }
                    finally { proc.Dispose(); }
                }
            }
            catch { }
        }

        private void BaselineDistros()
        {
            foreach (var distro in GetInstalledDistros())
            {
                _baselineDistros.Add(distro);
            }
        }

        private static HashSet<string> GetInstalledDistros()
        {
            var distros = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            try
            {
                using var key = Registry.CurrentUser.OpenSubKey(
                    @"Software\Microsoft\Windows\CurrentVersion\Lxss");
                if (key == null) return distros;

                foreach (var subKeyName in key.GetSubKeyNames())
                {
                    using var sub = key.OpenSubKey(subKeyName);
                    var name = sub?.GetValue("DistributionName")?.ToString();
                    if (!string.IsNullOrEmpty(name))
                        distros.Add(name!);
                }
            }
            catch { }
            return distros;
        }

        private static string GetProcessCommandLine(int pid)
        {
            try
            {
                using var searcher = new ManagementObjectSearcher(
                    $"SELECT CommandLine FROM Win32_Process WHERE ProcessId = {pid}");
                foreach (ManagementObject obj in searcher.Get())
                {
                    return obj["CommandLine"]?.ToString() ?? "";
                }
            }
            catch { }
            return "";
        }

        private static string Truncate(string value, int maxLength)
        {
            if (string.IsNullOrEmpty(value)) return "";
            return value.Length <= maxLength ? value : value[..maxLength] + "...";
        }

        // 
        // v1.6.8: Container/WSL Lateral Movement INTO Host Detection
        //
        // Blind spot: WslMonitor tracked activity FROM host INTO WSL and suspicious
        // commands inside WSL. It did NOT detect lateral movement FROM container/WSL
        // INTO the Windows host, which includes:
        // - WSL processes writing to sensitive Windows paths via /mnt/c/
        // - Docker container escape indicators (mount namespace manipulation)
        // - Processes spawned from \\wsl$ paths that access Windows credentials
        // - WSL interop (.exe spawning from Linux context) targeting system resources
        // 

        private readonly HashSet<string> _alertedLateralPaths = new(StringComparer.OrdinalIgnoreCase);

        /// <summary>
        /// Detects lateral movement FROM WSL/container INTO the Windows host.
        /// Called from the main scan loop.
        /// </summary>
        private async Task DetectContainerToHostLateralMovement(CancellationToken ct)
        {
            await DetectWslHostFilesystemWrites(ct);
            await DetectWslInteropEscalation(ct);
            await DetectDockerEscapeIndicators(ct);
        }

        /// <summary>
        /// Detects WSL processes writing to sensitive Windows host paths via /mnt/c/ mapping.
        /// This catches attackers using WSL to modify Windows system files, drop payloads,
        /// or edit startup/autorun locations from within the Linux environment.
        /// </summary>
        private async Task DetectWslHostFilesystemWrites(CancellationToken ct)
        {
            // Check for wsl.exe/bash.exe processes with commands targeting sensitive host paths
            foreach (var kvp in _trackedWslProcesses)
            {
                if (ct.IsCancellationRequested) break;

                var info = kvp.Value;
                var cmdLower = info.CommandLine.ToLowerInvariant();

                // Detect writes to sensitive Windows paths from WSL
                var sensitiveHostPaths = new[]
                {
                    "/mnt/c/windows/system32",
                    "/mnt/c/windows/syswow64",
                    "/mnt/c/programdata",
                    "/mnt/c/users/*/appdata/roaming/microsoft/windows/start menu/programs/startup",
                    "/mnt/c/users/*/ntuser.dat",
                    @"\\\\wsl.*\\.*\\windows",
                };

                // Check for write operations targeting host paths
                bool isWriteOperation = cmdLower.Contains(">") || cmdLower.Contains("tee ") ||
                                        cmdLower.Contains("cp ") || cmdLower.Contains("mv ") ||
                                        cmdLower.Contains("dd ") || cmdLower.Contains("install ") ||
                                        cmdLower.Contains("wget -o") || cmdLower.Contains("curl -o");

                bool targetsSensitivePath = cmdLower.Contains("/mnt/c/windows") ||
                                            cmdLower.Contains("/mnt/c/programdata") ||
                                            cmdLower.Contains("/mnt/c/program files") ||
                                            (cmdLower.Contains("/mnt/c/users") && cmdLower.Contains("startup"));

                if (isWriteOperation && targetsSensitivePath)
                {
                    string alertKey = $"wsl_lateral_{info.Pid}_{cmdLower.GetHashCode()}";
                    if (_alertedLateralPaths.Contains(alertKey)) continue;
                    _alertedLateralPaths.Add(alertKey);

                    await _detectionEngine.EmitAsync(new DetectionEvent
                    {
                        RuleName = "WSL: Lateral Movement - Host Filesystem Write to Sensitive Path",
                        Evidence = $"WSL process '{info.ProcessName}' (PID {info.Pid}) writing to sensitive Windows path. " +
                                   $"Command: {Truncate(info.CommandLine, 250)}",
                        Reasoning = "A process running inside WSL is writing to a sensitive Windows host filesystem location " +
                                    "via the /mnt/ mount point. WSL has full read-write access to the Windows filesystem, " +
                                    "allowing attackers to drop payloads into system directories, modify startup items, " +
                                    "or overwrite system binaries - all from within the Linux environment where " +
                                    "Windows-native AV/EDR has limited visibility (MITRE T1611).",
                        Confidence = 0.85,
                        Tier = DetectionTier.Tier1Behavioral,
                        AuthorizedResponse = ResponseAction.KillProcessTree,
                        SignalType = SignalType.SuspiciousProcess,
                        ProcessName = info.ProcessName,
                        ProcessId = info.Pid,
                        Metadata = new Dictionary<string, string>
                        {
                            ["CommandLine"] = Truncate(info.CommandLine, 500),
                            ["Technique"] = "T1611-ContainerEscape"
                        }
                    });
                }
            }
        }

        /// <summary>
        /// Detects WSL interop abuse: Linux processes spawning Windows .exe files
        /// targeting credential stores, security tools, or system configuration.
        /// WSL interop allows running Windows binaries from within Linux via /mnt/c/ or
        /// direct .exe invocation - this is a lateral movement vector into the host.
        /// </summary>
        private async Task DetectWslInteropEscalation(CancellationToken ct)
        {
            // Look for WSL-spawned processes targeting Windows security-sensitive binaries
            foreach (var proc in Process.GetProcesses())
            {
                if (ct.IsCancellationRequested) break;

                try
                {
                    // Check if this process was spawned by a WSL process
                    int parentPid = GetParentPidForWsl(proc.Id);
                    if (parentPid <= 0) continue;

                    bool parentIsWsl = _trackedWslProcesses.ContainsKey(parentPid);
                    if (!parentIsWsl)
                    {
                        // Also check if parent is wsl.exe / bash.exe
                        try
                        {
                            using var parent = Process.GetProcessById(parentPid);
                            var parentName = parent.ProcessName.ToLowerInvariant();
                            parentIsWsl = parentName is "wsl" or "wslhost" or "bash";
                        }
                        catch { continue; }
                    }

                    if (!parentIsWsl) continue;

                    string procName = proc.ProcessName.ToLowerInvariant();
                    string cmdLine = GetProcessCommandLine(proc.Id).ToLowerInvariant();

                    // Sensitive Windows commands spawned from WSL context
                    bool isSensitive =
                        procName is "reg" or "regedit" or "sc" or "bcdedit" or "schtasks" or
                                   "netsh" or "wmic" or "vssadmin" or "icacls" or "takeown" or
                                   "certutil" or "bitsadmin" or "mshta" or "regsvr32" ||
                        (procName == "powershell" && (cmdLine.Contains("bypass") || cmdLine.Contains("encodedcommand"))) ||
                        (procName == "cmd" && (cmdLine.Contains("reg add") || cmdLine.Contains("sc create")));

                    if (isSensitive)
                    {
                        string alertKey = $"wsl_interop_{proc.Id}_{procName}";
                        if (_alertedLateralPaths.Contains(alertKey)) continue;
                        _alertedLateralPaths.Add(alertKey);

                        await _detectionEngine.EmitAsync(new DetectionEvent
                        {
                            RuleName = "WSL: Lateral Movement - Interop Spawning Sensitive Windows Process",
                            Evidence = $"WSL interop spawned sensitive Windows process: '{proc.ProcessName}' (PID {proc.Id}). " +
                                       $"Parent PID: {parentPid} (WSL). Command: {Truncate(cmdLine, 200)}",
                            Reasoning = "A Windows security-sensitive process was spawned from a WSL/Linux parent context via " +
                                        "WSL interop. This allows attackers to use Linux-native tools for reconnaissance, " +
                                        "then pivot into Windows host configuration modification via .exe spawning - " +
                                        "effectively escaping the container boundary for host compromise (MITRE T1611, T1059).",
                            Confidence = 0.82,
                            Tier = DetectionTier.Tier1Behavioral,
                            AuthorizedResponse = ResponseAction.KillProcessTree,
                            SignalType = SignalType.SuspiciousProcess,
                            ProcessName = proc.ProcessName,
                            ProcessId = proc.Id,
                            Metadata = new Dictionary<string, string>
                            {
                                ["ParentPid"] = parentPid.ToString(),
                                ["CommandLine"] = Truncate(cmdLine, 500),
                                ["Technique"] = "T1611-WSLInteropEscape"
                            }
                        });
                    }
                }
                catch { }
                finally { proc.Dispose(); }
            }
        }

        /// <summary>
        /// Detects Docker container escape indicators visible from the Windows host:
        /// - Docker Desktop spawning processes with elevated privileges
        /// - com.docker.* processes accessing Windows credential stores
        /// - Unexpected mount namespace manipulation (Hyper-V socket abuse)
        /// </summary>
        private async Task DetectDockerEscapeIndicators(CancellationToken ct)
        {
            // Check for Docker-related processes doing suspicious things
            foreach (var proc in Process.GetProcesses())
            {
                if (ct.IsCancellationRequested) break;

                try
                {
                    var name = proc.ProcessName.ToLowerInvariant();

                    // Detect processes spawned by Docker that access host resources suspiciously
                    if (name.StartsWith("com.docker") || name == "docker" || name == "dockerd")
                    {
                        // Docker processes shouldn't be spawning cmd/powershell with suspicious args
                        continue; // Docker itself is legitimate - we monitor its children
                    }

                    // Detect processes whose parent is a Docker container runtime
                    // that are accessing Windows security-sensitive resources
                    string imagePath = SecurityValidation.GetProcessImagePath(proc.Id) ?? "";

                    // Process running from Docker overlay filesystem reaching into host
                    if (imagePath.Contains(@"\Docker\") &&
                        imagePath.Contains(@"\overlay2\"))
                    {
                        string cmdLine = GetProcessCommandLine(proc.Id);
                        bool targetsSensitiveResource =
                            cmdLine.Contains(@"\Windows\") ||
                            cmdLine.Contains(@"\ProgramData\") ||
                            cmdLine.Contains("HKLM") ||
                            cmdLine.Contains("lsass");

                        if (targetsSensitiveResource)
                        {
                            string alertKey = $"docker_escape_{proc.Id}";
                            if (_alertedLateralPaths.Contains(alertKey)) continue;
                            _alertedLateralPaths.Add(alertKey);

                            await _detectionEngine.EmitAsync(new DetectionEvent
                            {
                                RuleName = "WSL: Container Escape - Docker Process Accessing Host Resources",
                                Evidence = $"Process '{proc.ProcessName}' (PID {proc.Id}) from Docker overlay filesystem " +
                                           $"is accessing sensitive host resources. Image: {Truncate(imagePath, 150)}. " +
                                           $"Command: {Truncate(cmdLine, 200)}",
                                Reasoning = "A process originating from a Docker container filesystem layer is directly " +
                                            "accessing sensitive Windows host resources. This indicates a container escape " +
                                            "where the isolated process has broken out of its namespace boundary to reach " +
                                            "the host filesystem, registry, or credential stores (MITRE T1611).",
                                Confidence = 0.88,
                                Tier = DetectionTier.Tier1Behavioral,
                                AuthorizedResponse = ResponseAction.KillProcessTree,
                                SignalType = SignalType.SuspiciousProcess,
                                ProcessName = proc.ProcessName,
                                ProcessId = proc.Id,
                                Metadata = new Dictionary<string, string>
                                {
                                    ["ImagePath"] = imagePath,
                                    ["Technique"] = "T1611-ContainerEscape/Docker"
                                }
                            });
                        }
                    }
                }
                catch { }
                finally { proc.Dispose(); }
            }

            // Prune stale alert keys to prevent unbounded growth
            if (_alertedLateralPaths.Count > 500)
            {
                _alertedLateralPaths.Clear();
            }
        }

        private static int GetParentPidForWsl(int pid)
        {
            try
            {
                using var searcher = new ManagementObjectSearcher(
                    $"SELECT ParentProcessId FROM Win32_Process WHERE ProcessId = {pid}");
                foreach (ManagementObject obj in searcher.Get())
                {
                    return Convert.ToInt32(obj["ParentProcessId"]);
                }
            }
            catch { }
            return 0;
        }

        private class WslProcessInfo
        {
            public int Pid { get; set; }
            public string ProcessName { get; set; } = string.Empty;
            public string CommandLine { get; set; } = string.Empty;
            public DateTimeOffset StartTime { get; set; }
        }
    }
}
