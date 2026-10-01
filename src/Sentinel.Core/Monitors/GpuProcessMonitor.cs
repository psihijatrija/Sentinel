// GPU Process Anomaly Monitor - detects hardware acceleration exploitation and GPU sandbox escapes
// v2.1.5: New monitor. SystemIntegrity Group.
//
// Threat model:
//   Browser GPU processes (chrome --type=gpu-process, msedge --gpu-process, etc.) are sandboxed
//   helpers that should NEVER: spawn child processes, open network connections, touch LSASS,
//   write registry, or load unexpected DLLs. If they do, it means a WebGL/WebGPU exploit
//   achieved sandbox escape - the most dangerous browser attack chain.
//
//   Additionally, outdated GPU drivers with known privilege-escalation CVEs are flagged
//   as Tier2 informational alerts so users know to update.
//
//   This monitor does NOT interfere with normal GPU operation (gaming, video, compute).
//   It only watches for post-exploitation indicators from browser GPU helper processes.

using System;
using System.Collections.Concurrent;
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
    /// Monitors browser GPU processes for sandbox escape indicators and audits
    /// GPU driver versions against known-vulnerable ranges.
    ///
    /// Detection approach:
    ///   1. Enumerate browser GPU helper processes (--type=gpu-process)
    ///   2. Detect child process spawning from GPU helpers (sandbox escape)
    ///   3. Detect network connections owned by GPU helper PIDs (data exfil / C2)
    ///   4. Detect suspicious DLL loads in GPU processes (post-exploitation tooling)
    ///   5. Periodic GPU driver version audit against known-vulnerable CVE ranges
    ///
    /// Response:
    ///   - GPU helper spawning child process -> KillProcessTree (Tier1, 0.95)
    ///   - GPU helper with outbound network connections -> KillProcessTree (Tier1, 0.92)
    ///   - GPU helper with suspicious DLL -> LogOnly (Tier1, 0.80) - needs corroboration
    ///   - Vulnerable GPU driver version -> LogOnly (Tier2, 0.70) - informational
    ///
    /// Scans every 20s for process anomalies, every 6h for driver audit.
    /// Does NOT touch gaming, video playback, or GPU compute workloads.
    /// </summary>
    public sealed class GpuProcessMonitor : BackgroundService
    {
        private readonly DetectionEngine _detectionEngine;
        private readonly ILogger<GpuProcessMonitor> _logger;

        private readonly ConcurrentDictionary<int, DateTimeOffset> _alertedPids = new();
        private readonly HashSet<string> _alertedDriverVersions = new(StringComparer.OrdinalIgnoreCase);

        private static readonly TimeSpan ScanInterval = TimeSpan.FromSeconds(20);
        private static readonly TimeSpan DriverAuditInterval = TimeSpan.FromHours(6);
        private static readonly TimeSpan AlertCooldown = TimeSpan.FromMinutes(10);

        private DateTime _lastDriverAudit = DateTime.MinValue;

        // Browser GPU process identifiers - these are the sandboxed GPU helpers
        private static readonly HashSet<string> BrowserProcessNames = new(StringComparer.OrdinalIgnoreCase)
        {
            "chrome", "msedge", "brave", "vivaldi", "opera", "chromium",
            "firefox", "waterfox", "librewolf"
        };

        // DLLs that should NEVER appear in a legitimate GPU helper process
        private static readonly HashSet<string> SuspiciousDllsInGpuProcess = new(StringComparer.OrdinalIgnoreCase)
        {
            "amsi.dll",          // AMSI - why would GPU process need this? Indicates script eval
            "clr.dll",           // .NET CLR - GPU process shouldn't load managed code
            "clrjit.dll",        // .NET JIT - same
            "mscorlib.ni.dll",   // .NET managed - same
            "powershell.exe",    // Should not be loaded as DLL/module
            "vaultcli.dll",      // Credential vault access
            "samlib.dll",        // SAM database access
            "wdigest.dll",       // Credential harvesting
            "dbghelp.dll",       // Debugging - post-exploitation indicator
            "dbgcore.dll",       // Debugging
            "winhttp.dll",       // HTTP client - GPU process uses raw sockets via driver, not WinHTTP
            "urlmon.dll",        // URL moniker - shouldn't be in GPU sandbox
            "jscript.dll",       // JavaScript engine - not in GPU process
            "vbscript.dll",      // VBScript - definitely not
            "scrrun.dll",        // Scripting runtime
            "wbemdisp.dll",      // WMI scripting
            "netapi32.dll",      // Network management APIs - not for GPU
        };

        // Known vulnerable GPU driver version ranges (NVIDIA), keyed to the BRANDED driver
        // version (e.g. "552.22"), not the 4-part Windows driver version. The Win32_VideoController
        // DriverVersion form (e.g. "31.0.15.5222") is normalized to the branded form by
        // NormalizeNvidiaVersion() before range matching - see GetNvidiaDriverVersion().
        //
        // Sources (NVIDIA GPU Display Driver security bulletins, 2025):
        //   - Jan 2025 bulletin (5586): fixes across the R565/R550/R535 branches.
        //   - Oct 2025 bulletin (5703) + the June/2025 kernel-mode driver batch
        //     (CVE-2025-23244/23281/33218 etc., nvlddmkm.sys) fixed at 580.88 / 573.x.
        // Ranges are inclusive lower bound, inclusive upper bound of the LAST vulnerable build;
        // update the MaxVersion to just-below the fixed build as new bulletins land.
        // Format: (minVersion, maxVersion, cveId, description)
        private static readonly List<VulnerableDriverRange> NvidiaVulnerableRanges = new()
        {
            // June 2025 kernel-mode driver (nvlddmkm.sys) LPE/UAF/integer-overflow cluster.
            // Local privilege escalation to kernel; fixed in the 580.88 / 576.x / 573.x branches.
            new("570.0", "576.79", "CVE-2025-33218", "NVIDIA GPU Display Driver (nvlddmkm.sys) integer overflow -> kernel memory corruption / LPE"),
            new("570.0", "576.79", "CVE-2025-23281", "NVIDIA GPU Display Driver use-after-free -> local privilege escalation"),
            new("550.0", "553.99", "CVE-2025-33218", "NVIDIA GPU Display Driver (nvlddmkm.sys) integer overflow -> kernel memory corruption / LPE"),
            new("535.0", "539.99", "CVE-2025-33218", "NVIDIA GPU Display Driver (nvlddmkm.sys) integer overflow -> kernel memory corruption / LPE"),
            // Oct 2025 bulletin (5703): additional escalation issues incl. G-Assist component.
            // Fixed in 580.88+; treat the 577.x-580.87 window as vulnerable.
            new("577.0", "580.87", "CVE-2025-23347", "NVIDIA driver/G-Assist component -> privilege escalation"),
        };

        // Known vulnerable AMD driver ranges. AMD's kernel-mode surface splits between the
        // Adrenalin display driver (amdkmdag) and the Platform Management Framework (PMF) driver.
        // The PMF cluster is a distinct kernel component; we still key off the display driver
        // version as the observable proxy since PMF ships alongside the platform stack.
        //
        // Sources (AMD security bulletins, 2025): PMF out-of-bounds write / improper input
        // validation LPE cluster (CVE-2025-52540 / 29935 / 48519 / 0028) and the AMDGV driver
        // OOB-write LPE (CVE-2025-54517).
        private static readonly List<VulnerableDriverRange> AmdVulnerableRanges = new()
        {
            // Legacy (retained): pre-2024 Adrenalin kernel RCE / info-disclosure.
            new("23.0", "23.11.1", "CVE-2023-20598", "AMD GPU driver arbitrary code execution in kernel"),
            new("24.0", "24.5.1",  "CVE-2024-21979", "AMD GPU driver information disclosure"),
            // 2025 PMF / kernel-driver LPE cluster. Adrenalin 24.x releases shipping the
            // pre-fix PMF driver; update MaxVersion as AMD publishes the fixed build.
            new("24.0", "25.5.1",  "CVE-2025-54517", "AMD AMDGV driver out-of-bounds write -> local privilege escalation"),
            new("24.0", "25.5.1",  "CVE-2025-52540", "AMD Platform Management Framework (PMF) driver improper input validation -> LPE"),
            new("24.0", "25.5.1",  "CVE-2025-48519", "AMD PMF driver out-of-bounds read/write -> local privilege escalation"),
            new("24.0", "25.5.1",  "CVE-2025-29935", "AMD PMF driver out-of-bounds write -> local privilege escalation"),
        };

        public GpuProcessMonitor(DetectionEngine detectionEngine, ILogger<GpuProcessMonitor> logger)
        {
            _detectionEngine = detectionEngine;
            _logger = logger;
        }

        protected override async Task ExecuteAsync(CancellationToken ct)
        {
            _logger.LogInformation("[GpuProcessMonitor] Started - monitoring browser GPU processes for sandbox escape indicators");

            // Initial delay to let other monitors start
            await Task.Delay(15000, ct);

            // Run driver audit on startup
            await AuditGpuDriverVersionsAsync(ct);

            while (!ct.IsCancellationRequested)
            {
                try
                {
                    await Task.Delay(ScanInterval, ct);
                    PruneAlertCache();

                    await ScanGpuProcessesForAnomaliesAsync(ct);

                    // Periodic driver audit
                    if ((DateTime.UtcNow - _lastDriverAudit) > DriverAuditInterval)
                    {
                        await AuditGpuDriverVersionsAsync(ct);
                    }
                }
                catch (OperationCanceledException) { break; }
                catch (Exception ex)
                {
                    _logger.LogDebug(ex, "[GpuProcessMonitor] Error in scan cycle");
                }
            }
        }

        // 
        // DETECTION 1: GPU Process Anomaly Scan
        // 

        private async Task ScanGpuProcessesForAnomaliesAsync(CancellationToken ct)
        {
            var gpuHelperPids = FindBrowserGpuHelperPids();
            if (gpuHelperPids.Count == 0) return;

            foreach (var (pid, browserName) in gpuHelperPids)
            {
                if (ct.IsCancellationRequested) break;
                if (IsAlertCoolingDown(pid)) continue;

                // Check 1: Child processes spawned by GPU helper (sandbox escape)
                await CheckForChildProcessesAsync(pid, browserName, ct);

                // Check 2: Network connections from GPU helper (C2/exfil after escape)
                await CheckForNetworkConnectionsAsync(pid, browserName, ct);

                // Check 3: Suspicious DLLs loaded in GPU helper (post-exploitation tooling)
                await CheckForSuspiciousDllsAsync(pid, browserName, ct);
            }
        }

        /// <summary>
        /// Finds running browser GPU helper processes.
        /// Chromium browsers use --type=gpu-process for the sandboxed GPU helper.
        /// Firefox uses a separate process with GeckoChildProcess type=gpu.
        /// </summary>
        private List<(int pid, string browserName)> FindBrowserGpuHelperPids()
        {
            var results = new List<(int, string)>();

            try
            {
                foreach (var proc in Process.GetProcesses())
                {
                    try
                    {
                        var name = proc.ProcessName;
                        if (!BrowserProcessNames.Contains(
                            StringNet48.ReplaceIgnoreCase(name, ".exe", "")))
                        {
                            proc.Dispose();
                            continue;
                        }

                        string cmdLine = GetCommandLine(proc.Id);
                        if (string.IsNullOrEmpty(cmdLine))
                        {
                            proc.Dispose();
                            continue;
                        }

                        // Chromium: --type=gpu-process
                        // Firefox: --type=gpu (content_child_main)
                        bool isGpuHelper = cmdLine.Contains("--type=gpu-process") ||
                                          cmdLine.Contains("--type=gpu");

                        if (isGpuHelper)
                        {
                            results.Add((proc.Id, name));
                        }

                        proc.Dispose();
                    }
                    catch
                    {
                        try { proc.Dispose(); } catch { }
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "[GpuProcessMonitor] Error enumerating processes");
            }

            return results;
        }

        /// <summary>
        /// A browser GPU helper process should NEVER spawn child processes.
        /// If it does, that's a definitive sandbox escape indicator.
        /// </summary>
        private async Task CheckForChildProcessesAsync(int gpuPid, string browserName, CancellationToken ct)
        {
            try
            {
                using var searcher = new System.Management.ManagementObjectSearcher(
                    $"SELECT ProcessId, Name, ExecutablePath FROM Win32_Process WHERE ParentProcessId = {gpuPid}");

                var children = new List<(int pid, string name, string path)>();
                foreach (var obj in searcher.Get())
                {
                    int childPid = Convert.ToInt32(obj["ProcessId"]);
                    string childName = obj["Name"]?.ToString() ?? "unknown";
                    string childPath = obj["ExecutablePath"]?.ToString() ?? "";

                    // Exclude the browser's own utility processes that might briefly
                    // show GPU process as parent during startup race conditions
                    if (childName.Equals("conhost.exe", StringComparison.OrdinalIgnoreCase))
                        continue;

                    children.Add((childPid, childName, childPath));
                }

                if (children.Count > 0)
                {
                    var childDesc = string.Join(", ", children.Select(c => $"'{c.name}' (PID {c.pid})"));

                    await _detectionEngine.EmitAsync(new DetectionEvent
                    {
                        RuleName = "GpuProcessMonitor: GPU Sandbox Escape - Child Process Spawned",
                        Evidence = $"Browser GPU helper '{browserName}' (PID {gpuPid}) spawned child processes: {childDesc}. " +
                                   $"GPU helpers are sandboxed and should never spawn processes.",
                        Reasoning = "A browser GPU helper process (--type=gpu-process) spawned one or more child processes. " +
                                    "This is a definitive indicator of GPU sandbox escape - likely via a WebGL/WebGPU memory safety " +
                                    "vulnerability (use-after-free, heap overflow, or out-of-bounds write in the GPU command buffer). " +
                                    "The attacker has broken out of the GPU sandbox and achieved code execution.",
                        Confidence = 0.95,
                        Tier = DetectionTier.Tier1Behavioral,
                        AuthorizedResponse = ResponseAction.KillProcessTree,
                        ProcessName = browserName,
                        ProcessId = gpuPid,
                        SignalType = SignalType.SecurityEvasion,
                        Metadata = new Dictionary<string, string>
                        {
                            { "AttackVector", "GPU_SANDBOX_ESCAPE" },
                            { "ChildProcesses", childDesc },
                            { "MITRE", "T1203 (Exploitation for Client Execution)" },
                        }
                    });

                    MarkAlerted(gpuPid);
                }
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "[GpuProcessMonitor] Error checking children for PID {Pid}", gpuPid);
            }
        }

        /// <summary>
        /// A browser GPU helper process should NOT have its own outbound TCP connections.
        /// Network I/O in Chromium goes through the browser (main) process, not GPU helper.
        /// Connections from the GPU PID indicate post-escape C2 or exfiltration.
        /// </summary>
        private async Task CheckForNetworkConnectionsAsync(int gpuPid, string browserName, CancellationToken ct)
        {
            try
            {
                var connections = GetTcpConnectionsForPid(gpuPid);

                // Filter out loopback connections (GPU <-> browser IPC can use localhost sockets)
                var externalConnections = connections
                    .Where(c => !IsLoopback(c.remoteIp) && c.state == TcpState.Established)
                    .ToList();

                if (externalConnections.Count > 0)
                {
                    var connDesc = string.Join(", ", externalConnections.Select(c =>
                        $"{c.remoteIp}:{c.remotePort}"));

                    await _detectionEngine.EmitAsync(new DetectionEvent
                    {
                        RuleName = "GpuProcessMonitor: GPU Sandbox Escape - Outbound Network Connection",
                        Evidence = $"Browser GPU helper '{browserName}' (PID {gpuPid}) has outbound TCP connections: {connDesc}. " +
                                   $"GPU helper processes should not make network connections directly.",
                        Reasoning = "A browser GPU helper process has established outbound TCP connections to external hosts. " +
                                    "In Chromium's architecture, ALL network I/O routes through the browser (main) process - " +
                                    "the GPU process communicates only via IPC (Mojo/shared memory) with the browser process. " +
                                    "Direct outbound connections from the GPU helper indicate sandbox escape followed by " +
                                    "C2 channel establishment or data exfiltration.",
                        Confidence = 0.92,
                        Tier = DetectionTier.Tier1Behavioral,
                        AuthorizedResponse = ResponseAction.KillProcessTree,
                        ProcessName = browserName,
                        ProcessId = gpuPid,
                        SignalType = SignalType.NetworkC2,
                        Family = TerminalFamily.C2Beacon,
                        Metadata = new Dictionary<string, string>
                        {
                            { "AttackVector", "GPU_SANDBOX_ESCAPE_C2" },
                            { "Connections", connDesc },
                            { "MITRE", "T1071 (Application Layer Protocol)" },
                        }
                    });

                    MarkAlerted(gpuPid);
                }
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "[GpuProcessMonitor] Error checking network for PID {Pid}", gpuPid);
            }
        }

        /// <summary>
        /// Checks if the GPU helper loaded DLLs that indicate post-exploitation activity.
        /// Legitimate GPU helpers load: d3d11.dll, dxgi.dll, nvoglv64.dll, vulkan-1.dll, etc.
        /// Loading AMSI, .NET CLR, WMI scripting, or credential libs is post-exploitation.
        /// </summary>
        private async Task CheckForSuspiciousDllsAsync(int gpuPid, string browserName, CancellationToken ct)
        {
            try
            {
                var proc = Process.GetProcessById(gpuPid);
                var suspiciousModules = new List<string>();

                try
                {
                    foreach (ProcessModule module in proc.Modules)
                    {
                        try
                        {
                            var moduleName = module.ModuleName?.ToLowerInvariant() ?? "";
                            if (SuspiciousDllsInGpuProcess.Contains(moduleName))
                            {
                                suspiciousModules.Add(moduleName);
                            }
                        }
                        catch { }
                    }
                }
                catch (System.ComponentModel.Win32Exception)
                {
                    // Access denied - common for SYSTEM inspecting sandboxed processes
                    // This is expected and not an error
                    return;
                }
                finally
                {
                    proc.Dispose();
                }

                if (suspiciousModules.Count > 0)
                {
                    var dllDesc = string.Join(", ", suspiciousModules);

                    await _detectionEngine.EmitAsync(new DetectionEvent
                    {
                        RuleName = "GpuProcessMonitor: GPU Process Suspicious DLL Load",
                        Evidence = $"Browser GPU helper '{browserName}' (PID {gpuPid}) has loaded suspicious DLLs: {dllDesc}. " +
                                   $"These modules are inconsistent with legitimate GPU rendering operations.",
                        Reasoning = "A browser GPU helper process has loaded modules associated with credential access, " +
                                    "scripting engines, or debugging tools. Legitimate GPU processes only load graphics " +
                                    "driver DLLs (d3d11, dxgi, vulkan, opengl), the C runtime, and browser-internal libraries. " +
                                    "Loading AMSI, .NET, WMI, or credential vault DLLs indicates post-exploitation activity " +
                                    "following a GPU sandbox escape.",
                        Confidence = 0.80,
                        Tier = DetectionTier.Tier1Behavioral,
                        AuthorizedResponse = ResponseAction.LogOnly, // Needs corroboration - DLL enum can have edge cases
                        ProcessName = browserName,
                        ProcessId = gpuPid,
                        SignalType = SignalType.SuspiciousProcess,
                        Metadata = new Dictionary<string, string>
                        {
                            { "AttackVector", "GPU_SANDBOX_ESCAPE_DLL" },
                            { "SuspiciousDlls", dllDesc },
                            { "MITRE", "T1055 (Process Injection)" },
                        }
                    });

                    MarkAlerted(gpuPid);
                }
            }
            catch (ArgumentException)
            {
                // Process exited between enumeration and inspection - normal
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "[GpuProcessMonitor] Error checking DLLs for PID {Pid}", gpuPid);
            }
        }

        // 
        // DETECTION 2: GPU Driver Version Audit
        // 

        /// <summary>
        /// Queries installed GPU driver versions from registry and compares against
        /// known-vulnerable version ranges. Generates Tier2/LogOnly informational alerts.
        /// Does NOT block anything - purely advisory for the user to update drivers.
        /// </summary>
        private async Task AuditGpuDriverVersionsAsync(CancellationToken ct)
        {
            _lastDriverAudit = DateTime.UtcNow;

            try
            {
                // Check NVIDIA drivers
                await CheckNvidiaDriverAsync(ct);

                // Check AMD drivers
                await CheckAmdDriverAsync(ct);

                // Check Intel drivers
                await CheckIntelDriverAsync(ct);
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "[GpuProcessMonitor] Error during GPU driver audit");
            }
        }

        private async Task CheckNvidiaDriverAsync(CancellationToken ct)
        {
            string? version = GetNvidiaDriverVersion();
            if (string.IsNullOrEmpty(version)) return;

            foreach (var detection in BuildNvidiaDriverDetections(version!))
            {
                string alertKey = detection.Metadata["AlertKey"];
                if (_alertedDriverVersions.Contains(alertKey)) continue;
                _alertedDriverVersions.Add(alertKey);
                await _detectionEngine.EmitAsync(detection);
            }
        }

        private async Task CheckAmdDriverAsync(CancellationToken ct)
        {
            string? version = GetAmdDriverVersion();
            if (string.IsNullOrEmpty(version)) return;

            foreach (var detection in BuildAmdDriverDetections(version!))
            {
                string alertKey = detection.Metadata["AlertKey"];
                if (_alertedDriverVersions.Contains(alertKey)) continue;
                _alertedDriverVersions.Add(alertKey);
                await _detectionEngine.EmitAsync(detection);
            }
        }

        private async Task CheckIntelDriverAsync(CancellationToken ct)
        {
            string? version = GetIntelDriverVersion();
            if (string.IsNullOrEmpty(version)) return;

            var detection = BuildIntelDriverDetection(version!);
            if (detection == null) return;

            string alertKey = detection.Metadata["AlertKey"];
            if (_alertedDriverVersions.Contains(alertKey)) return;
            _alertedDriverVersions.Add(alertKey);
            await _detectionEngine.EmitAsync(detection);
        }

        // 
        // PURE DETECTION BUILDERS (I/O-free, InternalsVisibleTo Sentinel.Tests)
        //
        // These take an already-resolved driver version string and return the advisory
        // DetectionEvent(s). No registry, WMI, or process access - so the tier contract
        // (Tier2Indicator + LogOnly, never kill-authorized) is unit-testable without
        // touching live GPU hardware. The AlertKey metadata drives dedup in the callers.
        // 

        /// <summary>
        /// Builds vulnerable-NVIDIA-driver advisory detections for a resolved branded version.
        /// Always Tier2Indicator + LogOnly - a "you should update" advisory, never a kill.
        /// </summary>
        internal static IReadOnlyList<DetectionEvent> BuildNvidiaDriverDetections(string version)
        {
            var results = new List<DetectionEvent>();
            if (string.IsNullOrEmpty(version)) return results;

            foreach (var range in NvidiaVulnerableRanges)
            {
                if (!IsVersionInRange(version, range.MinVersion, range.MaxVersion)) continue;

                results.Add(new DetectionEvent
                {
                    RuleName = "GpuProcessMonitor: Vulnerable NVIDIA Driver Detected",
                    Evidence = $"NVIDIA GPU driver version {version} is within vulnerable range " +
                               $"{range.MinVersion}-{range.MaxVersion}. Affected by {range.CveId}: {range.Description}.",
                    Reasoning = "The installed NVIDIA GPU driver version falls within a known-vulnerable range. " +
                                "GPU driver vulnerabilities can be exploited for local privilege escalation to kernel level, " +
                                "or chained with browser WebGL/WebGPU exploits for remote-to-kernel attack chains. " +
                                "Updating the driver to the latest version closes this attack surface.",
                    Confidence = 0.70,
                    Tier = DetectionTier.Tier2Indicator,
                    AuthorizedResponse = ResponseAction.LogOnly,
                    ProcessName = "nvlddmkm", // NVIDIA kernel mode driver
                    ProcessId = 0,
                    SignalType = SignalType.Generic,
                    Metadata = new Dictionary<string, string>
                    {
                        { "DriverVendor", "NVIDIA" },
                        { "DriverVersion", version },
                        { "CVE", range.CveId },
                        { "VulnerableRange", $"{range.MinVersion}-{range.MaxVersion}" },
                        { "Recommendation", "Update NVIDIA drivers via the NVIDIA App / GeForce Experience or nvidia.com" },
                        { "AlertKey", $"NVIDIA_{version}_{range.CveId}" },
                    }
                });
            }
            return results;
        }

        /// <summary>
        /// Builds vulnerable-AMD-driver advisory detections for a resolved version.
        /// Always Tier2Indicator + LogOnly.
        /// </summary>
        internal static IReadOnlyList<DetectionEvent> BuildAmdDriverDetections(string version)
        {
            var results = new List<DetectionEvent>();
            if (string.IsNullOrEmpty(version)) return results;

            foreach (var range in AmdVulnerableRanges)
            {
                if (!IsVersionInRange(version, range.MinVersion, range.MaxVersion)) continue;

                results.Add(new DetectionEvent
                {
                    RuleName = "GpuProcessMonitor: Vulnerable AMD Driver Detected",
                    Evidence = $"AMD GPU driver version {version} is within vulnerable range " +
                               $"{range.MinVersion}-{range.MaxVersion}. Affected by {range.CveId}: {range.Description}.",
                    Reasoning = "The installed AMD GPU driver version falls within a known-vulnerable range. " +
                                "GPU driver vulnerabilities can be exploited for local privilege escalation or " +
                                "chained with browser GPU exploits for remote code execution.",
                    Confidence = 0.70,
                    Tier = DetectionTier.Tier2Indicator,
                    AuthorizedResponse = ResponseAction.LogOnly,
                    ProcessName = "amdkmdag", // AMD kernel mode driver
                    ProcessId = 0,
                    SignalType = SignalType.Generic,
                    Metadata = new Dictionary<string, string>
                    {
                        { "DriverVendor", "AMD" },
                        { "DriverVersion", version },
                        { "CVE", range.CveId },
                        { "VulnerableRange", $"{range.MinVersion}-{range.MaxVersion}" },
                        { "Recommendation", "Update AMD drivers via AMD Software: Adrenalin Edition" },
                        { "AlertKey", $"AMD_{version}_{range.CveId}" },
                    }
                });
            }
            return results;
        }

        /// <summary>
        /// Builds an outdated-Intel-GPU-driver advisory for a resolved version, or null if the
        /// version is current enough. Always Tier2Indicator + LogOnly.
        /// </summary>
        internal static DetectionEvent? BuildIntelDriverDetection(string version)
        {
            if (string.IsNullOrEmpty(version)) return null;

            // Intel GPU driver CVEs are less commonly exploited in the wild,
            // but we still flag severely outdated versions (pre-2024).
            if (!IsVersionBefore(version, "31.0.101.4900")) return null;

            return new DetectionEvent
            {
                RuleName = "GpuProcessMonitor: Outdated Intel GPU Driver",
                Evidence = $"Intel GPU driver version {version} is significantly outdated (pre-2024). " +
                           "Multiple privilege escalation CVEs affect older Intel GPU drivers.",
                Reasoning = "The installed Intel GPU driver is severely outdated and likely affected by " +
                            "multiple known vulnerabilities including privilege escalation flaws. " +
                            "Updating through Windows Update or Intel's driver utility is recommended.",
                Confidence = 0.60,
                Tier = DetectionTier.Tier2Indicator,
                AuthorizedResponse = ResponseAction.LogOnly,
                ProcessName = "igdkmd64", // Intel kernel mode driver
                ProcessId = 0,
                SignalType = SignalType.Generic,
                Metadata = new Dictionary<string, string>
                {
                    { "DriverVendor", "Intel" },
                    { "DriverVersion", version },
                    { "Recommendation", "Update Intel GPU driver via Windows Update or Intel Driver & Support Assistant" },
                    { "AlertKey", $"Intel_{version}_outdated" },
                }
            };
        }

        // 
        // HELPER: Driver Version Queries
        // 

        private string? GetNvidiaDriverVersion()
        {
            try
            {
                // NVIDIA stores version in registry under Video controller
                using var key = Registry.LocalMachine.OpenSubKey(
                    @"SOFTWARE\NVIDIA Corporation\Global\NvTweak");
                var version = key?.GetValue("NvTweakVersion")?.ToString();
                if (!string.IsNullOrEmpty(version)) return NormalizeNvidiaVersion(version!);
            }
            catch { }

            // Fallback: query display adapters. Win32_VideoController reports the 4-part
            // Windows driver version (e.g. "31.0.15.5222"); normalize to the branded form.
            var adapterVersion = GetDriverVersionFromDisplayAdapters("nvidia");
            return string.IsNullOrEmpty(adapterVersion) ? adapterVersion : NormalizeNvidiaVersion(adapterVersion!);
        }

        /// <summary>
        /// Normalizes an NVIDIA driver version to the branded 3-digit form (e.g. "552.22").
        /// NVIDIA reports two shapes:
        ///   - Branded/vendor form: "552.22" or "31.0.101.5222"-style is NOT used here.
        ///   - Windows driver form (Win32_VideoController.DriverVersion): "31.0.15.5222", where
        ///     the branded version is encoded in the last five digits of the final two parts
        ///     ("15.5222" -> "5" + "5222" = "55222" -> 552.22).
        /// If the input is already in branded form (major in a plausible NVIDIA range and only
        /// two parts) it is returned unchanged. On any parse failure the original string is
        /// returned so range matching degrades safely rather than throwing.
        /// </summary>
        internal static string NormalizeNvidiaVersion(string raw)
        {
            if (string.IsNullOrWhiteSpace(raw)) return raw;

            var parts = raw.Split('.');

            // Already branded 3-digit form like "552.22" (major >= 100): use as-is.
            if (parts.Length == 2 &&
                int.TryParse(parts[0], out var brandedMajor) && brandedMajor >= 100)
            {
                return raw;
            }

            // Windows 4-part form "aa.b.cc.ddddd" -> take the last 5 significant digits
            // from the final two components: e.g. "31.0.15.5222" -> "15" + "5222" tail.
            if (parts.Length == 4)
            {
                // Concatenate the digits of the last two parts, then take the trailing 5 digits.
                var tail = (parts[2] + parts[3]);
                var digits = new string(tail.Where(char.IsDigit).ToArray());
                if (digits.Length >= 5)
                {
                    var last5 = digits.Substring(digits.Length - 5); // e.g. "55222"
                    var major = last5.Substring(0, 3);               // "552"
                    var minor = last5.Substring(3);                  // "22"
                    return $"{major}.{minor}";
                }
            }

            // Unknown shape - return original; ParseVersion will best-effort handle or reject it.
            return raw;
        }

        private string? GetAmdDriverVersion()
        {
            try
            {
                using var key = Registry.LocalMachine.OpenSubKey(
                    @"SOFTWARE\AMD\CN");
                var version = key?.GetValue("DriverVersion")?.ToString();
                if (!string.IsNullOrEmpty(version)) return version;
            }
            catch { }

            return GetDriverVersionFromDisplayAdapters("amd");
        }

        private string? GetIntelDriverVersion()
        {
            return GetDriverVersionFromDisplayAdapters("intel");
        }

        private string? GetDriverVersionFromDisplayAdapters(string vendorHint)
        {
            try
            {
                using var searcher = new System.Management.ManagementObjectSearcher(
                    "SELECT Name, DriverVersion FROM Win32_VideoController");

                foreach (var obj in searcher.Get())
                {
                    var name = obj["Name"]?.ToString()?.ToLowerInvariant() ?? "";
                    if (name.Contains(vendorHint))
                    {
                        return obj["DriverVersion"]?.ToString();
                    }
                }
            }
            catch { }

            return null;
        }

        // 
        // HELPER: Network Connection Query (TCP table via iphlpapi)
        // 

        [DllImport("iphlpapi.dll", SetLastError = true)]
        private static extern uint GetExtendedTcpTable(IntPtr pTcpTable, ref int pdwSize,
            bool bOrder, int ulAf, int tableClass, uint reserved);

        private const int AF_INET = 2;
        private const int TCP_TABLE_OWNER_PID_ALL = 5;

        private enum TcpState : int
        {
            Closed = 1, Listen = 2, SynSent = 3, SynReceived = 4,
            Established = 5, FinWait1 = 6, FinWait2 = 7, CloseWait = 8,
            Closing = 9, LastAck = 10, TimeWait = 11, DeleteTcb = 12
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct MIB_TCPROW_OWNER_PID
        {
            public TcpState State;
            public uint LocalAddr;
            public int LocalPort;
            public uint RemoteAddr;
            public int RemotePort;
            public int OwningPid;
        }

        private List<(string remoteIp, int remotePort, TcpState state)> GetTcpConnectionsForPid(int targetPid)
        {
            var results = new List<(string, int, TcpState)>();

            int size = 0;
            uint ret = GetExtendedTcpTable(IntPtr.Zero, ref size, true, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);
            if (ret != 122) return results; // ERROR_INSUFFICIENT_BUFFER expected

            IntPtr buffer = Marshal.AllocHGlobal(size);
            try
            {
                ret = GetExtendedTcpTable(buffer, ref size, true, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);
                if (ret != 0) return results;

                int numEntries = Marshal.ReadInt32(buffer);
                int rowSize = Marshal.SizeOf<MIB_TCPROW_OWNER_PID>();
                IntPtr rowPtr = buffer + 4;

                for (int i = 0; i < numEntries; i++)
                {
                    var row = Marshal.PtrToStructure<MIB_TCPROW_OWNER_PID>(rowPtr);
                    if (row.OwningPid == targetPid)
                    {
                        var remoteIp = new System.Net.IPAddress(row.RemoteAddr).ToString();
                        int remotePort = ((row.RemotePort & 0xFF) << 8) | ((row.RemotePort >> 8) & 0xFF);
                        results.Add((remoteIp, remotePort, row.State));
                    }
                    rowPtr += rowSize;
                }
            }
            finally
            {
                Marshal.FreeHGlobal(buffer);
            }

            return results;
        }

        private static bool IsLoopback(string ip)
        {
            return ip == "127.0.0.1" || ip == "0.0.0.0" || ip.StartsWith("127.");
        }

        // 
        // HELPER: Version Comparison
        // 

        private static bool IsVersionInRange(string version, string min, string max)
        {
            try
            {
                var v = ParseVersion(version);
                var vMin = ParseVersion(min);
                var vMax = ParseVersion(max);

                if (v == null || vMin == null || vMax == null) return false;
                return v >= vMin && v <= vMax;
            }
            catch { return false; }
        }

        private static bool IsVersionBefore(string version, string threshold)
        {
            try
            {
                var v = ParseVersion(version);
                var t = ParseVersion(threshold);
                if (v == null || t == null) return false;
                return v < t;
            }
            catch { return false; }
        }

        private static Version? ParseVersion(string versionStr)
        {
            if (string.IsNullOrEmpty(versionStr)) return null;

            // Handle NVIDIA-style versions (e.g., "556.12") and standard (e.g., "31.0.101.4900")
            // Normalize: strip any non-version prefixes
            var cleaned = new string(versionStr.Where(c => char.IsDigit(c) || c == '.').ToArray());
            if (string.IsNullOrEmpty(cleaned)) return null;

            // Ensure at least major.minor
            var parts = cleaned.Split('.');
            while (parts.Length < 2)
            {
                cleaned += ".0";
                parts = cleaned.Split('.');
            }

            if (Version.TryParse(cleaned, out var result))
                return result;

            return null;
        }

        // 
        // HELPER: Process Utilities
        // 

        private static string GetCommandLine(int pid)
        {
            try
            {
                using var searcher = new System.Management.ManagementObjectSearcher(
                    $"SELECT CommandLine FROM Win32_Process WHERE ProcessId = {pid}");
                foreach (var obj in searcher.Get())
                {
                    return obj["CommandLine"]?.ToString() ?? "";
                }
            }
            catch { }
            return "";
        }

        private bool IsAlertCoolingDown(int pid)
        {
            if (_alertedPids.TryGetValue(pid, out var lastAlert))
            {
                if (DateTimeOffset.UtcNow - lastAlert < AlertCooldown)
                    return true;
            }
            return false;
        }

        private void MarkAlerted(int pid)
        {
            _alertedPids[pid] = DateTimeOffset.UtcNow;
        }

        private void PruneAlertCache()
        {
            var cutoff = DateTimeOffset.UtcNow - AlertCooldown;
            var expired = _alertedPids.Where(kvp => kvp.Value < cutoff).Select(kvp => kvp.Key).ToList();
            foreach (var pid in expired) _alertedPids.TryRemove(pid, out _);
        }

        // 
        // INNER TYPES
        // 

        private sealed class VulnerableDriverRange
        {
            public string MinVersion { get; }
            public string MaxVersion { get; }
            public string CveId { get; }
            public string Description { get; }

            public VulnerableDriverRange(string min, string max, string cve, string description)
            {
                MinVersion = min;
                MaxVersion = max;
                CveId = cve;
                Description = description;
            }
        }
    }
}
