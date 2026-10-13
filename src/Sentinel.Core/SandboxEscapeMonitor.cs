using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Management;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Win32;

namespace Sentinel.Core
{
    /// <summary>
    /// Monitors for sandbox/container escape indicators:
    /// - Windows Sandbox (WindowsSandbox.exe) process activity
    /// - Docker for Windows container breakout signals
    /// - Hyper-V isolation boundary violations
    /// - Processes spawning from sandbox/container context into host
    ///
    /// Also monitors for malware hiding inside containers:
    /// - Docker containers with host network mode (direct network access)
    /// - Containers with host PID namespace (can see host processes)
    /// - Windows Sandbox with folder mappings to sensitive host paths
    ///
    /// v1.0.1: New monitor.
    /// </summary>
    public sealed class SandboxEscapeMonitor : BackgroundService
    {
        private readonly DetectionEngine _detectionEngine;
        private readonly ProcessAncestryCache _ancestryCache;
        private readonly ILogger<SandboxEscapeMonitor> _logger;

        private readonly ConcurrentDictionary<string, DateTimeOffset> _alertedContainers = new();
        private readonly HashSet<int> _baselineDockerPids = new();

        private static readonly TimeSpan ScanInterval = TimeSpan.FromSeconds(15);
        private static readonly TimeSpan AlertCooldown = TimeSpan.FromMinutes(10);

        // Processes that indicate sandbox/container runtime
        private static readonly HashSet<string> SandboxProcesses = new(StringComparer.OrdinalIgnoreCase)
        {
            "WindowsSandbox", "WindowsSandboxClient", "CmService"
        };

        private static readonly HashSet<string> ContainerProcesses = new(StringComparer.OrdinalIgnoreCase)
        {
            "dockerd", "containerd", "containerd-shim", "runc",
            "hcsshim", "vmcompute", "vmms", "vmwp"
        };

        public SandboxEscapeMonitor(
            DetectionEngine detectionEngine,
            ProcessAncestryCache ancestryCache,
            ILogger<SandboxEscapeMonitor> logger)
        {
            _detectionEngine = detectionEngine;
            _ancestryCache = ancestryCache;
            _logger = logger;
        }

        protected override async Task ExecuteAsync(CancellationToken ct)
        {
            _logger.LogInformation("[SandboxEscapeMonitor] Started");

            while (!ct.IsCancellationRequested)
            {
                try
                {
                    await Task.Delay(ScanInterval, ct);

                    await MonitorDockerContainers(ct);
                    await MonitorWindowsSandbox(ct);
                    await DetectContainerEscapeSignals(ct);
                }
                catch (OperationCanceledException) { break; }
                catch (Exception ex) { _logger.LogDebug(ex, "[SandboxEscapeMonitor] Error"); }
            }
        }

        private async Task MonitorDockerContainers(CancellationToken ct)
        {
            // Check if Docker is running
            var dockerProc = Process.GetProcessesByName("dockerd");
            if (dockerProc.Length == 0)
            {
                foreach (var p in dockerProc) p.Dispose();
                return;
            }
            foreach (var p in dockerProc) p.Dispose();

            try
            {
                // Query running containers via docker CLI
                var psi = new ProcessStartInfo("docker", "ps --format \"{{.ID}} {{.Image}} {{.Command}}\" --no-trunc")
                {
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    UseShellExecute = false,
                    CreateNoWindow = true
                };

                using var proc = Process.Start(psi);
                if (proc == null) return;

                var output = await proc.StandardOutput.ReadToEndAsync();
                await proc.WaitForExitAsync(ct);

                if (proc.ExitCode != 0) return;

                foreach (var line in output.Split(new[] { '\n' }, StringSplitOptions.RemoveEmptyEntries))
                {
                    var parts = line.Trim().Split(new[] { ' ' }, 3);
                    if (parts.Length < 2) continue;

                    var containerId = parts[0];
                    var image = parts[1];

                    // Check for dangerous container configurations
                    await InspectContainerSecurity(containerId, image, ct);
                }
            }
            catch { }
        }

        private async Task InspectContainerSecurity(string containerId, string image, CancellationToken ct)
        {
            var alertKey = $"docker:{containerId}";
            if (_alertedContainers.TryGetValue(alertKey, out var lastAlert) &&
                DateTimeOffset.UtcNow - lastAlert < AlertCooldown)
                return;

            try
            {
                var psi = new ProcessStartInfo("docker", $"inspect {containerId} --format " +
                    "\"{{.HostConfig.NetworkMode}} {{.HostConfig.PidMode}} {{.HostConfig.Privileged}} {{.HostConfig.SecurityOpt}}\"")
                {
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    UseShellExecute = false,
                    CreateNoWindow = true
                };

                using var proc = Process.Start(psi);
                if (proc == null) return;

                var output = (await proc.StandardOutput.ReadToEndAsync()).Trim();
                await proc.WaitForExitAsync(ct);

                if (proc.ExitCode != 0) return;

                var configParts = output.Split(' ');
                var networkMode = configParts.Length > 0 ? configParts[0] : "";
                var pidMode = configParts.Length > 1 ? configParts[1] : "";
                var privileged = configParts.Length > 2 ? configParts[2] : "";

                bool isHostNetwork = networkMode.Equals("host");
                bool isHostPid = pidMode.Equals("host");
                bool isPrivileged = privileged.Equals("true");

                if (isPrivileged)
                {
                    _alertedContainers[alertKey] = DateTimeOffset.UtcNow;
                    await _detectionEngine.EmitAsync(new DetectionEvent
                    {
                        RuleName = "Container: Privileged Docker Container Running",
                        Evidence = $"Container {containerId[..12]} (image: {image}) running in --privileged mode",
                        Reasoning = "A Docker container is running in privileged mode, which grants full " +
                                    "access to all host devices and disables security isolation. This is " +
                                    "equivalent to running on the host directly and enables trivial container escape.",
                        Confidence = 0.82,
                        Tier = DetectionTier.Tier1Behavioral,
                        AuthorizedResponse = ResponseAction.LogOnly,
                        ProcessName = "dockerd",
                        ProcessId = 0,
                        Metadata = new Dictionary<string, string>
                        {
                            ["ContainerId"] = containerId,
                            ["Image"] = image,
                            ["NetworkMode"] = networkMode,
                            ["Privileged"] = "true"
                        }
                    });
                }
                else if (isHostNetwork || isHostPid)
                {
                    _alertedContainers[alertKey] = DateTimeOffset.UtcNow;
                    await _detectionEngine.EmitAsync(new DetectionEvent
                    {
                        RuleName = "Container: Weakened Isolation Detected",
                        Evidence = $"Container {containerId[..12]} (image: {image}) with " +
                                   $"host_network={isHostNetwork}, host_pid={isHostPid}",
                        Reasoning = "A Docker container is running with weakened isolation (host network " +
                                    "or host PID namespace). This allows the container to see host network " +
                                    "traffic or host processes, reducing the effectiveness of containment.",
                        Confidence = 0.65,
                        Tier = DetectionTier.Tier2Indicator,
                        AuthorizedResponse = ResponseAction.LogOnly,
                        ProcessName = "dockerd",
                        ProcessId = 0,
                        Metadata = new Dictionary<string, string>
                        {
                            ["ContainerId"] = containerId,
                            ["Image"] = image,
                            ["HostNetwork"] = isHostNetwork.ToString(),
                            ["HostPid"] = isHostPid.ToString()
                        }
                    });
                }
            }
            catch { }
        }

        private async Task MonitorWindowsSandbox(CancellationToken ct)
        {
            // Check if Windows Sandbox is running
            var sandboxProcs = Process.GetProcessesByName("WindowsSandbox");
            if (sandboxProcs.Length == 0)
            {
                foreach (var p in sandboxProcs) p.Dispose();
                return;
            }
            foreach (var p in sandboxProcs) p.Dispose();

            // Check for .wsb configuration files that map sensitive host paths
            try
            {
                var recentWsb = Directory.GetFiles(
                    Environment.GetFolderPath(Environment.SpecialFolder.Recent) ?? "",
                    "*.wsb", SearchOption.AllDirectories);

                // Also check temp and downloads
                var searchPaths = new[]
                {
                    Path.GetTempPath(),
                    Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads"),
                    Environment.GetFolderPath(Environment.SpecialFolder.Desktop)
                };

                foreach (var searchPath in searchPaths)
                {
                    if (!Directory.Exists(searchPath)) continue;
                    try
                    {
                        foreach (var wsb in Directory.GetFiles(searchPath, "*.wsb"))
                        {
                            var content = File.ReadAllText(wsb);
                            // Check for sensitive path mappings
                            if (content.Contains(@"C:\Users") ||
                                content.Contains(@"C:\Windows") ||
                                content.Contains("ReadWrite"))
                            {
                                var alertKey = $"sandbox:{wsb}";
                                if (_alertedContainers.TryGetValue(alertKey, out var last) &&
                                    DateTimeOffset.UtcNow - last < AlertCooldown)
                                    continue;

                                _alertedContainers[alertKey] = DateTimeOffset.UtcNow;

                                await _detectionEngine.EmitAsync(new DetectionEvent
                                {
                                    RuleName = "Sandbox: Sensitive Host Path Mapped to Windows Sandbox",
                                    Evidence = $"Windows Sandbox config at {wsb} maps sensitive host paths with write access",
                                    Reasoning = "A Windows Sandbox configuration file maps sensitive host directories " +
                                                "(user profiles, system paths) with read-write access. Malware running " +
                                                "inside the sandbox could modify host files through this mapping.",
                                    Confidence = 0.72,
                                    Tier = DetectionTier.Tier1Behavioral,
                                    AuthorizedResponse = ResponseAction.LogOnly,
                                    ProcessName = "WindowsSandbox",
                                    ProcessId = 0,
                                    Metadata = new Dictionary<string, string>
                                    {
                                        ["ConfigPath"] = wsb
                                    }
                                });
                            }
                        }
                    }
                    catch { }
                }
            }
            catch { }
        }

        private async Task DetectContainerEscapeSignals(CancellationToken ct)
        {
            // Look for processes that spawned from container runtime but are executing host binaries
            foreach (var proc in Process.GetProcesses())
            {
                try
                {
                    var (_, parentName) = _ancestryCache.GetParent(proc.Id);
                    if (string.IsNullOrEmpty(parentName)) continue;

                    // Process whose parent is a container runtime but runs from host paths
                    if (!ContainerProcesses.Contains(parentName)) continue;

                    string? imagePath = SecurityValidation.GetProcessImagePath(proc.Id);
                    if (string.IsNullOrEmpty(imagePath)) continue;

                    // If it's running from a host path (not container layer), that's suspicious
                    if (imagePath!.Contains(@"\docker\") ||
                        imagePath.Contains(@"\containerd\"))
                        continue;

                    // Process spawned by container runtime running from host filesystem
                    var alertKey = $"escape:{proc.Id}:{imagePath}";
                    if (_alertedContainers.ContainsKey(alertKey)) continue;
                    _alertedContainers[alertKey] = DateTimeOffset.UtcNow;

                    await _detectionEngine.EmitAsync(new DetectionEvent
                    {
                        RuleName = "Container: Possible Container Escape",
                        Evidence = $"Process '{proc.ProcessName}' (PID {proc.Id}) spawned by container runtime " +
                                   $"'{parentName}' but executing from host path: {imagePath}",
                        Reasoning = "A process was spawned by a container runtime process but is executing " +
                                    "a binary from the host filesystem (not from within a container layer). " +
                                    "This may indicate a container escape where code execution broke out of " +
                                    "the container's filesystem isolation.",
                        Confidence = 0.88,
                        Tier = DetectionTier.Tier1Behavioral,
                        AuthorizedResponse = ResponseAction.KillProcessTree,
                        ProcessName = proc.ProcessName,
                        ProcessId = proc.Id,
                        SignalType = SignalType.ProcessInjection,
                        Metadata = new Dictionary<string, string>
                        {
                            ["ParentProcess"] = parentName,
                            ["ImagePath"] = imagePath
                        }
                    });
                }
                catch { }
                finally { proc.Dispose(); }
            }
        }
    }
}
