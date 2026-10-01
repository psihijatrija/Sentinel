using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace Sentinel.Core
{
    /// <summary>
    /// Coordinates forensic evidence collection when a kill response is triggered:
    /// - Memory dump of the target process (if still alive)
    /// - Module inventory (loaded DLLs)
    /// - Network connections snapshot
    /// - Process tree snapshot
    /// Integrates with ChainTracer for persistence removal.
    /// </summary>
    public sealed class IncidentResponseService
    {
        private readonly ILogger<IncidentResponseService> _logger;
        private readonly ChainTracer _chainTracer;
        private readonly QuarantineManager _quarantine;
        private readonly JsonlEventLogger _eventLogger;

        private static readonly string EvidenceDir = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
            "Sentinel", "Evidence");

        public IncidentResponseService(
            ILogger<IncidentResponseService> logger,
            ChainTracer chainTracer,
            QuarantineManager quarantine,
            JsonlEventLogger eventLogger)
        {
            _logger = logger;
            _chainTracer = chainTracer;
            _quarantine = quarantine;
            _eventLogger = eventLogger;

            if (!Directory.Exists(EvidenceDir))
            {
                try { Directory.CreateDirectory(EvidenceDir); } catch { }
            }
        }

        /// <summary>
        /// Collects forensic evidence for an incident triggered by a detection event.
        /// Call this BEFORE killing the process for best results.
        /// </summary>
        public async Task CollectEvidenceAsync(DetectionEvent detection)
        {
            var timestamp = DateTime.UtcNow.ToString("yyyyMMdd_HHmmss");
            var incidentDir = Path.Combine(EvidenceDir, $"{timestamp}_PID{detection.ProcessId}_{detection.RuleName.Replace(" ", "_").Replace(":", "")}");

            try
            {
                Directory.CreateDirectory(incidentDir);
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "[IncidentResponseService] Failed to create evidence directory");
                return;
            }

            var evidence = new Dictionary<string, object>
            {
                ["Timestamp"] = DateTime.UtcNow,
                ["Detection"] = detection.RuleName,
                ["ProcessId"] = detection.ProcessId,
                ["ProcessName"] = detection.ProcessName,
                ["Confidence"] = detection.Confidence,
                ["Evidence"] = detection.Evidence
            };

            // 1. Module inventory
            try
            {
                var modules = CollectModuleInventory(detection.ProcessId);
                if (modules.Count > 0)
                {
                    File.WriteAllLines(
                        Path.Combine(incidentDir, "modules.txt"),
                        modules);
                    evidence["ModuleCount"] = modules.Count;
                }
            }
            catch (Exception ex) { _logger.LogDebug(ex, "[IncidentResponseService] Module collection failed"); }

            // 2. Network connections
            try
            {
                var connections = CollectNetworkSnapshot(detection.ProcessId);
                if (connections.Count > 0)
                {
                    File.WriteAllLines(
                        Path.Combine(incidentDir, "network.txt"),
                        connections);
                    evidence["NetworkConnections"] = connections.Count;
                }
            }
            catch (Exception ex) { _logger.LogDebug(ex, "[IncidentResponseService] Network snapshot failed"); }

            // 3. Process tree
            try
            {
                var tree = CollectProcessTree(detection.ProcessId);
                if (tree.Count > 0)
                {
                    File.WriteAllLines(
                        Path.Combine(incidentDir, "process_tree.txt"),
                        tree);
                    evidence["ProcessTreeDepth"] = tree.Count;
                }
            }
            catch (Exception ex) { _logger.LogDebug(ex, "[IncidentResponseService] Process tree collection failed"); }

            // 4. Quarantine the binary - NEVER OS-critical paths (v1.6.3: powershell.exe FP)
            try
            {
                using var proc = Process.GetProcessById(detection.ProcessId);
                var imagePath = SecurityValidation.GetProcessImagePath(detection.ProcessId);
                if (!string.IsNullOrEmpty(imagePath) && File.Exists(imagePath))
                {
                    if (SecurityValidation.IsOsCriticalPath(imagePath))
                    {
                        evidence["QuarantineSkippedOsCritical"] = imagePath!;
                        _logger.LogWarning(
                            "[IncidentResponseService] Refusing quarantine of OS-critical path: {Path}",
                            imagePath);
                    }
                    else if (SecurityValidation.IsGameOrAntiCheatPath(imagePath))
                    {
                        evidence["QuarantineSkippedGamePath"] = imagePath!;
                    }
                    else
                    {
                        var qPath = await _quarantine.QuarantineFileAtomicAsync(imagePath!);
                        if (qPath != null)
                            evidence["QuarantinedBinary"] = imagePath!;
                        else
                            evidence["QuarantineSkippedSigned"] = imagePath!;
                    }
                }
            }
            catch { } // Process may already be dead

            // 5. Log incident summary
            evidence["EvidenceDirectory"] = incidentDir;
            await _eventLogger.LogEventAsync("incident", evidence);

            _logger.LogWarning("[IncidentResponseService] Evidence collected for PID {Pid} ({Rule}) -> {Dir}",
                detection.ProcessId, detection.RuleName, incidentDir);
        }

        private static List<string> CollectModuleInventory(int pid)
        {
            var result = new List<string>();
            try
            {
                // Evidence collection only after a detection. Still refuse game/anti-cheat paths
                // (PROCESS_VM_READ would kill the title during IR).
                var imagePath = SecurityValidation.GetProcessImagePath(pid);
                if (SecurityValidation.IsGameOrAntiCheatPath(imagePath))
                    return result;
                if (!NativeProcessMemory.CanInspect(pid))
                    return result;

                using var proc = Process.GetProcessById(pid);
                foreach (ProcessModule mod in proc.Modules)
                {
                    result.Add($"{mod.ModuleName}\t{mod.FileName}\t{mod.ModuleMemorySize}");
                }
            }
            catch { }
            return result;
        }

        private static List<string> CollectNetworkSnapshot(int pid)
        {
            var result = new List<string>();
            try
            {
                var psi = new ProcessStartInfo("netstat", "-anop tcp")
                {
                    CreateNoWindow = true,
                    UseShellExecute = false,
                    RedirectStandardOutput = true
                };
                using var p = Process.Start(psi);
                if (p == null) return result;
                var output = p.StandardOutput.ReadToEnd();
                p.WaitForExit(5000);

                foreach (var line in output.Split('\n'))
                {
                    if (line.Contains(pid.ToString()))
                        result.Add(line.Trim());
                }
            }
            catch { }
            return result;
        }

        private static List<string> CollectProcessTree(int pid)
        {
            var result = new List<string>();
            try
            {
                using var proc = Process.GetProcessById(pid);
                result.Add($"PID={proc.Id} Name={proc.ProcessName} StartTime={proc.StartTime:O}");
            }
            catch { }
            return result;
        }
    }
}
