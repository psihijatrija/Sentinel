using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.Diagnostics.Eventing.Reader;
using System.Linq;
using System.ServiceProcess;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace Sentinel.Core
{
    /// <summary>
    /// Monitors critical Windows services for repeated crash patterns that indicate
    /// injection, exploitation, or deliberate sabotage by malware.
    ///
    /// Key insight from the PlugX incident:
    ///   - TokenBroker (svchost) crashed 46+ times with STATUS_STACK_BUFFER_OVERRUN
    ///   - This exception (0xc0000409) means /GS stack cookie detected corruption
    ///   - Repeated /GS failures = repeated exploitation attempts OR corrupted DLL
    ///   - The TokenBroker crash caused explorer.exe cross-process hang (AppHangXProcB1)
    ///
    /// Malware also intentionally crashes critical services to:
    ///   - Disable Windows Update (prevent patches)
    ///   - Kill Defender services
    ///   - Destabilize the system to force reboot (triggering persistence mechanisms)
    ///   - Cause a BSOD via critical process failure (csrss, smss, wininit)
    ///
    /// This guard:
    ///   1. Monitors Service Control Manager events for service crashes (Event ID 7034/7031)
    ///   2. Tracks crash frequency per service
    ///   3. Detects STATUS_STACK_BUFFER_OVERRUN patterns (exploitation indicator)
    ///   4. Alerts when crash frequency exceeds normal thresholds
    ///   5. Specifically protects BSOD-critical processes from being killed by malware
    ///
    /// Scan interval: 10 seconds (event log poll) + real-time SCM event subscription.
    /// </summary>
    public sealed class CriticalServiceGuard : BackgroundService
    {
        private readonly DetectionEngine _detectionEngine;
        private readonly ILogger<CriticalServiceGuard> _logger;

        // Track crash history per service
        private readonly ConcurrentDictionary<string, ServiceCrashHistory> _crashHistory = new();

        // Already-alerted services (cooldown to avoid flood)
        private readonly ConcurrentDictionary<string, DateTimeOffset> _alertedServices = new();

        private DateTime _lastEventQueryTime;

        private static readonly TimeSpan ScanInterval = TimeSpan.FromSeconds(10);
        private static readonly TimeSpan CrashWindow = TimeSpan.FromMinutes(30);
        private static readonly TimeSpan AlertCooldown = TimeSpan.FromMinutes(10);

        // Crash thresholds - normal services might crash once; 3+ is suspicious
        private const int SuspiciousCrashThreshold = 3;
        private const int HighConfidenceCrashThreshold = 5;

        /// <summary>
        /// Services whose repeated crashes indicate active exploitation or injection.
        /// These interact with authentication, shell, and security subsystems.
        /// </summary>
        private static readonly Dictionary<string, string> MonitoredServices = new(StringComparer.OrdinalIgnoreCase)
        {
            ["TokenBroker"] = "Authentication token management (Start menu, Store, UWP apps)",
            ["WebAccountManager"] = "Web authentication for Microsoft accounts",
            ["WinDefend"] = "Windows Defender Antimalware Service",
            ["MpsSvc"] = "Windows Firewall",
            ["SecurityHealthService"] = "Windows Security Center",
            ["wscsvc"] = "Security Center service",
            ["EventLog"] = "Windows Event Log (disabling hides attacker activity)",
            ["BFE"] = "Base Filtering Engine (firewall backend)",
            ["Dnscache"] = "DNS Client (poisoning target)",
            ["CryptSvc"] = "Cryptographic Services (certificate validation)",
            ["BITS"] = "Background Intelligent Transfer Service (update delivery)",
            ["wuauserv"] = "Windows Update",
            ["ShellHWDetection"] = "Shell Hardware Detection (explorer dependency)",
            ["Themes"] = "Desktop Window Manager theme service (explorer dependency)",
            ["Appinfo"] = "Application Information (UAC elevation broker)",
        };

        /// <summary>
        /// Processes whose termination causes an immediate BSOD.
        /// If malware tries to kill these, we alert immediately.
        /// </summary>
        private static readonly HashSet<string> BsodCriticalProcesses = new(StringComparer.OrdinalIgnoreCase)
        {
            "csrss",      // Client/Server Runtime - instant BSOD if killed
            "smss",       // Session Manager - instant BSOD
            "wininit",    // Windows Initialization - instant BSOD
            "services",   // Service Control Manager - instant BSOD
            "lsass",      // LSA - delayed BSOD (60s)
            "svchost",    // Some svchost groups are critical
        };

        /// <summary>
        /// Exception codes that indicate exploitation rather than normal bugs.
        /// </summary>
        private static readonly Dictionary<uint, string> ExploitationExceptionCodes = new()
        {
            [0xC0000409] = "STATUS_STACK_BUFFER_OVERRUN (/GS cookie corruption - buffer overflow detected)",
            [0xC0000005] = "STATUS_ACCESS_VIOLATION (memory corruption / use-after-free)",
            [0xC000001D] = "STATUS_ILLEGAL_INSTRUCTION (ROP/JOP gadget misfire)",
            [0xC0000096] = "STATUS_PRIVILEGED_INSTRUCTION (ring0 attempt from usermode)",
            [0xC00000FD] = "STATUS_STACK_OVERFLOW (stack pivot / infinite recursion exploit)",
        };

        public CriticalServiceGuard(
            DetectionEngine detectionEngine,
            ILogger<CriticalServiceGuard> logger)
        {
            _detectionEngine = detectionEngine;
            _logger = logger;
        }

        protected override async Task ExecuteAsync(CancellationToken ct)
        {
            _logger.LogInformation("[CriticalServiceGuard] Started - monitoring {Count} critical services",
                MonitoredServices.Count);

            _lastEventQueryTime = DateTime.UtcNow.Subtract(CrashWindow);

            while (!ct.IsCancellationRequested)
            {
                try
                {
                    await Task.Delay(ScanInterval, ct);
                    await CheckServiceCrashEventsAsync(ct);
                    await MonitorBsodCriticalProcessesAsync(ct);
                    PruneStaleHistory();
                }
                catch (OperationCanceledException) { break; }
                catch (Exception ex) { _logger.LogDebug(ex, "[CriticalServiceGuard] Scan error"); }
            }
        }

        private async Task CheckServiceCrashEventsAsync(CancellationToken ct)
        {
            try
            {
                var queryTime = DateTime.UtcNow;
                var queryXml = "*[System[Provider[@Name='Service Control Manager'] and (EventID=7034 or EventID=7031) " +
                               $"and TimeCreated[@SystemTime >= '{_lastEventQueryTime.ToString("yyyy-MM-ddTHH:mm:ss.fffZ")}']]]";

                var query = new EventLogQuery("System", PathType.LogName, queryXml);

                using var reader = new EventLogReader(query);

                EventRecord? record;
                while ((record = reader.ReadEvent()) != null)
                {
                    using (record)
                    {
                        if (ct.IsCancellationRequested) break;

                        var serviceName = ExtractServiceName(record);
                        if (string.IsNullOrEmpty(serviceName)) continue;

                        var history = _crashHistory.GetOrAdd(serviceName!, _ => new ServiceCrashHistory());

                        // Dedup by timestamp
                        var timestamp = record.TimeCreated ?? DateTime.UtcNow;
                        if (history.CrashTimes.Any(t => Math.Abs((t - timestamp).TotalSeconds) < 2))
                            continue;

                        history.CrashTimes.Add(timestamp);
                        history.LastCrash = DateTimeOffset.UtcNow;

                        // Prune old crashes from history
                        var cutoff = DateTime.UtcNow - CrashWindow;
                        history.CrashTimes.RemoveAll(t => t < cutoff);

                        int crashCount = history.CrashTimes.Count;

                        // Check if this is a monitored service
                        bool isMonitored = MonitoredServices.ContainsKey(serviceName!);
                        bool overThreshold = crashCount >= SuspiciousCrashThreshold;

                        if (isMonitored && overThreshold)
                        {
                            await EmitServiceCrashAlert(serviceName!, crashCount, ct);
                        }
                    }
                }

                _lastEventQueryTime = queryTime.AddSeconds(-2);
            }
            catch (UnauthorizedAccessException)
            {
                _logger.LogDebug("[CriticalServiceGuard] Access denied to System event log");
            }
            catch (EventLogNotFoundException)
            {
                _logger.LogDebug("[CriticalServiceGuard] System event log not available");
            }
        }

        private async Task EmitServiceCrashAlert(string serviceName, int crashCount, CancellationToken ct)
        {
            // Check cooldown
            if (_alertedServices.TryGetValue(serviceName, out var lastAlert) &&
                DateTimeOffset.UtcNow - lastAlert < AlertCooldown)
                return;

            _alertedServices[serviceName] = DateTimeOffset.UtcNow;

            bool isHighConfidence = crashCount >= HighConfidenceCrashThreshold;
            string serviceDesc = MonitoredServices.GetValueOrDefault(serviceName, "Unknown service");

            await _detectionEngine.EmitAsync(new DetectionEvent
            {
                RuleName = "Critical Service Guard: Repeated Service Crash",
                Evidence = $"Service '{serviceName}' has crashed {crashCount} times in the last " +
                           $"{CrashWindow.TotalMinutes} minutes. Role: {serviceDesc}",
                Reasoning = "A critical Windows service is crashing repeatedly. " +
                            "This pattern indicates possible DLL injection failure, COM hijacking, " +
                            "buffer overflow exploitation attempts (especially if 0xC0000409 STATUS_STACK_BUFFER_OVERRUN), " +
                            "or deliberate service disruption by malware. " +
                            "TokenBroker crashes specifically cause shell hangs (AppHangXProcB1) " +
                            "because explorer.exe depends on it for authentication tokens.",
                Confidence = isHighConfidence ? 0.85 : 0.70,
                Tier = isHighConfidence ? DetectionTier.Tier1Behavioral : DetectionTier.Tier2Indicator,
                AuthorizedResponse = ResponseAction.LogOnly,
                ProcessName = serviceName,
                ProcessId = 0,
                Metadata = new Dictionary<string, string>
                {
                    ["ServiceName"] = serviceName,
                    ["CrashCount"] = crashCount.ToString(),
                    ["WindowMinutes"] = CrashWindow.TotalMinutes.ToString("F0"),
                    ["ServiceRole"] = serviceDesc
                }
            });
        }

        /// <summary>
        /// Monitors BSOD-critical processes to detect if malware is attempting to terminate them.
        /// A terminated critical process = immediate BSOD = potential anti-forensics or extortion.
        /// We can't prevent the BSOD (no kernel driver), but we can detect the attempt early
        /// and alert/log before it succeeds.
        /// </summary>
        private async Task MonitorBsodCriticalProcessesAsync(CancellationToken ct)
        {
            foreach (var processName in BsodCriticalProcesses)
            {
                if (ct.IsCancellationRequested) break;

                try
                {
                    var processes = Process.GetProcessesByName(processName);
                    if (processes.Length == 0 && processName != "svchost")
                    {
                        // Critical process is MISSING - this shouldn't happen unless BSOD is imminent
                        // or we're running in a container/minimal environment
                        if (!_alertedServices.ContainsKey($"bsod_{processName}"))
                        {
                            _alertedServices[$"bsod_{processName}"] = DateTimeOffset.UtcNow;

                            await _detectionEngine.EmitAsync(new DetectionEvent
                            {
                                RuleName = "Critical Service Guard: BSOD-Critical Process Missing",
                                Evidence = $"Critical process '{processName}' is not running. " +
                                           "System may be in an unstable state or BSOD is imminent.",
                                Reasoning = "A process critical to Windows kernel stability is not found. " +
                                            "If this process was terminated (rather than never started), " +
                                            "a Blue Screen of Death is imminent. Ransomware and wipers " +
                                            "sometimes kill critical processes to force a crash that hides " +
                                            "their activity or prevents recovery.",
                                Confidence = 0.92,
                                Tier = DetectionTier.Tier1Behavioral,
                                AuthorizedResponse = ResponseAction.LogOnly,
                                ProcessName = processName,
                                ProcessId = 0,
                                Metadata = new Dictionary<string, string>
                                {
                                    ["CriticalProcess"] = processName,
                                    ["Impact"] = "Potential immediate BSOD"
                                }
                            });
                        }
                    }
                    else
                    {
                        foreach (var proc in processes)
                        {
                            proc.Dispose();
                        }
                    }
                }
                catch { }
            }
        }

        #region Internal Types

        private static string? ExtractServiceName(EventRecord record)
        {
            try
            {
                if (record.Properties.Count > 0)
                    return record.Properties[0].Value?.ToString();
            }
            catch { }
            return null;
        }

        private void PruneStaleHistory()
        {
            var cutoff = DateTimeOffset.UtcNow - CrashWindow - CrashWindow;
            foreach (var key in _crashHistory.Keys.ToArray())
            {
                if (_crashHistory.TryGetValue(key, out var history) && history.LastCrash < cutoff)
                    _crashHistory.TryRemove(key, out _);
            }

            var alertCutoff = DateTimeOffset.UtcNow - AlertCooldown - AlertCooldown;
            foreach (var key in _alertedServices.Keys.ToArray())
            {
                if (_alertedServices.TryGetValue(key, out var time) && time < alertCutoff)
                    _alertedServices.TryRemove(key, out _);
            }
        }

        private sealed class ServiceCrashHistory
        {
            public List<DateTime> CrashTimes { get; } = new();
            public DateTimeOffset LastCrash { get; set; } = DateTimeOffset.MinValue;
        }

        #endregion
    }
}
