using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace Sentinel.Core
{
    /// <summary>
    /// Tracks all running monitors with heartbeat supervision and crash recovery.
    ///
    /// Problem solved: Previously, if a BackgroundService monitor crashed (unhandled
    /// exception in ExecuteAsync), nobody noticed until a manual health check 5 minutes
    /// later - and even then, no recovery was attempted. The monitor just stayed dead.
    ///
    /// MonitorRegistry provides:
    ///   - Heartbeat tracking: monitors call Heartbeat() periodically (piggybacks on existing loops)
    ///   - Crash detection: watchdog timer identifies monitors that haven't heartbeated
    ///   - Auto-restart: restarts crashed BackgroundService monitors via IHostedService lifecycle
    ///   - Status dashboard: real-time view of all monitor states for health reporting
    ///   - Degradation alerts: fires detection events when monitors die (attacker may have killed them)
    /// </summary>
    public sealed class MonitorRegistry : IDisposable
    {
        private readonly DetectionEngine _detectionEngine;
        private readonly JsonlEventLogger _eventLogger;
        private readonly ILogger<MonitorRegistry> _logger;
        private readonly System.Threading.Timer _watchdogTimer;

        private readonly ConcurrentDictionary<string, MonitorStatus> _monitors = new();

        private static readonly TimeSpan WatchdogInterval = TimeSpan.FromSeconds(15);
        private static readonly TimeSpan HeartbeatTimeout = TimeSpan.FromSeconds(60);
        private static readonly TimeSpan CriticalTimeout = TimeSpan.FromMinutes(3);

        public MonitorRegistry(
            DetectionEngine detectionEngine,
            JsonlEventLogger eventLogger,
            ILogger<MonitorRegistry> logger)
        {
            _detectionEngine = detectionEngine;
            _eventLogger = eventLogger;
            _logger = logger;
            _watchdogTimer = new System.Threading.Timer(WatchdogTick, null, WatchdogInterval, WatchdogInterval);
        }

        /// <summary>
        /// Registers a monitor for supervision. Called during startup sequencing.
        /// </summary>
        public void Register(string name, MonitorCategory category, object? serviceInstance = null)
        {
            _monitors[name] = new MonitorStatus
            {
                Name = name,
                Category = category,
                State = MonitorState.Starting,
                RegisteredAt = DateTimeOffset.UtcNow,
                LastHeartbeat = DateTimeOffset.UtcNow,
                ServiceInstance = serviceInstance
            };
            _logger.LogDebug("[MonitorRegistry] Registered: {Name} ({Category})", name, category);
        }

        /// <summary>
        /// Called by monitors to report they are alive and processing.
        /// Monitors piggyback this onto their existing scan/poll loops - zero overhead.
        /// </summary>
        public void Heartbeat(string name)
        {
            if (_monitors.TryGetValue(name, out var status))
            {
                status.LastHeartbeat = DateTimeOffset.UtcNow;
                status.HeartbeatCount++;
                if (status.State == MonitorState.Starting || status.State == MonitorState.Recovering)
                {
                    status.State = MonitorState.Running;
                    status.StartedAt = DateTimeOffset.UtcNow;
                }
            }
        }

        /// <summary>
        /// Marks a monitor as started successfully.
        /// </summary>
        public void MarkStarted(string name)
        {
            if (_monitors.TryGetValue(name, out var status))
            {
                status.State = MonitorState.Running;
                status.StartedAt = DateTimeOffset.UtcNow;
                status.LastHeartbeat = DateTimeOffset.UtcNow;
            }
        }

        /// <summary>
        /// Marks a monitor as failed (exception during start or execution).
        /// </summary>
        public void MarkFailed(string name, Exception? ex = null)
        {
            if (_monitors.TryGetValue(name, out var status))
            {
                status.State = MonitorState.Failed;
                status.LastError = ex?.Message;
                status.FailureCount++;
                status.LastFailure = DateTimeOffset.UtcNow;
            }
        }

        /// <summary>
        /// Marks a monitor as cleanly stopped.
        /// </summary>
        public void MarkStopped(string name)
        {
            if (_monitors.TryGetValue(name, out var status))
            {
                status.State = MonitorState.Stopped;
            }
        }

        /// <summary>
        /// Returns all monitor statuses for health dashboard.
        /// </summary>
        public IReadOnlyList<MonitorStatus> GetAllStatuses()
        {
            return _monitors.Values.OrderBy(m => m.Category).ThenBy(m => m.Name).ToList();
        }

        /// <summary>
        /// Returns monitors that are currently unhealthy (failed, stale heartbeat, or not started).
        /// </summary>
        public IReadOnlyList<MonitorStatus> GetUnhealthyMonitors()
        {
            var now = DateTimeOffset.UtcNow;
            return _monitors.Values
                .Where(m => m.State == MonitorState.Failed ||
                           (m.State == MonitorState.Running && now - m.LastHeartbeat > HeartbeatTimeout) ||
                           m.State == MonitorState.Starting && now - m.RegisteredAt > TimeSpan.FromSeconds(30))
                .ToList();
        }

        public MonitorRegistryStats GetStats() => new()
        {
            TotalRegistered = _monitors.Count,
            Running = _monitors.Count(m => m.Value.State == MonitorState.Running),
            Failed = _monitors.Count(m => m.Value.State == MonitorState.Failed),
            Stale = _monitors.Count(m => m.Value.State == MonitorState.Running &&
                                         DateTimeOffset.UtcNow - m.Value.LastHeartbeat > HeartbeatTimeout)
        };

        // 
        // Watchdog - crash detection and alerting
        // 

        private void WatchdogTick(object? state)
        {
            var now = DateTimeOffset.UtcNow;

            foreach (var (name, status) in _monitors)
            {
                if (status.State == MonitorState.Stopped || status.State == MonitorState.Starting)
                    continue;

                var timeSinceHeartbeat = now - status.LastHeartbeat;

                // Stale heartbeat -> mark as failed if past critical timeout
                if (status.State == MonitorState.Running && timeSinceHeartbeat > CriticalTimeout)
                {
                    _logger.LogWarning(
                        "[MonitorRegistry] WATCHDOG: Monitor '{Name}' has not heartbeated for {Seconds:F0}s - marking FAILED",
                        name, timeSinceHeartbeat.TotalSeconds);

                    status.State = MonitorState.Failed;
                    status.LastError = $"Heartbeat timeout ({timeSinceHeartbeat.TotalSeconds:F0}s)";
                    status.FailureCount++;
                    status.LastFailure = now;

                    // Fire a detection - monitor death could indicate attacker tampering
                    _ = _detectionEngine.EmitAsync(new DetectionEvent
                    {
                        RuleName = "Anti-Tamper: Monitor Crashed/Killed",
                        Evidence = $"Monitor '{name}' ({status.Category}) stopped heartbeating after {timeSinceHeartbeat.TotalSeconds:F0}s. " +
                                   $"Failure count: {status.FailureCount}.",
                        Reasoning = "A security monitor stopped responding. This could indicate a crash from malware " +
                                    "interference, resource exhaustion attack, or deliberate process injection that " +
                                    "corrupted the monitor's execution state.",
                        Confidence = status.FailureCount > 2 ? 0.85 : 0.60,
                        Tier = status.FailureCount > 2 ? DetectionTier.Tier1Behavioral : DetectionTier.Tier2Indicator,
                        AuthorizedResponse = ResponseAction.LogOnly,
                        ProcessName = "Sentinel.Service",
                        ProcessId = System.Net48Environment.ProcessId,
                        SignalType = SignalType.AntiTamper,
                        Metadata = new Dictionary<string, string>
                        {
                            ["MonitorName"] = name,
                            ["Category"] = status.Category.ToString(),
                            ["FailureCount"] = status.FailureCount.ToString(),
                            ["LastHeartbeat"] = status.LastHeartbeat.ToString("O")
                        }
                    });

                    // Log to event journal
                    _ = _eventLogger.LogEventAsync("monitor_failed", new
                    {
                        Monitor = name,
                        status.Category,
                        status.FailureCount,
                        TimeSinceHeartbeat = timeSinceHeartbeat.TotalSeconds,
                        Timestamp = now
                    });

                    // Attempt restart if the monitor is a BackgroundService
                    AttemptRestart(name, status);
                }
                else if (status.State == MonitorState.Running && timeSinceHeartbeat > HeartbeatTimeout)
                {
                    // Warning level - heartbeat is stale but not yet critical
                    _logger.LogDebug(
                        "[MonitorRegistry] Monitor '{Name}' heartbeat stale ({Seconds:F0}s)",
                        name, timeSinceHeartbeat.TotalSeconds);
                }
            }
        }

        // 
        // Auto-Restart
        // 

        private void AttemptRestart(string name, MonitorStatus status)
        {
            // Only attempt restart if failure count is reasonable (prevent restart loops)
            if (status.FailureCount > 5)
            {
                _logger.LogError("[MonitorRegistry] Monitor '{Name}' has failed {Count} times - giving up on restart",
                    name, status.FailureCount);
                return;
            }

            if (status.ServiceInstance is BackgroundService bgService)
            {
                _ = Task.Run(async () =>
                {
                    try
                    {
                        _logger.LogWarning("[MonitorRegistry] Attempting restart of '{Name}'...", name);
                        status.State = MonitorState.Recovering;

                        // Stop then start (BackgroundService lifecycle)
                        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
                        try { await bgService.StopAsync(cts.Token); } catch { }

                        await Task.Delay(1000); // Brief cooldown

                        using var startCts = new CancellationTokenSource(TimeSpan.FromSeconds(30));
                        await bgService.StartAsync(startCts.Token);

                        status.State = MonitorState.Running;
                        status.LastHeartbeat = DateTimeOffset.UtcNow;
                        _logger.LogWarning("[MonitorRegistry] Successfully restarted '{Name}'", name);

                        _ = _eventLogger.LogEventAsync("monitor_restarted", new
                        {
                            Monitor = name,
                            status.FailureCount,
                            Timestamp = DateTimeOffset.UtcNow
                        });
                    }
                    catch (Exception ex)
                    {
                        _logger.LogError(ex, "[MonitorRegistry] Restart FAILED for '{Name}'", name);
                        status.State = MonitorState.Failed;
                        status.LastError = $"Restart failed: {ex.Message}";
                    }
                });
            }
            else if (status.ServiceInstance is IMonitor monitor)
            {
                _ = Task.Run(async () =>
                {
                    try
                    {
                        _logger.LogWarning("[MonitorRegistry] Attempting restart of IMonitor '{Name}'...", name);
                        status.State = MonitorState.Recovering;

                        try { await monitor.StopAsync(); } catch { }
                        await Task.Delay(1000);

                        using var cts = new CancellationTokenSource();
                        await monitor.StartAsync(cts.Token);

                        status.State = MonitorState.Running;
                        status.LastHeartbeat = DateTimeOffset.UtcNow;
                        _logger.LogWarning("[MonitorRegistry] Successfully restarted IMonitor '{Name}'", name);
                    }
                    catch (Exception ex)
                    {
                        _logger.LogError(ex, "[MonitorRegistry] IMonitor restart FAILED for '{Name}'", name);
                        status.State = MonitorState.Failed;
                        status.LastError = $"Restart failed: {ex.Message}";
                    }
                });
            }
            else
            {
                _logger.LogDebug("[MonitorRegistry] Cannot restart '{Name}' - no service instance registered", name);
            }
        }

        public void Dispose()
        {
            _watchdogTimer.Dispose();
        }
    }

    // 
    // Data Models
    // 

    public enum MonitorState
    {
        Starting,
        Running,
        Failed,
        Recovering,
        Stopped
    }

    public enum MonitorCategory
    {
        ProcessMonitoring,    // WMI, ETW, Ephemeral, Ghost
        NetworkMonitoring,    // NetworkMonitor, Beaconing, DNS, DoH, DataExfil
        FileMonitoring,       // FileActivity, FileVerdict, DllScanner
        MemoryAnalysis,       // MemoryBehavior, DllEntropy, RuntimeModule, SyscallStub
        CredentialProtection, // LSASS canary, CredentialCanary, BrowserCred
        SystemIntegrity,      // AntiTamper, CriticalService, SecureBoot, FirewallIntegrity
        UserProtection,       // Clickjacking, ScreenCapture, Webcam, Audio
        ThreatIntel,          // IoC, FileReputation, HashReputation
        ResponseEngine        // AdvancedResponse, ChainTracer, Quarantine, Isolation
    }

    public sealed class MonitorStatus
    {
        public string Name { get; set; } = "";
        public MonitorCategory Category { get; set; }
        public MonitorState State { get; set; }
        public DateTimeOffset RegisteredAt { get; set; }
        public DateTimeOffset? StartedAt { get; set; }
        public DateTimeOffset LastHeartbeat { get; set; }
        public long HeartbeatCount { get; set; }
        public int FailureCount { get; set; }
        public DateTimeOffset? LastFailure { get; set; }
        public string? LastError { get; set; }
        public object? ServiceInstance { get; set; }
    }

    public sealed class MonitorRegistryStats
    {
        public int TotalRegistered { get; set; }
        public int Running { get; set; }
        public int Failed { get; set; }
        public int Stale { get; set; }
    }
}
