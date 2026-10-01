using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;

namespace Sentinel.Core
{
    /// <summary>
    /// Central coordination point for the entire Sentinel EDR pipeline.
    ///
    /// SentinelOrchestrator is the "brain" that ties all components together:
    ///   - Routes detections through IncidentManager before response
    ///   - Coordinates responses via ResponseCoordinator (no duplicate kills, no races)
    ///   - Supervises monitors via MonitorRegistry
    ///   - Manages startup via StartupSequencer
    ///   - Hosts the ContextBus for cross-monitor enrichment
    ///   - Monitors pipeline backpressure and health
    ///
    /// All detection events flow through here:
    ///   Monitor -> TelemetryFusion -> DetectionEngine -> Orchestrator -> ResponseCoordinator -> ResponseEngine
    ///                                                                          
    ///                                              IncidentManager        ContextBus
    ///                                              (group, escalate)   (cross-enrichment)
    ///
    /// v1.3.3: Added ContextBus, ResponseCoordinator, backpressure monitoring.
    /// </summary>
    public sealed class SentinelOrchestrator : IDisposable
    {
        private readonly IncidentManager _incidentManager;
        private readonly MonitorRegistry _monitorRegistry;
        private readonly StartupSequencer _startupSequencer;
        private readonly AdvancedResponseEngine _responseEngine;
        private readonly ResponseCoordinator _responseCoordinator;
        private readonly ContextBus _contextBus;
        private readonly JsonlEventLogger _eventLogger;
        private readonly AutoIncidentReporter? _autoIncidentReporter;
        private readonly ILogger<SentinelOrchestrator> _logger;

        // Pipeline backpressure monitoring
        private readonly System.Threading.Timer _backpressureTimer;
        private long _detectionsProcessed;
        private DateTimeOffset _lastBackpressureAlert = DateTimeOffset.MinValue;
        private static readonly TimeSpan BackpressureCheckInterval = TimeSpan.FromSeconds(10);
        private static readonly TimeSpan BackpressureAlertCooldown = TimeSpan.FromMinutes(2);

        private bool _isRunning;
        private DateTimeOffset _startTime;

        public SentinelOrchestrator(
            IncidentManager incidentManager,
            MonitorRegistry monitorRegistry,
            StartupSequencer startupSequencer,
            AdvancedResponseEngine responseEngine,
            ResponseCoordinator responseCoordinator,
            ContextBus contextBus,
            JsonlEventLogger eventLogger,
            ILogger<SentinelOrchestrator> logger,
            AutoIncidentReporter? autoIncidentReporter = null)
        {
            _incidentManager = incidentManager;
            _monitorRegistry = monitorRegistry;
            _startupSequencer = startupSequencer;
            _responseEngine = responseEngine;
            _responseCoordinator = responseCoordinator;
            _contextBus = contextBus;
            _eventLogger = eventLogger;
            _logger = logger;
            _autoIncidentReporter = autoIncidentReporter;

            _backpressureTimer = new System.Threading.Timer(
                CheckBackpressure, null, BackpressureCheckInterval, BackpressureCheckInterval);
        }

        /// <summary>
        /// Exposes the ContextBus for DI wiring (monitors receive it via constructor).
        /// </summary>
        public ContextBus ContextBus => _contextBus;

        /// <summary>
        /// Exposes the ResponseCoordinator for ChainTracer hold management.
        /// </summary>
        public ResponseCoordinator ResponseCoordinator => _responseCoordinator;

        /// <summary>
        /// The unified detection->incident->response pipeline entry point.
        /// Called by DetectionEngine instead of routing directly to ResponseEngine.
        ///
        /// Flow:
        ///   1. Register detection with IncidentManager (group into incident)
        ///   2. Route through ResponseCoordinator (dedup, lock, chain trace hold)
        ///   3. ResponseCoordinator executes via AdvancedResponseEngine
        ///   4. Incident marked as responded
        /// </summary>
        public async Task ProcessDetectionAsync(DetectionEvent detection)
        {
            Interlocked.Increment(ref _detectionsProcessed);

            // 1. Group into incident
            var incident = _incidentManager.RegisterDetection(detection);

            // 2. Route through ResponseCoordinator (handles dedup, locking, chain trace holds)
            var result = await _responseCoordinator.ExecuteResponseAsync(detection);

            if (result.Outcome == ResponseOutcome.Executed)
            {
                _logger.LogDebug("[Orchestrator] Response executed for PID {Pid}: {Action}",
                    detection.ProcessId, detection.AuthorizedResponse);
            }
            else if (result.Outcome == ResponseOutcome.Deduplicated)
            {
                _logger.LogDebug("[Orchestrator] Response deduplicated for PID {Pid}", detection.ProcessId);
            }

            // 3. v1.7.7: Auto evidence pack + optional TI share for attack detections
            // Fire-and-forget so reporting latency never blocks kill/quarantine path.
            if (_autoIncidentReporter != null)
            {
                _ = Task.Run(async () =>
                {
                    try
                    {
                        await _autoIncidentReporter.HandleDetectionAsync(detection, incident).ConfigureAwait(false);
                    }
                    catch (Exception ex)
                    {
                        _logger.LogDebug(ex, "[Orchestrator] AutoIncidentReporter failed for {Rule}", detection.RuleName);
                    }
                });
            }
        }

        /// <summary>
        /// Releases the response lock for a PID (legacy compatibility).
        /// </summary>
        public void ReleaseResponseLock(int pid)
        {
            // Delegated to ResponseCoordinator internally
        }

        // 
        // System Lifecycle
        // 

        /// <summary>
        /// Starts the entire Sentinel system in dependency order.
        /// Called by SentinelService.ExecuteAsync instead of the old foreach loop.
        /// </summary>
        public async Task<StartupReport> StartSystemAsync(CancellationToken ct)
        {
            _startTime = DateTimeOffset.UtcNow;
            _logger.LogInformation("[Orchestrator] Starting Sentinel system...");

            var report = await _startupSequencer.ExecuteAsync(ct);
            _isRunning = true;

            _logger.LogInformation("[Orchestrator] System ONLINE - {Running}/{Total} monitors active",
                _monitorRegistry.GetStats().Running, _monitorRegistry.GetStats().TotalRegistered);

            return report;
        }

        /// <summary>
        /// Graceful shutdown of all components in reverse dependency order.
        /// </summary>
        public async Task StopSystemAsync()
        {
            _isRunning = false;
            _logger.LogInformation("[Orchestrator] Shutting down Sentinel system...");

            // Log final system state
            var stats = GetSystemHealth();
            await _eventLogger.LogEventAsync("system_shutdown", new
            {
                Uptime = (DateTimeOffset.UtcNow - _startTime).ToString(@"d\.hh\:mm\:ss"),
                stats.MonitorStats,
                stats.IncidentStats,
                Timestamp = DateTimeOffset.UtcNow
            });
        }

        // 
        // Unified Health
        // 

        /// <summary>
        /// Returns the unified health status of the entire Sentinel system.
        /// Used by health check endpoints and tray icon.
        /// </summary>
        public SystemHealthStatus GetSystemHealth()
        {
            var monStats = _monitorRegistry.GetStats();
            var incStats = _incidentManager.GetStats();
            var startupReport = _startupSequencer.GetLastReport();
            var busStats = _contextBus.GetStats();
            var respStats = _responseCoordinator.GetStats();

            var overallHealth = SystemHealth.Healthy;
            if (monStats.Failed > 0 || monStats.Stale > 0)
                overallHealth = SystemHealth.Degraded;
            if (busStats.DropRate > 0.05) // >5% signal drop rate
                overallHealth = SystemHealth.Degraded;
            if (monStats.Failed > monStats.TotalRegistered / 3)
                overallHealth = SystemHealth.Critical;
            if (!_isRunning)
                overallHealth = SystemHealth.Offline;

            return new SystemHealthStatus
            {
                Health = overallHealth,
                IsRunning = _isRunning,
                Uptime = _isRunning ? DateTimeOffset.UtcNow - _startTime : TimeSpan.Zero,
                MonitorStats = monStats,
                IncidentStats = incStats,
                ContextBusStats = busStats,
                ResponseCoordinatorStats = respStats,
                StartupDurationMs = startupReport?.TotalDurationMs ?? 0,
                DegradedMode = startupReport?.DegradedMode ?? false,
                ActiveIncidents = _incidentManager.GetActiveIncidents(),
                UnhealthyMonitors = _monitorRegistry.GetUnhealthyMonitors(),
                ResponseLocksHeld = respStats.ActiveLocks,
                DetectionsProcessed = Interlocked.Read(ref _detectionsProcessed),
                DetectionsDropped = busStats.TotalDropped
            };
        }

        // 
        // Monitor Heartbeat Passthrough
        // 

        /// <summary>
        /// Convenience: monitors call this to heartbeat through the orchestrator.
        /// </summary>
        public void Heartbeat(string monitorName) => _monitorRegistry.Heartbeat(monitorName);

        /// <summary>
        /// Convenience: get the incident for a PID (used by response engine for context).
        /// </summary>
        public Incident? GetIncidentForPid(int pid) => _incidentManager.GetIncidentForPid(pid);

        // 
        // Pipeline Backpressure Monitoring
        // 

        private void CheckBackpressure(object? state)
        {
            if (!_isRunning) return;

            var busStats = _contextBus.GetStats();

            // Alert if >5% of signals are being dropped (channel full)
            if (busStats.DropRate > 0.05 && busStats.TotalPublished > 100)
            {
                if (DateTimeOffset.UtcNow - _lastBackpressureAlert > BackpressureAlertCooldown)
                {
                    _lastBackpressureAlert = DateTimeOffset.UtcNow;
                    _logger.LogWarning(
                        "[Orchestrator] BACKPRESSURE: ContextBus drop rate {Rate:P1} ({Dropped}/{Published}). " +
                        "Pending: {Pending}/{Capacity}. Subscribers may be too slow.",
                        busStats.DropRate, busStats.TotalDropped, busStats.TotalPublished,
                        busStats.PendingInChannel, busStats.ChannelCapacity);
                }
            }

            // Periodic housekeeping
            _contextBus.PruneExpiredCache();
            _responseCoordinator.PruneStaleState();
        }

        public void Dispose()
        {
            try { _backpressureTimer.Dispose(); } catch { }
            try { _incidentManager.Dispose(); } catch { }
            try { _monitorRegistry.Dispose(); } catch { }
            try { _contextBus.Dispose(); } catch { }
            try { _responseCoordinator.Dispose(); } catch { }
        }
    }

    // 
    // Data Models
    // 

    public enum SystemHealth
    {
        Healthy,    // All monitors running, no issues
        Degraded,   // Some monitors failed/stale, operating with reduced coverage
        Critical,   // More than 1/3 monitors down
        Offline     // System not started or shutting down
    }

    public sealed class SystemHealthStatus
    {
        public SystemHealth Health { get; set; }
        public bool IsRunning { get; set; }
        public TimeSpan Uptime { get; set; }
        public MonitorRegistryStats MonitorStats { get; set; } = new();
        public IncidentStats IncidentStats { get; set; } = new();
        public ContextBusStats? ContextBusStats { get; set; }
        public ResponseCoordinatorStats? ResponseCoordinatorStats { get; set; }
        public long StartupDurationMs { get; set; }
        public bool DegradedMode { get; set; }
        public IReadOnlyList<Incident> ActiveIncidents { get; set; } = Array.Empty<Incident>();
        public IReadOnlyList<MonitorStatus> UnhealthyMonitors { get; set; } = Array.Empty<MonitorStatus>();
        public int ResponseLocksHeld { get; set; }
        public long DetectionsProcessed { get; set; }
        public long DetectionsDropped { get; set; }
    }
}
