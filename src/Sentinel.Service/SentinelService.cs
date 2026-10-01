using System;
using System.Collections.Generic;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Sentinel.Core;

namespace Sentinel.Service
{
    public class SentinelService : BackgroundService
    {
        private readonly ILogger<SentinelService> _logger;
        private readonly SentinelConfig _config;
        private readonly JsonlEventLogger _eventLogger;
        private readonly DetectionEngine _detectionEngine;
        private readonly ProcessAncestryCache _ancestryCache;
        private readonly IEnumerable<IMonitor> _monitors;
        private readonly MonitorRegistry _monitorRegistry;

        // Unified ETW session - started before monitors for event-driven telemetry
        private readonly UnifiedEtwSession _unifiedEtwSession;
        private readonly EtwEventDispatcher _etwEventDispatcher;

        // Constructor-injected singletons that self-start
        private readonly UsbDeviceFingerprinter _usbDeviceFingerprinter;
        private readonly AppNetworkPolicyMonitor _networkPolicyMonitor;
        private readonly WmiProcessMonitor _wmiProcessMonitor;
        private readonly FileActivityMonitor _fileActivityMonitor;
        private readonly NetworkMonitor _networkMonitor;
        private readonly LsassDumpCanaryMonitor _lsassDumpCanaryMonitor;
        private readonly RouteTableMonitor _routeTableMonitor;
        private readonly MemoryBehaviorAnalyzer _memoryBehaviorAnalyzer;
        private readonly TokenIntegrityMonitor _tokenIntegrityMonitor;
        private readonly CredentialCanaryMonitor _credentialCanaryMonitor;
        private readonly LocalServerMonitor _localServerMonitor;
        private readonly ParentPidSpoofDetector _parentPidSpoofDetector;
        private readonly ChainTracer _chainTracer;
        private readonly SentinelEventLogWriter? _windowsEventLog;
        private readonly string _version;

        public SentinelService(
            ILogger<SentinelService> logger,
            SentinelConfig config,
            JsonlEventLogger eventLogger,
            DetectionEngine detectionEngine,
            ProcessAncestryCache ancestryCache,
            IEnumerable<IMonitor> monitors,
            UnifiedEtwSession unifiedEtwSession,
            EtwEventDispatcher etwEventDispatcher,
            UsbDeviceFingerprinter usbDeviceFingerprinter,
            AppNetworkPolicyMonitor networkPolicyMonitor,
            WmiProcessMonitor wmiProcessMonitor,
            FileActivityMonitor fileActivityMonitor,
            NetworkMonitor networkMonitor,
            LsassDumpCanaryMonitor lsassDumpCanaryMonitor,
            RouteTableMonitor routeTableMonitor,
            MemoryBehaviorAnalyzer memoryBehaviorAnalyzer,
            TokenIntegrityMonitor tokenIntegrityMonitor,
            CredentialCanaryMonitor credentialCanaryMonitor,
            LocalServerMonitor localServerMonitor,
            AdvancedResponseEngine responseEngine,
            IncidentResponseService incidentResponseService,
            DllUnloadEngine dllUnloadEngine,
            ParentPidSpoofDetector parentPidSpoofDetector,
            ChainTracer chainTracer,
            SentinelOrchestrator orchestrator,
            MonitorRegistry monitorRegistry,
            VpnShieldEngine vpnShieldEngine,
            SentinelEventLogWriter? windowsEventLog = null)
        {
            // Wire incident response into response engine (late binding to avoid circular DI)
            responseEngine.SetIncidentResponseService(incidentResponseService);
            responseEngine.SetDllUnloadEngine(dllUnloadEngine);
            responseEngine.SetChainTracer(chainTracer);
            // v2.6.0: Wire the protective VPN-shield engine (network-tamper remediation)
            responseEngine.SetVpnShieldEngine(vpnShieldEngine);
            // v1.6.1: budget-exhaustion Tier1 alerts
            responseEngine.SetDetectionEngine(detectionEngine);

            // v1.3.2: Wire orchestrator into detection engine
            detectionEngine.SetOrchestrator(orchestrator);

            // v2.6.0: Wire ancestry cache into ResponsePolicy for cross-PID chain correlation.
            ResponsePolicy.SetAncestryCache(ancestryCache);

            // v1.5.5 (WIRE-2): Validate all late-bindings were established.
            // If any SetXxx() call was accidentally removed during refactoring,
            // this logs CRITICAL at startup rather than silently degrading.
            ValidateLateBoundWiring(responseEngine, detectionEngine, logger);

            _logger = logger;
            _config = config;
            _eventLogger = eventLogger;
            _detectionEngine = detectionEngine;
            _ancestryCache = ancestryCache;
            _monitors = monitors;
            _monitorRegistry = monitorRegistry;
            _unifiedEtwSession = unifiedEtwSession;
            _etwEventDispatcher = etwEventDispatcher;
            _usbDeviceFingerprinter = usbDeviceFingerprinter;
            _networkPolicyMonitor = networkPolicyMonitor;
            _wmiProcessMonitor = wmiProcessMonitor;
            _fileActivityMonitor = fileActivityMonitor;
            _networkMonitor = networkMonitor;
            _lsassDumpCanaryMonitor = lsassDumpCanaryMonitor;
            _routeTableMonitor = routeTableMonitor;
            _memoryBehaviorAnalyzer = memoryBehaviorAnalyzer;
            _tokenIntegrityMonitor = tokenIntegrityMonitor;
            _credentialCanaryMonitor = credentialCanaryMonitor;
            _localServerMonitor = localServerMonitor;
            _parentPidSpoofDetector = parentPidSpoofDetector;
            _chainTracer = chainTracer;
            _windowsEventLog = windowsEventLog;
            _version = LoadVersion();
        }

        private static string LoadVersion()
        {
            var exeDir = AppContext.BaseDirectory;
            var versionFile = System.IO.Path.Combine(exeDir, "version.txt");
            if (System.IO.File.Exists(versionFile))
            {
                var text = System.IO.File.ReadAllText(versionFile).Trim();
                if (!string.IsNullOrEmpty(text)) return text;
            }
            return typeof(SentinelService).Assembly.GetName().Version?.ToString(3) ?? "0.0.0";
        }

        // The singleton monitors below are constructor-injected and self-start in their
        // own ctors/loops. They aren't part of _monitors or any MonitorGroup, so we
        // register them here and mark them running.
        private readonly List<string> _ownedSingletonNames = new();

        private void RegisterInjectedMonitors()
        {
            void Reg(string name, MonitorCategory cat)
            {
                _monitorRegistry.Register(name, cat, null);
                _monitorRegistry.MarkStarted(name);
                _ownedSingletonNames.Add(name);
            }

            Reg(nameof(UsbDeviceFingerprinter), MonitorCategory.UserProtection);
            Reg(nameof(AppNetworkPolicyMonitor), MonitorCategory.NetworkMonitoring);
            Reg(nameof(WmiProcessMonitor), MonitorCategory.ProcessMonitoring);
            Reg(nameof(FileActivityMonitor), MonitorCategory.FileMonitoring);
            Reg(nameof(NetworkMonitor), MonitorCategory.NetworkMonitoring);
            Reg(nameof(LsassDumpCanaryMonitor), MonitorCategory.CredentialProtection);
            Reg(nameof(RouteTableMonitor), MonitorCategory.NetworkMonitoring);
            Reg(nameof(MemoryBehaviorAnalyzer), MonitorCategory.MemoryAnalysis);
            Reg(nameof(TokenIntegrityMonitor), MonitorCategory.SystemIntegrity);
            Reg(nameof(CredentialCanaryMonitor), MonitorCategory.CredentialProtection);
            Reg(nameof(LocalServerMonitor), MonitorCategory.NetworkMonitoring);
            Reg(nameof(ParentPidSpoofDetector), MonitorCategory.ProcessMonitoring);
            Reg(nameof(ChainTracer), MonitorCategory.ResponseEngine);
        }

        private void HeartbeatOwnedMonitors()
        {
            try
            {
                foreach (var name in _ownedSingletonNames)
                    _monitorRegistry.Heartbeat(name);
                foreach (var monitor in _monitors)
                    _monitorRegistry.Heartbeat(monitor.Name);
            }
            catch { /* heartbeat is best-effort */ }
        }

        /// <summary>Best-effort category assignment for IMonitor implementations by name.</summary>
        private static MonitorCategory CategorizeMonitor(string name)
        {
            var n = name.ToLowerInvariant();
            if (n.Contains("dns") || n.Contains("network") || n.Contains("beacon") || n.Contains("exfil"))
                return MonitorCategory.NetworkMonitoring;
            if (n.Contains("file") || n.Contains("dll") || n.Contains("ads"))
                return MonitorCategory.FileMonitoring;
            if (n.Contains("cred") || n.Contains("lsass") || n.Contains("token"))
                return MonitorCategory.CredentialProtection;
            if (n.Contains("memory") || n.Contains("module"))
                return MonitorCategory.MemoryAnalysis;
            if (n.Contains("threatintel") || n.Contains("ioc") || n.Contains("reputation"))
                return MonitorCategory.ThreatIntel;
            if (n.Contains("etw") || n.Contains("process") || n.Contains("ghost") || n.Contains("ephemeral"))
                return MonitorCategory.ProcessMonitoring;
            return MonitorCategory.SystemIntegrity;
        }


        /// <summary>
        /// Invoked by the .NET host when the Service Control Manager issues a cooperative Stop
        /// (e.g. `sc stop`, host shutdown, upgrade/uninstall teardown). Recording this marks the
        /// impending process exit as <b>expected</b> so the AntiTamperGuard exit hook does not
        /// classify it as a suspicious tamper stop (threat-model B1 - alert-before-suppression).
        /// A hard kill (TerminateProcess) never routes through here, so it correctly stays
        /// classified as unexpected.
        /// </summary>
        public override Task StopAsync(CancellationToken cancellationToken)
        {
            // If OS shutdown already marked SystemShutdown, the first-writer-wins rule keeps it.
            Sentinel.Core.ShutdownContext.MarkExpected(
                Sentinel.Core.ExpectedShutdownReason.ServiceControllerStop);
            return base.StopAsync(cancellationToken);
        }

        protected override async Task ExecuteAsync(CancellationToken stoppingToken)
        {
            // STABILITY v1.4.8: If ExecuteAsync returns for ANY reason, the .NET Host
            // shuts down the entire process. Wrap everything so we NEVER return early.
            try
            {
            _logger.LogInformation("Sentinel Service starting...");

            // Startup Self-Test
            if (!RunStartupSelfTest())
            {
                _logger.LogCritical("Sentinel startup self-test FAILED. Stopping service.");
                return;
            }

            // Start Unified ETW Session - v1.5.5: Re-enabled with corrected P/Invoke implementation.
            // Uses buffer-offset approach instead of marshaled structs to avoid alignment issues.
            // Falls back gracefully to WMI/polling if ETW start fails (non-admin, session limit, etc.)
            try
            {
                _etwEventDispatcher.RegisterHandlers(_unifiedEtwSession);
                await _unifiedEtwSession.StartAsync(CancellationToken.None);
                if (_unifiedEtwSession.IsActive)
                {
                    _logger.LogInformation("UnifiedEtwSession active - real-time telemetry at ~50ms latency");
                    // Disable WMI process monitor when ETW is active (prevents duplicate events)
                    _wmiProcessMonitor.Disable();
                }
                else
                {
                    _logger.LogWarning("UnifiedEtwSession not active - using WMI/polling fallback (higher latency)");
                }
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "UnifiedEtwSession start failed - using WMI/polling fallback");
            }

            // Register the constructor-injected singleton monitors that self-start
            // (WMI/File/Network/etc.). These run but were never tracked by the registry,
            // which is why the dashboard showed 0/0 monitors running.
            RegisterInjectedMonitors();

            // Start all IMonitor implementations
            foreach (var monitor in _monitors)
            {
                if (stoppingToken.IsCancellationRequested) break;
                _monitorRegistry.Register(monitor.Name, CategorizeMonitor(monitor.Name), monitor);
                try
                {
                    await monitor.StartAsync(CancellationToken.None);
                    _monitorRegistry.MarkStarted(monitor.Name);
                    _logger.LogInformation("Started monitor: {Monitor}", monitor.Name);
                }
                catch (OperationCanceledException) { break; }
                catch (Exception ex)
                {
                    _monitorRegistry.MarkFailed(monitor.Name, ex);
                    _logger.LogError(ex, "Failed to start monitor: {Monitor}", monitor.Name);
                }
            }

            _logger.LogInformation("Sentinel Service successfully started.");

            await _eventLogger.LogEventAsync("service_start", new
            {
                Status = "started",
                Version = _version,
                Timestamp = DateTime.UtcNow,
                WindowsEventLogAvailable = _windowsEventLog?.IsAvailable == true,
                WindowsEventLogDisabled = _windowsEventLog?.IsPermanentlyDisabled == true
                    ? _windowsEventLog.DisableReason
                    : null
            });

            try
            {
                _windowsEventLog?.WriteServiceStart(_version);
            }
            catch { /* Event Log optional on stripped Windows */ }

            try
            {
                _logger.LogInformation("Entering main keep-alive loop. StoppingToken cancelled: {Cancelled}", stoppingToken.IsCancellationRequested);
                while (!stoppingToken.IsCancellationRequested)
                {
                    await Task.Delay(5000, stoppingToken);

                    // Heartbeat the monitors this service owns so the registry watchdog
                    // keeps them marked Running (they don't self-heartbeat).
                    HeartbeatOwnedMonitors();
                }
            }
            catch (OperationCanceledException) { }
            catch (Exception ex)
            {
                _logger.LogCritical(ex, "Unexpected exception in keep-alive loop");
            }
            finally
            {
                _logger.LogInformation("Sentinel Service stopping...");
                try { _windowsEventLog?.WriteServiceStop(_version); } catch { /* optional */ }

                // Stop and dispose IMonitors
                foreach (var monitor in _monitors)
                {
                    _monitorRegistry.MarkStopped(monitor.Name);
                    try { await monitor.StopAsync(); }
                    catch (Exception ex) { _logger.LogError(ex, "Error stopping monitor: {Monitor}", monitor.Name); }

                    if (monitor is IDisposable disposable)
                    {
                        try { disposable.Dispose(); }
                        catch (Exception ex) { _logger.LogError(ex, "Error disposing monitor: {Monitor}", monitor.Name); }
                    }
                }

                // Dispose of other injected singletons to prevent handle/thread leaks
                var disposables = new object[]
                {
                    _usbDeviceFingerprinter,
                    _networkPolicyMonitor,
                    _wmiProcessMonitor,
                    _fileActivityMonitor,
                    _networkMonitor,
                    _lsassDumpCanaryMonitor,
                    _routeTableMonitor,
                    _memoryBehaviorAnalyzer,
                    _tokenIntegrityMonitor,
                    _credentialCanaryMonitor,
                    _localServerMonitor,
                    _parentPidSpoofDetector,
                    _chainTracer
                };

                foreach (var item in disposables)
                {
                    if (item is IDisposable disposable)
                    {
                        try
                        {
                            disposable.Dispose();
                        }
                        catch (Exception ex)
                        {
                            _logger.LogError(ex, "Error disposing singleton: {Type}", item.GetType().Name);
                        }
                    }
                }

                _ancestryCache.Stop();
                _detectionEngine.Stop();
                await _unifiedEtwSession.StopAsync();
            }
            }
            catch (Exception ex)
            {
                // STABILITY: Never let ExecuteAsync return - that kills the host.
                // Log the error and enter infinite sleep until SCM sends stop signal.
                _logger.LogCritical(ex, "FATAL: ExecuteAsync threw unexpectedly. Entering infinite wait to prevent host shutdown.");
                try { await Task.Delay(Timeout.Infinite, stoppingToken); } catch { }
            }
        }

        private bool RunStartupSelfTest()
        {
            _logger.LogInformation("Running startup self-test...");

            // 1. Verify log path access
            var logDir = Path.GetDirectoryName(_eventLogger.LogFilePath);
            if (string.IsNullOrEmpty(logDir))
                logDir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "Sentinel");
            if (!Directory.Exists(logDir))
            {
                try
                {
                    Directory.CreateDirectory(logDir);
                }
                catch (Exception ex)
                {
                    _logger.LogError($"Self-test failed to create log directory: {ex.Message}");
                    return false;
                }
            }

            // 2. Verify quarantine access
            var quarantineDir = Path.Combine(logDir, "Quarantine");
            if (!Directory.Exists(quarantineDir))
            {
                try
                {
                    Directory.CreateDirectory(quarantineDir);
                }
                catch (Exception ex)
                {
                    _logger.LogError($"Self-test failed to create quarantine directory: {ex.Message}");
                    return false;
                }
            }

            // 3. Verify process hardening module
            if (!HardeningModule.ApplyOrFail())
            {
                _logger.LogWarning("Self-test: HardeningModule.ApplyOrFail returned false (likely non-fatal, continuing).");
            }

            _logger.LogInformation("Startup self-test PASSED.");
            return true;
        }

        /// <summary>
        /// v1.5.5 (WIRE-2): Validates that all late-bound SetXxx() wirings are complete.
        /// Logs CRITICAL if any orchestrator/response-engine binding is null, which would
        /// cause silent fallback to degraded behavior (e.g. bypassing incident grouping).
        /// </summary>
        private static void ValidateLateBoundWiring(
            AdvancedResponseEngine responseEngine,
            DetectionEngine detectionEngine,
            ILogger logger)
        {
            // Use reflection to check private nullable fields that should be non-null after wiring
            var reType = typeof(AdvancedResponseEngine);
            var fields = new[] { "_incidentResponse", "_dllUnloadEngine", "_chainTracer", "_vpnShieldEngine" };
            foreach (var fieldName in fields)
            {
                var field = reType.GetField(fieldName, System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance);
                if (field != null && field.GetValue(responseEngine) == null)
                {
                    logger.LogCritical("WIRE VALIDATION FAILED: AdvancedResponseEngine.{Field} is null after startup wiring. " +
                        "This indicates a missed SetXxx() call. Response actions may be degraded.", fieldName);
                }
            }

            // DetectionEngine orchestrator check
            var deType = typeof(DetectionEngine);
            var orchField = deType.GetField("_orchestrator", System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance);
            if (orchField != null && orchField.GetValue(detectionEngine) == null)
            {
                logger.LogCritical("WIRE VALIDATION FAILED: DetectionEngine._orchestrator is null after startup wiring. " +
                    "Detections will bypass incident grouping and response coordination.");
            }
        }
    }
}

