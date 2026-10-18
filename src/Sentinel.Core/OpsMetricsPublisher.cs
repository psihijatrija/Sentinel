using System;
using System.IO;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Sentinel.Core.Plugins;

namespace Sentinel.Core
{
    /// <summary>
    /// v2.0 - Publishes ops_metrics.json for the Agent Ops dashboard.
    /// Fail-soft: never crashes the host if ProgramData is unavailable.
    /// </summary>
    public sealed class OpsMetricsPublisher : BackgroundService
    {
        private readonly SentinelMetrics _metrics;
        private readonly MonitorRegistry? _monitorRegistry;
        private readonly JsonlEventLogger? _eventLogger;
        private readonly DetectionEngine? _detectionEngine;
        private readonly UnifiedEtwSession? _etw;
        private readonly PluginRegistry _plugins;
        private readonly WeightedCorrelationConfig _weightedConfig;
        private readonly ILogger<OpsMetricsPublisher> _logger;
        private readonly string _outputPath;

        public OpsMetricsPublisher(
            SentinelMetrics metrics,
            PluginRegistry plugins,
            WeightedCorrelationConfig weightedConfig,
            ILogger<OpsMetricsPublisher> logger,
            MonitorRegistry? monitorRegistry = null,
            JsonlEventLogger? eventLogger = null, DetectionEngine? detectionEngine = null, UnifiedEtwSession? etw = null)
        {
            _metrics = metrics;
            _plugins = plugins;
            _weightedConfig = weightedConfig;
            _logger = logger;
            _monitorRegistry = monitorRegistry;
            _eventLogger = eventLogger;
            _detectionEngine = detectionEngine;
            _etw = etw;

            var programData = Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData);
            _outputPath = Path.Combine(programData, "Sentinel", "ops_metrics.json");
        }

        protected override async Task ExecuteAsync(CancellationToken stoppingToken)
        {
            // Delay first publish until monitors start
            try { await Task.Delay(TimeSpan.FromSeconds(8), stoppingToken).ConfigureAwait(false); }
            catch (OperationCanceledException) { return; }

            while (!stoppingToken.IsCancellationRequested)
            {
                try
                {
                    PublishOnce();
                }
                catch (Exception ex)
                {
                    _logger.LogDebug(ex, "[OpsMetrics] Publish failed");
                }

                try
                {
                    await Task.Delay(TimeSpan.FromSeconds(10), stoppingToken).ConfigureAwait(false);
                }
                catch (OperationCanceledException)
                {
                    break;
                }
            }
        }

        public void PublishOnce()
        {
            _metrics.TickRates();
            var snap = _metrics.CreateSnapshot();
            snap.ProductVersion = ProductInfo.Version;
            snap.WeightedCorrelationEnabled = _weightedConfig.Enabled;
            snap.WeightedThreshold = _weightedConfig.Threshold;
            snap.PluginCount = _plugins.TotalCount;
            snap.Pipeline = _detectionEngine?.GetTelemetryHealth() ?? new TelemetryPipelineSnapshot();
            snap.Etw = _etw?.LastHealthSnapshot ?? new EtwHealthSnapshot();
            snap.AuditIntegrityDegraded = _eventLogger?.AuditIntegrityDegraded ?? true;

            if (_monitorRegistry != null)
            {
                try
                {
                    var stats = _monitorRegistry.GetStats();
                    snap.RegisteredMonitors = stats.TotalRegistered;
                    snap.RunningMonitors = stats.Running;
                    foreach (var monitor in _monitorRegistry.GetAllStatuses())
                    {
                        snap.SensorProgress[monitor.Name] = monitor.Progress;
                        snap.MonitorStates[monitor.Name] = new MonitorRuntimeSnapshot
                        { State = monitor.State.ToString(), LastError = monitor.LastError };
                        snap.SensorBudgets[monitor.Name] = monitor.Budget;
                    }
                }
                catch (Exception ex)
                {
                    _logger.LogDebug(ex, "Monitor status snapshot unavailable during startup");
                }
            }

            var dir = Path.GetDirectoryName(_outputPath);
            if (!string.IsNullOrEmpty(dir) && !Directory.Exists(dir))
                Directory.CreateDirectory(dir);

            var json = JsonSerializer.Serialize(snap, new JsonSerializerOptions
            {
                WriteIndented = true
            });
            File.WriteAllText(_outputPath, json, Encoding.UTF8);
        }
    }

    /// <summary>
    /// Product version is taken from the stamped binary. A stale sidecar cannot
    /// misidentify the executing engine after an incomplete update.
    /// </summary>
    public static class ProductInfo
    {
        private static readonly string _version = ResolveVersion();

        public static string Version => _version;

        private static string ResolveVersion()
        {
            return typeof(ProductInfo).Assembly.GetName().Version?.ToString(3) ?? "0.0.0";
        }
    }
}
