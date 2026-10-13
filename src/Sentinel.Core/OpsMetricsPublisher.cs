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
        private readonly PluginRegistry _plugins;
        private readonly WeightedCorrelationConfig _weightedConfig;
        private readonly ILogger<OpsMetricsPublisher> _logger;
        private readonly string _outputPath;

        public OpsMetricsPublisher(
            SentinelMetrics metrics,
            PluginRegistry plugins,
            WeightedCorrelationConfig weightedConfig,
            ILogger<OpsMetricsPublisher> logger,
            MonitorRegistry? monitorRegistry = null)
        {
            _metrics = metrics;
            _plugins = plugins;
            _weightedConfig = weightedConfig;
            _logger = logger;
            _monitorRegistry = monitorRegistry;

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

            if (_monitorRegistry != null)
            {
                try
                {
                    var stats = _monitorRegistry.GetStats();
                    snap.RegisteredMonitors = stats.TotalRegistered;
                    snap.RunningMonitors = stats.Running;
                }
                catch
                {
                    // registry optional during early startup
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
    /// Central product version for metrics/UI. v2.6.0: computed at runtime from the single
    /// source of truth (<c>version.txt</c> shipped next to the binary, which the build stamps
    /// from the repo-root <c>version.txt</c>), falling back to the stamped assembly version.
    /// Previously a hand-maintained <c>const</c> that silently drifted from <c>version.txt</c>
    /// every release - computing it here means it can never go stale again.
    /// </summary>
    public static class ProductInfo
    {
        private static readonly string _version = ResolveVersion();

        public static string Version => _version;

        private static string ResolveVersion()
        {
            try
            {
                var versionFile = Path.Combine(System.AppContext.BaseDirectory, "version.txt");
                if (File.Exists(versionFile))
                {
                    var text = File.ReadAllText(versionFile).Trim();
                    if (!string.IsNullOrEmpty(text))
                        return text;
                }
            }
            catch { /* fall through to assembly version */ }

            return typeof(ProductInfo).Assembly.GetName().Version?.ToString(3) ?? "0.0.0";
        }
    }
}
