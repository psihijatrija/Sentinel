using System;
using System.Diagnostics;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace Sentinel.Core
{
    /// <summary>
    /// Periodic health check: process stats, memory, handles, log file size,
    /// quarantine count, thread pool availability.
    /// </summary>
    public sealed class SentinelHealthCheck : BackgroundService
    {
        private readonly ILogger<SentinelHealthCheck> _logger;
        private readonly JsonlEventLogger _eventLogger;
        private readonly SentinelMetrics _metrics;
        private static readonly TimeSpan Interval = TimeSpan.FromMinutes(5);

        public SentinelHealthCheck(
            ILogger<SentinelHealthCheck> logger,
            JsonlEventLogger eventLogger,
            SentinelMetrics metrics)
        {
            _logger = logger;
            _eventLogger = eventLogger;
            _metrics = metrics;
        }

        protected override async Task ExecuteAsync(CancellationToken ct)
        {
            _logger.LogInformation("[SentinelHealthCheck] Started (interval: {Interval})", Interval);

            do
            {
                try
                {
                    using var proc = Process.GetCurrentProcess();
                    var workingSetMb = proc.WorkingSet64 / (1024.0 * 1024.0);
                    var handleCount = proc.HandleCount;
                    var threadCount = proc.Threads.Count;

                    // Log file size (use configured path from logger)
                    double logFileSizeMb = 0;
                    var logPath = _eventLogger.LogFilePath;
                    if (File.Exists(logPath))
                    {
                        logFileSizeMb = new FileInfo(logPath).Length / (1024.0 * 1024.0);
                    }

                    // Quarantine count (derive from log directory)
                    int quarantineCount = 0;
                    var logDir = Path.GetDirectoryName(logPath);
                    var quarantineDir = logDir != null ? Path.Combine(logDir, "Quarantine") : null;
                    if (quarantineDir != null && Directory.Exists(quarantineDir))
                    {
                        quarantineCount = Directory.GetFiles(quarantineDir).Length;
                    }

                    // Thread pool
                    ThreadPool.GetAvailableThreads(out int workerThreads, out int ioThreads);

                    var health = new
                    {
                        WorkingSetMB = workingSetMb,
                        HandleCount = handleCount,
                        ThreadCount = threadCount,
                        LogFileSizeMB = logFileSizeMb,
                        QuarantinedFiles = quarantineCount,
                        AvailableWorkerThreads = workerThreads,
                        AvailableIOThreads = ioThreads,
                        Uptime = (DateTime.UtcNow - proc.StartTime.ToUniversalTime()).ToString(@"d\.hh\:mm\:ss"),
                        DetectionsTotal = _metrics.GetDetectionsCount(),
                        ResponsesTotal = _metrics.GetResponsesCount()
                    };

                    await _eventLogger.LogEventAsync("health", health, ct);

                    // Warn if resources are getting high
                    if (workingSetMb > 500)
                        _logger.LogWarning("[SentinelHealthCheck] High memory usage: {MB:F0}MB", workingSetMb);
                    if (handleCount > 5000)
                        _logger.LogWarning("[SentinelHealthCheck] High handle count: {Handles}", handleCount);
                    if (logFileSizeMb > 40)
                        _logger.LogWarning("[SentinelHealthCheck] Log file approaching rotation threshold: {MB:F0}MB", logFileSizeMb);
                }
                catch (OperationCanceledException) { break; }
                catch (Exception ex) { _logger.LogError(ex, "[SentinelHealthCheck] Error"); }

                try
                {
                    await Task.Delay(Interval, ct);
                }
                catch (OperationCanceledException) { break; }
            }
            while (!ct.IsCancellationRequested);
        }
    }
}
