using System;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace Sentinel.Core
{
    /// <summary>
    /// Upgrade cleanup: once per machine after install of 1.9.2+, walk fixed drives
    /// and delete leftover <c>*.sentinel_verdict</c> sidecars from pre-1.8.8 pollution.
    /// Runs on a background thread after a short delay so startup is not blocked.
    /// </summary>
    public sealed class LegacyVerdictSidecarPurgeService : IHostedService, IDisposable
    {
        private readonly FileVerdictAds _verdictAds;
        private readonly ILogger<LegacyVerdictSidecarPurgeService> _logger;
        private CancellationTokenSource? _cts;
        private Thread? _thread;

        public LegacyVerdictSidecarPurgeService(
            FileVerdictAds verdictAds,
            ILogger<LegacyVerdictSidecarPurgeService> logger)
        {
            _verdictAds = verdictAds ?? throw new ArgumentNullException(nameof(verdictAds));
            _logger = logger;
        }

        public Task StartAsync(CancellationToken cancellationToken)
        {
            _cts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            _thread = new Thread(() => Run(_cts.Token))
            {
                IsBackground = true,
                Name = "SentinelLegacyVerdictPurge",
                Priority = ThreadPriority.BelowNormal
            };
            _thread.Start();
            return Task.CompletedTask;
        }

        public Task StopAsync(CancellationToken cancellationToken)
        {
            try { _cts?.Cancel(); } catch { }
            return Task.CompletedTask;
        }

        private void Run(CancellationToken ct)
        {
            try
            {
                // Let critical monitors / self-test settle; purge is I/O heavy.
                if (ct.WaitHandle.WaitOne(TimeSpan.FromSeconds(60)))
                    return;

                if (System.IO.File.Exists(_verdictAds.LegacySidecarPurgeMarkerPath))
                {
                    _logger.LogDebug("[LegacyVerdictPurge] Marker present - skip.");
                    return;
                }

                _logger.LogInformation(
                    "[LegacyVerdictPurge] Starting one-shot force removal of *.sentinel_verdict sidecars " +
                    "(upgrade cleanup for pre-1.8.8 pollution). Central VerdictCache is kept.");

                var deleted = _verdictAds.PurgeLegacySidecarsOnce(
                    force: false,
                    log: msg => _logger.LogInformation("[LegacyVerdictPurge] {Msg}", msg),
                    cancellationToken: ct);

                _logger.LogInformation(
                    "[LegacyVerdictPurge] Done. Deleted {Count} legacy sidecar file(s).",
                    deleted);
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "[LegacyVerdictPurge] Unexpected failure (non-fatal)");
            }
        }

        public void Dispose()
        {
            try { _cts?.Cancel(); } catch { }
            _cts?.Dispose();
        }
    }
}
