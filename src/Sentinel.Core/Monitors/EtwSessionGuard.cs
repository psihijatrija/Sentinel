// EtwSessionGuard - Critical self-protection: detect and heal ETW session kill
// v1.6.1: Addresses RT-HIGH-1 (silent blind by stopping SentinelUnifiedTrace)

using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace Sentinel.Core
{
    /// <summary>
    /// Watches the unified ETW real-time session. Ransomware/EDR-killer tradecraft
    /// (The Register / HN 2025: "ransomware crews don't care about your endpoint
    /// security they killed it") often stops telemetry channels without killing the
    /// EDR process - the product looks healthy but is blind.
    ///
    /// Every few seconds:
    ///   1. If !IsActive -> RestartAsync + Tier1 AntiTamper detection
    ///   2. Query native session/loss state and consumer liveness. Idle event streams
    ///      alone do not justify restart; unavailable providers degrade coverage.
    /// </summary>
    public sealed class EtwSessionGuard : BackgroundService, ISensorProgressSource
    {
        private readonly UnifiedEtwSession _etwSession;
        private readonly DetectionEngine _detectionEngine;
        private readonly ILogger<EtwSessionGuard> _logger;

        private const int CheckIntervalMs = 3000;
        public SensorProgress Progress { get; } = new(TimeSpan.FromSeconds(15));
        private readonly VisibilityGapTracker? _gaps;
        private long _lastEventsLost, _lastBuffersLost, _lastDispatchDrops;
        private readonly EtwCoverageAlertState _alerts = new();
        private bool _coverageDegraded;
        private const int AlertCooldownSeconds = 60;

        private DateTimeOffset _lastAlertUtc = DateTimeOffset.MinValue;
        private int _restartAttempts;
        private int _restartBackoffStep;
        private DateTimeOffset _nextRestartUtc;

        public EtwSessionGuard(
            UnifiedEtwSession etwSession,
            DetectionEngine detectionEngine,
            ILogger<EtwSessionGuard> logger, VisibilityGapTracker? gaps = null)
        {
            _etwSession = etwSession;
            _detectionEngine = detectionEngine;
            _logger = logger;
            _gaps = gaps;
        }

        protected override async Task ExecuteAsync(CancellationToken stoppingToken)
        {
            _logger.LogInformation("[EtwSessionGuard] Started - monitoring UnifiedEtwSession health");

            // Allow startup time for session creation
            try { await Task.Delay(5000, stoppingToken); } catch { return; }


            while (!stoppingToken.IsCancellationRequested)
            {
                try
                {
                    await Task.Delay(CheckIntervalMs, stoppingToken);
                    await CheckAndHealAsync(stoppingToken);
                }
                catch (OperationCanceledException) { break; }
                catch (Exception ex)
                {
                    Progress.Failed(ex.Message);
                    _logger.LogDebug(ex, "[EtwSessionGuard] Error in check loop");
                }
            }
        }

        private async Task CheckAndHealAsync(CancellationToken ct)
        {
            var health = _etwSession.QueryHealth();
            long events = health.EventsProcessed;
            // Compare independently: a native counter reset must not hide dispatch loss.
            bool lossIncreased = health.QuerySucceeded &&
                (health.NativeEventsLost > _lastEventsLost || health.NativeBuffersLost > _lastBuffersLost);
            lossIncreased |= health.DispatchDrops > _lastDispatchDrops;
            if (health.QuerySucceeded)
            {
                _lastEventsLost = health.NativeEventsLost;
                _lastBuffersLost = health.NativeBuffersLost;
            }
            _lastDispatchDrops = health.DispatchDrops;
            bool inactive = !_etwSession.IsActive;
            bool stalled = health.QuerySucceeded && !health.ConsumerAlive;
            bool providersAvailable = health.ProviderStatus.Count == 10 &&
                System.Linq.Enumerable.All(health.ProviderStatus.Values, code => code == 0);
            if (!inactive && !stalled)
            {
                if (!health.QuerySucceeded || !providersAvailable || lossIncreased)
                {
                    string degraded = !health.QuerySucceeded ? "ETW session query unavailable" :
                        !providersAvailable ? "ETW provider coverage incomplete (" + health.ProviderStatus.Count + "/10 statuses): " + string.Join("; ",
                            System.Linq.Enumerable.Select(System.Linq.Enumerable.OrderBy(System.Linq.Enumerable.Where(health.ProviderStatus, p => p.Value != 0), p => p.Key),
                                p => p.Key + ": Win32 " + p.Value + " (" + new System.ComponentModel.Win32Exception((int)p.Value).Message + ")"))
                        : "ETW events/buffers were lost";
                    Progress.Failed(degraded);
                    if (!_coverageDegraded) _gaps?.Report("ETW", degraded);
                    if (_alerts.Observe(degraded, DateTimeOffset.UtcNow))
                    {
                        await _detectionEngine.EmitAsync(new DetectionEvent
                        {
                            RuleName = "Telemetry: ETW Visibility Degraded", Evidence = degraded,
                            Reasoning = "Missing visibility is not proof of attack or of a clean system.",
                            Tier = DetectionTier.Tier2Indicator, AuthorizedResponse = ResponseAction.LogOnly,
                            Confidence = 0.5, SignalType = SignalType.Generic,
                            Metadata = new Dictionary<string, string>
                            {
                                ["NativeEventsLost"] = health.NativeEventsLost.ToString(),
                                ["NativeBuffersLost"] = health.NativeBuffersLost.ToString(),
                                ["DispatchDrops"] = health.DispatchDrops.ToString(),
                                ["CoverageState"] = "Degraded"
                            }
                        });
                    }
                    _coverageDegraded = true;
                }
                else
                {
                    // A single quiet poll cannot close an intermittent visibility gap.
                    _alerts.Observe(null, DateTimeOffset.UtcNow);
                    if (_alerts.IsDegraded)
                    {
                        Progress.Failed("ETW recovery pending 30 seconds of stable coverage");
                        return;
                    }
                    // A successful native query and live consumer can be healthy while idle.
                    Progress.Succeeded();
                    _restartBackoffStep = 0;
                    _nextRestartUtc = DateTimeOffset.MinValue;
                    if (_coverageDegraded) _gaps?.Report("ETW", "Collection coverage recovered; reconcile current state");
                    if (_coverageDegraded)
                        await _detectionEngine.EmitAsync(new DetectionEvent
                        {
                            RuleName = "Telemetry: ETW Coverage Recovered",
                            Evidence = "Session query, consumer and configured providers are available; no new loss in this sample.",
                            Reasoning = "Recovery does not restore events lost during the visibility gap.",
                            Tier = DetectionTier.Tier2Indicator, AuthorizedResponse = ResponseAction.LogOnly,
                            Confidence = 0.5, SignalType = SignalType.Generic
                        });
                    _coverageDegraded = false;
                }
                return;
            }

            string reason = inactive ? "Unified ETW session is inactive" : "ETW processing thread is not alive";
            _alerts.Observe(reason, DateTimeOffset.UtcNow);
            Progress.Failed(reason);
            if (!_coverageDegraded) _gaps?.Report("ETW", reason);
            _coverageDegraded = true;

            // Failed/short-lived recreations must not form a restart storm. Provider-only
            // access denial never enters this path; restarting cannot grant protected-provider access.
            if (DateTimeOffset.UtcNow < _nextRestartUtc) return;
            _nextRestartUtc = DateTimeOffset.UtcNow.AddSeconds(Math.Min(60, 5 * Math.Pow(2, _restartBackoffStep)));
            _restartBackoffStep = Math.Min(4, _restartBackoffStep + 1);
            _logger.LogCritical("[EtwSessionGuard] {Reason} - attempting restart", reason);

            bool restarted = await _etwSession.RestartAsync(ct);
            _restartAttempts++;

            if (restarted)
            {
                _logger.LogWarning("[EtwSessionGuard] ETW session recreated successfully (attempt {N})", _restartAttempts);
            }
            else
            {
                _logger.LogError("[EtwSessionGuard] ETW session restart FAILED (attempt {N})", _restartAttempts);
            }

            // Rate-limit alerts
            if ((DateTimeOffset.UtcNow - _lastAlertUtc).TotalSeconds < AlertCooldownSeconds)
                return;

            _lastAlertUtc = DateTimeOffset.UtcNow;

            await _detectionEngine.EmitAsync(new DetectionEvent
            {
                RuleName = "Telemetry: ETW Session Unavailable",
                Evidence = reason + (restarted
                    ? ". Session was automatically recreated."
                    : ". Automatic recreation failed - detection may be degraded to WMI/polling fallback."),
                Reasoning = "The session or consumer is unavailable. Software failure, missing optional components, " +
                    "permissions and tampering are possible causes; this observation does not identify a cause or actor.",
                Confidence = 0.5,
                Tier = DetectionTier.Tier2Indicator,
                AuthorizedResponse = ResponseAction.LogOnly, // always fires
                ProcessName = "SYSTEM",
                ProcessId = 0,
                SignalType = SignalType.AntiTamper,
                Metadata = new Dictionary<string, string>
                {
                    ["VisibilityFailureType"] = inactive ? "EtwSessionInactive" : "EtwSessionStalled",
                    ["RestartSucceeded"] = restarted.ToString(),
                    ["RestartAttempts"] = _restartAttempts.ToString(),
                    ["EventsProcessed"] = events.ToString()
                }
            });
        }
    }
}
