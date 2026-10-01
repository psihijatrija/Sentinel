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
    ///   2. If IsActive but event counter stalled for too long while we previously
    ///      saw activity -> treat as hung consumer and restart
    /// </summary>
    public sealed class EtwSessionGuard : BackgroundService
    {
        private readonly UnifiedEtwSession _etwSession;
        private readonly DetectionEngine _detectionEngine;
        private readonly ILogger<EtwSessionGuard> _logger;

        private const int CheckIntervalMs = 3000;
        private const int StallThresholdSeconds = 90;
        private const int AlertCooldownSeconds = 60;

        private long _lastEventsProcessed;
        private DateTimeOffset _lastProgressUtc = DateTimeOffset.UtcNow;
        private DateTimeOffset _lastAlertUtc = DateTimeOffset.MinValue;
        private bool _sawActivity;
        private int _restartAttempts;

        public EtwSessionGuard(
            UnifiedEtwSession etwSession,
            DetectionEngine detectionEngine,
            ILogger<EtwSessionGuard> logger)
        {
            _etwSession = etwSession;
            _detectionEngine = detectionEngine;
            _logger = logger;
        }

        protected override async Task ExecuteAsync(CancellationToken stoppingToken)
        {
            _logger.LogInformation("[EtwSessionGuard] Started - monitoring UnifiedEtwSession health");

            // Allow startup time for session creation
            try { await Task.Delay(5000, stoppingToken); } catch { return; }

            _lastEventsProcessed = _etwSession.EventsProcessed;
            _lastProgressUtc = DateTimeOffset.UtcNow;

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
                    _logger.LogDebug(ex, "[EtwSessionGuard] Error in check loop");
                }
            }
        }

        private async Task CheckAndHealAsync(CancellationToken ct)
        {
            long events = _etwSession.EventsProcessed;
            if (events > _lastEventsProcessed)
            {
                _lastEventsProcessed = events;
                _lastProgressUtc = DateTimeOffset.UtcNow;
                _sawActivity = true;
                _restartAttempts = 0;
            }

            bool inactive = !_etwSession.IsActive;
            bool stalled = _sawActivity &&
                           _etwSession.IsActive &&
                           (DateTimeOffset.UtcNow - _lastProgressUtc).TotalSeconds >= StallThresholdSeconds;

            if (!inactive && !stalled)
                return;

            string reason = inactive
                ? "Unified ETW session is inactive (stopped, failed to start, or externally terminated)"
                : $"Unified ETW session stalled - no events for {StallThresholdSeconds}s after prior activity (EventsProcessed={events})";

            _logger.LogCritical("[EtwSessionGuard] {Reason} - attempting restart", reason);

            bool restarted = await _etwSession.RestartAsync(ct);
            _restartAttempts++;

            if (restarted)
            {
                _lastEventsProcessed = _etwSession.EventsProcessed;
                _lastProgressUtc = DateTimeOffset.UtcNow;
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
                RuleName = "Anti-Tamper: ETW Session Disabled",
                Evidence = reason + (restarted
                    ? ". Session was automatically recreated."
                    : ". Automatic recreation failed - detection may be degraded to WMI/polling fallback."),
                Reasoning =
                    "Sentinel's real-time detection depends on the unified ETW session (Kernel-Process, File, " +
                    "Registry, DNS, Threat-Intelligence, PowerShell, etc.). Stopping this session (logman, " +
                    "ControlTrace, or EDR-killer tools) blinds behavioral monitoring while the service process " +
                    "still appears healthy - a technique used by modern ransomware crews before encryption. " +
                    "This is high-confidence telemetry tampering.",
                Confidence = 0.99,
                Tier = DetectionTier.Tier1Behavioral,
                AuthorizedResponse = ResponseAction.LogOnly, // always fires
                ProcessName = "SYSTEM",
                ProcessId = 0,
                SignalType = SignalType.AntiTamper,
                Metadata = new Dictionary<string, string>
                {
                    ["TamperType"] = inactive ? "EtwSessionInactive" : "EtwSessionStalled",
                    ["RestartSucceeded"] = restarted.ToString(),
                    ["RestartAttempts"] = _restartAttempts.ToString(),
                    ["EventsProcessed"] = events.ToString()
                }
            });
        }
    }
}
