using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Channels;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;

namespace Sentinel.Core
{
    public interface IDetectionRule
    {
        string Name { get; }
        DetectionEvent? Evaluate(FusedTelemetryContext context);
    }

    public class DetectionEngine
    {
        private readonly List<IDetectionRule> _rules = new();
        public int RuleCount => _rules.Count;
        // v1.8.1 RT-MED-1: Bound the queue to prevent memory exhaustion under adversarial
        // process-creation storms. DropOldest keeps the newest telemetry for scoring.
        private const int TelemetryChannelCapacity = 10_000;
        private readonly Channel<FusedTelemetryContext> _telemetryChannel =
            Channel.CreateBounded<FusedTelemetryContext>(new BoundedChannelOptions(TelemetryChannelCapacity)
            {
                FullMode = BoundedChannelFullMode.DropOldest,
                SingleReader = true,
                SingleWriter = false
            });
        private readonly ConcurrentDictionary<(string, int), DateTime> _dedupCache = new();
        private int _dedupOps;
        private readonly SentinelMetrics _metrics;
        private readonly JsonlEventLogger _eventLogger;
        private readonly AdvancedResponseEngine _responseEngine;
        private readonly IoCScanner _iocScanner;
        private readonly HashReputationService _reputationService;
        private readonly FileReputationEngine _fileReputationEngine;
        private readonly BehavioralCorrelationEngine _correlationEngine;
        private readonly WeightedCorrelationEngine? _weightedCorrelation;
        private readonly ScoringEngine _scoringEngine;
        private readonly ILogger<DetectionEngine> _logger;
        private readonly CancellationTokenSource _cts = new();
        private readonly Task _processingTask;
        private SentinelOrchestrator? _orchestrator;

        /// <summary>
        /// Late-bound orchestrator injection to avoid circular DI.
        /// Called by SentinelService during startup wiring.
        /// </summary>
        public void SetOrchestrator(SentinelOrchestrator orchestrator) => _orchestrator = orchestrator;

        public DetectionEngine(
            IEnumerable<IDetectionRule> rules,
            SentinelMetrics metrics,
            JsonlEventLogger eventLogger,
            AdvancedResponseEngine responseEngine,
            IoCScanner iocScanner,
            HashReputationService reputationService,
            FileReputationEngine fileReputationEngine,
            BehavioralCorrelationEngine correlationEngine,
            ScoringEngine scoringEngine,
            ILogger<DetectionEngine> logger,
            WeightedCorrelationEngine? weightedCorrelation = null)
        {
            _rules.AddRange(rules);
            _metrics = metrics;
            _eventLogger = eventLogger;
            _responseEngine = responseEngine;
            _iocScanner = iocScanner;
            _reputationService = reputationService;
            _fileReputationEngine = fileReputationEngine;
            _correlationEngine = correlationEngine;
            _weightedCorrelation = weightedCorrelation;
            _scoringEngine = scoringEngine;
            _logger = logger;

            // Wire up correlation engines (hand-authored composites + v2.0 weighted)
            _correlationEngine.Initialize(this.EmitCompositeAsync);
            _weightedCorrelation?.Initialize(this.EmitCompositeAsync);

            // Start background processing
            _processingTask = Task.Run(ProcessTelemetryQueueAsync);
        }

        public void SubmitTelemetry(FusedTelemetryContext context)
        {
            _metrics.RecordTelemetryReceived();
            // DropOldest: TryWrite always accepts; oldest is discarded under pressure.
            // Approximate drop signal when channel is saturated (Count ~= capacity).
            if (_telemetryChannel.Reader.Count >= TelemetryChannelCapacity - 1)
                _metrics.RecordTelemetryDropped();
            _telemetryChannel.Writer.TryWrite(context);
        }

        public async Task EmitAsync(DetectionEvent detectionEvent)
        {
            // Direct emission bypassing rules (for monitors that emit detections directly).
            // v2.3.1: Record detection metric here too - previously only rule-based detections
            // were counted, leaving monitors (Ephemeral, Hardware, DNS, NamedPipe, etc.) invisible
            // in ops metrics.
            _metrics.RecordDetection(0);
            await HandleDetectionEventAsync(detectionEvent);
        }

        /// <summary>
        /// Composite callback from correlation engines. Marks metrics and routes
        /// through full detection handling (score, tier law, response).
        /// </summary>
        private async Task EmitCompositeAsync(DetectionEvent detectionEvent)
        {
            if (detectionEvent == null) return;
            if (detectionEvent.RuleName != null &&
                detectionEvent.RuleName.IndexOf("Weighted Correlation", StringComparison.OrdinalIgnoreCase) >= 0)
                _metrics.RecordWeightedEmitted();
            else
                _metrics.RecordCompositeEmitted();

            if (detectionEvent.Metadata != null &&
                detectionEvent.Metadata.TryGetValue(ResponsePolicy.ChainConfirmedKey, out var cc) &&
                string.Equals(cc, "true", StringComparison.OrdinalIgnoreCase))
            {
                _metrics.RecordChainConfirmed();
            }

            AttackTechniqueMap.Enrich(detectionEvent);
            await HandleDetectionEventAsync(detectionEvent).ConfigureAwait(false);
        }

        public async Task SubmitConsultantSignalAsync(DetectionEvent detectionEvent)
        {
            if (detectionEvent == null) return;
            // v1.8.1 RT-NEW-2: consultant signals are observational only - never kill authority.
            // Previously ProcessDetectionAsync re-promoted Verdict.Critical -> KillProcessTree.
            detectionEvent.Tier = DetectionTier.Tier2Indicator;
            detectionEvent.AuthorizedResponse = ResponseAction.LogOnly;
            if (detectionEvent.Metadata == null)
                detectionEvent.Metadata = new Dictionary<string, string>();
            detectionEvent.Metadata["ConsultantSignal"] = "true";
            await ProcessDetectionAsync(detectionEvent);
        }

        private async Task ProcessTelemetryQueueAsync()
        {
            try
            {
                var reader = _telemetryChannel.Reader;
                while (await reader.WaitToReadAsync(_cts.Token))
                {
                    while (reader.TryRead(out var context))
                    {
                        try
                        {
                            // If it is a process start, calculate process image hash and check reputations/IoCs asynchronously
                            if (context.TriggeringEvent is ProcessTelemetry pt)
                            {
                                // SECURITY v1.4.6: Capture token into local variable to prevent
                                // ObjectDisposedException when CTS is disposed during shutdown.
                                // Previously, accessing _cts.Token after Stop() caused unhandled
                                // exceptions that crashed the service - an attacker could exploit
                                // this by triggering rapid stop/start cycles to keep Sentinel down.
                                var ct = _cts.Token;
                                _ = Task.Run(async () =>
                                {
                                    try
                                    {
                                        var imagePath = pt.ImagePath;
                                        if (!string.IsNullOrEmpty(imagePath) && System.IO.File.Exists(imagePath))
                                        {
                                            // HARDENING v1.3.8: Self-exclusion - never reputation-scan our own binaries.
                                            // Sentinel.Agent.exe and Sentinel.Service.exe are unsigned
                                            // dev builds unknown to reputation DBs, so they score ~43-48/100 (Suspicious).
                                            // This generated false detections, fed the correlation engine with
                                            // SuspiciousProcess signals, and created bogus incidents against ourselves.
                                            //
                                            // v2.0 RT-HIGH-2: hardlink-aware self-exclusion (not string prefix alone)
                                            if (SelfPathGuard.IsSentinelSelfBinary(imagePath) ||
                                                SelfPathGuard.IsUnderInstallDirectory(imagePath) &&
                                                Path.GetFileName(imagePath).StartsWith("Sentinel.", StringComparison.OrdinalIgnoreCase))
                                                return;

                                            // v2.0.5: Never reputation-scan game/anti-cheat or DirectX/runtime
                                            // redistributable binaries. These are interactive entertainment or
                                            // runtime installers that Sentinel must never touch - observe only.
                                            // Consistent with DllUnloadEngine, AdvancedResponseEngine, and
                                            // IncidentResponseService which already skip these paths.
                                            if (SecurityValidation.ShouldSkipReputationForGamePath(imagePath) ||
                                                InstallerHeuristics.IsDirectXOrRuntimeRedist(pt.ProcessName, imagePath))
                                                return;

                                            // v1.3.1: Use multi-signal FileReputationEngine for on-execute verdicts
                                            var repoResult = await _fileReputationEngine.EvaluateFileAsync(imagePath, ct);

                                            // Also check local IoC cache for immediate known-bad
                                            string hash = repoResult.Sha256;
                                            bool isIoC = !string.IsNullOrEmpty(hash) && _iocScanner.IsKnownBadHash(hash);

                                            if (isIoC || repoResult.Verdict == FileVerdict.Malicious)
                                            {
                                                var reputationEvent = new DetectionEvent
                                                {
                                                    RuleName = "File Reputation: Malicious Binary Executed",
                                                    Evidence = $"Process '{pt.ProcessName}' (PID {pt.ProcessId}) binary scored {repoResult.CompositeScore}/100 " +
                                                               $"(Verdict: {repoResult.Verdict}, SHA256: {hash})",
                                                    Reasoning = "The executed binary's composite reputation score exceeds the malicious threshold. " +
                                                                "Score is derived from hash reputation (CIRCL + MalwareBazaar + VirusTotal), " +
                                                                "static PE analysis (entropy, imports, packing), signer trust, and contextual risk.",
                                                    Confidence = 0.95,
                                                    Tier = DetectionTier.Tier1Behavioral,
                                                    AuthorizedResponse = ResponseAction.KillProcessTree,
                                                    ProcessName = pt.ProcessName,
                                                    ProcessId = pt.ProcessId,
                                                    SignalType = SignalType.SuspiciousProcess,
                                                    Metadata = new Dictionary<string, string>
                                                    {
                                                        { "SHA256", hash },
                                                        { "CompositeScore", repoResult.CompositeScore.ToString() },
                                                        { "FileVerdict", repoResult.Verdict.ToString() },
                                                        { "Signed", repoResult.IsSigned.ToString() },
                                                        { "Entropy", repoResult.StaticAnalysis.Entropy.ToString("F2") }
                                                    }
                                                };
                                                await ProcessDetectionAsync(reputationEvent);
                                            }
                                            else if (repoResult.Verdict == FileVerdict.HighRisk)
                                            {
                                                // v1.6.4: EDR philosophy - "unknown" != "malicious".
                                                // If the binary looks like a legitimate installer and NO reputation
                                                // source positively confirmed it as malicious (just "not found" / error),
                                                // demote to Tier2/LogOnly. Let it run; behavioral monitors will catch
                                                // actual malicious activity. This prevents killing our own installer
                                                // and other legitimate unsigned software (Git, Python, etc.).
                                                // v1.8.1 RT-LOW-2: require name match AND benign install path
                                                var isInstallerLike = InstallerHeuristics.LooksLikeInstallerName(pt.ProcessName, imagePath)
                                                    && InstallerHeuristics.IsLikelyInstallerPath(imagePath);
                                                var hasPositiveMaliciousSignal =
                                                    repoResult.HashReputation.MalwareBazaarVerdict.Status == VerdictStatus.Malicious ||
                                                    (repoResult.HashReputation.VirusTotalVerdict.Status == VerdictStatus.Malicious) ||
                                                    isIoC;

                                                var effectiveTier = DetectionTier.Tier1Behavioral;
                                                var effectiveResponse = ResponseAction.KillProcess;
                                                var effectiveConfidence = 0.80;

                                                if (isInstallerLike && !hasPositiveMaliciousSignal)
                                                {
                                                    // Installer-like + merely "unknown" = observe only
                                                    effectiveTier = DetectionTier.Tier2Indicator;
                                                    effectiveResponse = ResponseAction.LogOnly;
                                                    effectiveConfidence = 0.45;
                                                }

                                                var reputationEvent = new DetectionEvent
                                                {
                                                    RuleName = "File Reputation: High-Risk Binary Executed",
                                                    Evidence = $"Process '{pt.ProcessName}' (PID {pt.ProcessId}) binary scored {repoResult.CompositeScore}/100 " +
                                                               $"(Verdict: {repoResult.Verdict}, Signed: {repoResult.IsSigned})",
                                                    Reasoning = isInstallerLike && !hasPositiveMaliciousSignal
                                                        ? "The binary scored HighRisk but matches installer heuristics and has no positive malicious confirmation. " +
                                                          "Demoted to Tier2/LogOnly per EDR observe-first principle. Behavioral monitors remain active."
                                                        : "The binary's reputation score indicates high risk based on multi-signal analysis. " +
                                                          "Flagged by one or more threat intelligence sources or exhibits suspicious static properties.",
                                                    Confidence = effectiveConfidence,
                                                    Tier = effectiveTier,
                                                    AuthorizedResponse = effectiveResponse,
                                                    ProcessName = pt.ProcessName,
                                                    ProcessId = pt.ProcessId,
                                                    SignalType = SignalType.SuspiciousProcess,
                                                    Metadata = new Dictionary<string, string>
                                                    {
                                                        { "SHA256", hash },
                                                        { "CompositeScore", repoResult.CompositeScore.ToString() },
                                                        { "FileVerdict", repoResult.Verdict.ToString() },
                                                        { "InstallerHeuristic", isInstallerLike.ToString() },
                                                        { "Demoted", (isInstallerLike && !hasPositiveMaliciousSignal).ToString() }
                                                    }
                                                };
                                                await ProcessDetectionAsync(reputationEvent);
                                            }
                                            else if (repoResult.Verdict == FileVerdict.Suspicious)
                                            {
                                                var reputationEvent = new DetectionEvent
                                                {
                                                    RuleName = "File Reputation: Suspicious Binary Executed",
                                                    Evidence = $"Process '{pt.ProcessName}' (PID {pt.ProcessId}) binary scored {repoResult.CompositeScore}/100 " +
                                                               $"(Unknown to reputation DBs, Entropy: {repoResult.StaticAnalysis.Entropy:F2})",
                                                    Reasoning = "The binary is unknown to all reputation sources and exhibits some suspicious characteristics. " +
                                                                "Logged as a Tier2 indicator to feed the correlation engine.",
                                                    Confidence = 0.55,
                                                    Tier = DetectionTier.Tier2Indicator,
                                                    AuthorizedResponse = ResponseAction.LogOnly,
                                                    ProcessName = pt.ProcessName,
                                                    ProcessId = pt.ProcessId,
                                                    SignalType = SignalType.SuspiciousProcess,
                                                    Metadata = new Dictionary<string, string>
                                                    {
                                                        { "SHA256", hash },
                                                        { "CompositeScore", repoResult.CompositeScore.ToString() },
                                                        { "FileVerdict", repoResult.Verdict.ToString() }
                                                    }
                                                };
                                                await ProcessDetectionAsync(reputationEvent);
                                            }
                                        }
                                    }
                                    catch (OperationCanceledException) { }
                                    catch (ObjectDisposedException) { } // CTS disposed during shutdown - safe to ignore
                                    catch (Exception ex)
                                    {
                                        _logger.LogError(ex, "[DetectionEngine] Error checking process reputation for {ProcessName} (PID {ProcessId})", pt.ProcessName, pt.ProcessId);
                                    }
                                }, ct);
                            }

                            foreach (var rule in _rules)
                            {
                                try
                                {
                                    var startTime = DateTime.UtcNow;
                                    var detection = rule.Evaluate(context);

                                    if (detection != null)
                                    {
                                        var duration = (DateTime.UtcNow - startTime).TotalMilliseconds;
                                        _metrics.RecordDetection(duration);
                                        await ProcessDetectionAsync(detection);
                                    }
                                }
                                catch (Exception ex)
                                {
                                    _logger.LogError(ex, "[DetectionEngine] Error running rule {RuleName}", rule.Name);
                                }
                            }
                        }
                        catch (Exception ex)
                        {
                            _logger.LogError(ex, "[DetectionEngine] Error processing telemetry context item");
                        }
                    }
                }
            }
            catch (OperationCanceledException)
            {
                // Normal shutdown
            }
            catch (ObjectDisposedException)
            {
                // CTS disposed during shutdown - safe to exit
            }
            catch (Exception ex)
            {
                _logger.LogCritical(ex, "[DetectionEngine] Critical error in telemetry queue processing loop");
            }
        }

        private async Task ProcessDetectionAsync(DetectionEvent detection)
        {
            var key = (detection.RuleName, detection.ProcessId);
            var now = DateTime.UtcNow;

            // HARDENING v1.3.0: Reduced dedup window from 60s to 10s for Tier1 detections.
            // Previously, an attacker could trigger one alert and then operate freely for 60s
            // knowing the same rule wouldn't fire again. Tier2 indicators keep 30s dedup
            // to reduce noise, but Tier1 behavioral detections need rapid re-alerting.
            var dedupWindow = detection.Tier == DetectionTier.Tier1Behavioral
                ? TimeSpan.FromSeconds(10)
                : TimeSpan.FromSeconds(30);

            // Determine - atomically per key - whether THIS call is the one that claims
            // the dedup slot (fresh insert or window expired). Relying on timestamp equality
            // is unsafe: two events processed within the same ~15ms DateTime.UtcNow tick share
            // an identical `now`, so the old `lastTime != now` check let a duplicate slip
            // through and emit twice. The add/update factories run atomically under
            // ConcurrentDictionary's per-key lock, so a bool set inside them is race-free.
            bool claimed = false;
            _dedupCache.AddOrUpdate(
                key,
                _ => { claimed = true; return now; },              // first time we've seen this key
                (_, oldTime) =>
                {
                    if (now - oldTime < dedupWindow)
                        return oldTime;                            // still inside window -> suppress
                    claimed = true;                                // window expired -> re-arm + emit
                    return now;
                });

            if (!claimed)
            {
                return; // Suppressed by existing recent entry
            }

            if ((++_dedupOps & 0x3F) == 0)
            {
                foreach (var kv in _dedupCache)
                {
                    if (now - kv.Value > TimeSpan.FromMinutes(2))
                        _dedupCache.TryRemove(kv.Key, out _);
                }
            }

            // Apply threat scoring
            if (detection.Metadata == null)
                detection.Metadata = new Dictionary<string, string>();
            var scoreProfile = _scoringEngine.Score(detection);
            detection.Metadata["ThreatScore"] = scoreProfile.Score.ToString();
            detection.Metadata["ThreatVerdict"] = scoreProfile.Verdict.ToString();
            detection.Metadata["ThreatCategory"] = scoreProfile.Category.ToString();

            // v2.0: ATT&CK technique mapping on every detection
            AttackTechniqueMap.Enrich(detection);

            bool isConsultant = detection.Metadata.TryGetValue("ConsultantSignal", out var csFlag)
                && string.Equals(csFlag, "true");

            // Consultant / external signals are observational only - never kill authority.
            if (isConsultant)
            {
                detection.Tier = DetectionTier.Tier2Indicator;
                detection.AuthorizedResponse = ResponseAction.LogOnly;
            }
            else
            {
                // Standing tier law: Tier1 only for high-confidence kill-grade terminals
                // (token theft, cred dump, reverse shell, C2) or multi-signal composites.
                // Critical score alone must NOT promote random heuristics to kill.
                // Scoring still enriches Metadata for correlation.
                ResponsePolicy.ApplyTierLaw(detection);
            }

            await HandleDetectionEventAsync(detection);

            // Feed ALL tiers to correlation - Tier2 observe signals seed composites;
            // multi-signal composites are what authorize kill.
            var corrStart = DateTime.UtcNow;
            await _correlationEngine.RegisterSignalAsync(detection);
            if (_weightedCorrelation != null)
                await _weightedCorrelation.RegisterSignalAsync(detection);
            _metrics.RecordCorrelation((DateTime.UtcNow - corrStart).TotalMilliseconds);
        }

        private async Task HandleDetectionEventAsync(DetectionEvent detection)
        {
            // Log the event
            await _eventLogger.LogEventAsync("detection", detection);

            // v1.3.2: Route through SentinelOrchestrator for incident grouping and response coordination
            if (_orchestrator != null)
            {
                await _orchestrator.ProcessDetectionAsync(detection);
            }
            else
            {
                // Fallback: direct to response engine (should not happen in production)
                await _responseEngine.HandleAsync(detection);
            }
        }

        public void Stop()
        {
            if (_stopped) return;
            _stopped = true;
            try { _cts.Cancel(); } catch (ObjectDisposedException) { }
            try
            {
                _processingTask?.Wait(2000);
            }
            catch { }
        }

        private volatile bool _stopped;
    }
}
