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
        private readonly TelemetryQueue _telemetryChannel;

        // 1D terminal-class fast lane (FEAT-002): a second, smaller high-priority queue drained
        // with precedence so terminal-class telemetry (BYOVD loaders, kernel-exploit scaffolds,
        // confirmed C2, etc.) reaches the response path without waiting behind the normal rule
        // sweep. This is SCHEDULING ONLY - events in this lane run the identical ProcessContextAsync
        // body and still flow ProcessDetectionAsync -> HandleDetectionEventAsync ->
        // AdvancedResponseEngine.HandleAsync, so all tier law, the Tier2-never-acts gate,
        // observe-until-chain, and the mandatory pre-action audit still apply. Routing in
        // SubmitTelemetry is mutually exclusive, so an event enters exactly one lane.
        private const int PriorityChannelCapacity = 1_000;
        private readonly TelemetryQueue _priorityChannel;
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
        private readonly BoundedWorkQueue<ProcessTelemetry> _reputationQueue;
        private long _lastProcessedUtcTicks;
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
            _telemetryChannel = new TelemetryQueue(TelemetryChannelCapacity, _metrics.RecordTelemetryDropped);
            _priorityChannel = new TelemetryQueue(PriorityChannelCapacity, _metrics.RecordTelemetryDropped);
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

            // Fixed workers and a bounded backlog keep process storms from creating unlimited tasks.
            _reputationQueue = new BoundedWorkQueue<ProcessTelemetry>(256, 2,
                CheckProcessReputationAsync,
                () => _metrics.RecordReputationDropped(),
                ex => _logger.LogError(ex, "[DetectionEngine] Reputation worker failed"));

            // Start background processing
            _processingTask = Task.Run(ProcessTelemetryQueueAsync);
        }

        public void SubmitTelemetry(FusedTelemetryContext context)
        {
            _metrics.RecordTelemetryReceived();

            // FEAT-002 1D: mutually-exclusive routing. Terminal-class telemetry jumps the
            // high-priority lane; everything else keeps the existing normal-lane behavior.
            // Exactly one lane per event - no double-processing (dedup is unchanged downstream).
            if (ShouldFastLane(context, ResponsePolicy.DefaultMinTier1Confidence))
            {
                // DropOldest on the priority lane too; this is a scheduling hint, not authority.
                _priorityChannel.TryWrite(context);
                return;
            }

            _telemetryChannel.TryWrite(context);
        }

        /// <summary>
        /// Pure scheduling hint (FEAT-002 1D): decides whether a telemetry context should take
        /// the terminal-class fast lane. Derives a DetectionEvent-shaped candidate from
        /// <paramref name="context"/>.TriggeringEvent and returns true ONLY when
        /// <see cref="ResponsePolicy.IsAttackClassTerminal"/> is true for that candidate AND the
        /// candidate's confidence meets <paramref name="minConfidence"/>.
        ///
        /// This is NEVER an authorization decision - it only changes queue ordering. The real
        /// detection still flows through the rule sweep and ProcessDetectionAsync ->
        /// HandleDetectionEventAsync -> AdvancedResponseEngine.HandleAsync, where tier law, the
        /// Tier2-never-acts gate, observe-until-chain, and the mandatory pre-action audit decide
        /// what (if anything) actually happens. The triggering telemetry carries no confidence of
        /// its own, so a candidate derived from a terminal-class signal is treated at full
        /// confidence; the gate is therefore driven by the attack-class classification (which
        /// includes the PID &lt;= 4 guard) plus the terminal rule-name mapping. If the triggering
        /// event cannot be mapped to a terminal-class rule name, this returns false.
        /// </summary>
        internal static bool ShouldFastLane(FusedTelemetryContext context, double minConfidence)
        {
            if (context?.TriggeringEvent == null)
                return false;

            var trigger = context.TriggeringEvent;

            // The only semantic label a raw telemetry event carries is its Type; map that to a
            // candidate rule name. Prefer the fused context's PID/name (populated by the fusion
            // engine), falling back to the triggering event's own fields.
            var ruleName = trigger.Type;
            if (string.IsNullOrEmpty(ruleName))
                return false;

            var pid = context.ProcessId != 0 ? context.ProcessId : trigger.ProcessId;
            var processName = !string.IsNullOrEmpty(context.ProcessName)
                ? context.ProcessName
                : trigger.ProcessName;

            var candidate = new DetectionEvent
            {
                RuleName = ruleName,
                ProcessId = pid,
                ProcessName = processName ?? string.Empty,
                // Telemetry has no confidence of its own; a terminal-class signal is treated at
                // full confidence so the gate is governed by the terminal classification and the
                // minConfidence floor, not by an absent telemetry score.
                Confidence = 1.0,
            };

            return ResponsePolicy.IsAttackClassTerminal(candidate)
                   && candidate.Confidence >= minConfidence;
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
                var ct = _cts.Token;
                var priorityReader = _priorityChannel.Reader;
                var normalReader = _telemetryChannel.Reader;

                // Single drain loop awaiting readability on EITHER lane. Each iteration FIRST fully
                // drains the priority lane, THEN consumes a single normal-lane item, then loops back
                // to re-check priority first - so terminal-class telemetry never queues behind the
                // normal rule sweep. Both lanes run the identical ProcessContextAsync body.
                while (true)
                {
                    ct.ThrowIfCancellationRequested();

                    // Fully drain the high-priority lane before touching the normal lane.
                    while (priorityReader.TryRead(out var priorityContext))
                    {
                        await ProcessQueuedAsync(priorityContext, ct);
                    }

                    // Then take at most one normal-lane item, so we re-check priority promptly.
                    if (normalReader.TryRead(out var normalContext))
                    {
                        await ProcessQueuedAsync(normalContext, ct);
                        continue; // Re-check priority before the next normal item.
                    }

                    // Both lanes are momentarily empty - wait until either becomes readable.
                    var priorityWait = priorityReader.WaitToReadAsync(ct).AsTask();
                    var normalWait = normalReader.WaitToReadAsync(ct).AsTask();
                    var ready = await Task.WhenAny(priorityWait, normalWait);

                    // If the completed wait reports no more data AND both channels are complete,
                    // exit; otherwise loop and let the TryRead drains above pick up new items.
                    if (ready.Status == TaskStatus.RanToCompletion && !ready.Result &&
                        priorityReader.Completion.IsCompleted && normalReader.Completion.IsCompleted)
                    {
                        break;
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

        /// <summary>
        /// Processes a single fused telemetry context: the asynchronous reputation/IoC offload for
        /// process-start events plus the full rule sweep. Shared by BOTH the normal and the
        /// terminal-class fast lane so processing is identical regardless of which lane delivered
        /// the context. <paramref name="ct"/> is threaded into the reputation offload so it unwinds
        /// cleanly on shutdown.
        /// </summary>
        public TelemetryPipelineSnapshot GetTelemetryHealth()
        {
            var age = Math.Max(_telemetryChannel.OldestAgeMs, _priorityChannel.OldestAgeMs);
            var ticks = Interlocked.Read(ref _lastProcessedUtcTicks);
            int normal = _telemetryChannel.Reader.Count, priority = _priorityChannel.Reader.Count;
            return new TelemetryPipelineSnapshot
            {
                State = _processingTask.IsFaulted || _processingTask.IsCanceled ? "Failed" :
                    age > 5000 ? "Backlogged" : normal + priority > 0 ? "Processing" : "Idle",
                NormalQueueDepth = normal, PriorityQueueDepth = priority,
                OldestQueuedAgeMs = age,
                LastProcessedUtc = ticks == 0 ? null : new DateTime(ticks, DateTimeKind.Utc)
            };
        }

        private async Task ProcessQueuedAsync(QueuedTelemetry item, CancellationToken ct)
        {
            _metrics.RecordQueueWait(item.AgeMs);
            await ProcessContextAsync(item.Context, ct).ConfigureAwait(false);
            Interlocked.Exchange(ref _lastProcessedUtcTicks, DateTime.UtcNow.Ticks);
        }

        private async Task ProcessContextAsync(FusedTelemetryContext context, CancellationToken ct)
        {
            try
            {
                ct.ThrowIfCancellationRequested();
                if (context.TriggeringEvent is ProcessTelemetry pt)
                    _reputationQueue.TryEnqueue(pt);

                foreach (var rule in _rules)
                {
                    ct.ThrowIfCancellationRequested();
                    try
                    {
                        var startTime = DateTime.UtcNow;
                        var detection = rule.Evaluate(context);
                        if (detection != null)
                        {
                            _metrics.RecordDetection((DateTime.UtcNow - startTime).TotalMilliseconds);
                            await ProcessDetectionAsync(detection);
                        }
                    }
                    catch (Exception ex)
                    {
                        _logger.LogError(ex, "[DetectionEngine] Error running rule {RuleName}", rule.Name);
                    }
                }
            }
            catch (OperationCanceledException) when (ct.IsCancellationRequested) { }
            catch (Exception ex)
            {
                _logger.LogError(ex, "[DetectionEngine] Error processing telemetry context item");
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

            bool claimed = DetectionDeduplication.TryClaim(_dedupCache, key, now, dedupWindow);

            if (!claimed)
            {
                return; // Suppressed by existing recent entry
            }

            if ((Interlocked.Increment(ref _dedupOps) & 0x3F) == 0)
            {
                foreach (var kv in _dedupCache)
                {
                    if (now - kv.Value > TimeSpan.FromMinutes(2))
                        ((ICollection<KeyValuePair<(string, int), DateTime>>)_dedupCache).Remove(kv);
                }
            }

            // Apply threat scoring
            if (detection.Metadata == null)
                detection.Metadata = new Dictionary<string, string>();
            var scoreProfile = _scoringEngine.Score(detection);
            detection.Metadata["EngineVersion"] = typeof(DetectionEngine).Assembly.GetName().Version?.ToString() ?? "unknown";
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

        private async Task CheckProcessReputationAsync(ProcessTelemetry pt, CancellationToken ct)
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
                if (SelfPathGuard.IsSentinelSelfBinary(imagePath))
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
                        Timestamp = pt.Timestamp,
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
                        Timestamp = pt.Timestamp,
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
                        Timestamp = pt.Timestamp,
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

        public void Stop()
        {
            if (_stopped) return;
            _stopped = true;
            try { _cts.Cancel(); } catch (ObjectDisposedException) { }
            _reputationQueue.Stop();
            try
            {
                if (!Task.WhenAll(_processingTask, _reputationQueue.DisposeAsync().AsTask()).Wait(2000))
                    _logger.LogWarning("[DetectionEngine] Workers did not stop within two seconds");
            }
            catch (Exception ex) { _logger.LogWarning(ex, "[DetectionEngine] Worker shutdown failed"); }
        }

        private volatile bool _stopped;
    }
}
