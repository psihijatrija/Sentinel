using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

namespace Sentinel.Core
{
    /// <summary>Offline weighted-correlation evaluation. It has no response engine,
    /// plugins, live graph, or host-action dependencies.</summary>
    public sealed class DetectionReplay
    {
        public async Task<DetectionReplayReport> RunAsync(IEnumerable<DetectionEvent> events,
            WeightedCorrelationConfig config, CancellationToken cancellationToken = default, bool includeBehavioral = false)
        {
            if (events == null) throw new ArgumentNullException(nameof(events));
            if (config == null) throw new ArgumentNullException(nameof(config));
            cancellationToken.ThrowIfCancellationRequested();
            // Copy inputs: replay must not mutate live detections or caller configuration.
            var ordered = events.Select(e => JsonSerializer.Deserialize<DetectionEvent>(JsonSerializer.Serialize(e))!)
                .OrderBy(e => e.Timestamp).ToList();
            if (ordered.Any(e => e.Timestamp.Kind != DateTimeKind.Utc || double.IsNaN(e.Confidence) ||
                double.IsInfinity(e.Confidence) || e.Confidence < 0 || e.Confidence > 1))
                throw new ArgumentException("Replay requires UTC timestamps and finite confidence in [0,1].", nameof(events));
            var settings = JsonSerializer.Deserialize<WeightedCorrelationConfig>(JsonSerializer.Serialize(config))!;
            settings.EnableGraphBoost = false;
            string fingerprint;
            using (var sha = SHA256.Create())
                fingerprint = BitConverter.ToString(sha.ComputeHash(Encoding.UTF8.GetBytes(JsonSerializer.Serialize(ordered))))
                    .Replace("-", "").ToLowerInvariant();
            var report = new DetectionReplayReport { Configuration = settings, InputSha256 = fingerprint };
            if (includeBehavioral)
                report.Scope = "Detection-level behavioral + weighted correlation with tier law; no live identity, telemetry rules, graph, plugins or response execution";
            foreach (var detection in ordered) detection.Metadata ??= new Dictionary<string, string>();
            report.SkippedDerivedCount = ordered.RemoveAll(e =>
                e.Metadata.TryGetValue("WeightedCorrelation", out var derived) && derived == "true" ||
                e.RuleName == "Weighted Correlation: Multi-Signal Threat");
            DateTime now = ordered.FirstOrDefault()?.Timestamp ?? new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc);
            var engine = new WeightedCorrelationEngine(settings, utcNow: () => now);
            // Unknown historical image identity never acquires a live or recorded trust grant.
            var behavioral = includeBehavioral ? new BehavioralCorrelationEngine(() => now, _ => false) : null;
            behavioral?.Initialize(async composite =>
            {
                ResponsePolicy.ApplyTierLaw(composite);
                composite.AuthorizedResponse = ResponseAction.LogOnly;
                composite.Metadata["ReplayOnly"] = "true";
                composite.Metadata["ReplaySource"] = "BehavioralCorrelation";
                report.BehavioralComposites.Add(composite);
                // The live pipeline feeds behavioral composites into weighted correlation.
                await engine.RegisterSignalAsync(composite).ConfigureAwait(false);
            });
            engine.Initialize(composite =>
            {
                // Hypothetical recommendations are never actionable replay outputs.
                composite.AuthorizedResponse = ResponseAction.LogOnly;
                composite.Metadata["ReplayOnly"] = "true";
                report.Composites.Add(composite);
                return Task.CompletedTask;
            });
            foreach (var detection in ordered)
            {
                cancellationToken.ThrowIfCancellationRequested();
                now = detection.Timestamp;
                if (behavioral != null)
                {
                    bool consultant = detection.Metadata.TryGetValue("ConsultantSignal", out var flag) && flag == "true";
                    if (consultant) detection.Tier = DetectionTier.Tier2Indicator;
                    else ResponsePolicy.ApplyTierLaw(detection);
                    detection.AuthorizedResponse = ResponseAction.LogOnly;
                    await behavioral.RegisterSignalAsync(detection).ConfigureAwait(false);
                }
                await engine.RegisterSignalAsync(detection).ConfigureAwait(false);
                report.InputCount++;
                if (detection.ProcessId > 0)
                    report.Steps.Add(new ReplayStep { Timestamp = now, ScoreCard = engine.GetScoreCard(detection.ProcessId) });
            }
            return report;
        }
    }

    public sealed class DetectionReplayReport
    {
        public int SchemaVersion { get; set; } = 1;
        public string EngineVersion { get; set; } = typeof(WeightedCorrelationEngine).Assembly.GetName().Version?.ToString() ?? "unknown";
        public string InputSha256 { get; set; } = "";
        public string Scope { get; set; } = "Weighted correlation only; graph/plugin/full response policy not replayed";
        public int InputCount { get; set; }
        public int SkippedDerivedCount { get; set; }
        public WeightedCorrelationConfig Configuration { get; set; } = new();
        public List<ReplayStep> Steps { get; set; } = new();
        public List<DetectionEvent> Composites { get; set; } = new();
        public List<DetectionEvent> BehavioralComposites { get; set; } = new();
    }

    public sealed class ReplayComparison
    {
        public string PreviousEngineVersion { get; set; } = "";
        public string CurrentEngineVersion { get; set; } = "";
        public int PreviousCompositeCount { get; set; }
        public int CurrentCompositeCount { get; set; }
        public int PreviousBehavioralCompositeCount { get; set; }
        public int CurrentBehavioralCompositeCount { get; set; }
        public bool BehavioralOutputsChanged { get; set; }
        public List<int> ChangedStepIndexes { get; set; } = new();

        public static ReplayComparison Compare(DetectionReplayReport previous, DetectionReplayReport current)
        {
            if (string.IsNullOrEmpty(previous.InputSha256) || previous.InputSha256 != current.InputSha256 ||
                previous.Steps.Count != current.Steps.Count || previous.Scope != current.Scope)
                throw new ArgumentException("Replay comparison requires reports from the same normalized input events.");
            var result = new ReplayComparison
            {
                PreviousEngineVersion = previous.EngineVersion, CurrentEngineVersion = current.EngineVersion,
                PreviousCompositeCount = previous.Composites.Count, CurrentCompositeCount = current.Composites.Count,
                PreviousBehavioralCompositeCount = previous.BehavioralComposites.Count,
                CurrentBehavioralCompositeCount = current.BehavioralComposites.Count,
                BehavioralOutputsChanged = JsonSerializer.Serialize(previous.BehavioralComposites) !=
                    JsonSerializer.Serialize(current.BehavioralComposites)
            };
            for (int i = 0; i < previous.Steps.Count; i++)
            {
                var oldCard = previous.Steps[i].ScoreCard;
                var newCard = current.Steps[i].ScoreCard;
                if (oldCard.Decision != newCard.Decision || oldCard.TotalScore != newCard.TotalScore ||
                    oldCard.EligibleForComposite != newCard.EligibleForComposite)
                    result.ChangedStepIndexes.Add(i);
            }
            return result;
        }
    }

    public sealed class ReplayStep
    {
        public DateTime Timestamp { get; set; }
        public CorrelationScoreCard ScoreCard { get; set; } = new();
    }
}
