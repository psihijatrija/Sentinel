using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

namespace Sentinel.Core
{
    public sealed class TelemetryReplayRecord
    {
        public string Kind { get; set; } = "";
        public JsonElement Data { get; set; }
        public static TelemetryReplayRecord FromEvent(TelemetryEvent value)
        {
            string kind = value is ProcessTelemetry ? "Process" : value is NetworkTelemetry ? "Network" :
                value is FileActivityTelemetry ? "File" : value is ThreatIntelTelemetry ? "ThreatIntel" :
                throw new ArgumentException("Unsupported telemetry kind.");
            return new TelemetryReplayRecord { Kind = kind, Data = JsonSerializer.SerializeToElement(value, value.GetType()) };
        }
        internal TelemetryEvent Materialize()
        {
            var options = new JsonSerializerOptions { PropertyNameCaseInsensitive = true };
            if (Data.ValueKind != JsonValueKind.Object || !Data.EnumerateObject().Any(p => string.Equals(p.Name, "Timestamp", StringComparison.OrdinalIgnoreCase)))
                throw new InvalidDataException("Recorded telemetry requires an explicit timestamp.");
            TelemetryEvent value = Kind switch
            {
                "Process" => Data.Deserialize<ProcessTelemetry>(options)!, "Network" => Data.Deserialize<NetworkTelemetry>(options)!,
                "File" => Data.Deserialize<FileActivityTelemetry>(options)!, "ThreatIntel" => Data.Deserialize<ThreatIntelTelemetry>(options)!,
                _ => throw new InvalidDataException("Unsupported telemetry kind.")
            };
            if (value == null || value.Timestamp.Kind != DateTimeKind.Utc || value.ProcessId < 0 || value.ProcessName == null ||
                (value is ProcessTelemetry process && (process.CommandLine == null || process.ImagePath == null)))
                throw new InvalidDataException("Telemetry requires UTC time, a nonnegative PID and non-null rule inputs.");
            return value;
        }
    }

    public sealed class TelemetryReplayReport
    {
        public int SchemaVersion { get; set; } = 1;
        public string Profile { get; set; } = "RecordedInputRules-v1";
        public string Scope { get; set; } = "Selected recorded-input rules + shared fusion features + behavioral/weighted correlation. No live identity, scoring/allowlists, reputation, graph, dynamic rules, sliding-window rules or response execution. Historical PIDs never query the current machine.";
        public string RuleArtifactId { get; set; } = typeof(TelemetryReplay).Module.ModuleVersionId.ToString("D");
        public string InputSha256 { get; set; } = "";
        public int InputCount { get; set; }
        public int RuleEvaluationCount { get; set; }
        public int SuppressedDetectionCount { get; set; }
        public List<string> RuleNames { get; set; } = new();
        public List<TelemetryReplayDetection> Detections { get; set; } = new();
        public DetectionReplayReport Correlation { get; set; } = new();
    }
    public sealed class TelemetryReplayDetection
    {
        public int EventIndex { get; set; }
        public DetectionEvent Detection { get; set; } = new();
    }

    /// <summary>A fixed, reviewed profile cannot load plugins, arbitrary rule types, processes or live services.</summary>
    public sealed class TelemetryReplay
    {
        public async Task<TelemetryReplayReport> RunAsync(IEnumerable<TelemetryReplayRecord> records,
            WeightedCorrelationConfig config, CancellationToken ct = default)
        {
            if (records == null) throw new ArgumentNullException(nameof(records));
            if (config == null) throw new ArgumentNullException(nameof(config));
            ct.ThrowIfCancellationRequested();
            var events = new List<TelemetryEvent>();
            foreach (var record in records)
            {
                ct.ThrowIfCancellationRequested();
                if (record == null || events.Count >= 100000) throw new InvalidDataException("Maximum 100000 non-null telemetry records.");
                events.Add(record.Materialize());
            }
            if (events.Count == 0) throw new InvalidDataException("No telemetry records found.");
            events = events.OrderBy(e => e.Timestamp).ToList(); // Stable ordering preserves ties from the capture.
            var report = new TelemetryReplayReport { InputCount = events.Count };
            using (var sha = SHA256.Create())
                report.InputSha256 = BitConverter.ToString(sha.ComputeHash(Encoding.UTF8.GetBytes(
                    JsonSerializer.Serialize(events.Select(TelemetryReplayRecord.FromEvent))))).Replace("-", "").ToLowerInvariant();
            IDetectionRule[] rules = { new LsassAccessRule(), new RansomwareDetectionRule(), new ReverseShellRule(),
                new PrivilegeEscalationRule(), new ClickFixDetectionRule(), new NpmSupplyChainRule(),
                new ChromeRemoteDebuggingRule(), new DangerousBrowserFlagRule() };
            report.RuleNames = rules.Select(rule => rule.Name).ToList();
            var history = new Dictionary<int, Queue<TelemetryEvent>>();
            var dedup = new System.Collections.Concurrent.ConcurrentDictionary<(string, int), DateTime>();
            for (int index = 0; index < events.Count; index++)
            {
                ct.ThrowIfCancellationRequested();
                var value = events[index];
                if (!history.TryGetValue(value.ProcessId, out var chain))
                {
                    // Bound active context without silently dropping inputs or creating partial reports.
                    foreach (var pid in history.Where(kv => kv.Value.Last().Timestamp < value.Timestamp.AddMinutes(-2)).Select(kv => kv.Key).ToArray()) history.Remove(pid);
                    if (history.Count >= 8000) throw new InvalidDataException("Replay exceeds 8000 active PID histories.");
                    history[value.ProcessId] = chain = new Queue<TelemetryEvent>();
                }
                chain.Enqueue(value);
                while (chain.Count > 500) chain.Dequeue(); // Same per-PID event cap as live fusion.
                var context = TelemetryContextBuilder.Build(value, chain, value.Timestamp);
                foreach (var rule in rules)
                {
                    ct.ThrowIfCancellationRequested();
                    report.RuleEvaluationCount++;
                    var detection = rule.Evaluate(context);
                    if (detection == null) continue;
                    // Rules traditionally timestamp at construction; replay binds them to recorded time.
                    detection.Timestamp = value.Timestamp;
                    if (!DetectionDeduplication.TryClaim(dedup, (detection.RuleName, detection.ProcessId), value.Timestamp,
                        detection.Tier == DetectionTier.Tier1Behavioral ? TimeSpan.FromSeconds(10) : TimeSpan.FromSeconds(30)))
                    { report.SuppressedDetectionCount++; continue; }
                    detection.Metadata ??= new Dictionary<string, string>();
                    detection.Metadata["ReplayRequestedAction"] = detection.AuthorizedResponse.ToString();
                    ResponsePolicy.ApplyTierLaw(detection);
                    detection.Metadata["ReplayTierLawAction"] = detection.AuthorizedResponse.ToString();
                    detection.AuthorizedResponse = ResponseAction.LogOnly;
                    detection.Metadata["ReplayOnly"] = "true";
                    report.Detections.Add(new TelemetryReplayDetection { EventIndex = index, Detection = detection });
                }
            }
            report.Correlation = await new DetectionReplay().RunAsync(report.Detections.Select(d => d.Detection), config, ct, includeBehavioral: true).ConfigureAwait(false);
            return report;
        }
    }

    public sealed class TelemetryReplayComparison
    {
        public string PreviousRuleArtifactId { get; set; } = "";
        public string CurrentRuleArtifactId { get; set; } = "";
        public List<int> ChangedEventIndexes { get; set; } = new();
        public bool CorrelationOutputsChanged { get; set; }
        public static TelemetryReplayComparison Compare(TelemetryReplayReport previous, TelemetryReplayReport current)
        {
            if (previous.SchemaVersion != 1 || current.SchemaVersion != 1 || string.IsNullOrEmpty(previous.InputSha256) ||
                previous.InputSha256 != current.InputSha256 || previous.Profile != current.Profile || previous.InputCount != current.InputCount)
                throw new ArgumentException("Telemetry comparison requires the same recorded input and replay profile.");
            var result = new TelemetryReplayComparison { PreviousRuleArtifactId = previous.RuleArtifactId, CurrentRuleArtifactId = current.RuleArtifactId };
            var oldEvents = previous.Detections.GroupBy(d => d.EventIndex).ToDictionary(g => g.Key, g => JsonSerializer.Serialize(g.ToList()));
            var newEvents = current.Detections.GroupBy(d => d.EventIndex).ToDictionary(g => g.Key, g => JsonSerializer.Serialize(g.ToList()));
            foreach (var index in oldEvents.Keys.Union(newEvents.Keys).OrderBy(i => i))
                if (!oldEvents.TryGetValue(index, out var old) || !newEvents.TryGetValue(index, out var next) || old != next)
                    result.ChangedEventIndexes.Add(index);
            result.CorrelationOutputsChanged = JsonSerializer.Serialize(previous.Correlation.Composites) != JsonSerializer.Serialize(current.Correlation.Composites) ||
                JsonSerializer.Serialize(previous.Correlation.BehavioralComposites) != JsonSerializer.Serialize(current.Correlation.BehavioralComposites);
            return result;
        }
    }
}
