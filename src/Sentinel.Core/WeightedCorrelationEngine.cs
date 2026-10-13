using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using Sentinel.Core.Plugins;

namespace Sentinel.Core
{
    /// <summary>
    /// v2.0 - Explainable weighted multi-signal correlation.
    ///
    /// Complements BehavioralCorrelationEngine (hand-authored composites) with a
    /// transparent score card:
    ///
    ///   Network=18, Memory/Injection=44, Persistence=31, Credential=50, ...
    ///   Total >= Threshold (default 100) + >=2 distinct weight categories
    ///   + at least one terminal-family contribution -> emit composite.
    ///
    /// Score cards are always attached to detections for ops/explainability even
    /// when the threshold is not met.
    /// </summary>
    public sealed class WeightedCorrelationEngine
    {
        private readonly ConcurrentDictionary<int, List<DetectionEvent>> _buffers = new();
        private readonly ConcurrentDictionary<int, DateTime> _lastEmit = new();
        private readonly WeightedCorrelationConfig _config;
        private readonly PluginRegistry? _plugins;
        private readonly EventGraph? _eventGraph;
        private readonly ILogger<WeightedCorrelationEngine>? _logger;
        private Func<DetectionEvent, Task>? _emitCallback;
        private DateTime _lastPrune = DateTime.UtcNow;

        private static readonly TimeSpan CorrelationWindow = TimeSpan.FromSeconds(90);
        private static readonly TimeSpan EmitCooldown = TimeSpan.FromSeconds(60);
        private static readonly TimeSpan PruneInterval = TimeSpan.FromSeconds(60);

        /// <summary>Category -> weight (0-100 scale contribution, not confidence).</summary>
        public static readonly IReadOnlyDictionary<string, int> DefaultWeights =
            new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase)
            {
                ["Credential"] = 50,
                ["TokenTheft"] = 48,
                ["Injection"] = 44,
                ["Memory"] = 40,
                ["Ransomware"] = 55,
                ["C2"] = 42,
                ["ReverseShell"] = 48,
                ["Exfil"] = 38,
                ["Persistence"] = 31,
                ["PrivilegeEscalation"] = 35,
                ["Evasion"] = 33,
                ["BYOVD"] = 60,
                ["Network"] = 18,
                ["Dns"] = 20,
                ["Lateral"] = 36,
                ["Surveillance"] = 28,
                ["Unsigned"] = 22,
                ["Generic"] = 10,
            };

        public WeightedCorrelationEngine(
            WeightedCorrelationConfig? config = null,
            PluginRegistry? plugins = null,
            ILogger<WeightedCorrelationEngine>? logger = null,
            EventGraph? eventGraph = null)
        {
            _config = config ?? new WeightedCorrelationConfig();
            _plugins = plugins;
            _logger = logger;
            _eventGraph = eventGraph;
        }

        public void Initialize(Func<DetectionEvent, Task> emitCallback)
        {
            _emitCallback = emitCallback;
        }

        /// <summary>
        /// Register a detection signal. Always writes ScoreCard metadata onto the signal.
        /// May emit a weighted composite when threshold + terminal contribution are met.
        /// </summary>
        public async Task RegisterSignalAsync(DetectionEvent signal)
        {
            if (signal == null || signal.ProcessId <= 0) return;
            if (!_config.Enabled) return;

            // Respect product law: pure UX / installer noise never participates.
            if (ResponsePolicy.IsNonCorrelatingObserveNoise(signal))
                return;
            if (ResponsePolicy.IsPureUxObserveNoise(signal))
                return;

            PruneStale();

            var buffer = _buffers.GetOrAdd(signal.ProcessId, _ => new List<DetectionEvent>());
            lock (buffer)
            {
                buffer.Add(signal);
                if (buffer.Count > 80)
                    buffer.RemoveAt(0);
                var cutoff = DateTime.UtcNow - CorrelationWindow;
                buffer.RemoveAll(s => s.Timestamp < cutoff);
            }

            List<DetectionEvent> snapshot;
            lock (buffer)
                snapshot = new List<DetectionEvent>(buffer);

            var card = BuildScoreCard(signal.ProcessId, signal.ProcessName, snapshot);
            AttachScoreCard(signal, card);

            // Plugin correlation rules (extensibility surface)
            if (_plugins != null && _emitCallback != null)
            {
                foreach (var rule in _plugins.CorrelationRules)
                {
                    try
                    {
                        var pluginHit = rule.Evaluate(signal.ProcessId, signal.ProcessName, snapshot);
                        if (pluginHit != null)
                        {
                            pluginHit.Metadata ??= new Dictionary<string, string>();
                            pluginHit.Metadata[ResponsePolicy.ChainConfirmedKey] = "true";
                            pluginHit.Metadata[ResponsePolicy.TerminalOutcomeKey] = "Composite";
                            pluginHit.Metadata["WeightedPluginRule"] = rule.Name;
                            AttackTechniqueMap.Enrich(pluginHit);
                            await _emitCallback(pluginHit).ConfigureAwait(false);
                            _lastEmit[signal.ProcessId] = DateTime.UtcNow;
                            return;
                        }
                    }
                    catch (Exception ex)
                    {
                        _logger?.LogDebug(ex, "[WeightedCorrelation] Plugin rule {Name} failed", rule.Name);
                    }
                }
            }

            if (!ShouldEmit(card, snapshot))
                return;

            if (_lastEmit.TryGetValue(signal.ProcessId, out var last) &&
                DateTime.UtcNow - last < EmitCooldown)
                return;

            if (_emitCallback == null) return;

            var composite = BuildComposite(card, snapshot);
            _lastEmit[signal.ProcessId] = DateTime.UtcNow;
            await _emitCallback(composite).ConfigureAwait(false);
        }

        /// <summary>Build an explainable score card for current buffer state (test/ops helper).</summary>
        public CorrelationScoreCard GetScoreCard(int processId)
        {
            if (!_buffers.TryGetValue(processId, out var buffer))
                return new CorrelationScoreCard { ProcessId = processId };

            List<DetectionEvent> snapshot;
            lock (buffer)
                snapshot = new List<DetectionEvent>(buffer);

            var name = snapshot.FirstOrDefault()?.ProcessName ?? "";
            return BuildScoreCard(processId, name, snapshot);
        }

        private bool ShouldEmit(CorrelationScoreCard card, List<DetectionEvent> signals)
        {
            if (card.TotalScore < _config.Threshold)
                return false;
            if (card.CategoryContributions.Count < _config.MinDistinctCategories)
                return false;

            // Require a terminal-family leg OR very high score (defense in depth).
            bool hasTerminal = signals.Any(s =>
                ResponsePolicy.IsKillGradeTerminal(s) ||
                ResponsePolicy.IsNukeComposite(s) ||
                IsTerminalCategory(MapWeightCategory(s)));

            if (!hasTerminal && card.TotalScore < _config.Threshold + 40)
                return false;

            return true;
        }

        private CorrelationScoreCard BuildScoreCard(int pid, string processName, List<DetectionEvent> signals)
        {
            var card = new CorrelationScoreCard
            {
                ProcessId = pid,
                ProcessName = processName ?? "",
                Threshold = _config.Threshold,
                WindowSeconds = (int)CorrelationWindow.TotalSeconds,
            };

            var weights = _config.Weights ?? DefaultWeights;
            var bestByCategory = new Dictionary<string, (int Weight, string Rule, double Conf)>(
                StringComparer.OrdinalIgnoreCase);

            foreach (var s in signals)
            {
                if (ResponsePolicy.IsNonCorrelatingObserveNoise(s) ||
                    ResponsePolicy.IsPureUxObserveNoise(s))
                    continue;

                var cat = MapWeightCategory(s);
                if (!weights.TryGetValue(cat, out var w))
                    w = weights.TryGetValue("Generic", out var g) ? g : 10;

                // Scale weight by confidence (0.5-1.0 floor so weak signals still contribute less)
                double conf = s.Confidence > 0 ? Math.Min(1.0, s.Confidence) : 0.55;
                int scaled = (int)Math.Round(w * (0.5 + 0.5 * conf));

                if (!bestByCategory.TryGetValue(cat, out var existing) || scaled > existing.Weight)
                    bestByCategory[cat] = (scaled, s.RuleName ?? "", conf);
            }

            foreach (var kv in bestByCategory.OrderByDescending(k => k.Value.Weight))
            {
                card.CategoryContributions[kv.Key] = kv.Value.Weight;
                card.ContributingRules.Add($"{kv.Key}={kv.Value.Weight} ({kv.Value.Rule})");
            }

            card.TotalScore = card.CategoryContributions.Values.Sum();

            // v2.0: EventGraph diversity boost (PROCESS->FILE/ENDPOINT fan-out)
            if (_eventGraph != null && _config.EnableGraphBoost)
            {
                var diversity = _eventGraph.GetProcessDiversity(pid, processName);
                if (diversity.WeightBoost > 0)
                {
                    card.GraphBoost = diversity.WeightBoost;
                    card.TotalScore += diversity.WeightBoost;
                    card.CategoryContributions["GraphDiversity"] = diversity.WeightBoost;
                    card.ContributingRules.Add(
                        $"GraphDiversity={diversity.WeightBoost} (edges={diversity.EdgeCount}, " +
                        $"endpoints={diversity.DistinctEndpoints}, files={diversity.DistinctFiles})");
                }
            }

            card.DistinctCategories = card.CategoryContributions.Count(kv =>
                !string.Equals(kv.Key, "GraphDiversity", StringComparison.OrdinalIgnoreCase));
            card.SignalCount = signals.Count;
            card.MeetsThreshold = card.TotalScore >= _config.Threshold &&
                                  card.DistinctCategories >= _config.MinDistinctCategories;
            card.Explanation = BuildExplanation(card);
            return card;
        }

        private static string BuildExplanation(CorrelationScoreCard card)
        {
            var sb = new StringBuilder();
            sb.Append("Weighted correlation: ");
            sb.Append(string.Join(" + ", card.CategoryContributions.Select(kv => $"{kv.Key}={kv.Value}")));
            sb.Append($" = {card.TotalScore}");
            sb.Append(card.MeetsThreshold
                ? $" >= threshold {card.Threshold} (emit)"
                : $" < threshold {card.Threshold} (observe)");
            return sb.ToString();
        }

        private static void AttachScoreCard(DetectionEvent signal, CorrelationScoreCard card)
        {
            signal.Metadata ??= new Dictionary<string, string>();
            signal.Metadata["ScoreCardTotal"] = card.TotalScore.ToString();
            signal.Metadata["ScoreCardThreshold"] = card.Threshold.ToString();
            signal.Metadata["ScoreCardCategories"] = string.Join(",", card.CategoryContributions.Keys);
            signal.Metadata["ScoreCardBreakdown"] = string.Join(";",
                card.CategoryContributions.Select(kv => $"{kv.Key}={kv.Value}"));
            signal.Metadata["ScoreCardExplanation"] = card.Explanation;
            signal.Metadata["ScoreCardMeetsThreshold"] = card.MeetsThreshold ? "true" : "false";
            AttackTechniqueMap.Enrich(signal);
        }

        private DetectionEvent BuildComposite(CorrelationScoreCard card, List<DetectionEvent> signals)
        {
            var techniques = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (var s in signals)
            {
                foreach (var t in AttackTechniqueMap.Resolve(s.RuleName))
                    techniques.Add(t);
            }

            var ev = new DetectionEvent
            {
                RuleName = "Weighted Correlation: Multi-Signal Threat",
                ProcessId = card.ProcessId,
                ProcessName = card.ProcessName,
                Confidence = Math.Min(0.97, 0.82 + (card.TotalScore / 500.0)),
                Tier = DetectionTier.Tier1Behavioral,
                AuthorizedResponse = ResponseAction.QuarantineAndKill,
                SignalType = SignalType.SuspiciousProcess,
                Evidence = $"[COMPOSITE] {card.Explanation} (PID {card.ProcessId})",
                Reasoning =
                    "Explainable weighted multi-category correlation exceeded the configured threshold. " +
                    "Distinct behavioral categories on the same process within the correlation window " +
                    "constitute multi-signal proof under ObserveUntilChain. Breakdown: " +
                    string.Join(", ", card.ContributingRules),
                Timestamp = DateTime.UtcNow,
                Metadata = new Dictionary<string, string>
                {
                    [ResponsePolicy.ChainConfirmedKey] = "true",
                    [ResponsePolicy.TerminalOutcomeKey] = "Composite",
                    ["ScoreCardTotal"] = card.TotalScore.ToString(),
                    ["ScoreCardThreshold"] = card.Threshold.ToString(),
                    ["ScoreCardBreakdown"] = string.Join(";",
                        card.CategoryContributions.Select(kv => $"{kv.Key}={kv.Value}")),
                    ["ScoreCardExplanation"] = card.Explanation,
                    ["WeightedCorrelation"] = "true",
                }
            };

            if (techniques.Count > 0)
            {
                ev.Metadata["AttackTechniques"] = string.Join(",", techniques);
                ev.Metadata["AttackTechniqueCount"] = techniques.Count.ToString();
            }
            else
            {
                AttackTechniqueMap.Enrich(ev);
            }

            return ev;
        }

        /// <summary>Map a detection to a weight-bucket category.</summary>
        public static string MapWeightCategory(DetectionEvent s)
        {
            if (s == null) return "Generic";
            var r = s.RuleName ?? "";
            var cat = ScoringEngine.CategorizeDetection(r);

            // Prefer terminal / high-signal families by name first
            if (ContainsAny(r, "BYOVD", "Vulnerable Driver", "kdmapper")) return "BYOVD";
            if (ContainsAny(r, "Token Theft", "Impersonat", "SeImpersonate", "Potato")) return "TokenTheft";
            if (ContainsAny(r, "LSASS", "Credential Dump", "Mimikatz", "SAM hive", "DCSync")) return "Credential";
            if (ContainsAny(r, "Sensitive File Access", "Infostealer")) return "Credential";
            if (ContainsAny(r, "Archive of User Documents", "Data Staging")) return "Exfil";
            if (ContainsAny(r, "Reverse Shell", "Bind Shell", "revshell", "meterpreter")) return "ReverseShell";
            if (ContainsAny(r, "Ransomware", "Shadow Copy", "Mass File Rename", "Bulk Encrypt")) return "Ransomware";
            if (ContainsAny(r, "Beacon", "C2", "Command-and-Control")) return "C2";
            if (ContainsAny(r, "Exfil", "DNS Tunnel", "DNS Exfil", "Data Staging")) return "Exfil";
            if (ContainsAny(r, "Injection", "Unbacked RWX", "Hollowing", "RWX")) return "Injection";
            if (ContainsAny(r, "Hell's Gate", "Syscall", "Unbacked")) return "Memory";
            if (ContainsAny(r, "Persistence", "Scheduled Task", "Run Key", "Autorun", "WMI Subscription")) return "Persistence";
            if (ContainsAny(r, "Privilege", "UAC Bypass", "Elevated Process", "LegacyHive", "FudModule", "Dream Job", "Kernel Exploit Loader", "Installer EoP", "AlwaysInstallElevated", "Package Manager EoP")) return "PrivilegeEscalation";
            if (ContainsAny(r, "AMSI", "ETW", "Evasion", "Tamper", "Cloud Files", "ShieldBreak")) return "Evasion";
            if (ContainsAny(r, "Lateral", "PsExec", "WinRM", "DCOM", "SMB Admin")) return "Lateral";
            if (ContainsAny(r, "Screen Capture", "Webcam", "Desktop Duplication", "Surveillance", "Stalkerware")) return "Surveillance";
            if (ContainsAny(r, "DNS", "DGA")) return "Dns";
            if (ContainsAny(r, "Network", "Outbound", "Connection")) return "Network";
            if (ContainsAny(r, "Unsigned", "High Entropy")) return "Unsigned";

            return cat switch
            {
                DetectionCategory.CredentialDump => "Credential",
                DetectionCategory.ReverseShell => "ReverseShell",
                DetectionCategory.ProcessInjection => "Injection",
                DetectionCategory.Ransomware => "Ransomware",
                DetectionCategory.C2Beaconing => "C2",
                DetectionCategory.Persistence => "Persistence",
                DetectionCategory.PrivilegeEscalation => "PrivilegeEscalation",
                DetectionCategory.SecurityEvasion => "Evasion",
                DetectionCategory.AntiTamper => "Evasion",
                DetectionCategory.DataExfiltration => "Exfil",
                DetectionCategory.DnsAnomaly => "Dns",
                DetectionCategory.NetworkAnomaly => "Network",
                DetectionCategory.LateralMovement => "Lateral",
                DetectionCategory.FilelessAttack => "Memory",
                DetectionCategory.UnsignedBinary => "Unsigned",
                DetectionCategory.HighEntropy => "Unsigned",
                _ => s.SignalType switch
                {
                    SignalType.LsassAccess => "Credential",
                    SignalType.CredentialTheft => "Credential",
                    SignalType.Ransomware => "Ransomware",
                    SignalType.ReverseShell => "ReverseShell",
                    SignalType.NetworkC2 => "C2",
                    SignalType.ProcessInjection => "Injection",
                    SignalType.SecurityEvasion => "Evasion",
                    SignalType.AmsiTampering => "Evasion",
                    SignalType.EtwTampering => "Evasion",
                    _ => "Generic"
                }
            };
        }

        private static bool IsTerminalCategory(string cat) =>
            cat is "Credential" or "TokenTheft" or "ReverseShell" or "C2"
                or "Ransomware" or "BYOVD" or "Exfil" or "Injection";

        private static bool ContainsAny(string haystack, params string[] needles)
        {
            foreach (var n in needles)
            {
                if (haystack.IndexOf(n, StringComparison.OrdinalIgnoreCase) >= 0)
                    return true;
            }
            return false;
        }

        private void PruneStale()
        {
            var now = DateTime.UtcNow;
            if (now - _lastPrune < PruneInterval) return;
            _lastPrune = now;

            var cutoff = now - CorrelationWindow;
            var stale = new List<int>();
            foreach (var kvp in _buffers)
            {
                lock (kvp.Value)
                {
                    kvp.Value.RemoveAll(s => s.Timestamp < cutoff);
                    if (kvp.Value.Count == 0)
                        stale.Add(kvp.Key);
                }
            }
            foreach (var k in stale)
                _buffers.TryRemove(k, out _);
        }
    }

    /// <summary>Explainable per-process correlation score card (v2.0).</summary>
    public sealed class CorrelationScoreCard
    {
        public int ProcessId { get; set; }
        public string ProcessName { get; set; } = "";
        public int TotalScore { get; set; }
        public int Threshold { get; set; }
        public int DistinctCategories { get; set; }
        public int SignalCount { get; set; }
        public int WindowSeconds { get; set; }
        public bool MeetsThreshold { get; set; }
        public string Explanation { get; set; } = "";
        public Dictionary<string, int> CategoryContributions { get; set; } =
            new(StringComparer.OrdinalIgnoreCase);
        public List<string> ContributingRules { get; set; } = new();
        /// <summary>v2.0 EventGraph diversity boost applied to TotalScore.</summary>
        public int GraphBoost { get; set; }
    }

    /// <summary>Config for WeightedCorrelationEngine (bound under Sentinel:WeightedCorrelation).</summary>
    public sealed class WeightedCorrelationConfig
    {
        public bool Enabled { get; set; } = true;
        /// <summary>Total weight threshold to emit a composite (default 100).</summary>
        public int Threshold { get; set; } = 100;
        /// <summary>Minimum distinct weight categories required.</summary>
        public int MinDistinctCategories { get; set; } = 2;
        /// <summary>When true (default), add EventGraph fan-out boost to the score card.</summary>
        public bool EnableGraphBoost { get; set; } = true;
        /// <summary>Optional override weights; null uses DefaultWeights.</summary>
        public Dictionary<string, int>? Weights { get; set; }
    }
}
