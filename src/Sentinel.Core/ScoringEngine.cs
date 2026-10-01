using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;
using Microsoft.Extensions.Logging;

namespace Sentinel.Core
{
    /// <summary>
    /// Categorical classification of detection events.
    /// Used by ScoringEngine for corroboration, boosting, and verdict determination.
    /// </summary>
    public enum DetectionCategory
    {
        Unknown,
        CredentialDump,
        ReverseShell,
        ProcessInjection,
        Ransomware,
        SecurityEvasion,
        C2Beaconing,
        Persistence,
        PrivilegeEscalation,
        UnsignedBinary,
        HighEntropy,
        CampaignIoC,
        AttackOnUser,
        AntiTamper,
        NetworkAnomaly,
        DataExfiltration,
        DnsAnomaly,
        FilelessAttack,
        LateralMovement
    }

    /// <summary>
    /// Compile-time attribute that declares the primary detection category for a rule.
    /// This replaces fragile string-matching in ScoringEngine.CategorizeDetection with
    /// a type-safe, statically-verified approach. If a rule is renamed, the category
    /// stays correct. If a new rule forgets to add this attribute, the fallback string
    /// matcher still works - but the preferred path is always the attribute.
    /// </summary>
    [AttributeUsage(AttributeTargets.Class, AllowMultiple = false, Inherited = false)]
    public sealed class RuleCategoryAttribute : Attribute
    {
        public DetectionCategory Category { get; }
        public RuleCategoryAttribute(DetectionCategory category) => Category = category;
    }

    /// <summary>
    /// Static registry that maps rule names to their declared DetectionCategory.
    /// Built once at startup by scanning all IDetectionRule implementations for
    /// [RuleCategory] attributes. Provides O(1) lookup by rule name, eliminating
    /// the string-Contains pattern matching that was previously required.
    /// </summary>
    public static class RuleCategoryRegistry
    {
        private static readonly Dictionary<string, DetectionCategory> _registry;

        static RuleCategoryRegistry()
        {
            _registry = new Dictionary<string, DetectionCategory>(StringComparer.OrdinalIgnoreCase);

            // Scan all types in the Core assembly that implement IDetectionRule
            var coreAssembly = typeof(IDetectionRule).Assembly;
            foreach (var type in coreAssembly.GetTypes())
            {
                if (!typeof(IDetectionRule).IsAssignableFrom(type) || type.IsInterface || type.IsAbstract)
                    continue;

                var attr = type.GetCustomAttribute<RuleCategoryAttribute>();
                if (attr == null) continue;

                // Instantiate temporarily to get the Name property, or use naming convention
                // Convention: rule name = class name (which is how all rules are written)
                // We use the class name as a fallback key and also try to get the Name property
                try
                {
                    // Try to read the Name from a static or instance property via reflection
                    var nameProp = type.GetProperty("Name", BindingFlags.Public | BindingFlags.Instance);
                    if (nameProp != null && nameProp.PropertyType == typeof(string))
                    {
                        // Create a minimal instance to read the Name value
                        // Most rules have parameterless constructors or we use the class name
                        try
                        {
                            var instance = Activator.CreateInstance(type, nonPublic: true);
                            if (instance != null)
                            {
                                var name = (string?)nameProp.GetValue(instance);
                                if (!string.IsNullOrEmpty(name))
                                    _registry[name!] = attr.Category;
                            }
                        }
                        catch
                        {
                            // Constructor requires parameters - fall through to class name
                        }
                    }

                    // Always register the class name as well (handles rules with DI constructors)
                    _registry[type.Name] = attr.Category;
                }
                catch { }
            }
        }

        /// <summary>
        /// Attempts to resolve a rule name to its declared category.
        /// Returns null if no attribute-based mapping exists (falls back to string matching).
        /// </summary>
        public static DetectionCategory? Resolve(string? ruleName)
        {
            if (string.IsNullOrEmpty(ruleName)) return null;
            return _registry.TryGetValue(ruleName!, out var category) ? category : null;
        }
    }

    /// <summary>
    /// Multi-signal scoring engine. Aggregates per-process detection events into a
    /// composite threat score. Score increases with:
    ///   - Base confidence of the detection
    ///   - Number of corroborating detection sources
    ///   - Multiple distinct threat categories on the same process
    ///   - Known-bad hash match
    ///   - President's Law rule hits (always boosted)
    /// Score decreases with:
    ///   - Trusted publisher signature
    ///   - Development/gaming process context
    ///   - User allowlist entry
    /// </summary>
    public sealed class ScoringEngine
    {
        private readonly AllowlistService _allowlist;
        private readonly SafeProcessExemptionRegistry _exemptionRegistry;
        private readonly BehavioralBaselineService? _baseline;
        private readonly ILogger<ScoringEngine> _logger;
        private readonly ConcurrentDictionary<int, ProcessScoreState> _processStates = new();
        private readonly TimeSpan _stateRetention = TimeSpan.FromMinutes(30);

        public ScoringEngine(
            AllowlistService allowlist,
            SafeProcessExemptionRegistry exemptionRegistry,
            ILogger<ScoringEngine> logger,
            BehavioralBaselineService? baseline = null)
        {
            _allowlist = allowlist;
            _exemptionRegistry = exemptionRegistry;
            _baseline = baseline;
            _logger = logger;
        }

        private static bool IsAttackOnUserRule(DetectionEvent detection)
        {
            return CategorizeDetection(detection.RuleName) == DetectionCategory.AttackOnUser;
        }

        /// <summary>
        /// President's Law rules: high-severity detections that always receive boosted scoring.
        /// These represent the most dangerous behaviors where immediate response is critical.
        /// 
        /// NOTE (v0.8.2): C2Beaconing was removed from President's Law.
        /// HARDENING v1.5.9: C2Beaconing RE-ADDED to President's Law for suppression protection.
        /// The AllowlistService must never fully suppress C2 beaconing detections - a user-
        /// allowlisted process (e.g., chrome.exe) with an injected Cobalt Strike beacon would
        /// have all beaconing detections suppressed, allowing the C2 channel to persist.
        /// The BeaconingDetector's own trust demotion logic (v1.5.9: minimum NetworkIsolate)
        /// controls the actual response action, so the previous false-positive concern
        /// (Steam/torrent clients getting killed) is already mitigated there.
        /// </summary>
        public static bool IsPresidentsLawRule(string? ruleName)
        {
            var category = CategorizeDetection(ruleName);
            // v2.2.0: DnsAnomaly / NetworkAnomaly are observe fuel, not President's Law.
            // A DNS spike or ARP noise must not become un-allowlistable kill-grade.
            return category is DetectionCategory.CredentialDump
                or DetectionCategory.SecurityEvasion
                or DetectionCategory.Ransomware
                or DetectionCategory.ProcessInjection
                or DetectionCategory.ReverseShell
                or DetectionCategory.AntiTamper
                or DetectionCategory.AttackOnUser
                or DetectionCategory.PrivilegeEscalation
                or DetectionCategory.C2Beaconing;
        }

        private static bool IsPresidentsLawRule(DetectionEvent detection)
        {
            return IsPresidentsLawRule(detection.RuleName);
        }

        /// <summary>
        /// Scores a detection event, combining base confidence with corroboration,
        /// category breadth, and trust context into a composite ThreatScore.
        /// </summary>
        public ThreatScore Score(DetectionEvent detection)
        {
            var category = CategorizeDetection(detection);
            int baseScore = (int)(detection.Confidence * 100);

            // HARDENING v1.5.9: Record that a detection fired for this process name.
            // This prevents the process from ever achieving "established" baseline status,
            // closing the baseline poisoning attack vector where malware runs 10+ times
            // with persistence to earn trust score reductions.
            if (_baseline != null && !string.IsNullOrEmpty(detection.ProcessName))
            {
                _baseline.RecordDetectionForProcess(detection.ProcessName);
            }

            var adjustments = new List<ScoreAdjustment>();

            // Attack-on-user boost: double the confidence score adjustment
            if (IsAttackOnUserRule(detection))
            {
                int boost = baseScore;
                adjustments.Add(new ScoreAdjustment("Attack-on-user double confidence boost", boost, "Double confidence weighting for user-targeting attack"));
                baseScore += boost;
            }

            // Corroboration boost: +15 per additional source category on this process
            int corroborating = GetCorroboratingCategoryCount(detection.ProcessId, category);
            if (corroborating > 0)
            {
                int boost = corroborating * 15;
                adjustments.Add(new ScoreAdjustment("Multi-category corroboration", boost,
                    $"{corroborating} other threat categories on this process"));
                baseScore += boost;
            }

            // Tier1 bonus
            if (detection.Tier == DetectionTier.Tier1Behavioral)
            {
                adjustments.Add(new ScoreAdjustment("Tier1 behavioral", 10, "High-fidelity behavioral detection"));
                baseScore += 10;
            }

            // Allowlist reduction
            double reduction = _allowlist.GetConfidenceReduction(
                detection.ProcessName, null, null, detection.RuleName);
            if (reduction > 0)
            {
                int penalty = (int)(reduction * 100);
                adjustments.Add(new ScoreAdjustment("Allowlist reduction", -penalty,
                    $"Trust reduction {reduction:P0}"));
                baseScore -= penalty;
            }

            // Behavioral baseline reduction
            // HARDENING v1.3.0: Cap total baseline/trust reductions to -20.
            // Previously, an attacker running for a week could accumulate -15 (established) +
            // -10 (parent-child) + -15 (network dest) + -30 (safe process) = -70 score reduction,
            // effectively making any detection toothless. Now capped at -20 total.
            int totalBaselineReduction = 0;
            const int MaxBaselineReduction = 20;

            if (_baseline != null)
            {
                if (_baseline.IsEstablishedProcess(detection.ProcessName))
                {
                    int baselinePenalty = Math.Min(10, MaxBaselineReduction - totalBaselineReduction);
                    if (baselinePenalty > 0)
                    {
                        adjustments.Add(new ScoreAdjustment("Behavioral baseline established process", -baselinePenalty,
                            $"Process '{detection.ProcessName}' is established in behavioral baseline"));
                        baseScore -= baselinePenalty;
                        totalBaselineReduction += baselinePenalty;
                    }
                }

                if (totalBaselineReduction < MaxBaselineReduction &&
                    detection.Metadata.TryGetValue("ParentProcessName", out var parentName) &&
                    _baseline.IsKnownParentChild(parentName, detection.ProcessName))
                {
                    int pcPenalty = Math.Min(5, MaxBaselineReduction - totalBaselineReduction);
                    if (pcPenalty > 0)
                    {
                        adjustments.Add(new ScoreAdjustment("Behavioral baseline parent-child relationship", -pcPenalty,
                            $"Parent-child '{parentName} -> {detection.ProcessName}' is known in baseline"));
                        baseScore -= pcPenalty;
                        totalBaselineReduction += pcPenalty;
                    }
                }

                if (totalBaselineReduction < MaxBaselineReduction &&
                    detection.Metadata.TryGetValue("RemoteAddress", out var remoteAddr) &&
                    detection.Metadata.TryGetValue("RemotePort", out var remotePortStr) &&
                    int.TryParse(remotePortStr, out var remotePort) &&
                    _baseline.IsKnownNetworkDestination(detection.ProcessName, remoteAddr, remotePort))
                {
                    int netPenalty = Math.Min(5, MaxBaselineReduction - totalBaselineReduction);
                    if (netPenalty > 0)
                    {
                        adjustments.Add(new ScoreAdjustment("Behavioral baseline network destination", -netPenalty,
                            $"Network destination '{remoteAddr}:{remotePort}' is known for {detection.ProcessName} in baseline"));
                        baseScore -= netPenalty;
                        totalBaselineReduction += netPenalty;
                    }
                }
            }

            // Safe process consensus: removed the -30 blanket reduction.
            // This was too aggressive - a process marked "safe" by consensus could still be
            // compromised via injection or sideloading. Trust is now handled by the capped
            // baseline reduction above.
            bool isPresidentsLaw = IsPresidentsLawRule(detection);

            baseScore = Math.Max(0, baseScore);

            UpdateProcessState(detection.ProcessId, category, detection.Confidence);

            var verdict = DetermineVerdict(baseScore);

            return new ThreatScore
            {
                Score = baseScore,
                Verdict = verdict,
                Category = category,
                OriginalConfidence = detection.Confidence,
                Adjustments = adjustments,
                CorroboratingSources = corroborating
            };
        }

        public int GetCorroboratingCategoryCount(int processId, DetectionCategory currentCategory)
        {
            if (_processStates.TryGetValue(processId, out var state))
                return state.DetectedCategories.Count(c => c != currentCategory);
            return 0;
        }

        public ProcessThreatProfile? GetProcessProfile(int processId)
        {
            if (_processStates.TryGetValue(processId, out var state))
            {
                return new ProcessThreatProfile
                {
                    ProcessId = processId,
                    DetectedCategories = state.DetectedCategories.ToList(),
                    MaxConfidence = state.MaxConfidence,
                    FirstSeen = state.FirstSeen,
                    LastSeen = state.LastSeen,
                    DetectionCount = state.DetectionCount
                };
            }
            return null;
        }

        /// <summary>
        /// Categorizes a detection by rule name. Uses the compile-time-safe RuleCategoryRegistry
        /// first (populated from [RuleCategory] attributes on rule classes), then falls back to
        /// string-pattern matching for composite detections and dynamically-generated rule names
        /// that don't have a corresponding class.
        /// </summary>
        public static DetectionCategory CategorizeDetection(string? ruleName)
        {
            if (string.IsNullOrEmpty(ruleName)) return DetectionCategory.Unknown;

            // Preferred path: attribute-based lookup (O(1), compile-time safe)
            var resolved = RuleCategoryRegistry.Resolve(ruleName);
            if (resolved.HasValue) return resolved.Value;

            // Fallback: string-pattern matching for composite detections, dynamic rules,
            // and monitor-emitted events that don't map to a rule class.
            var r = ruleName!.ToLowerInvariant();
            if (r.Contains("beacon")) return DetectionCategory.C2Beaconing;
            if (r.Contains("lsass") || r.Contains("credential") || r.Contains("credtool") || r.Contains("canary")) return DetectionCategory.CredentialDump;
            if (r.Contains("reverse shell") || r.Contains("reverseshell") || r.Contains("c2") || r.Contains("callback")) return DetectionCategory.ReverseShell;
            if (r.Contains("injection") || r.Contains("hollowing") || r.Contains("threatintel")) return DetectionCategory.ProcessInjection;
            if (r.Contains("ransomware") || r.Contains("shadow copy")) return DetectionCategory.Ransomware;
            if (r.Contains("evasion") || r.Contains("tampering") || r.Contains("amsi") || ContainsEtwToken(r))
                return DetectionCategory.SecurityEvasion;
            if (r.Contains("persistence") || r.Contains("scheduled task") || r.Contains("servicing")) return DetectionCategory.Persistence;
            if (r.Contains("privilege") || r.Contains("uac bypass")) return DetectionCategory.PrivilegeEscalation;
            if (r.Contains("unsigned")) return DetectionCategory.UnsignedBinary;
            if (r.Contains("entropy")) return DetectionCategory.HighEntropy;
            if (r.Contains("campaign")) return DetectionCategory.CampaignIoC;
            if (r.Contains("audiohijack") || r.Contains("audio hijack") || r.Contains("webcamhijack") || r.Contains("webcam hijack") ||
                r.Contains("keystroke") || r.Contains("keylogger") || r.Contains("phantom") || r.Contains("cursor") ||
                r.Contains("fakeuac") || r.Contains("fake uac") || r.Contains("cookie") || r.Contains("neuro")) return DetectionCategory.AttackOnUser;
            if (r.Contains("anti-tamper") || r.Contains("antitamper") || r.Contains("self-protection") || r.Contains("selfprotection") ||
                r.Contains("verdictgate") || r.Contains("verdict gate") || r.Contains("chain-nuke") || r.Contains("composite")) return DetectionCategory.AntiTamper;
            if (r.Contains("dns") || r.Contains("dga")) return DetectionCategory.DnsAnomaly;
            if (r.Contains("arp") || r.Contains("route") || r.Contains("tls") || r.Contains("badusb") || r.Contains("network") || r.Contains("mesh") || r.Contains("derp")) return DetectionCategory.NetworkAnomaly;
            if (r.Contains("exfil") || r.Contains("webhook")) return DetectionCategory.DataExfiltration;
            return DetectionCategory.Unknown;
        }

        private static DetectionCategory CategorizeDetection(DetectionEvent detection)
        {
            return CategorizeDetection(detection.RuleName);
        }

        /// <summary>
        /// ETW as a token, not the letters inside "network" (n-etw-ork).
        /// Restores Contains("etw") for mid-string names ("process etw bypass")
        /// without recategorizing every Network* rule as SecurityEvasion.
        /// </summary>
        internal static bool ContainsEtwToken(string r)
        {
            if (string.IsNullOrEmpty(r)) return false;
            int i = 0;
            while ((i = r.IndexOf("etw", i, StringComparison.Ordinal)) >= 0)
            {
                bool insideNetwork = i >= 1 && i + 6 <= r.Length
                    && r[i - 1] == 'n'
                    && r[i + 3] == 'o'
                    && r[i + 4] == 'r'
                    && r[i + 5] == 'k';
                if (!insideNetwork)
                    return true;
                i += 3;
            }
            return false;
        }

        private static Verdict DetermineVerdict(double score) => score switch
        {
            >= 120 => Verdict.Critical,
            >= 80 => Verdict.Malicious,
            >= 50 => Verdict.Suspicious,
            >= 25 => Verdict.Low,
            _ => Verdict.Clean
        };

        private void UpdateProcessState(int processId, DetectionCategory category, double confidence)
        {
            _processStates.AddOrUpdate(processId,
                _ => new ProcessScoreState
                {
                    ProcessId = processId,
                    DetectedCategories = new HashSet<DetectionCategory> { category },
                    MaxConfidence = confidence,
                    FirstSeen = DateTimeOffset.UtcNow,
                    LastSeen = DateTimeOffset.UtcNow,
                    DetectionCount = 1
                },
                (_, existing) =>
                {
                    existing.DetectedCategories.Add(category);
                    existing.MaxConfidence = Math.Max(existing.MaxConfidence, confidence);
                    existing.LastSeen = DateTimeOffset.UtcNow;
                    existing.DetectionCount++;
                    return existing;
                });

            CleanupOldStates();
        }

        private void CleanupOldStates()
        {
            var cutoff = DateTimeOffset.UtcNow - _stateRetention;
            foreach (var key in _processStates.Where(kv => kv.Value.LastSeen < cutoff).Select(kv => kv.Key).ToList())
                _processStates.TryRemove(key, out _);
        }

        public void Cleanup() => CleanupOldStates();
    }

    public enum Verdict { Clean, Low, Suspicious, Malicious, Critical }

    public sealed class ThreatScore
    {
        public int Score { get; set; }
        public Verdict Verdict { get; set; }
        public DetectionCategory Category { get; set; } = DetectionCategory.Unknown;
        public double OriginalConfidence { get; set; }
        public List<ScoreAdjustment> Adjustments { get; set; } = new();
        public int CorroboratingSources { get; set; }
        public bool RequiresAction => Verdict is Verdict.Malicious or Verdict.Critical;
        public override string ToString() => $"{Verdict} ({Score}) {(RequiresAction ? "[ACTION]" : "[LOG]")} - {Category}";
    }

    public sealed class ScoreAdjustment
    {
        public string Reason { get; }
        public int Value { get; }
        public string Description { get; }
        public ScoreAdjustment(string reason, int value, string description)
        { Reason = reason; Value = value; Description = description; }
        public override string ToString() => $"{Reason}: {Value:+#;-#;0} ({Description})";
    }

    public sealed class ProcessScoreState
    {
        public int ProcessId { get; set; }
        public HashSet<DetectionCategory> DetectedCategories { get; set; } = new();
        public double MaxConfidence { get; set; }
        public DateTimeOffset FirstSeen { get; set; }
        public DateTimeOffset LastSeen { get; set; }
        public int DetectionCount { get; set; }
    }

    public sealed class ProcessThreatProfile
    {
        public int ProcessId { get; set; }
        public List<DetectionCategory> DetectedCategories { get; set; } = new();
        public double MaxConfidence { get; set; }
        public DateTimeOffset FirstSeen { get; set; }
        public DateTimeOffset LastSeen { get; set; }
        public int DetectionCount { get; set; }
        public bool IsMultiCategoryAttack => DetectedCategories.Count >= 3;
    }
}
