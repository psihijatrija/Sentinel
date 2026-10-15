using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace Sentinel.Core
{
    /// <summary>Allowlisted derived export. Never rewrites or claims to preserve an
    /// original evidence seal. Does not export raw paths, arguments, names or metadata.</summary>
    public sealed class InvestigationExport
    {
        public InvestigationExportReport Redact(IEnumerable<DetectionEvent> detections, bool relativeTime = false)
        {
            if (detections == null) throw new ArgumentNullException(nameof(detections));
            var report = new InvestigationExportReport { RelativeTime = relativeTime };
            if (relativeTime)
                report.PrivacyScope = "Absolute dates removed; timestamps shifted to a synthetic UTC epoch. Retains intervals, categories and decisions. Drops raw identifiers, paths, evidence, arguments and metadata. Timing patterns can still be identifying.";
            var ordered = detections.OrderBy(d => d.Timestamp).ToList();
            if (ordered.Any(d => d.Timestamp.Kind != DateTimeKind.Utc || double.IsNaN(d.Confidence) ||
                double.IsInfinity(d.Confidence) || d.Confidence < 0 || d.Confidence > 1))
                throw new ArgumentException("Export requires UTC timestamps and finite confidence in [0,1].", nameof(detections));
            var origin = ordered.FirstOrDefault()?.Timestamp ?? new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc);
            var epoch = new DateTime(2000, 1, 1, 0, 0, 0, DateTimeKind.Utc);
            using (var sha = SHA256.Create())
                report.SourceSha256 = BitConverter.ToString(sha.ComputeHash(Encoding.UTF8.GetBytes(JsonSerializer.Serialize(ordered))))
                    .Replace("-", "").ToLowerInvariant();
            var processAliases = new Dictionary<int, int>();
            foreach (var detection in ordered)
            {
                if (!processAliases.TryGetValue(detection.ProcessId, out int alias))
                {
                    alias = processAliases.Count + 1;
                    processAliases[detection.ProcessId] = alias;
                }
                report.Events.Add(new RedactedInvestigationEvent
                {
                    Timestamp = relativeTime ? epoch + (detection.Timestamp - origin) : detection.Timestamp, ProcessAlias = alias,
                    Category = WeightedCorrelationEngine.MapWeightCategory(detection),
                    Confidence = detection.Confidence, Tier = detection.Tier.ToString(),
                    SignalType = detection.SignalType.ToString(),
                    RequestedAction = detection.AuthorizedResponse.ToString()
                });
            }
            return report;
        }
    }

    public sealed class InvestigationExportReport
    {
        public int SchemaVersion { get; set; } = 1;
        public bool RelativeTime { get; set; }
        public bool DerivedRedactedCopy { get; set; } = true;
        public string SourceSha256 { get; set; } = "";
        public string SourceHashScope { get; set; } = "Normalized detection objects; not a signature or a hash of non-detection log records";
        public string PrivacyScope { get; set; } = "Retains timestamps, categories and decisions; drops raw identifiers, paths, evidence, arguments and metadata. Review timing sensitivity before sharing.";
        public List<RedactedInvestigationEvent> Events { get; set; } = new();
    }

    public sealed class RedactedInvestigationEvent
    {
        public DateTime Timestamp { get; set; }
        public int ProcessAlias { get; set; }
        public string Category { get; set; } = "";
        public double Confidence { get; set; }
        public string Tier { get; set; } = "";
        public string SignalType { get; set; } = "";
        public string RequestedAction { get; set; } = "";
    }
}
