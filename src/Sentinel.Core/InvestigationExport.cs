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
        public InvestigationExportReport Redact(IEnumerable<DetectionEvent> detections)
        {
            var report = new InvestigationExportReport();
            var ordered = detections.OrderBy(d => d.Timestamp).ToList();
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
                    Timestamp = detection.Timestamp, ProcessAlias = alias,
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
