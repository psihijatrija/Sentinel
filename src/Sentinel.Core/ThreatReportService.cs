using System;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;

namespace Sentinel.Core
{
    /// <summary>Offline compatibility facade. Evidence remains on this device; nothing is transmitted.</summary>
    public class ThreatReportService
    {
        public ThreatReportService(ThreatReportingConfig config, ILogger<ThreatReportService> logger,
            SecureCacheStore? cacheStore = null) { }
        public Task ReportHashAsync(string sha256, string[] tags, string comment) => Task.CompletedTask;
        public Task ReportUrlAsync(string url, string threat, string[] tags) => Task.CompletedTask;
        public Task ReportIpAsync(string ip, int[] categories, string comment) => Task.CompletedTask;
        public Task ReportEvidenceAsync(EvidenceSummary summary) => Task.CompletedTask;
    }

    public sealed class EvidenceSummary
    {
        public string ReportId { get; set; } = string.Empty;
        public string SentinelVersion { get; set; } = string.Empty;
        public string Host { get; set; } = string.Empty;
        public string SealedUtc { get; set; } = string.Empty;

        public string Rule { get; set; } = string.Empty;
        public string SignalType { get; set; } = string.Empty;
        public string Tier { get; set; } = string.Empty;
        public double Confidence { get; set; }
        public string ProcessName { get; set; } = string.Empty;
        public int ProcessId { get; set; }

        public string[] Hashes { get; set; } = Array.Empty<string>();
        public string[] Ips { get; set; } = Array.Empty<string>();
        public string[] Urls { get; set; } = Array.Empty<string>();

        /// <summary>SHA-256 of the sealed MANIFEST.sha256 bytes (content integrity).</summary>
        public string ManifestSha256 { get; set; } = string.Empty;

        /// <summary>Machine-bound HMAC of the manifest - origin proof, verifies on the source host.</summary>
        public string ManifestHmacSha256 { get; set; } = string.Empty;
        public string LedgerFile { get; set; } = string.Empty;
        public long LedgerSequence { get; set; }
        public string LedgerHash { get; set; } = string.Empty;
    }
}
