// ThreatFoxFeedService - ported from GorstaksProtection (ThreatIntelService.cs)
//
// Augments the existing IP-only ThreatIntelFeedBlocker with ThreatFox coverage:
//   - SHA-256 hashes (fed into IoCScanner)
//   - Domain indicators (fed into DnsQueryMonitor via DomainIoCStore)
//   - Malware-family metadata on every indicator
//
// Loads a local snapshot only; there is no API refresh or download fallback.
// Snapshot path: %ProgramData%\Sentinel\threatfox-bundle.json.gz.
// A missing snapshot means no bundled IOC coverage, not a clean verdict.

using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace Sentinel.Core
{
    /// <summary>Verdict returned for any indicator queried against the ThreatFox store.</summary>
    public sealed class ThreatFoxVerdict
    {
        public string Indicator { get; init; } = string.Empty;
        public bool IsKnownMalicious { get; init; }
        public int Confidence { get; init; }
        public string? MalwareFamily { get; init; }
        public string? IocType { get; init; }
        public string Source { get; init; } = string.Empty;

        public static ThreatFoxVerdict Clean(string indicator) => new()
        {
            Indicator = indicator,
            IsKnownMalicious = false,
            Source = "NotFound"
        };
    }

    /// <summary>Internal IOC record held in the in-memory store.</summary>
    internal sealed class ThreatFoxIoc
    {
        public string Indicator { get; set; } = string.Empty;
        public string IocType { get; set; } = "unknown";
        public string? MalwareFamily { get; set; }
        public int Confidence { get; set; } = 75;
        public string Source { get; set; } = "BundledBaseline";
    }

    /// <summary>
    /// Background service: loads bundled IOC snapshot on start, then refreshes every 6 hours
    /// from the ThreatFox API (abuse.ch). Covers SHA-256 hashes, IPs, and domain indicators.
    /// Thread-safe for concurrent Query calls from DetectionEngine rules.
    /// </summary>
    public sealed class ThreatFoxFeedService : BackgroundService
    {
        private readonly IoCScanner _iocScanner;
        private readonly ILogger<ThreatFoxFeedService> _logger;
        private readonly JsonlEventLogger _eventLogger;

        // Unified IOC store: normalised indicator -> metadata
        private readonly ConcurrentDictionary<string, ThreatFoxIoc> _store =
            new(StringComparer.OrdinalIgnoreCase);

        // Domain-specific index for fast O(1) lookup from DnsQueryMonitor
        private readonly ConcurrentDictionary<string, ThreatFoxIoc> _domainStore =
            new(StringComparer.OrdinalIgnoreCase);

        public int LoadedIocCount      => _store.Count;
        public bool IsLiveFeedActive   { get; private set; }
        public DateTimeOffset? LastRefreshed { get; private set; }

        private static string BundlePath =>
            Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
                "Sentinel", "threatfox-bundle.json.gz");

        public ThreatFoxFeedService(
            IoCScanner iocScanner,
            JsonlEventLogger eventLogger,
            ILogger<ThreatFoxFeedService> logger)
        {
            _iocScanner   = iocScanner;
            _eventLogger  = eventLogger;
            _logger       = logger;
        }

        protected override async Task ExecuteAsync(CancellationToken ct)
        {
            ct.ThrowIfCancellationRequested();
            await LoadBundleAsync();
            PropagateHashesToScanner();
            _logger.LogInformation("[ThreatFoxFeedService] Offline bundle loaded: {Count} IOCs; no live refresh", _store.Count);
        }

        //  Public API 

        /// <summary>Query any indicator (hash, IP, domain) against the store.</summary>
        public ThreatFoxVerdict Query(string indicator)
        {
            if (string.IsNullOrWhiteSpace(indicator))
                return ThreatFoxVerdict.Clean(string.Empty);

            var key = Normalise(indicator);
            if (_store.TryGetValue(key, out var ioc))
            {
                return new ThreatFoxVerdict
                {
                    Indicator      = indicator,
                    IsKnownMalicious = true,
                    Confidence     = ioc.Confidence,
                    MalwareFamily  = ioc.MalwareFamily,
                    IocType        = ioc.IocType,
                    Source         = ioc.Source
                };
            }
            return ThreatFoxVerdict.Clean(indicator);
        }

        /// <summary>Fast domain-specific query used by DnsQueryMonitor.</summary>
        public bool IsMaliciousDomain(string domain, out ThreatFoxVerdict verdict)
        {
            if (_domainStore.TryGetValue(Normalise(domain), out var ioc))
            {
                verdict = new ThreatFoxVerdict
                {
                    Indicator      = domain,
                    IsKnownMalicious = true,
                    Confidence     = ioc.Confidence,
                    MalwareFamily  = ioc.MalwareFamily,
                    IocType        = "domain",
                    Source         = ioc.Source
                };
                return true;
            }
            verdict = ThreatFoxVerdict.Clean(domain);
            return false;
        }

        //  Bundle loading 

        private async Task LoadBundleAsync()
        {
            if (!File.Exists(BundlePath))
            {
                _logger.LogInformation(
                    "[ThreatFoxFeedService] No offline bundle at {Path} - starting empty until live refresh.",
                    BundlePath);
                return;
            }

            try
            {
                using var fs = File.OpenRead(BundlePath);
                using var gz = new GZipStream(fs, CompressionMode.Decompress);

                var iocs = await JsonSerializer.DeserializeAsync<List<ThreatFoxIoc>>(gz,
                    new JsonSerializerOptions { PropertyNameCaseInsensitive = true });

                if (iocs == null || iocs.Count == 0)
                {
                    _logger.LogWarning("[ThreatFoxFeedService] Bundle at {Path} was empty.", BundlePath);
                    return;
                }

                foreach (var ioc in iocs)
                    IngestIoc(ioc, "Bundle");

                _logger.LogInformation(
                    "[ThreatFoxFeedService] Loaded {Count} IOCs from bundle.", _store.Count);
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "[ThreatFoxFeedService] Failed to load bundle - live refresh will seed the store.");
            }
        }

        //  Live feed refresh 

        private void IngestIoc(ThreatFoxIoc ioc, string source)
        {
            if (string.IsNullOrWhiteSpace(ioc.Indicator)) return;

            ioc.Source = source;
            var key = Normalise(ioc.Indicator);
            _store[key] = ioc;

            // Mirror domain-class IOCs into the fast domain index
            if (ioc.IocType == "domain" || ioc.IocType == "url" ||
                (!ioc.Indicator.Contains('/') && ioc.Indicator.Contains('.')))
            {
                _domainStore[key] = ioc;
            }
        }

        /// <summary>Push all SHA-256 hash IOCs from the store into IoCScanner.</summary>
        private void PropagateHashesToScanner()
        {
            var hashes = new List<string>();
            foreach (var kv in _store)
            {
                // SHA-256 hex strings are exactly 64 chars, all hex digits
                if (kv.Key.Length == 64 && IsHexString(kv.Key))
                    hashes.Add(kv.Key);
            }

            if (hashes.Count > 0)
                _iocScanner.AddHashes(hashes);
        }

        private static bool IsHexString(string s)
        {
            foreach (var c in s)
                if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')))
                    return false;
            return true;
        }

        private static string Normalise(string indicator)
            => indicator.Trim().ToLowerInvariant();
    }
}
