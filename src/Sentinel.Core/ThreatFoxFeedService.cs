// ThreatFoxFeedService - ported from GorstaksProtection (ThreatIntelService.cs)
//
// Augments the existing IP-only ThreatIntelFeedBlocker with ThreatFox coverage:
//   - SHA-256 hashes (fed into IoCScanner)
//   - Domain indicators (fed into DnsQueryMonitor via DomainIoCStore)
//   - Malware-family metadata on every indicator
//
// Refreshes from ThreatFox API every 6 hours. On startup loads a bundled offline
// snapshot so detections work from first launch without waiting for live network.
//
// Bundled snapshot path: %ProgramData%\Sentinel\threatfox-bundle.json.gz
// If the file is absent, the service starts empty and relies solely on live feed.

using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Net.Http;
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

        private static readonly TimeSpan RefreshInterval = TimeSpan.FromHours(6);
        private static readonly TimeSpan InitialDelay   = TimeSpan.FromSeconds(60);

        private const string ThreatFoxApiUrl = "https://threatfox-api.abuse.ch/api/v1/";
        private const int    MaxIocsPerRefresh = 5000;

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
            await LoadBundleAsync();
            PropagateHashesToScanner();

            _logger.LogInformation(
                "[ThreatFoxFeedService] Started - {Count} IOCs from bundle. Live refresh in {Delay}s.",
                _store.Count, InitialDelay.TotalSeconds);

            try { await Task.Delay(InitialDelay, ct); }
            catch (OperationCanceledException) { return; }

            while (!ct.IsCancellationRequested)
            {
                await RefreshFromThreatFoxAsync(ct);

                try { await Task.Delay(RefreshInterval, ct); }
                catch (OperationCanceledException) { break; }
            }
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

        private async Task RefreshFromThreatFoxAsync(CancellationToken ct)
        {
            _logger.LogInformation("[ThreatFoxFeedService] Refreshing from ThreatFox API...");

            try
            {
                using var http = new HttpClient { Timeout = TimeSpan.FromSeconds(30) };
                http.DefaultRequestHeaders.UserAgent.ParseAdd("Sentinel-EDR/2.4 (ThreatFoxFeedService)");

                var requestBody = JsonSerializer.Serialize(new { query = "get_iocs", days = 7 });
                using var content = new StringContent(requestBody, Encoding.UTF8, "application/json");
                using var response = await http.PostAsync(ThreatFoxApiUrl, content, ct);

                if (!response.IsSuccessStatusCode)
                {
                    _logger.LogWarning(
                        "[ThreatFoxFeedService] ThreatFox returned HTTP {Status} - keeping existing store.",
                        (int)response.StatusCode);
                    return;
                }

                var json = await response.Content.ReadAsStringAsync();
                using var doc = JsonDocument.Parse(json);

                if (!doc.RootElement.TryGetProperty("data", out var data))
                {
                    _logger.LogWarning("[ThreatFoxFeedService] ThreatFox response missing 'data' field.");
                    return;
                }

                int added = 0;
                foreach (var item in data.EnumerateArray())
                {
                    if (added >= MaxIocsPerRefresh) break;

                    string? iocValue    = null;
                    string? iocType     = null;
                    string? malware     = null;
                    int     confidence  = 75;

                    if (item.TryGetProperty("ioc",              out var iocProp))   iocValue   = iocProp.GetString();
                    if (item.TryGetProperty("ioc_type",         out var typeProp))  iocType    = typeProp.GetString();
                    if (item.TryGetProperty("malware",          out var mwProp))    malware    = mwProp.GetString();
                    if (item.TryGetProperty("confidence_level", out var confProp))  confidence = confProp.GetInt32();

                    if (string.IsNullOrWhiteSpace(iocValue)) continue;

                    var ioc = new ThreatFoxIoc
                    {
                        Indicator     = iocValue!,
                        IocType       = iocType ?? "unknown",
                        MalwareFamily = malware,
                        Confidence    = Math.Min(100, Math.Max(0, confidence)),
                        Source        = "ThreatFox"
                    };

                    IngestIoc(ioc, "ThreatFox");
                    added++;
                }

                IsLiveFeedActive = true;
                LastRefreshed    = DateTimeOffset.UtcNow;

                PropagateHashesToScanner();

                _logger.LogInformation(
                    "[ThreatFoxFeedService] Refresh complete - added/updated {Added} IOCs. Total: {Total}.",
                    added, _store.Count);

                await _eventLogger.LogEventAsync("threatfox_feed_refresh", new
                {
                    Added     = added,
                    Total     = _store.Count,
                    Domains   = _domainStore.Count,
                    Timestamp = DateTime.UtcNow
                });
            }
            catch (OperationCanceledException) { /* normal shutdown */ }
            catch (Exception ex)
            {
                IsLiveFeedActive = false;
                _logger.LogWarning(ex,
                    "[ThreatFoxFeedService] Live refresh failed - continuing with {Count} cached IOCs.",
                    _store.Count);
            }
        }

        //  Helpers 

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
