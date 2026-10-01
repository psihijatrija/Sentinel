using System;
using System.Net.Http;
using System.Text.Json;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;

namespace Sentinel.Core
{
    /// <summary>
    /// Reports detected threats to threat intelligence platforms via the Cloudflare Worker proxy.
    /// The proxy holds API keys server-side so they never appear in the open-source repo.
    ///
    /// SECURITY v1.6.0:
    ///   - All requests HMAC-signed with ThreatReporting:ProxySharedSecret (server-known).
    ///   - Never uses a client-generated key; never sends X-Sentinel-Key.
    ///   - Reporting is skipped (fail closed) when ProxySharedSecret is missing.
    ///   - Replay protection via X-Sentinel-Timestamp + X-Sentinel-Nonce (60s window, v2.0.8).
    ///   - TLS certificate pinning on the proxy HttpClient (v2.0.8).
    ///
    /// If ProxyEndpoint is null or secret is unset, reporting is silently skipped
    /// (lookups still work via HashReputationService / FileReputationEngine when configured).
    /// </summary>
    public class ThreatReportService
    {
        private readonly ThreatReportingConfig _config;
        private readonly ILogger<ThreatReportService> _logger;
        // v2.0.8: pinned TLS for proxy endpoint (same pins as FileReputationEngine VT path)
        private readonly HttpClient _httpClient;

        public ThreatReportService(ThreatReportingConfig config, ILogger<ThreatReportService> logger, SecureCacheStore? cacheStore = null)
        {
            _config = config;
            _logger = logger;
            _httpClient = ProxyAuthHelper.CreatePinnedHttpClient(10);

            if (_config.Enabled && !string.IsNullOrWhiteSpace(_config.ProxyEndpoint) && !ProxyAuthHelper.HasSharedSecret(_config))
            {
                _logger.LogWarning(
                    "ThreatReporting is enabled and ProxyEndpoint is set, but ProxySharedSecret is missing or too short. " +
                    "Outbound reports will be skipped until a secret (>=16 chars) matching the Worker SENTINEL_SHARED_SECRET is configured.");
            }
        }

        public async Task ReportHashAsync(string sha256, string[] tags, string comment)
        {
            if (!CanReport()) return;

            await SendReportAsync("/report/hash", new
            {
                type = "hash",
                value = sha256,
                tags,
                comment
            });
        }

        public async Task ReportUrlAsync(string url, string threat, string[] tags)
        {
            if (!CanReport()) return;

            await SendReportAsync("/report/url", new
            {
                type = "url",
                value = url,
                threat,
                tags
            });
        }

        public async Task ReportIpAsync(string ip, int[] categories, string comment)
        {
            if (!CanReport()) return;

            await SendReportAsync("/report/ip", new
            {
                type = "ip",
                value = ip,
                categories,
                comment
            });
        }

        /// <summary>
        /// B1 (durable evidence survival): mirrors a signed <b>summary</b> of a sealed evidence
        /// pack off-host so a local admin who suppresses Sentinel cannot also erase the proof.
        /// Fails closed exactly like the other report methods (skips silently when reporting is
        /// disabled or the shared secret is missing). Never transmits file contents or secrets -
        /// only the summary, indicators, and the machine-bound manifest hashes as origin proof.
        /// Never throws.
        /// </summary>
        public async Task ReportEvidenceAsync(EvidenceSummary summary)
        {
            if (summary == null) return;
            if (!CanReport()) return;

            await SendReportAsync("/report/evidence", summary);
        }

        private bool CanReport()
        {
            if (!_config.Enabled) return false;
            if (string.IsNullOrWhiteSpace(_config.ProxyEndpoint)) return false;
            // v1.6.0: fail closed without shared secret
            if (!ProxyAuthHelper.HasSharedSecret(_config)) return false;
            return true;
        }

        private async Task SendReportAsync(string path, object payload)
        {
            try
            {
                var json = JsonSerializer.Serialize(payload);
                var (request, error) = ProxyAuthHelper.CreateAuthenticatedPost(
                    _config.ProxyEndpoint!, path, json, _config);

                if (request == null)
                {
                    _logger.LogDebug("Threat report skipped: {Error}", error);
                    return;
                }

                using (request)
                {
                    var response = await _httpClient.SendAsync(request);

                    if (response.IsSuccessStatusCode)
                    {
                        _logger.LogDebug("Threat report submitted: {Path}", path);
                    }
                    else
                    {
                        _logger.LogWarning("Threat report failed ({Status}): {Path}",
                            (int)response.StatusCode, path);
                    }
                }
            }
            catch (Exception ex)
            {
                // Never crash on reporting failure - detection/response is more important
                _logger.LogDebug("Threat report error: {Message}", ex.Message);
            }
        }
    }

    /// <summary>
    /// B1 (durable evidence survival): the minimal, off-host mirror of a sealed evidence pack.
    /// Deliberately contains NO file contents and NO secrets - only detection metadata, extracted
    /// indicators, and the machine-bound manifest hashes (origin proof that verifies on the
    /// original host only; see the pack's VERIFY.txt). Serialized with System.Text.Json.
    /// </summary>
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
    }
}
