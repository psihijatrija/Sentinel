using System;
using System.Net.Http;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
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
    ///   - Mutating requests use deployment-only ReportingProxySharedSecret, distinct
    ///     from the public lookup compatibility credential.
    ///   - Never uses a client-generated key; never sends X-Sentinel-Key.
    ///   - Reporting is skipped (fail closed) when ProxySharedSecret is missing.
    ///   - Replay protection via X-Sentinel-Timestamp + X-Sentinel-Nonce (60s window, v2.0.8).
    ///   - TLS certificate pinning on the proxy HttpClient (v2.0.8).
    ///
    /// If ProxyEndpoint is null or secret is unset, reporting is silently skipped
    /// (lookups still work via HashReputationService / FileReputationEngine when configured).
    /// </summary>
    public class ThreatReportService : IDisposable
    {
        private readonly ThreatReportingConfig _config;
        private readonly ILogger<ThreatReportService> _logger;
        // v2.0.8: pinned TLS for proxy endpoint (same pins as FileReputationEngine VT path)
        private readonly HttpClient _httpClient;
        private readonly bool _ownsClient;
        private volatile EvidenceAnchorStatus? _anchorStatus;
        public EvidenceAnchorStatus AnchorStatus => _anchorStatus ??
            new EvidenceAnchorStatus(EvidenceAnchoringConfigured ? "Pending" : "NotConfigured");

        public ThreatReportService(ThreatReportingConfig config, ILogger<ThreatReportService> logger, SecureCacheStore? cacheStore = null, HttpClient? httpClient = null)
        {
            _config = config;
            _logger = logger;
            _httpClient = httpClient ?? ProxyAuthHelper.CreatePinnedHttpClient(10);
            _ownsClient = httpClient == null;

            if (_config.Enabled && !string.IsNullOrWhiteSpace(_config.ProxyEndpoint) && !EvidenceAnchoringConfigured)
            {
                _logger.LogWarning(
                    "Outbound reports require a separate deployment ReportingProxySharedSecret (>=32 chars) " +
                    "matching Worker SENTINEL_REPORT_SHARED_SECRET; public compatibility credentials authorize lookups only");
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
        /// only content hashes and checkpoint coordinates. A separate deployment credential is
        /// required. A receipt confirms storage, not malware attribution or source-host identity.
        /// </summary>
        public async Task ReportEvidenceAsync(EvidenceSummary summary)
        {
            await TryReportEvidenceAsync(summary, CancellationToken.None).ConfigureAwait(false);
        }

        public bool EvidenceAnchoringConfigured => _config.Enabled && !string.IsNullOrWhiteSpace(_config.ProxyEndpoint) &&
            _config.ReportingProxySharedSecret?.Length >= 32 &&
            _config.ReportingProxySharedSecret != _config.ProxySharedSecret;

        public async Task<bool> TryReportEvidenceAsync(EvidenceSummary summary, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (summary == null || !EvidenceAnchoringConfigured) return false;
            _anchorStatus = new EvidenceAnchorStatus("Failed", DateTimeOffset.UtcNow);
            try
            {
                string reportHash;
                using (var sha = SHA256.Create())
                    reportHash = BitConverter.ToString(sha.ComputeHash(Encoding.UTF8.GetBytes(summary.ReportId)))
                        .Replace("-", "").ToLowerInvariant();
                // Minimize before transmission, not merely before server-side storage.
                var json = JsonSerializer.Serialize(new
                {
                    ReportId = reportHash, summary.ManifestSha256,
                    summary.LedgerFile, summary.LedgerSequence, summary.LedgerHash
                });
                var evidenceConfig = new ThreatReportingConfig
                {
                    ProxyEndpoint = _config.ProxyEndpoint, ProxySharedSecret = _config.ReportingProxySharedSecret
                };
                var (request, error) = ProxyAuthHelper.CreateAuthenticatedPost(
                    _config.ProxyEndpoint!, "/report/evidence", json, evidenceConfig);
                if (request == null)
                {
                    _logger.LogWarning("Evidence anchor skipped: {Reason}", error);
                    return false;
                }
                using (request)
                using (var response = await _httpClient.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, cancellationToken).ConfigureAwait(false))
                {
                    if (!response.IsSuccessStatusCode)
                    {
                        _logger.LogWarning("Evidence anchor failed with HTTP {Status}", (int)response.StatusCode);
                        return false;
                    }
                    using var input = await response.Content.ReadAsStreamAsync().ConfigureAwait(false);
                    using var bounded = new System.IO.MemoryStream();
                    var buffer = new byte[1024];
                    int count;
                    while ((count = await input.ReadAsync(buffer, 0, buffer.Length, cancellationToken).ConfigureAwait(false)) > 0)
                    {
                        if (bounded.Length + count > 4096) return false;
                        bounded.Write(buffer, 0, count);
                    }
                    using var receipt = JsonDocument.Parse(bounded.ToArray());
                    bool accepted = receipt.RootElement.TryGetProperty("success", out var success) && success.ValueKind == JsonValueKind.True &&
                        receipt.RootElement.TryGetProperty("receipt", out var key) && key.ValueKind == JsonValueKind.String &&
                        IsAnchorReceipt(key.GetString());
                    if (accepted) _anchorStatus = new EvidenceAnchorStatus("Confirmed", DateTimeOffset.UtcNow, receipt.RootElement.GetProperty("receipt").GetString());
                    return accepted;
                }
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { throw; }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Evidence anchor was not confirmed; local evidence retained");
                return false;
            }
        }

        private static bool IsAnchorReceipt(string? value) => value != null && value.StartsWith("evidence:v1:", StringComparison.Ordinal) &&
            value.Length == 76 && value.Substring(12).All(Uri.IsHexDigit);

        public void Dispose() { if (_ownsClient) _httpClient.Dispose(); }

        private bool CanReport()
        {
            if (!_config.Enabled) return false;
            if (string.IsNullOrWhiteSpace(_config.ProxyEndpoint)) return false;
            // Public lookup compatibility credentials cannot authorize external reports.
            return EvidenceAnchoringConfigured;
        }

        private async Task SendReportAsync(string path, object payload)
        {
            try
            {
                var json = JsonSerializer.Serialize(payload);
                var (request, error) = ProxyAuthHelper.CreateAuthenticatedPost(
                    _config.ProxyEndpoint!, path, json, new ThreatReportingConfig
                    { ProxyEndpoint = _config.ProxyEndpoint, ProxySharedSecret = _config.ReportingProxySharedSecret });

                if (request == null)
                {
                    _logger.LogDebug("Threat report skipped: {Error}", error);
                    return;
                }

                using (request)
                {
                    using var response = await _httpClient.SendAsync(request);

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

    public sealed class EvidenceAnchorStatus
    {
        public string State { get; }
        public DateTimeOffset? ObservedUtc { get; }
        public string? Receipt { get; }
        public EvidenceAnchorStatus(string state, DateTimeOffset? observedUtc = null, string? receipt = null)
        { State = state; ObservedUtc = observedUtc; Receipt = receipt; }
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
        public string LedgerFile { get; set; } = string.Empty;
        public long LedgerSequence { get; set; }
        public string LedgerHash { get; set; } = string.Empty;
    }
}
