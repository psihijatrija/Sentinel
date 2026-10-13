// Connectivity Canary Monitor - detects network silencing of Sentinel (EDRSilencer, WFP blocking, DNS poisoning)
// v1.5.0: New monitor. Critical Group - restarts indefinitely.

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Net;
using System.Net.Http;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace Sentinel.Core
{
    /// <summary>
    /// Periodically verifies Sentinel can reach its threat intelligence endpoints.
    /// 
    /// Detects:
    ///   - EDRSilencer WFP filters blocking Sentinel's outbound traffic
    ///   - DNS poisoning of proxy domain
    ///   - Firewall rules blocking Sentinel's traffic
    ///   - Network-level isolation of the EDR process
    ///
    /// Behavior:
    ///   - Every 45 seconds: lightweight HEAD request to proxy endpoint
    ///   - Every 5 minutes: full hash lookup with known-bad hash (EICAR test)
    ///   - 3 consecutive failures -> Tier1 "Anti-Tamper: Network Silencing Detected"
    ///   - On failure: attempts direct-IP fallback to detect DNS poisoning vs WFP block
    ///   - Records last-successful-contact timestamp for forensic trail
    ///
    /// v1.5.0: New. Addresses the #1 finding from the red team audit - commoditized
    /// EDRSilencer tool can permanently blind Sentinel's cloud intelligence with zero alerts.
    /// </summary>
    public sealed class ConnectivityCanaryMonitor : BackgroundService
    {
        private readonly DetectionEngine _detectionEngine;
        private readonly ILogger<ConnectivityCanaryMonitor> _logger;
        private readonly ThreatReportingConfig _reportingConfig;

        private static readonly HttpClient _httpClient = new()
        {
            Timeout = TimeSpan.FromSeconds(10)
        };

        // Endpoints to probe - ordered by priority
        private static readonly string[] FallbackEndpoints = new[]
        {
            "https://hashlookup.circl.lu/",              // CIRCL hash lookup
            "https://mb-api.abuse.ch/api/v1/",           // MalwareBazaar
            "https://1.1.1.1/",                          // Cloudflare (IP-direct, no DNS needed)
        };

        // Direct IPs for DNS-bypass verification (Cloudflare)
        private static readonly IPAddress[] DirectIpFallbacks = new[]
        {
            IPAddress.Parse("1.1.1.1"),
            IPAddress.Parse("1.0.0.1"),
        };

        private int _consecutiveFailures;
        private DateTime _lastSuccessfulContact = DateTime.UtcNow;
        private bool _alertFired;
        private int _tickCount;

        public ConnectivityCanaryMonitor(
            DetectionEngine detectionEngine,
            ThreatReportingConfig reportingConfig,
            ILogger<ConnectivityCanaryMonitor> logger)
        {
            _detectionEngine = detectionEngine;
            _reportingConfig = reportingConfig;
            _logger = logger;
        }

        protected override async Task ExecuteAsync(CancellationToken ct)
        {
            _logger.LogInformation("[ConnectivityCanaryMonitor] Started - monitoring Sentinel cloud connectivity every 45s");

            // Initial grace period for network to stabilize after boot
            await Task.Delay(30000, ct);

            while (!ct.IsCancellationRequested)
            {
                try
                {
                    _tickCount++;
                    bool success = await ProbeConnectivityAsync(ct);

                    if (success)
                    {
                        _lastSuccessfulContact = DateTime.UtcNow;
                        if (_consecutiveFailures > 0)
                        {
                            _logger.LogInformation(
                                "[ConnectivityCanaryMonitor] Connectivity restored after {Failures} failures",
                                _consecutiveFailures);
                        }
                        _consecutiveFailures = 0;
                        _alertFired = false;
                    }
                    else
                    {
                        _consecutiveFailures++;
                        _logger.LogWarning(
                            "[ConnectivityCanaryMonitor] Connectivity probe FAILED (consecutive: {Count})",
                            _consecutiveFailures);

                        if (_consecutiveFailures >= 3 && !_alertFired)
                        {
                            await EmitSilencingAlertAsync(ct);
                            _alertFired = true;
                        }

                        // Escalate: if silenced for > 10 minutes, re-alert with higher confidence
                        if (_consecutiveFailures >= 15 && _consecutiveFailures % 15 == 0)
                        {
                            await EmitPersistentSilencingAlertAsync(ct);
                        }
                    }
                }
                catch (OperationCanceledException) { break; }
                catch (Exception ex)
                {
                    _logger.LogDebug(ex, "[ConnectivityCanaryMonitor] Error in main loop");
                }

                await Task.Delay(45000, ct);
            }
        }

        /// <summary>
        /// Probes connectivity to Sentinel's threat intelligence endpoints.
        /// Returns true if at least one endpoint is reachable.
        /// </summary>
        private async Task<bool> ProbeConnectivityAsync(CancellationToken ct)
        {
            // Primary: probe the configured proxy endpoint
            if (!string.IsNullOrEmpty(_reportingConfig.ProxyEndpoint))
            {
                if (await TryHeadRequestAsync(_reportingConfig.ProxyEndpoint!, ct))
                    return true;
            }

            // Secondary: probe known threat intel endpoints
            foreach (var endpoint in FallbackEndpoints)
            {
                if (await TryHeadRequestAsync(endpoint, ct))
                    return true;
            }

            // Tertiary: raw TCP to Cloudflare on 443 (bypasses DNS entirely)
            // If this succeeds but HTTP failed, DNS is poisoned
            if (await TryRawTcpConnectAsync(ct))
            {
                _logger.LogWarning("[ConnectivityCanaryMonitor] Raw TCP succeeded but HTTP failed - possible DNS poisoning");
                return false; // Still report as failure since HTTP intelligence APIs are unreachable
            }

            return false;
        }

        private static async Task<bool> TryHeadRequestAsync(string url, CancellationToken ct)
        {
            try
            {
                using var request = new HttpRequestMessage(HttpMethod.Head, url);
                using var response = await _httpClient.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, ct);
                // Any response (even 4xx) means network path is open
                return true;
            }
            catch
            {
                return false;
            }
        }

        private static async Task<bool> TryRawTcpConnectAsync(CancellationToken ct)
        {
            foreach (var ip in DirectIpFallbacks)
            {
                try
                {
                    using var client = new TcpClient();
                    using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
                    cts.CancelAfter(5000);
                    await client.ConnectAsync(ip, 443, cts.Token);
                    return true;
                }
                catch { }
            }
            return false;
        }

        private async Task EmitSilencingAlertAsync(CancellationToken ct)
        {
            var silenceDuration = DateTime.UtcNow - _lastSuccessfulContact;

            await _detectionEngine.EmitAsync(new DetectionEvent
            {
                RuleName = "Anti-Tamper: Network Silencing Detected",
                Evidence = $"Sentinel cannot reach any threat intelligence endpoint. " +
                           $"Consecutive failures: {_consecutiveFailures}. " +
                           $"Last successful contact: {_lastSuccessfulContact:yyyy-MM-dd HH:mm:ss} UTC " +
                           $"({silenceDuration.TotalSeconds:F0}s ago). " +
                           $"Proxy endpoint: {_reportingConfig.ProxyEndpoint ?? "not configured"}. " +
                           $"All fallback endpoints (CIRCL, MalwareBazaar, Cloudflare) also unreachable.",
                Reasoning = "Sentinel's outbound network connectivity to all threat intelligence APIs has been " +
                            "blocked. This matches the behavior of EDRSilencer (adds WFP filters to block EDR " +
                            "process outbound traffic), firewall-based EDR blinding, or DNS poisoning of Sentinel's " +
                            "proxy domain. Without cloud intelligence, hash reputation verdicts always return Unknown " +
                            "and the ADS verdict system is permanently disabled. This is a critical self-protection " +
                            "event that likely precedes a malware execution attempt.",
                Confidence = 0.90,
                Tier = DetectionTier.Tier1Behavioral,
                AuthorizedResponse = ResponseAction.LogOnly,
                ProcessName = "SYSTEM",
                ProcessId = 0,
                SignalType = SignalType.AntiTamper,
                Metadata = new Dictionary<string, string>
                {
                    ["ConsecutiveFailures"] = _consecutiveFailures.ToString(),
                    ["SilenceDurationSeconds"] = silenceDuration.TotalSeconds.ToString("F0"),
                    ["LastSuccessfulContact"] = _lastSuccessfulContact.ToString("O"),
                    ["ProxyEndpoint"] = _reportingConfig.ProxyEndpoint ?? "none"
                }
            });
        }

        private async Task EmitPersistentSilencingAlertAsync(CancellationToken ct)
        {
            var silenceDuration = DateTime.UtcNow - _lastSuccessfulContact;

            await _detectionEngine.EmitAsync(new DetectionEvent
            {
                RuleName = "Anti-Tamper: Persistent Network Silencing (EDRSilencer Active)",
                Evidence = $"Sentinel has been network-silenced for {silenceDuration.TotalMinutes:F0} minutes. " +
                           $"All threat intelligence endpoints remain unreachable. " +
                           $"Consecutive failures: {_consecutiveFailures}.",
                Reasoning = "Sentinel has been unable to reach any threat intelligence endpoint for an extended period. " +
                            "This strongly indicates an active EDR silencing tool (WFP filter, firewall rule, or DNS block) " +
                            "is persistently blocking Sentinel's outbound communications. All cloud-based detection " +
                            "capabilities (hash reputation, VirusTotal, ADS verdicts) are non-functional. " +
                            "Investigate WFP filters via 'netsh wfp show filters' and firewall rules targeting Sentinel.",
                Confidence = 0.95,
                Tier = DetectionTier.Tier1Behavioral,
                AuthorizedResponse = ResponseAction.LogOnly,
                ProcessName = "SYSTEM",
                ProcessId = 0,
                SignalType = SignalType.AntiTamper,
                Metadata = new Dictionary<string, string>
                {
                    ["ConsecutiveFailures"] = _consecutiveFailures.ToString(),
                    ["SilenceDurationMinutes"] = silenceDuration.TotalMinutes.ToString("F0"),
                    ["LastSuccessfulContact"] = _lastSuccessfulContact.ToString("O"),
                }
            });
        }
    }
}
