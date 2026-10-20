using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Net;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using Sentinel.Core.Ml;

namespace Sentinel.Core
{
    /// <summary>
    /// Monitors DNS queries for beaconing/tunneling behavior.
    /// 
    /// Previously used ETW (Microsoft-Windows-DNS-Client) via TraceEvent.
    /// Now uses Windows DNS Client event log + periodic polling as telemetry source
    /// to avoid embedding TraceEvent's injection API strings in the binary.
    /// 
    /// Detects:
    /// - Rapid query volume to single domains (beaconing/tunneling)
    /// - High-entropy domain names (DGA - domain generation algorithms)
    /// </summary>
    public sealed class DnsQueryMonitor : IMonitor, IDisposable
    {
        public string Name => "DnsQueryMonitor";

        private readonly DetectionEngine _detectionEngine;
        private readonly SentinelConfig _config;
        private readonly ILogger<DnsQueryMonitor> _logger;
        private readonly PersistentConnectionMonitor? _persistentConnMon;
        private readonly ContextBus? _contextBus;
        private readonly TimeSpan _pollInterval;
        private CancellationTokenSource? _cts;
        private Task? _monitorTask;

        private readonly ConcurrentDictionary<string, DomainStats> _domainStats = new(StringComparer.OrdinalIgnoreCase);
        // GorstaksProtection v2.4.0: optional ThreatFox domain IOC feed integration
        private ThreatFoxFeedService? _threatFoxFeed;
        private const int RapidQueryThreshold = 50;
        private const double EntropyThreshold = 4.0;

        private static readonly HashSet<string> TrustedBaseDomains = new(StringComparer.OrdinalIgnoreCase)
        {
            // HARDENING v1.3.0: Drastically reduced trusted domains list.
            // Previously included amazonaws.com, cloudfront.net, akamai.net, azurefd.net -
            // attackers routinely host C2 on these CDN/cloud platforms and subdomains were
            // completely invisible to DGA and rapid-query detection.
            // Now: only Microsoft OS update domains, Sentinel's own API endpoints, and
            // local resolution names are trusted. Everything else gets monitored.
            
            // Windows Update & OS telemetry (required for system stability)
            "windowsupdate.com", "windows.com", "microsoft.com",
            "office.com", "office365.com", "live.com",
            
            // Local resolution
            "wpad", "local", "localhost", "mshome.net",
            
            // Sentinel's own API dependencies (hash reputation lookups)
            "gorstak.eu",
            "circl.lu", "hashlookup.circl.lu",
            "abuse.ch", "mb-api.abuse.ch",
        };

        private static readonly HashSet<string> LocalHostNames = BuildLocalHostNames();

        private static HashSet<string> BuildLocalHostNames()
        {
            var names = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { "localhost", "wpad" };
            try { names.Add(Dns.GetHostName()); } catch { }
            try { names.Add(Environment.MachineName); } catch { }
            return names;
        }

        public DnsQueryMonitor(
            DetectionEngine detectionEngine,
            SentinelConfig config,
            ILogger<DnsQueryMonitor> logger,
            PersistentConnectionMonitor? persistentConnMon = null,
            ContextBus? contextBus = null,
            ThreatFoxFeedService? threatFoxFeed = null)
        {
            _detectionEngine = detectionEngine;
            _config = config;
            _logger = logger;
            _persistentConnMon = persistentConnMon;
            _contextBus = contextBus;
            _threatFoxFeed = threatFoxFeed;
            _pollInterval = TimeSpan.FromSeconds(config.DnsPollIntervalSeconds > 0 ? config.DnsPollIntervalSeconds : 15);
        }

        // The real Windows log/channel name is "Microsoft-Windows-DNS-Client/Operational"
        // (hyphens, owning provider "Microsoft-Windows-DNS-Client"). The previous literal
        // "Microsoft-Windows-DNS Client Events/Operational" does not exist on Windows, so BOTH
        // the read query and the enable attempt silently failed ("channel could not be found")
        // and the monitor was permanently blind. Verified against Get-WinEvent -ListLog.
        private const string DnsChannelName = "Microsoft-Windows-DNS-Client/Operational";

        /// <summary>
        /// Whether enabling the DNS Client Operational analytic channel (a proactive host
        /// mutation - it changes OS event-log configuration) is permitted. Follows the always-on
        /// hardening posture (<see cref="ProductPosture.AllowsProactiveHostLockdown"/>), so a
        /// null/default config still allows it. Exposed for the default-deny seam test required
        /// by docs/constraints.md.
        /// </summary>
        internal static bool MayEnableDnsChannel(SentinelConfig? config) =>
            ProductPosture.AllowsProactiveHostLockdown(config);

        public Task StartAsync(CancellationToken ct)
        {
            EnsureDnsChannelEnabled();
            _cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            _monitorTask = Task.Run(() => PollLoop(_cts.Token), _cts.Token);
            _logger.LogInformation("[{Monitor}] Started (event log polling mode)", Name);
            return Task.CompletedTask;
        }

        /// <summary>
        /// The DNS Client Operational channel is an analytic channel that Windows ships
        /// DISABLED by default. While it is off this monitor has no telemetry and every
        /// DNS-layer detection (DGA, rapid-query, covert mesh, webhook sink) is blind. Sentinel
        /// runs as SYSTEM and legitimately owns this telemetry source, so enable the channel on
        /// start via the managed EventLog configuration API (no wevtutil / shell invocation -
        /// EtwProviderTamperMonitor flags 'wevtutil sl ... enabled:false' and we must not look
        /// like that, nor build shell command strings).
        ///
        /// This is a proactive host mutation, so it is gated on
        /// <see cref="MayEnableDnsChannel"/> (the always-on hardening posture). Best-effort: a
        /// failure degrades to cache-based detection, it never prevents the monitor from running.
        /// </summary>
        private void EnsureDnsChannelEnabled()
        {
            if (!MayEnableDnsChannel(_config))
            {
                _logger.LogInformation(
                    "[{Monitor}] Posture does not permit enabling the '{Channel}' channel; degrading to cache-based DNS detection only",
                    Name, DnsChannelName);
                return;
            }
            try
            {
                using var session = new System.Diagnostics.Eventing.Reader.EventLogSession();
                var cfg = new System.Diagnostics.Eventing.Reader.EventLogConfiguration(DnsChannelName, session);
                if (cfg.IsEnabled)
                {
                    _logger.LogDebug("[{Monitor}] DNS Client Operational channel already enabled", Name);
                    return;
                }
                cfg.IsEnabled = true;
                cfg.SaveChanges();
                _logger.LogInformation(
                    "[{Monitor}] Enabled the '{Channel}' analytic channel (was disabled - DNS-layer detection would otherwise be blind)",
                    Name, DnsChannelName);
            }
            catch (Exception ex)
            {
                // UnauthorizedAccess, EventLogNotFound (stripped image), or provider refusal.
                _logger.LogWarning(ex,
                    "[{Monitor}] Could not enable the '{Channel}' channel; degrading to cache-based DNS detection only",
                    Name, DnsChannelName);
            }
        }

        private async Task PollLoop(CancellationToken ct)
        {
            // Monitor DNS Client event log (Event ID 3006 = DNS query completed)
            long lastRecordId = 0;

            while (!ct.IsCancellationRequested)
            {
                try
                {
                    await Task.Delay(_pollInterval, ct);
                    PruneStats();

                    // Read recent DNS Client Operational log events
                    // HARDENING: Removed time filter (timediff <= 30000). Previously, events older
                    // than 30s were invisible even if lastRecordId hadn't processed them yet.
                    // A fast C2 that resolves a domain between polls could age out before the next
                    // poll cycle. Now we rely solely on lastRecordId for deduplication - this is
                    // correct because the record ID monotonically increases and we never re-process.
                    try
                    {
                        var query = new System.Diagnostics.Eventing.Reader.EventLogQuery(
                            DnsChannelName,
                            System.Diagnostics.Eventing.Reader.PathType.LogName,
                            "*[System[(EventID=3006 or EventID=3008)]]");

                        using var reader = new System.Diagnostics.Eventing.Reader.EventLogReader(query);
                        System.Diagnostics.Eventing.Reader.EventRecord? record;
                        while ((record = reader.ReadEvent()) != null)
                        {
                            using (record)
                            {
                                var recordId = record.RecordId ?? 0;
                                if (recordId <= lastRecordId) continue;
                                lastRecordId = recordId;

                                var domain = record.FormatDescription()?.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries)
                                    .FirstOrDefault()?.Trim() ?? "";
                                if (!string.IsNullOrEmpty(domain))
                                {
                                    ProcessDnsQuery(domain, 0);
                                }
                            }
                        }
                    }
                    catch (Exception ex)
                    {
                        _logger.LogDebug(ex, "[{Monitor}] DNS event log read failed, using cache-based detection only", Name);
                    }
                }
                catch (OperationCanceledException) { break; }
                catch (Exception ex)
                {
                    _logger.LogDebug(ex, "[{Monitor}] Poll error", Name);
                }
            }
        }

        private void ProcessDnsQuery(string domain, int pid)
        {
            if (string.IsNullOrWhiteSpace(domain)) return;
            if (LocalHostNames.Contains(domain)) return;

            var baseDomain = GetBaseDomain(domain);
            if (TrustedBaseDomains.Contains(baseDomain)) return;

            _persistentConnMon?.RecordDnsQuery(pid, domain);
            CovertMeshSightings.NoteDomain(domain);
            CovertWebhookSightings.NoteDomain(domain, pid);

            string processName = ResolveDnsProcessName(pid);

            if (UserlandProtocolHeuristics.IsDedicatedWebhookSink(domain))
            {
                bool attributed = pid > 4;
                _ = _detectionEngine.EmitAsync(new DetectionEvent
                {
                    RuleName = "Covert Webhook: Disposable Sink Lookup",
                    Evidence = $"DNS query for disposable webhook sink '{domain}' PID={pid} process='{processName}'",
                    Reasoning = attributed
                        ? "This PID resolved a disposable webhook sink (webhook.site / interact.sh / ...). Stealer DNS. Kill-grade C2."
                        : "Unattributed DNS for a disposable webhook sink. Observe only until a process PID is known.",
                    Confidence = attributed ? 0.86 : 0.55,
                    Tier = attributed ? DetectionTier.Tier1Behavioral : DetectionTier.Tier2Indicator,
                    AuthorizedResponse = attributed ? ResponseAction.KillProcessTree : ResponseAction.LogOnly,
                    ProcessName = processName,
                    ProcessId = pid,
                    SignalType = attributed ? SignalType.NetworkC2 : SignalType.Generic,
                    Metadata = new Dictionary<string, string>
                    {
                        ["Domain"] = domain,
                        ["Protocol"] = "DNS",
                        ["WeakObserveSeed"] = attributed ? "false" : "true",
                    }
                });
            }

            if (UserlandProtocolHeuristics.IsCovertMeshDomain(domain))
            {
                bool attributed = pid > 4;
                _ = _detectionEngine.EmitAsync(new DetectionEvent
                {
                    RuleName = "Covert Mesh: DERP/tailcat DNS",
                    Evidence = $"DNS query for mesh bootstrap host '{domain}' PID={pid} process='{processName}'",
                    Reasoning = attributed
                        ? "This PID resolved a DERP/tailcat bootstrap host and is not official Tailscale. Kill-grade C2."
                        : "Unattributed DERP/tailcat DNS. Observe only until a process PID is known.",
                    Confidence = attributed ? 0.86 : 0.55,
                    Tier = attributed ? DetectionTier.Tier1Behavioral : DetectionTier.Tier2Indicator,
                    AuthorizedResponse = attributed ? ResponseAction.KillProcessTree : ResponseAction.LogOnly,
                    ProcessName = processName,
                    ProcessId = pid,
                    SignalType = attributed ? SignalType.NetworkC2 : SignalType.Generic,
                    Metadata = new Dictionary<string, string>
                    {
                        ["Domain"] = domain,
                        ["Protocol"] = "DNS",
                        ["WeakObserveSeed"] = attributed ? "false" : "true",
                    }
                });
            }

            // GorstaksProtection v2.4.0: ThreatFox domain IOC check - fast O(1) lookup
            if (_threatFoxFeed != null && _threatFoxFeed.IsMaliciousDomain(domain, out var tfVerdict))
            {
                _ = _detectionEngine.EmitAsync(new DetectionEvent
                {
                    RuleName          = "DNS: ThreatFox Known-Malicious Domain",
                    RuleId            = "SENT-TF-001",
                    Evidence          = $"DNS query for '{domain}' matched ThreatFox IOC " +
                                        $"(malware: {tfVerdict.MalwareFamily ?? "unknown"}, confidence: {tfVerdict.Confidence})",
                    Reasoning         = "The queried domain is listed in the ThreatFox threat intelligence database as a known C2 or malicious domain. " +
                                        "Block or investigate the originating process.",
                    Confidence        = Math.Min(1.0, tfVerdict.Confidence / 100.0),
                    Tier              = DetectionTier.Tier1Behavioral,
                    AuthorizedResponse = ResponseAction.NetworkIsolate,
                    ProcessName       = processName,
                    ProcessId         = pid,
                    Metadata          = new Dictionary<string, string>
                    {
                        { "RuleId",         "SENT-TF-001" },
                        { "Domain",         domain },
                        { "MalwareFamily",  tfVerdict.MalwareFamily ?? "unknown" },
                        { "ThreatFoxConf",  tfVerdict.Confidence.ToString() },
                        { "IocSource",      tfVerdict.Source }
                    }
                });
            }

            var stats = _domainStats.GetOrAdd(baseDomain, _ => new DomainStats());
            stats.QueryCount++;
            stats.LastSeen = DateTime.UtcNow;

            // Rapid query volume detection
            if (stats.QueryCount >= RapidQueryThreshold && !stats.Alerted)
            {
                stats.Alerted = true;
                _ = _detectionEngine.EmitAsync(new DetectionEvent
                {
                    RuleName = "DNS: Rapid Query Volume (Beaconing/Tunneling)",
                    Evidence = $"Base domain '{baseDomain}' received {stats.QueryCount} queries in current window",
                    Reasoning = "An abnormally high volume of DNS queries to a single base domain was detected, consistent with DNS tunneling or C2 beaconing.",
                    Confidence = 0.75,
                    Tier = DetectionTier.Tier1Behavioral,
                    ProcessName = "SYSTEM", ProcessId = pid
                });

                _contextBus?.Publish(new DnsAnomalySignal
                {
                    ProcessId = pid,
                    ProcessName = "SYSTEM",
                    SourceMonitor = "DnsQueryMonitor",
                    Domain = baseDomain,
                    AnomalyType = DnsAnomalyType.RapidQueryVolume,
                    QueryCount = stats.QueryCount
                });
            }

            // DGA detection via entropy
            var labels = domain.Split('.');
            if (labels.Length > 2)
            {
                var subdomain = labels[0];
                if (subdomain.Length > 12 && CalculateEntropy(subdomain) > EntropyThreshold)
                {
                    var entropy = CalculateEntropy(subdomain);
                    _ = _detectionEngine.EmitAsync(new DetectionEvent
                    {
                        RuleName = "DNS: High-Entropy Subdomain (DGA Indicator)",
                        Evidence = $"Domain '{domain}' has high-entropy subdomain (entropy={entropy:F2})",
                        Reasoning = "The queried domain contains a high-entropy subdomain label, consistent with domain generation algorithms used by malware to evade domain blocklists.",
                        Confidence = 0.65,
                        Tier = DetectionTier.Tier2Indicator,
                        ProcessName = "SYSTEM", ProcessId = pid
                    });

                    _contextBus?.Publish(new DnsAnomalySignal
                    {
                        ProcessId = pid,
                        ProcessName = "SYSTEM",
                        SourceMonitor = "DnsQueryMonitor",
                        Domain = domain,
                        AnomalyType = DnsAnomalyType.HighEntropySubdomain,
                        Entropy = entropy
                    });
                }
            }

        }

        private void PruneStats()
        {
            var cutoff = DateTime.UtcNow.AddMinutes(-5);
            foreach (var key in _domainStats.Keys.ToList())
            {
                if (_domainStats.TryGetValue(key, out var stats) && stats.LastSeen < cutoff)
                    _domainStats.TryRemove(key, out _);
            }
        }

        private static double CalculateEntropy(string s)
        {
            var freq = new Dictionary<char, int>();
            foreach (var c in s) { freq[c] = freq.GetValueOrDefault(c) + 1; }
            double entropy = 0;
            foreach (var count in freq.Values)
            {
                double p = (double)count / s.Length;
                entropy -= p * MathNet48.Log2(p);
            }
            return entropy;
        }

        private static string GetBaseDomain(string domain)
        {
            var parts = domain.TrimEnd('.').Split('.');
            return parts.Length >= 2 ? $"{parts[^2]}.{parts[^1]}" : domain;
        }

        /// <summary>
        /// DNS Client event log often has PID 0. When PID is real, resolve the
        /// live name so webhook/mesh/ThreatFox events match other DNS detections.
        /// </summary>
        internal static string ResolveDnsProcessName(int pid)
        {
            if (pid <= 4) return "SYSTEM";
            try
            {
                using var p = Process.GetProcessById(pid);
                var name = p.ProcessName;
                if (!string.IsNullOrWhiteSpace(name))
                    return name;
            }
            catch { /* process already exited */ }
            return "unknown";
        }

        public async Task StopAsync()
        {
            _cts?.Cancel();
            if (_monitorTask != null)
            {
                try
                {
                    await _monitorTask;
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "[{Monitor}] Error awaiting background task shutdown", Name);
                }
            }
            _logger.LogInformation("[{Monitor}] Stopped", Name);
        }

        public void Dispose()
        {
            _cts?.Dispose();
        }

        private class DomainStats
        {
            public int QueryCount;
            public DateTime LastSeen = DateTime.UtcNow;
            public bool Alerted;
        }
    }
}
