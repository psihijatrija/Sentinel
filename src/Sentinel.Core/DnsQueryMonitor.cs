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
    public sealed class DnsQueryMonitor : IMonitor, IDisposable, ISensorProgressSource, IMonitorWorker
    {
        public string Name => "DnsQueryMonitor";
        public SensorProgress Progress { get; }
        public bool IsWorkerRunning => _monitorTask is { IsCompleted: false };
        public long QueriesProcessed => Interlocked.Read(ref _queriesProcessed);
        private long _queriesProcessed;
        private readonly IDnsEventSource _eventSource;

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
            IDnsEventSource eventSource,
            PersistentConnectionMonitor? persistentConnMon = null,
            ContextBus? contextBus = null,
            ThreatFoxFeedService? threatFoxFeed = null)
        {
            _eventSource = eventSource;
            _detectionEngine = detectionEngine;
            _config = config;
            _logger = logger;
            _persistentConnMon = persistentConnMon;
            _contextBus = contextBus;
            _threatFoxFeed = threatFoxFeed;
            _pollInterval = TimeSpan.FromSeconds(config.DnsPollIntervalSeconds > 0 ? config.DnsPollIntervalSeconds : 15);
            Progress = new SensorProgress(TimeSpan.FromSeconds(Math.Max(30, _pollInterval.TotalSeconds * 3)))
                { Scope = "DNS collection reads; Observations counts parsed query-start events, not detections. No cache fallback." };
        }

        internal static bool MayEnableDnsChannel(SentinelConfig? config) =>
            ProductPosture.AllowsProactiveHostLockdown(config);

        public Task StartAsync(CancellationToken ct)
        {
            ct.ThrowIfCancellationRequested();
            _cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            _monitorTask = Task.Run(() => PollLoop(_cts.Token), _cts.Token);
            return Task.CompletedTask;
        }

        private async Task PollLoop(CancellationToken ct)
        {
            bool initialized = false;
            bool warned = false;
            while (!ct.IsCancellationRequested)
            {
                try
                {
                    if (!initialized)
                    {
                        _eventSource.Initialize(MayEnableDnsChannel(_config));
                        initialized = true;
                    }
                    var queries = _eventSource.ReadQueries(ct);
                    if (_eventSource is IDnsEventSourceDiagnostics diagnostics)
                        Progress.Scope = diagnostics.CollectionMode + "; Observations counts parsed query starts; " +
                            diagnostics.DroppedQueries + " real-time queue drops since startup. No cache fallback.";
                    int processed = 0;
                    string? parseError = null;
                    foreach (var query in queries)
                    {
                        if (query.Error != null) { parseError = query.Error; continue; }
                        // Preserve the observe-only boundary for unattributed DNS.
                        ProcessDnsQuery(query.Domain, 0);
                        Interlocked.Increment(ref _queriesProcessed);
                        processed++;
                    }
                    PruneStats();
                    Progress.Succeeded(processed); // Even an empty successful read proves a collection cycle, not test-query arrival.
                    if (_eventSource is IDnsEventSourceDiagnostics loss && loss.LastReadHadLoss)
                    {
                        Progress.Failed($"DNS real-time collection lost queries; {loss.DroppedQueries} drops since startup. Available queries were still processed.");
                        if (!warned) _logger.LogWarning("DNS collection lost queries; available batch was processed, cumulative drops={Drops}", loss.DroppedQueries);
                        warned = true;
                    }
                    else if (parseError != null)
                    {
                        Progress.Failed(parseError);
                        if (!warned) _logger.LogWarning("DNS collection skipped an unsupported query event: {Error}", parseError);
                        warned = true;
                    }
                    else
                    {
                        if (warned) _logger.LogInformation("DNS event reads recovered; processed {Count} queries this cycle", processed);
                        warned = false;
                    }
                }
                catch (OperationCanceledException) when (ct.IsCancellationRequested) { break; }
                catch (Exception ex)
                {
                    Progress.Failed($"DNS event collection unavailable: {ex.GetType().Name}: {ex.Message}. No cache fallback exists.");
                    if (!warned) _logger.LogWarning(ex, "DNS event collection failed; DNS query detection has a coverage gap (no cache fallback)");
                    warned = true;
                    // Retry reads without reinitializing the cursor: replayed queries must not
                    // become fake rapid-query evidence after a transient read failure.
                }
                try { await Task.Delay(_pollInterval, ct).ConfigureAwait(false); }
                catch (OperationCanceledException) when (ct.IsCancellationRequested) { break; }
            }
        }

        private void ProcessDnsQuery(string domain, int pid)
        {
            if (string.IsNullOrWhiteSpace(domain) || domain == ".") return;
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
