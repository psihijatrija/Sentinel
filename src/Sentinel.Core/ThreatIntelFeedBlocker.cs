// ThreatIntelFeedBlocker - Threat intelligence feed observation + optional proactive block
//
// Default (v1.8.3+): OBSERVE ONLY
//   - Loads Spamhaus DROP, Feodo Tracker, EmergingThreats into memory
//   - Watches established TCP connections against the list
//   - Emits detections on hits; NetworkIsolate only when ActiveResponse is on
//   - Does NOT pre-install thousands of firewall rules (that meddles with legitimate traffic)
//
// Optional: Sentinel:ThreatIntelProactiveFirewall=true re-enables legacy pre-block mode
// for high-security air-gapped style deployments that accept collateral risk.

using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace Sentinel.Core
{
    public sealed class ThreatIntelFeedBlocker : BackgroundService
    {
        private readonly DetectionEngine _detectionEngine;
        private readonly JsonlEventLogger _eventLogger;
        private readonly SentinelConfig _config;
        private readonly ILogger<ThreatIntelFeedBlocker> _logger;

        // All IPs/CIDRs loaded from feeds - used for connection checking
        private readonly ConcurrentDictionary<string, string> _blockedIps = new(StringComparer.OrdinalIgnoreCase);

        // Track which IPs already have firewall rules (proactive mode only)
        private readonly HashSet<string> _rulesCreated = new(StringComparer.OrdinalIgnoreCase);

        // Dedup alerts (don't spam detection engine for the same IP)
        private readonly ConcurrentDictionary<string, DateTime> _alertedConnections = new();

        private static readonly TimeSpan InitialDelay = TimeSpan.FromSeconds(45);
        private static readonly TimeSpan RefreshInterval = TimeSpan.FromHours(4);
        private static readonly TimeSpan ConnectionCheckInterval = TimeSpan.FromSeconds(30);
        private static readonly TimeSpan AlertCooldown = TimeSpan.FromMinutes(10);

        private static readonly (string Url, string Name)[] Feeds = new[]
        {
            ("https://www.spamhaus.org/drop/drop.txt", "Spamhaus-DROP"),
            ("https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.txt", "Feodo-Tracker"),
            ("https://rules.emergingthreats.net/fwrules/emerging-Block-IPs.txt", "EmergingThreats"),
        };

        // Windows Firewall COM constants
        private const int NET_FW_RULE_DIR_IN = 1;
        private const int NET_FW_RULE_DIR_OUT = 2;
        private const int NET_FW_ACTION_BLOCK = 0;
        private const int ALL_PROFILES = 0x7FFFFFFF;

        // Max IPs to track per feed (prevent memory exhaustion)
        private const int MaxIpsPerFeed = 2000;
        private const int MaxTotalRules = 5000;

        // Minimum CIDR prefix length - /8-/15 ranges are far too broad and hit legitimate CDNs/OCSP
        private const int MinCidrPrefix = 16;

        private const string RuleNamePrefix = "Sentinel-ThreatIntel-";

        public ThreatIntelFeedBlocker(
            DetectionEngine detectionEngine,
            JsonlEventLogger eventLogger,
            SentinelConfig config,
            ILogger<ThreatIntelFeedBlocker> logger)
        {
            _detectionEngine = detectionEngine;
            _eventLogger = eventLogger;
            _config = config;
            _logger = logger;
        }

        protected override async Task ExecuteAsync(CancellationToken ct)
        {
            bool proactive = _config.ThreatIntelProactiveFirewall && _config.ActiveResponse;
            _logger.LogInformation(
                "[ThreatIntelFeedBlocker] Starting - mode={Mode} (ProactiveFirewall={Proactive}, ActiveResponse={AR}), initial delay {Delay}s",
                proactive ? "PROACTIVE-FIREWALL" : "OBSERVE-ONLY",
                _config.ThreatIntelProactiveFirewall,
                _config.ActiveResponse,
                InitialDelay.TotalSeconds);

            // Always scrub leftover proactive rules when not in proactive mode so
            // upgrades leave the host without thousands of residual block rules.
            if (!proactive)
            {
                try
                {
                    int removed = RemoveProactiveFirewallRules();
                    if (removed > 0)
                    {
                        _logger.LogWarning(
                            "[ThreatIntelFeedBlocker] Removed {Count} leftover proactive ThreatIntel firewall rules (observe-only mode)",
                            removed);
                        await _eventLogger.LogEventAsync("threat_intel_firewall_cleanup", new
                        {
                            RulesRemoved = removed,
                            Mode = "observe-only",
                            Timestamp = DateTime.UtcNow
                        });
                    }
                }
                catch (Exception ex)
                {
                    _logger.LogWarning(ex, "[ThreatIntelFeedBlocker] Failed to clean leftover ThreatIntel firewall rules");
                }
            }

            try { await Task.Delay(InitialDelay, ct); }
            catch (OperationCanceledException) { return; }

            while (!ct.IsCancellationRequested)
            {
                try
                {
                    await RefreshFeedsAsync(ct);
                }
                catch (OperationCanceledException) { break; }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "[ThreatIntelFeedBlocker] Feed refresh failed");
                }

                // Between refreshes, periodically check active connections against blocklist
                var nextRefresh = DateTime.UtcNow.Add(RefreshInterval);
                while (DateTime.UtcNow < nextRefresh && !ct.IsCancellationRequested)
                {
                    try
                    {
                        CheckActiveConnections();
                        PruneAlertCache();
                    }
                    catch (Exception ex)
                    {
                        _logger.LogDebug(ex, "[ThreatIntelFeedBlocker] Connection check error");
                    }

                    try { await Task.Delay(ConnectionCheckInterval, ct); }
                    catch (OperationCanceledException) { break; }
                }
            }
        }

        private async Task RefreshFeedsAsync(CancellationToken ct)
        {
            _logger.LogInformation("[ThreatIntelFeedBlocker] Refreshing threat intelligence feeds...");

            using var http = new HttpClient { Timeout = TimeSpan.FromSeconds(30) };
            http.DefaultRequestHeaders.UserAgent.ParseAdd("Sentinel-EDR/1.8 (ThreatIntelFeedBlocker)");

            int totalNewIps = 0;

            foreach (var (url, name) in Feeds)
            {
                if (ct.IsCancellationRequested) break;

                try
                {
                    var response = await http.GetStringAsync(url, ct);
                    var ips = ParseFeed(response, name);

                    int added = 0;
                    foreach (var ip in ips.Take(MaxIpsPerFeed))
                    {
                        if (_blockedIps.TryAdd(ip, name))
                        {
                            added++;
                        }
                    }

                    if (added > 0)
                    {
                        _logger.LogInformation("[ThreatIntelFeedBlocker] {Feed}: added {Count} new IPs/CIDRs", name, added);
                        totalNewIps += added;
                    }
                }
                catch (Exception ex)
                {
                    _logger.LogWarning("[ThreatIntelFeedBlocker] Failed to fetch {Feed}: {Error}", name, ex.Message);
                }
            }

            bool proactive = _config.ThreatIntelProactiveFirewall && _config.ActiveResponse;

            // Create firewall rules for new IPs ONLY in explicit proactive mode
            if (proactive && totalNewIps > 0)
            {
                CreateFirewallRules();

                await _eventLogger.LogEventAsync("threat_intel_feed_refresh", new
                {
                    TotalBlockedIps = _blockedIps.Count,
                    NewIpsAdded = totalNewIps,
                    FirewallRulesCreated = _rulesCreated.Count,
                    Mode = "proactive",
                    Timestamp = DateTime.UtcNow
                });
            }
            else if (totalNewIps > 0)
            {
                await _eventLogger.LogEventAsync("threat_intel_feed_refresh", new
                {
                    TotalBlockedIps = _blockedIps.Count,
                    NewIpsAdded = totalNewIps,
                    FirewallRulesCreated = 0,
                    Mode = "observe-only",
                    Timestamp = DateTime.UtcNow
                });
            }

            _logger.LogInformation(
                "[ThreatIntelFeedBlocker] Feed refresh complete - {Total} IPs/CIDRs tracked, proactiveRules={Rules}, mode={Mode}",
                _blockedIps.Count, _rulesCreated.Count, proactive ? "proactive" : "observe-only");
        }

        /// <summary>Parse a threat-intel feed body. Internal for unit tests.</summary>
        internal static List<string> ParseFeed(string content, string feedName)
        {
            var results = new List<string>();

            foreach (var rawLine in content.Split('\n'))
            {
                var line = rawLine.Trim();

                // Skip comments and empty lines
                if (string.IsNullOrEmpty(line) || line[0] == '#' || line[0] == ';')
                    continue;

                // Spamhaus DROP format: "x.x.x.x/xx ; SBnnnnn"
                if (feedName.Contains("Spamhaus"))
                {
                    var parts = line.Split(';');
                    var ipPart = parts[0].Trim();
                    if (IsValidIpOrCidr(ipPart))
                        results.Add(ipPart);
                    continue;
                }

                // Feodo/ET format: one IP per line (may have trailing comments)
                var ipCandidate = line.Split(new[] { ' ', '\t', ';', '#' }, 2)[0].Trim();
                if (IsValidIpOrCidr(ipCandidate))
                    results.Add(ipCandidate);
            }

            return results;
        }

        /// <summary>
        /// Validate dotted-quad IPv4 or CIDR. Prefix must be /16-/32 (reject /0-/15 - too broad).
        /// Internal for unit tests.
        /// </summary>
        internal static bool IsValidIpOrCidr(string value)
        {
            if (string.IsNullOrWhiteSpace(value)) return false;

            // CIDR notation: x.x.x.x/nn
            if (value.IndexOf('/') >= 0)
            {
                var parts = value.Split('/');
                if (parts.Length != 2) return false;
                if (!IsDottedQuadIPv4(parts[0])) return false;
                if (!int.TryParse(parts[1], out int prefix)) return false;
                return prefix >= MinCidrPrefix && prefix <= 32;
            }

            return IsDottedQuadIPv4(value);
        }

        /// <summary>
        /// Require strict a.b.c.d form. IPAddress.TryParse accepts incomplete forms like "1.2.3".
        /// </summary>
        private static bool IsDottedQuadIPv4(string value)
        {
            var octets = value.Split('.');
            if (octets.Length != 4) return false;
            foreach (var o in octets)
            {
                if (!int.TryParse(o, out int n) || n < 0 || n > 255) return false;
                // Reject leading zeros like "01" (except single "0")
                if (o.Length > 1 && o[0] == '0') return false;
            }
            return IPAddress.TryParse(value, out var addr) &&
                   addr.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork;
        }

        private void CreateFirewallRules()
        {
            if (_rulesCreated.Count >= MaxTotalRules)
            {
                _logger.LogWarning("[ThreatIntelFeedBlocker] Max firewall rules ({Max}) reached, skipping new rules", MaxTotalRules);
                return;
            }

            try
            {
                var fwPolicyType = Type.GetTypeFromProgID("HNetCfg.FwPolicy2");
                if (fwPolicyType == null) return;
                dynamic? fwPolicy = Activator.CreateInstance(fwPolicyType);
                if (fwPolicy == null) return;

                var ruleType = Type.GetTypeFromProgID("HNetCfg.FWRule");
                if (ruleType == null) return;

                // Batch IPs into groups of 100 for fewer firewall rules
                var newIps = _blockedIps.Keys.Where(ip => !_rulesCreated.Contains(ip)).ToList();
                if (newIps.Count == 0) return;

                const int batchSize = 100;
                int batchIndex = _rulesCreated.Count / batchSize;

                for (int i = 0; i < newIps.Count && _rulesCreated.Count < MaxTotalRules; i += batchSize)
                {
                    var batch = newIps.Skip(i).Take(batchSize).ToList();
                    var remoteAddresses = string.Join(",", batch);
                    var ruleName = $"{RuleNamePrefix}{batchIndex++}";

                    try
                    {
                        dynamic? outRule = Activator.CreateInstance(ruleType);
                        if (outRule != null)
                        {
                            outRule.Name = $"{ruleName}-OUT";
                            outRule.Description = $"Sentinel ThreatIntelFeedBlocker: Block {batch.Count} known-bad IPs (outbound)";
                            outRule.Direction = NET_FW_RULE_DIR_OUT;
                            outRule.Action = NET_FW_ACTION_BLOCK;
                            outRule.RemoteAddresses = remoteAddresses;
                            outRule.Enabled = true;
                            outRule.Profiles = ALL_PROFILES;
                            fwPolicy.Rules.Add(outRule);
                        }

                        dynamic? inRule = Activator.CreateInstance(ruleType);
                        if (inRule != null)
                        {
                            inRule.Name = $"{ruleName}-IN";
                            inRule.Description = $"Sentinel ThreatIntelFeedBlocker: Block {batch.Count} known-bad IPs (inbound)";
                            inRule.Direction = NET_FW_RULE_DIR_IN;
                            inRule.Action = NET_FW_ACTION_BLOCK;
                            inRule.RemoteAddresses = remoteAddresses;
                            inRule.Enabled = true;
                            inRule.Profiles = ALL_PROFILES;
                            fwPolicy.Rules.Add(inRule);
                        }

                        foreach (var ip in batch)
                            _rulesCreated.Add(ip);
                    }
                    catch (Exception ex)
                    {
                        _logger.LogDebug(ex, "[ThreatIntelFeedBlocker] Failed to create rule batch {Index}", batchIndex);
                    }
                }

                _logger.LogInformation("[ThreatIntelFeedBlocker] Created firewall rules - total tracked IPs with rules: {Count}", _rulesCreated.Count);
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "[ThreatIntelFeedBlocker] Firewall COM API failed");
            }
        }

        /// <summary>
        /// Removes all Sentinel-ThreatIntel-* firewall rules left from older proactive mode.
        /// Returns number of rules removed.
        /// </summary>
        internal static int RemoveProactiveFirewallRules()
        {
            int removed = 0;
            try
            {
                var fwPolicyType = Type.GetTypeFromProgID("HNetCfg.FwPolicy2");
                if (fwPolicyType == null) return 0;
                dynamic? fwPolicy = Activator.CreateInstance(fwPolicyType);
                if (fwPolicy == null) return 0;

                var toRemove = new List<string>();
                foreach (dynamic rule in fwPolicy.Rules)
                {
                    try
                    {
                        string? name = rule.Name as string;
                        if (name != null && name.StartsWith(RuleNamePrefix))
                            toRemove.Add(name);
                    }
                    catch { /* skip malformed rule */ }
                }

                foreach (var name in toRemove)
                {
                    try
                    {
                        fwPolicy.Rules.Remove(name);
                        removed++;
                    }
                    catch { /* rule may already be gone */ }
                }
            }
            catch
            {
                // Fallback: netsh (some hosts have broken firewall COM)
                try
                {
                    var psi = new System.Diagnostics.ProcessStartInfo("netsh.exe",
                        "advfirewall firewall show rule name=all")
                    {
                        CreateNoWindow = true,
                        UseShellExecute = false,
                        RedirectStandardOutput = true
                    };
                    using var proc = System.Diagnostics.Process.Start(psi);
                    if (proc == null) return removed;
                    var output = proc.StandardOutput.ReadToEnd();
                    proc.WaitForExit(15000);

                    foreach (var line in output.Split('\n'))
                    {
                        // "Rule Name:                            Sentinel-ThreatIntel-0-OUT"
                        if (!line.Contains(RuleNamePrefix))
                            continue;
                        var idx = line.IndexOf(':');
                        if (idx < 0) continue;
                        var name = line[(idx + 1)..].Trim();
                        if (!name.StartsWith(RuleNamePrefix))
                            continue;

                        var del = new System.Diagnostics.ProcessStartInfo("netsh.exe",
                            $"advfirewall firewall delete rule name=\"{name}\"")
                        {
                            CreateNoWindow = true,
                            UseShellExecute = false
                        };
                        using var d = System.Diagnostics.Process.Start(del);
                        d?.WaitForExit(5000);
                        if (d is { ExitCode: 0 }) removed++;
                    }
                }
                catch { /* best effort */ }
            }

            return removed;
        }

        /// <summary>
        /// Checks active TCP connections against the blocklist.
        /// Observe-first: always emit a detection on hit.
        /// NetworkIsolate only when ActiveResponse is enabled (reactive single-IP block).
        /// </summary>
        private void CheckActiveConnections()
        {
            if (_blockedIps.IsEmpty) return;

            try
            {
                var connections = GetEstablishedConnections();

                foreach (var (pid, remoteIp) in connections)
                {
                    if (pid > 0 && pid <= 4) continue;

                    if (!TryMatchBlocked(remoteIp, out var feedSource))
                        continue;

                    // Dedup: don't alert on the same IP+PID within cooldown
                    var alertKey = $"{pid}|{remoteIp}";
                    if (_alertedConnections.TryGetValue(alertKey, out var lastAlert) &&
                        DateTime.UtcNow - lastAlert < AlertCooldown)
                        continue;

                    _alertedConnections[alertKey] = DateTime.UtcNow;

                    // Resolve process name
                    string processName = "unknown";
                    if (pid > 0)
                    {
                        try
                        {
                            using var proc = System.Diagnostics.Process.GetProcessById(pid);
                            processName = proc.ProcessName;
                        }
                        catch { }
                    }

                    // Observe-first: act only when ActiveResponse is on AND something is
                    // actually talking to a listed IP. Never pre-block the rest of the internet.
                    var response = _config.ActiveResponse
                        ? ResponseAction.NetworkIsolate
                        : ResponseAction.LogOnly;

                    _ = _detectionEngine.EmitAsync(new DetectionEvent
                    {
                        RuleName = "ThreatIntelFeedBlocker: Connection to Known-Bad IP",
                        ProcessName = processName,
                        ProcessId = pid,
                        SignalType = SignalType.NetworkC2,
                        Family = TerminalFamily.C2Beacon,
                        Confidence = 0.92,
                        Tier = DetectionTier.Tier1Behavioral,
                        AuthorizedResponse = response,
                        Evidence = $"Process '{processName}' (PID {pid}) connected to threat-intel-listed IP: {remoteIp} (Feed: {feedSource})",
                        Reasoning = "Active TCP connection to an IP address listed in public threat intelligence feeds " +
                                    "(Spamhaus DROP, Feodo Tracker, or EmergingThreats). " +
                                    (response == ResponseAction.NetworkIsolate
                                        ? "ActiveResponse on - isolating this IP only (reactive)."
                                        : "Observation mode - logged only; no firewall change."),
                        Metadata = new Dictionary<string, string>
                        {
                            { "RemoteIp", remoteIp },
                            { "FeedSource", feedSource },
                            { "Detection", "ReactiveFeedMatch" },
                            { "Mode", _config.ActiveResponse ? "active" : "observe" }
                        }
                    });

                    _logger.LogWarning(
                        "[ThreatIntelFeedBlocker] Connection to listed IP: {Process} (PID {Pid}) -> {Ip} (Feed: {Feed}, response={Response})",
                        processName, pid, remoteIp, feedSource, response);
                }
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "[ThreatIntelFeedBlocker] Connection check failed");
            }
        }

        /// <summary>Exact IP or CIDR membership match against the in-memory feed set.</summary>
        private bool TryMatchBlocked(string remoteIp, out string feedSource)
        {
            if (_blockedIps.TryGetValue(remoteIp, out feedSource!))
                return true;

            foreach (var kv in _blockedIps)
            {
                if (kv.Key.IndexOf('/') < 0) continue;
                if (IpInCidr(remoteIp, kv.Key))
                {
                    feedSource = kv.Value;
                    return true;
                }
            }

            feedSource = string.Empty;
            return false;
        }

        internal static bool IpInCidr(string ip, string cidr)
        {
            try
            {
                var parts = cidr.Split('/');
                if (parts.Length != 2) return false;
                if (!IPAddress.TryParse(parts[0], out var network)) return false;
                if (!IPAddress.TryParse(ip, out var address)) return false;
                if (!int.TryParse(parts[1], out int prefix) || prefix < 0 || prefix > 32) return false;

                var netBytes = network.GetAddressBytes();
                var addrBytes = address.GetAddressBytes();
                if (netBytes.Length != 4 || addrBytes.Length != 4) return false;

                // Network byte order -> host uint
                uint net = ((uint)netBytes[0] << 24) | ((uint)netBytes[1] << 16) | ((uint)netBytes[2] << 8) | netBytes[3];
                uint addr = ((uint)addrBytes[0] << 24) | ((uint)addrBytes[1] << 16) | ((uint)addrBytes[2] << 8) | addrBytes[3];
                uint mask = prefix == 0 ? 0u : uint.MaxValue << (32 - prefix);
                return (addr & mask) == (net & mask);
            }
            catch
            {
                return false;
            }
        }

        private static List<(int pid, string remoteIp)> GetEstablishedConnections()
        {
            var results = new List<(int, string)>();

            try
            {
                // IPGlobalProperties lacks PID; still useful for IP-level observe/alert.
                var properties = System.Net.NetworkInformation.IPGlobalProperties.GetIPGlobalProperties();
                var connections = properties.GetActiveTcpConnections();

                foreach (var conn in connections)
                {
                    if (conn.State != System.Net.NetworkInformation.TcpState.Established)
                        continue;

                    var remoteIp = conn.RemoteEndPoint.Address.ToString();

                    // Skip private/loopback
                    if (remoteIp.StartsWith("127.") || remoteIp.StartsWith("10.") ||
                        remoteIp.StartsWith("192.168.") || remoteIp.StartsWith("169.254.") ||
                        remoteIp == "::1" || remoteIp.StartsWith("fe80") ||
                        remoteIp.StartsWith("172.16.") || remoteIp.StartsWith("172.17.") ||
                        remoteIp.StartsWith("172.18.") || remoteIp.StartsWith("172.19.") ||
                        remoteIp.StartsWith("172.2") || remoteIp.StartsWith("172.30.") ||
                        remoteIp.StartsWith("172.31."))
                        continue;

                    // PID unknown via this API
                    results.Add((0, remoteIp));
                }
            }
            catch { }

            return results;
        }

        private void PruneAlertCache()
        {
            var cutoff = DateTime.UtcNow.AddMinutes(-30);
            var stale = _alertedConnections.Where(kv => kv.Value < cutoff).Select(kv => kv.Key).ToList();
            foreach (var key in stale)
                _alertedConnections.TryRemove(key, out _);
        }
    }
}
