using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Text.Json;
using Microsoft.Extensions.Logging;

namespace Sentinel.Core
{
    /// <summary>
    /// Shared, thread-safe runtime blocklist for domains and IPs. This is the simple
    /// "add or remove and the site is (un)blocked" surface any code in the codebase can use:
    /// call <see cref="BlockDomain"/> / <see cref="UnblockDomain"/> (or the IP variants) and
    /// <c>HostsFileGuard</c> enforces the change on its next scan (and on startup), using the
    /// same proven mechanism the removed forum.hr block used - a hosts-file line plus a wildcard
    /// NRPT rule for domains, and inbound + outbound Windows Firewall rules for IPs.
    ///
    /// This complements the operator-defined static <see cref="SentinelConfig.EnforcedDomainBlocks"/>
    /// / <see cref="SentinelConfig.EnforcedIpBlocks"/> arrays: those are compile/config-time,
    /// this one is runtime-mutable. HostsFileGuard enforces the UNION of both.
    ///
    /// Design notes (honors Sentinel constraints):
    /// - No static mutable state: all state lives in this DI singleton instance.
    /// - Persisted via <see cref="SecureCacheStore"/> using System.Text.Json (no string-built
    ///   JSON), so runtime blocks survive a service restart.
    /// - IP entries refuse loopback / broadcast / Any / invalid addresses so a caller can never
    ///   self-inflict a lockout.
    /// - Enforcement/removal is performed by HostsFileGuard (the single host-mutation authority);
    ///   this service only holds the desired set. It never mutates the hosts file or firewall
    ///   directly.
    /// </summary>
    public sealed class RuntimeBlocklistService
    {
        // SecureCacheStore stores ONE key/value per "{cacheName}.cache" file (each Save overwrites
        // the whole file), so each logical value must use a DISTINCT cache name to avoid clobbering.
        private const string DomainsCache = "blocklist-domains";
        private const string IpsCache = "blocklist-ips";
        private const string SeededCache = "blocklist-seeded";
        private const string PayloadKey = "v1"; // single fixed key within each cache file

        // Marker persisted once the first-run default seed has been applied, so a user who later
        // unblocks a seeded domain (e.g. forum.hr) does not get it silently re-added on restart.

        // Domains blocked by default on a genuine first run (no persisted state yet). forum.hr is
        // re-added here: it is the historical spy-pairing origin, and shipping it blocked restores
        // the pre-removal policy without the old blind auto-cleanup. A user can still UnblockDomain
        // it explicitly - the SeededKey marker ensures that removal survives restarts.
        private static readonly string[] DefaultSeedDomains = new[] { "forum.hr" };

        private readonly SecureCacheStore _cacheStore;
        private readonly ILogger<RuntimeBlocklistService> _logger;

        // Bare, normalized lowercase domain -> present. Value is unused (set semantics).
        private readonly ConcurrentDictionary<string, byte> _domains =
            new(StringComparer.OrdinalIgnoreCase);
        // Canonical IP string -> present.
        private readonly ConcurrentDictionary<string, byte> _ips =
            new(StringComparer.OrdinalIgnoreCase);

        public RuntimeBlocklistService(SecureCacheStore cacheStore, ILogger<RuntimeBlocklistService> logger)
        {
            _cacheStore = cacheStore;
            _logger = logger;
            Load();
            SeedDefaultsIfFirstRun();
        }

        /// <summary>
        /// On a genuine first run (the seed marker has never been written), adds the default
        /// seed domains and records the marker. Runs exactly once per machine: a later explicit
        /// UnblockDomain persists and is NOT undone by re-seeding, because the marker is already set.
        /// </summary>
        private void SeedDefaultsIfFirstRun()
        {
            try
            {
                var alreadySeeded = !string.IsNullOrWhiteSpace(_cacheStore.Load(SeededCache, PayloadKey));
                if (alreadySeeded) return;

                foreach (var d in DefaultSeedDomains)
                {
                    var n = NormalizeDomain(d);
                    if (n != null) _domains.TryAdd(n, 0);
                }

                _cacheStore.Save(SeededCache, PayloadKey, "1");
                Save();
                _logger.LogInformation(
                    "[RuntimeBlocklist] First-run seed applied: {N} default domain block(s) [{Domains}]",
                    DefaultSeedDomains.Length, string.Join(", ", DefaultSeedDomains));
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "[RuntimeBlocklist] First-run seed failed");
            }
        }

        // ---- Domain API --------------------------------------------------------

        /// <summary>
        /// Adds a domain to the runtime blocklist. Accepts a URL, "www.example.com",
        /// "example.com:8080", ".example.com", etc.; it is normalized to a bare lowercase host.
        /// The block covers the apex and all subdomains (wildcard NRPT). Idempotent.
        /// Returns true if the set changed (a new domain was added).
        /// </summary>
        public bool BlockDomain(string domain)
        {
            var d = NormalizeDomain(domain);
            if (d == null)
            {
                _logger.LogDebug("[RuntimeBlocklist] Ignoring invalid domain '{Raw}'", domain);
                return false;
            }
            if (_domains.TryAdd(d, 0))
            {
                Save();
                _logger.LogWarning("[RuntimeBlocklist] Domain blocked: {Domain} (apex + subdomains)", d);
                return true;
            }
            return false;
        }

        /// <summary>
        /// Removes a domain from the runtime blocklist. HostsFileGuard tears down its hosts line
        /// and NRPT rule on the next scan. Idempotent. Returns true if the set changed.
        /// </summary>
        public bool UnblockDomain(string domain)
        {
            var d = NormalizeDomain(domain);
            if (d == null) return false;
            if (_domains.TryRemove(d, out _))
            {
                Save();
                _logger.LogWarning("[RuntimeBlocklist] Domain unblocked: {Domain}", d);
                return true;
            }
            return false;
        }

        public bool IsDomainBlocked(string domain)
        {
            var d = NormalizeDomain(domain);
            return d != null && _domains.ContainsKey(d);
        }

        /// <summary>Snapshot of the currently blocked bare domains (lowercase).</summary>
        public IReadOnlyList<string> GetBlockedDomains() => _domains.Keys.ToArray();

        // ---- IP API ------------------------------------------------------------

        /// <summary>
        /// Adds an IP to the runtime blocklist (inbound + outbound firewall block). Refuses
        /// loopback / broadcast / Any / invalid addresses so a caller can never self-lock.
        /// Idempotent. Returns true if the set changed.
        /// </summary>
        public bool BlockIp(string ip)
        {
            var canonical = NormalizeIp(ip);
            if (canonical == null)
            {
                _logger.LogDebug("[RuntimeBlocklist] Refusing invalid/reserved IP '{Raw}'", ip);
                return false;
            }
            if (_ips.TryAdd(canonical, 0))
            {
                Save();
                _logger.LogWarning("[RuntimeBlocklist] IP blocked: {IP} (inbound + outbound)", canonical);
                return true;
            }
            return false;
        }

        /// <summary>
        /// Removes an IP from the runtime blocklist. HostsFileGuard removes its firewall rules on
        /// the next scan. Idempotent. Returns true if the set changed.
        /// </summary>
        public bool UnblockIp(string ip)
        {
            var canonical = NormalizeIp(ip);
            if (canonical == null) return false;
            if (_ips.TryRemove(canonical, out _))
            {
                Save();
                _logger.LogWarning("[RuntimeBlocklist] IP unblocked: {IP}", canonical);
                return true;
            }
            return false;
        }

        public bool IsIpBlocked(string ip)
        {
            var canonical = NormalizeIp(ip);
            return canonical != null && _ips.ContainsKey(canonical);
        }

        /// <summary>Snapshot of the currently blocked IPs (canonical form).</summary>
        public IReadOnlyList<string> GetBlockedIps() => _ips.Keys.ToArray();

        // ---- Normalization (pure, testable) ------------------------------------

        /// <summary>
        /// Normalizes a raw domain to a bare lowercase host (strips scheme/port/path/leading-dot).
        /// Mirrors HostsFileGuard.NormalizeBlockDomain so runtime + config entries key identically.
        /// Returns null for empty/invalid input.
        /// </summary>
        public static string? NormalizeDomain(string? raw)
        {
            if (string.IsNullOrWhiteSpace(raw)) return null;
            var d = raw!.Trim().ToLowerInvariant();
            int scheme = d.IndexOf("://", StringComparison.Ordinal);
            if (scheme >= 0) d = d.Substring(scheme + 3);
            d = d.Split('/')[0].Split(':')[0].TrimStart('.');
            return string.IsNullOrWhiteSpace(d) ? null : d;
        }

        /// <summary>
        /// Validates and canonicalizes an IP. Refuses loopback / broadcast / Any / unparseable
        /// addresses (never self-inflict a lockout - same guard HostsFileGuard.EnsureIpFirewallBlock
        /// applies). Returns null when the IP must not be blocked.
        /// </summary>
        public static string? NormalizeIp(string? raw)
        {
            if (string.IsNullOrWhiteSpace(raw)) return null;
            if (!IPAddress.TryParse(raw!.Trim(), out var parsed)) return null;
            if (IPAddress.IsLoopback(parsed) ||
                parsed.Equals(IPAddress.Broadcast) ||
                parsed.Equals(IPAddress.Any) ||
                parsed.Equals(IPAddress.IPv6Any))
            {
                return null;
            }
            return parsed.ToString();
        }

        // ---- Persistence -------------------------------------------------------

        private void Load()
        {
            try
            {
                var domainsJson = _cacheStore.Load(DomainsCache, PayloadKey);
                if (!string.IsNullOrWhiteSpace(domainsJson))
                {
                    var list = JsonSerializer.Deserialize<List<string>>(domainsJson!);
                    if (list != null)
                        foreach (var d in list)
                        {
                            var n = NormalizeDomain(d);
                            if (n != null) _domains.TryAdd(n, 0);
                        }
                }

                var ipsJson = _cacheStore.Load(IpsCache, PayloadKey);
                if (!string.IsNullOrWhiteSpace(ipsJson))
                {
                    var list = JsonSerializer.Deserialize<List<string>>(ipsJson!);
                    if (list != null)
                        foreach (var ip in list)
                        {
                            var n = NormalizeIp(ip);
                            if (n != null) _ips.TryAdd(n, 0);
                        }
                }

                if (_domains.Count > 0 || _ips.Count > 0)
                    _logger.LogInformation(
                        "[RuntimeBlocklist] Loaded {Domains} domain(s) and {Ips} IP(s)",
                        _domains.Count, _ips.Count);
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "[RuntimeBlocklist] Load failed");
            }
        }

        private void Save()
        {
            try
            {
                _cacheStore.Save(DomainsCache, PayloadKey, JsonSerializer.Serialize(_domains.Keys.ToList()));
                _cacheStore.Save(IpsCache, PayloadKey, JsonSerializer.Serialize(_ips.Keys.ToList()));
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "[RuntimeBlocklist] Save failed");
            }
        }
    }
}
