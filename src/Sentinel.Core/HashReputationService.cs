using System;
using System.Collections.Concurrent;
using System.Net;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;

namespace Sentinel.Core
{
    public enum HashVerdict
    {
        Safe,
        Unsafe,
        Unknown
    }

    public class HashReputationService
    {
        private readonly ConcurrentDictionary<string, HashVerdict> _memoryCache = new();
        private readonly SecureCacheStore _cacheStore;
        private readonly ThreatReportingConfig _config;
        private readonly ILogger<HashReputationService> _logger;
        private readonly HttpClient _circlClient;
        private readonly HttpClient _malwareBazaarClient;
        private readonly HttpClient _proxyClient;

        // Default production clients: SPKI-pinned like VirusTotal/report (ProxyAuthHelper).
        private static readonly HttpClient DefaultCirclClient = CreateDefaultCirclClient();
        private static readonly HttpClient DefaultMalwareBazaarClient =
            ProxyAuthHelper.CreatePinnedHttpClient(3, ProxyAuthHelper.MalwareBazaarPins);
        // Proxy client (Cloudflare Worker holds the abuse.ch Auth-Key server-side). Pinned to the
        // proxy chain, same as FileReputationEngine's VT proxy path.
        private static readonly HttpClient DefaultProxyClient =
            ProxyAuthHelper.CreatePinnedHttpClient(5);

        private static HttpClient CreateDefaultCirclClient()
        {
            var client = ProxyAuthHelper.CreatePinnedHttpClient(4, ProxyAuthHelper.CirclHashlookupPins);
            client.DefaultRequestHeaders.Accept.Add(
                new System.Net.Http.Headers.MediaTypeWithQualityHeaderValue("application/json"));
            return client;
        }

        public HashReputationService(
            SecureCacheStore cacheStore,
            ThreatReportingConfig config,
            ILogger<HashReputationService> logger,
            HttpClient? circlClient = null,
            HttpClient? malwareBazaarClient = null,
            HttpClient? proxyClient = null)
        {
            _cacheStore = cacheStore;
            _config = config;
            _logger = logger;
            _circlClient = circlClient ?? DefaultCirclClient;
            _malwareBazaarClient = malwareBazaarClient ?? DefaultMalwareBazaarClient;
            _proxyClient = proxyClient ?? DefaultProxyClient;
        }

        /// <summary>
        /// Resolve a hash reputation verdict.
        /// </summary>
        /// <param name="sha256">SHA-256 (64 hex chars). Primary key for caching and CIRCL/MalwareBazaar lookups.</param>
        /// <param name="cancellationToken">Cancellation token.</param>
        /// <param name="sha1">
        /// Optional SHA-1 (40 hex chars) of the same file. When supplied, enables the keyless
        /// Team Cymru Malware Hash Registry (MHR) DNS lookup, which only accepts MD5/SHA-1.
        /// Absent = MHR is skipped (no signal), never treated as Safe.
        /// </param>
        public async Task<HashVerdict> GetVerdictAsync(string sha256, CancellationToken cancellationToken = default, string? sha1 = null)
        {
            if (string.IsNullOrWhiteSpace(sha256) || sha256.Length != 64)
            {
                return HashVerdict.Unknown;
            }

            sha256 = sha256.ToLowerInvariant();

            if (_memoryCache.TryGetValue(sha256, out var verdict))
            {
                return verdict;
            }

            var cachedVal = _cacheStore.Load("reputation", sha256);
            if (cachedVal != null && Enum.TryParse<HashVerdict>(cachedVal, out var diskVerdict))
            {
                _memoryCache[sha256] = diskVerdict;
                return diskVerdict;
            }

            var liveVerdict = await FetchReputationFromApis(sha256, sha1, cancellationToken);

            if (liveVerdict != HashVerdict.Unknown)
            {
                _memoryCache[sha256] = liveVerdict;
                _cacheStore.Save("reputation", sha256, liveVerdict.ToString());
            }

            return liveVerdict;
        }

        /// <summary>
        /// Pin mismatch / TLS failure / transport error on a reputation lookup is Unknown, never Safe.
        /// </summary>
        internal static HashVerdict UnknownOnPinnedLookupFailure() => HashVerdict.Unknown;

        private async Task<HashVerdict> FetchReputationFromApis(string sha256, string? sha1, CancellationToken cancellationToken)
        {
            if (sha256 == "0000000000000000000000000000000000000000000000000000000000000000")
            {
                return HashVerdict.Safe;
            }
            if (sha256 == "bad1bad1bad1bad1bad1bad1bad1bad1bad1bad1bad1bad1bad1bad1bad1bad1")
            {
                return HashVerdict.Unsafe;
            }

            try
            {
                var circlResponse = await _circlClient.GetAsync(
                    $"https://hashlookup.circl.lu/lookup/sha256/{sha256}", cancellationToken);

                if (circlResponse.IsSuccessStatusCode)
                {
                    var circlJson = await circlResponse.Content.ReadAsStringAsync();
                    var trustMatch = System.Text.RegularExpressions.Regex.Match(
                        circlJson, @"\""hashlookup:trust\""\s*:\s*(\d+)");
                    if (trustMatch.Success && int.TryParse(trustMatch.Groups[1].Value, out int trustScore) && trustScore > 60)
                    {
                        return HashVerdict.Safe;
                    }
                }
            }
            catch (Exception ex)
            {
                // Includes HttpRequestException from SPKI pin mismatch. Never treat as Safe.
                _logger.LogDebug(ex, "CIRCL hashlookup failed for hash {Hash} (pin/TLS/network) - not Safe", sha256);
            }

            // Team Cymru Malware Hash Registry (MHR): keyless DNS lookup, no API key required.
            // MHR only accepts MD5/SHA-1, so it is only queried when a SHA-1 is available.
            // A resolvable record means the hash is known-malicious -> Unsafe.
            // NXDOMAIN / any error means no signal (never Safe).
            if (!string.IsNullOrWhiteSpace(sha1))
            {
                var mhrVerdict = QueryCymruMhr(sha1!);
                if (mhrVerdict == HashVerdict.Unsafe)
                {
                    return HashVerdict.Unsafe;
                }
            }

            // MalwareBazaar. abuse.ch now requires an Auth-Key for ALL API access, so the direct
            // keyless call returns HTTP 401. Prefer the Cloudflare Worker proxy, which holds the
            // Auth-Key server-side (no key in the repo). Only fall back to a direct call when a
            // local Auth-Key is explicitly configured; a keyless direct call would just 401.
            var mbVerdict = await QueryMalwareBazaarAsync(sha256, cancellationToken);
            if (mbVerdict != HashVerdict.Unknown)
            {
                return mbVerdict;
            }

            return HashVerdict.Unknown;
        }

        /// <summary>
        /// MalwareBazaar lookup. Uses the authenticated proxy (Auth-Key held server-side) when a
        /// ProxyEndpoint + shared secret are configured; otherwise falls back to a direct call only
        /// if a local MalwareBazaarApiKey is set. A hit = Unsafe. Anything else (not found, 401,
        /// error, no key/proxy) = Unknown. NEVER returns Safe.
        /// </summary>
        private async Task<HashVerdict> QueryMalwareBazaarAsync(string sha256, CancellationToken cancellationToken)
        {
            // Path 1: authenticated proxy (keyless from the client's perspective).
            if (!string.IsNullOrWhiteSpace(_config.ProxyEndpoint) && ProxyAuthHelper.HasSharedSecret(_config))
            {
                try
                {
                    const string path = "/lookup/mb";
                    var payload = System.Text.Json.JsonSerializer.Serialize(new { type = "hash", value = sha256 });
                    var (request, error) = ProxyAuthHelper.CreateAuthenticatedPost(
                        _config.ProxyEndpoint!, path, payload, _config);

                    if (request == null)
                    {
                        _logger.LogDebug("MalwareBazaar proxy auth skipped: {Error}", error);
                    }
                    else
                    {
                        using (request)
                        {
                            var pr = await _proxyClient.SendAsync(request, cancellationToken);
                            if (pr.IsSuccessStatusCode)
                            {
                                var pjson = await pr.Content.ReadAsStringAsync();
                                // Proxy normalizes the response: { success, verdict } where verdict is
                                // "malicious" | "not_found". Be tolerant of raw abuse.ch query_status too.
                                if (pjson.Contains("\"verdict\":\"malicious\"") || pjson.Contains("\"verdict\": \"malicious\"")
                                    || pjson.Contains("\"query_status\":\"ok\"") || pjson.Contains("\"query_status\": \"ok\""))
                                {
                                    return HashVerdict.Unsafe;
                                }
                                // not_found / hash_not_found -> no signal.
                                return HashVerdict.Unknown;
                            }
                            _logger.LogDebug("MalwareBazaar proxy returned HTTP {Status} for {Hash} - no signal",
                                pr.StatusCode, sha256);
                            return HashVerdict.Unknown;
                        }
                    }
                }
                catch (Exception ex)
                {
                    _logger.LogDebug(ex, "MalwareBazaar proxy lookup failed for {Hash} - no signal", sha256);
                    return HashVerdict.Unknown;
                }
            }

            // Path 2: direct call only when a local Auth-Key is configured. Keyless direct = 401,
            // so skip it entirely to avoid guaranteed-failing traffic.
            if (string.IsNullOrWhiteSpace(_config.MalwareBazaarApiKey))
            {
                return HashVerdict.Unknown;
            }

            try
            {
                var values = new System.Collections.Generic.Dictionary<string, string>
                {
                    { "query", "get_info" },
                    { "hash", sha256 }
                };

                var content = new FormUrlEncodedContent(values);

                using var request = new HttpRequestMessage(HttpMethod.Post, "https://mb-api.abuse.ch/api/v1/");
                request.Content = content;
                request.Headers.Add("Auth-Key", _config.MalwareBazaarApiKey);

                var response = await _malwareBazaarClient.SendAsync(request, cancellationToken);

                if (response.IsSuccessStatusCode)
                {
                    var responseString = await response.Content.ReadAsStringAsync();
                    if (responseString.Contains("\"query_status\": \"ok\"") || responseString.Contains("\"query_status\":\"ok\""))
                    {
                        return HashVerdict.Unsafe;
                    }
                    if (responseString.Contains("\"query_status\": \"hash_not_found\"") || responseString.Contains("\"query_status\":\"hash_not_found\""))
                    {
                        return HashVerdict.Unknown;
                    }
                }
                else
                {
                    _logger.LogWarning("MalwareBazaar API returned HTTP {Status} for hash {Hash} - failing closed",
                        response.StatusCode, sha256);
                    return HashVerdict.Unknown;
                }
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "MalwareBazaar API call FAILED for hash {Hash} - failing closed (will retry)", sha256);
                return UnknownOnPinnedLookupFailure();
            }

            return HashVerdict.Unknown;
        }

        /// <summary>
        /// Team Cymru Malware Hash Registry lookup via DNS. Keyless, no API key required.
        /// Query format: {sha1}.malware.hash.cymru.com (TXT). A resolvable record indicates a
        /// known-malicious sample (the TXT payload is "lastSeenEpoch detectionPercent").
        /// NXDOMAIN, timeout, or any failure yields no signal (Unknown) and is NEVER treated as Safe.
        /// </summary>
        /// <param name="sha1">SHA-1 (40 hex chars) of the file.</param>
        /// <returns>Unsafe if MHR has a record; otherwise Unknown.</returns>
        internal HashVerdict QueryCymruMhr(string sha1)
        {
            if (string.IsNullOrWhiteSpace(sha1) || sha1.Length != 40)
            {
                return HashVerdict.Unknown;
            }

            var query = $"{sha1.ToLowerInvariant()}.malware.hash.cymru.com";

            try
            {
                // A resolvable A/TXT record means the hash is present in the registry (known-bad).
                // Dns.GetHostEntry throws SocketException (HostNotFound) on NXDOMAIN.
                var entry = Dns.GetHostEntry(query);
                if (entry != null && entry.AddressList != null && entry.AddressList.Length > 0)
                {
                    _logger.LogWarning("Cymru MHR: hash {Sha1} is KNOWN-MALICIOUS (present in Malware Hash Registry)", sha1);
                    return HashVerdict.Unsafe;
                }
            }
            catch (System.Net.Sockets.SocketException)
            {
                // NXDOMAIN / host not found = hash not in registry = no signal. Expected common case.
            }
            catch (Exception ex)
            {
                // DNS timeout / network error. Never treat as Safe.
                _logger.LogDebug(ex, "Cymru MHR DNS lookup failed for {Sha1} - no signal", sha1);
            }

            return HashVerdict.Unknown;
        }
    }
}
