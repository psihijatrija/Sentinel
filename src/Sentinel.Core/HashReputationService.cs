using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;

namespace Sentinel.Core
{
    public enum HashVerdict { Safe, Unsafe, Unknown }

    /// <summary>Offline compatibility facade. Online reputation and its cache are no longer consulted.</summary>
    public class HashReputationService
    {
        public HashReputationService(SecureCacheStore cacheStore, ThreatReportingConfig config,
            ILogger<HashReputationService> logger, HttpClient? circlClient = null,
            HttpClient? malwareBazaarClient = null, HttpClient? proxyClient = null) { }

        public Task<HashVerdict> GetVerdictAsync(string sha256,
            CancellationToken cancellationToken = default, string? sha1 = null)
        {
            cancellationToken.ThrowIfCancellationRequested();
            return Task.FromResult(HashVerdict.Unknown);
        }

        internal static HashVerdict UnknownOnPinnedLookupFailure() => HashVerdict.Unknown;
    }
}
