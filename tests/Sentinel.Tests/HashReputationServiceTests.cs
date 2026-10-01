using System;
using System.IO;
using System.Threading.Tasks;
using Xunit;
using Sentinel.Core;
using Microsoft.Extensions.Logging.Abstractions;

namespace Sentinel.Tests
{
    public class HashReputationServiceTests
    {
        [Fact]
        public async Task GetVerdictAsync_ReturnsSafe_ForPredefinedSafeHash()
        {
            var tempDir = Path.Combine(Path.GetTempPath(), "rep_test_" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(tempDir);
            try
            {
                var cache = new SecureCacheStore(tempDir);
                var config = new ThreatReportingConfig();
                var service = new HashReputationService(cache, config, NullLogger<HashReputationService>.Instance);

                var verdict = await service.GetVerdictAsync("0000000000000000000000000000000000000000000000000000000000000000");

                Assert.Equal(HashVerdict.Safe, verdict);
            }
            finally
            {
                try { Directory.Delete(tempDir, true); } catch { }
            }
        }

        [Fact]
        public async Task GetVerdictAsync_ReturnsUnsafe_ForPredefinedUnsafeHash()
        {
            var tempDir = Path.Combine(Path.GetTempPath(), "rep_test_" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(tempDir);
            try
            {
                var cache = new SecureCacheStore(tempDir);
                var config = new ThreatReportingConfig();
                var service = new HashReputationService(cache, config, NullLogger<HashReputationService>.Instance);

                var verdict = await service.GetVerdictAsync("bad1bad1bad1bad1bad1bad1bad1bad1bad1bad1bad1bad1bad1bad1bad1bad1");

                Assert.Equal(HashVerdict.Unsafe, verdict);
            }
            finally
            {
                try { Directory.Delete(tempDir, true); } catch { }
            }
        }

        [Fact]
        public async Task GetVerdictAsync_ReturnsCachedVerdict_FromDiskStore()
        {
            var tempDir = Path.Combine(Path.GetTempPath(), "rep_test_" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(tempDir);
            try
            {
                var cache = new SecureCacheStore(tempDir);
                var config = new ThreatReportingConfig();
                
                var sha256 = "c0ffee0000000000000000000000000000000000000000000000000000000000";
                cache.Save("reputation", sha256, HashVerdict.Unsafe.ToString());

                var service = new HashReputationService(cache, config, NullLogger<HashReputationService>.Instance);
                var verdict = await service.GetVerdictAsync(sha256);

                Assert.Equal(HashVerdict.Unsafe, verdict);
            }
            finally
            {
                try { Directory.Delete(tempDir, true); } catch { }
            }
        }

        [Fact]
        public async Task GetVerdictAsync_DegradesGracefullyToUnknown_OnNetworkFailure()
        {
            var tempDir = Path.Combine(Path.GetTempPath(), "rep_test_" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(tempDir);
            try
            {
                var cache = new SecureCacheStore(tempDir);
                var config = new ThreatReportingConfig { MalwareBazaarApiKey = "dummy_key" };
                var service = new HashReputationService(cache, config, NullLogger<HashReputationService>.Instance);

                // A random non-cached hash will attempt live query and timeout/fail without actual network or invalid target.
                var sha256 = "1234567890123456789012345678901234567890123456789012345678901234";
                var verdict = await service.GetVerdictAsync(sha256);

                Assert.Equal(HashVerdict.Unknown, verdict);
            }
            finally
            {
                try { Directory.Delete(tempDir, true); } catch { }
            }
        }

        // Cymru MHR is keyless (DNS-based). A malformed/short SHA-1 must be rejected by the
        // length guard BEFORE any DNS lookup, and must never be treated as Safe/Unsafe.
        // These inputs are all length-invalid so the test performs no network I/O.
        [Theory]
        [InlineData(null)]
        [InlineData("")]
        [InlineData("tooshort")]
        [InlineData("abcdef")] // still < 40 chars -> guarded out, no DNS
        public void QueryCymruMhr_ReturnsUnknown_ForInvalidSha1(string? sha1)
        {
            var tempDir = Path.Combine(Path.GetTempPath(), "rep_test_" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(tempDir);
            try
            {
                var cache = new SecureCacheStore(tempDir);
                var service = new HashReputationService(cache, new ThreatReportingConfig(), NullLogger<HashReputationService>.Instance);

                // Length-invalid inputs return Unknown immediately without a DNS lookup.
                var verdict = service.QueryCymruMhr(sha1!);

                Assert.Equal(HashVerdict.Unknown, verdict);
            }
            finally
            {
                try { Directory.Delete(tempDir, true); } catch { }
            }
        }

        // Passing an optional SHA-1 through GetVerdictAsync must remain backward compatible
        // and still degrade to Unknown when no source has a verdict.
        [Fact]
        public async Task GetVerdictAsync_WithSha1_DegradesToUnknown_WhenNoSourceHasVerdict()
        {
            var tempDir = Path.Combine(Path.GetTempPath(), "rep_test_" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(tempDir);
            try
            {
                var cache = new SecureCacheStore(tempDir);
                var service = new HashReputationService(cache, new ThreatReportingConfig(), NullLogger<HashReputationService>.Instance);

                var sha256 = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";
                var sha1 = "3b054bdaf8bdf85b0086df9488bf450d58edbc6c";
                var verdict = await service.GetVerdictAsync(sha256, sha1: sha1);

                Assert.Equal(HashVerdict.Unknown, verdict);
            }
            finally
            {
                try { Directory.Delete(tempDir, true); } catch { }
            }
        }
    }
}
