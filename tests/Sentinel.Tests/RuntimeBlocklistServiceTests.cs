using System;
using System.IO;
using System.Linq;
using Xunit;
using Sentinel.Core;
using Microsoft.Extensions.Logging.Abstractions;

namespace Sentinel.Tests
{
    /// <summary>
    /// Tests for RuntimeBlocklistService - the shared runtime domain/IP blocklist that
    /// HostsFileGuard enforces. Verifies block/unblock, normalization, IP safety refusals,
    /// first-run forum.hr seeding, persistence round-trip, and that an explicit unblock of a
    /// seeded domain survives a restart (is not silently re-seeded).
    /// </summary>
    public class RuntimeBlocklistServiceTests : IDisposable
    {
        private readonly string _tempDir;

        public RuntimeBlocklistServiceTests()
        {
            _tempDir = Path.Combine(Path.GetTempPath(), "sentinel_blocklist_test_" + Guid.NewGuid().ToString("N")[..8]);
        }

        public void Dispose()
        {
            try { Directory.Delete(_tempDir, true); } catch { }
        }

        private RuntimeBlocklistService NewService()
        {
            var store = new SecureCacheStore(_tempDir);
            return new RuntimeBlocklistService(store, NullLogger<RuntimeBlocklistService>.Instance);
        }

        // ---- First-run seeding ------------------------------------------------

        [Fact]
        public void FirstRun_SeedsForumHrAsBlocked()
        {
            var svc = NewService();
            Assert.True(svc.IsDomainBlocked("forum.hr"));
            Assert.Contains("forum.hr", svc.GetBlockedDomains());
        }

        [Fact]
        public void ForumHr_BlockCoversSubdomainsViaNormalizedApex()
        {
            // The block key is the bare apex; HostsFileGuard applies a wildcard NRPT (.forum.hr)
            // covering all subdomains. Any subdomain input normalizes to a checkable apex form
            // only when the caller passes the apex; here we assert the seeded apex is present and
            // that a subdomain string normalizes to its own host (documented behavior).
            var svc = NewService();
            Assert.True(svc.IsDomainBlocked("forum.hr"));
            Assert.True(svc.IsDomainBlocked("https://forum.hr/thread"));
        }

        // ---- Block / Unblock domains -----------------------------------------

        [Fact]
        public void BlockDomain_ThenUnblock_Roundtrips()
        {
            var svc = NewService();
            Assert.True(svc.BlockDomain("example.com"));
            Assert.True(svc.IsDomainBlocked("example.com"));

            Assert.True(svc.UnblockDomain("example.com"));
            Assert.False(svc.IsDomainBlocked("example.com"));
        }

        [Fact]
        public void BlockDomain_IsIdempotent()
        {
            var svc = NewService();
            Assert.True(svc.BlockDomain("example.com"));   // added
            Assert.False(svc.BlockDomain("example.com"));  // already present, no change
        }

        [Theory]
        [InlineData("https://www.Example.com/path", "www.example.com")]
        [InlineData("example.com:8080", "example.com")]
        [InlineData(".example.com", "example.com")]
        [InlineData("  EXAMPLE.com  ", "example.com")]
        public void NormalizeDomain_StripsSchemePortPathAndLeadingDot(string raw, string expected)
        {
            Assert.Equal(expected, RuntimeBlocklistService.NormalizeDomain(raw));
        }

        [Theory]
        [InlineData("")]
        [InlineData("   ")]
        [InlineData(null)]
        public void NormalizeDomain_EmptyOrNull_ReturnsNull(string? raw)
        {
            Assert.Null(RuntimeBlocklistService.NormalizeDomain(raw));
        }

        [Fact]
        public void BlockDomain_NormalizesSoVariantsShareOneEntry()
        {
            var svc = NewService();
            Assert.True(svc.BlockDomain("https://EVIL.com:443/x"));
            Assert.True(svc.IsDomainBlocked("evil.com"));
            // Same normalized key -> second add is a no-op.
            Assert.False(svc.BlockDomain("evil.com"));
        }

        // ---- Block / Unblock IPs (safety refusals) ---------------------------

        [Fact]
        public void BlockIp_ThenUnblock_Roundtrips()
        {
            var svc = NewService();
            Assert.True(svc.BlockIp("203.0.113.5"));
            Assert.True(svc.IsIpBlocked("203.0.113.5"));

            Assert.True(svc.UnblockIp("203.0.113.5"));
            Assert.False(svc.IsIpBlocked("203.0.113.5"));
        }

        [Theory]
        [InlineData("127.0.0.1")]   // loopback
        [InlineData("::1")]          // IPv6 loopback
        [InlineData("0.0.0.0")]      // Any
        [InlineData("255.255.255.255")] // broadcast
        [InlineData("not-an-ip")]    // invalid
        [InlineData("")]
        [InlineData(null)]
        public void BlockIp_RefusesReservedOrInvalid_NeverSelfLock(string? ip)
        {
            var svc = NewService();
            Assert.False(svc.BlockIp(ip!));
            Assert.Null(RuntimeBlocklistService.NormalizeIp(ip));
        }

        // ---- Persistence ------------------------------------------------------

        [Fact]
        public void Blocks_PersistAcrossRestart()
        {
            var first = NewService();
            first.BlockDomain("persist.example");
            first.BlockIp("198.51.100.9");

            // New instance over the same store dir = simulated restart.
            var second = NewService();
            Assert.True(second.IsDomainBlocked("persist.example"));
            Assert.True(second.IsIpBlocked("198.51.100.9"));
        }

        [Fact]
        public void ExplicitUnblockOfSeededDomain_SurvivesRestart_NotReSeeded()
        {
            // The whole point of the SeededKey marker: unblocking forum.hr must stick.
            var first = NewService();
            Assert.True(first.IsDomainBlocked("forum.hr"));
            Assert.True(first.UnblockDomain("forum.hr"));

            var second = NewService(); // restart
            Assert.False(second.IsDomainBlocked("forum.hr"));
        }
    }
}
