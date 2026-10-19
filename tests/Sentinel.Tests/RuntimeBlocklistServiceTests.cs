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
    /// persistence round-trip, and that an explicit unblock of a blocked domain survives a
    /// restart (is not silently re-seeded).
    ///
    /// v3.1.3: forum.hr removed from DefaultSeedDomains. Tests updated accordingly.
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
        public void FirstRun_NoDefaultSeedDomains_EmptyBlocklist()
        {
            // v3.1.3: DefaultSeedDomains is empty; a fresh instance has no blocked domains.
            var svc = NewService();
            Assert.False(svc.IsDomainBlocked("forum.hr"));
            Assert.Empty(svc.GetBlockedDomains());
        }

        [Fact]
        public void ForumHr_IsNotBlockedByDefault_V313()
        {
            // forum.hr was removed from the default seed in v3.1.3.
            // Reverse shell detection (NetworkFacingParentShellRule / RawSocketRedirectRule)
            // now covers the threat class that justified the domain block.
            var svc = NewService();
            Assert.False(svc.IsDomainBlocked("forum.hr"));
            Assert.False(svc.IsDomainBlocked("https://forum.hr/thread"));
        }

        [Fact]
        public void ForumHr_IsEvictedOnLoad_WhenPreviouslyPersisted()
        {
            // Simulate an existing install that has forum.hr in its persisted cache
            // (written by a pre-v3.1.3 seed). On the next Load() it must be evicted automatically.
            var store = new SecureCacheStore(_tempDir);
            // Manually write forum.hr into the cache as if the old version had seeded it.
            store.Save("blocklist-domains", "v1",
                System.Text.Json.JsonSerializer.Serialize(new[] { "forum.hr" }));
            store.Save("blocklist-seeded", "v1", "1"); // marker already set

            var svc = new RuntimeBlocklistService(store, NullLogger<RuntimeBlocklistService>.Instance);
            Assert.False(svc.IsDomainBlocked("forum.hr")); // must have been evicted on load

            // Verify it also no longer persists — a second load must not bring it back.
            var svc2 = new RuntimeBlocklistService(store, NullLogger<RuntimeBlocklistService>.Instance);
            Assert.False(svc2.IsDomainBlocked("forum.hr"));
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
            Assert.True(first.BlockDomain("persist.example"));
            Assert.True(first.BlockIp("198.51.100.9"));

            // New instance over the same store dir = simulated restart.
            var second = NewService();
            Assert.True(second.IsDomainBlocked("persist.example"));
            Assert.True(second.IsIpBlocked("198.51.100.9"));
        }

        [Fact]
        public void ExplicitBlock_ThenUnblock_SurvivesRestart_NotReSeeded()
        {
            // Explicitly blocked domains that are later unblocked must not come back on restart.
            var first = NewService();
            Assert.True(first.BlockDomain("example.com"));
            Assert.True(first.UnblockDomain("example.com"));

            var second = NewService(); // restart
            Assert.False(second.IsDomainBlocked("example.com"));
        }
    }
}
