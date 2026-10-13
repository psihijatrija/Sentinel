using System.Collections.Generic;
using Xunit;
using Sentinel.Core;

namespace Sentinel.Tests
{
    public class IoCScannerTests
    {
        private IoCScanner CreateScanner()
        {
            var cache = new SecureCacheStore(System.IO.Path.GetTempPath());
            return new IoCScanner(cache);
        }

        [Fact]
        public void IsKnownBadHash_ReturnsFalse_WhenEmpty()
        {
            var scanner = CreateScanner();
            Assert.False(scanner.IsKnownBadHash("abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234"));
        }

        [Fact]
        public void UpdateHashes_ThenIsKnownBadHash_ReturnsTrue()
        {
            var scanner = CreateScanner();
            var hash = "a94a8fe5ccb19ba61c4c0873d391e987982fbbd3a94a8fe5ccb19ba61c4c0873";
            scanner.UpdateHashes(new[] { hash });
            Assert.True(scanner.IsKnownBadHash(hash));
        }

        [Fact]
        public void UpdateHashes_CaseInsensitive()
        {
            var scanner = CreateScanner();
            var hash = "A94A8FE5CCB19BA61C4C0873D391E987982FBBD3A94A8FE5CCB19BA61C4C0873";
            scanner.UpdateHashes(new[] { hash.ToLowerInvariant() });
            Assert.True(scanner.IsKnownBadHash(hash));
        }

        [Fact]
        public void UpdateHashes_ClearsOldHashes()
        {
            var scanner = CreateScanner();
            var hash1 = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
            var hash2 = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
            scanner.UpdateHashes(new[] { hash1 });
            Assert.True(scanner.IsKnownBadHash(hash1));

            scanner.UpdateHashes(new[] { hash2 });
            Assert.False(scanner.IsKnownBadHash(hash1));
            Assert.True(scanner.IsKnownBadHash(hash2));
        }

        [Fact]
        public void IsKnownBadHash_ReturnsFalse_ForPartialMatch()
        {
            var scanner = CreateScanner();
            var hash = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
            scanner.UpdateHashes(new[] { hash });
            Assert.False(scanner.IsKnownBadHash("cccccccccccc")); // Too short
        }
    }
}
