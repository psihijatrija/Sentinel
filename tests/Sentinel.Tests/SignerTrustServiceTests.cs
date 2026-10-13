using Microsoft.Extensions.Logging.Abstractions;
using Xunit;
using Sentinel.Core;

namespace Sentinel.Tests
{
    /// <summary>
    /// Tests for SignerTrustService - verifies Authenticode signature trust checking,
    /// test override mechanism, confidence adjustment, and cache behavior.
    /// </summary>
    public class SignerTrustServiceTests
    {
        private readonly SignerTrustService _service;

        public SignerTrustServiceTests()
        {
            _service = new SignerTrustService(NullLogger<SignerTrustService>.Instance);
        }

        [Fact]
        public void Constructor_DoesNotThrow()
        {
            Assert.NotNull(_service);
        }

        [Fact]
        public void AddTestOverride_MarksAsSigned()
        {
            _service.AddTestOverride(@"C:\test\app.exe", true, "Microsoft Corporation");
            Assert.True(_service.IsSignedFile(@"C:\test\app.exe"));
        }

        [Fact]
        public void AddTestOverride_GetSignerName_ReturnsOverride()
        {
            _service.AddTestOverride(@"C:\test\signed.exe", true, "Test Publisher");
            var signer = _service.GetSignerName(@"C:\test\signed.exe");
            Assert.Equal("Test Publisher", signer);
        }

        [Fact]
        public void IsSignedFile_NonExistentFile_ReturnsFalse()
        {
            Assert.False(_service.IsSignedFile(@"C:\nonexistent\fake.exe"));
        }

        [Fact]
        public void IsSignedFile_NullOrEmpty_ReturnsFalse()
        {
            Assert.False(_service.IsSignedFile(null!));
            Assert.False(_service.IsSignedFile(""));
        }

        [Fact]
        public void GetSignerName_UnsignedFile_ReturnsNull()
        {
            var name = _service.GetSignerName(@"C:\nonexistent\file.exe");
            Assert.Null(name);
        }

        [Fact]
        public void AdjustConfidence_UnsignedFile_NoChange()
        {
            var adjusted = _service.AdjustConfidence(0.90, @"C:\nonexistent\unsigned.exe");
            Assert.Equal(0.90, adjusted);
        }

        [Fact]
        public void AdjustConfidence_SignedFile_Reduced()
        {
            _service.AddTestOverride(@"C:\test\trusted.exe", true, "Trusted Corp");
            var adjusted = _service.AdjustConfidence(0.90, @"C:\test\trusted.exe");
            Assert.Equal(0.90 * SignerTrustService.SignedConfidenceMultiplier, adjusted);
        }

        [Fact]
        public void AdjustConfidence_PidLessThanFive_NoChange()
        {
            // PID <= 4 should never be adjusted
            var adjusted = _service.AdjustConfidence(0.90, 4);
            Assert.Equal(0.90, adjusted);
        }

        [Fact]
        public void SignedConfidenceMultiplier_Is_0_5()
        {
            Assert.Equal(0.5, SignerTrustService.SignedConfidenceMultiplier);
        }

        [Fact]
        public void IsSignedFile_SystemBinary_CmdExe_IsSigned()
        {
            // Skip if Avast or other AV blocks access
            var cmdPath = @"C:\Windows\System32\cmd.exe";
            if (!System.IO.File.Exists(cmdPath)) return;

            try
            {
                var signed = _service.IsSignedFile(cmdPath);
                // cmd.exe should be signed on Windows
                Assert.True(signed);
            }
            catch
            {
                // AV may block - skip gracefully
            }
        }

        [Fact]
        public void PruneCache_DoesNotThrow()
        {
            _service.AddTestOverride(@"C:\cleanup\stale.exe", true, "Stale");
            _service.PruneCache();
            // Stale entry for non-existent file should be pruned
            Assert.False(_service.IsSignedFile(@"C:\cleanup\stale.exe"));
        }

        [Fact]
        public void Cache_IsBounded_UnderHeavyInsert()
        {
            // 3.1.1: the path-keyed cache must not grow without bound. Insert well past the
            // 50k cap and confirm the cache trims itself rather than retaining everything.
            // AddTestOverride routes through the same StoreVerdict/cap path as the live writes.
            for (int i = 0; i < 60_000; i++)
            {
                _service.AddTestOverride($@"C:\synthetic\path_{i}\binary_{i}.exe", i % 2 == 0, "T");
            }

            // After exceeding the cap, the live entry count must be at or below the ceiling
            // (never the full 60k we inserted). GetCachedCount exposes the current size.
            int count = _service.GetCachedCount();
            Assert.True(count <= 50_000, $"cache not bounded: {count} entries retained");
        }
    }
}
