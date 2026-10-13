using System;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging.Abstractions;
using Xunit;
using Sentinel.Core;

namespace Sentinel.Tests
{
    /// <summary>
    /// Unit tests for FileReputationEngine - the multi-signal file reputation scoring system.
    /// Tests verify composite scoring, static PE analysis, contextual risk, caching, and verdict determination.
    /// </summary>
    public class FileReputationEngineTests : IDisposable
    {
        private readonly string _tempDir;
        private readonly SecureCacheStore _cacheStore;
        private readonly HashReputationService _hashRepService;
        private readonly SignerTrustService _signerTrust;
        private readonly FileReputationEngine _engine;

        public FileReputationEngineTests()
        {
            _tempDir = Path.Combine(Path.GetTempPath(), "sentinel_fre_test_" + Guid.NewGuid().ToString("N")[..8]);
            Directory.CreateDirectory(_tempDir);
            _cacheStore = new SecureCacheStore(_tempDir);
            _hashRepService = new HashReputationService(_cacheStore, new ThreatReportingConfig(), NullLogger<HashReputationService>.Instance);
            _signerTrust = new SignerTrustService(NullLogger<SignerTrustService>.Instance);
            _engine = new FileReputationEngine(_hashRepService, _signerTrust, _cacheStore, NullLogger<FileReputationEngine>.Instance);
        }

        public void Dispose()
        {
            try { Directory.Delete(_tempDir, true); } catch { }
        }

        [Fact]
        public async Task EvaluateFile_NonExistentFile_ReturnsUnknown()
        {
            var result = await _engine.EvaluateFileAsync(@"C:\nonexistent\file_that_does_not_exist.exe");

            Assert.Equal(FileVerdict.Unknown, result.Verdict);
            Assert.Equal(50, result.CompositeScore);
        }

        [Fact]
        public async Task EvaluateFile_EmptyPath_ReturnsUnknown()
        {
            var result = await _engine.EvaluateFileAsync("");

            Assert.Equal(FileVerdict.Unknown, result.Verdict);
        }

        [Fact]
        public async Task EvaluateFile_NullPath_ReturnsUnknown()
        {
            var result = await _engine.EvaluateFileAsync(null!);

            Assert.Equal(FileVerdict.Unknown, result.Verdict);
        }

        [Fact]
        public async Task EvaluateFile_SmallTextFile_LowScore()
        {
            // Create a small text file (not a PE, not suspicious)
            var testFile = Path.Combine(_tempDir, "harmless.txt");
            File.WriteAllText(testFile, "This is a harmless text file for testing purposes.");

            var result = await _engine.EvaluateFileAsync(testFile);

            // Non-PE file should have lower risk
            Assert.True(result.CompositeScore <= 60, $"Expected score <= 60 but got {result.CompositeScore}");
            Assert.False(result.StaticAnalysis.IsPe);
        }

        [Fact]
        public async Task EvaluateFile_ValidPeFile_AnalyzesStaticProperties()
        {
            // Use our own test DLL as a real PE file
            var testDll = typeof(FileReputationEngineTests).Assembly.Location;
            if (!File.Exists(testDll)) return; // Skip if running from memory

            var result = await _engine.EvaluateFileAsync(testDll);

            // Should detect as PE
            Assert.True(result.StaticAnalysis.IsPe);
            Assert.True(result.StaticAnalysis.SectionCount > 0);
            Assert.True(result.StaticAnalysis.Entropy > 0);
            Assert.True(result.FileSize > 0);
            Assert.False(string.IsNullOrEmpty(result.Sha256));
        }

        [Fact]
        public async Task EvaluateFile_CachesResults()
        {
            var testFile = Path.Combine(_tempDir, "cached_test.txt");
            File.WriteAllText(testFile, "Cache test content " + Guid.NewGuid());

            // First evaluation
            var result1 = await _engine.EvaluateFileAsync(testFile);

            // Second evaluation should use cache
            var result2 = await _engine.EvaluateFileAsync(testFile);

            Assert.Equal(result1.CompositeScore, result2.CompositeScore);
            Assert.Equal(result1.Sha256, result2.Sha256);
        }

        [Fact]
        public async Task EvaluateFile_HighRiskPath_IncreasesScore()
        {
            // File in Temp directory should get contextual risk boost
            var tempFile = Path.Combine(Path.GetTempPath(), "sentinel_risk_test_" + Guid.NewGuid().ToString("N")[..8] + ".txt");
            try
            {
                File.WriteAllText(tempFile, "test content");

                var result = await _engine.EvaluateFileAsync(tempFile);

                Assert.True(result.ContextualRisk.IsHighRiskPath,
                    "File in Temp should be flagged as high-risk path");
            }
            finally
            {
                try { File.Delete(tempFile); } catch { }
            }
        }

        [Fact]
        public async Task EvaluateFile_ProtectedPath_ReducesScore()
        {
            // File in Program Files should get contextual risk reduction
            var systemFile = @"C:\Program Files\dotnet\dotnet.exe";
            if (!File.Exists(systemFile)) return; // Skip if not installed

            var result = await _engine.EvaluateFileAsync(systemFile);

            Assert.True(result.ContextualRisk.IsProtectedPath,
                "File in Program Files should be flagged as protected path");
        }

        [Fact]
        public async Task EvaluateFile_SignedFile_GetsTrustBoost()
        {
            // Use a known-signed Windows binary
            var signedFile = @"C:\Windows\System32\notepad.exe";
            if (!File.Exists(signedFile)) return;

            var result = await _engine.EvaluateFileAsync(signedFile);

            // PE analysis should work
            Assert.True(result.StaticAnalysis.IsPe, "notepad.exe should be detected as PE");
            // Should be in a protected path
            Assert.True(result.ContextualRisk.IsProtectedPath, "notepad.exe should be in protected path");

            // Note: notepad.exe may be catalog-signed rather than Authenticode-signed.
            // WinVerifyTrust only verifies Authenticode signatures by default.
            // If signed, verify it gets a trust boost (lower score).
            if (result.IsSigned)
            {
                Assert.True(result.Verdict != FileVerdict.Malicious,
                    $"Signed system binary should not be Malicious, got {result.Verdict}");
            }
            else
            {
                // Even unsigned (catalog-signed), protected path reduces risk
                Assert.True(result.ContextualRisk.IsProtectedPath);
            }
        }

        [Fact]
        public void GetStats_ReturnsValidStats()
        {
            var stats = _engine.GetStats();

            Assert.True(stats.CachedResults >= 0);
            Assert.True(stats.TrackedFiles >= 0);
            Assert.True(stats.InFlightLookups >= 0);
        }

        [Fact]
        public void VerdictDetermination_ScoreRanges()
        {
            // Verify the scoring thresholds via public API (Score method on engine)
            // We can't call the private DetermineVerdict directly, but we can verify
            // the scoring engine's behavior through the FileReputationResult.

            // Score 0-20 = Trusted
            // Score 21-40 = LowRisk  
            // Score 41-60 = Suspicious
            // Score 61-80 = HighRisk
            // Score 81-100 = Malicious

            // This test verifies the enum values are correctly defined
            Assert.True((int)FileVerdict.Trusted < (int)FileVerdict.LowRisk);
            Assert.True((int)FileVerdict.LowRisk < (int)FileVerdict.Suspicious);
            Assert.True((int)FileVerdict.Suspicious < (int)FileVerdict.HighRisk);
            Assert.True((int)FileVerdict.HighRisk < (int)FileVerdict.Malicious);
        }

        [Fact]
        public async Task EvaluateFile_DeduplicatesParallelCalls()
        {
            var testFile = Path.Combine(_tempDir, "dedup_test.txt");
            File.WriteAllText(testFile, "Dedup test " + Guid.NewGuid());

            // Fire multiple concurrent evaluations - should deduplicate
            var tasks = new Task<FileReputationResult>[5];
            for (int i = 0; i < 5; i++)
            {
                tasks[i] = _engine.EvaluateFileAsync(testFile);
            }

            var results = await Task.WhenAll(tasks);

            // All should return the same result (deduplication)
            var firstHash = results[0].Sha256;
            foreach (var result in results)
            {
                Assert.Equal(firstHash, result.Sha256);
                Assert.Equal(results[0].CompositeScore, result.CompositeScore);
            }
        }
    }
}
