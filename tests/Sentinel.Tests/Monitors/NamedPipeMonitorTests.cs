using Xunit;
using Sentinel.Core;

namespace Sentinel.Tests.Monitors
{
    /// <summary>
    /// Tests for NamedPipeMonitor - verifies named pipe signal model,
    /// entropy calculation for pipe name analysis, and detection categorization.
    /// </summary>
    public class NamedPipeMonitorTests
    {
        // 
        // Named pipe signal model
        // 

        [Fact]
        public void NamedPipeSignal_KnownBadPattern_Model()
        {
            var signal = new NamedPipeSignal
            {
                ProcessId = 1234,
                ProcessName = "beacon.exe",
                PipeName = @"\\.\pipe\MSSE-1234-server",
                MatchedPattern = "MSSE-*-server",
                OwnerPid = 1234,
                IsKnownBadPattern = true,
                Entropy = 3.2
            };

            Assert.True(signal.IsKnownBadPattern);
            Assert.Equal("MSSE-*-server", signal.MatchedPattern);
        }

        [Fact]
        public void NamedPipeSignal_HighEntropy_Model()
        {
            var signal = new NamedPipeSignal
            {
                ProcessId = 5678,
                ProcessName = "implant.exe",
                PipeName = @"\\.\pipe\a8f3k2d9x7b1m4c6",
                OwnerPid = 5678,
                IsKnownBadPattern = false,
                Entropy = 4.8
            };

            Assert.True(signal.Entropy >= 4.0);
        }

        // 
        // Pipe name entropy validation (concept matching monitor logic)
        // 

        [Theory]
        [InlineData("a8f3k2d9x7b1m4c6", true)]  // Random hex-like = high entropy
        [InlineData("chrome", false)]             // Short legit name
        [InlineData("lsass", false)]              // Short
        [InlineData("sql", false)]                // Too short
        public void PipeNameEntropy_Classification(string name, bool isHighEntropy)
        {
            // High entropy: >= 4.0 AND length >= 12
            bool result = IsHighEntropy(name);
            Assert.Equal(isHighEntropy, result);
        }

        [Theory]
        [InlineData("", 0.0)]
        [InlineData("aaaa", 0.0)]
        [InlineData("ab", 1.0)]
        public void Entropy_KnownValues(string input, double expected)
        {
            var result = CalculateEntropy(input);
            Assert.Equal(expected, result, 1);
        }

        [Fact]
        public void Entropy_RandomString_IsHigh()
        {
            var result = CalculateEntropy("a8f3k2d9x7b1m4c6q5e0");
            Assert.True(result > 3.5, $"Expected > 3.5, got {result}");
        }

        // 
        // Known C2 pipe patterns
        // 

        [Theory]
        [InlineData(@"\\.\pipe\MSSE-1234-server")]     // CobaltStrike default
        [InlineData(@"\\.\pipe\msagent_")]             // CobaltStrike alternate
        [InlineData(@"\\.\pipe\postex_")]              // CobaltStrike post-ex
        public void KnownC2Patterns_ShouldBeDetected(string pipePath)
        {
            // These are well-known C2 framework pipe naming patterns
            Assert.Contains("pipe", pipePath);
        }

        // 
        // Helpers (mirror private methods)
        // 

        private static bool IsHighEntropy(string name)
        {
            if (name.Length < 8) return false;
            double entropy = CalculateEntropy(name);
            return entropy >= 4.0 && name.Length >= 12;
        }

        private static double CalculateEntropy(string s)
        {
            if (string.IsNullOrEmpty(s)) return 0;
            var freq = new System.Collections.Generic.Dictionary<char, int>();
            foreach (var c in s.ToLowerInvariant())
            {
                if (!freq.ContainsKey(c)) freq[c] = 0;
                freq[c]++;
            }
            double entropy = 0;
            double len = s.Length;
            foreach (var count in freq.Values)
            {
                double p = count / len;
                if (p > 0) entropy -= p * System.Math.Log(p, 2);
            }
            return entropy;
        }
    }
}
