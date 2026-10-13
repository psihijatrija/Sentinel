using Xunit;
using Sentinel.Core;

namespace Sentinel.Tests
{
    /// <summary>
    /// Tests for DNS monitoring detection models and signal types.
    /// DnsQueryMonitor requires complex DI (DetectionEngine + SentinelConfig + PersistentConnectionMonitor),
    /// so we test the observable data model and enum behavior.
    /// </summary>
    public class DnsQueryMonitorTests
    {
        [Fact]
        public void DnsAnomalyType_HasExpectedValues()
        {
            Assert.Equal(0, (int)DnsAnomalyType.HighEntropySubdomain);
            Assert.Equal(1, (int)DnsAnomalyType.RapidQueryVolume);
            Assert.Equal(2, (int)DnsAnomalyType.DoHBypass);
        }

        [Theory]
        [InlineData(0)]
        [InlineData(4)]
        public void ResolveDnsProcessName_LowPid_IsSystem(int pid)
        {
            Assert.Equal("SYSTEM", DnsQueryMonitor.ResolveDnsProcessName(pid));
        }

        [Fact]
        public void ResolveDnsProcessName_CurrentProcess_IsNotUnknown()
        {
            int pid = System.Diagnostics.Process.GetCurrentProcess().Id;
            var name = DnsQueryMonitor.ResolveDnsProcessName(pid);
            Assert.False(string.IsNullOrWhiteSpace(name));
            Assert.NotEqual("SYSTEM", name);
            Assert.NotEqual("unknown", name);
        }

        [Fact]
        public void ResolveDnsProcessName_DeadPid_IsUnknown()
        {
            Assert.Equal("unknown", DnsQueryMonitor.ResolveDnsProcessName(int.MaxValue - 7));
        }

        [Fact]
        public void DnsAnomalySignal_Properties_SetCorrectly()
        {
            var signal = new DnsAnomalySignal
            {
                ProcessId = 1234,
                ProcessName = "malware.exe",
                SourceMonitor = "DnsQueryMonitor",
                Domain = "x8a3kf9.evil.tk",
                AnomalyType = DnsAnomalyType.HighEntropySubdomain,
                Entropy = 4.8,
                QueryCount = 50,
                ResolverIp = "8.8.8.8"
            };

            Assert.Equal("x8a3kf9.evil.tk", signal.Domain);
            Assert.Equal(DnsAnomalyType.HighEntropySubdomain, signal.AnomalyType);
            Assert.Equal(4.8, signal.Entropy);
            Assert.Equal(50, signal.QueryCount);
            Assert.Equal("8.8.8.8", signal.ResolverIp);
        }

        [Fact]
        public void DnsAnomalySignal_NullResolverIp_IsAllowed()
        {
            var signal = new DnsAnomalySignal
            {
                Domain = "test.com",
                ResolverIp = null
            };
            Assert.Null(signal.ResolverIp);
        }

        [Fact]
        public void HighEntropyDomain_ConceptualValidation()
        {
            // DGA domains have high entropy (4.0+); legit domains have lower entropy
            // This validates the principle used by the monitor
            double CalculateEntropy(string s)
            {
                if (string.IsNullOrEmpty(s)) return 0;
                var freq = new int[256];
                foreach (var c in s) freq[c]++;
                double ent = 0, len = s.Length;
                for (int i = 0; i < 256; i++)
                {
                    if (freq[i] == 0) continue;
                    double p = freq[i] / len;
                    ent -= p * System.Math.Log(p, 2);
                }
                return ent;
            }

            var dgaDomain = "x8a3kf9qw2lz7.evil.tk";
            var legitDomain = "www.google.com";

            var dgaEntropy = CalculateEntropy(dgaDomain);
            var legitEntropy = CalculateEntropy(legitDomain);

            Assert.True(dgaEntropy > legitEntropy, "DGA domains should have higher entropy");
        }
    }
}
