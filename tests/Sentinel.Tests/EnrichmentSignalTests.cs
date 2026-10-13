using System;
using System.Threading;
using Xunit;
using Sentinel.Core;

namespace Sentinel.Tests
{
    public class EnrichmentSignalTests
    {
        [Fact]
        public void IsExpired_ReturnsFalse_WhenFresh()
        {
            var signal = new NetworkC2Signal
            {
                ProcessId = 1,
                ProcessName = "test",
                Ttl = TimeSpan.FromMinutes(5)
            };

            Assert.False(signal.IsExpired);
        }

        [Fact]
        public void IsExpired_ReturnsTrue_WhenPastTtl()
        {
            var signal = new NetworkC2Signal
            {
                ProcessId = 1,
                ProcessName = "test",
                Timestamp = DateTimeOffset.UtcNow - TimeSpan.FromMinutes(10),
                Ttl = TimeSpan.FromMinutes(5)
            };

            Assert.True(signal.IsExpired);
        }

        [Fact]
        public void IsExpired_ReturnsTrue_WhenVeryShortTtl()
        {
            var signal = new GhostProcessSignal
            {
                ProcessId = 1,
                ProcessName = "ghost",
                Ttl = TimeSpan.FromMilliseconds(1)
            };

            Thread.Sleep(10);
            Assert.True(signal.IsExpired);
        }

        [Fact]
        public void NetworkC2Signal_Properties_SetCorrectly()
        {
            var signal = new NetworkC2Signal
            {
                ProcessId = 42,
                ProcessName = "beacon.exe",
                SourceMonitor = "BeaconingDetector",
                RemoteAddress = "10.0.0.1",
                RemotePort = 443,
                CoefficientOfVariation = 0.05,
                MeanIntervalSeconds = 30.0,
                Confidence = 0.92,
                ObservationCount = 15
            };

            Assert.Equal(42, signal.ProcessId);
            Assert.Equal("beacon.exe", signal.ProcessName);
            Assert.Equal("BeaconingDetector", signal.SourceMonitor);
            Assert.Equal("10.0.0.1", signal.RemoteAddress);
            Assert.Equal(443, signal.RemotePort);
            Assert.Equal(0.05, signal.CoefficientOfVariation);
            Assert.Equal(30.0, signal.MeanIntervalSeconds);
            Assert.Equal(0.92, signal.Confidence);
            Assert.Equal(15, signal.ObservationCount);
        }

        [Fact]
        public void GhostProcessSignal_Properties_SetCorrectly()
        {
            var signal = new GhostProcessSignal
            {
                ProcessId = 99,
                ProcessName = "ghost",
                Destinations = { "1.2.3.4", "5.6.7.8" },
                ScansSeen = 5,
                ConnectsToBlockedDevice = true,
                HasSuspiciousPort = false
            };

            Assert.Equal(2, signal.Destinations.Count);
            Assert.Equal(5, signal.ScansSeen);
            Assert.True(signal.ConnectsToBlockedDevice);
            Assert.False(signal.HasSuspiciousPort);
        }

        [Fact]
        public void DnsAnomalySignal_Properties_SetCorrectly()
        {
            var signal = new DnsAnomalySignal
            {
                Domain = "asdkj2342.evil.tk",
                AnomalyType = DnsAnomalyType.HighEntropySubdomain,
                Entropy = 4.2,
                QueryCount = 100,
                ResolverIp = "8.8.8.8"
            };

            Assert.Equal("asdkj2342.evil.tk", signal.Domain);
            Assert.Equal(DnsAnomalyType.HighEntropySubdomain, signal.AnomalyType);
            Assert.Equal(4.2, signal.Entropy);
        }

        [Fact]
        public void ExfiltrationSpikeSignal_Properties_SetCorrectly()
        {
            var signal = new ExfiltrationSpikeSignal
            {
                ProcessId = 0,
                ProcessName = "SYSTEM",
                BytesDelta = 50_000_000,
                BaselineRate = 5_000_000,
                SpikeMultiplier = 10.0,
                Interval = TimeSpan.FromSeconds(15)
            };

            Assert.Equal(50_000_000, signal.BytesDelta);
            Assert.Equal(10.0, signal.SpikeMultiplier);
        }

        [Fact]
        public void FileVerdictSignal_Properties_SetCorrectly()
        {
            var signal = new FileVerdictSignal
            {
                FilePath = @"C:\test.exe",
                Sha256 = "abcdef123456",
                CompositeScore = 75,
                Verdict = FileVerdict.Malicious,
                IsSigned = false,
                SignerName = null
            };

            Assert.Equal(@"C:\test.exe", signal.FilePath);
            Assert.Equal(FileVerdict.Malicious, signal.Verdict);
            Assert.False(signal.IsSigned);
        }

        [Fact]
        public void CredentialAccessSignal_Properties_SetCorrectly()
        {
            var signal = new CredentialAccessSignal
            {
                TargetName = "Exchange_SMTP_Relay_abc123",
                AccessType = CredentialAccessType.CanaryDeleted
            };

            Assert.Equal(CredentialAccessType.CanaryDeleted, signal.AccessType);
        }

        [Fact]
        public void NamedPipeSignal_Properties_SetCorrectly()
        {
            var signal = new NamedPipeSignal
            {
                PipeName = @"\\.\pipe\evil_c2",
                MatchedPattern = "evil_c2",
                OwnerPid = 1234,
                IsKnownBadPattern = true,
                Entropy = 3.8
            };

            Assert.True(signal.IsKnownBadPattern);
            Assert.Equal(3.8, signal.Entropy);
        }

        [Fact]
        public void TokenTheftSignal_Properties_SetCorrectly()
        {
            var signal = new TokenTheftSignal
            {
                TokenUserName = "NT AUTHORITY\\SYSTEM",
                TheftType = TokenTheftType.SystemTokenFromUserProcess,
                ImagePath = @"C:\Temp\evil.exe",
                HasImpersonatePrivilege = true
            };

            Assert.Equal(TokenTheftType.SystemTokenFromUserProcess, signal.TheftType);
            Assert.True(signal.HasImpersonatePrivilege);
        }

        [Fact]
        public void DefaultTtl_IsFiveMinutes()
        {
            var signal = new NetworkC2Signal { ProcessId = 1, ProcessName = "x" };
            Assert.Equal(TimeSpan.FromMinutes(5), signal.Ttl);
        }

        [Fact]
        public void Timestamp_DefaultsToUtcNow()
        {
            var before = DateTimeOffset.UtcNow;
            var signal = new NetworkC2Signal { ProcessId = 1, ProcessName = "x" };
            var after = DateTimeOffset.UtcNow;

            Assert.True(signal.Timestamp >= before);
            Assert.True(signal.Timestamp <= after);
        }
    }
}
