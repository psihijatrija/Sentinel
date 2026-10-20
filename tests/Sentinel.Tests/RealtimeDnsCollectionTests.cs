using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Threading;
using Microsoft.Extensions.Logging.Abstractions;
using Sentinel.Core;
using Xunit;

namespace Sentinel.Tests
{
    public class RealtimeDnsCollectionTests
    {
        [Theory]
        [InlineData(3006, "example.com")]
        [InlineData(3008, "example.com")]
        [InlineData(1001, null)]
        [InlineData(1002, null)]
        public void NativeDecoderRecognizesQueryEventsInsteadOfServerConfiguration(int eventId, string? expected)
        {
            const string name = "example.com";
            var payload = Marshal.StringToHGlobalUni(name);
            try
            {
                Assert.Equal(expected, EtwEventDispatcher.DecodeDnsQuery(new EtwRawEvent
                {
                    EventId = (ushort)eventId, UserData = payload, UserDataLength = (ushort)((name.Length + 1) * 2)
                }));
            }
            finally { Marshal.FreeHGlobal(payload); }
        }

        [Fact]
        public void RealTimeDnsWorksWithoutOpeningAMissingWindowsLogChannel()
        {
            var stream = new Stream { IsDnsProviderActive = true };
            var fallback = new LogSource { ThrowIfOpened = true };
            using var source = new UnifiedDnsEventSource(stream, fallback, NullLogger<UnifiedDnsEventSource>.Instance);
            source.Initialize(true);
            stream.Emit("first.example.com");
            Assert.Equal("first.example.com", Assert.Single(source.ReadQueries(CancellationToken.None)).Domain);
            Assert.Empty(source.ReadQueries(CancellationToken.None));
            Assert.Equal(0, fallback.Opens);
        }

        [Fact]
        public void ConsumerLossActivatesFallbackAndConsumerRecoveryResumesRealtime()
        {
            var stream = new Stream { IsDnsProviderActive = true };
            var fallback = new LogSource();
            using var source = new UnifiedDnsEventSource(stream, fallback, NullLogger<UnifiedDnsEventSource>.Instance);
            source.Initialize(true);
            stream.IsDnsProviderActive = false;
            Assert.Equal("log.example.com", Assert.Single(source.ReadQueries(CancellationToken.None)).Domain);
            Assert.Equal(1, fallback.Opens);
            stream.IsDnsProviderActive = true;
            stream.Emit("live.example.com");
            Assert.Equal("live.example.com", Assert.Single(source.ReadQueries(CancellationToken.None)).Domain);
        }

        [Fact]
        public void QueueOverflowIsBoundedAndReportedInsteadOfSilentlyDiscarded()
        {
            var stream = new Stream { IsDnsProviderActive = true };
            using var source = new UnifiedDnsEventSource(stream, new LogSource(), NullLogger<UnifiedDnsEventSource>.Instance);
            source.Initialize(true);
            for (int i = 0; i < 4097; i++) stream.Emit("example.com");
            Assert.Equal(1, source.DroppedQueries);
            Assert.Equal(4096, source.ReadQueries(CancellationToken.None).Count);
            Assert.True(source.LastReadHadLoss);
            Assert.Empty(source.ReadQueries(CancellationToken.None));
            Assert.False(source.LastReadHadLoss);
        }

        private sealed class Stream : IRealtimeDnsTelemetry
        {
            public bool IsDnsProviderActive { get; set; }
            public event Action<string>? DnsQueryObserved;
            public void Emit(string name) => DnsQueryObserved?.Invoke(name);
        }
        private sealed class LogSource : IDnsEventLogSource
        {
            public int Opens;
            public bool ThrowIfOpened;
            public void Initialize(bool mayEnableChannel)
            {
                Opens++;
                if (ThrowIfOpened) throw new InvalidOperationException("Windows log channel is absent.");
            }
            public IReadOnlyList<DnsQueryRecord> ReadQueries(CancellationToken ct) =>
                new[] { new DnsQueryRecord { RecordId = 1, Domain = "log.example.com" } };
        }
    }
}
