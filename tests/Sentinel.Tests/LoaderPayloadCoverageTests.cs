using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Sentinel.Core;
using Xunit;

namespace Sentinel.Tests
{
    [Collection("ResponsePolicy")]
    public class LoaderPayloadCoverageTests
    {
        internal static byte[] Header()
        {
            var bytes = new byte[4096];
            bytes[0] = (byte)'M'; bytes[1] = (byte)'Z';
            void Write(int offset, byte[] value) => Array.Copy(value, 0, bytes, offset, value.Length);
            Write(0x3c, BitConverter.GetBytes(128));
            Write(128, BitConverter.GetBytes(0x00004550));
            Write(132, BitConverter.GetBytes((ushort)0x8664));
            Write(134, BitConverter.GetBytes((ushort)3));
            Write(148, BitConverter.GetBytes((ushort)240));
            Write(152, BitConverter.GetBytes((ushort)0x20b));
            Write(208, BitConverter.GetBytes(0x4000));
            // One executable section at RVA 0x1000, within SizeOfImage.
            Write(392 + 8, BitConverter.GetBytes(0x1000));
            Write(392 + 12, BitConverter.GetBytes(0x1000));
            Write(392 + 36, BitConverter.GetBytes(0x60000020u));
            return bytes;
        }

        private static NativeProcessMemory.MEMORY_BASIC_INFORMATION Region(long start, long allocation,
            uint protection, uint type = 0x20000) => new()
        {
            BaseAddress = new IntPtr(start), AllocationBase = new IntPtr(allocation),
            RegionSize = new IntPtr(4096), State = NativeProcessMemory.MEM_COMMIT,
            Type = type, Protect = protection
        };

        private static IReadOnlyList<UnbackedPeScanner.Payload> Scan(uint protection, byte[]? header,
            uint type = 0x20000, long codeAddress = 8192)
        {
            var map = new Dictionary<ulong, NativeProcessMemory.MEMORY_BASIC_INFORMATION>
            {
                [4096] = Region(4096, 4096, 0x02, type), // non-executable PE headers
                [(ulong)codeAddress] = Region(codeAddress, 4096, protection, type)
            };
            // For the gap case advance to the code region without reading the gap.
            var head = map[4096]; head.RegionSize = new IntPtr(codeAddress - 4096); map[4096] = head;
            return UnbackedPeScanner.Scan(address => map.TryGetValue(address, out var value) ? value :
                (NativeProcessMemory.MEMORY_BASIC_INFORMATION?)null, _ => header, CancellationToken.None, 4096);
        }

        [Theory]
        [InlineData(0x10u)]
        [InlineData(0x20u)]
        [InlineData(0x40u)]
        [InlineData(0x80u)]
        public void ExecutableSectionsFindPeAtReadonlyAllocationBase(uint protection)
        {
            var payload = Assert.Single(Scan(protection, Header()));
            Assert.Equal(4096ul, payload.Allocation);
            Assert.Equal(8192ul, payload.ExecutablePage);
            Assert.Equal(protection, payload.Protection);
        }

        [Theory]
        [InlineData(0x120u, 0x20000u)] // guard
        [InlineData(0x04u, 0x20000u)] // non-executable data
        [InlineData(0x20u, 0x1000000u)] // normal loaded image, including Qt
        [InlineData(0x20u, 0x40000u)] // mapped file
        public void GuardDataAndNormalImageMappingsAreNotPrivatePayloads(uint protection, uint type)
            => Assert.Empty(Scan(protection, Header(), type));

        [Fact]
        public void JitMzOnlyUnreadableAndOutOfImagePagesCannotSupplyPeEvidence()
        {
            var bytes = Header(); bytes[128] = 0;
            Assert.Empty(Scan(0x20, bytes));
            Assert.Empty(Scan(0x20, new byte[4096]));
            Assert.Empty(Scan(0x20, null));
            Assert.Empty(Scan(0x20, new byte[] { 77, 90 }));
            Assert.Empty(Scan(0x20, Header(), codeAddress: 0x9000));
        }

        [Fact]
        public void PeShapedDataWithoutExecutableSectionOrCompleteSectionTableIsNotEvidence()
        {
            var noCode = Header(); Array.Clear(noCode, 392 + 36, 4);
            Assert.Empty(Scan(0x20, noCode));
            var oversized = Header(); Array.Copy(BitConverter.GetBytes(uint.MaxValue), 0, oversized, 392 + 8, 4);
            Assert.Empty(Scan(0x20, oversized));
            var incomplete = Header(); Array.Resize(ref incomplete, 400);
            Assert.Empty(Scan(0x20, incomplete));
        }

        [Fact]
        public void WalkIsCancellableAndRejectsNonAdvancingAddressData()
        {
            using var stop = new CancellationTokenSource(); stop.Cancel();
            Assert.Throws<OperationCanceledException>(() => UnbackedPeScanner.Scan(_ => null, _ => null, stop.Token));
            int queries = 0;
            Assert.Empty(UnbackedPeScanner.Scan(_ => { queries++; return new NativeProcessMemory.MEMORY_BASIC_INFORMATION(); },
                _ => throw new Exception("No read expected"), CancellationToken.None));
            Assert.Equal(1, queries);
        }

        [Fact]
        public void HeaderInspectionAndReportedPayloadsHaveHardCaps()
        {
            int reads = 0;
            IReadOnlyList<UnbackedPeScanner.Payload> Run(bool valid) => UnbackedPeScanner.Scan(address =>
            {
                if (address >= 1000ul * 4096) return null;
                var region = Region((long)address, (long)address, 0x40);
                region.RegionSize = new IntPtr(8192);
                return region;
            },
                _ => { reads++; return valid ? Header() : new byte[4096]; }, CancellationToken.None, 4096);
            Assert.Empty(Run(false));
            Assert.InRange(reads, 1, 128);
            reads = 0;
            Assert.Equal(8, Run(true).Count);
            Assert.Equal(8, reads);
        }

        [Theory]
        [InlineData("Quantum-Suite")]
        [InlineData("arbitrary-host")]
        [InlineData("chrome")]
        public async Task ScannedTargetPeAndRealCredentialReadAuthorizeOnlyTarget(string name)
        {
            ResponsePolicy.ResetForTests();
            var created = DateTime.UtcNow.AddHours(-1).ToFileTimeUtc();
            var payload = EtwThreatIntelMonitor.CreatePayloadObservation(4242, name, @"C:\Apps\host.exe",
                created, Scan(0x20, Header()), DateTime.UtcNow);
            ResponsePolicy.EnforceDispatchPolicy(payload);
            Assert.Equal(DetectionTier.Tier2Indicator, payload.Tier);
            Assert.Equal(ResponseAction.LogOnly, payload.AuthorizedResponse);
            Assert.Null(ResponsePolicy.ClassifyTerminalOutcome(payload));
            var read = Read(created);
            var engine = new BehavioralCorrelationEngine(_ => null, _ => created);
            var results = new List<DetectionEvent>();
            engine.Initialize(e => { results.Add(e); return Task.CompletedTask; });
            await engine.RegisterSignalAsync(payload);
            Assert.Empty(results);
            await engine.RegisterSignalAsync(read);
            var result = Assert.Single(results);
            ResponsePolicy.EnforceDispatchPolicy(result);
            Assert.True(result.KillAuthorized);
            Assert.Equal(4242, result.ProcessId);
            Assert.Equal(created.ToString(), result.Metadata!["ProcessCreationTime"]);
            Assert.Equal("InjectedVictim", result.Metadata["ContainmentScope"]);
            Assert.Equal("Credential Theft: Unbacked PE + Store Read", result.RuleName);
        }

        private static DetectionEvent Read(long created) => new()
        {
            RuleName = "Sensitive File Access: ETW Credential Store Read", ProcessId = 4242,
            ProcessName = "host", Confidence = 0.60, Tier = DetectionTier.Tier2Indicator,
            AuthorizedResponse = ResponseAction.LogOnly, SignalType = SignalType.Generic,
            Metadata = new Dictionary<string, string>
            {
                ["SensitiveFileAccess"] = "true", ["AccessSource"] = "KernelFileRead",
                ["ProcessCreationTime"] = created.ToString()
            }
        };

        [Theory]
        [InlineData("pid-reuse")]
        [InlineData("source-read")]
        [InlineData("watcher")]
        [InlineData("expired")]
        [InlineData("unknown-source")]
        [InlineData("identity-denied")]
        public async Task LoaderOrUnrelatedEvidenceCannotKillTheVictim(string scenario)
        {
            var created = DateTime.UtcNow.AddHours(-1).ToFileTimeUtc();
            var payload = EtwThreatIntelMonitor.CreatePayloadObservation(4242, "target", @"C:\Apps\target.exe",
                created, Scan(0x20, Header()), DateTime.UtcNow);
            var read = Read(created);
            if (scenario == "source-read") read.ProcessId = 5151;
            if (scenario == "watcher") read.Metadata!["AccessSource"] = "FileSystemWatcher";
            if (scenario == "expired") payload.Timestamp = DateTime.UtcNow.AddSeconds(-16);
            if (scenario == "unknown-source") payload.Metadata!.Remove("PayloadEvidenceSource");
            var engine = new BehavioralCorrelationEngine(_ => null, _ => scenario == "identity-denied"
                ? throw new System.ComponentModel.Win32Exception(5) : created + (scenario == "pid-reuse" ? 1 : 0));
            var results = new List<DetectionEvent>();
            engine.Initialize(e => { results.Add(e); return Task.CompletedTask; });
            await engine.RegisterSignalAsync(payload);
            await engine.RegisterSignalAsync(read);
            Assert.Empty(results);
        }

        [Theory]
        [InlineData("chrome")]
        [InlineData("CHROME.EXE")]
        [InlineData("msedge")]
        [InlineData("firefox")]
        public void BrowserApiSuppressionStillQueuesItsTargetWithoutAuthorizingAction(string caller)
        {
            var candidates = new List<int>();
            var rule = new ThreatIntelInjectionRule((pid, payloadOnly) => { Assert.True(payloadOnly); candidates.Add(pid); });
            var result = rule.Evaluate(new FusedTelemetryContext
            {
                TriggeringEvent = new ThreatIntelTelemetry { ProcessId = 5151, ProcessName = caller,
                    TargetProcessId = 4242, ApiName = "ThreatIntel_EventId_4" }
            });
            Assert.Null(result);
            Assert.Equal(new[] { 5151, 4242 }, candidates);
        }
    }
}
