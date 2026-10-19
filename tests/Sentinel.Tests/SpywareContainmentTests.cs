using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using Sentinel.Core;
using Xunit;

namespace Sentinel.Tests
{
    [Collection("ResponsePolicy")]
    public class SpywareContainmentTests
    {
        private static DetectionEvent Payload() => new()
        {
            RuleName = "Threat Intel: Remote Memory Injection (ALLOCVM_REMOTE + PROTECTVM_REMOTE)",
            ProcessId = 4242, ProcessName = "chrome", Confidence = 0.95,
            SignalType = SignalType.ProcessInjection, Tier = DetectionTier.Tier2Indicator,
            AuthorizedResponse = ResponseAction.LogOnly,
            Metadata = new Dictionary<string, string>
            {
                ["UnbackedPePayload"] = "true",
                ["ProcessCreationTime"] = DateTime.UtcNow.AddHours(-1).ToFileTimeUtc().ToString()
            }
        };

        private static DetectionEvent Read(DetectionEvent payload) => new()
        {
            RuleName = "Sensitive File Access: ETW Credential Store Read",
            ProcessId = payload.ProcessId, ProcessName = "chrome", Confidence = 0.60,
            Tier = DetectionTier.Tier2Indicator, AuthorizedResponse = ResponseAction.LogOnly,
            Metadata = new Dictionary<string, string>
            {
                ["SensitiveFileAccess"] = "true", ["AccessSource"] = "KernelFileRead",
                ["ProcessCreationTime"] = payload.Metadata!["ProcessCreationTime"]
            }
        };

        [Theory]
        [InlineData(false)]
        [InlineData(true)]
        public async Task PayloadAndCredentialReadContainWithoutC2OrUploadThreshold(bool readFirst)
        {
            ResponsePolicy.ResetForTests();
            var payload = Payload(); var read = Read(payload);
            ResponsePolicy.ApplyTierLaw(payload);
            ResponsePolicy.ApplyTierLaw(read);
            Assert.Equal(ResponseAction.LogOnly, read.AuthorizedResponse);
            var engine = new BehavioralCorrelationEngine(_ => null);
            var emitted = new List<DetectionEvent>();
            engine.Initialize(e => { emitted.Add(e); return Task.CompletedTask; });
            await engine.RegisterSignalAsync(readFirst ? read : payload);
            Assert.Empty(emitted);
            await engine.RegisterSignalAsync(readFirst ? payload : read);
            var result = Assert.Single(emitted);
            Assert.Equal("Credential Theft: Unbacked PE + Store Read", result.RuleName);
            ResponsePolicy.EnforceDispatchPolicy(result);
            Assert.True(result.KillAuthorized);
            Assert.Equal(DetectionTier.Tier1Behavioral, result.Tier);
            Assert.Equal(SignalType.CredentialTheft, result.SignalType);
            Assert.True(ResponsePolicy.IsNukeComposite(result));
        }

        [Theory]
        [InlineData("jit")]
        [InlineData("weak")]
        [InlineData("low-confidence")]
        [InlineData("different-pid")]
        [InlineData("reused-pid")]
        [InlineData("unknown-lifetime")]
        [InlineData("expired")]
        [InlineData("future")]
        [InlineData("watcher-write")]
        [InlineData("consultant")]
        public async Task AmbiguousOrUnrelatedEvidenceNeverAuthorizesContainment(string scenario)
        {
            var payload = Payload(); var read = Read(payload);
            switch (scenario)
            {
                case "jit": payload.Metadata!["UnbackedPePayload"] = "false"; break;
                case "weak": payload.Metadata!["WeakObserveSeed"] = "true"; break;
                case "low-confidence": payload.Confidence = 0.80; break;
                case "different-pid": read.ProcessId++; break;
                case "reused-pid": read.Metadata!["ProcessCreationTime"] = DateTime.UtcNow.AddMinutes(-1).ToFileTimeUtc().ToString(); break;
                case "unknown-lifetime": read.Metadata!.Remove("ProcessCreationTime"); break;
                case "expired": payload.Timestamp = DateTime.UtcNow.AddSeconds(-16); break;
                case "future": payload.Timestamp = DateTime.UtcNow.AddMinutes(1); break;
                case "watcher-write": read.Metadata!["AccessSource"] = "FileSystemWatcher"; break;
                case "consultant": payload.Metadata!["ConsultantSignal"] = "true"; break;
            }
            Assert.False(BehavioralCorrelationEngine.HasInjectedCredentialRead(new[] { payload, read }));
            var engine = new BehavioralCorrelationEngine(_ => null);
            var emitted = new List<DetectionEvent>();
            engine.Initialize(e => { emitted.Add(e); return Task.CompletedTask; });
            await engine.RegisterSignalAsync(payload);
            await engine.RegisterSignalAsync(read);
            Assert.Empty(emitted);
        }

        [Theory]
        [InlineData(100_000_000, 1_000_000, true)]
        [InlineData(5_000_001, 0, true)]
        [InlineData(5_000_000, 0, false)]
        [InlineData(10_000_000, 1_000_000, false)]
        [InlineData(10_000_001, 1_000_000, true)]
        [InlineData(1_000_000, 1_000_000, false)]
        [InlineData(-1, 0, false)]
        [InlineData(long.MaxValue, long.MaxValue, false)]
        public void UploadSpikeUsesPriorBaseline(long bytes, long baseline, bool expected)
            => Assert.Equal(expected, DataExfiltrationMonitor.IsOutboundSpike(bytes, baseline));

        [Theory]
        [InlineData(false)]
        [InlineData(true)]
        public void PeEvidenceRequiresMoreThanMz(bool x64)
        {
            var header = new byte[4096];
            header[0] = (byte)'M'; header[1] = (byte)'Z';
            Assert.False(NativeProcessMemory.HasPeHeaders(header, header.Length));
            void Write(int offset, byte[] bytes) => Array.Copy(bytes, 0, header, offset, bytes.Length);
            Write(0x3c, BitConverter.GetBytes(128));
            Write(128, BitConverter.GetBytes(0x00004550));
            Write(132, BitConverter.GetBytes((ushort)(x64 ? 0x8664 : 0x14c)));
            Write(134, BitConverter.GetBytes((ushort)3));
            Write(148, BitConverter.GetBytes((ushort)240));
            Write(152, BitConverter.GetBytes((ushort)(x64 ? 0x20b : 0x10b)));
            Write(208, BitConverter.GetBytes(0x4000));
            Assert.True(NativeProcessMemory.HasPeHeaders(header, header.Length));
            Assert.False(NativeProcessMemory.HasPeHeaders(header, 160));
            Write(0x3c, BitConverter.GetBytes(int.MaxValue));
            Assert.False(NativeProcessMemory.HasPeHeaders(header, header.Length));
        }
    }
}
