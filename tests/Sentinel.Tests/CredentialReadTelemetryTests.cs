using System;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;
using Sentinel.Core;
using Xunit;

namespace Sentinel.Tests
{
    public sealed class CredentialReadTelemetryTests
    {
        private const string Store = @"\Device\HarddiskVolume3\Users\alice\AppData\Local\Google\Chrome\User Data\Default\Login Data";
        private static readonly DateTime Now = new(2026, 10, 18, 12, 0, 0, DateTimeKind.Utc);

        private static byte[] NamePayload(int width, string path, ulong key = 123)
        {
            var text = Encoding.Unicode.GetBytes(path + "\0");
            var result = new byte[width + text.Length];
            Array.Copy(BitConverter.GetBytes(key), result, width);
            Array.Copy(text, 0, result, width, text.Length);
            return result;
        }

        private static byte[] ReadPayload(int width, byte version, ulong key = 123)
        {
            var offset = 8 + (version == 0 ? 3 : 2) * width;
            var result = new byte[offset + width + (version == 0 ? 8 : 16)];
            Array.Copy(BitConverter.GetBytes(key), 0, result, offset, width);
            return result;
        }

        private static T WithEvent<T>(byte[] bytes, ushort id, byte version, int width,
            Func<EtwRawEvent, T> action, DateTime? time = null, int pid = 4242)
        {
            var memory = Marshal.AllocHGlobal(bytes.Length);
            try
            {
                Marshal.Copy(bytes, 0, memory, bytes.Length);
                return action(new EtwRawEvent
                {
                    UserData = memory, UserDataLength = (ushort)bytes.Length,
                    EventId = id, Version = version, PointerSize = width,
                    ProcessId = pid, Timestamp = time ?? Now
                });
            }
            finally { Marshal.FreeHGlobal(memory); }
        }

        [Theory]
        [InlineData(4, 0)] [InlineData(4, 1)] [InlineData(8, 0)] [InlineData(8, 1)]
        public void ManifestReadLayouts_ResolveOnlyPreviouslyNamedSensitiveKey(int width, byte version)
        {
            var tracker = new CredentialReadTracker();
            Assert.Null(WithEvent(ReadPayload(width, version), 15, version, width, tracker.Observe));
            WithEvent(NamePayload(width, Store), 10, 0, width, tracker.Observe);
            Assert.Equal(Store, WithEvent(ReadPayload(width, version), 15, version, width, tracker.Observe));
            Assert.Null(WithEvent(ReadPayload(width, version), 15, version, width, tracker.Observe));
            Assert.Equal(Store, WithEvent(ReadPayload(width, version), 15, version, width, tracker.Observe,
                Now.AddSeconds(21)));
        }

        [Theory]
        [InlineData(11, Store)]
        [InlineData(10, @"C:\Users\alice\cache\ordinary.tmp")]
        public void NameRemovalOrKeyReuse_InvalidatesSensitiveMapping(ushort id, string replacement)
        {
            var tracker = new CredentialReadTracker();
            WithEvent(NamePayload(8, Store), 10, 0, 8, tracker.Observe);
            WithEvent(NamePayload(8, replacement), id, 0, 8, tracker.Observe);
            Assert.Null(WithEvent(ReadPayload(8, 1), 15, 1, 8, tracker.Observe));
        }

        [Fact]
        public void StaleUnknownVersionTruncatedOrSystemRead_IsNotAttributed()
        {
            var tracker = new CredentialReadTracker();
            WithEvent(NamePayload(8, Store), 10, 0, 8, tracker.Observe);
            Assert.Null(WithEvent(ReadPayload(8, 1), 15, 2, 8, tracker.Observe));
            Assert.Null(WithEvent(new byte[12], 15, 1, 8, tracker.Observe));
            Assert.Null(WithEvent(ReadPayload(8, 1), 15, 1, 8, tracker.Observe, pid: 4));
            Assert.Null(WithEvent(ReadPayload(8, 1), 15, 1, 8, tracker.Observe, Now.AddMinutes(3)));
        }

        [Theory]
        [InlineData(@"C:\Users\a\AppData\Roaming\discord\Local Storage\leveldb\000001.ldb", true)]
        [InlineData(@"C:\Users\a\AppData\Roaming\discordcanary\Local Storage\leveldb\000001.log", true)]
        [InlineData(@"C:\Users\a\.aws\credentials", true)]
        [InlineData(@"C:\Users\a\.ssh\id_ed25519", true)]
        [InlineData(@"C:\Users\a\.ssh\id_ed25519.pub", false)]
        [InlineData(@"C:\Users\a\AppData\Roaming\discord\Cache\data.log", false)]
        [InlineData(@"C:\Users\a\browser\Login Data.bak", false)]
        public void StoreScope_IncludesSessionsAndSecretsWithoutBroadCacheMatching(string path, bool expected)
            => Assert.Equal(expected, CredentialReadTracker.IsSensitivePath(path));

        [Fact]
        public async Task ActualReadRule_RequiresIndependentC2BeforeComposite()
        {
            var tracker = new CredentialReadTracker();
            WithEvent(NamePayload(8, Store), 10, 0, 8, tracker.Observe);
            var path = WithEvent(ReadPayload(8, 1), 15, 1, 8, tracker.Observe);
            var detection = new SensitiveStoreReadRule().Evaluate(new FusedTelemetryContext
            {
                TriggeringEvent = new FileActivityTelemetry
                {
                    ProcessId = 4242, ProcessName = "renamed-tool.exe", FilePath = path!,
                    OperationType = "READ", Timestamp = DateTime.UtcNow
                }
            });
            Assert.NotNull(detection);
            ResponsePolicy.ApplyTierLaw(detection!);
            Assert.Equal(DetectionTier.Tier2Indicator, detection!.Tier);
            Assert.Equal(ResponseAction.LogOnly, detection.AuthorizedResponse);
            Assert.Null(detection.Family);
            var engine = new BehavioralCorrelationEngine();
            DetectionEvent? composite = null;
            engine.Initialize(d => { composite = d; return Task.CompletedTask; });
            await engine.RegisterSignalAsync(detection);
            await engine.RegisterSignalAsync(new DetectionEvent
            {
                RuleName = "Ordinary outbound connection", ProcessId = 4242,
                SignalType = SignalType.Generic, Tier = DetectionTier.Tier2Indicator,
                AuthorizedResponse = ResponseAction.LogOnly, Confidence = 0.5
            });
            Assert.Null(composite);
            await engine.RegisterSignalAsync(new DetectionEvent
            {
                RuleName = "Weak network observation", ProcessId = 4242,
                SignalType = SignalType.NetworkC2, Tier = DetectionTier.Tier2Indicator,
                AuthorizedResponse = ResponseAction.LogOnly, Confidence = 0.4
            });
            Assert.Null(composite);
            await engine.RegisterSignalAsync(new DetectionEvent
            {
                RuleName = "C2 Beaconing Behavior (Statistical)", ProcessId = 4242,
                SignalType = SignalType.NetworkC2, Tier = DetectionTier.Tier1Behavioral,
                Confidence = 0.95
            });
            Assert.NotNull(composite);
            Assert.True(composite!.KillAuthorized);
        }

        private static byte[] ScriptPayload(string text, int number = 1, int total = 1)
        {
            var content = Encoding.Unicode.GetBytes(text + "\0id\0path\0");
            var data = new byte[8 + content.Length];
            Array.Copy(BitConverter.GetBytes(number), data, 4);
            Array.Copy(BitConverter.GetBytes(total), 0, data, 4, 4);
            Array.Copy(content, 0, data, 8, content.Length);
            return data;
        }

        [Fact]
        public void ScriptBlockPayload_SkipsBinaryCountersAndPreservesLongText()
        {
            var text = new string(' ', 9000) + "Write-Output 'end'";
            Assert.Equal(text, WithEvent(ScriptPayload(text), 4104, 1, 8, PowerShellScriptBlockPayload.Read));
        }

        [Theory]
        [InlineData(0, 1, 1)] [InlineData(1, 0, 1)]
        [InlineData(1, 2, 1)] [InlineData(1, 1, 5000)]
        public void InvalidScriptVersionOrFragmentCounters_AreRejected(byte version, int number, int total)
            => Assert.Equal("", WithEvent(ScriptPayload("bad", number, total), 4104, version, 8,
                PowerShellScriptBlockPayload.Read));

        [Fact]
        public void ScriptBlockPayload_RejectsUnterminatedOrTruncatedText()
        {
            Assert.Equal("", WithEvent(new byte[8], 4104, 1, 8, PowerShellScriptBlockPayload.Read));
            var bytes = ScriptPayload("hello");
            for (int i = 8; i < bytes.Length; i += 2) { bytes[i] = 65; bytes[i + 1] = 0; }
            Assert.Equal("", WithEvent(bytes, 4104, 1, 8, PowerShellScriptBlockPayload.Read));
        }
    }
}
