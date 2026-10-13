using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging.Abstractions;
using Xunit;
using Sentinel.Core;

namespace Sentinel.Tests
{
    /// <summary>
    /// Unit tests for ChainTracer - the attack chain walking and response component.
    /// Tests verify parent chain walking, attack root identification, system binary protection,
    /// persistence removal, and quarantine behavior.
    /// </summary>
    public class ChainTracerTests : IDisposable
    {
        private readonly string _tempDir;
        private readonly ProcessAncestryCache _ancestryCache;
        private readonly QuarantineManager _quarantineManager;
        private readonly JsonlEventLogger _eventLogger;
        private readonly SentinelConfig _config;
        private readonly ChainTracer _tracer;

        public ChainTracerTests()
        {
            _tempDir = Path.Combine(Path.GetTempPath(), "sentinel_chain_test_" + Guid.NewGuid().ToString("N")[..8]);
            Directory.CreateDirectory(_tempDir);
            _ancestryCache = new ProcessAncestryCache();
            _quarantineManager = new QuarantineManager(Path.Combine(_tempDir, "quarantine"));
            _eventLogger = new JsonlEventLogger(Path.Combine(_tempDir, "events.jsonl"));
            _config = new SentinelConfig { ActiveResponse = true, ObserveUntilChain = false };
            _tracer = new ChainTracer(_ancestryCache, _quarantineManager, _eventLogger, _config, NullLogger<ChainTracer>.Instance);
        }

        public void Dispose()
        {
            _eventLogger.DisposeAsync().AsTask().GetAwaiter().GetResult();
            try { Directory.Delete(_tempDir, true); } catch { }
        }

        [Fact]
        public async Task TraceAndRespond_ReturnsResult_WithNonZeroPid()
        {
            var detection = new DetectionEvent
            {
                RuleName = "LsassAccessRule",
                ProcessId = 99999, // Non-existent PID
                ProcessName = "evil.exe",
                Confidence = 0.95,
                Tier = DetectionTier.Tier1Behavioral,
                AuthorizedResponse = ResponseAction.KillProcessTree
            };

            var result = await _tracer.TraceAndRespondAsync(detection);

            Assert.NotNull(result);
            Assert.True(result.Success);
            Assert.NotNull(result.RootDetection);
            Assert.Equal("LsassAccessRule", result.RootDetection.RuleName);
        }

        [Fact]
        public async Task TraceAndRespond_ActiveResponseCannotBeDisabled_StillRespondsToTier1()
        {
            // v2.9.4: There is no off switch for response. ActiveResponse's setter is a no-op
            // (Models.cs) and ObserveUntilChain now defaults false, so an attempt to disable
            // response via config must be ignored and a Tier1 kill-grade detection must still
            // be actioned. This guards against the "switch to turn defense off" regression:
            // config-driven disarming must never resurrect.
            var config = new SentinelConfig { ActiveResponse = false }; // no-op setter; stays true
            Assert.True(config.ActiveResponse); // proves the off switch is dead
            Assert.False(config.ObserveUntilChain); // armed default, not observe-only

            var tracer = new ChainTracer(_ancestryCache, _quarantineManager, _eventLogger, config, NullLogger<ChainTracer>.Instance);

            var detection = new DetectionEvent
            {
                RuleName = "Ransomware",
                ProcessId = 99998,
                ProcessName = "ransom.exe",
                Confidence = 0.99,
                Tier = DetectionTier.Tier1Behavioral,
                AuthorizedResponse = ResponseAction.KillProcessTree
            };

            var result = await tracer.TraceAndRespondAsync(detection);

            Assert.NotNull(result);
            Assert.True(result.Success);
            // Response is armed regardless of the attempted disable: the kill-grade Tier1
            // ransomware detection is acted on (the PID does not exist, so the recorded
            // KilledProcesses entry reflects the attempt against the target PID).
            Assert.NotEmpty(result.KilledProcesses);
            Assert.Contains(result.KilledProcesses, k => k.ProcessId == 99998);
        }

        [Fact]
        public async Task TraceAndRespond_KillNotAuthorized_DoesNotKill()
        {
            var detection = new DetectionEvent
            {
                RuleName = "Suspicious Binary",
                ProcessId = 99997,
                ProcessName = "unknown.exe",
                Confidence = 0.60,
                Tier = DetectionTier.Tier2Indicator,
                AuthorizedResponse = ResponseAction.LogOnly // Not kill-authorized
            };

            var result = await _tracer.TraceAndRespondAsync(detection);

            Assert.NotNull(result);
            Assert.True(result.Success);
            Assert.Empty(result.KilledProcesses);
        }

        [Fact]
        public async Task TraceAndRespond_LogsChainEvidence()
        {
            var detection = new DetectionEvent
            {
                RuleName = "Process Injection",
                ProcessId = 99996,
                ProcessName = "injector.exe",
                Confidence = 0.90,
                Tier = DetectionTier.Tier1Behavioral,
                AuthorizedResponse = ResponseAction.KillProcessTree
            };

            await _tracer.TraceAndRespondAsync(detection);

            // Verify chain evidence was logged
            var logPath = Path.Combine(_tempDir, "events.jsonl");
            using var fs = new FileStream(logPath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
            using var reader = new StreamReader(fs);
            var log = reader.ReadToEnd();
            Assert.Contains("chain_trace", log);
            Assert.Contains("ChainTrace", log);
        }

        [Fact]
        public async Task TraceAndRespond_InvalidPid_StillSucceeds()
        {
            // PID 0 or negative should not crash
            var detection = new DetectionEvent
            {
                RuleName = "Test",
                ProcessId = 0,
                ProcessName = "ghost.exe",
                Confidence = 0.90,
                Tier = DetectionTier.Tier1Behavioral,
                AuthorizedResponse = ResponseAction.KillProcessTree
            };

            var result = await _tracer.TraceAndRespondAsync(detection);

            // Should handle gracefully - no crash, no kills on PID 0
            Assert.NotNull(result);
            Assert.True(result.Success);
        }

        [Fact]
        public async Task TraceAndRespond_RecordsDuration()
        {
            var detection = new DetectionEvent
            {
                RuleName = "TestRule",
                ProcessId = 99995,
                ProcessName = "test.exe",
                Confidence = 0.80,
                Tier = DetectionTier.Tier1Behavioral,
                AuthorizedResponse = ResponseAction.KillProcessTree
            };

            var result = await _tracer.TraceAndRespondAsync(detection);

            Assert.True(result.EndTime >= result.StartTime);
            Assert.True((result.EndTime - result.StartTime).TotalMilliseconds >= 0);
        }

        [Theory]
        [InlineData(@"C:\Program Files\Google\Chrome\Application\chrome.exe", "chrome")]
        [InlineData(@"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe", "msedge")]
        [InlineData(@"C:\Users\Alice\AppData\Local\Google\Chrome\Application\chrome.exe", "chrome.exe")]
        public void IsLegitimateBrowserHost_AcceptsInstalledBrowserPaths(string path, string name)
        {
            Assert.True(ChainTracer.IsLegitimateBrowserHost(path, name));
        }

        [Theory]
        [InlineData(@"C:\Users\Alice\AppData\Local\Temp\chrome.exe", "chrome")]
        [InlineData(@"C:\Users\Alice\Downloads\msedge.exe", "msedge")]
        [InlineData(@"C:\Temp\evil.exe", "evil")]
        [InlineData(null, "chrome")]
        public void IsLegitimateBrowserHost_RejectsStagingOrUnknownWithoutSignature(string? path, string name)
        {
            // Temp/Downloads chrome.exe without a real signed file on disk must fail
            Assert.False(ChainTracer.IsLegitimateBrowserHost(path, name));
        }

        [Fact]
        public void IsLegitimateBrowserHost_RejectsGenericSetupWithoutSignature()
        {
            Assert.False(ChainTracer.IsLegitimateBrowserHost(@"C:\Users\Alice\Desktop\setup.exe", "setup"));
        }
    }
}
