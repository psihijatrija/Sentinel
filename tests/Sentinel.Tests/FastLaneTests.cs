using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Xunit;
using Sentinel.Core;
using Microsoft.Extensions.Logging.Abstractions;

namespace Sentinel.Tests
{
    /// <summary>
    /// FEAT-002 1D: terminal-class fast lane. Verifies that DetectionEngine.ShouldFastLane is a
    /// pure scheduling hint keyed on ResponsePolicy.IsAttackClassTerminal, and that routing stays
    /// mutually exclusive and never changes the response contract: a Tier2 detection still produces
    /// a LOG response and never a kill, regardless of lane.
    /// </summary>
    public class FastLaneTests : IDisposable
    {
        private readonly string _tempDir;
        private readonly SecureCacheStore _cache;
        private readonly SentinelMetrics _metrics;
        private readonly JsonlEventLogger _logger;
        private readonly AllowlistService _allowlist;
        private readonly AdvancedResponseEngine _responseEngine;
        private readonly IoCScanner _iocScanner;
        private readonly HashReputationService _reputationService;
        private readonly BehavioralCorrelationEngine _correlationEngine;
        private readonly ScoringEngine _scoringEngine;
        private readonly FileReputationEngine _fileReputationEngine;

        public FastLaneTests()
        {
            _tempDir = Path.Combine(Path.GetTempPath(), "sentinel_fastlane_test_" + Guid.NewGuid().ToString("N")[..8]);
            Directory.CreateDirectory(_tempDir);
            _cache = new SecureCacheStore(_tempDir);
            _metrics = new SentinelMetrics();
            _logger = new JsonlEventLogger(Path.Combine(_tempDir, "events.jsonl"));
            _allowlist = new AllowlistService(_cache, NullLogger<AllowlistService>.Instance);
            var config = new SentinelConfig { ActiveResponse = true, ObserveUntilChain = false };
            _responseEngine = new AdvancedResponseEngine(config, _metrics, _logger, new QuarantineManager(_tempDir), _allowlist);
            _iocScanner = new IoCScanner(_cache);
            _reputationService = new HashReputationService(_cache, new ThreatReportingConfig(), NullLogger<HashReputationService>.Instance);
            _correlationEngine = new BehavioralCorrelationEngine();
            _scoringEngine = new ScoringEngine(_allowlist, new SafeProcessExemptionRegistry(), NullLogger<ScoringEngine>.Instance);
            var signerTrust = new SignerTrustService(NullLogger<SignerTrustService>.Instance);
            _fileReputationEngine = new FileReputationEngine(_reputationService, signerTrust, _cache, NullLogger<FileReputationEngine>.Instance);
        }

        public void Dispose()
        {
            _logger.DisposeAsync().AsTask().GetAwaiter().GetResult();
            try { Directory.Delete(_tempDir, true); } catch { }
        }

        private string ReadLog()
        {
            var logPath = Path.Combine(_tempDir, "events.jsonl");
            if (!File.Exists(logPath)) return string.Empty;
            using var fs = new FileStream(logPath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
            using var reader = new StreamReader(fs, Encoding.UTF8);
            return reader.ReadToEnd();
        }

        private async Task<string> WaitForLogAsync(params string[] needles)
        {
            string log = string.Empty;
            for (int i = 0; i < 40; i++)
            {
                await Task.Delay(100);
                log = ReadLog();
                if (needles.All(n => log.Contains(n)))
                    return log;
            }
            return log;
        }

        private DetectionEngine CreateEngine(IEnumerable<IDetectionRule> rules)
        {
            return new DetectionEngine(
                rules, _metrics, _logger, _responseEngine,
                _iocScanner, _reputationService, _fileReputationEngine,
                _correlationEngine, _scoringEngine,
                NullLogger<DetectionEngine>.Instance);
        }

        /// <summary>
        /// Builds a FusedTelemetryContext whose triggering event's Type carries the given rule-name
        /// label - this is the only semantic signal ShouldFastLane can derive from raw telemetry.
        /// </summary>
        private static FusedTelemetryContext ContextForType(string type, int pid, string processName)
            => new()
            {
                ProcessId = pid,
                ProcessName = processName,
                TriggeringEvent = new ProcessTelemetry
                {
                    Type = type,
                    ProcessId = pid,
                    ProcessName = processName,
                    ImagePath = @"C:\temp\" + processName + ".exe",
                    CommandLine = processName + ".exe",
                }
            };

        // Test rule that emits a Tier2/LogOnly detection whose rule name LOOKS terminal
        // (contains "Reverse Shell") but is a civilian - never attack-class terminal.
        private sealed class Tier2LookalikeRule : IDetectionRule
        {
            public const string RuleNameConst = "Reverse Shell: Suspicious Outbound Connection";
            public string Name => "Tier2LookalikeRule";
            public DetectionEvent? Evaluate(FusedTelemetryContext context)
            {
                if (context.TriggeringEvent is not ProcessTelemetry pt) return null;
                return new DetectionEvent
                {
                    RuleName = RuleNameConst,
                    Evidence = "Lookalike civilian signal",
                    Reasoning = "Looks terminal but is observe-only",
                    Confidence = 0.90,
                    Tier = DetectionTier.Tier2Indicator,
                    AuthorizedResponse = ResponseAction.LogOnly,
                    ProcessName = pt.ProcessName,
                    ProcessId = pt.ProcessId,
                    SignalType = SignalType.SuspiciousProcess,
                };
            }
        }

        [Fact]
        public void ShouldFastLane_Tier1TerminalClass_ReturnsTrue()
        {
            // Test B: a terminal-class rule name (kernel exploit loader), pid > 4.
            // ResponsePolicy.IsAttackClassTerminal must be true, so the context fast-lanes.
            var context = ContextForType("CVE Class: Kernel Exploit Loader", pid: 4242, processName: "AfdEoP");

            // Sanity: the derived candidate is attack-class terminal.
            var candidate = new DetectionEvent
            {
                RuleName = "CVE Class: Kernel Exploit Loader",
                ProcessId = 4242,
                ProcessName = "AfdEoP",
                Confidence = 1.0,
            };
            Assert.True(ResponsePolicy.IsAttackClassTerminal(candidate));

            Assert.True(DetectionEngine.ShouldFastLane(context, ResponsePolicy.DefaultMinTier1Confidence));
        }

        [Fact]
        public void ShouldFastLane_PidTooLow_ReturnsFalse()
        {
            // The attack-class gate excludes PID <= 4, so even a terminal rule name does not fast-lane.
            var context = ContextForType("CVE Class: Kernel Exploit Loader", pid: 0, processName: "SYSTEM");
            Assert.False(DetectionEngine.ShouldFastLane(context, ResponsePolicy.DefaultMinTier1Confidence));
        }

        [Fact]
        public async Task Tier2Lookalike_DoesNotFastLane_AndLogsNeverKills()
        {
            // Test A: a Tier2 detection with an IsAttackClassTerminal-looking rule name.
            // ShouldFastLane must be false (the civilian rule name is not attack-class terminal),
            // and when submitted through the engine it produces a LOG response and never a kill.
            int pid = 51000;
            var context = ContextForType(Tier2LookalikeRule.RuleNameConst, pid, "chrome");

            // ShouldFastLane is false for this civilian lookalike.
            Assert.False(DetectionEngine.ShouldFastLane(context, ResponsePolicy.DefaultMinTier1Confidence));

            var engine = CreateEngine(new List<IDetectionRule> { new Tier2LookalikeRule() });
            try
            {
                engine.SubmitTelemetry(context);

                var log = await WaitForLogAsync(Tier2LookalikeRule.RuleNameConst, "\"ActionTaken\":\"LOG\"");

                // The detection was logged and resolved to a LOG (observe) response.
                Assert.Contains(Tier2LookalikeRule.RuleNameConst, log);
                Assert.Contains("\"ActionTaken\":\"LOG\"", log);

                // It must NEVER have killed this process.
                string pidToken = $"\"ProcessId\":{pid}";
                foreach (var line in log.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries))
                {
                    if (line.IndexOf(pidToken, StringComparison.Ordinal) < 0) continue;
                    Assert.DoesNotContain("\"ActionTaken\":\"KILL", line);
                    Assert.DoesNotContain("QUARANTINE_AND_KILL", line);
                }
            }
            finally
            {
                engine.Stop();
            }
        }

        [Fact]
        public void ShouldFastLane_NullOrEmptyTrigger_ReturnsFalse()
        {
            Assert.False(DetectionEngine.ShouldFastLane(null!, ResponsePolicy.DefaultMinTier1Confidence));

            var noType = new FusedTelemetryContext
            {
                ProcessId = 4242,
                ProcessName = "x",
                TriggeringEvent = new ProcessTelemetry { ProcessId = 4242, ProcessName = "x" }
            };
            Assert.False(DetectionEngine.ShouldFastLane(noType, ResponsePolicy.DefaultMinTier1Confidence));
        }
    }
}
