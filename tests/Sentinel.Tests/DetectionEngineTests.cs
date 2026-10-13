using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Xunit;
using Sentinel.Core;
using Microsoft.Extensions.Logging.Abstractions;

namespace Sentinel.Tests
{
    public class DetectionEngineTests : IDisposable
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

        public DetectionEngineTests()
        {
            _tempDir = Path.Combine(Path.GetTempPath(), "sentinel_det_test_" + Guid.NewGuid().ToString("N")[..8]);
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

        [Fact]
        public void DetectionEngine_InitializesCorrectly()
        {
            var rules = new List<IDetectionRule> { new LsassAccessRule(), new RansomwareDetectionRule() };
            var engine = CreateEngine(rules);
            Assert.Equal(2, engine.RuleCount);
            engine.Stop();
        }

        [Fact]
        public async Task SubmitTelemetry_MatchingRule_LogsDetection()
        {
            var rules = new List<IDetectionRule> { new LsassAccessRule() };
            var engine = CreateEngine(rules);

            try
            {
                var context = new FusedTelemetryContext
                {
                    TriggeringEvent = new ProcessTelemetry
                    {
                        ProcessName = "procdump.exe",
                        ProcessId = 11111,
                        CommandLine = "procdump.exe -ma lsass.exe dump.dmp",
                        ImagePath = @"C:\temp\procdump.exe",
                        ParentProcessName = "cmd.exe",
                        ParentProcessId = 100
                    }
                };

                engine.SubmitTelemetry(context);
                await Task.Delay(500);

                var log = ReadLog();
                Assert.Contains("LsassAccessRule", log);
                Assert.Contains("detection", log);
            }
            finally
            {
                engine.Stop();
            }
        }

        [Fact]
        public async Task SubmitTelemetry_NoMatchingRule_NoDetection()
        {
            var rules = new List<IDetectionRule> { new LsassAccessRule() };
            var engine = CreateEngine(rules);

            try
            {
                var context = new FusedTelemetryContext
                {
                    TriggeringEvent = new ProcessTelemetry
                    {
                        ProcessName = "notepad.exe",
                        ProcessId = 22222,
                        CommandLine = "notepad.exe readme.txt",
                        ImagePath = @"C:\Windows\System32\notepad.exe",
                        ParentProcessName = "explorer.exe",
                        ParentProcessId = 100
                    }
                };

                engine.SubmitTelemetry(context);
                await Task.Delay(300);

                var log = ReadLog();
                Assert.DoesNotContain("LsassAccessRule", log);
            }
            finally
            {
                engine.Stop();
            }
        }

        [Fact]
        public async Task SubmitTelemetry_Deduplication_SuppressesRepeats()
        {
            var rules = new List<IDetectionRule> { new LsassAccessRule() };
            var engine = CreateEngine(rules);

            try
            {
                // Unique PID so shared fixture log from other tests cannot confuse counts.
                int pid = 40000 + Environment.TickCount % 20000;
                string pidToken = $"\"ProcessId\":{pid}";

                int CountDetectionsForPid()
                {
                    var n = 0;
                    foreach (var line in ReadLog().Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries))
                    {
                        if (line.IndexOf("\"type\":\"detection\"", StringComparison.Ordinal) >= 0 &&
                            line.IndexOf("LsassAccessRule", StringComparison.Ordinal) >= 0 &&
                            line.IndexOf(pidToken, StringComparison.Ordinal) >= 0)
                            n++;
                    }
                    return n;
                }

                var context = new FusedTelemetryContext
                {
                    TriggeringEvent = new ProcessTelemetry
                    {
                        ProcessName = "procdump.exe",
                        ProcessId = pid,
                        CommandLine = "procdump.exe -ma lsass.exe dump.dmp",
                        ImagePath = @"C:\temp\procdump.exe",
                        ParentProcessName = "cmd.exe",
                        ParentProcessId = 100
                    }
                };

                // Submit same event twice rapidly (within dedup window)
                engine.SubmitTelemetry(context);
                engine.SubmitTelemetry(context);

                // Poll for the first detection to land instead of a fixed delay - under full-suite
                // CPU contention the single-reader channel drain can lag past any fixed timeout,
                // which previously made this test flaky (count observed as 0).
                int count = 0;
                for (int i = 0; i < 40; i++)
                {
                    await Task.Delay(100);
                    count = CountDetectionsForPid();
                    if (count >= 1) break;
                }

                // Give the duplicate a chance to (incorrectly) slip through, then confirm dedup
                // held the count at exactly one.
                await Task.Delay(300);

                // Dedup should produce exactly one detection for this PID.
                Assert.Equal(1, CountDetectionsForPid());
            }
            finally
            {
                engine.Stop();
            }
        }

        [Fact]
        public async Task EmitAsync_DirectEmission_BypassesRules()
        {
            var rules = new List<IDetectionRule>(); // No rules
            var engine = CreateEngine(rules);

            try
            {
                // EmitAsync allows direct detection event injection (used by composite detections)
                var detection = new DetectionEvent
                {
                    RuleName = "Active Ransomware Chain",
                    ProcessId = 44444,
                    ProcessName = "ransom.exe",
                    Confidence = 0.99,
                    Tier = DetectionTier.Tier1Behavioral,
                    AuthorizedResponse = ResponseAction.KillProcessTree,
                    Evidence = "Test composite detection"
                };

                await engine.EmitAsync(detection);
                await Task.Delay(300);

                var log = ReadLog();
                Assert.Contains("Active Ransomware Chain", log);
            }
            finally
            {
                engine.Stop();
            }
        }

        [Fact]
        public async Task SubmitConsultantSignalAsync_SetsToTier2()
        {
            var rules = new List<IDetectionRule>();
            var engine = CreateEngine(rules);

            try
            {
                var signal = new DetectionEvent
                {
                    RuleName = "External Signal: Suspicious Activity",
                    ProcessId = 55555,
                    ProcessName = "suspicious.exe",
                    Confidence = 0.70,
                    Tier = DetectionTier.Tier1Behavioral, // Will be overridden to Tier2
                    AuthorizedResponse = ResponseAction.KillProcess
                };

                await engine.SubmitConsultantSignalAsync(signal);
                await Task.Delay(300);

                var log = ReadLog();
                Assert.Contains("External Signal", log);
                // Consultant signals are always Tier2 (logged, not killed)
                Assert.Contains("\"ActionTaken\":\"LOG\"", log);
            }
            finally
            {
                engine.Stop();
            }
        }

        [Fact]
        public async Task SubmitTelemetry_MultipleRules_AllEvaluated()
        {
            // Register multiple rules - both should fire on their respective inputs
            var rules = new List<IDetectionRule>
            {
                new LsassAccessRule(),
                new RansomwareDetectionRule()
            };
            var engine = CreateEngine(rules);

            try
            {
                // LSASS dump command
                var context1 = new FusedTelemetryContext
                {
                    TriggeringEvent = new ProcessTelemetry
                    {
                        ProcessName = "procdump.exe",
                        ProcessId = 66666,
                        CommandLine = "procdump.exe -ma lsass.exe dump.dmp",
                        ImagePath = @"C:\temp\procdump.exe",
                        ParentProcessName = "cmd.exe",
                        ParentProcessId = 100
                    }
                };
                engine.SubmitTelemetry(context1);

                // Ransomware command (different PID)
                var context2 = new FusedTelemetryContext
                {
                    TriggeringEvent = new ProcessTelemetry
                    {
                        ProcessName = "cmd.exe",
                        ProcessId = 66667,
                        CommandLine = "cmd.exe /c vssadmin delete shadows /all /quiet",
                        ImagePath = @"C:\Windows\System32\cmd.exe",
                        ParentProcessName = "explorer.exe",
                        ParentProcessId = 100
                    }
                };
                engine.SubmitTelemetry(context2);

                var log = await WaitForLogAsync("LsassAccessRule", "RansomwareDetectionRule");
                Assert.Contains("LsassAccessRule", log);
                Assert.Contains("RansomwareDetectionRule", log);
            }
            finally
            {
                engine.Stop();
            }
        }

        [Fact]
        public async Task SubmitTelemetry_ScoringIntegration_UpdatesProcessProfile()
        {
            var rules = new List<IDetectionRule> { new LsassAccessRule() };
            var engine = CreateEngine(rules);

            try
            {
                var context = new FusedTelemetryContext
                {
                    TriggeringEvent = new ProcessTelemetry
                    {
                        ProcessName = "dumptool.exe",
                        ProcessId = 77777,
                        CommandLine = "dumptool.exe -ma lsass.exe credentials.dmp",
                        ImagePath = @"C:\temp\dumptool.exe",
                        ParentProcessName = "cmd.exe",
                        ParentProcessId = 100
                    }
                };

                engine.SubmitTelemetry(context);
                await Task.Delay(500);

                // Verify the scoring engine tracked this PID
                var profile = _scoringEngine.GetProcessProfile(77777);
                Assert.NotNull(profile);
                Assert.True(profile!.MaxConfidence >= 0.85);
                Assert.Contains(DetectionCategory.CredentialDump, profile.DetectedCategories);
            }
            finally
            {
                engine.Stop();
            }
        }

        [Fact]
        public void Stop_CanBeCalledSafely()
        {
            var rules = new List<IDetectionRule> { new LsassAccessRule() };
            var engine = CreateEngine(rules);
            engine.Stop(); // Should not throw
            engine.Stop(); // Double-stop should also be safe
        }

        private static int CountOccurrences(string text, string pattern)
        {
            int count = 0;
            int idx = 0;
            while ((idx = text.IndexOf(pattern, idx, StringComparison.Ordinal)) >= 0)
            {
                count++;
                idx += pattern.Length;
            }
            return count;
        }
    }
}
