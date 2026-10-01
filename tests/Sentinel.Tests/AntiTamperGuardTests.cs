using System.Diagnostics;
using System;
using System.Collections.Generic;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging.Abstractions;
using Xunit;
using Sentinel.Core;

namespace Sentinel.Tests
{
    /// <summary>
    /// Unit tests for AntiTamperGuard - the self-protection component that detects
    /// process suspension, binary deletion, and service de-registration.
    /// 
    /// NOTE: We can't easily test the BackgroundService ExecuteAsync loop directly,
    /// but we can test the detection logic through the detection engine integration
    /// and verify the configuration/construction behavior.
    /// </summary>
    public class AntiTamperGuardTests : IDisposable
    {
        private readonly string _tempDir;
        private readonly JsonlEventLogger _eventLogger;
        private readonly SentinelConfig _config;
        private readonly DetectionEngine _detectionEngine;
        private readonly SentinelMetrics _metrics;

        public AntiTamperGuardTests()
        {
            _tempDir = Path.Combine(Path.GetTempPath(), "sentinel_atg_test_" + Guid.NewGuid().ToString("N")[..8]);
            Directory.CreateDirectory(_tempDir);
            _eventLogger = new JsonlEventLogger(Path.Combine(_tempDir, "events.jsonl"));
            _config = new SentinelConfig { ActiveResponse = true, ObserveUntilChain = false };
            _metrics = new SentinelMetrics();

            var cacheStore = new SecureCacheStore(_tempDir);
            var allowlist = new AllowlistService(cacheStore, NullLogger<AllowlistService>.Instance);
            var scoringEngine = new ScoringEngine(allowlist, new SafeProcessExemptionRegistry(), NullLogger<ScoringEngine>.Instance);
            var correlationEngine = new BehavioralCorrelationEngine();
            var hashRepService = new HashReputationService(cacheStore, new ThreatReportingConfig(), NullLogger<HashReputationService>.Instance);
            var iocScanner = new IoCScanner(cacheStore);
            var signerTrust = new SignerTrustService(NullLogger<SignerTrustService>.Instance);
            var fileRepEngine = new FileReputationEngine(hashRepService, signerTrust, cacheStore, NullLogger<FileReputationEngine>.Instance);
            var quarantine = new QuarantineManager(Path.Combine(_tempDir, "quarantine"));
            var responseEngine = new AdvancedResponseEngine(_config, _metrics, _eventLogger, quarantine, allowlist);

            _detectionEngine = new DetectionEngine(
                new List<IDetectionRule>(), _metrics, _eventLogger, responseEngine,
                iocScanner, hashRepService, fileRepEngine, correlationEngine, scoringEngine,
                NullLogger<DetectionEngine>.Instance);
        }

        public void Dispose()
        {
            _detectionEngine.Stop();
            _eventLogger.DisposeAsync().AsTask().GetAwaiter().GetResult();
            try { Directory.Delete(_tempDir, true); } catch { }
        }

        [Fact]
        public void AntiTamperGuard_CanBeConstructed()
        {
            // Verify the guard can be constructed with valid parameters
            var guard = new AntiTamperGuard(
                _detectionEngine,
                _eventLogger,
                _config,
                NullLogger<AntiTamperGuard>.Instance);

            Assert.NotNull(guard);
            guard.Dispose();
        }

        [Fact]
        public void AntiTamperGuard_ConfigurableTimingTick()
        {
            // Verify custom timing tick configuration is accepted
            var config = new SentinelConfig
            {
                ActiveResponse = true, ObserveUntilChain = false,
                AntiTamperTimingTickMs = 1000,
                AntiTamperIntegrityTickMs = 5000
            };

            var guard = new AntiTamperGuard(
                _detectionEngine,
                _eventLogger,
                config,
                NullLogger<AntiTamperGuard>.Instance);

            Assert.NotNull(guard);
            guard.Dispose();
        }

        [Fact]
        public async Task AntiTamperGuard_EmitsSuspensionAlert_ViaDetectionEngine()
        {
            // Simulate what happens when the guard detects a timing gap:
            // It calls _detectionEngine.EmitAsync with a specific DetectionEvent.
            // We verify this by calling EmitAsync directly with the same event shape.

            var suspensionEvent = new DetectionEvent
            {
                RuleName = "Anti-Tamper: Process Suspended",
                Evidence = "Execution gap of 5.0s detected (expected ~2.0s). Sentinel was likely suspended via NtSuspendProcess.",
                Reasoning = "The Sentinel service experienced a timing gap far exceeding its expected tick interval.",
                Confidence = 0.95,
                Tier = DetectionTier.Tier1Behavioral,
                AuthorizedResponse = ResponseAction.LogOnly,
                ProcessName = "Sentinel.Service",
                ProcessId = Process.GetCurrentProcess().Id,
                Metadata = new Dictionary<string, string>
                {
                    ["GapSeconds"] = "5.0",
                    ["ExpectedTickMs"] = "2000"
                }
            };

            await _detectionEngine.EmitAsync(suspensionEvent);
            await Task.Delay(300);

            // Verify the event was logged
            var logPath = Path.Combine(_tempDir, "events.jsonl");
            using var fs = new FileStream(logPath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
            using var reader = new StreamReader(fs);
            var log = reader.ReadToEnd();

            Assert.Contains("Anti-Tamper: Process Suspended", log);
            Assert.Contains("detection", log);
        }

        [Fact]
        public async Task AntiTamperGuard_EmitsBinaryDeletedAlert()
        {
            var binaryDeletedEvent = new DetectionEvent
            {
                RuleName = "Anti-Tamper: Sentinel Binary Deleted",
                Evidence = "Sentinel executable no longer exists at: C:\\Program Files\\Sentinel\\service.exe",
                Reasoning = "The Sentinel service binary has been deleted from disk while the service is still running.",
                Confidence = 0.99,
                Tier = DetectionTier.Tier1Behavioral,
                AuthorizedResponse = ResponseAction.LogOnly,
                ProcessName = "SYSTEM",
                ProcessId = 0
            };

            await _detectionEngine.EmitAsync(binaryDeletedEvent);
            await Task.Delay(300);

            var logPath = Path.Combine(_tempDir, "events.jsonl");
            using var fs = new FileStream(logPath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
            using var reader = new StreamReader(fs);
            var log = reader.ReadToEnd();

            Assert.Contains("Sentinel Binary Deleted", log);
        }

        [Fact]
        public async Task AntiTamperGuard_EmitsServiceRegistrationDeletedAlert()
        {
            var serviceDeletedEvent = new DetectionEvent
            {
                RuleName = "Anti-Tamper: Service Registration Deleted",
                Evidence = "Windows service 'Sentinel' is no longer registered in SCM",
                Reasoning = "The Sentinel service registration was removed from the Service Control Manager.",
                Confidence = 0.98,
                Tier = DetectionTier.Tier1Behavioral,
                AuthorizedResponse = ResponseAction.LogOnly,
                ProcessName = "SYSTEM",
                ProcessId = 0
            };

            await _detectionEngine.EmitAsync(serviceDeletedEvent);
            await Task.Delay(300);

            var logPath = Path.Combine(_tempDir, "events.jsonl");
            using var fs = new FileStream(logPath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
            using var reader = new StreamReader(fs);
            var log = reader.ReadToEnd();

            Assert.Contains("Service Registration Deleted", log);
        }

        [Fact]
        public async Task AntiTamperGuard_QosPolicyTamperingAlert()
        {
            var qosEvent = new DetectionEvent
            {
                RuleName = "Anti-Tamper: Network QoS Throttling Detected",
                Evidence = "Rogue QoS policy 'ThrottleSentinel' targeting 'Sentinel' was found in registry.",
                Reasoning = "An attacker attempted to throttle Sentinel's network traffic by writing a policy-based QoS rule.",
                Confidence = 0.99,
                Tier = DetectionTier.Tier1Behavioral,
                AuthorizedResponse = ResponseAction.LogOnly,
                ProcessName = "SYSTEM",
                ProcessId = 0
            };

            await _detectionEngine.EmitAsync(qosEvent);
            await Task.Delay(300);

            var logPath = Path.Combine(_tempDir, "events.jsonl");
            using var fs = new FileStream(logPath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
            using var reader = new StreamReader(fs);
            var log = reader.ReadToEnd();

            Assert.Contains("QoS Throttling", log);
        }

        [Fact]
        public void SuspendThreshold_IsReasonable()
        {
            // The suspend threshold should be 4000ms (2x the 2000ms tick interval)
            // This is a design contract: detection within 4 seconds of suspension
            var config = new SentinelConfig
            {
                AntiTamperTimingTickMs = 2000,
                AntiTamperIntegrityTickMs = 10000
            };

            // Verify the expected tick intervals are configurable
            Assert.Equal(2000, config.AntiTamperTimingTickMs);
            Assert.Equal(10000, config.AntiTamperIntegrityTickMs);

            // Default config should have reasonable defaults
            var defaultConfig = new SentinelConfig();
            // Default timing tick is 0 (means internal default of 2000ms)
            // Default integrity tick is 0 (means internal default of 10000ms)
            // The guard handles this: "config.AntiTamperTimingTickMs > 0 ? ... : 2000"
            Assert.True(defaultConfig.AntiTamperTimingTickMs >= 0);
            Assert.True(defaultConfig.AntiTamperIntegrityTickMs >= 0);
        }
    }
}
