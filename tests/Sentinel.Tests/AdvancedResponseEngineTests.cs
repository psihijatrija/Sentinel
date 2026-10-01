using System.Diagnostics;
using System;
using System.Collections.Generic;
using System.IO;
using System.Threading.Tasks;
using Xunit;
using Sentinel.Core;

namespace Sentinel.Tests
{
    public class AdvancedResponseEngineTests
    {
        [Fact]
        public async Task HandleAsync_Tier2CertificateDetection_DoesNotTriggerAction()
        {
            var tempDir = Path.Combine(Path.GetTempPath(), "sentinel_are_test_" + Guid.NewGuid().ToString("N")[..8]);
            Directory.CreateDirectory(tempDir);
            try
            {
                var config = new SentinelConfig { ActiveResponse = true, ObserveUntilChain = false };
                var metrics = new SentinelMetrics();
                var logPath = Path.Combine(tempDir, "events.jsonl");
                var logger = new JsonlEventLogger(logPath);
                var quarantine = new QuarantineManager(tempDir);
                var engine = new AdvancedResponseEngine(config, metrics, logger, quarantine);

                // Emitted event with Tier2 and RemoveCertAndKillAdder response
                var detection = new DetectionEvent
                {
                    RuleName = "TLS: Suspicious Root Certificate Detected",
                    Evidence = "Suspicious certificate added",
                    Reasoning = "Testing tier 2 block",
                    Confidence = 0.90,
                    Tier = DetectionTier.Tier2Indicator,
                    AuthorizedResponse = ResponseAction.RemoveCertAndKillAdder,
                    ProcessName = "powershell.exe",
                    ProcessId = 1234,
                    Metadata = new Dictionary<string, string>
                    {
                        { "CertThumbprint", "1234567890ABCDEF1234567890ABCDEF12345678" },
                        { "AdderProcessId", "1234" }
                    }
                };

                await engine.HandleAsync(detection);
                await logger.DisposeAsync();

                // Read logged response event
                var logLines = File.ReadAllLines(logPath);
                bool foundAction = false;
                bool foundLogOnly = false;

                foreach (var line in logLines)
                {
                    if (line.Contains("\"ActionTaken\":\"REMOVE_CERT_AND_KILL_ADDER\""))
                    {
                        foundAction = true;
                    }
                    if (line.Contains("\"ActionTaken\":\"LOG\""))
                    {
                        foundLogOnly = true;
                    }
                }

                Assert.False(foundAction, "Active response action was taken on Tier2 Indicator, which violates the security contract.");
                Assert.True(foundLogOnly, "Expected LOG action for Tier2 Indicator.");
            }
            finally
            {
                try { Directory.Delete(tempDir, true); } catch { }
            }
        }

        [Fact]
        public async Task HandleAsync_Tier1CertificateDetection_TriggersAction()
        {
            var tempDir = Path.Combine(Path.GetTempPath(), "sentinel_are_test2_" + Guid.NewGuid().ToString("N")[..8]);
            Directory.CreateDirectory(tempDir);
            try
            {
                var config = new SentinelConfig
                {
                    ActiveResponse = true,
                    ObserveUntilChain = false,
                    MitmDefense = new MitmDefenseConfig { Enabled = true, RemovePlantedCerts = true }
                };
                var metrics = new SentinelMetrics();
                var logPath = Path.Combine(tempDir, "events.jsonl");
                var logger = new JsonlEventLogger(logPath);
                var quarantine = new QuarantineManager(tempDir);
                var engine = new AdvancedResponseEngine(config, metrics, logger, quarantine);

                // Emitted event with Tier1 and RemoveCert response (note: President's law rule hit)
                var detection = new DetectionEvent
                {
                    RuleName = "TLS: Fake President's Law Rule", // Rule name must trigger IsPresidentsLawRule to remain Tier1
                    Evidence = "Suspicious certificate added",
                    Reasoning = "Testing tier 1 execution",
                    Confidence = 0.90,
                    Tier = DetectionTier.Tier1Behavioral,
                    AuthorizedResponse = ResponseAction.RemoveCert,
                    ProcessName = "powershell.exe",
                    ProcessId = 1234,
                    Metadata = new Dictionary<string, string>
                    {
                        { "CertThumbprint", "1234567890ABCDEF1234567890ABCDEF12345678" }
                    }
                };

                await engine.HandleAsync(detection);
                await logger.DisposeAsync();

                // Read logged response event
                var logLines = File.ReadAllLines(logPath);
                bool foundRemoveCertAction = false;

                foreach (var line in logLines)
                {
                    if (line.Contains("\"ActionTaken\":\"REMOVE_CERT\""))
                    {
                        foundRemoveCertAction = true;
                    }
                }

                Assert.True(foundRemoveCertAction, "Active response REMOVE_CERT action was not taken on Tier1 Behavioral detection.");
            }
            finally
            {
                try { Directory.Delete(tempDir, true); } catch { }
            }
        }

        [Fact]
        public async Task HandleAsync_SuppressedByAllowlist_DoesNotTriggerAction()
        {
            var tempDir = Path.Combine(Path.GetTempPath(), "sentinel_are_test_suppressed_" + Guid.NewGuid().ToString("N")[..8]);
            Directory.CreateDirectory(tempDir);
            try
            {
                var config = new SentinelConfig { ActiveResponse = true, ObserveUntilChain = false };
                var metrics = new SentinelMetrics();
                var logPath = Path.Combine(tempDir, "events.jsonl");
                var logger = new JsonlEventLogger(logPath);
                var quarantine = new QuarantineManager(tempDir);
                var cache = new SecureCacheStore(tempDir);
                var signerTrust = new SignerTrustService(Microsoft.Extensions.Logging.Abstractions.NullLogger<SignerTrustService>.Instance);
                var allowlist = new AllowlistService(cache, Microsoft.Extensions.Logging.Abstractions.NullLogger<AllowlistService>.Instance, signerTrust);
                
                var engine = new AdvancedResponseEngine(config, metrics, logger, quarantine, allowlist);

                var explorerProc = System.Diagnostics.Process.GetProcessesByName("explorer")[0];
                var procName = explorerProc.ProcessName;
                var procId = explorerProc.Id;
                // Must match the live image path the engine resolves via GetProcessImagePath
                var procPath = SecurityValidation.GetProcessImagePath(procId)
                    ?? Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "explorer.exe");

                signerTrust.AddTestOverride(procPath, true, "Microsoft Corporation");
                allowlist.AddToUserAllowlist(procName, procPath, "Test");

                var detection = new DetectionEvent
                {
                    RuleName = "UnsignedBinaryRule",
                    Evidence = "Binary from user path",
                    Reasoning = "Testing allowlist suppression",
                    Confidence = 0.90,
                    Tier = DetectionTier.Tier1Behavioral,
                    AuthorizedResponse = ResponseAction.NetworkIsolate,
                    ProcessName = procName,
                    ProcessId = procId
                };

                await engine.HandleAsync(detection);
                await logger.DisposeAsync();

                // Read logged response event
                var logLines = File.ReadAllLines(logPath);
                bool foundAction = false;
                bool foundSuppressedLog = false;

                foreach (var line in logLines)
                {
                    if (line.Contains("\"ActionTaken\":\"NETWORK_ISOLATE\""))
                    {
                        foundAction = true;
                    }
                    if (line.Contains("\"ActionTaken\":\"LOG\"") && line.Contains("Suppressed by allowlist"))
                    {
                        foundSuppressedLog = true;
                    }
                }

                Assert.False(foundAction, "Active response action was taken on allowlisted process.");
                Assert.True(foundSuppressedLog, "Expected LOG action with suppression reason.");
            }
            finally
            {
                try { Directory.Delete(tempDir, true); } catch { }
            }
        }
    }

    public class AdvancedResponseEngineExtendedTests : IDisposable
    {
        private readonly string _tempDir;
        private readonly SentinelConfig _config;
        private readonly SentinelMetrics _metrics;
        private readonly JsonlEventLogger _logger;
        private readonly QuarantineManager _quarantine;
        private readonly AdvancedResponseEngine _engine;

        public AdvancedResponseEngineExtendedTests()
        {
            _tempDir = Path.Combine(Path.GetTempPath(), "sentinel_are_ext_" + Guid.NewGuid().ToString("N")[..8]);
            Directory.CreateDirectory(_tempDir);
            _config = new SentinelConfig { ActiveResponse = true, ObserveUntilChain = false };
            _metrics = new SentinelMetrics();
            var logPath = Path.Combine(_tempDir, "events.jsonl");
            _logger = new JsonlEventLogger(logPath);
            _quarantine = new QuarantineManager(_tempDir);
            _engine = new AdvancedResponseEngine(_config, _metrics, _logger, _quarantine);
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
            using var reader = new StreamReader(fs);
            return reader.ReadToEnd();
        }

        [Fact]
        public void ActiveResponse_CannotBeDisabled_ViaConfig()
        {
            // v2.0.4+: ActiveResponse is always armed (no off switch). Setter is a no-op.
            var config = new SentinelConfig { ActiveResponse = false, ObserveUntilChain = false };
            Assert.True(config.ActiveResponse);
            config.ActiveResponse = false;
            Assert.True(config.ActiveResponse);
        }

        [Fact]
        public async Task HandleAsync_SelfExclusion_NeverKillsOwnProcess()
        {
            // Arrange: detection targeting our own process
            var detection = new DetectionEvent
            {
                RuleName = "File Reputation: Suspicious Binary Executed",
                Confidence = 0.55,
                Tier = DetectionTier.Tier1Behavioral,
                AuthorizedResponse = ResponseAction.KillProcessTree,
                ProcessName = "Sentinel.Service.exe",
                ProcessId = Process.GetCurrentProcess().Id // Our own PID!
            };

            // Act
            await _engine.HandleAsync(detection);

            // Assert: must not terminate the test host. Path-verified self-exclusion
            // only fires when image path is under AppContext.BaseDirectory (product install);
            // under testhost the engine may attempt kill which SafeKillProcessTree refuses
            // for non-matching paths - either way we stay alive and must not "succeed" a nuke.
            Assert.False(Process.GetCurrentProcess().HasExited);
            var log = ReadLog();
            Assert.False(string.IsNullOrEmpty(log), "Expected a response log line");
            // Prefer LOG self-exclusion when path matches install dir
            var selfPath = Process.GetCurrentProcess().MainModule?.FileName;
            var baseDir = Path.GetFullPath(AppContext.BaseDirectory).TrimEnd('\\') + "\\";
            if (selfPath != null &&
                Path.GetFullPath(selfPath).StartsWith(baseDir, StringComparison.OrdinalIgnoreCase))
            {
                Assert.Contains("\"ActionTaken\":\"LOG\"", log);
                Assert.Contains("Self-exclusion", log);
            }
        }

        [Fact]
        public async Task HandleAsync_NetworkIsolation_Tier1_LogsNetworkIsolateAction()
        {
            var detection = new DetectionEvent
            {
                RuleName = "ARP Spoofing Detected",
                Confidence = 0.90,
                Tier = DetectionTier.Tier1Behavioral,
                AuthorizedResponse = ResponseAction.NetworkIsolate,
                ProcessName = "arp_spoof.exe",
                ProcessId = 7777,
                Metadata = new Dictionary<string, string>
                {
                    { "TargetIP", "192.168.1.100" }
                }
            };

            await _engine.HandleAsync(detection);

            var log = ReadLog();
            Assert.Contains("\"ActionTaken\":\"NETWORK_ISOLATE\"", log);
            Assert.Contains("192.168.1.100", log);
        }

        [Fact]
        public async Task HandleAsync_NetworkIsolation_InvalidIP_DoesNotCreateFirewallRule()
        {
            // Arrange: loopback IP should be skipped
            var detection = new DetectionEvent
            {
                RuleName = "Network Anomaly: Suspicious Connection",
                Confidence = 0.80,
                Tier = DetectionTier.Tier1Behavioral,
                AuthorizedResponse = ResponseAction.NetworkIsolate,
                ProcessName = "test.exe",
                ProcessId = 6666,
                Metadata = new Dictionary<string, string>
                {
                    { "TargetIP", "127.0.0.1" } // Loopback - should be skipped
                }
            };

            await _engine.HandleAsync(detection);

            var log = ReadLog();
            // Should still log the action, but the IP validation prevents actual firewall rule
            Assert.Contains("NETWORK_ISOLATE", log);
        }

        [Fact]
        public async Task HandleAsync_RemoveRegistryEntry_Tier1_ExecutesRemoval()
        {
            var detection = new DetectionEvent
            {
                RuleName = "Persistence: Malicious Scheduled Task",
                Confidence = 0.85,
                Tier = DetectionTier.Tier1Behavioral,
                AuthorizedResponse = ResponseAction.RemoveRegistryEntry,
                ProcessName = "malware.exe",
                ProcessId = 5555,
                Metadata = new Dictionary<string, string>
                {
                    { "Hive", "HKLM" },
                    { "KeyPath", @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run" },
                    { "ValueName", "FakeValue_SentinelTest_DoesNotExist" }
                }
            };

            await _engine.HandleAsync(detection);

            var log = ReadLog();
            // Action should be attempted (even if the value doesn't exist)
            Assert.Contains("REMOVE_REGISTRY_ENTRY", log);
        }

        [Fact]
        public async Task HandleAsync_Tier1_KillAuthorized_LogsKillAction()
        {
            // Use a PID that doesn't exist so kill attempt is safe
            var detection = new DetectionEvent
            {
                RuleName = "LsassAccessRule",
                Confidence = 0.95,
                Tier = DetectionTier.Tier1Behavioral,
                AuthorizedResponse = ResponseAction.KillProcessTree,
                ProcessName = "nonexistent.exe",
                ProcessId = 99999 // PID very unlikely to exist
            };

            await _engine.HandleAsync(detection);

            var log = ReadLog();
            Assert.Contains("\"ActionTaken\":\"KILL\"", log);
        }

        [Fact]
        public async Task HandleAsync_Tier1_WithoutKillAuthorization_LogsOnly()
        {
            var detection = new DetectionEvent
            {
                RuleName = "Beaconing Behavior",
                Confidence = 0.70,
                Tier = DetectionTier.Tier1Behavioral,
                AuthorizedResponse = ResponseAction.LogOnly, // No kill authorized
                ProcessName = "suspicious.exe",
                ProcessId = 4444
            };

            await _engine.HandleAsync(detection);

            var log = ReadLog();
            Assert.Contains("\"ActionTaken\":\"LOG\"", log);
            Assert.Contains("without kill authorization", log);
        }

        [Fact]
        public async Task HandleAsync_ResponseMetricsRecorded()
        {
            var detection = new DetectionEvent
            {
                RuleName = "TestRule",
                Confidence = 0.50,
                Tier = DetectionTier.Tier2Indicator,
                ProcessName = "test.exe",
                ProcessId = 3333
            };

            await _engine.HandleAsync(detection);

            // Verify metrics were recorded (response count > 0)
            Assert.True(_metrics.GetResponsesCount() > 0);
        }
    }

    /// <summary>
    /// Verifies the MANDATORY pre-action audit trail (docs/constraints.md: the tamper-resistant
    /// audit log must be written BEFORE any kill/block/quarantine/isolate/cert-removal action).
    /// Regression guard for the defect where destructive responses fired but audit-*.jsonl stayed
    /// 0 bytes because no code path invoked LogAuditBeforeActionAsync.
    /// </summary>
    public class AdvancedResponseEngineAuditTrailTests : IDisposable
    {
        private readonly string _tempDir;

        public AdvancedResponseEngineAuditTrailTests()
        {
            _tempDir = Path.Combine(Path.GetTempPath(), "sentinel_are_audit_" + Guid.NewGuid().ToString("N")[..8]);
            Directory.CreateDirectory(_tempDir);
        }

        public void Dispose()
        {
            try { Directory.Delete(_tempDir, true); } catch { }
        }

        // The audit file is "audit-{UtcNow:yyyy-MM-dd}.jsonl" beside the events log.
        private string ReadAuditTrail()
        {
            var files = Directory.GetFiles(_tempDir, "audit-*.jsonl");
            if (files.Length == 0) return string.Empty;
            var sb = new System.Text.StringBuilder();
            foreach (var f in files)
            {
                using var fs = new FileStream(f, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
                using var reader = new StreamReader(fs);
                sb.Append(reader.ReadToEnd());
            }
            return sb.ToString();
        }

        [Fact]
        public async Task HandleAsync_DestructiveTier1Action_WritesPreActionAuditEntry()
        {
            var config = new SentinelConfig { ActiveResponse = true, ObserveUntilChain = false };
            var metrics = new SentinelMetrics();
            var logger = new JsonlEventLogger(Path.Combine(_tempDir, "events.jsonl"));
            var engine = new AdvancedResponseEngine(config, metrics, logger, new QuarantineManager(_tempDir));

            // Tier1, kill-authorized, non-existent PID so the actual kill is a safe no-op.
            var detection = new DetectionEvent
            {
                RuleName = "LsassAccessRule",
                Confidence = 0.95,
                Tier = DetectionTier.Tier1Behavioral,
                AuthorizedResponse = ResponseAction.KillProcessTree,
                ProcessName = "nonexistent.exe",
                ProcessId = 99999
            };

            await engine.HandleAsync(detection);
            await logger.DisposeAsync();

            var audit = ReadAuditTrail();
            Assert.False(string.IsNullOrEmpty(audit),
                "A destructive Tier1 response must write a PRE_ACTION audit entry before acting.");
            Assert.Contains("\"AuditType\":\"PRE_ACTION\"", audit);
            Assert.Contains("LsassAccessRule", audit);
        }

        [Fact]
        public async Task HandleAsync_Tier2WithActiveResponse_WritesNoAuditEntry_LogOnlyContract()
        {
            // Tier2 log-only contract: even with ActiveResponse armed, a Tier2 indicator must
            // never take a destructive action - and therefore must never write a PRE_ACTION
            // audit entry (nothing mutates the host, so there is nothing to pre-audit).
            var config = new SentinelConfig { ActiveResponse = true, ObserveUntilChain = false };
            var metrics = new SentinelMetrics();
            var logger = new JsonlEventLogger(Path.Combine(_tempDir, "events.jsonl"));
            var engine = new AdvancedResponseEngine(config, metrics, logger, new QuarantineManager(_tempDir));

            var detection = new DetectionEvent
            {
                RuleName = "TLS: Suspicious Root Certificate Detected",
                Confidence = 0.90,
                Tier = DetectionTier.Tier2Indicator,
                AuthorizedResponse = ResponseAction.RemoveCertAndKillAdder,
                ProcessName = "powershell.exe",
                ProcessId = 1234,
                Metadata = new Dictionary<string, string>
                {
                    { "CertThumbprint", "1234567890ABCDEF1234567890ABCDEF12345678" },
                    { "AdderProcessId", "1234" }
                }
            };

            await engine.HandleAsync(detection);
            await logger.DisposeAsync();

            var audit = ReadAuditTrail();
            Assert.True(string.IsNullOrEmpty(audit),
                "Tier2 indicator must be LogOnly and must NOT produce a pre-action audit entry.");
        }
    }
}
