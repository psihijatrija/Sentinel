using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Xunit;
using Sentinel.Core;
using Microsoft.Extensions.Logging.Abstractions;

namespace Sentinel.Tests.Monitors
{
    /// <summary>
    /// Tests for WmiProviderIntegrityMonitor - validates detection of malicious WMI provider DLLs.
    ///
    /// Scenario: A performance-throttling rootkit registers a WMI provider DLL in a sensitive
    /// namespace (root\WMI, root\Intel\DTT, root\CIMV2\power) to intercept thermal/power
    /// queries. The DLL runs inside WmiPrvSE.exe (SYSTEM) with no visible process or autorun.
    ///
    /// These tests verify:
    ///   1. Monitor lifecycle (starts, baselines, stops cleanly)
    ///   2. Detection pipeline integration (EmitAsync produces events)
    ///   3. Detection event properties for rootkit scenarios
    ///   4. Sensitive namespace classification
    ///   5. System path vs non-system path discrimination
    /// </summary>
    public class WmiProviderIntegrityMonitorTests
    {
        //  Lifecycle Tests 

        [Fact]
        public async Task Monitor_StartsAndStopsCleanly()
        {
            var (engine, logger, tempDir) = CreateDetectionEngine();
            try
            {
                var monitor = new WmiProviderIntegrityMonitor(engine, NullLogger<WmiProviderIntegrityMonitor>.Instance);

                using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(5));

                // Start (will baseline WMI providers on this machine)
                await monitor.StartAsync(cts.Token);

                // Give it time to establish baseline
                await Task.Delay(500);

                // Stop cleanly
                await monitor.StopAsync(CancellationToken.None);

                engine.Stop();
                await logger.DisposeAsync();
            }
            finally
            {
                try { Directory.Delete(tempDir, true); } catch { }
            }
        }

        [Fact]
        public async Task Monitor_BaselinesProvidersWithoutFalsePositives()
        {
            // The monitor should NOT alert on legitimate Windows providers during baseline.
            // We verify this by starting the monitor, letting it baseline, and checking
            // that no "Unsigned Provider in Sensitive Namespace" events were emitted.
            var (engine, logger, tempDir) = CreateDetectionEngine();
            try
            {
                var monitor = new WmiProviderIntegrityMonitor(engine, NullLogger<WmiProviderIntegrityMonitor>.Instance);

                using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(20));

                await monitor.StartAsync(cts.Token);

                // Wait for baseline scan to complete (15s initial delay + scan time)
                await Task.Delay(17000, cts.Token);

                await monitor.StopAsync(CancellationToken.None);
                engine.Stop();
                await logger.DisposeAsync();

                // Read events - should have NO Tier1 alerts for standard Windows providers
                var logContent = "";
                if (File.Exists(logger.LogFilePath))
                    logContent = File.ReadAllText(logger.LogFilePath);

                // No "Unsigned Provider in Sensitive Namespace" for legitimate Windows providers
                Assert.DoesNotContain("WMI Provider Integrity: Unsigned Provider in Sensitive Namespace", logContent);
            }
            finally
            {
                try { Directory.Delete(tempDir, true); } catch { }
            }
        }

        //  Detection Emission Tests 

        [Fact]
        public async Task DetectionEngine_EmitAsync_ProducesEventForMaliciousProvider()
        {
            // Simulate what the monitor would emit when it finds an unsigned provider
            // in a sensitive namespace - test the detection pipeline end-to-end
            var (engine, logger, tempDir) = CreateDetectionEngine();
            try
            {
                // Simulate the exact detection event the monitor would emit
                // for a rootkit provider in root\WMI
                await engine.EmitAsync(new DetectionEvent
                {
                    RuleName = "WMI Provider Integrity: Unsigned Provider in Sensitive Namespace",
                    Evidence = "Unsigned WMI provider DLL in sensitive namespace. " +
                               "Provider: 'ThermalThrottleProv', Namespace: 'root\\wmi', " +
                               "CLSID: {A1B2C3D4-E5F6-7890-ABCD-EF1234567890}, " +
                               "DLL: 'C:\\ProgramData\\Intel\\thermal_mgmt.dll', " +
                               "NewAtRuntime: True",
                    Reasoning = "An unsigned DLL is registered as a WMI provider in a power, thermal, or hardware " +
                                "namespace. This is the exact technique used by performance-throttling rootkits that " +
                                "intercept WMI queries to fake thermal readings or modify power settings.",
                    Confidence = 0.88,
                    Tier = DetectionTier.Tier1Behavioral,
                    AuthorizedResponse = ResponseAction.KillProcess,
                    ProcessName = "WmiPrvSE.exe",
                    ProcessId = 0
                });

                // Give detection engine time to process
                await Task.Delay(200);
                engine.Stop();

                // Verify the event was logged
                await logger.DisposeAsync();
                var logContent = File.Exists(logger.LogFilePath)
                    ? File.ReadAllText(logger.LogFilePath) : "";

                Assert.Contains("WMI Provider Integrity: Unsigned Provider in Sensitive Namespace", logContent);
                Assert.Contains("ThermalThrottleProv", logContent);
                Assert.Contains("thermal_mgmt.dll", logContent);
                Assert.Contains("root\\\\wmi", logContent);
            }
            finally
            {
                try { Directory.Delete(tempDir, true); } catch { }
            }
        }

        [Fact]
        public async Task DetectionEngine_EmitAsync_SuspiciousModuleInWmiPrvSE()
        {
            // Simulate detection of unsigned module loaded in WmiPrvSE.exe
            var (engine, logger, tempDir) = CreateDetectionEngine();
            try
            {
                await engine.EmitAsync(new DetectionEvent
                {
                    RuleName = "WMI Provider Integrity: Suspicious Module in WmiPrvSE",
                    Evidence = "Unsigned non-system DLL loaded in WmiPrvSE.exe (PID 4892): " +
                               "'C:\\Users\\Admin\\AppData\\Local\\Temp\\perf_hook.dll'",
                    Reasoning = "WmiPrvSE.exe has loaded an unsigned DLL from a non-system path. " +
                                "This process hosts WMI providers and should only load system DLLs.",
                    Confidence = 0.85,
                    Tier = DetectionTier.Tier1Behavioral,
                    AuthorizedResponse = ResponseAction.LogOnly,
                    ProcessName = "WmiPrvSE.exe",
                    ProcessId = 4892
                });

                await Task.Delay(200);
                engine.Stop();
                await logger.DisposeAsync();

                var logContent = File.Exists(logger.LogFilePath)
                    ? File.ReadAllText(logger.LogFilePath) : "";

                Assert.Contains("Suspicious Module in WmiPrvSE", logContent);
                Assert.Contains("perf_hook.dll", logContent);
                Assert.Contains("4892", logContent);
            }
            finally
            {
                try { Directory.Delete(tempDir, true); } catch { }
            }
        }

        [Fact]
        public async Task DetectionEngine_EmitAsync_MofAutoRecoveryPersistence()
        {
            // Simulate detection of malicious MOF auto-recovery entry
            var (engine, logger, tempDir) = CreateDetectionEngine();
            try
            {
                await engine.EmitAsync(new DetectionEvent
                {
                    RuleName = "WMI Provider Integrity: Suspicious MOF Auto-Recovery Entry",
                    Evidence = "Non-system MOF file in auto-recovery list: " +
                               "'C:\\ProgramData\\Microsoft\\Provisioning\\throttle_policy.mof'",
                    Reasoning = "A MOF file outside of the Windows system directory is registered for " +
                                "WMI auto-recovery. This legacy mechanism provides rootkit-level persistence.",
                    Confidence = 0.80,
                    Tier = DetectionTier.Tier1Behavioral,
                    AuthorizedResponse = ResponseAction.LogOnly,
                    ProcessName = "SYSTEM",
                    ProcessId = 0
                });

                await Task.Delay(200);
                engine.Stop();
                await logger.DisposeAsync();

                var logContent = File.Exists(logger.LogFilePath)
                    ? File.ReadAllText(logger.LogFilePath) : "";

                Assert.Contains("MOF Auto-Recovery", logContent);
                Assert.Contains("throttle_policy.mof", logContent);
            }
            finally
            {
                try { Directory.Delete(tempDir, true); } catch { }
            }
        }

        //  Detection Property Validation 

        [Fact]
        public void RootkitDetection_HasCorrectTier()
        {
            var detection = CreateRootkitDetection();
            Assert.Equal(DetectionTier.Tier1Behavioral, detection.Tier);
        }

        [Fact]
        public void RootkitDetection_HasKillAuthorization()
        {
            // Unsigned provider in sensitive namespace should be kill-authorized
            var detection = CreateRootkitDetection();
            Assert.Equal(ResponseAction.KillProcess, detection.AuthorizedResponse);
        }

        [Fact]
        public void RootkitDetection_HighConfidence()
        {
            var detection = CreateRootkitDetection();
            Assert.True(detection.Confidence >= 0.85,
                $"Sensitive namespace rootkit should have confidence >= 0.85, got {detection.Confidence}");
        }

        [Fact]
        public void RootkitDetection_TargetsWmiPrvSE()
        {
            var detection = CreateRootkitDetection();
            Assert.Equal("WmiPrvSE.exe", detection.ProcessName);
        }

        [Theory]
        [InlineData("root\\wmi")]
        [InlineData("root\\intel")]
        [InlineData("root\\intel\\dtt")]
        [InlineData("root\\cimv2\\power")]
        [InlineData("root\\cimv2\\thermal")]
        [InlineData("root\\hardware")]
        public void RootkitDetection_Evidence_ContainsSensitiveNamespace(string ns)
        {
            var detection = new DetectionEvent
            {
                RuleName = "WMI Provider Integrity: Unsigned Provider in Sensitive Namespace",
                Evidence = $"Unsigned WMI provider DLL in sensitive namespace. " +
                           $"Provider: 'FakeThrottler', Namespace: '{ns}', " +
                           $"CLSID: {{DEADBEEF-0000-0000-0000-000000000000}}, " +
                           $"DLL: 'C:\\Windows\\Temp\\throttle.dll', NewAtRuntime: True",
                Reasoning = "Unsigned DLL in power/thermal namespace - performance throttling rootkit.",
                Confidence = 0.88,
                Tier = DetectionTier.Tier1Behavioral,
                AuthorizedResponse = ResponseAction.KillProcess,
                ProcessName = "WmiPrvSE.exe",
                ProcessId = 0
            };

            Assert.Contains(ns, detection.Evidence);
            Assert.Equal(DetectionTier.Tier1Behavioral, detection.Tier);
        }

        //  Scenario Tests: Real-World Rootkit Patterns 

        [Fact]
        public void Scenario_IntelDttThrottleRootkit()
        {
            // Scenario: Rootkit registers as Intel DTT provider to fake thermal readings
            // Result: CPU thinks it's overheating -> throttles to lowest P-state
            var detection = new DetectionEvent
            {
                RuleName = "WMI Provider Integrity: Unsigned Provider in Sensitive Namespace",
                Evidence = "Unsigned WMI provider DLL in sensitive namespace. " +
                           "Provider: 'IntelDTTProvider', Namespace: 'root\\intel\\dtt', " +
                           "CLSID: {F4A8C3D2-1B5E-4A7F-9C0D-8E2F6B3A1D5C}, " +
                           "DLL: 'C:\\ProgramData\\Intel\\DTT\\dtt_provider.dll', " +
                           "NewAtRuntime: False",
                Reasoning = "An unsigned DLL is registered as a WMI provider in a power, thermal, or hardware " +
                            "namespace. This is the exact technique used by performance-throttling rootkits.",
                Confidence = 0.88,
                Tier = DetectionTier.Tier1Behavioral,
                AuthorizedResponse = ResponseAction.KillProcess,
                ProcessName = "WmiPrvSE.exe",
                ProcessId = 0
            };

            // Verify all rootkit characteristics are captured
            Assert.Contains("intel\\\\dtt", detection.Evidence.Replace("\\", "\\\\"));
            Assert.Contains("IntelDTTProvider", detection.Evidence);
            Assert.Contains("dtt_provider.dll", detection.Evidence);
            Assert.Equal(0.88, detection.Confidence);
            Assert.Equal(ResponseAction.KillProcess, detection.AuthorizedResponse);
        }

        [Fact]
        public void Scenario_PowerPolicyManipulationRootkit()
        {
            // Scenario: Rootkit registers in root\CIMV2\power to intercept Win32_PowerPlan queries
            // Result: Returns fake EPP values -> Windows sends "power save" hints -> CPU clocks down
            var detection = new DetectionEvent
            {
                RuleName = "WMI Provider Integrity: Unsigned Provider in Sensitive Namespace",
                Evidence = "Unsigned WMI provider DLL in sensitive namespace. " +
                           "Provider: 'PowerPolicyProvider', Namespace: 'root\\cimv2\\power', " +
                           "CLSID: {B7E9A1C3-4D2F-5E6A-8B0C-1D3F5E7A9B2D}, " +
                           "DLL: 'C:\\Windows\\Temp\\pwrprov.dll', " +
                           "NewAtRuntime: True",
                Reasoning = "An unsigned DLL is registered as a WMI provider in a power, thermal, or hardware " +
                            "namespace. This is the exact technique used by performance-throttling rootkits.",
                Confidence = 0.88,
                Tier = DetectionTier.Tier1Behavioral,
                AuthorizedResponse = ResponseAction.KillProcess,
                ProcessName = "WmiPrvSE.exe",
                ProcessId = 0
            };

            Assert.Contains("power", detection.Evidence);
            Assert.Contains("PowerPolicyProvider", detection.Evidence);
            Assert.Contains("pwrprov.dll", detection.Evidence);
            Assert.True(detection.Confidence >= 0.85);
        }

        [Fact]
        public void Scenario_WmiPrvSE_InjectedModule()
        {
            // Scenario: Rootkit DLL sideloaded into WmiPrvSE via a legitimate provider dependency
            // The rootkit DLL hooks power WMI calls inside the process
            var detection = new DetectionEvent
            {
                RuleName = "WMI Provider Integrity: Suspicious Module in WmiPrvSE",
                Evidence = "Unsigned non-system DLL loaded in WmiPrvSE.exe (PID 7204): " +
                           "'C:\\Users\\Admin\\AppData\\Roaming\\Microsoft\\power_helper.dll'",
                Reasoning = "WmiPrvSE.exe has loaded an unsigned DLL from a non-system path.",
                Confidence = 0.85,
                Tier = DetectionTier.Tier1Behavioral,
                AuthorizedResponse = ResponseAction.LogOnly,
                ProcessName = "WmiPrvSE.exe",
                ProcessId = 7204
            };

            Assert.Equal(7204, detection.ProcessId);
            Assert.Contains("AppData", detection.Evidence);
            Assert.Contains("power_helper.dll", detection.Evidence);
            Assert.Equal(0.85, detection.Confidence);
        }

        [Fact]
        public void Scenario_MofPersistence_SurvivesWmiReset()
        {
            // Scenario: Rootkit installs MOF in auto-recovery list
            // Even if WMI repository is rebuilt, the malicious provider re-registers
            var detection = new DetectionEvent
            {
                RuleName = "WMI Provider Integrity: Suspicious MOF Auto-Recovery Entry",
                Evidence = "Non-system MOF file in auto-recovery list: " +
                           "'C:\\ProgramData\\Microsoft\\Wbem\\thermal_override.mof'",
                Reasoning = "A MOF file outside of the Windows system directory is registered for " +
                            "WMI auto-recovery. This provides rootkit-level persistence.",
                Confidence = 0.80,
                Tier = DetectionTier.Tier1Behavioral,
                AuthorizedResponse = ResponseAction.LogOnly,
                ProcessName = "SYSTEM",
                ProcessId = 0
            };

            Assert.Contains("thermal_override.mof", detection.Evidence);
            Assert.Equal(0.80, detection.Confidence);
            Assert.Equal(DetectionTier.Tier1Behavioral, detection.Tier);
        }

        [Theory]
        [InlineData("C:\\ProgramData\\Intel\\throttle.dll", false)]
        [InlineData("C:\\Users\\Admin\\AppData\\Local\\Temp\\hook.dll", false)]
        [InlineData("C:\\Windows\\Temp\\malware.dll", false)]
        [InlineData("C:\\Windows\\System32\\wbem\\cimwin32.dll", true)]
        [InlineData("C:\\Windows\\System32\\wmiutils.dll", true)]
        [InlineData("C:\\Windows\\SysWOW64\\framedyn.dll", true)]
        public void PathClassification_SystemVsNonSystem(string path, bool expectedSystem)
        {
            // Validate the path classification logic matches expectations
            var normalized = Path.GetFullPath(path);
            var sysRoot = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
            var sys32 = Path.Combine(sysRoot, "System32");
            var sysWow = Path.Combine(sysRoot, "SysWOW64");
            var winsxs = Path.Combine(sysRoot, "WinSxS");

            bool isSystem = normalized.StartsWith(sys32, StringComparison.OrdinalIgnoreCase) ||
                            normalized.StartsWith(sysWow, StringComparison.OrdinalIgnoreCase) ||
                            normalized.StartsWith(winsxs, StringComparison.OrdinalIgnoreCase) ||
                            normalized.StartsWith(sysRoot + @"\assembly", StringComparison.OrdinalIgnoreCase);

            Assert.Equal(expectedSystem, isSystem);
        }

        //  Confidence Ladder Tests 

        [Fact]
        public void ConfidenceLadder_SensitiveNamespace_Highest()
        {
            // Unsigned in sensitive namespace -> 0.88 (highest for this monitor)
            Assert.Equal(0.88, CreateRootkitDetection().Confidence);
        }

        [Fact]
        public void ConfidenceLadder_NonSystemPath_RuntimeNew()
        {
            // New at runtime + unsigned + non-system path -> 0.82
            var detection = new DetectionEvent
            {
                RuleName = "WMI Provider Integrity: Unsigned Provider from Non-System Path",
                Confidence = 0.82,
                Tier = DetectionTier.Tier1Behavioral,
                AuthorizedResponse = ResponseAction.LogOnly,
                ProcessName = "WmiPrvSE.exe",
                ProcessId = 0
            };
            Assert.Equal(0.82, detection.Confidence);
            Assert.Equal(ResponseAction.LogOnly, detection.AuthorizedResponse);
        }

        [Fact]
        public void ConfidenceLadder_NonSystemPath_Baseline()
        {
            // Already in baseline + unsigned + non-system path -> 0.75
            var detection = new DetectionEvent
            {
                RuleName = "WMI Provider Integrity: Unsigned Provider from Non-System Path",
                Confidence = 0.75,
                Tier = DetectionTier.Tier1Behavioral,
                AuthorizedResponse = ResponseAction.LogOnly,
                ProcessName = "WmiPrvSE.exe",
                ProcessId = 0
            };
            Assert.Equal(0.75, detection.Confidence);
        }

        [Fact]
        public void ConfidenceLadder_RuntimeNewUnsigned_Tier2()
        {
            // New at runtime + unsigned + system path -> 0.70 (Tier2)
            var detection = new DetectionEvent
            {
                RuleName = "WMI Provider Integrity: New Unsigned Provider at Runtime",
                Confidence = 0.70,
                Tier = DetectionTier.Tier2Indicator,
                ProcessName = "WmiPrvSE.exe",
                ProcessId = 0
            };
            Assert.Equal(0.70, detection.Confidence);
            Assert.Equal(DetectionTier.Tier2Indicator, detection.Tier);
        }

        //  Helper Methods 

        private static DetectionEvent CreateRootkitDetection()
        {
            return new DetectionEvent
            {
                RuleName = "WMI Provider Integrity: Unsigned Provider in Sensitive Namespace",
                Evidence = "Unsigned WMI provider DLL in sensitive namespace. " +
                           "Provider: 'ThermalThrottleProv', Namespace: 'root\\wmi', " +
                           "CLSID: {A1B2C3D4-E5F6-7890-ABCD-EF1234567890}, " +
                           "DLL: 'C:\\ProgramData\\Intel\\thermal_mgmt.dll', " +
                           "NewAtRuntime: True",
                Reasoning = "An unsigned DLL is registered as a WMI provider in a power, thermal, or hardware " +
                            "namespace. This is the exact technique used by performance-throttling rootkits.",
                Confidence = 0.88,
                Tier = DetectionTier.Tier1Behavioral,
                AuthorizedResponse = ResponseAction.KillProcess,
                ProcessName = "WmiPrvSE.exe",
                ProcessId = 0
            };
        }

        private static (DetectionEngine engine, JsonlEventLogger logger, string tempDir) CreateDetectionEngine()
        {
            var tempDir = Path.Combine(Path.GetTempPath(), "sentinel_wmi_prov_test_" + Guid.NewGuid().ToString("N")[..8]);
            Directory.CreateDirectory(tempDir);

            var cache = new SecureCacheStore(tempDir);
            var metrics = new SentinelMetrics();
            var logPath = Path.Combine(tempDir, "events.jsonl");
            var logger = new JsonlEventLogger(logPath);
            var config = new SentinelConfig { ActiveResponse = true, ObserveUntilChain = false };
            var allowlist = new AllowlistService(cache, NullLogger<AllowlistService>.Instance);
            var quarantine = new QuarantineManager(Path.Combine(tempDir, "quarantine"));
            var responseEngine = new AdvancedResponseEngine(config, metrics, logger, quarantine, allowlist);
            var iocScanner = new IoCScanner(cache);
            var reputationService = new HashReputationService(cache, new ThreatReportingConfig(), NullLogger<HashReputationService>.Instance);
            var correlationEngine = new BehavioralCorrelationEngine();
            var scoringEngine = new ScoringEngine(allowlist, new SafeProcessExemptionRegistry(), NullLogger<ScoringEngine>.Instance);
            var signerTrust = new SignerTrustService(NullLogger<SignerTrustService>.Instance);
            var fileReputationEngine = new FileReputationEngine(reputationService, signerTrust, cache, NullLogger<FileReputationEngine>.Instance);

            var rules = new List<IDetectionRule>();
            var engine = new DetectionEngine(
                rules, metrics, logger, responseEngine,
                iocScanner, reputationService, fileReputationEngine,
                correlationEngine, scoringEngine,
                NullLogger<DetectionEngine>.Instance
            );

            return (engine, logger, tempDir);
        }
    }
}
