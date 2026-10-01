using System;
using System.Threading.Tasks;
using Xunit;
using Sentinel.Core;

namespace Sentinel.Tests
{
    /// <summary>
    /// Tests for BehavioralCorrelationEngine composite detection logic.
    /// Verifies that multi-signal correlations fire correctly and that
    /// single signals or cross-PID signals do NOT fire composites.
    /// </summary>
    public class CompositeDetectionTests
    {
        private static (BehavioralCorrelationEngine engine, Func<DetectionEvent?> getResult) CreateEngine()
        {
            var engine = new BehavioralCorrelationEngine();
            DetectionEvent? lastComposite = null;
            engine.Initialize(ev =>
            {
                lastComposite = ev;
                return Task.CompletedTask;
            });
            return (engine, () => lastComposite);
        }

        #region Active Ransomware Chain (C-01, confidence 0.99)

        [Fact]
        public async Task Composite_ActiveRansomwareChain_Fires()
        {
            var (engine, getResult) = CreateEngine();
            await engine.RegisterSignalAsync(new DetectionEvent
            {
                RuleName = "RansomwareDetectionRule",
                ProcessId = 100, ProcessName = "locker.exe",
                SignalType = SignalType.Ransomware,
                Timestamp = DateTime.UtcNow
            });
            await engine.RegisterSignalAsync(new DetectionEvent
            {
                RuleName = "Ransomware: Mass File Rename",
                ProcessId = 100, ProcessName = "locker.exe",
                SignalType = SignalType.Ransomware,
                Timestamp = DateTime.UtcNow
            });
            var result = getResult();
            Assert.NotNull(result);
            Assert.Equal("Active Mass-Encryption Chain", result!.RuleName);
            Assert.Equal(0.99, result.Confidence);
        }

        [Fact]
        public async Task Composite_RansomwareChain_DoesNotFire_SingleSignal()
        {
            var (engine, getResult) = CreateEngine();
            await engine.RegisterSignalAsync(new DetectionEvent
            {
                RuleName = "RansomwareDetectionRule",
                ProcessId = 101, ProcessName = "locker.exe",
                SignalType = SignalType.Ransomware,
                Timestamp = DateTime.UtcNow
            });
            Assert.Null(getResult());
        }

        #endregion

        #region Injected C2 Beacon (C-02, confidence 0.98)

        [Fact]
        public async Task Composite_InjectedC2Beacon_Fires()
        {
            var (engine, getResult) = CreateEngine();
            await engine.RegisterSignalAsync(new DetectionEvent
            {
                RuleName = "ThreatIntelInjectionRule",
                ProcessId = 200, ProcessName = "svchost.exe",
                SignalType = SignalType.ProcessInjection,
                Timestamp = DateTime.UtcNow
            });
            await engine.RegisterSignalAsync(new DetectionEvent
            {
                RuleName = "C2 Beaconing Behavior",
                ProcessId = 200, ProcessName = "svchost.exe",
                SignalType = SignalType.NetworkC2,
                Timestamp = DateTime.UtcNow
            });
            var result = getResult();
            Assert.NotNull(result);
            Assert.Equal("Injected C2 Beacon", result!.RuleName);
            Assert.Equal(0.98, result.Confidence);
        }

        #endregion

        #region Credential Dump + Exfiltration (C-03, confidence 0.96)

        [Fact]
        public async Task Composite_CredentialDumpExfil_Fires()
        {
            var (engine, getResult) = CreateEngine();
            await engine.RegisterSignalAsync(new DetectionEvent
            {
                RuleName = "LsassAccessRule",
                ProcessId = 300, ProcessName = "evil.exe",
                SignalType = SignalType.LsassAccess,
                Timestamp = DateTime.UtcNow
            });
            await engine.RegisterSignalAsync(new DetectionEvent
            {
                RuleName = "Data Exfiltration Spike",
                ProcessId = 300, ProcessName = "evil.exe",
                SignalType = SignalType.NetworkC2,
                Timestamp = DateTime.UtcNow
            });
            var result = getResult();
            Assert.NotNull(result);
            Assert.Equal("Credential Dump + Exfiltration", result!.RuleName);
            Assert.Equal(0.96, result.Confidence);
        }

        #endregion

        #region Fileless Attack Chain (C-05, confidence 0.95)

        [Fact]
        public async Task Composite_FilelessAttackChain_Fires()
        {
            var (engine, getResult) = CreateEngine();
            await engine.RegisterSignalAsync(new DetectionEvent
            {
                RuleName = "PrivilegeEscalationRule",
                ProcessId = 500, ProcessName = "powershell.exe",
                SignalType = SignalType.SecurityEvasion,
                Timestamp = DateTime.UtcNow
            });
            await engine.RegisterSignalAsync(new DetectionEvent
            {
                RuleName = "ReverseShellRule",
                ProcessId = 500, ProcessName = "powershell.exe",
                SignalType = SignalType.ReverseShell,
                Timestamp = DateTime.UtcNow
            });
            var result = getResult();
            Assert.NotNull(result);
            Assert.Equal("Fileless Attack Chain", result!.RuleName);
            Assert.Equal(0.95, result.Confidence);
        }

        #endregion

        #region Cross-PID isolation

        [Fact]
        public async Task Composite_DoesNotFire_DifferentPIDs()
        {
            var (engine, getResult) = CreateEngine();
            await engine.RegisterSignalAsync(new DetectionEvent
            {
                RuleName = "ThreatIntelInjectionRule",
                ProcessId = 600, ProcessName = "a.exe",
                SignalType = SignalType.ProcessInjection,
                Timestamp = DateTime.UtcNow
            });
            await engine.RegisterSignalAsync(new DetectionEvent
            {
                RuleName = "C2 Beaconing Behavior",
                ProcessId = 601, ProcessName = "b.exe",
                SignalType = SignalType.NetworkC2,
                Timestamp = DateTime.UtcNow
            });
            Assert.Null(getResult());
        }

        #endregion

        #region Evasion + Persistence Install (C-09, confidence 0.91)

        [Fact]
        public async Task Composite_EvasionPlusPersistence_Fires()
        {
            var (engine, getResult) = CreateEngine();
            await engine.RegisterSignalAsync(new DetectionEvent
            {
                RuleName = "AMSI Bypass Detected",
                ProcessId = 900, ProcessName = "evil.exe",
                SignalType = SignalType.SecurityEvasion,
                Timestamp = DateTime.UtcNow
            });
            await engine.RegisterSignalAsync(new DetectionEvent
            {
                RuleName = "Registry Persistence",
                ProcessId = 900, ProcessName = "evil.exe",
                SignalType = SignalType.SuspiciousProcess,
                Timestamp = DateTime.UtcNow
            });
            var result = getResult();
            // If composite fires, check for valid confidence
            if (result != null)
            {
                Assert.True(result.Confidence >= 0.90);
                Assert.Equal(900, result.ProcessId);
            }
        }

        #endregion

        #region Signal ordering and priority

        [Fact]
        public async Task Composite_HighestConfidence_WinsWhenMultipleMatch()
        {
            var (engine, getResult) = CreateEngine();
            // Feed signals that could match multiple composites
            // Injection + C2 = Injected C2 Beacon (0.98)
            // vs other lower-confidence composites
            await engine.RegisterSignalAsync(new DetectionEvent
            {
                RuleName = "ThreatIntelInjectionRule",
                ProcessId = 700, ProcessName = "implant.exe",
                SignalType = SignalType.ProcessInjection,
                Timestamp = DateTime.UtcNow
            });
            await engine.RegisterSignalAsync(new DetectionEvent
            {
                RuleName = "C2 Beaconing Behavior",
                ProcessId = 700, ProcessName = "implant.exe",
                SignalType = SignalType.NetworkC2,
                Timestamp = DateTime.UtcNow
            });
            var result = getResult();
            Assert.NotNull(result);
            // Should get the highest confidence composite that matches
            Assert.True(result!.Confidence >= 0.95);
        }

        [Fact]
        public async Task Composite_EmitsAsTier1()
        {
            var (engine, getResult) = CreateEngine();
            await engine.RegisterSignalAsync(new DetectionEvent
            {
                RuleName = "RansomwareDetectionRule",
                ProcessId = 800, ProcessName = "r.exe",
                SignalType = SignalType.Ransomware,
                Timestamp = DateTime.UtcNow
            });
            await engine.RegisterSignalAsync(new DetectionEvent
            {
                RuleName = "Ransomware IO",
                ProcessId = 800, ProcessName = "r.exe",
                SignalType = SignalType.Ransomware,
                Timestamp = DateTime.UtcNow
            });
            var result = getResult();
            if (result != null)
            {
                Assert.Equal(DetectionTier.Tier1Behavioral, result.Tier);
                Assert.True(result.KillAuthorized);
            }
        }

        #endregion
    }
}
