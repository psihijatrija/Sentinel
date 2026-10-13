using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using Xunit;
using Sentinel.Core;

namespace Sentinel.Tests
{
    public class BehavioralCorrelationEngineTests
    {
        [Fact]
        public async Task EvaluateComposites_RansomwareChain_Fires()
        {
            // Arrange
            var engine = new BehavioralCorrelationEngine();
            DetectionEvent? composite = null;
            engine.Initialize(ev =>
            {
                composite = ev;
                return Task.CompletedTask;
            });

            // Act
            // Feed first ransomware signal (shadow copy deletion)
            var signal1 = new DetectionEvent
            {
                RuleName = "RansomwareDetectionRule",
                ProcessId = 1234,
                ProcessName = "ransomware.exe",
                SignalType = SignalType.Ransomware,
                Timestamp = DateTime.UtcNow
            };
            await engine.RegisterSignalAsync(signal1);

            // Feed second ransomware signal (file rename)
            var signal2 = new DetectionEvent
            {
                RuleName = "Ransomware: Mass File Rename",
                ProcessId = 1234,
                ProcessName = "ransomware.exe",
                SignalType = SignalType.Ransomware,
                Timestamp = DateTime.UtcNow
            };
            await engine.RegisterSignalAsync(signal2);

            // Assert
            Assert.NotNull(composite);
            Assert.Equal("Active Mass-Encryption Chain", composite!.RuleName);
            Assert.Equal(0.99, composite.Confidence);
            Assert.Equal(1234, composite.ProcessId);
        }

        [Fact]
        public async Task EvaluateComposites_FilelessAttackChain_Fires()
        {
            // Arrange
            var engine = new BehavioralCorrelationEngine();
            DetectionEvent? composite = null;
            engine.Initialize(ev =>
            {
                composite = ev;
                return Task.CompletedTask;
            });

            // Act
            // Feed evasion signal
            var signal1 = new DetectionEvent
            {
                RuleName = "PrivilegeEscalationRule",
                ProcessId = 5555,
                ProcessName = "powershell.exe",
                SignalType = SignalType.SecurityEvasion,
                Timestamp = DateTime.UtcNow
            };
            await engine.RegisterSignalAsync(signal1);

            // Feed shell signal
            var signal2 = new DetectionEvent
            {
                RuleName = "ReverseShellRule",
                ProcessId = 5555,
                ProcessName = "powershell.exe",
                SignalType = SignalType.ReverseShell,
                Timestamp = DateTime.UtcNow
            };
            await engine.RegisterSignalAsync(signal2);

            // Assert
            Assert.NotNull(composite);
            Assert.Equal("Fileless Attack Chain", composite!.RuleName);
            Assert.Equal(0.95, composite.Confidence);
        }

        [Fact]
        public async Task EvaluateComposites_CredentialDumpAndExfil_Fires()
        {
            // Arrange
            var engine = new BehavioralCorrelationEngine();
            DetectionEvent? composite = null;
            engine.Initialize(ev =>
            {
                composite = ev;
                return Task.CompletedTask;
            });

            // Act
            // Feed LSASS access
            var signal1 = new DetectionEvent
            {
                RuleName = "Credential Theft: LSASS Process Access",
                ProcessId = 9999,
                ProcessName = "mimikatz.exe",
                SignalType = SignalType.LsassAccess,
                Timestamp = DateTime.UtcNow
            };
            await engine.RegisterSignalAsync(signal1);

            // Feed network connection
            var signal2 = new DetectionEvent
            {
                RuleName = "C2 Beaconing Behavior (Statistical)",
                ProcessId = 9999,
                ProcessName = "mimikatz.exe",
                SignalType = SignalType.NetworkC2,
                Timestamp = DateTime.UtcNow
            };
            await engine.RegisterSignalAsync(signal2);

            // Assert
            Assert.NotNull(composite);
            Assert.Equal("Credential Dump + Exfiltration", composite!.RuleName);
            Assert.Equal(0.96, composite.Confidence);
        }
    }

    public class BehavioralCorrelationEngineExtendedTests
    {
        [Fact]
        public async Task RegisterSignal_SingleSignal_DoesNotFireComposite()
        {
            var engine = new BehavioralCorrelationEngine();
            DetectionEvent? composite = null;
            engine.Initialize(ev => { composite = ev; return Task.CompletedTask; });

            await engine.RegisterSignalAsync(new DetectionEvent
            {
                RuleName = "LsassAccessRule",
                ProcessId = 1000,
                ProcessName = "test.exe",
                SignalType = SignalType.LsassAccess,
                Timestamp = DateTime.UtcNow
            });

            Assert.Null(composite);
        }

        [Fact]
        public async Task RegisterSignal_TwoSignalsSameType_DoesNotFireNonRansomwareComposite()
        {
            var engine = new BehavioralCorrelationEngine();
            DetectionEvent? composite = null;
            engine.Initialize(ev => { composite = ev; return Task.CompletedTask; });

            // Two C2 signals - should NOT fire "Injected C2 Beacon" (needs injection + C2)
            await engine.RegisterSignalAsync(new DetectionEvent
            {
                RuleName = "Beaconing Signal 1",
                ProcessId = 2000,
                ProcessName = "test.exe",
                SignalType = SignalType.NetworkC2,
                Timestamp = DateTime.UtcNow
            });

            await engine.RegisterSignalAsync(new DetectionEvent
            {
                RuleName = "Beaconing Signal 2",
                ProcessId = 2000,
                ProcessName = "test.exe",
                SignalType = SignalType.NetworkC2,
                Timestamp = DateTime.UtcNow
            });

            // Only ransomware composite fires on same-type signals
            Assert.Null(composite);
        }

        [Fact]
        public async Task RegisterSignal_InjectedC2Beacon_Fires()
        {
            var engine = new BehavioralCorrelationEngine();
            DetectionEvent? composite = null;
            engine.Initialize(ev => { composite = ev; return Task.CompletedTask; });

            // Injection signal
            await engine.RegisterSignalAsync(new DetectionEvent
            {
                RuleName = "ThreatIntelInjectionRule",
                ProcessId = 3000,
                ProcessName = "svchost.exe",
                SignalType = SignalType.ProcessInjection,
                Timestamp = DateTime.UtcNow
            });

            // C2 network signal on same PID
            await engine.RegisterSignalAsync(new DetectionEvent
            {
                RuleName = "C2 Beaconing",
                ProcessId = 3000,
                ProcessName = "svchost.exe",
                SignalType = SignalType.NetworkC2,
                Timestamp = DateTime.UtcNow
            });

            Assert.NotNull(composite);
            Assert.Equal("Injected C2 Beacon", composite!.RuleName);
            Assert.Equal(0.98, composite.Confidence);
            // Composites authorize full destructive response (quarantine+kill)
            Assert.True(composite.AuthorizedResponse >= ResponseAction.KillProcessTree);
        }

        [Fact]
        public async Task RegisterSignal_DifferentPids_DoesNotCorrelate()
        {
            var engine = new BehavioralCorrelationEngine();
            DetectionEvent? composite = null;
            engine.Initialize(ev => { composite = ev; return Task.CompletedTask; });

            // Injection on PID 4000
            await engine.RegisterSignalAsync(new DetectionEvent
            {
                RuleName = "ThreatIntelInjectionRule",
                ProcessId = 4000,
                ProcessName = "proc_a.exe",
                SignalType = SignalType.ProcessInjection,
                Timestamp = DateTime.UtcNow
            });

            // C2 on DIFFERENT PID 4001
            await engine.RegisterSignalAsync(new DetectionEvent
            {
                RuleName = "C2 Connection",
                ProcessId = 4001,
                ProcessName = "proc_b.exe",
                SignalType = SignalType.NetworkC2,
                Timestamp = DateTime.UtcNow
            });

            // Should NOT fire - different PIDs
            Assert.Null(composite);
        }

        [Fact]
        public async Task RegisterSignal_EvasionPlusPersistence_Fires()
        {
            var engine = new BehavioralCorrelationEngine();
            DetectionEvent? composite = null;
            engine.Initialize(ev => { composite = ev; return Task.CompletedTask; });

            // Security evasion
            await engine.RegisterSignalAsync(new DetectionEvent
            {
                RuleName = "AMSI Bypass Detected",
                ProcessId = 5000,
                ProcessName = "malware.exe",
                SignalType = SignalType.SecurityEvasion,
                Timestamp = DateTime.UtcNow
            });

            // Persistence signal (contains "Autorun" in name for pattern match)
            await engine.RegisterSignalAsync(new DetectionEvent
            {
                RuleName = "Autorun Registry Key Added",
                ProcessId = 5000,
                ProcessName = "malware.exe",
                SignalType = SignalType.Generic,
                Timestamp = DateTime.UtcNow
            });

            Assert.NotNull(composite);
            Assert.Equal("Evasion + Persistence Install", composite!.RuleName);
            Assert.Equal(0.91, composite.Confidence);
        }

        [Fact]
        public async Task RegisterSignal_HighestConfidenceCompositeWins()
        {
            // When multiple composites could fire, the highest confidence one should fire first
            var engine = new BehavioralCorrelationEngine();
            DetectionEvent? composite = null;
            engine.Initialize(ev => { composite = ev; return Task.CompletedTask; });

            // Signal set that matches both "Injected C2 Beacon" (0.98) and
            // "In-Memory Implant Active" (0.96) - injection + C2 + reverse shell
            await engine.RegisterSignalAsync(new DetectionEvent
            {
                RuleName = "Injection API",
                ProcessId = 6000,
                ProcessName = "implant.exe",
                SignalType = SignalType.ProcessInjection,
                Timestamp = DateTime.UtcNow
            });

            await engine.RegisterSignalAsync(new DetectionEvent
            {
                RuleName = "C2 Callback",
                ProcessId = 6000,
                ProcessName = "implant.exe",
                SignalType = SignalType.NetworkC2,
                Timestamp = DateTime.UtcNow
            });

            // Highest confidence composite should win (Injected C2 Beacon at 0.98)
            Assert.NotNull(composite);
            Assert.Equal("Injected C2 Beacon", composite!.RuleName);
            Assert.Equal(0.98, composite.Confidence);
        }

        [Fact]
        public async Task RegisterSignal_InvalidPid_Ignored()
        {
            var engine = new BehavioralCorrelationEngine();
            DetectionEvent? composite = null;
            engine.Initialize(ev => { composite = ev; return Task.CompletedTask; });

            // PID 0 should be ignored
            await engine.RegisterSignalAsync(new DetectionEvent
            {
                RuleName = "Test",
                ProcessId = 0,
                ProcessName = "test.exe",
                SignalType = SignalType.ProcessInjection,
                Timestamp = DateTime.UtcNow
            });

            await engine.RegisterSignalAsync(new DetectionEvent
            {
                RuleName = "Test2",
                ProcessId = 0,
                ProcessName = "test.exe",
                SignalType = SignalType.NetworkC2,
                Timestamp = DateTime.UtcNow
            });

            Assert.Null(composite);
        }

        [Fact]
        public async Task RegisterSignal_CompositeEmittedAsTier1()
        {
            var engine = new BehavioralCorrelationEngine();
            DetectionEvent? composite = null;
            engine.Initialize(ev => { composite = ev; return Task.CompletedTask; });

            await engine.RegisterSignalAsync(new DetectionEvent
            {
                RuleName = "RansomwareDetectionRule",
                ProcessId = 7000,
                ProcessName = "ransom.exe",
                SignalType = SignalType.Ransomware,
                Timestamp = DateTime.UtcNow
            });

            await engine.RegisterSignalAsync(new DetectionEvent
            {
                RuleName = "Ransomware IO: Mass Rename",
                ProcessId = 7000,
                ProcessName = "ransom.exe",
                SignalType = SignalType.Ransomware,
                Timestamp = DateTime.UtcNow
            });

            Assert.NotNull(composite);
            Assert.Equal(DetectionTier.Tier1Behavioral, composite!.Tier);
            Assert.True(composite.AuthorizedResponse >= ResponseAction.KillProcessTree);
        }
    }
}
