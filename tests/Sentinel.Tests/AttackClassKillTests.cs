using System.Collections.Generic;
using Xunit;
using Sentinel.Core;

namespace Sentinel.Tests
{
    [CollectionDefinition("ResponsePolicy")]
    public class ResponsePolicyCollection { }

    /// <summary>
    /// v2.5.3: the 10 murderers, not the 90 civilians.
    /// Attack-class rules solo-confirm a kill chain. Browse/play heuristics stay observe.
    /// </summary>
    [Collection("ResponsePolicy")]
    public class AttackClassKillTests
    {
        public AttackClassKillTests()
        {
            ResponsePolicy.ResetForTests();
        }

        private static SentinelConfig ObserveConfig() => new()
        {
            ActiveResponse = true,
            ObserveUntilChain = true,
            ChainConfirmMinSignals = 2,
            ChainConfirmWindowSeconds = 300,
            MinTier1Confidence = 0.85,
        };

        private static DetectionEvent Attack(string rule, double conf = 0.90, int pid = 4242,
            SignalType signal = SignalType.SecurityEvasion, string process = "evil")
            => new()
            {
                RuleName = rule,
                Confidence = conf,
                Tier = DetectionTier.Tier1Behavioral,
                AuthorizedResponse = ResponseAction.KillProcessTree,
                ProcessId = pid,
                ProcessName = process,
                SignalType = signal,
            };

        private void AssertKills(DetectionEvent d, string family)
        {
            Assert.False(ResponsePolicy.IsWeakObserveSeed(d));
            Assert.Equal(family, ResponsePolicy.ClassifyTerminalOutcome(d));
            Assert.True(ResponsePolicy.IsAttackClassTerminal(d));
            Assert.True(ResponsePolicy.IsKillGradeTerminal(d));
            Assert.True(ResponsePolicy.MayPerformDestructiveResponse(d, ObserveConfig()));
        }

        private static void AssertObserves(DetectionEvent d)
        {
            // v2.9.4: observe-until-chain removed as a settable mode; the destructive-response
            // gate no longer distinguishes observe vs live. The safety property that survives is
            // the classification: these civilians must never classify as attack-class terminal.
            Assert.False(ResponsePolicy.IsAttackClassTerminal(d));
        }

        [Fact]
        public void LpeNamedTool_Kills()
        {
            ResponsePolicy.ResetForTests();
            AssertKills(Attack("LPE Scaffold: Privilege Escalation Tool", process: "JuicyPotato"),
                "TokenTheft");
        }

        [Fact]
        public void KernelExploitLoader_Kills()
        {
            ResponsePolicy.ResetForTests();
            AssertKills(Attack("CVE Class: Kernel Exploit Loader", process: "AfdEoP"),
                "TokenTheft");
        }

        [Fact]
        public void ClickFixEncoded_Kills()
        {
            ResponsePolicy.ResetForTests();
            AssertKills(Attack("CVE Class: ClickFix Encoded Run", process: "powershell",
                signal: SignalType.SuspiciousProcess), "ReverseShell");
        }

        [Fact]
        public void UnmappedThread_Kills()
        {
            ResponsePolicy.ResetForTests();
            AssertKills(Attack("Evasion: Unmapped Thread Start Address",
                signal: SignalType.AntiTamper), "Evasion");
        }

        [Fact]
        public void ClassicMalwarePort_Kills()
        {
            ResponsePolicy.ResetForTests();
            AssertKills(Attack("Network Indicator: Classic Malware Port",
                signal: SignalType.NetworkC2, process: "payload"), "C2Beacon");
        }

        [Fact]
        public void NamedPipeKnownC2_Kills()
        {
            ResponsePolicy.ResetForTests();
            AssertKills(Attack("Named Pipe: Known C2/Lateral Movement Pattern",
                conf: 0.86, signal: SignalType.NetworkC2), "C2Beacon");
        }

        [Fact]
        public void TunnelingTool_Kills()
        {
            ResponsePolicy.ResetForTests();
            AssertKills(Attack("Remote Access: Tunneling Tool Detected",
                process: "ngrok", signal: SignalType.NetworkC2), "C2Beacon");
        }

        [Fact]
        public void EvasionRule_IsNotByovd_AsioSubstring()
        {
            // "AsIO" used to match the letters inside "Evasion" and steal the family.
            var d = Attack("Evasion: Indirect Syscall / Hell's Gate Pattern Detected");
            Assert.NotEqual("BYOVD", ResponsePolicy.ClassifyTerminalOutcome(d));
            Assert.Equal("Evasion", ResponsePolicy.ClassifyTerminalOutcome(d));
        }

        [Fact]
        public void HellsGate_Kills()
        {
            ResponsePolicy.ResetForTests();
            AssertKills(Attack("Evasion: Indirect Syscall / Hell's Gate Pattern Detected"),
                "Evasion");
        }

        [Fact]
        public void AmsiBypass_NonSystem_Kills()
        {
            ResponsePolicy.ResetForTests();
            AssertKills(Attack("Script: AMSI Bypass Detected (amsi.dll Unloaded)",
                process: "powershell", signal: SignalType.AmsiTampering), "Evasion");
        }

        [Fact]
        public void ThreatIntelInjection_Kills()
        {
            ResponsePolicy.ResetForTests();
            AssertKills(Attack("ThreatIntelInjectionRule", process: "injector",
                signal: SignalType.ProcessInjection), "Injection");
        }

        [Fact]
        public void EtwManipulation_Kills()
        {
            ResponsePolicy.ResetForTests();
            AssertKills(Attack("Anti-Tamper: ETW/Event Log Manipulation Detected",
                process: "wevtutil", signal: SignalType.AntiTamper), "Evasion");
        }

        [Fact]
        public void CovertMesh_StillKills()
        {
            ResponsePolicy.ResetForTests();
            var d = Attack("Covert Mesh: Userspace Overlay Tool", process: "tailcat",
                signal: SignalType.NetworkC2);
            AssertKills(d, "C2Beacon");
            Assert.True(ResponsePolicy.IsCovertChannelTerminal(d));
        }

        [Theory]
        [InlineData("Reverse Shell: Suspicious Outbound Connection")]
        [InlineData("Named Pipe: High-Entropy Name (Non-System Owner)")]
        [InlineData("Remote Access: Known RAT Process Running")]
        [InlineData("Script: AMSI Not Loaded (System PowerShell)")]
        [InlineData("DNS Bypass: Application-Level DoH Detected")]
        [InlineData("Network UDP: Classic Malware Port")]
        [InlineData("Network ICMP: Echo Flood")]
        [InlineData("Network VoIP: SIP Signaling")]
        [InlineData("CVE Class: PE Missing Mark-of-the-Web")]
        [InlineData("CVE Class: Package Manager EoP")]
        [InlineData("CVE Class: VS Code Encoded Shell")]
        [InlineData("LPE Scaffold: Elevated Process from Staging Path")]
        [InlineData("Token Theft: SeImpersonatePrivilege")]
        [InlineData("Persistence: New Scheduled Task")]
        public void Civilians_DoNotSoloNuke(string rule)
        {
            ResponsePolicy.ResetForTests();
            var d = Attack(rule, process: "chrome");
            AssertObserves(d);
        }

        [Fact]
        public void PidZero_DoesNotNuke()
        {
            ResponsePolicy.ResetForTests();
            var d = Attack("CVE Class: Kernel Exploit Loader", pid: 0, process: "SYSTEM");
            Assert.False(ResponsePolicy.IsAttackClassTerminal(d));
            AssertObserves(d);
        }

        [Fact]
        public void WeakObserveSeedMetadata_BlocksSoloKill()
        {
            ResponsePolicy.ResetForTests();
            var d = Attack("CVE Class: Kernel Exploit Loader");
            d.Metadata = new Dictionary<string, string> { ["WeakObserveSeed"] = "true" };
            Assert.True(ResponsePolicy.IsWeakObserveSeed(d));
            Assert.False(ResponsePolicy.IsAttackClassTerminal(d));
            AssertObserves(d);
        }

        [Fact]
        public void StatisticalBeacon_StillNeedsSecondSignal()
        {
            ResponsePolicy.ResetForTests();
            var d = Attack("C2 Beaconing: Statistical Beacon Detected",
                signal: SignalType.NetworkC2);
            Assert.Equal("C2Beacon", ResponsePolicy.ClassifyTerminalOutcome(d));
            Assert.False(ResponsePolicy.IsAttackClassTerminal(d));
            AssertObserves(d);
        }

        [Fact]
        public void UdpClassicPort_StaysWeak_EvenWhenNamedMalwarePort()
        {
            ResponsePolicy.ResetForTests();
            var d = Attack("Network UDP: Classic Malware Port", signal: SignalType.NetworkC2);
            Assert.True(ResponsePolicy.IsWeakObserveSeed(d));
            Assert.Null(ResponsePolicy.ClassifyTerminalOutcome(d));
            AssertObserves(d);
        }
    }
}
