using System;
using System.Collections.Generic;
using System.Linq;
using Xunit;
using Sentinel.Core;

namespace Sentinel.Tests
{
    /// <summary>
    /// Behavioral false-positive / true-positive corpus.
    ///
    /// Each scenario is a realistic, named SEQUENCE of detection signals fed through the
    /// real <see cref="ResponsePolicy"/> chain logic under a production-like ObserveUntilChain
    /// config. This is the EDR-grade contract that unit tests alone don't cover:
    ///
    ///   - BENIGN scenarios (legit software behavior) must NEVER authorize a destructive
    ///     response, no matter how many weak signals stack up.
    ///   - MALICIOUS scenarios (real attack chains) MUST confirm the chain and authorize.
    ///
    /// These are synthetic signal sequences - no real malware, no process execution. They
    /// exercise the decision logic exactly as the live pipeline would drive it.
    /// </summary>
    [Collection("ResponsePolicy")]
    public class FalsePositiveCorpusTests
    {
        public FalsePositiveCorpusTests()
        {
            ResponsePolicy.ResetForTests();
        }

        private static SentinelConfig LiveConfig() => new()
        {
            ActiveResponse = true,
            ObserveUntilChain = true,
            ChainConfirmMinSignals = 2,
            ChainConfirmWindowSeconds = 300,
            MinTier1Confidence = 0.85,
        };

        private static DetectionEvent Sig(
            string rule, int pid, string process,
            double conf = 0.80,
            SignalType signal = SignalType.Generic,
            string? evidence = null,
            Dictionary<string, string>? metadata = null)
            => new()
            {
                RuleName = rule,
                ProcessId = pid,
                ProcessName = process,
                Confidence = conf,
                SignalType = signal,
                Evidence = evidence ?? rule,
                Tier = DetectionTier.Tier1Behavioral,
                AuthorizedResponse = ResponseAction.KillProcessTree,
                Metadata = metadata ?? new Dictionary<string, string>(),
            };

        /// <summary>
        /// Feed a whole scenario through the chain and return true if ANY signal in the
        /// sequence authorized a destructive response - mirrors how the live orchestrator
        /// evaluates each detection as it arrives.
        /// </summary>
        private static bool ScenarioAuthorizesKill(IEnumerable<DetectionEvent> signals)
        {
            var cfg = LiveConfig();
            bool authorized = false;
            foreach (var s in signals)
            {
                // Tier law runs first in the live path (non-consultant branch).
                ResponsePolicy.ApplyTierLaw(s);
                // v2.9.4: observe-until-chain removed as a settable mode, so
                // MayPerformDestructiveResponse no longer gates on the chain buffer.
                // Drive the observe-independent multi-signal correlation directly - this is
                // the same RegisterAndEvaluateChain path the observe gate used to invoke, so
                // the benign/malicious contract (weak seeds + benign noise never confirm, real
                // multi-signal / attack-class chains do) is preserved exactly.
                if (ResponsePolicy.RegisterAndEvaluateChain(s, cfg))
                    authorized = true;
            }
            return authorized;
        }

        // =====================================================================
        // BENIGN CORPUS - must NEVER authorize a kill.
        // =====================================================================

        [Fact]
        public void Benign_Browser_Cast_Plus_ModuleGrowth_Never_Kills()
        {
            var pid = 20001;
            var scenario = new[]
            {
                Sig("Cast Device Guard: Cast Connection Observed", pid, "msedge",
                    conf: 0.55, signal: SignalType.NetworkC2,
                    metadata: new() { ["Mode"] = "observe-only", ["WeakObserveSeed"] = "true" }),
                Sig("Memory Injection: Module Count Growth Detected", pid, "msedge",
                    conf: 0.65, metadata: new() { ["WeakObserveSeed"] = "true" }),
                Sig("Network Policy: Unusual Destination", pid, "msedge", conf: 0.60),
            };
            Assert.False(ScenarioAuthorizesKill(scenario));
        }

        [Fact]
        public void Benign_Steam_DirectX_Installer_Noise_Never_Kills()
        {
            var scenario = new[]
            {
                Sig("System Integrity: Unauthorized Write to System Directory", 0, "dxsetup",
                    conf: 0.92,
                    evidence: @"File 'C:\WINDOWS\System32\d3dx9_43.dll' created by 'dxsetup' (PID 0)",
                    metadata: new()
                    {
                        ["FilePath"] = @"C:\WINDOWS\System32\d3dx9_43.dll",
                        ["BenignInstallerNoise"] = "true",
                    }),
                Sig("Ephemeral Process: Self-Deleting Binary", 5501, "dxsetup", conf: 0.80,
                    metadata: new()
                    {
                        ["ImagePath"] = @"C:\Program Files (x86)\Steam\steamapps\common\Game\_CommonRedist\DirectX\DXSETUP.exe",
                    }),
            };
            Assert.False(ScenarioAuthorizesKill(scenario));
        }

        [Fact]
        public void Benign_Dev_PowerShell_Build_Never_Kills()
        {
            var pid = 20003;
            var scenario = new[]
            {
                Sig("Suspicious Outbound Connection", pid, "powershell", conf: 0.62),
                Sig("Persistence: New Scheduled Task", pid, "powershell", conf: 0.70),
                Sig("Script: AMSI Not Loaded (System PowerShell)", pid, "powershell", conf: 0.55),
            };
            Assert.False(ScenarioAuthorizesKill(scenario));
        }

        [Fact]
        public void Benign_WindowsUpdate_System32_Writes_Never_Kills()
        {
            var scenario = new[]
            {
                Sig("System Integrity: Unauthorized Write to System Directory", 0, "TiWorker",
                    conf: 0.90,
                    evidence: @"File 'C:\WINDOWS\System32\vulkan-1.dll' changed by 'TiWorker' (PID 0)",
                    metadata: new() { ["FilePath"] = @"C:\WINDOWS\System32\vulkan-1.dll" }),
                Sig("System Integrity: Unauthorized Write to System Directory", 0, "wuauclt",
                    conf: 0.88,
                    evidence: @"File 'C:\WINDOWS\System32\nvcuda.dll' changed by 'wuauclt' (PID 0)",
                    metadata: new() { ["FilePath"] = @"C:\WINDOWS\System32\nvcuda.dll" }),
            };
            Assert.False(ScenarioAuthorizesKill(scenario));
        }

        [Fact]
        public void Benign_Single_Weak_Signal_Never_Kills()
        {
            var scenario = new[]
            {
                Sig("PPID Spoofing: Parent PID Mismatch", 20005, "dllhost", conf: 0.88),
            };
            Assert.False(ScenarioAuthorizesKill(scenario));
        }

        [Fact]
        public void Benign_Single_HighConf_C2_Alone_Never_Kills_Under_Observe()
        {
            // Even a legitimately-classified high-confidence C2 beacon must not solo-nuke;
            // it needs a second independent signal. A lone statistical beacon on a browser
            // updater is a classic false positive.
            var scenario = new[]
            {
                Sig("C2 Beaconing: Statistical Beacon Detected", 20006, "updater",
                    conf: 0.90, signal: SignalType.NetworkC2),
            };
            Assert.False(ScenarioAuthorizesKill(scenario));
        }

        [Fact]
        public void Benign_Many_Weak_Signals_Do_Not_Stack_Into_Kill()
        {
            // Stacking a pile of weak observe-fuel signals on one PID must not manufacture a
            // chain confirm without a real terminal leg.
            var pid = 20007;
            var scenario = new[]
            {
                Sig("PPID Spoofing: Parent PID Mismatch", pid, "svc", conf: 0.80),
                Sig("Ephemeral Process: Self-Deleting", pid, "svc", conf: 0.80),
                Sig("Suspicious Outbound Connection", pid, "svc", conf: 0.75),
                Sig("Network UDP: Classic Malware Port", pid, "svc", conf: 0.70,
                    signal: SignalType.NetworkC2),
                Sig("DNS Bypass: Application-Level DoH Detected", pid, "svc", conf: 0.65),
            };
            Assert.False(ScenarioAuthorizesKill(scenario));
        }

        // =====================================================================
        // MALICIOUS CORPUS - must confirm the chain and authorize.
        // =====================================================================

        [Fact]
        public void Malicious_CredentialDump_Plus_Exfil_Confirms_Chain()
        {
            var pid = 30001;
            var scenario = new[]
            {
                Sig("LSASS Credential Dump via comsvcs MiniDump", pid, "rundll32",
                    conf: 0.93, signal: SignalType.CredentialTheft),
                Sig("Data Staging: Bulk Upload Exfiltration", pid, "rundll32", conf: 0.90),
            };
            Assert.True(ScenarioAuthorizesKill(scenario));
        }

        [Fact]
        public void Malicious_Injection_Plus_C2_Confirms_Chain()
        {
            var pid = 30002;
            var scenario = new[]
            {
                Sig("C2 Beaconing: Statistical Beacon Detected", pid, "evil",
                    conf: 0.90, signal: SignalType.NetworkC2),
                Sig("Threat Intel: Remote Memory Injection", pid, "evil",
                    conf: 0.88, signal: SignalType.ProcessInjection),
            };
            Assert.True(ScenarioAuthorizesKill(scenario));
        }

        [Fact]
        public void Malicious_Composite_Injected_C2_Beacon_Authorizes_Immediately()
        {
            var scenario = new[]
            {
                Sig("Injected C2 Beacon", 30003, "host",
                    conf: 0.98, evidence: "[COMPOSITE] injection + C2 on same PID"),
            };
            Assert.True(ScenarioAuthorizesKill(scenario));
        }

        [Fact]
        public void Malicious_AttackClass_KernelExploitLoader_Solo_Confirms()
        {
            // The "10 murderers": attack-class terminals solo-confirm at high confidence.
            var scenario = new[]
            {
                Sig("CVE Class: Kernel Exploit Loader", 30004, "AfdEoP",
                    conf: 0.92, signal: SignalType.SecurityEvasion),
            };
            Assert.True(ScenarioAuthorizesKill(scenario));
        }

        [Fact]
        public void Malicious_TokenTheft_Plus_LateralMovement_Confirms()
        {
            var pid = 30005;
            var scenario = new[]
            {
                Sig("Token Theft: SYSTEM Token Stolen via GodPotato", pid, "evil",
                    conf: 0.91),
                Sig("Lateral Movement: PsExec Service Created", pid, "evil", conf: 0.88),
            };
            Assert.True(ScenarioAuthorizesKill(scenario));
        }

        // =====================================================================
        // CORPUS SUMMARY - a single aggregate assertion so a regression that flips any
        // scenario is impossible to miss, and the benign/malicious split is explicit.
        // =====================================================================

        [Fact]
        public void Corpus_Benign_Zero_Kills_And_Malicious_All_Confirm()
        {
            var benign = new (string Name, DetectionEvent[] Signals)[]
            {
                ("browser-cast", new[]
                {
                    Sig("Cast Device Guard: Cast Connection Observed", 40001, "msedge", 0.55,
                        SignalType.NetworkC2, metadata: new() { ["WeakObserveSeed"] = "true" }),
                    Sig("Memory Injection: Module Count Growth Detected", 40001, "msedge", 0.65,
                        metadata: new() { ["WeakObserveSeed"] = "true" }),
                }),
                ("directx-installer", new[]
                {
                    Sig("System Integrity: Unauthorized Write to System Directory", 0, "dxsetup", 0.92,
                        evidence: @"C:\WINDOWS\System32\d3dx9_43.dll",
                        metadata: new() { ["FilePath"] = @"C:\WINDOWS\System32\d3dx9_43.dll", ["BenignInstallerNoise"] = "true" }),
                }),
                ("lone-weak", new[] { Sig("PPID Spoofing: Parent PID Mismatch", 40003, "dllhost", 0.88) }),
                ("lone-c2", new[] { Sig("C2 Beaconing: Statistical Beacon Detected", 40004, "updater", 0.90, SignalType.NetworkC2) }),
            };

            var malicious = new (string Name, DetectionEvent[] Signals)[]
            {
                ("creddump+exfil", new[]
                {
                    Sig("LSASS Credential Dump", 50001, "rundll32", 0.93, SignalType.CredentialTheft),
                    Sig("Data Staging: Bulk Upload Exfiltration", 50001, "rundll32", 0.90),
                }),
                ("inject+c2", new[]
                {
                    Sig("C2 Beaconing: Statistical Beacon Detected", 50002, "evil", 0.90, SignalType.NetworkC2),
                    Sig("Threat Intel: Remote Memory Injection", 50002, "evil", 0.88, SignalType.ProcessInjection),
                }),
                ("attack-class-solo", new[]
                {
                    Sig("CVE Class: Kernel Exploit Loader", 50003, "AfdEoP", 0.92, SignalType.SecurityEvasion),
                }),
            };

            var benignFailures = benign
                .Where(s => { ResponsePolicy.ResetForTests(); return ScenarioAuthorizesKill(s.Signals); })
                .Select(s => s.Name)
                .ToList();

            var maliciousMisses = malicious
                .Where(s => { ResponsePolicy.ResetForTests(); return !ScenarioAuthorizesKill(s.Signals); })
                .Select(s => s.Name)
                .ToList();

            Assert.True(benignFailures.Count == 0,
                "Benign scenarios that wrongly authorized a kill (FALSE POSITIVE): " + string.Join(", ", benignFailures));
            Assert.True(maliciousMisses.Count == 0,
                "Malicious scenarios that failed to confirm (FALSE NEGATIVE): " + string.Join(", ", maliciousMisses));
        }
    }
}
