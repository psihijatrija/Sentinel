using System.Collections.Generic;
using Xunit;
using Sentinel.Core;

namespace Sentinel.Tests
{
    [Collection("ResponsePolicy")]
    public class ResponsePolicyTests
    {
        public ResponsePolicyTests()
        {
            ResponsePolicy.ResetForTests();
        }

        private static SentinelConfig ObserveConfig() => new()
        {
            ActiveResponse = true,
            ObserveUntilChain = true,
            ChainConfirmMinSignals = 2,
            ChainConfirmWindowSeconds = 300,
            SilentObserve = true,
        };

        [Fact]
        public void MinTier1Confidence_Default_Is_PointEightyFive()
        {
            // Locks the kill-grade confidence floor used by ApplyTierLaw / AdvancedResponseEngine.
            Assert.Equal(0.85, ResponsePolicy.DefaultMinTier1Confidence);
            Assert.Equal(0.85, new SentinelConfig().MinTier1Confidence);
        }

        [Fact]
        public void DirectX_Install_Is_Tier2_Observe_Never_Composite_Or_Kill()
        {
            // Typical Steam DirectX System32 drop (often PID 0 race)
            var sysWrite = new DetectionEvent
            {
                RuleName = "System Integrity: Unauthorized Write to System Directory",
                Evidence = @"File 'C:\WINDOWS\System32\d3dx9_43.dll' was created by process 'dxsetup' (PID 0)",
                ProcessId = 0,
                ProcessName = "dxsetup",
                Confidence = 0.92, // monitors must not "confidence wash" this into Tier1
                Tier = DetectionTier.Tier1Behavioral,
                AuthorizedResponse = ResponseAction.KillProcessTree,
                Metadata = new Dictionary<string, string>
                {
                    ["FilePath"] = @"C:\WINDOWS\System32\d3dx9_43.dll",
                    ["BenignInstallerNoise"] = "true",
                }
            };
            ResponsePolicy.ApplyTierLaw(sysWrite);
            Assert.Equal(DetectionTier.Tier2Indicator, sysWrite.Tier);
            Assert.Equal(ResponseAction.LogOnly, sysWrite.AuthorizedResponse);
            Assert.True(ResponsePolicy.IsBenignInstallerNoise(sysWrite));
            Assert.True(ResponsePolicy.IsNonCorrelatingObserveNoise(sysWrite));
            Assert.Null(ResponsePolicy.ClassifyTerminalOutcome(sysWrite));

            // Second weak signal from same installer wave must still classify as benign noise
            var ephemeral = new DetectionEvent
            {
                RuleName = "Ephemeral Process: Self-Deleting Binary",
                ProcessId = 5555,
                ProcessName = "dxsetup",
                Confidence = 0.80,
                Tier = DetectionTier.Tier1Behavioral,
                AuthorizedResponse = ResponseAction.KillProcessTree,
                Metadata = new Dictionary<string, string>
                {
                    ["ImagePath"] = @"C:\Program Files (x86)\Steam\steamapps\common\Game\_CommonRedist\DirectX\DXSETUP.exe",
                }
            };
            ResponsePolicy.ApplyTierLaw(ephemeral);
            Assert.Equal(DetectionTier.Tier2Indicator, ephemeral.Tier);
            Assert.True(ResponsePolicy.IsBenignInstallerNoise(ephemeral));
            // v2.9.4: observe-until-chain removed as a settable mode; the destructive-response
            // gate no longer distinguishes observe vs live. The surviving safety property is the
            // Tier2/benign-noise classification asserted above, which keeps this out of kill-grade.
        }

        [Fact]
        public void TierLaw_Only_KillGrade_HighConfidence_Is_Tier1()
        {
            var weakGhost = new DetectionEvent
            {
                RuleName = "Ghost Process: Unresolvable PID",
                ProcessId = 1001,
                ProcessName = "something.exe",
                Confidence = 0.95,
                Tier = DetectionTier.Tier1Behavioral,
                AuthorizedResponse = ResponseAction.KillProcessTree,
            };
            ResponsePolicy.ApplyTierLaw(weakGhost);
            Assert.Equal(DetectionTier.Tier2Indicator, weakGhost.Tier);
            Assert.Equal(ResponseAction.LogOnly, weakGhost.AuthorizedResponse);

            var lowConfC2 = new DetectionEvent
            {
                RuleName = "C2 Beaconing: Statistical Beacon Detected",
                SignalType = SignalType.NetworkC2,
                ProcessId = 1002,
                ProcessName = "maybe.exe",
                Confidence = 0.50,
                Tier = DetectionTier.Tier1Behavioral,
                AuthorizedResponse = ResponseAction.KillProcessTree,
            };
            ResponsePolicy.ApplyTierLaw(lowConfC2);
            Assert.Equal(DetectionTier.Tier2Indicator, lowConfC2.Tier);
            Assert.Equal(ResponseAction.LogOnly, lowConfC2.AuthorizedResponse);

            var highConfCred = new DetectionEvent
            {
                RuleName = "LSASS Credential Dump",
                SignalType = SignalType.CredentialTheft,
                ProcessId = 1003,
                ProcessName = "mimikatz.exe",
                Confidence = 0.92,
                Tier = DetectionTier.Tier2Indicator,
                AuthorizedResponse = ResponseAction.KillProcessTree,
            };
            ResponsePolicy.ApplyTierLaw(highConfCred);
            Assert.Equal(DetectionTier.Tier1Behavioral, highConfCred.Tier);
            Assert.True(ResponsePolicy.IsKillGradeTerminal(highConfCred));

            var highConfToken = new DetectionEvent
            {
                RuleName = "Token Theft: SYSTEM Token Stolen",
                ProcessId = 1004,
                ProcessName = "evil.exe",
                Confidence = 0.90,
                Tier = DetectionTier.Tier2Indicator,
                AuthorizedResponse = ResponseAction.KillProcessTree,
            };
            ResponsePolicy.ApplyTierLaw(highConfToken);
            Assert.Equal(DetectionTier.Tier1Behavioral, highConfToken.Tier);

            var highConfShell = new DetectionEvent
            {
                RuleName = "Reverse Shell Detected",
                SignalType = SignalType.ReverseShell,
                ProcessId = 1005,
                ProcessName = "nc.exe",
                Confidence = 0.91,
                Tier = DetectionTier.Tier2Indicator,
                AuthorizedResponse = ResponseAction.KillProcessTree,
            };
            ResponsePolicy.ApplyTierLaw(highConfShell);
            Assert.Equal(DetectionTier.Tier1Behavioral, highConfShell.Tier);

            var highConfC2 = new DetectionEvent
            {
                RuleName = "C2 Beaconing: Statistical Beacon Detected",
                SignalType = SignalType.NetworkC2,
                ProcessId = 1006,
                ProcessName = "beacon.exe",
                Confidence = 0.90,
                Tier = DetectionTier.Tier2Indicator,
                AuthorizedResponse = ResponseAction.NetworkIsolate,
            };
            ResponsePolicy.ApplyTierLaw(highConfC2);
            Assert.Equal(DetectionTier.Tier1Behavioral, highConfC2.Tier);
            // v2.9.4: observe-until-chain removed as a settable mode; the "no single-signal nuke
            // under observe" gate no longer exists. The tier-law classification above is the
            // surviving safety coverage.
        }

        [Fact]
        public void TierLaw_Composite_Stays_Tier1_KillGrade()
        {
            var composite = new DetectionEvent
            {
                RuleName = "Injected C2 Beacon",
                Evidence = "[COMPOSITE] injection + C2",
                ProcessId = 2001,
                ProcessName = "evil.exe",
                Confidence = 0.98,
                Tier = DetectionTier.Tier2Indicator,
                AuthorizedResponse = ResponseAction.LogOnly,
            };
            ResponsePolicy.ApplyTierLaw(composite);
            Assert.Equal(DetectionTier.Tier1Behavioral, composite.Tier);
            Assert.True(composite.AuthorizedResponse >= ResponseAction.KillProcessTree);
        }

        [Fact]
        public void DirectX_System32_Write_Is_Benign_Noise_Never_Chain()
        {
            var d = new DetectionEvent
            {
                RuleName = "System Integrity: Unauthorized Write to System Directory",
                Evidence = @"File 'C:\WINDOWS\System32\vulkan-1-999-0-0-0.dll' was changed by process 'unknown' (PID 0)",
                ProcessId = 0,
                ProcessName = "unknown",
                Confidence = 0.92,
                Tier = DetectionTier.Tier1Behavioral,
                AuthorizedResponse = ResponseAction.KillProcessTree,
                Metadata = new Dictionary<string, string>
                {
                    ["FilePath"] = @"C:\WINDOWS\System32\vulkan-1-999-0-0-0.dll"
                }
            };

            Assert.True(ResponsePolicy.IsBenignInstallerNoise(d));
            Assert.Null(ResponsePolicy.ClassifyTerminalOutcome(d));
            // v2.9.4: observe-until-chain removed as a settable mode; benign-noise classification
            // (asserted above) is the surviving safety property that keeps this out of kill-grade.
        }

        [Fact]
        public void Single_Statistical_Beacon_Classifies_As_C2Beacon_But_Is_Not_AttackClassSolo()
        {
            // v2.9.4: observe-until-chain removed as a settable mode, so the old "does not nuke
            // alone under observe" gate no longer exists. The surviving safety property is the
            // classification: a lone statistical beacon is a C2Beacon family signal, but it is
            // NOT an attack-class terminal that could solo-confirm a chain (needs a 2nd signal).
            var d = new DetectionEvent
            {
                RuleName = "C2 Beaconing: Statistical Beacon Detected",
                SignalType = SignalType.NetworkC2,
                ProcessId = 4242,
                ProcessName = "evil.exe",
                Confidence = 0.90,
                Tier = DetectionTier.Tier1Behavioral,
                AuthorizedResponse = ResponseAction.KillProcessTree,
            };

            Assert.Equal("C2Beacon", ResponsePolicy.ClassifyTerminalOutcome(d));
            Assert.False(ResponsePolicy.IsAttackClassTerminal(d));
        }

        [Fact]
        public void C2_Plus_Second_Signal_Chain_Nukes()
        {
            var cfg = ObserveConfig();
            var c2 = new DetectionEvent
            {
                RuleName = "C2 Beaconing: Statistical Beacon Detected",
                SignalType = SignalType.NetworkC2,
                ProcessId = 7777,
                ProcessName = "evil.exe",
                Confidence = 0.90,
                Tier = DetectionTier.Tier1Behavioral,
                AuthorizedResponse = ResponseAction.NetworkIsolate,
            };
            var inject = new DetectionEvent
            {
                RuleName = "Threat Intel: Remote Memory Injection",
                SignalType = SignalType.ProcessInjection,
                ProcessId = 7777,
                ProcessName = "evil.exe",
                Confidence = 0.88,
                Tier = DetectionTier.Tier1Behavioral,
                AuthorizedResponse = ResponseAction.KillProcessTree,
            };

            // v2.9.4: observe-until-chain removed as a settable mode. Drive the observe-independent
            // multi-signal correlation directly (the same RegisterAndEvaluateChain path the observe
            // gate used to invoke): a lone C2 beacon must not confirm, and the second independent
            // signal on the same PID completes the chain and tags it ChainConfirmed.
            Assert.False(ResponsePolicy.RegisterAndEvaluateChain(c2, cfg));
            Assert.True(ResponsePolicy.RegisterAndEvaluateChain(inject, cfg));
            Assert.True(inject.Metadata.ContainsKey(ResponsePolicy.ChainConfirmedKey));
        }

        [Fact]
        public void Composite_Is_Immediately_Authorized()
        {
            var d = new DetectionEvent
            {
                RuleName = "Injected C2 Beacon",
                Evidence = "[COMPOSITE] injection + C2",
                ProcessId = 100,
                ProcessName = "host.exe",
                Confidence = 0.98,
                Tier = DetectionTier.Tier1Behavioral,
                AuthorizedResponse = ResponseAction.QuarantineAndKill,
            };

            Assert.True(ResponsePolicy.IsNukeComposite(d));
            Assert.True(ResponsePolicy.MayPerformDestructiveResponse(d, ObserveConfig()));
        }

        [Fact]
        public void DllUnload_Exempt_Always_May_Act()
        {
            var d = new DetectionEvent
            {
                RuleName = "DLL Sideloading: Proven Load - Unloaded & Quarantined",
                ProcessId = 55,
                ProcessName = "host.exe",
                Confidence = 0.95,
                Tier = DetectionTier.Tier1Behavioral,
                AuthorizedResponse = ResponseAction.QuarantineAndKill,
            };

            Assert.True(ResponsePolicy.IsDllUnloadExempt(d));
            Assert.True(ResponsePolicy.MayPerformDestructiveResponse(d, ObserveConfig()));
        }

        [Fact]
        public void Hijack_Name_Plant_Quarantined_Stays_Tier1_After_ApplyTierLaw()
        {
            var d = new DetectionEvent
            {
                RuleName = "DLL Sideloading: Hijack-Name Plant Quarantined",
                ProcessId = 0,
                ProcessName = "dropper",
                Confidence = 0.90,
                Tier = DetectionTier.Tier1Behavioral,
                AuthorizedResponse = ResponseAction.LogOnly,
            };

            ResponsePolicy.ApplyTierLaw(d);
            Assert.Equal(DetectionTier.Tier1Behavioral, d.Tier);
            Assert.Equal(ResponseAction.LogOnly, d.AuthorizedResponse);
            Assert.True(ResponsePolicy.IsPermanentModuleIdentityUnload(d));
        }

        [Fact]
        public void Foreign_Module_Unloaded_Stays_Tier1_After_ApplyTierLaw()
        {
            var d = new DetectionEvent
            {
                RuleName = "DLL Injection: Foreign Module Unloaded",
                ProcessId = 55,
                ProcessName = "host.exe",
                Confidence = 0.90,
                Tier = DetectionTier.Tier1Behavioral,
                AuthorizedResponse = ResponseAction.LogOnly,
            };

            ResponsePolicy.ApplyTierLaw(d);
            Assert.Equal(DetectionTier.Tier1Behavioral, d.Tier);
            Assert.Equal(ResponseAction.LogOnly, d.AuthorizedResponse);
            Assert.True(ResponsePolicy.IsPermanentModuleIdentityUnload(d));
        }

        // v2.9.4: observe-until-chain removed as a settable mode; the "inline host mutation blocked
        // while observing" scenario no longer exists (MayPerformInlineHostMutation no longer gates
        // on observe), so Inline_Host_Mutation_Blocked_While_Observing was removed.

        [Fact]
        public void Cast_Observe_Is_Weak_Seed_Never_Terminal_Or_Chain()
        {
            var cast = new DetectionEvent
            {
                RuleName = "Cast Device Guard: Cast Connection Observed",
                ProcessId = 9001,
                ProcessName = "msedge",
                Confidence = 0.55,
                SignalType = SignalType.NetworkC2, // even if mis-tagged NetworkC2
                Tier = DetectionTier.Tier2Indicator,
                AuthorizedResponse = ResponseAction.LogOnly,
                Metadata = new Dictionary<string, string>
                {
                    ["Mode"] = "observe-only",
                    ["WeakObserveSeed"] = "true",
                    ["RemoteIP"] = "192.168.1.100",
                    ["RemotePort"] = "8009",
                }
            };

            Assert.True(ResponsePolicy.IsWeakObserveSeed(cast));
            Assert.Null(ResponsePolicy.ClassifyTerminalOutcome(cast));
            Assert.True(ResponsePolicy.IsNonCorrelatingObserveNoise(cast));

            // Cast + module growth: both must classify as weak observe seeds (never chain fuel)
            var growth = new DetectionEvent
            {
                RuleName = "Memory Injection: Module Count Growth Detected",
                ProcessId = 9001,
                ProcessName = "msedge",
                Confidence = 0.65,
                Tier = DetectionTier.Tier2Indicator,
                AuthorizedResponse = ResponseAction.LogOnly,
                Metadata = new Dictionary<string, string> { ["WeakObserveSeed"] = "true" }
            };
            Assert.True(ResponsePolicy.IsWeakObserveSeed(growth));
            // v2.9.4: observe-until-chain removed as a settable mode; the weak-observe-seed
            // classification above is the surviving safety property (weak seeds never fill the
            // chain buffer inside RegisterAndEvaluateChain).
        }

        [Fact]
        public void Module_Growth_Plus_Ppid_Does_Not_Chain_Nuke()
        {
            var cfg = ObserveConfig();
            var pid = 9002;
            var growth = new DetectionEvent
            {
                RuleName = "Memory Injection: Module Count Growth Detected",
                ProcessId = pid,
                ProcessName = "msedge",
                Confidence = 0.75,
            };
            var ppid = new DetectionEvent
            {
                RuleName = "PPID Spoofing: Parent PID Mismatch",
                ProcessId = pid,
                ProcessName = "dllhost",
                Confidence = 0.88,
            };

            // v2.9.4: observe-until-chain removed as a settable mode. Drive the observe-independent
            // multi-signal correlation directly: module growth is a weak observe seed and PPID
            // mismatch is a weak chain-only seed, so neither completes a chain on its own.
            Assert.False(ResponsePolicy.RegisterAndEvaluateChain(growth, cfg));
            Assert.False(ResponsePolicy.RegisterAndEvaluateChain(ppid, cfg));
        }

        [Fact]
        public void Chain_Confirm_Promotes_Kill_Fields_For_Evidence_Packs()
        {
            var cfg = ObserveConfig();
            var c2 = new DetectionEvent
            {
                RuleName = "C2 Beaconing: Statistical Beacon Detected",
                SignalType = SignalType.NetworkC2,
                ProcessId = 9010,
                ProcessName = "evil.exe",
                Confidence = 0.90,
                Tier = DetectionTier.Tier1Behavioral,
                AuthorizedResponse = ResponseAction.NetworkIsolate,
            };
            var inject = new DetectionEvent
            {
                RuleName = "Threat Intel: Remote Memory Injection",
                SignalType = SignalType.ProcessInjection,
                ProcessId = 9010,
                ProcessName = "evil.exe",
                Confidence = 0.88,
                Tier = DetectionTier.Tier1Behavioral,
                // Start as LogOnly - chain confirm must promote kill-grade fields
                AuthorizedResponse = ResponseAction.LogOnly,
            };

            // v2.9.4: observe-until-chain removed as a settable mode. Drive the observe-independent
            // multi-signal correlation directly so the chain-confirm still promotes the kill-grade
            // fields the evidence packs rely on.
            Assert.False(ResponsePolicy.RegisterAndEvaluateChain(c2, cfg));
            Assert.True(ResponsePolicy.RegisterAndEvaluateChain(inject, cfg));
            Assert.True(inject.KillAuthorized); // derived from AuthorizedResponse
            Assert.Equal(DetectionTier.Tier1Behavioral, inject.Tier);
            Assert.True(inject.AuthorizedResponse >= ResponseAction.KillProcessTree);
            Assert.Equal(ResponseAction.QuarantineAndKill, inject.AuthorizedResponse);
            Assert.Equal("true", inject.Metadata[ResponsePolicy.ChainConfirmedKey]);
        }

        [Fact]
        public void Low_Confidence_C2_Does_Not_Complete_Chain()
        {
            var cfg = ObserveConfig();
            // Two weak observe-fuel signals that must never alone confirm a chain:
            // low-confidence C2 (conf 0.50 - below MinTier1Confidence) and a
            // suspicious path alert (non-terminal family). Neither is kill-grade.
            var lowC2 = new DetectionEvent
            {
                RuleName = "C2 Beaconing: Statistical Beacon Detected",
                SignalType = SignalType.NetworkC2,
                ProcessId = 9020,
                ProcessName = "maybe.exe",
                Confidence = 0.50,
            };
            var suspPath = new DetectionEvent
            {
                RuleName = "Attack Tool: Connection from Suspicious Path",
                SignalType = SignalType.SuspiciousProcess,
                ProcessId = 9020,
                ProcessName = "maybe.exe",
                Confidence = 0.40,
            };

            // v2.9.4: observe-until-chain removed as a settable mode. Drive the observe-independent
            // multi-signal correlation directly: low-confidence + non-terminal signals must not
            // confirm a chain.
            Assert.False(ResponsePolicy.RegisterAndEvaluateChain(lowC2, cfg));
            Assert.False(ResponsePolicy.RegisterAndEvaluateChain(suspPath, cfg));
        }
    }
}
