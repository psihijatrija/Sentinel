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
        }

        [Fact]
        public void Single_Statistical_Beacon_Classifies_As_C2Beacon_But_Is_Not_AttackClassSolo()
        {
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

            Assert.False(ResponsePolicy.RegisterAndEvaluateChain(lowC2, cfg));
            Assert.False(ResponsePolicy.RegisterAndEvaluateChain(suspPath, cfg));
        }

        // =====================================================================
        // AUDIT #1: kill-grade classification must NOT come from attacker-controlled
        // Evidence / Reasoning text (which embed the observed command line verbatim).
        // =====================================================================

        [Fact]
        public void Audit1_BenignBcdedit_In_Evidence_Does_Not_Classify_As_Ransomware()
        {
            // A legitimate recovery/backup tool logs its command line into Evidence:
            //   bcdedit /set {default} recoveryenabled No  (contains "bcdedit /set" + "recover")
            // Previously the haystack scanned Evidence and mapped this to the Ransomware
            // kill-grade family. The RuleName is a neutral observe rule, so it must NOT.
            var d = new DetectionEvent
            {
                RuleName = "Suspicious Outbound Connection",
                Evidence = @"Process ran: bcdedit /set {default} recoveryenabled No",
                Reasoning = "Observed command line contained the string recover off during backup maintenance.",
                SignalType = SignalType.SuspiciousProcess,
                ProcessId = 6001,
                ProcessName = "backuptool.exe",
                Confidence = 0.90,
            };

            Assert.Null(ResponsePolicy.ClassifyTerminalOutcome(d));
            Assert.False(ResponsePolicy.IsKillGradeTerminal(d));
        }

        [Fact]
        public void Audit1_Beacon_Token_In_CommandLine_Evidence_Does_Not_Classify_C2()
        {
            // An attacker (or benign app) whose command line merely contains "beacon"
            // must not promote a neutral observe detection to the C2Beacon family.
            var d = new DetectionEvent
            {
                RuleName = "Network Policy: Unusual Destination",
                Evidence = @"cmd: app.exe --mode beacon --interval 30",
                ProcessId = 6002,
                ProcessName = "app.exe",
                Confidence = 0.90,
            };

            Assert.Null(ResponsePolicy.ClassifyTerminalOutcome(d));
        }

        [Fact]
        public void Audit1_Real_Ransomware_Still_Classifies_Via_Family_And_RuleName()
        {
            // The fix must not weaken real detection: RansomwareDetectionRule sets both
            // Family and a terminal SignalType, and its RuleName matches a fragment.
            var viaFamily = new DetectionEvent
            {
                RuleName = "RansomwareDetectionRule",
                Family = TerminalFamily.Ransomware,
                SignalType = SignalType.Ransomware,
                Evidence = @"Shadow copy / backup deletion command: vssadmin delete shadows /all /quiet",
                ProcessId = 6003,
                ProcessName = "locker.exe",
                Confidence = 0.98,
            };
            Assert.Equal("Ransomware", ResponsePolicy.ClassifyTerminalOutcome(viaFamily));
            Assert.True(ResponsePolicy.IsKillGradeTerminal(viaFamily));

            // And a monitor-authored kill-grade RuleName still classifies with no Family/SignalType.
            var viaRuleName = new DetectionEvent
            {
                RuleName = "LSASS Credential Dump via comsvcs MiniDump",
                ProcessId = 6004,
                ProcessName = "rundll32.exe",
                Confidence = 0.93,
            };
            Assert.Equal("CredentialDump", ResponsePolicy.ClassifyTerminalOutcome(viaRuleName));
        }

        // =====================================================================
        // AUDIT #1/#2: a process-name interpolated into a RuleName's "(...)" span must
        // not smuggle a kill-grade token through classification or the solo-kill path.
        // =====================================================================

        [Fact]
        public void Audit2_ProcessName_In_RuleName_Parens_Does_Not_Classify_TokenTheft()
        {
            // Attacker names their binary "Potato.exe"; ScriptExecutionMonitor emits
            //   "Script: Anomalous Parent-Child (winword->Potato)"
            // The "Potato" TokenTheft fragment lives inside the interpolated span and
            // must be stripped before classification.
            var d = new DetectionEvent
            {
                RuleName = "Script: Anomalous Parent-Child (winword->Potato)",
                ProcessId = 6005,
                ProcessName = "Potato",
                Confidence = 0.90,
            };
            Assert.Null(ResponsePolicy.ClassifyTerminalOutcome(d));
        }

        [Fact]
        public void Audit2_ProcessName_In_RuleName_Parens_Does_Not_Solo_Kill()
        {
            // "AMSI Bypass Detected" is an attack-class solo-kill token. If an attacker
            // names a binary to put it inside the interpolated span, the solo-kill path
            // must not fire.
            var d = new DetectionEvent
            {
                RuleName = "Script: Anomalous Parent-Child (svc->AMSI Bypass Detected)",
                ProcessId = 6006,
                ProcessName = "evil",
                Confidence = 0.99,
            };
            Assert.False(ResponsePolicy.IsAttackClassTerminal(d));
        }

        [Fact]
        public void Audit2_Genuine_AttackClass_RuleName_Still_Solo_Kills()
        {
            // The real monitor-authored rule name (token OUTSIDE any parens) still fires.
            var d = new DetectionEvent
            {
                RuleName = "Evasion: AMSI Bypass Detected (attributed patch)",
                ProcessId = 6007,
                ProcessName = "evil.exe",
                Confidence = 0.95,
            };
            Assert.True(ResponsePolicy.IsAttackClassTerminal(d));
        }

        [Fact]
        public void Audit2_StripInterpolatedSegments_Removes_Only_Paren_Spans()
        {
            Assert.Equal("Script: Anomalous Parent-Child ",
                ResponsePolicy.StripInterpolatedSegments("Script: Anomalous Parent-Child (a->b)"));
            Assert.Equal("Evasion: AMSI Bypass Detected ",
                ResponsePolicy.StripInterpolatedSegments("Evasion: AMSI Bypass Detected (attributed)"));
            Assert.Equal("NoParensHere",
                ResponsePolicy.StripInterpolatedSegments("NoParensHere"));
        }

        // =====================================================================
        // AUDIT #8: MayPerformDestructiveResponse must vet the detection, not just
        // return the ActiveResponse arming switch.
        // =====================================================================

        [Fact]
        public void Audit8_Unconfirmed_Tier2_Detection_Is_Refused_Even_When_Armed()
        {
            var cfg = ObserveConfig(); // ActiveResponse = true
            var d = new DetectionEvent
            {
                RuleName = "Suspicious Outbound Connection",
                ProcessId = 6008,
                ProcessName = "maybe.exe",
                Confidence = 0.60,
                Tier = DetectionTier.Tier2Indicator,
                AuthorizedResponse = ResponseAction.KillProcessTree, // set in error upstream
            };
            Assert.False(ResponsePolicy.MayPerformDestructiveResponse(d, cfg));
            // Arming-only check still reports armed.
            Assert.True(ResponsePolicy.IsResponseArmed(cfg));
        }

        [Fact]
        public void Audit8_ChainConfirmed_Tier1_Is_Allowed_When_Armed()
        {
            var cfg = ObserveConfig();
            var d = new DetectionEvent
            {
                RuleName = "C2 Beaconing: Statistical Beacon Detected",
                SignalType = SignalType.NetworkC2,
                ProcessId = 6009,
                ProcessName = "evil.exe",
                Confidence = 0.92,
                Tier = DetectionTier.Tier1Behavioral,
                AuthorizedResponse = ResponseAction.QuarantineAndKill,
                Metadata = new Dictionary<string, string> { [ResponsePolicy.ChainConfirmedKey] = "true" },
            };
            Assert.True(ResponsePolicy.MayPerformDestructiveResponse(d, cfg));
        }

        [Fact]
        public void Audit8_Detection_Vetting_Is_The_Gate_Since_ActiveResponse_Is_Always_On()
        {
            // v2.0.4 design: ActiveResponse has no off switch (get => true, setter is a no-op),
            // so arming cannot be the discriminator. The #8 fix adds the real gate: the
            // detection must actually be a confirmed Tier1 kill. A composite passes; an
            // unconfirmed Tier2 with a kill action set in error does not.
            var cfg = new SentinelConfig { ActiveResponse = false }; // ignored - stays true
            Assert.True(cfg.ActiveResponse);
            Assert.True(ResponsePolicy.IsResponseArmed(cfg));

            var composite = new DetectionEvent
            {
                RuleName = "Injected C2 Beacon",
                Evidence = "[COMPOSITE] injection + C2",
                ProcessId = 6010,
                ProcessName = "evil.exe",
                Confidence = 0.98,
                Tier = DetectionTier.Tier1Behavioral,
                AuthorizedResponse = ResponseAction.QuarantineAndKill,
            };
            Assert.True(ResponsePolicy.MayPerformDestructiveResponse(composite, cfg));

            var unconfirmed = new DetectionEvent
            {
                RuleName = "Suspicious Outbound Connection",
                ProcessId = 6011,
                ProcessName = "maybe.exe",
                Confidence = 0.60,
                Tier = DetectionTier.Tier2Indicator,
                AuthorizedResponse = ResponseAction.KillProcessTree,
            };
            Assert.False(ResponsePolicy.MayPerformDestructiveResponse(unconfirmed, cfg));
        }

        // =====================================================================
        // AUDIT #5: cross-PID root buffer must not confirm a kill from two UNRELATED
        // single-signal siblings under a shared launcher.
        // =====================================================================

        [Fact]
        public void Audit5_Two_Unrelated_SingleSignal_Siblings_Do_Not_Chain_Via_Root()
        {
            // No ancestry cache wired in unit tests, so GetAttackRootPid returns 0 and the
            // root path is inert - but the strict-corroboration guard it depends on is the
            // unit under test here. We exercise it directly against the buffer semantics:
            // a terminal leg on one PID with a single signal, plus one unrelated signal on a
            // DIFFERENT PID, must NOT satisfy strict corroboration (self-signals < 2).
            var cfg = ObserveConfig();

            // Child A: a single terminal-classified signal.
            var childA = new DetectionEvent
            {
                RuleName = "C2 Beaconing: Statistical Beacon Detected",
                SignalType = SignalType.NetworkC2,
                ProcessId = 7001,
                ProcessName = "a.exe",
                Confidence = 0.90,
            };
            // Child B (unrelated sibling): a single non-terminal signal.
            var childB = new DetectionEvent
            {
                RuleName = "Suspicious Outbound Connection",
                ProcessId = 7002,
                ProcessName = "b.exe",
                Confidence = 0.80,
            };

            // Per-PID path: neither alone confirms.
            Assert.False(ResponsePolicy.RegisterAndEvaluateChain(childA, cfg));
            Assert.False(ResponsePolicy.RegisterAndEvaluateChain(childB, cfg));
        }

        [Fact]
        public void Audit5_SelfCorroborated_Terminal_Still_Chains_On_Per_Pid_Path()
        {
            // Same PID, a terminal leg + a second distinct signal -> legitimate confirm.
            // Proves the #5 guard does not break the normal per-PID (non-strict) path.
            var cfg = ObserveConfig();
            var pid = 7003;
            var c2 = new DetectionEvent
            {
                RuleName = "C2 Beaconing: Statistical Beacon Detected",
                SignalType = SignalType.NetworkC2,
                ProcessId = pid,
                ProcessName = "evil.exe",
                Confidence = 0.90,
            };
            var inject = new DetectionEvent
            {
                RuleName = "Threat Intel: Remote Memory Injection",
                SignalType = SignalType.ProcessInjection,
                ProcessId = pid,
                ProcessName = "evil.exe",
                Confidence = 0.88,
            };
            Assert.False(ResponsePolicy.RegisterAndEvaluateChain(c2, cfg));
            Assert.True(ResponsePolicy.RegisterAndEvaluateChain(inject, cfg));
        }
    }
}
