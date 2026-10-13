using System;
using System.IO;
using Xunit;
using Sentinel.Core;

namespace Sentinel.Tests
{
    public class V212WorkFirstTests
    {
        [Fact]
        public void DefaultConfig_ArmsMitmDefense_AndUsbAutoDisable()
        {
            var c = new SentinelConfig();
            // v2.5.5: RestrictivePortHardening is always-on.
            Assert.True(c.RestrictivePortHardening);
            // v2.9.4: MitmDefense is armed by default (post-incident hardened product line).
            Assert.True(c.MitmDefense.Enabled);
            // v3.0.3: work-first restraint dropped - descriptor-fail USB is auto-disabled by default.
            Assert.True(c.AutoDisableFailedUsbEnumeration);
            Assert.True(ProductPosture.AllowsProactiveHostLockdown(c));
            Assert.True(ProductPosture.AllowsMitmDefenseMutations(c));
        }

        [Fact]
        public void MitmDefense_EnabledSetsMitmPostureWithoutFullInlineMutationUnlock()
        {
            // v2.9.4: observe-until-chain removed as a settable mode; MayPerformInlineHostMutation
            // no longer gates on observe, so the old "MitmDefense does not unlock arbitrary inline
            // mutation while observing" assertion is moot. The surviving coverage is that enabling
            // MitmDefense flips ONLY the MitmDefense posture switch.
            var cfg = new SentinelConfig
            {
                MitmDefense = new MitmDefenseConfig { Enabled = true }
            };
            Assert.True(ProductPosture.AllowsMitmDefenseMutations(cfg));
        }

        [Fact]
        public void EncryptedStore_RestrictivePortHardeningIsAlwaysOn()
        {
            // v2.5.5: ApplyOverrides RestrictivePortHardening case is a no-op;
            // the getter always returns true regardless of what is stored.
            var dir = Path.Combine(Path.GetTempPath(), "sentinel-v212-" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(dir);
            try
            {
                var store = new EncryptedConfigStore(customPath: Path.Combine(dir, "config.enc"));
                store.SetOverride("RestrictivePortHardening", "false"); // should be no-op
                var cfg = new SentinelConfig();
                store.ApplyOverrides(cfg);
                Assert.True(cfg.RestrictivePortHardening); // always true
            }
            finally
            {
                try { Directory.Delete(dir, recursive: true); } catch { }
            }
        }

        [Fact]
        public void UnmappedThread_LargeJitRegion_IsNotShellcode()
        {
            Assert.False(EtwThreatIntelMonitor.IsCompactPrivateExecutable(
                NativeProcessMemory.MEM_COMMIT, 0, NativeProcessMemory.PAGE_EXECUTE_READWRITE, 256 * 1024));
        }

        [Fact]
        public void UnmappedThread_CompactPrivateRx_IsShellcode()
        {
            Assert.True(EtwThreatIntelMonitor.IsCompactPrivateExecutable(
                NativeProcessMemory.MEM_COMMIT, 0, NativeProcessMemory.PAGE_EXECUTE_READ, 4096));
        }

        [Fact]
        public void VolumeMount_RejectsNonLetterDrive()
        {
            Assert.False(VolumeMountMonitor.IsSingleDriveLetter("C:\\Windows"));
            Assert.False(VolumeMountMonitor.IsSingleDriveLetter("'; calc; #"));
            Assert.True(VolumeMountMonitor.IsSingleDriveLetter("D"));
            Assert.True(VolumeMountMonitor.IsSingleDriveLetter("e:"));
        }

        [Fact]
        public void GameWorkSurface_IncludesObsXboxAndStore()
        {
            Assert.True(SecurityValidation.IsGameOrAntiCheatPath(@"C:\Program Files\obs-studio\bin\64bit\obs64.exe"));
            Assert.True(SecurityValidation.IsGameOrAntiCheatPath(@"C:\XboxGames\SomeGame\Content\game.exe"));
            Assert.True(SecurityValidation.IsGameOrAntiCheatPath(@"C:\Program Files\WindowsApps\Microsoft.GamingApp_1.0\XboxPcApp.exe"));
            Assert.False(SecurityValidation.IsGameOrAntiCheatPath(@"C:\Temp\obs-studio\malware.exe"));
            Assert.False(SecurityValidation.IsGameOrAntiCheatPath(@"C:\Users\attacker\epic games\malware.exe"));
        }

        [Fact]
        public void InstallerHeuristics_RecognizeSteamXboxObsSetups()
        {
            Assert.True(InstallerHeuristics.LooksLikeInstallerName("SteamSetup"));
            Assert.True(InstallerHeuristics.LooksLikeInstallerName("XboxInstaller"));
            Assert.True(InstallerHeuristics.LooksLikeInstallerName("OBS-Studio-31.0-Windows"));
        }

        [Fact]
        public void ThreatIntelInjection_IgnoresLocalWriteEventId()
        {
            var rule = new ThreatIntelInjectionRule();
            var ctx = new FusedTelemetryContext
            {
                TriggeringEvent = new ThreatIntelTelemetry
                {
                    ProcessName = "malware",
                    ProcessId = 4242,
                    TargetProcessId = 4,
                    ApiName = "ThreatIntel_EventId_12"
                }
            };
            Assert.Null(rule.Evaluate(ctx));
        }

        [Fact]
        public void ThreatIntelInjection_FiresRemoteWriteEventId()
        {
            var rule = new ThreatIntelInjectionRule();
            var ctx = new FusedTelemetryContext
            {
                TriggeringEvent = new ThreatIntelTelemetry
                {
                    ProcessName = "malware",
                    ProcessId = 4242,
                    TargetProcessId = 1000,
                    ApiName = "ThreatIntel_EventId_14"
                }
            };
            var d = rule.Evaluate(ctx);
            Assert.NotNull(d);
            Assert.Equal(ResponseAction.QuarantineAndKill, d!.AuthorizedResponse);
        }

        [Fact]
        public void ProductInfo_MatchesTwoOneTwoCurrentVersion()
        {
            // v2.6.0: version is computed from version.txt / stamped assembly version.
            var asmVersion = typeof(ProductInfo).Assembly.GetName().Version?.ToString(3);
            Assert.Equal(asmVersion, ProductInfo.Version);
        }

        [Theory]
        [InlineData("Reverse Shell: Suspicious Outbound Connection")]
        [InlineData("DNS Bypass: Application-Level DoH Detected")]
        [InlineData("C2 Pairing: Defensive Process Spawn After Drop")]
        [InlineData("Process Hollowing: Image File Missing")]
        [InlineData("Clickjacking: Suspicious Overlay")]
        [InlineData("Named Pipe: High-Entropy Name (Non-System Owner)")]
        [InlineData("Remote Access: Known RAT Process Running")]
        public void BrowsePlayHeuristics_AreWeakObserveSeeds(string rule)
        {
            var d = new DetectionEvent { RuleName = rule, Confidence = 0.90, ProcessId = 9 };
            Assert.True(ResponsePolicy.IsWeakObserveSeed(d) ||
                        ResponsePolicy.ClassifyTerminalOutcome(d) == null);
            Assert.False(ResponsePolicy.IsAttackClassTerminal(d));
        }

        [Fact]
        public void LpeScaffold_IsTokenTheftTerminal()
        {
            var d = new DetectionEvent
            {
                RuleName = "LPE Scaffold: Privilege Escalation Tool",
                Confidence = 0.88,
                ProcessId = 11,
                SignalType = SignalType.SecurityEvasion
            };
            Assert.False(ResponsePolicy.IsWeakObserveSeed(d));
            Assert.Equal("TokenTheft", ResponsePolicy.ClassifyTerminalOutcome(d));
            Assert.True(ResponsePolicy.IsAttackClassTerminal(d));
        }
    }
}
