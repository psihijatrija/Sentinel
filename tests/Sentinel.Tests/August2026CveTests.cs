using System;
using System.Collections.Generic;
using System.IO;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging.Abstractions;
using Xunit;
using Sentinel.Core;

namespace Sentinel.Tests
{
    public class August2026CveTests
    {
        [Theory]
        [InlineData("SecurityPDF.exe", true)]
        [InlineData(@"C:\Users\x\Downloads\SecurityPDF.exe", true)]
        [InlineData("Afd4Eop12_x64.dll", true)]
        [InlineData("OneScreenCapture64.dll", true)]
        [InlineData("chrome.exe", false)]
        [InlineData("new.exe", false)]
        public void DreamJob_FileName_Match(string name, bool expected)
        {
            Assert.Equal(expected, August2026CveHeuristics.MatchesDreamJobFileName(name));
        }

        [Fact]
        public void DreamJob_Libmupdf_Sideload_Only_In_Staging()
        {
            Assert.True(August2026CveHeuristics.IsLibmupdfSideload(
                @"C:\Users\x\Downloads\job\libmupdf.dll",
                @"C:\Users\x\Downloads\job\viewer.exe"));
            Assert.False(August2026CveHeuristics.IsLibmupdfSideload(
                @"C:\Program Files\SumatraPDF\libmupdf.dll",
                @"C:\Program Files\SumatraPDF\SumatraPDF.exe"));
        }

        [Fact]
        public void DreamJob_TempNewExe_Requires_Staging()
        {
            Assert.True(August2026CveHeuristics.IsTempNewExe(@"C:\Users\x\AppData\Local\Temp\new.exe", "new"));
            Assert.False(August2026CveHeuristics.IsTempNewExe(@"C:\Windows\System32\new.exe", "new"));
        }

        [Fact]
        public void DreamJob_Domains_And_Hashes()
        {
            Assert.True(August2026CveHeuristics.ContainsDreamJobDomain("https://envell.xyz/open"));
            Assert.True(August2026CveHeuristics.ContainsDreamJobDomain("135.181.67.203"));
            Assert.False(August2026CveHeuristics.ContainsDreamJobDomain("https://enveil.com"));
            Assert.True(August2026CveHeuristics.IsDreamJobHash(
                "743172aab606974b054a64561534ae66baa3a840657f79d7c6fa18350e8d45d1"));
            Assert.False(August2026CveHeuristics.IsDreamJobHash("00"));
        }

        [Fact]
        public void Kev_Win11_UBR_Below_9168_Is_Unpatched()
        {
            var eval = August2026CveHeuristics.EvaluateKevAfdPatch(26100, 8000, DateTime.Now);
            Assert.True(eval.Unpatched);
            Assert.True(eval.HighConfidence);
            Assert.Equal("CVE-2026-68820", eval.CveId);
        }

        [Fact]
        public void Kev_Win11_UBR_9168_Is_Patched()
        {
            var eval = August2026CveHeuristics.EvaluateKevAfdPatch(26200, 9168, DateTime.Now);
            Assert.False(eval.Unpatched);
        }

        [Fact]
        public void Kev_Older_Build_Uses_Install_Date()
        {
            var eval = August2026CveHeuristics.EvaluateKevAfdPatch(19045, 1, new DateTime(2026, 7, 1));
            Assert.True(eval.Unpatched);
            Assert.False(eval.HighConfidence);

            var patched = August2026CveHeuristics.EvaluateKevAfdPatch(19045, 1, new DateTime(2026, 8, 12));
            Assert.False(patched.Unpatched);
        }

        [Fact]
        public void LegacyHive_Custom_Named_Hive_Is_Unexpected()
        {
            var loggedOn = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { "S-1-5-21-1-2-3-1001" };
            Assert.True(August2026CveHeuristics.IsUnexpectedUserHive("LegacyHive", loggedOn, @"C:\Users\victim"));
            Assert.True(August2026CveHeuristics.IsCustomNamedHive("evil"));
            Assert.False(August2026CveHeuristics.IsCustomNamedHive("S-1-5-21-1-2-3-1001"));
        }

        [Fact]
        public void LegacyHive_Logged_On_User_Is_Expected()
        {
            var sid = "S-1-5-21-1-2-3-1001";
            var loggedOn = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { sid };
            Assert.False(August2026CveHeuristics.IsUnexpectedUserHive(sid, loggedOn, @"C:\Users\alice"));
        }

        [Fact]
        public void LegacyHive_Other_User_Hive_Is_Unexpected()
        {
            var loggedOn = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { "S-1-5-21-1-2-3-1001" };
            Assert.True(August2026CveHeuristics.IsUnexpectedUserHive(
                "S-1-5-21-1-2-3-1002", loggedOn, @"C:\Users\admin"));
        }

        [Fact]
        public void LegacyHive_No_Session_Data_Fails_Closed()
        {
            var empty = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            Assert.False(August2026CveHeuristics.IsUnexpectedUserHive(
                "S-1-5-21-1-2-3-1002", empty, @"C:\Users\admin"));
        }

        [Fact]
        public void LegacyHive_Skips_WellKnown_And_Service_Profiles()
        {
            var loggedOn = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { "S-1-5-21-1" };
            Assert.False(August2026CveHeuristics.IsUnexpectedUserHive("S-1-5-18", loggedOn, null));
            Assert.False(August2026CveHeuristics.IsUnexpectedUserHive(
                "S-1-5-21-9", loggedOn, @"C:\Windows\ServiceProfiles\NetworkService"));
            Assert.True(August2026CveHeuristics.IsHiveFilePath(@"C:\Users\bob\NTUSER.DAT"));
            Assert.False(August2026CveHeuristics.IsHiveFilePath(@"C:\Users\bob\Documents\file.txt"));
        }

        [Fact]
        public void CloudFiles_Known_Sync_Root_And_Client()
        {
            Assert.True(August2026CveHeuristics.IsKnownSyncRootId(
                @"S-1-5-21-1!Microsoft.OneDrive!abcdef"));
            Assert.False(August2026CveHeuristics.IsKnownSyncRootId(
                @"S-1-5-21-1!ShieldBreak.Hydration!deadbeef"));
            Assert.True(August2026CveHeuristics.IsKnownCloudSyncClient("OneDrive.exe"));
            Assert.False(August2026CveHeuristics.IsKnownCloudSyncClient("evil.exe"));
            Assert.True(August2026CveHeuristics.IsKnownCloudSyncFolder(@"C:\Users\x\OneDrive\file"));
            Assert.False(August2026CveHeuristics.IsKnownCloudSyncFolder(@"C:\Users\x\Downloads\bait"));
        }

        [Fact]
        public void CloudFiles_Placeholder_Attributes()
        {
            Assert.True(August2026CveHeuristics.IsCloudPlaceholderAttributes(
                August2026CveHeuristics.FileAttributeRecallOnDataAccess));
            Assert.False(August2026CveHeuristics.IsCloudPlaceholderAttributes((int)FileAttributes.Archive));
        }

        [Fact]
        public void CampaignRule_Fires_On_SecurityPDF()
        {
            var rule = new CampaignDetectionRule(NullLogger<CampaignDetectionRule>.Instance);
            var result = rule.Evaluate(new FusedTelemetryContext
            {
                ProcessId = 4242,
                ProcessName = "SecurityPDF",
                TriggeringEvent = new ProcessTelemetry
                {
                    ProcessName = "SecurityPDF",
                    ProcessId = 4242,
                    ImagePath = @"C:\Users\x\Downloads\SecurityPDF.exe",
                    CommandLine = ""
                }
            });
            Assert.NotNull(result);
            Assert.Contains("Lazarus", result!.RuleName);
            Assert.True(result.Confidence >= 0.5);
        }

        [Fact]
        public void CampaignIocRule_Fires_On_DreamJob_Domain()
        {
            var rule = new CampaignIocRule();
            var result = rule.Evaluate(new FusedTelemetryContext
            {
                ProcessId = 7,
                ProcessName = "curl",
                TriggeringEvent = new ProcessTelemetry
                {
                    ProcessName = "curl",
                    ProcessId = 7,
                    ImagePath = @"C:\Windows\System32\curl.exe",
                    CommandLine = @"curl.exe https://envell.xyz/job"
                }
            });
            Assert.NotNull(result);
            Assert.Equal(SignalType.NetworkC2, result!.SignalType);
        }

        [Fact]
        public async Task Composite_LazarusDreamJob_Requires_Two_Legs()
        {
            var engine = new BehavioralCorrelationEngine();
            DetectionEvent? composite = null;
            engine.Initialize(ev => { composite = ev; return Task.CompletedTask; });

            await engine.RegisterSignalAsync(new DetectionEvent
            {
                RuleName = "Dream Job: SecurityPDF loader",
                ProcessId = 9001,
                ProcessName = "SecurityPDF",
                SignalType = SignalType.SuspiciousProcess,
                Timestamp = DateTime.UtcNow
            });
            Assert.Null(composite);

            await engine.RegisterSignalAsync(new DetectionEvent
            {
                RuleName = "Dream Job: FudModule LPE module",
                ProcessId = 9001,
                ProcessName = "SecurityPDF",
                SignalType = SignalType.SecurityEvasion,
                Timestamp = DateTime.UtcNow
            });
            Assert.NotNull(composite);
            Assert.Equal("Lazarus Dream Job Chain", composite!.RuleName);
            Assert.True(composite.Confidence >= 0.90);
        }

        [Fact]
        public async Task Composite_LegacyHive_With_TokenTheft()
        {
            var engine = new BehavioralCorrelationEngine();
            DetectionEvent? composite = null;
            engine.Initialize(ev => { composite = ev; return Task.CompletedTask; });

            await engine.RegisterSignalAsync(new DetectionEvent
            {
                RuleName = "LegacyHive: Another user's hive loaded",
                ProcessId = 55,
                ProcessName = "ProfSvc",
                SignalType = SignalType.SecurityEvasion,
                Timestamp = DateTime.UtcNow
            });
            await engine.RegisterSignalAsync(new DetectionEvent
            {
                RuleName = "Token Theft: SYSTEM Impersonation",
                ProcessId = 55,
                ProcessName = "ProfSvc",
                SignalType = SignalType.SecurityEvasion,
                Timestamp = DateTime.UtcNow
            });
            Assert.NotNull(composite);
            Assert.Equal("LegacyHive Privilege Escalation Chain", composite!.RuleName);
        }

        [Fact]
        public async Task Composite_CloudFiles_With_Lpe()
        {
            var engine = new BehavioralCorrelationEngine();
            DetectionEvent? composite = null;
            engine.Initialize(ev => { composite = ev; return Task.CompletedTask; });

            await engine.RegisterSignalAsync(new DetectionEvent
            {
                RuleName = "Cloud Files: Unauthorized sync root",
                ProcessId = 66,
                ProcessName = "evil",
                SignalType = SignalType.AntiTamper,
                Timestamp = DateTime.UtcNow
            });
            Assert.Null(composite);

            await engine.RegisterSignalAsync(new DetectionEvent
            {
                RuleName = "LPE Scaffold: Privilege Escalation Tool",
                ProcessId = 66,
                ProcessName = "evil",
                SignalType = SignalType.SecurityEvasion,
                Timestamp = DateTime.UtcNow
            });
            Assert.NotNull(composite);
            Assert.Equal("Cloud Files Hydration Tamper Chain", composite!.RuleName);
        }

        [Fact]
        public void IoCScanner_AddHashes_Does_Not_Wipe()
        {
            var cache = new SecureCacheStore(Path.GetTempPath());
            var scanner = new IoCScanner(cache);
            var a = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
            var b = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
            scanner.UpdateHashes(new[] { a });
            scanner.AddHashes(new[] { b });
            Assert.True(scanner.IsKnownBadHash(a));
            Assert.True(scanner.IsKnownBadHash(b));
        }

        [Fact]
        public void Weighted_Maps_DreamJob_And_CloudFiles()
        {
            Assert.Equal("PrivilegeEscalation", WeightedCorrelationEngine.MapWeightCategory(
                new DetectionEvent { RuleName = "Dream Job: FudModule LPE module" }));
            Assert.Equal("Evasion", WeightedCorrelationEngine.MapWeightCategory(
                new DetectionEvent { RuleName = "Cloud Files: Unauthorized sync root" }));
        }
    }
}
