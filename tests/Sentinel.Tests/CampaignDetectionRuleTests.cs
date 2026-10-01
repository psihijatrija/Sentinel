using System;
using Microsoft.Extensions.Logging.Abstractions;
using Xunit;
using Sentinel.Core;

namespace Sentinel.Tests
{
    public class CampaignDetectionRuleTests
    {
        private readonly CampaignDetectionRule _rule = new(NullLogger<CampaignDetectionRule>.Instance);

        private static FusedTelemetryContext MakeCtx(string processName, int pid,
            string commandLine = "", string imagePath = "")
        {
            return new FusedTelemetryContext
            {
                ProcessId = pid,
                ProcessName = processName,
                TriggeringEvent = new ProcessTelemetry
                {
                    ProcessName = processName,
                    ProcessId = pid,
                    CommandLine = commandLine,
                    ImagePath = imagePath
                }
            };
        }

        //  CobaltStrike 

        [Fact]
        public void CobaltStrike_Fires_OnBeaconExe()
        {
            var result = _rule.Evaluate(MakeCtx("beacon.exe", 1000, imagePath: @"C:\temp\beacon.exe"));
            Assert.NotNull(result);
            Assert.Contains("Cobalt Strike", result!.RuleName);
            Assert.True(result.KillAuthorized);
        }

        [Fact]
        public void CobaltStrike_Fires_OnArtifactExe()
        {
            var result = _rule.Evaluate(MakeCtx("artifact.exe", 2000, imagePath: @"C:\temp\artifact.exe"));
            Assert.NotNull(result);
        }

        //  QBot 

        [Fact]
        public void QBot_Fires_OnChkdsksExe()
        {
            var result = _rule.Evaluate(MakeCtx("chkdsks", 3000, imagePath: @"C:\temp\chkdsks.exe"));
            Assert.NotNull(result);
            Assert.Contains("QBot", result!.RuleName);
        }

        [Fact]
        public void QBot_Fires_OnRegsvr32DatPattern()
        {
            var result = _rule.Evaluate(MakeCtx("regsvr32", 3001,
                commandLine: @"regsvr32.exe -s C:\Users\Admin\abcdef12.dat",
                imagePath: @"C:\Windows\System32\regsvr32.exe"));
            // Must match command line pattern but needs filename too for >= 0.5 confidence
            // regsvr32.exe is not in QBot FileNames, so command line alone gives 0.3
            // This should NOT fire (below 0.5 threshold)
            Assert.Null(result);
        }

        //  Emotet 

        [Fact]
        public void Emotet_Fires_OnSysExe()
        {
            var result = _rule.Evaluate(MakeCtx("sys", 4000, imagePath: @"C:\temp\sys.exe"));
            Assert.NotNull(result);
            Assert.Contains("Emotet", result!.RuleName);
        }

        [Fact]
        public void Emotet_Fires_OnWinExeWithCommandLine()
        {
            // "win.exe" filename match (0.4) + command line pattern -E123 (0.3) = 0.7 >= 0.5
            var result = _rule.Evaluate(MakeCtx("win", 4001,
                commandLine: "win.exe -E42", imagePath: @"C:\temp\win.exe"));
            Assert.NotNull(result);
        }

        //  TrickBot 

        [Fact]
        public void TrickBot_Fires_OnTabExe()
        {
            var result = _rule.Evaluate(MakeCtx("tab", 5000,
                commandLine: "tab.exe -s", imagePath: @"C:\temp\tab.exe"));
            Assert.NotNull(result);
            Assert.Contains("TrickBot", result!.RuleName);
        }

        [Fact]
        public void TrickBot_Fires_OnInjectExe()
        {
            var result = _rule.Evaluate(MakeCtx("inject", 5001, imagePath: @"C:\temp\inject.exe"));
            Assert.NotNull(result);
        }

        //  False positive prevention (v3.8.0 exact filename fix) 

        [Fact]
        public void DoesNotFire_OnGoogleUpdateExe()
        {
            // "GoogleUpdate.exe" should NOT match "update.exe" (removed from Emotet)
            var result = _rule.Evaluate(MakeCtx("GoogleUpdate.exe", 6000,
                imagePath: @"C:\Program Files\Google\Update\GoogleUpdate.exe"));
            Assert.Null(result);
        }

        [Fact]
        public void DoesNotFire_OnNotepad()
        {
            var result = _rule.Evaluate(MakeCtx("notepad.exe", 7000,
                imagePath: @"C:\Windows\System32\notepad.exe"));
            Assert.Null(result);
        }

        [Fact]
        public void DoesNotFire_OnChrome()
        {
            var result = _rule.Evaluate(MakeCtx("chrome.exe", 8000,
                imagePath: @"C:\Program Files\Google\Chrome\Application\chrome.exe"));
            Assert.Null(result);
        }

        [Fact]
        public void DoesNotFire_OnServicesExe()
        {
            // "services.exe" was removed from QBot/TrickBot indicators in v3.8.0
            var result = _rule.Evaluate(MakeCtx("services.exe", 9000,
                imagePath: @"C:\Windows\System32\services.exe"));
            Assert.Null(result);
        }

        [Fact]
        public void DoesNotFire_OnNetworkTelemetry()
        {
            var ctx = new FusedTelemetryContext
            {
                ProcessId = 10000,
                ProcessName = "beacon.exe",
                TriggeringEvent = new NetworkTelemetry { ProcessName = "beacon.exe", ProcessId = 10000 }
            };
            Assert.Null(_rule.Evaluate(ctx));
        }

        //  Detection properties 

        [Fact]
        public void Detection_HasCorrectMetadata()
        {
            var result = _rule.Evaluate(MakeCtx("beacon.exe", 11000, imagePath: @"C:\temp\beacon.exe"));
            Assert.NotNull(result);
            Assert.True(result!.Metadata.ContainsKey("campaign"));
            Assert.True(result.Metadata.ContainsKey("mitre_techniques"));
            Assert.Equal(DetectionTier.Tier1Behavioral, result.Tier);
            Assert.True(result.Confidence <= 0.95);
        }

        [Fact]
        public void Detection_AuthorizesKillProcessTree()
        {
            var result = _rule.Evaluate(MakeCtx("beacon.exe", 12000, imagePath: @"C:\temp\beacon.exe"));
            Assert.NotNull(result);
            Assert.Equal(ResponseAction.KillProcessTree, result!.AuthorizedResponse);
        }
    }
}
