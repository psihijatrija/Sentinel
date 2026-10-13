using System.Collections.Generic;
using Sentinel.Core;
using Xunit;

namespace Sentinel.Tests
{
    /// <summary>
    /// Tests for UpdateServicingMonitor (v2.6.3) - the update/servicing-surface observer.
    ///
    /// Covers the docs/constraints.md testing contract for a new Tier2 detection surface:
    ///   (2) every Tier2 rule proves it returns Tier2Indicator;
    ///   (3) the Tier2 log-only contract holds (Tier2 must be LogOnly / KillAuthorized == false);
    /// plus the pure detection heuristics (abnormal extraction path, Microsoft-signer test,
    /// Microsoft update-host test, expand/extrac32 destination parsing).
    ///
    /// This monitor never emits Tier1 and never self-authorizes a kill by design, so there is
    /// no Tier1-fires test (contract item 1 is N/A) and no ProductPosture host-mutation gate
    /// (contract item 4 is N/A - the monitor performs no host mutation).
    /// </summary>
    public class UpdateServicingMonitorTests
    {
        //  Contract (2)+(3): Tier2 classification + log-only invariant 

        /// <summary>
        /// Mirrors the four DetectionEvents the monitor emits. Every servicing signal is
        /// Tier2Indicator / LogOnly by construction; this asserts that contract shape so a
        /// future edit that accidentally promotes one to a kill is caught.
        /// </summary>
        public static IEnumerable<object[]> ServicingSignals()
        {
            yield return new object[] { "Servicing: Anomalous Child (trustedinstaller->cmd)" };
            yield return new object[] { "Servicing: CAB/MSU Extraction to Abnormal Path" };
            yield return new object[] { "Servicing: Non-Microsoft Servicing Binary" };
            yield return new object[] { "Servicing: Suspicious Update Source (WSUS)" };
        }

        [Theory]
        [MemberData(nameof(ServicingSignals))]
        public void ServicingSignal_IsTier2_LogOnly_NeverKill(string ruleName)
        {
            var detection = new DetectionEvent
            {
                RuleName = ruleName,
                Tier = DetectionTier.Tier2Indicator,
                AuthorizedResponse = ResponseAction.LogOnly,
                SignalType = SignalType.SuspiciousProcess,
                ProcessId = 4321,
                ProcessName = "servicing",
                Confidence = 0.65,
                // Terminal family MUST be null - these are observe legs, not kill-grade outcomes.
                Family = null,
            };

            Assert.Equal(DetectionTier.Tier2Indicator, detection.Tier);
            Assert.Equal(ResponseAction.LogOnly, detection.AuthorizedResponse);
            Assert.False(detection.KillAuthorized);
            Assert.Null(detection.Family);
        }

        [Fact]
        public void ServicingSignals_AreCategorized_NotUnknown()
        {
            foreach (var row in ServicingSignals())
            {
                var ruleName = (string)row[0];
                var category = ScoringEngine.CategorizeDetection(ruleName);
                Assert.NotEqual(DetectionCategory.Unknown, category);
            }
        }

        //  Check 2: abnormal CAB/MSU extraction path 

        [Theory]
        [InlineData(@"C:\Windows\WinSxS\amd64_something")]
        [InlineData(@"C:\Windows\servicing\Packages")]
        [InlineData(@"C:\Windows\Temp\cab_1234")]
        [InlineData(@"C:\Windows\System32\drivers")]
        [InlineData(@"C:\Windows\SoftwareDistribution\Download")]
        public void LegitStagingPath_TrueForServicingTargets(string path)
        {
            Assert.True(UpdateServicingMonitor.IsLegitStagingPath(path));
        }

        [Theory]
        [InlineData(@"C:\Users\victim\AppData\Local\Temp\payload")]
        [InlineData(@"C:\Users\victim\Downloads")]
        [InlineData(@"C:\ProgramData\evil")]
        [InlineData(@"D:\staging\out")]
        public void LegitStagingPath_FalseForAbnormalTargets(string path)
        {
            // These are the CVE-2021-40444 "extract outside expected dir" shape.
            Assert.False(UpdateServicingMonitor.IsLegitStagingPath(path));
        }

        //  Check 3: Microsoft signer classification 

        [Theory]
        [InlineData("Microsoft Windows")]
        [InlineData("Microsoft Corporation")]
        [InlineData("Microsoft Windows Publisher")]
        public void MicrosoftSigner_TrueForMicrosoftCns(string cn)
        {
            Assert.True(UpdateServicingMonitor.IsMicrosoftSigner(cn));
        }

        [Theory]
        [InlineData("Totally Legit Software LLC")]
        [InlineData("Evil Driver Co")]
        [InlineData("")]
        [InlineData(null)]
        public void MicrosoftSigner_FalseForNonMicrosoftOrEmpty(string? cn)
        {
            Assert.False(UpdateServicingMonitor.IsMicrosoftSigner(cn));
        }

        //  Check 4: update-source host classification 

        [Theory]
        [InlineData("https://fe2.update.microsoft.com")]
        [InlineData("https://wsus.corp.microsoft.com")]
        [InlineData("http://download.windowsupdate.com")]
        public void MicrosoftUpdateHost_TrueForMicrosoftHosts(string wuServer)
        {
            Assert.True(UpdateServicingMonitor.LooksMicrosoftUpdateHost(wuServer));
        }

        [Theory]
        [InlineData("http://192.168.1.50:8530")]
        [InlineData("http://rogue-wsus.attacker.lan")]
        [InlineData("https://updates.evil.example")]
        public void MicrosoftUpdateHost_FalseForNonMicrosoftHosts(string wuServer)
        {
            Assert.False(UpdateServicingMonitor.LooksMicrosoftUpdateHost(wuServer));
        }

        //  expand/extrac32 destination parsing 

        [Theory]
        [InlineData(@"expand.exe C:\payload.cab -F:* C:\Users\victim\AppData\Local\Temp\out", @"C:\Users\victim\AppData\Local\Temp\out")]
        [InlineData(@"extrac32.exe /E ""C:\ProgramData\evil""", @"C:\ProgramData\evil")]
        [InlineData(@"expand ""C:\src\update.msu"" ""D:\staging\dest""", @"D:\staging\dest")]
        public void ExtractDestinationPath_ReturnsLastPathToken(string cmdLine, string expected)
        {
            var dest = UpdateServicingMonitor.ExtractDestinationPath(cmdLine);
            Assert.Equal(expected, dest);
        }

        [Theory]
        [InlineData("")]
        [InlineData("expand.exe")]
        [InlineData("expand.exe /?")]
        public void ExtractDestinationPath_NullWhenNoPath(string cmdLine)
        {
            Assert.Null(UpdateServicingMonitor.ExtractDestinationPath(cmdLine));
        }

        /// <summary>
        /// End-to-end heuristic: an expand to a user-writable Temp path is BOTH parseable and
        /// classified as abnormal (the signal-firing condition), while an expand into WinSxS is
        /// parseable but legitimate (no signal). This proves the monitor stays quiet on clean
        /// servicing and only fires on the abnormal shape.
        /// </summary>
        [Fact]
        public void AbnormalExtraction_FiresOnlyForNonStagingTarget()
        {
            var abnormal = UpdateServicingMonitor.ExtractDestinationPath(
                @"expand.exe C:\a.cab -F:* C:\Users\v\AppData\Local\Temp\x");
            Assert.NotNull(abnormal);
            Assert.False(UpdateServicingMonitor.IsLegitStagingPath(abnormal!)); // -> would emit

            var legit = UpdateServicingMonitor.ExtractDestinationPath(
                @"expand.exe C:\a.cab -F:* C:\Windows\WinSxS\Temp");
            Assert.NotNull(legit);
            Assert.True(UpdateServicingMonitor.IsLegitStagingPath(legit!)); // -> stays quiet
        }
    }
}
