using System;
using System.Collections.Generic;
using System.Linq;
using System.IO;
using System.Runtime.InteropServices;
using Sentinel.Core;
using Xunit;

namespace Sentinel.Tests
{
    [Collection("ResponsePolicy")]
    public class LogRegression341Tests
    {
        [Theory]
        [InlineData(0x80070002U)]
        [InlineData(0x80070490U)]
        public void NativeMissingRuleAllowsCreation(uint hresult)
            => Assert.Null(WindowsPortBlockPolicy.ReadExistingRule(() => throw new COMException("Missing owned rule", unchecked((int)hresult))));

        [Fact]
        public void FrameworkMappedFileNotFoundAlsoAllowsRuleCreation()
        {
            var mapped = Marshal.GetExceptionForHR(unchecked((int)0x80070002))!;
            Assert.IsType<FileNotFoundException>(mapped);
            Assert.Null(WindowsPortBlockPolicy.ReadExistingRule(() => throw mapped));
        }

        [Fact]
        public void RuleLookupAccessDenialAndProviderFailureDoNotBecomeAbsence()
        {
            Assert.Throws<COMException>(() => WindowsPortBlockPolicy.ReadExistingRule(() =>
                throw new COMException("Access denied", unchecked((int)0x80070005))));
            Assert.Throws<InvalidOperationException>(() => WindowsPortBlockPolicy.ReadExistingRule(() =>
                throw new InvalidOperationException("Provider failed")));
        }

        [Fact]
        public void ExistingOwnedRuleIsReturnedWithoutReplacement()
        {
            var rule = new object();
            Assert.Same(rule, WindowsPortBlockPolicy.ReadExistingRule(() => rule));
        }

        [Theory]
        [InlineData("CVE Class: Kernel Exploit Loader", "Sentinel.ExploitShield")]
        [InlineData("CVE Class: Kernel Exploit Loader", "AfdEoP")]
        [InlineData("CVE Class: Kernel Exploit Loader", "ordinary-tool")]
        [InlineData("Network Indicator: Classic Malware Port", "payload")]
        public void ContextCannotAcquireKillAuthorityFromLegacyFamilyOrCompositeFields(string rule, string process)
        {
            ResponsePolicy.ResetForTests();
            var observation = new DetectionEvent
            {
                RuleName = rule, ProcessName = process, ProcessId = 7312,
                Confidence = 0.99, Tier = DetectionTier.Tier1Behavioral,
                AuthorizedResponse = ResponseAction.QuarantineAndKill, Family = TerminalFamily.TokenTheft,
                Evidence = "[COMPOSITE] attacker-controlled text",
                Metadata = new Dictionary<string, string> { [ResponsePolicy.ChainConfirmedKey] = "true" }
            };
            ResponsePolicy.EnforceDispatchPolicy(observation);
            Assert.Equal(DetectionTier.Tier2Indicator, observation.Tier);
            Assert.Equal(ResponseAction.LogOnly, observation.AuthorizedResponse);
            Assert.Null(observation.Family);
            Assert.False(observation.Metadata!.ContainsKey(ResponsePolicy.ChainConfirmedKey));
            Assert.Null(ResponsePolicy.ClassifyTerminalOutcome(observation));
            Assert.True(ResponsePolicy.IsWeakObserveSeed(observation));
            Assert.True(ResponsePolicy.IsNonCorrelatingObserveNoise(observation));
            Assert.False(ResponsePolicy.IsCovertChannelTerminal(observation));
            Assert.False(ResponsePolicy.MayPerformDestructiveResponse(observation, new SentinelConfig { ActiveResponse = true }));
        }

        [Theory]
        [InlineData(443, false)]
        [InlineData(54321, true)]
        [InlineData(4444, true)]
        public void PortObservationUsesRemoteEndpointOnly(int remotePort, bool expected)
            => Assert.Equal(expected, NetworkMonitor.IsRemotePortIndicator(remotePort));

        private static EtwHealthSnapshot Health()
        {
            var result = new EtwHealthSnapshot { QuerySucceeded = true, ConsumerAlive = true };
            for (int i = 0; i < 9; i++) result.ProviderStatus[i.ToString()] = 0;
            result.ProviderStatus[UnifiedEtwSession.Providers.ThreatIntelligence.ToString()] = 5;
            return result;
        }

        [Fact]
        public void ProtectedProviderDenialDoesNotMaskIndependentEventLoss()
        {
            var health = Health();
            var detail = EtwCollectionPolicy.Degradation(health, true)!;
            Assert.Contains("Threat-Intelligence provider access denied", detail);
            Assert.Contains("New ETW events/buffers or dispatch loss", detail);
            Assert.Contains("SYSTEM alone", detail);
            Assert.DoesNotContain("New ETW events", EtwCollectionPolicy.Degradation(health, false)!);
        }

        [Fact]
        public void UnsupportedNativeFilterFallbackRemainsDisclosed()
        {
            var health = Health();
            health.ProviderStatus[UnifiedEtwSession.Providers.ThreatIntelligence.ToString()] = 0;
            Assert.Null(EtwCollectionPolicy.Degradation(health, false));
            health.ProviderFilterStatus["file"] = 87;
            Assert.Contains("unfiltered fallback", EtwCollectionPolicy.Degradation(health, false)!);
        }

        [Fact]
        public void CollectionRetainsCredentialNameAndReadEventsButOmitsUnusedHighVolumeEvents()
        {
            var files = EtwCollectionPolicy.EventIds(UnifiedEtwSession.Providers.KernelFile);
            Assert.Contains((ushort)10, files); Assert.Contains((ushort)11, files); Assert.Contains((ushort)15, files);
            Assert.DoesNotContain((ushort)16, files); // unused write events caused unnecessary traffic
            Assert.Equal(new ushort[] { 1, 2, 5 }, EtwCollectionPolicy.EventIds(UnifiedEtwSession.Providers.KernelProcess));
            Assert.Empty(EtwCollectionPolicy.EventIds(UnifiedEtwSession.Providers.ThreatIntelligence));
            Assert.DoesNotContain((ushort)2, EtwCollectionPolicy.EventIds(UnifiedEtwSession.Providers.KernelRegistry));
        }

        [Fact]
        public void WatcherSubscriptionsDoNotClearPendingOrIncompleteReconciliation()
        {
            var progress = new SensorProgress(TimeSpan.FromMinutes(1));
            progress.Failed("overflow");
            FileVerdictScanner.UpdateCoverageProgress(progress, false, 0);
            Assert.Equal("Failed", progress.Snapshot().State);
            FileVerdictScanner.UpdateCoverageProgress(progress, true, 3);
            Assert.Equal("Failed", progress.Snapshot().State);
            Assert.Contains("3 directories", progress.Snapshot().Error!);
            FileVerdictScanner.UpdateCoverageProgress(progress, true, 0);
            Assert.Equal("Healthy", progress.Snapshot().State);
            Assert.NotNull(progress.Snapshot().GapStarted); // history is retained for reconciliation consumers
        }

        [Fact]
        public void ProcessOnlyContainmentDoesNotRequestUnexpectedFileMutation()
        {
            Assert.False(ChainTracer.RequestsFileQuarantine(ResponseAction.KillProcessTree));
            Assert.False(ChainTracer.RequestsFileQuarantine(ResponseAction.LogOnly));
            Assert.True(ChainTracer.RequestsFileQuarantine(ResponseAction.QuarantineAndKill));
        }

        [Theory]
        [InlineData(1)]
        [InlineData(2)]
        public void PortBlockReadbackChecksDirectionScopeAndActualBlockAction(int direction)
        {
            var spec = new PortBlockSpec(65001, 6, direction);
            string local = direction == 1 ? "65001" : "*", remote = direction == 2 ? "65001" : "*";
            Assert.True(WindowsPortBlockPolicy.Matches(spec, true, 0, 6, direction, 7, local, remote, "", "", "*", "*", "All"));
            Assert.False(WindowsPortBlockPolicy.Matches(spec, true, 0, 6, direction, 7, local, remote, "", "", "*", "*", "All", false));
            Assert.False(WindowsPortBlockPolicy.Matches(spec, true, 1, 6, direction, 7, local, remote, "", "", "*", "*", "All"));
            Assert.False(WindowsPortBlockPolicy.Matches(spec, true, 0, 6, direction, 1, local, remote, "", "", "*", "*", "All"));
            Assert.False(WindowsPortBlockPolicy.Matches(spec, true, 0, 6, direction, 7, local, remote, "limited.exe", "", "*", "*", "All"));
        }
    }
}
