using System;
using System.Collections.Generic;
using System.Threading;
using Sentinel.Core;
using Xunit;

namespace Sentinel.Tests
{
    public sealed class SecurityAuditTests
    {
        private static AuditPolicy Policy => new("Example", "key", "value", 1);

        [Theory]
        [InlineData(1, "Configured")]
        [InlineData(0, "NeedsReview")]
        [InlineData(2, "NeedsReview")]
        [InlineData("1", "Unknown")]
        [InlineData(1L, "Unknown")]
        [InlineData(null, "Unknown")]
        public void ConfigurationReadback_DoesNotCoerceOrImplyActiveProtection(object? value, string expected)
        {
            var check = SecurityAuditService.Evaluate(Policy, new AuditRegistryReading { Available = true, Value = value });
            Assert.Equal(expected, check.State);
            if (expected == "Configured") Assert.Contains("Runtime enforcement is not verified", check.Detail);
        }

        [Fact]
        public void UnavailableRead_CannotLookConfiguredEvenWithAValue()
            => Assert.Equal("Unknown", SecurityAuditService.Evaluate(Policy,
                new AuditRegistryReading { Available = false, Value = 1 }).State);

        [Fact]
        public void PplWithoutUefiLock_IsStillAConfiguredValue()
            => Assert.Equal("Configured", SecurityAuditService.Evaluate(new AuditPolicy("PPL", "key", "value", 1, true),
                new AuditRegistryReading { Available = true, Value = 2 }).State);

        [Fact]
        public void MissingSources_RemainUnknownInConsolidatedReport()
        {
            var report = new SecurityAuditService(new MissingSource()).Collect(DateTime.UtcNow, CancellationToken.None);
            Assert.Equal(10, report.Hardening.Count);
            Assert.All(report.Hardening, c => Assert.Equal("Unknown", c.State));
            Assert.Equal(4, report.History.Count);
            Assert.All(report.History, s => Assert.Equal("Unknown", s.State));
            Assert.Equal(TimeSpan.FromHours(6), report.WindowEndUtc - report.WindowStartUtc);
            Assert.Contains("not a clean-system verdict", report.Scope);
        }

        [Fact]
        public void Cancellation_PropagatesInsteadOfReturningACleanReport()
        {
            using var cancellation = new CancellationTokenSource();
            cancellation.Cancel();
            Assert.Throws<OperationCanceledException>(() => new SecurityAuditService(new MissingSource())
                .Collect(DateTime.UtcNow, cancellation.Token));
        }

        [Fact]
        public void Collection_RejectsUnspecifiedOrLocalWindowTimes()
            => Assert.Throws<ArgumentException>(() => new SecurityAuditService(new MissingSource())
                .Collect(DateTime.SpecifyKind(DateTime.Now, DateTimeKind.Unspecified), CancellationToken.None));

        private const string Prefix = "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><EventID>";
        private const string Between = "</EventID><TimeCreated SystemTime='2026-10-18T12:00:00Z'/></System><EventData>";
        private const string Suffix = "</EventData></Event>";

        [Theory]
        [InlineData(4624, "Successful logon")]
        [InlineData(4625, "Failed logon")]
        public void LogonXml_UsesNamedFieldsRegardlessOfOrder(int id, string kind)
        {
            var item = WindowsSecurityAuditSource.ParseEvent(Prefix + id + Between +
                "<Data Name='IpAddress'>192.0.2.1</Data><Data Name='LogonType'>10</Data>" +
                "<Data Name='TargetUserName'>alice</Data><Data Name='TargetDomainName'>PC</Data>" + Suffix);
            Assert.NotNull(item);
            Assert.Equal(kind, item!.Kind);
            Assert.Equal("PC\\alice", item.Account);
            Assert.Equal("192.0.2.1", item.Subject);
            Assert.Contains("Logon type: 10", item.Detail);
            Assert.Equal(DateTimeKind.Utc, item.TimestampUtc!.Value.Kind);
        }

        [Theory]
        [InlineData(7045, "ServiceName", "Service installed")]
        [InlineData(106, "TaskName", "Scheduled task registered")]
        public void PersistenceEvents_OmitRawCommandsAndDoNotDeclareMalice(int id, string field, string kind)
        {
            var item = WindowsSecurityAuditSource.ParseEvent(Prefix + id + Between +
                "<Data Name='" + field + "'>Example</Data><Data Name='ImagePath'>secret-command</Data>" + Suffix);
            Assert.Equal(kind, item!.Kind);
            Assert.Equal("Example", item.Subject);
            Assert.DoesNotContain("secret-command", item.Detail);
            Assert.Contains("not proof", item.Detail);
        }

        [Fact]
        public void UnknownEventAndMalformedTime_AreNotInvented()
        {
            Assert.Null(WindowsSecurityAuditSource.ParseEvent(Prefix + 123 + Between + Suffix));
            var xml = (Prefix + 7045 + Between + Suffix).Replace("2026-10-18T12:00:00Z", "not-a-date");
            Assert.Null(WindowsSecurityAuditSource.ParseEvent(xml)!.TimestampUtc);
        }

        [Fact]
        public void ExternalEntities_AreRejected()
            => Assert.Throws<System.Xml.XmlException>(() => WindowsSecurityAuditSource.ParseEvent(
                "<!DOCTYPE Event [<!ENTITY x SYSTEM 'file:///does-not-exist'>]><Event>&x;</Event>"));

        [Fact]
        public void MalformedDeviceTimestamp_IsUnknown()
        {
            Assert.Null(WindowsSecurityAuditSource.FromFileTime(0L));
            Assert.Null(WindowsSecurityAuditSource.FromFileTime(-1L));
            Assert.Null(WindowsSecurityAuditSource.FromFileTime(long.MaxValue));
            Assert.Null(WindowsSecurityAuditSource.FromFileTime("12345"));
            var now = DateTime.UtcNow;
            Assert.Equal(now, WindowsSecurityAuditSource.FromFileTime(now.ToFileTimeUtc()));
        }

        [Theory]
        [InlineData(true, "ObservedActive")]
        [InlineData(false, "NeedsReview")]
        [InlineData("true", "Unknown")]
        [InlineData(null, "Unknown")]
        public void RuntimeBooleans_AreStrictSnapshots(object? value, string state)
            => Assert.Equal(state, WindowsSecurityAuditSource.EvaluateRuntime("Defender antivirus", value).State);

        [Fact]
        public void VbsRuntime_DoesNotClaimCredentialGuard()
        {
            var active = WindowsSecurityAuditSource.EvaluateRuntime("Virtualization-based security", 2U);
            Assert.Equal("ObservedActive", active.State);
            Assert.Contains("does not by itself prove Credential Guard", active.Detail);
            Assert.Equal("NeedsReview", WindowsSecurityAuditSource.EvaluateRuntime("Virtualization-based security", 1U).State);
            Assert.Equal("Unknown", WindowsSecurityAuditSource.EvaluateRuntime("Virtualization-based security", 3U).State);
            Assert.Equal("Unknown", WindowsSecurityAuditSource.EvaluateRuntime("Virtualization-based security", true).State);
        }

        private sealed class MissingSource : ISecurityAuditSource
        {
            public AuditRegistryReading ReadPolicy(AuditPolicy policy, CancellationToken ct) => new();
            public AuditSection ReadHistory(string logName, int[] ids, DateTime start, DateTime end, CancellationToken ct) => throw new UnauthorizedAccessException();
            public AuditSection ReadDeviceUsage(DateTime start, DateTime end, CancellationToken ct) => throw new InvalidOperationException();
            public IEnumerable<HardeningAuditCheck> ReadRuntimeChecks(CancellationToken ct) => throw new InvalidOperationException();
        }
    }
}
