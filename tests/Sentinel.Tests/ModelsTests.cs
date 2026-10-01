using System;
using Xunit;
using Sentinel.Core;

namespace Sentinel.Tests
{
    public class ModelsTests
    {
        //  DetectionEvent structured verdicts 

        [Fact]
        public void DetectionEvent_LogOnly_IsNotKillAuthorized()
        {
            var evt = new DetectionEvent { AuthorizedResponse = ResponseAction.LogOnly };
            Assert.False(evt.KillAuthorized);
        }

        [Fact]
        public void DetectionEvent_KillProcess_IsKillAuthorized()
        {
            var evt = new DetectionEvent { AuthorizedResponse = ResponseAction.KillProcess };
            Assert.True(evt.KillAuthorized);
        }

        [Fact]
        public void DetectionEvent_KillProcessTree_IsKillAuthorized()
        {
            var evt = new DetectionEvent { AuthorizedResponse = ResponseAction.KillProcessTree };
            Assert.True(evt.KillAuthorized);
        }

        [Fact]
        public void DetectionEvent_Quarantine_IsKillAuthorized()
        {
            var evt = new DetectionEvent { AuthorizedResponse = ResponseAction.Quarantine };
            Assert.True(evt.KillAuthorized);
        }

        [Fact]
        public void DetectionEvent_UnloadDllAndKillOwner_IsKillAuthorized()
        {
            var evt = new DetectionEvent { AuthorizedResponse = ResponseAction.QuarantineAndKill };
            Assert.True(evt.KillAuthorized);
        }

        [Fact]
        public void DetectionEvent_RemoveCertAndKillAdder_IsKillAuthorized()
        {
            var evt = new DetectionEvent { AuthorizedResponse = ResponseAction.RemoveCertAndKillAdder };
            Assert.True(evt.KillAuthorized);
        }

        [Fact]
        public void DetectionEvent_DefaultIsLogOnly()
        {
            var evt = new DetectionEvent();
            Assert.Equal(ResponseAction.LogOnly, evt.AuthorizedResponse);
            Assert.False(evt.KillAuthorized);
        }

        [Fact]
        public void DetectionEvent_TimestampIsUtcNow()
        {
            var before = DateTime.UtcNow.AddSeconds(-1);
            var evt = new DetectionEvent();
            var after = DateTime.UtcNow.AddSeconds(1);
            Assert.True(evt.Timestamp >= before && evt.Timestamp <= after);
        }

        [Fact]
        public void DetectionEvent_MetadataIsEmptyByDefault()
        {
            var evt = new DetectionEvent();
            Assert.NotNull(evt.Metadata);
            Assert.Empty(evt.Metadata);
        }

        //  ResponseAction enum values 

        [Fact]
        public void ResponseAction_LogOnly_IsSmallestValue()
        {
            Assert.True(ResponseAction.LogOnly < ResponseAction.KillProcess);
        }

        [Fact]
        public void ResponseAction_Ordering_IsCorrect()
        {
            Assert.True(ResponseAction.LogOnly < ResponseAction.KillProcess);
            Assert.True(ResponseAction.KillProcess < ResponseAction.KillProcessTree);
            Assert.True(ResponseAction.KillProcessTree < ResponseAction.Quarantine);
            Assert.True(ResponseAction.Quarantine < ResponseAction.QuarantineAndKill);
            Assert.True(ResponseAction.QuarantineAndKill < ResponseAction.RemoveCertAndKillAdder);
        }

        //  ThreatScore 

        [Fact]
        public void ThreatScore_RequiresAction_OnMalicious()
        {
            var score = new ThreatScore { Verdict = Verdict.Malicious };
            Assert.True(score.RequiresAction);
        }

        [Fact]
        public void ThreatScore_RequiresAction_OnCritical()
        {
            var score = new ThreatScore { Verdict = Verdict.Critical };
            Assert.True(score.RequiresAction);
        }

        [Fact]
        public void ThreatScore_DoesNotRequireAction_OnSuspicious()
        {
            var score = new ThreatScore { Verdict = Verdict.Suspicious };
            Assert.False(score.RequiresAction);
        }

        [Fact]
        public void ThreatScore_DoesNotRequireAction_OnClean()
        {
            var score = new ThreatScore { Verdict = Verdict.Clean };
            Assert.False(score.RequiresAction);
        }

        [Fact]
        public void ThreatScore_ToString_IncludesVerdict()
        {
            var score = new ThreatScore { Verdict = Verdict.Critical, Score = 150, Category = DetectionCategory.Ransomware };
            var str = score.ToString();
            Assert.Contains("Critical", str);
            Assert.Contains("150", str);
        }

        //  ProcessTelemetry 

        [Fact]
        public void ProcessTelemetry_DefaultsAreEmpty()
        {
            var pt = new ProcessTelemetry();
            Assert.Equal(string.Empty, pt.ImagePath);
            Assert.Equal(string.Empty, pt.CommandLine);
            Assert.Equal(string.Empty, pt.ParentProcessName);
            Assert.Equal(0, pt.ParentProcessId);
        }

        //  SentinelConfig 

        [Fact]
        public void SentinelConfig_ActiveResponse_DefaultTrue()
        {
            var config = new SentinelConfig();
            Assert.True(config.ActiveResponse);
        }

        //  ConnectionHistory (BeaconingDetector support type) 

        [Fact]
        public void ConnectionHistory_RecordsTimestamps()
        {
            var ch = new ConnectionHistory(100, "test.exe", "10.0.0.1", 4444);
            ch.Record(DateTimeOffset.UtcNow);
            ch.Record(DateTimeOffset.UtcNow.AddSeconds(10));
            ch.Record(DateTimeOffset.UtcNow.AddSeconds(20));
            var intervals = ch.GetIntervals();
            Assert.Equal(2, intervals.Count);
        }

        [Fact]
        public void ConnectionHistory_GetIntervals_Empty_WhenLessThan2()
        {
            var ch = new ConnectionHistory(100, "test.exe", "10.0.0.1", 4444);
            ch.Record(DateTimeOffset.UtcNow);
            Assert.Empty(ch.GetIntervals());
        }

        [Fact]
        public void ConnectionHistory_Properties_SetCorrectly()
        {
            var ch = new ConnectionHistory(42, "beacon.exe", "192.168.1.1", 8080);
            Assert.Equal(42, ch.ProcessId);
            Assert.Equal("beacon.exe", ch.ProcessName);
            Assert.Equal("192.168.1.1", ch.RemoteAddress);
            Assert.Equal(8080, ch.RemotePort);
            Assert.False(ch.HasFired);
        }
    }
}
