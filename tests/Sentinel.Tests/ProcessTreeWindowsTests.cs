using System;
using System.Diagnostics;
using System.IO;
using System.Text;
using System.Threading.Tasks;
using Xunit;

namespace Sentinel.Tests
{
    public sealed class WindowsContainmentFactAttribute : FactAttribute
    {
        public WindowsContainmentFactAttribute()
        {
            if (Environment.OSVersion.Platform != PlatformID.Win32NT)
                Skip = "Requires Windows process handles and process enumeration.";
        }
    }

    public class ProcessTreeWindowsTests
    {
        [WindowsContainmentFact]
        public async Task KillTree_VerifiesParentChildAndGrandchildExit_LeavesUnrelatedProcessRunning()
        {
            string directory = Path.Combine(Path.GetTempPath(), "SentinelTree_" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(directory);
            string childFile = Path.Combine(directory, "child.pid");
            string grandchildFile = Path.Combine(directory, "grandchild.pid");
            string powershell = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System),
                "WindowsPowerShell", "v1.0", "powershell.exe");
            string grandchildCode = "[IO.File]::WriteAllText(" + Quote(grandchildFile) +
                ", [string]$PID); Start-Sleep -Seconds 120";
            string childCode = Spawn(powershell, grandchildCode) +
                "; [IO.File]::WriteAllText(" + Quote(childFile) + ", [string]$PID); Start-Sleep -Seconds 120";
            string rootCode = Spawn(powershell, childCode) + "; Start-Sleep -Seconds 120";

            Process? root = null, child = null, grandchild = null, unrelated = null;
            try
            {
                root = Start(powershell, rootCode);
                unrelated = Start(powershell, "Start-Sleep -Seconds 120");
                int childPid = await ReadPidAsync(childFile);
                int grandchildPid = await ReadPidAsync(grandchildFile);
                child = Process.GetProcessById(childPid);
                grandchild = Process.GetProcessById(grandchildPid);
                // Pin the original instances before containment, including for test cleanup.
                _ = child.Handle;
                _ = grandchild.Handle;
                _ = unrelated.Handle;

                var result = root.KillTree();

                Assert.True(result.Success, result.Error);
                Assert.Contains(root.Id, result.ExitedProcessIds);
                Assert.Contains(childPid, result.ExitedProcessIds);
                Assert.Contains(grandchildPid, result.ExitedProcessIds);
                Assert.True(root.WaitForExit(5000));
                Assert.True(child.WaitForExit(5000));
                Assert.True(grandchild.WaitForExit(5000));
                Assert.False(unrelated.HasExited);
            }
            finally
            {
                foreach (var process in new[] { grandchild, child, root, unrelated })
                {
                    if (process == null) continue;
                    try
                    {
                        if (!process.HasExited) { process.Kill(); process.WaitForExit(5000); }
                    }
                    catch (InvalidOperationException) { /* fixture already exited */ }
                    finally { process.Dispose(); }
                }
                Directory.Delete(directory, true);
            }
        }

        private static string Encode(string code) => Convert.ToBase64String(Encoding.Unicode.GetBytes(code));
        private static string Quote(string text) => "'" + text.Replace("'", "''") + "'";
        private static string Spawn(string powershell, string code)
            => "Start-Process -FilePath " + Quote(powershell) +
               " -ArgumentList @('-NoProfile','-NonInteractive','-EncodedCommand'," + Quote(Encode(code)) + ")";
        private static Process Start(string executable, string code)
            => Process.Start(new ProcessStartInfo(executable,
                "-NoProfile -NonInteractive -EncodedCommand " + Encode(code)) { UseShellExecute = false })
               ?? throw new InvalidOperationException("Unable to start process-tree fixture.");
        private static async Task<int> ReadPidAsync(string path)
        {
            var timer = Stopwatch.StartNew();
            while (timer.Elapsed < TimeSpan.FromSeconds(30))
            {
                if (File.Exists(path) && int.TryParse(File.ReadAllText(path), out int pid)) return pid;
                await Task.Delay(50);
            }
            throw new TimeoutException("Process-tree fixture did not publish its PID.");
        }
    }
}
