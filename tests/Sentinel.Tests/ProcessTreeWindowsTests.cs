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
            string grandchildCode = PublishPid(grandchildFile) + "; Start-Sleep -Seconds 120";
            string childCode = Spawn(powershell, grandchildCode) +
                "; " + PublishPid(childFile) + "; Start-Sleep -Seconds 120";
            string rootCode = Spawn(powershell, childCode) + "; Start-Sleep -Seconds 120";

            Process? root = null, child = null, grandchild = null, unrelated = null;
            try
            {
                root = Start(powershell, rootCode);
                unrelated = Start(powershell, "Start-Sleep -Seconds 120");
                int rootPid = root.Id;
                int childPid = await ReadPidAsync(childFile);
                int grandchildPid = await ReadPidAsync(grandchildFile);
                child = Process.GetProcessById(childPid);
                grandchild = Process.GetProcessById(grandchildPid);
                // Pin the original instances before containment, including for test cleanup.
                _ = root.Handle;
                _ = child.Handle;
                _ = grandchild.Handle;
                _ = unrelated.Handle;

                var result = root.KillTree();

                Assert.True(result.Success,
                    $"{result.Error}; rootExited={result.RootExited}; discoveryComplete={result.DiscoveryComplete}; " +
                    $"exited={string.Join(",", result.ExitedProcessIds)}; " +
                    $"failed={string.Join(",", result.FailedProcessIds)}; " +
                    $"refused={string.Join(",", result.RefusedProcessIds)}");
                Assert.Contains(rootPid, result.ExitedProcessIds);
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
        private static string PublishPid(string path) =>
            "[IO.File]::WriteAllText(" + Quote(path + ".tmp") + ", [string]$PID); " +
            "[IO.File]::Move(" + Quote(path + ".tmp") + ", " + Quote(path) + ")";
        private static string Quote(string text) => "'" + text.Replace("'", "''") + "'";
        private static string Spawn(string powershell, string code)
            => "$psi = New-Object System.Diagnostics.ProcessStartInfo; " +
               "$psi.FileName = " + Quote(powershell) + "; " +
               "$psi.Arguments = " + Quote("-NoProfile -NonInteractive -EncodedCommand " + Encode(code)) + "; " +
               "$psi.UseShellExecute = $false; $psi.CreateNoWindow = $true; " +
               "[void][System.Diagnostics.Process]::Start($psi)";
        private static Process Start(string executable, string code)
            => Process.Start(new ProcessStartInfo(executable,
                "-NoProfile -NonInteractive -EncodedCommand " + Encode(code)) { UseShellExecute = false, CreateNoWindow = true })
               ?? throw new InvalidOperationException("Unable to start process-tree fixture.");
        private static async Task<int> ReadPidAsync(string path)
        {
            var timer = Stopwatch.StartNew();
            while (timer.Elapsed < TimeSpan.FromSeconds(30))
            {
                try
                {
                    using var stream = new FileStream(path, FileMode.Open, FileAccess.Read,
                        FileShare.ReadWrite | FileShare.Delete);
                    using var reader = new StreamReader(stream);
                    if (int.TryParse(reader.ReadToEnd(), out int pid) && pid > 0) return pid;
                }
                catch (FileNotFoundException) { /* atomic publication has not completed */ }
                catch (IOException ex) when ((ex.HResult & 0xffff) is 32 or 33)
                { /* transient sharing/lock conflict; retain the existing bounded deadline */ }
                await Task.Delay(50);
            }
            throw new TimeoutException("Process-tree fixture did not publish its PID.");
        }

        [WindowsContainmentFact]
        public async Task ReadPid_RetriesTransientExclusiveWriter()
        {
            string path = Path.Combine(Path.GetTempPath(), "SentinelPid_" + Guid.NewGuid().ToString("N"));
            try
            {
                Task<int> read;
                using (var writer = new FileStream(path, FileMode.CreateNew, FileAccess.Write, FileShare.None))
                {
                    var bytes = Encoding.UTF8.GetBytes("12345");
                    writer.Write(bytes, 0, bytes.Length);
                    writer.Flush();
                    read = ReadPidAsync(path);
                    await Task.Delay(150);
                    Assert.False(read.IsCompleted);
                }
                Assert.Equal(12345, await read);
            }
            finally { File.Delete(path); }
        }
    }
}
