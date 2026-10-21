using System;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Win32;

[assembly: System.Runtime.CompilerServices.InternalsVisibleTo("Sentinel.Tests")]

namespace NanoAV
{
    // The only behavioral patch: exclude Sentinel's actual installed files/processes.
    // This helper does not evaluate NanoAV verdicts or invoke Sentinel response policy.
    internal static class SentinelCoexistence
    {
        internal static bool IsInside(string candidate, string directory)
        {
            if (string.IsNullOrWhiteSpace(candidate) || string.IsNullOrWhiteSpace(directory)
                || !Path.IsPathRooted(candidate) || !Path.IsPathRooted(directory)) return false;
            string root = Path.GetFullPath(directory).TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
            string full = Path.GetFullPath(candidate);
            return full.Equals(root, StringComparison.OrdinalIgnoreCase)
                || full.StartsWith(root + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase);
        }

        internal static bool IsProtectedResolvedPath(string path, string installDirectory, string dataDirectory)
        {
            return IsInside(path, installDirectory) || IsInside(path, dataDirectory);
        }

        private static string SentinelDirectory()
        {
            using (var key = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services\Sentinel"))
            {
                string command = key == null ? null : key.GetValue("ImagePath") as string;
                if (!string.IsNullOrWhiteSpace(command))
                {
                    command = Environment.ExpandEnvironmentVariables(command.Trim());
                    string exe;
                    if (command.StartsWith("\"", StringComparison.Ordinal))
                    {
                        int end = command.IndexOf('"', 1);
                        if (end < 0) return null;
                        exe = command.Substring(1, end - 1);
                    }
                    else
                    {
                        int end = command.IndexOf(".exe", StringComparison.OrdinalIgnoreCase);
                        if (end < 0) return null;
                        exe = command.Substring(0, end + 4);
                    }
                    if (Path.IsPathRooted(exe) && File.Exists(exe)
                        && Path.GetFileName(exe).Equals("Sentinel.Service.exe", StringComparison.OrdinalIgnoreCase))
                        return Path.GetDirectoryName(Resolve(exe));
                }
            }
            // Installation bootstrap may not have registered SCM yet. A co-installed
            // Sentinel.Service.exe is a fallback; a matching process name is never used.
            string local = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "Sentinel.Service.exe");
            return File.Exists(local) ? Path.GetDirectoryName(Resolve(local)) : null;
        }

        internal static bool IsProtectedFile(string path)
        {
            if (string.IsNullOrWhiteSpace(path) || !Path.IsPathRooted(path)) return false;
            try
            {
                string root = SentinelDirectory();
                if (root == null) return true; // Cannot establish Sentinel identity: no destructive file action.
                string full = Resolve(path);
                string data = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "Sentinel");
                return IsProtectedResolvedPath(full, root, Resolve(data));
            }
            catch (Exception ex)
            { Logger.Log("Sentinel coexistence could not resolve file identity: " + ex.Message); return true; }
        }

        internal static bool IsProtectedProcess(Process process)
        {
            try
            {
                if (process.HasExited) return true;
                var text = new StringBuilder(32768);
                int count = text.Capacity;
                // The Process handle pins the object subsequently used by Kill().
                if (!QueryFullProcessImageName(process.Handle, 0, text, ref count)) return true;
                return IsProtectedFile(text.ToString());
            }
            catch (Exception ex)
            { Logger.Log("Sentinel coexistence could not resolve process identity: " + ex.Message); return true; }
        }

        internal static void KillUnlessSentinel(Process process)
        {
            if (IsProtectedProcess(process))
            { Logger.Log("NanoAV action skipped: protected/unresolved Sentinel identity, PID " + process.Id); return; }
            process.Kill();
        }

        private static string Resolve(string path)
        {
            string full = Path.GetFullPath(path);
            if (!File.Exists(full) && !Directory.Exists(full)) return full;
            IntPtr handle = CreateFile(full, 0x80, 7, IntPtr.Zero, 3, 0x02000000, IntPtr.Zero);
            if (handle == new IntPtr(-1)) throw new IOException("Final-path handle unavailable.");
            try
            {
                var buffer = new StringBuilder(32768);
                uint length = GetFinalPathNameByHandle(handle, buffer, (uint)buffer.Capacity, 0);
                if (length == 0 || length >= buffer.Capacity) throw new IOException("Final path unavailable.");
                string result = buffer.ToString();
                if (result.StartsWith(@"\\?\UNC\", StringComparison.OrdinalIgnoreCase)) return @"\\" + result.Substring(8);
                return result.StartsWith(@"\\?\", StringComparison.Ordinal) ? result.Substring(4) : result;
            }
            finally { CloseHandle(handle); }
        }

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern bool QueryFullProcessImageName(IntPtr process, int flags, StringBuilder path, ref int size);
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern IntPtr CreateFile(string path, uint access, uint share, IntPtr security, uint disposition, uint flags, IntPtr template);
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern uint GetFinalPathNameByHandle(IntPtr handle, StringBuilder path, uint size, uint flags);
        [DllImport("kernel32.dll")]
        private static extern bool CloseHandle(IntPtr handle);
    }
}
