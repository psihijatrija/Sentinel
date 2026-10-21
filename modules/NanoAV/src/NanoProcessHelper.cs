using System;
using System.Diagnostics;

namespace NanoAV
{
    // Thin wrapper for invoking console utilities (taskkill, icacls, takeown,
    // netsh, schtasks) silently, replacing the PS call-operator usage.
    internal static class ProcessHelper
    {
        public static int Run(string fileName, string arguments)
        {
            var psi = new ProcessStartInfo(fileName, arguments)
            {
                CreateNoWindow = true,
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                WindowStyle = ProcessWindowStyle.Hidden
            };
            using (var p = Process.Start(psi))
            {
                if (p == null) return -1;
                p.StandardOutput.ReadToEnd();
                p.StandardError.ReadToEnd();
                p.WaitForExit();
                return p.ExitCode;
            }
        }
    }
}
