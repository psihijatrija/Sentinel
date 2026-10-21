using System;
using System.Diagnostics;

namespace NanoAV
{
    // Register-AutoStart: register a scheduled task (schtasks) that runs this
    // exe at startup as SYSTEM with highest privileges. Replaces the
    // ScheduledTasks cmdlets used by the PS1.
    internal static class AutoStart
    {
        public static void Register()
        {
            if (!Config.EnableAutoStart) return;

            if (!C2Engine.IsAdmin)
            {
                Logger.Log("AutoStart skipped - not running as administrator (task registration needs admin)");
                return;
            }

            string exePath = Process.GetCurrentProcess().MainModule.FileName;
            if (string.IsNullOrEmpty(exePath) || !System.IO.File.Exists(exePath))
            {
                Logger.Log("AutoStart skipped - could not resolve this exe's own path");
                return;
            }

            string taskName = Config.AutoStartTaskName;

            try
            {
                // Query existing task; if present and targets this exe, leNanoAVe it.
                var query = new ProcessStartInfo("schtasks",
                    "/Query /TN \"" + taskName + "\" /FO LIST /V")
                {
                    CreateNoWindow = true,
                    UseShellExecute = false,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true
                };
                string output = "";
                using (var p = Process.Start(query))
                {
                    output = p.StandardOutput.ReadToEnd();
                    p.StandardError.ReadToEnd();
                    p.WaitForExit();
                }

                if (output.IndexOf(exePath, StringComparison.OrdinalIgnoreCase) >= 0)
                {
                    Logger.Log("AutoStart task '" + taskName + "' already present and current");
                    return;
                }

                // (Re)create the task to run at startup as SYSTEM, highest privileges.
                ProcessHelper.Run("schtasks",
                    "/Create /F /SC ONSTART /RL HIGHEST /RU SYSTEM /TN \"" + taskName +
                    "\" /TR \"\\\"" + exePath + "\\\"\"");

                Logger.Log("AutoStart task '" + taskName + "' registered (runs at startup as SYSTEM)");
            }
            catch (Exception ex)
            {
                Logger.Log("AutoStart registration failed: " + ex.Message);
            }
        }
    }
}
