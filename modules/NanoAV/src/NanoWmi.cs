using System;
using System.Collections.Generic;
using System.Management;

namespace NanoAV
{
    // WMI helpers, replacing Get-CimInstance Win32_Process usage and the
    // Win32_ProcessStartTrace event watcher.
    internal static class Wmi
    {
        public sealed class ProcInfo
        {
            public int ProcessId;
            public string Name;
            public string CommandLine;
            public string ExecutablePath;
        }

        public static string GetCommandLine(int processId)
        {
            try
            {
                using (var searcher = new ManagementObjectSearcher(
                    "SELECT CommandLine FROM Win32_Process WHERE ProcessId=" + processId))
                {
                    foreach (ManagementObject mo in searcher.Get())
                    {
                        object cl = mo["CommandLine"];
                        mo.Dispose();
                        return cl == null ? null : cl.ToString();
                    }
                }
            }
            catch { }
            return null;
        }

        public static List<ProcInfo> GetProcessesWithCommandLine()
        {
            var list = new List<ProcInfo>();
            try
            {
                using (var searcher = new ManagementObjectSearcher(
                    "SELECT ProcessId, Name, CommandLine, ExecutablePath FROM Win32_Process"))
                foreach (ManagementObject mo in searcher.Get())
                {
                    object cl = mo["CommandLine"];
                    if (cl == null) { mo.Dispose(); continue; }
                    list.Add(new ProcInfo
                    {
                        ProcessId = Convert.ToInt32(mo["ProcessId"]),
                        Name = mo["Name"] == null ? "" : mo["Name"].ToString(),
                        CommandLine = cl.ToString(),
                        ExecutablePath = mo["ExecutablePath"] == null ? null : mo["ExecutablePath"].ToString()
                    });
                    mo.Dispose();
                }
            }
            catch { }
            return list;
        }

        public static string GetProcessOwnerSid(int processId)
        {
            try
            {
                using (var searcher = new ManagementObjectSearcher(
                    "SELECT * FROM Win32_Process WHERE ProcessId=" + processId))
                foreach (ManagementObject mo in searcher.Get())
                {
                    try
                    {
                        var outParams = mo.InvokeMethod("GetOwnerSid", null, null);
                        if (outParams != null && outParams["Sid"] != null)
                            return outParams["Sid"].ToString();
                    }
                    catch { }
                    finally { mo.Dispose(); }
                }
            }
            catch { }
            return "Unknown";
        }

        // Subscribe to Win32_ProcessStartTrace; invokes the callback per start.
        public static ManagementEventWatcher WatchProcessStart(Action<string, int> onStart)
        {
            var watcher = new ManagementEventWatcher(
                new WqlEventQuery("SELECT * FROM Win32_ProcessStartTrace"));
            watcher.EventArrived += (sender, e) =>
            {
                try
                {
                    var ev = e.NewEvent;
                    string name = ev["ProcessName"] == null ? "" : ev["ProcessName"].ToString();
                    int pid = Convert.ToInt32(ev["ProcessID"]);
                    onStart(name, pid);
                }
                catch { }
            };
            watcher.Start();
            return watcher;
        }
    }
}
