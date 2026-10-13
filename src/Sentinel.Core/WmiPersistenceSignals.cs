using System;
using System.Diagnostics;
using System.Threading;

namespace Sentinel.Core
{
    /// <summary>
    /// v2.2.8 - shared WMI persistence / policy-rewrite classifiers.
    /// Permanent WMI persistence is the filter + consumer + binding triple (T1546.003),
    /// not a consumer name count. Hostile consumers execute from WmiPrvSE / wmiadap / scrcons.
    /// </summary>
    public static class WmiPersistenceSignals
    {
        public static readonly string[] SubscriptionNamespaces =
        {
            @"root\subscription",
            @"root\default",
        };

        /// <summary>
        /// Command / script fragments that turn a WMI consumer into an executable persistence leg.
        /// NTEventLogEventConsumer without these is ordinary logging, not a nuke seed.
        /// </summary>
        public static readonly string[] HostileConsumerFragments =
        {
            "powershell", "pwsh", "cmd.exe", "cmd /c", "cmd /k",
            "wscript", "cscript", "mshta", "rundll32", "regsvr32",
            "bitsadmin", "certutil", "msiexec",
            "-enc", "-encodedcommand", "frombase64string",
            "downloadstring", "downloadfile", "invoke-webrequest",
            "invoke-expression", "iex(", "iex ",
            @"\temp\", @"\appdata\", @"\users\", @"\programdata\",
            "http://", "https://", "\\\\",
            "activeXObject", "eval(",
        };

        public static readonly string[] WmiHostProcessNames =
        {
            "wmiprvse", "wmiadap", "scrcons", "wmiapsrv",
        };

        private static long _lastHostileUtcTicks;

        public static void MarkHostileObserved()
            => Interlocked.Exchange(ref _lastHostileUtcTicks, DateTime.UtcNow.Ticks);

        public static bool HostileObservedRecently(TimeSpan window)
        {
            var ticks = Interlocked.Read(ref _lastHostileUtcTicks);
            if (ticks <= 0) return false;
            return DateTime.UtcNow - new DateTime(ticks, DateTimeKind.Utc) <= window;
        }

        public static bool LooksHostile(string? text)
        {
            if (string.IsNullOrWhiteSpace(text)) return false;
            var haystack = text!;
            foreach (var f in HostileConsumerFragments)
            {
                if (haystack.IndexOf(f, StringComparison.OrdinalIgnoreCase) >= 0)
                    return true;
            }
            return false;
        }

        public static bool IsWmiHostProcess(string? processName)
        {
            if (string.IsNullOrWhiteSpace(processName)) return false;
            var stem = processName!.Trim();
            if (stem.EndsWith(".exe", StringComparison.OrdinalIgnoreCase))
                stem = stem.Substring(0, stem.Length - 4);
            foreach (var h in WmiHostProcessNames)
            {
                if (stem.Equals(h, StringComparison.OrdinalIgnoreCase))
                    return true;
            }
            return false;
        }

        public static bool IsSentinelSelfProcess(string? processName)
        {
            if (string.IsNullOrWhiteSpace(processName)) return false;
            return processName!.IndexOf("Sentinel", StringComparison.OrdinalIgnoreCase) >= 0;
        }

        /// <summary>
        /// Stable snapshot identity: kind|namespace|name|detail (truncated).
        /// Names alone are spoofable; query/command/script is the implant.
        /// </summary>
        public static string SnapshotKey(string kind, string ns, string name, string? detail)
        {
            var d = detail ?? "";
            if (d.Length > 240)
                d = d.Substring(0, 240);
            d = d.Replace('\r', ' ').Replace('\n', ' ');
            return string.Concat(kind, "|", ns ?? "", "|", name ?? "", "|", d);
        }

        public static int TryGetLiveWmiHostPid()
        {
            foreach (var host in WmiHostProcessNames)
            {
                try
                {
                    var procs = Process.GetProcessesByName(host);
                    foreach (var p in procs)
                    {
                        try
                        {
                            if (p.Id > 4)
                                return p.Id;
                        }
                        finally { p.Dispose(); }
                    }
                }
                catch { }
            }
            return 0;
        }
    }

    /// <summary>
    /// Last Kernel-Registry write from a WMI host. Policy-tree watchers correlate this
    /// with HKLM/HKU Policies changes (StdRegProv has no path in userland ETW).
    /// </summary>
    internal static class WmiHostRegistryHint
    {
        private static readonly object Gate = new();
        private static long _ticks;
        private static int _pid;
        private static string _name = "";

        public static void Record(int pid, string? processName)
        {
            if (pid <= 4 || !WmiPersistenceSignals.IsWmiHostProcess(processName))
                return;
            lock (Gate)
            {
                _pid = pid;
                _name = processName ?? "";
                _ticks = DateTime.UtcNow.Ticks;
            }
        }

        public static bool TryGetRecent(TimeSpan window, out int pid, out string name)
        {
            lock (Gate)
            {
                pid = _pid;
                name = _name ?? "";
                if (_ticks <= 0) return false;
                if (DateTime.UtcNow - new DateTime(_ticks, DateTimeKind.Utc) > window)
                    return false;
                return pid > 4;
            }
        }

        internal static void Reset()
        {
            lock (Gate)
            {
                _ticks = 0;
                _pid = 0;
                _name = "";
            }
        }
    }
}
