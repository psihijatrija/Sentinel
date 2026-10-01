using System;

namespace Sentinel.Core
{
    /// <summary>
    /// Shared "is a Windows OS-image servicing actor active" check.
    ///
    /// Lifted from <c>FileActivityMonitor.IsServicingProcessActive</c> so multiple detectors
    /// (path-exclusion validation, state-baseline reconciliation attribution) share one definition
    /// of "servicing is happening right now". Servicing actors (DISM/TrustedInstaller/tiworker/...)
    /// legitimately stage and load modules from otherwise-suspicious paths, so a delta observed
    /// while one is active is attributable, not hostile.
    ///
    /// Cheap point-in-time process-name scan. Optionally records the last time servicing was seen
    /// so callers can honor a short "recently active" grace window (an update that just finished
    /// can still leave freshly-staged modules mapped).
    /// </summary>
    public static class ServicingWindow
    {
        private static readonly string[] ServicingProcessNames =
        {
            "dism", "dismhost", "ntlite", "tiworker",
            "trustedinstaller", "msmgtoolkit", "imagex",
        };

        // Process-lifetime advisory timestamp of the last observed servicing activity.
        // Deliberate single mutable field: it is a best-effort grace hint, not authority, and is
        // only ever read by observe-only logic. Interlocked-guarded ticks (no lock needed).
        private static long _lastActiveTicksUtc;

        /// <summary>Default grace after servicing stops during which staged modules are still attributable.</summary>
        public static readonly TimeSpan DefaultGrace = TimeSpan.FromMinutes(10);

        /// <summary>
        /// True if a known OS-image servicing process is currently running. Records the observation
        /// time as a side effect so <see cref="IsActiveOrRecent"/> can apply a grace window.
        /// </summary>
        public static bool IsActive()
        {
            bool active = ScanForServicingProcess();
            if (active)
                System.Threading.Interlocked.Exchange(ref _lastActiveTicksUtc, DateTime.UtcNow.Ticks);
            return active;
        }

        /// <summary>
        /// True if servicing is active now OR was observed active within <paramref name="grace"/>
        /// (default <see cref="DefaultGrace"/>). Use this for delta attribution so a module staged
        /// by an update that just completed is not flagged as unexplained.
        /// </summary>
        public static bool IsActiveOrRecent(TimeSpan? grace = null)
        {
            if (IsActive()) return true;
            long last = System.Threading.Interlocked.Read(ref _lastActiveTicksUtc);
            if (last == 0) return false;
            var window = grace ?? DefaultGrace;
            return DateTime.UtcNow - new DateTime(last, DateTimeKind.Utc) <= window;
        }

        private static bool ScanForServicingProcess()
        {
            try
            {
                foreach (var proc in System.Diagnostics.Process.GetProcesses())
                {
                    string n;
                    try { n = proc.ProcessName; }
                    catch { continue; }
                    finally { try { proc.Dispose(); } catch { } }

                    foreach (var svc in ServicingProcessNames)
                    {
                        if (n.Equals(svc, StringComparison.OrdinalIgnoreCase))
                            return true;
                    }
                }
            }
            catch { }
            return false;
        }
    }
}
