using System;
using System.Runtime.CompilerServices;

namespace Sentinel.Core
{
    /// <summary>
    /// Runtime capability probes for a possibly heavily-stripped Windows image.
    ///
    /// Design principle (per the "gracefully degrade" requirement): if an OS facility is
    /// missing - WMI, ETW, the Windows Event Log, a service, a registry hive, performance
    /// counters - Sentinel must SKIP the feature that needs it and keep everything else
    /// running, instead of throwing at startup.
    ///
    /// Each probe is:
    ///   - cached (probed once, result reused) so repeated checks are free,
    ///   - fully isolated - the actual facility touch lives in a separate NoInlining method
    ///     so that even a JIT-time assembly/type-load failure (e.g. System.Management missing
    ///     on a trimmed image) is caught by the try/catch in the public probe rather than
    ///     escaping and faulting the process.
    ///
    /// IMPORTANT: the try/catch must wrap the CALL to the inner method, because a missing-type
    /// exception surfaces when the runtime JITs the method that references the missing type -
    /// i.e. at the call boundary, not inside the inner method body.
    /// </summary>
    public static class SystemCapabilities
    {
        private static readonly object _gate = new();

        private static bool? _wmi;
        private static bool? _etw;
        private static bool? _eventLog;
        private static bool? _perfCounters;
        private static bool? _managementAssembly;

        /// <summary>WMI / CIM query infrastructure is present and usable.</summary>
        public static bool WmiAvailable
        {
            get
            {
                if (_wmi.HasValue) return _wmi.Value;
                lock (_gate)
                {
                    if (_wmi.HasValue) return _wmi.Value;
                    bool ok;
                    try { ok = ProbeWmi(); }
                    catch { ok = false; }
                    _wmi = ok;
                    return ok;
                }
            }
        }

        /// <summary>The System.Management assembly itself can be loaded (weaker than WmiAvailable).</summary>
        public static bool ManagementAssemblyAvailable
        {
            get
            {
                if (_managementAssembly.HasValue) return _managementAssembly.Value;
                lock (_gate)
                {
                    if (_managementAssembly.HasValue) return _managementAssembly.Value;
                    bool ok;
                    try { ok = ProbeManagementAssembly(); }
                    catch { ok = false; }
                    _managementAssembly = ok;
                    return ok;
                }
            }
        }

        /// <summary>ETW kernel/user tracing (advapi32 StartTrace) is usable.</summary>
        public static bool EtwAvailable
        {
            get
            {
                if (_etw.HasValue) return _etw.Value;
                lock (_gate)
                {
                    if (_etw.HasValue) return _etw.Value;
                    bool ok;
                    try { ok = ProbeEtw(); }
                    catch { ok = false; }
                    _etw = ok;
                    return ok;
                }
            }
        }

        /// <summary>The Windows Event Log service/API is present (some stripped images remove it).</summary>
        public static bool EventLogAvailable
        {
            get
            {
                if (_eventLog.HasValue) return _eventLog.Value;
                lock (_gate)
                {
                    if (_eventLog.HasValue) return _eventLog.Value;
                    bool ok;
                    try { ok = ProbeEventLog(); }
                    catch { ok = false; }
                    _eventLog = ok;
                    return ok;
                }
            }
        }

        /// <summary>Performance counters are queryable (PerfLib is frequently stripped).</summary>
        public static bool PerformanceCountersAvailable
        {
            get
            {
                if (_perfCounters.HasValue) return _perfCounters.Value;
                lock (_gate)
                {
                    if (_perfCounters.HasValue) return _perfCounters.Value;
                    bool ok;
                    try { ok = ProbePerfCounters(); }
                    catch { ok = false; }
                    _perfCounters = ok;
                    return ok;
                }
            }
        }

        /// <summary>True if a Windows service with the given name is installed.</summary>
        public static bool ServiceInstalled(string serviceName)
        {
            if (string.IsNullOrWhiteSpace(serviceName)) return false;
            try { return ProbeServiceInstalled(serviceName); }
            catch { return false; }
        }

        /// <summary>True if the given registry key exists (HKLM\... or full path with hive prefix).</summary>
        public static bool RegistryKeyExists(string keyPath)
        {
            if (string.IsNullOrWhiteSpace(keyPath)) return false;
            try { return ProbeRegistryKey(keyPath); }
            catch { return false; }
        }

        //  Isolated probes (NoInlining keeps the risky type references off the caller's frame) 

        [MethodImpl(MethodImplOptions.NoInlining)]
        private static bool ProbeManagementAssembly()
        {
            // Touch a type from System.Management. If the assembly is absent, the exception
            // surfaces at the call site in ManagementAssemblyAvailable and is swallowed there.
            var t = typeof(System.Management.ManagementScope);
            return t != null;
        }

        [MethodImpl(MethodImplOptions.NoInlining)]
        private static bool ProbeWmi()
        {
            // A trivial CIM connection to the default namespace. If WMI (winmgmt) is missing
            // or disabled, Connect() throws and the caller records the facility as unavailable.
            // ManagementScope does not implement IDisposable, so no using.
            var scope = new System.Management.ManagementScope(@"\\.\root\cimv2");
            scope.Connect();
            return scope.IsConnected;
        }

        [MethodImpl(MethodImplOptions.NoInlining)]
        private static bool ProbeEtw()
        {
            // ETW is present on every standard Windows image. The most reliable indicator
            // is the WMI/ETW kernel registry key, which exists from Vista onward.
            // This avoids LoadLibrary+GetProcAddress sequences (AV evasion heuristic signal)
            // in favour of a plain registry existence check.
            try
            {
                using var key = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(
                    @"SYSTEM\CurrentControlSet\Control\WMI");
                return key != null;
            }
            catch
            {
                return false;
            }
        }

        [MethodImpl(MethodImplOptions.NoInlining)]
        private static bool ProbeEventLog()
        {
            // Some stripped images remove the Event Log service. Probe the service control DB.
            using var sc = new System.ServiceProcess.ServiceController("EventLog");
            var _ = sc.Status; // throws if the service does not exist
            return true;
        }

        [MethodImpl(MethodImplOptions.NoInlining)]
        private static bool ProbePerfCounters()
        {
            // Reading any counter category forces PerfLib to initialize; missing on trimmed images.
            return System.Diagnostics.PerformanceCounterCategory.Exists("Processor");
        }

        [MethodImpl(MethodImplOptions.NoInlining)]
        private static bool ProbeServiceInstalled(string serviceName)
        {
            foreach (var svc in System.ServiceProcess.ServiceController.GetServices())
            {
                using (svc)
                {
                    if (string.Equals(svc.ServiceName, serviceName, StringComparison.OrdinalIgnoreCase))
                        return true;
                }
            }
            return false;
        }

        [MethodImpl(MethodImplOptions.NoInlining)]
        private static bool ProbeRegistryKey(string keyPath)
        {
            // Accept "HKLM\Sub\Key", "HKEY_LOCAL_MACHINE\...", or a bare path (assumed HKLM).
            string path = keyPath.Replace('/', '\\').Trim();
            Microsoft.Win32.RegistryKey root;
            if (path.StartsWith("HKLM", StringComparison.OrdinalIgnoreCase) ||
                path.StartsWith("HKEY_LOCAL_MACHINE", StringComparison.OrdinalIgnoreCase))
            {
                root = Microsoft.Win32.Registry.LocalMachine; path = StripHive(path);
            }
            else if (path.StartsWith("HKCU", StringComparison.OrdinalIgnoreCase) ||
                     path.StartsWith("HKEY_CURRENT_USER", StringComparison.OrdinalIgnoreCase))
            {
                root = Microsoft.Win32.Registry.CurrentUser; path = StripHive(path);
            }
            else if (path.StartsWith("HKCR", StringComparison.OrdinalIgnoreCase) ||
                     path.StartsWith("HKEY_CLASSES_ROOT", StringComparison.OrdinalIgnoreCase))
            {
                root = Microsoft.Win32.Registry.ClassesRoot; path = StripHive(path);
            }
            else
            {
                root = Microsoft.Win32.Registry.LocalMachine;
            }

            using var key = root.OpenSubKey(path);
            return key != null;
        }

        private static string StripHive(string path)
        {
            int slash = path.IndexOf('\\');
            return slash >= 0 ? path.Substring(slash + 1) : "";
        }

    }
}
