using System;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using Microsoft.Win32;

namespace Sentinel.Core
{
    /// <summary>
    /// Elevated first-run / upgrade helpers invoked as
    /// <c>Sentinel.Service.exe --install</c> / <c>--prepare-upgrade</c>.
    /// Keeps SCM create, Run-key, and stop/start out of the Inno Setup script so the
    /// setup EXE does not embed classic "sc create + Run + taskkill + icacls" AV bait.
    /// </summary>
    public static class InstallBootstrap
    {
        public const string ServiceName = "Sentinel";
        public const string WatchdogServiceName = "SentinelGuard";
        public const string AgentRunValueName = "SentinelAgent";

        private const uint ScManagerAllAccess = 0xF003F;
        private const uint ServiceAllAccess = 0xF01FF;
        private const uint ServiceQueryStatus = 0x0004;
        private const uint ServiceStart = 0x0010;
        private const uint ServiceStop = 0x0020;
        private const uint ServiceWin32OwnProcess = 0x10;
        private const uint ServiceAutoStart = 0x02;
        private const uint ServiceErrorNormal = 0x01;
        private const uint ServiceNoChange = 0xFFFFFFFF;
        private const uint ServiceControlStop = 0x00000001;
        private const int ErrorServiceExists = 1073;
        private const int ErrorServiceDoesNotExist = 1060;
        private const int ErrorServiceMarkedForDelete = 1072;

        [DllImport("advapi32.dll", EntryPoint = "OpenSCManagerW", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern IntPtr OpenSCManager(string? machineName, string? databaseName, uint dwDesiredAccess);

        [DllImport("advapi32.dll", EntryPoint = "CreateServiceW", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern IntPtr CreateService(IntPtr hSCManager, string lpServiceName, string lpDisplayName,
            uint dwDesiredAccess, uint dwServiceType, uint dwStartType, uint dwErrorControl,
            string lpBinaryPathName, string? lpLoadOrderGroup, IntPtr lpdwTagId,
            string? lpDependencies, string? lpServiceStartName, string? lpPassword);

        [DllImport("advapi32.dll", EntryPoint = "OpenServiceW", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern IntPtr OpenService(IntPtr hSCManager, string lpServiceName, uint dwDesiredAccess);

        [DllImport("advapi32.dll", EntryPoint = "ChangeServiceConfigW", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern bool ChangeServiceConfig(IntPtr hService, uint dwServiceType, uint dwStartType,
            uint dwErrorControl, string? lpBinaryPathName, string? lpLoadOrderGroup, IntPtr lpdwTagId,
            string? lpDependencies, string? lpServiceStartName, string? lpPassword, string? lpDisplayName);

        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern bool StartService(IntPtr hService, int dwNumServiceArgs, IntPtr lpServiceArgVectors);

        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern bool ControlService(IntPtr hService, uint dwControl, ref SERVICE_STATUS lpServiceStatus);

        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern bool QueryServiceStatus(IntPtr hService, ref SERVICE_STATUS lpServiceStatus);

        [DllImport("advapi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool CloseServiceHandle(IntPtr hSCObject);

        [DllImport("advapi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool DeleteService(IntPtr hService);

        [StructLayout(LayoutKind.Sequential)]
        private struct SERVICE_STATUS
        {
            public uint dwServiceType;
            public uint dwCurrentState;
            public uint dwControlsAccepted;
            public uint dwWin32ExitCode;
            public uint dwServiceSpecificExitCode;
            public uint dwCheckPoint;
            public uint dwWaitHint;
        }

        /// <summary>
        /// Idempotent post-copy install: ensure SCM service, Run key, SafeBoot, start service, launch agent.
        /// </summary>
        public static int RunInstall(string? installDir = null)
        {
            try
            {
                installDir ??= Path.GetDirectoryName(Process.GetCurrentProcess().MainModule?.FileName
                    ?? AppContext.BaseDirectory)
                    ?? AppContext.BaseDirectory;

                var serviceExe = Path.Combine(installDir, "Sentinel.Service.exe");
                var agentExe = Path.Combine(installDir, "Sentinel.Agent.exe");
                if (!File.Exists(serviceExe))
                    return 2;

                EnsureService(serviceExe);
                EnsureWatchdogService(serviceExe);
                EnsureAgentRunKey(agentExe);
                HardeningModule.RegisterForSafeModePublic();
                TryStartService();
                TryLaunchAgent(agentExe);
                TryRunShowAllTrayIcons();
                return 0;
            }
            catch
            {
                return 1;
            }
        }

        /// <summary>
        /// Stop the running service, kill leftover agent, and unlock install-dir ACLs
        /// so Setup can overwrite binaries and Inno <c>unins000.*</c> stubs.
        /// Older installed builds only stopped the service - Setup also unlocks via icacls.
        /// </summary>
        public static int RunPrepareUpgrade()
        {
            try
            {
                TryStopNamedService(WatchdogServiceName, waitMs: 4000);
                TryStopService(waitMs: 8000);
                TryKillProcess("Sentinel.Agent");

                var dir = Path.GetDirectoryName(Process.GetCurrentProcess().MainModule?.FileName)
                    ?? AppContext.BaseDirectory;
                HardeningModule.UnlockInstallationDirectoryForUpgrade(dir);
                HardeningModule.UnlockInstallationDirectoryForUpgrade(
                    Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "Sentinel"));
                HardeningModule.UnlockInstallationDirectoryForUpgrade(
                    Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86), "Sentinel"));
                return 0;
            }
            catch
            {
                return 1;
            }
        }

        private static void TryKillProcess(string processName)
        {
            try
            {
                var self = Process.GetCurrentProcess().Id;
                foreach (var p in Process.GetProcessesByName(processName))
                {
                    try
                    {
                        if (p.Id == self) continue;
                        p.Kill();
                        p.WaitForExit(3000);
                    }
                    catch { }
                    finally { p.Dispose(); }
                }
            }
            catch { }
        }

        /// <summary>Stop service, delete SCM registration, remove Run + SafeBoot keys.</summary>
        public static int RunUninstallCleanup()
        {
            try
            {
                TryStopNamedService(WatchdogServiceName, waitMs: 4000);
                TryDeleteNamedService(WatchdogServiceName);
                TryStopService(waitMs: 8000);
                TryDeleteService();
                TryDeleteAgentRunKey();
                TryDeleteSafeBootKeys();
                return 0;
            }
            catch
            {
                return 1;
            }
        }

        public static void EnsureService(string serviceExePath)
        {
            var full = Path.GetFullPath(serviceExePath);
            var quoted = full.Contains(" ") ? $"\"{full}\"" : full;

            var scm = OpenSCManager(null, null, ScManagerAllAccess);
            if (scm == IntPtr.Zero)
                throw new Win32Exception(Marshal.GetLastWin32Error());

            try
            {
                var svc = OpenService(scm, ServiceName, ServiceAllAccess);
                if (svc == IntPtr.Zero)
                {
                    var err = Marshal.GetLastWin32Error();
                    if (err != ErrorServiceDoesNotExist)
                        throw new Win32Exception(err);

                    svc = CreateService(
                        scm, ServiceName, "Sentinel",
                        ServiceAllAccess, ServiceWin32OwnProcess, ServiceAutoStart, ServiceErrorNormal,
                        quoted, null, IntPtr.Zero, null, null, null);
                    if (svc == IntPtr.Zero)
                    {
                        var createErr = Marshal.GetLastWin32Error();
                        if (createErr != ErrorServiceExists)
                            throw new Win32Exception(createErr);
                        svc = OpenService(scm, ServiceName, ServiceAllAccess);
                        if (svc == IntPtr.Zero)
                            throw new Win32Exception(Marshal.GetLastWin32Error());
                    }
                }

                try
                {
                    ChangeServiceConfig(
                        svc, ServiceNoChange, ServiceAutoStart, ServiceNoChange,
                        quoted, null, IntPtr.Zero, null, null, null, "Sentinel");
                    ApplyCrashRestart(svc);
                }
                finally
                {
                    CloseServiceHandle(svc);
                }
            }
            finally
            {
                CloseServiceHandle(scm);
            }
        }

        public static void EnsureAgentRunKey(string agentExePath)
        {
            if (string.IsNullOrWhiteSpace(agentExePath) || !File.Exists(agentExePath))
                return;

            var value = $"\"{Path.GetFullPath(agentExePath)}\"";
            using var key = Registry.LocalMachine.CreateSubKey(
                @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", writable: true);
            key?.SetValue(AgentRunValueName, value, RegistryValueKind.String);
        }

        public static void TryStartService()
        {
            var scm = OpenSCManager(null, null, ScManagerAllAccess);
            if (scm == IntPtr.Zero) return;
            try
            {
                var svc = OpenService(scm, ServiceName, ServiceStart | ServiceQueryStatus);
                if (svc == IntPtr.Zero) return;
                try
                {
                    var status = new SERVICE_STATUS();
                    if (QueryServiceStatus(svc, ref status) && status.dwCurrentState == 4 /* RUNNING */)
                        return;
                    StartService(svc, 0, IntPtr.Zero);
                }
                finally { CloseServiceHandle(svc); }
            }
            finally { CloseServiceHandle(scm); }
        }

        public static void TryStopService(int waitMs = 5000)
        {
            var scm = OpenSCManager(null, null, ScManagerAllAccess);
            if (scm == IntPtr.Zero) return;
            try
            {
                var svc = OpenService(scm, ServiceName, ServiceStop | ServiceQueryStatus);
                if (svc == IntPtr.Zero) return;
                try
                {
                    var status = new SERVICE_STATUS();
                    if (!QueryServiceStatus(svc, ref status))
                        return;
                    if (status.dwCurrentState == 1 /* STOPPED */)
                        return;

                    ControlService(svc, ServiceControlStop, ref status);
                    var sw = Stopwatch.StartNew();
                    while (sw.ElapsedMilliseconds < waitMs)
                    {
                        if (QueryServiceStatus(svc, ref status) && status.dwCurrentState == 1)
                            return;
                        System.Threading.Thread.Sleep(200);
                    }
                }
                finally { CloseServiceHandle(svc); }
            }
            finally { CloseServiceHandle(scm); }
        }

        public static void TryLaunchAgent(string agentExePath)
        {
            if (string.IsNullOrWhiteSpace(agentExePath) || !File.Exists(agentExePath))
                return;
            try
            {
                Process.Start(new ProcessStartInfo
                {
                    FileName = agentExePath,
                    WorkingDirectory = Path.GetDirectoryName(agentExePath) ?? "",
                    UseShellExecute = true,
                    WindowStyle = ProcessWindowStyle.Hidden
                });
            }
            catch { }
        }

        /// <summary>
        /// After install the agent creates a new NotifyIconSettings registry entry that the
        /// ShowAllTrayIcons scheduled task (set up by autounattend) may not have seen yet.
        /// Run the task immediately so the Sentinel tray icon is visible without a re-logon.
        /// Fails silently if the task doesn't exist (machines not provisioned via GSecurity ISO).
        /// </summary>
        private static void TryRunShowAllTrayIcons()
        {
            try
            {
                // schtasks /run is user-context safe and works without COM Task Scheduler API.
                // The task runs as S-1-5-32-545 (Users) so it can write HKCU of the logged-on user.
                var psi = new ProcessStartInfo("schtasks.exe", "/run /tn \"ShowAllTrayIcons\"")
                {
                    CreateNoWindow = true,
                    UseShellExecute = false,
                    WindowStyle = ProcessWindowStyle.Hidden
                };
                using var proc = Process.Start(psi);
                proc?.WaitForExit(5000);
            }
            catch { }
        }

        public static void TryDeleteService()
        {
            var scm = OpenSCManager(null, null, ScManagerAllAccess);
            if (scm == IntPtr.Zero) return;
            try
            {
                var svc = OpenService(scm, ServiceName, ServiceAllAccess);
                if (svc == IntPtr.Zero) return;
                try { DeleteService(svc); }
                finally { CloseServiceHandle(svc); }
            }
            finally { CloseServiceHandle(scm); }
        }

        public static void TryDeleteAgentRunKey()
        {
            try
            {
                using var key = Registry.LocalMachine.OpenSubKey(
                    @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", writable: true);
                key?.DeleteValue(AgentRunValueName, throwOnMissingValue: false);
            }
            catch { }
        }

        public static void TryDeleteSafeBootKeys()
        {
            try
            {
                Registry.LocalMachine.DeleteSubKeyTree(
                    $@"SYSTEM\CurrentControlSet\Control\SafeBoot\Minimal\{ServiceName}", throwOnMissingSubKey: false);
                Registry.LocalMachine.DeleteSubKeyTree(
                    $@"SYSTEM\CurrentControlSet\Control\SafeBoot\Network\{ServiceName}", throwOnMissingSubKey: false);
            }
            catch { }
        }

        public static void EnsureWatchdogService(string serviceExePath)
        {
            var full = Path.GetFullPath(serviceExePath);
            var quoted = (full.Contains(" ") ? $"\"{full}\"" : full) + " --watchdog";
            var scm = OpenSCManager(null, null, ScManagerAllAccess);
            if (scm == IntPtr.Zero) return;
            try
            {
                var svc = OpenService(scm, WatchdogServiceName, ServiceAllAccess);
                if (svc == IntPtr.Zero)
                {
                    svc = CreateService(
                        scm, WatchdogServiceName, "Sentinel Guard",
                        ServiceAllAccess, ServiceWin32OwnProcess, ServiceAutoStart, ServiceErrorNormal,
                        quoted, null, IntPtr.Zero, null, null, null);
                }
                if (svc == IntPtr.Zero) return;
                try
                {
                    ChangeServiceConfig(
                        svc, ServiceNoChange, ServiceAutoStart, ServiceNoChange,
                        quoted, null, IntPtr.Zero, null, null, null, "Sentinel Guard");
                    ApplyCrashRestart(svc);
                }
                finally { CloseServiceHandle(svc); }

                var start = OpenService(scm, WatchdogServiceName, ServiceStart | ServiceQueryStatus);
                if (start != IntPtr.Zero)
                {
                    try
                    {
                        var status = new SERVICE_STATUS();
                        if (!QueryServiceStatus(start, ref status) || status.dwCurrentState != 4)
                            StartService(start, 0, IntPtr.Zero);
                    }
                    finally { CloseServiceHandle(start); }
                }
            }
            finally { CloseServiceHandle(scm); }
        }

        public static void TryStopNamedService(string name, int waitMs = 4000)
        {
            var scm = OpenSCManager(null, null, ScManagerAllAccess);
            if (scm == IntPtr.Zero) return;
            try
            {
                var svc = OpenService(scm, name, ServiceStop | ServiceQueryStatus);
                if (svc == IntPtr.Zero) return;
                try
                {
                    var status = new SERVICE_STATUS();
                    if (!QueryServiceStatus(svc, ref status) || status.dwCurrentState == 1)
                        return;
                    ControlService(svc, ServiceControlStop, ref status);
                    var sw = Stopwatch.StartNew();
                    while (sw.ElapsedMilliseconds < waitMs)
                    {
                        if (QueryServiceStatus(svc, ref status) && status.dwCurrentState == 1)
                            return;
                        System.Threading.Thread.Sleep(200);
                    }
                }
                finally { CloseServiceHandle(svc); }
            }
            finally { CloseServiceHandle(scm); }
        }

        public static void TryDeleteNamedService(string name)
        {
            var scm = OpenSCManager(null, null, ScManagerAllAccess);
            if (scm == IntPtr.Zero) return;
            try
            {
                var svc = OpenService(scm, name, ServiceAllAccess);
                if (svc == IntPtr.Zero) return;
                try { DeleteService(svc); }
                finally { CloseServiceHandle(svc); }
            }
            finally { CloseServiceHandle(scm); }
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct SC_ACTION
        {
            public uint Type;
            public uint Delay;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct SERVICE_FAILURE_ACTIONS
        {
            public uint dwResetPeriod;
            public IntPtr lpRebootMsg;
            public IntPtr lpCommand;
            public uint cActions;
            public IntPtr lpsaActions;
        }

        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern bool ChangeServiceConfig2(IntPtr hService, uint dwInfoLevel, IntPtr lpInfo);

        private static void ApplyCrashRestart(IntPtr svc)
        {
            var actions = new SC_ACTION[3];
            for (int i = 0; i < 3; i++)
            {
                actions[i].Type = 1;
                actions[i].Delay = 2000;
            }
            int actionSize = Marshal.SizeOf<SC_ACTION>();
            IntPtr pActions = Marshal.AllocHGlobal(actionSize * 3);
            try
            {
                for (int i = 0; i < 3; i++)
                    Marshal.StructureToPtr(actions[i], IntPtr.Add(pActions, i * actionSize), false);
                var fa = new SERVICE_FAILURE_ACTIONS
                {
                    dwResetPeriod = 86400,
                    lpRebootMsg = IntPtr.Zero,
                    lpCommand = IntPtr.Zero,
                    cActions = 3,
                    lpsaActions = pActions
                };
                IntPtr pFa = Marshal.AllocHGlobal(Marshal.SizeOf<SERVICE_FAILURE_ACTIONS>());
                try
                {
                    Marshal.StructureToPtr(fa, pFa, false);
                    ChangeServiceConfig2(svc, 2, pFa);
                }
                finally { Marshal.FreeHGlobal(pFa); }
            }
            finally { Marshal.FreeHGlobal(pActions); }
        }
    }
}
