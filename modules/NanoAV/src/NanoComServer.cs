using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Management;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Threading;

namespace NanoAV
{
    /// <summary>
    /// COM-visible NanoAV server class.
    /// This class can be activated via COM or rundll32.
    /// </summary>
    [ComVisible(true)]
    [Guid("A0B8E5D2-4F3C-4A1B-9C8F-7E6D5A4B3C2D")]
    [ClassInterface(ClassInterfaceType.AutoDual)]
    [ProgId("NanoAV.Server")]
    public class NanoAVComServer
    {
        private static readonly List<FileSystemWatcher> Watchers = new List<FileSystemWatcher>();
        private static ManagementEventWatcher _procWatcher;
        private static bool _isRunning = false;

        /// <summary>
        /// COM entry point - called by rundll32 or COM activation
        /// </summary>
        public static int DllMain(IntPtr hInstance, IntPtr lpCmdLine, int nShowCmd)
        {
            StartMonitoring();
            return 1;
        }

        /// <summary>
        /// Start the NanoAV monitoring
        /// </summary>
        public static void Start()
        {
            if (!_isRunning)
            {
                StartMonitoring();
            }
        }

        /// <summary>
        /// Stop the NanoAV monitoring
        /// </summary>
        public static void Stop()
        {
            Cleanup();
            _isRunning = false;
        }

        /// <summary>
        /// Status check
        /// </summary>
        public static bool IsRunning()
        {
            return _isRunning;
        }

        private static void StartMonitoring()
        {
            if (_isRunning) return;

            foreach (string dir in new[] { Config.BaseDirectory, Config.QuarantineDirectory,
                         Config.BackupDirectory, Config.RulesDirectory })
            {
                try { Directory.CreateDirectory(dir); } catch { }
            }

            bool isAdmin = IsAdministrator();
            C2Engine.IsAdmin = isAdmin;

            try { if (File.Exists(Config.OwnPidFile)) File.Delete(Config.OwnPidFile); } catch { }
            PidRegistry.RegisterSelf();

            Logger.Log("=== NanoAV COM Server Started ===");
            Logger.Log("Admin: " + isAdmin);

            Database.Load();

            Logger.Log("Performing initial scan");
            foreach (string folder in HighRiskFolders())
            {
                if (!Directory.Exists(folder)) continue;
                try
                {
                    foreach (string file in Directory.GetFiles(folder, "*", SearchOption.AllDirectories))
                        ThreatAnalysis.Analyze(file);
                }
                catch { }
            }

            if (Config.EnableRealtimeMonitor)
            {
                foreach (string folder in HighRiskFolders())
                {
                    if (!Directory.Exists(folder)) continue;
                    try
                    {
                        var watcher = new FileSystemWatcher(folder, "*.*")
                        {
                            IncludeSubdirectories = true,
                            NotifyFilter = NotifyFilters.FileName | NotifyFilters.LastWrite
                        };
                        watcher.Created += OnFileCreated;
                        watcher.EnableRaisingEvents = true;
                        Watchers.Add(watcher);
                    }
                    catch { }
                }
            }

            try
            {
                _procWatcher = Wmi.WatchProcessStart(OnProcessStart);
            }
            catch { }

            if (Config.EnableMemoryScanning)
                MemoryScanner.Start();

            _isRunning = true;
            Logger.Log("NanoAV COM Server is running");
        }

        private static void Cleanup()
        {
            foreach (var watcher in Watchers)
            {
                try { watcher.Dispose(); } catch { }
            }
            Watchers.Clear();

            if (_procWatcher != null)
            {
                _procWatcher.Dispose();
                _procWatcher = null;
            }

            Logger.Log("NanoAV COM Server stopped");
        }

        private static string[] HighRiskFolders()
        {
            return new[]
            {
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads"),
                Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory),
                Path.GetTempPath(),
                Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Temp")
            };
        }

        private static bool IsAdministrator()
        {
            try
            {
                var identity = WindowsIdentity.GetCurrent();
                var principal = new WindowsPrincipal(identity);
                return principal.IsInRole(WindowsBuiltInRole.Administrator);
            }
            catch { return false; }
        }

        private static void OnFileCreated(object sender, FileSystemEventArgs e)
        {
            try
            {
                string ext = Path.GetExtension(e.FullPath).ToLowerInvariant();
                if (Config.MonitoredExtensions.Contains(ext))
                {
                    Thread.Sleep(800);
                    ThreatAnalysis.Analyze(e.FullPath);
                }
            }
            catch { }
        }

        private static void OnProcessStart(string processName, int processId)
        {
            try
            {
                string ownerSid = Wmi.GetProcessOwnerSid(processId);
                if (Array.IndexOf(Config.AllowedSIDs, ownerSid) >= 0)
                {
                    if (FileScanner.GetSignatureStatus(processName) == FileScanner.SignatureStatus.Valid)
                        return;
                }
                ThreatAnalysis.BlockFileExecution(processName, processId, "EXE");
            }
            catch { }
        }
    }

    /// <summary>
    /// COM Server Registration/Unregistration helper.
    /// Call DllRegisterServer() from regsvr32 or install script.
    /// </summary>
    [ComVisible(false)]
    public static class ComServerRegistrar
    {
        public static void DllRegisterServer()
        {
            try
            {
                string dllPath = Process.GetCurrentProcess().MainModule.FileName;
                Directory.CreateDirectory(Config.BaseDirectory);

                // Register COM
                RegisterComServer(dllPath);
                
                // Register Run key for persistence via rundll32
                using (var runKey = Microsoft.Win32.Registry.CurrentUser.CreateSubKey(@"Software\Microsoft\Windows\CurrentVersion\Run"))
                {
                    runKey.SetValue("NanoAV", "rundll32.exe \"" + dllPath + "\",DllMain");
                }

                Logger.Log("COM Server registered");
            }
            catch (Exception ex)
            {
                Logger.Log("COM Server registration failed: " + ex.Message);
                throw;
            }
        }

        public static void DllUnregisterServer()
        {
            try
            {
                UnregisterComServer();
                UnregisterRunKey();
                Logger.Log("COM Server unregistered");
            }
            catch (Exception ex)
            {
                Logger.Log("COM Server unregistration failed: " + ex.Message);
                throw;
            }
        }

        private static void RegisterComServer(string dllPath)
        {
            string clsid = "A0B8E5D2-4F3C-4A1B-9C8F-7E6D5A4B3C2D";
            string progId = "NanoAV.Server";

            using (var clsidKey = Microsoft.Win32.Registry.ClassesRoot.CreateSubKey("CLSID\\" + clsid))
            {
                clsidKey.SetValue("", "NanoAV Lite COM Server");
                clsidKey.SetValue("AppID", clsid);

                using (var inprocKey = clsidKey.CreateSubKey("InprocServer32"))
                {
                    inprocKey.SetValue("", dllPath);
                    inprocKey.SetValue("ThreadingModel", "Apartment");
                }
            }

            using (var progIdKey = Microsoft.Win32.Registry.ClassesRoot.CreateSubKey(progId))
            {
                progIdKey.SetValue("", "NanoAV Lite COM Server");
                progIdKey.SetValue("CLSID", clsid);
                using (var curVerKey = progIdKey.CreateSubKey("CurVer"))
                {
                    curVerKey.SetValue("", progId + ".Server");
                }
            }
        }

        private static void UnregisterComServer()
        {
            try
            {
                Microsoft.Win32.Registry.ClassesRoot.DeleteSubKeyTree("CLSID\\A0B8E5D2-4F3C-4A1B-9C8F-7E6D5A4B3C2D", false);
                Microsoft.Win32.Registry.ClassesRoot.DeleteSubKeyTree("NanoAV.Server", false);
            }
            catch { }
        }

        private static void UnregisterRunKey()
        {
            try
            {
                using (var runKey = Microsoft.Win32.Registry.CurrentUser.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\Run", true))
                {
                    if (runKey != null) runKey.DeleteValue("NanoAV", false);
                }
            }
            catch { }
        }
    }
}
