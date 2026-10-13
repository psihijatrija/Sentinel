using System;
using System.IO;
using System.Diagnostics;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using Microsoft.Extensions.Logging;

namespace Sentinel.Core
{
    public class FileActivityMonitor : IDisposable
    {
        private readonly TelemetryFusionEngine _fusionEngine;
        private readonly DetectionEngine _detectionEngine;
        private readonly RansomwareIoMonitor? _ransomwareIoMonitor;
        private readonly DllUnloadEngine? _dllUnloadEngine;
        private readonly SentinelConfig _config;
        private readonly ILogger<FileActivityMonitor> _logger;
        private readonly SignerTrustService _signerTrust;
        private readonly List<FileSystemWatcher> _watchers = new();

        [StructLayout(LayoutKind.Sequential)]
        private struct RM_UNIQUE_PROCESS
        {
            public int dwProcessId;
            public System.Runtime.InteropServices.ComTypes.FILETIME ProcessStartTime;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private struct RM_PROCESS_INFO
        {
            public RM_UNIQUE_PROCESS Process;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 256)]
            public string strAppName;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 64)]
            public string strServiceShortName;
            public int ApplicationType;
            public uint AppStatus;
            public uint TSSessionId;
            [MarshalAs(UnmanagedType.Bool)]
            public bool bRestartable;
        }

        [DllImport("rstrtmgr.dll", CharSet = CharSet.Unicode)]
        private static extern int RmStartSession(out uint pSessionHandle, int dwSessionFlags, string strSessionKey);

        [DllImport("rstrtmgr.dll", CharSet = CharSet.Unicode)]
        private static extern int RmRegisterResources(
            uint pSessionHandle,
            uint nFiles,
            string[] rgsFilenames,
            uint nApplications,
            IntPtr rgApplications,
            uint nServices,
            IntPtr rgsServiceNames);

        [DllImport("rstrtmgr.dll")]
        private static extern int RmGetList(
            uint dwSessionHandle,
            out uint pnProcInfoNeeded,
            ref uint pnProcInfo,
            [In, Out] RM_PROCESS_INFO[]? rgApps,
            out uint lpdwRebootReasons);

        [DllImport("rstrtmgr.dll")]
        private static extern int RmEndSession(uint pSessionHandle);

        public FileActivityMonitor(
            TelemetryFusionEngine fusionEngine,
            DetectionEngine detectionEngine,
            SentinelConfig config,
            ILogger<FileActivityMonitor> logger,
            SignerTrustService signerTrust,
            RansomwareIoMonitor? ransomwareIoMonitor = null,
            DllUnloadEngine? dllUnloadEngine = null)
        {
            _fusionEngine = fusionEngine;
            _detectionEngine = detectionEngine;
            _ransomwareIoMonitor = ransomwareIoMonitor;
            _dllUnloadEngine = dllUnloadEngine;
            _config = config;
            _logger = logger;
            _signerTrust = signerTrust;

            Start();
        }

        public void Start()
        {
            var paths = GetPathsToWatch(_config);
            foreach (var path in paths)
            {
                StartWatchersForPath(path);
            }
        }

        private List<string> GetPathsToWatch(SentinelConfig config)
        {
            var paths = new List<string>();
            if (!string.IsNullOrWhiteSpace(config.WatchPath))
            {
                if (Directory.Exists(config.WatchPath))
                {
                    paths.Add(config.WatchPath!);
                }
                else
                {
                    _logger.LogWarning($"Configured WatchPath does not exist: {config.WatchPath}");
                }
            }
            else
            {
                // Default: get all actual user profile paths under C:\Users
                var usersDir = Path.Combine(Environment.GetEnvironmentVariable("SystemDrive") ?? "C:", "Users");
                if (Directory.Exists(usersDir))
                {
                    try
                    {
                        foreach (var dir in Directory.GetDirectories(usersDir))
                        {
                            var name = Path.GetFileName(dir);
                            if (name.Equals("Public") ||
                                name.Equals("Default") ||
                                name.Equals("Default User") ||
                                name.Equals("All Users") ||
                                name.StartsWith("."))
                            {
                                continue;
                            }
                            paths.Add(dir);
                        }
                    }
                    catch (Exception ex)
                    {
                        _logger.LogError($"Failed to list directories under {usersDir}: {ex.Message}. Falling back to system user profile.");
                        paths.Add(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile));
                    }
                }
                else
                {
                    paths.Add(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile));
                }
            }

            // Always monitor critical OS directories for unauthorized writes
            var system32 = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "System32");
            var sysWOW64 = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "SysWOW64");
            if (Directory.Exists(system32)) paths.Add(system32);
            if (Directory.Exists(sysWOW64)) paths.Add(sysWOW64);

            return paths;
        }

        private void StartWatchersForPath(string path)
        {
            try
            {
                if (!Directory.Exists(path)) return;

                // 1. Try to start a single recursive watcher
                try
                {
                    var watcher = CreateWatcher(path, true);
                    _watchers.Add(watcher);
                    _logger.LogInformation($"Successfully started recursive FileSystemWatcher on {path}");
                }
                catch (UnauthorizedAccessException ex)
                {
                    _logger.LogWarning($"Recursive watcher failed on {path} due to access permissions: {ex.Message}. Falling back to non-recursive root and recursive subfolders.");

                    // Fallback 1: Watch the root path non-recursively
                    try
                    {
                        var rootWatcher = CreateWatcher(path, false);
                        _watchers.Add(rootWatcher);
                        _logger.LogInformation($"Started non-recursive FileSystemWatcher on {path}");
                    }
                    catch (Exception rootEx)
                    {
                        _logger.LogError($"Failed to start non-recursive watcher on root {path}: {rootEx.Message}");
                    }

                    // Fallback 2: Watch standard common subfolders recursively
                    var subdirs = new[] { "Desktop", "Documents", "Downloads", "Pictures", "Videos", "Music" };
                    foreach (var subdir in subdirs)
                    {
                        var fullSubdirPath = Path.Combine(path, subdir);
                        if (Directory.Exists(fullSubdirPath))
                        {
                            try
                            {
                                var subWatcher = CreateWatcher(fullSubdirPath, true);
                                _watchers.Add(subWatcher);
                                _logger.LogInformation($"Started recursive FileSystemWatcher on subfolder {fullSubdirPath}");
                            }
                            catch (Exception subEx)
                            {
                                _logger.LogWarning($"Failed to start recursive watcher on {fullSubdirPath}: {subEx.Message}");
                            }
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogError($"Failed to initialize watchers for path {path}: {ex.Message}");
            }
        }

        /// <summary>
        /// Dynamically adds a new path to the file activity monitoring scope.
        /// Used by VolumeMountMonitor to extend coverage to newly mounted volumes.
        /// v1.0.1: New method.
        /// </summary>
        public void AddWatchPath(string path)
        {
            if (string.IsNullOrWhiteSpace(path) || !Directory.Exists(path)) return;

            // Check if already watched
            lock (_watchers)
            {
                if (_watchers.Any(w => w.Path.Equals(path)))
                    return;
            }

            StartWatchersForPath(path);
            _logger.LogInformation("[FileActivityMonitor] Dynamically added watch path: {Path}", path);
        }

        private FileSystemWatcher CreateWatcher(string path, bool includeSubdirectories)
        {
            var watcher = new FileSystemWatcher(path)
            {
                IncludeSubdirectories = includeSubdirectories,
                NotifyFilter = NotifyFilters.FileName | NotifyFilters.LastWrite,
                Filter = "*.*"
            };

            watcher.Created += OnFileEvent;
            watcher.Changed += OnFileEvent;
            watcher.Deleted += OnFileEvent;
            watcher.Renamed += OnFileRenamed;

            watcher.EnableRaisingEvents = true;
            return watcher;
        }
        private void OnFileEvent(object sender, FileSystemEventArgs e)
        {
            var pathLower = e.FullPath.ToLowerInvariant();
            if (pathLower.Contains(@"\.git\") || pathLower.Contains(@"\.gemini\"))
            {
                return;
            }

            // Non-module/script files: no File.Exists, no Restart Manager, no fusion.
            // Opening/stat'ing every user-profile write was a hard-fault firehose.
            bool maybeDir = e.ChangeType == WatcherChangeTypes.Created
                && string.IsNullOrEmpty(Path.GetExtension(e.FullPath));
            if (!maybeDir
                && !DllUnloadEngine.IsSideloadTargetFileName(e.FullPath)
                && !SecurityFileScope.IsRelevantOrHighRisk(e.FullPath)
                && !IsProtectedOsDirectory(pathLower))
            {
                return;
            }

            // v1.4.1: Detect junction/symlink creation targeting or within monitored directories.
            // An attacker can create junctions to redirect monitored paths or to make excluded
            // paths point to sensitive areas. Detect any reparse point creation.
            if (e.ChangeType == WatcherChangeTypes.Created)
            {
                try
                {
                    if (Directory.Exists(e.FullPath) || File.Exists(e.FullPath))
                    {
                        var attrs = File.GetAttributes(e.FullPath);
                        if ((attrs & FileAttributes.ReparsePoint) != 0)
                        {
                            var reparseCreator = GetProcessUsingFile(e.FullPath);
                            var cloud = August2026CveHeuristics.IsCloudPlaceholderAttributes((int)attrs);
                            var hive = August2026CveHeuristics.IsHiveFilePath(e.FullPath);
                            var knownSync = August2026CveHeuristics.IsKnownCloudSyncClient(reparseCreator.name)
                                            || August2026CveHeuristics.IsKnownCloudSyncFolder(e.FullPath);

                            // OneDrive/Dropbox hydration placeholders are not junction attacks.
                            if (cloud && knownSync)
                            {
                                // skip junction kill
                            }
                            // Allow TrustedInstaller/DISM reparse points (Windows component store uses them)
                            else if (!IsTrustedSystemWriter(reparseCreator.pid, reparseCreator.name, e.FullPath))
                            {
                                var rule = hive
                                    ? "LegacyHive: Reparse targeting user hive"
                                    : cloud
                                        ? "Cloud Files: Unauthorized placeholder reparse"
                                        : "File Integrity: Junction/Symlink Created in Monitored Path";
                                var conf = hive ? 0.88 : (cloud ? 0.80 : 0.85);
                                var action = (cloud || hive) ? ResponseAction.LogOnly : ResponseAction.KillProcessTree;
                                _ = _detectionEngine.EmitAsync(new DetectionEvent
                                {
                                    RuleName = rule,
                                    Evidence = $"Reparse point created at '{e.FullPath}' by process '{reparseCreator.name}' (PID {reparseCreator.pid})" +
                                               (hive ? " (NTUSER/UsrClass hive path)" : cloud ? " (Cloud Files placeholder)" : ""),
                                    Reasoning = hive
                                        ? "A junction/symlink onto NTUSER.DAT or UsrClass.dat is the CVE-2026-62832 (LegacyHive) link-following primitive."
                                        : cloud
                                            ? "A Cloud Files placeholder reparse outside OneDrive is the ShieldBreak / CVE-2026-62713 hydration TOCTOU primitive. LogOnly unless chained."
                                            : "A directory junction or symbolic link was created within a monitored path. " +
                                              "Attackers use junctions to redirect monitored directories to attacker-controlled locations, " +
                                              "bypass file monitoring exclusions, or exploit TOCTOU vulnerabilities in privilege escalation attacks.",
                                    Confidence = conf,
                                    Tier = DetectionTier.Tier1Behavioral,
                                    AuthorizedResponse = action,
                                    ProcessName = reparseCreator.name,
                                    ProcessId = reparseCreator.pid,
                                    SignalType = hive || cloud ? SignalType.SecurityEvasion : SignalType.Generic,
                                    // Terminal TokenTheft only for the LegacyHive branch (rule name
                                    // "LegacyHive: ..." matches the "LegacyHive" fragment). The cloud
                                    // branch is SecurityEvasion observe and the else branch is a
                                    // Generic junction kill - neither classifies as TokenTheft today.
                                    Family = hive ? (TerminalFamily?)TerminalFamily.TokenTheft : null,
                                    Metadata = new Dictionary<string, string>
                                    {
                                        ["Path"] = e.FullPath,
                                        ["Operation"] = "ReparsePointCreated",
                                        ["CVE"] = hive ? August2026CveHeuristics.CveLegacyHive
                                            : cloud ? August2026CveHeuristics.CveCloudFiles : "",
                                    }
                                });
                            }
                        }
                    }
                }
                catch { }
            }

            // Skip user working directories where tools like NTLite, UUP dump, DISM perform
            // bulk file extraction/modification. These generate thousands of events/second
            // and the Restart Manager handle scan causes file contention that stalls the tools.
            // Security coverage for these paths is maintained by FileVerdictScanner (hash checks)
            // and process-level monitoring (WMI/ETW).
            if (IsUserToolWorkingPath(pathLower))
            {
                return;
            }

            // Targeted AppData noise suppression - only skip known high-noise, low-threat subpaths.
            // DO NOT blanket-exclude \appdata\ - attackers stage payloads in Temp, Roaming\Microsoft, etc.
            if (IsNoisyAppDataPath(pathLower))
            {
                return;
            }

            // Optimize: if it is a write of a valid Microsoft-signed file to a protected OS directory,
            // allow it immediately without doing a process lookup. This avoids sharing locks/violations
            // (e.g. during DirectX or redistributable installations).
            if ((e.ChangeType == WatcherChangeTypes.Created || e.ChangeType == WatcherChangeTypes.Changed) &&
                IsProtectedOsDirectory(pathLower) &&
                !pathLower.Contains(@"\drivers\etc\"))
            {
                try
                {
                    if (File.Exists(e.FullPath))
                    {
                        if (_signerTrust.IsSignedFile(e.FullPath))
                        {
                            SubmitEvent(e.FullPath, e.ChangeType.ToString().ToUpperInvariant(), null, 0, "System (Trusted File)");
                            return;
                        }
                    }
                }
                catch { }
            }

            // Opening every user-profile file (Restart Manager + FileStream) hard-faults
            // cache pages into this process. Only do it for modules/scripts/OS writes.
            bool needWriter = DllUnloadEngine.IsSideloadTargetFileName(e.FullPath)
                || IsProtectedOsDirectory(pathLower)
                || SecurityFileScope.IsRelevantOrHighRisk(e.FullPath);
            var processInfo = needWriter ? GetProcessUsingFile(e.FullPath) : (pid: 0, name: "unknown");

            // System-wide DLL sideload plant: known system DLL names written outside System32
            if ((e.ChangeType == WatcherChangeTypes.Created || e.ChangeType == WatcherChangeTypes.Changed) &&
                _dllUnloadEngine != null &&
                DllUnloadEngine.IsSideloadTargetFileName(e.FullPath) &&
                !IsProtectedOsDirectory(pathLower))
            {
                _ = _dllUnloadEngine.OnSideloadDllDroppedAsync(
                    e.FullPath, processInfo.pid, processInfo.name);
            }

            // Critical: detect writes to System32/SysWOW64 by non-OS processes
            // Exclude drivers\etc - managed by HostsFileGuard directly
            if ((e.ChangeType == WatcherChangeTypes.Created || e.ChangeType == WatcherChangeTypes.Changed) &&
                IsProtectedOsDirectory(pathLower) &&
                !pathLower.Contains(@"\drivers\etc\"))
            {
                // Only inspect executable/binary extensions to avoid false positives on system logs/configs (.log, .txt, .tmp, etc.)
                string ext = Path.GetExtension(pathLower);
                bool isExecutableOrLibrary = ext == ".dll" || ext == ".exe" || ext == ".sys" || ext == ".ocx" || 
                                             ext == ".scr" || ext == ".msi" || ext == ".drv" || ext == ".cpl" || ext == ".com";

                if (isExecutableOrLibrary)
                {
                    // Only alert if the writer is NOT TrustedInstaller, Windows Update, Defender, or Sentinel itself
                    if (!IsTrustedSystemWriter(processInfo.pid, processInfo.name, e.FullPath) &&
                        !processInfo.name.Contains("Sentinel") &&
                        !processInfo.name.Contains("Delivery Optimization") &&
                        !processInfo.name.Contains("AppX") &&
                        !processInfo.name.Contains("WinStore"))
                    {
                        var changeVerb = e.ChangeType == WatcherChangeTypes.Created ? "created" : "changed";
                        // Observe-only: Steam DirectX / GPU redistributables write here constantly.
                        // Kill only if a multi-signal chain later ties the same PID to C2/exfil/etc.
                        // Unresolved writer (PID 0) is never kill-class - attribution race, not BYOVD.
                        bool attributed = processInfo.pid > 4;
                        bool redist = InstallerHeuristics.IsDirectXOrRuntimeRedist(processInfo.name, e.FullPath);
                        // DirectX / VC++ / GPU redist -> Tier2 observe only (maybe 1-2 signals).
                        // Never kill-grade confidence, never composite/chain seed.
                        _ = _detectionEngine.EmitAsync(new DetectionEvent
                        {
                            RuleName = "System Integrity: Unauthorized Write to System Directory",
                            Evidence = $"File '{e.FullPath}' was {changeVerb} by process '{processInfo.name}' (PID {processInfo.pid})",
                            Reasoning = redist
                                ? "DirectX/runtime redistributable wrote to System32/SysWOW64 - normal installer life. Tier2 observe only; never Tier1/composite/kill."
                                : "A non-system process wrote to a protected OS directory (System32/SysWOW64). " +
                                  "Logged for correlation only - installers (DirectX, VC++, GPU runtimes) do this legitimately. " +
                                  "Destructive response requires multi-signal proof of token theft / cred dump / reverse shell / C2.",
                            Confidence = redist ? 0.35 : (attributed ? 0.55 : 0.40),
                            Tier = DetectionTier.Tier2Indicator,
                            AuthorizedResponse = ResponseAction.LogOnly,
                            ProcessName = processInfo.name,
                            ProcessId = processInfo.pid,
                            Metadata = new Dictionary<string, string>
                            {
                                ["FilePath"] = e.FullPath,
                                ["Operation"] = e.ChangeType.ToString(),
                                ["BenignInstallerNoise"] = "true",
                                ["ObserveOnly"] = "true",
                            }
                        });
                    }
                }
            }

            SubmitEvent(e.FullPath, e.ChangeType.ToString().ToUpperInvariant(), null, processInfo.pid, processInfo.name);
        }

        private void OnFileRenamed(object sender, RenamedEventArgs e)
        {
            var pathLower = e.FullPath.ToLowerInvariant();
            if (pathLower.Contains(@"\.git\") || pathLower.Contains(@"\.gemini\"))
            {
                return;
            }

            if (IsNoisyAppDataPath(pathLower))
            {
                return;
            }

            if (!DllUnloadEngine.IsSideloadTargetFileName(e.FullPath)
                && !SecurityFileScope.IsRelevantOrHighRisk(e.FullPath)
                && !IsProtectedOsDirectory(pathLower))
            {
                _ransomwareIoMonitor?.RecordRename(0, "unknown");
                return;
            }

            var processInfo = GetProcessUsingFile(e.FullPath);

            // Feed mass-rename counter for ransomware behavioral detection
            _ransomwareIoMonitor?.RecordRename(processInfo.pid, processInfo.name);

            SubmitEvent(e.OldFullPath, "RENAME", e.FullPath, processInfo.pid, processInfo.name);
        }

        private void SubmitEvent(string path, string operation, string? targetPath, int pid, string name)
        {
            try
            {
                var telemetry = new FileActivityTelemetry
                {
                    Type = "file",
                    FilePath = path,
                    OperationType = operation,
                    TargetPath = targetPath,
                    ProcessId = pid,
                    ProcessName = name,
                    Timestamp = DateTime.UtcNow
                };

                var context = _fusionEngine.FeedEvent(telemetry);
                _detectionEngine.SubmitTelemetry(context);
            }
            catch (Exception ex)
            {
                _logger.LogError($"Error processing file event: {ex.Message}");
            }
        }

        private static (int pid, string name) GetProcessUsingFile(string filePath)
        {
            if (string.IsNullOrWhiteSpace(filePath) || !File.Exists(filePath))
            {
                return (0, "unknown");
            }

            // Retry loop to handle temporary sharing violations (e.g. while process is writing the file)
            int retries = 5;
            while (retries > 0)
            {
                try
                {
                    using (var fs = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete))
                    {
                        break; // Successfully opened, not exclusively locked
                    }
                }
                catch (IOException ex) when ((ex.HResult & 0xFFFF) == 32) // Sharing violation (locked)
                {
                    Thread.Sleep(30);
                    retries--;
                }
                catch
                {
                    break;
                }
            }

            string sessionKey = Guid.NewGuid().ToString();
            int res = RmStartSession(out uint sessionHandle, 0, sessionKey);
            if (res != 0) return (0, "unknown");

            try
            {
                string[] resources = { filePath };
                res = RmRegisterResources(sessionHandle, (uint)resources.Length, resources, 0, IntPtr.Zero, 0, IntPtr.Zero);
                if (res != 0) return (0, "unknown");

                uint pnProcInfoNeeded = 0;
                uint pnProcInfo = 0;
                uint lpdwRebootReasons = 0;

                res = RmGetList(sessionHandle, out pnProcInfoNeeded, ref pnProcInfo, null, out lpdwRebootReasons);
                if (res != 0 && res != 234) return (0, "unknown");

                if (pnProcInfoNeeded > 0)
                {
                    pnProcInfo = pnProcInfoNeeded;
                    var processInfo = new RM_PROCESS_INFO[pnProcInfo];
                    res = RmGetList(sessionHandle, out pnProcInfoNeeded, ref pnProcInfo, processInfo, out lpdwRebootReasons);
                    if (res == 0 && pnProcInfo > 0)
                    {
                        var proc = processInfo[0];
                        int pid = proc.Process.dwProcessId;
                        string name = proc.strAppName;
                        if (string.IsNullOrWhiteSpace(name))
                        {
                            try
                            {
                                using var p = Process.GetProcessById(pid);
                                name = p.ProcessName;
                            }
                            catch
                            {
                                name = "unknown";
                            }
                        }
                        return (pid, name);
                    }
                }
            }
            catch
            {
                // Ignore and fall through
            }
            finally
            {
                RmEndSession(sessionHandle);
            }

            return (0, "unknown");
        }

        /// <summary>
        /// Identifies paths belonging to legitimate user tools that perform bulk file operations.
        /// These tools (NTLite, UUP dump, DISM offline) extract/modify hundreds of files per second.
        /// The Restart Manager handle scan on every event causes severe contention that stalls them.
        ///
        /// v1.3.10: Added CBS component-store paths and DISM offline servicing paths.
        /// NTLite's feature-disable operation modifies WinSxS, CBS package manifests, and
        /// DISM scratch directories - all of which generate hundreds of events/second that
        /// previously caused the RM scan to stall the feature-disable operation for minutes.
        ///
        /// SECURITY: These paths are still protected by:
        ///   - FileVerdictScanner (hashes every new .exe/.dll against reputation DBs)
        ///   - Process-level monitoring (WMI/ETW detects suspicious process launches)
        ///   - RawDiskAccessMonitor (detects bypass of filesystem layer)
        /// We only skip the per-file Restart Manager scan and telemetry submission here.
        ///
        /// HARDENING: Only skip if the path is NOT inside a Windows system directory.
        /// An attacker cannot abuse this by placing files in these named folders inside System32
        /// because the system directory check fires first and is separate.
        /// </summary>
        private static bool IsUserToolWorkingPath(string pathLower)
        {
            // Never skip live System32/SysWOW64 - those stay fully monitored.
            // NOTE: WinSxS and CBS are excluded below because they are only ever written
            // by TrustedInstaller/DISM/NTLite during OS servicing - not by malware at runtime.
            // The IsTrustedSystemWriter check on System32/SysWOW64 already gates those paths.
            if (pathLower.Contains(@"\windows\system32\") ||
                pathLower.Contains(@"\windows\syswow64\"))
                return false;

            // v1.4.1: User OS-image / debloat tool working directories are ONLY excluded
            // when an active servicing process is running. Without this check, an attacker
            // could create a directory named "\mount\" or "\scratch\" and stage payloads
            // that bypass file monitoring entirely.
            if (pathLower.Contains(@"\ntlite\") ||
                pathLower.Contains(@"\uupdump\") ||
                pathLower.Contains(@"\uup\") ||
                pathLower.Contains(@"\uups\") ||
                pathLower.Contains(@"\msmg\") ||
                pathLower.Contains(@"\mount\") ||
                pathLower.Contains(@"\extracted\") ||
                pathLower.Contains(@"\winpe\") ||
                pathLower.Contains(@"\wim\") ||
                pathLower.Contains(@"\scratch\") ||
                pathLower.Contains(@"\offlineimage\"))
            {
                // Only suppress if a known servicing process is actually running
                if (!IsServicingProcessActive())
                    return false; // No servicing tool running - monitor this path normally
                return true;
            }

            // CBS / Windows component store - written en-masse by DISM and NTLite during
            // feature enable/disable. Generates thousands of manifest/delta/catalog writes
            // per feature operation; RM calls on every event cause minutes-long stalls.
            // These paths are ALWAYS safe to suppress because they live under \Windows\
            // and only TrustedInstaller/DISM can write there (ACLed at filesystem level).
            if (pathLower.Contains(@"\windows\winsxs\") ||
                pathLower.Contains(@"\windows\servicing\") ||
                pathLower.Contains(@"\windows\temp\cab") ||
                pathLower.Contains(@"\windows\temp\dism") ||
                pathLower.Contains(@"\windows\logs\cbs\") ||
                pathLower.Contains(@"\windows\logs\dism\"))
                return true;

            return false;
        }

        /// <summary>
        /// Returns true if a known OS-image servicing process is currently running.
        /// Used to validate that user tool working path exclusions are legitimate.
        /// </summary>
        private static bool IsServicingProcessActive() => ServicingWindow.IsActive();

        /// <summary>
        /// Filters AppData events to only monitor security-relevant activity:
        /// - Executable/script file writes anywhere in AppData (payload drops)
        /// - Any file activity in \Temp\ subdirectories (staging area)
        /// - DLL writes to \Roaming\Microsoft\ (COM hijack, startup persistence)
        /// Everything else (browser caches, app state, GPUCache, logs) is excluded
        /// as it generates thousands of events/second with zero security value.
        /// </summary>
        private static bool IsNoisyAppDataPath(string pathLower)
        {
            // Only apply AppData filtering to AppData paths
            if (!pathLower.Contains(@"\appdata\"))
                return false;

            // ALWAYS monitor: executable/script files anywhere in AppData
            // These are the actual attack vectors (payload drops, DLL sideloading)
            string ext = System.IO.Path.GetExtension(pathLower);
            if (ext == ".exe" || ext == ".dll" || ext == ".sys" || ext == ".bat" ||
                ext == ".cmd" || ext == ".ps1" || ext == ".vbs" || ext == ".js" ||
                ext == ".hta" || ext == ".msi" || ext == ".scr" || ext == ".com" ||
                ext == ".pif" || ext == ".lnk" || ext == ".wsf")
            {
                return false; // Not noisy - monitor this
            }

            // ALWAYS monitor: Temp directories (primary staging area for payloads)
            if (pathLower.Contains(@"\appdata\local\temp\"))
                return false; // Not noisy - monitor this

            // ALWAYS monitor: Startup-related paths
            if (pathLower.Contains(@"\appdata\roaming\microsoft\windows\start menu\"))
                return false;

            // Everything else in AppData is noise (browser state, app caches, GPU shaders, etc.)
            return true;
        }

        private static bool IsProtectedOsDirectory(string pathLower)
        {
            return pathLower.Contains(@"\windows\system32\") ||
                   pathLower.Contains(@"\windows\syswow64\");
        }

        internal bool IsTrustedSystemWriter(int pid, string processName, string filePath)
        {
            // TrustedInstaller (Windows Modules Installer), Windows Update, Defender, DISM, NTLite
            var trustedNames = new[] { "trustedinstaller", "tiworker", "msiexec",
                "wuauclt", "usoclient", "musnotification",
                "msmpeng", "nissrv", "securityhealthservice",
                "dism", "dismhost", "sfc", "poqexec",
                // NTLite performs offline OS servicing (feature removal, component cleanup)
                // and commits changes to mounted WIM images - writes signed MS binaries to System32
                "ntlite",
                // Critical system processes that legitimately modify System32
                "csrss", "smss", "wininit", "services", "lsass", "svchost",
                "lsaiso", "cng key isolation", "credential guard",
                "vbs key protection", "keyiso",
                // Sentinel itself
                "windowssentinel.service", "windowssentinel.agent",
                "windows sentinel" };

            var lowerName = processName.ToLowerInvariant();
            if (trustedNames.Any(t => lowerName.Contains(t))) return true;

            // PID 4 = SYSTEM kernel
            if (pid == 4) return true;

            // If PID is 0 (unresolved process because the handle was closed quickly),
            // only trust it if the file itself is signed by a trusted publisher.
            if (pid == 0)
            {
                for (int i = 0; i < 3; i++)
                {
                    try
                    {
                        if (File.Exists(filePath))
                        {
                            // Catalog-signed system files in System32 won't return signer CN via GetSignerName,
                            // but WinVerifyTrust confirms they chain to a trusted Microsoft root.
                            if (IsProtectedOsDirectory(filePath.ToLowerInvariant()) &&
                                SecurityValidation.VerifyAuthenticodeSignature(filePath))
                            {
                                return true;
                            }

                            if (_signerTrust.IsSignedFile(filePath))
                            {
                                return true;
                            }
                        }
                    }
                    catch { }
                    Thread.Sleep(50);
                }
                return false;
            }

            // Own PID = Sentinel itself writing (e.g., quarantine lock files)
            if (pid == System.Net48Environment.ProcessId) return true;

             // Verify by path - only trust if running from System32/Windows or Defender folder, or if it is signed by Microsoft
             try
             {
                 var imagePath = SecurityValidation.GetProcessImagePath(pid);
                 if (!string.IsNullOrEmpty(imagePath))
                 {
                     if (imagePath!.StartsWith(@"C:\Windows\") ||
                         imagePath.Contains(@"\Windows Defender\") ||
                         imagePath.Contains(@"\Microsoft Security Client\") ||
                         imagePath.Contains(@"\Sentinel\"))
                     {
                         return true;
                     }

                     // Trust any Authenticode-signed Microsoft updater/setup tool running from non-standard paths (e.g. dxsetup.exe from Steam)
                     if (_signerTrust.IsSignedFile(imagePath))
                     {
                         return true;
                     }
                 }
             }
             catch (System.ComponentModel.Win32Exception)
             {
                 // Access denied - likely a protected system process (csrss, smss, lsass)
                 // If we can't read it but it has a system-like name, trust it
                 return lowerName == "system" || pid <= 4;
             }
             catch { }
 
             return false;
         }

        public void Dispose()
        {
            foreach (var watcher in _watchers)
            {
                try
                {
                    watcher.EnableRaisingEvents = false;
                    watcher.Dispose();
                }
                catch { }
            }
            _watchers.Clear();
        }
    }
}
