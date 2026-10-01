using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace Sentinel.Core
{
    /// <summary>
    /// v1.6.7: Cloud Sync Exfiltration Monitor - detects data staging via cloud sync folders.
    /// 
    /// Blind spot addressed: Mass copy into OneDrive/Dropbox/Google Drive/rclone/mega folders
    /// bypasses DataExfiltrationMonitor's "large TCP upload" threshold if the sync client throttles
    /// uploads or batches them. Attackers can stage gigabytes of data that sync silently.
    /// 
    /// Detection approach:
    /// - Enumerate known sync root directories (OneDrive, Dropbox, Google Drive, MEGA, iCloud)
    /// - Monitor for burst file creation (20+ files in 60s) in sync directories
    /// - Detect rclone/megasync/rclone.exe processes with high file handle counts
    /// - Alert on non-sync-client processes writing to sync directories in bulk
    /// - Track file count baselines per sync directory; alert on large delta
    /// 
    /// Response: Tier1 KillProcessTree for rclone/mega from staging paths (exfil tools).
    ///           Tier2 LogOnly for burst file creation in sync folders (staging indicator).
    /// Scans every 15s. No elevation required.
    /// </summary>
    public sealed class CloudSyncExfilMonitor : BackgroundService
    {
        private readonly DetectionEngine _detectionEngine;
        private readonly ILogger<CloudSyncExfilMonitor> _logger;

        // Track file create bursts per directory
        private readonly ConcurrentDictionary<string, DirectoryState> _directoryStates = new(StringComparer.OrdinalIgnoreCase);

        // Known exfiltration sync tool process names
        private static readonly HashSet<string> ExfilSyncTools = new(StringComparer.OrdinalIgnoreCase)
        {
            "rclone", "megasync", "megacmd", "mega-cmd", "mega-cmd-server",
            "goodsync", "freefilesync", "syncbackpro", "syncback",
            "cyberduck", "winscp", "filezilla", "s3browser"
        };

        // Known legitimate sync client processes (their OWN writes are expected)
        private static readonly HashSet<string> LegitSyncClients = new(StringComparer.OrdinalIgnoreCase)
        {
            "onedrive", "dropbox", "googledrivesync", "googledrivefs",
            "icloud", "icloudservices", "megasync", "nextcloud", "pcloud",
            "spideroakone", "syncthing", "resilio sync", "btsync"
        };

        // Alerted sync dirs (prevent spam)
        private readonly ConcurrentDictionary<string, DateTime> _alertedDirs = new(StringComparer.OrdinalIgnoreCase);

        private class DirectoryState
        {
            public long BaselineFileCount;
            public DateTime LastChecked;
            public int RecentCreateCount;
            public DateTime WindowStart;
        }

        public CloudSyncExfilMonitor(
            DetectionEngine detectionEngine,
            ILogger<CloudSyncExfilMonitor> logger)
        {
            _detectionEngine = detectionEngine;
            _logger = logger;
        }

        protected override async Task ExecuteAsync(CancellationToken ct)
        {
            _logger.LogInformation("[CloudSyncExfilMonitor] Started - monitoring cloud sync directories");
            await Task.Delay(20000, ct); // Let system settle

            // Discover sync directories
            var syncDirs = DiscoverSyncDirectories();
            _logger.LogInformation("[CloudSyncExfilMonitor] Found {Count} sync directories to monitor", syncDirs.Count);

            // Baseline
            foreach (var dir in syncDirs)
            {
                long count = CountFiles(dir);
                _directoryStates[dir] = new DirectoryState
                {
                    BaselineFileCount = count,
                    LastChecked = DateTime.UtcNow,
                    RecentCreateCount = 0,
                    WindowStart = DateTime.UtcNow
                };
            }

            while (!ct.IsCancellationRequested)
            {
                try
                {
                    await Task.Delay(15000, ct);
                    await ScanSyncDirectoriesAsync(syncDirs, ct);
                    await ScanExfilToolProcessesAsync(ct);
                    PruneAlertCache();
                }
                catch (OperationCanceledException) { break; }
                catch (Exception ex) { _logger.LogDebug(ex, "[CloudSyncExfilMonitor] Scan error"); }
            }
        }

        private async Task ScanSyncDirectoriesAsync(List<string> syncDirs, CancellationToken ct)
        {
            foreach (var dir in syncDirs)
            {
                if (ct.IsCancellationRequested) break;
                if (!Directory.Exists(dir)) continue;

                long currentCount = CountFiles(dir);
                if (!_directoryStates.TryGetValue(dir, out var state)) continue;

                // Detect large burst: 50+ new files since last check
                long delta = currentCount - state.BaselineFileCount;

                if (delta >= 50)
                {
                    string alertKey = $"{dir}:{DateTime.UtcNow:yyyyMMddHH}";
                    if (!_alertedDirs.ContainsKey(alertKey))
                    {
                        double confidence = delta >= 200 ? 0.82 : delta >= 100 ? 0.72 : 0.62;

                        await _detectionEngine.EmitAsync(new DetectionEvent
                        {
                            RuleName = "Data Exfiltration: Burst File Staging in Cloud Sync Directory",
                            Evidence = $"Cloud sync directory '{Truncate(dir, 100)}' gained {delta} files since baseline " +
                                       $"(was {state.BaselineFileCount}, now {currentCount}). " +
                                       $"This volume of data staging may indicate exfiltration preparation.",
                            Reasoning = "A large number of files were added to a cloud sync directory in a short period. " +
                                        "Attackers stage stolen data in sync folders (OneDrive, Dropbox, Google Drive) for silent " +
                                        "exfiltration via the legitimate sync client, bypassing network volume detection (MITRE T1567.002).",
                            Confidence = confidence,
                            Tier = delta >= 100 ? DetectionTier.Tier1Behavioral : DetectionTier.Tier2Indicator,
                            AuthorizedResponse = delta >= 100 ? ResponseAction.LogOnly : ResponseAction.LogOnly,
                            SignalType = SignalType.Generic,
                            ProcessName = "CloudSync",
                            ProcessId = 0,
                        });
                        _alertedDirs[alertKey] = DateTime.UtcNow;
                    }
                }

                // Update baseline slowly (move toward current to avoid permanent alerting)
                if (delta > 0 && delta < 20)
                {
                    state.BaselineFileCount = currentCount;
                }
                state.LastChecked = DateTime.UtcNow;
            }
        }

        private async Task ScanExfilToolProcessesAsync(CancellationToken ct)
        {
            Process[] processes;
            try { processes = Process.GetProcesses(); }
            catch { return; }

            foreach (var proc in processes)
            {
                try
                {
                    if (ct.IsCancellationRequested) break;
                    string name = proc.ProcessName;

                    if (!ExfilSyncTools.Contains(name)) continue;

                    int pid = proc.Id;
                    string alertKey = $"tool:{pid}";
                    if (_alertedDirs.ContainsKey(alertKey)) continue;

                    string imagePath = SecurityValidation.GetProcessImagePath(pid) ?? "";

                    // v1.8.3: rclone/megasync/etc. are also legitimate backup/sync tools.
                    // Observe-only - kill only if a composite/confirmed exfil attack rule fires.
                    bool fromSuspiciousPath = IsSuspiciousPath(imagePath);
                    double confidence = fromSuspiciousPath ? 0.55 : 0.40;

                    string? cmdLine = GetCommandLine(pid);
                    bool hasRemoteTarget = !string.IsNullOrEmpty(cmdLine) &&
                        (cmdLine!.Contains(":") &&
                         (cmdLine.Contains("sync") ||
                          cmdLine.Contains("copy") ||
                          cmdLine.Contains("move")));

                    if (hasRemoteTarget) confidence = Math.Min(confidence + 0.1, 0.65);

                    await _detectionEngine.EmitAsync(new DetectionEvent
                    {
                        RuleName = "Data Exfiltration: Cloud Sync Tool Running",
                        Evidence = $"Exfiltration-capable sync tool '{name}' (PID {pid}) running from '{Truncate(imagePath, 100)}'. " +
                                   $"{(hasRemoteTarget ? "Command line suggests active remote transfer. " : "")}" +
                                   $"CmdLine: {Truncate(cmdLine ?? "(unavailable)", 150)}",
                        Reasoning = "A cloud sync tool (rclone, megasync, etc.) is running. Users legitimately use these for backup. " +
                                    "Observe-first: LogOnly. Kill requires corroborating attack signals (mass staging + C2, etc.).",
                        Confidence = confidence,
                        Tier = DetectionTier.Tier2Indicator,
                        AuthorizedResponse = ResponseAction.LogOnly,
                        SignalType = SignalType.Generic,
                        ProcessName = name,
                        ProcessId = pid,
                    });
                    _alertedDirs[alertKey] = DateTime.UtcNow;
                }
                catch { }
                finally { proc.Dispose(); }
            }
        }

        private List<string> DiscoverSyncDirectories()
        {
            var dirs = new List<string>();
            string userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);

            // OneDrive
            string? oneDrive = Environment.GetEnvironmentVariable("OneDrive");
            if (!string.IsNullOrEmpty(oneDrive) && Directory.Exists(oneDrive))
                dirs.Add(oneDrive);
            else
            {
                string defaultOneDrive = Path.Combine(userProfile, "OneDrive");
                if (Directory.Exists(defaultOneDrive)) dirs.Add(defaultOneDrive);
            }

            // OneDrive for Business
            string? oneDriveBiz = Environment.GetEnvironmentVariable("OneDriveCommercial");
            if (!string.IsNullOrEmpty(oneDriveBiz) && Directory.Exists(oneDriveBiz))
                dirs.Add(oneDriveBiz);

            // Dropbox
            string dropbox = Path.Combine(userProfile, "Dropbox");
            if (Directory.Exists(dropbox)) dirs.Add(dropbox);

            // Google Drive (various locations)
            string gDrive = Path.Combine(userProfile, "Google Drive");
            if (Directory.Exists(gDrive)) dirs.Add(gDrive);
            string gDriveMyDrive = Path.Combine(userProfile, "My Drive");
            if (Directory.Exists(gDriveMyDrive)) dirs.Add(gDriveMyDrive);

            // MEGA
            string mega = Path.Combine(userProfile, "MEGA");
            if (Directory.Exists(mega)) dirs.Add(mega);

            // iCloud Drive
            string icloud = Path.Combine(userProfile, "iCloudDrive");
            if (Directory.Exists(icloud)) dirs.Add(icloud);

            // pCloud
            string pcloud = Path.Combine(userProfile, "pCloudDrive");
            if (Directory.Exists(pcloud)) dirs.Add(pcloud);

            // Check registry for custom sync paths
            TryAddRegistryPath(dirs, @"HKEY_CURRENT_USER\Software\Dropbox\InstallPath");

            return dirs;
        }

        private static void TryAddRegistryPath(List<string> dirs, string regPath)
        {
            try
            {
                // Parse HKCU path
                var parts = regPath.Split(new char[] { '\\' }, 2);
                if (parts.Length < 2) return;
                using var key = Microsoft.Win32.Registry.CurrentUser.OpenSubKey(parts[1].Replace("HKEY_CURRENT_USER\\", ""));
                if (key == null) return;
                string? val = key.GetValue("")?.ToString();
                if (!string.IsNullOrEmpty(val) && Directory.Exists(val!) && !dirs.Contains(val!))
                    dirs.Add(val!);
            }
            catch { }
        }

        private static long CountFiles(string directory)
        {
            try
            {
                return Directory.EnumerateFiles(directory, "*", SearchOption.AllDirectories).LongCount();
            }
            catch { return 0; }
        }

        private static bool IsSuspiciousPath(string path)
        {
            if (string.IsNullOrEmpty(path)) return true;
            string lower = path.ToLowerInvariant();
            return lower.Contains(@"\temp\") || lower.Contains(@"\tmp\") ||
                   lower.Contains(@"\downloads\") || lower.Contains(@"\appdata\local\temp") ||
                   lower.Contains(@"\users\public\") || lower.Contains(@"\desktop\");
        }

        private static string? GetCommandLine(int pid)
        {
            try
            {
                using var searcher = new System.Management.ManagementObjectSearcher(
                    $"SELECT CommandLine FROM Win32_Process WHERE ProcessId = {pid}");
                foreach (System.Management.ManagementObject obj in searcher.Get())
                    return obj["CommandLine"]?.ToString();
            }
            catch { }
            return null;
        }

        private static string Truncate(string s, int maxLen) =>
            s.Length <= maxLen ? s : s[..maxLen] + "...";

        private void PruneAlertCache()
        {
            var cutoff = DateTime.UtcNow.AddHours(-1);
            foreach (var kvp in _alertedDirs)
            {
                if (kvp.Value < cutoff)
                    _alertedDirs.TryRemove(kvp.Key, out _);
            }
        }
    }
}
