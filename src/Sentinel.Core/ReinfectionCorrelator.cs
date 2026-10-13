using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace Sentinel.Core
{
    /// <summary>
    /// Tracks hashes of binaries that were previously killed or quarantined.
    /// If the same hash reappears on disk or in a running process after a reboot
    /// (or after cleanup), it indicates persistent malware with distributed
    /// self-healing - e.g., copies in pagefile, recycle bin, router, secondary drives.
    /// 
    /// Detection: Tier1 with KillProcessTree + quarantine. Emits high-confidence alert
    /// because the binary has already been confirmed malicious by a prior action.
    /// </summary>
    public sealed class ReinfectionCorrelator : BackgroundService
    {
        private readonly DetectionEngine _detectionEngine;
        private readonly ILogger<ReinfectionCorrelator> _logger;

        // Hashes we have killed/quarantined - loaded from quarantine dir + kill log
        private readonly ConcurrentDictionary<string, KilledEntry> _killedHashes = new(StringComparer.OrdinalIgnoreCase);

        // Track what we've already alerted on to avoid spam
        private readonly ConcurrentDictionary<string, DateTime> _alertedHashes = new(StringComparer.OrdinalIgnoreCase);

        // Paths to scan for reappearance (high-value persistence locations)
        private static readonly string[] PersistencePaths = new[]
        {
            @"$Recycle.Bin",
            @"System Volume Information",
            @"ProgramData",
            @"Windows\Temp",
        };

        // File where we persist killed hashes across reboots (complementary to quarantine dir)
        private static readonly string KillLogPath = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
            "Sentinel", "killed_hashes.log");

        private record KilledEntry(string OriginalPath, string ProcessName, DateTime KilledAt);

        public ReinfectionCorrelator(
            DetectionEngine detectionEngine,
            ILogger<ReinfectionCorrelator> logger)
        {
            _detectionEngine = detectionEngine;
            _logger = logger;
        }

        /// <summary>
        /// Called by AdvancedResponseEngine after a successful kill to register the hash.
        /// Excludes Windows system binaries to prevent false positives when the response
        /// engine mistakenly hashes a service host process instead of the actual malware.
        /// </summary>
        public void RegisterKilledHash(string hash, string imagePath, string processName)
        {
            if (string.IsNullOrEmpty(hash)) return;
            if (IsWindowsSystemBinary(imagePath) || IsWindowsSystemBinary(processName)) return;

            _killedHashes[hash] = new KilledEntry(imagePath, processName, DateTime.UtcNow);

            // Persist to kill log for cross-reboot tracking
            try
            {
                var dir = Path.GetDirectoryName(KillLogPath);
                if (dir != null && !Directory.Exists(dir)) Directory.CreateDirectory(dir);
                File.AppendAllText(KillLogPath, $"{hash}|{processName}|{imagePath}|{DateTime.UtcNow:O}\n");
            }
            catch { }
        }

        /// <summary>
        /// Windows system binaries that must NEVER be tracked as "killed malware".
        /// If the response engine kills a process hosted in svchost.exe or other system
        /// binaries, we must not register that hash - it would cause every svchost instance
        /// on the system to trigger reinfection alerts.
        /// </summary>
        private static readonly HashSet<string> SystemBinaryNames = new(StringComparer.OrdinalIgnoreCase)
        {
            "svchost", "svchost.exe",
            "csrss", "csrss.exe",
            "wininit", "wininit.exe",
            "winlogon", "winlogon.exe",
            "lsass", "lsass.exe",
            "services", "services.exe",
            "smss", "smss.exe",
            "dwm", "dwm.exe",
            "explorer", "explorer.exe",
            "conhost", "conhost.exe",
            "taskhostw", "taskhostw.exe",
            "sihost", "sihost.exe",
            "RuntimeBroker", "RuntimeBroker.exe",
            "dllhost", "dllhost.exe",
            "spoolsv", "spoolsv.exe",
            "SearchHost", "SearchHost.exe",
            "ShellExperienceHost", "ShellExperienceHost.exe",
            "StartMenuExperienceHost", "StartMenuExperienceHost.exe",
            "SecurityHealthService", "SecurityHealthService.exe",
            "MsMpEng", "MsMpEng.exe",
            "WmiPrvSE", "WmiPrvSE.exe",
            "wuauclt", "wuauclt.exe",
            "TrustedInstaller", "TrustedInstaller.exe",
            // v2.9.3: Windows Update / Unified Update Stack workers. These restart
            // automatically after any kill, so registering their hash caused a reinfection
            // storm (MoUsoCoreWorker killed -> Windows Update relaunches -> "reinfection").
            "MoUsoCoreWorker", "MoUsoCoreWorker.exe",
            "usocoreworker", "usocoreworker.exe",
            "usoclient", "usoclient.exe",
            "sedsvc", "sedsvc.exe",
            "WaaSMedicAgent", "WaaSMedicAgent.exe",
            "mscorsvw", "mscorsvw.exe",
            "ngen", "ngen.exe",
            "ngentask", "ngentask.exe",
        };

        private static bool IsWindowsSystemBinary(string? pathOrName)
        {
            if (string.IsNullOrEmpty(pathOrName)) return false;

            // Check by name
            var fileName = Path.GetFileName(pathOrName);
            if (SystemBinaryNames.Contains(fileName)) return true;
            var nameNoExt = Path.GetFileNameWithoutExtension(pathOrName);
            if (SystemBinaryNames.Contains(nameNoExt)) return true;

            // Check by path - anything in Windows\System32 or Windows\SysWOW64 is a system binary
            var normalized = pathOrName!.Replace('/', '\\');
            if (normalized.IndexOf(@"\Windows\System32\", StringComparison.OrdinalIgnoreCase) >= 0 ||
                normalized.IndexOf(@"\Windows\SysWOW64\", StringComparison.OrdinalIgnoreCase) >= 0 ||
                normalized.IndexOf(@"\Windows\WinSxS\", StringComparison.OrdinalIgnoreCase) >= 0 ||
                // v2.9.3: Unified Update Stack + servicing stack are OS-owned, non-user-writable
                normalized.IndexOf(@"\Windows\UUS\", StringComparison.OrdinalIgnoreCase) >= 0 ||
                normalized.IndexOf(@"\Windows\servicing\", StringComparison.OrdinalIgnoreCase) >= 0 ||
                normalized.IndexOf(@"\Windows\Microsoft.NET\Framework64\", StringComparison.OrdinalIgnoreCase) >= 0 ||
                normalized.IndexOf(@"\Windows\Microsoft.NET\Framework\", StringComparison.OrdinalIgnoreCase) >= 0)
                return true;

            return false;
        }

        /// <summary>
        /// v2.5.5: Skip processes at protected install paths - Program Files, WindowsApps,
        /// Chrome, Edge, dotnet. These ship DLLs whose hashes may collide with quarantined
        /// copies and trigger false reinfection storms.
        /// </summary>
        private static bool IsProtectedInstallPath(string? path)
        {
            if (string.IsNullOrEmpty(path)) return false;
            var n = path!.Replace('/', '\\');
            return n.Contains(@"\Program Files\")
                || n.Contains(@"\Program Files (x86)\")
                || n.Contains(@"\WindowsApps\")
                || n.Contains(@"\Google\Chrome\")
                || n.Contains(@"\Microsoft\Edge\")
                || n.Contains(@"\dotnet\");
        }

        protected override async Task ExecuteAsync(CancellationToken ct)
        {
            _logger.LogInformation("[ReinfectionCorrelator] Started - loading quarantine history and kill log");

            // Load all previously quarantined hashes as known-bad
            LoadQuarantineHistory();
            LoadKillLog();

            // Wait for system to stabilize after boot
            await Task.Delay(30000, ct);

            while (!ct.IsCancellationRequested)
            {
                try
                {
                    await Task.Delay(60000, ct); // Scan every 60 seconds

                    if (_killedHashes.IsEmpty) continue;

                    // 1. Check running processes for known-bad hashes
                    await ScanRunningProcessesAsync(ct);

                    // 2. Scan high-value persistence directories on all drives
                    await ScanPersistenceLocationsAsync(ct);

                    // Prune old alerts (re-alert after 1 hour if still reappearing)
                    var cutoff = DateTime.UtcNow.AddHours(-1);
                    foreach (var kvp in _alertedHashes)
                    {
                        if (kvp.Value < cutoff)
                            _alertedHashes.TryRemove(kvp.Key, out _);
                    }
                }
                catch (OperationCanceledException) { break; }
                catch (Exception ex) { _logger.LogDebug(ex, "[ReinfectionCorrelator] Error"); }
            }
        }

        private void LoadQuarantineHistory()
        {
            try
            {
                var quarantineDir = Path.Combine(
                    Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
                    "Sentinel", "Quarantine");

                if (!Directory.Exists(quarantineDir)) return;

                foreach (var file in Directory.GetFiles(quarantineDir))
                {
                    var name = Path.GetFileNameWithoutExtension(file);
                    // Format: q_{sha256hash}_{originalname}
                    if (name.StartsWith("q_") && name.Length > 66)
                    {
                        var hash = name.Substring(2, 64); // SHA256 = 64 hex chars
                        var originalName = name.Length > 67 ? name.Substring(67) : "unknown";
                        // v2.5.5: Only seed the reinfection table with executable types.
                        // DLL quarantines must not - Chrome/Edge bundle DLLs whose hash
                        // matches a quarantined copy and that caused a reinfection storm
                        // (324 quarantine entries, 150 responses in 15 minutes).
                        var ext = System.IO.Path.GetExtension(originalName).ToLowerInvariant();
                        if (ext != ".exe" && ext != ".com" && ext != ".scr") continue;
                        _killedHashes.TryAdd(hash, new KilledEntry("quarantine", originalName, File.GetCreationTimeUtc(file)));
                    }
                }

                _logger.LogInformation("[ReinfectionCorrelator] Loaded {Count} hashes from quarantine history",
                    _killedHashes.Count);
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "[ReinfectionCorrelator] Failed to load quarantine history");
            }
        }

        private void LoadKillLog()
        {
            try
            {
                if (!File.Exists(KillLogPath)) return;
                foreach (var line in File.ReadAllLines(KillLogPath))
                {
                    var parts = line.Split('|');
                    if (parts.Length >= 4)
                    {
                        var hash = parts[0];
                        var procName = parts[1];
                        var path = parts[2];
                        DateTime.TryParse(parts[3], out var killedAt);

                        // Skip system binaries that were incorrectly logged
                        if (IsWindowsSystemBinary(path) || IsWindowsSystemBinary(procName))
                            continue;

                        _killedHashes.TryAdd(hash, new KilledEntry(path, procName, killedAt));
                    }
                }
                _logger.LogInformation("[ReinfectionCorrelator] Loaded {Count} total tracked hashes", _killedHashes.Count);
            }
            catch { }
        }

        private async Task ScanRunningProcessesAsync(CancellationToken ct)
        {
            foreach (var proc in Process.GetProcesses())
            {
                if (ct.IsCancellationRequested) break;
                try
                {
                    if (proc.Id <= 4) continue;
                    string? imagePath = null;
                    try { imagePath = SecurityValidation.GetProcessImagePath(proc.Id); } catch { }
                    if (string.IsNullOrEmpty(imagePath) || !File.Exists(imagePath)) continue;

                    // Never alert on Windows system binaries or protected install paths
                    if (IsWindowsSystemBinary(imagePath)) continue;
                    if (IsProtectedInstallPath(imagePath)) continue;

                    var hash = ComputeFileHash(imagePath!);
                    if (hash == null) continue;

                    if (_killedHashes.TryGetValue(hash, out var entry))
                    {
                        var alertKey = $"{hash}_{proc.Id}";
                        if (_alertedHashes.ContainsKey(alertKey)) continue;
                        _alertedHashes[alertKey] = DateTime.UtcNow;

                        await _detectionEngine.EmitAsync(new DetectionEvent
                        {
                            RuleName = "Reinfection: Previously Killed Binary Reappeared in Running Process",
                            Evidence = $"Process '{proc.ProcessName}' (PID {proc.Id}) at '{imagePath}' " +
                                       $"matches previously killed/quarantined hash {hash[..16]}... " +
                                       $"(originally '{entry.ProcessName}' at '{entry.OriginalPath}', killed at {entry.KilledAt:O})",
                            Reasoning = "A binary that was previously identified as malicious and killed/quarantined has reappeared " +
                                        "in a running process. This indicates persistent malware with distributed self-healing - " +
                                        "copies likely exist in pagefile, Recycle Bin, System Volume Information, secondary drives, " +
                                        "or are being pushed from an infected router. All persistence vectors must be cleaned simultaneously.",
                            Confidence = 0.95,
                            Tier = DetectionTier.Tier1Behavioral,
                            AuthorizedResponse = ResponseAction.KillProcessTree,
                            SignalType = SignalType.SecurityEvasion,
                            ProcessName = proc.ProcessName,
                            ProcessId = proc.Id,
                            Metadata = new Dictionary<string, string>
                            {
                                ["SHA256"] = hash,
                                ["CurrentPath"] = imagePath!,
                                ["OriginalPath"] = entry.OriginalPath,
                                ["OriginalProcessName"] = entry.ProcessName,
                                ["KilledAt"] = entry.KilledAt.ToString("O"),
                                ["ReinfectionType"] = "ProcessReappearance"
                            }
                        });
                    }
                }
                catch { }
                finally { proc.Dispose(); }
            }
        }

        private async Task ScanPersistenceLocationsAsync(CancellationToken ct)
        {
            // Scan all drive roots for known-bad hashes in persistence locations
            foreach (var drive in DriveInfo.GetDrives())
            {
                if (ct.IsCancellationRequested) break;
                if (!drive.IsReady || drive.DriveType == DriveType.CDRom || drive.DriveType == DriveType.Network)
                    continue;

                foreach (var subPath in PersistencePaths)
                {
                    if (ct.IsCancellationRequested) break;
                    var fullPath = Path.Combine(drive.RootDirectory.FullName, subPath);
                    if (!Directory.Exists(fullPath)) continue;

                    try
                    {
                        var files = Directory.EnumerateFiles(fullPath, "*.*", SearchOption.AllDirectories)
                            .Where(f => IsExecutableExtension(Path.GetExtension(f)))
                            .Take(500); // Cap per-directory to avoid performance issues

                        foreach (var file in files)
                        {
                            if (ct.IsCancellationRequested) break;
                            try
                            {
                                var hash = ComputeFileHash(file);
                                if (hash == null) continue;

                                if (_killedHashes.TryGetValue(hash, out var entry))
                                {
                                    var alertKey = $"file_{hash}_{file}";
                                    if (_alertedHashes.ContainsKey(alertKey)) continue;
                                    _alertedHashes[alertKey] = DateTime.UtcNow;

                                    await _detectionEngine.EmitAsync(new DetectionEvent
                                    {
                                        RuleName = "Reinfection: Known-Bad Binary Found in Persistence Location",
                                        Evidence = $"File '{file}' matches previously killed/quarantined hash {hash[..16]}... " +
                                                   $"(originally '{entry.ProcessName}' killed at {entry.KilledAt:O})",
                                        Reasoning = "A copy of a previously killed/quarantined malicious binary was found in a " +
                                                    "persistence location (Recycle Bin, System Volume Information, Temp, etc.). " +
                                                    "This is a dormant reinfection vector - it will execute on reboot, scheduled task, " +
                                                    "or watchdog trigger unless removed simultaneously with all other copies.",
                                        Confidence = 0.92,
                                        Tier = DetectionTier.Tier1Behavioral,
                                        AuthorizedResponse = ResponseAction.Quarantine,
                                        SignalType = SignalType.SecurityEvasion,
                                        ProcessName = "SYSTEM",
                                        ProcessId = 0,
                                        Metadata = new Dictionary<string, string>
                                        {
                                            ["SHA256"] = hash,
                                            ["FilePath"] = file,
                                            ["OriginalProcessName"] = entry.ProcessName,
                                            ["OriginalPath"] = entry.OriginalPath,
                                            ["KilledAt"] = entry.KilledAt.ToString("O"),
                                            ["ReinfectionType"] = "DormantCopy"
                                        }
                                    });
                                }
                            }
                            catch { }
                        }
                    }
                    catch { }
                }
            }
        }

        private static string? ComputeFileHash(string path)
        {
            try
            {
                using var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                // Skip files larger than 100MB to avoid performance issues
                if (fs.Length > 100 * 1024 * 1024) return null;
                var hashBytes = System.Security.Cryptography.Sha256Net48.HashData(fs);
                return ConvertHex.ToHexString(hashBytes).ToLowerInvariant();
            }
            catch { return null; }
        }

        private static bool IsExecutableExtension(string ext)
        {
            return ext.Equals(".exe") ||
                   ext.Equals(".dll") ||
                   ext.Equals(".scr") ||
                   ext.Equals(".com") ||
                   ext.Equals(".bat") ||
                   ext.Equals(".cmd") ||
                   ext.Equals(".ps1") ||
                   ext.Equals(".vbs") ||
                   ext.Equals(".js");
        }
    }
}
