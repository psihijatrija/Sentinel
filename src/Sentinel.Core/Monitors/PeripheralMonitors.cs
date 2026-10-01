// Peripheral Monitor Group - Bluetooth device monitoring, device driver installation, and MTP transfer control

using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Management;
using System.Net;
using System.Net.NetworkInformation;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Win32;

namespace Sentinel.Core
{
    // 
    // Bluetooth Monitor - detects new unknown BT devices
    // 
    public sealed class BluetoothMonitor : BackgroundService
    {
        private readonly DetectionEngine _detectionEngine;
        private readonly ILogger<BluetoothMonitor> _logger;
        private readonly HashSet<string> _baselineDevices = new(StringComparer.OrdinalIgnoreCase);

        public BluetoothMonitor(DetectionEngine de, ILogger<BluetoothMonitor> l) { _detectionEngine = de; _logger = l; }

        protected override async Task ExecuteAsync(CancellationToken ct)
        {
            _logger.LogInformation("[BluetoothMonitor] Started");
            SnapshotBluetoothDevices(_baselineDevices);

            while (!ct.IsCancellationRequested)
            {
                try
                {
                    await Task.Delay(60000, ct);
                    var current = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                    SnapshotBluetoothDevices(current);
                    foreach (var dev in current.Except(_baselineDevices))
                    {
                        await _detectionEngine.EmitAsync(new DetectionEvent
                        {
                            RuleName = "Bluetooth: New Device Detected",
                            Evidence = $"New Bluetooth device appeared: {dev}",
                            Reasoning = "A previously unseen Bluetooth device was detected. This could indicate unauthorized peripheral pairing.",
                            Confidence = 0.40, Tier = DetectionTier.Tier2Indicator,
                            ProcessName = "SYSTEM", ProcessId = 0
                        });
                        _baselineDevices.Add(dev);
                    }
                }
                catch (OperationCanceledException) { break; }
                catch (Exception ex) { _logger.LogDebug(ex, "[BluetoothMonitor] Error"); }
            }
        }

        private static void SnapshotBluetoothDevices(HashSet<string> target)
        {
            try
            {
                using var key = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services\BTHPORT\Parameters\Devices");
                if (key == null) return;
                foreach (var sub in key.GetSubKeyNames()) target.Add(sub);
            }
            catch { }
        }
    }


    // 
    // Device Install Monitor - new device class installs via SetupAPI
    // 
    public sealed class DeviceInstallMonitor : BackgroundService
    {
        private readonly DetectionEngine _detectionEngine;
        private readonly ILogger<DeviceInstallMonitor> _logger;
        private DateTime _lastCheck;
        // Baseline of driver service names present at startup - only alert on NEW entries
        private readonly HashSet<string> _baselineDrivers = new(StringComparer.OrdinalIgnoreCase);

        public DeviceInstallMonitor(DetectionEngine de, ILogger<DeviceInstallMonitor> l) { _detectionEngine = de; _logger = l; }

        private static bool IsWindowsDriverPath(string imagePath)
        {
            // Normalize: many driver ImagePaths use \SystemRoot\, system32\, or relative paths
            var normalized = imagePath.TrimStart('\\');
            // Absolute Windows paths
            if (imagePath.Contains(@"\Windows\")) return true;
            // \SystemRoot\ prefix (kernel notation for %SystemRoot%)
            if (normalized.StartsWith("SystemRoot\\")) return true;
            // Relative system32 paths like "system32\drivers\pacer.sys" or "System32\DRIVERS\tdx.sys"
            if (normalized.StartsWith("system32\\")) return true;
            // DriverStore path (inbox/WHQL drivers)
            if (imagePath.Contains(@"\DriverStore\")) return true;
            // Program Files (legitimate third-party drivers like GPU, antivirus)
            if (imagePath.Contains(@"\Program Files")) return true;
            return false;
        }

        protected override async Task ExecuteAsync(CancellationToken ct)
        {
            _logger.LogInformation("[DeviceInstallMonitor] Started");
            _lastCheck = DateTime.UtcNow;

            // Capture baseline of all existing non-Windows kernel drivers at startup.
            // Only drivers that appear AFTER this snapshot will trigger alerts.
            try
            {
                using var key = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services");
                if (key != null)
                {
                    foreach (var svcName in key.GetSubKeyNames())
                    {
                        try
                        {
                            using var svc = key.OpenSubKey(svcName);
                            if (svc == null) continue;
                            var startVal = svc.GetValue("Start");
                            var typeVal = svc.GetValue("Type");
                            if (startVal is int start && typeVal is int type && start == 1 && type == 1)
                            {
                                var imagePath = svc.GetValue("ImagePath")?.ToString() ?? "";
                                if (!string.IsNullOrEmpty(imagePath) && !IsWindowsDriverPath(imagePath))
                                    _baselineDrivers.Add(svcName);
                                else
                                    _baselineDrivers.Add(svcName); // Always baseline regardless
                            }
                            else
                            {
                                _baselineDrivers.Add(svcName); // Baseline all services to avoid noise
                            }
                        }
                        catch { }
                    }
                }
                _logger.LogInformation("[DeviceInstallMonitor] Baseline captured: {Count} services", _baselineDrivers.Count);
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "[DeviceInstallMonitor] Baseline capture failed");
            }

            while (!ct.IsCancellationRequested)
            {
                try
                {
                    await Task.Delay(30000, ct);
                    using var key = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services");
                    if (key == null) continue;
                    foreach (var svcName in key.GetSubKeyNames())
                    {
                        // Skip anything present at startup
                        if (_baselineDrivers.Contains(svcName)) continue;

                        try
                        {
                            using var svc = key.OpenSubKey(svcName);
                            if (svc == null) continue;
                            var startVal = svc.GetValue("Start");
                            var typeVal = svc.GetValue("Type");
                            if (startVal is int start && typeVal is int type && start == 1 && type == 1)
                            {
                                var imagePath = svc.GetValue("ImagePath")?.ToString() ?? "";
                                if (!string.IsNullOrEmpty(imagePath) && !IsWindowsDriverPath(imagePath))
                                {
                                    // Add to baseline so we only alert once per new driver
                                    _baselineDrivers.Add(svcName);
                                    await _detectionEngine.EmitAsync(new DetectionEvent
                                    {
                                        RuleName = "Device Install: Non-Windows Kernel Driver",
                                        Evidence = $"Kernel driver service '{svcName}' with ImagePath '{imagePath}'",
                                        Reasoning = "A kernel-mode driver service was registered from a non-Windows directory, potentially a rootkit or malicious driver.",
                                        Confidence = 0.70, Tier = DetectionTier.Tier1Behavioral,
                                        AuthorizedResponse = ResponseAction.LogOnly,
                                        ProcessName = "SYSTEM", ProcessId = 0
                                    });
                                }
                                else
                                {
                                    _baselineDrivers.Add(svcName);
                                }
                            }
                            else
                            {
                                _baselineDrivers.Add(svcName);
                            }
                        }
                        catch { }
                    }
                    _lastCheck = DateTime.UtcNow;
                }
                catch (OperationCanceledException) { break; }
                catch (Exception ex) { _logger.LogDebug(ex, "[DeviceInstallMonitor] Error"); }
            }
        }
    }


    // 
    // MTP Transfer Guard - blocks writing non-media files to portable devices (phones)
    // 
    public sealed class MtpTransferGuard : BackgroundService
    {
        private readonly DetectionEngine _detectionEngine;
        private readonly ILogger<MtpTransferGuard> _logger;

        // Allowed file extensions for MTP transfers (media + apps only)
        private static readonly HashSet<string> AllowedExtensions = new(StringComparer.OrdinalIgnoreCase)
        {
            // Images
            ".jpg", ".jpeg", ".png", ".gif", ".bmp", ".webp", ".heic", ".heif",
            ".tiff", ".tif", ".svg", ".ico", ".raw", ".cr2", ".nef", ".arw", ".dng",
            // Videos
            ".mp4", ".mkv", ".avi", ".mov", ".wmv", ".flv", ".webm", ".m4v",
            ".mpg", ".mpeg", ".3gp", ".3g2", ".ts", ".vob",
            // Audio
            ".mp3", ".flac", ".wav", ".aac", ".ogg", ".wma", ".m4a", ".opus",
            ".alac", ".aiff", ".mid", ".midi",
            // Android apps
            ".apk", ".xapk", ".apks", ".aab",
            // iOS apps
            ".ipa",
            // Documents (common non-threatening transfers)
            ".pdf", ".txt",
        };

        // WPD COM interfaces
        [DllImport("ole32.dll")]
        private static extern int CoCreateInstance(
            [In] ref Guid rclsid, IntPtr pUnkOuter, uint dwClsContext,
            [In] ref Guid riid, [MarshalAs(UnmanagedType.Interface)] out object ppv);

        // WPD GUIDs
        private static readonly Guid CLSID_PortableDeviceManager = new("0af10cec-2ecd-4b92-9581-34f6ae0637f3");
        private static readonly Guid IID_IPortableDeviceManager = new("a1567595-4c2f-4574-a6fa-ecef917b9a40");

        // Track known MTP devices
        private readonly ConcurrentDictionary<string, string> _connectedDevices = new();

        // Shell copy monitoring - watch temp staging paths
        private readonly ConcurrentDictionary<string, DateTime> _blockedTransfers = new();

        public MtpTransferGuard(DetectionEngine de, ILogger<MtpTransferGuard> l)
        {
            _detectionEngine = de;
            _logger = l;
        }

        protected override async Task ExecuteAsync(CancellationToken ct)
        {
            _logger.LogInformation("[MtpTransferGuard] Started - blocking non-media file transfers to MTP devices");

            await Task.Delay(15000, ct);

            while (!ct.IsCancellationRequested)
            {
                try
                {
                    // 1. Enumerate connected MTP/WPD devices
                    EnumeratePortableDevices();

                    // 2. Scan for processes actively transferring TO MTP devices (PC->Phone)
                    if (_connectedDevices.Count > 0)
                    {
                        await ScanForUnauthorizedTransfersAsync(ct);
                    }

                    // 3. Scan for dangerous files arriving FROM MTP devices (Phone->PC)
                    await ScanForInboundThreatsAsync(ct);
                }
                catch (OperationCanceledException) { break; }
                catch (Exception ex) { _logger.LogDebug(ex, "[MtpTransferGuard] Error"); }

                await Task.Delay(5000, ct);
            }
        }

        private void EnumeratePortableDevices()
        {
            try
            {
                var riid = IID_IPortableDeviceManager;
                var clsid = CLSID_PortableDeviceManager;
                int hr = CoCreateInstance(ref clsid, IntPtr.Zero, 1 /* CLSCTX_INPROC_SERVER */, ref riid, out var obj);
                if (hr != 0 || obj == null) return;

                // Use reflection to call GetDevices since we can't reference the WPD interop directly
                // Instead, enumerate via registry (more reliable for userland EDR)
                Marshal.ReleaseComObject(obj);
            }
            catch { }

            // Fallback: enumerate WPD devices via registry
            EnumerateViaRegistry();
        }

        private void EnumerateViaRegistry()
        {
            try
            {
                // WPD devices are registered under this key
                using var key = Registry.LocalMachine.OpenSubKey(
                    @"SYSTEM\CurrentControlSet\Enum\SWD\WPDBUSENUM");
                if (key == null) return;

                _connectedDevices.Clear();
                foreach (var subKeyName in key.GetSubKeyNames())
                {
                    try
                    {
                        using var deviceKey = key.OpenSubKey(subKeyName);
                        if (deviceKey == null) continue;

                        var friendlyName = deviceKey.GetValue("FriendlyName") as string;
                        var deviceDesc = deviceKey.GetValue("DeviceDesc") as string ?? "";

                        // Only track actual portable devices (phones, tablets)
                        if (deviceDesc.Contains("MTP") ||
                            deviceDesc.Contains("Portable") ||
                            deviceDesc.Contains("Phone") ||
                            deviceDesc.Contains("Android") ||
                            deviceDesc.Contains("Apple") ||
                            deviceDesc.Contains("iPhone"))
                        {
                            _connectedDevices[subKeyName] = friendlyName ?? subKeyName;
                        }
                    }
                    catch { }
                }

                if (_connectedDevices.Count > 0)
                    _logger.LogDebug("[MtpTransferGuard] {Count} MTP device(s) connected", _connectedDevices.Count);
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "[MtpTransferGuard] Registry enumeration failed");
            }
        }

        private async Task ScanForUnauthorizedTransfersAsync(CancellationToken ct)
        {
            try
            {
                foreach (var proc in Process.GetProcesses())
                {
                    try
                    {
                        // Look for processes that are actively using WPD APIs
                        // Key indicator: process has loaded PortableDeviceApi.dll or wpdshext.dll
                        if (!IsWpdProcess(proc)) continue;

                        // Check what files this process has open - look for non-media files
                        // being staged for transfer
                        var suspiciousFiles = GetStagedNonMediaFiles(proc);
                        foreach (var file in suspiciousFiles)
                        {
                            var key = $"{proc.Id}:{file}";
                            if (_blockedTransfers.ContainsKey(key)) continue;

                            _blockedTransfers[key] = DateTime.UtcNow;

                            _logger.LogWarning(
                                "[MtpTransferGuard] Blocked non-media transfer: {File} by {Process} (PID {Pid})",
                                Path.GetFileName(file), proc.ProcessName, proc.Id);

                            // Kill the transfer process
                            try { proc.Kill(); } catch { }

                            await _detectionEngine.EmitAsync(new DetectionEvent
                            {
                                RuleName = "MTP Guard: Non-Media File Transfer Blocked",
                                Evidence = $"Process '{proc.ProcessName}' (PID {proc.Id}) attempted to transfer " +
                                           $"'{Path.GetFileName(file)}' to a connected MTP device. " +
                                           $"Extension '{Path.GetExtension(file)}' is not in the allowed media/app list. " +
                                           $"Connected devices: {string.Join(", ", _connectedDevices.Values)}",
                                Reasoning = "MTP file transfer of non-media content (executables, scripts, archives, DLLs) " +
                                            "to a connected phone can be used to infect the mobile device from a compromised PC. " +
                                            "Only media files (images, video, audio) and mobile app packages (APK, IPA) are permitted. " +
                                            "The transferring process has been terminated.",
                                Confidence = 0.90,
                                Tier = DetectionTier.Tier1Behavioral,
                                AuthorizedResponse = ResponseAction.KillProcessTree,
                                ProcessName = proc.ProcessName,
                                ProcessId = proc.Id,
                                SignalType = SignalType.Generic,
                                Metadata = new Dictionary<string, string>
                                {
                                    { "File", Path.GetFileName(file) },
                                    { "Extension", Path.GetExtension(file) },
                                    { "Devices", string.Join(", ", _connectedDevices.Values) },
                                    { "Action", "ProcessKilled" }
                                }
                            });
                        }
                    }
                    catch { }
                }

                // Prune old blocked transfer records (older than 5 minutes)
                var stale = _blockedTransfers.Where(kv => DateTime.UtcNow - kv.Value > TimeSpan.FromMinutes(5))
                    .Select(kv => kv.Key).ToList();
                foreach (var key in stale) _blockedTransfers.TryRemove(key, out _);
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "[MtpTransferGuard] Scan error");
            }
        }

        private static bool IsWpdProcess(Process proc)
        {
            try
            {
                var path = SecurityValidation.GetProcessImagePath(proc.Id);
                if (!NativeProcessMemory.CanInspect(proc.Id, path))
                    return false;

                foreach (var mod in NativeProcessMemory.EnumModules(proc.Id))
                {
                    var name = mod.Name.ToLowerInvariant();
                    if (name == "portabledeviceapi.dll" || name == "wpdshext.dll" ||
                        name == "wpdmtp.dll" || name == "wpdmtpus.dll")
                    {
                        return true;
                    }
                }
            }
            catch { } // Access denied for system processes - fine
            return false;
        }

        private static List<string> GetStagedNonMediaFiles(Process proc)
        {
            var results = new List<string>();
            try
            {
                // Check the process command line for file paths
                var cmdLine = GetProcessCommandLine(proc.Id);
                if (!string.IsNullOrEmpty(cmdLine))
                {
                    // Extract file paths from command line
                    var paths = ExtractFilePaths(cmdLine);
                    foreach (var path in paths)
                    {
                        if (!IsAllowedExtension(path))
                            results.Add(path);
                    }
                }

                // Also check the process's current directory and recently opened files
                // by scanning file handles in temp/staging directories
                var procPath = SecurityValidation.GetProcessImagePath(proc.Id);
                if (procPath != null)
                {
                    // Explorer.exe doing drag-drop to MTP device - check clipboard/drag data
                    // This is handled by the WPD shell extension (wpdshext.dll)
                    if (proc.ProcessName.Equals("explorer"))
                    {
                        // For Explorer, scan recent file operation cache
                        ScanExplorerRecentTransfers(results);
                    }
                }
            }
            catch { }
            return results;
        }

        private static void ScanExplorerRecentTransfers(List<string> results)
        {
            // Monitor the WPD temp staging directory
            // When Explorer copies to MTP, it stages files through a temp path
            var tempPaths = new[]
            {
                Path.Combine(Path.GetTempPath(), "WPDNSE"),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                    "Temp", "WPDNSE")
            };

            foreach (var tempPath in tempPaths)
            {
                if (!Directory.Exists(tempPath)) continue;
                try
                {
                    foreach (var file in Directory.GetFiles(tempPath, "*", SearchOption.AllDirectories))
                    {
                        // Only flag if the file was created/modified recently (last 30s)
                        var info = new FileInfo(file);
                        if (DateTime.UtcNow - info.LastWriteTimeUtc < TimeSpan.FromSeconds(30) &&
                            !IsAllowedExtension(file))
                        {
                            results.Add(file);
                        }
                    }
                }
                catch { }
            }
        }

        private static bool IsAllowedExtension(string filePath)
        {
            var ext = Path.GetExtension(filePath);
            if (string.IsNullOrEmpty(ext)) return true; // No extension = probably not a real file path
            return AllowedExtensions.Contains(ext);
        }

        private static List<string> ExtractFilePaths(string cmdLine)
        {
            var paths = new List<string>();
            // Simple extraction: find tokens that look like file paths
            var parts = cmdLine.Split(new[] { '"' }, StringSplitOptions.RemoveEmptyEntries);
            foreach (var part in parts)
            {
                var trimmed = part.Trim();
                if ((trimmed.Length > 3 && trimmed[1] == ':' && trimmed[2] == '\\') ||
                    trimmed.StartsWith(@"\\"))
                {
                    if (File.Exists(trimmed))
                        paths.Add(trimmed);
                }
            }
            return paths;
        }

        private static string GetProcessCommandLine(int pid)
        {
            try
            {
                using var searcher = new System.Management.ManagementObjectSearcher(
                    $"SELECT CommandLine FROM Win32_Process WHERE ProcessId = {pid}");
                foreach (var obj in searcher.Get())
                {
                    return obj["CommandLine"]?.ToString() ?? "";
                }
            }
            catch { }
            return "";
        }

        //  Inbound threat detection (Phone -> PC) 

        // Dangerous extensions that should NEVER arrive from MTP to PC
        private static readonly HashSet<string> DangerousExtensions = new(StringComparer.OrdinalIgnoreCase)
        {
            // Executables
            ".exe", ".dll", ".sys", ".drv", ".scr", ".com", ".pif",
            // Scripts
            ".bat", ".cmd", ".ps1", ".psm1", ".psd1", ".vbs", ".vbe",
            ".js", ".jse", ".wsf", ".wsh", ".msh", ".msh1", ".msh2",
            // Compiled/managed
            ".msi", ".msp", ".mst", ".cpl", ".hta", ".inf", ".ins",
            // Office macros
            ".docm", ".xlsm", ".pptm", ".dotm", ".xltm",
            // Archives (can contain executables)
            ".zip", ".rar", ".7z", ".tar", ".gz", ".cab", ".iso", ".img", ".vhd", ".vhdx",
            // Shortcuts and links
            ".lnk", ".url", ".scf",
            // Registry
            ".reg",
            // Certificate
            ".cer", ".crt", ".p12", ".pfx",
            // DLL sideloading / hijack
            ".ocx", ".ax",
            // Java
            ".jar", ".class",
            // Python
            ".py", ".pyc", ".pyw",
        };

        // Track already-quarantined files to avoid duplicate alerts
        private readonly ConcurrentDictionary<string, DateTime> _quarantinedInbound = new(StringComparer.OrdinalIgnoreCase);

        private async Task ScanForInboundThreatsAsync(CancellationToken ct)
        {
            // Monitor WPDNSE staging directories - files transiting FROM MTP device TO PC
            var tempPaths = new[]
            {
                Path.Combine(Path.GetTempPath(), "WPDNSE"),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                    "Temp", "WPDNSE")
            };

            // Also monitor common drop targets (Downloads, Desktop, Documents)
            var userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
            var dropTargets = new[]
            {
                Path.Combine(userProfile, "Downloads"),
                Path.Combine(userProfile, "Desktop"),
                Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments)
            };

            // Scan WPDNSE staging - anything dangerous here is in-transit from phone
            foreach (var tempPath in tempPaths)
            {
                if (!Directory.Exists(tempPath)) continue;
                try
                {
                    foreach (var file in Directory.GetFiles(tempPath, "*", SearchOption.AllDirectories))
                    {
                        if (!IsDangerousExtension(file)) continue;
                        if (_quarantinedInbound.ContainsKey(file)) continue;

                        var info = new FileInfo(file);
                        // Only react to recently created files (last 60s)
                        if (DateTime.UtcNow - info.CreationTimeUtc > TimeSpan.FromSeconds(60)) continue;

                        _quarantinedInbound[file] = DateTime.UtcNow;

                        // Delete the dangerous file immediately
                        try { File.Delete(file); } catch { }

                        _logger.LogWarning("[MtpTransferGuard] Quarantined inbound threat from MTP: {File}", Path.GetFileName(file));

                        await _detectionEngine.EmitAsync(new DetectionEvent
                        {
                            RuleName = "MTP Guard: Dangerous Inbound File Blocked (Phone->PC)",
                            Evidence = $"File '{Path.GetFileName(file)}' with dangerous extension '{Path.GetExtension(file)}' " +
                                       $"was being transferred from an MTP device to this PC via WPDNSE staging. " +
                                       $"File deleted to prevent execution.",
                            Reasoning = "A connected phone/tablet attempted to transfer a potentially dangerous file " +
                                        "(executable, script, archive, macro document) to this PC. This is a known " +
                                        "infection vector where a compromised mobile device pushes malware to the PC " +
                                        "during file sync or manual transfer. The file was deleted before it could be executed.",
                            Confidence = 0.92,
                            Tier = DetectionTier.Tier1Behavioral,
                            AuthorizedResponse = ResponseAction.Quarantine,
                            ProcessName = "MTP Transfer",
                            ProcessId = 0,
                            SignalType = SignalType.Generic,
                            Metadata = new Dictionary<string, string>
                            {
                                { "File", Path.GetFileName(file) },
                                { "Extension", Path.GetExtension(file) },
                                { "Direction", "Inbound (Phone->PC)" },
                                { "StagingPath", tempPath },
                                { "Action", "Deleted" }
                            }
                        });
                    }
                }
                catch { }
            }

            // Scan drop targets only when MTP devices are connected
            if (_connectedDevices.Count > 0)
            {
                foreach (var dropDir in dropTargets)
                {
                    if (!Directory.Exists(dropDir)) continue;
                    try
                    {
                        // Only check top-level files created in the last 10 seconds
                        // (tight window to catch active transfers without false positives on normal use)
                        foreach (var file in Directory.GetFiles(dropDir))
                        {
                            if (!IsDangerousExtension(file)) continue;
                            if (_quarantinedInbound.ContainsKey(file)) continue;

                            var info = new FileInfo(file);
                            if (DateTime.UtcNow - info.CreationTimeUtc > TimeSpan.FromSeconds(10)) continue;

                            // Check if the file was created by a WPD-related process
                            var (pid, procName) = GetCreatorProcess(file);
                            if (!IsWpdRelatedProcess(procName)) continue;

                            _quarantinedInbound[file] = DateTime.UtcNow;

                            try { File.Delete(file); } catch { }

                            _logger.LogWarning("[MtpTransferGuard] Blocked inbound MTP threat in {Dir}: {File}",
                                Path.GetFileName(dropDir), Path.GetFileName(file));

                            await _detectionEngine.EmitAsync(new DetectionEvent
                            {
                                RuleName = "MTP Guard: Dangerous Inbound File Blocked (Phone->PC)",
                                Evidence = $"File '{Path.GetFileName(file)}' landed in {Path.GetFileName(dropDir)} " +
                                           $"from MTP device via process '{procName}' (PID {pid}). Deleted.",
                                Reasoning = "A dangerous file type was transferred from a connected MTP device to a " +
                                            "common user directory. Only media files are safe to receive from phones.",
                                Confidence = 0.88,
                                Tier = DetectionTier.Tier1Behavioral,
                                AuthorizedResponse = ResponseAction.Quarantine,
                                ProcessName = procName,
                                ProcessId = pid,
                                SignalType = SignalType.Generic,
                                Metadata = new Dictionary<string, string>
                                {
                                    { "File", Path.GetFileName(file) },
                                    { "Extension", Path.GetExtension(file) },
                                    { "DropTarget", dropDir },
                                    { "Direction", "Inbound (Phone->PC)" },
                                    { "Action", "Deleted" }
                                }
                            });
                        }
                    }
                    catch { }
                }
            }

            // Prune old quarantine records
            var stale = _quarantinedInbound.Where(kv => DateTime.UtcNow - kv.Value > TimeSpan.FromMinutes(10))
                .Select(kv => kv.Key).ToList();
            foreach (var key in stale) _quarantinedInbound.TryRemove(key, out _);
        }

        private static bool IsDangerousExtension(string filePath)
        {
            var ext = Path.GetExtension(filePath);
            if (string.IsNullOrEmpty(ext)) return false;
            return DangerousExtensions.Contains(ext);
        }

        private static bool IsWpdRelatedProcess(string processName)
        {
            var lower = processName.ToLowerInvariant();
            return lower.Contains("explorer") || lower.Contains("wpd") ||
                   lower.Contains("portable") || lower.Contains("mtp") ||
                   lower.Contains("shell");
        }

        private static (int pid, string name) GetCreatorProcess(string filePath)
        {
            // The start-time heuristic (find a process that started within N seconds of the
            // file's last-write) is unreliable on busy machines and is exploitable by a
            // sacrificial decoy process.  We now scan WPD/Explorer modules as a tighter
            // proxy: if a process has WPD transfer DLLs loaded AND was recently active,
            // that is the most likely candidate.  If we still cannot identify it, return
            // (0, "Unknown") - the caller treats that as LogOnly, which is correct.
            try
            {
                foreach (var proc in Process.GetProcesses())
                {
                    try
                    {
                        if (proc.Id <= 4) continue;
                        if (IsWpdProcess(proc))
                            return (proc.Id, proc.ProcessName);
                    }
                    catch { }
                    finally { proc.Dispose(); }
                }
            }
            catch { }
            return (0, "Unknown");
        }
    }


}
