using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Management;
using System.Runtime.InteropServices;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace Sentinel.Core
{
    /// <summary>
    /// Monitors SMB/network share activity to detect:
    /// - Unauthorized access to network shares (mapped drives, UNC paths)
    /// - Bulk file access patterns over SMB (credential theft, data exfiltration)
    /// - New share mappings created at runtime
    /// - Suspicious processes accessing admin shares (C$, ADMIN$, IPC$)
    ///
    /// Addresses the blind spot where lateral movement and data exfiltration
    /// over SMB generates zero telemetry in the file activity monitors.
    ///
    /// v1.0.1: New monitor.
    /// </summary>
    public sealed class NetworkShareMonitor : BackgroundService
    {
        private readonly DetectionEngine _detectionEngine;
        private readonly ProcessAncestryCache _ancestryCache;
        private readonly ILogger<NetworkShareMonitor> _logger;

        private readonly HashSet<string> _baselineMappedDrives = new(StringComparer.OrdinalIgnoreCase);
        private readonly ConcurrentDictionary<string, ShareAccessStats> _shareAccessStats = new();
        private readonly ConcurrentDictionary<string, DateTimeOffset> _alertedShares = new();

        private static readonly TimeSpan ScanInterval = TimeSpan.FromSeconds(15);
        private static readonly TimeSpan AlertCooldown = TimeSpan.FromMinutes(5);

        // Admin shares are high-value targets for lateral movement
        private static readonly HashSet<string> AdminShares = new(StringComparer.OrdinalIgnoreCase)
        {
            "C$", "D$", "E$", "ADMIN$", "IPC$", "PRINT$"
        };

        // Processes that legitimately access network shares
        private static readonly HashSet<string> AllowedShareProcesses = new(StringComparer.OrdinalIgnoreCase)
        {
            "explorer", "onedrive", "dropbox", "googledrivesync",
            "sharex", "totalcmd", "doublecmd", "robocopy",
            "xcopy", "svchost", "spoolsv", "searchindexer",
            "msiexec", "trustedinstaller"
        };

        [DllImport("mpr.dll", CharSet = CharSet.Unicode)]
        private static extern int WNetEnumResource(IntPtr hEnum, ref int lpcCount, IntPtr lpBuffer, ref int lpBufferSize);

        [DllImport("mpr.dll", CharSet = CharSet.Unicode)]
        private static extern int WNetOpenEnum(int dwScope, int dwType, int dwUsage, IntPtr lpNetResource, out IntPtr lphEnum);

        [DllImport("mpr.dll")]
        private static extern int WNetCloseEnum(IntPtr hEnum);

        [DllImport("netapi32.dll", CharSet = CharSet.Unicode)]
        private static extern int NetSessionEnum(
            string? serverName, string? clientName, string? userName,
            int level, out IntPtr bufPtr, int prefMaxLen,
            out int entriesRead, out int totalEntries, ref int resumeHandle);

        [DllImport("netapi32.dll")]
        private static extern int NetApiBufferFree(IntPtr buffer);

        [DllImport("netapi32.dll", CharSet = CharSet.Unicode)]
        private static extern int NetFileEnum(
            string? serverName, string? basePath, string? userName,
            int level, out IntPtr bufPtr, int prefMaxLen,
            out int entriesRead, out int totalEntries, ref IntPtr resumeHandle);

        [DllImport("netapi32.dll", CharSet = CharSet.Unicode)]
        private static extern int NetShareEnum(
            string? serverName, int level, out IntPtr bufPtr, int prefMaxLen,
            out int entriesRead, out int totalEntries, ref int resumeHandle);

        // SHARE_INFO_2 structure for local share enumeration
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private struct SHARE_INFO_2
        {
            [MarshalAs(UnmanagedType.LPWStr)] public string shi2_netname;
            public uint shi2_type;
            [MarshalAs(UnmanagedType.LPWStr)] public string? shi2_remark;
            public uint shi2_permissions;
            public uint shi2_max_uses;
            public uint shi2_current_uses;
            [MarshalAs(UnmanagedType.LPWStr)] public string? shi2_path;
            [MarshalAs(UnmanagedType.LPWStr)] public string? shi2_passwd;
        }

        // Baseline of local shares at startup - new shares after this are suspicious
        private readonly HashSet<string> _baselineLocalShares = new(StringComparer.OrdinalIgnoreCase);

        public NetworkShareMonitor(
            DetectionEngine detectionEngine,
            ProcessAncestryCache ancestryCache,
            ILogger<NetworkShareMonitor> logger)
        {
            _detectionEngine = detectionEngine;
            _ancestryCache = ancestryCache;
            _logger = logger;
        }

        protected override async Task ExecuteAsync(CancellationToken ct)
        {
            _logger.LogInformation("[NetworkShareMonitor] Started");

            // Baseline currently mapped drives
            BaselineMappedDrives();

            // Baseline currently exported local shares
            BaselineLocalShares();

            while (!ct.IsCancellationRequested)
            {
                try
                {
                    await Task.Delay(ScanInterval, ct);

                    await DetectNewShareMappings(ct);
                    await DetectNewLocalShareCreation(ct);
                    await DetectAdminShareAccess(ct);
                    await DetectInboundSessions(ct);
                }
                catch (OperationCanceledException) { break; }
                catch (Exception ex) { _logger.LogDebug(ex, "[NetworkShareMonitor] Error"); }
            }
        }

        private async Task DetectNewShareMappings(CancellationToken ct)
        {
            var currentMappings = GetMappedDrives();
            foreach (var mapping in currentMappings)
            {
                if (_baselineMappedDrives.Contains(mapping.LocalDrive ?? mapping.RemotePath))
                    continue;

                _baselineMappedDrives.Add(mapping.LocalDrive ?? mapping.RemotePath);

                // Check if this is an admin share
                var shareName = GetShareName(mapping.RemotePath);
                bool isAdmin = AdminShares.Contains(shareName);

                var confidence = isAdmin ? 0.85 : 0.55;
                var tier = isAdmin ? DetectionTier.Tier1Behavioral : DetectionTier.Tier2Indicator;

                await _detectionEngine.EmitAsync(new DetectionEvent
                {
                    RuleName = isAdmin
                        ? "Network Share: Admin Share Mapped"
                        : "Network Share: New Drive Mapped",
                    Evidence = $"New network mapping: {mapping.LocalDrive ?? "net use"} -> {mapping.RemotePath}",
                    Reasoning = isAdmin
                        ? "An administrative share (C$, ADMIN$, IPC$) was mapped at runtime. " +
                          "This is a common lateral movement technique where attackers use stolen " +
                          "credentials to access remote administrative shares for code execution " +
                          "and data exfiltration."
                        : "A new network share was mapped after service startup. Runtime share " +
                          "mapping may indicate lateral movement or data staging for exfiltration.",
                    Confidence = confidence,
                    Tier = tier,
                    AuthorizedResponse = isAdmin ? ResponseAction.NetworkIsolate : ResponseAction.LogOnly,
                    ProcessName = "SYSTEM",
                    ProcessId = 0,
                    Metadata = new Dictionary<string, string>
                    {
                        ["RemotePath"] = mapping.RemotePath,
                        ["LocalDrive"] = mapping.LocalDrive ?? "",
                        ["ShareName"] = shareName,
                        ["IsAdminShare"] = isAdmin.ToString()
                    }
                });
            }
        }

        /// <summary>
        /// Detects new local SMB shares being created after service start.
        /// An attacker can run 'net share PWNED=C:\ /grant:everyone,full' to expose drives
        /// to the network without triggering any existing monitor.
        /// v1.4.1: New detection - closes local share creation blind spot.
        /// </summary>
        private async Task DetectNewLocalShareCreation(CancellationToken ct)
        {
            try
            {
                var currentShares = EnumerateLocalShares();
                foreach (var share in currentShares)
                {
                    if (_baselineLocalShares.Contains(share.Name)) continue;

                    // New share appeared after startup
                    _baselineLocalShares.Add(share.Name);

                    // Default admin shares are always present - don't alert on them
                    if (AdminShares.Contains(share.Name)) continue;

                    // Determine severity based on what's being shared
                    bool isFullDrive = !string.IsNullOrEmpty(share.Path) &&
                        share.Path!.Length <= 3 && share.Path.IndexOf(':') >= 0;
                    bool isSystemPath = !string.IsNullOrEmpty(share.Path) &&
                        (share.Path!.StartsWith(@"C:\Windows") ||
                         share.Path.StartsWith(@"C:\Users") ||
                         share.Path.StartsWith(@"C:\Program"));

                    var confidence = isFullDrive ? 0.95 : isSystemPath ? 0.88 : 0.75;

                    await _detectionEngine.EmitAsync(new DetectionEvent
                    {
                        RuleName = "Network Share: Unauthorized Local Share Created",
                        Evidence = $"New SMB share '{share.Name}' created exposing path '{share.Path}' " +
                                   $"(Type: {share.Type}, Remark: '{share.Remark}')",
                        Reasoning = isFullDrive
                            ? "A new network share was created exposing an ENTIRE DRIVE to the network. " +
                              "This gives any network-reachable machine full read/write access to all files on the drive. " +
                              "This is a critical data exposure - either an attacker creating exfiltration access or " +
                              "preparing for remote file manipulation via passive FTP/SMB from a rogue device."
                            : "A new network share was created after Sentinel startup. Runtime share creation " +
                              "is uncommon in normal operation and may indicate an attacker exposing local files " +
                              "for remote access, data exfiltration, or establishing a staging area.",
                        Confidence = confidence,
                        Tier = DetectionTier.Tier1Behavioral,
                        AuthorizedResponse = ResponseAction.KillProcessTree,
                        ProcessName = "SYSTEM",
                        ProcessId = 0,
                        Metadata = new Dictionary<string, string>
                        {
                            ["ShareName"] = share.Name,
                            ["SharedPath"] = share.Path ?? "",
                            ["ShareType"] = share.Type.ToString(),
                            ["IsFullDrive"] = isFullDrive.ToString()
                        }
                    });

                    // Auto-delete the unauthorized share
                    try
                    {
                        var psi = new ProcessStartInfo("net.exe", $"share \"{share.Name}\" /delete /yes")
                        {
                            CreateNoWindow = true,
                            UseShellExecute = false,
                            RedirectStandardOutput = true,
                            RedirectStandardError = true
                        };
                        using var proc = Process.Start(psi);
                        proc?.WaitForExit(5000);
                        _logger.LogWarning(
                            "[NetworkShareMonitor] AUTO-DELETED unauthorized share '{Name}' exposing '{Path}'",
                            share.Name, share.Path);
                    }
                    catch (Exception ex)
                    {
                        _logger.LogDebug(ex, "[NetworkShareMonitor] Failed to delete share {Name}", share.Name);
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "[NetworkShareMonitor] DetectNewLocalShareCreation error");
            }
        }

        private void BaselineLocalShares()
        {
            foreach (var share in EnumerateLocalShares())
            {
                _baselineLocalShares.Add(share.Name);
            }
            _logger.LogInformation("[NetworkShareMonitor] Baselined {Count} local shares", _baselineLocalShares.Count);
        }

        private List<LocalShareInfo> EnumerateLocalShares()
        {
            var shares = new List<LocalShareInfo>();
            try
            {
                int resumeHandle = 0;
                int result = NetShareEnum(null, 2, out IntPtr bufPtr, -1,
                    out int entriesRead, out int totalEntries, ref resumeHandle);

                if (result != 0 || bufPtr == IntPtr.Zero) return shares;

                try
                {
                    int structSize = Marshal.SizeOf<SHARE_INFO_2>();
                    for (int i = 0; i < entriesRead; i++)
                    {
                        var entry = Marshal.PtrToStructure<SHARE_INFO_2>(
                            IntPtr.Add(bufPtr, i * structSize));
                        shares.Add(new LocalShareInfo
                        {
                            Name = entry.shi2_netname,
                            Type = entry.shi2_type,
                            Path = entry.shi2_path,
                            Remark = entry.shi2_remark
                        });
                    }
                }
                finally
                {
                    NetApiBufferFree(bufPtr);
                }
            }
            catch { }
            return shares;
        }

        private async Task DetectAdminShareAccess(CancellationToken ct)
        {
            // Monitor open files on local admin shares (inbound lateral movement)
            try
            {
                var resumeHandle = IntPtr.Zero;
                int result = NetFileEnum(null, null, null, 3, out IntPtr bufPtr, -1,
                    out int entriesRead, out int totalEntries, ref resumeHandle);

                if (result != 0 || bufPtr == IntPtr.Zero) return;

                try
                {
                    // Parse FILE_INFO_3 structures
                    int structSize = Marshal.SizeOf<FILE_INFO_3>();
                    for (int i = 0; i < entriesRead; i++)
                    {
                        var entry = Marshal.PtrToStructure<FILE_INFO_3>(
                            IntPtr.Add(bufPtr, i * structSize));

                        var path = Marshal.PtrToStringUni(entry.fi3_pathname) ?? "";
                        var username = Marshal.PtrToStringUni(entry.fi3_username) ?? "";

                        // Check if access is to admin shares from non-local user
                        if (string.IsNullOrEmpty(path)) continue;

                        var sharePart = GetShareFromPath(path);
                        if (!AdminShares.Contains(sharePart)) continue;

                        var alertKey = $"{username}:{path}";
                        if (_alertedShares.TryGetValue(alertKey, out var lastAlert) &&
                            DateTimeOffset.UtcNow - lastAlert < AlertCooldown)
                            continue;

                        _alertedShares[alertKey] = DateTimeOffset.UtcNow;

                        await _detectionEngine.EmitAsync(new DetectionEvent
                        {
                            RuleName = "Network Share: Inbound Admin Share Access",
                            Evidence = $"User '{username}' accessing admin share path: {path} " +
                                       $"(Permissions: {entry.fi3_permissions})",
                            Reasoning = "A remote user is accessing an administrative share on this system. " +
                                        "This is a strong indicator of lateral movement - the attacker has " +
                                        "obtained valid credentials and is accessing the system remotely " +
                                        "via SMB for file operations, code deployment, or data theft.",
                            Confidence = 0.88,
                            Tier = DetectionTier.Tier1Behavioral,
                            AuthorizedResponse = ResponseAction.NetworkIsolate,
                            ProcessName = "SYSTEM",
                            ProcessId = 0,
                            SignalType = SignalType.CredentialTheft,
                            Family = TerminalFamily.CredentialDump,
                            Metadata = new Dictionary<string, string>
                            {
                                ["Username"] = username,
                                ["Path"] = path,
                                ["Permissions"] = entry.fi3_permissions.ToString()
                            }
                        });
                    }
                }
                finally
                {
                    NetApiBufferFree(bufPtr);
                }
            }
            catch { }
        }

        private async Task DetectInboundSessions(CancellationToken ct)
        {
            // Detect new SMB sessions to this machine
            try
            {
                int resumeHandle = 0;
                int result = NetSessionEnum(null, null, null, 10, out IntPtr bufPtr, -1,
                    out int entriesRead, out int totalEntries, ref resumeHandle);

                if (result != 0 || bufPtr == IntPtr.Zero) return;

                try
                {
                    int structSize = Marshal.SizeOf<SESSION_INFO_10>();
                    for (int i = 0; i < entriesRead; i++)
                    {
                        var entry = Marshal.PtrToStructure<SESSION_INFO_10>(
                            IntPtr.Add(bufPtr, i * structSize));

                        var clientName = Marshal.PtrToStringUni(entry.sesi10_cname) ?? "";
                        var username = Marshal.PtrToStringUni(entry.sesi10_username) ?? "";

                        // Skip localhost sessions
                        if (clientName is "127.0.0.1" or "::1" or "localhost") continue;

                        var alertKey = $"session:{clientName}:{username}";
                        if (_alertedShares.TryGetValue(alertKey, out var lastAlert) &&
                            DateTimeOffset.UtcNow - lastAlert < AlertCooldown)
                            continue;

                        _alertedShares[alertKey] = DateTimeOffset.UtcNow;

                        // New session from remote - low confidence by itself
                        // but feeds into correlation engine
                        await _detectionEngine.EmitAsync(new DetectionEvent
                        {
                            RuleName = "Network Share: Inbound SMB Session",
                            Evidence = $"SMB session from '{clientName}' as user '{username}' " +
                                       $"(active {entry.sesi10_time}s, idle {entry.sesi10_idle_time}s)",
                            Reasoning = "A remote system established an SMB session to this machine. " +
                                        "This is normal in domain environments but can indicate lateral movement " +
                                        "when combined with other signals (credential access, admin share access).",
                            Confidence = 0.45,
                            Tier = DetectionTier.Tier2Indicator,
                            AuthorizedResponse = ResponseAction.LogOnly,
                            ProcessName = "SYSTEM",
                            ProcessId = 0,
                            Metadata = new Dictionary<string, string>
                            {
                                ["ClientName"] = clientName,
                                ["Username"] = username,
                                ["ActiveSeconds"] = entry.sesi10_time.ToString(),
                                ["IdleSeconds"] = entry.sesi10_idle_time.ToString()
                            }
                        });
                    }
                }
                finally
                {
                    NetApiBufferFree(bufPtr);
                }
            }
            catch { }
        }

        private void BaselineMappedDrives()
        {
            foreach (var mapping in GetMappedDrives())
            {
                _baselineMappedDrives.Add(mapping.LocalDrive ?? mapping.RemotePath);
            }
        }

        private static List<DriveMapping> GetMappedDrives()
        {
            var mappings = new List<DriveMapping>();
            try
            {
                foreach (var drive in DriveInfo.GetDrives())
                {
                    if (drive.DriveType == DriveType.Network)
                    {
                        mappings.Add(new DriveMapping
                        {
                            LocalDrive = drive.Name.TrimEnd('\\'),
                            RemotePath = drive.Name // Will be resolved below
                        });
                    }
                }

                // Use WMI for full UNC path resolution
                using var searcher = new ManagementObjectSearcher(
                    "SELECT LocalName, RemoteName FROM Win32_NetworkConnection");
                foreach (ManagementObject obj in searcher.Get())
                {
                    var local = obj["LocalName"]?.ToString();
                    var remote = obj["RemoteName"]?.ToString() ?? "";
                    mappings.Add(new DriveMapping { LocalDrive = local, RemotePath = remote });
                }
            }
            catch { }
            return mappings;
        }

        private static string GetShareName(string uncPath)
        {
            // Extract share name from \\server\sharename\path
            var parts = uncPath.TrimStart('\\').Split('\\');
            return parts.Length >= 2 ? parts[1] : "";
        }

        private static string GetShareFromPath(string localPath)
        {
            // For NetFileEnum paths like "C$\Windows\System32\..."
            var idx = localPath.IndexOf('\\');
            return idx > 0 ? localPath[..idx] : localPath;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct FILE_INFO_3
        {
            public int fi3_id;
            public int fi3_permissions;
            public int fi3_num_locks;
            public IntPtr fi3_pathname;
            public IntPtr fi3_username;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct SESSION_INFO_10
        {
            public IntPtr sesi10_cname;
            public IntPtr sesi10_username;
            public int sesi10_time;
            public int sesi10_idle_time;
        }

        private class DriveMapping
        {
            public string? LocalDrive { get; set; }
            public string RemotePath { get; set; } = string.Empty;
        }

        private class ShareAccessStats
        {
            public int FileAccessCount { get; set; }
            public DateTimeOffset FirstAccess { get; set; }
            public DateTimeOffset LastAccess { get; set; }
        }

        private class LocalShareInfo
        {
            public string Name { get; set; } = string.Empty;
            public uint Type { get; set; }
            public string? Path { get; set; }
            public string? Remark { get; set; }
        }
    }
}
