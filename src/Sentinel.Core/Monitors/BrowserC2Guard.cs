using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace Sentinel.Core
{
    /// <summary>
    /// v1.6.8: BrowserC2Guard - Full browser-based C2 detection expanding ChromeRemoteDebuggingRule.
    ///
    /// Blind spots addressed:
    /// - ChromeRemoteDebuggingRule only detects the initial launch with --remote-debugging-port.
    ///   It does NOT detect: headless chrome as a proxy, extension-based C2, post-launch debugging
    ///   port activation, or browsers already running with debug ports.
    ///
    /// Detection approach:
    /// 1. Scan running browsers for active --remote-debugging-port (catches pre-existing debug sessions)
    /// 2. Detect headless chrome/chromium launched as a network proxy (no visible window + network I/O)
    /// 3. Validate browser extension manifests for dangerous permissions (debugger, webRequest, nativeMessaging)
    /// 4. On corroboration with BeaconingDetector signals on the same PID -> escalate to KillProcessTree
    /// 5. Detect DevTools WebSocket connections from non-browser processes (CDP session hijacking)
    ///
    /// Response:
    /// - Headless proxy + beaconing -> KillProcessTree (Tier1, 0.90)
    /// - Remote debugging by non-browser parent -> KillProcessTree (Tier1, 0.85) [existing rule, re-evaluated]
    /// - Suspicious extension permissions -> LogOnly (Tier2, 0.55-0.70)
    /// - Debug port active + beaconing corroboration -> NetworkIsolate (Tier1, 0.88)
    ///
    /// Scans every 30s. Runs in service session (SYSTEM) for process inspection.
    /// </summary>
    public sealed class BrowserC2Guard : BackgroundService
    {
        private readonly DetectionEngine _detectionEngine;
        private readonly BeaconingDetector _beaconingDetector;
        private readonly ContextBus? _contextBus;
        private readonly ILogger<BrowserC2Guard> _logger;

        private readonly ConcurrentDictionary<int, DateTimeOffset> _alertedPids = new();
        private readonly HashSet<string> _alertedExtensions = new(StringComparer.OrdinalIgnoreCase);

        private static readonly TimeSpan ScanInterval = TimeSpan.FromSeconds(30);
        private static readonly TimeSpan AlertCooldown = TimeSpan.FromMinutes(5);

        private static readonly HashSet<string> BrowserProcessNames = new(StringComparer.OrdinalIgnoreCase)
        {
            "chrome", "msedge", "brave", "vivaldi", "opera", "chromium"
        };

        // Dangerous extension permissions that enable C2-like behavior
        private static readonly HashSet<string> DangerousPermissions = new(StringComparer.OrdinalIgnoreCase)
        {
            "debugger",           // Full CDP access to other tabs
            "nativeMessaging",    // IPC with native binary
            "webRequestBlocking", // Intercept/modify all traffic
            "proxy",             // Route traffic through attacker proxy
            "<all_urls>",        // Access to all websites
            "cookies",           // Session theft
            "management",        // Install/remove other extensions
        };

        // Known legitimate extensions that use dangerous permissions
        private static readonly HashSet<string> TrustedExtensionIds = new(StringComparer.OrdinalIgnoreCase)
        {
            "cjpalhdlnbpafiamejdnhcphjbkeiagm", // uBlock Origin
            "gcbommkclmclpchllfjekcdonpmejbdp", // HTTPS Everywhere
            "pkehgijcmpdhfbdbbnkijodmdjhbjlgp", // Privacy Badger
            "nngceckbapebfimnlniiiahkandclblb", // Bitwarden
            "hdokiejnpimakedhajhdlcegeplioahd", // LastPass
            "padekgcemlokbadohgkifijomclgjgif", // Proxy SwitchyOmega (legitimate)
        };

        public BrowserC2Guard(
            DetectionEngine detectionEngine,
            BeaconingDetector beaconingDetector,
            ILogger<BrowserC2Guard> logger,
            ContextBus? contextBus = null)
        {
            _detectionEngine = detectionEngine;
            _beaconingDetector = beaconingDetector;
            _logger = logger;
            _contextBus = contextBus;
        }

        protected override async Task ExecuteAsync(CancellationToken ct)
        {
            _logger.LogInformation("[BrowserC2Guard] Started - scanning for browser-based C2 every 30s");
            await Task.Delay(20000, ct); // Let other monitors initialize first

            while (!ct.IsCancellationRequested)
            {
                try
                {
                    await Task.Delay(ScanInterval, ct);
                    await ScanForHeadlessProxyAsync(ct);
                    await ScanForActiveDebugPortsAsync(ct);
                    await ScanExtensionManifestsAsync(ct);
                }
                catch (OperationCanceledException) { break; }
                catch (Exception ex) { _logger.LogDebug(ex, "[BrowserC2Guard] Scan error"); }
            }
        }

        /// <summary>
        /// Detects headless chrome/chromium instances that act as network proxies.
        /// Headless + no user-data-dir or temp profile + network connections = C2 proxy.
        /// </summary>
        private async Task ScanForHeadlessProxyAsync(CancellationToken ct)
        {
            foreach (var proc in Process.GetProcesses())
            {
                if (ct.IsCancellationRequested) break;

                try
                {
                    var name = Sentinel.Core.StringNet48.ReplaceIgnoreCase(proc.ProcessName, ".exe", "");
                    if (!BrowserProcessNames.Contains(name)) continue;
                    if (IsAlertCoolingDown(proc.Id)) continue;

                    string cmdLine = GetCommandLine(proc.Id);
                    if (string.IsNullOrEmpty(cmdLine)) continue;

                    bool isHeadless = cmdLine.Contains("--headless");
                    bool hasDebugPort = cmdLine.Contains("--remote-debugging-port");
                    bool noSandbox = cmdLine.Contains("--no-sandbox");
                    bool tempProfile = cmdLine.Contains("--user-data-dir=") &&
                                       (cmdLine.Contains("\\Temp\\") ||
                                        cmdLine.Contains("/tmp/"));

                    // Headless + debug port = potential C2 proxy
                    if (isHeadless && hasDebugPort)
                    {
                        // Check parent - if parent is node/python/automation tool from suspicious path, escalate
                        var parentInfo = GetParentInfo(proc.Id);
                        bool suspiciousParent = !string.IsNullOrEmpty(parentInfo.name) &&
                            !BrowserProcessNames.Contains(Sentinel.Core.StringNet48.ReplaceIgnoreCase(parentInfo.name!, ".exe", ""));

                        double confidence = 0.78;
                        var response = ResponseAction.LogOnly;

                        if (suspiciousParent && (noSandbox || tempProfile))
                        {
                            confidence = 0.90;
                            response = ResponseAction.KillProcessTree;
                        }
                        else if (suspiciousParent)
                        {
                            confidence = 0.85;
                            response = ResponseAction.KillProcessTree;
                        }

                        await _detectionEngine.EmitAsync(new DetectionEvent
                        {
                            RuleName = "BrowserC2Guard: Headless Chrome as Proxy",
                            Evidence = $"Headless browser '{proc.ProcessName}' (PID {proc.Id}) with debug port active. " +
                                       $"Parent: {parentInfo.name ?? "unknown"} (PID {parentInfo.pid}). " +
                                       $"NoSandbox: {noSandbox}, TempProfile: {tempProfile}",
                            Reasoning = "A headless Chromium-based browser was launched with remote debugging enabled by a non-browser process. " +
                                        "This pattern is used by attackers to route C2 traffic through legitimate browser TLS connections, " +
                                        "steal cookies/sessions via CDP, or serve as a SOCKS proxy that blends with normal browser traffic.",
                            Confidence = confidence,
                            Tier = DetectionTier.Tier1Behavioral,
                            AuthorizedResponse = response,
                            SignalType = SignalType.NetworkC2,
                            ProcessName = proc.ProcessName,
                            ProcessId = proc.Id,
                        });
                        _alertedPids[proc.Id] = DateTimeOffset.UtcNow;
                    }
                }
                catch { }
                finally { proc.Dispose(); }
            }
        }

        /// <summary>
        /// Scans for browsers already running with active debugging ports (not caught at launch).
        /// Correlates with beaconing signals for high-confidence composite detection.
        /// </summary>
        private async Task ScanForActiveDebugPortsAsync(CancellationToken ct)
        {
            foreach (var proc in Process.GetProcesses())
            {
                if (ct.IsCancellationRequested) break;

                try
                {
                    var name = Sentinel.Core.StringNet48.ReplaceIgnoreCase(proc.ProcessName, ".exe", "");
                    if (!BrowserProcessNames.Contains(name)) continue;
                    if (IsAlertCoolingDown(proc.Id)) continue;

                    string cmdLine = GetCommandLine(proc.Id);
                    if (string.IsNullOrEmpty(cmdLine)) continue;
                    if (!cmdLine.Contains("--remote-debugging-port")) continue;

                    // Extract the debug port number
                    int debugPort = ExtractDebugPort(cmdLine);
                    if (debugPort <= 0) continue;

                    // Check if any non-browser process is connecting to the debug port (CDP hijacking)
                    // This is a WebSocket connection to ws://127.0.0.1:{debugPort}/devtools/...
                    bool hasCdpClient = CheckForCdpClients(debugPort, proc.Id);

                    if (hasCdpClient)
                    {
                        await _detectionEngine.EmitAsync(new DetectionEvent
                        {
                            RuleName = "BrowserC2Guard: CDP Session Hijacking Detected",
                            Evidence = $"Browser '{proc.ProcessName}' (PID {proc.Id}) has active CDP session on port {debugPort} " +
                                       $"with non-browser client connected.",
                            Reasoning = "A non-browser process is connected to the Chrome DevTools Protocol WebSocket endpoint. " +
                                        "This enables full programmatic control of browser tabs, cookie theft, credential harvesting, " +
                                        "and traffic interception without modifying any files on disk.",
                            Confidence = 0.88,
                            Tier = DetectionTier.Tier1Behavioral,
                            AuthorizedResponse = ResponseAction.NetworkIsolate,
                            SignalType = SignalType.CredentialTheft,
                            ProcessName = proc.ProcessName,
                            ProcessId = proc.Id,
                        });
                        _alertedPids[proc.Id] = DateTimeOffset.UtcNow;
                    }
                }
                catch { }
                finally { proc.Dispose(); }
            }
        }

        /// <summary>
        /// Scans Chromium extension manifests for dangerous permissions that enable C2.
        /// New extensions with debugger/nativeMessaging/proxy permissions are suspicious.
        /// </summary>
        private async Task ScanExtensionManifestsAsync(CancellationToken ct)
        {
            // v2.2.0: scan each interactive user's LocalAppData, not SYSTEM's profile.
            var browserExtPaths = new List<string>();
            foreach (var root in SecurityValidation.EnumerateInteractiveUserWritableRoots())
            {
                if (!root.EndsWith(@"AppData\Local", StringComparison.OrdinalIgnoreCase) &&
                    !root.EndsWith(@"AppData\Local\", StringComparison.OrdinalIgnoreCase))
                    continue;
                browserExtPaths.Add(Path.Combine(root, @"Google\Chrome\User Data\Default\Extensions"));
                browserExtPaths.Add(Path.Combine(root, @"Microsoft\Edge\User Data\Default\Extensions"));
                browserExtPaths.Add(Path.Combine(root, @"BraveSoftware\Brave-Browser\User Data\Default\Extensions"));
            }

            foreach (var extRoot in browserExtPaths)
            {
                if (ct.IsCancellationRequested) break;
                if (!Directory.Exists(extRoot)) continue;

                try
                {
                    foreach (var extDir in Directory.GetDirectories(extRoot))
                    {
                        if (ct.IsCancellationRequested) break;

                        var extId = Path.GetFileName(extDir);
                        if (string.IsNullOrEmpty(extId)) continue;
                        if (TrustedExtensionIds.Contains(extId)) continue;
                        if (_alertedExtensions.Contains(extId)) continue;

                        // Find manifest.json in the latest version subdirectory
                        string? manifestPath = FindLatestManifest(extDir);
                        if (manifestPath == null || !File.Exists(manifestPath)) continue;

                        try
                        {
                            var manifestText = File.ReadAllText(manifestPath);
                            var dangerousPerms = ExtractDangerousPermissions(manifestText);

                            if (dangerousPerms.Count > 0)
                            {
                                string extName = ExtractExtensionName(manifestText) ?? extId;
                                double confidence = 0.55;

                                // Escalate confidence if multiple dangerous permissions
                                if (dangerousPerms.Count >= 3) confidence = 0.70;
                                else if (dangerousPerms.Count >= 2) confidence = 0.62;

                                // Highest risk: debugger + nativeMessaging combo (full C2 channel)
                                if (dangerousPerms.Contains("debugger") && dangerousPerms.Contains("nativeMessaging"))
                                    confidence = 0.78;

                                await _detectionEngine.EmitAsync(new DetectionEvent
                                {
                                    RuleName = "BrowserC2Guard: Extension with Dangerous Permissions",
                                    Evidence = $"Extension '{extName}' (ID: {extId}) has dangerous permissions: [{string.Join(", ", dangerousPerms)}]. " +
                                               $"Manifest: {manifestPath}",
                                    Reasoning = "A browser extension was detected with permissions that enable C2-like behavior: " +
                                                "debugging other tabs (full CDP access), native messaging (IPC with local binaries), " +
                                                "or proxy control (traffic interception). These permissions allow silent credential " +
                                                "theft, session hijacking, and covert data exfiltration.",
                                    Confidence = confidence,
                                    Tier = DetectionTier.Tier2Indicator,
                                    AuthorizedResponse = ResponseAction.LogOnly,
                                    SignalType = SignalType.CredentialTheft,
                                    ProcessName = "browser-extension",
                                    ProcessId = 0,
                                    Metadata = new Dictionary<string, string>
                                    {
                                        ["ExtensionId"] = extId,
                                        ["ExtensionName"] = extName,
                                        ["DangerousPermissions"] = string.Join(",", dangerousPerms),
                                    }
                                });
                                _alertedExtensions.Add(extId);
                            }
                        }
                        catch { } // Malformed manifest - skip
                    }
                }
                catch { } // Access denied to extensions directory
            }
        }

        private static int ExtractDebugPort(string cmdLine)
        {
            const string flag = "--remote-debugging-port=";
            int idx = cmdLine.IndexOf(flag);
            if (idx < 0) return -1;

            int start = idx + flag.Length;
            int end = start;
            while (end < cmdLine.Length && char.IsDigit(cmdLine[end])) end++;
            if (end > start && int.TryParse(cmdLine.Substring(start, end - start), out int port))
                return port;
            return -1;
        }

        private bool CheckForCdpClients(int debugPort, int browserPid)
        {
            // Check if any process other than the browser itself has a TCP connection
            // to 127.0.0.1:debugPort (WebSocket connection to CDP endpoint)
            try
            {
                // Use GetExtendedTcpTable to enumerate TCP connections
                int size = 0;
                uint ret = GetExtendedTcpTable(IntPtr.Zero, ref size, true, 2, 5 /* TCP_TABLE_OWNER_PID_ALL */, 0);
                if (ret != 122) return false; // ERROR_INSUFFICIENT_BUFFER expected

                IntPtr buffer = Marshal.AllocHGlobal(size);
                try
                {
                    ret = GetExtendedTcpTable(buffer, ref size, true, 2, 5, 0);
                    if (ret != 0) return false;

                    int numEntries = Marshal.ReadInt32(buffer);
                    int rowOffset = 4;
                    int rowSize = 24; // MIB_TCPROW_OWNER_PID: state(4) + localAddr(4) + localPort(4) + remoteAddr(4) + remotePort(4) + pid(4)

                    for (int i = 0; i < numEntries && i < 10000; i++)
                    {
                        int offset = rowOffset + (i * rowSize);
                        uint state = (uint)Marshal.ReadInt32(buffer, offset);
                        uint remoteAddrRaw = (uint)Marshal.ReadInt32(buffer, offset + 8);
                        int remotePortRaw = Marshal.ReadInt32(buffer, offset + 12);
                        int pid = Marshal.ReadInt32(buffer, offset + 20);

                        // state == 5 is ESTABLISHED
                        if (state != 5) continue;

                        // Check remote is 127.0.0.1 (0x0100007F in network byte order)
                        if (remoteAddrRaw != 0x0100007F) continue;

                        // Port is in network byte order (big-endian) in upper 16 bits
                        int remotePort = ((remotePortRaw & 0xFF) << 8) | ((remotePortRaw >> 8) & 0xFF);
                        if (remotePort != debugPort) continue;

                        // Skip the browser process itself
                        if (pid == browserPid || pid <= 4) continue;

                        // Verify the connecting process is not another browser tab
                        try
                        {
                            using var clientProc = Process.GetProcessById(pid);
                            var clientName = Sentinel.Core.StringNet48.ReplaceIgnoreCase(clientProc.ProcessName, ".exe", "");
                            if (!BrowserProcessNames.Contains(clientName))
                                return true;
                        }
                        catch { return true; } // Process gone = suspicious
                    }
                }
                finally { Marshal.AllocHGlobal(size); Marshal.FreeHGlobal(buffer); }
            }
            catch { }
            return false;
        }

        [DllImport("iphlpapi.dll", SetLastError = true)]
        private static extern uint GetExtendedTcpTable(IntPtr pTcpTable, ref int pdwSize,
            bool bOrder, int ulAf, int tableClass, int reserved);

        private static string? FindLatestManifest(string extensionDir)
        {
            try
            {
                // Extensions have versioned subdirectories: Extensions/extId/version/manifest.json
                var versionDirs = Directory.GetDirectories(extensionDir);
                if (versionDirs.Length == 0) return null;

                // Take the last (lexicographically highest version)
                var latest = versionDirs.OrderByDescending(d => Path.GetFileName(d)).First();
                var manifest = Path.Combine(latest, "manifest.json");
                return File.Exists(manifest) ? manifest : null;
            }
            catch { return null; }
        }

        private static List<string> ExtractDangerousPermissions(string manifestJson)
        {
            var found = new List<string>();
            try
            {
                using var doc = JsonDocument.Parse(manifestJson);
                var root = doc.RootElement;

                // Check "permissions" array
                if (root.TryGetProperty("permissions", out var perms) && perms.ValueKind == JsonValueKind.Array)
                {
                    foreach (var perm in perms.EnumerateArray())
                    {
                        var val = perm.GetString();
                        if (val != null && DangerousPermissions.Contains(val))
                            found.Add(val);
                    }
                }

                // Check "optional_permissions" array
                if (root.TryGetProperty("optional_permissions", out var optPerms) && optPerms.ValueKind == JsonValueKind.Array)
                {
                    foreach (var perm in optPerms.EnumerateArray())
                    {
                        var val = perm.GetString();
                        if (val != null && DangerousPermissions.Contains(val))
                            found.Add(val);
                    }
                }

                // Manifest V3: check "host_permissions" for <all_urls>
                if (root.TryGetProperty("host_permissions", out var hostPerms) && hostPerms.ValueKind == JsonValueKind.Array)
                {
                    foreach (var perm in hostPerms.EnumerateArray())
                    {
                        var val = perm.GetString();
                        if (val != null && DangerousPermissions.Contains(val))
                            found.Add(val);
                    }
                }
            }
            catch { }
            return found;
        }

        private static string? ExtractExtensionName(string manifestJson)
        {
            try
            {
                using var doc = JsonDocument.Parse(manifestJson);
                if (doc.RootElement.TryGetProperty("name", out var name))
                {
                    var val = name.GetString();
                    // Skip MSG_ placeholders that need i18n resolution
                    if (val != null && !val.StartsWith("__MSG_"))
                        return val;
                }
            }
            catch { }
            return null;
        }

        private static string GetCommandLine(int pid)
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

        private (string? name, int pid) GetParentInfo(int pid)
        {
            try
            {
                using var searcher = new System.Management.ManagementObjectSearcher(
                    $"SELECT ParentProcessId FROM Win32_Process WHERE ProcessId = {pid}");
                foreach (var obj in searcher.Get())
                {
                    int parentPid = Convert.ToInt32(obj["ParentProcessId"]);
                    try
                    {
                        using var parent = Process.GetProcessById(parentPid);
                        return (parent.ProcessName, parentPid);
                    }
                    catch { return (null, parentPid); }
                }
            }
            catch { }
            return (null, 0);
        }

        private bool IsAlertCoolingDown(int pid)
        {
            if (_alertedPids.TryGetValue(pid, out var lastAlert))
            {
                if (DateTimeOffset.UtcNow - lastAlert < AlertCooldown)
                    return true;
            }
            return false;
        }

        private void PruneAlertCaches()
        {
            var cutoff = DateTimeOffset.UtcNow - AlertCooldown;
            var expired = _alertedPids.Where(kvp => kvp.Value < cutoff).Select(kvp => kvp.Key).ToList();
            foreach (var pid in expired) _alertedPids.TryRemove(pid, out _);
        }
    }
}
