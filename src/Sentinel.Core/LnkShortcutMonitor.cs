// LnkShortcutMonitor - Detects malicious .lnk shortcut files targeting UNC/network paths
// Watches Desktop, Start Menu, Taskbar, and Public Desktop for .lnk creation/modification.
// If a shortcut points to a UNC path (\\server\share), it's a known malware delivery vector
// (CVE-2024-21412, APT campaigns, initial access brokers). Emits Tier1 detection + quarantines.

using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Runtime.InteropServices.ComTypes;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace Sentinel.Core
{
    public sealed class LnkShortcutMonitor : BackgroundService
    {
        private readonly DetectionEngine _detectionEngine;
        private readonly JsonlEventLogger _eventLogger;
        private readonly QuarantineManager _quarantineManager;
        private readonly ILogger<LnkShortcutMonitor> _logger;

        private readonly List<FileSystemWatcher> _watchers = new();
        private readonly ConcurrentDictionary<string, DateTime> _recentAlerts = new(StringComparer.OrdinalIgnoreCase);

        private static readonly TimeSpan AlertCooldown = TimeSpan.FromMinutes(5);
        private static readonly TimeSpan PruneInterval = TimeSpan.FromMinutes(10);

        // COM GUIDs for IShellLink
        private static readonly Guid CLSID_ShellLink = new("00021401-0000-0000-C000-000000000046");

        [ComImport]
        [Guid("000214F9-0000-0000-C000-000000000046")]
        [InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
        private interface IShellLinkW
        {
            void GetPath([Out, MarshalAs(UnmanagedType.LPWStr)] System.Text.StringBuilder pszFile, int cch, IntPtr pfd, uint fFlags);
            void GetIDList(out IntPtr ppidl);
            void SetIDList(IntPtr pidl);
            void GetDescription([Out, MarshalAs(UnmanagedType.LPWStr)] System.Text.StringBuilder pszName, int cch);
            void SetDescription([MarshalAs(UnmanagedType.LPWStr)] string pszName);
            void GetWorkingDirectory([Out, MarshalAs(UnmanagedType.LPWStr)] System.Text.StringBuilder pszDir, int cch);
            void SetWorkingDirectory([MarshalAs(UnmanagedType.LPWStr)] string pszDir);
            void GetArguments([Out, MarshalAs(UnmanagedType.LPWStr)] System.Text.StringBuilder pszArgs, int cch);
            void SetArguments([MarshalAs(UnmanagedType.LPWStr)] string pszArgs);
            void GetHotkey(out ushort pwHotkey);
            void SetHotkey(ushort wHotkey);
            void GetShowCmd(out int piShowCmd);
            void SetShowCmd(int iShowCmd);
            void GetIconLocation([Out, MarshalAs(UnmanagedType.LPWStr)] System.Text.StringBuilder pszIconPath, int cch, out int piIcon);
            void SetIconLocation([MarshalAs(UnmanagedType.LPWStr)] string pszIconPath, int iIcon);
            void SetRelativePath([MarshalAs(UnmanagedType.LPWStr)] string pszPathRel, uint dwReserved);
            void Resolve(IntPtr hwnd, uint fFlags);
            void SetPath([MarshalAs(UnmanagedType.LPWStr)] string pszFile);
        }

        public LnkShortcutMonitor(
            DetectionEngine detectionEngine,
            JsonlEventLogger eventLogger,
            QuarantineManager quarantineManager,
            ILogger<LnkShortcutMonitor> logger)
        {
            _detectionEngine = detectionEngine;
            _eventLogger = eventLogger;
            _quarantineManager = quarantineManager;
            _logger = logger;
        }

        protected override async Task ExecuteAsync(CancellationToken ct)
        {
            _logger.LogInformation("[LnkShortcutMonitor] Starting - watching for malicious .lnk files");

            // Start watchers on all target directories
            var watchPaths = GetWatchPaths();
            foreach (var path in watchPaths)
            {
                StartWatcher(path);
            }

            _logger.LogInformation("[LnkShortcutMonitor] Watching {Count} directories for .lnk files", _watchers.Count);

            // Do an initial scan of existing shortcuts
            await Task.Run(() => ScanExistingShortcuts(watchPaths), ct);

            // Keep alive and periodically prune alert cache
            while (!ct.IsCancellationRequested)
            {
                try { await Task.Delay(PruneInterval, ct); }
                catch (OperationCanceledException) { break; }

                PruneAlertCache();
            }

            // Cleanup
            foreach (var watcher in _watchers)
            {
                try { watcher.EnableRaisingEvents = false; watcher.Dispose(); }
                catch { }
            }
        }

        private List<string> GetWatchPaths()
        {
            var paths = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

            void Add(string? p)
            {
                if (!string.IsNullOrWhiteSpace(p) && Directory.Exists(p))
                    paths.Add(p!);
            }

            // Service runs as SYSTEM - enumerate every interactive user profile (not just SYSTEM's dirs)
            try
            {
                var usersRoot = Path.GetFullPath(Path.Combine(
                    Environment.GetFolderPath(Environment.SpecialFolder.Windows), @"..\Users"));
                if (Directory.Exists(usersRoot))
                {
                    foreach (var userDir in Directory.EnumerateDirectories(usersRoot))
                    {
                        var name = Path.GetFileName(userDir);
                        if (name is "Public" or "Default" or "Default User" or "All Users" or "desktop.ini")
                            continue;
                        Add(Path.Combine(userDir, "Desktop"));
                        Add(Path.Combine(userDir, @"AppData\Roaming\Microsoft\Windows\Start Menu\Programs"));
                        Add(Path.Combine(userDir, @"AppData\Roaming\Microsoft\Internet Explorer\Quick Launch\User Pinned\TaskBar"));
                        Add(Path.Combine(userDir, @"AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup"));
                    }
                }
            }
            catch { /* best effort */ }

            // Common / current-session fallbacks
            Add(Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory));
            Add(Environment.GetFolderPath(Environment.SpecialFolder.CommonDesktopDirectory));
            Add(Environment.GetFolderPath(Environment.SpecialFolder.Programs));
            Add(Environment.GetFolderPath(Environment.SpecialFolder.CommonPrograms));
            Add(Environment.GetFolderPath(Environment.SpecialFolder.Startup));
            Add(Environment.GetFolderPath(Environment.SpecialFolder.CommonStartup));
            Add(Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
                @"Microsoft\Internet Explorer\Quick Launch\User Pinned\TaskBar"));

            return paths.ToList();
        }

        private void StartWatcher(string path)
        {
            try
            {
                var watcher = new FileSystemWatcher(path)
                {
                    IncludeSubdirectories = true,
                    NotifyFilter = NotifyFilters.FileName | NotifyFilters.LastWrite | NotifyFilters.CreationTime,
                    Filter = "*.lnk"
                };

                watcher.Created += OnLnkEvent;
                watcher.Changed += OnLnkEvent;
                watcher.Renamed += OnLnkRenamed;
                watcher.EnableRaisingEvents = true;

                _watchers.Add(watcher);
                _logger.LogDebug("[LnkShortcutMonitor] Watching: {Path}", path);
            }
            catch (Exception ex)
            {
                _logger.LogWarning("[LnkShortcutMonitor] Failed to watch {Path}: {Error}", path, ex.Message);
            }
        }

        private void OnLnkEvent(object sender, FileSystemEventArgs e)
        {
            // Small delay to let the file finish writing
            Thread.Sleep(200);
            AnalyzeShortcut(e.FullPath);
        }

        private void OnLnkRenamed(object sender, RenamedEventArgs e)
        {
            if (e.FullPath.EndsWith(".lnk"))
            {
                Thread.Sleep(200);
                AnalyzeShortcut(e.FullPath);
            }
        }

        private void AnalyzeShortcut(string lnkPath)
        {
            try
            {
                if (!File.Exists(lnkPath)) return;

                // Dedup: don't re-alert on the same file within cooldown
                if (_recentAlerts.TryGetValue(lnkPath, out var lastAlert) &&
                    DateTime.UtcNow - lastAlert < AlertCooldown)
                    return;

                if (!TryGetShortcut(lnkPath, out var target, out var args))
                    return;

                if (!IsMaliciousShortcut(target, args, out var attackVector))
                    return;

                _recentAlerts[lnkPath] = DateTime.UtcNow;

                var confidence = attackVector is "UNC_Path" or "RemoteLauncher" ? 0.92 : 0.80;
                var description = attackVector switch
                {
                    "UNC_Path" => $"Shortcut targets UNC network path: {target}",
                    "RemoteLauncher" => $"Shortcut launches remote payload via args: Target='{target}' Args='{args}'",
                    _ => $"Shortcut targets suspicious protocol handler: {target}"
                };

                var reasoning = attackVector switch
                {
                    "UNC_Path" =>
                        "A .lnk shortcut file was created or modified to point to a UNC network path (\\\\server\\share). " +
                        "This is a well-known initial access technique (T1566.002) used by APT groups and initial access brokers " +
                        "to deliver malware payloads from attacker-controlled SMB/WebDAV shares. " +
                        "CVE-2024-21412 and related vulnerabilities exploit this exact vector.",
                    "RemoteLauncher" =>
                        "A .lnk shortcut invokes powershell/cmd/mshta/wscript/rundll32 with a UNC path or remote URL in " +
                        "its arguments - a common phishing dropper pattern that executes remote code without a UNC target path.",
                    _ =>
                        "A .lnk shortcut file targets a suspicious protocol handler (search-ms:, ms-msdt:, or remote URL). " +
                        "These are used in phishing campaigns to trigger code execution via protocol handler abuse."
                };

                _ = _detectionEngine.EmitAsync(new DetectionEvent
                {
                    RuleName = "LnkShortcutMonitor: Malicious Network Shortcut",
                    ProcessName = "SYSTEM",
                    ProcessId = 0,
                    SignalType = SignalType.SuspiciousProcess,
                    Confidence = confidence,
                    Tier = DetectionTier.Tier1Behavioral,
                    AuthorizedResponse = ResponseAction.Quarantine,
                    Evidence = $"Malicious .lnk detected at '{lnkPath}' - {description}",
                    Reasoning = reasoning,
                    Metadata = new Dictionary<string, string>
                    {
                        { "LnkPath", lnkPath },
                        { "Target", target ?? string.Empty },
                        { "Arguments", args ?? string.Empty },
                        { "AttackVector", attackVector }
                    }
                });

                _logger.LogWarning("[LnkShortcutMonitor] MALICIOUS .lnk detected: {Path} -> {Target} | Args={Args}",
                    lnkPath, target, args);

                // Attempt to quarantine the malicious shortcut
                try
                {
                    _ = _quarantineManager.QuarantineFileAtomicAsync(lnkPath);
                    _logger.LogInformation("[LnkShortcutMonitor] Quarantined: {Path}", lnkPath);
                }
                catch (Exception qex)
                {
                    // Fallback: delete the shortcut if quarantine fails
                    try
                    {
                        File.Delete(lnkPath);
                        _logger.LogInformation("[LnkShortcutMonitor] Deleted malicious .lnk (quarantine failed): {Path}", lnkPath);
                    }
                    catch (Exception dex)
                    {
                        _logger.LogWarning("[LnkShortcutMonitor] Failed to remove malicious .lnk {Path}: quarantine={QError}, delete={DError}",
                            lnkPath, qex.Message, dex.Message);
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "[LnkShortcutMonitor] Error analyzing {Path}", lnkPath);
            }
        }

        private void ScanExistingShortcuts(List<string> paths)
        {
            int scanned = 0;
            int detected = 0;

            foreach (var path in paths)
            {
                try
                {
                    foreach (var lnk in Directory.EnumerateFiles(path, "*.lnk", SearchOption.AllDirectories))
                    {
                        scanned++;
                        try
                        {
                            if (TryGetShortcut(lnk, out var target, out var args) &&
                                IsMaliciousShortcut(target, args, out _))
                            {
                                detected++;
                                AnalyzeShortcut(lnk);
                            }
                        }
                        catch { }
                    }
                }
                catch { }
            }

            if (detected > 0)
            {
                _logger.LogWarning("[LnkShortcutMonitor] Initial scan: {Detected} malicious shortcuts found out of {Scanned} scanned", detected, scanned);
            }
            else
            {
                _logger.LogInformation("[LnkShortcutMonitor] Initial scan: {Scanned} shortcuts scanned, none malicious", scanned);
            }
        }

        /// <summary>
        /// Classifies shortcut target + arguments as malicious (UNC, protocol handler, remote launcher).
        /// Public for unit tests. Shared heuristics with the PowerShell LNKProtection / Grok.ps1 ports.
        /// </summary>
        public static bool IsMaliciousShortcut(string? targetPath, string? arguments)
            => IsMaliciousShortcut(targetPath, arguments, out _);

        /// <summary>
        /// Same as <see cref="IsMaliciousShortcut(string?,string?)"/> but returns a short attack-vector tag.
        /// </summary>
        public static bool IsMaliciousShortcut(string? targetPath, string? arguments, out string attackVector)
        {
            targetPath ??= string.Empty;
            arguments ??= string.Empty;
            attackVector = string.Empty;

            if (targetPath.StartsWith(@"\\") ||
                targetPath.StartsWith("//"))
            {
                attackVector = "UNC_Path";
                return true;
            }

            if (targetPath.StartsWith("http://") ||
                targetPath.StartsWith("https://") ||
                targetPath.StartsWith("search-ms:") ||
                targetPath.StartsWith("ms-msdt:"))
            {
                attackVector = "ProtocolHandler";
                return true;
            }

            var combo = (targetPath + " " + arguments).ToLowerInvariant();
            bool hasUncInArgs = arguments.Contains(@"\\") ||
                                arguments.Contains("//");
            bool hasRemoteUrl = combo.Contains("http://") || combo.Contains("https://");
            bool isLolbin = combo.Contains("powershell") || combo.Contains("cmd.exe") ||
                            combo.Contains("mshta") || combo.Contains("wscript") ||
                            combo.Contains("cscript") || combo.Contains("rundll32");

            // Bare UNC in arguments is still a delivery vector for .lnk phishing
            if (hasUncInArgs)
            {
                attackVector = isLolbin ? "RemoteLauncher" : "UNC_Path";
                return true;
            }

            // LOLBin + remote URL in target/args
            if (isLolbin && hasRemoteUrl)
            {
                attackVector = "RemoteLauncher";
                return true;
            }

            return false;
        }

        /// <summary>
        /// Resolves target path + arguments of a .lnk shortcut using COM IShellLink.
        /// Falls back to binary UNC scan if COM fails.
        /// </summary>
        internal static bool TryGetShortcut(string lnkPath, out string? targetPath, out string? arguments)
        {
            targetPath = null;
            arguments = null;

            // Method 1: COM IShellLink (most reliable)
            try
            {
                var shellLink = (IShellLinkW)Activator.CreateInstance(Type.GetTypeFromCLSID(CLSID_ShellLink)!)!;
                var persistFile = (IPersistFile)shellLink;
                persistFile.Load(lnkPath, 0);

                var pathBuffer = new System.Text.StringBuilder(1024);
                shellLink.GetPath(pathBuffer, pathBuffer.Capacity, IntPtr.Zero, 0x0004 /* SLGP_RAWPATH */);
                targetPath = pathBuffer.ToString();

                var argsBuffer = new System.Text.StringBuilder(2048);
                shellLink.GetArguments(argsBuffer, argsBuffer.Capacity);
                arguments = argsBuffer.ToString();

                if (!string.IsNullOrWhiteSpace(targetPath) || !string.IsNullOrWhiteSpace(arguments))
                    return true;
            }
            catch { }

            // Method 2: Simple binary scan for UNC paths in the .lnk file
            try
            {
                var bytes = File.ReadAllBytes(lnkPath);
                if (bytes.Length > 100)
                {
                    var content = System.Text.Encoding.Unicode.GetString(bytes);
                    var uncIdx = content.IndexOf(@"\\");
                    if (uncIdx >= 0)
                    {
                        var end = content.IndexOfAny(new[] { '\0', ' ', '"' }, uncIdx + 2);
                        if (end > uncIdx)
                        {
                            targetPath = content.Substring(uncIdx, end - uncIdx);
                            return true;
                        }
                    }
                }
            }
            catch { }

            return false;
        }

        private void PruneAlertCache()
        {
            var cutoff = DateTime.UtcNow.AddMinutes(-30);
            var stale = _recentAlerts.Where(kv => kv.Value < cutoff).Select(kv => kv.Key).ToList();
            foreach (var key in stale)
                _recentAlerts.TryRemove(key, out _);
        }
    }
}
