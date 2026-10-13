using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using Microsoft.Win32;

namespace Sentinel.Core
{
    /// <summary>
    /// Traces the full attack chain from a detected malicious process back to its
    /// origin. Walks the parent process tree, identifies the attack root (first
    /// non-system / non-browser host process), and performs chain-level response:
    ///   1. Kill processes in the chain (except system hosts and legitimate browsers)
    ///   2. Quarantine non-system, unsigned binaries (signed hosts preserved)
    ///   3. Remove persistence (Run keys, scheduled tasks)
    ///   4. Log complete chain evidence
    /// Only invoked for Tier1 detections with KillAuthorized when ActiveResponse is enabled.
    ///
    /// Drive-by / installer safety: if malware is launched from a browser or browser
    /// installer (chrome -> dropper, ChromeSetup -> setup -> payload), we kill/quarantine
    /// the payload but do NOT destroy the browser or signed installer on disk.
    /// </summary>
    public sealed class ChainTracer
    {
        private readonly ProcessAncestryCache _ancestryCache;
        private readonly QuarantineManager _quarantineManager;
        private readonly JsonlEventLogger _eventLogger;
        private readonly SentinelConfig _config;
        private readonly ILogger<ChainTracer> _logger;

        private static readonly HashSet<string> CriticalSystemProcesses = new(StringComparer.OrdinalIgnoreCase)
        {
            "system", "registry", "smss", "csrss", "wininit", "services", "lsass", "svchost",
            "explorer", "dwm", "sihost", "fontdrvhost", "winlogon"
        };

        private static readonly HashSet<string> SystemBinaries = new(StringComparer.OrdinalIgnoreCase)
        {
            "cmd", "cmd.exe", "powershell", "powershell.exe", "pwsh", "pwsh.exe",
            "conhost", "conhost.exe", "rundll32", "rundll32.exe",
            "mshta", "mshta.exe", "wscript", "wscript.exe", "cscript", "cscript.exe",
            "regsvr32", "regsvr32.exe", "msiexec", "msiexec.exe",
        };

        /// <summary>
        /// Browser / browser-installer process stems. Name alone is never enough -
        /// <see cref="IsLegitimateBrowserHost"/> also requires a legitimate install path
        /// or a valid Authenticode signature (for first-run installers on Desktop).
        /// </summary>
        private static readonly HashSet<string> BrowserHostNames = new(StringComparer.OrdinalIgnoreCase)
        {
            "chrome", "msedge", "msedgewebview2", "firefox", "brave", "opera", "vivaldi",
            "iexplore", "chromium",
            // Official installers / updaters (often run from Desktop/Downloads/Temp)
            "chromesetup", "chrome_installer", "mini_installer", "setup",
            "googleupdate", "googleupdated", "microsoftedgeupdate",
            "braveupdate", "opera_standalone", "firefox setup", "firefox setup stub"
        };

        /// <summary>
        /// IDE / development tool process stems. These are Electron/CEF apps that spawn
        /// many child processes (node, electron helpers, conhost, terminals). If a child
        /// triggers a detection, we kill the child but NEVER walk up and kill the IDE host
        /// - that destroys the developer's session and is an irreversible false positive.
        /// Protection requires the binary to reside in a legitimate install path (Program Files
        /// or user AppData/Local/Programs) to prevent abuse via renames in Temp/Downloads.
        /// </summary>
        private static readonly HashSet<string> IdeHostProcessNames = new(StringComparer.OrdinalIgnoreCase)
        {
            "code", "Code - Insiders", "kiro", "cursor", "windsurf", "positron",
            "Devin", "Antigravity IDE",
            "rider64", "idea64", "phpstorm64", "webstorm64", "goland64",
            "pycharm64", "clion64", "rubymine64", "datagrip64",
            "devenv", // Visual Studio
        };

        // Non-writable install roots: a name match here self-authorizes (an attacker cannot
        // write Program Files / WindowsApps without already being admin/TrustedInstaller).
        private static readonly string[] NonWritableIdePaths =
        {
            @"\program files\",
            @"\program files (x86)\",
            @"\windowsapps\",
        };

        // User-writable per-user install roots. IDEs legitimately install here, but so can an
        // attacker drop a renamed "code.exe" - so a name match in these locations is only
        // honored when the binary ALSO carries a valid Authenticode signature.
        private static readonly string[] UserWritableIdePaths =
        {
            @"\appdata\local\programs\",
            @"\appdata\local\kiro\",
            @"\appdata\local\cursor\",
            @"\appdata\local\microsoft vs code\",
            @"\appdata\local\devin\",
            @"\jetbrains\",
        };

        private static readonly string[] LegitimateBrowserPaths =
        {
            @"\program files\google\chrome\",
            @"\program files (x86)\google\chrome\",
            @"\program files\microsoft\edge\",
            @"\program files (x86)\microsoft\edge\",
            @"\program files\mozilla firefox\",
            @"\program files (x86)\mozilla firefox\",
            @"\program files\brave software\",
            @"\program files (x86)\brave software\",
            @"\program files\opera\",
            @"\program files (x86)\opera\",
            @"\program files\vivaldi\",
            @"\appdata\local\google\chrome\",
            @"\appdata\local\microsoft\edge\",
            @"\appdata\local\brave software\",
            @"\appdata\local\vivaldi\",
            @"\appdata\local\programs\opera\",
            @"\appdata\local\mozilla firefox\",
            @"\windowsapps\",
        };

        // v2.2.0: System32 / SysWOW64 only. The previous Windows\ prefix treated
        // C:\Windows\Temp (and Tasks, Prefetch, ...) as "OS critical" and skipped quarantine.
        private static readonly string[] SystemPaths = new[]
        {
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "System32") + @"\",
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "SysWOW64") + @"\",
        };

        public ChainTracer(
            ProcessAncestryCache ancestryCache,
            QuarantineManager quarantineManager,
            JsonlEventLogger eventLogger,
            SentinelConfig config,
            ILogger<ChainTracer> logger)
        {
            _ancestryCache = ancestryCache;
            _quarantineManager = quarantineManager;
            _eventLogger = eventLogger;
            _config = config;
            _logger = logger;
        }

        /// <summary>
        /// Traces and responds to the attack chain rooted at the detected process.
        /// </summary>
        public async Task<ChainTraceResult> TraceAndRespondAsync(DetectionEvent detection, CancellationToken ct = default)
        {
            var result = new ChainTraceResult
            {
                RootDetection = detection,
                StartTime = DateTimeOffset.UtcNow
            };

            try
            {
                // 1. Walk parent chain
                var chain = WalkParentChain(detection.ProcessId, detection.ProcessName);
                result.ParentChain = chain;
                result.AllChainProcesses = chain;

                // 2. Attack root = first non-system, non-browser host walking toward the parent.
                //    malware -> chrome -> explorer  => attack root is malware (not chrome).
                result.AttackRoot = chain.LastOrDefault(n =>
                    !IsSystemBinary(n.ImagePath, n.ProcessName) &&
                    !IsLegitimateBrowserHost(n.ImagePath, n.ProcessName))
                    ?? chain.LastOrDefault(n => !IsSystemBinary(n.ImagePath, n.ProcessName))
                    ?? chain.LastOrDefault();

                // 3. Kill chain if active response is enabled
                if (_config.ActiveResponse && detection.KillAuthorized &&
                    ResponsePolicy.MayPerformDestructiveResponse(detection, _config))
                {
                    // FP 2026-08-01: PPID mismatch on System32\conhost -> chain walked to WinReducer and killed it.
                    // If the *detected* process is a stock Windows console host (or any OS-critical path),
                    // never walk-up kill user tools. Log/response engine should already demote these;
                    // this is defense-in-depth if KillAuthorized was set incorrectly.
                    // Prefer ancestry path for the detection PID (DetectionEvent has no ImagePath).
                    string? detectionPath = chain.FirstOrDefault(n => n.ProcessId == detection.ProcessId)?.ImagePath
                        ?? chain.FirstOrDefault()?.ImagePath;
                    if (string.IsNullOrEmpty(detectionPath))
                        detectionPath = SecurityValidation.GetProcessImagePath(detection.ProcessId);

                    if (ParentPidSpoofDetector.IsStockWindowsConsoleHost(detection.ProcessName, detectionPath) ||
                        (!string.IsNullOrEmpty(detectionPath) && SecurityValidation.IsOsCriticalPath(detectionPath) &&
                         detection.RuleName.StartsWith("PPID Spoofing")))
                    {
                        _logger.LogInformation(
                            "[ChainTracer] Skipping chain kill - detection is stock OS console/host PPID race (PID {Pid} {Name} path={Path})",
                            detection.ProcessId, detection.ProcessName, detectionPath);
                        result.EndTime = DateTimeOffset.UtcNow;
                        result.Success = true;
                        await LogChainEvidenceAsync(result);
                        return result;
                    }

                    foreach (var node in chain)
                    {
                        var cleanName = Sentinel.Core.StringNet48.ReplaceIgnoreCase(node.ProcessName, ".exe", "");

                        // Critical system hosts (explorer, csrss, ...):
                        // - Path under Windows -> never kill
                        // - Path unknown/empty -> never kill (FP 2026-07-25: explorer killed when path unresolved)
                        // - Path known OUTSIDE Windows -> kill (malware renamed explorer.exe in Temp)
                        if (CriticalSystemProcesses.Contains(cleanName))
                        {
                            if (string.IsNullOrEmpty(node.ImagePath) || IsSystemBinary(node.ImagePath, node.ProcessName))
                                continue;
                        }

                        // Stock conhost/openconsole under Windows: never kill as chain member
                        if (ParentPidSpoofDetector.IsStockWindowsConsoleHost(node.ProcessName, node.ImagePath))
                            continue;

                        // Preserve browser / signed browser-installer ancestors.
                        // If the *detected* process itself is a browser (extension compromise,
                        // remote-debug abuse), we still kill that PID - only ancestors are skipped.
                        if (node.ProcessId != detection.ProcessId &&
                            IsLegitimateBrowserHost(node.ImagePath, node.ProcessName))
                        {
                            _logger.LogInformation(
                                "[ChainTracer] Preserving browser/installer host PID {Pid} ({Name}) path={Path}",
                                node.ProcessId, node.ProcessName, node.ImagePath);
                            continue;
                        }

                        // Signed installer ancestors (Git, ChromeSetup, SentinelSetup, ...)
                        if (node.ProcessId != detection.ProcessId &&
                            !string.IsNullOrEmpty(node.ImagePath) &&
                            InstallerHeuristics.LooksLikeInstallerName(node.ProcessName, node.ImagePath) &&
                            File.Exists(node.ImagePath) &&
                            SecurityValidation.VerifyAuthenticodeSignature(node.ImagePath!))
                        {
                            _logger.LogInformation(
                                "[ChainTracer] Preserving signed installer ancestor PID {Pid} ({Name})",
                                node.ProcessId, node.ProcessName);
                            continue;
                        }

                        if (node.ProcessId != detection.ProcessId &&
                            InstallerHeuristics.IsInstallerExtractor(node.ProcessName, node.ImagePath))
                        {
                            _logger.LogInformation(
                                "[ChainTracer] Preserving installer extractor ancestor PID {Pid} ({Name})",
                                node.ProcessId, node.ProcessName);
                            continue;
                        }

                        // IDE / development tool hosts (Kiro, VS Code, Cursor, Rider, etc.):
                        // These Electron/JIT apps spawn many child processes (node, tsserver,
                        // extension hosts, terminals). Killing the IDE host is an irreversible
                        // false positive that destroys the developer's entire session.
                        // We only skip killing if the binary is in a legitimate install path.
                        if (node.ProcessId != detection.ProcessId && IsLegitimateIdeHost(node.ImagePath, node.ProcessName))
                        {
                            _logger.LogInformation(
                                "[ChainTracer] Preserving IDE host PID {Pid} ({Name}) path={Path}",
                                node.ProcessId, node.ProcessName, node.ImagePath);
                            continue;
                        }

                        try
                        {
                            HardeningModule.SafeKillProcessTree(node.ProcessId);
                            result.KilledProcesses.Add(new KilledProcessInfo
                            {
                                ProcessId = node.ProcessId,
                                ProcessName = node.ProcessName,
                                ImagePath = node.ImagePath,
                                IsSystemBinary = IsSystemBinary(node.ImagePath, node.ProcessName),
                                KillTime = DateTimeOffset.UtcNow
                            });
                        }
                        catch (Exception ex)
                        {
                            _logger.LogDebug(ex, "[ChainTracer] Failed to kill PID {Pid}", node.ProcessId);
                        }
                    }

                    // 4. Quarantine non-system binaries - never browsers, never signed Authenticode hosts.
                    //    Matches AdvancedResponseEngine v1.5.9: signed injectors are killed but preserved on disk.
                    foreach (var node in chain.Where(n => !string.IsNullOrEmpty(n.ImagePath) && !IsSystemBinary(n.ImagePath, n.ProcessName)))
                    {
                        try
                        {
                            if (File.Exists(node.ImagePath))
                            {
                                // NEVER quarantine files from Windows system directories -
                                // these are WRP-protected and removing them breaks the OS.
                                var lowerPath = node.ImagePath!.ToLowerInvariant();
                                if (lowerPath.Contains(@"\windows\system32\") ||
                                    lowerPath.Contains(@"\windows\syswow64\") ||
                                    lowerPath.Contains(@"\windows\winsxs\"))
                                {
                                    _logger.LogWarning("[ChainTracer] Skipping quarantine of system binary: {Path}", node.ImagePath);
                                    continue;
                                }

                                if (IsLegitimateBrowserHost(node.ImagePath, node.ProcessName))
                                {
                                    _logger.LogInformation(
                                        "[ChainTracer] Skipping quarantine of browser/installer host: {Path}",
                                        node.ImagePath);
                                    continue;
                                }

                                var hash = await ComputeFileHashAsync(node.ImagePath!, ct);
                                // QuarantineManager refuses Authenticode-signed files by default
                                // (Git/Chrome/VS installers, etc.). Only unsigned chain members move.
                                var qPath = await _quarantineManager.QuarantineFileAtomicAsync(node.ImagePath!);
                                if (qPath == null)
                                {
                                    _logger.LogInformation(
                                        "[ChainTracer] Skipping quarantine (signed or refused): {Path}",
                                        node.ImagePath);
                                    continue;
                                }

                                result.QuarantinedFiles.Add(new QuarantinedFileInfo
                                {
                                    OriginalPath = node.ImagePath!,
                                    ProcessId = node.ProcessId,
                                    ProcessName = node.ProcessName,
                                    FileHash = hash,
                                    QuarantineTime = DateTimeOffset.UtcNow
                                });
                            }
                        }
                        catch { }
                    }

                    // 5. Remove persistence
                    await RemovePersistenceAsync(chain, result, ct);
                }

                // 6. Log chain evidence
                result.EndTime = DateTimeOffset.UtcNow;
                result.Success = true;
                await LogChainEvidenceAsync(result);
            }
            catch (Exception ex)
            {
                result.Success = false;
                result.ErrorMessage = ex.Message;
                _logger.LogError(ex, "[ChainTracer] Chain trace failed for PID {Pid}", detection.ProcessId);
            }

            return result;
        }

        private List<ProcessNode> WalkParentChain(int pid, string processName)
        {
            var chain = new List<ProcessNode>();
            var visited = new HashSet<int>();
            int currentPid = pid;
            string currentName = processName;

            for (int depth = 0; depth < 20; depth++)
            {
                if (currentPid <= 4 || visited.Contains(currentPid)) break;
                visited.Add(currentPid);

                var procInfo = _ancestryCache.GetProcessInfo(currentPid);
                string? imagePath = !string.IsNullOrEmpty(procInfo.imagePath) ? procInfo.imagePath : null;
                if (string.IsNullOrEmpty(currentName)) currentName = procInfo.name;

                chain.Add(new ProcessNode
                {
                    ProcessId = currentPid,
                    ProcessName = currentName,
                    ImagePath = imagePath,
                    IsSystemBinary = IsSystemBinary(imagePath, currentName)
                });

                var (parentPid, parentName) = _ancestryCache.GetParent(currentPid);
                if (parentPid <= 0) break;
                currentPid = parentPid;
                currentName = parentName;
            }

            return chain;
        }

        private async Task RemovePersistenceAsync(List<ProcessNode> chain, ChainTraceResult result, CancellationToken ct)
        {
            var imagePaths = chain
                .Where(n => !string.IsNullOrEmpty(n.ImagePath))
                .Select(n => n.ImagePath!.ToLowerInvariant())
                .ToHashSet();

            // Check Run keys
            var runKeyPaths = new[]
            {
                @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
                @"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
            };

            foreach (var keyPath in runKeyPaths)
            {
                try
                {
                    using var key = Registry.LocalMachine.OpenSubKey(keyPath, writable: true);
                    if (key == null) continue;
                    foreach (var name in key.GetValueNames())
                    {
                        var val = key.GetValue(name)?.ToString()?.ToLowerInvariant() ?? "";
                        if (imagePaths.Any(p => val.Contains(p)))
                        {
                            key.DeleteValue(name);
                            result.PersistenceRemoved.Add(new PersistenceInfo
                            {
                                Type = "RunKey", Location = $"HKLM\\{keyPath}", Name = name, Value = val, Removed = true
                            });
                        }
                    }
                }
                catch { }
            }
        }

        private async Task LogChainEvidenceAsync(ChainTraceResult result)
        {
            var evidence = new
            {
                Type = "ChainTrace",
                result.RootDetection.RuleName,
                result.RootDetection.ProcessId,
                result.RootDetection.ProcessName,
                AttackRoot = result.AttackRoot?.ProcessName,
                ChainLength = result.AllChainProcesses.Count,
                Killed = result.KilledProcesses.Count,
                Quarantined = result.QuarantinedFiles.Count,
                PersistenceRemoved = result.PersistenceRemoved.Count,
                result.StartTime,
                result.EndTime,
                DurationMs = (result.EndTime - result.StartTime).TotalMilliseconds
            };
            await _eventLogger.LogEventAsync("chain_trace", evidence);
        }

        internal static bool IsSystemBinary(string? imagePath, string processName)
        {
            // Never trust name alone - require path verification.
            // v2.2.0: OrdinalIgnoreCase; never treat Windows\Temp as system.
            if (string.IsNullOrEmpty(imagePath)) return false;
            try
            {
                var full = Path.GetFullPath(imagePath);
                var win = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
                var winTemp = Path.Combine(win, "Temp") + Path.DirectorySeparatorChar;
                if (full.StartsWith(winTemp, StringComparison.OrdinalIgnoreCase))
                    return false;
                return SystemPaths.Any(sp => full.StartsWith(sp, StringComparison.OrdinalIgnoreCase));
            }
            catch
            {
                return false;
            }
        }

        /// <summary>
        /// True for a real browser or browser installer that must not be killed as a
        /// parent of a malicious child, and must never be quarantined.
        ///
        /// Trust rules (never name alone):
        /// 1. Known browser name + path under a legitimate browser install dir
        /// 2. Known browser/installer name + valid Authenticode (covers Desktop/Downloads
        ///    ChromeSetup.exe on a fresh Windows image before install completes)
        /// 3. Name "setup" only via Authenticode (too generic for path-only trust)
        ///
        /// Malware renamed chrome.exe in Temp without a valid Google signature fails both checks.
        /// </summary>
        internal static bool IsLegitimateBrowserHost(string? imagePath, string processName)
        {
            if (string.IsNullOrEmpty(processName)) return false;

            var stem = Sentinel.Core.StringNet48.ReplaceIgnoreCase(processName, ".exe", "").Trim();
            if (string.IsNullOrEmpty(stem)) return false;

            bool isGenericSetup = stem.Equals("setup");
            bool nameMatches = BrowserHostNames.Contains(stem) ||
                               stem.StartsWith("firefox setup") ||
                               stem.Contains("chromesetup") ||
                               stem.Contains("chrome_installer") ||
                               stem.Contains("mini_installer");

            if (!nameMatches) return false;

            // Installed browser at an expected path (not Temp staging of "chrome.exe").
            if (!isGenericSetup && !string.IsNullOrEmpty(imagePath))
            {
                var lower = imagePath!.ToLowerInvariant();

                // True staging / drop dirs are never a trusted install location - a renamed
                // chrome.exe there must fail. We check these EXPLICITLY (Temp/Downloads/Desktop/
                // Public) rather than via ModuleIdentity.IsUserWritableDrop, because that helper
                // treats the whole of \appdata\local\ as a drop - yet Chrome/Edge/Firefox
                // legitimately install PER-USER under AppData (\appdata\local\google\chrome\, ...).
                bool inStagingDrop =
                    lower.Contains(@"\temp\") ||
                    lower.Contains(@"\tmp\") ||
                    lower.Contains(@"\downloads\") ||
                    lower.Contains(@"\desktop\") ||
                    lower.Contains(@"\users\public\") ||
                    lower.Contains(@"\appdata\local\temp\");

                // The LegitimateBrowserPaths entries are deep, vendor-structured canonical install
                // subpaths; that specific structure IS the non-attacker-controllable anchor. A
                // shallow AppData drop (\appdata\local\chrome.exe) does not match them.
                if (!inStagingDrop && LegitimateBrowserPaths.Any(p => lower.Contains(p)))
                {
                    return true;
                }
            }

            // Desktop extras / Downloads installers, or setup.exe extracted under Temp:
            // require a real Authenticode signature (Google LLC, Microsoft, Mozilla, ...).
            if (!string.IsNullOrEmpty(imagePath) && File.Exists(imagePath))
            {
                try
                {
                    if (SecurityValidation.VerifyAuthenticodeSignature(imagePath!))
                        return true;
                }
                catch { /* treat as untrusted */ }
            }

            return false;
        }

        private static async Task<string> ComputeFileHashAsync(string filePath, CancellationToken ct)
        {
            try
            {
                using var sha256 = SHA256.Create();
                using var stream = new FileStream(filePath, FileMode.Open, FileAccess.Read,
                    FileShare.ReadWrite | FileShare.Delete);
                var hash = await sha256.ComputeHashAsync(stream, ct);
                return ConvertHex.ToHexString(hash);
            }
            catch { return ""; }
        }

        /// <summary>
        /// v1.6.9 / hardened: Determines whether a process is a legitimate IDE/dev-tool host,
        /// so we never walk up and kill the developer's IDE on a child-process detection.
        /// Requires the process NAME to match a known IDE stem AND a non-attacker-controllable
        /// anchor:
        ///   - a NON-writable install root (Program Files / WindowsApps) - self-authorizes, OR
        ///   - a user-writable per-user install root (AppData\Local\Programs, JetBrains, ...)
        ///     ONLY when the binary carries a valid Authenticode signature, OR
        ///   - any other location ONLY when validly Authenticode-signed.
        /// A renamed "kiro.exe" / "code.exe" in Temp/Downloads (or unsigned in AppData) is NOT
        /// protected. Name + writable-path-substring alone is never sufficient.
        /// </summary>
        internal static bool IsLegitimateIdeHost(string? imagePath, string processName)
        {
            if (string.IsNullOrEmpty(processName)) return false;
            var cleanName = Sentinel.Core.StringNet48.ReplaceIgnoreCase(processName, ".exe", "");
            if (!IdeHostProcessNames.Contains(cleanName)) return false;
            if (string.IsNullOrEmpty(imagePath)) return false;

            var lowerPath = imagePath!.ToLowerInvariant();

            // True staging / drop dirs are never protected - a renamed "kiro.exe"/"code.exe"
            // there must fail. Checked explicitly (not via ModuleIdentity.IsUserWritableDrop)
            // because that helper treats all of \appdata\local\ as a drop, yet IDEs legitimately
            // install PER-USER under \appdata\local\programs\.
            bool inStagingDrop =
                lowerPath.Contains(@"\temp\") ||
                lowerPath.Contains(@"\tmp\") ||
                lowerPath.Contains(@"\downloads\") ||
                lowerPath.Contains(@"\desktop\") ||
                lowerPath.Contains(@"\users\public\") ||
                lowerPath.Contains(@"\appdata\local\temp\");
            if (inStagingDrop)
                return false;

            // Non-writable install root (Program Files / WindowsApps) -> name match is enough.
            if (NonWritableIdePaths.Any(p => lowerPath.Contains(p)))
                return true;

            // Per-user install roots are deep, vendor-structured canonical paths
            // (\appdata\local\programs\, \appdata\local\kiro\, \jetbrains\, ...). IDEs legitimately
            // install per-user there, so that specific install-subpath structure is the anchor and
            // self-authorizes. Shallow drops don't match (and were already rejected above).
            if (UserWritableIdePaths.Any(p => lowerPath.Contains(p)))
                return true;

            // Anywhere else (e.g. a secondary drive): only protected when validly Authenticode-signed.
            try
            {
                if (File.Exists(imagePath) && SecurityValidation.VerifyAuthenticodeSignature(imagePath))
                    return true;
            }
            catch { /* treat as untrusted */ }

            return false;
        }
    }

    public sealed class ProcessNode
    {
        public int ProcessId { get; set; }
        public string ProcessName { get; set; } = "";
        public string? ImagePath { get; set; }
        public bool IsSystemBinary { get; set; }
    }

    public sealed class KilledProcessInfo
    {
        public int ProcessId { get; set; }
        public string ProcessName { get; set; } = "";
        public string? ImagePath { get; set; }
        public bool IsSystemBinary { get; set; }
        public DateTimeOffset KillTime { get; set; }
    }

    public sealed class QuarantinedFileInfo
    {
        public string OriginalPath { get; set; } = "";
        public int ProcessId { get; set; }
        public string ProcessName { get; set; } = "";
        public string FileHash { get; set; } = "";
        public DateTimeOffset QuarantineTime { get; set; }
    }

    public sealed class PersistenceInfo
    {
        public string Type { get; set; } = "";
        public string Location { get; set; } = "";
        public string Name { get; set; } = "";
        public string Value { get; set; } = "";
        public bool Removed { get; set; }
    }

    public sealed class ChainTraceResult
    {
        public DetectionEvent RootDetection { get; set; } = null!;
        public DateTimeOffset StartTime { get; set; }
        public DateTimeOffset EndTime { get; set; }
        public List<ProcessNode> ParentChain { get; set; } = new();
        public ProcessNode? AttackRoot { get; set; }
        public List<ProcessNode> AllChainProcesses { get; set; } = new();
        public List<KilledProcessInfo> KilledProcesses { get; set; } = new();
        public List<QuarantinedFileInfo> QuarantinedFiles { get; set; } = new();
        public List<PersistenceInfo> PersistenceRemoved { get; set; } = new();
        public bool Success { get; set; }
        public string? ErrorMessage { get; set; }
    }
}
