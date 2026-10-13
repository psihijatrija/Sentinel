// Infostealer coverage (v2.6.x) - general-case sensitive-file access + collect/package/exfil.
//
// Gap this closes: the modern infostealer kill chain (RedLine / Lumma / Vidar class) never
// touches LSASS. It reads the browser credential/cookie SQLite DBs and developer secret files
// (.ssh, .aws, tokens), optionally packages user documents into an archive, then exfiltrates.
//
// Existing coverage was partial:
//   - BrowserCredentialGuard only fires when the browser is CLOSED and emits PID 0 / LogOnly
//     (no attribution, cannot feed a chain).
//   - AgenticProcessMonitor watches the same credential paths but ONLY for AI-agent process trees.
//   - DataExfiltrationMonitor is host-wide PID 0 volume only (deliberately weak).
//
// This monitor supplies the missing behavioral leg: an ATTRIBUTED (real PID) observe signal when
// a non-owning, non-trusted process reads a sensitive credential/secret store, or packages user
// documents into an archive. It is Tier2 + LogOnly + SignalType.Generic by itself and can NEVER
// solo-kill (ClassifyTerminalOutcome returns null for it). Kill authority arrives only through the
// hand-authored composites (read/staging + outbound) in BehavioralCorrelationEngine.
//
// SAFETY: the raw signal is deliberately NOT tagged WeakObserveSeed - that flag would exclude it
// from the correlation engines. It is Generic/Tier2 so the tier law demotes it to observe while
// still feeding correlation, which is exactly the observe-until-chain contract.

using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace Sentinel.Core
{
    /// <summary>
    /// Watches browser credential/cookie stores and developer-secret files across all user
    /// profiles, plus archive creation over user document directories. Attributes the accessing
    /// process via the Restart Manager and emits attributed Tier2 observe signals that feed the
    /// infostealer / data-staging composites. Never a solo kill.
    /// </summary>
    public sealed class SensitiveFileAccessMonitor : BackgroundService
    {
        private readonly DetectionEngine _detectionEngine;
        private readonly SignerTrustService _signerTrust;
        private readonly ILogger<SensitiveFileAccessMonitor> _logger;
        private readonly List<FileSystemWatcher> _watchers = new();

        // Per (pid, category) dedup so a busy stealer doesn't flood the log; correlation only
        // needs one attributed leg inside the 60s window.
        private readonly ConcurrentDictionary<string, DateTime> _recent = new();
        private static readonly TimeSpan Dedup = TimeSpan.FromSeconds(20);

        // Minimum archive size (bytes) that counts as "packaging documents" rather than a stray
        // small zip. 512 KB avoids single-file zips of a config while still catching doc bundles.
        private const long MinArchiveBytes = 512 * 1024;

        // Path fragments (lower-case) identifying browser credential / session stores.
        private static readonly string[] BrowserCredentialFragments =
        {
            @"\login data", @"\web data", @"\cookies", @"\network\cookies",
            @"\key4.db", @"\logins.json", @"\signons.sqlite", @"\formhistory.sqlite",
            @"\local state", // Chromium DPAPI-wrapped master key
        };

        // Path fragments identifying developer / cloud secret stores.
        private static readonly string[] DeveloperSecretFragments =
        {
            @"\.ssh\id_", @"\.ssh\known_hosts", @"\.ssh\authorized_keys",
            @"\.aws\credentials", @"\.aws\config",
            @"\.azure\accesstokens", @"\.azure\azureprofile.json",
            @"\.config\gcloud\credentials", @"\.config\gcloud\access_tokens",
            @"\.kube\config",
            @"\.docker\config.json",
            @"\.npmrc", @"\.pypirc", @"\.netrc",
            @"\.gnupg\", @"\.git-credentials",
        };

        private static readonly string[] ArchiveExtensions =
        {
            ".zip", ".rar", ".7z", ".tar", ".gz", ".tgz", ".cab", ".ace", ".arj",
        };

        // Document directory leaf names that, when packaged, look like collection-for-exfil.
        private static readonly string[] DocumentDirFragments =
        {
            @"\documents\", @"\desktop\", @"\downloads\", @"\pictures\", @"\onedrive\",
        };

        #region Restart Manager P/Invoke (owning-process attribution)

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
            uint pSessionHandle, uint nFiles, string[] rgsFilenames,
            uint nApplications, IntPtr rgApplications, uint nServices, IntPtr rgsServiceNames);

        [DllImport("rstrtmgr.dll")]
        private static extern int RmGetList(
            uint dwSessionHandle, out uint pnProcInfoNeeded, ref uint pnProcInfo,
            [In, Out] RM_PROCESS_INFO[]? rgApps, out uint lpdwRebootReasons);

        [DllImport("rstrtmgr.dll")]
        private static extern int RmEndSession(uint pSessionHandle);

        #endregion

        public SensitiveFileAccessMonitor(
            DetectionEngine detectionEngine,
            SignerTrustService signerTrust,
            ILogger<SensitiveFileAccessMonitor> logger)
        {
            _detectionEngine = detectionEngine;
            _signerTrust = signerTrust;
            _logger = logger;
        }

        protected override Task ExecuteAsync(CancellationToken stoppingToken)
        {
            _logger.LogInformation("[SensitiveFileAccessMonitor] Started - credential store + dev secret + archive staging");

            foreach (var profile in EnumerateUserProfiles())
            {
                TryWatch(profile, stoppingToken);
            }

            // FileSystemWatcher is event-driven; nothing to poll. Keep the task alive until stop
            // so the group treats the monitor as running, and tear watchers down on cancellation.
            stoppingToken.Register(DisposeWatchers);
            return Task.CompletedTask;
        }

        private static IEnumerable<string> EnumerateUserProfiles()
        {
            var results = new List<string>();
            try
            {
                var usersDir = Path.Combine(
                    Environment.GetEnvironmentVariable("SystemDrive") ?? "C:", "Users");
                if (!Directory.Exists(usersDir)) return results;

                foreach (var dir in Directory.GetDirectories(usersDir))
                {
                    var name = Path.GetFileName(dir);
                    if (name.Equals("Public", StringComparison.OrdinalIgnoreCase) ||
                        name.Equals("Default", StringComparison.OrdinalIgnoreCase) ||
                        name.Equals("Default User", StringComparison.OrdinalIgnoreCase) ||
                        name.Equals("All Users", StringComparison.OrdinalIgnoreCase) ||
                        name.StartsWith("."))
                        continue;
                    results.Add(dir);
                }
            }
            catch { /* enumeration best-effort */ }
            return results;
        }

        private void TryWatch(string profilePath, CancellationToken ct)
        {
            try
            {
                var watcher = new FileSystemWatcher(profilePath)
                {
                    IncludeSubdirectories = true,
                    // LastAccess is expensive/unreliable; a stealer copying the DB triggers a
                    // LastWrite on the copy target and Created for archives. We watch write+create.
                    NotifyFilter = NotifyFilters.LastWrite | NotifyFilters.FileName | NotifyFilters.CreationTime,
                };
                watcher.Changed += OnChanged;
                watcher.Created += OnChanged;
                watcher.Renamed += OnRenamed;
                watcher.Error += (_, e) =>
                    _logger.LogDebug(e.GetException(), "[SensitiveFileAccessMonitor] watcher error on {Path}", profilePath);
                watcher.EnableRaisingEvents = true;
                _watchers.Add(watcher);
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "[SensitiveFileAccessMonitor] could not watch {Path}", profilePath);
            }
        }

        private void OnRenamed(object sender, RenamedEventArgs e) => Inspect(e.FullPath);
        private void OnChanged(object sender, FileSystemEventArgs e) => Inspect(e.FullPath);

        private void Inspect(string fullPath)
        {
            // FileSystemWatcher callbacks run on a thread-pool thread. Keep the work short and
            // never let an exception escape (would tear the watcher down).
            try
            {
                if (string.IsNullOrEmpty(fullPath)) return;
                var lower = fullPath.ToLowerInvariant();

                if (MatchesAny(lower, BrowserCredentialFragments))
                {
                    RaiseSensitiveAccess(fullPath, "Browser Credential Store",
                        "browser login/cookie/session store");
                    return;
                }

                if (MatchesAny(lower, DeveloperSecretFragments))
                {
                    RaiseSensitiveAccess(fullPath, "Developer Secret",
                        "developer / cloud credential file");
                    return;
                }

                if (IsStagedArchive(lower, fullPath))
                {
                    RaiseArchiveStaging(fullPath);
                }
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "[SensitiveFileAccessMonitor] inspect error");
            }
        }

        private bool IsStagedArchive(string lower, string fullPath)
        {
            bool isArchive = false;
            foreach (var ext in ArchiveExtensions)
            {
                if (lower.EndsWith(ext, StringComparison.Ordinal)) { isArchive = true; break; }
            }
            if (!isArchive) return false;

            // Only treat as document-collection staging when the archive lives in / next to a
            // user document tree. A build artifact under \source\ or \node_modules\ is not this.
            if (!MatchesAny(lower, DocumentDirFragments)) return false;

            try
            {
                var fi = new FileInfo(fullPath);
                if (!fi.Exists || fi.Length < MinArchiveBytes) return false;
            }
            catch { return false; }

            return true;
        }

        private void RaiseSensitiveAccess(string filePath, string kind, string humanKind)
        {
            var (pid, procName) = GetProcessUsingFile(filePath);
            if (pid <= 4) return; // no attribution -> BrowserCredentialGuard already covers PID-0 case

            // The owning application reading its OWN store is normal. Skip signed browsers /
            // trusted system readers; a stealer is typically an unsigned process from Temp/AppData.
            if (IsTrustedOwner(pid, procName)) return;

            if (!ShouldEmit(pid, "sensitive")) return;

            _ = _detectionEngine.EmitAsync(new DetectionEvent
            {
                RuleName = $"Sensitive File Access: {kind}",
                Evidence = $"Non-owning process '{procName}' (PID {pid}) accessed {humanKind} '{filePath}'",
                Reasoning =
                    "A process that does not own this credential/secret store touched it. Modern " +
                    "infostealers read browser Login Data / Cookies / Local State and developer " +
                    "secret files (.ssh, .aws, tokens) directly - no LSASS involved. Observe-only " +
                    "on its own; becomes a kill-grade chain only when correlated with outbound " +
                    "network activity or archive staging on the same process.",
                Confidence = 0.6,
                Tier = DetectionTier.Tier2Indicator,
                AuthorizedResponse = ResponseAction.LogOnly,
                SignalType = SignalType.Generic, // NOT CredentialTheft: must never solo-classify kill-grade
                ProcessName = procName,
                ProcessId = pid,
                Metadata = new Dictionary<string, string>
                {
                    ["SensitiveFileAccess"] = "true",
                    ["SensitiveKind"] = kind,
                    ["FilePath"] = filePath,
                }
            });
        }

        private void RaiseArchiveStaging(string archivePath)
        {
            var (pid, procName) = GetProcessUsingFile(archivePath);
            if (pid <= 4) return;

            if (IsTrustedOwner(pid, procName)) return;
            if (!ShouldEmit(pid, "staging")) return;

            long size = 0;
            try { size = new FileInfo(archivePath).Length; } catch { }

            _ = _detectionEngine.EmitAsync(new DetectionEvent
            {
                RuleName = "Data Staging: Archive of User Documents",
                Evidence = $"Process '{procName}' (PID {pid}) created archive '{archivePath}' ({size / 1024}KB) over a user document tree",
                Reasoning =
                    "A process packaged files from a user document directory (Documents / Desktop / " +
                    "Downloads / Pictures / OneDrive) into an archive. This is the 'collect and " +
                    "package' stage of the collect->package->exfil kill chain. Observe-only alone; " +
                    "becomes a data-exfiltration terminal only when correlated with outbound network " +
                    "activity on the same process.",
                Confidence = 0.55,
                Tier = DetectionTier.Tier2Indicator,
                AuthorizedResponse = ResponseAction.LogOnly,
                SignalType = SignalType.Generic,
                ProcessName = procName,
                ProcessId = pid,
                Metadata = new Dictionary<string, string>
                {
                    ["ArchiveStaging"] = "true",
                    ["FilePath"] = archivePath,
                    ["ArchiveBytes"] = size.ToString(),
                }
            });
        }

        private bool IsTrustedOwner(int pid, string procName)
        {
            // A browser reading its own store, or a signed first-party client, is not a stealer.
            var stem = StringNet48.ReplaceIgnoreCase(procName ?? "", ".exe", "");
            if (KnownStoreOwners.Contains(stem))
                return true;

            try
            {
                var path = SecurityValidation.GetProcessImagePath(pid);
                if (!string.IsNullOrEmpty(path))
                {
                    // Signed binaries under Program Files / Windows are trusted readers
                    // (Chrome, Edge, Firefox, OneDrive, backup agents, sync clients).
                    if (SecurityValidation.IsOsCriticalPath(path!))
                        return true;
                    if (_signerTrust.IsSignedFile(path!))
                        return true;
                }
            }
            catch { }

            return false;
        }

        private static readonly HashSet<string> KnownStoreOwners = new(StringComparer.OrdinalIgnoreCase)
        {
            "chrome", "msedge", "firefox", "brave", "opera", "vivaldi", "iexplore",
            "msedgewebview2", "onedrive", "git", "ssh", "ssh-agent", "gpg", "gpg-agent",
            "aws", "az", "gcloud", "kubectl", "docker", "npm", "node",
        };

        private bool ShouldEmit(int pid, string category)
        {
            var key = pid + ":" + category;
            var now = DateTime.UtcNow;
            if (_recent.TryGetValue(key, out var last) && now - last < Dedup)
                return false;
            _recent[key] = now;

            // Bound the dedup map.
            if (_recent.Count > 4096)
            {
                foreach (var kv in _recent)
                {
                    if (now - kv.Value > Dedup)
                        _recent.TryRemove(kv.Key, out _);
                }
            }
            return true;
        }

        private static bool MatchesAny(string haystackLower, string[] fragments)
        {
            foreach (var f in fragments)
            {
                if (haystackLower.IndexOf(f, StringComparison.Ordinal) >= 0)
                    return true;
            }
            return false;
        }

        /// <summary>
        /// Resolves the process currently holding a handle to the file via the Restart Manager.
        /// Same technique FileActivityMonitor uses for file-event attribution.
        /// </summary>
        private static (int pid, string name) GetProcessUsingFile(string filePath)
        {
            if (string.IsNullOrWhiteSpace(filePath)) return (0, "unknown");

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
                if (res != 0 && res != 234 /* ERROR_MORE_DATA */) return (0, "unknown");

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
                            catch { name = "unknown"; }
                        }
                        return (pid, name);
                    }
                }
            }
            catch { /* process may have exited between event and scan */ }
            finally
            {
                RmEndSession(sessionHandle);
            }

            return (0, "unknown");
        }

        private void DisposeWatchers()
        {
            foreach (var w in _watchers)
            {
                try { w.EnableRaisingEvents = false; w.Dispose(); } catch { }
            }
            _watchers.Clear();
        }

        public override void Dispose()
        {
            DisposeWatchers();
            base.Dispose();
        }
    }
}
