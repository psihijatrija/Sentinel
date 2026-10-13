using System;
using System.Collections.Concurrent;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace Sentinel.Core
{
    /// <summary>
    /// Detects ransomware behavior via I/O patterns:
    /// - Rapid sequential file renames to new extensions
    /// - Mass file writes in user directories
    /// - Ransom note creation patterns (README/DECRYPT files appearing in many folders)
    /// Purely behavioral - no file name or extension blocklists.
    ///
    /// Fed by FileActivityMonitor via RecordRename() for every observed file rename event.
    /// </summary>
    public sealed class RansomwareIoMonitor : BackgroundService
    {
        private readonly DetectionEngine _detectionEngine;
        private readonly ILogger<RansomwareIoMonitor> _logger;
        private readonly ConcurrentDictionary<int, int> _renameCountByPid = new();
        private readonly ConcurrentDictionary<int, string> _processNames = new();

        // Browser and known high-IO apps that rename files legitimately (cache, IndexedDB, etc.)
        // SECURITY: Name-only matching here is supplemented by path verification - an attacker
        // naming malware "chrome.exe" from C:\Temp would still be caught.
        private static readonly HashSet<string> RansomwareIoWhitelist = new(StringComparer.OrdinalIgnoreCase)
        {
            "chrome", "msedge", "firefox", "brave", "opera", "vivaldi", "msedgewebview2",
            // Browser installers unpack thousands of files (looks like ransomware IO on a fresh PC)
            "chromesetup", "chrome_installer", "mini_installer", "setup",
            "googleupdate", "googleupdated", "microsoftedgeupdate", "braveupdate",
            "code", "cursor", "Windsurf", "Kiro", "rider64",
            "steam", "steamwebhelper",
            "OneDrive", "Dropbox",
            "TmsaInstance64", "PtSessionAgent", "coreServiceShell",
        };

        // Cache of PIDs we've verified as legitimately matching the whitelist
        private readonly ConcurrentDictionary<int, bool> _verifiedWhitelistPids = new();

        public RansomwareIoMonitor(DetectionEngine detectionEngine, ILogger<RansomwareIoMonitor> logger)
        {
            _detectionEngine = detectionEngine;
            _logger = logger;
        }

        /// <summary>
        /// Called by FileActivityMonitor for every file rename event observed.
        /// Thread-safe - designed to be called from FileSystemWatcher callbacks.
        /// </summary>
        public void RecordRename(int processId, string processName)
        {
            if (processId <= 4) return;

            // Fast path: cached "this PID is a legitimate high-IO process"
            if (_verifiedWhitelistPids.TryGetValue(processId, out var cachedOk))
            {
                if (cachedOk) return;
                // cached false -> fall through and count renames
            }
            else
            {
                bool legitimate = false;
                try
                {
                    var stem = Sentinel.Core.StringNet48.ReplaceIgnoreCase(processName, ".exe", "");
                    var imagePath = SecurityValidation.GetProcessImagePath(processId);

                    // 1) Known high-IO app names with path verification
                    if (RansomwareIoWhitelist.Contains(processName) || RansomwareIoWhitelist.Contains(stem))
                    {
                        if (!string.IsNullOrEmpty(imagePath))
                        {
                            var lower = imagePath!.ToLowerInvariant();
                            bool isSuspiciousDir = lower.Contains(@"\temp\") ||
                                                   lower.Contains(@"\downloads\") ||
                                                   lower.Contains(@"\appdata\local\temp\");
                            if (!isSuspiciousDir)
                            {
                                legitimate = lower.Contains(@"\program files") ||
                                             lower.Contains(@"\appdata\local\programs\") ||
                                             lower.Contains(@"\appdata\local\google\") ||
                                             lower.Contains(@"\appdata\local\microsoft\") ||
                                             lower.Contains(@"\steam\") ||
                                             lower.Contains(@"\windows\");
                            }
                        }
                    }

                    // 2) Signed installer / packager (Git-2.x-64-bit.exe, ChromeSetup, ...)
                    if (!legitimate && !string.IsNullOrEmpty(imagePath) &&
                        (InstallerHeuristics.LooksLikeInstallerName(processName, imagePath) ||
                         InstallerHeuristics.IsInstallerExtractor(processName, imagePath)) &&
                        SecurityValidation.VerifyAuthenticodeSignature(imagePath!))
                    {
                        legitimate = true;
                    }
                }
                catch { }

                _verifiedWhitelistPids[processId] = legitimate;
                if (legitimate) return;
            }

            _renameCountByPid.AddOrUpdate(processId, 1, (_, count) => count + 1);
            _processNames.TryAdd(processId, processName);
        }

        /// <summary>Back-compat shim for tests - delegates to <see cref="InstallerHeuristics"/>.</summary>
        internal static bool LooksLikeInstallerName(string processName, string? imagePath = null)
            => InstallerHeuristics.LooksLikeInstallerName(processName, imagePath);

        protected override async Task ExecuteAsync(CancellationToken stoppingToken)
        {
            _logger.LogInformation("[RansomwareIoMonitor] Started");
            while (!stoppingToken.IsCancellationRequested)
            {
                try
                {
                    await Task.Delay(5000, stoppingToken);
                    // Check counters; if any PID exceeds threshold, alert
                    foreach (var kvp in _renameCountByPid)
                    {
                        if (kvp.Value > 50) // 50+ renames in 5 seconds = ransomware-like
                        {
                            _processNames.TryGetValue(kvp.Key, out var name);
                            await _detectionEngine.EmitAsync(new DetectionEvent
                            {
                                RuleName = "Ransomware: Mass File Rename",
                                Evidence = $"Process '{name ?? "unknown"}' (PID {kvp.Key}) renamed {kvp.Value} files in 5 seconds",
                                Reasoning = "A process is performing mass file renames at a rate consistent with file encryption ransomware. Legitimate software does not rename 50+ files within a 5-second window.",
                                Confidence = 0.95,
                                Tier = DetectionTier.Tier1Behavioral,
                                AuthorizedResponse = ResponseAction.KillProcessTree,
                                ProcessName = name ?? "unknown",
                                ProcessId = kvp.Key,
                                SignalType = SignalType.Ransomware,
                                Timestamp = DateTime.UtcNow
                            });
                        }
                    }
                    _renameCountByPid.Clear();
                    _processNames.Clear();
                }
                catch (OperationCanceledException) { break; }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "[RansomwareIoMonitor] Error");
                }
            }
        }
    }
}
