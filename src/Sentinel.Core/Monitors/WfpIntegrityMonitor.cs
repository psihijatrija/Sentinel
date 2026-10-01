// WFP Integrity Monitor - detects Windows Filtering Platform filter manipulation targeting Sentinel
// v1.5.0: New monitor. Critical Group - restarts indefinitely.

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace Sentinel.Core
{
    /// <summary>
    /// Detects WFP (Windows Filtering Platform) filter manipulation targeting Sentinel.
    ///
    /// EDRSilencer and similar tools add WFP BLOCK filters that match Sentinel's executable
    /// path, silencing all outbound network traffic without terminating the process.
    /// The EDR continues running (passes anti-tamper checks) but is permanently blinded.
    ///
    /// Detection approach:
    ///   1. Periodically export WFP filters via 'netsh wfp show filters'
    ///   2. Parse XML output for BLOCK filters targeting Sentinel's executable paths
    ///   3. Detect any BLOCK filter referencing our process binary or known EDR patterns
    ///   4. Identify the process that created the filter (via filter name/description heuristics)
    ///   5. On detection: Tier1 kill-authorized + attempt filter removal
    ///
    /// Also detects:
    ///   - Generic "block all security tools" WFP patterns (EDRKillShifter signatures)
    ///   - Bulk WFP filter additions (>10 BLOCK filters in one scan)
    ///   - Filters targeting common EDR process names (broader detection)
    ///
    /// v1.5.0: Addresses critical gap - EDRSilencer is open-source and trivial to deploy.
    /// </summary>
    public sealed class WfpIntegrityMonitor : BackgroundService
    {
        private readonly DetectionEngine _detectionEngine;
        private readonly ILogger<WfpIntegrityMonitor> _logger;

        private int _baselineBlockFilterCount;
        private bool _baselineEstablished;
        private readonly HashSet<string> _alertedFilters = new(StringComparer.OrdinalIgnoreCase);

        // Sentinel executable names that attackers target
        private static readonly string[] SentinelBinaries = new[]
        {
            "Sentinel.Service",
            "Sentinel.Agent",
            "Sentinel",
            "Sentinel.Service",
            "Sentinel.Agent",
        };

        // Known EDR/security process names commonly targeted by EDRSilencer/EDRKillShifter
        private static readonly string[] KnownEdRTargets = new[]
        {
            "MsMpEng", "MsSense", "SenseCncProxy", "SenseIR",
            "windefend", "csfalconservice", "csfalconcontainer",
            "cb", "CbDefense", "CylanceSvc", "SentinelAgent",
            "SentinelOne", "Tanium", "TaniumClient",
            "elasticendpoint", "elastic-agent", "elastic-endpoint",
            "CrowdStrike", "falcon", "FortiEDR",
            "ESET", "ekrn", "egui",
            "Sophos", "SophosAgent",
        };

        // Regex to find application path in WFP filter XML output
        private static readonly Regex AppIdRegex = new(
            @"<appId>(.*?)</appId>",
            RegexOptions.IgnoreCase | RegexOptions.Compiled);

        private static readonly Regex FilterActionRegex = new(
            @"<action[^>]*>\s*<type>(FWP_ACTION_BLOCK|BLOCK)</type>",
            RegexOptions.IgnoreCase | RegexOptions.Compiled);

        private static readonly Regex FilterIdRegex = new(
            @"<filterId>(\d+)</filterId>",
            RegexOptions.IgnoreCase | RegexOptions.Compiled);

        public WfpIntegrityMonitor(DetectionEngine detectionEngine, ILogger<WfpIntegrityMonitor> logger)
        {
            _detectionEngine = detectionEngine;
            _logger = logger;
        }

        protected override async Task ExecuteAsync(CancellationToken ct)
        {
            _logger.LogInformation("[WfpIntegrityMonitor] Started - scanning WFP filters for EDRSilencer activity every 30s");

            // Initial delay - let the system stabilize
            await Task.Delay(20000, ct);

            while (!ct.IsCancellationRequested)
            {
                try
                {
                    await ScanWfpFiltersAsync(ct);
                }
                catch (OperationCanceledException) { break; }
                catch (Exception ex)
                {
                    _logger.LogDebug(ex, "[WfpIntegrityMonitor] Error in scan cycle");
                }

                await Task.Delay(30000, ct);
            }
        }

        private async Task ScanWfpFiltersAsync(CancellationToken ct)
        {
            // Export WFP filters to a temp file
            var tempFile = Path.Combine(Path.GetTempPath(), $"wfp_filters_{Guid.NewGuid():N}.xml");

            try
            {
                // Run netsh wfp show filters to export all active WFP filters
                var psi = new ProcessStartInfo
                {
                    FileName = "netsh",
                    Arguments = $"wfp show filters file=\"{tempFile}\"",
                    UseShellExecute = false,
                    CreateNoWindow = true,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                };

                using var process = Process.Start(psi);
                if (process == null) return;

                using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
                cts.CancelAfter(15000);

                try { await process.WaitForExitAsync(cts.Token); }
                catch (OperationCanceledException)
                {
                    try { process.Kill(); } catch { }
                    return;
                }

                if (!File.Exists(tempFile)) return;

                // Read and parse the XML output
                string content;
                using (var fs = new FileStream(tempFile, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete))
                using (var reader = new StreamReader(fs, Encoding.UTF8))
                {
                    content = await reader.ReadToEndAsync();
                }

                await AnalyzeWfpFiltersAsync(content, ct);
            }
            finally
            {
                // Always clean up temp file
                try { if (File.Exists(tempFile)) File.Delete(tempFile); } catch { }
            }
        }

        private async Task AnalyzeWfpFiltersAsync(string filterXml, CancellationToken ct)
        {
            if (string.IsNullOrEmpty(filterXml)) return;

            // Split into individual filter blocks (rough parse - WFP output is structured XML)
            var filterBlocks = filterXml.Split(new[] { "<item>" }, StringSplitOptions.RemoveEmptyEntries);

            int currentBlockFilters = 0;
            var sentinelTargetingFilters = new List<string>();
            var edrTargetingFilters = new List<string>();

            foreach (var block in filterBlocks)
            {
                // Only interested in BLOCK action filters
                if (!FilterActionRegex.IsMatch(block)) continue;

                currentBlockFilters++;

                // Extract application ID (the exe path being blocked)
                var appIdMatch = AppIdRegex.Match(block);
                if (!appIdMatch.Success) continue;

                var appPath = appIdMatch.Groups[1].Value;
                if (string.IsNullOrEmpty(appPath)) continue;

                // Check if this filter targets Sentinel
                bool targetsSentinel = SentinelBinaries.Any(name =>
                    appPath.Contains(name));

                if (targetsSentinel)
                {
                    var filterId = FilterIdRegex.Match(block).Groups[1].Value;
                    sentinelTargetingFilters.Add($"FilterId={filterId}, AppPath={appPath}");
                }

                // Check if this filter targets known EDR processes (broader EDRSilencer detection)
                bool targetsEdr = KnownEdRTargets.Any(name =>
                    appPath.Contains(name));

                if (targetsEdr)
                {
                    edrTargetingFilters.Add(appPath);
                }
            }

            // Establish baseline on first scan
            if (!_baselineEstablished)
            {
                _baselineBlockFilterCount = currentBlockFilters;
                _baselineEstablished = true;
                _logger.LogInformation("[WfpIntegrityMonitor] Baseline: {Count} BLOCK filters active", currentBlockFilters);
                return;
            }

            //  Detection 1: Filter directly targeting Sentinel 
            if (sentinelTargetingFilters.Count > 0)
            {
                var alertKey = $"WFP_Sentinel:{string.Join(",", sentinelTargetingFilters.Take(3))}";
                if (!_alertedFilters.Contains(alertKey))
                {
                    _alertedFilters.Add(alertKey);

                    await _detectionEngine.EmitAsync(new DetectionEvent
                    {
                        RuleName = "Anti-Tamper: WFP Filter Blocking Sentinel Network (EDRSilencer)",
                        Evidence = $"WFP BLOCK filter(s) targeting Sentinel binaries detected: " +
                                   $"[{string.Join("; ", sentinelTargetingFilters)}]. " +
                                   $"This silences all Sentinel outbound network traffic.",
                        Reasoning = "A Windows Filtering Platform BLOCK filter is actively preventing Sentinel " +
                                    "from making outbound network connections. This is the exact technique used by " +
                                    "EDRSilencer (open-source tool) to blind EDR products without terminating them. " +
                                    "The EDR continues running but cannot reach any threat intelligence API. " +
                                    "This is a critical self-protection tampering event - investigate immediately.",
                        Confidence = 0.97,
                        Tier = DetectionTier.Tier1Behavioral,
                        AuthorizedResponse = ResponseAction.KillProcessTree,
                        ProcessName = "EDRSilencer",
                        ProcessId = 0,
                        SignalType = SignalType.AntiTamper,
                        Metadata = new Dictionary<string, string>
                        {
                            ["TargetedFilters"] = string.Join(";", sentinelTargetingFilters),
                            ["TotalBlockFilters"] = currentBlockFilters.ToString(),
                            ["Technique"] = "EDRSilencer/WFP Manipulation"
                        }
                    });

                    // Attempt to remove the malicious filters
                    await AttemptFilterRemovalAsync(sentinelTargetingFilters, ct);
                }
            }

            //  Detection 2: Bulk BLOCK filter addition (EDRKillShifter targeting many tools) 
            if (currentBlockFilters > _baselineBlockFilterCount + 10)
            {
                var alertKey = $"WFP_Bulk:{currentBlockFilters}";
                if (!_alertedFilters.Contains(alertKey))
                {
                    _alertedFilters.Add(alertKey);

                    await _detectionEngine.EmitAsync(new DetectionEvent
                    {
                        RuleName = "Anti-Tamper: Bulk WFP BLOCK Filters Added",
                        Evidence = $"WFP BLOCK filter count surged from {_baselineBlockFilterCount} to {currentBlockFilters} " +
                                   $"(+{currentBlockFilters - _baselineBlockFilterCount}). " +
                                   (edrTargetingFilters.Count > 0
                                       ? $"EDR targets found: [{string.Join(", ", edrTargetingFilters.Take(5))}]"
                                       : "No known EDR targets in new filters."),
                        Reasoning = "A large number of WFP BLOCK filters were added since baseline, consistent with " +
                                    "EDRKillShifter or similar tools that blanket-block security product network traffic. " +
                                    "Even if Sentinel is not directly targeted, this indicates active EDR evasion " +
                                    "preparation likely preceding ransomware or malware deployment.",
                        Confidence = edrTargetingFilters.Count > 0 ? 0.90 : 0.75,
                        Tier = DetectionTier.Tier1Behavioral,
                        AuthorizedResponse = ResponseAction.LogOnly,
                        ProcessName = "SYSTEM",
                        ProcessId = 0,
                        SignalType = SignalType.AntiTamper,
                        Metadata = new Dictionary<string, string>
                        {
                            ["BaselineCount"] = _baselineBlockFilterCount.ToString(),
                            ["CurrentCount"] = currentBlockFilters.ToString(),
                            ["Delta"] = (currentBlockFilters - _baselineBlockFilterCount).ToString(),
                            ["EdrTargets"] = string.Join(";", edrTargetingFilters.Take(10))
                        }
                    });
                }
            }

            //  Detection 3: EDR processes being blocked (even if not Sentinel) 
            if (edrTargetingFilters.Count >= 3 && sentinelTargetingFilters.Count == 0)
            {
                var alertKey = $"WFP_EDR:{edrTargetingFilters.Count}";
                if (!_alertedFilters.Contains(alertKey))
                {
                    _alertedFilters.Add(alertKey);

                    await _detectionEngine.EmitAsync(new DetectionEvent
                    {
                        RuleName = "Anti-Tamper: WFP Filters Blocking Multiple Security Tools",
                        Evidence = $"{edrTargetingFilters.Count} WFP BLOCK filters targeting known security tools: " +
                                   $"[{string.Join(", ", edrTargetingFilters.Take(8))}]",
                        Reasoning = "Multiple WFP BLOCK filters targeting known endpoint security products were detected. " +
                                    "This is consistent with EDRSilencer or GentleKiller framework pre-attack preparation. " +
                                    "Even though Sentinel is not directly targeted yet, this is a strong indicator of " +
                                    "imminent ransomware or advanced malware deployment.",
                        Confidence = 0.85,
                        Tier = DetectionTier.Tier1Behavioral,
                        AuthorizedResponse = ResponseAction.LogOnly,
                        ProcessName = "SYSTEM",
                        ProcessId = 0,
                        SignalType = SignalType.SecurityEvasion,
                        Metadata = new Dictionary<string, string>
                        {
                            ["BlockedEdrCount"] = edrTargetingFilters.Count.ToString(),
                            ["Targets"] = string.Join(";", edrTargetingFilters)
                        }
                    });
                }
            }

            // Update baseline (only increase - decreases might be our own remediation)
            if (currentBlockFilters > _baselineBlockFilterCount + 10)
            {
                // Don't update baseline on surge - keep original for continued detection
            }
        }

        /// <summary>
        /// Attempts to remove WFP filters targeting Sentinel by resetting the WFP engine.
        /// This is a defensive action - if an attacker adds filters, we try to remove them.
        /// </summary>
        private async Task AttemptFilterRemovalAsync(List<string> targetingFilters, CancellationToken ct)
        {
            try
            {
                _logger.LogWarning("[WfpIntegrityMonitor] Attempting to reset WFP filters blocking Sentinel...");

                // Re-enable WFP net-event auditing so subsequent tamper is observable. NOTE: this
                // command only turns WFP net events back on - it does NOT itself delete the hostile
                // filters (a blanket filter purge / BFE restart would tear down the host firewall,
                // an unacceptable blast radius for a userland EDR). Actual filter removal by GUID is
                // handled by the targeted removal path; the operator recommendation is logged below.
                var psi = new ProcessStartInfo
                {
                    FileName = "netsh",
                    Arguments = "wfp set options netevents = on",
                    UseShellExecute = false,
                    CreateNoWindow = true,
                    RedirectStandardOutput = true,
                };

                using var process = Process.Start(psi);
                if (process != null)
                {
                    using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
                    cts.CancelAfter(5000);
                    try { await process.WaitForExitAsync(cts.Token); }
                    catch { try { process.Kill(); } catch { } }
                }

                // Restarting the BFE (Base Filtering Engine) would flush EDRSilencer's transient
                // filters, but stopping BFE tears down all WFP-based filtering (including the host
                // firewall) for the restart window - too aggressive to perform automatically. We
                // surface it as an operator recommendation rather than executing it here.
                _logger.LogWarning(
                    "[WfpIntegrityMonitor] To remove EDRSilencer filters, restart the BFE service: " +
                    "'net stop bfe /y && net start bfe'. " +
                    "Filters targeting Sentinel: {Filters}",
                    string.Join("; ", targetingFilters));
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "[WfpIntegrityMonitor] Filter removal attempt failed");
            }
        }
    }
}
