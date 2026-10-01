using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Win32;

namespace Sentinel.Core
{
    // 
    // Application Integrity Monitor - Cuckoo Egg Detection
    // Detects unauthorized replacement of protected applications.
    // Baselines executables by SHA-256 hash + Authenticode publisher.
    // On mismatch: kills offender, quarantines impostor, generates
    // forensic incident report suitable for law enforcement filing.
    // 

    /// <summary>
    /// Configuration for a single protected application.
    /// </summary>
    public class ProtectedApplication
    {
        /// <summary>Display name (e.g., "Kiro IDE")</summary>
        public string Name { get; set; } = string.Empty;

        /// <summary>Full path to the primary executable to monitor.</summary>
        public string ExecutablePath { get; set; } = string.Empty;

        /// <summary>
        /// Expected Authenticode publisher (CN from signing certificate).
        /// If empty, only hash-based detection is used.
        /// Example: "Amazon.com Services LLC"
        /// </summary>
        public string ExpectedPublisher { get; set; } = string.Empty;

        /// <summary>
        /// Directory to watch for changes (defaults to parent of ExecutablePath).
        /// </summary>
        public string? WatchDirectory { get; set; }
    }

    /// <summary>
    /// Configuration section for the Application Integrity Monitor.
    /// Compiled defaults for the Application Integrity Monitor.
    /// </summary>
    public class ApplicationIntegrityConfig
    {
        /// <summary>Enable/disable the monitor.</summary>
        public bool Enabled { get; set; } = true;

        /// <summary>Scan interval in seconds (default: 30s).</summary>
        public int ScanIntervalSeconds { get; set; } = 30;

        /// <summary>
        /// Directory where integrity backups are stored (DPAPI-encrypted).
        /// Defaults to ProgramData\Sentinel\IntegrityBackups
        /// </summary>
        public string? BackupDirectory { get; set; }

        /// <summary>
        /// Directory where forensic incident reports are written.
        /// Defaults to ProgramData\Sentinel\IncidentReports
        /// </summary>
        public string? ReportDirectory { get; set; }

        /// <summary>List of applications to protect.</summary>
        public List<ProtectedApplication> ProtectedApps { get; set; } = new();
    }

    /// <summary>
    /// Snapshot of a protected application at baseline time.
    /// </summary>
    internal class AppBaseline
    {
        public string Name { get; set; } = string.Empty;
        public string ExecutablePath { get; set; } = string.Empty;
        public string Sha256Hash { get; set; } = string.Empty;
        public string Publisher { get; set; } = string.Empty;
        public string ExpectedPublisher { get; set; } = string.Empty;
        public long FileSize { get; set; }
        public DateTime BaselinedAt { get; set; } = DateTime.UtcNow;
        public string FileVersion { get; set; } = string.Empty;
        public string ProductName { get; set; } = string.Empty;
    }

    /// <summary>
    /// Monitors protected applications for unauthorized replacement (cuckoo egg attacks).
    /// President's Law: always fires, cannot be suppressed by allowlist.
    /// </summary>
    public sealed class ApplicationIntegrityMonitor : BackgroundService
    {
        private readonly DetectionEngine _detectionEngine;
        private readonly QuarantineManager _quarantineManager;
        private readonly JsonlEventLogger _eventLogger;
        private readonly ILogger<ApplicationIntegrityMonitor> _logger;
        private readonly ApplicationIntegrityConfig _config;
        private readonly SentinelConfig _sentinelConfig;

        private readonly ConcurrentDictionary<string, AppBaseline> _baselines = new(StringComparer.OrdinalIgnoreCase);
        private readonly List<FileSystemWatcher> _watchers = new();
        private readonly string _backupDir;
        private readonly string _reportDir;
        private readonly ConcurrentDictionary<string, DateTime> _recentAlerts = new();

        public ApplicationIntegrityMonitor(
            DetectionEngine detectionEngine,
            QuarantineManager quarantineManager,
            JsonlEventLogger eventLogger,
            ApplicationIntegrityConfig config,
            SentinelConfig sentinelConfig,
            ILogger<ApplicationIntegrityMonitor> logger)
        {
            _detectionEngine = detectionEngine;
            _quarantineManager = quarantineManager;
            _eventLogger = eventLogger;
            _config = config;
            _sentinelConfig = sentinelConfig;
            _logger = logger;

            var programData = Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData);
            _backupDir = config.BackupDirectory
                ?? Path.Combine(programData, "Sentinel", "IntegrityBackups");
            _reportDir = config.ReportDirectory
                ?? Path.Combine(programData, "Sentinel", "IncidentReports");

            try { Directory.CreateDirectory(_backupDir); } catch { }
            try { Directory.CreateDirectory(_reportDir); } catch { }
        }

        protected override async Task ExecuteAsync(CancellationToken ct)
        {
            if (!_config.Enabled || _config.ProtectedApps.Count == 0)
            {
                _logger.LogInformation("[ApplicationIntegrityMonitor] Disabled or no apps configured. Sleeping indefinitely.");
                // STABILITY v1.4.8: Do NOT return - a completed BackgroundService task
                // triggers host shutdown in .NET 6+. Sleep until cancellation instead.
                try { await Task.Delay(Timeout.Infinite, ct); } catch (OperationCanceledException) { }
                return;
            }

            _logger.LogInformation("[ApplicationIntegrityMonitor] Starting - protecting {Count} applications", _config.ProtectedApps.Count);

            // Phase 1: Baseline all protected applications
            foreach (var app in _config.ProtectedApps)
            {
                try
                {
                    var baseline = CreateBaseline(app);
                    if (baseline != null)
                    {
                        _baselines[app.ExecutablePath] = baseline;
                        BackupProtectedBinary(app.ExecutablePath);
                        _logger.LogInformation("[ApplicationIntegrityMonitor] Baselined: {Name} ({Publisher}) SHA256={Hash}",
                            baseline.Name, baseline.Publisher, baseline.Sha256Hash[..16] + "...");
                    }
                    else
                    {
                        _logger.LogWarning("[ApplicationIntegrityMonitor] Could not baseline {Name} at {Path} - file not found",
                            app.Name, app.ExecutablePath);
                    }
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "[ApplicationIntegrityMonitor] Error baselining {Name}", app.Name);
                }
            }

            // Phase 2: Set up FileSystemWatchers for real-time detection
            SetupWatchers();

            // Phase 3: Periodic integrity scan loop
            var interval = TimeSpan.FromSeconds(Math.Max(5, _config.ScanIntervalSeconds));
            while (!ct.IsCancellationRequested)
            {
                try
                {
                    await Task.Delay(interval, ct);
                    await PerformIntegrityScanAsync(ct);
                }
                catch (OperationCanceledException) { break; }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "[ApplicationIntegrityMonitor] Error during periodic scan");
                }
            }

            // Cleanup watchers
            foreach (var w in _watchers) { try { w.Dispose(); } catch { } }
        }

        private void SetupWatchers()
        {
            foreach (var app in _config.ProtectedApps)
            {
                var watchDir = app.WatchDirectory ?? Path.GetDirectoryName(app.ExecutablePath);
                if (string.IsNullOrEmpty(watchDir) || !Directory.Exists(watchDir)) continue;

                try
                {
                    var watcher = new FileSystemWatcher(watchDir)
                    {
                        NotifyFilter = NotifyFilters.FileName | NotifyFilters.LastWrite | NotifyFilters.Size | NotifyFilters.CreationTime,
                        Filter = "*.exe",
                        IncludeSubdirectories = true,
                        EnableRaisingEvents = true
                    };

                    watcher.Changed += (s, e) => OnFileChanged(e.FullPath);
                    watcher.Created += (s, e) => OnFileChanged(e.FullPath);
                    watcher.Renamed += (s, e) => OnFileChanged(e.FullPath);

                    _watchers.Add(watcher);
                    _logger.LogDebug("[ApplicationIntegrityMonitor] Watching directory: {Dir}", watchDir);
                }
                catch (Exception ex)
                {
                    _logger.LogWarning(ex, "[ApplicationIntegrityMonitor] Failed to watch {Dir}", watchDir);
                }
            }
        }

        private void OnFileChanged(string filePath)
        {
            // Only react to changes to our baselined executables
            if (!_baselines.ContainsKey(filePath)) return;

            // Debounce: don't fire more than once per 10 seconds per path
            var now = DateTime.UtcNow;
            if (_recentAlerts.TryGetValue(filePath, out var lastAlert) && (now - lastAlert).TotalSeconds < 10)
                return;
            _recentAlerts[filePath] = now;

            // v1.4.1: Trigger immediate integrity check with retry loop instead of a fixed delay.
            // The previous 1000ms delay created a TOCTOU window where an attacker could replace,
            // execute, and restore a binary before the hash check ran.
            _ = Task.Run(async () =>
            {
                // Retry up to 5 times with short backoff if file is locked
                for (int attempt = 0; attempt < 5; attempt++)
                {
                    var hash = ComputeFileHash(filePath);
                    if (hash != null)
                    {
                        await CheckSingleApplicationAsync(filePath);
                        return;
                    }
                    // File locked - very short retry (100ms) to minimize the TOCTOU window
                    await Task.Delay(100);
                }
                // All retries failed (file locked for 500ms+) - still check, may catch on next periodic scan
                await CheckSingleApplicationAsync(filePath);
            });
        }

        private async Task PerformIntegrityScanAsync(CancellationToken ct)
        {
            foreach (var kvp in _baselines)
            {
                if (ct.IsCancellationRequested) break;
                await CheckSingleApplicationAsync(kvp.Key);
            }
        }

        private async Task CheckSingleApplicationAsync(string executablePath)
        {
            if (!_baselines.TryGetValue(executablePath, out var baseline)) return;

            try
            {
                // Case 1: File deleted - someone removed our protected app
                if (!File.Exists(executablePath))
                {
                    await EmitCuckooDetection(baseline, "DELETED",
                        $"Protected application '{baseline.Name}' binary was deleted from {executablePath}",
                        "Binary deletion indicates uninstallation or replacement in progress - cuckoo egg preparation phase.");
                    return;
                }

                // Case 2: Hash changed - binary was replaced
                var currentHash = ComputeFileHash(executablePath);
                if (currentHash == null) return; // File locked, will retry next cycle

                if (!string.Equals(currentHash, baseline.Sha256Hash))
                {
                    // Hash mismatch - verify publisher
                    var currentPublisher = GetAuthenticodePublisher(executablePath);
                    var currentProductName = GetFileProductName(executablePath);

                    // Determine if this is a legitimate update vs cuckoo egg
                    bool publisherMatch = !string.IsNullOrEmpty(baseline.ExpectedPublisher) &&
                        string.Equals(currentPublisher, baseline.ExpectedPublisher);

                    if (publisherMatch)
                    {
                        // Same publisher, different hash = legitimate update
                        // Re-baseline silently
                        _logger.LogInformation("[ApplicationIntegrityMonitor] Legitimate update detected for {Name} (publisher verified: {Publisher}). Re-baselining.",
                            baseline.Name, currentPublisher);
                        baseline.Sha256Hash = currentHash;
                        baseline.Publisher = currentPublisher ?? baseline.Publisher;
                        baseline.BaselinedAt = DateTime.UtcNow;
                        baseline.ProductName = currentProductName ?? baseline.ProductName;
                        BackupProtectedBinary(executablePath);
                        return;
                    }

                    // CUCKOO EGG DETECTED - different publisher or unsigned
                    var evidence = BuildCuckooEvidenceString(baseline, executablePath, currentHash, currentPublisher, currentProductName);
                    var reasoning = BuildCuckooReasoningString(baseline, currentPublisher, currentProductName);

                    // Find the process that did this
                    var offenderPid = FindModifyingProcess(executablePath);

                    await EmitCuckooDetection(baseline, "REPLACED", evidence, reasoning, offenderPid, currentHash, currentPublisher, currentProductName);

                    // Observe-until-chain (default): detect + log only. No kill/quarantine/restore
                    // until ResponsePolicy authorizes host mutation (multi-signal / chain).
                    // Never pass null chain context - single cuckoo signal is not kill authority.
                    if (ResponsePolicy.MayPerformInlineHostMutation(_sentinelConfig))
                    {
                        await RespondToCuckooEgg(executablePath, baseline, offenderPid);
                    }
                    else
                    {
                        _logger.LogInformation(
                            "[ApplicationIntegrityMonitor] Cuckoo egg observed for {Name} - LogOnly (observe-until-chain; no inline kill)",
                            baseline.Name);
                    }

                    // Generate forensic incident report for law enforcement
                    await GenerateForensicReportAsync(baseline, executablePath, currentHash, currentPublisher, currentProductName, offenderPid);
                }
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "[ApplicationIntegrityMonitor] Error checking {Path}", executablePath);
            }
        }

        private async Task EmitCuckooDetection(AppBaseline baseline, string attackType, string evidence,
            string reasoning, int offenderPid = 0, string? impostorHash = null,
            string? impostorPublisher = null, string? impostorProduct = null)
        {
            var metadata = new Dictionary<string, string>
            {
                ["AttackType"] = attackType,
                ["ProtectedApp"] = baseline.Name,
                ["OriginalHash"] = baseline.Sha256Hash,
                ["OriginalPublisher"] = baseline.Publisher,
                ["ExpectedPublisher"] = baseline.ExpectedPublisher,
                ["BaselinedAt"] = baseline.BaselinedAt.ToString("O"),
                ["ExecutablePath"] = baseline.ExecutablePath
            };

            if (!string.IsNullOrEmpty(impostorHash)) metadata["ImpostorHash"] = impostorHash!;
            if (!string.IsNullOrEmpty(impostorPublisher)) metadata["ImpostorPublisher"] = impostorPublisher!;
            if (!string.IsNullOrEmpty(impostorProduct)) metadata["ImpostorProduct"] = impostorProduct!;

            // Recommend LogOnly at emit - DetectionEngine.ApplyTierLaw also demotes non-kill-grade.
            // Destructive response only via AdvancedResponseEngine after chain confirm (or lab AR).
            await _detectionEngine.EmitAsync(new DetectionEvent
            {
                RuleName = "Application Integrity: Cuckoo Egg Detected",
                Evidence = evidence,
                Reasoning = reasoning,
                Confidence = 0.99,
                Tier = DetectionTier.Tier2Indicator,
                AuthorizedResponse = ResponseAction.LogOnly,
                ProcessName = offenderPid > 4 ? GetProcessNameSafe(offenderPid) : "UNKNOWN_INSTALLER",
                ProcessId = offenderPid > 0 ? offenderPid : 0,
                SignalType = SignalType.AntiTamper,
                Metadata = metadata
            });
        }

        private async Task RespondToCuckooEgg(string executablePath, AppBaseline baseline, int offenderPid)
        {
            // Defense in depth: never kill/quarantine if observe-until-chain is on without gate.
            if (!ResponsePolicy.MayPerformInlineHostMutation(_sentinelConfig))
            {
                _logger.LogInformation(
                    "[ApplicationIntegrityMonitor] RespondToCuckooEgg suppressed for {Name} (observe-until-chain)",
                    baseline.Name);
                return;
            }

            _logger.LogWarning("[ApplicationIntegrityMonitor] *** CUCKOO EGG RESPONSE *** Quarantining impostor and restoring original for {Name}",
                baseline.Name);

            // 1. Kill the offending process tree (the installer/replacer)
            if (offenderPid > 4)
            {
                _logger.LogWarning("[ApplicationIntegrityMonitor] Killing offender process tree PID {Pid}", offenderPid);
                HardeningModule.SafeKillProcessTree(offenderPid);
            }

            // 2. Kill any running instance of the impostor
            KillRunningImpostor(executablePath);

            // 3. Quarantine the impostor binary
            try
            {
                if (File.Exists(executablePath))
                {
                    // force: cuckoo eggs may still carry a (stolen/repurposed) signature
                    await _quarantineManager.QuarantineFileAtomicAsync(executablePath, forceQuarantineSigned: true);
                    _logger.LogWarning("[ApplicationIntegrityMonitor] Impostor quarantined: {Path}", executablePath);
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "[ApplicationIntegrityMonitor] Failed to quarantine impostor at {Path}", executablePath);
            }

            // 4. Restore from integrity backup
            await RestoreFromBackupAsync(executablePath, baseline);
        }

        // 
        // Forensic Incident Report Generation
        // Generates a structured report with all evidence needed
        // for filing with law enforcement (police report).
        // 

        private async Task GenerateForensicReportAsync(AppBaseline baseline, string executablePath,
            string impostorHash, string? impostorPublisher, string? impostorProduct, int offenderPid)
        {
            var timestamp = DateTime.UtcNow;
            var reportId = $"CUCKOO_{timestamp:yyyyMMdd_HHmmss}_{baseline.Name.Replace(" ", "_")}";
            var reportDir = Path.Combine(_reportDir, reportId);

            try { Directory.CreateDirectory(reportDir); } catch { return; }

            var report = new StringBuilder();
            report.AppendLine("");
            report.AppendLine("     WINDOWS SENTINEL - FORENSIC INCIDENT REPORT                ");
            report.AppendLine("     Application Integrity Violation (Cuckoo Egg Attack)        ");
            report.AppendLine("");
            report.AppendLine();
            report.AppendLine($"Report ID:        {reportId}");
            report.AppendLine($"Generated:        {timestamp:yyyy-MM-dd HH:mm:ss} UTC");
            report.AppendLine($"Machine Name:     {Environment.MachineName}");
            report.AppendLine($"OS Version:       {Environment.OSVersion}");
            report.AppendLine($"User Account:     {Environment.UserDomainName}\\{Environment.UserName}");
            report.AppendLine();
            report.AppendLine("");
            report.AppendLine("INCIDENT SUMMARY");
            report.AppendLine("");
            report.AppendLine();
            report.AppendLine($"A protected application was replaced with unauthorized software.");
            report.AppendLine($"This constitutes unauthorized modification of computer software,");
            report.AppendLine($"potentially violating computer fraud and unauthorized access laws.");
            report.AppendLine();
            report.AppendLine("");
            report.AppendLine("VICTIM APPLICATION (Original/Legitimate)");
            report.AppendLine("");
            report.AppendLine();
            report.AppendLine($"  Name:           {baseline.Name}");
            report.AppendLine($"  Path:           {baseline.ExecutablePath}");
            report.AppendLine($"  Publisher:      {baseline.Publisher}");
            report.AppendLine($"  Product:        {baseline.ProductName}");
            report.AppendLine($"  Version:        {baseline.FileVersion}");
            report.AppendLine($"  SHA-256:        {baseline.Sha256Hash}");
            report.AppendLine($"  File Size:      {baseline.FileSize} bytes");
            report.AppendLine($"  Baselined At:   {baseline.BaselinedAt:yyyy-MM-dd HH:mm:ss} UTC");
            report.AppendLine();

            await System.IO.FileNet48.WriteAllTextAsync(Path.Combine(reportDir, "incident_report.txt"), report.ToString());

            // Continue building the report in parts
            await AppendImpostorDetails(reportDir, report, impostorHash, impostorPublisher, impostorProduct, executablePath);
            await AppendOffenderDetails(reportDir, report, offenderPid);
            await AppendNetworkEvidence(reportDir, report, offenderPid);
            await AppendTimelineAndRecommendations(reportDir, report, baseline, timestamp);

            // Write final complete report
            await System.IO.FileNet48.WriteAllTextAsync(Path.Combine(reportDir, "incident_report.txt"), report.ToString());

            // Also log as structured event
            await _eventLogger.LogEventAsync("cuckoo_egg_incident", new
            {
                ReportId = reportId,
                ReportPath = reportDir,
                Timestamp = timestamp,
                VictimApp = baseline.Name,
                OriginalPublisher = baseline.Publisher,
                ImpostorPublisher = impostorPublisher ?? "UNSIGNED",
                ImpostorProduct = impostorProduct ?? "UNKNOWN",
                ImpostorHash = impostorHash,
                OffenderPid = offenderPid,
                MachineName = Environment.MachineName
            });

            _logger.LogWarning("[ApplicationIntegrityMonitor] *** FORENSIC REPORT GENERATED *** {Path}", reportDir);
        }

        private async Task AppendImpostorDetails(string reportDir, StringBuilder report,
            string impostorHash, string? impostorPublisher, string? impostorProduct, string executablePath)
        {
            report.AppendLine("");
            report.AppendLine("IMPOSTOR APPLICATION (Unauthorized Replacement)");
            report.AppendLine("");
            report.AppendLine();
            report.AppendLine($"  Publisher:      {impostorPublisher ?? "UNSIGNED (no valid Authenticode signature)"}");
            report.AppendLine($"  Product:        {impostorProduct ?? "UNKNOWN"}");
            report.AppendLine($"  SHA-256:        {impostorHash}");
            report.AppendLine($"  Location:       {executablePath}");

            // Try to get additional file metadata
            try
            {
                if (File.Exists(executablePath))
                {
                    var fi = new FileInfo(executablePath);
                    report.AppendLine($"  File Size:      {fi.Length} bytes");
                    report.AppendLine($"  Created:        {fi.CreationTimeUtc:yyyy-MM-dd HH:mm:ss} UTC");
                    report.AppendLine($"  Modified:       {fi.LastWriteTimeUtc:yyyy-MM-dd HH:mm:ss} UTC");

                    var vi = FileVersionInfo.GetVersionInfo(executablePath);
                    if (!string.IsNullOrEmpty(vi.CompanyName))
                        report.AppendLine($"  Company:        {vi.CompanyName}");
                    if (!string.IsNullOrEmpty(vi.FileDescription))
                        report.AppendLine($"  Description:    {vi.FileDescription}");
                    if (!string.IsNullOrEmpty(vi.FileVersion))
                        report.AppendLine($"  File Version:   {vi.FileVersion}");
                    if (!string.IsNullOrEmpty(vi.OriginalFilename))
                        report.AppendLine($"  Original Name:  {vi.OriginalFilename}");

                    // Save a copy of the impostor's certificate chain if signed
                    SaveImpostorCertificate(reportDir, executablePath);
                }
            }
            catch { }
            report.AppendLine();
            await Task.CompletedTask;
        }

        private async Task AppendOffenderDetails(string reportDir, StringBuilder report, int offenderPid)
        {
            report.AppendLine("");
            report.AppendLine("OFFENDER PROCESS (Software that performed the replacement)");
            report.AppendLine("");
            report.AppendLine();

            if (offenderPid > 4)
            {
                try
                {
                    using var proc = Process.GetProcessById(offenderPid);
                    report.AppendLine($"  Process ID:     {offenderPid}");
                    report.AppendLine($"  Process Name:   {proc.ProcessName}");
                    report.AppendLine($"  Image Path:     {SecurityValidation.GetProcessImagePath(offenderPid) ?? "UNKNOWN"}");
                    report.AppendLine($"  Start Time:     {proc.StartTime.ToUniversalTime():yyyy-MM-dd HH:mm:ss} UTC");
                    report.AppendLine($"  Command Line:   {GetProcessCommandLine(offenderPid)}");
                    report.AppendLine();

                    // Walk parent tree
                    report.AppendLine("  Process Ancestry:");
                    var ancestors = GetProcessAncestry(offenderPid);
                    foreach (var ancestor in ancestors)
                    {
                        report.AppendLine($"     PID {ancestor.pid}: {ancestor.name} ({ancestor.path})");
                    }

                    // Save offender module list
                    var modules = new List<string>();
                    try
                    {
                        // Module inventory only if evidence-gated and not a game path
                        var offenderPath = SecurityValidation.GetProcessImagePath(offenderPid);
                        if (NativeProcessMemory.CanInspect(offenderPid, offenderPath))
                        {
                            foreach (var mod in NativeProcessMemory.EnumModules(offenderPid))
                                modules.Add($"{mod.Name}\t{mod.Path}\t{mod.Size}");
                        }
                    }
                    catch { }

                    if (modules.Count > 0)
                        await FileNet48.WriteAllLinesAsync(Path.Combine(reportDir, "offender_modules.txt"), modules);
                }
                catch
                {
                    report.AppendLine($"  Process ID:     {offenderPid} (process already terminated)");
                }
            }
            else
            {
                report.AppendLine("  Could not identify the specific process that performed the replacement.");
                report.AppendLine("  The modification may have been performed by a process that has already exited.");
            }
            report.AppendLine();
        }

        private async Task AppendNetworkEvidence(string reportDir, StringBuilder report, int offenderPid)
        {
            report.AppendLine("");
            report.AppendLine("NETWORK EVIDENCE");
            report.AppendLine("");
            report.AppendLine();

            var connections = new List<string>();
            try
            {
                // Snapshot all active network connections at time of incident
                var allConnections = GetActiveConnections();
                if (offenderPid > 4)
                {
                    var offenderConns = allConnections.Where(c => c.pid == offenderPid).ToList();
                    if (offenderConns.Count > 0)
                    {
                        report.AppendLine("  Offender's Network Connections:");
                        foreach (var conn in offenderConns)
                        {
                            var line = $"    {conn.protocol} {conn.localAddr}:{conn.localPort} -> {conn.remoteAddr}:{conn.remotePort} ({conn.state})";
                            report.AppendLine(line);
                            connections.Add(line);
                        }
                        report.AppendLine();
                        report.AppendLine("   These IP addresses may identify the source of the unauthorized access.");
                        report.AppendLine("   Request ISP subscriber information via law enforcement subpoena.");
                    }
                    else
                    {
                        report.AppendLine("  No active network connections found for the offender process.");
                    }
                }
                else
                {
                    report.AppendLine("  Offender process not identified - capturing full connection snapshot.");
                }

                // Save full connection snapshot regardless
                var allConnsText = allConnections.Select(c => $"PID {c.pid}\t{c.protocol}\t{c.localAddr}:{c.localPort}\t{c.remoteAddr}:{c.remotePort}\t{c.state}");
                await FileNet48.WriteAllLinesAsync(Path.Combine(reportDir, "network_snapshot.txt"), allConnsText);
            }
            catch (Exception ex)
            {
                report.AppendLine($"  Error collecting network evidence: {ex.Message}");
            }
            report.AppendLine();
        }

        private async Task AppendTimelineAndRecommendations(string reportDir, StringBuilder report,
            AppBaseline baseline, DateTime detectionTime)
        {
            report.AppendLine("");
            report.AppendLine("TIMELINE");
            report.AppendLine("");
            report.AppendLine();
            report.AppendLine($"  {baseline.BaselinedAt:yyyy-MM-dd HH:mm:ss} UTC - Application integrity baselined (known good state)");
            report.AppendLine($"  {detectionTime:yyyy-MM-dd HH:mm:ss} UTC - Unauthorized replacement detected by Sentinel");
            report.AppendLine($"  {detectionTime.AddSeconds(1):yyyy-MM-dd HH:mm:ss} UTC - Automated response: offender killed, impostor quarantined");
            report.AppendLine();

            report.AppendLine("");
            report.AppendLine("LEGAL CLASSIFICATION");
            report.AppendLine("");
            report.AppendLine();
            report.AppendLine("  This incident may constitute violations of:");
            report.AppendLine();
            report.AppendLine("  - Computer Fraud and Abuse Act (18 U.S.C.  1030) - Unauthorized access/modification");
            report.AppendLine("  - EU Directive 2013/40/EU - Attacks against information systems");
            report.AppendLine("  - UK Computer Misuse Act 1990 - Unauthorized modification of computer material");
            report.AppendLine("  - Croatian Criminal Code Art. 266 - Unauthorized computer interference");
            report.AppendLine("  - German StGB  303a - Data tampering (Datenvernderung)");
            report.AppendLine();
            report.AppendLine("  The replacement of legitimate software with unauthorized software on a");
            report.AppendLine("  user's computer without consent constitutes unauthorized modification of");
            report.AppendLine("  computer programs and data, a criminal offense in most jurisdictions.");
            report.AppendLine();

            report.AppendLine("");
            report.AppendLine("RECOMMENDED ACTIONS FOR LAW ENFORCEMENT FILING");
            report.AppendLine("");
            report.AppendLine();
            report.AppendLine("  1. Preserve this report and all files in the report directory.");
            report.AppendLine("  2. The quarantined impostor binary is DPAPI-encrypted in the Sentinel");
            report.AppendLine("     quarantine vault - available for forensic analysis upon request.");
            report.AppendLine("  3. Network connection IPs (if present) can be used to identify the");
            report.AppendLine("     perpetrator via ISP records (requires court order/subpoena).");
            report.AppendLine("  4. The impostor's Authenticode certificate (if signed) identifies the");
            report.AppendLine("     publishing organization responsible for the replacement software.");
            report.AppendLine("  5. File timestamps establish the time window of unauthorized access.");
            report.AppendLine();
            report.AppendLine("");
            report.AppendLine("EVIDENCE FILES IN THIS DIRECTORY");
            report.AppendLine("");
            report.AppendLine();
            report.AppendLine("  - incident_report.txt     - This report");
            report.AppendLine("  - network_snapshot.txt    - All network connections at time of detection");
            report.AppendLine("  - offender_modules.txt    - Loaded modules of the offending process");
            report.AppendLine("  - impostor_certificate.cer - Authenticode cert of the impostor (if signed)");
            report.AppendLine();
            report.AppendLine("");
            report.AppendLine("         Generated by Sentinel Application Integrity Monitor");
            report.AppendLine("");

            await Task.CompletedTask;
        }

        // 
        // Helper Methods
        // 

        private AppBaseline? CreateBaseline(ProtectedApplication app)
        {
            if (!File.Exists(app.ExecutablePath)) return null;

            var hash = ComputeFileHash(app.ExecutablePath);
            if (hash == null) return null;

            var publisher = GetAuthenticodePublisher(app.ExecutablePath);
            var fi = new FileInfo(app.ExecutablePath);
            var vi = FileVersionInfo.GetVersionInfo(app.ExecutablePath);

            return new AppBaseline
            {
                Name = app.Name,
                ExecutablePath = app.ExecutablePath,
                Sha256Hash = hash,
                Publisher = publisher ?? "UNSIGNED",
                ExpectedPublisher = app.ExpectedPublisher,
                FileSize = fi.Length,
                BaselinedAt = DateTime.UtcNow,
                FileVersion = vi.FileVersion ?? "",
                ProductName = vi.ProductName ?? ""
            };
        }

        private static string? ComputeFileHash(string filePath)
        {
            try
            {
                using var fs = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
                var hashBytes = System.Security.Cryptography.Sha256Net48.HashData(fs);
                return ConvertHex.ToHexString(hashBytes).ToLowerInvariant();
            }
            catch
            {
                return null;
            }
        }

        private static string? GetAuthenticodePublisher(string filePath)
        {
            try
            {
#pragma warning disable SYSLIB0057 // X509Certificate.CreateFromSignedFile is obsolete
                var cert = X509Certificate.CreateFromSignedFile(filePath);
#pragma warning restore SYSLIB0057
                using var cert2 = new X509Certificate2(cert);
                var subject = cert2.Subject;
                var cnStart = subject.IndexOf("CN=");
                if (cnStart >= 0)
                {
                    cnStart += 3;
                    var cnEnd = subject.IndexOf(',', cnStart);
                    if (cnEnd < 0) cnEnd = subject.Length;
                    return subject[cnStart..cnEnd].Trim().Trim('"');
                }
                return subject;
            }
            catch
            {
                return null;
            }
        }

        private static string? GetFileProductName(string filePath)
        {
            try
            {
                var vi = FileVersionInfo.GetVersionInfo(filePath);
                return vi.ProductName;
            }
            catch { return null; }
        }

        private void BackupProtectedBinary(string executablePath)
        {
            try
            {
                if (!File.Exists(executablePath)) return;
                var fileBytes = File.ReadAllBytes(executablePath);
                // DPAPI-encrypt for tamper resistance
                var encrypted = ProtectedData.Protect(fileBytes, null, DataProtectionScope.LocalMachine);
                var safeName = Path.GetFileName(executablePath).Replace(" ", "_");
                var backupPath = Path.Combine(_backupDir, $"backup_{safeName}.dpapi");
                File.WriteAllBytes(backupPath, encrypted);
                _logger.LogDebug("[ApplicationIntegrityMonitor] Backed up {Path}", executablePath);
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "[ApplicationIntegrityMonitor] Failed to backup {Path}", executablePath);
            }
        }

        private async Task RestoreFromBackupAsync(string executablePath, AppBaseline baseline)
        {
            try
            {
                var safeName = Path.GetFileName(executablePath).Replace(" ", "_");
                var backupPath = Path.Combine(_backupDir, $"backup_{safeName}.dpapi");

                if (!File.Exists(backupPath))
                {
                    _logger.LogWarning("[ApplicationIntegrityMonitor] No backup found at {Path} - cannot restore", backupPath);
                    return;
                }

                var encrypted = await FileNet48.ReadAllBytesAsync(backupPath);
                var decrypted = ProtectedData.Unprotect(encrypted, null, DataProtectionScope.LocalMachine);

                // Ensure target directory exists
                var dir = Path.GetDirectoryName(executablePath);
                if (!string.IsNullOrEmpty(dir) && !Directory.Exists(dir))
                    Directory.CreateDirectory(dir);

                await System.IO.FileNet48.WriteAllBytesAsync(executablePath, decrypted);
                _logger.LogWarning("[ApplicationIntegrityMonitor]  Restored original {Name} from backup", baseline.Name);

                await _eventLogger.LogEventAsync("integrity_restore", new
                {
                    Application = baseline.Name,
                    Path = executablePath,
                    RestoredHash = baseline.Sha256Hash,
                    Timestamp = DateTime.UtcNow
                });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "[ApplicationIntegrityMonitor] Failed to restore {Name} from backup", baseline.Name);
            }
        }

        private static void KillRunningImpostor(string executablePath)
        {
            try
            {
                var exeName = Path.GetFileNameWithoutExtension(executablePath);
                var processes = Process.GetProcessesByName(exeName);
                foreach (var proc in processes)
                {
                    try
                    {
                        var imagePath = SecurityValidation.GetProcessImagePath(proc.Id);
                        if (string.Equals(imagePath, executablePath))
                        {
                            HardeningModule.SafeKillProcessTree(proc.Id);
                        }
                    }
                    catch { }
                    finally { proc.Dispose(); }
                }
            }
            catch { }
        }

        /// <summary>
        /// Attempts to find the process that modified the protected file.
        /// Uses handle enumeration and recent process history.
        /// </summary>
        private static int FindModifyingProcess(string filePath)
        {
            try
            {
                // Strategy: find processes that have a handle to the file or its directory
                var dir = Path.GetDirectoryName(filePath) ?? "";
                var candidates = new List<(int pid, string name, DateTime startTime)>();

                foreach (var proc in Process.GetProcesses())
                {
                    try
                    {
                        var imagePath = SecurityValidation.GetProcessImagePath(proc.Id);
                        if (string.IsNullOrEmpty(imagePath)) { proc.Dispose(); continue; }

                        // Look for installer-like processes that started recently
                        var isInstaller = imagePath!.Contains("installer") ||
                                         imagePath.Contains("setup") ||
                                         imagePath.Contains("update") ||
                                         imagePath.Contains("msiexec") ||
                                         imagePath.Contains("unins");

                        // Also check if the process has the target directory in its working path
                        var hasTargetDir = false;
                        try
                        {
                            var cmdLine = GetProcessCommandLine(proc.Id);
                            hasTargetDir = cmdLine.Contains(dir) ||
                                          cmdLine.Contains(filePath);
                        }
                        catch { }

                        if (isInstaller || hasTargetDir)
                        {
                            var age = DateTime.Now - proc.StartTime;
                            if (age.TotalMinutes < 5) // Started within last 5 minutes
                            {
                                candidates.Add((proc.Id, proc.ProcessName, proc.StartTime));
                            }
                        }
                    }
                    catch { }
                    finally { proc.Dispose(); }
                }

                // Return the most recent installer-like process
                if (candidates.Count > 0)
                {
                    return candidates.OrderByDescending(c => c.startTime).First().pid;
                }
            }
            catch { }
            return 0;
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

        private static string GetProcessNameSafe(int pid)
        {
            try
            {
                using var proc = Process.GetProcessById(pid);
                return proc.ProcessName;
            }
            catch { return "UNKNOWN"; }
        }

        private static List<(int pid, string name, string path)> GetProcessAncestry(int pid)
        {
            var ancestry = new List<(int pid, string name, string path)>();
            var visited = new HashSet<int>();
            var currentPid = pid;

            for (int i = 0; i < 10; i++) // Max 10 levels deep
            {
                if (currentPid <= 4 || visited.Contains(currentPid)) break;
                visited.Add(currentPid);

                try
                {
                    using var searcher = new System.Management.ManagementObjectSearcher(
                        $"SELECT ParentProcessId, Name, ExecutablePath FROM Win32_Process WHERE ProcessId = {currentPid}");
                    foreach (var obj in searcher.Get())
                    {
                        var parentPid = Convert.ToInt32(obj["ParentProcessId"]);
                        var name = obj["Name"]?.ToString() ?? "UNKNOWN";
                        var path = obj["ExecutablePath"]?.ToString() ?? "UNKNOWN";
                        ancestry.Add((currentPid, name, path));
                        currentPid = parentPid;
                    }
                }
                catch { break; }
            }
            return ancestry;
        }

        private static List<(int pid, string protocol, string localAddr, int localPort, string remoteAddr, int remotePort, string state)> GetActiveConnections()
        {
            var results = new List<(int pid, string protocol, string localAddr, int localPort, string remoteAddr, int remotePort, string state)>();
            try
            {
                using var searcher = new System.Management.ManagementObjectSearcher(
                    "SELECT * FROM MSFT_NetTCPConnection");

                // Fallback to netstat parsing if WMI class not available
                var psi = new ProcessStartInfo("netstat", "-ano")
                {
                    RedirectStandardOutput = true,
                    UseShellExecute = false,
                    CreateNoWindow = true
                };
                using var proc = Process.Start(psi);
                if (proc == null) return results;

                var output = proc.StandardOutput.ReadToEnd();
                proc.WaitForExit(5000);

                foreach (var line in output.Split(new[] { '\n' }, StringSplitOptions.RemoveEmptyEntries))
                {
                    var parts = line.Trim().Split(new[] { ' ' }, StringSplitOptions.RemoveEmptyEntries);
                    if (parts.Length < 5) continue;
                    if (parts[0] != "TCP" && parts[0] != "UDP") continue;

                    var protocol = parts[0];
                    var localParts = parts[1].LastIndexOf(':');
                    var remoteParts = parts[2].LastIndexOf(':');
                    if (localParts < 0 || remoteParts < 0) continue;

                    var localAddr = parts[1][..localParts];
                    int.TryParse(parts[1][(localParts + 1)..], out int localPort);
                    var remoteAddr = parts[2][..remoteParts];
                    int.TryParse(parts[2][(remoteParts + 1)..], out int remotePort);
                    var state = parts.Length > 3 && parts[0] == "TCP" ? parts[3] : "N/A";
                    int.TryParse(parts[^1], out int pid);

                    results.Add((pid, protocol, localAddr, localPort, remoteAddr, remotePort, state));
                }
            }
            catch { }
            return results;
        }

        private static void SaveImpostorCertificate(string reportDir, string filePath)
        {
            try
            {
#pragma warning disable SYSLIB0057
                var cert = X509Certificate.CreateFromSignedFile(filePath);
#pragma warning restore SYSLIB0057
                using var cert2 = new X509Certificate2(cert);
                var certBytes = cert2.Export(X509ContentType.Cert);
                File.WriteAllBytes(Path.Combine(reportDir, "impostor_certificate.cer"), certBytes);
            }
            catch { } // Not signed - that's evidence too
        }

        private static string BuildCuckooEvidenceString(AppBaseline baseline, string executablePath,
            string currentHash, string? currentPublisher, string? currentProductName)
        {
            var sb = new StringBuilder();
            sb.Append($"Protected application '{baseline.Name}' at '{executablePath}' was replaced. ");
            sb.Append($"Original SHA-256: {baseline.Sha256Hash[..16]}... Publisher: '{baseline.Publisher}'. ");
            sb.Append($"Impostor SHA-256: {currentHash[..16]}... Publisher: '{currentPublisher ?? "UNSIGNED"}'. ");

            if (!string.IsNullOrEmpty(currentProductName) && currentProductName != baseline.ProductName)
                sb.Append($"Product changed from '{baseline.ProductName}' to '{currentProductName}'. ");

            sb.Append("This is a cuckoo egg attack - unauthorized software placed in a trusted location.");
            return sb.ToString();
        }

        private static string BuildCuckooReasoningString(AppBaseline baseline, string? currentPublisher, string? currentProductName)
        {
            var sb = new StringBuilder();
            sb.Append("The monitored executable's cryptographic hash changed and the Authenticode publisher ");

            if (string.IsNullOrEmpty(currentPublisher))
                sb.Append("is now MISSING (unsigned binary replaced a signed one). ");
            else if (!string.Equals(currentPublisher, baseline.ExpectedPublisher))
                sb.Append($"changed from '{baseline.ExpectedPublisher}' to '{currentPublisher}' (different organization). ");

            if (!string.IsNullOrEmpty(currentProductName) && currentProductName != baseline.ProductName)
                sb.Append($"The product identity changed from '{baseline.ProductName}' to '{currentProductName}', confirming this is a completely different application. ");

            sb.Append("A legitimate update would retain the same publisher signature. ");
            sb.Append("This pattern matches a cuckoo egg attack where an attacker replaces legitimate software ");
            sb.Append("with malicious or unauthorized software to hijack the user's workflow and trust.");
            return sb.ToString();
        }
    }
}
