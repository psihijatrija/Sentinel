using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;

namespace Sentinel.Core
{
    /// <summary>
    /// Automatic incident evidence packs for high-confidence attack detections.
    ///
    /// What this DOES automatically:
    ///   1. Writes a police-ready local evidence pack under ProgramData\Sentinel\IncidentReports
    ///   2. Seals the pack with SHA-256 file hashes + machine-bound HMAC (integrity / anti-tamper)
    ///   3. Includes victim affidavit template + chain-of-custody notes
    ///   4. Includes country-specific filing URLs (national portals; NOT INTERPOL direct intake)
    ///   5. Optionally submits malware indicators to ThreatReportService (TI platforms)
    ///   6. Notifies the user via critical toast
    ///
    /// What this does NOT do:
    ///   - File a criminal complaint with INTERPOL, FBI, or any police API
    ///
    /// v1.7.8: Reportable-grade-only policy, integrity export, affidavit.
    /// </summary>
    public sealed class AutoIncidentReporter
    {
        private static readonly HashSet<SignalType> AttackSignalTypes = new()
        {
            SignalType.LsassAccess,
            SignalType.AmsiTampering,
            SignalType.EtwTampering,
            SignalType.Ransomware,
            SignalType.ReverseShell,
            SignalType.NetworkC2,
            SignalType.CredentialTheft,
            SignalType.ProcessInjection,
            SignalType.AntiTamper,
            SignalType.SecurityEvasion,
            SignalType.PhantomKeystroke
        };

        private static readonly string[] AttackRuleKeywords =
        {
            "ransomware", "cuckoo", "injection", "reverse shell", "credential", "lsass",
            "beacon", "exfil", "c2", "dump", "mimikatz", "cobalt", "lateral", "token theft",
            "shadow copy", "uac bypass", "persistence", "rootkit", "keylog", "clipbanker",
            "process hollowing", "dll sideload", "supply chain", "reinfection", "malware",
            "stalkerware", "surveillance", "remote control", "session theft", "webcam", "screen capture"
        };

        private static readonly Regex Sha256Regex = new(
            @"\b[a-fA-F0-9]{64}\b", RegexOptions.Compiled);

        private static readonly Regex Ipv4Regex = new(
            @"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b",
            RegexOptions.Compiled);

        private static readonly HashSet<string> IntegritySkipFileNames = new(StringComparer.OrdinalIgnoreCase)
        {
            "MANIFEST.sha256",
            "MANIFEST.hmac",
            "evidence_manifest.json",
            "VERIFY.txt",
            // Filled after seal by complainant / custodians - excluded on purpose.
            "victim_affidavit.txt",
            "chain_of_custody.txt"
        };

        private readonly AutoIncidentReportingConfig _config;
        private readonly SentinelConfig _sentinelConfig;
        private readonly ThreatReportService _threatReportService;
        private readonly ToastService? _toastService;
        private readonly SentinelEventLogWriter? _windowsEventLog;
        private readonly ILogger<AutoIncidentReporter> _logger;
        private readonly string _reportRoot;
        private readonly string _productVersion;

        private readonly ConcurrentDictionary<string, DateTimeOffset> _cooldown = new(StringComparer.OrdinalIgnoreCase);
        private readonly ConcurrentQueue<DateTimeOffset> _packTimestamps = new();
        private long _packsGenerated;
        private long _tiSubmissions;

        public AutoIncidentReporter(
            AutoIncidentReportingConfig config,
            ThreatReportService threatReportService,
            ILogger<AutoIncidentReporter> logger,
            ToastService? toastService = null,
            SentinelConfig? sentinelConfig = null,
            SentinelEventLogWriter? windowsEventLog = null)
        {
            _config = config ?? new AutoIncidentReportingConfig();
            _sentinelConfig = sentinelConfig ?? new SentinelConfig();
            _threatReportService = threatReportService;
            _toastService = toastService;
            _windowsEventLog = windowsEventLog;
            _logger = logger;
            _productVersion = typeof(AutoIncidentReporter).Assembly.GetName().Version?.ToString() ?? "1.8.0";

            _reportRoot = _config.ReportDirectory
                ?? Path.Combine(
                    Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
                    "Sentinel", "IncidentReports");

            try { Directory.CreateDirectory(_reportRoot); } catch { /* best effort */ }
        }

        public long PacksGenerated => Interlocked.Read(ref _packsGenerated);
        public long ThreatIntelSubmissions => Interlocked.Read(ref _tiSubmissions);

        /// <summary>
        /// Evaluates a detection and, when policy matches, builds an evidence pack
        /// and optionally submits indicators to TI platforms. Never throws.
        /// </summary>
        public async Task HandleDetectionAsync(DetectionEvent detection, Incident? incident = null)
        {
            if (!_config.Enabled || detection == null)
                return;

            try
            {
                // Silent observe: no evidence packs / TI / toasts until chain-confirmed terminal attack.
                if (!ResponsePolicy.ShouldAutoReportIncident(detection, _sentinelConfig))
                    return;

                if (!ShouldReport(detection))
                    return;

                var cooldownKey = BuildCooldownKey(detection);
                if (IsOnCooldown(cooldownKey))
                    return;

                if (!TryAcquireRateLimitSlot())
                {
                    _logger.LogDebug("[AutoIncidentReporter] Rate limit reached - skipping pack for {Rule}",
                        detection.RuleName);
                    return;
                }

                _cooldown[cooldownKey] = DateTimeOffset.UtcNow;

                string? packPath = null;
                if (_config.GenerateLocalEvidencePack)
                {
                    packPath = await WriteEvidencePackAsync(detection, incident).ConfigureAwait(false);
                    Interlocked.Increment(ref _packsGenerated);
                    try
                    {
                        if (!string.IsNullOrEmpty(packPath) && _windowsEventLog != null)
                            _windowsEventLog.WriteEvidencePack(detection, packPath);
                    }
                    catch { /* Event Log optional */ }

                    // B1: mirror a signed summary off-host so a local admin who suppresses
                    // Sentinel cannot also erase the proof. Opt-in + fail-closed; the local pack
                    // write above is independent of mirror success.
                    if (_config.MirrorEvidenceOffHost && !string.IsNullOrEmpty(packPath))
                    {
                        await MirrorEvidenceOffHostAsync(detection, packPath!).ConfigureAwait(false);
                    }
                }

                if (_config.ReportThreatIntel)
                {
                    var submitted = await SubmitThreatIntelAsync(detection).ConfigureAwait(false);
                    if (submitted > 0)
                        Interlocked.Add(ref _tiSubmissions, submitted);
                }

                if (_config.NotifyUser && _toastService != null && !string.IsNullOrEmpty(packPath))
                {
                    var portal = LawEnforcementPortals.Resolve(_config.CountryCode);
                    // 1.8.4 API: ShowCriticalToast (always delivers; CriticalOnly does not suppress)
                    var toastTitle = CoercionAbusePolicy.IsDigitalCoercionToolkit(detection)
                        ? "Sentinel: Surveillance / remote-control abuse - evidence pack ready"
                        : "Sentinel: Attack chain confirmed - evidence pack ready";
                    var toastBody = CoercionAbusePolicy.IsDigitalCoercionToolkit(detection)
                        ? $"{detection.RuleName} - technical indicators of device takeover or covert surveillance. " +
                          $"Sealed pack + affidavit for {portal.PrimaryPortalName}. Path: {packPath}"
                        : $"{detection.RuleName} - integrity-sealed pack + affidavit template. " +
                          $"File with {portal.PrimaryPortalName}. Path: {packPath}";
                    _toastService.ShowCriticalToast(toastTitle, toastBody);
                }

                _logger.LogWarning(
                    "[AutoIncidentReporter] Auto-reported incident: rule={Rule} conf={Conf:F2} pack={Pack} incident={Incident}",
                    detection.RuleName, detection.Confidence, packPath ?? "(none)", incident?.Id ?? "n/a");
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "[AutoIncidentReporter] Failed handling detection {Rule}", detection.RuleName);
            }
        }

        /// <summary>
        /// Policy gate: reportable-grade attack activity only (when ReportableGradeOnly is true).
        /// </summary>
        public bool ShouldReport(DetectionEvent detection)
        {
            if (detection == null) return false;

            // v1.8.0: never generate police packs for known TokenTheft OS false positives
            // (Memory Compression / Registry / empty-path SYSTEM noise).
            if (IsTokenTheftOsFalsePositive(detection))
                return false;

            // v1.9.3: chain-confirmed / composite nukes always get a sealed evidence pack.
            // Previously SilentObserve passed but ReportableGradeOnly + low seed Confidence
            // (or KillAuthorized not written back) dropped packs after real kills.
            if (IsChainConfirmedOrComposite(detection))
                return true;

            var minConf = _config.MinConfidence;
            var killFloor = _config.ReportableGradeOnly
                ? _config.KillAuthorizedMinConfidence
                : Math.Min(minConf, 0.70);

            if (_config.IncludeKillAuthorized && detection.KillAuthorized)
            {
                if (detection.Confidence < killFloor)
                    return false;

                // Reportable-grade: kills still need attack character when grade-only
                if (_config.ReportableGradeOnly)
                {
                    return IsAttackCharacter(detection) ||
                           detection.Confidence >= Math.Max(minConf, 0.90) ||
                           detection.Tier == DetectionTier.Tier1Behavioral;
                }

                return true;
            }

            if (_config.IncludeNetworkIsolate &&
                detection.AuthorizedResponse == ResponseAction.NetworkIsolate &&
                detection.Confidence >= minConf)
            {
                if (_config.ReportableGradeOnly)
                    return IsAttackCharacter(detection) || detection.SignalType == SignalType.NetworkC2;
                return true;
            }

            // Tier1 attack signals at MinConfidence
            if (detection.Tier == DetectionTier.Tier1Behavioral &&
                detection.Confidence >= minConf &&
                IsAttackCharacter(detection))
            {
                return true;
            }

            // Legacy broader path only when not reportable-grade-only
            if (!_config.ReportableGradeOnly &&
                detection.Confidence >= 0.90 &&
                detection.Tier == DetectionTier.Tier1Behavioral)
            {
                return true;
            }

            return false;
        }

        public static bool IsChainConfirmedOrComposite(DetectionEvent detection)
        {
            if (detection == null) return false;
            if (ResponsePolicy.IsNukeComposite(detection))
                return true;
            if (detection.Metadata != null &&
                detection.Metadata.TryGetValue(ResponsePolicy.ChainConfirmedKey, out var v) &&
                string.Equals(v, "true", StringComparison.OrdinalIgnoreCase))
                return true;
            return false;
        }

        public static bool IsAttackCharacter(DetectionEvent detection)
        {
            if (AttackSignalTypes.Contains(detection.SignalType))
                return true;
            if (RuleNameLooksLikeAttack(detection.RuleName))
                return true;
            // Explicit high-risk responses count as attack character
            if (detection.AuthorizedResponse is ResponseAction.QuarantineAndKill
                or ResponseAction.KillProcessTree
                or ResponseAction.Quarantine)
                return true;
            return false;
        }

        public static bool RuleNameLooksLikeAttack(string? ruleName)
        {
            if (string.IsNullOrWhiteSpace(ruleName)) return false;
            var lower = ruleName!.ToLowerInvariant();
            return AttackRuleKeywords.Any(k => lower.Contains(k));
        }

        /// <summary>
        /// Verifies MANIFEST.sha256 hashes and MANIFEST.hmac for a pack directory.
        /// </summary>
        public static EvidenceIntegrityResult VerifyPackIntegrity(string packDirectory)
        {
            if (string.IsNullOrWhiteSpace(packDirectory) || !Directory.Exists(packDirectory))
                return new EvidenceIntegrityResult(false, "Pack directory missing.");

            var manifestPath = Path.Combine(packDirectory, "MANIFEST.sha256");
            var hmacPath = Path.Combine(packDirectory, "MANIFEST.hmac");
            if (!File.Exists(manifestPath))
                return new EvidenceIntegrityResult(false, "MANIFEST.sha256 missing.");

            try
            {
                var lines = File.ReadAllLines(manifestPath);
                var mismatches = new List<string>();
                foreach (var line in lines)
                {
                    if (string.IsNullOrWhiteSpace(line) || line.StartsWith("#"))
                        continue;
                    var parts = line.Split(new[] { "  " }, 2, StringSplitOptions.None);
                    if (parts.Length != 2)
                    {
                        // also allow "hash *filename" or "hash filename"
                        parts = line.Split(new[] { ' ', '\t' }, 2, StringSplitOptions.RemoveEmptyEntries);
                        if (parts.Length != 2)
                            continue;
                    }

                    var expected = parts[0].Trim().ToLowerInvariant();
                    var rel = parts[1].Trim().TrimStart('*');
                    var full = Path.Combine(packDirectory, rel.Replace('/', Path.DirectorySeparatorChar));
                    if (!File.Exists(full))
                    {
                        mismatches.Add($"missing:{rel}");
                        continue;
                    }

                    var actual = ComputeFileSha256Hex(full);
                    if (!string.Equals(actual, expected))
                        mismatches.Add($"hash-mismatch:{rel}");
                }

                if (mismatches.Count > 0)
                    return new EvidenceIntegrityResult(false, "File hash verification failed: " + string.Join(", ", mismatches));

                if (File.Exists(hmacPath))
                {
                    var expectedHmac = File.ReadAllText(hmacPath).Trim().ToLowerInvariant();
                    var actualHmac = ComputeManifestHmacHex(File.ReadAllBytes(manifestPath));
                    if (!string.Equals(expectedHmac, actualHmac))
                    {
                        return new EvidenceIntegrityResult(false, "MANIFEST.hmac signature mismatch (pack may have been altered or moved from original machine).");
                    }
                }

                return new EvidenceIntegrityResult(true, "OK");
            }
            catch (Exception ex)
            {
                return new EvidenceIntegrityResult(false, ex.Message);
            }
        }

        private string BuildCooldownKey(DetectionEvent d) =>
            $"{d.RuleName}|{d.ProcessId}|{d.SignalType}";

        /// <summary>
        /// v1.8.0: Token Theft rules that only name built-in OS processes (or empty image path
        /// with those names in evidence) must not create LE evidence packs. Real potato/token
        /// theft from Temp/Downloads still reports normally.
        /// </summary>
        internal static bool IsTokenTheftOsFalsePositive(DetectionEvent detection)
        {
            if (detection == null) return false;
            var rule = detection.RuleName ?? "";
            if (!rule.Contains("Token Theft"))
                return false;

            var name = detection.ProcessName ?? "";
            if (TokenTheftMonitor.IsLikelyProtectedOsProcess(name) ||
                TokenTheftMonitor.IsLegitimateSystemTokenHolder(name))
                return true;

            // v1.8.3: UUP dump aria2c / portable archive tools from Downloads are not LE pack material
            var evidence = detection.Evidence ?? "";
            if (InstallerHeuristics.IsPortableDownloadOrArchiveTool(name) ||
                InstallerHeuristics.IsPortableDownloadOrArchiveTool(null, evidence) ||
                InstallerHeuristics.IsOfflineImageWorkPath(evidence))
                return true;

            // Classic FP wording when image path is inaccessible
            if (evidence.Contains("at ''") &&
                (evidence.Contains("Memory Compression") ||
                 evidence.Contains("Process 'Registry'") ||
                 evidence.Contains("'Registry'")))
                return true;

            return false;
        }

        private bool IsOnCooldown(string key)
        {
            if (_cooldown.TryGetValue(key, out var last))
            {
                // v1.8.0: Token Theft packs use a longer cooldown (1h) even if config is 300s -
                // prevents hundreds of near-identical packs from the same PID.
                var seconds = Math.Max(30, _config.CooldownSeconds);
                if (key.StartsWith("Token Theft"))
                    seconds = Math.Max(seconds, 3600);

                if (DateTimeOffset.UtcNow - last < TimeSpan.FromSeconds(seconds))
                    return true;
            }
            return false;
        }

        private bool TryAcquireRateLimitSlot()
        {
            var now = DateTimeOffset.UtcNow;
            var windowStart = now - TimeSpan.FromHours(1);

            while (_packTimestamps.TryPeek(out var oldest) && oldest < windowStart)
                _packTimestamps.TryDequeue(out _);

            if (_packTimestamps.Count >= Math.Max(1, _config.MaxPacksPerHour))
                return false;

            _packTimestamps.Enqueue(now);
            return true;
        }

        private async Task<string> WriteEvidencePackAsync(DetectionEvent detection, Incident? incident)
        {
            var timestamp = DateTime.UtcNow;
            var safeRule = SanitizeFileToken(detection.RuleName, 48);
            var reportId = $"AUTO_{timestamp:yyyyMMdd_HHmmss}_{safeRule}_{detection.ProcessId}";
            var reportDir = Path.Combine(_reportRoot, reportId);
            Directory.CreateDirectory(reportDir);

            var portal = LawEnforcementPortals.Resolve(_config.CountryCode);
            var systemCountry = LawEnforcementPortals.DetectSystemCountryCode();
            var sealedAt = timestamp;

            var report = new StringBuilder();
            report.AppendLine("");
            report.AppendLine("     WINDOWS SENTINEL - REPORTABLE-GRADE EVIDENCE PACK          ");
            report.AppendLine("     Integrity-sealed - High-confidence attack activity         ");
            report.AppendLine("");
            report.AppendLine();
            report.AppendLine($"Report ID:        {reportId}");
            report.AppendLine($"Generated:        {timestamp:yyyy-MM-dd HH:mm:ss} UTC");
            report.AppendLine($"Sentinel Version: {_productVersion}");
            report.AppendLine($"Machine Name:     {Environment.MachineName}");
            report.AppendLine($"OS Version:       {Environment.OSVersion}");
            report.AppendLine($"User Account:     {Environment.UserDomainName}\\{Environment.UserName}");
            report.AppendLine($"System Region:    {systemCountry}");
            report.AppendLine($"Incident ID:      {incident?.Id ?? "n/a"}");
            report.AppendLine($"Incident Severity:{incident?.Severity.ToString() ?? "n/a"}");
            report.AppendLine($"Policy:           ReportableGradeOnly={_config.ReportableGradeOnly}; MinConfidence={_config.MinConfidence:F2}");
            report.AppendLine();
            report.AppendLine("");
            report.AppendLine("IMPORTANT - WHAT THIS PACK IS (AND IS NOT)");
            report.AppendLine("");
            report.AppendLine();
            report.AppendLine("  This package was generated AUTOMATICALLY by Sentinel for a");
            report.AppendLine("  REPORTABLE-GRADE detection (kill-class / C2 isolate / Tier1 attack).");
            report.AppendLine();
            report.AppendLine("  It is evidence for YOU (the victim/complainant) to file with your");
            report.AppendLine("  national cybercrime portal or local police. Complete victim_affidavit.txt.");
            report.AppendLine("  Sentinel does NOT file the report with INTERPOL, the FBI, or any police force.");
            report.AppendLine();
            report.AppendLine("  Integrity: see MANIFEST.sha256 + MANIFEST.hmac + VERIFY.txt.");
            report.AppendLine("  Do not edit sealed evidence files after generation.");
            report.AppendLine();
            report.AppendLine("  Secondary audit trail: Windows Event Log Application/Sentinel");
            report.AppendLine("  (Event ID 1200 evidence pack / 1100 chain response when Event Log is available).");
            report.AppendLine("  On stripped/custom Windows where Event Log is missing, JSONL + this pack remain authoritative.");
            report.AppendLine();
            if (CoercionAbusePolicy.IsDigitalCoercionToolkit(detection))
            {
                report.Append(CoercionAbusePolicy.BuildPackSection(detection));
            }
            report.AppendLine("");
            report.AppendLine("DETECTION SUMMARY");
            report.AppendLine("");
            report.AppendLine();
            report.AppendLine($"  Rule:              {detection.RuleName}");
            report.AppendLine($"  Signal Type:       {detection.SignalType}");
            report.AppendLine($"  Tier:              {detection.Tier}");
            report.AppendLine($"  Confidence:        {detection.Confidence:F2}");
            report.AppendLine($"  Authorized Action: {detection.AuthorizedResponse}");
            report.AppendLine($"  Kill Authorized:   {detection.KillAuthorized}");
            report.AppendLine($"  Attack Character:  {IsAttackCharacter(detection)}");
            report.AppendLine($"  Coercion toolkit:  {CoercionAbusePolicy.IsDigitalCoercionToolkit(detection)}");
            report.AppendLine($"  Process:           {detection.ProcessName} (PID {detection.ProcessId})");
            report.AppendLine($"  Detected At:       {detection.Timestamp:yyyy-MM-dd HH:mm:ss} UTC");
            report.AppendLine();
            report.AppendLine("  Evidence:");
            report.AppendLine(WrapIndented(detection.Evidence, "    "));
            report.AppendLine();
            report.AppendLine("  Reasoning:");
            report.AppendLine(WrapIndented(detection.Reasoning, "    "));
            report.AppendLine();

            if (detection.Metadata is { Count: > 0 })
            {
                report.AppendLine("");
                report.AppendLine("METADATA / INDICATORS");
                report.AppendLine("");
                report.AppendLine();
                foreach (var kv in detection.Metadata.OrderBy(k => k.Key, StringComparer.OrdinalIgnoreCase))
                {
                    report.AppendLine($"  {kv.Key}: {kv.Value}");
                }
                report.AppendLine();
            }

            report.AppendLine("");
            report.AppendLine("PROCESS SNAPSHOT");
            report.AppendLine("");
            report.AppendLine();
            AppendProcessSnapshot(report, detection.ProcessId);
            report.AppendLine();

            report.AppendLine("");
            report.AppendLine("NETWORK SNAPSHOT (time of report)");
            report.AppendLine("");
            report.AppendLine();
            var networkLines = CaptureNetworkSnapshot(detection.ProcessId);
            foreach (var line in networkLines)
                report.AppendLine(line);
            report.AppendLine();
            try
            {
                await FileNet48.WriteAllLinesAsync(
                    Path.Combine(reportDir, "network_snapshot.txt"),
                    networkLines).ConfigureAwait(false);
            }
            catch { /* best effort */ }

            if (incident?.Detections is { Count: > 0 })
            {
                report.AppendLine("");
                report.AppendLine("RELATED DETECTIONS IN THIS INCIDENT");
                report.AppendLine("");
                report.AppendLine();
                foreach (var d in incident.Detections.Take(25))
                {
                    report.AppendLine(
                        $"  {d.ReceivedAt:yyyy-MM-dd HH:mm:ss} UTC - {d.DetectionEvent.RuleName} " +
                        $"(conf={d.DetectionEvent.Confidence:F2}, pid={d.DetectionEvent.ProcessId})");
                }
                report.AppendLine();
            }

            report.AppendLine("");
            report.AppendLine("WHERE TO FILE A POLICE / CYBERCRIME REPORT");
            report.AppendLine("");
            report.AppendLine();
            report.AppendLine($"  Detected region:     {systemCountry}");
            report.AppendLine($"  Recommended portal:  {portal.CountryName} - {portal.PrimaryPortalName}");
            report.AppendLine($"  URL:                 {portal.PrimaryPortalUrl}");
            report.AppendLine($"  Notes:               {portal.Notes}");
            report.AppendLine();
            report.AppendLine($"  EU multi-country directory: {LawEnforcementPortals.EuropolDirectory.PrimaryPortalUrl}");
            report.AppendLine($"  INTERPOL (info only):       {LawEnforcementPortals.InterpolInfo.PrimaryPortalUrl}");
            report.AppendLine($"    {LawEnforcementPortals.InterpolInfo.Notes}");
            report.AppendLine();
            report.AppendLine("  Recommended filing steps:");
            report.AppendLine("    1. Complete victim_affidavit.txt (complainant identity + signature).");
            report.AppendLine("    2. Preserve this folder; verify with MANIFEST.sha256 / VERIFY.txt.");
            report.AppendLine("    3. Prefer the .zip export if present (includes sealed contents).");
            report.AppendLine("    4. Open the recommended national portal and file the complaint.");
            report.AppendLine("    5. Attach pack + list hashes/IPs from indicators.txt.");
            report.AppendLine("    6. Quarantined binaries (if any): ProgramData\\Sentinel\\Quarantine.");
            report.AppendLine();
            report.AppendLine("");
            report.AppendLine("LEGAL CLASSIFICATION (INFORMATIONAL ONLY)");
            report.AppendLine("");
            report.AppendLine();
            report.AppendLine("  Depending on jurisdiction, this activity may relate to:");
            report.AppendLine("  - Unauthorized access / modification of computer systems");
            report.AppendLine("  - Malware deployment or computer fraud statutes");
            report.AppendLine("  - Data interference / system interference (Budapest Convention style)");
            report.AppendLine("  This is not legal advice - consult local law enforcement or counsel.");
            report.AppendLine();
            report.AppendLine("");
            report.AppendLine("THREAT INTELLIGENCE AUTO-SHARE");
            report.AppendLine("");
            report.AppendLine();
            report.AppendLine(_config.ReportThreatIntel
                ? "  Indicator auto-share to MalwareBazaar/URLhaus/AbuseIPDB is ENABLED when the"
                : "  Indicator auto-share to TI platforms is DISABLED in configuration.");
            if (_config.ReportThreatIntel)
            {
                report.AppendLine("  ThreatReporting proxy is configured (community malware intel - NOT police).");
            }
            report.AppendLine();
            report.AppendLine("");
            report.AppendLine($"         Generated by Sentinel AutoIncidentReporter (v{_productVersion})");
            report.AppendLine("");

            var reportPath = Path.Combine(reportDir, "incident_report.txt");
            await System.IO.FileNet48.WriteAllTextAsync(reportPath, report.ToString(), Encoding.UTF8).ConfigureAwait(false);

            var indicators = ExtractIndicators(detection);
            var summary = new StringBuilder();
            summary.AppendLine($"report_id={reportId}");
            summary.AppendLine($"rule={detection.RuleName}");
            summary.AppendLine($"confidence={detection.Confidence:F2}");
            summary.AppendLine($"signal={detection.SignalType}");
            summary.AppendLine($"process={detection.ProcessName}");
            summary.AppendLine($"pid={detection.ProcessId}");
            summary.AppendLine($"portal_url={portal.PrimaryPortalUrl}");
            summary.AppendLine($"country={portal.CountryCode}");
            summary.AppendLine($"sentinel_version={_productVersion}");
            summary.AppendLine($"reportable_grade_only={_config.ReportableGradeOnly}");
            foreach (var h in indicators.Hashes)
                summary.AppendLine($"sha256={h}");
            foreach (var ip in indicators.Ips)
                summary.AppendLine($"ip={ip}");
            foreach (var url in indicators.Urls)
                summary.AppendLine($"url={url}");
            await System.IO.FileNet48.WriteAllTextAsync(
                Path.Combine(reportDir, "indicators.txt"),
                summary.ToString(), Encoding.UTF8).ConfigureAwait(false);

            await WriteChainOfCustodyAsync(reportDir, reportId, detection, incident, sealedAt).ConfigureAwait(false);

            if (_config.IncludeVictimAffidavit)
            {
                await WriteVictimAffidavitAsync(reportDir, reportId, detection, portal, sealedAt).ConfigureAwait(false);
            }

            if (_config.IncludeIntegrityManifest)
            {
                await SealPackIntegrityAsync(reportDir, reportId, detection, sealedAt).ConfigureAwait(false);
            }

            if (_config.CreateZipExport)
            {
                try
                {
                    var zipPath = reportDir.TrimEnd(Path.DirectorySeparatorChar) + ".zip";
                    if (File.Exists(zipPath)) File.Delete(zipPath);
                    ZipFile.CreateFromDirectory(reportDir, zipPath, CompressionLevel.Optimal, includeBaseDirectory: false);
                    // Seal zip hash alongside for transport integrity
                    var zipHash = ComputeFileSha256Hex(zipPath);
                    await System.IO.FileNet48.WriteAllTextAsync(
                        zipPath + ".sha256",
                        $"{zipHash}  {Path.GetFileName(zipPath)}{Environment.NewLine}",
                        Encoding.UTF8).ConfigureAwait(false);
                }
                catch (Exception ex)
                {
                    _logger.LogDebug(ex, "[AutoIncidentReporter] Zip export failed for {Dir}", reportDir);
                }
            }

            return reportDir;
        }

        private async Task WriteChainOfCustodyAsync(
            string reportDir, string reportId, DetectionEvent detection, Incident? incident, DateTime sealedAt)
        {
            var sb = new StringBuilder();
            sb.AppendLine("SENTINEL - CHAIN OF CUSTODY");
            sb.AppendLine("==========================");
            sb.AppendLine();
            sb.AppendLine($"Report ID:           {reportId}");
            sb.AppendLine($"Sensor:              Sentinel AutoIncidentReporter v{_productVersion}");
            sb.AppendLine($"Host:                {Environment.MachineName}");
            sb.AppendLine($"Collecting account:  {Environment.UserDomainName}\\{Environment.UserName}");
            sb.AppendLine();
            sb.AppendLine("Timeline (UTC):");
            sb.AppendLine($"  {detection.Timestamp:yyyy-MM-dd HH:mm:ss}  Detection raised by rule \"{detection.RuleName}\"");
            if (incident != null)
            {
                sb.AppendLine($"  {incident.CreatedAt.UtcDateTime:yyyy-MM-dd HH:mm:ss}  Incident {incident.Id} opened (severity={incident.Severity})");
                if (incident.RespondedAt.HasValue)
                    sb.AppendLine($"  {incident.RespondedAt.Value.UtcDateTime:yyyy-MM-dd HH:mm:ss}  Automated response: {incident.ResponseAction ?? detection.AuthorizedResponse.ToString()}");
            }
            sb.AppendLine($"  {sealedAt:yyyy-MM-dd HH:mm:ss}  Evidence pack written and integrity seal applied");
            sb.AppendLine();
            sb.AppendLine("Handling notes:");
            sb.AppendLine("  - Pack was generated automatically on the victim host.");
            sb.AppendLine("  - Files listed in MANIFEST.sha256 should not be modified after seal time.");
            sb.AppendLine("  - MANIFEST.hmac is machine-bound; verify on original host when possible.");
            sb.AppendLine("  - Quarantined samples (if any) remain under ProgramData\\Sentinel\\Quarantine");
            sb.AppendLine("    (DPAPI machine-scope encrypted) and are available for forensic export.");
            sb.AppendLine("  - Transfer: prefer the .zip + .zip.sha256 pair; record who received the pack.");
            sb.AppendLine();
            sb.AppendLine("Custodian log (fill in by hand as the pack changes hands):");
            sb.AppendLine("  Date/Time UTC | Name | Org | Action (created/copied/filed) | Signature");
            sb.AppendLine("  ------------- | ---- | --- | ----------------------------- | ---------");
            sb.AppendLine($"  {sealedAt:yyyy-MM-dd HH:mm} | Sentinel | local host | created sealed pack | (automatic)");
            sb.AppendLine("  _____________ | ____ | ___ | _____________________________ | _________");
            sb.AppendLine("  _____________ | ____ | ___ | _____________________________ | _________");

            await System.IO.FileNet48.WriteAllTextAsync(
                Path.Combine(reportDir, "chain_of_custody.txt"),
                sb.ToString(), Encoding.UTF8).ConfigureAwait(false);
        }

        private async Task WriteVictimAffidavitAsync(
            string reportDir,
            string reportId,
            DetectionEvent detection,
            LawEnforcementPortals.PortalEntry portal,
            DateTime sealedAt)
        {
            var name = _config.VictimFullName ?? "________________________________";
            var email = _config.VictimEmail ?? "________________________________";
            var phone = _config.VictimPhone ?? "________________________________";
            var address = _config.VictimAddress ?? "________________________________";

            var sb = new StringBuilder();
            sb.AppendLine("VICTIM / COMPLAINANT AFFIDAVIT (TEMPLATE)");
            sb.AppendLine("=========================================");
            sb.AppendLine();
            sb.AppendLine("Complete this form before filing with police / your national cybercrime portal.");
            sb.AppendLine("This is a voluntary statement template - not a court form for every jurisdiction.");
            sb.AppendLine("Sign only if the contents are true to the best of your knowledge.");
            sb.AppendLine();
            sb.AppendLine($"Linked evidence pack:  {reportId}");
            sb.AppendLine($"Detection rule:        {detection.RuleName}");
            sb.AppendLine($"Detection time (UTC):  {detection.Timestamp:yyyy-MM-dd HH:mm:ss}");
            sb.AppendLine($"Pack sealed (UTC):     {sealedAt:yyyy-MM-dd HH:mm:ss}");
            sb.AppendLine($"Recommended portal:    {portal.PrimaryPortalName}");
            sb.AppendLine($"Portal URL:            {portal.PrimaryPortalUrl}");
            sb.AppendLine();
            sb.AppendLine("1. COMPLAINANT IDENTITY");
            sb.AppendLine($"   Full legal name:     {name}");
            sb.AppendLine($"   Email:               {email}");
            sb.AppendLine($"   Phone:               {phone}");
            sb.AppendLine($"   Address:             {address}");
            sb.AppendLine($"   National ID / other: ________________________________");
            sb.AppendLine();
            sb.AppendLine("2. RELATIONSHIP TO THE AFFECTED SYSTEM");
            sb.AppendLine($"   Machine name:        {Environment.MachineName}");
            sb.AppendLine($"   Windows account:     {Environment.UserDomainName}\\{Environment.UserName}");
            sb.AppendLine("   I am the:            [ ] owner  [ ] authorized user  [ ] administrator  [ ] other: ______");
            sb.AppendLine();
            sb.AppendLine("3. STATEMENT OF FACTS (edit as needed)");
            sb.AppendLine("   I state that, on or about the detection time above, the computer system identified");
            sb.AppendLine("   in this pack was the subject of suspected unauthorized access, malware activity,");
            sb.AppendLine("   or computer interference. Sentinel (endpoint security software) automatically");
            sb.AppendLine("   detected the activity, applied a defensive response where authorized, and");
            sb.AppendLine("   generated the accompanying integrity-sealed evidence package.");
            sb.AppendLine();
            sb.AppendLine($"   Observed rule / behaviour: {detection.RuleName}");
            sb.AppendLine($"   Process involved:          {detection.ProcessName} (PID {detection.ProcessId})");
            sb.AppendLine($"   Confidence score:          {detection.Confidence:F2}");
            sb.AppendLine($"   Automated response:        {detection.AuthorizedResponse}");
            sb.AppendLine();
            sb.AppendLine("   Additional narrative (what I noticed, financial loss, data stolen, etc.):");
            sb.AppendLine("   ___________________________________________________________________________");
            sb.AppendLine("   ___________________________________________________________________________");
            sb.AppendLine("   ___________________________________________________________________________");
            sb.AppendLine();
            sb.AppendLine("4. LOSS / HARM (if any)");
            sb.AppendLine("   Estimated financial loss (currency): ________________________________");
            sb.AppendLine("   Data or accounts affected: __________________________________________");
            sb.AppendLine("   Other harm: _________________________________________________________");
            sb.AppendLine();
            if (CoercionAbusePolicy.IsDigitalCoercionToolkit(detection))
            {
                sb.AppendLine("4b. DEVICE / COERCION HARM (optional - complete only if true)");
                sb.AppendLine("   Sentinel only proved technical indicators on this PC. You decide what to report.");
                sb.Append(CoercionAbusePolicy.BuildAffidavitHarmHints());
                sb.AppendLine();
            }
            sb.AppendLine("5. CONSENT");
            sb.AppendLine("   [ ] I wish to file a formal complaint with law enforcement / the portal above.");
            sb.AppendLine("   [ ] I authorize investigators to examine the attached evidence pack and,");
            sb.AppendLine("       where lawfully required, quarantined malware samples from this host.");
            sb.AppendLine("   [ ] I understand false statements to authorities may be a criminal offense.");
            sb.AppendLine();
            sb.AppendLine("6. SIGNATURE");
            sb.AppendLine("   I declare that the information I completed above is true and correct to the");
            sb.AppendLine("   best of my knowledge.");
            sb.AppendLine();
            sb.AppendLine("   Signature: _______________________________    Date: _______________");
            sb.AppendLine("   Printed name: ____________________________    Place: ______________");
            sb.AppendLine();
            sb.AppendLine("Attach: incident_report.txt, indicators.txt, MANIFEST.sha256, chain_of_custody.txt,");
            sb.AppendLine("and the .zip export if filing electronically.");

            await System.IO.FileNet48.WriteAllTextAsync(
                Path.Combine(reportDir, "victim_affidavit.txt"),
                sb.ToString(), Encoding.UTF8).ConfigureAwait(false);
        }

        /// <summary>
        /// B1: builds a minimal <see cref="EvidenceSummary"/> from a sealed pack and mirrors it
        /// off-host via the HMAC-signed ThreatReporting proxy. No file contents or secrets are
        /// sent - only detection metadata, indicators, and the machine-bound manifest hashes as
        /// origin proof. Fail-closed and never-throw (delegates to ThreatReportService).
        /// </summary>
        private async Task MirrorEvidenceOffHostAsync(DetectionEvent detection, string packDir)
        {
            try
            {
                var reportId = Path.GetFileName(packDir.TrimEnd(Path.DirectorySeparatorChar));
                var indicators = ExtractIndicators(detection);

                // Read the sealed manifest hashes from disk (origin proof). Best-effort.
                string manifestSha256 = string.Empty;
                string manifestHmac = string.Empty;
                try
                {
                    var manifestPath = Path.Combine(packDir, "MANIFEST.sha256");
                    var hmacPath = Path.Combine(packDir, "MANIFEST.hmac");
                    if (File.Exists(manifestPath))
                        manifestSha256 = ComputeSha256Hex(File.ReadAllBytes(manifestPath));
                    if (File.Exists(hmacPath))
                        manifestHmac = File.ReadAllText(hmacPath).Trim().ToLowerInvariant();
                }
                catch { /* origin proof is optional; summary still useful */ }

                var summary = new EvidenceSummary
                {
                    ReportId = reportId,
                    SentinelVersion = _productVersion,
                    Host = Environment.MachineName,
                    SealedUtc = DateTime.UtcNow.ToString("O"),
                    Rule = detection.RuleName,
                    SignalType = detection.SignalType.ToString(),
                    Tier = detection.Tier.ToString(),
                    Confidence = detection.Confidence,
                    ProcessName = detection.ProcessName,
                    ProcessId = detection.ProcessId,
                    Hashes = indicators.Hashes.Take(10).ToArray(),
                    Ips = indicators.Ips.Where(ip => !IsPrivateOrLocalIp(ip)).Take(10).ToArray(),
                    Urls = indicators.Urls.Take(10).ToArray(),
                    ManifestSha256 = manifestSha256,
                    ManifestHmacSha256 = manifestHmac
                };

                await _threatReportService.ReportEvidenceAsync(summary).ConfigureAwait(false);
                _logger.LogDebug("[AutoIncidentReporter] Off-host evidence mirror attempted for {ReportId}", reportId);
            }
            catch (Exception ex)
            {
                // Never let off-host mirroring affect local pack behavior.
                _logger.LogDebug(ex, "[AutoIncidentReporter] Off-host evidence mirror failed");
            }
        }

        private async Task SealPackIntegrityAsync(
            string reportDir, string reportId, DetectionEvent detection, DateTime sealedAt)
        {
            // Hash all evidence files except integrity outputs themselves
            var files = Directory.GetFiles(reportDir)
                .Select(f => new FileInfo(f))
                .Where(f => !IntegritySkipFileNames.Contains(f.Name))
                .Where(f => !f.Name.EndsWith(".zip"))
                .OrderBy(f => f.Name, StringComparer.OrdinalIgnoreCase)
                .ToList();

            var manifestLines = new List<string>
            {
                $"# Sentinel evidence MANIFEST.sha256",
                $"# report_id={reportId}",
                $"# sealed_utc={sealedAt:O}",
                $"# host={Environment.MachineName}",
                $"# version={_productVersion}",
                $"# format=sha256  relative_filename"
            };

            var fileHashes = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            foreach (var fi in files)
            {
                var hash = ComputeFileSha256Hex(fi.FullName);
                fileHashes[fi.Name] = hash;
                manifestLines.Add($"{hash}  {fi.Name}");
            }

            var manifestBody = string.Join(Environment.NewLine, manifestLines) + Environment.NewLine;
            var manifestBytes = Encoding.UTF8.GetBytes(manifestBody);
            var manifestPath = Path.Combine(reportDir, "MANIFEST.sha256");
            await System.IO.FileNet48.WriteAllBytesAsync(manifestPath, manifestBytes).ConfigureAwait(false);

            var hmacHex = ComputeManifestHmacHex(manifestBytes);
            await System.IO.FileNet48.WriteAllTextAsync(
                Path.Combine(reportDir, "MANIFEST.hmac"),
                hmacHex + Environment.NewLine,
                Encoding.UTF8).ConfigureAwait(false);

            var json = new
            {
                reportId,
                sealedUtc = sealedAt.ToString("O"),
                host = Environment.MachineName,
                user = $"{Environment.UserDomainName}\\{Environment.UserName}",
                sentinelVersion = _productVersion,
                rule = detection.RuleName,
                confidence = detection.Confidence,
                signalType = detection.SignalType.ToString(),
                processName = detection.ProcessName,
                processId = detection.ProcessId,
                reportableGradeOnly = _config.ReportableGradeOnly,
                minConfidence = _config.MinConfidence,
                files = fileHashes.Select(kv => new { name = kv.Key, sha256 = kv.Value }).ToArray(),
                manifestSha256 = ComputeSha256Hex(manifestBytes),
                manifestHmacSha256 = hmacHex,
                hmacScope = "machine-bound (MachineName + domain + fixed salt); verify on original host"
            };

            await System.IO.FileNet48.WriteAllTextAsync(
                Path.Combine(reportDir, "evidence_manifest.json"),
                JsonSerializer.Serialize(json, new JsonSerializerOptions { WriteIndented = true }),
                Encoding.UTF8).ConfigureAwait(false);

            var verify = new StringBuilder();
            verify.AppendLine("HOW TO VERIFY THIS EVIDENCE PACK");
            verify.AppendLine("================================");
            verify.AppendLine();
            verify.AppendLine("1. On the original machine (preferred), re-run integrity check if available, or:");
            verify.AppendLine("   - For each line in MANIFEST.sha256: sha256sum <file> must match.");
            verify.AppendLine("   - MANIFEST.hmac must match HMAC-SHA256 of MANIFEST.sha256 bytes");
            verify.AppendLine("     using the machine-bound key (see evidence_manifest.json).");
            verify.AppendLine();
            verify.AppendLine("2. If MANIFEST.hmac fails after the pack left this PC, hashes may still be");
            verify.AppendLine("   valid for content integrity; the HMAC proves seal origin on this host.");
            verify.AppendLine();
            verify.AppendLine("3. Do not edit sealed files (incident_report.txt, indicators.txt, network_snapshot.txt).");
            verify.AppendLine("   victim_affidavit.txt and chain_of_custody.txt are intentionally NOT listed");
            verify.AppendLine("   in MANIFEST.sha256 so you can complete/sign them without breaking the seal.");
            verify.AppendLine();
            verify.AppendLine($"Sealed UTC: {sealedAt:O}");
            verify.AppendLine($"Report ID:  {reportId}");
            await System.IO.FileNet48.WriteAllTextAsync(
                Path.Combine(reportDir, "VERIFY.txt"),
                verify.ToString(), Encoding.UTF8).ConfigureAwait(false);
        }

        /// <summary>
        /// Machine-bound HMAC key material - not a public PKI signature, but proves the
        /// manifest was sealed on this host and detects post-seal manifest edits.
        /// </summary>
        internal static byte[] DeriveEvidenceHmacKey()
        {
            var material = Encoding.UTF8.GetBytes(
                $"SentinelEvidenceV1|{Environment.MachineName}|{Environment.UserDomainName}|LE-Pack");
            return System.Security.Cryptography.Sha256Net48.HashData(material);
        }

        internal static string ComputeManifestHmacHex(byte[] manifestBytes)
        {
            using var hmac = new HMACSHA256(DeriveEvidenceHmacKey());
            return ConvertHex.ToHexString(hmac.ComputeHash(manifestBytes)).ToLowerInvariant();
        }

        internal static string ComputeFileSha256Hex(string path)
        {
            using var fs = File.OpenRead(path);
            return ConvertHex.ToHexString(System.Security.Cryptography.Sha256Net48.HashData(fs)).ToLowerInvariant();
        }

        internal static string ComputeSha256Hex(byte[] data) =>
            ConvertHex.ToHexString(System.Security.Cryptography.Sha256Net48.HashData(data)).ToLowerInvariant();

        private async Task<int> SubmitThreatIntelAsync(DetectionEvent detection)
        {
            var indicators = ExtractIndicators(detection);
            var count = 0;
            var comment = $"Sentinel auto-report: {detection.RuleName} (conf={detection.Confidence:F2})";

            foreach (var hash in indicators.Hashes.Take(5))
            {
                await _threatReportService.ReportHashAsync(
                    hash,
                    new[] { "sentinel", "auto", "reportable-grade", detection.SignalType.ToString() },
                    comment).ConfigureAwait(false);
                count++;
            }

            foreach (var url in indicators.Urls.Take(5))
            {
                await _threatReportService.ReportUrlAsync(
                    url,
                    detection.RuleName,
                    new[] { "sentinel", "auto", "reportable-grade" }).ConfigureAwait(false);
                count++;
            }

            foreach (var ip in indicators.Ips.Take(10))
            {
                if (IsPrivateOrLocalIp(ip)) continue;
                await _threatReportService.ReportIpAsync(
                    ip,
                    new[] { 15 },
                    comment).ConfigureAwait(false);
                count++;
            }

            return count;
        }

        internal static IndicatorSet ExtractIndicators(DetectionEvent detection)
        {
            var hashes = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            var ips = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            var urls = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

            void ConsiderKey(string key, string value)
            {
                if (string.IsNullOrWhiteSpace(value)) return;
                var k = key.ToLowerInvariant();

                if (k.Contains("sha256") || k is "hash" or "filehash" or "impostorhash" or "originalhash")
                {
                    foreach (Match m in Sha256Regex.Matches(value))
                        hashes.Add(m.Value.ToLowerInvariant());
                }

                if (k.Contains("url") || k.Contains("uri"))
                {
                    if (value.StartsWith("http://") ||
                        value.StartsWith("https://"))
                        urls.Add(value.Trim());
                }

                if (k.Contains("ip") || k.Contains("address") || k.Contains("remote") || k.Contains("c2"))
                {
                    foreach (Match m in Ipv4Regex.Matches(value))
                        ips.Add(m.Value);
                }
            }

            if (detection.Metadata != null)
            {
                foreach (var kv in detection.Metadata)
                    ConsiderKey(kv.Key, kv.Value);
            }

            foreach (Match m in Sha256Regex.Matches(detection.Evidence ?? ""))
                hashes.Add(m.Value.ToLowerInvariant());
            foreach (Match m in Ipv4Regex.Matches(detection.Evidence ?? ""))
                ips.Add(m.Value);
            foreach (Match m in Ipv4Regex.Matches(detection.Reasoning ?? ""))
                ips.Add(m.Value);

            return new IndicatorSet(hashes, ips, urls);
        }

        private static void AppendProcessSnapshot(StringBuilder report, int pid)
        {
            if (pid <= 4)
            {
                report.AppendLine("  No usable process id on this detection.");
                return;
            }

            try
            {
                using var proc = System.Diagnostics.Process.GetProcessById(pid);
                report.AppendLine($"  PID:          {pid}");
                report.AppendLine($"  Name:         {proc.ProcessName}");
                try { report.AppendLine($"  Start:        {proc.StartTime.ToUniversalTime():yyyy-MM-dd HH:mm:ss} UTC"); }
                catch { report.AppendLine("  Start:        (unavailable)"); }
                try { report.AppendLine($"  Image:        {SecurityValidation.GetProcessImagePath(proc.Id) ?? "unknown"}"); }
                catch { report.AppendLine("  Image:        (access denied / exited)"); }
            }
            catch
            {
                report.AppendLine($"  PID {pid}: process no longer running or access denied.");
            }
        }

        private static List<string> CaptureNetworkSnapshot(int pid)
        {
            var lines = new List<string>();
            try
            {
                var psi = new System.Diagnostics.ProcessStartInfo
                {
                    FileName = "netstat.exe",
                    Arguments = "-ano",
                    RedirectStandardOutput = true,
                    UseShellExecute = false,
                    CreateNoWindow = true
                };
                using var p = System.Diagnostics.Process.Start(psi);
                if (p == null)
                {
                    lines.Add("  (netstat unavailable)");
                    return lines;
                }

                var output = p.StandardOutput.ReadToEnd();
                p.WaitForExit(5000);

                var pidToken = pid > 4 ? pid.ToString() : null;
                var all = output.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries);
                var matched = 0;
                foreach (var line in all)
                {
                    if (pidToken != null && line.TrimEnd().EndsWith(pidToken))
                    {
                        lines.Add("  " + line.Trim());
                        matched++;
                    }
                }

                if (matched == 0)
                {
                    lines.Add(pid > 4
                        ? $"  No netstat rows for PID {pid} at report time (process may have exited)."
                        : "  No offender PID - full snapshot omitted (see process metadata).");
                }

                lines.Add("");
                lines.Add("  Sample ESTABLISHED foreign endpoints (first 20):");
                var sample = 0;
                foreach (var line in all)
                {
                    if (line.Contains("ESTABLISHED"))
                    {
                        lines.Add("  " + line.Trim());
                        if (++sample >= 20) break;
                    }
                }
            }
            catch (Exception ex)
            {
                lines.Add($"  Network capture failed: {ex.Message}");
            }

            return lines;
        }

        private static bool IsPrivateOrLocalIp(string ip)
        {
            if (!IPAddress.TryParse(ip, out var addr)) return true;
            if (IPAddress.IsLoopback(addr)) return true;
            var bytes = addr.GetAddressBytes();
            if (bytes.Length != 4) return true;
            if (bytes[0] == 10) return true;
            if (bytes[0] == 127) return true;
            if (bytes[0] == 192 && bytes[1] == 168) return true;
            if (bytes[0] == 172 && bytes[1] >= 16 && bytes[1] <= 31) return true;
            if (bytes[0] == 169 && bytes[1] == 254) return true;
            return false;
        }

        private static string SanitizeFileToken(string value, int maxLen)
        {
            var sb = new StringBuilder(Math.Min(value.Length, maxLen));
            foreach (var ch in value)
            {
                if (char.IsLetterOrDigit(ch) || ch is '_' or '-')
                    sb.Append(ch);
                else if (ch is ' ' or '.' or ':' or '/')
                    sb.Append('_');
                if (sb.Length >= maxLen) break;
            }
            return sb.Length == 0 ? "detection" : sb.ToString();
        }

        private static string WrapIndented(string? text, string indent)
        {
            if (string.IsNullOrWhiteSpace(text)) return indent + "(none)";
            var lines = text!.Replace("\r\n", "\n").Split('\n');
            return string.Join(Environment.NewLine, lines.Select(l => indent + l));
        }

        internal readonly record struct IndicatorSet(
            HashSet<string> Hashes,
            HashSet<string> Ips,
            HashSet<string> Urls);

        public readonly record struct EvidenceIntegrityResult(bool Ok, string Message);
    }
}
