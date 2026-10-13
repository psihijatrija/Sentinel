using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.Diagnostics.Eventing.Reader;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;

namespace Sentinel.Core
{
    /// <summary>
    /// Detects LSASS credential dumping attempts via Windows event log monitoring.
    ///
    /// Detection sources:
    ///   1. Sysmon Event ID 10 (ProcessAccess) targeting lsass.exe with GrantedAccess
    ///      containing PROCESS_VM_READ (0x0010) from non-trusted processes.
    ///   2. Windows Security Event ID 4656/4663 (Handle to object requested/accessed)
    ///      targeting \Device\... lsass with read permissions.
    ///   3. Defender Event ID 1121 (ASR rule triggered) for LSASS credential theft.
    ///
    /// Why not NtQuerySystemInformation + DuplicateHandle?
    ///   That approach (enumerating all system handles) uses the exact same API pattern
    ///   as Mimikatz and gets flagged by every AV engine. Event log monitoring achieves
    ///   the same detection without looking like a credential dumper itself.
    ///
    /// Trust model: processes accessing LSASS are trusted ONLY by verified path
    /// (System32, Defender platform folder). Never by name alone.
    /// </summary>
    public sealed class LsassDumpCanaryMonitor : IDisposable
    {
        private readonly DetectionEngine _detectionEngine;
        private readonly SignerTrustService? _signerTrust;
        private readonly ILogger<LsassDumpCanaryMonitor> _logger;
        private readonly System.Threading.Timer _timer;
        private readonly ConcurrentDictionary<string, DateTimeOffset> _alertedProcesses = new();

        // Dynamically resolved system paths where legitimate LSASS accessors live
        private static readonly string[] SystemLsassAccessorPaths = new[]
        {
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "System32") + @"\",
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "SysWOW64") + @"\",
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), @"Microsoft\Windows Defender\Platform") + @"\",
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "Windows Defender") + @"\",
        };

        private static readonly TimeSpan ScanInterval = TimeSpan.FromSeconds(30);
        private static readonly TimeSpan AlertCooldown = TimeSpan.FromMinutes(5);
        private DateTime _lastQueryTime = DateTime.UtcNow.AddMinutes(-1);

        public LsassDumpCanaryMonitor(
            DetectionEngine detectionEngine,
            ILogger<LsassDumpCanaryMonitor> logger,
            SignerTrustService? signerTrust = null)
        {
            _detectionEngine = detectionEngine;
            _logger = logger;
            _signerTrust = signerTrust;
            _timer = new System.Threading.Timer(CheckLsassAccess, null, ScanInterval, ScanInterval);
        }

        private void CheckLsassAccess(object? state)
        {
            try
            {
                CheckSysmonProcessAccess();
                CheckDefenderAsrEvents();
                PruneAlertHistory();
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "[LsassDumpCanaryMonitor] Check error");
            }
        }

        /// <summary>
        /// Sysmon Event ID 10: ProcessAccess
        /// Fires when a process opens a handle to another process.
        /// We look for accesses to lsass.exe with read permissions from untrusted paths.
        /// </summary>
        private void CheckSysmonProcessAccess()
        {
            try
            {
                // Query Sysmon operational log for Event ID 10 (ProcessAccess) targeting lsass
                var queryTime = _lastQueryTime;
                _lastQueryTime = DateTime.UtcNow;

                var query = new EventLogQuery(
                    "Microsoft-Windows-Sysmon/Operational",
                    PathType.LogName,
                    $"*[System[EventID=10 and TimeCreated[timediff(@SystemTime) <= 35000]]]");

                using var reader = new EventLogReader(query);
                EventRecord? record;
                while ((record = reader.ReadEvent()) != null)
                {
                    using (record)
                    {
                        if (record.TimeCreated <= queryTime) continue;

                        var xml = record.ToXml();
                        if (!xml.Contains("lsass.exe")) continue;

                        // Extract source process info
                        var sourceImage = ExtractXmlField(xml, "SourceImage");
                        var targetImage = ExtractXmlField(xml, "TargetImage");
                        var grantedAccess = ExtractXmlField(xml, "GrantedAccess");
                        var sourceProcessId = ExtractXmlField(xml, "SourceProcessId");

                        if (string.IsNullOrEmpty(sourceImage)) continue;
                        if (!targetImage?.Contains("lsass.exe") == true) continue;

                        // Check if granted access includes PROCESS_VM_READ (0x10)
                        if (!string.IsNullOrEmpty(grantedAccess))
                        {
                            if (uint.TryParse(grantedAccess!.Replace("0x", ""),
                                System.Globalization.NumberStyles.HexNumber, null, out var access))
                            {
                                if ((access & 0x0010) == 0) continue; // No VM_READ - not a dump attempt
                            }
                        }

                        // Verify trust by path
                        if (IsTrustedPath(sourceImage)) continue;

                        // Dedup by source process
                        var dedupKey = $"{sourceImage}:{sourceProcessId}";
                        if (_alertedProcesses.TryGetValue(dedupKey, out var lastAlert) &&
                            DateTimeOffset.UtcNow - lastAlert < AlertCooldown)
                            continue;
                        _alertedProcesses[dedupKey] = DateTimeOffset.UtcNow;

                        int.TryParse(sourceProcessId, out int pid);
                        var processName = Path.GetFileNameWithoutExtension(sourceImage);

                        _ = _detectionEngine.EmitAsync(new DetectionEvent
                        {
                            RuleName = "Credential Theft: LSASS Process Access",
                            Evidence = $"Process '{processName}' (PID {pid}, path: '{sourceImage}') opened a handle to LSASS with access 0x{grantedAccess}",
                            Reasoning = "An untrusted process opened a handle to LSASS with memory read permissions. This is the primary technique for credential dumping (T1003.001). Trust is verified by path - only System32 and Defender binaries are exempted.",
                            Confidence = 0.92,
                            Tier = DetectionTier.Tier1Behavioral,
                            AuthorizedResponse = ResponseAction.KillProcessTree,
                            ProcessName = processName,
                            ProcessId = pid,
                            SignalType = SignalType.LsassAccess,
                            // v2.6: declare the terminal family typed, so classification is
                            // robust to any future rule-name or SignalType change.
                            Family = TerminalFamily.CredentialDump,
                            Metadata = new Dictionary<string, string>
                            {
                                ["SourceImage"] = sourceImage!,
                                ["GrantedAccess"] = grantedAccess ?? "unknown"
                            }
                        });
                    }
                }
            }
            catch (EventLogNotFoundException)
            {
                // Sysmon not installed - fall back to Security event log
                CheckSecurityAuditEvents();
            }
            catch (UnauthorizedAccessException)
            {
                _logger.LogDebug("[LsassDumpCanaryMonitor] Access denied to Sysmon log, trying Security log");
                CheckSecurityAuditEvents();
            }
            catch { }
        }

        /// <summary>
        /// Security Event ID 4656: A handle to an object was requested.
        /// Requires "Audit Handle Manipulation" policy to be enabled.
        /// Fallback when Sysmon is not installed.
        /// </summary>
        private void CheckSecurityAuditEvents()
        {
            try
            {
                var query = new EventLogQuery(
                    "Security",
                    PathType.LogName,
                    "*[System[EventID=4656 and TimeCreated[timediff(@SystemTime) <= 35000]]]");

                using var reader = new EventLogReader(query);
                EventRecord? record;
                while ((record = reader.ReadEvent()) != null)
                {
                    using (record)
                    {
                        var xml = record.ToXml();
                        if (!xml.Contains("lsass")) continue;

                        var processName = ExtractXmlField(xml, "ProcessName") ?? "";
                        if (IsTrustedPath(processName)) continue;

                        var subjectPid = ExtractXmlField(xml, "ProcessId");
                        int.TryParse(subjectPid, out int pid);
                        var shortName = Path.GetFileNameWithoutExtension(processName);

                        var dedupKey = $"sec:{processName}";
                        if (_alertedProcesses.TryGetValue(dedupKey, out var lastAlert) &&
                            DateTimeOffset.UtcNow - lastAlert < AlertCooldown)
                            continue;
                        _alertedProcesses[dedupKey] = DateTimeOffset.UtcNow;

                        _ = _detectionEngine.EmitAsync(new DetectionEvent
                        {
                            RuleName = "Credential Theft: LSASS Handle Requested (Audit)",
                            Evidence = $"Process '{shortName}' (PID {pid}, path: '{processName}') requested handle to LSASS",
                            Reasoning = "Windows Security audit detected an untrusted process requesting a handle to the LSASS process. This is a credential dumping indicator.",
                            Confidence = 0.85,
                            Tier = DetectionTier.Tier1Behavioral,
                            AuthorizedResponse = ResponseAction.KillProcessTree,
                            ProcessName = shortName,
                            ProcessId = pid,
                            SignalType = SignalType.LsassAccess,
                            Family = TerminalFamily.CredentialDump
                        });
                    }
                }
            }
            catch { }
        }

        /// <summary>
        /// Defender ASR Event ID 1121: Attack Surface Reduction rule triggered.
        /// If Defender's "Block credential stealing from lsass" ASR rule fires,
        /// we get a free detection even if our other methods miss it.
        /// </summary>
        private void CheckDefenderAsrEvents()
        {
            try
            {
                var query = new EventLogQuery(
                    "Microsoft-Windows-Windows Defender/Operational",
                    PathType.LogName,
                    "*[System[EventID=1121 and TimeCreated[timediff(@SystemTime) <= 35000]]]");

                using var reader = new EventLogReader(query);
                EventRecord? record;
                while ((record = reader.ReadEvent()) != null)
                {
                    using (record)
                    {
                        var xml = record.ToXml();
                        // ASR rule GUID for credential theft: 9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2
                        if (!xml.Contains("9e6c4e1f")) continue;

                        var processPath = ExtractXmlField(xml, "Path") ?? "unknown";
                        var shortName = Path.GetFileNameWithoutExtension(processPath);

                        var dedupKey = $"asr:{processPath}";
                        if (_alertedProcesses.ContainsKey(dedupKey)) continue;
                        _alertedProcesses[dedupKey] = DateTimeOffset.UtcNow;

                        _ = _detectionEngine.EmitAsync(new DetectionEvent
                        {
                            RuleName = "Credential Theft: Defender ASR LSASS Block",
                            Evidence = $"Windows Defender ASR blocked credential theft attempt by '{shortName}' (path: '{processPath}')",
                            Reasoning = "Windows Defender's Attack Surface Reduction rule for LSASS credential theft was triggered. This confirms an active credential dumping attempt was blocked by Defender, and Sentinel independently corroborates the threat.",
                            Confidence = 0.95,
                            Tier = DetectionTier.Tier1Behavioral,
                            AuthorizedResponse = ResponseAction.KillProcessTree,
                            ProcessName = shortName,
                            ProcessId = 0,
                            SignalType = SignalType.LsassAccess,
                            Family = TerminalFamily.CredentialDump
                        });
                    }
                }
            }
            catch { }
        }

        private bool IsTrustedPath(string? path)
        {
            if (string.IsNullOrEmpty(path)) return false;

            // Canonicalize before comparing. The raw string comes from event-log XML, so a
            // case-sensitive StartsWith on it is bypassable: "C:\Windows\System32Malware\x.exe"
            // starts with the "C:\Windows\System32\" prefix only by accident of separators, and
            // 8.3 / \\?\ / mixed-case / trailing-dot variants dodge a naive prefix match. Resolve
            // to a full path and compare on directory boundaries.
            string full;
            try
            {
                var raw = path!.Trim().Trim('"');
                if (raw.StartsWith(@"\\?\", StringComparison.Ordinal)) raw = raw.Substring(4);
                if (raw.StartsWith(@"\??\", StringComparison.Ordinal)) raw = raw.Substring(4);
                full = Path.GetFullPath(raw);
            }
            catch { return false; } // unparseable path -> not trusted (fail closed)

            string normalized = full.TrimEnd('\\').ToLowerInvariant() + @"\";
            bool inSystemFolder = SystemLsassAccessorPaths.Any(t =>
            {
                var root = t.ToLowerInvariant();
                // Directory-boundary match: the path must be the folder itself or sit UNDER it,
                // so "system32malware\" cannot match the "system32\" root.
                return normalized.StartsWith(root, StringComparison.Ordinal);
            });
            if (!inSystemFolder) return false;

            // A trusted system path is NOT enough on its own - an attacker who can drop into a
            // system folder (or trick the event log path) must still fail the signature gate.
            // Fail closed: unsigned, unverifiable, or no-signer-service all mean NOT trusted, so
            // the 0.92-confidence LSASS-access kill is never suppressed on path alone.
            if (_signerTrust != null)
                return _signerTrust.IsSignedFile(full);
            return SecurityValidation.VerifyAuthenticodeSignature(full, _logger);
        }

        private static string? ExtractXmlField(string xml, string fieldName)
        {
            // Simple extraction: look for Name="fieldName">value<
            var marker = $"Name=\"{fieldName}\">";
            var idx = xml.IndexOf(marker);
            if (idx < 0) return null;
            idx += marker.Length;
            var endIdx = xml.IndexOf('<', idx);
            if (endIdx < 0) return null;
            return xml[idx..endIdx];
        }

        private void PruneAlertHistory()
        {
            var cutoff = DateTimeOffset.UtcNow - AlertCooldown - AlertCooldown;
            foreach (var key in _alertedProcesses.Keys.ToArray())
            {
                if (_alertedProcesses.TryGetValue(key, out var time) && time < cutoff)
                    _alertedProcesses.TryRemove(key, out _);
            }
        }

        public void Dispose()
        {
            _timer.Dispose();
        }
    }
}
