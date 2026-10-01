using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.RegularExpressions;
using Microsoft.Extensions.Logging;

namespace Sentinel.Core
{
    /// <summary>
    /// Detects indicators associated with known malware campaigns/families.
    /// Uses exact filename matching (v3.8.0 fix) to prevent false positives
    /// from legitimate software whose names end with campaign indicators.
    /// </summary>
    [RuleCategory(DetectionCategory.CampaignIoC)]
    public sealed class CampaignDetectionRule : IDetectionRule
    {
        public string Name => "Campaign IOC Detection";

        private readonly ILogger<CampaignDetectionRule> _logger;

        private static readonly Dictionary<string, CampaignIndicators> CampaignDatabase = new()
        {
            ["CobaltStrike"] = new CampaignIndicators
            {
                CampaignName = "Cobalt Strike",
                Description = "Cobalt Strike beacon and post-exploitation",
                FileNames = new[] { "beacon.exe", "artifact.exe", "pipeclient.exe" },
                ProcessPatterns = new[] { "beacon", "artifact" },
                CommandLinePatterns = new[] { @"-http-get|-http-post|-dns", @"pipeclient" },
                NamedPipePatterns = new[] { @"\\\\.\\pipe\\[ms]{1}[a-z]{4,8}[0-9]{1,4}" },
                MitreTechniques = new[] { "T1071", "T1055", "T1059", "T1021" }
            },
            ["QBot"] = new CampaignIndicators
            {
                CampaignName = "QBot/QakBot",
                Description = "QBot banking trojan",
                // v3.8.0: Removed "regsvr32.exe" and "services.exe" - legitimate system binaries
                FileNames = new[] { "chkdsks.exe", "disk.exe", "taskhost.exe" },
                ProcessPatterns = new[] { "chkdsks", "disk" },
                CommandLinePatterns = new[] { @"regsvr32.*-s.*[a-z0-9]{8}\.dat" },
                RegistryKeys = new[] { @"Software\\Microsoft\\Windows\\CurrentVersion\\Run\\[a-z]{8}" },
                ScheduledTaskPatterns = new[] { @"[a-z]{8}_[0-9]{6}" },
                MitreTechniques = new[] { "T1053", "T1055", "T1059", "T1547" }
            },
            ["Emotet"] = new CampaignIndicators
            {
                CampaignName = "Emotet",
                Description = "Emotet malware",
                // v3.8.0: Removed generic "update.exe" - false positives
                FileNames = new[] { "sys.exe", "win.exe", "syswow.exe" },
                ProcessPatterns = new[] { "sys", "syswow" },
                CommandLinePatterns = new[] { @"-E\d+" },
                ServicePatterns = new[] { @"RemoteRegistry[0-9a-f]{4}" },
                MitreTechniques = new[] { "T1055", "T1059", "T1543", "T1547" }
            },
            ["TrickBot"] = new CampaignIndicators
            {
                CampaignName = "TrickBot",
                Description = "TrickBot banking trojan",
                // v3.8.0: Removed "services.exe" and "client.exe" - too generic
                FileNames = new[] { "tab.exe", "inject.exe" },
                ProcessPatterns = new[] { "tab", "inject" },
                CommandLinePatterns = new[] { @"tab.exe.*-s", @"tab.exe.*-i" },
                ModulePatterns = new[] { @"[a-z]{8}64.dll", @"[a-z]{8}32.dll" },
                MitreTechniques = new[] { "T1003", "T1055", "T1056", "T1071" }
            },
            ["LazarusDreamJob"] = new CampaignIndicators
            {
                CampaignName = "Lazarus Operation Dream Job",
                Description = "DPRK Lazarus Dream Job: trojanized PDF viewer / FudModule CVE-2026-68820 loader (does not patch afd.sys)",
                FileNames = new[]
                {
                    "SecurityPDF.exe", "SecurityPDF",
                    "Afd4Eop12_x64.dll", "Afd4Eop12_x64",
                    "OneScreenCapture64.dll", "OneScreenCapture64",
                },
                ProcessPatterns = new[] { "SecurityPDF", "Afd4Eop12" },
                CommandLinePatterns = new[]
                {
                    @"envell\.xyz", @"enveil\.online", @"uxtramine\.org",
                    @"enable_god_mode", @"Afd4Eop12",
                    @"135\.181\.67\.203", @"135\.181\.185\.158",
                },
                MitreTechniques = new[] { "T1204.002", "T1574.002", "T1068", "T1071", "T1055" }
            }
        };

        public CampaignDetectionRule(ILogger<CampaignDetectionRule> logger)
        {
            _logger = logger;
        }

        public DetectionEvent? Evaluate(FusedTelemetryContext context)
        {
            if (context.TriggeringEvent is not ProcessTelemetry proc) return null;

            foreach (var campaign in CampaignDatabase)
            {
                var indicators = campaign.Value;
                var confidence = 0.0;
                var matches = new List<string>();

                // Check file name - v3.8.0: exact filename match (Path.GetFileName)
                var imageFileName = !string.IsNullOrEmpty(proc.ImagePath)
                    ? Path.GetFileName(proc.ImagePath)
                    : null;
                if (indicators.FileNames.Any(f =>
                    proc.ProcessName.Equals(f) ||
                    (imageFileName != null && imageFileName.Equals(f))))
                {
                    confidence += 0.4;
                    matches.Add($"File name matches {campaign.Key}");
                }

                // Check process name pattern
                if (indicators.ProcessPatterns.Any(p =>
                    proc.ProcessName.Contains(p)))
                {
                    confidence += 0.3;
                    matches.Add($"Process name pattern matches {campaign.Key}");
                }

                // Check command line patterns
                if (!string.IsNullOrEmpty(proc.CommandLine))
                {
                    foreach (var pattern in indicators.CommandLinePatterns)
                    {
                        if (Regex.IsMatch(proc.CommandLine, pattern))
                        {
                            confidence += 0.3;
                            matches.Add($"Command line matches {campaign.Key}");
                            break;
                        }
                    }
                }

                if (confidence >= 0.5)
                {
                    var evidence = $"Campaign IOC match: {campaign.Key}. {indicators.Description}. " +
                                   $"Indicators: {string.Join("; ", matches)}. " +
                                   $"MITRE ATT&CK: {string.Join(", ", indicators.MitreTechniques)}";

                    _logger.LogCritical(
                        "CampaignDetection: {Campaign} indicators for {Process} (PID {Pid})",
                        campaign.Key, proc.ProcessName, proc.ProcessId);

                    return new DetectionEvent
                    {
                        RuleName = $"Campaign: {indicators.CampaignName}",
                        Evidence = evidence,
                        Reasoning = $"Detected indicators associated with the {campaign.Key} campaign/malware family",
                        Confidence = Math.Min(0.95, confidence),
                        Tier = DetectionTier.Tier1Behavioral,
                        AuthorizedResponse = ResponseAction.KillProcessTree,
                        ProcessName = proc.ProcessName,
                        ProcessId = proc.ProcessId,
                        Metadata = new Dictionary<string, string>
                        {
                            ["campaign"] = campaign.Key,
                            ["mitre_techniques"] = string.Join(",", indicators.MitreTechniques),
                            ["indicators_matched"] = string.Join(";", matches)
                        }
                    };
                }
            }

            return null;
        }

        private sealed class CampaignIndicators
        {
            public string CampaignName { get; set; } = "";
            public string Description { get; set; } = "";
            public string[] FileNames { get; set; } = Array.Empty<string>();
            public string[] ProcessPatterns { get; set; } = Array.Empty<string>();
            public string[] CommandLinePatterns { get; set; } = Array.Empty<string>();
            public string[] RegistryKeys { get; set; } = Array.Empty<string>();
            public string[] NamedPipePatterns { get; set; } = Array.Empty<string>();
            public string[] ScheduledTaskPatterns { get; set; } = Array.Empty<string>();
            public string[] ServicePatterns { get; set; } = Array.Empty<string>();
            public string[] ModulePatterns { get; set; } = Array.Empty<string>();
            public string[] MitreTechniques { get; set; } = Array.Empty<string>();
        }
    }
}
