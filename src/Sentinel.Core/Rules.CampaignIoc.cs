using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;

namespace Sentinel.Core
{
    [RuleCategory(DetectionCategory.CampaignIoC)]
    public class CampaignIocRule : IDetectionRule
    {
        public string Name => "CampaignIocRule";

        // Known malicious filename patterns from tracked campaigns
        private static readonly string[] MaliciousFilenames = new[]
        {
            "svchosts.exe", "svchost.exe.exe", "csrss.exe.exe",
            "lsass.exe.exe", "explorer.exe.exe",
            "windowsupdate.exe", "windowsdefender.exe",
            "chrome_update.exe", "firefox_update.exe",
            "system32.exe", "kernel32.exe",
            // Lazarus Operation Dream Job (Aug 2026) - distinctive names only
            "securitypdf.exe", "afd4eop12_x64.dll",
        };

        // Known C2 domain substrings
        private static readonly string[] MaliciousDomainPatterns = new[]
        {
            "pastebin.com/raw", "hastebin.com/raw",
            "discord.com/api/webhooks", "discordapp.com/api/webhooks",
            "api.telegram.org/bot", "hooks.slack.com",
            "telegram-bot", "webhook.site", "interact.sh",
            "requestbin.com", "canarytokens.com",
            ".onion.", ".tor2web.",
            "envell.xyz", "enveil.online", "uxtramine.org",
        };

        public DetectionEvent? Evaluate(FusedTelemetryContext context)
        {
            if (context.TriggeringEvent is ProcessTelemetry pt)
            {
                var filename = Path.GetFileName(pt.ImagePath).ToLowerInvariant();

                foreach (var mal in MaliciousFilenames)
                {
                    if (filename.Equals(mal))
                    {
                        return new DetectionEvent
                        {
                            RuleName = Name,
                            ProcessName = pt.ProcessName,
                            ProcessId = pt.ProcessId,
                            SignalType = SignalType.SuspiciousProcess,
                            Confidence = 0.80,
                            Tier = DetectionTier.Tier2Indicator,
                            Evidence = $"Known malicious filename executed: {pt.ImagePath}",
                            Reasoning = $"Process filename '{filename}' matches a known IoC from tracked malware campaigns."
                        };
                    }
                }

                var cmd = (pt.CommandLine ?? "").ToLowerInvariant();
                foreach (var domain in MaliciousDomainPatterns)
                {
                    if (cmd.Contains(domain))
                    {
                        return new DetectionEvent
                        {
                            RuleName = Name,
                            ProcessName = pt.ProcessName,
                            ProcessId = pt.ProcessId,
                            SignalType = SignalType.NetworkC2,
                            Family = TerminalFamily.C2Beacon,
                            Confidence = 0.85,
                            Tier = DetectionTier.Tier1Behavioral,
                            AuthorizedResponse = ResponseAction.KillProcessTree,
                            Evidence = $"Known malicious C2 domain in command line: {domain}",
                            Reasoning = $"Command line contains a known C2 exfiltration endpoint ({domain}), indicating active malware communication."
                        };
                    }
                }
            }
            return null;
        }
    }

}
