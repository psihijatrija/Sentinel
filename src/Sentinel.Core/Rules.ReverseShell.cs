using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;

namespace Sentinel.Core
{
    [RuleCategory(DetectionCategory.ReverseShell)]
    public class ReverseShellRule : IDetectionRule
    {
        public string Name => "ReverseShellRule";

        private static readonly string[] EscalationIndicators = new[]
        {
            "-nop", "-w hidden", "-windowstyle hidden", "-sta", "-noni",
            "net.webclient", "downloadstring", "invoke-expression", "iex",
            "net.sockets", "tcpclient", "system.net"
        };

        public DetectionEvent? Evaluate(FusedTelemetryContext context)
        {
            if (context.TriggeringEvent is ProcessTelemetry pt)
            {
                var cmd = (pt.CommandLine ?? "").ToLowerInvariant();
                if (pt.ProcessName.Contains("powershell") && 
                    (cmd.Contains("-enc") || 
                     cmd.Contains("-encodedcommand")))
                {
                    // Check for escalation indicators that suggest malicious use
                    bool hasEscalationIndicator = EscalationIndicators.Any(
                        indicator => cmd.Contains(indicator));

                    if (hasEscalationIndicator)
                    {
                        // Combined with evasion flags or network indicators -> Tier1 + Kill
                        return new DetectionEvent
                        {
                            RuleName = Name,
                            ProcessName = pt.ProcessName,
                            ProcessId = pt.ProcessId,
                            SignalType = SignalType.ReverseShell,
                            Family = TerminalFamily.ReverseShell,
                            Confidence = 0.85,
                            Tier = DetectionTier.Tier1Behavioral,
                            AuthorizedResponse = ResponseAction.KillProcessTree,
                            Evidence = $"Encoded PowerShell with evasion/network indicators: {cmd}",
                            Reasoning = "Process launched an obfuscated PowerShell session combined with evasion flags or network indicators, commonly used to execute downloader cradles or C2 shell callbacks."
                        };
                    }
                    else
                    {
                        // Encoded command alone -> Tier2 (log only, no kill)
                        return new DetectionEvent
                        {
                            RuleName = Name,
                            ProcessName = pt.ProcessName,
                            ProcessId = pt.ProcessId,
                            SignalType = SignalType.ReverseShell,
                            Confidence = 0.50,
                            Tier = DetectionTier.Tier2Indicator,
                            AuthorizedResponse = ResponseAction.LogOnly,
                            Evidence = $"Encoded PowerShell execution (no evasion indicators): {cmd}",
                            Reasoning = "Process launched PowerShell with an encoded command. Without additional evasion or network indicators this may be legitimate automation. Logged for correlation."
                        };
                    }
                }
            }
            return null;
        }
    }


    [RuleCategory(DetectionCategory.ReverseShell)]
    public class ClickFixDetectionRule : IDetectionRule
    {
        public string Name => "ClickFixDetectionRule";

        public DetectionEvent? Evaluate(FusedTelemetryContext context)
        {
            if (context.TriggeringEvent is not ProcessTelemetry pt)
                return null;

            var cmd = pt.CommandLine?.ToLowerInvariant() ?? "";
            var parent = pt.ParentProcessName?.ToLowerInvariant() ?? "";
            var name = pt.ProcessName ?? "";

            // Win+R / browser-driven spawn, or shell-out from conhost (Run dialog intermediate)
            bool isExplorerOrBrowserParent =
                parent is "explorer" or "explorer.exe" or
                    "chrome" or "chrome.exe" or
                    "msedge" or "msedge.exe" or
                    "firefox" or "firefox.exe" or
                    "brave" or "brave.exe" or
                    "opera" or "opera.exe" or
                    "vivaldi" or "vivaldi.exe" or
                    "conhost" or "conhost.exe" or
                    "runtimebroker" or "runtimebroker.exe";

            bool isSuspiciousShell =
                name.Contains("powershell") ||
                name.Contains("pwsh") ||
                name.Contains("cmd") ||
                name.Contains("mshta") ||
                name.Contains("wscript") ||
                name.Contains("cscript") ||
                name.Contains("msdt") ||
                name.Contains("forfiles");

            if (!isExplorerOrBrowserParent || !isSuspiciousShell)
                return null;

            // v1.6.1: Expanded payload signatures from 2025-26 ClickFix campaigns
            bool isClickFixPayload =
                cmd.Contains("frombase64string") ||
                cmd.Contains("downloadstring") ||
                cmd.Contains("downloadfile") ||
                cmd.Contains("downloaddata") ||
                cmd.Contains("iex ") ||
                cmd.Contains("|iex") ||
                cmd.Contains("iex(") ||
                cmd.Contains("invoke-expression") ||
                cmd.Contains("invoke-webrequest") ||
                cmd.Contains("invoke-restmethod") ||
                cmd.Contains(" iwr ") ||
                cmd.Contains(" irm ") ||
                cmd.Contains("| iwr") ||
                cmd.Contains("| irm") ||
                cmd.Contains("certutil -urlcache") ||
                cmd.Contains("certutil.exe -urlcache") ||
                cmd.Contains("bitsadmin") ||
                cmd.Contains("start-bitstransfer") ||
                cmd.Contains("curl ") && (cmd.Contains("http") || cmd.Contains("|")) ||
                cmd.Contains("wget ") && cmd.Contains("http") ||
                cmd.Contains("-enc ") ||
                cmd.Contains("-encodedcommand") ||
                cmd.Contains("-e ") && cmd.Contains("powershell") ||
                cmd.Contains("-w h") || cmd.Contains("-w hidden") || cmd.Contains("windowstyle hidden") ||
                cmd.Contains("-nop") && (cmd.Contains("http") || cmd.Contains("iex") || cmd.Contains("irm")) ||
                cmd.Contains("mshta") && cmd.Contains("http") ||
                (cmd.Contains("http") && name.Contains("mshta")) ||
                cmd.Contains("javascript:") ||
                cmd.Contains("vbscript:") ||
                // Fake CAPTCHA clipboard often starts with verification noise then command
                cmd.Contains("verification") && (cmd.Contains("powershell") || cmd.Contains("http")) ||
                cmd.Contains("captcha") && cmd.Contains("http");

            if (!isClickFixPayload)
                return null;

            return new DetectionEvent
            {
                RuleName = Name,
                ProcessName = pt.ProcessName ?? "",
                ProcessId = pt.ProcessId,
                SignalType = SignalType.ReverseShell,
                Family = TerminalFamily.ReverseShell,
                Confidence = 0.96,
                Tier = DetectionTier.Tier1Behavioral,
                AuthorizedResponse = ResponseAction.KillProcessTree,
                Evidence = $"ClickFix / FakeCAPTCHA paste-run detected (parent={pt.ParentProcessName}): {pt.CommandLine}",
                Reasoning =
                    "Shell spawned from explorer/browser (Win+R or paste-run) with download/encode/hidden-window " +
                    "patterns matching ClickFix and FakeCAPTCHA campaigns (Microsoft 2025, ESET +500% H1 2025). " +
                    "Victims are socially engineered to paste attacker-controlled PowerShell/cmd themselves."
            };
        }
    }

    /// <summary>
    /// v1.6.1: Detects compromised npm/node lifecycle scripts that shell out to downloaders.
    /// Inspired by 2025 supply-chain waves (Shai-Hulud / Tinycolor / Crowdstrike npm packages on HN).
    /// </summary>
}
