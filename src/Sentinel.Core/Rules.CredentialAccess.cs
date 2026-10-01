using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;

namespace Sentinel.Core
{
    [RuleCategory(DetectionCategory.CredentialDump)]
    public class LsassAccessRule : IDetectionRule
    {
        public string Name => "LsassAccessRule";

        public DetectionEvent? Evaluate(FusedTelemetryContext context)
        {
            if (context.TriggeringEvent is ProcessTelemetry pt)
            {
                var cmd = (pt.CommandLine ?? "").ToLowerInvariant();
                if (cmd.Contains("lsass") && 
                    (cmd.Contains("dumptool") || 
                     cmd.Contains("minidump") || 
                     cmd.Contains("procdump")))
                {
                    return new DetectionEvent
                    {
                        RuleName = Name,
                        ProcessName = pt.ProcessName,
                        ProcessId = pt.ProcessId,
                        SignalType = SignalType.LsassAccess,
                        Family = TerminalFamily.CredentialDump,
                        Confidence = 0.90,
                        Tier = DetectionTier.Tier1Behavioral,
                        AuthorizedResponse = ResponseAction.KillProcessTree,
                        Evidence = $"LSASS dumping command pattern: {cmd}",
                        Reasoning = "Process invoked utility targeting the Local Security Authority Subsystem Service (LSASS) memory space."
                    };
                }
            }
            return null;
        }
    }


    [RuleCategory(DetectionCategory.CredentialDump)]
    public class ChromeRemoteDebuggingRule : IDetectionRule
    {
        public string Name => "ChromeRemoteDebuggingRule";

        private static readonly HashSet<string> BrowserProcesses = new(StringComparer.OrdinalIgnoreCase)
        {
            "chrome", "msedge", "brave", "vivaldi", "opera", "chromium"
        };

        public DetectionEvent? Evaluate(FusedTelemetryContext context)
        {
            if (context.TriggeringEvent is ProcessTelemetry pt)
            {
                // Detect browser launched with --remote-debugging-port which enables
                // full session/cookie access via Chrome DevTools Protocol (CDP)
                var procName = Sentinel.Core.StringNet48.ReplaceIgnoreCase(pt.ProcessName, ".exe", "");
                if (!BrowserProcesses.Contains(procName)) return null;

                var cmd = (pt.CommandLine ?? "").ToLowerInvariant();
                if (cmd.Contains("--remote-debugging-port"))
                {
                    // Check who launched it - if parent is a known browser (self-spawn), skip
                    if (!string.IsNullOrEmpty(pt.ParentProcessName))
                    {
                        var parentName = Sentinel.Core.StringNet48.ReplaceIgnoreCase(pt.ParentProcessName, ".exe", "");
                        if (BrowserProcesses.Contains(parentName))
                            return null; // Browser spawning its own subprocess with debug port - normal
                    }

                    return new DetectionEvent
                    {
                        RuleName = Name,
                        ProcessName = pt.ProcessName,
                        ProcessId = pt.ProcessId,
                        SignalType = SignalType.CredentialTheft,
                        Family = TerminalFamily.CredentialDump,
                        Confidence = 0.90,
                        Tier = DetectionTier.Tier1Behavioral,
                        AuthorizedResponse = ResponseAction.KillProcessTree,
                        Evidence = $"Browser '{pt.ProcessName}' (PID {pt.ProcessId}) launched with --remote-debugging-port: {cmd}",
                        Reasoning = "A browser was launched with the Chrome DevTools Protocol remote debugging port enabled by a non-browser parent process. " +
                                    "This allows full programmatic access to all open tabs, cookies, session tokens, and saved passwords " +
                                    "without touching any credential file on disk. Common technique in session hijacking attacks."
                    };
                }
            }
            return null;
        }
    }

    /// <summary>
    /// v2.7.1: Detects browser / browser-like apps launched with dangerous control or
    /// origin-isolation-defeating flags (--load-extension, --disable-web-security,
    /// --remote-debugging-*, site-isolation disable, or app-mode + persistent profile).
    /// Complements ChromeRemoteDebuggingRule (which is CDP-port-only and browser-only) by
    /// covering the wider flag set and any process, not just the mainstream browser names.
    ///
    /// Strong control/evasion flag launched by a NON-browser parent -> Tier1 KillProcessTree
    /// (that is the site->app hijack launch shape). A strong flag from a browser parent, or
    /// only weak flags, is Tier2 LogOnly (legitimate automation / kiosk / packaged web app).
    /// </summary>

    [RuleCategory(DetectionCategory.CredentialDump)]
    public class DangerousBrowserFlagRule : IDetectionRule
    {
        public string Name => "DangerousBrowserFlagRule";

        private static readonly HashSet<string> BrowserProcesses = new(StringComparer.OrdinalIgnoreCase)
        {
            "chrome", "msedge", "msedgewebview2", "brave", "vivaldi", "opera", "chromium", "firefox"
        };

        public DetectionEvent? Evaluate(FusedTelemetryContext context)
        {
            if (!(context.TriggeringEvent is ProcessTelemetry pt)) return null;

            var (risk, flags) = Sentinel.Core.DangerousLaunchFlagHeuristics.Classify(pt.CommandLine);
            if (risk == Sentinel.Core.DangerousLaunchFlagHeuristics.FlagRisk.None) return null;

            // The Chrome debug port alone is already owned by ChromeRemoteDebuggingRule for
            // known browsers - don't double-fire when that is the ONLY flag on a browser.
            bool parentIsBrowser = false;
            if (!string.IsNullOrEmpty(pt.ParentProcessName))
            {
                var parentName = Sentinel.Core.StringNet48.ReplaceIgnoreCase(pt.ParentProcessName, ".exe", "");
                parentIsBrowser = BrowserProcesses.Contains(parentName);
            }

            bool strong = risk == Sentinel.Core.DangerousLaunchFlagHeuristics.FlagRisk.Strong;
            bool killShape = strong && !parentIsBrowser;

            var matched = string.Join(" ", flags);

            return new DetectionEvent
            {
                RuleName = Name,
                ProcessName = pt.ProcessName,
                ProcessId = pt.ProcessId,
                SignalType = killShape ? SignalType.CredentialTheft : SignalType.SuspiciousProcess,
                Family = killShape ? TerminalFamily.CredentialDump : (TerminalFamily?)null,
                Confidence = killShape ? 0.85 : 0.55,
                Tier = killShape ? DetectionTier.Tier1Behavioral : DetectionTier.Tier2Indicator,
                AuthorizedResponse = killShape ? ResponseAction.KillProcessTree : ResponseAction.LogOnly,
                Evidence = $"'{pt.ProcessName}' (PID {pt.ProcessId}) launched with dangerous flag(s) [{matched}] " +
                           $"by parent '{pt.ParentProcessName ?? "?"}'. CommandLine: {pt.CommandLine}",
                Reasoning = "The process was launched with browser control/automation or origin-isolation-defeating flags. " +
                            "--load-extension side-loads an unpacked extension (full page access), --disable-web-security / " +
                            "site-isolation disable removes cross-origin protections, and remote-debugging exposes the whole " +
                            "session to a local controller. Launched by a non-browser parent, this is the launch shape of a " +
                            "site-to-local-app hijack / relay. " +
                            (killShape
                                ? "Non-browser parent + strong control flag - kill-grade."
                                : "Browser-parent or weak flags only - observe/log (legitimate automation, kiosk, or packaged web app can look like this)."),
                Metadata = new Dictionary<string, string>
                {
                    ["Flags"] = matched,
                    ["ParentProcess"] = pt.ParentProcessName ?? "",
                    ["ParentIsBrowser"] = parentIsBrowser.ToString(),
                    ["WeakObserveSeed"] = killShape ? "false" : "true",
                }
            };
        }
    }

}
