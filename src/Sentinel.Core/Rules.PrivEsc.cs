using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;

namespace Sentinel.Core
{
    [RuleCategory(DetectionCategory.PrivilegeEscalation)]
    public class PrivilegeEscalationRule : IDetectionRule
    {
        public string Name => "PrivilegeEscalationRule";

        private static readonly string[] UacBypassPatterns = new[]
        {
            "fodhelper.exe", "computerdefaults.exe", "sdclt.exe",
            "eventvwr.exe", "slui.exe", "cmstp.exe",
            // Token manipulation
            "tokenvator", "incognito", "getsystem",
            // Privilege escalation exploits (GodPotato, JuicyPotato, PrintSpoofer, etc.)
            "potato", "printspoof", "juicypotato", "godpotato", "sweetpotato",
            "roguepotato", "localpotato", "printspoofer", "efspotato",
            // Defense evasion: Clearing Windows Application, System, or Security event logs
            "wevtutil cl ", "wevtutil.exe cl ", "wevtutil clear-log",
            // Named pipe impersonation
            "\\pipe\\", "ImpersonateNamedPipeClient",
            // DLL hijack indicators
            "\\syswow64\\version.dll", "\\temp\\version.dll", "\\temp\\winmm.dll",
            // v2.1.0: additional LPE / coerce helpers (command-line)
            "petitpotam", "dfscoerce", "spoolsample", "sharpup", "winpeas",
            "seatbelt", "privesccheck", "getsystem", "enable-privilege",
        };

        public DetectionEvent? Evaluate(FusedTelemetryContext context)
        {
            if (context.TriggeringEvent is ProcessTelemetry pt)
            {
                var cmd = pt.CommandLine.ToLowerInvariant();
                var image = pt.ImagePath.ToLowerInvariant();

                foreach (var pattern in UacBypassPatterns)
                {
                    if (cmd.Contains(pattern) ||
                        image.Contains(pattern))
                    {
                        // Skip legitimate uses - these only trigger when spawned by non-explorer parents
                        if (pattern.EndsWith(".exe") && pt.ParentProcessName?.Equals("explorer") == true)
                            continue;

                        // Skip COM auto-elevation: when auto-elevate binaries are launched with
                        // "-Embedding" by the COM runtime (svchost/DcomLaunch), it's legitimate.
                        // This prevents false positives on FodHelper.exe, eventvwr.exe, etc.
                        if (pattern.EndsWith(".exe") && cmd.Contains("-embedding"))
                            continue;

                        // Skip false positives on legitimate named pipes used for IPC by development/IDE tools or other applications
                        if (pattern.Equals("\\pipe\\"))
                        {
                            var procName = pt.ProcessName.ToLowerInvariant();
                            bool isShell = procName == "cmd" || procName == "cmd.exe" ||
                                           procName == "powershell" || procName == "powershell.exe" ||
                                           procName == "pwsh" || procName == "pwsh.exe";
                            if (!isShell)
                                continue;

                            // Exclude common IPC parameters to prevent false positives on shell IPC
                            if (cmd.Contains("parent_pipe") || cmd.Contains("parent-pipe") || cmd.Contains("pipe-name") || cmd.Contains("chrome-signaling"))
                                continue;
                        }

                        return new DetectionEvent
                        {
                            RuleName = Name,
                            ProcessName = pt.ProcessName,
                            ProcessId = pt.ProcessId,
                            SignalType = SignalType.SecurityEvasion,
                            Confidence = 0.85,
                            Tier = DetectionTier.Tier1Behavioral,
                            AuthorizedResponse = ResponseAction.KillProcessTree,
                            Evidence = $"Privilege escalation pattern detected: '{pattern}' in {pt.ProcessName} (PID {pt.ProcessId}) cmd: {pt.CommandLine}",
                            Reasoning = "Process matches a known UAC bypass vector, token manipulation tool, or DLL hijacking pattern indicating privilege escalation."
                        };
                    }
                }
            }
            return null;
        }
    }

}
