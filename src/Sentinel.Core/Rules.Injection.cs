using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;

namespace Sentinel.Core
{
    [RuleCategory(DetectionCategory.ProcessInjection)]
    public class ThreatIntelInjectionRule : IDetectionRule
    {
        public string Name => "ThreatIntelInjectionRule";

        // Browsers legitimately use cross-process memory APIs for their sandbox model
        // (broker process allocates memory in renderer/tab processes). Skip to avoid FP kills.
        private static readonly HashSet<string> KnownBrowserProcesses = new(StringComparer.OrdinalIgnoreCase)
        {
            "chrome", "msedge", "firefox", "brave", "opera", "vivaldi", "iexplore",
            "msedgewebview2", "electron"
        };

        public DetectionEvent? Evaluate(FusedTelemetryContext context)
        {
            if (context.TriggeringEvent is not ThreatIntelTelemetry tit)
                return null;

            if (!ThreatIntelMap.IsRemoteInjection(tit.ApiName))
                return null;

            // Browser sandbox: chrome->chrome is normal. chrome->lsass is not.
            if (KnownBrowserProcesses.Contains(tit.ProcessName) &&
                tit.TargetProcessId != 4 &&
                !IsSensitiveTargetName(tit.TargetProcessId))
                return null;

            var imagePath = SecurityValidation.GetProcessImagePath(tit.ProcessId);
            if (SecurityValidation.IsGameOrAntiCheatPath(imagePath))
                return null;

            InjectionSuspectBoard.Mark(tit.ProcessId);
            if (tit.TargetProcessId > 4)
                InjectionSuspectBoard.Mark(tit.TargetProcessId);

            var label = ThreatIntelMap.Describe(tit.ApiName);
            return new DetectionEvent
            {
                RuleName = Name,
                ProcessName = tit.ProcessName,
                ProcessId = tit.ProcessId,
                SignalType = SignalType.ProcessInjection,
                Family = TerminalFamily.Injection,
                Confidence = 0.90,
                Tier = DetectionTier.Tier1Behavioral,
                AuthorizedResponse = ResponseAction.QuarantineAndKill,
                Evidence = $"Injection TI {label} by {tit.ProcessName} (PID {tit.ProcessId}) targeting PID {tit.TargetProcessId}",
                Reasoning = "Kernel Threat-Intelligence observed a remote memory/thread API (T1055).",
                Metadata = new Dictionary<string, string>
                {
                    { "TargetProcessId", tit.TargetProcessId.ToString() },
                    { "ApiName", tit.ApiName },
                    { "TiLabel", label }
                }
            };
        }

        private static bool IsSensitiveTargetName(int pid)
        {
            try
            {
                using var p = System.Diagnostics.Process.GetProcessById(pid);
                var n = p.ProcessName ?? "";
                return n.Equals("lsass", StringComparison.OrdinalIgnoreCase)
                    || n.Equals("winlogon", StringComparison.OrdinalIgnoreCase)
                    || n.Equals("csrss", StringComparison.OrdinalIgnoreCase)
                    || n.Equals("services", StringComparison.OrdinalIgnoreCase)
                    || n.Equals("smss", StringComparison.OrdinalIgnoreCase);
            }
            catch { return false; }
        }
    }


    [RuleCategory(DetectionCategory.ProcessInjection)]
    public class DllSideloadingDetectionRule : IDetectionRule
    {
        public string Name => "DllSideloadingDetectionRule";

        public DetectionEvent? Evaluate(FusedTelemetryContext context)
        {
            if (context.TriggeringEvent is ProcessTelemetry pt)
            {
                var path = pt.ImagePath.ToLowerInvariant();
                
                // Check if process runs out of user-writeable paths
                bool isUserWriteablePath = path.Contains(@"\users\") || 
                                           path.Contains(@"\appdata\") || 
                                           path.Contains(@"\temp\");

                if (isUserWriteablePath)
                {
                    // A binary whose NAME matches a Microsoft system tool but which runs from a
                    // user-writable path is a classic sideload/masquerade (T1574.002). The genuine
                    // tool lives in System32 / Program Files.
                    var procName = Sentinel.Core.StringNet48.ReplaceIgnoreCase(pt.ProcessName, ".exe", "");
                    bool isSystemToolName = procName.Equals("onedrive") ||
                                            procName.Equals("msoju") ||
                                            procName.Equals("winword") ||
                                            procName.Equals("excel") ||
                                            procName.Equals("powershell") ||
                                            procName.Equals("cmd");

                    if (isSystemToolName)
                    {
                        // The developer-build exclusion (\bin\debug, \bin\release, .nuget) is a
                        // path fragment an attacker fully controls - dropping a fake "powershell.exe"
                        // under any "...\bin\debug\..." folder previously bypassed this KILL entirely.
                        // Per docs/constraints.md a path allow must combine with a
                        // non-attacker-controllable anchor. Only honor the dev-env skip when the
                        // binary is Authenticode-signed: a real signed tool a developer staged there
                        // is exonerated, but an UNSIGNED system-tool-named impostor in a dev path is
                        // still caught. (Developer build output is essentially never named after an
                        // OS system tool, so genuine dev binaries do not hit this branch at all.)
                        bool inDevEnvPath = path.Contains(@"\bin\debug") ||
                                            path.Contains(@"\bin\release") ||
                                            path.Contains(@".nuget");
                        if (inDevEnvPath && SecurityValidation.VerifyAuthenticodeSignature(pt.ImagePath))
                        {
                            return null;
                        }

                        return new DetectionEvent
                        {
                            RuleName = Name,
                            ProcessName = pt.ProcessName,
                            ProcessId = pt.ProcessId,
                            SignalType = SignalType.SuspiciousProcess,
                            Confidence = 0.85,
                            Tier = DetectionTier.Tier1Behavioral,
                            AuthorizedResponse = ResponseAction.KillProcessTree,
                            Evidence = $"System-tool-named binary '{pt.ProcessName}' running from user-writeable path (not Authenticode-signed): {pt.ImagePath}",
                            Reasoning = "A binary named after a Microsoft system utility executed from an untrusted user-writeable directory without a valid Authenticode signature. The genuine tool lives in System32 / Program Files; a signed dev-staged copy is exempt. This is highly indicative of masquerade / DLL sideloading (T1574.002)."
                        };
                    }
                }
            }
            return null;
        }
    }

    // 
    // Full-Path Parent-Child Verification Rule  (SENT-003)
    // Ported from GorstaksProtection SuspiciousParentChildRule.cs
    // 

    /// <summary>
    /// Detects Office apps, browsers, and PDF readers spawning shells / scripting
    /// engines - with FULL PATH verification of the parent binary.
    ///
    /// Why full-path? Sentinel's AttackToolsRule matches parent by process name only,
    /// which an attacker can trivially spoof by naming malware "winword.exe".
    /// This rule also verifies that the parent lives in a known legitimate install
    /// path before firing - a winword.exe in C:\Temp\ is NOT a genuine Office install.
    ///
    /// Confidence: 0.75  ->  Tier2 / LogOnly (feeds BehavioralCorrelationEngine).
    /// The correlation engine promotes to Tier1 once additional signals arrive.
    /// </summary>
}
