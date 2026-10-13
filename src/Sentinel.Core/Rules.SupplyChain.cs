using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;

namespace Sentinel.Core
{
    [RuleCategory(DetectionCategory.SecurityEvasion)]
    public class NpmSupplyChainRule : IDetectionRule
    {
        public string Name => "NpmSupplyChainRule";

        public DetectionEvent? Evaluate(FusedTelemetryContext context)
        {
            if (context.TriggeringEvent is not ProcessTelemetry pt)
                return null;

            var parent = pt.ParentProcessName?.ToLowerInvariant() ?? "";
            bool parentIsNode =
                parent is "node" or "node.exe" or "npm" or "npm.exe" or
                    "npx" or "npx.exe" or "yarn" or "yarn.exe" or "pnpm" or "pnpm.exe";

            if (!parentIsNode)
                return null;

            var name = pt.ProcessName ?? "";
            bool childIsShell =
                name.Contains("powershell") ||
                name.Contains("pwsh") ||
                name.Contains("cmd") ||
                name.Contains("curl") ||
                name.Contains("wget") ||
                name.Contains("bitsadmin") ||
                name.Contains("certutil");

            if (!childIsShell)
                return null;

            var cmd = pt.CommandLine?.ToLowerInvariant() ?? "";
            bool suspicious =
                cmd.Contains("http://") || cmd.Contains("https://") ||
                cmd.Contains("frombase64string") || cmd.Contains("downloadstring") ||
                cmd.Contains("iex") || cmd.Contains("invoke-expression") ||
                cmd.Contains("invoke-webrequest") || cmd.Contains("curl ") ||
                cmd.Contains("-enc") || cmd.Contains("hidden");

            if (!suspicious)
                return null;

            return new DetectionEvent
            {
                RuleName = Name,
                ProcessName = pt.ProcessName ?? "",
                ProcessId = pt.ProcessId,
                SignalType = SignalType.SuspiciousProcess,
                Confidence = 0.88,
                Tier = DetectionTier.Tier1Behavioral,
                AuthorizedResponse = ResponseAction.KillProcessTree,
                Evidence = $"Node/npm parent spawned shell with download/encode payload: {pt.CommandLine}",
                Reasoning =
                    "Package-manager process (node/npm/yarn/pnpm) launched a shell with network download or " +
                    "encoded execution - consistent with malicious postinstall/preinstall scripts in npm " +
                    "supply-chain attacks (e.g. 2025 Shai-Hulud/Tinycolor waves)."
            };
        }
    }

}
