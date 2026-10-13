using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;

namespace Sentinel.Core
{
    [RuleCategory(DetectionCategory.Ransomware)]
    public class RansomwareDetectionRule : IDetectionRule
    {
        public string Name => "RansomwareDetectionRule";

        public DetectionEvent? Evaluate(FusedTelemetryContext context)
        {
            if (context.TriggeringEvent is ProcessTelemetry pt)
            {
                var cmd = (pt.CommandLine ?? "").ToLowerInvariant();
                if (cmd.Contains("vssadmin") && 
                    cmd.Contains("delete") && 
                    cmd.Contains("shadows"))
                {
                    return new DetectionEvent
                    {
                        RuleName = Name,
                        ProcessName = pt.ProcessName,
                        ProcessId = pt.ProcessId,
                        SignalType = SignalType.Ransomware,
                        Confidence = 0.98,
                        Tier = DetectionTier.Tier1Behavioral,
                        AuthorizedResponse = ResponseAction.KillProcessTree,
                        Evidence = $"Volume shadow copy deletion command: {cmd}",
                        Reasoning = "Process attempted to delete volume shadow copies, which is a classic ransomware technique to prevent file recovery."
                    };
                }
            }

            if (context.TriggeringEvent is FileActivityTelemetry ft)
            {
                if (ft.OperationType == "RENAME" && ft.TargetPath != null)
                {
                    var ext = Path.GetExtension(ft.TargetPath).ToLowerInvariant();
                    if (ext == ".locked" || ext == ".enc" || ext == ".crypto")
                    {
                        return new DetectionEvent
                        {
                            RuleName = Name,
                            ProcessName = ft.ProcessName,
                            ProcessId = ft.ProcessId,
                            SignalType = SignalType.Ransomware,
                            Confidence = 0.95,
                            Tier = DetectionTier.Tier1Behavioral,
                            AuthorizedResponse = ResponseAction.KillProcessTree,
                            Evidence = $"File renamed to suspected ransomware extension: {ft.TargetPath}",
                            Reasoning = "Process renamed a file to an extension associated with cryptographic locker ransomware."
                        };
                    }
                }
            }

            return null;
        }
    }

}
