using System;

namespace Sentinel.Core
{
    // Memory evidence identifies the victim process, not a malicious backing file
    // or its parent. Keep this route independent of broad ancestor/quarantine tracing.
    internal static class InjectedVictimResponse
    {
        internal static bool AppliesTo(DetectionEvent detection) =>
            detection.RuleName == "Credential Theft: Unbacked PE + Store Read";

        internal static ProcessTreeTerminationResult Execute(DetectionEvent detection, IProcessTreeOperations operations)
        {
            if (!AppliesTo(detection) || detection.ProcessId <= 4 ||
                detection.Tier != DetectionTier.Tier1Behavioral || !detection.KillAuthorized ||
                detection.Timestamp > DateTime.UtcNow || DateTime.UtcNow - detection.Timestamp > TimeSpan.FromSeconds(15) ||
                detection.Confidence < ResponsePolicy.DefaultMinTier1Confidence ||
                !ResponsePolicy.IsNukeComposite(detection) ||
                detection.Metadata == null ||
                !detection.Metadata.TryGetValue(ResponsePolicy.ChainConfirmedKey, out var chain) || chain != "true" ||
                !detection.Metadata.TryGetValue(ResponsePolicy.TerminalOutcomeKey, out var terminal) || terminal != "Composite" ||
                !detection.Metadata.TryGetValue("ContainmentScope", out var scope) || scope != "InjectedVictim" ||
                !detection.Metadata.TryGetValue("ProcessCreationTime", out var birth) ||
                !long.TryParse(birth, out long created) || created <= 0 || created > detection.Timestamp.ToFileTimeUtc())
            {
                var refused = new ProcessTreeTerminationResult
                {
                    RootProcessId = detection.ProcessId,
                    Error = "Injected-victim containment requires an authorized composite and pinned process lifetime."
                };
                refused.RefusedProcessIds.Add(detection.ProcessId);
                return refused;
            }
            return new ProcessTreeTerminator(operations).Terminate(detection.ProcessId, created);
        }
    }
}
