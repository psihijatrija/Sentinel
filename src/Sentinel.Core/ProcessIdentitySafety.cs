using System;

namespace Sentinel.Core
{
    /// <summary>Rejects evidence that predates the currently running PID generation.
    /// This is a fail-closed temporal check, not a substitute for handle-bound termination.</summary>
    public static class ProcessIdentitySafety
    {
        public static bool EvidenceCanReferToGeneration(DateTime evidenceUtc, DateTime processStartUtc, DateTime nowUtc)
        {
            return evidenceUtc.Kind == DateTimeKind.Utc && processStartUtc.Kind == DateTimeKind.Utc &&
                evidenceUtc >= processStartUtc && evidenceUtc <= nowUtc.AddSeconds(5) && processStartUtc <= nowUtc;
        }
    }
}
