using System;
using System.Diagnostics;

namespace Sentinel.Core
{
    /// <summary>Trusted application dependency, not a runtime setting or IPC bypass.
    /// Production uses native identity/termination; tests supply isolated process fixtures.</summary>
    public interface IResponseProcessOperations
    {
        bool EvidenceMatches(int pid, DateTime evidenceUtc);
        bool TryTerminate(int pid, DateTime evidenceUtc, out string reason);
    }
    public sealed class WindowsResponseProcessOperations : IResponseProcessOperations
    {
        public bool EvidenceMatches(int pid, DateTime evidenceUtc)
        {
            if (pid <= 4) return false;
            using var process = Process.GetProcessById(pid);
            return ProcessIdentitySafety.EvidenceCanReferToGeneration(evidenceUtc, process.StartTime.ToUniversalTime(), DateTime.UtcNow);
        }
        public bool TryTerminate(int pid, DateTime evidenceUtc, out string reason)
            => VerifiedProcessTermination.TryTerminate(pid, evidenceUtc, out reason);
    }
}
