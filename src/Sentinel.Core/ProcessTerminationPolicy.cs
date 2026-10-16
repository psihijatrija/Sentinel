using System;
using System.IO;

namespace Sentinel.Core
{
    internal interface IProcessTerminationTarget : IDisposable
    {
        DateTime CreatedUtc { get; }
        bool IsCritical { get; }
        string ImagePath { get; }
        bool Terminate();
        bool WaitForExit(int milliseconds);
    }

    /// <summary>Identity and outcome gates shared by the native handle adapter and offline regression tests.</summary>
    internal static class ProcessTerminationPolicy
    {
        internal static bool TryTerminate(IProcessTerminationTarget target, DateTime evidenceUtc,
            DateTime nowUtc, Func<string, bool> isProtected, out string reason,
            string? expectedImagePath = null, DateTime? expectedStartUtc = null)
        {
            try
            {
                var createdUtc = target.CreatedUtc;
                if (!ProcessIdentitySafety.EvidenceCanReferToGeneration(evidenceUtc, createdUtc, nowUtc) ||
                    (expectedStartUtc.HasValue && expectedStartUtc.Value != createdUtc))
                { reason = "Target generation no longer matches recorded evidence"; return false; }
                if (target.IsCritical)
                { reason = "Critical process termination refused"; return false; }
                var image = target.ImagePath;
                if (string.IsNullOrWhiteSpace(image) || isProtected(image))
                { reason = "Target image is protected or unavailable"; return false; }
                if (expectedImagePath != null && !string.Equals(Path.GetFullPath(expectedImagePath),
                    Path.GetFullPath(image), StringComparison.OrdinalIgnoreCase))
                { reason = "Target image no longer matches recorded ancestry"; return false; }
                if (!target.Terminate())
                { reason = "Windows refused process termination"; return false; }
                if (!target.WaitForExit(2000))
                { reason = "Termination requested but exit not verified"; return false; }
                reason = "Target exit verified on the same generation-bound process handle";
                return true;
            }
            catch (Exception ex)
            {
                reason = "Process identity or termination unavailable: " + ex.GetType().Name;
                return false;
            }
        }
    }
}
