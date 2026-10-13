using System;
using System.Collections.Concurrent;

namespace Sentinel.Core
{
    /// <summary>
    /// Microsoft-Windows-Threat-Intelligence ETW event IDs as shipped on
    /// Win10/11. UnifiedEtwSession labels them ThreatIntel_EventId_N.
    /// Remote alloc/write/APC/context/map are injection. Local write is JIT noise.
    /// </summary>
    public static class ThreatIntelMap
    {
        public const string EventIdPrefix = "ThreatIntel_EventId_";

        // Remote injection (kernel TI). Local 1/2/3/11/12 are too noisy (JIT).
        private static readonly int[] RemoteInjectionIds =
        {
            4, 5, 6, 7, 8, 13, 14,
            26, 27, 28, 29, 30
        };

        public static bool TryParseEventId(string? apiName, out int eventId)
        {
            eventId = 0;
            if (string.IsNullOrEmpty(apiName) ||
                !apiName!.StartsWith(EventIdPrefix, StringComparison.Ordinal))
                return false;
            return int.TryParse(apiName.Substring(EventIdPrefix.Length), out eventId);
        }

        public static bool IsRemoteInjection(string? apiName)
        {
            if (string.IsNullOrEmpty(apiName)) return false;
            if (TryParseEventId(apiName, out int id))
            {
                for (int i = 0; i < RemoteInjectionIds.Length; i++)
                    if (RemoteInjectionIds[i] == id) return true;
                return false;
            }

            return apiName!.IndexOf("VirtualAllocEx", StringComparison.OrdinalIgnoreCase) >= 0
                || apiName.IndexOf("WriteProcessMemory", StringComparison.OrdinalIgnoreCase) >= 0
                || apiName.IndexOf("NtWriteVirtualMemory", StringComparison.OrdinalIgnoreCase) >= 0
                || apiName.IndexOf("NtAllocateVirtualMemory", StringComparison.OrdinalIgnoreCase) >= 0
                || apiName.IndexOf("MapViewOfSection", StringComparison.OrdinalIgnoreCase) >= 0
                || apiName.IndexOf("QueueUserAPC", StringComparison.OrdinalIgnoreCase) >= 0
                || apiName.IndexOf("NtQueueApcThread", StringComparison.OrdinalIgnoreCase) >= 0
                || apiName.IndexOf("SetThreadContext", StringComparison.OrdinalIgnoreCase) >= 0
                || apiName.IndexOf("NtSetContextThread", StringComparison.OrdinalIgnoreCase) >= 0
                || apiName.IndexOf("CreateRemoteThread", StringComparison.OrdinalIgnoreCase) >= 0
                || apiName.IndexOf("RtlCreateUserThread", StringComparison.OrdinalIgnoreCase) >= 0;
        }

        public static string Describe(string? apiName)
        {
            if (TryParseEventId(apiName, out int id))
            {
                return id switch
                {
                    4 or 26 => "ALLOCVM_REMOTE",
                    5 or 27 => "PROTECTVM_REMOTE",
                    6 or 28 => "MAPVIEW_REMOTE",
                    7 or 29 => "QUEUEUSERAPC_REMOTE",
                    8 or 30 => "SETTHREADCONTEXT_REMOTE",
                    13 => "READVM_REMOTE",
                    14 => "WRITEVM_REMOTE",
                    _ => apiName ?? "TI"
                };
            }
            return apiName ?? "TI";
        }
    }

    /// <summary>
    /// PIDs that just did remote TI. EtwThreatIntelMonitor scans only these
    /// (no full-system 5s EnumModules - that was the LatencyMon hard-fault source).
    /// </summary>
    public static class InjectionSuspectBoard
    {
        private static readonly ConcurrentDictionary<int, DateTimeOffset> Pids = new();
        private static readonly TimeSpan Ttl = TimeSpan.FromMinutes(2);

        // Most recent ETW-TI captured call-stack frames per caller PID. Stashed cheaply on
        // the ETW callback thread; the heavy per-frame memory classification runs off-thread
        // in EtwThreatIntelMonitor (same reason the module walk lives there, not here).
        private static readonly ConcurrentDictionary<int, (DateTimeOffset When, ulong[] Frames)> StackFrames = new();

        public static void Mark(int pid)
        {
            if (pid > 4)
                Pids[pid] = DateTimeOffset.UtcNow;
        }

        /// <summary>
        /// Stash a captured user-mode return-address chain for later off-thread analysis.
        /// Marks the PID as a suspect as well. No memory inspection happens here.
        /// </summary>
        public static void RecordStack(int pid, ulong[] frames)
        {
            if (pid <= 4 || frames == null || frames.Length == 0)
                return;
            StackFrames[pid] = (DateTimeOffset.UtcNow, frames);
            Pids[pid] = DateTimeOffset.UtcNow;
        }

        /// <summary>
        /// Takes (and clears) the stashed frames for a PID if fresh, else returns null.
        /// One-shot: consuming the stash prevents re-alerting on the same capture.
        /// </summary>
        public static ulong[]? TakeStack(int pid)
        {
            if (!StackFrames.TryRemove(pid, out var entry))
                return null;
            if (DateTimeOffset.UtcNow - entry.When > Ttl)
                return null;
            return entry.Frames;
        }

        public static int[] Snapshot()
        {
            var now = DateTimeOffset.UtcNow;
            foreach (var kv in Pids)
            {
                if (now - kv.Value > Ttl)
                    Pids.TryRemove(kv.Key, out _);
            }
            foreach (var kv in StackFrames)
            {
                if (now - kv.Value.When > Ttl)
                    StackFrames.TryRemove(kv.Key, out _);
            }
            var keys = Pids.Keys;
            var arr = new int[keys.Count];
            keys.CopyTo(arr, 0);
            return arr;
        }
    }
}
