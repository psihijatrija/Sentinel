// SlidingWindowRules.cs - ported from GorstaksProtection
//
// Two production-quality sliding-window detection rules that complement the existing
// single-event RansomwareDetectionRule (shadow-copy / renamed-extension):
//
//   SlidingWindowRansomwareRule (SENT-SW-001)
//     Fires when a single process writes/renames files bearing more than
//     ExtensionThreshold unique extensions within a 30-second window.
//     Confidence: 0.90  ->  Tier1 / KillProcessTree
//
//   SlidingWindowMassDeletionRule (SENT-SW-002)
//     Fires when a single process deletes more than DeletionThreshold files
//     within a 10-second window.
//     Confidence: 0.85  ->  Tier1 / KillProcessTree
//
// Both use:
//   - Per-PID state in a ConcurrentDictionary
//   - A sliding-window Prune() that removes stale timestamps
//   - Idle-PID eviction every EvictionInterval evaluations to bound memory
//     (Interlocked.Increment counter - zero heap pressure between evictions)

using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Threading;

namespace Sentinel.Core
{
    // 
    // Rule 1: Ransomware File Extension Spray  (SENT-SW-001)
    // 

    /// <summary>
    /// Detects ransomware-style encryption by tracking how many unique file
    /// extensions a single process touches within a 30-second sliding window.
    /// Fires at &gt;ExtensionThreshold unique extensions - independently of the
    /// existing shadow-copy / .locked-extension single-event rule.
    /// </summary>
    public sealed class SlidingWindowRansomwareRule : IDetectionRule
    {
        public string Name => "SlidingWindowRansomwareRule";

        private const int ExtensionThreshold = 50;
        private static readonly TimeSpan Window  = TimeSpan.FromSeconds(30);
        private static readonly TimeSpan IdleTtl = TimeSpan.FromMinutes(5);
        private const int EvictionInterval = 1_000;

        private readonly ConcurrentDictionary<int, PidExtensionActivity> _activity = new();
        private int _evalCount;

        public DetectionEvent? Evaluate(FusedTelemetryContext context)
        {
            if (context.TriggeringEvent is not FileActivityTelemetry ft)
                return null;
            if (ft.OperationType != "WRITE" && ft.OperationType != "RENAME")
                return null;

            // Prefer TargetPath for renames (the new name carries the encrypted extension)
            var targetFile = (ft.OperationType == "RENAME" && !string.IsNullOrEmpty(ft.TargetPath))
                ? ft.TargetPath! : ft.FilePath;

            var ext = Path.GetExtension(targetFile)?.ToLowerInvariant() ?? "";
            if (string.IsNullOrEmpty(ext)) return null;

            var now      = DateTime.UtcNow;
            var activity = _activity.GetOrAdd(ft.ProcessId, _ => new PidExtensionActivity());
            int uniqueCount;

            lock (activity)
            {
                activity.Prune(now, Window);
                activity.RecordExtension(ext, now);
                uniqueCount = activity.UniqueExtensionCount;
            }

            // Periodic idle-PID eviction
            if (Interlocked.Increment(ref _evalCount) % EvictionInterval == 0)
                EvictIdleEntries(now);

            if (uniqueCount < ExtensionThreshold) return null;

            return new DetectionEvent
            {
                RuleName          = Name,
                ProcessName       = ft.ProcessName,
                ProcessId         = ft.ProcessId,
                SignalType        = SignalType.Ransomware,
                Confidence        = 0.90,
                Tier              = DetectionTier.Tier1Behavioral,
                AuthorizedResponse = ResponseAction.KillProcessTree,
                Evidence          = $"Process '{ft.ProcessName}' (PID {ft.ProcessId}) touched {uniqueCount} " +
                                    $"unique file extensions within {Window.TotalSeconds}s (threshold: {ExtensionThreshold}).",
                Reasoning         = "A single process generating writes/renames across a high number of distinct " +
                                    "file extensions in a short window is the primary behavioural fingerprint of " +
                                    "ransomware file-encryption loops. Kill authorised.",
                Metadata          = new System.Collections.Generic.Dictionary<string, string>
                {
                    { "RuleId",           "SENT-SW-001" },
                    { "UniqueExtensions", uniqueCount.ToString() },
                    { "WindowSeconds",    Window.TotalSeconds.ToString() }
                }
            };
        }

        private void EvictIdleEntries(DateTime now)
        {
            foreach (var kv in _activity)
            {
                bool idle;
                lock (kv.Value) { idle = (now - kv.Value.LastSeen) > IdleTtl; }
                if (idle) _activity.TryRemove(kv.Key, out _);
            }
        }

        //  Per-PID extension tracker 

        private sealed class PidExtensionActivity
        {
            // extension -> most recent timestamp within the window
            private readonly Dictionary<string, DateTime> _extensions =
                new(StringComparer.OrdinalIgnoreCase);

            public DateTime LastSeen { get; private set; } = DateTime.UtcNow;
            public int UniqueExtensionCount => _extensions.Count;

            public void RecordExtension(string ext, DateTime when)
            {
                _extensions[ext] = when;
                LastSeen = when;
            }

            public void Prune(DateTime now, TimeSpan window)
            {
                var cutoff   = now - window;
                var toRemove = new List<string>();
                foreach (var kv in _extensions)
                    if (kv.Value < cutoff) toRemove.Add(kv.Key);
                foreach (var key in toRemove) _extensions.Remove(key);
            }
        }
    }

    // 
    // Rule 2: Mass File Deletion  (SENT-SW-002)
    // 

    /// <summary>
    /// Fires when a single process performs more than DeletionThreshold file
    /// deletions within a 10-second sliding window.
    /// Consistent with wiper malware or ransomware shadow-copy / backup deletion.
    /// </summary>
    public sealed class SlidingWindowMassDeletionRule : IDetectionRule
    {
        public string Name => "SlidingWindowMassDeletionRule";

        private const int DeletionThreshold = 100;
        private static readonly TimeSpan Window  = TimeSpan.FromSeconds(10);
        private static readonly TimeSpan IdleTtl = TimeSpan.FromMinutes(5);
        private const int EvictionInterval = 1_000;

        private readonly ConcurrentDictionary<int, PidDeletionActivity> _activity = new();
        private int _evalCount;

        public DetectionEvent? Evaluate(FusedTelemetryContext context)
        {
            if (context.TriggeringEvent is not FileActivityTelemetry ft)
                return null;
            if (ft.OperationType != "DELETE") return null;

            var now      = DateTime.UtcNow;
            var activity = _activity.GetOrAdd(ft.ProcessId, _ => new PidDeletionActivity());
            int count;

            lock (activity)
            {
                activity.Prune(now, Window);
                activity.Record(now);
                count = activity.Count;
            }

            if (Interlocked.Increment(ref _evalCount) % EvictionInterval == 0)
                EvictIdleEntries(now);

            if (count < DeletionThreshold) return null;

            return new DetectionEvent
            {
                RuleName          = Name,
                ProcessName       = ft.ProcessName,
                ProcessId         = ft.ProcessId,
                SignalType        = SignalType.Ransomware,
                Confidence        = 0.85,
                Tier              = DetectionTier.Tier1Behavioral,
                AuthorizedResponse = ResponseAction.KillProcessTree,
                Evidence          = $"Process '{ft.ProcessName}' (PID {ft.ProcessId}) deleted {count} files " +
                                    $"in {Window.TotalSeconds}s (threshold: {DeletionThreshold}).",
                Reasoning         = "Deleting over 100 files in 10 seconds is consistent with wiper malware " +
                                    "or ransomware destroying backups / shadow copies prior to encryption. Kill authorised.",
                Metadata          = new System.Collections.Generic.Dictionary<string, string>
                {
                    { "RuleId",          "SENT-SW-002" },
                    { "DeletionCount",   count.ToString() },
                    { "WindowSeconds",   Window.TotalSeconds.ToString() }
                }
            };
        }

        private void EvictIdleEntries(DateTime now)
        {
            foreach (var kv in _activity)
            {
                bool idle;
                lock (kv.Value) { idle = (now - kv.Value.LastSeen) > IdleTtl; }
                if (idle) _activity.TryRemove(kv.Key, out _);
            }
        }

        //  Per-PID deletion tracker 

        private sealed class PidDeletionActivity
        {
            private readonly List<DateTime> _timestamps = new();

            public DateTime LastSeen { get; private set; } = DateTime.UtcNow;
            public int Count => _timestamps.Count;

            public void Record(DateTime when)
            {
                _timestamps.Add(when);
                LastSeen = when;
            }

            public void Prune(DateTime now, TimeSpan window)
            {
                var cutoff = now - window;
                _timestamps.RemoveAll(t => t < cutoff);
            }
        }
    }
}
