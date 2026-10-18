using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Threading;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

namespace Sentinel.Core
{
    /// <summary>PID plus creation time identifies a process. Dead entries are evidence only.</summary>
    public class ProcessAncestryCache : IDisposable
    {
        internal sealed class Identity
        {
            public int Pid { get; set; }
            public int ParentPid { get; set; }
            public string Name { get; set; } = "";
            public string ImagePath { get; set; } = "";
            public long CreationTicks { get; set; }
        }
        private sealed class Entry
        {
            public Identity Process { get; set; } = new();
            public DateTimeOffset? DeadSince { get; set; }
        }
        private readonly object _gate = new();
        private readonly Dictionary<int, Entry> _cache = new();
        private readonly Func<int, Identity?> _readIdentity;
        private readonly System.Threading.Timer? _refreshTimer;
        private readonly ILogger<ProcessAncestryCache> _logger;
        private static readonly TimeSpan Retention = TimeSpan.FromSeconds(60);

        public ProcessAncestryCache(ILogger<ProcessAncestryCache>? logger = null) : this(ReadIdentity, true, logger) { }
        internal ProcessAncestryCache(Func<int, Identity?> readIdentity, bool refresh, ILogger<ProcessAncestryCache>? logger = null)
        {
            _readIdentity = readIdentity;
            _logger = logger ?? NullLogger<ProcessAncestryCache>.Instance;
            if (refresh)
            {
                SafeRefresh();
                _refreshTimer = new System.Threading.Timer(_ => SafeRefresh(), null, TimeSpan.FromSeconds(5), TimeSpan.FromSeconds(5));
            }
        }

        private static Identity? ReadIdentity(int pid)
        {
            try
            {
                using var process = Process.GetProcessById(pid);
                long created = process.StartTime.ToUniversalTime().Ticks;
                var pbi = new ParentPidSpoofDetector.PROCESS_BASIC_INFORMATION();
                int status = NativeResolver.NtQueryInformationProcess(process.Handle, 0, ref pbi, out _);
                string imagePath = SecurityValidation.GetProcessImagePath(pid) ?? "";
                using var verify = Process.GetProcessById(pid);
                if (verify.StartTime.ToUniversalTime().Ticks != created) return null;
                return new Identity
                {
                    Pid = pid, CreationTicks = created, Name = process.ProcessName,
                    ParentPid = status == 0 ? pbi.InheritedFromUniqueProcessId.ToInt32() : 0,
                    ImagePath = imagePath
                };
            }
            catch (ArgumentException) { return null; }
            catch (InvalidOperationException) { return null; }
            catch (System.ComponentModel.Win32Exception) { return null; }
        }

        private void SafeRefresh()
        {
            try { RefreshCache(); }
            catch (Exception ex) { _logger.LogDebug(ex, "Process ancestry refresh unavailable"); }
        }

        private void RefreshCache()
        {
            var living = new HashSet<int>();
            foreach (var process in Process.GetProcesses())
            {
                using (process)
                {
                    int pid;
                    try { pid = process.Id; }
                    catch (InvalidOperationException) { continue; }
                    living.Add(pid);
                    TryGetLiveProcessInfo(pid, out _);
                }
            }
            PruneDeadEntries(living, DateTimeOffset.UtcNow);
        }

        internal void PruneDeadEntries(ISet<int> living, DateTimeOffset now)
        {
            lock (_gate)
            {
                foreach (var pid in _cache.Keys.ToArray())
                {
                    var entry = _cache[pid];
                    if (living.Contains(pid)) continue;
                    entry.DeadSince ??= now;
                    if (now - entry.DeadSince.Value >= Retention) _cache.Remove(pid);
                }
            }
        }

        public void RecordProcessStart(int pid, int parentPid, string processName, string imagePath)
        {
            lock (_gate)
            {
                var live = _readIdentity(pid);
                // Delayed telemetry for a different image cannot overwrite live identity.
                if (live != null && (live.CreationTicks <= 0 ||
                    !SameName(live.Name, processName) ||
                    (!string.IsNullOrEmpty(imagePath) && !string.IsNullOrEmpty(live.ImagePath) &&
                     !string.Equals(imagePath, live.ImagePath, StringComparison.OrdinalIgnoreCase)))) return;
                live ??= new Identity { Pid = pid, Name = processName, ImagePath = imagePath ?? "" };
                live.ParentPid = parentPid;
                _cache[pid] = new Entry { Process = live };
            }
        }

        private static bool SameName(string left, string right)
        {
            string Normalize(string name) => name.EndsWith(".exe", StringComparison.OrdinalIgnoreCase) ? name[..^4] : name;
            return string.Equals(Normalize(left), Normalize(right), StringComparison.OrdinalIgnoreCase);
        }

        /// <summary>Live generation-validated data only; never returns retained history on failure.</summary>
        public bool TryGetLiveProcessInfo(int pid, out (int parentId, string name, string imagePath) info)
        {
            info = (0, "unknown", "");
            lock (_gate)
            {
                var live = _readIdentity(pid);
                if (live == null || live.CreationTicks <= 0) return false;
                if (!_cache.TryGetValue(pid, out var entry) || entry.Process.CreationTicks != live.CreationTicks)
                    _cache[pid] = entry = new Entry { Process = live };
                entry.DeadSince = null;
                info = (entry.Process.ParentPid, live.Name, live.ImagePath);
                return true;
            }
        }

        public (int parentId, string name) GetParent(int pid)
        {
            var info = GetProcessInfo(pid);
            var parent = GetProcessInfo(info.parentId);
            return (info.parentId, parent.name);
        }

        public (int parentId, string name, string imagePath) GetProcessInfo(int pid)
        {
            if (TryGetLiveProcessInfo(pid, out var info)) return info;
            // Historical data remains available for evidence, never response targeting.
            lock (_gate)
                return _cache.TryGetValue(pid, out var entry)
                    ? (entry.Process.ParentPid, entry.Process.Name, entry.Process.ImagePath) : (0, "unknown", "");
        }
        public void Stop() => Dispose();
        public void Dispose() => _refreshTimer?.Dispose();
    }
}
