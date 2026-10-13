using System;
using System.Collections.Concurrent;
using System.Diagnostics;

namespace Sentinel.Core
{
    public class SafeProcessExemptionRegistry
    {
        private readonly ConcurrentDictionary<int, DateTime> _safePids = new();

        public void RegisterSafeProcess(int pid)
        {
            if (pid > 0)
            {
                var startTime = GetProcessStartTime(pid);
                _safePids[pid] = startTime;
            }
        }

        public bool IsSafeProcess(int pid)
        {
            if (!_safePids.TryGetValue(pid, out var registeredStartTime))
                return false;

            // Verify the process at this PID still has the same start time (PID reuse detection)
            var currentStartTime = GetProcessStartTime(pid);
            if (currentStartTime != registeredStartTime)
            {
                // PID was recycled - remove stale entry
                _safePids.TryRemove(pid, out _);
                return false;
            }

            return true;
        }

        public void Remove(int pid)
        {
            _safePids.TryRemove(pid, out _);
        }

        private static DateTime GetProcessStartTime(int pid)
        {
            try
            {
                using var proc = Process.GetProcessById(pid);
                return proc.StartTime;
            }
            catch
            {
                return DateTime.MinValue;
            }
        }
    }
}
