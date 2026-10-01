using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace Sentinel.Core
{
    /// <summary>
    /// Builds a behavioral baseline of normal system activity over time:
    /// - Known process names and execution paths
    /// - Known parent-child process relationships
    /// - Known network destinations per process
    /// The baseline is persisted in SecureCacheStore and used by rules and the
    /// ScoringEngine to reduce confidence on known-good activity.
    /// </summary>
    public sealed class BehavioralBaselineService : BackgroundService
    {
        private readonly SecureCacheStore _cacheStore;
        private readonly ILogger<BehavioralBaselineService> _logger;

        private readonly ConcurrentDictionary<string, ProcessBehaviorProfile> _knownProcesses = new(StringComparer.OrdinalIgnoreCase);
        private readonly ConcurrentDictionary<string, PathReputation> _knownExecutablePaths = new(StringComparer.OrdinalIgnoreCase);
        private readonly ConcurrentDictionary<string, ParentChildRelationship> _knownParentChild = new(StringComparer.OrdinalIgnoreCase);
        private readonly ConcurrentDictionary<string, NetworkDestination> _knownNetworkDestinations = new(StringComparer.OrdinalIgnoreCase);

        // HARDENING v1.5.9: Track processes that have triggered detections.
        // A process with ANY detection events during its observation period is excluded
        // from "established" status, preventing malware from poisoning the baseline
        // by running 10+ times with persistence to earn trust score reductions.
        private readonly ConcurrentDictionary<string, DetectionRecord> _detectionHistory = new(StringComparer.OrdinalIgnoreCase);

        private DateTimeOffset _lastSave = DateTimeOffset.UtcNow;
        // HARDENING v1.3.0: Raised from 3 to 10. Previously, malware only needed 3 executions
        // (e.g., 3 reboots with persistence) to become "established" and receive -15 scoring
        // reduction from the ScoringEngine. Now requires 10 executions over multiple days,
        // making it significantly harder for malware to achieve baseline trust.
        private const int EstablishedThreshold = 10;

        public BehavioralBaselineService(SecureCacheStore cache, ILogger<BehavioralBaselineService> logger)
        {
            _cacheStore = cache;
            _logger = logger;
        }

        protected override async Task ExecuteAsync(CancellationToken ct)
        {
            LoadBaseline();
            _logger.LogInformation("[BehavioralBaseline] Started with {P} processes, {Pa} paths, {PC} parent-child, {N} net destinations",
                _knownProcesses.Count, _knownExecutablePaths.Count, _knownParentChild.Count, _knownNetworkDestinations.Count);

            while (!ct.IsCancellationRequested)
            {
                try
                {
                    await Task.Delay(60_000, ct);
                    CleanupOldEntries();

                    if ((DateTimeOffset.UtcNow - _lastSave).TotalMinutes >= 5)
                        SaveBaseline();
                }
                catch (OperationCanceledException) { break; }
                catch (Exception ex) { _logger.LogDebug(ex, "[BehavioralBaseline] Error"); }
            }

            SaveBaseline();
        }

        /// <summary>Records a process execution for baseline building.</summary>
        public void RecordProcess(string processName, string? imagePath, int parentPid, string? parentName)
        {
            if (string.IsNullOrEmpty(processName)) return;

            var key = processName.ToLowerInvariant();
            _knownProcesses.AddOrUpdate(key,
                _ => new ProcessBehaviorProfile
                {
                    ProcessName = processName,
                    FirstSeen = DateTimeOffset.UtcNow,
                    LastSeen = DateTimeOffset.UtcNow,
                    ExecutionCount = 1
                },
                (_, p) => { p.LastSeen = DateTimeOffset.UtcNow; p.ExecutionCount++; return p; });

            if (!string.IsNullOrEmpty(imagePath))
            {
                var pathKey = imagePath!.ToLowerInvariant();
                _knownExecutablePaths.AddOrUpdate(pathKey,
                    _ => new PathReputation { Path = imagePath, FirstSeen = DateTimeOffset.UtcNow, LastSeen = DateTimeOffset.UtcNow, ExecutionCount = 1 },
                    (_, p) => { p.LastSeen = DateTimeOffset.UtcNow; p.ExecutionCount++; return p; });
            }

            if (!string.IsNullOrEmpty(parentName))
            {
                var pcKey = $"{parentName!.ToLowerInvariant()}->{key}";
                _knownParentChild.AddOrUpdate(pcKey,
                    _ => new ParentChildRelationship { ParentName = parentName, ChildName = processName, FirstSeen = DateTimeOffset.UtcNow, LastSeen = DateTimeOffset.UtcNow, OccurrenceCount = 1 },
                    (_, r) => { r.LastSeen = DateTimeOffset.UtcNow; r.OccurrenceCount++; return r; });
            }
        }

        /// <summary>Records a network connection for baseline building.</summary>
        public void RecordNetworkConnection(string processName, string remoteAddress, int remotePort)
        {
            if (string.IsNullOrEmpty(processName)) return;
            var key = $"{processName.ToLowerInvariant()}:{remoteAddress}:{remotePort}";
            _knownNetworkDestinations.AddOrUpdate(key,
                _ => new NetworkDestination { ProcessName = processName, RemoteAddress = remoteAddress, RemotePort = remotePort, FirstSeen = DateTimeOffset.UtcNow, LastSeen = DateTimeOffset.UtcNow, ConnectionCount = 1 },
                (_, n) => { n.LastSeen = DateTimeOffset.UtcNow; n.ConnectionCount++; return n; });
        }

        /// <summary>
        /// Returns true if a process is established in the baseline (seen N+ times)
        /// AND has ZERO detection events recorded against it.
        /// HARDENING v1.5.9: Malware with persistence that runs 10+ times can no longer
        /// earn "established" status if any detection has ever fired against it.
        /// </summary>
        public bool IsEstablishedProcess(string processName)
        {
            var key = processName.ToLowerInvariant();
            if (!_knownProcesses.TryGetValue(key, out var p) || p.ExecutionCount < EstablishedThreshold)
                return false;

            // Deny established status if any detection has been recorded for this process name
            if (_detectionHistory.TryGetValue(key, out var record) && record.DetectionCount > 0)
                return false;

            return true;
        }

        /// <summary>
        /// HARDENING v1.5.9: Records that a detection event fired for a given process name.
        /// Called by the detection pipeline after processing a detection. Processes with
        /// any detection history are permanently excluded from "established" baseline status
        /// until the detection record ages out (7 days with no new detections).
        /// </summary>
        public void RecordDetectionForProcess(string processName)
        {
            if (string.IsNullOrEmpty(processName)) return;
            var key = processName.ToLowerInvariant();
            _detectionHistory.AddOrUpdate(key,
                _ => new DetectionRecord
                {
                    ProcessName = processName,
                    FirstDetection = DateTimeOffset.UtcNow,
                    LastDetection = DateTimeOffset.UtcNow,
                    DetectionCount = 1
                },
                (_, r) => { r.LastDetection = DateTimeOffset.UtcNow; r.DetectionCount++; return r; });
        }

        /// <summary>Returns true if a parent-child relationship is known.</summary>
        public bool IsKnownParentChild(string parentName, string childName) =>
            _knownParentChild.ContainsKey($"{parentName.ToLowerInvariant()}->{childName.ToLowerInvariant()}");

        /// <summary>Returns true if a network destination is known for a process.</summary>
        public bool IsKnownNetworkDestination(string processName, string remoteAddress, int remotePort) =>
            _knownNetworkDestinations.ContainsKey($"{processName.ToLowerInvariant()}:{remoteAddress}:{remotePort}");

        public BaselineStatistics GetStatistics() => new()
        {
            KnownProcesses = _knownProcesses.Count,
            KnownPaths = _knownExecutablePaths.Count,
            KnownParentChild = _knownParentChild.Count,
            KnownNetworkDestinations = _knownNetworkDestinations.Count,
            EstablishedProcesses = _knownProcesses.Values.Count(p => p.ExecutionCount >= EstablishedThreshold),
            LastUpdated = DateTimeOffset.UtcNow
        };

        private void LoadBaseline()
        {
            try
            {
                var json = _cacheStore.Load("baseline", "data");
                if (string.IsNullOrWhiteSpace(json)) return;
                var data = JsonSerializer.Deserialize<BaselineData>(json!);
                if (data == null) return;

                foreach (var p in data.Processes) _knownProcesses[p.ProcessName.ToLowerInvariant()] = p;
                foreach (var p in data.Paths) _knownExecutablePaths[p.Path.ToLowerInvariant()] = p;
                foreach (var pc in data.ParentChild) _knownParentChild[$"{pc.ParentName.ToLowerInvariant()}->{pc.ChildName.ToLowerInvariant()}"] = pc;
                foreach (var n in data.NetworkDestinations) _knownNetworkDestinations[$"{n.ProcessName.ToLowerInvariant()}:{n.RemoteAddress}:{n.RemotePort}"] = n;
            }
            catch { }
        }

        private void SaveBaseline()
        {
            try
            {
                var data = new BaselineData
                {
                    Processes = _knownProcesses.Values.ToList(),
                    Paths = _knownExecutablePaths.Values.ToList(),
                    ParentChild = _knownParentChild.Values.ToList(),
                    NetworkDestinations = _knownNetworkDestinations.Values
                        .OrderByDescending(n => n.ConnectionCount)
                        .ThenByDescending(n => n.LastSeen)
                        .Take(1000)
                        .ToList(),
                    ExportedAt = DateTimeOffset.UtcNow
                };
                _cacheStore.Save("baseline", "data", JsonSerializer.Serialize(data));
                _lastSave = DateTimeOffset.UtcNow;
            }
            catch (Exception ex) { _logger.LogWarning(ex, "[BehavioralBaseline] Save failed"); }
        }

        private void CleanupOldEntries()
        {
            var cutoff = DateTimeOffset.UtcNow.AddDays(-7);
            foreach (var k in _knownProcesses.Where(kv => kv.Value.LastSeen < cutoff).Select(kv => kv.Key).ToList())
                _knownProcesses.TryRemove(k, out _);
            foreach (var k in _knownExecutablePaths.Where(kv => kv.Value.LastSeen < cutoff).Select(kv => kv.Key).ToList())
                _knownExecutablePaths.TryRemove(k, out _);
            foreach (var k in _knownParentChild.Where(kv => kv.Value.LastSeen < cutoff).Select(kv => kv.Key).ToList())
                _knownParentChild.TryRemove(k, out _);
            foreach (var k in _knownNetworkDestinations.Where(kv => kv.Value.LastSeen < cutoff).Select(kv => kv.Key).ToList())
                _knownNetworkDestinations.TryRemove(k, out _);
            // v1.5.9: Clean up old detection records (allow process to re-earn established status
            // after 7 days with no new detections - covers one-time false positives)
            foreach (var k in _detectionHistory.Where(kv => kv.Value.LastDetection < cutoff).Select(kv => kv.Key).ToList())
                _detectionHistory.TryRemove(k, out _);

            // Hard caps
            if (_knownNetworkDestinations.Count > 1500)
                foreach (var k in _knownNetworkDestinations.OrderBy(kv => kv.Value.ConnectionCount).ThenBy(kv => kv.Value.LastSeen).Take(_knownNetworkDestinations.Count - 1000).Select(kv => kv.Key).ToList())
                    _knownNetworkDestinations.TryRemove(k, out _);
        }
    }

    public sealed class ProcessBehaviorProfile
    {
        public string ProcessName { get; set; } = "";
        public DateTimeOffset FirstSeen { get; set; }
        public DateTimeOffset LastSeen { get; set; }
        public int ExecutionCount { get; set; }
    }

    public sealed class PathReputation
    {
        public string Path { get; set; } = "";
        public DateTimeOffset FirstSeen { get; set; }
        public DateTimeOffset LastSeen { get; set; }
        public int ExecutionCount { get; set; }
    }

    public sealed class ParentChildRelationship
    {
        public string ParentName { get; set; } = "";
        public string ChildName { get; set; } = "";
        public DateTimeOffset FirstSeen { get; set; }
        public DateTimeOffset LastSeen { get; set; }
        public int OccurrenceCount { get; set; }
    }

    public sealed class NetworkDestination
    {
        public string ProcessName { get; set; } = "";
        public string RemoteAddress { get; set; } = "";
        public int RemotePort { get; set; }
        public DateTimeOffset FirstSeen { get; set; }
        public DateTimeOffset LastSeen { get; set; }
        public int ConnectionCount { get; set; }
    }

    public sealed class BaselineData
    {
        public List<ProcessBehaviorProfile> Processes { get; set; } = new();
        public List<PathReputation> Paths { get; set; } = new();
        public List<ParentChildRelationship> ParentChild { get; set; } = new();
        public List<NetworkDestination> NetworkDestinations { get; set; } = new();
        public DateTimeOffset ExportedAt { get; set; }
    }

    public sealed class BaselineStatistics
    {
        public int KnownProcesses { get; set; }
        public int KnownPaths { get; set; }
        public int KnownParentChild { get; set; }
        public int KnownNetworkDestinations { get; set; }
        public int EstablishedProcesses { get; set; }
        public DateTimeOffset LastUpdated { get; set; }
    }

    /// <summary>
    /// v1.5.9: Tracks detection events per process name to prevent baseline poisoning.
    /// </summary>
    public sealed class DetectionRecord
    {
        public string ProcessName { get; set; } = "";
        public DateTimeOffset FirstDetection { get; set; }
        public DateTimeOffset LastDetection { get; set; }
        public int DetectionCount { get; set; }
    }
}
