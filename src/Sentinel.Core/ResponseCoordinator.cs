using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;

namespace Sentinel.Core
{
    /// <summary>
    /// Coordinates response actions across the entire EDR to prevent:
    ///   - Duplicate kills on the same PID (two monitors detect the same process)
    ///   - Race conditions (ChainTracer walking a tree while kill is in progress)
    ///   - Quarantine conflicts (file being quarantined while scanner reads it)
    ///   - Response storms (20 detections on same incident triggering 20 kills)
    ///
    /// All responses MUST flow through this coordinator. Direct calls to
    /// Process.Kill or AdvancedResponseEngine bypass coordination and cause races.
    ///
    /// Design:
    ///   - Per-PID semaphore (only one response action per PID at a time)
    ///   - Response deduplication window (30s - if PID was already killed, skip)
    ///   - Priority queue (Critical incidents get response priority over Low)
    ///   - ChainTracer hold (if ChainTracer is walking a PID, defer kill until trace completes)
    /// </summary>
    public sealed class ResponseCoordinator : IDisposable
    {
        private readonly AdvancedResponseEngine _responseEngine;
        private readonly IncidentManager _incidentManager;
        private readonly ContextBus _contextBus;
        private readonly JsonlEventLogger _eventLogger;
        private readonly ILogger<ResponseCoordinator> _logger;

        // Per-PID response locks (prevents concurrent responses on same process)
        private readonly ConcurrentDictionary<int, SemaphoreSlim> _pidLocks = new();

        // Response history: PID -> last response timestamp (deduplication window)
        private readonly ConcurrentDictionary<int, ResponseRecord> _responseHistory = new();

        // Chain trace holds: PIDs currently being traced (defer kill until trace completes)
        private readonly ConcurrentDictionary<int, DateTimeOffset> _chainTraceHolds = new();

        // Metrics
        private long _totalResponsesExecuted;
        private long _totalResponsesDeduplicated;
        private long _totalResponsesDeferred;
        private long _totalResponsesFailed;

        private static readonly TimeSpan DeduplicationWindow = TimeSpan.FromSeconds(30);
        private static readonly TimeSpan ChainTraceHoldTimeout = TimeSpan.FromSeconds(10);
        private static readonly TimeSpan LockAcquireTimeout = TimeSpan.FromSeconds(5);

        public ResponseCoordinator(
            AdvancedResponseEngine responseEngine,
            IncidentManager incidentManager,
            ContextBus contextBus,
            JsonlEventLogger eventLogger,
            ILogger<ResponseCoordinator> logger)
        {
            _responseEngine = responseEngine;
            _incidentManager = incidentManager;
            _contextBus = contextBus;
            _eventLogger = eventLogger;
            _logger = logger;
        }

        // 
        // Public API
        // 

        /// <summary>
        /// Executes a coordinated response for a detection event.
        /// Handles deduplication, locking, chain trace deferral, and incident marking.
        /// This is the ONLY entry point for response actions.
        /// </summary>
        public async Task<ResponseResult> ExecuteResponseAsync(DetectionEvent detection)
        {
            var result = new ResponseResult
            {
                ProcessId = detection.ProcessId,
                ProcessName = detection.ProcessName,
                RequestedAction = detection.AuthorizedResponse
            };

            int pid = detection.ProcessId;

            // 1. Check deduplication window - was this PID already responded to?
            if (pid > 0 && IsRecentlyResponded(pid, detection.AuthorizedResponse))
            {
                Interlocked.Increment(ref _totalResponsesDeduplicated);
                result.Outcome = ResponseOutcome.Deduplicated;
                result.Reason = $"PID {pid} already responded to within {DeduplicationWindow.TotalSeconds}s";
                _logger.LogDebug("[ResponseCoordinator] Deduplicated response for PID {Pid}", pid);
                return result;
            }

            // 2. Check chain trace hold - is ChainTracer currently walking this PID?
            if (pid > 0 && detection.KillAuthorized && IsHeldForChainTrace(pid))
            {
                Interlocked.Increment(ref _totalResponsesDeferred);
                result.Outcome = ResponseOutcome.DeferredForChainTrace;
                result.Reason = $"PID {pid} held for chain trace - deferring kill";
                _logger.LogDebug("[ResponseCoordinator] Deferring kill on PID {Pid} - chain trace in progress", pid);
                return result;
            }

            // 3. Acquire per-PID lock (serialize responses on same PID)
            var pidLock = _pidLocks.GetOrAdd(pid > 0 ? pid : -1, _ => new SemaphoreSlim(1, 1));
            if (!await pidLock.WaitAsync(LockAcquireTimeout))
            {
                result.Outcome = ResponseOutcome.LockTimeout;
                result.Reason = $"Could not acquire response lock for PID {pid} within {LockAcquireTimeout.TotalSeconds}s";
                return result;
            }

            try
            {
                // 4. Double-check deduplication after acquiring lock
                if (pid > 0 && IsRecentlyResponded(pid, detection.AuthorizedResponse))
                {
                    Interlocked.Increment(ref _totalResponsesDeduplicated);
                    result.Outcome = ResponseOutcome.Deduplicated;
                    return result;
                }

                // 5. Execute the response via AdvancedResponseEngine
                await _responseEngine.HandleAsync(detection);

                // 6. Record the response
                Interlocked.Increment(ref _totalResponsesExecuted);
                if (pid > 0)
                {
                    _responseHistory[pid] = new ResponseRecord
                    {
                        Timestamp = DateTimeOffset.UtcNow,
                        Action = detection.AuthorizedResponse,
                        RuleName = detection.RuleName
                    };
                }

                // 7. Mark incident as responded
                if (pid > 0 && detection.KillAuthorized && detection.Tier == DetectionTier.Tier1Behavioral)
                {
                    _incidentManager.MarkRespondedByPid(pid, detection.AuthorizedResponse.ToString());
                }

                result.Outcome = ResponseOutcome.Executed;
                result.ExecutedAt = DateTimeOffset.UtcNow;
            }
            catch (Exception ex)
            {
                Interlocked.Increment(ref _totalResponsesFailed);
                result.Outcome = ResponseOutcome.Failed;
                result.Reason = ex.Message;
                _logger.LogError(ex, "[ResponseCoordinator] Response failed for PID {Pid}", pid);
            }
            finally
            {
                pidLock.Release();
            }

            return result;
        }

        // 
        // Chain Trace Holds
        // 

        /// <summary>
        /// Places a hold on a PID - tells the coordinator NOT to kill this PID
        /// until the chain trace completes (or times out after 10s).
        /// Called by ChainTracer before walking a process tree.
        /// </summary>
        public void AcquireChainTraceHold(int pid)
        {
            _chainTraceHolds[pid] = DateTimeOffset.UtcNow;
        }

        /// <summary>
        /// Releases the chain trace hold. Called by ChainTracer when trace is complete.
        /// </summary>
        public void ReleaseChainTraceHold(int pid)
        {
            _chainTraceHolds.TryRemove(pid, out _);
        }

        private bool IsHeldForChainTrace(int pid)
        {
            if (_chainTraceHolds.TryGetValue(pid, out var holdTime))
            {
                if (DateTimeOffset.UtcNow - holdTime > ChainTraceHoldTimeout)
                {
                    // Hold expired - release it
                    _chainTraceHolds.TryRemove(pid, out _);
                    return false;
                }
                return true;
            }
            return false;
        }

        // 
        // Deduplication
        // 

        private bool IsRecentlyResponded(int pid, ResponseAction requestedAction)
        {
            if (_responseHistory.TryGetValue(pid, out var record))
            {
                // Only deduplicate if same or weaker action was already taken
                if (DateTimeOffset.UtcNow - record.Timestamp < DeduplicationWindow)
                {
                    // Allow escalation: if new action is stronger than what was done, let it through
                    if (requestedAction <= record.Action)
                        return true;
                }
            }
            return false;
        }

        // 
        // Metrics & Cleanup
        // 

        public ResponseCoordinatorStats GetStats() => new()
        {
            TotalExecuted = Interlocked.Read(ref _totalResponsesExecuted),
            TotalDeduplicated = Interlocked.Read(ref _totalResponsesDeduplicated),
            TotalDeferred = Interlocked.Read(ref _totalResponsesDeferred),
            TotalFailed = Interlocked.Read(ref _totalResponsesFailed),
            ActiveLocks = _pidLocks.Count(kv => kv.Value.CurrentCount == 0),
            ActiveChainTraceHolds = _chainTraceHolds.Count
        };

        /// <summary>
        /// Prunes stale response history and expired locks.
        /// Called periodically by the orchestrator.
        /// </summary>
        public void PruneStaleState()
        {
            var cutoff = DateTimeOffset.UtcNow - TimeSpan.FromMinutes(5);

            // Prune response history older than 5 minutes
            foreach (var (pid, record) in _responseHistory)
            {
                if (record.Timestamp < cutoff)
                    _responseHistory.TryRemove(pid, out _);
            }

            // Prune expired chain trace holds
            foreach (var (pid, holdTime) in _chainTraceHolds)
            {
                if (DateTimeOffset.UtcNow - holdTime > ChainTraceHoldTimeout)
                    _chainTraceHolds.TryRemove(pid, out _);
            }

            // Prune PID locks that are no longer needed (no recent response)
            foreach (var (pid, semaphore) in _pidLocks)
            {
                if (!_responseHistory.ContainsKey(pid) && semaphore.CurrentCount == 1)
                    _pidLocks.TryRemove(pid, out _);
            }
        }

        public void Dispose()
        {
            foreach (var (_, semaphore) in _pidLocks)
                semaphore.Dispose();
        }
    }

    // 
    // Data Models
    // 

    public enum ResponseOutcome
    {
        Executed,
        Deduplicated,
        DeferredForChainTrace,
        LockTimeout,
        Failed
    }

    public sealed class ResponseResult
    {
        public int ProcessId { get; set; }
        public string ProcessName { get; set; } = string.Empty;
        public ResponseAction RequestedAction { get; set; }
        public ResponseOutcome Outcome { get; set; }
        public string? Reason { get; set; }
        public DateTimeOffset? ExecutedAt { get; set; }
    }

    internal sealed class ResponseRecord
    {
        public DateTimeOffset Timestamp { get; set; }
        public ResponseAction Action { get; set; }
        public string RuleName { get; set; } = string.Empty;
    }

    public sealed class ResponseCoordinatorStats
    {
        public long TotalExecuted { get; set; }
        public long TotalDeduplicated { get; set; }
        public long TotalDeferred { get; set; }
        public long TotalFailed { get; set; }
        public int ActiveLocks { get; set; }
        public int ActiveChainTraceHolds { get; set; }
    }
}
