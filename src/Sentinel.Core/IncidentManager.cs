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
    /// Groups related detections into unified incidents with lifecycle management.
    ///
    /// Problem solved: Previously, 5 detections on the same PID were 5 independent log entries.
    /// Now they're grouped into a single Incident with escalating severity, timeline,
    /// and coordinated response. This is how real EDRs present threats to analysts.
    ///
    /// Grouping logic:
    ///   - Same PID within 5 minutes -> same incident
    ///   - Parent-child PIDs (via ProcessAncestryCache) -> same incident
    ///   - Same SHA-256 hash across different PIDs -> same incident (reinfection)
    ///
    /// Lifecycle: Open -> Active -> Responded -> Closed
    ///   - Open: First detection received, investigation window starts
    ///   - Active: Multiple detections corroborating, severity escalating
    ///   - Responded: Requested response effects verified
    ///   - Closed: Incident resolved (process dead, no reinfection within 5 min)
    /// </summary>
    public sealed class IncidentManager : IDisposable
    {
        private readonly ProcessAncestryCache _ancestryCache;
        private readonly JsonlEventLogger _eventLogger;
        private readonly ILogger<IncidentManager> _logger;
        private readonly System.Threading.Timer _lifecycleTimer;

        private readonly ConcurrentDictionary<string, Incident> _activeIncidents = new();
        private readonly ConcurrentDictionary<int, string> _pidToIncident = new(); // PID -> IncidentId
        private long _incidentCounter;

        private static readonly TimeSpan GroupingWindow = TimeSpan.FromMinutes(5);
        private static readonly TimeSpan AutoCloseDelay = TimeSpan.FromMinutes(5);
        private static readonly TimeSpan LifecycleTickInterval = TimeSpan.FromSeconds(10);

        public IncidentManager(
            ProcessAncestryCache ancestryCache,
            JsonlEventLogger eventLogger,
            ILogger<IncidentManager> logger)
        {
            _ancestryCache = ancestryCache;
            _eventLogger = eventLogger;
            _logger = logger;
            _lifecycleTimer = new System.Threading.Timer(ProcessLifecycles, null, LifecycleTickInterval, LifecycleTickInterval);
        }

        /// <summary>
        /// Registers a detection event - either creates a new incident or adds to an existing one.
        /// Returns the incident this detection was assigned to.
        /// </summary>
        public Incident RegisterDetection(DetectionEvent detection)
        {
            var incidentId = FindOrCreateIncident(detection);
            var incident = _activeIncidents[incidentId];

            lock (incident)
            {
                if (detection.RecordedExecution == null && detection.Tier == DetectionTier.Tier1Behavioral &&
                    detection.AuthorizedResponse != ResponseAction.LogOnly)
                    incident.LastActionableDetectionAt = DateTimeOffset.UtcNow;
                incident.Detections.Add(new IncidentDetection
                {
                    DetectionEvent = detection,
                    ReceivedAt = DateTimeOffset.UtcNow
                });

                // Escalate severity based on detection count and confidence
                EscalateSeverity(incident);

                // Fresh actionable evidence reopens a previously responded incident. An old
                // verified action is not proof that a newly observed threat remains contained.
                if (incident.State == IncidentState.Responded && detection.Tier == DetectionTier.Tier1Behavioral &&
                    detection.AuthorizedResponse != ResponseAction.LogOnly)
                {
                    incident.State = IncidentState.Active;
                    incident.LastStateChange = DateTimeOffset.UtcNow;
                    incident.ResponseAction = null;
                    incident.RespondedAt = null;
                    incident.LastResponse = null;
                    incident.ResponseStatus = ResponseExecutionStatus.NotRequested;
                }

                // Transition state if needed
                if (incident.State == IncidentState.Open && incident.Detections.Count >= 2)
                {
                    incident.State = IncidentState.Active;
                    incident.LastStateChange = DateTimeOffset.UtcNow;
                }

                incident.LastActivity = DateTimeOffset.UtcNow;
            }

            _logger.LogDebug(
                "[IncidentManager] Detection '{Rule}' on PID {Pid} -> Incident {Id} (state={State}, severity={Severity}, detections={Count})",
                detection.RuleName, detection.ProcessId, incidentId, incident.State, incident.Severity, incident.Detections.Count);

            return incident;
        }

        /// <summary>Record an outcome without confusing attempted effects with completed response.</summary>
        public void RecordResponse(string incidentId, ResponseExecutionResult execution)
        {
            if (execution.RequestedAction == nameof(ResponseAction.LogOnly)) return;
            if (!_activeIncidents.TryGetValue(incidentId, out var incident)) return;
            lock (incident)
            {
                incident.ResponseAttempts.Add(execution);
                if (incident.ResponseAttempts.Count > 16) incident.ResponseAttempts.RemoveAt(0);
                var receiptTime = execution.CompletedAt ?? execution.StartedAt;
                if (incident.LastActionableDetectionAt > receiptTime ||
                    (incident.LastResponse != null &&
                     (incident.LastResponse.CompletedAt ?? incident.LastResponse.StartedAt) > receiptTime))
                    return; // Late inline receipts cannot erase newer unresolved evidence/outcomes.
                incident.LastResponse = execution;
                incident.ResponseStatus = execution.Status;
                incident.LastActivity = DateTimeOffset.UtcNow;
                incident.LastStateChange = DateTimeOffset.UtcNow;
                if (execution.VerifiesRequestedAction)
                {
                    incident.State = IncidentState.Responded;
                    incident.ResponseAction = execution.EffectiveAction;
                    incident.RespondedAt = execution.CompletedAt ?? DateTimeOffset.UtcNow;
                }
                else if (execution.RequestedAction != nameof(ResponseAction.LogOnly))
                {
                    // A new incomplete response supersedes any previous completion claim.
                    incident.State = IncidentState.Active;
                    incident.ResponseAction = null;
                    incident.RespondedAt = null;
                }
            }
        }

        public void RecordResponseByPid(int pid, ResponseExecutionResult execution)
        {
            if (_pidToIncident.TryGetValue(pid, out var incidentId)) RecordResponse(incidentId, execution);
        }

        /// <summary>
        /// Gets the current incident for a PID, or null if no active incident.
        /// Used by ResponseEngine to check if a response is already in progress.
        /// </summary>
        public Incident? GetIncidentForPid(int pid)
        {
            if (_pidToIncident.TryGetValue(pid, out var id) && _activeIncidents.TryGetValue(id, out var inc))
                return inc;
            return null;
        }

        /// <summary>
        /// Returns all currently active (non-closed) incidents for monitoring/health display.
        /// </summary>
        public IReadOnlyList<Incident> GetActiveIncidents()
        {
            return _activeIncidents.Values
                .Where(i => i.State != IncidentState.Closed)
                .OrderByDescending(i => i.Severity)
                .ThenByDescending(i => i.LastActivity)
                .ToList();
        }

        public IncidentStats GetStats() => new()
        {
            TotalCreated = _incidentCounter,
            ActiveCount = _activeIncidents.Count(i => i.Value.State != IncidentState.Closed),
            RespondedCount = _activeIncidents.Count(i => i.Value.State == IncidentState.Responded),
            ClosedCount = _activeIncidents.Count(i => i.Value.State == IncidentState.Closed)
        };

        // 
        // Grouping Logic
        // 

        private string FindOrCreateIncident(DetectionEvent detection)
        {
            int pid = detection.ProcessId;

            // 1. Check if this PID already has an active incident
            if (pid > 0 && _pidToIncident.TryGetValue(pid, out var existingId))
            {
                if (_activeIncidents.TryGetValue(existingId, out var existing) &&
                    existing.State != IncidentState.Closed &&
                    DateTimeOffset.UtcNow - existing.LastActivity < GroupingWindow)
                {
                    return existingId;
                }
            }

            // 2. Check if parent PID has an active incident (process tree grouping)
            if (pid > 0)
            {
                var (parentPid, _) = _ancestryCache.GetParent(pid);
                if (parentPid > 0 && _pidToIncident.TryGetValue(parentPid, out var parentIncId))
                {
                    if (_activeIncidents.TryGetValue(parentIncId, out var parentInc) &&
                        parentInc.State != IncidentState.Closed &&
                        DateTimeOffset.UtcNow - parentInc.LastActivity < GroupingWindow)
                    {
                        // Add this PID to parent's incident
                        _pidToIncident[pid] = parentIncId;
                        lock (parentInc) { parentInc.InvolvedPids.Add(pid); }
                        return parentIncId;
                    }
                }
            }

            // 3. Check if same hash has an active incident (reinfection grouping)
            if (detection.Metadata.TryGetValue("SHA256", out var hash) && !string.IsNullOrEmpty(hash))
            {
                var hashIncident = _activeIncidents.Values.FirstOrDefault(i =>
                    i.State != IncidentState.Closed &&
                    i.Hashes.Contains(hash) &&
                    DateTimeOffset.UtcNow - i.LastActivity < GroupingWindow);

                if (hashIncident != null)
                {
                    if (pid > 0) { _pidToIncident[pid] = hashIncident.Id; }
                    lock (hashIncident)
                    {
                        hashIncident.InvolvedPids.Add(pid);
                        hashIncident.IsReinfection = true;
                    }
                    return hashIncident.Id;
                }
            }

            // 4. Create new incident
            var newId = $"INC-{Interlocked.Increment(ref _incidentCounter):D6}";
            var newIncident = new Incident
            {
                Id = newId,
                CreatedAt = DateTimeOffset.UtcNow,
                LastActivity = DateTimeOffset.UtcNow,
                LastStateChange = DateTimeOffset.UtcNow,
                State = IncidentState.Open,
                PrimaryPid = pid,
                PrimaryProcessName = detection.ProcessName
            };
            newIncident.InvolvedPids.Add(pid);

            if (detection.Metadata.TryGetValue("SHA256", out var newHash) && !string.IsNullOrEmpty(newHash))
                newIncident.Hashes.Add(newHash);

            _activeIncidents[newId] = newIncident;
            if (pid > 0) _pidToIncident[pid] = newId;

            _ = _eventLogger.LogEventAsync("incident_created", new
            {
                IncidentId = newId,
                PrimaryPid = pid,
                ProcessName = detection.ProcessName,
                TriggeringRule = detection.RuleName,
                Timestamp = DateTimeOffset.UtcNow
            });

            return newId;
        }

        // 
        // Severity Escalation
        // 

        private static void EscalateSeverity(Incident incident)
        {
            var detections = incident.Detections;
            int tier1Count = detections.Count(d => d.DetectionEvent.Tier == DetectionTier.Tier1Behavioral);
            int totalCount = detections.Count;
            double maxConfidence = detections.Max(d => d.DetectionEvent.Confidence);
            int distinctRules = detections.Select(d => d.DetectionEvent.RuleName).Distinct().Count();

            // Escalation rules:
            // Critical: 3+ Tier1 detections OR max confidence >= 0.95 OR composite/chain detection
            // High: 2+ Tier1 OR max confidence >= 0.80 OR reinfection
            // Medium: 1 Tier1 OR 3+ Tier2 indicators
            // Low: 1-2 Tier2 indicators only
            if (tier1Count >= 3 || maxConfidence >= 0.95 || incident.IsReinfection && tier1Count >= 2)
            {
                incident.Severity = IncidentSeverity.Critical;
            }
            else if (tier1Count >= 2 || maxConfidence >= 0.80 || incident.IsReinfection)
            {
                incident.Severity = IncidentSeverity.High;
            }
            else if (tier1Count >= 1 || totalCount >= 3)
            {
                incident.Severity = IncidentSeverity.Medium;
            }
            else
            {
                incident.Severity = IncidentSeverity.Low;
            }
        }

        // 
        // Lifecycle Management
        // 

        private void ProcessLifecycles(object? state)
            => ProcessLifecyclesAt(DateTimeOffset.UtcNow);

        internal void ProcessLifecyclesAt(DateTimeOffset now)
        {
            var toClose = new List<string>();

            foreach (var (id, incident) in _activeIncidents)
            {
                lock (incident)
                {
                    // Auto-close responded incidents after 5 minutes of inactivity
                    if (incident.State == IncidentState.Responded &&
                        now - incident.LastActivity > AutoCloseDelay)
                    {
                        incident.State = IncidentState.Closed;
                        incident.ClosedAt = now;
                        incident.LastStateChange = now;
                        toClose.Add(id);
                    }

                    // Inactivity is not proof that an actionable detection was resolved.
                    // A missing receipt must remain visible just like a failed response.
                    if ((incident.State == IncidentState.Open || incident.State == IncidentState.Active) &&
                        now - incident.LastActivity > TimeSpan.FromMinutes(10) &&
                        incident.LastActionableDetectionAt == null &&
                        (incident.LastResponse == null || incident.LastResponse.RequestedAction == nameof(ResponseAction.LogOnly)))
                    {
                        incident.State = IncidentState.Closed;
                        incident.ClosedAt = now;
                        incident.LastStateChange = now;
                        incident.ResponseAction = "AutoClosed (stale)";
                        toClose.Add(id);
                    }
                }
            }

            // Log closed incidents and clean up PID mappings
            foreach (var id in toClose)
            {
                if (_activeIncidents.TryGetValue(id, out var closed))
                {
                    _ = _eventLogger.LogEventAsync("incident_closed", new
                    {
                        IncidentId = id,
                        closed.Severity,
                        closed.State,
                        closed.ResponseAction,
                        DetectionCount = closed.Detections.Count,
                        Duration = (closed.ClosedAt ?? now) - closed.CreatedAt,
                        closed.IsReinfection
                    });

                    // Remove PID mappings for closed incident
                    foreach (var pid in closed.InvolvedPids)
                    {
                        // A newer incident may already own this PID. Remove only the
                        // exact mapping being closed, atomically with the value check.
                        ((ICollection<KeyValuePair<int, string>>)_pidToIncident)
                            .Remove(new KeyValuePair<int, string>(pid, id));
                    }
                }

                // Remove from active after 30 minutes (keep for querying)
                // Actually keep in memory for now - prune separately
            }

            // Prune incidents closed more than 30 minutes ago
            var pruneThreshold = now - TimeSpan.FromMinutes(30);
            foreach (var (id, inc) in _activeIncidents)
            {
                if (inc.State == IncidentState.Closed && inc.ClosedAt < pruneThreshold)
                {
                    _activeIncidents.TryRemove(id, out _);
                }
            }
        }

        public void Dispose()
        {
            _lifecycleTimer.Dispose();
        }
    }

    // 
    // Data Models
    // 

    public enum IncidentState
    {
        Open,       // First detection received
        Active,     // Multiple detections corroborating
        Responded,  // Requested response effects verified
        Closed      // Resolved, no reinfection
    }

    public enum IncidentSeverity
    {
        Low,
        Medium,
        High,
        Critical
    }

    public sealed class Incident
    {
        public string Id { get; set; } = "";
        public IncidentState State { get; set; } = IncidentState.Open;
        public IncidentSeverity Severity { get; set; } = IncidentSeverity.Low;
        public DateTimeOffset CreatedAt { get; set; }
        public DateTimeOffset LastActivity { get; set; }
        public DateTimeOffset LastStateChange { get; set; }
        public DateTimeOffset? RespondedAt { get; set; }
        public DateTimeOffset? ClosedAt { get; set; }
        public int PrimaryPid { get; set; }
        public string PrimaryProcessName { get; set; } = "";
        public string? ResponseAction { get; set; }
        public ResponseExecutionStatus ResponseStatus { get; set; } = ResponseExecutionStatus.NotRequested;
        public ResponseExecutionResult? LastResponse { get; set; }
        public DateTimeOffset? LastActionableDetectionAt { get; set; }
        public List<ResponseExecutionResult> ResponseAttempts { get; set; } = new();
        public bool IsReinfection { get; set; }
        public HashSet<int> InvolvedPids { get; set; } = new();
        public HashSet<string> Hashes { get; set; } = new(StringComparer.OrdinalIgnoreCase);
        public List<IncidentDetection> Detections { get; set; } = new();
    }

    public sealed class IncidentDetection
    {
        public DetectionEvent DetectionEvent { get; set; } = null!;
        public DateTimeOffset ReceivedAt { get; set; }
    }

    public sealed class IncidentStats
    {
        public long TotalCreated { get; set; }
        public int ActiveCount { get; set; }
        public int RespondedCount { get; set; }
        public int ClosedCount { get; set; }
    }
}
