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
    ///   - Responded: Kill/quarantine/isolate action executed
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
        private readonly object _stateGate = new();
        private readonly IIncidentStateStore? _stateStore;
        public bool PersistenceDegraded { get; private set; }
        private bool _disposed;
        private bool _stateChanged;
        private const int MaximumDetectionsPerIncident = 256;

        private void SaveState()
        {
            if (_stateStore == null || !_stateChanged) return;
            try
            {
                _stateStore.Save(new IncidentStateSnapshot
                {
                    TotalCreated = _incidentCounter,
                    Incidents = _activeIncidents.Values.ToList()
                });
                if (PersistenceDegraded) _logger.LogInformation("Incident history persistence recovered");
                PersistenceDegraded = false;
                _stateChanged = false;
            }
            catch (Exception ex)
            {
                if (!PersistenceDegraded)
                    _logger.LogError(ex, "Incident history persistence degraded; detection remains active");
                PersistenceDegraded = true;
            }
        }

        private static readonly TimeSpan GroupingWindow = TimeSpan.FromMinutes(5);
        private static readonly TimeSpan AutoCloseDelay = TimeSpan.FromMinutes(5);
        private static readonly TimeSpan LifecycleTickInterval = TimeSpan.FromSeconds(10);

        public IncidentManager(
            ProcessAncestryCache ancestryCache,
            JsonlEventLogger eventLogger,
            ILogger<IncidentManager> logger,
            IIncidentStateStore? stateStore = null)
        {
            _ancestryCache = ancestryCache;
            _eventLogger = eventLogger;
            _logger = logger;
            _stateStore = stateStore;
            if (_stateStore != null)
            {
                try
                {
                    var snapshot = _stateStore.Load();
                    _incidentCounter = snapshot.TotalCreated;
                    foreach (var incident in snapshot.Incidents)
                    {
                        incident.RecoveredHistory = true;
                        _activeIncidents[incident.Id] = incident;
                    }
                    // Deliberately do not restore PID mappings, correlation or action authority.
                }
                catch (Exception ex)
                {
                    PersistenceDegraded = true;
                    _logger.LogError(ex, "Incident history recovery failed; prior state retained on disk");
                }
            }
            _lifecycleTimer = new System.Threading.Timer(ProcessLifecycles, null, LifecycleTickInterval, LifecycleTickInterval);
        }

        /// <summary>
        /// Registers a detection event - either creates a new incident or adds to an existing one.
        /// Returns the incident this detection was assigned to.
        /// </summary>
        public Incident RegisterDetection(DetectionEvent detection)
        {
            lock (_stateGate)
            {
                if (_disposed) throw new ObjectDisposedException(nameof(IncidentManager));
                if (detection == null) throw new ArgumentNullException(nameof(detection));
                // Detach persisted history from caller-owned mutable metadata.
                detection = System.Text.Json.JsonSerializer.Deserialize<DetectionEvent>(
                    System.Text.Json.JsonSerializer.Serialize(detection))!;
                detection.Metadata ??= new Dictionary<string, string>();
                var incidentId = FindOrCreateIncident(detection);
                var incident = _activeIncidents[incidentId];

                lock (incident)
                {
                    incident.Detections.Add(new IncidentDetection
                    {
                        DetectionEvent = detection,
                        ReceivedAt = DateTimeOffset.UtcNow
                    });

                    // Escalate severity based on detection count and confidence
                    var priorSeverity = incident.Severity;
                    EscalateSeverity(incident);
                    if (incident.Severity < priorSeverity) incident.Severity = priorSeverity;

                    incident.TotalDetectionCount++;
                    if (incident.Detections.Count > MaximumDetectionsPerIncident)
                    {
                        incident.Detections.RemoveAt(0);
                        incident.OmittedDetectionCount++;
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

                _stateChanged = true;
                SaveState();
                return incident;

            }
        }

        /// <summary>
        /// Marks an incident as responded - a kill/quarantine/isolate action was executed.
        /// </summary>
        public void MarkResponded(string incidentId, string actionTaken)
        {
            lock (_stateGate)
            {
                if (_disposed) return;
                if (_activeIncidents.TryGetValue(incidentId, out var incident) && !incident.RecoveredHistory)
                {
                    lock (incident)
                    {
                        incident.State = IncidentState.Responded;
                        incident.ResponseAction = actionTaken;
                        incident.RespondedAt = DateTimeOffset.UtcNow;
                        incident.LastStateChange = DateTimeOffset.UtcNow;
                        _stateChanged = true;
                    }
                }

                SaveState();
            }
        }

        /// <summary>
        /// Marks an incident as responded by PID (convenience for ResponseEngine which doesn't track incident IDs).
        /// </summary>
        public void MarkRespondedByPid(int pid, string actionTaken)
        {
            if (_pidToIncident.TryGetValue(pid, out var incidentId))
            {
                MarkResponded(incidentId, actionTaken);
            }
        }

        public void BeginResponseEvaluation(int pid, ResponseAction requestedAction, string? incidentId = null)
        {
            lock (_stateGate)
            {
                if (_disposed) return;
                string? id = incidentId;
                if (id == null && !_pidToIncident.TryGetValue(pid, out id)) return;
                if (!_activeIncidents.TryGetValue(id, out var incident) || incident.RecoveredHistory) return;
                incident.ResponseEvaluation = new IncidentResponseEvaluation
                {
                    Id = Guid.NewGuid().ToString("N"), RequestedAction = requestedAction,
                    StartedUtc = DateTimeOffset.UtcNow, State = "Pending"
                };
                _stateChanged = true;
                SaveState();
            }
        }

        public void CompleteResponseEvaluation(int pid, ResponseExecutionOutcome outcome, string action, string reason, string? incidentId = null)
        {
            lock (_stateGate)
            {
                if (_disposed) return;
                string? id = incidentId;
                if (id == null && !_pidToIncident.TryGetValue(pid, out id)) return;
                if (!_activeIncidents.TryGetValue(id, out var incident) || incident.RecoveredHistory) return;
                if (incident.ResponseEvaluation == null && outcome == ResponseExecutionOutcome.Observed) return;
                if (incident.ResponseEvaluation != null)
                {
                    incident.ResponseEvaluation.State = outcome.ToString();
                    incident.ResponseEvaluation.CompletedUtc = DateTimeOffset.UtcNow;
                    incident.ResponseEvaluation.Reason = reason;
                }
                incident.ResponseAction = action;
                if (outcome == ResponseExecutionOutcome.Confirmed) MarkResponded(id, action);
                _stateChanged = true;
                SaveState();
            }
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
            PersistenceDegraded = PersistenceDegraded,
            RecoveredCount = _activeIncidents.Count(i => i.Value.RecoveredHistory),
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
                    !existing.RecoveredHistory && existing.State != IncidentState.Closed &&
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
                    !i.RecoveredHistory && i.State != IncidentState.Closed &&
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
            Interlocked.Increment(ref _incidentCounter);
            var newId = "INC-" + Guid.NewGuid().ToString("N");
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
        {
            lock (_stateGate)
            {
                if (_disposed) return;
                var now = DateTimeOffset.UtcNow;
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
                            toClose.Add(id);
                        }

                        // Auto-close stale open/active incidents (no new detections in 10 minutes)
                        if ((incident.State == IncidentState.Open || incident.State == IncidentState.Active) &&
                            now - incident.LastActivity > TimeSpan.FromMinutes(10) &&
                            incident.ResponseEvaluation?.State != "Pending")
                        {
                            incident.State = IncidentState.Closed;
                            incident.ClosedAt = now;
                            incident.ClosureReason = "No recent activity; host outcome not verified";
                            toClose.Add(id);
                        }
                    }
                }

                if (toClose.Count > 0) _stateChanged = true;
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
                            DetectionCount = closed.TotalDetectionCount,
                        closed.OmittedDetectionCount, closed.ClosureReason,
                            Duration = (closed.ClosedAt ?? now) - closed.CreatedAt,
                            closed.IsReinfection
                        });

                        // Remove PID mappings for closed incident
                        foreach (var pid in closed.InvolvedPids)
                        {
                            if (_pidToIncident.TryGetValue(pid, out var mapped) && mapped == id)
                                _pidToIncident.TryRemove(pid, out _);
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
                        if (_activeIncidents.TryRemove(id, out _)) _stateChanged = true;
                    }
                }

                SaveState();
            }
        }

        public void Dispose()
        {
            _lifecycleTimer.Dispose();
            lock (_stateGate)
            {
                if (_disposed) return;
                SaveState();
                _disposed = true;
            }
        }
    }

    // 
    // Data Models
    // 

    public enum IncidentState
    {
        Open,       // First detection received
        Active,     // Multiple detections corroborating
        Responded,  // Kill/quarantine/isolate executed
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
        /// <summary>Recovered evidence only: never rebind old PIDs or replay responses.</summary>
        public bool RecoveredHistory { get; set; }
        public IncidentResponseEvaluation? ResponseEvaluation { get; set; }
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
        public string? ClosureReason { get; set; }
        public string? ResponseAction { get; set; }
        public bool IsReinfection { get; set; }
        public HashSet<int> InvolvedPids { get; set; } = new();
        public HashSet<string> Hashes { get; set; } = new(StringComparer.OrdinalIgnoreCase);
        public long TotalDetectionCount { get; set; }
        public long OmittedDetectionCount { get; set; }
        public List<IncidentDetection> Detections { get; set; } = new();
    }

    public sealed class IncidentResponseEvaluation
    {
        public string Id { get; set; } = "";
        public ResponseAction RequestedAction { get; set; }
        public DateTimeOffset StartedUtc { get; set; }
        public DateTimeOffset? CompletedUtc { get; set; }
        public string State { get; set; } = "Pending";
        public string? Reason { get; set; }
    }

    public sealed class IncidentDetection
    {
        public DetectionEvent DetectionEvent { get; set; } = null!;
        public DateTimeOffset ReceivedAt { get; set; }
    }

    public sealed class IncidentStats
    {
        public bool PersistenceDegraded { get; set; }
        public int RecoveredCount { get; set; }
        public long TotalCreated { get; set; }
        public int ActiveCount { get; set; }
        public int RespondedCount { get; set; }
        public int ClosedCount { get; set; }
    }
}
