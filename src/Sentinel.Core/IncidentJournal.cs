using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.Json;
using System.Threading;
using Microsoft.Extensions.Logging;

namespace Sentinel.Core
{
    /// <summary>
    /// Write-ahead journal for incident state transitions.
    ///
    /// Problem: BehavioralCorrelationEngine and WeightedCorrelationEngine hold all
    /// in-progress chain state in memory. A service crash mid-confirmation silently
    /// loses the chain — no one knows a kill was pending, and the evidence window
    /// closes. An attacker who can crash the service can erase a pending kill decision.
    ///
    /// Solution: each incident is journaled atomically to disk as it transitions states.
    /// On restart, open journals are surfaced as Tier2/LogOnly
    /// "Incident: Interrupted Chain Recovered" detections so the operator knows the
    /// service died mid-chain. Sealed journals become part of the evidence pack.
    ///
    /// States: Seeding → Confirming → Sealed(Executed|Abandoned|Interrupted)
    ///
    /// Note: JournalState is distinct from IncidentManager.IncidentState
    /// (Open/Active/Responded/Closed), which tracks the in-memory incident manager.
    /// </summary>
    public sealed class IncidentJournal : IDisposable
    {
        private readonly string _directory;
        private readonly ILogger<IncidentJournal>? _logger;
        private readonly object _gate = new();

        public static readonly string JournalDirectory = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
            "Sentinel", "Incidents");

        public IncidentJournal(string? customDirectory = null, ILogger<IncidentJournal>? logger = null)
        {
            _directory = customDirectory ?? JournalDirectory;
            _logger = logger;
            Directory.CreateDirectory(_directory);
            if (customDirectory == null) SecureCacheStore.TryLockDirectoryAcl(_directory);
        }

        /// <summary>
        /// Open a new incident journal. Returns the journal path for further transitions.
        /// </summary>
        public string Open(IncidentRecord record, CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (string.IsNullOrEmpty(record.IncidentId)) throw new ArgumentException("IncidentId is required.");
            record.JournalState = JournalState.Seeding;
            record.LastUpdatedUtc = DateTimeOffset.UtcNow;
            var path = JournalPath(record.IncidentId);
            WriteRecord(path, record);
            _logger?.LogDebug("[IncidentJournal] Opened {Id} for PID {Pid} ({Process})",
                record.IncidentId, record.TargetPid, record.TargetProcess);
            return path;
        }

        /// <summary>Transition to Confirming — multi-signal chain threshold met.</summary>
        public void Confirm(string journalPath, IReadOnlyList<string> chainedRuleNames,
            ResponseAction pendingResponse, CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var record = LoadRecord(journalPath);
            record.JournalState = JournalState.Confirming;
            record.ChainedRuleNames = chainedRuleNames.ToList();
            record.PendingResponse = pendingResponse.ToString();
            record.LastUpdatedUtc = DateTimeOffset.UtcNow;
            WriteRecord(journalPath, record);
            _logger?.LogDebug("[IncidentJournal] Confirmed {Id}: {Rules}",
                record.IncidentId, string.Join(", ", chainedRuleNames));
        }

        /// <summary>Seal as Executed — response was carried out.</summary>
        public void SealExecuted(string journalPath, ResponseAction authorizedResponse,
            CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            Seal(journalPath, JournalState.SealedExecuted, authorizedResponse.ToString());
        }

        /// <summary>Seal as Abandoned — chain window expired without confirmation.</summary>
        public void SealAbandoned(string journalPath, CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            Seal(journalPath, JournalState.SealedAbandoned, null);
        }

        private void Seal(string journalPath, JournalState state, string? authorizedResponse)
        {
            var record = LoadRecord(journalPath);
            record.JournalState = state;
            if (authorizedResponse != null) record.AuthorizedResponse = authorizedResponse;
            record.SealedUtc = DateTimeOffset.UtcNow;
            record.LastUpdatedUtc = DateTimeOffset.UtcNow;
            WriteRecord(journalPath, record);
            _logger?.LogDebug("[IncidentJournal] Sealed {Id} as {State}", record.IncidentId, state);
        }

        /// <summary>
        /// On service restart: find all unsealed journals and return them for recovery.
        /// Each unsealed journal represents a chain interrupted by a crash.
        /// </summary>
        public static IReadOnlyList<IncidentRecord> RecoverOpenJournals(string? customDirectory = null)
        {
            var directory = customDirectory ?? JournalDirectory;
            if (!Directory.Exists(directory)) return Array.Empty<IncidentRecord>();
            var open = new List<IncidentRecord>();
            foreach (var file in Directory.GetFiles(directory, "incident-*.json"))
            {
                try
                {
                    using var stream = new FileStream(file, FileMode.Open, FileAccess.Read,
                        FileShare.ReadWrite | FileShare.Delete);
                    var record = JsonSerializer.Deserialize<IncidentRecord>(stream);
                    if (record == null) continue;
                    if (record.JournalState == JournalState.Seeding ||
                        record.JournalState == JournalState.Confirming)
                    {
                        record.JournalState = JournalState.SealedInterrupted;
                        record.SealedUtc = DateTimeOffset.UtcNow;
                        record.LastUpdatedUtc = DateTimeOffset.UtcNow;
                        var bytes = Encoding.UTF8.GetBytes(JsonSerializer.Serialize(record));
                        var tmp = file + ".tmp";
                        File.WriteAllBytes(tmp, bytes);
                        if (File.Exists(file)) File.Replace(tmp, file, null);
                        else File.Move(tmp, file);
                        open.Add(record);
                    }
                }
                catch { /* corrupt/partial journal; skip */ }
            }
            return open;
        }

        /// <summary>
        /// Load all sealed journals for evidence pack inclusion.
        /// Capped at maxRecords to avoid unbounded reads.
        /// </summary>
        public static IReadOnlyList<IncidentRecord> LoadSealed(string? customDirectory = null, int maxRecords = 100)
        {
            var directory = customDirectory ?? JournalDirectory;
            if (!Directory.Exists(directory)) return Array.Empty<IncidentRecord>();
            var records = new List<IncidentRecord>();
            foreach (var file in Directory.GetFiles(directory, "incident-*.json")
                .OrderByDescending(f => f))
            {
                if (records.Count >= maxRecords) break;
                try
                {
                    using var stream = new FileStream(file, FileMode.Open, FileAccess.Read,
                        FileShare.ReadWrite | FileShare.Delete);
                    var record = JsonSerializer.Deserialize<IncidentRecord>(stream);
                    if (record != null && (record.JournalState == JournalState.SealedExecuted ||
                        record.JournalState == JournalState.SealedAbandoned ||
                        record.JournalState == JournalState.SealedInterrupted))
                        records.Add(record);
                }
                catch { /* skip */ }
            }
            return records;
        }

        private string JournalPath(string incidentId) =>
            Path.Combine(_directory, $"incident-{incidentId}.json");

        private void WriteRecord(string path, IncidentRecord record)
        {
            lock (_gate)
            {
                var bytes = Encoding.UTF8.GetBytes(JsonSerializer.Serialize(record));
                var tmp = path + ".tmp";
                using (var stream = new FileStream(tmp, FileMode.Create, FileAccess.Write,
                    FileShare.Read | FileShare.Delete))
                {
                    stream.Write(bytes, 0, bytes.Length);
                    stream.Flush(flushToDisk: true);
                }
                if (File.Exists(path)) File.Replace(tmp, path, null);
                else File.Move(tmp, path);
            }
        }

        private static IncidentRecord LoadRecord(string path)
        {
            using var stream = new FileStream(path, FileMode.Open, FileAccess.Read,
                FileShare.ReadWrite | FileShare.Delete);
            return JsonSerializer.Deserialize<IncidentRecord>(stream)
                ?? throw new InvalidDataException($"Null incident record at {path}.");
        }

        public void Dispose() { }
    }

    /// <summary>
    /// Journal lifecycle state for IncidentJournal write-ahead log.
    /// Distinct from IncidentManager.IncidentState (Open/Active/Responded/Closed).
    /// </summary>
    public enum JournalState
    {
        Seeding,
        Confirming,
        SealedExecuted,
        SealedAbandoned,
        SealedInterrupted
    }

    public sealed class IncidentRecord
    {
        public int SchemaVersion { get; set; } = 1;
        public string IncidentId { get; set; } = "";
        public JournalState JournalState { get; set; }
        public int TargetPid { get; set; }
        public string TargetProcess { get; set; } = "";
        public string TargetImagePath { get; set; } = "";
        public List<string> ChainedRuleNames { get; set; } = new();
        public string PendingResponse { get; set; } = "";
        public string AuthorizedResponse { get; set; } = "";
        public DateTimeOffset StartedUtc { get; set; }
        public DateTimeOffset LastUpdatedUtc { get; set; }
        public DateTimeOffset? SealedUtc { get; set; }
        /// <summary>True when recovery found this journal open on restart — implies a crash occurred.</summary>
        public bool WasInterrupted => JournalState == JournalState.SealedInterrupted;
    }
}
