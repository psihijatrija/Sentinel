using System;
using System.Collections.Generic;
using System.IO;
using System.Text.Json;

namespace Sentinel.Core
{
    /// <summary>
    /// Reboot-durable baseline for state reconciliation (drift detection).
    ///
    /// Persisted as plain <see cref="System.Text.Json"/> under
    /// <c>%ProgramData%\Sentinel\baseline\module_baseline.json</c> - deliberately NOT
    /// <see cref="SecureCacheStore"/>, whose HMAC key is boot-bound and would invalidate the
    /// baseline on every reboot (re-flagging every module as "new"). A baseline must survive
    /// reboots to be meaningful, so tamper-resistance here is the SYSTEM+Admins directory ACL,
    /// same as the other ProgramData surfaces.
    /// </summary>
    public sealed class ModuleBaselineStore
    {
        private readonly string _baselineDir;
        private readonly string _baselineFile;
        private static readonly JsonSerializerOptions JsonOpts = new()
        {
            PropertyNameCaseInsensitive = true,
            WriteIndented = false,
        };

        public ModuleBaselineStore(string? customPath = null)
        {
            if (!string.IsNullOrWhiteSpace(customPath))
            {
                _baselineDir = customPath!;
            }
            else
            {
                var programData = Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData);
                _baselineDir = Path.Combine(programData, "Sentinel", "baseline");
            }
            _baselineFile = Path.Combine(_baselineDir, "module_baseline.json");

            try
            {
                if (!Directory.Exists(_baselineDir))
                    Directory.CreateDirectory(_baselineDir);
                // Lock to SYSTEM+Admins in production only (mirrors SecureCacheStore behavior).
                if (string.IsNullOrWhiteSpace(customPath))
                    SecureCacheStore.TryLockDirectoryAcl(_baselineDir);
            }
            catch
            {
                // Degrade gracefully - reconciliation still works in-memory this session.
            }
        }

        public string BaselineFilePath => _baselineFile;

        /// <summary>
        /// Loads the persisted baseline. Returns an EMPTY snapshot (learn mode) if the file is
        /// missing or unreadable - the reconciler treats the first snapshot as the baseline and
        /// emits nothing on that pass.
        /// </summary>
        public ModuleBaselineSnapshot Load()
        {
            try
            {
                if (!File.Exists(_baselineFile))
                    return new ModuleBaselineSnapshot();
                var json = File.ReadAllText(_baselineFile);
                if (string.IsNullOrWhiteSpace(json))
                    return new ModuleBaselineSnapshot();
                var snap = JsonSerializer.Deserialize<ModuleBaselineSnapshot>(json, JsonOpts);
                return snap ?? new ModuleBaselineSnapshot();
            }
            catch
            {
                // Corrupt/unreadable baseline -> learn mode. Never throw.
                return new ModuleBaselineSnapshot();
            }
        }

        /// <summary>Best-effort compatibility entry point.</summary>
        public void Save(ModuleBaselineSnapshot snapshot) => TrySave(snapshot);

        /// <summary>Durably replace a baseline without deleting the last valid copy first.</summary>
        public bool TrySave(ModuleBaselineSnapshot snapshot)
        {
            if (snapshot == null) return false;
            try
            {
                Directory.CreateDirectory(_baselineDir);
                var bytes = System.Text.Encoding.UTF8.GetBytes(JsonSerializer.Serialize(snapshot, JsonOpts));
                var tmp = _baselineFile + ".tmp";
                using (var stream = new FileStream(tmp, FileMode.Create, FileAccess.Write, FileShare.Read | FileShare.Delete))
                {
                    stream.Write(bytes, 0, bytes.Length);
                    stream.Flush(flushToDisk: true);
                }
                if (File.Exists(_baselineFile)) File.Replace(tmp, _baselineFile, null);
                else File.Move(tmp, _baselineFile);
                return true;
            }
            catch (Exception ex)
            {
                System.Diagnostics.Trace.TraceWarning("Module baseline persistence failed: {0}", ex.Message);
                return false;
            }
        }

    }

    /// <summary>
    /// Serializable baseline state for module reconciliation. Uses <see cref="List{T}"/>-friendly
    /// collections that round-trip cleanly through System.Text.Json.
    /// </summary>
    public sealed class ModuleBaselineSnapshot
    {
        public int SchemaVersion { get; set; } = 1;

        /// <summary>Process name (lowercased, no extension) -> set of normalized module identities.</summary>
        public Dictionary<string, HashSet<string>> ModulesByProcess { get; set; } =
            new(StringComparer.OrdinalIgnoreCase);

        /// <summary>Authenticode signer CN (lowercased) -> first-seen UTC on THIS machine.</summary>
        public Dictionary<string, DateTime> KnownPublishers { get; set; } =
            new(StringComparer.OrdinalIgnoreCase);

        /// <summary>Normalized module identity -> "unexplained since" UTC (durable review ledger).</summary>
        public Dictionary<string, DateTime> UnexplainedSince { get; set; } =
            new(StringComparer.OrdinalIgnoreCase);

        public bool NeedsAttribution(string processName, string identity) =>
            !ModulesFor(processName).Contains(identity) || UnexplainedSince.ContainsKey(identity);

        public HashSet<string> ModulesFor(string processName)
        {
            if (!ModulesByProcess.TryGetValue(processName, out var set))
            {
                set = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                ModulesByProcess[processName] = set;
            }
            return set;
        }
    }
}
