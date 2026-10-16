using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.Json;

namespace Sentinel.Core
{
    public enum DllFileOutcome { Failed, Quarantined, Deferred, AlreadyAbsent }

    public sealed class DllUnloadResult
    {
        private readonly Dictionary<string, DllFileOutcome> _files = new(StringComparer.OrdinalIgnoreCase);
        public int ProcessId { get; set; }
        public string ProcessName { get; set; } = "";
        public List<string> DetectedDlls { get; } = new();
        public ProcessTreeTerminationResult? Containment { get; internal set; }
        public List<ProcessTreeTerminationResult> Containments { get; } = new();
        public IReadOnlyDictionary<string, DllFileOutcome> FileOutcomes => _files;
        public IReadOnlyList<string> QuarantinedDlls => FilesWith(DllFileOutcome.Quarantined);
        public IReadOnlyList<string> DeferredDlls => FilesWith(DllFileOutcome.Deferred);
        public IReadOnlyList<string> AbsentDlls => FilesWith(DllFileOutcome.AlreadyAbsent);
        public IReadOnlyList<string> FailedDlls => FilesWith(DllFileOutcome.Failed);
        private IEnumerable<ProcessTreeTerminationResult> AllContainments => Containment == null
            ? Containments : Containments.Concat(new[] { Containment });
        public bool HostContained => AllContainments.Any() && AllContainments.All(c => c.Success);
        public bool Success => _files.Count > 0 &&
            DetectedDlls.All(path => _files.ContainsKey(path)) &&
            _files.Values.All(v => v == DllFileOutcome.Quarantined || v == DllFileOutcome.AlreadyAbsent) &&
            AllContainments.All(c => c.Success);
        public string ContainmentSummary => $"HostContained={HostContained}; " +
            $"quarantined={QuarantinedDlls.Count}; alreadyAbsent={AbsentDlls.Count}; " +
            $"deferred={DeferredDlls.Count}; failed={FailedDlls.Count}; " +
            $"processOutcomes={JsonSerializer.Serialize(AllContainments.ToArray())}";

        internal void RecordFileOutcome(string path, DllFileOutcome outcome) => _files[path] = outcome;
        internal ResponseExecutionResult CreateExecutionReceipt()
        {
            string action = AllContainments.Any() ? "QuarantineAndKill" : "Quarantine";
            var receipt = new ResponseExecutionResult
            {
                ProcessId = ProcessId, ProcessName = ProcessName, RequestedAction = action, EffectiveAction = action,
                CompletedAt = DateTimeOffset.UtcNow, Reason = ContainmentSummary
            };
            foreach (var tree in AllContainments) receipt.AddProcessTree(tree);
            if (_files.Count == 0)
                receipt.Add("DllQuarantine", ProcessId.ToString(), ResponseExecutionStatus.Failed, "No file-remediation receipt was recorded.");
            foreach (var file in _files)
                receipt.Add("DllQuarantine", file.Key,
                    file.Value == DllFileOutcome.Quarantined ? ResponseExecutionStatus.Verified
                        : file.Value == DllFileOutcome.Failed ? ResponseExecutionStatus.Failed : ResponseExecutionStatus.Attempted,
                    file.Value == DllFileOutcome.AlreadyAbsent ? "Source already absent; no new vault receipt." : file.Value.ToString());
            foreach (string path in DetectedDlls.Where(path => !_files.ContainsKey(path)))
                receipt.Add("DllQuarantine", path, ResponseExecutionStatus.Failed, "File remediation was not completed.");
            return receipt;
        }
        internal void MergeFileOutcomes(DllUnloadResult other)
        {
            foreach (var file in other._files) _files[file.Key] = file.Value;
            DetectedDlls.AddRange(other.DetectedDlls);
            Containments.AddRange(other.Containments);
        }
        private IReadOnlyList<string> FilesWith(DllFileOutcome outcome)
            => _files.Where(f => f.Value == outcome).Select(f => f.Key).ToArray();

        internal Dictionary<string, string> CreateContainmentMetadata(string imagePath) => new()
        {
            ["ImagePath"] = imagePath,
            ["SideloadedDlls"] = string.Join(";", DetectedDlls),
            ["HostContained"] = HostContained.ToString(),
            ["ProcessContainment"] = JsonSerializer.Serialize(AllContainments.ToArray()),
            ["QuarantinedDlls"] = JsonSerializer.Serialize(QuarantinedDlls),
            ["DeferredDlls"] = JsonSerializer.Serialize(DeferredDlls),
            ["AbsentDlls"] = JsonSerializer.Serialize(AbsentDlls),
            ["FailedDlls"] = JsonSerializer.Serialize(FailedDlls),
            ["Phase"] = "Remediate",
            ["DllUnloadExempt"] = "true",
            ["PermanentRule"] = "ModuleIdentityUnload",
            ["AlwaysOnPolicy"] = "DllUnload"
        };
    }
}
