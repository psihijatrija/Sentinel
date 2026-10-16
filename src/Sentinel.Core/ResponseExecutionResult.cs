using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.Json.Serialization;

namespace Sentinel.Core
{
    [JsonConverter(typeof(JsonStringEnumConverter))]
    public enum ResponseExecutionStatus
    {
        NotRequested, Refused, Attempted, Failed, PartiallyCompleted, Verified
    }

    public sealed class ResponseEffect
    {
        public string Action { get; set; } = "";
        public string Target { get; set; } = "";
        public ResponseExecutionStatus Status { get; set; } = ResponseExecutionStatus.Attempted;
        public string Detail { get; set; } = "";
    }

    /// <summary>Evidence of effects, independent of the requested action or normal task completion.</summary>
    public sealed class ResponseExecutionResult
    {
        public string ExecutionId { get; set; } = Guid.NewGuid().ToString("N");
        public int ProcessId { get; set; }
        public string ProcessName { get; set; } = "";
        public string RequestedAction { get; set; } = "LogOnly";
        public string EffectiveAction { get; set; } = "LogOnly";
        public string Reason { get; set; } = "No authorized action was executed.";
        public DateTimeOffset StartedAt { get; set; } = DateTimeOffset.UtcNow;
        public DateTimeOffset? CompletedAt { get; set; }
        public List<ResponseEffect> Effects { get; } = new();
        public ResponseExecutionStatus Status
        {
            get
            {
                if (Effects.Count == 0)
                    return RequestedAction == "LogOnly" ? ResponseExecutionStatus.NotRequested : ResponseExecutionStatus.Refused;
                if (Effects.All(e => e.Status == ResponseExecutionStatus.Verified))
                    return !CompletedAt.HasValue ? ResponseExecutionStatus.Attempted
                        : EffectiveAction != RequestedAction || !HasRequiredEffects() ? ResponseExecutionStatus.PartiallyCompleted
                        : ResponseExecutionStatus.Verified;
                if (Effects.Any(e => e.Status == ResponseExecutionStatus.Verified || e.Status == ResponseExecutionStatus.PartiallyCompleted))
                    return ResponseExecutionStatus.PartiallyCompleted;
                if (Effects.Any(e => e.Status == ResponseExecutionStatus.Failed)) return ResponseExecutionStatus.Failed;
                if (Effects.Any(e => e.Status == ResponseExecutionStatus.Attempted)) return ResponseExecutionStatus.Attempted;
                return ResponseExecutionStatus.Refused;
            }
        }
        public bool VerifiesRequestedAction => CompletedAt.HasValue && RequestedAction != "LogOnly" &&
            EffectiveAction == RequestedAction && Status == ResponseExecutionStatus.Verified;

        public bool HasVerifiedProcessExit(int pid) => Effects.Any(e => e.Action == "ProcessTree" &&
            e.Target == pid.ToString(System.Globalization.CultureInfo.InvariantCulture) &&
            e.Status == ResponseExecutionStatus.Verified);

        private bool HasRequiredEffects()
        {
            bool Has(string action) => Effects.Any(e => e.Action == action && e.Status == ResponseExecutionStatus.Verified);
            bool HasCertificateStores() => Effects.Where(e => e.Action == "CertificateRemoval" && e.Status == ResponseExecutionStatus.Verified)
                .Select(e => e.Target).Distinct(StringComparer.OrdinalIgnoreCase).Count() >= 4;
            return RequestedAction switch
            {
                "KillProcess" or "KillProcessTree" => HasVerifiedProcessExit(ProcessId),
                "Quarantine" => Has("Quarantine") || Has("DllQuarantine"),
                "QuarantineAndKill" => HasVerifiedProcessExit(ProcessId) && (Has("Quarantine") || Has("DllQuarantine")),
                "NetworkIsolate" => Has("FirewallRules"),
                "RemoveCert" => HasCertificateStores(),
                "RemoveCertAndKillAdder" => HasCertificateStores() && Has("ProcessTree"),
                "RemoveRegistryEntry" => Has("RegistryRemoval"),
                "VpnShieldUp" => Has("VpnShield"),
                "DismountVolume" => Has("IsoContainment"),
                _ => false
            };
        }

        public void Add(string action, string target, ResponseExecutionStatus status, string detail)
            => Effects.Add(new ResponseEffect { Action = action, Target = target, Status = status, Detail = detail });

        public void AddProcessTree(ProcessTreeTerminationResult tree)
        {
            var status = tree.Success ? ResponseExecutionStatus.Verified
                : tree.RootExited || tree.ExitedProcessIds.Count > 0 ? ResponseExecutionStatus.PartiallyCompleted
                : tree.RefusedProcessIds.Count > 0 ? ResponseExecutionStatus.Refused : ResponseExecutionStatus.Failed;
            Add("ProcessTree", tree.RootProcessId.ToString(System.Globalization.CultureInfo.InvariantCulture), status,
                $"RootExited={tree.RootExited}; DiscoveryComplete={tree.DiscoveryComplete}; " +
                $"Exited={string.Join(",", tree.ExitedProcessIds)}; Failed={string.Join(",", tree.FailedProcessIds)}; " +
                $"Refused={string.Join(",", tree.RefusedProcessIds)}. {tree.Error}");
        }
    }
}
