using System;
using System.Collections.Generic;
using System.Linq;

namespace Sentinel.Core
{
    internal static class ProtectionPosture
    {
        internal const string CredentialScope = "Credential Guard chiefly protects domain authentication secrets. It does not protect local-account or personal Microsoft-account sign-in passwords, browser cookies, or saved browser passwords; priority depends on whether domain credentials are used.";
        internal const string CredentialGuard = "Credential Guard runtime";
        internal const string MemoryIntegrity = "Memory Integrity runtime";
        internal const string LsassProtection = "LSASS process protection runtime";

        internal static IReadOnlyList<HardeningAuditCheck> DeviceGuard(object? vbs, object? configured, object? running)
            => new[]
            {
                WindowsSecurityAuditSource.EvaluateRuntime("Virtualization-based security", vbs),
                Feature(CredentialGuard, 1, vbs, configured, running),
                Feature(MemoryIntegrity, 2, vbs, configured, running)
            };

        private static bool TryServices(object? value, out uint[] services)
        {
            services = value as uint[] ?? Array.Empty<uint>();
            return value?.GetType() == typeof(uint[]) && services.Length <= 32 && services.All(s => s <= 7) &&
                !(services.Contains(0U) && services.Length > 1);
        }

        private static HardeningAuditCheck Feature(string name, uint service, object? vbs, object? configured, object? running)
        {
            var check = new HardeningAuditCheck { Name = name };
            if (vbs is not uint state || state > 2 || !TryServices(running, out var active))
            {
                check.Detail = "Windows runtime status is missing or unsupported; configuration alone cannot prove this protection is running." +
                    (name == CredentialGuard ? " " + CredentialScope : "");
                return check;
            }
            bool runningFeature = active.Contains(service);
            check.Observed = "VBS=" + state + "; running services=" + string.Join(",", active);
            if (runningFeature && state != 2)
            { check.Detail = "Windows returned inconsistent runtime protection states; enforcement is unknown." + (name == CredentialGuard ? " " + CredentialScope : ""); return check; }
            bool configuredFeature = TryServices(configured, out var wanted) && wanted.Contains(service);
            if (name == CredentialGuard && !runningFeature)
            {
                check.State = "ContextDependent";
                check.Detail = (configuredFeature ? "Configured but not reported running. " : "Not reported running. ") + CredentialScope;
                return check;
            }
            check.State = runningFeature ? "ObservedActive" : configuredFeature ? "ConfiguredNotRunning" : "NeedsReview";
            check.Detail = runningFeature
                ? "Windows reports this protection running now. This snapshot does not prove resistance to every credential or driver attack."
                : configuredFeature
                    ? "Configured, but Windows does not report it running. Restart, policy, firmware or hardware requirements may apply; a pending reboot is not independently verified."
                    : "Windows does not report this protection running. This is a protection gap, not evidence of infection.";
            if (name == CredentialGuard) check.Detail += " " + CredentialScope;
            return check;
        }

        internal static HardeningAuditCheck Lsass(uint? level) => new()
        {
            Name = LsassProtection,
            State = !level.HasValue ? "Unknown" : level.Value <= 8 ? "ObservedActive" :
                level.Value == 0xfffffffe ? "NeedsReview" : "Unknown",
            Observed = level.HasValue ? "Protection level 0x" + level.Value.ToString("X8") : "Unavailable",
            Detail = !level.HasValue ? "The verified system LSASS process protection could not be queried." :
                level.Value <= 8 ? "Windows reports process protection on the verified system LSASS handle. This does not establish Credential Guard or protect against all kernel compromise." :
                level.Value == 0xfffffffe ? "Windows reports no LSASS process protection. Registry configuration alone does not establish enforcement." :
                "Windows returned an unrecognized protection level; enforcement is unknown."
        };
    }
}
