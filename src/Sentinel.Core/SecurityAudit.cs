using System;
using System.Collections.Generic;
using System.Threading;

namespace Sentinel.Core
{
    public sealed class SecurityAuditReport
    {
        public DateTime WindowStartUtc { get; set; }
        public DateTime WindowEndUtc { get; set; }
        public string Scope { get; set; } = "Read-only observations; not a clean-system verdict. Configuration read-back does not prove runtime enforcement.";
        public List<HardeningAuditCheck> Hardening { get; set; } = new();
        public List<AuditSection> History { get; set; } = new();
    }

    public sealed class HardeningAuditCheck
    {
        public string Name { get; set; } = "";
        public string State { get; set; } = "Unknown";
        public string Observed { get; set; } = "";
        public string Detail { get; set; } = "";
    }

    public sealed class AuditSection
    {
        public string Name { get; set; } = "";
        public string State { get; set; } = "Unknown";
        public string Detail { get; set; } = "Collection unavailable.";
        public List<AuditHistoryItem> Items { get; set; } = new();
    }

    public sealed class AuditHistoryItem
    {
        public DateTime? TimestampUtc { get; set; }
        public string Kind { get; set; } = "";
        public string Account { get; set; } = "";
        public string Subject { get; set; } = "";
        public string Detail { get; set; } = "";
    }

    public sealed class AuditPolicy
    {
        public string Name { get; }
        public string Key { get; }
        public string ValueName { get; }
        public int Expected { get; }
        public bool AcceptTwo { get; }
        public string Scope { get; }
        public AuditPolicy(string name, string key, string value, int expected, bool acceptTwo = false, string scope = "")
        { Name = name; Key = key; ValueName = value; Expected = expected; AcceptTwo = acceptTwo; Scope = scope; }
    }

    public sealed class AuditRegistryReading
    {
        public bool Available { get; set; }
        public object? Value { get; set; }
        public string Detail { get; set; } = "";
    }

    public interface ISecurityAuditSource
    {
        AuditRegistryReading ReadPolicy(AuditPolicy policy, CancellationToken ct);
        AuditSection ReadHistory(string logName, int[] eventIds, DateTime startUtc, DateTime endUtc, CancellationToken ct);
        AuditSection ReadDeviceUsage(DateTime startUtc, DateTime endUtc, CancellationToken ct);
        IEnumerable<HardeningAuditCheck> ReadRuntimeChecks(CancellationToken ct);
    }

    public sealed class SecurityAuditService
    {
        private readonly ISecurityAuditSource _source;
        public SecurityAuditService(ISecurityAuditSource source) => _source = source;

        public SecurityAuditReport Collect(DateTime endUtc, CancellationToken ct)
        {
            if (endUtc.Kind != DateTimeKind.Utc) throw new ArgumentException("UTC time required", nameof(endUtc));
            var report = new SecurityAuditReport { WindowEndUtc = endUtc, WindowStartUtc = endUtc.AddHours(-6) };
            foreach (var policy in Policies())
            {
                ct.ThrowIfCancellationRequested();
                try { report.Hardening.Add(Evaluate(policy, _source.ReadPolicy(policy, ct))); }
                catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
                catch (Exception ex) { report.Hardening.Add(new HardeningAuditCheck { Name = policy.Name, Detail = "Read unavailable: " + ex.GetType().Name }); }
            }
            ct.ThrowIfCancellationRequested();
            try { report.Hardening.AddRange(_source.ReadRuntimeChecks(ct)); }
            catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
            catch (Exception ex) { report.Hardening.Add(new HardeningAuditCheck { Name = "Runtime protection", Detail = "Provider unavailable: " + ex.GetType().Name }); }
            AddHistory(report, "Security", new[] { 4624, 4625 }, ct);
            AddHistory(report, "System", new[] { 7045 }, ct);
            AddHistory(report, "Microsoft-Windows-TaskScheduler/Operational", new[] { 106 }, ct);
            ct.ThrowIfCancellationRequested();
            try { report.History.Add(_source.ReadDeviceUsage(report.WindowStartUtc, endUtc, ct)); }
            catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
            catch (Exception ex) { report.History.Add(new AuditSection { Name = "Camera and microphone usage", Detail = "Read unavailable: " + ex.GetType().Name }); }
            return report;
        }

        private void AddHistory(SecurityAuditReport report, string log, int[] ids, CancellationToken ct)
        {
            ct.ThrowIfCancellationRequested();
            try { report.History.Add(_source.ReadHistory(log, ids, report.WindowStartUtc, report.WindowEndUtc, ct)); }
            catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
            catch (Exception ex) { report.History.Add(new AuditSection { Name = log, Detail = "Read unavailable: " + ex.GetType().Name }); }
        }

        internal static HardeningAuditCheck Evaluate(AuditPolicy policy, AuditRegistryReading reading)
        {
            var check = new HardeningAuditCheck { Name = policy.Name, Detail = reading.Detail };
            HardeningAuditCheck Finish()
            {
                if (!string.IsNullOrEmpty(policy.Scope))
                {
                    check.Detail += " " + policy.Scope;
                    if (check.State == "NeedsReview") check.State = "ContextDependent";
                }
                return check;
            }
            if (!reading.Available || reading.Value == null)
            {
                check.Detail = string.IsNullOrEmpty(reading.Detail) ? "No readable explicit setting; defaults and effective enforcement are unknown." : reading.Detail;
                return Finish();
            }
            // Do not coerce strings, QWORDs or malformed registry types into DWORD policy.
            if (reading.Value is not int value)
            { check.Detail = "Unexpected registry value type; configuration is unknown."; return Finish(); }
            check.Observed = value.ToString(System.Globalization.CultureInfo.InvariantCulture);
            bool matches = value == policy.Expected || (policy.AcceptTwo && value == 2);
            check.State = matches ? "Configured" : "NeedsReview";
            check.Detail = matches
                ? "Explicit registry configuration matches the baseline. Runtime enforcement is not verified; restart or policy refresh may be required."
                : "Explicit registry configuration differs from the baseline; review OS defaults and enterprise policy before changing it.";
            return Finish();
        }

        private static IEnumerable<AuditPolicy> Policies()
        {
            yield return new AuditPolicy("LSASS protected-process configuration", @"SYSTEM\CurrentControlSet\Control\Lsa", "RunAsPPL", 1, true);
            yield return new AuditPolicy("Credential Guard configuration", @"SYSTEM\CurrentControlSet\Control\Lsa", "LsaCfgFlags", 1, true, ProtectionPosture.CredentialScope);
            yield return new AuditPolicy("Memory Integrity configuration", @"SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity", "Enabled", 1);
            yield return new AuditPolicy("Vulnerable-driver blocklist configuration", @"SYSTEM\CurrentControlSet\Control\CI\Config", "VulnerableDriverBlocklistEnable", 1);
            yield return new AuditPolicy("WDigest plaintext credential caching disabled", @"SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest", "UseLogonCredential", 0);
            yield return new AuditPolicy("PowerShell script-block logging", @"SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging", "EnableScriptBlockLogging", 1);
            yield return new AuditPolicy("SMB client signing required", @"SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters", "RequireSecuritySignature", 1);
            yield return new AuditPolicy("SMB server signing required", @"SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters", "RequireSecuritySignature", 1);
            yield return new AuditPolicy("SMB1 server disabled", @"SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters", "SMB1", 0);
        }
    }
}
