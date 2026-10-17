using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

namespace Sentinel.Core
{
    public sealed class DnsAdapterState
    {
        public string Id { get; set; } = "";
        public string Name { get; set; } = "";
        public string Ipv4Static { get; set; } = "";
        public string Ipv6Static { get; set; } = "";
        public string[] EffectiveServers { get; set; } = Array.Empty<string>();
        public bool SupportsIpv4 { get; set; }
        public bool SupportsIpv6 { get; set; }
        public bool InspectionComplete { get; set; } = true;
        public bool Eligible { get; set; }
        public bool PolicyManaged { get; set; }
        public string Detail { get; set; } = "";
        public string ApprovedProfile { get; set; } = "";
        public bool? ApprovedConfigurationMatches { get; set; }
        public string Fingerprint
        {
            get
            {
                using var sha = SHA256.Create();
                return BitConverter.ToString(sha.ComputeHash(Encoding.UTF8.GetBytes(JsonSerializer.Serialize(new
                {
                    Id, Ipv4Static, Ipv6Static,
                    Servers = EffectiveServers,
                    SupportsIpv4, SupportsIpv6, InspectionComplete, Eligible, PolicyManaged
                })))).Replace("-", "");
            }
        }
    }

    public sealed class DnsRepairRequest
    {
        public string AdapterId { get; set; } = "";
        public string Profile { get; set; } = "";
        public string ExpectedFingerprint { get; set; } = "";
        public string TransactionId { get; set; } = "";
    }

    public sealed class DnsRepairRecord
    {
        public string Id { get; set; } = "";
        public DateTimeOffset CreatedAt { get; set; }
        public string Profile { get; set; } = "";
        public string Phase { get; set; } = "Prepared";
        public DnsAdapterState Before { get; set; } = new();
        public DnsAdapterState? Applied { get; set; }
        // Written before mutation; constrains explicit recovery after a process crash.
        public DnsAdapterState? PendingFrom { get; set; }
        public DnsAdapterState? PendingTarget { get; set; }
    }

    public sealed class DnsRepairReceipt
    {
        public string TransactionId { get; set; } = "";
        public DateTimeOffset StartedAt { get; set; } = DateTimeOffset.UtcNow;
        public DateTimeOffset? CompletedAt { get; set; }
        public string Operation { get; set; } = "Repair";
        public string Status { get; set; } = "Refused";
        public bool ConfigurationVerified { get; set; }
        public bool CacheFlushed { get; set; }
        public bool RollbackVerified { get; set; }
        public string Detail { get; set; } = "";
        public string Scope => "Local DNS configuration and cache only; router, resolver trust and DNS answers are not verified.";
        public DnsAdapterState? Before { get; set; }
        public DnsAdapterState? After { get; set; }
    }

    public interface IDnsConfigurationBackend
    {
        IReadOnlyList<DnsAdapterState> Inspect();
        void SetServers(string adapterId, AddressFamily family, string servers);
        bool FlushCache();
    }

    public interface IDnsRepairJournal
    {
        IReadOnlyList<DnsRepairRecord> ReadAll();
        void Save(DnsRepairRecord record);
    }

    public interface IDnsRepairAudit
    {
        Task WriteBeforeAsync(DnsRepairRecord record, string operation, CancellationToken ct);
        Task WriteResultAsync(DnsRepairReceipt receipt, CancellationToken ct);
    }

    public sealed class DnsRepairService
    {
        private readonly IDnsConfigurationBackend _backend;
        private readonly IDnsRepairJournal _journal;
        private readonly IDnsRepairAudit _audit;
        private readonly SemaphoreSlim _gate = new(1, 1);
        private DnsRepairReceipt? _last;
        private readonly TimeSpan _verificationBudget;
        public DnsRepairService(IDnsConfigurationBackend backend, IDnsRepairJournal journal, IDnsRepairAudit audit)
            : this(backend, journal, audit, TimeSpan.FromSeconds(5)) { }
        internal DnsRepairService(IDnsConfigurationBackend backend, IDnsRepairJournal journal, IDnsRepairAudit audit, TimeSpan verificationBudget)
        { _backend = backend; _journal = journal; _audit = audit; _verificationBudget = verificationBudget; }
        public object Inspect()
        {
            var adapters = _backend.Inspect();
            var records = _journal.ReadAll();
            foreach (var adapter in adapters)
            {
                var approval = records.Where(r => r.Phase == "Verified" && r.Applied != null &&
                    r.Before.Id.Equals(adapter.Id, StringComparison.OrdinalIgnoreCase)).OrderByDescending(r => r.CreatedAt).FirstOrDefault();
                if (approval == null) continue;
                adapter.ApprovedProfile = approval.Profile;
                adapter.ApprovedConfigurationMatches = approval.Applied!.Fingerprint == adapter.Fingerprint;
            }
            return new
            {
                Adapters = adapters, LastResult = _last,
                Transactions = records.Select(r => new { r.Id, r.CreatedAt, r.Profile, r.Phase, AdapterId = r.Before.Id,
                PreviousIpv4 = r.Before.Ipv4Static, PreviousIpv6 = r.Before.Ipv6Static, PreviousEffectiveServers = r.Before.EffectiveServers,
                RecoveryAvailable = IsPending(r) && r.PendingFrom != null && r.PendingTarget != null }).ToArray(),
                Profiles = new[] { "Quad9", "Cloudflare", "Google" }.Select(name => new { Name = name, Ipv4 = Profile(name).V4, Ipv6 = Profile(name).V6 }).ToArray(),
                Scope = "Offline configuration inspection. An unknown resolver is not proof of hijacking. Managed policies and VPN/tunnel adapters require separate administration."
            };
        }
        internal static (string V4, string V6) Profile(string profile) => profile switch
        {
            "Quad9" => ("9.9.9.9,149.112.112.112", "2620:fe::fe,2620:fe::9"),
            "Cloudflare" => ("1.1.1.1,1.0.0.1", "2606:4700:4700::1111,2606:4700:4700::1001"),
            "Google" => ("8.8.8.8,8.8.4.4", "2001:4860:4860::8888,2001:4860:4860::8844"),
            _ => throw new ArgumentException("Choose a supported resolver profile.")
        };
        internal static string[] Servers(string value) => value.Split(new[] { ',', ';', ' ', '\t', '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries)
            .Select(x => IPAddress.Parse(x).ToString()).ToArray();
        internal static bool SameServers(IEnumerable<string> left, IEnumerable<string> right)
            => left.Select(x => IPAddress.Parse(x).ToString()).SequenceEqual(right.Select(x => IPAddress.Parse(x).ToString()), StringComparer.OrdinalIgnoreCase);
        private DnsAdapterState Read(string id) => _backend.Inspect().SingleOrDefault(a => a.Id.Equals(id, StringComparison.OrdinalIgnoreCase))
            ?? throw new InvalidOperationException("Adapter is no longer available.");
        private static void RequireEligible(DnsAdapterState state)
        {
            if (!state.InspectionComplete || !state.Eligible || state.PolicyManaged || !(state.SupportsIpv4 || state.SupportsIpv6))
                throw new InvalidOperationException("Adapter is unavailable, policy-managed or outside the supported repair scope.");
        }
        private static bool IsPending(DnsRepairRecord record) => record.Phase == "Prepared" || record.Phase == "RestorePrepared"
            || record.Phase == "RecoveryPrepared" || record.Phase == "RecoveryRequired" || record.Phase == "RollbackFailed";
        private static DnsAdapterState Target(DnsAdapterState current, string v4, string v6, string[] effective) => new()
        {
            Id = current.Id, Name = current.Name, SupportsIpv4 = current.SupportsIpv4, SupportsIpv6 = current.SupportsIpv6,
            Eligible = current.Eligible, InspectionComplete = current.InspectionComplete, PolicyManaged = current.PolicyManaged,
            Ipv4Static = v4, Ipv6Static = v6, EffectiveServers = effective
        };
        private static bool WithinPendingOperation(DnsAdapterState current, DnsRepairRecord record)
        {
            var from = record.PendingFrom; var target = record.PendingTarget;
            if (from == null || target == null || current.SupportsIpv4 != from.SupportsIpv4 || current.SupportsIpv6 != from.SupportsIpv6)
                return false;
            // Either family may have changed before the crash or during rollback. Anything
            // outside those exact saved static values is newer/unexplained state: refuse.
            bool FamilyMatches(string value, string before, string after)
                => SameServers(Servers(value), Servers(before)) || SameServers(Servers(value), Servers(after));
            return (!current.SupportsIpv4 || FamilyMatches(current.Ipv4Static, from.Ipv4Static, target.Ipv4Static))
                && (!current.SupportsIpv6 || FamilyMatches(current.Ipv6Static, from.Ipv6Static, target.Ipv6Static));
        }
        private void Apply(DnsAdapterState before, string v4, string v6, CancellationToken ct)
        {
            ct.ThrowIfCancellationRequested();
            if (before.SupportsIpv4) _backend.SetServers(before.Id, AddressFamily.InterNetwork, v4);
            ct.ThrowIfCancellationRequested();
            if (before.SupportsIpv6) _backend.SetServers(before.Id, AddressFamily.InterNetworkV6, v6);
        }
        private async Task<DnsAdapterState> Verify(string id, string v4, string v6, string[] effective, CancellationToken ct)
        {
            var elapsed = System.Diagnostics.Stopwatch.StartNew();
            do
            {
                ct.ThrowIfCancellationRequested();
                var state = Read(id);
                RequireEligible(state);
                bool staticMatches = (!state.SupportsIpv4 || SameServers(Servers(state.Ipv4Static), Servers(v4)))
                    && (!state.SupportsIpv6 || SameServers(Servers(state.Ipv6Static), Servers(v6)));
                if (staticMatches && new HashSet<string>(state.EffectiveServers.Select(x => IPAddress.Parse(x).ToString()), StringComparer.OrdinalIgnoreCase)
                    .SetEquals(effective.Select(x => IPAddress.Parse(x).ToString()))) return state;
                if (elapsed.Elapsed >= _verificationBudget) break;
                await Task.Delay(100, ct).ConfigureAwait(false);
            } while (elapsed.Elapsed < _verificationBudget);
            throw new InvalidOperationException("Configured and effective DNS read-back did not match within the verification budget.");
        }

        public async Task<DnsRepairReceipt> ExecuteAsync(DnsRepairRequest request, bool restore, CancellationToken ct, bool recover = false)
        {
            var receipt = new DnsRepairReceipt { Operation = recover ? "Recover" : restore ? "Restore" : "Repair" };
            await _gate.WaitAsync(ct).ConfigureAwait(false);
            DnsRepairRecord? record = null;
            bool mutationStarted = false;
            string? priorPhase = null;
            try
            {
                if (!Guid.TryParse(request.AdapterId, out _)) throw new ArgumentException("Invalid adapter identity.");
                ct.ThrowIfCancellationRequested();
                var current = Read(request.AdapterId);
                receipt.Before = current;
                RequireEligible(current);
                if (string.IsNullOrEmpty(request.ExpectedFingerprint) || request.ExpectedFingerprint != current.Fingerprint)
                    throw new InvalidOperationException("Network configuration changed. Inspect again before approving.");
                string v4, v6;
                string[] effective;
                if (restore || recover)
                {
                    record = _journal.ReadAll().SingleOrDefault(r => r.Id == request.TransactionId && r.Before.Id.Equals(current.Id, StringComparison.OrdinalIgnoreCase));
                    if (record == null) throw new InvalidOperationException("No matching DNS snapshot is available.");
                    if (recover)
                    {
                        if (_journal.ReadAll().Any(r => r.Id != record.Id && r.CreatedAt > record.CreatedAt && r.Before.Id.Equals(current.Id, StringComparison.OrdinalIgnoreCase))
                            || !IsPending(record) || !WithinPendingOperation(current, record))
                            throw new InvalidOperationException("Interrupted DNS recovery refused: current settings are outside the saved operation, or its recovery plan is unavailable.");
                    }
                    else
                    {
                        if (record.Phase != "Verified" || record.Applied == null)
                            throw new InvalidOperationException("No verified repair snapshot is available for restoration.");
                        if (record.Applied.Fingerprint != current.Fingerprint)
                            throw new InvalidOperationException("DNS changed since repair. Restoration would overwrite newer configuration; inspect it first.");
                    }
                    v4 = record.Before.Ipv4Static; v6 = record.Before.Ipv6Static; effective = record.Before.EffectiveServers;
                    receipt.TransactionId = record.Id;
                    priorPhase = record.Phase;
                    record.Phase = recover ? "RecoveryPrepared" : "RestorePrepared";
                }
                else
                {
                    if (_journal.ReadAll().Any(r => IsPending(r) && r.Before.Id.Equals(current.Id, StringComparison.OrdinalIgnoreCase)))
                        throw new InvalidOperationException("An unresolved DNS transaction requires recovery or administrator review before another repair.");
                    var profile = Profile(request.Profile);
                    v4 = profile.V4; v6 = profile.V6;
                    effective = (current.SupportsIpv4 ? Servers(v4) : Array.Empty<string>())
                        .Concat(current.SupportsIpv6 ? Servers(v6) : Array.Empty<string>()).ToArray();
                    record = new DnsRepairRecord { Id = Guid.NewGuid().ToString("N"), CreatedAt = DateTimeOffset.UtcNow,
                        Profile = request.Profile, Before = current };
                    receipt.TransactionId = record.Id;
                }
                record.PendingFrom = current;
                record.PendingTarget = Target(current, v4, v6, effective);
                // Durable rollback evidence and audit acceptance are required before mutation.
                _journal.Save(record);
                await _audit.WriteBeforeAsync(record, receipt.Operation, ct).ConfigureAwait(false);
                ct.ThrowIfCancellationRequested();
                if (Read(current.Id).Fingerprint != current.Fingerprint)
                    throw new InvalidOperationException("DNS changed while the snapshot/audit was being saved. Inspect again before approving.");
                mutationStarted = true;
                Apply(current, v4, v6, ct);
                receipt.After = await Verify(current.Id, v4, v6, effective, ct).ConfigureAwait(false);
                receipt.ConfigurationVerified = true;
                receipt.CacheFlushed = _backend.FlushCache();
                if (!receipt.CacheFlushed) throw new InvalidOperationException("DNS configuration matched, but cache flushing failed.");
                record.Phase = recover ? "Recovered" : restore ? "Restored" : "Verified";
                if (!restore && !recover) record.Applied = receipt.After;
                _journal.Save(record);
                receipt.Status = "Verified";
                receipt.Detail = recover ? "Interrupted operation recovered to its original DNS settings and read back; resolver trust remains unverified."
                    : restore ? "Previous DNS configuration restored and read back; this does not establish it was trustworthy."
                    : "Selected resolver configuration read back and cache flushed. No DNS-answer or router verification was performed.";
            }
            catch (Exception ex)
            {
                receipt.Status = mutationStarted ? "Failed" : "Refused";
                receipt.ConfigurationVerified = false;
                receipt.CacheFlushed = false;
                receipt.Detail = ex.Message;
                if (!mutationStarted && priorPhase != null && record != null)
                {
                    record.Phase = priorPhase;
                    try { _journal.Save(record); }
                    catch (Exception journalError) { receipt.Detail += " Journal requires review: " + journalError.Message; }
                }
                if (mutationStarted && receipt.Before != null && record != null)
                {
                    try
                    {
                        Apply(receipt.Before, receipt.Before.Ipv4Static, receipt.Before.Ipv6Static, CancellationToken.None);
                        receipt.After = await Verify(receipt.Before.Id, receipt.Before.Ipv4Static, receipt.Before.Ipv6Static,
                            receipt.Before.EffectiveServers, CancellationToken.None).ConfigureAwait(false);
                        receipt.RollbackVerified = _backend.FlushCache();
                        if (!receipt.RollbackVerified) throw new InvalidOperationException("Rollback cache flush failed.");
                        record.Phase = recover ? "RecoveryRequired" : restore ? "Verified" : "RolledBack";
                    }
                    catch (Exception rollbackError)
                    {
                        record.Phase = "RollbackFailed";
                        receipt.Status = "PartiallyCompleted";
                        receipt.Detail += " Rollback requires attention: " + rollbackError.Message;
                    }
                    try { _journal.Save(record); }
                    catch (Exception saveError) { receipt.Status = "PartiallyCompleted"; receipt.Detail += " Journal failure: " + saveError.Message; }
                }
            }
            finally { receipt.CompletedAt = DateTimeOffset.UtcNow; _last = receipt; _gate.Release(); }
            try { await _audit.WriteResultAsync(receipt, CancellationToken.None).ConfigureAwait(false); }
            catch (Exception ex)
            {
                if (receipt.Status == "Verified") receipt.Status = "PartiallyCompleted";
                receipt.Detail += " Final audit write failed: " + ex.Message;
            }
            return receipt;
        }
    }
}
